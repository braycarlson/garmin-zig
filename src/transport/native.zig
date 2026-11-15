const std = @import("std");

const socket_module = @import("socket.zig");
const transport = @import("../transport.zig");
const url_module = @import("../url.zig");

const assert = std.debug.assert;

const Certificate = std.crypto.Certificate;
const HostName = std.Io.net.HostName;
const IPAddress = std.Io.net.IpAddress;
const TLS = std.crypto.tls.Client;
const URL = url_module.URL;

pub const bundle_bytes_max: u32 = 4 * 1024 * 1024;

const address_count_max: u32 = 16;
const buffer_bytes: u32 = TLS.min_buffer_len;
const read_bytes: u32 = buffer_bytes + transport.head_bytes_max;

comptime {
    assert(address_count_max >= 16);
    assert(read_bytes > transport.head_bytes_max);
}

pub const Native = struct {
    bundle: Certificate.Bundle,
    bundle_arena: [bundle_bytes_max]u8,
    bundle_lock: std.Io.RwLock,
    cause_last: []const u8,
    link: Link,
    socket: Socket,
    socket_read: [read_bytes]u8,
    socket_write: [buffer_bytes]u8,
    timeout_seconds: u32,
    tls: TLS,
    tls_read: [read_bytes]u8,
    tls_write: [buffer_bytes]u8,

    pub const Options = struct {
        timeout_seconds: u32,
    };

    const Link = enum {
        closed,
        plain,
        secure,
    };

    pub fn init(native: *Native, io: std.Io, options: Options) transport.Error!void {
        assert(options.timeout_seconds > 0);
        assert(options.timeout_seconds <= transport.timeout_seconds);

        native.bundle = .empty;
        native.bundle_lock = .init;
        native.cause_last = "";
        native.link = .closed;
        native.timeout_seconds = options.timeout_seconds;

        socket_module.startup() catch |err| return native.failed(err);
        errdefer socket_module.cleanup();

        var arena: std.heap.FixedBufferAllocator = .init(&native.bundle_arena);

        native.bundle.rescan(arena.allocator(), io, std.Io.Clock.real.now(io)) catch |err| {
            native.bundle = .empty;
            native.cause_last = @errorName(err);

            return error.CertificatesUnavailable;
        };

        if (native.bundle.map.count() == 0) {
            native.cause_last = "CertificatesEmpty";

            return error.CertificatesUnavailable;
        }
    }

    pub fn deinit(native: *Native) void {
        assert(native.link == .closed);
        assert(native.bundle.map.count() > 0);

        native.bundle = .empty;

        socket_module.cleanup();
    }

    pub fn send(
        native: *Native,
        io: std.Io,
        url: *const URL,
        request: []const u8,
    ) transport.Error!*std.Io.Reader {
        assert(native.link == .closed);
        assert(request.len > 0);

        native.cause_last = "";

        const duration: std.Io.Clock.Duration = .{
            .clock = .awake,
            .raw = .fromSeconds(native.timeout_seconds),
        };

        const deadline = (std.Io.Timeout{ .duration = duration }).toDeadline(io);
        const stream = try native.connect(io, url, deadline);

        native.socket = .{
            .deadline = deadline,
            .err = null,
            .io = io,
            .reader = .{
                .buffer = &native.socket_read,
                .end = 0,
                .seek = 0,
                .vtable = &.{ .stream = socket_stream },
            },
            .stream = stream,
            .writer = .{
                .buffer = &native.socket_write,
                .end = 0,
                .vtable = &.{ .drain = socket_drain },
            },
        };

        native.link = .plain;
        errdefer native.close(io);

        if (url.scheme == .https) try native.handshake(io, url);

        try native.request_write(request);

        return native.reader();
    }

    pub fn close(native: *Native, io: std.Io) void {
        assert(native.link != .closed);
        assert(native.socket.reader.buffer.len == read_bytes);

        socket_module.close(io, &native.socket.stream);
        native.link = .closed;
    }

    pub fn cause(native: *const Native) []const u8 {
        assert(native.timeout_seconds > 0);
        if (native.bundle.map.count() == 0) assert(native.cause_last.len > 0);

        if (native.link != .closed) {
            if (native.socket.err) |err| return @errorName(err);
        }

        return native.cause_last;
    }

    fn connect(
        native: *Native,
        io: std.Io,
        url: *const URL,
        deadline: std.Io.Timeout,
    ) transport.Error!std.Io.net.Stream {
        assert(url.host.len > 0);
        assert(deadline == .deadline);

        var addresses: [address_count_max]IPAddress = undefined;

        const count = try native.lookup(io, url, &addresses);

        for (addresses[0..count]) |*address| {
            const stream = socket_module.connect(io, address, deadline) catch |err| {
                native.cause_last = @errorName(err);

                continue;
            };

            return stream;
        }

        return error.ConnectFailed;
    }

    fn lookup(
        native: *Native,
        io: std.Io,
        url: *const URL,
        addresses: *[address_count_max]IPAddress,
    ) transport.Error!u32 {
        assert(url.host.len > 0);
        assert(url.port > 0);

        if (host_numeric(url.host)) {
            const literal = IPAddress.parse(url.host, url.port) catch |err| {
                return native.failed(err);
            };

            addresses[0] = literal;

            return 1;
        }

        const name = HostName.init(url.host) catch |err| return native.failed(err);

        var results: [address_count_max]HostName.LookupResult = undefined;
        var queue: std.Io.Queue(HostName.LookupResult) = .init(&results);

        name.lookup(io, &queue, .{
            .canonical_name_buffer = null,
            .family = null,
            .port = url.port,
        }) catch |err| return native.failed(err);

        var count: u32 = 0;

        for (0..address_count_max + 1) |_| {
            const result = queue.getOne(io) catch |err| switch (err) {
                error.Canceled => return native.failed(err),
                error.Closed => break,
            };

            switch (result) {
                .address => |address| {
                    if (count == addresses.len) break;

                    addresses[count] = address;
                    count += 1;
                },
                .canonical_name => continue,
            }
        }

        if (count == 0) return native.failed(error.NoAddressReturned);

        assert(count <= addresses.len);

        return count;
    }

    fn handshake(native: *Native, io: std.Io, url: *const URL) transport.Error!void {
        assert(native.link == .plain);
        assert(url.scheme == .https);

        var entropy: [TLS.Options.entropy_len]u8 = undefined;

        io.random(&entropy);

        native.tls = TLS.init(&native.socket.reader, &native.socket.writer, .{
            .alert = null,
            .allow_truncation_attacks = false,
            .ca = .{ .bundle = .{
                .bundle = &native.bundle,
                .gpa = .failing,
                .io = io,
                .lock = &native.bundle_lock,
            } },
            .entropy = &entropy,
            .host = .{ .explicit = url.host },
            .read_buffer = &native.tls_read,
            .realtime_now = std.Io.Clock.real.now(io),
            .ssl_key_log = null,
            .write_buffer = &native.tls_write,
        }) catch |err| return native.failed(err);

        native.link = .secure;
    }

    fn request_write(native: *Native, request: []const u8) transport.Error!void {
        assert(native.link != .closed);
        assert(request.len > 0);

        const writer = switch (native.link) {
            .closed => unreachable,
            .plain => &native.socket.writer,
            .secure => &native.tls.writer,
        };

        writer.writeAll(request) catch return error.WriteFailed;
        writer.flush() catch return error.WriteFailed;

        if (native.link == .secure) {
            native.socket.writer.flush() catch return error.WriteFailed;
        }
    }

    fn reader(native: *Native) *std.Io.Reader {
        assert(native.link != .closed);
        assert(native.socket.reader.buffer.len == read_bytes);

        return switch (native.link) {
            .closed => unreachable,
            .plain => &native.socket.reader,
            .secure => &native.tls.reader,
        };
    }

    fn failed(native: *Native, err: anyerror) transport.Error {
        assert(@errorName(err).len > 0);
        assert(native.timeout_seconds > 0);

        native.cause_last = @errorName(err);

        return error.ConnectFailed;
    }
};

fn host_numeric(host: []const u8) bool {
    assert(host.len > 0);
    assert(host.len <= HostName.max_len);

    for (host) |byte| {
        if (byte == '.') continue;
        if (!std.ascii.isDigit(byte)) return false;
    }

    return true;
}

const Socket = struct {
    deadline: std.Io.Timeout,
    err: ?Socket.Error,
    io: std.Io,
    reader: std.Io.Reader,
    stream: std.Io.net.Stream,
    writer: std.Io.Writer,

    const Error = socket_module.Error;
};

fn socket_stream(
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    limit: std.Io.Limit,
) std.Io.Reader.StreamError!usize {
    assert(limit != .nothing);
    assert(reader.seek <= reader.end);

    const socket: *Socket = @alignCast(@fieldParentPtr("reader", reader));
    const destination = limit.slice(try writer.writableSliceGreedy(1));

    assert(destination.len > 0);
    assert(socket.err == null);

    const count = socket_module.read(
        socket.io,
        &socket.stream,
        destination,
        socket.deadline,
    ) catch |err| {
        socket.err = err;

        return error.ReadFailed;
    };

    if (count == 0) return error.EndOfStream;

    assert(count <= destination.len);

    writer.advance(count);

    return count;
}

fn socket_drain(
    writer: *std.Io.Writer,
    data: []const []const u8,
    splat: usize,
) std.Io.Writer.Error!usize {
    assert(data.len > 0);
    assert(splat <= std.math.maxInt(u32));

    const socket: *Socket = @alignCast(@fieldParentPtr("writer", writer));

    assert(socket.err == null);

    const gather: socket_module.Gather = .{
        .data = data,
        .header = writer.buffered(),
        .splat = @intCast(splat),
    };

    const count = socket_module.write(
        socket.io,
        &socket.stream,
        &gather,
        socket.deadline,
    ) catch |err| {
        socket.err = err;

        return error.WriteFailed;
    };

    return writer.consume(count);
}

test Native {
    const native = try std.testing.allocator.create(Native);
    defer std.testing.allocator.destroy(native);

    try native.init(std.testing.io, .{ .timeout_seconds = transport.timeout_seconds });
    defer native.deinit();

    try std.testing.expect(native.bundle.map.count() > 0);
    try std.testing.expectEqualStrings("", native.cause());
}
