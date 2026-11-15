const builtin = @import("builtin");
const std = @import("std");

const assert = std.debug.assert;
const posix = std.posix;
const windows = std.os.windows;

const IPAddress = std.Io.net.IpAddress;
const Stream = std.Io.net.Stream;

pub const ConnectError = error{
    Canceled,
    ConnectFailed,
    Timeout,
};

pub const Error = std.Io.Operation.NetRead.Error ||
    std.Io.Operation.NetWrite.Error ||
    std.Io.Timeout.Error ||
    std.Io.Cancelable;

pub const StartupError = error{SocketsUnavailable};

pub const Gather = struct {
    data: []const []const u8,
    header: []const u8,
    splat: u32,
};

const Blocking = enum {
    blocking,
    nonblocking,
};

const Control = struct {
    argument: u32,
    command: i32,
};

const PollDescriptor = extern struct {
    socket: windows.HANDLE,
    events: i16,
    returned_events: i16,
};

const WSAData = extern struct {
    version: u16,
    version_high: u16,
    sockets_max: u16,
    datagram_bytes_max: u16,
    vendor_information: ?[*]u8,
    description: [257]u8,
    system_status: [129]u8,
};

const attempt_count_max: u32 = 64;
const command_nonblocking: i32 = @bitCast(@as(u32, 0x8004667E));
const error_would_block: i32 = 10035;
const flags_overlapped_uninherited: u32 = 0x01 | 0x80;
const level_socket: i32 = 0xFFFF;
const option_error: i32 = 0x1007;
const poll_read_normal: i16 = 0x0100;
const poll_write_normal: i16 = 0x0010;
const protocol_tcp: i32 = 6;
const socket_kind_stream: i32 = 1;
const winsock_version: u16 = 0x0202;

comptime {
    assert(attempt_count_max > 0);
    assert(@sizeOf(PollDescriptor) == 16);
}

pub const cleanup = switch (builtin.target.os.tag) {
    .windows => cleanup_windows,
    else => cleanup_posix,
};

pub const close = switch (builtin.target.os.tag) {
    .windows => close_windows,
    else => close_posix,
};

pub const connect = switch (builtin.target.os.tag) {
    .windows => connect_windows,
    else => connect_posix,
};

pub const read = switch (builtin.target.os.tag) {
    .windows => read_windows,
    else => read_posix,
};

pub const startup = switch (builtin.target.os.tag) {
    .windows => startup_windows,
    else => startup_posix,
};

pub const write = switch (builtin.target.os.tag) {
    .windows => write_windows,
    else => write_posix,
};

fn startup_posix() StartupError!void {
    comptime assert(builtin.target.os.tag != .windows);
    comptime assert(attempt_count_max > 0);
}

fn cleanup_posix() void {
    comptime assert(builtin.target.os.tag != .windows);
    comptime assert(attempt_count_max > 0);
}

fn connect_posix(
    io: std.Io,
    address: *const IPAddress,
    deadline: std.Io.Timeout,
) ConnectError!Stream {
    assert(address.getPort() > 0);
    assert(deadline != .duration);

    const family = std.Io.Threaded.posixAddressFamily(address);
    const opened = posix.system.socket(family, posix.SOCK.STREAM, posix.IPPROTO.TCP);

    if (posix.errno(opened) != .SUCCESS) return error.ConnectFailed;

    const descriptor: posix.socket_t = @intCast(opened);
    errdefer _ = posix.system.close(descriptor);

    try descriptor_control(descriptor, .{ .argument = posix.FD_CLOEXEC, .command = posix.F.SETFD });
    try descriptor_blocking_set(descriptor, .nonblocking);

    var storage: std.Io.Threaded.PosixAddress = undefined;

    const length = std.Io.Threaded.addressToPosix(address, &storage);

    switch (posix.errno(posix.system.connect(descriptor, &storage.any, length))) {
        .SUCCESS => {},
        .INPROGRESS, .INTR => try connect_wait_posix(io, descriptor, deadline),
        else => return error.ConnectFailed,
    }

    try descriptor_blocking_set(descriptor, .blocking);

    return .{ .socket = .{ .address = address.*, .handle = descriptor } };
}

fn connect_wait_posix(
    io: std.Io,
    descriptor: posix.socket_t,
    deadline: std.Io.Timeout,
) ConnectError!void {
    assert(descriptor >= 0);
    assert(deadline != .duration);

    var descriptors = [1]posix.pollfd{.{
        .events = posix.POLL.OUT,
        .fd = descriptor,
        .revents = 0,
    }};

    const ready = posix.poll(&descriptors, milliseconds_until(io, deadline)) catch {
        return error.ConnectFailed;
    };

    if (ready == 0) return error.Timeout;

    var code: i32 = 0;
    var code_length: posix.socklen_t = @sizeOf(i32);

    const status = posix.system.getsockopt(
        descriptor,
        posix.SOL.SOCKET,
        posix.SO.ERROR,
        @ptrCast(&code),
        &code_length,
    );

    if (posix.errno(status) != .SUCCESS) return error.ConnectFailed;
    if (code != 0) return error.ConnectFailed;
}

fn descriptor_blocking_set(descriptor: posix.socket_t, blocking: Blocking) ConnectError!void {
    comptime assert(builtin.target.os.tag != .windows);
    assert(descriptor >= 0);

    const Flags = @Int(.unsigned, @bitSizeOf(posix.O));
    const current = posix.system.fcntl(descriptor, posix.F.GETFL, @as(usize, 0));

    if (posix.errno(current) != .SUCCESS) return error.ConnectFailed;

    var flags: posix.O = @bitCast(@as(Flags, @intCast(current)));

    flags.NONBLOCK = blocking == .nonblocking;

    try descriptor_control(descriptor, .{
        .argument = @as(Flags, @bitCast(flags)),
        .command = posix.F.SETFL,
    });
}

fn descriptor_control(descriptor: posix.socket_t, control: Control) ConnectError!void {
    assert(descriptor >= 0);
    assert(control.command >= 0);

    const status = posix.system.fcntl(descriptor, control.command, @as(usize, control.argument));

    if (posix.errno(status) != .SUCCESS) return error.ConnectFailed;
}

fn read_posix(
    io: std.Io,
    stream: *const Stream,
    buffer: []u8,
    deadline: std.Io.Timeout,
) Error!u32 {
    assert(buffer.len > 0);
    assert(buffer.len <= std.math.maxInt(u32));
    assert(deadline != .duration);

    var vectors: [1][]u8 = .{buffer};

    const operation: std.Io.Operation = .{ .net_read = .{
        .data = &vectors,
        .socket_handle = stream.socket.handle,
    } };

    const result = io.operateTimeout(operation, deadline) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.ConcurrencyUnavailable => return error.Unexpected,
        error.Timeout => return error.Timeout,
    };

    const received = try result.net_read;

    assert(received.data_len <= buffer.len);

    return @intCast(received.data_len);
}

fn write_posix(
    io: std.Io,
    stream: *const Stream,
    gather: *const Gather,
    deadline: std.Io.Timeout,
) Error!u32 {
    assert(gather.data.len > 0);
    assert(deadline != .duration);

    const operation: std.Io.Operation = .{ .net_write = .{
        .data = gather.data,
        .header = gather.header,
        .socket_handle = stream.socket.handle,
        .splat = gather.splat,
    } };

    const result = io.operateTimeout(operation, deadline) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.ConcurrencyUnavailable => return error.Unexpected,
        error.Timeout => return error.Timeout,
    };

    const written = try result.net_write;

    assert(written <= gather_bytes(gather));

    return @intCast(written);
}

fn gather_bytes(gather: *const Gather) u64 {
    assert(gather.data.len > 0);

    const last = gather.data.len - 1;

    var result: u64 = gather.header.len;

    for (gather.data[0..last]) |element| result += element.len;

    result += @as(u64, gather.data[last].len) * gather.splat;

    assert(result >= gather.header.len);

    return result;
}

fn close_posix(io: std.Io, stream: *const Stream) void {
    comptime assert(builtin.target.os.tag != .windows);
    assert(stream.socket.handle >= 0);

    stream.close(io);
}

fn startup_windows() StartupError!void {
    comptime assert(builtin.target.os.tag == .windows);

    var data: WSAData = undefined;

    if (wsa_startup(winsock_version, &data) != 0) return error.SocketsUnavailable;

    assert(data.version == winsock_version);
}

fn cleanup_windows() void {
    comptime assert(builtin.target.os.tag == .windows);
    comptime assert(winsock_version == 0x0202);

    _ = wsa_cleanup();
}

fn connect_windows(
    io: std.Io,
    address: *const IPAddress,
    deadline: std.Io.Timeout,
) ConnectError!Stream {
    assert(address.getPort() > 0);
    assert(deadline != .duration);

    const family: i32 = @intCast(std.Io.Threaded.posixAddressFamily(address));

    const handle = wsa_socket(
        family,
        socket_kind_stream,
        protocol_tcp,
        null,
        0,
        flags_overlapped_uninherited,
    );

    if (handle == windows.INVALID_HANDLE_VALUE) return error.ConnectFailed;
    errdefer _ = close_socket(handle);

    var nonblocking: u32 = 1;

    if (ioctl_socket(handle, command_nonblocking, &nonblocking) != 0) return error.ConnectFailed;

    var storage: std.Io.Threaded.PosixAddress = undefined;

    const length: i32 = @intCast(std.Io.Threaded.addressToPosix(address, &storage));

    if (connect_socket(handle, &storage.any, length) != 0) {
        if (wsa_last_error() != error_would_block) return error.ConnectFailed;

        try connect_wait_windows(io, handle, deadline);
    }

    return .{ .socket = .{ .address = address.*, .handle = handle } };
}

fn connect_wait_windows(
    io: std.Io,
    handle: windows.HANDLE,
    deadline: std.Io.Timeout,
) ConnectError!void {
    assert(handle != windows.INVALID_HANDLE_VALUE);
    assert(deadline != .duration);

    var descriptors = [1]PollDescriptor{.{
        .events = poll_write_normal,
        .returned_events = 0,
        .socket = handle,
    }};

    const ready = wsa_poll(&descriptors, descriptors.len, milliseconds_until(io, deadline));

    if (ready == 0) return error.Timeout;
    if (ready < 0) return error.ConnectFailed;

    var code: i32 = 0;
    var code_length: i32 = @sizeOf(i32);

    const status = get_socket_option(
        handle,
        level_socket,
        option_error,
        @ptrCast(&code),
        &code_length,
    );

    if (status != 0) return error.ConnectFailed;
    if (code != 0) return error.ConnectFailed;
}

fn read_windows(
    io: std.Io,
    stream: *const Stream,
    buffer: []u8,
    deadline: std.Io.Timeout,
) Error!u32 {
    assert(buffer.len > 0);
    assert(deadline != .duration);

    const handle = stream.socket.handle;
    const length: i32 = @intCast(@min(buffer.len, std.math.maxInt(i32)));

    for (0..attempt_count_max) |_| {
        try ready_wait_windows(io, handle, poll_read_normal, deadline);

        const count = receive(handle, buffer.ptr, length, 0);

        if (count >= 0) {
            const result: u32 = @intCast(count);

            assert(result <= buffer.len);

            return result;
        }

        const code = wsa_last_error();
        if (code != error_would_block) return error_of(code);
    }

    return error.Timeout;
}

fn write_windows(
    io: std.Io,
    stream: *const Stream,
    gather: *const Gather,
    deadline: std.Io.Timeout,
) Error!u32 {
    assert(gather.data.len > 0);
    assert(deadline != .duration);

    const handle = stream.socket.handle;
    const buffer = gather_first(gather);
    if (buffer.len == 0) return 0;

    for (0..attempt_count_max) |_| {
        try ready_wait_windows(io, handle, poll_write_normal, deadline);

        const count = send_socket(handle, buffer.ptr, @intCast(buffer.len), 0);

        if (count >= 0) {
            const result: u32 = @intCast(count);

            assert(result <= buffer.len);

            return result;
        }

        const code = wsa_last_error();
        if (code != error_would_block) return error_of(code);
    }

    return error.Timeout;
}

fn gather_first(gather: *const Gather) []const u8 {
    assert(gather.data.len > 0);

    const last = gather.data.len - 1;

    const buffer = found: {
        if (gather.header.len != 0) break :found gather.header;

        for (gather.data[0..last]) |element| {
            if (element.len != 0) break :found element;
        }

        if (gather.splat == 0) return &.{};

        break :found gather.data[last];
    };

    return buffer[0..@min(buffer.len, std.math.maxInt(i32))];
}

fn ready_wait_windows(
    io: std.Io,
    handle: windows.HANDLE,
    events: i16,
    deadline: std.Io.Timeout,
) Error!void {
    assert(handle != windows.INVALID_HANDLE_VALUE);
    assert(events == poll_read_normal or events == poll_write_normal);
    assert(deadline != .duration);

    var descriptors = [1]PollDescriptor{.{
        .events = events,
        .returned_events = 0,
        .socket = handle,
    }};

    const ready = wsa_poll(&descriptors, descriptors.len, milliseconds_until(io, deadline));

    if (ready == 0) return error.Timeout;
    if (ready < 0) return error_of(wsa_last_error());
}

fn error_of(code: i32) Error {
    assert(code != 0);
    assert(code != error_would_block);

    return switch (code) {
        10050 => error.NetworkDown,
        10051 => error.NetworkUnreachable,
        10053, 10054 => error.ConnectionResetByPeer,
        10055 => error.SystemResources,
        10057 => error.SocketUnconnected,
        10060 => error.ConnectionTimedOut,
        10065 => error.HostUnreachable,
        else => error.Unexpected,
    };
}

fn close_windows(io: std.Io, stream: *const Stream) void {
    comptime assert(builtin.target.os.tag == .windows);
    assert(stream.socket.handle != windows.INVALID_HANDLE_VALUE);

    _ = io;
    _ = close_socket(stream.socket.handle);
}

fn milliseconds_until(io: std.Io, deadline: std.Io.Timeout) i32 {
    assert(deadline != .duration);
    assert(attempt_count_max > 0);

    const end = switch (deadline) {
        .deadline => |value| value,
        .duration => unreachable,
        .none => return -1,
    };

    const milliseconds = end.durationFromNow(io).raw.toMilliseconds();
    const result: i32 = @intCast(std.math.clamp(milliseconds, 0, std.math.maxInt(i32)));

    assert(result >= 0);

    return result;
}

const close_socket = @extern(*const fn (windows.HANDLE) callconv(.winapi) i32, .{
    .library_name = "ws2_32",
    .name = "closesocket",
});

const connect_socket = @extern(
    *const fn (windows.HANDLE, *const posix.sockaddr, i32) callconv(.winapi) i32,
    .{ .library_name = "ws2_32", .name = "connect" },
);

const get_socket_option = @extern(
    *const fn (windows.HANDLE, i32, i32, [*]u8, *i32) callconv(.winapi) i32,
    .{ .library_name = "ws2_32", .name = "getsockopt" },
);

const ioctl_socket = @extern(*const fn (windows.HANDLE, i32, *u32) callconv(.winapi) i32, .{
    .library_name = "ws2_32",
    .name = "ioctlsocket",
});

const receive = @extern(*const fn (windows.HANDLE, [*]u8, i32, i32) callconv(.winapi) i32, .{
    .library_name = "ws2_32",
    .name = "recv",
});

const send_socket = @extern(
    *const fn (windows.HANDLE, [*]const u8, i32, i32) callconv(.winapi) i32,
    .{ .library_name = "ws2_32", .name = "send" },
);

const wsa_cleanup = @extern(*const fn () callconv(.winapi) i32, .{
    .library_name = "ws2_32",
    .name = "WSACleanup",
});

const wsa_last_error = @extern(*const fn () callconv(.winapi) i32, .{
    .library_name = "ws2_32",
    .name = "WSAGetLastError",
});

const wsa_poll = @extern(*const fn ([*]PollDescriptor, u32, i32) callconv(.winapi) i32, .{
    .library_name = "ws2_32",
    .name = "WSAPoll",
});

const wsa_socket = @extern(
    *const fn (i32, i32, i32, ?*anyopaque, u32, u32) callconv(.winapi) windows.HANDLE,
    .{ .library_name = "ws2_32", .name = "WSASocketW" },
);

const wsa_startup = @extern(*const fn (u16, *WSAData) callconv(.winapi) i32, .{
    .library_name = "ws2_32",
    .name = "WSAStartup",
});

const test_count_max: u32 = 64;

test connect {
    const io = std.testing.io;
    const any: IPAddress = try .parseIp4("127.0.0.1", 0);

    try startup();
    defer cleanup();

    var listener = try any.listen(io, .{
        .kernel_backlog = 1,
        .mode = .stream,
        .protocol = .tcp,
        .reuse_address = true,
    });

    defer listener.deinit(io);

    var streams: [test_count_max]Stream = undefined;
    var stream_count: u32 = 0;

    defer for (streams[0..stream_count]) |stream| close(io, &stream);

    const outcome = for (0..test_count_max) |_| {
        const duration: std.Io.Clock.Duration = .{ .clock = .awake, .raw = .fromMilliseconds(150) };
        const deadline: std.Io.Timeout = .{ .deadline = .fromNow(io, duration) };
        const started = std.Io.Clock.awake.now(io);

        const stream = connect(io, &listener.socket.address, deadline) catch |err| {
            const elapsed = started.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds();

            break .{ err, elapsed };
        };

        streams[stream_count] = stream;
        stream_count += 1;
    } else return error.TestUnexpectedResult;

    const failure, const elapsed = outcome;

    try std.testing.expect(failure == error.Timeout or failure == error.ConnectFailed);
    try std.testing.expect(elapsed < 1000);

    if (builtin.target.os.tag != .windows) {
        try std.testing.expectEqual(error.Timeout, failure);
        try std.testing.expect(elapsed >= 100);
    }
}

test read {
    const io = std.testing.io;
    const any: IPAddress = try .parseIp4("127.0.0.1", 0);

    try startup();
    defer cleanup();

    var listener = try any.listen(io, .{
        .kernel_backlog = 4,
        .mode = .stream,
        .protocol = .tcp,
        .reuse_address = true,
    });

    defer listener.deinit(io);

    const duration: std.Io.Clock.Duration = .{ .clock = .awake, .raw = .fromMilliseconds(150) };
    const deadline: std.Io.Timeout = .{ .deadline = .fromNow(io, duration) };

    const client = try connect(io, &listener.socket.address, deadline);
    defer close(io, &client);

    var buffer: [16]u8 = undefined;

    const started = std.Io.Clock.awake.now(io);
    const silent = read(io, &client, &buffer, deadline);
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds();

    try std.testing.expectError(error.Timeout, silent);
    try std.testing.expect(elapsed >= 100);
    try std.testing.expect(elapsed < 1000);

    const server = try listener.accept(io);
    defer server.close(io);

    var server_buffer: [16]u8 = undefined;
    var server_writer = server.writer(io, &server_buffer);

    try server_writer.interface.writeAll("pong");
    try server_writer.interface.flush();

    const later = (std.Io.Timeout{ .duration = duration }).toDeadline(io);
    const count = try read(io, &client, &buffer, later);

    try std.testing.expectEqualStrings("pong", buffer[0..count]);
}

test write {
    const io = std.testing.io;
    const any: IPAddress = try .parseIp4("127.0.0.1", 0);

    try startup();
    defer cleanup();

    var listener = try any.listen(io, .{
        .kernel_backlog = 4,
        .mode = .stream,
        .protocol = .tcp,
        .reuse_address = true,
    });

    defer listener.deinit(io);

    const duration: std.Io.Clock.Duration = .{ .clock = .awake, .raw = .fromMilliseconds(500) };
    const deadline = (std.Io.Timeout{ .duration = duration }).toDeadline(io);

    const client = try connect(io, &listener.socket.address, deadline);
    defer close(io, &client);

    const server = try listener.accept(io);
    defer server.close(io);

    const data = [_][]const u8{ "pi", "ng" };
    const first = try write(io, &client, &.{ .data = &data, .header = "", .splat = 1 }, deadline);

    try std.testing.expect(first >= 2);

    var server_buffer: [16]u8 = undefined;
    var server_reader = server.reader(io, &server_buffer);

    const received = try server_reader.interface.take(first);

    try std.testing.expectEqualStrings("ping"[0..first], received);
}
