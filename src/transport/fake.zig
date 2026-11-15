const std = @import("std");

const bounded = @import("bounded");
const transport = @import("../transport.zig");
const url_module = @import("../url.zig");

const assert = std.debug.assert;

const URL = url_module.URL;

pub const log_bytes_max: u32 = 256 * 1024;
pub const script_count_max: u32 = 64;

pub const Fake = struct {
    calls: [script_count_max]u32,
    cause_last: []const u8,
    exchange_count: u32,
    log: bounded.BufferType(log_bytes_max),
    open: bool,
    reader: std.Io.Reader,
    scripts: []const Script,

    pub const Options = struct {
        scripts: []const Script,
    };

    pub const Script = struct {
        needle: []const u8,
        responses: []const []const u8,
    };

    pub fn init(fake: *Fake, io: std.Io, options: Options) transport.Error!void {
        assert(options.scripts.len <= script_count_max);
        assert(options.scripts.len > 0);

        _ = io;

        for (options.scripts) |script| {
            assert(script.needle.len > 0);
            assert(script.responses.len > 0);
        }

        fake.calls = @splat(0);
        fake.cause_last = "";
        fake.exchange_count = 0;
        fake.log = .empty;
        fake.open = false;
        fake.scripts = options.scripts;
    }

    pub fn deinit(fake: *Fake) void {
        assert(!fake.open);
        assert(fake.scripts.len <= script_count_max);

        fake.scripts = &.{};
    }

    pub fn send(
        fake: *Fake,
        io: std.Io,
        url: *const URL,
        request: []const u8,
    ) transport.Error!*std.Io.Reader {
        assert(!fake.open);
        assert(url.host.len > 0);
        assert(request.len > 0);

        _ = io;

        fake.exchange_count += 1;
        fake.log.print("> {s}\n{s}\n", .{ url.host, request }) catch return fake.failed("LogFull");

        for (fake.scripts, 0..) |script, index| {
            if (std.mem.find(u8, request, script.needle) == null) continue;

            const call = fake.calls[index];
            const response = script.responses[@min(call, script.responses.len - 1)];

            fake.calls[index] = call + 1;

            if (response.len == 0) return fake.failed("FakeConnectFailed");

            fake.reader = .fixed(response);
            fake.open = true;

            return &fake.reader;
        }

        return fake.failed("FakeUnscripted");
    }

    pub fn close(fake: *Fake, io: std.Io) void {
        assert(fake.open);
        assert(fake.exchange_count > 0);

        _ = io;

        fake.open = false;
    }

    pub fn cause(fake: *const Fake) []const u8 {
        if (fake.exchange_count == 0) assert(fake.cause_last.len == 0);
        assert(fake.scripts.len <= script_count_max);

        return fake.cause_last;
    }

    pub fn logged(fake: *const Fake, needle: []const u8) bool {
        assert(needle.len > 0);
        assert(fake.log.count() <= log_bytes_max);

        return std.mem.find(u8, fake.log.slice(), needle) != null;
    }

    fn failed(fake: *Fake, text: []const u8) transport.Error {
        assert(text.len > 0);
        assert(!fake.open);

        fake.cause_last = text;

        return error.ConnectFailed;
    }
};

test Fake {
    const scripts = [_]Fake.Script{
        .{ .needle = "GET /a ", .responses = &.{ "first", "second" } },
        .{ .needle = "GET /down ", .responses = &.{""} },
    };

    var fake: Fake = undefined;

    try fake.init(std.testing.io, .{ .scripts = &scripts });
    defer fake.deinit();

    const url = try URL.parse("https://connectapi.garmin.com/a");
    const responses = [_][]const u8{ "first", "second", "second" };

    for (responses) |expected| {
        const reader = try fake.send(std.testing.io, &url, "GET /a HTTP/1.1\r\n\r\n");

        try std.testing.expectEqualStrings(expected, try reader.peek(expected.len));

        fake.close(std.testing.io);
    }

    const down = fake.send(std.testing.io, &url, "GET /down HTTP/1.1\r\n\r\n");

    try std.testing.expectError(error.ConnectFailed, down);
    try std.testing.expectEqualStrings("FakeConnectFailed", fake.cause());

    const unscripted = fake.send(std.testing.io, &url, "GET /b HTTP/1.1\r\n\r\n");

    try std.testing.expectError(error.ConnectFailed, unscripted);
    try std.testing.expectEqualStrings("FakeUnscripted", fake.cause());
    try std.testing.expectEqual(@as(u32, 5), fake.exchange_count);
    try std.testing.expect(fake.logged("> connectapi.garmin.com\nGET /b HTTP/1.1\r\n"));
    try std.testing.expect(!fake.logged("GET /c"));
}
