const std = @import("std");

const dotenv = @import("dotenv");

const assert = std.debug.assert;

pub const path_default = ".env";
pub const source_bytes_max: u32 = 64 * 1024;

pub const capacity: dotenv.Capacity = .{
    .entry_count_max = 256,
    .failure_count_max = 64,
    .text_bytes_max = 2 * source_bytes_max,
};

pub const Document = dotenv.DocumentType(capacity, void);

comptime {
    assert(source_bytes_max <= dotenv.limits.source_bytes_max);
}

pub const LoadError = dotenv.Error || std.Io.Dir.ReadFileError || error{EnvironmentTooLarge};

pub const Environment = struct {
    document: Document,
    source: [source_bytes_max + 1]u8,

    pub fn load(environment: *Environment, io: std.Io, path: []const u8) LoadError!void {
        assert(path.len > 0);
        assert(environment.source.len == source_bytes_max + 1);

        const source = std.Io.Dir.cwd().readFile(io, path, &environment.source) catch |err| {
            return switch (err) {
                error.FileNotFound => environment.parse(""),
                else => err,
            };
        };

        if (source.len > source_bytes_max) return error.EnvironmentTooLarge;

        try environment.parse(source);
    }

    pub fn parse(environment: *Environment, source: []const u8) dotenv.Error!void {
        assert(source.len <= source_bytes_max);
        assert(environment.source.len > source_bytes_max);

        try environment.document.parse(source, .{ .interpolate = false, .override = false });
    }

    pub fn lookup(
        environment: *const Environment,
        process: *const std.process.Environ.Map,
        key: []const u8,
    ) ?[]const u8 {
        assert(key.len > 0);
        assert(!environment.document.base.options.override);

        return environment.document.base.loaded(std.process.Environ.Map, process, key);
    }

    pub fn get(environment: *const Environment, key: []const u8) ?[]const u8 {
        assert(key.len > 0);
        assert(environment.document.base.entry_count <= capacity.entry_count_max);

        const entry = environment.document.get(key) orelse return null;

        return entry.value;
    }
};

const fixture =
    \\# garmin account
    \\export GARMIN_EMAIL=athlete@example.com
    \\GARMIN_PASSWORD="pa\"ss #word"  # inline comment
    \\GARMIN_CONSUMER_KEY='single $key ${HOME}'
    \\GARMIN_CONSUMER_SECRET=bare value # comment
    \\  SPACED_KEY = spaced value
    \\HASH=a#b
    \\EMPTY=
    \\KEY_ONLY
    \\ESCAPES="tab\tnewline\nback\\slash"
    \\MULTILINE="first
    \\second"
    \\
    \\=missing key
    \\BROKEN="unterminated
    \\TRAILING=after
    \\
;

const fixture_expected = [_]struct { []const u8, ?[]const u8 }{
    .{ "GARMIN_EMAIL", "athlete@example.com" },
    .{ "GARMIN_PASSWORD", "pa\"ss #word" },
    .{ "GARMIN_CONSUMER_KEY", "single $key ${HOME}" },
    .{ "GARMIN_CONSUMER_SECRET", "bare value" },
    .{ "SPACED_KEY", "spaced value" },
    .{ "HASH", "a#b" },
    .{ "EMPTY", "" },
    .{ "KEY_ONLY", null },
    .{ "ESCAPES", "tab\tnewline\nback\\slash" },
    .{ "MULTILINE", "first\nsecond" },
    .{ "TRAILING", "after" },
    .{ "BROKEN", null },
    .{ "missing", null },
};

fn fixture_check(environment: *const Environment) !void {
    for (fixture_expected) |expected| {
        const value = environment.get(expected[0]);

        if (expected[1]) |text| {
            try std.testing.expectEqualStrings(text, value orelse return error.TestValueMissing);
        } else {
            try std.testing.expect(value == null);
        }
    }

    try std.testing.expectEqual(@as(usize, 11), environment.document.list().len);

    var failures = environment.document.failures();
    var lines: [2]u32 = undefined;

    for (&lines) |*line| {
        const position = failures.next() orelse return error.TestFailureMissing;

        line.* = position.line;
    }

    const trailing = failures.next();

    try std.testing.expectEqualSlices(u32, &.{ 14, 15 }, &lines);
    try std.testing.expect(trailing == null);
}

test "an environment follows python-dotenv on the garmin fixture" {
    const environment = try std.testing.allocator.create(Environment);
    defer std.testing.allocator.destroy(environment);

    try environment.parse(fixture);
    try fixture_check(environment);
}

test "an environment reads carriage return line endings as line feeds" {
    const environment = try std.testing.allocator.create(Environment);
    defer std.testing.allocator.destroy(environment);

    var buffer: [2 * fixture.len]u8 = undefined;

    const count = std.mem.replace(u8, fixture, "\n", "\r\n", &buffer);
    const length = fixture.len + count;

    try environment.parse(buffer[0..length]);
    try fixture_check(environment);
}

test "a lookup prefers the process environment over the file" {
    const environment = try std.testing.allocator.create(Environment);
    defer std.testing.allocator.destroy(environment);

    try environment.parse(fixture);

    var process = std.process.Environ.Map.init(std.testing.allocator);
    defer process.deinit();

    try process.put("GARMIN_EMAIL", "override@example.com");
    try process.put("KEY_ONLY", "from process");

    const email = environment.lookup(&process, "GARMIN_EMAIL") orelse return error.TestMissing;

    const password = environment.lookup(&process, "GARMIN_PASSWORD") orelse {
        return error.TestMissing;
    };

    const key_only = environment.lookup(&process, "KEY_ONLY") orelse return error.TestMissing;

    try std.testing.expectEqualStrings("override@example.com", email);
    try std.testing.expectEqualStrings("pa\"ss #word", password);
    try std.testing.expectEqualStrings("from process", key_only);
    try std.testing.expect(environment.lookup(&process, "GARMIN_ABSENT") == null);
}

test "an environment refuses invalid UTF-8 and accepts an empty file" {
    const environment = try std.testing.allocator.create(Environment);
    defer std.testing.allocator.destroy(environment);

    try std.testing.expectError(error.Utf8Invalid, environment.parse("GARMIN_EMAIL=\xff\n"));

    try environment.parse("");
    try std.testing.expectEqual(@as(usize, 0), environment.document.list().len);
    try std.testing.expectEqual(@as(u32, 0), environment.document.failure_count());
}
