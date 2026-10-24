const std = @import("std");

const dotenv = @import("dotenv");

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const Env = struct {
    arena: std.heap.ArenaAllocator,
    document: dotenv.Document,
    lines_failed: []const u32,

    pub fn deinit(env: *Env) void {
        env.arena.deinit();
    }

    pub fn get(env: *const Env, key: []const u8) ?[]const u8 {
        assert(key.len != 0);

        const entry = env.document.get(key) orelse return null;
        return entry.value;
    }

    pub fn lookup(
        env: *const Env,
        process: *const std.process.Environ.Map,
        key: []const u8,
    ) ?[]const u8 {
        assert(key.len != 0);
        assert(!env.document.options.override);

        return env.document.loaded(std.process.Environ.Map, process, key);
    }
};

pub const path_default: []const u8 = ".env";
pub const file_len_max: u32 = 64 * 1024;
const options: dotenv.Options = .{ .interpolate = false, .override = false };

comptime {
    assert(file_len_max <= dotenv.limits.source_bytes_max);
}

pub fn load(gpa: Allocator, io: std.Io, path: []const u8) !Env {
    assert(path.len != 0);

    const limit: std.Io.Limit = .limited(file_len_max);

    const source = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, limit) catch |err| switch (err) {
        error.FileNotFound => return parse(gpa, ""),
        else => return err,
    };

    defer gpa.free(source);

    return parse(gpa, source);
}

pub fn parse(gpa: Allocator, source: []const u8) !Env {
    assert(source.len <= file_len_max);

    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();

    const scratch = arena.allocator();
    const owned = try scratch.dupe(u8, source);
    const entries = try scratch.alloc(dotenv.Entry, @divFloor(source.len, 2) + 1);
    const failures = try scratch.alloc(dotenv.Position, @divFloor(source.len, 2) + 1);
    const text = try scratch.alloc(u8, 2 * source.len);
    const storage: dotenv.Storage = .{ .entries = entries, .failures = failures, .text = text };

    var document: dotenv.Document = undefined;

    document.parse(void, storage, &{}, owned, options) catch |err| {
        switch (err) {
            error.EntriesExhausted, error.TextExhausted => unreachable,
            error.Utf8Invalid => return error.Utf8Invalid,
        }
    };

    const lines_failed = try lines_failed_collect(scratch, &document);

    assert(document.list().len <= entries.len);

    return .{
        .arena = arena,
        .document = document,
        .lines_failed = lines_failed,
    };
}

fn lines_failed_collect(
    gpa: Allocator,
    document: *const dotenv.Document,
) Allocator.Error![]const u32 {
    assert(document.failure_count <= document.failure_positions.len);

    var lines: std.ArrayList(u32) = try .initCapacity(gpa, document.failure_count);
    var failures = document.failures();

    for (0..document.failure_count) |_| {
        const position = failures.next() orelse break;

        lines.appendAssumeCapacity(position.line);
    }

    assert(lines.items.len == document.failure_count);
    assert(failures.remaining == 0);

    return lines.items;
}

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

fn fixture_check(env: *const Env) !void {
    for (fixture_expected) |expected| {
        const value = env.get(expected[0]);

        if (expected[1]) |text| {
            try std.testing.expectEqualStrings(text, value orelse return error.TestValueMissing);
        } else {
            try std.testing.expect(value == null);
        }
    }

    try std.testing.expectEqual(@as(usize, 11), env.document.list().len);
    try std.testing.expectEqualSlices(u32, &.{ 14, 15 }, env.lines_failed);
}

test "parse follows python-dotenv on the garmin fixture" {
    const gpa = std.testing.allocator;

    var env = try parse(gpa, fixture);
    defer env.deinit();

    try fixture_check(&env);
}

test "parse reads carriage return line endings as line feeds" {
    const gpa = std.testing.allocator;
    const crlf = try std.mem.replaceOwned(u8, gpa, fixture, "\n", "\r\n");
    defer gpa.free(crlf);

    var env = try parse(gpa, crlf);
    defer env.deinit();

    try fixture_check(&env);
}

test "lookup prefers the process environment over the file" {
    const gpa = std.testing.allocator;

    var env = try parse(gpa, fixture);
    defer env.deinit();

    var process = std.process.Environ.Map.init(gpa);
    defer process.deinit();

    try process.put("GARMIN_EMAIL", "override@example.com");
    try process.put("KEY_ONLY", "from process");

    try std.testing.expectEqualStrings(
        "override@example.com",
        env.lookup(&process, "GARMIN_EMAIL") orelse return error.TestValueMissing,
    );

    try std.testing.expectEqualStrings(
        "pa\"ss #word",
        env.lookup(&process, "GARMIN_PASSWORD") orelse return error.TestValueMissing,
    );

    try std.testing.expectEqualStrings(
        "from process",
        env.lookup(&process, "KEY_ONLY") orelse return error.TestValueMissing,
    );

    try std.testing.expect(env.lookup(&process, "GARMIN_ABSENT") == null);
}

test "parse refuses invalid UTF-8 and accepts an empty file" {
    const gpa = std.testing.allocator;

    try std.testing.expectError(error.Utf8Invalid, parse(gpa, "GARMIN_EMAIL=\xff\n"));

    var env = try parse(gpa, "");
    defer env.deinit();

    try std.testing.expectEqual(@as(usize, 0), env.document.list().len);
    try std.testing.expectEqual(@as(usize, 0), env.lines_failed.len);
}
