const std = @import("std");

const environment_module = @import("environment.zig");
const garmin = @import("garmin.zig");
const json = @import("json");
const oauth1 = @import("oauth1.zig");

const assert = std.debug.assert;

const Client = garmin.Client;
const Environment = environment_module.Environment;
const api = garmin.api;

const consumer_key_variable = "GARMIN_CONSUMER_KEY";
const consumer_secret_variable = "GARMIN_CONSUMER_SECRET";
const download_delay_ms: u32 = 350;
const download_page_count_max: u32 = 100_000;
const email_variable = "GARMIN_EMAIL";
const password_variable = "GARMIN_PASSWORD";
const path_bytes_max: u32 = 4096;
const region_bytes_max: u32 = 64 * 1024;
const stdin_bytes: u32 = 256;
const stdout_bytes: u32 = 64 * 1024;
const tokens_directory_name = ".garmin";
const tokens_file_name = "tokens.json";
const tokens_partial_suffix = ".partial";

comptime {
    assert(garmin.limits.body_bytes_max <= json.limits.input_bytes_max);
    assert(path_bytes_max >= 256);
}

const Command = enum {
    activities,
    activity,
    badges,
    consumer,
    devices,
    download,
    download_all,
    goals,
    heart_rate,
    hrv,
    intensity,
    login,
    profile,
    raw,
    respiration,
    settings,
    sleep,
    spo2,
    steps,
    stress,
    summary,
    weight,
};

const ActivityEntry = struct {
    activity_id: i64,

    pub const json = .{ .activity_id = "activityId" };
};

const ActivityList = ?[]const ActivityEntry;

const Download = union(enum) {
    downloaded: u32,
    failed: garmin.Error,
    skipped,
};

const DownloadTarget = struct {
    activity_id: i64,
    directory: []const u8,
};

const State = struct {
    client: Client,
    environ: *const std.process.Environ.Map,
    environment: Environment,
    file: [garmin.limits.token_file_bytes_max + 1]u8,
    io: std.Io,
    path: [path_bytes_max]u8,
    path_partial: [path_bytes_max]u8,
    region: [region_bytes_max]u8,
    stdin: [stdin_bytes]u8,
    stdout: [stdout_bytes]u8,
};

const Tally = struct {
    downloaded: u32,
    failed: u32,
    skipped: u32,

    fn add(tally: *Tally, download: Download) void {
        assert(tally.downloaded <= std.math.maxInt(u32) - 1);
        assert(tally.failed <= std.math.maxInt(u32) - 1);

        switch (download) {
            .downloaded => tally.downloaded += 1,
            .failed => tally.failed += 1,
            .skipped => tally.skipped += 1,
        }
    }
};

const command_names = std.StaticStringMap(Command).initComptime(.{
    .{ "activities", .activities },
    .{ "activity", .activity },
    .{ "badges", .badges },
    .{ "consumer", .consumer },
    .{ "devices", .devices },
    .{ "download", .download },
    .{ "download-all", .download_all },
    .{ "goals", .goals },
    .{ "hr", .heart_rate },
    .{ "hrv", .hrv },
    .{ "intensity", .intensity },
    .{ "login", .login },
    .{ "profile", .profile },
    .{ "raw", .raw },
    .{ "respiration", .respiration },
    .{ "settings", .settings },
    .{ "sleep", .sleep },
    .{ "spo2", .spo2 },
    .{ "steps", .steps },
    .{ "stress", .stress },
    .{ "summary", .summary },
    .{ "weight", .weight },
});

const usage_text =
    \\usage: garmin <command> [arguments]
    \\
    \\authentication:
    \\    consumer                       print the OAuth consumer credentials in use
    \\    login                          authenticate and print the tokens
    \\
    \\activities:
    \\    activities [start] [limit]     list activities as JSON
    \\    activity <id>                  activity detail as JSON
    \\    download <id> <path>           download the original FIT zip to path
    \\    download-all <directory> [limit]
    \\                                   download every activity's FIT zip (resumes)
    \\
    \\wellness (date is YYYY-MM-DD):
    \\    summary <date>                 daily summary
    \\    sleep <date>                   sleep data
    \\    steps <date>                   step chart
    \\    hr <date>                      daily heart rate
    \\    hrv <date>                     heart rate variability
    \\    stress <date>                  stress
    \\    spo2 <date>                    pulse ox
    \\    respiration <date>             respiration
    \\    intensity <date>               intensity minutes
    \\
    \\body:
    \\    weight <start> <end>           body composition over a date range
    \\
    \\account:
    \\    profile                        social profile
    \\    settings                       user settings
    \\    devices                        registered devices
    \\    badges                         earned badges
    \\    goals                          active goals
    \\
    \\    raw <path>                     GET an arbitrary connectapi path
    \\
    \\credentials come from GARMIN_EMAIL and GARMIN_PASSWORD (environment or .env)
    \\GARMIN_CONSUMER_KEY and GARMIN_CONSUMER_SECRET override the built-in pair
    \\tokens cache to ~/.garmin/tokens.json; delete the file to force a fresh login
    \\
;

pub fn main(init: std.process.Init) !void {
    assert(init.minimal.args.vector.len < std.math.maxInt(u32));
    assert(stdout_bytes > 0);

    const arguments = try init.minimal.args.toSlice(init.arena.allocator());

    const state = try init.gpa.create(State);
    defer init.gpa.destroy(state);

    state.environ = init.environ_map;
    state.io = init.io;

    var stdout_writer: std.Io.File.Writer = .init(.stdout(), init.io, &state.stdout);
    const out = &stdout_writer.interface;

    run(state, arguments, out) catch |err| {
        try out.flush();

        return err;
    };

    try out.flush();
}

fn run(state: *State, arguments: []const [:0]const u8, out: *std.Io.Writer) !void {
    assert(arguments.len > 0);
    assert(state.stdout.len == stdout_bytes);

    if (arguments.len < 2) return usage_fail(out);

    const command = command_names.get(arguments[1]) orelse return usage_fail(out);

    try state.environment.load(state.io, environment_module.path_default);
    try failures_warn(&state.environment, out);

    if (command == .consumer) return consumer_print(state, out);

    try state.client.init(state.io, .{
        .consumer_key = consumer_key(state),
        .consumer_secret = consumer_secret(state),
        .retry_delay_ms = 250,
        .transport = .{ .timeout_seconds = garmin.limits.timeout_seconds },
    });

    defer state.client.deinit();

    authenticate(state, out) catch |err| {
        try failure_report(out, &state.client, err);

        return err;
    };

    command_run(state, command, arguments, out) catch |err| {
        if (err == error.ArgumentMissing) try usage(out);

        try failure_report(out, &state.client, err);

        return err;
    };

    if (state.client.tokens_changed) try tokens_save(state, out);
}

fn command_run(
    state: *State,
    command: Command,
    arguments: []const [:0]const u8,
    out: *std.Io.Writer,
) !void {
    assert(arguments.len >= 2);
    assert(command != .consumer);

    const client = &state.client;

    const body = switch (command) {
        .activities => try activities_list(client, arguments),
        .activity => try api.activities.by_id(client, try argument(arguments, 2)),
        .badges => try api.badges.earned(client),
        .consumer => unreachable,
        .devices => try api.devices.list(client),
        .download => return download_one(state, arguments, out),
        .download_all => return download_all(state, arguments, out),
        .goals => try api.goals.list(client),
        .heart_rate => try api.wellness.heart_rate(client, try argument(arguments, 2)),
        .hrv => try api.wellness.hrv(client, try argument(arguments, 2)),
        .intensity => try api.wellness.intensity_minutes(client, try argument(arguments, 2)),
        .login => return tokens_print(client, out),
        .profile => try api.account.social_profile(client),
        .raw => try raw_fetch(client, try argument(arguments, 2)),
        .respiration => try api.wellness.respiration(client, try argument(arguments, 2)),
        .settings => try api.account.user_settings(client),
        .sleep => try api.wellness.sleep(client, try argument(arguments, 2)),
        .spo2 => try api.wellness.spo2(client, try argument(arguments, 2)),
        .steps => try api.wellness.steps(client, try argument(arguments, 2)),
        .stress => try api.wellness.stress(client, try argument(arguments, 2)),
        .summary => try api.wellness.daily_summary(client, try argument(arguments, 2)),
        .weight => try api.body.composition(client, .{
            .end = try argument(arguments, 3),
            .start = try argument(arguments, 2),
        }),
    };

    try out.print("{s}\n", .{body});
}

fn argument(arguments: []const [:0]const u8, index: u32) error{ArgumentMissing}![]const u8 {
    assert(index >= 2);
    assert(arguments.len >= 2);

    const text = argument_optional(arguments, index) orelse return error.ArgumentMissing;

    if (text.len == 0) return error.ArgumentMissing;

    return text;
}

fn argument_optional(arguments: []const [:0]const u8, index: u32) ?[]const u8 {
    assert(index >= 2);
    assert(arguments.len >= 2);

    if (index >= arguments.len) return null;

    return arguments[index];
}

fn number(text: []const u8) std.fmt.ParseIntError!u32 {
    if (text.len == 0) return error.InvalidCharacter;

    assert(text.len <= std.math.maxInt(u32));

    return std.fmt.parseInt(u32, text, 10);
}

fn activities_list(client: *Client, arguments: []const [:0]const u8) ![]const u8 {
    assert(arguments.len >= 2);
    assert(client.diagnostic.status <= 999);

    const start_text = argument_optional(arguments, 2);
    const limit_text = argument_optional(arguments, 3);
    const start = if (start_text) |text| try number(text) else 0;
    const limit = if (limit_text) |text| try number(text) else 20;

    if (limit == 0) return error.ArgumentInvalid;
    if (limit > garmin.limits.activities_page_max) return error.ArgumentInvalid;

    return api.activities.list(client, .{ .limit = limit, .start = start });
}

fn raw_fetch(client: *Client, target: []const u8) ![]const u8 {
    assert(target.len > 0);
    assert(client.diagnostic.status <= 999);

    return client.fetch(&.{ .method = .get, .payload = "", .target = target });
}

fn authenticate(state: *State, out: *std.Io.Writer) !void {
    assert(state.client.diagnostic.status == 0);
    assert(state.path.len == path_bytes_max);

    if (tokens_path(state)) |path| {
        if (try tokens_restore(state, path, out)) return;
    }

    const email = state.environment.lookup(state.environ, email_variable) orelse {
        return error.GarminEmailMissing;
    };

    const password = state.environment.lookup(state.environ, password_variable) orelse {
        return error.GarminPasswordMissing;
    };

    const outcome = try state.client.login(&.{ .email = email, .password = password });

    if (outcome == .challenged) {
        try out.writeAll("MFA code: ");
        try out.flush();

        var stdin_reader = std.Io.File.stdin().reader(state.io, &state.stdin);

        const line = try stdin_reader.interface.takeDelimiterExclusive('\n');

        try state.client.login_verify(line);
    }

    try tokens_save(state, out);
}

fn tokens_restore(state: *State, path: []const u8, out: *std.Io.Writer) !bool {
    assert(path.len > 0);
    assert(state.file.len == garmin.limits.token_file_bytes_max + 1);

    const source = std.Io.Dir.cwd().readFile(state.io, path, &state.file) catch |err| {
        return switch (err) {
            error.FileNotFound => false,
            else => cache_skip(out, err),
        };
    };

    state.client.restore(source) catch |err| return cache_skip(out, err);

    return true;
}

fn cache_skip(out: *std.Io.Writer, err: anyerror) std.Io.Writer.Error!bool {
    assert(@errorName(err).len > 0);
    assert(out.buffer.len > 0);

    try out.print("token cache unusable ({t}); logging in\n", .{err});

    return false;
}

fn tokens_save(state: *State, out: *std.Io.Writer) !void {
    assert(state.client.tokens_changed);
    assert(state.path_partial.len == path_bytes_max);

    const path = tokens_path(state) orelse return warn(out, error.HomeDirectoryUnknown);
    const directory = std.Io.Dir.path.dirname(path) orelse ".";

    var writer: std.Io.Writer = .fixed(state.file[0..garmin.limits.token_file_bytes_max]);

    state.client.save(&writer) catch return warn(out, error.TokensTooLarge);

    const partial = std.mem.print(&state.path_partial, "{s}{s}", .{
        path,
        tokens_partial_suffix,
    }) catch return warn(out, error.PathTooLong);

    const cwd = std.Io.Dir.cwd();

    cwd.createDirPath(state.io, directory) catch |err| return warn(out, err);

    cwd.writeFile(state.io, .{ .data = writer.buffered(), .sub_path = partial }) catch |err| {
        return warn(out, err);
    };

    cwd.rename(partial, cwd, path, state.io) catch |err| return warn(out, err);
}

fn warn(out: *std.Io.Writer, err: anyerror) std.Io.Writer.Error!void {
    assert(@errorName(err).len > 0);
    assert(out.buffer.len > 0);

    try out.print("warning: token save failed ({t})\n", .{err});
}

fn tokens_path(state: *State) ?[]const u8 {
    assert(state.path.len == path_bytes_max);
    assert(tokens_file_name.len > 0);

    const home = state.environ.get("USERPROFILE") orelse state.environ.get("HOME") orelse {
        return null;
    };

    const suffix_length = tokens_directory_name.len + tokens_file_name.len + 2;

    if (home.len > path_bytes_max - suffix_length) return null;

    const result = std.mem.print(&state.path, "{s}/{s}/{s}", .{
        home,
        tokens_directory_name,
        tokens_file_name,
    }) catch |err| switch (err) {
        error.NoSpaceLeft => unreachable,
    };

    return result;
}

fn tokens_print(client: *Client, out: *std.Io.Writer) !void {
    assert(client.oauth2_token.access_token.count() > 0);
    assert(client.oauth2_token.obtained_at > 0);

    const token = &client.oauth2_token;

    try out.print("display_name:  {s}\n", .{client.display_name()});
    try out.print("access_token:  {s}\n", .{token.access_token.slice()});
    try out.print("refresh_token: {s}\n", .{token.refresh_token.slice()});
    try out.print("expires_at:    {d}\n", .{token.expires_at()});
    try out.print("refresh_until: {d}\n", .{token.refresh_expires_at()});
}

fn download_one(state: *State, arguments: []const [:0]const u8, out: *std.Io.Writer) !void {
    assert(arguments.len >= 2);
    assert(state.client.diagnostic.status <= 999);

    const activity_id = try argument(arguments, 2);
    const path = try argument(arguments, 3);
    const body = try api.activities.download(&state.client, activity_id);

    try std.Io.Dir.cwd().writeFile(state.io, .{ .data = body, .sub_path = path });
    try out.print("wrote {d} bytes to {s}\n", .{ body.len, path });
}

fn download_all(state: *State, arguments: []const [:0]const u8, out: *std.Io.Writer) !void {
    assert(arguments.len >= 2);
    assert(state.region.len == region_bytes_max);

    const directory = try argument(arguments, 2);
    const limit_text = argument_optional(arguments, 3);
    const limit = if (limit_text) |text| try number(text) else garmin.limits.activities_page_max;

    if (limit == 0) return error.ArgumentInvalid;
    if (limit > garmin.limits.activities_page_max) return error.ArgumentInvalid;

    try std.Io.Dir.cwd().createDirPath(state.io, directory);

    var tally: Tally = .{ .downloaded = 0, .failed = 0, .skipped = 0 };
    var start: u32 = 0;

    for (0..download_page_count_max) |_| {
        const body = try api.activities.list(&state.client, .{ .limit = limit, .start = start });
        const identifiers = try activity_identifiers(&state.region, body, out);

        for (identifiers) |entry| {
            const download = try download_activity(state, .{
                .activity_id = entry.activity_id,
                .directory = directory,
            });

            try download_report(out, entry.activity_id, download);
            tally.add(download);
        }

        start += @intCast(identifiers.len);

        if (identifiers.len < limit) break;
    } else return error.DownloadPagesExhausted;

    try out.print("done: {d} downloaded, {d} skipped, {d} failed\n", .{
        tally.downloaded,
        tally.skipped,
        tally.failed,
    });
}

fn download_activity(state: *State, target: DownloadTarget) !Download {
    assert(target.directory.len > 0);
    assert(state.path.len == path_bytes_max);

    const path = try std.mem.print(&state.path, "{s}/{d}.zip", .{
        target.directory,
        target.activity_id,
    });

    if (try file_exists(state.io, path)) return .skipped;

    var identifier_buffer: [32]u8 = undefined;

    const identifier = try std.mem.print(&identifier_buffer, "{d}", .{target.activity_id});

    const body = api.activities.download(&state.client, identifier) catch |err| {
        return .{ .failed = err };
    };

    try std.Io.Dir.cwd().writeFile(state.io, .{ .data = body, .sub_path = path });
    try std.Io.sleep(state.io, .fromMilliseconds(download_delay_ms), .awake);

    return .{ .downloaded = @intCast(body.len) };
}

fn download_report(out: *std.Io.Writer, activity_id: i64, download: Download) !void {
    assert(activity_id >= 0);
    assert(out.buffer.len > 0);

    switch (download) {
        .downloaded => |byte_count| {
            try out.print("{d}.zip ({d} bytes)\n", .{ activity_id, byte_count });
        },
        .failed => |err| try out.print("fail {d}: {s}\n", .{ activity_id, garmin.message(err) }),
        .skipped => return,
    }

    try out.flush();
}

fn file_exists(io: std.Io, path: []const u8) std.Io.Dir.StatFileError!bool {
    assert(path.len > 0);
    assert(path.len <= path_bytes_max);

    const options: std.Io.Dir.StatFileOptions = .{ .follow_symlinks = true };

    _ = std.Io.Dir.cwd().statFile(io, path, options) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };

    return true;
}

fn activity_identifiers(
    region_buffer: *[region_bytes_max]u8,
    body: []const u8,
    out: *std.Io.Writer,
) ![]const ActivityEntry {
    assert(body.len <= garmin.limits.body_bytes_max);
    assert(region_buffer.len == region_bytes_max);

    var region: json.Region = .init(region_buffer);
    var list: ActivityList = undefined;
    var diagnostic: json.Diagnostic = undefined;

    json.decode(ActivityList, &region, body, &list, .{
        .diagnostic = &diagnostic,
        .unknown_members = .ignored,
    }) catch |err| {
        try out.print("activities response invalid ({s} at {d}:{d})\n", .{
            json.message(err),
            diagnostic.position.line,
            diagnostic.position.column,
        });

        return err;
    };

    const entries = list orelse {
        try out.writeAll("activities response invalid (null)\n");

        return error.Mismatch;
    };

    return entries;
}

fn consumer_print(state: *const State, out: *std.Io.Writer) !void {
    assert(state.environment.source.len > 0);
    assert(out.buffer.len > 0);

    try out.print("consumer_key:    {s}\n", .{consumer_key(state)});
    try out.print("consumer_secret: {s}\n", .{consumer_secret(state)});
}

fn consumer_key(state: *const State) []const u8 {
    assert(consumer_key_variable.len > 0);
    assert(state.environment.source.len > 0);

    const result = state.environment.lookup(state.environ, consumer_key_variable) orelse
        oauth1.consumer_key_default;

    assert(result.len > 0);

    return result;
}

fn consumer_secret(state: *const State) []const u8 {
    assert(consumer_secret_variable.len > 0);
    assert(state.environment.source.len > 0);

    const result = state.environment.lookup(state.environ, consumer_secret_variable) orelse
        oauth1.consumer_secret_default;

    assert(result.len > 0);

    return result;
}

fn failures_warn(environment: *const Environment, out: *std.Io.Writer) !void {
    assert(environment.document.failure_count() <= 64);
    assert(out.buffer.len > 0);

    var failures = environment.document.failures();

    for (0..environment.document.failure_count()) |_| {
        const position = failures.next() orelse break;

        try out.print("warning: {s} line {d} could not be parsed\n", .{
            environment_module.path_default,
            position.line,
        });
    }
}

fn failure_report(
    out: *std.Io.Writer,
    client: *const Client,
    err: anyerror,
) std.Io.Writer.Error!void {
    assert(@errorName(err).len > 0);
    assert(out.buffer.len > 0);

    const diagnostic = client.diagnostic;

    try out.print("error: {t}", .{err});

    if (diagnostic.status != 0) try out.print(" (HTTP {d})", .{diagnostic.status});
    if (diagnostic.cause.len > 0) try out.print(" ({s})", .{diagnostic.cause});

    try out.writeAll("\n");

    if (diagnostic.body.len > 0) try out.print("{s}\n", .{diagnostic.body});
}

fn usage(out: *std.Io.Writer) !void {
    assert(usage_text.len > 0);
    assert(out.buffer.len > 0);

    try out.writeAll(usage_text);
}

fn usage_fail(out: *std.Io.Writer) !void {
    assert(usage_text.len > 0);
    assert(out.buffer.len > 0);

    try usage(out);

    return error.ArgumentsInvalid;
}

test activity_identifiers {
    var region: [region_bytes_max]u8 = undefined;
    var buffer: [256]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);

    const body =
        \\[{"activityId": 21890000001, "activityName": "Morning \"Run\" é",
        \\  "activityType": {"typeId": 1, "typeKey": "running", "parentTypeId": 17},
        \\  "startTimeLocal": "2026-10-01 07:00:00", "distance": 5012.34,
        \\  "averageHR": null, "splitSummaries": [{"noOfSplits": 1, "splitType": "RUN"}],
        \\  "summarizedDiveInfo": {"summarizedDiveGases": []}, "manualActivity": false},
        \\ {"activityName": "Evening Ride", "activityId": 9007199254740993,
        \\  "description": null, "elevationGain": -0.5e1, "laps": [[1, 2], [3]]},
        \\ {"activityId": 1}]
    ;

    const entries = try activity_identifiers(&region, body, &out);

    try std.testing.expectEqual(@as(usize, 3), entries.len);
    try std.testing.expectEqual(@as(i64, 21890000001), entries[0].activity_id);
    try std.testing.expectEqual(@as(i64, 9007199254740993), entries[1].activity_id);
    try std.testing.expectEqual(@as(i64, 1), entries[2].activity_id);
    try std.testing.expectEqualStrings("", out.buffered());

    const empty = try activity_identifiers(&region, " [ ] ", &out);

    try std.testing.expectEqual(@as(usize, 0), empty.len);
    try std.testing.expectEqualStrings("", out.buffered());
}

test "activity identifiers report where an activity list response is invalid" {
    var region: [region_bytes_max]u8 = undefined;

    const malformed = "(malformed JSON at ";
    const mismatch = "(the value does not match the field's type at ";
    const prefix = "activities response invalid ";

    const cases = [_]struct { []const u8, anyerror, []const u8 }{
        .{ "null", error.Mismatch, "activities response invalid (null)\n" },
        .{ "{\"activityId\": 1}", error.Mismatch, prefix ++ mismatch ++ "1:" },
        .{ "[{\"activityId\": 1},\n {\"activityId\": \"2\"}]", error.Mismatch, mismatch ++ "2:" },
        .{ "[{\"activityId\": 1},\n {\"activityId\": 2.5}]", error.Mismatch, mismatch ++ "2:" },
        .{ "[{\"activityId\": 1},\n {\"activityId\": null}]", error.Mismatch, mismatch ++ "2:" },
        .{ "[{\"activityId\": 1},\n {\"activityName\": \"x\"}]", error.MemberMissing, "at 2:" },
        .{ "[{\"activityId\": 1},\n\n {\"activityId\": 2}", error.Malformed, malformed ++ "3:" },
    };

    for (cases) |case| {
        var buffer: [256]u8 = undefined;
        var out: std.Io.Writer = .fixed(&buffer);

        try std.testing.expectError(case[1], activity_identifiers(&region, case[0], &out));
        try std.testing.expect(std.mem.find(u8, out.buffered(), case[2]) != null);
    }
}

test "a token file that is missing falls back to a login without a warning" {
    const state = try std.testing.allocator.create(State);
    defer std.testing.allocator.destroy(state);

    state.io = std.testing.io;

    var temporary = std.testing.tmpDir(.{
        .access_sub_paths = true,
        .follow_symlinks = true,
        .iterate = false,
    });

    defer temporary.cleanup();

    var path_buffer: [256]u8 = undefined;

    const path = try std.mem.print(&path_buffer, ".zig-cache/tmp/{s}/absent.json", .{
        temporary.sub_path,
    });

    var buffer: [256]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);

    const restored = try tokens_restore(state, path, &out);

    try std.testing.expect(!restored);
    try std.testing.expectEqualStrings("", out.buffered());
}
