const std = @import("std");

const json = @import("json");
const oauth1 = @import("oauth1.zig");
const oauth2 = @import("oauth2.zig");

const assert = std.debug.assert;

pub const file_bytes_max: u32 = 64 * 1024;
pub const format_version: u32 = 2;
pub const region_bytes_max: u32 = 2 * file_bytes_max + 16;

comptime {
    assert(file_bytes_max <= json.limits.input_bytes_max);
    assert(region_bytes_max >= 2 * file_bytes_max);
}

pub const FileError = error{
    TokensInvalid,
    TokensVersionUnknown,
};

pub const File = struct {
    format: u32,
    consumer: ConsumerRecord,
    oauth1: OAuth1Record,
    oauth2: OAuth2Record,
    profile: ProfileRecord,

    const ConsumerRecord = struct {
        key: []const u8,
        secret: []const u8,
    };

    const OAuth1Record = struct {
        token: []const u8,
        secret: []const u8,
        mfa: ?[]const u8 = null,
    };

    const OAuth2Record = struct {
        access: []const u8,
        refresh: []const u8,
        obtained_at: i64,
        lifetime_seconds: i64,
        refresh_lifetime_seconds: i64,
    };

    const ProfileRecord = struct {
        display_name: []const u8,
    };
};

pub const Stored = struct {
    consumer: *const oauth1.Consumer,
    display_name: []const u8,
    oauth1: *const oauth1.Token,
    oauth2: *const oauth2.Token,
};

pub fn write(writer: *std.Io.Writer, stored: *const Stored) std.Io.Writer.Error!void {
    assert(stored.consumer.key.count() > 0);
    assert(stored.display_name.len > 0);
    assert(stored.oauth2.obtained_at > 0);

    const mfa_token = stored.oauth1.mfa.slice();

    const file = File{
        .format = format_version,
        .consumer = .{
            .key = stored.consumer.key.slice(),
            .secret = stored.consumer.secret.slice(),
        },
        .oauth1 = .{
            .token = stored.oauth1.identifier.slice(),
            .secret = stored.oauth1.secret.slice(),
            .mfa = if (mfa_token.len > 0) mfa_token else null,
        },
        .oauth2 = .{
            .access = stored.oauth2.access_token.slice(),
            .refresh = stored.oauth2.refresh_token.slice(),
            .obtained_at = stored.oauth2.obtained_at,
            .lifetime_seconds = stored.oauth2.lifetime_seconds,
            .refresh_lifetime_seconds = stored.oauth2.refresh_lifetime_seconds,
        },
        .profile = .{ .display_name = stored.display_name },
    };

    var json_writer: json.Writer = .init(writer, .{
        .indent = 2,
        .layout = .compact,
        .non_finite = .refused,
        .notation = .ecmascript,
        .utf8 = .checked,
    });

    try json.encode(File, &json_writer, &file, .{ .null_members = .emitted });

    json_writer.finish();
}

pub fn parse(region: *json.Region, source: []const u8, file: *File) FileError!void {
    assert(source.len <= file_bytes_max);
    assert(region.used == 0);

    json.decode(File, region, source, file, .{
        .diagnostic = null,
        .unknown_members = .refused,
    }) catch return error.TokensInvalid;

    if (file.format != format_version) return error.TokensVersionUnknown;
    if (file.oauth2.obtained_at <= 0) return error.TokensInvalid;
    if (file.oauth2.lifetime_seconds <= 0) return error.TokensInvalid;
    if (file.oauth2.lifetime_seconds > oauth2.lifetime_seconds_max) return error.TokensInvalid;
    if (file.oauth2.refresh_lifetime_seconds < 0) return error.TokensInvalid;

    const texts = [_][]const u8{
        file.consumer.key,
        file.consumer.secret,
        file.oauth1.token,
        file.oauth1.secret,
        file.oauth2.access,
        file.oauth2.refresh,
        file.profile.display_name,
    };

    for (texts) |text| {
        if (text.len == 0) return error.TokensInvalid;
    }
}

const display_name_checked = "\" \\ \t \x00 \u{ff} caf\u{e9} \u{2028} \u{10348}";
const display_name_escaped = "\" \\ \t \x00 \xff caf\u{e9} \u{2028} \u{10348}";
const obtained_at_fixture: i64 = 1_700_000_000;

const Fixture = struct {
    consumer: oauth1.Consumer,
    oauth1: oauth1.Token,
    oauth2: oauth2.Token,

    fn init(fixture: *Fixture) !void {
        fixture.oauth1 = .empty;

        fixture.oauth2 = .{
            .access_token = .empty,
            .lifetime_seconds = 3600,
            .obtained_at = obtained_at_fixture,
            .refresh_lifetime_seconds = 7200,
            .refresh_token = .empty,
        };

        try fixture.consumer.init(.{ .key = "consumer-key", .secret = "consumer-secret" });
        try fixture.oauth1.identifier.set("oauth-token");
        try fixture.oauth1.secret.set("oauth-token-secret");
        try fixture.oauth1.mfa.set("mfa-token");
        try fixture.oauth2.access_token.set("access-token");
        try fixture.oauth2.refresh_token.set("refresh-token");
    }

    fn stored(fixture: *const Fixture, display_name: []const u8) Stored {
        assert(display_name.len > 0);
        assert(fixture.consumer.key.count() > 0);

        return .{
            .consumer = &fixture.consumer,
            .display_name = display_name,
            .oauth1 = &fixture.oauth1,
            .oauth2 = &fixture.oauth2,
        };
    }
};

fn parse_text(source: []const u8) FileError!File {
    assert(source.len <= file_bytes_max);
    assert(region_bytes_max > 0);

    var region_buffer: [4096]u8 = undefined;
    var region: json.Region = .init(&region_buffer);
    var file: File = undefined;

    try parse(&region, source, &file);

    return file;
}

test write {
    var fixture: Fixture = undefined;

    try fixture.init();

    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    try write(&writer, &fixture.stored("athlete"));

    const expected = "{\"format\":2," ++
        "\"consumer\":{\"key\":\"consumer-key\",\"secret\":\"consumer-secret\"}," ++
        "\"oauth1\":{\"token\":\"oauth-token\",\"secret\":\"oauth-token-secret\"," ++
        "\"mfa\":\"mfa-token\"}," ++
        "\"oauth2\":{\"access\":\"access-token\",\"refresh\":\"refresh-token\"," ++
        "\"obtained_at\":1700000000,\"lifetime_seconds\":3600," ++
        "\"refresh_lifetime_seconds\":7200}," ++
        "\"profile\":{\"display_name\":\"athlete\"}}";

    try std.testing.expectEqualStrings(expected, writer.buffered());
}

test parse {
    var fixture: Fixture = undefined;

    try fixture.init();
    fixture.oauth1.mfa.clear();

    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    try write(&writer, &fixture.stored(display_name_escaped));
    try std.testing.expect(std.unicode.utf8ValidateSlice(writer.buffered()));

    const file = try parse_text(writer.buffered());

    try std.testing.expectEqual(format_version, file.format);
    try std.testing.expectEqualStrings("consumer-key", file.consumer.key);
    try std.testing.expectEqualStrings("consumer-secret", file.consumer.secret);
    try std.testing.expectEqualStrings("oauth-token", file.oauth1.token);
    try std.testing.expectEqualStrings("oauth-token-secret", file.oauth1.secret);
    try std.testing.expect(file.oauth1.mfa == null);
    try std.testing.expectEqualStrings("access-token", file.oauth2.access);
    try std.testing.expectEqualStrings("refresh-token", file.oauth2.refresh);
    try std.testing.expectEqual(obtained_at_fixture, file.oauth2.obtained_at);
    try std.testing.expectEqual(@as(i64, 3600), file.oauth2.lifetime_seconds);
    try std.testing.expectEqual(@as(i64, 7200), file.oauth2.refresh_lifetime_seconds);
    try std.testing.expectEqualStrings(display_name_checked, file.profile.display_name);
}

test "a token file refuses an unknown version, an empty text, and a bad lifetime" {
    const template =
        \\{{"format":{d},
        \\"consumer":{{"key":"{s}","secret":"s"}},
        \\"oauth1":{{"token":"t","secret":"ts","mfa":null}},
        \\"oauth2":{{"access":"a","refresh":"r","obtained_at":1,
        \\"lifetime_seconds":{d},"refresh_lifetime_seconds":1}},
        \\"profile":{{"display_name":"d"{s}}}}}
    ;

    const Case = struct { u32, []const u8, i64, []const u8, FileError };

    const cases = [_]Case{
        .{ 999, "k", 1, "", error.TokensVersionUnknown },
        .{ 2, "", 1, "", error.TokensInvalid },
        .{ 2, "k", 0, "", error.TokensInvalid },
        .{ 2, "k", oauth2.lifetime_seconds_max + 1, "", error.TokensInvalid },
        .{ 2, "k", 1, ",\"avatar\":\"x\"", error.TokensInvalid },
    };

    for (cases) |case| {
        var buffer: [512]u8 = undefined;

        const source = try std.mem.print(&buffer, template, .{
            case[0],
            case[1],
            case[2],
            case[3],
        });

        try std.testing.expectError(case[4], parse_text(source));
    }

    try std.testing.expectError(error.TokensInvalid, parse_text("{ not json"));
}
