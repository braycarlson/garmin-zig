const std = @import("std");

const json = @import("json");

const http = @import("../http.zig");
const oauth1 = @import("oauth1.zig");
const Consumer = @import("consumer.zig").Consumer;

const Allocating = std.Io.Writer.Allocating;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const OAuth2Token = struct {
    access_token: []u8,
    refresh_token: []u8,
    obtained_at: i64,
    lifetime_seconds: i64,
    refresh_lifetime_seconds: i64,
    gpa: Allocator,

    pub fn deinit(token: *OAuth2Token) void {
        assert(token.access_token.len != 0);

        token.gpa.free(token.access_token);
        token.gpa.free(token.refresh_token);
    }

    pub fn expires_at(token: *const OAuth2Token) i64 {
        assert(token.obtained_at > 0);
        assert(token.lifetime_seconds > 0);

        return token.obtained_at + token.lifetime_seconds;
    }

    pub fn refresh_expires_at(token: *const OAuth2Token) i64 {
        assert(token.obtained_at > 0);
        assert(token.refresh_lifetime_seconds >= 0);

        return token.obtained_at + token.refresh_lifetime_seconds;
    }

    pub fn expired(token: *const OAuth2Token, io: std.Io) bool {
        const now = std.Io.Clock.real.now(io).toSeconds();

        assert(now > 0);

        return now + renewal_margin_seconds >= token.expires_at();
    }

    pub fn refresh_expired(token: *const OAuth2Token, io: std.Io) bool {
        const now = std.Io.Clock.real.now(io).toSeconds();

        assert(now > 0);

        return now >= token.refresh_expires_at();
    }

    pub fn authorization(token: *const OAuth2Token, gpa: Allocator) ![]u8 {
        assert(token.access_token.len != 0);

        return gpa.print("{s} {s}", .{ scheme, token.access_token });
    }
};

const Granted = struct {
    token_type: []const u8,
    access_token: []const u8,
    refresh_token: []const u8,
    expires_in: i64,
    refresh_token_expires_in: i64,
};

pub const renewal_margin_seconds: i64 = 60;
pub const lifetime_seconds_max: i64 = 10 * 365 * 24 * 60 * 60;
pub const scheme: []const u8 = "Bearer";
const exchange_path: []const u8 = "/oauth-service/oauth/exchange/user/2.0";

comptime {
    assert(renewal_margin_seconds > 0);
    assert(renewal_margin_seconds < lifetime_seconds_max);
    assert(http.body_len_max <= json.limits.input_bytes_max);
}

pub fn exchange(
    gpa: Allocator,
    io: std.Io,
    client: *http.Client,
    consumer: *const Consumer,
    token_oauth1: *const oauth1.OAuth1Token,
) !OAuth2Token {
    assert(consumer.key.len != 0);
    assert(token_oauth1.oauth_token.len != 0);

    const url = oauth1.connectapi_url ++ exchange_path;

    var params_buffer: [1]oauth1.Param = undefined;
    var params_count: usize = 0;

    if (token_oauth1.mfa_token) |mfa| {
        params_buffer[params_count] = .{ .key = "mfa_token", .value = mfa };
        params_count += 1;
    }

    const params = params_buffer[0..params_count];

    var buffers: oauth1.SigningBuffers = .{};

    const signing = try oauth1.signing_init(io, &buffers, &.{
        .method = "POST",
        .base_url = url,
        .consumer = consumer,
        .token = token_oauth1.oauth_token,
        .token_secret = token_oauth1.oauth_token_secret,
    });

    const authorization = try oauth1.authorization_header(gpa, &signing, params);
    defer gpa.free(authorization);

    const payload = try signed_body(gpa, params);
    defer gpa.free(payload);

    var response = try client.send(&.{
        .method = .POST,
        .url = url,
        .user_agent = http.user_agent_android,
        .content_type = "application/x-www-form-urlencoded",
        .authorization = authorization,
        .payload = payload,
        .redirect = false,
    });

    defer response.deinit();

    if (response.status != 200) return error.OAuth2ExchangeFailed;
    return parse_granted(gpa, io, response.body);
}

fn signed_body(
    gpa: Allocator,
    params: []const oauth1.Param,
) ![]u8 {
    var body: Allocating = .init(gpa);
    errdefer body.deinit();

    for (params, 0..) |param, index| {
        assert(param.key.len != 0);

        if (index != 0) try body.writer.writeByte('&');

        try body.writer.writeAll(param.key);
        try body.writer.writeByte('=');
        try oauth1.percent_encode(&body.writer, param.value);
    }

    return body.toOwnedSlice();
}

fn parse_granted(gpa: Allocator, io: std.Io, body: []const u8) !OAuth2Token {
    assert(body.len <= http.body_len_max);

    const region_bytes: usize = @intCast(json.region_bytes_max(Granted, body.len));
    const buffer = try gpa.alignedAlloc(u8, .@"16", region_bytes);
    defer gpa.free(buffer);

    var region: json.Region = .init(buffer);
    var granted: Granted = undefined;

    const options: json.DecodeOptions = .{ .diagnostic = null, .unknown_members = .ignored };

    try json.decode(Granted, &region, body, &granted, options);

    if (!std.ascii.eqlIgnoreCase(granted.token_type, scheme)) return error.OAuth2SchemeUnsupported;
    if (granted.access_token.len == 0) return error.OAuth2ResponseInvalid;
    if (granted.refresh_token.len == 0) return error.OAuth2ResponseInvalid;

    try check_lifetime(granted.expires_in, 1);
    try check_lifetime(granted.refresh_token_expires_in, 0);

    const obtained_at = std.Io.Clock.real.now(io).toSeconds();
    const token = try adopt(gpa, &granted, obtained_at);

    assert(token.expires_at() > obtained_at);

    return token;
}

fn check_lifetime(seconds: i64, floor: i64) !void {
    assert(floor >= 0);

    if (seconds < floor) return error.OAuth2ResponseInvalid;
    if (seconds > lifetime_seconds_max) return error.OAuth2ResponseInvalid;
}

fn adopt(gpa: Allocator, granted: *const Granted, obtained_at: i64) !OAuth2Token {
    assert(obtained_at > 0);
    assert(granted.access_token.len != 0);

    const access_token = try gpa.dupe(u8, granted.access_token);
    errdefer gpa.free(access_token);

    const refresh_token = try gpa.dupe(u8, granted.refresh_token);

    return .{
        .access_token = access_token,
        .refresh_token = refresh_token,
        .obtained_at = obtained_at,
        .lifetime_seconds = granted.expires_in,
        .refresh_lifetime_seconds = granted.refresh_token_expires_in,
        .gpa = gpa,
    };
}

test "granted tokens decode from an OAuth2 exchange response" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    const body =
        \\{"scope": "COMMUNITY_COURSE_READ GARMINPAY_WRITE CONNECT_READ",
        \\ "jti": "00000000-0000-0000-0000-000000000000", "token_type": "bearer",
        \\ "access_token": "eyJhbGciOiJSUzI1NiJ9.e30.c2lnbmF0dXJl",
        \\ "refresh_token": "eyJyZWZyZXNoIjp0cnVlfQ\/r\u0065fresh", "expires_in": 3599,
        \\ "refresh_token_expires_in": 7199, "customerId": null, "mfa": {"enabled": false}}
    ;

    var token = try parse_granted(gpa, io, body);
    defer token.deinit();

    try std.testing.expectEqualStrings("eyJhbGciOiJSUzI1NiJ9.e30.c2lnbmF0dXJl", token.access_token);
    try std.testing.expectEqualStrings("eyJyZWZyZXNoIjp0cnVlfQ/refresh", token.refresh_token);
    try std.testing.expectEqual(@as(i64, 3599), token.lifetime_seconds);
    try std.testing.expectEqual(@as(i64, 7199), token.refresh_lifetime_seconds);
    try std.testing.expect(token.obtained_at > 0);
}

test "granted tokens refuse a response the session cannot use" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    const template =
        \\{{"token_type": "{s}", "access_token": "{s}", "refresh_token": "r",
        \\ "expires_in": {s}, "refresh_token_expires_in": 0}}
    ;

    const cases = [_]struct { []const u8, []const u8, []const u8, anyerror }{
        .{ "MAC", "a", "1", error.OAuth2SchemeUnsupported },
        .{ "Bearer", "", "1", error.OAuth2ResponseInvalid },
        .{ "Bearer", "a", "0", error.OAuth2ResponseInvalid },
        .{ "Bearer", "a", "315360001", error.OAuth2ResponseInvalid },
        .{ "Bearer", "a", "\"1\"", error.Mismatch },
        .{ "Bearer", "a", "null", error.Mismatch },
    };

    for (cases) |case| {
        var buffer: [256]u8 = undefined;
        const body = try std.mem.print(&buffer, template, .{ case[0], case[1], case[2] });

        try std.testing.expectError(case[3], parse_granted(gpa, io, body));
    }

    const partial = "{\"token_type\": \"Bearer\", \"access_token\": \"a\"}";

    try std.testing.expectError(error.MemberMissing, parse_granted(gpa, io, partial));
    try std.testing.expectError(error.Malformed, parse_granted(gpa, io, "{\"token_type\""));
}
