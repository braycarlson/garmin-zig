const std = @import("std");

const bounded = @import("bounded");
const json = @import("json");

const assert = std.debug.assert;

pub const lifetime_seconds_max: i64 = 10 * 365 * 24 * 60 * 60;
pub const renewal_margin_seconds: i64 = 60;
pub const token_bytes_max: u32 = 8 * 1024;

comptime {
    assert(renewal_margin_seconds > 0);
    assert(renewal_margin_seconds < lifetime_seconds_max);
}

pub const ResponseError = json.DecodeError || error{
    ResponseInvalid,
    TokenTooLong,
    TokenTypeUnsupported,
};

pub const Text = bounded.BufferType(token_bytes_max);

pub const Token = struct {
    access_token: Text,
    lifetime_seconds: i64,
    obtained_at: i64,
    refresh_lifetime_seconds: i64,
    refresh_token: Text,

    pub fn expires_at(token: *const Token) i64 {
        assert(token.obtained_at > 0);
        assert(token.lifetime_seconds > 0);

        return token.obtained_at + token.lifetime_seconds;
    }

    pub fn refresh_expires_at(token: *const Token) i64 {
        assert(token.obtained_at > 0);
        assert(token.refresh_lifetime_seconds >= 0);

        return token.obtained_at + token.refresh_lifetime_seconds;
    }

    pub fn expired(token: *const Token, now: i64) bool {
        assert(now > 0);
        assert(token.access_token.count() > 0);

        return now + renewal_margin_seconds >= token.expires_at();
    }

    pub fn authorization_write(
        token: *const Token,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        assert(token.access_token.count() > 0);
        assert(token.obtained_at > 0);

        try writer.print("Authorization: Bearer {s}\r\n", .{token.access_token.slice()});
    }
};

const Floor = enum {
    positive,
    zero,
};

const Granted = struct {
    access_token: []const u8,
    expires_in: i64,
    refresh_token: []const u8,
    refresh_token_expires_in: i64,
    token_type: []const u8,
};

pub fn token_parse(
    token: *Token,
    region: *json.Region,
    body: []const u8,
    obtained_at: i64,
) ResponseError!void {
    assert(obtained_at > 0);
    assert(body.len <= json.limits.input_bytes_max);

    var granted: Granted = undefined;

    try json.decode(Granted, region, body, &granted, .{
        .diagnostic = null,
        .unknown_members = .ignored,
    });

    if (!std.ascii.eqlIgnoreCase(granted.token_type, "bearer")) return error.TokenTypeUnsupported;
    if (granted.access_token.len == 0) return error.ResponseInvalid;
    if (granted.refresh_token.len == 0) return error.ResponseInvalid;

    try lifetime_check(granted.expires_in, .positive);
    try lifetime_check(granted.refresh_token_expires_in, .zero);

    if (granted.access_token.len > token_bytes_max) return error.TokenTooLong;
    if (granted.refresh_token.len > token_bytes_max) return error.TokenTooLong;

    token.* = .{
        .access_token = .empty,
        .lifetime_seconds = granted.expires_in,
        .obtained_at = obtained_at,
        .refresh_lifetime_seconds = granted.refresh_token_expires_in,
        .refresh_token = .empty,
    };

    token.access_token.array.push_slice_assume_capacity(granted.access_token);
    token.refresh_token.array.push_slice_assume_capacity(granted.refresh_token);

    assert(token.expires_at() > obtained_at);
}

fn lifetime_check(seconds: i64, floor: Floor) error{ResponseInvalid}!void {
    if (seconds > lifetime_seconds_max) return error.ResponseInvalid;

    assert(lifetime_seconds_max > 0);

    switch (floor) {
        .positive => if (seconds < 1) return error.ResponseInvalid,
        .zero => if (seconds < 0) return error.ResponseInvalid,
    }
}

test token_parse {
    var buffer: [4096]u8 = undefined;
    var region: json.Region = .init(&buffer);
    var token: Token = undefined;

    const body =
        \\{"scope": "COMMUNITY_COURSE_READ GARMINPAY_WRITE CONNECT_READ",
        \\ "jti": "00000000-0000-0000-0000-000000000000", "token_type": "bearer",
        \\ "access_token": "eyJhbGciOiJSUzI1NiJ9.e30.c2lnbmF0dXJl",
        \\ "refresh_token": "eyJyZWZyZXNoIjp0cnVlfQ\/refresh", "expires_in": 3599,
        \\ "refresh_token_expires_in": 7199, "customerId": null, "mfa": {"enabled": false}}
    ;

    try token_parse(&token, &region, body, 1_700_000_000);

    const access_token = "eyJhbGciOiJSUzI1NiJ9.e30.c2lnbmF0dXJl";

    try std.testing.expectEqualStrings(access_token, token.access_token.slice());
    const refresh_token = "eyJyZWZyZXNoIjp0cnVlfQ/refresh";

    try std.testing.expectEqualStrings(refresh_token, token.refresh_token.slice());
    try std.testing.expectEqual(@as(i64, 3599), token.lifetime_seconds);
    try std.testing.expectEqual(@as(i64, 7199), token.refresh_lifetime_seconds);
    try std.testing.expectEqual(@as(i64, 1_700_003_599), token.expires_at());
    try std.testing.expectEqual(@as(i64, 1_700_007_199), token.refresh_expires_at());
    try std.testing.expect(!token.expired(1_700_000_000));
    try std.testing.expect(token.expired(1_700_003_539));

    var header_buffer: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&header_buffer);

    try token.authorization_write(&writer);
    const header = "Authorization: Bearer " ++ access_token ++ "\r\n";

    try std.testing.expectEqualStrings(header, writer.buffered());
}

test "a granted token refuses a response the client cannot use" {
    const template =
        \\{{"token_type": "{s}", "access_token": "{s}", "refresh_token": "r",
        \\ "expires_in": {s}, "refresh_token_expires_in": 0}}
    ;

    const Case = struct { []const u8, []const u8, []const u8, ResponseError };

    const cases = [_]Case{
        .{ "MAC", "a", "1", error.TokenTypeUnsupported },
        .{ "Bearer", "", "1", error.ResponseInvalid },
        .{ "Bearer", "a", "0", error.ResponseInvalid },
        .{ "Bearer", "a", "315360001", error.ResponseInvalid },
        .{ "Bearer", "a", "\"1\"", error.Mismatch },
        .{ "Bearer", "a", "null", error.Mismatch },
    };

    for (cases) |case| {
        var body_buffer: [256]u8 = undefined;
        var region_buffer: [1024]u8 = undefined;
        var region: json.Region = .init(&region_buffer);
        var token: Token = undefined;

        const body = try std.mem.print(&body_buffer, template, .{ case[0], case[1], case[2] });

        try std.testing.expectError(case[3], token_parse(&token, &region, body, 1));
    }

    const partial = "{\"token_type\": \"Bearer\", \"access_token\": \"a\"}";

    var region_buffer: [1024]u8 = undefined;
    var region: json.Region = .init(&region_buffer);
    var token: Token = undefined;

    try std.testing.expectError(error.MemberMissing, token_parse(&token, &region, partial, 1));

    region.reset();

    const truncated = "{\"token_type\"";

    try std.testing.expectError(error.Malformed, token_parse(&token, &region, truncated, 1));
}
