const std = @import("std");

const client_module = @import("client.zig");
const transport = @import("transport.zig");

const assert = std.debug.assert;
const testing = std.testing;

const Client = ClientType(transport.Fake);
const ClientType = client_module.ClientType;
const Script = transport.Fake.Script;

const granted_first =
    \\{"token_type":"Bearer","access_token":"access-1","refresh_token":"refresh-1",
    \\"expires_in":3600,"refresh_token_expires_in":7200}
;

const granted_second =
    \\{"token_type":"Bearer","access_token":"access-2","refresh_token":"refresh-2",
    \\"expires_in":3600,"refresh_token_expires_in":7200}
;

const signin_page = "<form><input type=\"hidden\" name=\"_csrf\" value=\"csrf-1\"></form>";

const challenge_page = "<form action=\"/sso/verifyMFA/loginEnterMfaCode\">" ++
    "<input type=\"hidden\" name=\"_csrf\" value=\"csrf-2\">" ++
    "<input type=\"text\" name=\"mfa-code\"></form>";

const ticket_page = "<script>response_url = " ++
    "\"https://sso.garmin.com/sso/embed?ticket=ST-1-abc\";</script>";

const tokens_valid =
    \\{"format":2,"consumer":{"key":"consumer-key","secret":"consumer-secret"},
    \\"oauth1":{"token":"token-1","secret":"secret-1","mfa":null},
    \\"oauth2":{"access":"access-1","refresh":"refresh-1","obtained_at":4000000000,
    \\"lifetime_seconds":3600,"refresh_lifetime_seconds":7200},
    \\"profile":{"display_name":"athlete"}}
;

const tokens_expired =
    \\{"format":2,"consumer":{"key":"consumer-key","secret":"consumer-secret"},
    \\"oauth1":{"token":"token-1","secret":"secret-1","mfa":"mfa-1"},
    \\"oauth2":{"access":"access-1","refresh":"refresh-1","obtained_at":1,
    \\"lifetime_seconds":3600,"refresh_lifetime_seconds":7200},
    \\"profile":{"display_name":"athlete"}}
;

const Response = struct {
    body: []const u8,
    headers: []const u8,
    status: []const u8,
};

fn ok(comptime body: []const u8) []const u8 {
    comptime assert(body.len <= 64 * 1024);

    return response(.{ .body = body, .headers = "", .status = "200 OK" });
}

fn response(comptime parts: Response) []const u8 {
    comptime assert(parts.status.len >= 3);
    if (parts.headers.len > 0) comptime assert(std.mem.endsWith(u8, parts.headers, "\r\n"));

    return std.fmt.comptimePrint("HTTP/1.1 {s}\r\n{s}Content-Length: {d}\r\n\r\n{s}", .{
        parts.status,
        parts.headers,
        parts.body.len,
        parts.body,
    });
}

fn client_create(scripts: []const Script) !*Client {
    assert(scripts.len > 0);
    assert(scripts.len <= 64);

    const client = try testing.allocator.create(Client);
    errdefer testing.allocator.destroy(client);

    try client.init(testing.io, .{
        .consumer_key = "consumer-key",
        .consumer_secret = "consumer-secret",
        .retry_delay_ms = 0,
        .transport = .{ .scripts = scripts },
    });

    return client;
}

fn client_destroy(client: *Client) void {
    assert(client.retry_delay_ms == 0);

    client.deinit();
    testing.allocator.destroy(client);
}

const login_scripts = [_]Script{
    .{
        .needle = "GET /sso/embed?",
        .responses = &.{response(.{
            .body = "widget",
            .headers = "Set-Cookie: GARMIN-SSO=1; Path=/\r\n",
            .status = "200 OK",
        })},
    },
    .{ .needle = "GET /sso/signin?", .responses = &.{ok(signin_page)} },
    .{ .needle = "POST /sso/signin?", .responses = &.{ok(ticket_page)} },
    .{
        .needle = "GET /oauth-service/oauth/preauthorized?",
        .responses = &.{ok("oauth_token=token-1&oauth_token_secret=secret-1")},
    },
    .{
        .needle = "POST /oauth-service/oauth/exchange/user/2.0",
        .responses = &.{ok(granted_first)},
    },
    .{
        .needle = "GET /userprofile-service/socialProfile",
        .responses = &.{ok("{\"displayName\":\"athlete\",\"id\":7}")},
    },
    .{
        .needle = "GET /activitylist-service/activities/count",
        .responses = &.{ok("42")},
    },
};

test "a login without a challenge signs in, exchanges the tokens, and reads the profile" {
    const client = try client_create(&login_scripts);
    defer client_destroy(client);

    const outcome = try client.login(&.{ .email = "athlete@example.com", .password = "p&ss" });

    try testing.expectEqual(client_module.Login.authorized, outcome);
    try testing.expectEqualStrings("athlete", client.display_name());
    try testing.expectEqualStrings("token-1", client.oauth1_token.identifier.slice());
    try testing.expectEqualStrings("access-1", client.oauth2_token.access_token.slice());
    try testing.expect(client.tokens_changed);

    const fake = &client.transport;

    try testing.expect(fake.logged("User-Agent: Mozilla/5.0"));
    try testing.expect(fake.logged("Referer: https://sso.garmin.com/sso/embed\r\n"));
    try testing.expect(fake.logged("_csrf=csrf-1&embed=true&username=athlete%40example.com"));
    try testing.expect(fake.logged("&password=p%26ss"));
    try testing.expect(fake.logged("Cookie: GARMIN-SSO=1\r\n"));
    try testing.expect(fake.logged("ticket=ST-1-abc HTTP/1.1"));
    try testing.expect(fake.logged("Authorization: OAuth oauth_consumer_key=\"consumer-key\""));
    try testing.expect(fake.logged("oauth_token=\"token-1\""));
    try testing.expect(fake.logged("Authorization: Bearer access-1\r\n"));

    const count = try client.fetch(&.{
        .method = .get,
        .payload = "",
        .target = "/activitylist-service/activities/count",
    });

    try testing.expectEqualStrings("42", count);
}

test "a login decodes the display name and refuses a profile without a usable one" {
    const profile =
        \\{"id": 77, "profileId": 1234, "displayName": "trail\u00e9_runner\/42",
        \\ "fullName": "Test Athlete", "favoriteActivityTypes": ["running", "cycling"],
        \\ "userPoint": 118.5, "personalRecordsVisibility": {"visible": false, "tags": []}}
    ;

    const Case = struct { body: []const u8, cause: []const u8 };

    const cases = [_]Case{
        .{ .body = "{\"displayName\": \"\"}", .cause = "DisplayNameEmpty" },
        .{ .body = "{\"fullName\": \"Test Athlete\"}", .cause = "MemberMissing" },
        .{ .body = "{\"displayName\": null}", .cause = "Mismatch" },
        .{ .body = "{\"displayName\": 7}", .cause = "Mismatch" },
        .{ .body = "[]", .cause = "Mismatch" },
        .{ .body = "{\"displayName\": \"athlete\"", .cause = "Malformed" },
    };

    var scripts = login_scripts;
    var profiles: [cases.len + 1][]const u8 = undefined;

    inline for (cases, 0..) |case, index| profiles[index] = ok(case.body);

    profiles[cases.len] = ok(profile);
    scripts[5] = .{ .needle = "GET /userprofile-service/socialProfile", .responses = &profiles };

    const client = try client_create(&scripts);
    defer client_destroy(client);

    const credentials: client_module.Credentials = .{ .email = "a@example.com", .password = "x" };

    for (cases) |case| {
        try testing.expectError(error.ResponseInvalid, client.login(&credentials));
        try testing.expectEqualStrings(case.cause, client.diagnostic.cause);
    }

    _ = try client.login(&credentials);

    try testing.expectEqualStrings("trail\u{e9}_runner/42", client.display_name());
}

test "a login answers a multi-factor challenge through login_verify" {
    const scripts = [_]Script{
        login_scripts[0],
        login_scripts[1],
        .{ .needle = "POST /sso/signin?", .responses = &.{ok(challenge_page)} },
        .{
            .needle = "POST /sso/verifyMFA/loginEnterMfaCode?",
            .responses = &.{
                ok(challenge_page),
                ok(ticket_page),
            },
        },
        .{
            .needle = "GET /oauth-service/oauth/preauthorized?",
            .responses = &.{ok("oauth_token=token-1&oauth_token_secret=secret-1&mfa_token=mfa-1")},
        },
        login_scripts[4],
        login_scripts[5],
    };

    const client = try client_create(&scripts);
    defer client_destroy(client);

    const outcome = try client.login(&.{ .email = "athlete@example.com", .password = "secret" });

    try testing.expectEqual(client_module.Login.challenged, outcome);
    try testing.expectError(error.CodeInvalid, client.login_verify(" \r\n"));
    try testing.expectError(error.CodeRefused, client.login_verify("000000"));

    try client.login_verify("123456\n");

    const fake = &client.transport;
    const verify_form = "_csrf=csrf-2&fromPage=setupEnterMfaCode&embed=true&mfa-code=123456";

    try testing.expect(fake.logged(verify_form));
    try testing.expect(fake.logged("\r\n\r\nmfa_token=mfa-1"));
    try testing.expectEqualStrings("mfa-1", client.oauth1_token.mfa.slice());
    try testing.expectEqualStrings("athlete", client.display_name());
}

test "a login that Garmin refuses reports the refusal" {
    const scripts = [_]Script{
        login_scripts[0],
        login_scripts[1],
        .{
            .needle = "POST /sso/signin?",
            .responses = &.{ok("<p>Invalid username or password.</p>")},
        },
    };

    const client = try client_create(&scripts);
    defer client_destroy(client);

    const credentials: client_module.Credentials = .{ .email = "a@example.com", .password = "x" };
    const empty: client_module.Credentials = .{ .email = "", .password = "x" };

    try testing.expectError(error.LoginRefused, client.login(&credentials));
    try testing.expectError(error.CredentialsInvalid, client.login(&empty));
}

test "a restored token file saves back byte for byte" {
    const client = try client_create(&login_scripts);
    defer client_destroy(client);

    try client.restore(tokens_valid);

    try testing.expect(!client.tokens_changed);
    try testing.expectEqualStrings("athlete", client.display_name());

    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    try client.save(&writer);

    const expected = "{\"format\":2,\"consumer\":{\"key\":\"consumer-key\"," ++
        "\"secret\":\"consumer-secret\"},\"oauth1\":{\"token\":\"token-1\"," ++
        "\"secret\":\"secret-1\",\"mfa\":null},\"oauth2\":{\"access\":\"access-1\"," ++
        "\"refresh\":\"refresh-1\",\"obtained_at\":4000000000,\"lifetime_seconds\":3600," ++
        "\"refresh_lifetime_seconds\":7200},\"profile\":{\"display_name\":\"athlete\"}}";

    try testing.expectEqualStrings(expected, writer.buffered());
}

test "a restore refreshes an expired token and a malformed file is refused" {
    const scripts = [_]Script{.{
        .needle = "POST /oauth-service/oauth/exchange/user/2.0",
        .responses = &.{ok(granted_second)},
    }};

    const client = try client_create(&scripts);
    defer client_destroy(client);

    try testing.expectError(error.TokensInvalid, client.restore("{\"format\":2}"));

    try client.restore(tokens_expired);

    try testing.expect(client.tokens_changed);
    try testing.expectEqualStrings("access-2", client.oauth2_token.access_token.slice());
    try testing.expect(client.transport.logged("\r\n\r\nmfa_token=mfa-1"));
}

test "a fetch refreshes the token once when Garmin answers 401" {
    const scripts = [_]Script{
        .{
            .needle = "GET /expiring",
            .responses = &.{
                response(.{
                    .body = "stale",
                    .headers = "",
                    .status = "401 Unauthorized",
                }),
                ok("fresh"),
            },
        },
        .{
            .needle = "POST /oauth-service/oauth/exchange/user/2.0",
            .responses = &.{ok(granted_second)},
        },
    };

    const client = try client_create(&scripts);
    defer client_destroy(client);

    try client.restore(tokens_valid);

    const body = try client.fetch(&.{ .method = .get, .payload = "", .target = "/expiring" });

    try testing.expectEqualStrings("fresh", body);
    try testing.expect(client.transport.logged("Authorization: Bearer access-1\r\n"));
    try testing.expect(client.transport.logged("Authorization: Bearer access-2\r\n"));
    try testing.expect(client.tokens_changed);
}

test "a redirect keeps the authorization on the same host and drops it on another" {
    const scripts = [_]Script{
        .{
            .needle = "GET /first ",
            .responses = &.{response(.{
                .body = "",
                .headers = "Location: /second\r\n",
                .status = "302 Found",
            })},
        },
        .{
            .needle = "GET /second ",
            .responses = &.{response(.{
                .body = "",
                .headers = "Location: https://example.com/third\r\n",
                .status = "302 Found",
            })},
        },
        .{ .needle = "GET /third ", .responses = &.{ok("landed")} },
        .{
            .needle = "GET /loop ",
            .responses = &.{response(.{
                .body = "",
                .headers = "Location: /loop\r\n",
                .status = "301 Moved Permanently",
            })},
        },
    };

    const client = try client_create(&scripts);
    defer client_destroy(client);

    try client.restore(tokens_valid);

    const body = try client.fetch(&.{ .method = .get, .payload = "", .target = "/first" });

    try testing.expectEqualStrings("landed", body);
    const log = client.transport.log.slice();
    const third = std.mem.find(u8, log, "> example.com").?;

    try testing.expect(client.transport.logged("> connectapi.garmin.com\nGET /second HTTP/1.1"));
    try testing.expect(client.transport.logged("> example.com\nGET /third HTTP/1.1\r\n"));
    try testing.expect(std.mem.find(u8, log[third..], "Authorization") == null);
    try testing.expect(std.mem.find(u8, log[third..], "Cookie") == null);

    const loop = client.fetch(&.{ .method = .get, .payload = "", .target = "/loop" });

    try testing.expectError(error.RedirectsExhausted, loop);
}

test "a fetch retries a failed connection for GET and never for POST" {
    const scripts = [_]Script{
        .{ .needle = "GET /flaky ", .responses = &.{ "", "", ok("steady") } },
        .{ .needle = "GET /down ", .responses = &.{""} },
        .{ .needle = "POST /post ", .responses = &.{ "", ok("late") } },
    };

    const client = try client_create(&scripts);
    defer client_destroy(client);

    try client.restore(tokens_valid);

    const steady = try client.fetch(&.{ .method = .get, .payload = "", .target = "/flaky" });

    try testing.expectEqualStrings("steady", steady);

    const down = client.fetch(&.{ .method = .get, .payload = "", .target = "/down" });

    try testing.expectError(error.ConnectFailed, down);
    try testing.expectEqualStrings("FakeConnectFailed", client.diagnostic.cause);

    const post = client.fetch(&.{ .method = .post, .payload = "{}", .target = "/post" });

    try testing.expectError(error.ConnectFailed, post);
}

const StatusCase = struct {
    expected: client_module.Error,
    status: []const u8,
};

const status_cases = [_]StatusCase{
    .{ .expected = error.BadRequest, .status = "400 Bad Request" },
    .{ .expected = error.Forbidden, .status = "403 Forbidden" },
    .{ .expected = error.NotFound, .status = "404 Not Found" },
    .{ .expected = error.Conflict, .status = "409 Conflict" },
    .{ .expected = error.TooManyRequests, .status = "429 Too Many Requests" },
    .{ .expected = error.ServerError, .status = "500 Internal Server Error" },
    .{ .expected = error.Unavailable, .status = "503 Service Unavailable" },
    .{ .expected = error.StatusUnexpected, .status = "418 I'm a teapot" },
};

const status_scripts = scripts: {
    var result: [status_cases.len]Script = undefined;

    for (status_cases, &result) |case, *script| {
        const reply = response(.{ .body = case.status, .headers = "", .status = case.status });

        script.* = .{ .needle = "GET /" ++ case.status[0..3] ++ " ", .responses = &.{reply} };
    }

    break :scripts result;
};

test "a status outside the two hundreds maps to a service error with its body" {
    const client = try client_create(&status_scripts);
    defer client_destroy(client);

    try client.restore(tokens_valid);

    for (status_cases) |case| {
        const target = "/" ++ case.status[0..3];
        const result = client.fetch(&.{ .method = .get, .payload = "", .target = target });
        const status = try std.fmt.parseInt(u16, case.status[0..3], 10);

        try testing.expectError(case.expected, result);
        try testing.expectEqual(status, client.diagnostic.status);
        try testing.expectEqualStrings(case.status, client.diagnostic.body);
    }
}

test "a chunked body is decoded and a malformed response is refused" {
    const chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "4\r\nWiki\r\n5;name=value\r\npedia\r\n0\r\nTrailer: x\r\n\r\n";

    const oversized_header: [64 * 1024]u8 = @splat('a');

    const scripts = [_]Script{
        .{ .needle = "GET /chunked ", .responses = &.{chunked} },
        .{
            .needle = "GET /gzip ",
            .responses = &.{response(.{
                .body = "x",
                .headers = "Content-Encoding: gzip\r\n",
                .status = "200 OK",
            })},
        },
        .{
            .needle = "GET /head ",
            .responses = &.{"HTTP/1.1 200 OK\r\nX-Large: " ++ oversized_header ++ "\r\n\r\n"},
        },
        .{
            .needle = "GET /short ",
            .responses = &.{"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nhi"},
        },
    };

    const client = try client_create(&scripts);
    defer client_destroy(client);

    try client.restore(tokens_valid);

    const body = try client.fetch(&.{ .method = .get, .payload = "", .target = "/chunked" });

    try testing.expectEqualStrings("Wikipedia", body);

    const gzip = client.fetch(&.{ .method = .get, .payload = "", .target = "/gzip" });

    try testing.expectError(error.ResponseInvalid, gzip);
    try testing.expectEqualStrings("ContentEncodingUnsupported", client.diagnostic.cause);

    const head = client.fetch(&.{ .method = .get, .payload = "", .target = "/head" });

    try testing.expectError(error.HeadTooLarge, head);

    const short = client.fetch(&.{ .method = .get, .payload = "", .target = "/short" });

    try testing.expectError(error.ReadFailed, short);
}

test "a fetch refuses a target that is not a path" {
    const client = try client_create(&login_scripts);
    defer client_destroy(client);

    try client.restore(tokens_valid);

    const targets = [_][]const u8{ "activities", "", "/a b" };

    for (targets) |target| {
        const result = client.fetch(&.{ .method = .get, .payload = "", .target = target });

        try testing.expectError(error.ArgumentInvalid, result);
    }
}
