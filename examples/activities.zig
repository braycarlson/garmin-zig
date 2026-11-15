const std = @import("std");

const garmin = @import("garmin");

const assert = std.debug.assert;

const Client = garmin.ClientType(garmin.Fake);
const api = garmin.APIType(Client);

const activities =
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 47\r\n\r\n" ++
    "[{\"activityId\":1,\"activityName\":\"Morning Run\"}]";

const scripts = [_]garmin.Fake.Script{
    .{ .needle = "GET /activitylist-service/", .responses = &.{activities} },
};

const tokens =
    \\{"format":2,"consumer":{"key":"consumer-key","secret":"consumer-secret"},
    \\"oauth1":{"token":"oauth-token","secret":"oauth-token-secret","mfa":null},
    \\"oauth2":{"access":"access-token","refresh":"refresh-token","obtained_at":4000000000,
    \\"lifetime_seconds":3600,"refresh_lifetime_seconds":7200},
    \\"profile":{"display_name":"athlete"}}
;

pub fn main(init: std.process.Init) !void {
    assert(init.minimal.args.vector.len < std.math.maxInt(u32));
    assert(tokens.len <= garmin.limits.token_file_bytes_max);

    const client = try init.gpa.create(Client);
    defer init.gpa.destroy(client);

    try client.init(init.io, .{
        .consumer_key = "consumer-key",
        .consumer_secret = "consumer-secret",
        .retry_delay_ms = 250,
        .transport = .{ .scripts = &scripts },
    });

    defer client.deinit();

    try client.restore(tokens);

    const body = api.activities.list(client, .{ .limit = 20, .start = 0 }) catch |err| {
        const diagnostic = client.diagnostic;

        std.debug.print("{s}: HTTP {d}\n", .{ garmin.message(err), diagnostic.status });

        return err;
    };

    std.debug.print("{s}\n", .{body});
}
