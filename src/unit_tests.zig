const std = @import("std");

const assert = std.debug.assert;

comptime {
    _ = @import("api.zig");
    _ = @import("client.zig");
    _ = @import("client_test.zig");
    _ = @import("environment.zig");
    _ = @import("fuzz_tests.zig");
    _ = @import("garmin.zig");
    _ = @import("html.zig");
    _ = @import("html_fuzz.zig");
    _ = @import("http.zig");
    _ = @import("http_fuzz.zig");
    _ = @import("main.zig");
    _ = @import("oauth1.zig");
    _ = @import("oauth1_fuzz.zig");
    _ = @import("oauth2.zig");
    _ = @import("sso.zig");
    _ = @import("testing/fuzz.zig");
    _ = @import("tidy.zig");
    _ = @import("tokens.zig");
    _ = @import("transport.zig");
    _ = @import("transport/fake.zig");
    _ = @import("transport/native.zig");
    _ = @import("transport/socket.zig");
    _ = @import("url.zig");
}

test "every public declaration compiles" {
    const garmin = @import("garmin.zig");

    const FakeClient = garmin.ClientType(garmin.Fake);
    const FakeAPI = garmin.APIType(FakeClient);

    comptime assert(@hasDecl(garmin, "Client"));
    comptime assert(@hasDecl(garmin, "limits"));

    std.testing.refAllDecls(garmin);
    std.testing.refAllDecls(garmin.Client);
    std.testing.refAllDecls(garmin.limits);
    std.testing.refAllDecls(FakeClient);

    inline for (.{ garmin.api, FakeAPI }) |API| {
        std.testing.refAllDecls(API.account);
        std.testing.refAllDecls(API.activities);
        std.testing.refAllDecls(API.badges);
        std.testing.refAllDecls(API.body);
        std.testing.refAllDecls(API.devices);
        std.testing.refAllDecls(API.gear);
        std.testing.refAllDecls(API.goals);
        std.testing.refAllDecls(API.metrics);
        std.testing.refAllDecls(API.mutations);
        std.testing.refAllDecls(API.records);
        std.testing.refAllDecls(API.stats);
        std.testing.refAllDecls(API.wellness);
        std.testing.refAllDecls(API.womens_health);
        std.testing.refAllDecls(API.workouts);
    }
}
