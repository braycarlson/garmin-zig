const std = @import("std");

const client_module = @import("client.zig");
const fuzz = @import("testing/fuzz.zig");
const transport = @import("transport.zig");

const assert = std.debug.assert;

const Client = ClientType(transport.Fake);
const ClientType = client_module.ClientType;

const body_bytes_max: u32 = 2048;
const response_bytes_max: u32 = 8 * 1024;

const statuses = [_]u16{ 200, 201, 204, 302, 400, 403, 404, 409, 429, 500, 503, 504, 418 };

const token_file =
    \\{"format":2,"consumer":{"key":"consumer-key","secret":"consumer-secret"},
    \\"oauth1":{"token":"oauth-token","secret":"oauth-token-secret","mfa":null},
    \\"oauth2":{"access":"access-token","refresh":"refresh-token","obtained_at":4000000000,
    \\"lifetime_seconds":3600,"refresh_lifetime_seconds":7200},
    \\"profile":{"display_name":"athlete"}}
;

const Framing = enum {
    chunked,
    close,
    length,
};

const Generated = struct {
    body: []const u8,
    response: []const u8,
    status: u16,
};

pub const State = struct {
    body: [body_bytes_max]u8,
    client: Client,
    response: [response_bytes_max]u8,
    responses: [1][]const u8,
    scripts: [1]transport.Fake.Script,
};

pub fn run(gpa: std.mem.Allocator, io: std.Io, campaign: *const fuzz.Campaign) !void {
    assert(campaign.events_max > 0);
    assert(campaign.events_max <= fuzz.events_max_limit);

    const state = try init(gpa, io);
    defer gpa.destroy(state);
    defer state.client.deinit();

    var prng = std.Random.DefaultPrng.init(campaign.seed);
    const random = prng.random();

    var failure_count: u32 = 0;

    for (0..campaign.events_max) |_| {
        const generated = response_generate(state, random);
        const mutated = random.uintLessThan(u32, 4) == 0;

        state.client.transport.log = .empty;
        state.responses[0] = generated.response;

        if (mutated) mutate(state, random, @intCast(generated.response.len));

        const result = state.client.fetch(&.{ .method = .get, .payload = "", .target = "/fuzz" });

        if (mutated) {
            const body = result catch {
                failure_count += 1;

                continue;
            };

            assert(body.len <= client_module.body_bytes_max);
        } else {
            if (result) |body| {
                success_check(&generated, body);
            } else |err| {
                failure_check(state, &generated, err);
            }
        }
    }

    if (campaign.events_max >= 256) assert(failure_count > 0);
}

fn init(gpa: std.mem.Allocator, io: std.Io) !*State {
    assert(response_bytes_max > body_bytes_max);
    assert(token_file.len > 0);

    const state = try gpa.create(State);
    errdefer gpa.destroy(state);

    state.responses = .{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"};
    state.scripts = .{.{ .needle = "GET /", .responses = &state.responses }};

    try state.client.init(io, .{
        .consumer_key = "consumer-key",
        .consumer_secret = "consumer-secret",
        .retry_delay_ms = 0,
        .transport = .{ .scripts = &state.scripts },
    });

    errdefer state.client.deinit();

    try state.client.restore(token_file);

    return state;
}

fn response_generate(state: *State, random: std.Random) Generated {
    assert(statuses.len > 0);
    assert(state.response.len == response_bytes_max);

    const status = statuses[random.uintLessThan(u32, statuses.len)];
    const framing = random.enumValue(Framing);
    const body_length = random.uintAtMost(u32, body_bytes_max);
    const body = state.body[0..body_length];

    random.bytes(body);

    var writer: std.Io.Writer = .fixed(&state.response);

    const shape: Generated = .{ .body = body, .response = "", .status = status };

    response_write(&writer, shape, framing) catch |err| switch (err) {
        error.WriteFailed => unreachable,
    };

    const empty = status == 204;

    const result = Generated{
        .body = if (empty) "" else body,
        .response = writer.buffered(),
        .status = status,
    };

    assert(result.response.len <= response_bytes_max);

    return result;
}

fn response_write(
    writer: *std.Io.Writer,
    generated: Generated,
    framing: Framing,
) std.Io.Writer.Error!void {
    assert(generated.status >= 200);
    assert(generated.body.len <= body_bytes_max);

    try writer.print("HTTP/1.1 {d} Fuzz\r\nSet-Cookie: fuzz=1; Path=/\r\n", .{generated.status});

    if (generated.status == 302) try writer.writeAll("Location: /fuzz\r\n");

    if (generated.status == 204) {
        try writer.writeAll("\r\n");

        return;
    }

    switch (framing) {
        .chunked => {
            try writer.writeAll("Transfer-Encoding: chunked\r\n\r\n");

            var rest = generated.body;

            for (0..generated.body.len + 1) |_| {
                if (rest.len == 0) break;

                const length = @min(rest.len, 97);

                try writer.print("{x}\r\n{s}\r\n", .{ length, rest[0..length] });
                rest = rest[length..];
            }

            try writer.writeAll("0\r\n\r\n");
        },
        .close => try writer.print("\r\n{s}", .{generated.body}),
        .length => try writer.print("Content-Length: {d}\r\n\r\n{s}", .{
            generated.body.len,
            generated.body,
        }),
    }
}

fn mutate(state: *State, random: std.Random, length: u32) void {
    assert(length > 0);
    assert(length <= response_bytes_max);

    const response = state.response[0..length];
    const index = random.uintLessThan(u32, length);

    switch (random.uintLessThan(u32, 3)) {
        0 => state.responses[0] = response[0..index],
        1 => response[index] = random.int(u8),
        2 => response[index] = '\n',
        else => unreachable,
    }
}

fn success_check(generated: *const Generated, body: []const u8) void {
    assert(generated.status < 300);
    assert(std.mem.eql(u8, body, generated.body));
}

fn failure_check(state: *const State, generated: *const Generated, err: client_module.Error) void {
    assert(err != error.ConnectFailed);
    assert(generated.status >= 300);
    assert(state.client.diagnostic.status == generated.status);

    if (generated.status == 302) {
        assert(err == error.RedirectsExhausted);
    } else {
        assert(std.mem.eql(u8, state.client.diagnostic.body, generated.body));
    }
}

test "the client reads every generated response and survives mutated ones" {
    try run(std.testing.allocator, std.testing.io, &.{ .events_max = 512, .seed = 0x5eed });
}
