const std = @import("std");

const fuzz = @import("testing/fuzz.zig");
const oauth1 = @import("oauth1.zig");

const assert = std.debug.assert;

const escape_alphabet = "%+0123456789abcdefzZ =&";
const input_bytes_max: u32 = 256;

comptime {
    assert(input_bytes_max > 0);
    assert(escape_alphabet.len > 0);
}

pub fn run(campaign: *const fuzz.Campaign) !void {
    assert(campaign.events_max > 0);
    assert(campaign.events_max <= fuzz.events_max_limit);

    var prng = std.Random.DefaultPrng.init(campaign.seed);
    const random = prng.random();

    var buffer: [input_bytes_max]u8 = undefined;

    for (0..campaign.events_max) |_| {
        const length = random.uintAtMost(u32, input_bytes_max);
        const input = buffer[0..length];

        random.bytes(input);

        try round_trip_check(input);

        for (input) |*byte| {
            byte.* = escape_alphabet[random.uintLessThan(u32, escape_alphabet.len)];
        }

        try malformed_check(input);
    }
}

fn round_trip_check(input: []const u8) !void {
    assert(input.len <= input_bytes_max);

    var encoded_buffer: [input_bytes_max * 3]u8 = undefined;
    var encoded: std.Io.Writer = .fixed(&encoded_buffer);

    try oauth1.percent_encode(&encoded, input);

    for (encoded.buffered()) |byte| {
        assert(oauth1.unreserved(byte) or byte == '%' or std.ascii.isHex(byte));
    }

    var decoded_buffer: [input_bytes_max]u8 = undefined;
    var decoded: std.Io.Writer = .fixed(&decoded_buffer);

    try oauth1.form_decode(&decoded, encoded.buffered());

    assert(std.mem.eql(u8, input, decoded.buffered()));
}

fn malformed_check(input: []const u8) !void {
    assert(input.len <= input_bytes_max);
    assert(escape_alphabet.len > 0);

    var decoded_buffer: [input_bytes_max]u8 = undefined;
    var decoded: std.Io.Writer = .fixed(&decoded_buffer);

    try oauth1.form_decode(&decoded, input);

    assert(decoded.end <= input.len);
}

test "percent encoding round trips arbitrary bytes and decoding never grows" {
    try run(&.{ .events_max = 500, .seed = 0x5eed_0a41_7b1d_92c3 });
    try run(&.{ .events_max = 500, .seed = 0x5eed_0a41_7b1d_92c4 });
}
