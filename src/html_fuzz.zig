const std = @import("std");

const fuzz = @import("testing/fuzz.zig");
const html = @import("html.zig");

const assert = std.debug.assert;

const alphabet = "<>=\"'/ \n\tnamevalue?ticket&-_";
const document_bytes_max: u32 = 512;

comptime {
    assert(alphabet.len > 0);
    assert(document_bytes_max > 0);
}

pub fn run(campaign: *const fuzz.Campaign) void {
    assert(campaign.events_max > 0);
    assert(campaign.events_max <= fuzz.events_max_limit);

    var prng = std.Random.DefaultPrng.init(campaign.seed);
    const random = prng.random();

    var buffer: [document_bytes_max]u8 = undefined;

    for (0..campaign.events_max) |_| {
        const length = random.uintAtMost(u32, document_bytes_max);
        const document = buffer[0..length];

        for (document) |*byte| {
            byte.* = alphabet[random.uintLessThan(u32, alphabet.len)];
        }

        const page: html.Document = .{ .source = document };

        if (page.field_value("name")) |value| subslice_check(page, value);
        if (page.field_present("value")) assert(std.mem.find(u8, document, "value") != null);

        if (page.service_ticket()) |ticket| {
            subslice_check(page, ticket);

            assert(ticket.len > 0);
        }
    }
}

fn subslice_check(page: html.Document, inner: []const u8) void {
    assert(page.source.len >= inner.len);

    const outer = page.source;
    const outer_address = @intFromPtr(outer.ptr);
    const inner_address = @intFromPtr(inner.ptr);

    assert(inner_address >= outer_address);
    assert(inner_address + inner.len <= outer_address + outer.len);
}

test "the html scanners survive arbitrary documents and return subslices" {
    run(&.{ .events_max = 2000, .seed = 0x7a3d_11d7_5eed_2a17 });
    run(&.{ .events_max = 128, .seed = 11 });
}
