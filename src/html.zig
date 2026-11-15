const std = @import("std");

const assert = std.debug.assert;

pub const attributes_scanned_max: u32 = 64;
pub const tags_scanned_max: u32 = 8192;
pub const ticket_marker = "?ticket=";
pub const ticket_terminators = "\"'&\\ \t\r\n>";

pub const Document = struct {
    source: []const u8,

    pub fn field_value(document: Document, name: []const u8) ?[]const u8 {
        assert(name.len > 0);
        assert(document.source.len <= std.math.maxInt(u32));

        const tag = document.tag_named(name) orelse return null;

        assert(tag.source.len > 0);

        return tag.attribute("value");
    }

    pub fn field_present(document: Document, name: []const u8) bool {
        assert(name.len > 0);
        assert(document.source.len <= std.math.maxInt(u32));

        return document.tag_named(name) != null;
    }

    pub fn service_ticket(document: Document) ?[]const u8 {
        assert(document.source.len <= std.math.maxInt(u32));
        assert(ticket_marker.len > 0);

        const at = std.mem.find(u8, document.source, ticket_marker) orelse return null;
        const rest = document.source[at + ticket_marker.len ..];
        const end = std.mem.findAny(u8, rest, ticket_terminators) orelse rest.len;

        if (end == 0) return null;

        return rest[0..end];
    }

    fn tag_named(document: Document, name: []const u8) ?Tag {
        assert(name.len > 0);
        assert(document.source.len <= std.math.maxInt(u32));

        const source = document.source;

        var cursor: u32 = 0;

        for (0..tags_scanned_max) |_| {
            const opened = std.mem.findScalarPos(u8, source, cursor, '<') orelse return null;
            const closed = std.mem.findScalarPos(u8, source, opened, '>') orelse return null;

            assert(closed > opened);

            const tag: Tag = .{ .source = source[opened + 1 .. closed] };

            cursor = @intCast(closed + 1);

            const candidate = tag.attribute("name") orelse continue;

            if (std.mem.eql(u8, candidate, name)) return tag;
        }

        return null;
    }
};

const Tag = struct {
    source: []const u8,

    fn attribute(tag: Tag, key: []const u8) ?[]const u8 {
        assert(key.len > 0);
        assert(tag.source.len <= std.math.maxInt(u32));

        const source = tag.source;

        var cursor: u32 = 0;

        for (0..attributes_scanned_max) |_| {
            const at = std.mem.findPos(u8, source, cursor, key) orelse return null;
            const after = at + key.len;

            cursor = @intCast(after);

            if (at > 0) {
                if (!boundary(source[at - 1])) continue;
            }

            if (after == source.len) return null;
            if (source[after] != '=') continue;

            const opened = after + 1;

            if (opened == source.len) return null;
            if (!quote(source[opened])) continue;

            const rest = source[opened + 1 ..];
            const closed = std.mem.findScalar(u8, rest, source[opened]) orelse return null;

            return rest[0..closed];
        }

        return null;
    }
};

fn boundary(byte: u8) bool {
    return switch (byte) {
        ' ', '\t', '\r', '\n', '/' => true,
        else => false,
    };
}

fn quote(byte: u8) bool {
    return switch (byte) {
        '"', '\'' => true,
        else => false,
    };
}

test "a field value is read regardless of attribute order and quoting" {
    const sources = [_][]const u8{
        "<form>\n  <input type=\"hidden\" name=\"_csrf\" value=\"ABC123-def456_GHI\" />\n</form>",
        "<form>\n  <input value=\"ABC123-def456_GHI\" name=\"_csrf\" type=\"hidden\">\n</form>",
        "<input name='_csrf' value='ABC123-def456_GHI'>",
    };

    for (sources) |source| {
        const document: Document = .{ .source = source };
        const value = document.field_value("_csrf") orelse return error.TestValueMissing;

        try std.testing.expectEqualStrings("ABC123-def456_GHI", value);
    }
}

test "a field value matches neither an attribute suffix nor a neighbouring tag" {
    const suffix: Document = .{
        .source = "<input data-name=\"_csrf\" value=\"decoy\">\n" ++
            "<input name=\"real\" value=\"kept\">",
    };

    const neighbour: Document = .{
        .source = "<input name=\"_csrf\">\n<input name=\"other\" value=\"not-the-csrf\">",
    };

    const bracket: Document = .{ .source = "<input name=\"a\" value=\"x < y\">" };

    try std.testing.expect(suffix.field_value("_csrf") == null);
    try std.testing.expectEqualStrings("kept", suffix.field_value("real") orelse "");
    try std.testing.expect(neighbour.field_value("_csrf") == null);
    try std.testing.expectEqualStrings("x < y", bracket.field_value("a") orelse "");
}

test "a valueless field is present" {
    const document: Document = .{
        .source = "<input type=\"text\" name=\"mfa-code\" maxlength=\"6\">",
    };

    try std.testing.expect(document.field_present("mfa-code"));
    try std.testing.expect(!document.field_present("_csrf"));
}

test "a service ticket is read out of the redirect URL up to its terminator" {
    const script: Document = .{
        .source = "<script>\n  response_url = " ++
            "\"https://sso.garmin.com/sso/embed?ticket=ST-0123456-abcXYZdef-cas\";\n</script>",
    };

    const query: Document = .{
        .source = "location = 'https://sso.garmin.com/sso/embed?ticket=ST-9-xyz&next=1';",
    };

    const ticket = "ST-0123456-abcXYZdef-cas";

    try std.testing.expectEqualStrings(ticket, script.service_ticket() orelse "");
    try std.testing.expectEqualStrings("ST-9-xyz", query.service_ticket() orelse "");
}

test "the extractors report absence with null" {
    const form: Document = .{ .source = "<form></form>" };
    const plain: Document = .{ .source = "no ticket here" };
    const empty: Document = .{ .source = "?ticket=" };

    try std.testing.expect(form.field_value("_csrf") == null);
    try std.testing.expect(plain.service_ticket() == null);
    try std.testing.expect(empty.service_ticket() == null);
}
