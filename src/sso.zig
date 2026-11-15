const std = @import("std");

const html = @import("html.zig");
const oauth1 = @import("oauth1.zig");

const assert = std.debug.assert;

pub const code_bytes_max: u32 = 64;
pub const field_code = "mfa-code";
pub const field_csrf = "_csrf";
pub const field_count_max: u32 = 8;
pub const field_password = "password";
pub const field_username = "username";
pub const form_media_type = "application/x-www-form-urlencoded";
pub const service_root = "https://sso.garmin.com/sso";
pub const widget_root = service_root ++ "/embed";

pub const Credentials = struct {
    email: []const u8,
    password: []const u8,
};

pub const Field = struct {
    name: []const u8,
    value: []const u8,
};

pub const Outcome = union(enum) {
    challenged,
    granted: []const u8,
    refused,
};

const widget_fields = [_]Field{
    .{ .name = "embedWidget", .value = "true" },
    .{ .name = "gauthHost", .value = service_root },
    .{ .name = "id", .value = "gauth-widget" },
};

const signin_fields = [_]Field{
    .{ .name = "service", .value = widget_root },
    .{ .name = "source", .value = widget_root },
    .{ .name = "gauthHost", .value = widget_root },
    .{ .name = "redirectAfterAccountCreationUrl", .value = widget_root },
    .{ .name = "redirectAfterAccountLoginUrl", .value = widget_root },
    .{ .name = "embedWidget", .value = "true" },
    .{ .name = "id", .value = "gauth-widget" },
};

pub const signin_url = service_root ++ "/signin?" ++ query_of(&signin_fields);
pub const verify_url = service_root ++ "/verifyMFA/loginEnterMfaCode?" ++ query_of(&signin_fields);
pub const widget_url = widget_root ++ "?" ++ query_of(&widget_fields);

comptime {
    assert(signin_fields.len <= field_count_max);
    assert(widget_fields.len <= field_count_max);
}

pub fn form_write(writer: *std.Io.Writer, fields: []const Field) std.Io.Writer.Error!void {
    assert(fields.len > 0);
    assert(fields.len <= field_count_max);

    for (fields, 0..) |field, index| {
        assert(field.name.len > 0);

        if (index > 0) try writer.writeByte('&');

        try writer.writeAll(field.name);
        try writer.writeByte('=');
        try oauth1.percent_encode(writer, field.value);
    }
}

pub fn classify(document: []const u8) Outcome {
    assert(document.len <= std.math.maxInt(u32));
    assert(field_code.len > 0);

    const page: html.Document = .{ .source = document };

    if (page.service_ticket()) |ticket| {
        assert(ticket.len > 0);

        return .{ .granted = ticket };
    }

    if (page.field_present(field_code)) return .challenged;

    return .refused;
}

fn query_of(comptime fields: []const Field) []const u8 {
    comptime assert(fields.len > 0);
    comptime assert(fields.len <= field_count_max);

    comptime {
        var query: []const u8 = "";

        for (fields, 0..) |field, index| {
            if (index > 0) query = query ++ "&";

            query = query ++ field.name ++ "=" ++ field.value;
        }

        return query;
    }
}

test classify {
    const granted =
        \\<html><head><title>Anything At All</title></head><body>
        \\<script>response_url = "https://sso.garmin.com/sso/embed?ticket=ST-42-abc";</script>
        \\</body></html>
    ;

    switch (classify(granted)) {
        .granted => |ticket| try std.testing.expectEqualStrings("ST-42-abc", ticket),
        .challenged, .refused => return error.TestUnexpectedOutcome,
    }

    const challenged =
        \\<form action="/sso/verifyMFA/loginEnterMfaCode" method="post">
        \\  <input type="hidden" name="_csrf" value="csrf-value">
        \\  <input type="text" name="mfa-code" maxlength="6">
        \\</form>
    ;

    try std.testing.expectEqual(.challenged, std.meta.activeTag(classify(challenged)));

    const refused = "<html><body><p>Invalid username or password.</p></body></html>";

    try std.testing.expectEqual(.refused, std.meta.activeTag(classify(refused)));
}

test "a ticket wins over a lingering challenge form" {
    const document =
        \\<input name="mfa-code">
        \\<script>response_url = "https://sso.garmin.com/sso/embed?ticket=ST-7-zzz";</script>
    ;

    switch (classify(document)) {
        .granted => |ticket| try std.testing.expectEqualStrings("ST-7-zzz", ticket),
        .challenged, .refused => return error.TestUnexpectedOutcome,
    }
}

test "the sign-in URLs carry the parameters Garmin requires" {
    const required = [_][]const u8{
        "embedWidget=true",
        "gauthHost=",
        "id=gauth-widget",
        "service=",
        "source=",
        "redirectAfterAccountLoginUrl=",
        "redirectAfterAccountCreationUrl=",
    };

    for (required) |parameter| {
        try std.testing.expect(std.mem.find(u8, signin_url, parameter) != null);
    }

    try std.testing.expect(std.mem.startsWith(u8, signin_url, service_root));
    try std.testing.expect(std.mem.startsWith(u8, widget_url, widget_root));
    try std.testing.expect(std.mem.find(u8, verify_url, "loginEnterMfaCode") != null);
}

test form_write {
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    try form_write(&writer, &.{
        .{ .name = field_csrf, .value = "a+b" },
        .{ .name = field_username, .value = "athlete@example.com" },
        .{ .name = field_password, .value = "p&ss word" },
    });

    const expected = "_csrf=a%2Bb&username=athlete%40example.com&password=p%26ss%20word";

    try std.testing.expectEqualStrings(expected, writer.buffered());
}
