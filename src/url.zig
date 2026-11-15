const std = @import("std");

const assert = std.debug.assert;

pub const bytes_max: u32 = 4096;

const port_digit_count_max: u32 = 5;

comptime {
    assert(bytes_max <= std.math.maxInt(u16));
    assert(port_digit_count_max == 5);
}

pub const URL = struct {
    host: []const u8,
    port: u16,
    scheme: Scheme,
    target: []const u8,

    pub const Error = error{URLInvalid};

    pub const Scheme = enum {
        http,
        https,
    };

    pub fn parse(text: []const u8) Error!URL {
        assert(bytes_max > 0);
        assert(port_digit_count_max == 5);

        if (text.len == 0) return error.URLInvalid;
        if (text.len > bytes_max) return error.URLInvalid;

        const scheme = scheme_of(text) orelse return error.URLInvalid;
        const rest = text[@tagName(scheme).len + "://".len ..];
        const slash = std.mem.findScalar(u8, rest, '/') orelse rest.len;
        const target = if (slash == rest.len) "/" else rest[slash..];

        for (target) |byte| {
            if (!target_byte_valid(byte)) return error.URLInvalid;
        }

        const authority = try Authority.parse(rest[0..slash], scheme);

        const result = URL{
            .host = authority.host,
            .port = authority.port,
            .scheme = scheme,
            .target = target,
        };

        assert(result.target[0] == '/');
        assert(result.host.len > 0);
        assert(result.port > 0);

        return result;
    }

    pub fn port_default(url: *const URL) bool {
        assert(url.host.len > 0);
        assert(url.target.len > 0);

        return switch (url.scheme) {
            .http => url.port == 80,
            .https => url.port == 443,
        };
    }

    pub fn origin_write(url: *const URL, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        assert(url.host.len > 0);
        assert(url.port > 0);

        try writer.print("{t}://{s}", .{ url.scheme, url.host });

        if (!url.port_default()) try writer.print(":{d}", .{url.port});
    }

    pub fn host_garmin(url: *const URL) bool {
        assert(url.host.len > 0);
        assert(url.host.len <= std.Io.net.HostName.max_len);

        if (std.ascii.eqlIgnoreCase(url.host, garmin_domain)) return true;
        if (url.host.len <= garmin_domain.len) return false;

        const suffix = url.host[url.host.len - garmin_domain.len ..];
        const dot = url.host[url.host.len - garmin_domain.len - 1];

        return dot == '.' and std.ascii.eqlIgnoreCase(suffix, garmin_domain);
    }

    pub fn host_same(url: *const URL, host: []const u8) bool {
        assert(url.host.len > 0);
        assert(host.len > 0);

        return std.ascii.eqlIgnoreCase(url.host, host);
    }
};

const garmin_domain = "garmin.com";

const Authority = struct {
    host: []const u8,
    port: u16,

    fn parse(text: []const u8, scheme: URL.Scheme) URL.Error!Authority {
        assert(text.len <= bytes_max);
        assert(@tagName(scheme).len > 0);

        const colon = std.mem.findScalarLast(u8, text, ':');
        const host = if (colon) |index| text[0..index] else text;

        if (host.len == 0) return error.URLInvalid;
        if (host.len > std.Io.net.HostName.max_len) return error.URLInvalid;

        for (host) |byte| {
            if (!host_byte_valid(byte)) return error.URLInvalid;
        }

        const port_scheme: u16 = switch (scheme) {
            .http => 80,
            .https => 443,
        };

        const index = colon orelse return .{ .host = host, .port = port_scheme };
        const port_text = text[index + 1 ..];

        if (port_text.len == 0) return error.URLInvalid;
        if (port_text.len > port_digit_count_max) return error.URLInvalid;

        for (port_text) |byte| {
            if (!std.ascii.isDigit(byte)) return error.URLInvalid;
        }

        const port = std.fmt.parseInt(u16, port_text, 10) catch return error.URLInvalid;
        if (port == 0) return error.URLInvalid;

        return .{ .host = host, .port = port };
    }
};

fn scheme_of(text: []const u8) ?URL.Scheme {
    assert(text.len > 0);
    assert(text.len <= bytes_max);

    if (std.mem.startsWith(u8, text, "https://")) return .https;
    if (std.mem.startsWith(u8, text, "http://")) return .http;

    return null;
}

fn host_byte_valid(byte: u8) bool {
    return switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '_' => true,
        else => false,
    };
}

fn target_byte_valid(byte: u8) bool {
    return switch (byte) {
        '!'...'"', '$'...'~' => true,
        else => false,
    };
}

test URL {
    const Case = struct {
        host: []const u8,
        port: u16,
        scheme: URL.Scheme,
        target: []const u8,
        text: []const u8,
    };

    const cases = [_]Case{
        .{
            .host = "connectapi.garmin.com",
            .port = 443,
            .scheme = .https,
            .target = "/activitylist-service/activities/count",
            .text = "https://connectapi.garmin.com/activitylist-service/activities/count",
        },
        .{
            .host = "127.0.0.1",
            .port = 8080,
            .scheme = .http,
            .target = "/sso/signin?service=x&id=y",
            .text = "http://127.0.0.1:8080/sso/signin?service=x&id=y",
        },
        .{
            .host = "sso.garmin.com",
            .port = 443,
            .scheme = .https,
            .target = "/",
            .text = "https://sso.garmin.com",
        },
    };

    for (cases) |case| {
        const url = try URL.parse(case.text);
        const port_default = case.port == 80 or case.port == 443;

        try std.testing.expectEqualStrings(case.host, url.host);
        try std.testing.expectEqualStrings(case.target, url.target);
        try std.testing.expectEqual(case.port, url.port);
        try std.testing.expectEqual(case.scheme, url.scheme);
        try std.testing.expectEqual(port_default, url.port_default());
    }
}

test "a URL refuses text it cannot send a request line for" {
    const texts = [_][]const u8{
        "",
        "connectapi.garmin.com/activities",
        "ftp://connectapi.garmin.com/",
        "https://",
        "https:///activities",
        "https://user@connectapi.garmin.com/",
        "https://connectapi.garmin.com:/",
        "https://connectapi.garmin.com:0/",
        "https://connectapi.garmin.com:65536/",
        "https://connectapi.garmin.com:123456/",
        "https://connectapi.garmin.com:80a/",
        "https://[::1]:8080/",
        "https://connectapi.garmin.com/a b",
        "https://connectapi.garmin.com/a\r\nHost: other",
        "https://connectapi.garmin.com/a#fragment",
        "https://connect api.garmin.com/",
    };

    for (texts) |text| {
        try std.testing.expectError(error.URLInvalid, URL.parse(text));
    }
}

test "the origin keeps a port only when it is not the scheme default" {
    const texts = [_][2][]const u8{
        .{ "https://sso.garmin.com/sso/signin", "https://sso.garmin.com" },
        .{ "http://127.0.0.1:8080/a", "http://127.0.0.1:8080" },
        .{ "http://example.com:80/a", "http://example.com" },
    };

    for (texts) |pair| {
        var buffer: [128]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);

        const url = try URL.parse(pair[0]);

        try url.origin_write(&writer);
        try std.testing.expectEqualStrings(pair[1], writer.buffered());
    }
}

test "a garmin host is garmin.com or one of its subdomains" {
    const garmin = [_][]const u8{
        "https://garmin.com/",
        "https://sso.garmin.com/sso",
        "https://connectapi.GARMIN.com/x",
    };

    const foreign = [_][]const u8{
        "https://example.com/",
        "https://notgarmin.com/",
        "https://garmin.com.evil.example/",
    };

    for (garmin) |text| try std.testing.expect((try URL.parse(text)).host_garmin());
    for (foreign) |text| try std.testing.expect(!(try URL.parse(text)).host_garmin());
}
