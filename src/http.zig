const std = @import("std");

const bounded = @import("bounded");
const url_module = @import("url.zig");

const assert = std.debug.assert;

const URL = url_module.URL;

pub const cookie_bytes_max: u32 = 4096;
pub const cookie_count_max: u32 = 64;

comptime {
    assert(cookie_bytes_max >= 4096);
    assert(cookie_count_max >= 50);
}

pub const CookieError = error{
    CookieTooLarge,
    CookiesExhausted,
};

pub const LocationError = error{LocationInvalid};

pub const Method = enum {
    delete,
    get,
    post,
    put,

    pub fn text(method: Method) []const u8 {
        return switch (method) {
            .delete => "DELETE",
            .get => "GET",
            .post => "POST",
            .put => "PUT",
        };
    }
};

pub const Cookie = struct {
    name_length: u32,
    pair: bounded.BufferType(cookie_bytes_max),

    pub fn name(cookie: *const Cookie) []const u8 {
        assert(cookie.name_length > 0);
        assert(cookie.name_length < cookie.pair.count());

        return cookie.pair.slice()[0..cookie.name_length];
    }
};

pub const CookieJar = struct {
    cookies: bounded.ArrayType(Cookie, cookie_count_max),

    pub const Pair = struct {
        name: []const u8,
        value: []const u8,
    };

    pub const empty: CookieJar = .{ .cookies = .empty };

    pub fn set_cookie(jar: *CookieJar, field: []const u8) CookieError!void {
        assert(jar.cookies.count <= cookie_count_max);
        assert(field.len <= std.math.maxInt(u32));

        const end = std.mem.findScalar(u8, field, ';') orelse field.len;
        const pair = std.mem.trim(u8, field[0..end], " \t");
        const equals = std.mem.findScalar(u8, pair, '=') orelse return;
        const name = std.mem.trim(u8, pair[0..equals], " \t");
        const value = std.mem.trim(u8, pair[equals + 1 ..], " \t");

        if (name.len == 0) return;

        try jar.set(.{ .name = name, .value = value });
    }

    pub fn set(jar: *CookieJar, pair: Pair) CookieError!void {
        assert(pair.name.len > 0);
        assert(jar.cookies.count <= cookie_count_max);

        if (pair.name.len + 1 + pair.value.len > cookie_bytes_max) return error.CookieTooLarge;

        const cookie = jar.find(pair.name) orelse found: {
            break :found jar.cookies.push_slot() catch return error.CookiesExhausted;
        };

        cookie.name_length = @intCast(pair.name.len);
        cookie.pair = .empty;
        cookie.pair.array.push_slice_assume_capacity(pair.name);
        cookie.pair.array.push_slice_assume_capacity("=");
        cookie.pair.array.push_slice_assume_capacity(pair.value);

        assert(std.mem.eql(u8, cookie.name(), pair.name));
        assert(cookie.pair.count() == pair.name.len + 1 + pair.value.len);
    }

    pub fn header_write(jar: *const CookieJar, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        assert(jar.cookies.count > 0);
        assert(jar.cookies.count <= cookie_count_max);

        try writer.writeAll("Cookie: ");

        for (jar.cookies.slice(), 0..) |*cookie, index| {
            if (index > 0) try writer.writeAll("; ");

            try writer.writeAll(cookie.pair.slice());
        }

        try writer.writeAll("\r\n");
    }

    fn find(jar: *CookieJar, name: []const u8) ?*Cookie {
        assert(name.len > 0);
        assert(jar.cookies.count <= cookie_count_max);

        for (jar.cookies.slice_mutable()) |*cookie| {
            if (std.mem.eql(u8, cookie.name(), name)) return cookie;
        }

        return null;
    }
};

pub fn location_resolve(
    writer: *std.Io.Writer,
    base: *const URL,
    location: []const u8,
) (LocationError || std.Io.Writer.Error)!void {
    assert(base.host.len > 0);
    assert(writer.end == 0);

    if (location.len == 0) return error.LocationInvalid;

    if (std.mem.startsWith(u8, location, "https://")) return writer.writeAll(location);
    if (std.mem.startsWith(u8, location, "http://")) return writer.writeAll(location);

    if (std.mem.startsWith(u8, location, "//")) {
        try writer.print("{t}:{s}", .{ base.scheme, location });

        return;
    }

    if (location[0] != '/') return error.LocationInvalid;

    try base.origin_write(writer);
    try writer.writeAll(location);
}

pub fn status_redirect(status: u16) bool {
    assert(status >= 100);
    assert(status <= 999);

    return switch (status) {
        301, 302, 303, 307, 308 => true,
        else => false,
    };
}

pub fn status_success(status: u16) bool {
    assert(status >= 100);
    assert(status <= 999);

    return status >= 200 and status < 300;
}

pub fn redirect_method(status: u16, method: Method) Method {
    assert(status_redirect(status));
    assert(method.text().len >= 3);

    return switch (status) {
        303 => .get,
        301, 302 => if (method == .post) .get else method,
        else => method,
    };
}

test CookieJar {
    var jar: CookieJar = .empty;

    try jar.set_cookie("session=one; Path=/; HttpOnly");
    try jar.set_cookie("theme=dark");
    try jar.set_cookie("session=two");
    try jar.set_cookie("=nameless");
    try jar.set_cookie("junk");

    var buffer: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    try jar.header_write(&writer);
    try std.testing.expectEqualStrings("Cookie: session=two; theme=dark\r\n", writer.buffered());
}

test "a cookie jar refuses a cookie past its count or its size" {
    var jar: CookieJar = .empty;
    var name_buffer: [32]u8 = undefined;

    for (0..cookie_count_max) |index| {
        const name = try std.mem.print(&name_buffer, "cookie{d}", .{index});

        try jar.set(.{ .name = name, .value = "value" });
    }

    const overflow = jar.set(.{ .name = "overflow", .value = "value" });

    try std.testing.expectError(error.CookiesExhausted, overflow);
    try jar.set(.{ .name = "cookie0", .value = "updated" });

    const value_oversized: [cookie_bytes_max]u8 = @splat('x');
    const oversized = jar.set(.{ .name = "cookie1", .value = &value_oversized });

    try std.testing.expectError(error.CookieTooLarge, oversized);
    try std.testing.expectEqualStrings("cookie0=updated", jar.cookies.get(0).pair.slice());
}

test location_resolve {
    const base = try URL.parse("https://sso.garmin.com/sso/signin?service=x");

    const cases = [_][2][]const u8{
        .{ "https://other.example/next", "https://other.example/next" },
        .{ "http://other.example/next", "http://other.example/next" },
        .{ "/sso/verify", "https://sso.garmin.com/sso/verify" },
        .{ "//connect.garmin.com/modern", "https://connect.garmin.com/modern" },
    };

    for (cases) |case| {
        var buffer: [128]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);

        try location_resolve(&writer, &base, case[0]);
        try std.testing.expectEqualStrings(case[1], writer.buffered());
    }

    var buffer: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    try std.testing.expectError(error.LocationInvalid, location_resolve(&writer, &base, "verify"));
    try std.testing.expectError(error.LocationInvalid, location_resolve(&writer, &base, ""));
}

test "a redirect status is one of the five redirect codes" {
    const redirects = [_]u16{ 301, 302, 303, 307, 308 };
    const others = [_]u16{ 200, 204, 300, 304, 400, 401, 404, 500 };

    for (redirects) |status| try std.testing.expect(status_redirect(status));
    for (others) |status| try std.testing.expect(!status_redirect(status));
}

test "a redirect rewrites to GET after 303 and after a POST answered with 301 or 302" {
    try std.testing.expectEqual(Method.get, redirect_method(303, .post));
    try std.testing.expectEqual(Method.get, redirect_method(303, .get));
    try std.testing.expectEqual(Method.get, redirect_method(301, .post));
    try std.testing.expectEqual(Method.get, redirect_method(302, .post));
    try std.testing.expectEqual(Method.put, redirect_method(302, .put));
    try std.testing.expectEqual(Method.post, redirect_method(307, .post));
    try std.testing.expectEqual(Method.post, redirect_method(308, .post));
}

test "a success status is in the two hundreds" {
    try std.testing.expect(status_success(200));
    try std.testing.expect(status_success(204));
    try std.testing.expect(!status_success(199));
    try std.testing.expect(!status_success(300));
    try std.testing.expect(!status_success(404));
}
