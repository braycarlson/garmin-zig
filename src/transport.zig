const std = @import("std");

const url_module = @import("url.zig");

const assert = std.debug.assert;

const URL = url_module.URL;

pub const Fake = @import("transport/fake.zig").Fake;
pub const Native = @import("transport/native.zig").Native;

pub const Error = error{
    CertificatesUnavailable,
    ConnectFailed,
    WriteFailed,
};

pub const head_bytes_max: u32 = 32 * 1024;
pub const request_bytes_max: u32 = 64 * 1024;
pub const timeout_seconds: u32 = 120;

comptime {
    assert(head_bytes_max >= 8 * 1024);
    assert(request_bytes_max > head_bytes_max);
    assert(timeout_seconds > 0);
}

const Signature = struct {
    Function: type,
    name: []const u8,
};

pub fn check(comptime Transport: type) void {
    comptime assert(@typeInfo(Transport) == .@"struct");
    comptime assert(@hasDecl(Transport, "Options"));

    const signatures = [_]Signature{
        .{ .Function = fn (*const Transport) []const u8, .name = "cause" },
        .{ .Function = fn (*Transport, std.Io) void, .name = "close" },
        .{ .Function = fn (*Transport) void, .name = "deinit" },
        .{ .Function = fn (*Transport, std.Io, Transport.Options) Error!void, .name = "init" },
        .{
            .Function = fn (*Transport, std.Io, *const URL, []const u8) Error!*std.Io.Reader,
            .name = "send",
        },
    };

    inline for (signatures) |signature| {
        if (!@hasDecl(Transport, signature.name)) {
            @compileError("garmin: the transport " ++ @typeName(Transport) ++
                " declares no '" ++ signature.name ++ "'");
        }

        if (@TypeOf(@field(Transport, signature.name)) != signature.Function) {
            @compileError("garmin: the transport " ++ @typeName(Transport) ++
                " declares '" ++ signature.name ++ "' with the wrong signature");
        }
    }
}

comptime {
    check(Fake);
    check(Native);
}
