const std = @import("std");

const bounded = @import("bounded");

const assert = std.debug.assert;
const base64 = std.base64.standard;

const HmacSHA1 = std.crypto.auth.hmac.HmacSha1;

pub const consumer_key_default = "fc3e99d2-118c-44b8-8ae3-03370dde24c0";
pub const consumer_secret_default = "E08WAR897WEy2knn7aFBrvegVAf0AFdWBBF";
pub const credential_bytes_max: u32 = 256;
pub const nonce_bytes: u32 = 16;
pub const nonce_length: u32 = nonce_bytes * 2;
pub const parameter_count_max: u32 = 16;
pub const protocol_parameter_count: u32 = 6;
pub const scratch_bytes_max: u32 = 16 * 1024;
pub const signature_length: u32 = 28;
pub const timestamp_length_max: u32 = 20;
pub const token_bytes_max: u32 = 512;

comptime {
    assert(base64.Encoder.calcSize(HmacSHA1.mac_length) == signature_length);
    assert(consumer_key_default.len <= credential_bytes_max);
    assert(consumer_secret_default.len <= credential_bytes_max);
}

pub const CredentialError = error{CredentialTooLong};

pub const Error = error{
    ParametersExhausted,
    ScratchExhausted,
};

pub const ResponseError = error{
    ResponseInvalid,
    TokenTooLong,
};

pub const Credential = bounded.BufferType(credential_bytes_max);
pub const Text = bounded.BufferType(token_bytes_max);

pub const Consumer = struct {
    key: Credential,
    secret: Credential,

    pub const Options = struct {
        key: []const u8,
        secret: []const u8,
    };

    pub fn init(consumer: *Consumer, options: Options) CredentialError!void {
        assert(options.key.len > 0);
        assert(options.secret.len > 0);

        consumer.* = .{ .key = .empty, .secret = .empty };
        consumer.key.set(options.key) catch return error.CredentialTooLong;
        consumer.secret.set(options.secret) catch return error.CredentialTooLong;
    }
};

pub const Token = struct {
    identifier: Text,
    mfa: Text,
    secret: Text,

    pub const empty: Token = .{ .identifier = .empty, .mfa = .empty, .secret = .empty };
};

pub const Parameter = struct {
    name: []const u8,
    value: []const u8,
};

pub const Signing = struct {
    consumer: *const Consumer,
    method: []const u8,
    nonce: []const u8,
    timestamp: []const u8,
    token: []const u8,
    token_secret: []const u8,
    url: []const u8,
};

const Encoded = struct {
    name: []const u8,
    value: []const u8,

    fn less(_: void, left: Encoded, right: Encoded) bool {
        assert(left.name.len <= scratch_bytes_max);
        assert(right.name.len <= scratch_bytes_max);

        const order = std.mem.order(u8, left.name, right.name);
        if (order != .eq) return order == .lt;
        return std.mem.order(u8, left.value, right.value) == .lt;
    }
};

pub fn authorization_write(
    writer: *std.Io.Writer,
    signing: *const Signing,
    parameters: []const Parameter,
) (Error || std.Io.Writer.Error)!void {
    if (parameters.len > parameter_count_max - protocol_parameter_count) {
        return error.ParametersExhausted;
    }

    assert(signing.consumer.key.count() > 0);
    assert(signing.nonce.len > 0);
    assert(signing.timestamp.len > 0);

    var all: [parameter_count_max]Parameter = undefined;

    const all_count = try parameters_merge(&all, signing, parameters);

    var signature: [signature_length]u8 = undefined;

    try signature_compute(signing, all[0..all_count], &signature);

    const header_parameters = [_]Parameter{
        .{ .name = "oauth_consumer_key", .value = signing.consumer.key.slice() },
        .{ .name = "oauth_nonce", .value = signing.nonce },
        .{ .name = "oauth_signature", .value = &signature },
        .{ .name = "oauth_signature_method", .value = "HMAC-SHA1" },
        .{ .name = "oauth_timestamp", .value = signing.timestamp },
        .{ .name = "oauth_token", .value = signing.token },
        .{ .name = "oauth_version", .value = "1.0" },
    };

    try writer.writeAll("Authorization: OAuth ");

    var written: u32 = 0;

    for (header_parameters) |parameter| {
        if (parameter.value.len == 0) continue;
        if (written > 0) try writer.writeAll(", ");

        try parameter_write(writer, parameter);
        written += 1;
    }

    try writer.writeAll("\r\n");

    assert(written >= header_parameters.len - 1);
}

fn parameters_merge(
    all: *[parameter_count_max]Parameter,
    signing: *const Signing,
    parameters: []const Parameter,
) Error!u32 {
    if (parameters.len > parameter_count_max - protocol_parameter_count) {
        return error.ParametersExhausted;
    }

    assert(signing.nonce.len > 0);
    assert(signing.timestamp.len > 0);

    const protocol = [protocol_parameter_count]Parameter{
        .{ .name = "oauth_consumer_key", .value = signing.consumer.key.slice() },
        .{ .name = "oauth_nonce", .value = signing.nonce },
        .{ .name = "oauth_signature_method", .value = "HMAC-SHA1" },
        .{ .name = "oauth_timestamp", .value = signing.timestamp },
        .{ .name = "oauth_token", .value = signing.token },
        .{ .name = "oauth_version", .value = "1.0" },
    };

    var count: u32 = 0;

    for (protocol) |parameter| {
        if (parameter.value.len == 0) continue;

        all[count] = parameter;
        count += 1;
    }

    for (parameters) |parameter| {
        all[count] = parameter;
        count += 1;
    }

    assert(count <= parameter_count_max);

    return count;
}

pub fn signature_compute(
    signing: *const Signing,
    parameters: []const Parameter,
    signature: *[signature_length]u8,
) Error!void {
    assert(signing.consumer.secret.count() > 0);
    assert(parameters.len <= parameter_count_max);

    var base_buffer: [scratch_bytes_max]u8 = undefined;
    var base: std.Io.Writer = .fixed(&base_buffer);

    signature_base_write(&base, signing, parameters) catch |err| {
        return switch (err) {
            error.ParametersExhausted => error.ParametersExhausted,
            error.ScratchExhausted, error.WriteFailed => error.ScratchExhausted,
        };
    };

    var key_buffer: [credential_bytes_max * 3 + token_bytes_max * 3 + 1]u8 = undefined;
    var key: std.Io.Writer = .fixed(&key_buffer);

    percent_encode(&key, signing.consumer.secret.slice()) catch return error.ScratchExhausted;
    key.writeByte('&') catch return error.ScratchExhausted;
    percent_encode(&key, signing.token_secret) catch return error.ScratchExhausted;

    var mac: [HmacSHA1.mac_length]u8 = undefined;

    HmacSHA1.create(&mac, base.buffered(), key.buffered());

    const written = base64.Encoder.encode(signature, &mac);

    assert(written.len == signature_length);
}

pub fn signature_base_write(
    writer: *std.Io.Writer,
    signing: *const Signing,
    parameters: []const Parameter,
) (Error || std.Io.Writer.Error)!void {
    assert(signing.method.len > 0);
    assert(signing.url.len > 0);

    if (parameters.len > parameter_count_max) return error.ParametersExhausted;

    var scratch_buffer: [scratch_bytes_max]u8 = undefined;
    var scratch: std.Io.Writer = .fixed(&scratch_buffer);
    var encoded: [parameter_count_max]Encoded = undefined;

    for (parameters, 0..) |parameter, index| {
        encoded[index] = .{
            .name = encoded_slice(&scratch, parameter.name) catch return error.ScratchExhausted,
            .value = encoded_slice(&scratch, parameter.value) catch return error.ScratchExhausted,
        };
    }

    const sorted = encoded[0..parameters.len];

    std.mem.sort(Encoded, sorted, {}, Encoded.less);

    var joined_buffer: [scratch_bytes_max]u8 = undefined;
    var joined: std.Io.Writer = .fixed(&joined_buffer);

    for (sorted, 0..) |entry, index| {
        if (index > 0) joined.writeByte('&') catch return error.ScratchExhausted;

        joined.print("{s}={s}", .{ entry.name, entry.value }) catch return error.ScratchExhausted;
    }

    try writer.writeAll(signing.method);
    try writer.writeByte('&');
    try percent_encode(writer, signing.url);
    try writer.writeByte('&');
    try percent_encode(writer, joined.buffered());
}

fn encoded_slice(scratch: *std.Io.Writer, text: []const u8) std.Io.Writer.Error![]const u8 {
    assert(scratch.end <= scratch.buffer.len);
    assert(text.len <= scratch_bytes_max);

    const start = scratch.end;

    try percent_encode(scratch, text);

    return scratch.buffered()[start..];
}

fn parameter_write(writer: *std.Io.Writer, parameter: Parameter) std.Io.Writer.Error!void {
    assert(parameter.name.len > 0);
    assert(parameter.value.len > 0);

    try writer.writeAll(parameter.name);
    try writer.writeAll("=\"");
    try percent_encode(writer, parameter.value);
    try writer.writeByte('"');
}

pub fn token_parse(token: *Token, body: []const u8) ResponseError!void {
    assert(body.len <= std.math.maxInt(u32));
    assert(token_bytes_max > 0);

    token.* = .empty;

    var pairs = std.mem.splitScalar(u8, body, '&');

    for (0..body.len + 1) |_| {
        const pair = pairs.next() orelse break;
        const equals = std.mem.findScalar(u8, pair, '=') orelse continue;
        const target = token_field(token, pair[0..equals]) orelse continue;

        target.clear();

        var writer: std.Io.Writer = .fixed(target.array.slice_unused());

        form_decode(&writer, pair[equals + 1 ..]) catch return error.TokenTooLong;
        target.array.resize_assume_capacity(@intCast(writer.end));
    }

    if (token.identifier.count() == 0) return error.ResponseInvalid;
    if (token.secret.count() == 0) return error.ResponseInvalid;
}

fn token_field(token: *Token, name: []const u8) ?*Text {
    assert(name.len <= std.math.maxInt(u32));
    assert(token.identifier.count() <= token_bytes_max);

    if (std.mem.eql(u8, name, "oauth_token")) return &token.identifier;
    if (std.mem.eql(u8, name, "oauth_token_secret")) return &token.secret;
    if (std.mem.eql(u8, name, "mfa_token")) return &token.mfa;

    return null;
}

pub fn form_decode(writer: *std.Io.Writer, input: []const u8) std.Io.Writer.Error!void {
    assert(input.len <= std.math.maxInt(u32));
    assert(writer.end <= writer.buffer.len);

    var index: u32 = 0;

    for (0..input.len) |_| {
        if (index >= input.len) break;

        const byte = input[index];
        const escaped = escape_value(input[index..]);

        if (byte == '+') {
            try writer.writeByte(' ');
            index += 1;
        } else if (escaped) |value| {
            try writer.writeByte(value);
            index += 3;
        } else {
            try writer.writeByte(byte);
            index += 1;
        }
    }

    assert(index == input.len);
}

fn escape_value(text: []const u8) ?u8 {
    assert(text.len > 0);

    if (text[0] != '%') return null;
    if (text.len < 3) return null;

    const high = std.fmt.charToDigit(text[1], 16) catch return null;
    const low = std.fmt.charToDigit(text[2], 16) catch return null;
    const result = high * 16 + low;

    assert(result >> 4 == high);

    return result;
}

pub fn percent_encode(writer: *std.Io.Writer, input: []const u8) std.Io.Writer.Error!void {
    assert(input.len <= std.math.maxInt(u32));
    assert(writer.end <= writer.buffer.len);

    const hex = "0123456789ABCDEF";

    for (input) |byte| {
        if (unreserved(byte)) {
            try writer.writeByte(byte);
        } else {
            try writer.writeByte('%');
            try writer.writeByte(hex[byte >> 4]);
            try writer.writeByte(hex[byte & 0x0f]);
        }
    }
}

pub fn unreserved(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

pub fn nonce_generate(io: std.Io, nonce: *[nonce_length]u8) void {
    assert(nonce_length == nonce_bytes * 2);
    assert(nonce.len == nonce_length);

    const hex = "0123456789abcdef";

    var raw: [nonce_bytes]u8 = undefined;

    io.random(&raw);

    for (raw, 0..) |byte, index| {
        nonce[index * 2] = hex[byte >> 4];
        nonce[index * 2 + 1] = hex[byte & 0x0f];
    }
}

pub fn timestamp_write(io: std.Io, buffer: *[timestamp_length_max]u8) []const u8 {
    assert(buffer.len == timestamp_length_max);
    assert(timestamp_length_max >= 20);

    const seconds = std.Io.Clock.real.now(io).toSeconds();

    const result = std.mem.print(buffer, "{d}", .{seconds}) catch |err| switch (err) {
        error.NoSpaceLeft => unreachable,
    };

    assert(result.len > 0);

    return result;
}

fn consumer_test(options: Consumer.Options) CredentialError!Consumer {
    assert(options.key.len > 0);
    assert(options.secret.len > 0);

    var result: Consumer = undefined;

    try result.init(options);

    return result;
}

test signature_compute {
    const consumer_vector = try consumer_test(.{
        .key = "dpf43f3p2l4k3l03",
        .secret = "kd94hf93k423kf44",
    });

    const parameters = [_]Parameter{
        .{ .name = "file", .value = "vacation.jpg" },
        .{ .name = "size", .value = "original" },
        .{ .name = "oauth_consumer_key", .value = "dpf43f3p2l4k3l03" },
        .{ .name = "oauth_token", .value = "nnch734d00sl2jdk" },
        .{ .name = "oauth_signature_method", .value = "HMAC-SHA1" },
        .{ .name = "oauth_timestamp", .value = "1191242096" },
        .{ .name = "oauth_nonce", .value = "kllo9940pd9333jh" },
        .{ .name = "oauth_version", .value = "1.0" },
    };

    var signature: [signature_length]u8 = undefined;

    const signing: Signing = .{
        .consumer = &consumer_vector,
        .method = "GET",
        .nonce = "kllo9940pd9333jh",
        .timestamp = "1191242096",
        .token = "nnch734d00sl2jdk",
        .token_secret = "pfkkdhi9sl3r4s00",
        .url = "http://photos.example.net/photos",
    };

    try signature_compute(&signing, &parameters, &signature);

    try std.testing.expectEqualStrings("tR3+Ty81lMeYAr/Fid0kMTYa/WM=", &signature);
}

test signature_base_write {
    const parameters = [_]Parameter{
        .{ .name = "b5", .value = "=%3D" },
        .{ .name = "a3", .value = "a" },
        .{ .name = "c@", .value = "" },
        .{ .name = "a2", .value = "r b" },
        .{ .name = "oauth_consumer_key", .value = "9djdj82h48djs9d2" },
        .{ .name = "oauth_token", .value = "kkk9d7dh3k39sjv7" },
        .{ .name = "oauth_signature_method", .value = "HMAC-SHA1" },
        .{ .name = "oauth_timestamp", .value = "137131201" },
        .{ .name = "oauth_nonce", .value = "7d8f3e4a" },
        .{ .name = "c2", .value = "" },
        .{ .name = "a3", .value = "2 q" },
    };

    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    const consumer = try consumer_test(.{ .key = "9djdj82h48djs9d2", .secret = "unused" });

    const signing: Signing = .{
        .consumer = &consumer,
        .method = "POST",
        .nonce = "7d8f3e4a",
        .timestamp = "137131201",
        .token = "kkk9d7dh3k39sjv7",
        .token_secret = "",
        .url = "http://example.com/request",
    };

    try signature_base_write(&writer, &signing, &parameters);

    const expected = "POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q" ++
        "%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_" ++
        "key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m" ++
        "ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk" ++
        "9d7dh3k39sjv7";

    try std.testing.expectEqualStrings(expected, writer.buffered());
}

test "the preauthorized and exchange signatures match the recorded Garmin requests" {
    const consumer = try consumer_test(.{
        .key = consumer_key_default,
        .secret = consumer_secret_default,
    });

    const preauthorized = [_]Parameter{
        .{ .name = "login-url", .value = "https://mobile.integration.garmin.com/gcm/android" },
        .{ .name = "accepts-mfa-tokens", .value = "true" },
        .{ .name = "ticket", .value = "ST-0123-abcXYZ-cas" },
        .{ .name = "oauth_consumer_key", .value = consumer_key_default },
        .{ .name = "oauth_nonce", .value = "0123456789abcdef0123456789abcdef" },
        .{ .name = "oauth_signature_method", .value = "HMAC-SHA1" },
        .{ .name = "oauth_timestamp", .value = "1700000000" },
        .{ .name = "oauth_version", .value = "1.0" },
    };

    var signature: [signature_length]u8 = undefined;

    const signing_preauthorized: Signing = .{
        .consumer = &consumer,
        .method = "GET",
        .nonce = "0123456789abcdef0123456789abcdef",
        .timestamp = "1700000000",
        .token = "",
        .token_secret = "",
        .url = "https://connectapi.garmin.com/oauth-service/oauth/preauthorized",
    };

    try signature_compute(&signing_preauthorized, &preauthorized, &signature);

    try std.testing.expectEqualStrings("npjfRCOcKNSbw7+G+Y3OSQBKfXU=", &signature);

    const exchange = [_]Parameter{
        .{ .name = "oauth_consumer_key", .value = consumer_key_default },
        .{ .name = "oauth_nonce", .value = "abcdef0123456789abcdef0123456789" },
        .{ .name = "oauth_signature_method", .value = "HMAC-SHA1" },
        .{ .name = "oauth_timestamp", .value = "1700000001" },
        .{ .name = "oauth_token", .value = "b1b2c3d4-e5f6-7890-abcd-ef0123456789" },
        .{ .name = "oauth_version", .value = "1.0" },
    };

    const signing_exchange: Signing = .{
        .consumer = &consumer,
        .method = "POST",
        .nonce = "abcdef0123456789abcdef0123456789",
        .timestamp = "1700000001",
        .token = "b1b2c3d4-e5f6-7890-abcd-ef0123456789",
        .token_secret = "tokensecret-9f8e7d6c5b4a",
        .url = "https://connectapi.garmin.com/oauth-service/oauth/exchange/user/2.0",
    };

    try signature_compute(&signing_exchange, &exchange, &signature);

    try std.testing.expectEqualStrings("r4bFcuf2noDddQZtQxlMIHgcUOU=", &signature);
}

test "a signature base string double encodes the reserved characters of Garmin's parameters" {
    const consumer = try consumer_test(.{
        .key = consumer_key_default,
        .secret = consumer_secret_default,
    });

    const parameters = [_]Parameter{
        .{ .name = "login-url", .value = "https://mobile.integration.garmin.com/gcm/android" },
        .{ .name = "accepts-mfa-tokens", .value = "true" },
        .{ .name = "ticket", .value = "ST-0123-abcXYZ-cas" },
        .{ .name = "oauth_consumer_key", .value = consumer_key_default },
        .{ .name = "oauth_nonce", .value = "0123456789abcdef0123456789abcdef" },
        .{ .name = "oauth_signature_method", .value = "HMAC-SHA1" },
        .{ .name = "oauth_timestamp", .value = "1700000000" },
        .{ .name = "oauth_version", .value = "1.0" },
    };

    const signing: Signing = .{
        .consumer = &consumer,
        .method = "GET",
        .nonce = "0123456789abcdef0123456789abcdef",
        .timestamp = "1700000000",
        .token = "",
        .token_secret = "",
        .url = "https://connectapi.garmin.com/oauth-service/oauth/preauthorized",
    };

    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    try signature_base_write(&writer, &signing, &parameters);

    const expected =
        "GET&https%3A%2F%2Fconnectapi.garmin.com%2Foauth-service%2Foauth%2Fpreauthorized" ++
        "&accepts-mfa-tokens%3Dtrue" ++
        "%26login-url%3Dhttps%253A%252F%252Fmobile.integration.garmin.com%252Fgcm%252Fandroid" ++
        "%26oauth_consumer_key%3Dfc3e99d2-118c-44b8-8ae3-03370dde24c0" ++
        "%26oauth_nonce%3D0123456789abcdef0123456789abcdef" ++
        "%26oauth_signature_method%3DHMAC-SHA1" ++
        "%26oauth_timestamp%3D1700000000" ++
        "%26oauth_version%3D1.0" ++
        "%26ticket%3DST-0123-abcXYZ-cas";

    try std.testing.expectEqualStrings(expected, writer.buffered());
}

test "a signature base string refuses more parameters than it holds" {
    var parameters: [parameter_count_max + 1]Parameter = undefined;

    for (&parameters) |*parameter| parameter.* = .{ .name = "k", .value = "v" };

    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    const consumer = try consumer_test(.{ .key = "key", .secret = "secret" });

    const signing: Signing = .{
        .consumer = &consumer,
        .method = "GET",
        .nonce = "nonce",
        .timestamp = "1",
        .token = "",
        .token_secret = "",
        .url = "https://example.com/",
    };

    const result = signature_base_write(&writer, &signing, &parameters);

    try std.testing.expectError(error.ParametersExhausted, result);
}

test authorization_write {
    const consumer = try consumer_test(.{
        .key = consumer_key_default,
        .secret = consumer_secret_default,
    });

    const parameters = [_]Parameter{
        .{ .name = "ticket", .value = "ST-0123-abcXYZ-cas" },
        .{ .name = "login-url", .value = "https://mobile.integration.garmin.com/gcm/android" },
        .{ .name = "accepts-mfa-tokens", .value = "true" },
    };

    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    const signing: Signing = .{
        .consumer = &consumer,
        .method = "GET",
        .nonce = "0123456789abcdef0123456789abcdef",
        .timestamp = "1700000000",
        .token = "",
        .token_secret = "",
        .url = "https://connectapi.garmin.com/oauth-service/oauth/preauthorized",
    };

    try authorization_write(&writer, &signing, &parameters);

    const header = writer.buffered();
    const signature = "oauth_signature=\"npjfRCOcKNSbw7%2BG%2BY3OSQBKfXU%3D\"";

    try std.testing.expect(std.mem.startsWith(u8, header, "Authorization: OAuth "));
    try std.testing.expect(std.mem.endsWith(u8, header, "oauth_version=\"1.0\"\r\n"));
    try std.testing.expect(std.mem.find(u8, header, signature) != null);
    try std.testing.expect(std.mem.find(u8, header, "oauth_token=") == null);
}

test token_parse {
    var token: Token = undefined;

    try token_parse(&token, "oauth_token=abc%2Bdef&oauth_token_secret=s+e&mfa_token=m&x=y");
    try std.testing.expectEqualStrings("abc+def", token.identifier.slice());
    try std.testing.expectEqualStrings("s e", token.secret.slice());
    try std.testing.expectEqualStrings("m", token.mfa.slice());

    try std.testing.expectError(error.ResponseInvalid, token_parse(&token, "oauth_token=a"));
    try std.testing.expectError(error.ResponseInvalid, token_parse(&token, "oauth_token_secret=s"));

    const long: [token_bytes_max + 1]u8 = @splat('t');
    const body = "oauth_token=" ++ long ++ "&oauth_token_secret=s";

    try std.testing.expectError(error.TokenTooLong, token_parse(&token, body));
}

test form_decode {
    const cases = [_][2][]const u8{
        .{ "a%3Db", "a=b" },
        .{ "a+b", "a b" },
        .{ "%4", "%4" },
        .{ "%", "%" },
        .{ "%zz", "%zz" },
        .{ "%41%4a", "AJ" },
    };

    for (cases) |case| {
        var buffer: [16]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);

        try form_decode(&writer, case[0]);
        try std.testing.expectEqualStrings(case[1], writer.buffered());
    }
}

test percent_encode {
    var buffer: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    try percent_encode(&writer, "a b+c/~_-.\xff");
    try std.testing.expectEqualStrings("a%20b%2Bc%2F~_-.%FF", writer.buffered());
}

test nonce_generate {
    var first: [nonce_length]u8 = undefined;
    var second: [nonce_length]u8 = undefined;

    nonce_generate(std.testing.io, &first);
    nonce_generate(std.testing.io, &second);

    for (first) |byte| try std.testing.expect(std.ascii.isHex(byte));

    try std.testing.expect(!std.mem.eql(u8, &first, &second));
}
