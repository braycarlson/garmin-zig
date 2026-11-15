const std = @import("std");

const bounded = @import("bounded");
const html = @import("html.zig");
const http = @import("http.zig");
const json = @import("json");
const oauth1 = @import("oauth1.zig");
const oauth2 = @import("oauth2.zig");
const sso = @import("sso.zig");
const tokens = @import("tokens.zig");
const transport = @import("transport.zig");
const url_module = @import("url.zig");

const assert = std.debug.assert;

const Method = http.Method;
const URL = url_module.URL;

pub const body_bytes_max: u32 = 8 * 1024 * 1024;
pub const connect_url = "https://connectapi.garmin.com";
pub const csrf_bytes_max: u32 = 256;
pub const display_name_bytes_max: u32 = 256;
pub const form_bytes_max: u32 = 4 * 1024;
pub const payload_bytes_max: u32 = 16 * 1024;
pub const redirect_count_max: u32 = 5;
pub const region_bytes_max: u32 = tokens.region_bytes_max;
pub const retry_count_max: u32 = 2;
pub const retry_delay_ms_default: u32 = 250;
pub const retry_delay_ms_max: u32 = 60 * 1000;
pub const user_agent_android = "com.garmin.android.apps.connectmobile";

pub const user_agent_browser = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " ++
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

const authorization_bytes_max: u32 = oauth2.token_bytes_max + 64;
const exchange_url = connect_url ++ "/oauth-service/oauth/exchange/user/2.0";
const preauthorized_url = connect_url ++ "/oauth-service/oauth/preauthorized";
const profile_target = "/userprofile-service/socialProfile";
const transfer_bytes: u32 = 64 * 1024;

comptime {
    assert(payload_bytes_max + transport.head_bytes_max <= transport.request_bytes_max);
    assert(form_bytes_max <= payload_bytes_max);
    assert(region_bytes_max >= 2 * tokens.file_bytes_max);
    assert(body_bytes_max <= json.limits.input_bytes_max);
}

pub const CapacityError = error{
    CookieTooLarge,
    CookiesExhausted,
    CredentialTooLong,
    DisplayNameTooLong,
    HeadTooLarge,
    PayloadTooLarge,
    RequestTooLarge,
    ResponseTooLarge,
    TokenTooLong,
};

pub const ServiceError = error{
    BadRequest,
    CodeRefused,
    Conflict,
    Forbidden,
    LoginRefused,
    NotFound,
    RedirectsExhausted,
    ResponseInvalid,
    ServerError,
    StatusUnexpected,
    TooManyRequests,
    Unauthorized,
    Unavailable,
};

pub const SettingsError = error{
    ArgumentInvalid,
    CodeInvalid,
    CredentialsInvalid,
    TokensInvalid,
    TokensVersionUnknown,
};

pub const TransportError = error{
    CertificatesUnavailable,
    ConnectFailed,
    ReadFailed,
    WriteFailed,
};

pub const Error = CapacityError || ServiceError || SettingsError || TransportError;

pub const Credentials = sso.Credentials;

pub const Diagnostic = struct {
    body: []const u8,
    cause: []const u8,
    status: u16,

    pub const empty: Diagnostic = .{ .body = "", .cause = "", .status = 0 };
};

pub const FetchOptions = struct {
    method: Method,
    payload: []const u8,
    target: []const u8,
};

pub const Login = enum {
    authorized,
    challenged,
};

const Phase = enum {
    anonymous,
    authorized,
    challenged,
};

const Page = struct {
    referer: []const u8,
    url: []const u8,
};

const Redirect = enum {
    followed,
    returned,
};

const UserAgent = enum {
    android,
    browser,

    fn text(user_agent: UserAgent) []const u8 {
        return switch (user_agent) {
            .android => user_agent_android,
            .browser => user_agent_browser,
        };
    }
};

const Exchange = struct {
    authorization: []const u8,
    content_type: []const u8,
    method: Method,
    payload: []const u8,
    redirect: Redirect,
    referer: []const u8,
    retry_count: u32,
    user_agent: UserAgent,
};

pub fn ClientType(comptime Transport: type) type {
    comptime transport.check(Transport);

    return struct {
        authorization: bounded.BufferType(authorization_bytes_max),
        body: [body_bytes_max]u8,
        consumer: oauth1.Consumer,
        csrf: bounded.BufferType(csrf_bytes_max),
        diagnostic: Diagnostic,
        display_name_text: bounded.BufferType(display_name_bytes_max),
        io: std.Io,
        jar: http.CookieJar,
        location: bounded.BufferType(url_module.bytes_max),
        oauth1_token: oauth1.Token,
        oauth2_token: oauth2.Token,
        payload_buffer: [payload_bytes_max]u8,
        phase: Phase,
        region_buffer: [region_bytes_max]u8,
        request_buffer: [transport.request_bytes_max]u8,
        retry_delay_ms: u32,
        target: bounded.BufferType(url_module.bytes_max),
        tokens_changed: bool,
        transfer: [transfer_bytes]u8,
        transport: Transport,
        url: bounded.BufferType(url_module.bytes_max),

        const Client = @This();

        pub const Options = struct {
            consumer_key: []const u8 = oauth1.consumer_key_default,
            consumer_secret: []const u8 = oauth1.consumer_secret_default,
            retry_delay_ms: u32 = retry_delay_ms_default,
            transport: Transport.Options,
        };

        pub fn init(client: *Client, io: std.Io, options: Options) Error!void {
            assert(options.consumer_key.len > 0);
            assert(options.consumer_secret.len > 0);

            client.authorization = .empty;
            client.consumer = .{ .key = .empty, .secret = .empty };
            client.csrf = .empty;
            client.diagnostic = .empty;
            client.display_name_text = .empty;
            client.io = io;
            client.jar = .empty;
            client.location = .empty;
            client.oauth1_token = .empty;

            client.oauth2_token = .{
                .access_token = .empty,
                .lifetime_seconds = 0,
                .obtained_at = 0,
                .refresh_lifetime_seconds = 0,
                .refresh_token = .empty,
            };

            client.phase = .anonymous;
            client.retry_delay_ms = options.retry_delay_ms;
            client.target = .empty;
            client.tokens_changed = false;
            client.url = .empty;

            if (options.retry_delay_ms > retry_delay_ms_max) return error.ArgumentInvalid;

            try client.consumer.init(.{
                .key = options.consumer_key,
                .secret = options.consumer_secret,
            });

            client.transport.init(io, options.transport) catch |err| {
                client.diagnostic.cause = client.transport.cause();

                return err;
            };
        }

        pub fn deinit(client: *Client) void {
            if (client.phase == .challenged) assert(client.csrf.count() > 0);
            if (client.phase == .authorized) assert(client.display_name_text.count() > 0);

            client.transport.deinit();
            client.phase = .anonymous;
        }

        pub fn login(client: *Client, credentials: *const Credentials) Error!Login {
            assert(client.phase == .anonymous);
            assert(client.jar.cookies.count <= http.cookie_count_max);

            if (credentials.email.len == 0) return error.CredentialsInvalid;
            if (credentials.password.len == 0) return error.CredentialsInvalid;

            client.jar = .empty;

            _ = try client.page_open(&.{ .referer = "", .url = sso.widget_url });

            const signin = try client.page_open(&.{
                .referer = sso.widget_root,
                .url = sso.signin_url,
            });

            const signin_page: html.Document = .{ .source = signin };

            const csrf = signin_page.field_value(sso.field_csrf) orelse {
                return client.response_invalid("CsrfMissing");
            };

            const submitted = try client.form_post(sso.signin_url, &.{
                .{ .name = sso.field_csrf, .value = csrf },
                .{ .name = "embed", .value = "true" },
                .{ .name = sso.field_username, .value = credentials.email },
                .{ .name = sso.field_password, .value = credentials.password },
            });

            return client.outcome_accept(sso.classify(submitted));
        }

        pub fn login_verify(client: *Client, code: []const u8) Error!void {
            if (code.len == 0) return error.CodeInvalid;

            assert(client.phase == .challenged);
            assert(client.csrf.count() > 0);

            const trimmed = std.mem.trim(u8, code, " \t\r\n");

            if (trimmed.len == 0) return error.CodeInvalid;
            if (trimmed.len > sso.code_bytes_max) return error.CodeInvalid;

            const verified = try client.form_post(sso.verify_url, &.{
                .{ .name = sso.field_csrf, .value = client.csrf.slice() },
                .{ .name = "fromPage", .value = "setupEnterMfaCode" },
                .{ .name = "embed", .value = "true" },
                .{ .name = sso.field_code, .value = trimmed },
            });

            switch (sso.classify(verified)) {
                .challenged => return error.CodeRefused,
                .granted => |ticket| try client.tokens_obtain(ticket),
                .refused => return error.LoginRefused,
            }

            assert(client.phase == .authorized);
        }

        pub fn restore(client: *Client, source: []const u8) Error!void {
            assert(client.phase == .anonymous);
            assert(source.len <= std.math.maxInt(u32));

            if (source.len > tokens.file_bytes_max) return error.TokensInvalid;

            var region: json.Region = .init(&client.region_buffer);
            var file: tokens.File = undefined;

            try tokens.parse(&region, source, &file);
            try client.consumer.init(.{ .key = file.consumer.key, .secret = file.consumer.secret });

            const oauth1_token = &client.oauth1_token;
            const oauth2_token = &client.oauth2_token;

            oauth1_token.* = .empty;
            oauth1_token.identifier.set(file.oauth1.token) catch return error.TokenTooLong;
            oauth1_token.secret.set(file.oauth1.secret) catch return error.TokenTooLong;
            oauth1_token.mfa.set(file.oauth1.mfa orelse "") catch return error.TokenTooLong;
            oauth2_token.access_token.set(file.oauth2.access) catch return error.TokenTooLong;
            oauth2_token.refresh_token.set(file.oauth2.refresh) catch return error.TokenTooLong;
            oauth2_token.obtained_at = file.oauth2.obtained_at;
            oauth2_token.lifetime_seconds = file.oauth2.lifetime_seconds;
            oauth2_token.refresh_lifetime_seconds = file.oauth2.refresh_lifetime_seconds;

            client.display_name_text.set(file.profile.display_name) catch {
                return error.DisplayNameTooLong;
            };

            client.phase = .authorized;
            client.tokens_changed = false;

            if (!oauth2_token.expired(client.now())) return;

            client.oauth2_exchange() catch |err| {
                client.phase = .anonymous;

                return err;
            };
        }

        pub fn save(client: *Client, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            assert(client.phase == .authorized);
            assert(client.display_name_text.count() > 0);

            try tokens.write(writer, &.{
                .consumer = &client.consumer,
                .display_name = client.display_name_text.slice(),
                .oauth1 = &client.oauth1_token,
                .oauth2 = &client.oauth2_token,
            });

            client.tokens_changed = false;
        }

        pub fn display_name(client: *const Client) []const u8 {
            assert(client.phase == .authorized);
            assert(client.display_name_text.count() > 0);

            return client.display_name_text.slice();
        }

        pub fn fetch(client: *Client, options: *const FetchOptions) Error![]const u8 {
            assert(client.phase == .authorized);
            assert(client.oauth2_token.access_token.count() > 0);

            if (options.target.len == 0) return error.ArgumentInvalid;
            if (options.target[0] != '/') return error.ArgumentInvalid;
            if (options.payload.len > payload_bytes_max) return error.PayloadTooLarge;

            const body = client.fetch_once(options) catch |err| switch (err) {
                error.Unauthorized => retry: {
                    try client.oauth2_exchange();

                    break :retry try client.fetch_once(options);
                },
                else => return err,
            };

            assert(body.len <= body_bytes_max);

            return body;
        }

        fn fetch_once(client: *Client, options: *const FetchOptions) Error![]const u8 {
            assert(client.phase == .authorized);
            assert(options.target[0] == '/');

            client.url = .empty;
            client.url.array.push_slice_assume_capacity(connect_url);
            client.url.push(options.target) catch return error.RequestTooLarge;
            client.authorization = .empty;

            var writer: std.Io.Writer = .fixed(client.authorization.array.slice_unused());

            client.oauth2_token.authorization_write(&writer) catch return error.RequestTooLarge;
            client.authorization.array.resize_assume_capacity(@intCast(writer.end));

            const content_type = if (options.payload.len > 0) "application/json" else "";
            const retry_count = if (options.method == .get) retry_count_max else 0;

            return client.send(&.{
                .authorization = client.authorization.slice(),
                .content_type = content_type,
                .method = options.method,
                .payload = options.payload,
                .redirect = if (options.method == .get) .followed else .returned,
                .referer = "",
                .retry_count = retry_count,
                .user_agent = .android,
            });
        }

        fn page_open(client: *Client, page: *const Page) Error![]const u8 {
            assert(page.url.len > 0);
            assert(page.url.len <= url_module.bytes_max);

            client.url = .empty;
            client.url.push(page.url) catch return error.RequestTooLarge;

            return client.send(&.{
                .authorization = "",
                .content_type = "",
                .method = .get,
                .payload = "",
                .redirect = .followed,
                .referer = page.referer,
                .retry_count = retry_count_max,
                .user_agent = .browser,
            });
        }

        fn form_post(client: *Client, url: []const u8, fields: []const sso.Field) Error![]const u8 {
            assert(url.len > 0);
            assert(fields.len > 0);

            var form_buffer: [form_bytes_max]u8 = undefined;
            var form: std.Io.Writer = .fixed(&form_buffer);

            sso.form_write(&form, fields) catch return error.PayloadTooLarge;

            client.url = .empty;
            client.url.push(url) catch return error.RequestTooLarge;

            return client.send(&.{
                .authorization = "",
                .content_type = sso.form_media_type,
                .method = .post,
                .payload = form.buffered(),
                .redirect = .followed,
                .referer = sso.signin_url,
                .retry_count = 0,
                .user_agent = .browser,
            });
        }

        fn outcome_accept(client: *Client, outcome: sso.Outcome) Error!Login {
            assert(client.phase == .anonymous);
            assert(client.diagnostic.status != 0);

            switch (outcome) {
                .challenged => {
                    const page: html.Document = .{ .source = client.diagnostic.body };

                    const csrf = page.field_value(sso.field_csrf) orelse {
                        return client.response_invalid("CsrfMissing");
                    };

                    client.csrf.set(csrf) catch return client.response_invalid("CsrfTooLong");
                    client.phase = .challenged;

                    return .challenged;
                },
                .granted => |ticket| {
                    try client.tokens_obtain(ticket);

                    return .authorized;
                },
                .refused => return error.LoginRefused,
            }
        }

        fn tokens_obtain(client: *Client, ticket: []const u8) Error!void {
            assert(ticket.len > 0);
            assert(client.phase != .authorized);

            try client.oauth1_obtain(ticket);
            try client.oauth2_exchange();

            client.phase = .authorized;
            client.csrf = .empty;

            const options: FetchOptions = .{
                .method = .get,
                .payload = "",
                .target = profile_target,
            };

            const body = client.fetch(&options) catch |err| {
                client.phase = .anonymous;

                return err;
            };

            client.display_name_decode(body) catch |err| {
                client.phase = .anonymous;

                return err;
            };
        }

        fn oauth1_obtain(client: *Client, ticket: []const u8) Error!void {
            assert(ticket.len > 0);
            assert(client.consumer.key.count() > 0);

            const parameters = [_]oauth1.Parameter{
                .{ .name = "accepts-mfa-tokens", .value = "true" },
                .{ .name = "login-url", .value = sso.widget_root },
                .{ .name = "ticket", .value = ticket },
            };

            client.url = .empty;

            var url: std.Io.Writer = .fixed(client.url.array.slice_unused());

            query_write(&url, preauthorized_url, &parameters) catch return error.RequestTooLarge;
            client.url.array.resize_assume_capacity(@intCast(url.end));

            try client.oauth1_authorize(.get, preauthorized_url, &parameters);

            const body = try client.send(&.{
                .authorization = client.authorization.slice(),
                .content_type = "",
                .method = .get,
                .payload = "",
                .redirect = .returned,
                .referer = "",
                .retry_count = 0,
                .user_agent = .android,
            });

            oauth1.token_parse(&client.oauth1_token, body) catch |err| switch (err) {
                error.ResponseInvalid => return client.response_invalid("OAuth1TokenMissing"),
                error.TokenTooLong => return error.TokenTooLong,
            };
        }

        fn oauth2_exchange(client: *Client) Error!void {
            assert(client.oauth1_token.identifier.count() > 0);
            assert(client.oauth1_token.secret.count() > 0);

            const mfa_token = client.oauth1_token.mfa.slice();
            const parameter = oauth1.Parameter{ .name = "mfa_token", .value = mfa_token };
            const parameters_all = [_]oauth1.Parameter{parameter};
            const parameters = if (mfa_token.len > 0) parameters_all[0..] else parameters_all[0..0];

            var form_buffer: [form_bytes_max]u8 = undefined;
            var form: std.Io.Writer = .fixed(&form_buffer);

            if (mfa_token.len > 0) {
                form.writeAll("mfa_token=") catch return error.PayloadTooLarge;
                oauth1.percent_encode(&form, mfa_token) catch return error.PayloadTooLarge;
            }

            client.url = .empty;
            client.url.array.push_slice_assume_capacity(exchange_url);

            try client.oauth1_authorize(.post, exchange_url, parameters);

            const body = try client.send(&.{
                .authorization = client.authorization.slice(),
                .content_type = sso.form_media_type,
                .method = .post,
                .payload = form.buffered(),
                .redirect = .returned,
                .referer = "",
                .retry_count = 0,
                .user_agent = .android,
            });

            try client.oauth2_accept(body);
        }

        fn oauth2_accept(client: *Client, body: []const u8) Error!void {
            assert(body.len <= body_bytes_max);
            assert(client.diagnostic.status != 0);

            var region: json.Region = .init(&client.region_buffer);

            oauth2.token_parse(&client.oauth2_token, &region, body, client.now()) catch |err| {
                return switch (err) {
                    error.TokenTooLong => error.TokenTooLong,
                    else => client.response_invalid(@errorName(err)),
                };
            };

            client.tokens_changed = true;
        }

        fn oauth1_authorize(
            client: *Client,
            method: Method,
            url: []const u8,
            parameters: []const oauth1.Parameter,
        ) Error!void {
            assert(url.len > 0);
            assert(parameters.len < oauth1.parameter_count_max);

            var nonce: [oauth1.nonce_length]u8 = undefined;
            var timestamp_buffer: [oauth1.timestamp_length_max]u8 = undefined;

            oauth1.nonce_generate(client.io, &nonce);

            client.authorization = .empty;

            var writer: std.Io.Writer = .fixed(client.authorization.array.slice_unused());

            const signing: oauth1.Signing = .{
                .consumer = &client.consumer,
                .method = method.text(),
                .nonce = &nonce,
                .timestamp = oauth1.timestamp_write(client.io, &timestamp_buffer),
                .token = client.oauth1_token.identifier.slice(),
                .token_secret = client.oauth1_token.secret.slice(),
                .url = url,
            };

            oauth1.authorization_write(&writer, &signing, parameters) catch {
                return error.RequestTooLarge;
            };

            client.authorization.array.resize_assume_capacity(@intCast(writer.end));
        }

        fn display_name_decode(client: *Client, body: []const u8) Error!void {
            assert(body.len <= body_bytes_max);
            assert(client.phase == .authorized);

            const Profile = struct {
                display_name: []const u8,

                pub const json = .{ .display_name = "displayName" };
            };

            var region: json.Region = .init(&client.region_buffer);
            var profile: Profile = undefined;

            json.decode(Profile, &region, body, &profile, .{
                .diagnostic = null,
                .unknown_members = .ignored,
            }) catch |err| return client.response_invalid(@errorName(err));

            if (profile.display_name.len == 0) return client.response_invalid("DisplayNameEmpty");

            client.display_name_text.set(profile.display_name) catch {
                return error.DisplayNameTooLong;
            };
        }

        fn send(client: *Client, exchange: *const Exchange) Error![]const u8 {
            assert(client.url.count() > 0);
            assert(exchange.retry_count <= retry_count_max);

            var hop = exchange.*;

            for (0..redirect_count_max + 1) |_| {
                const status = try client.attempt(&hop);

                if (http.status_success(status)) return client.diagnostic.body;
                if (!http.status_redirect(status)) return status_error(status);
                if (exchange.redirect == .returned) return error.StatusUnexpected;

                try client.redirect_follow(&hop, status);
            }

            return error.RedirectsExhausted;
        }

        fn redirect_follow(client: *Client, hop: *Exchange, status: u16) Error!void {
            assert(http.status_redirect(status));
            assert(client.location.count() > 0);

            const before = URL.parse(client.url.slice()) catch return error.ArgumentInvalid;

            const after = URL.parse(client.location.slice()) catch {
                return client.response_invalid("LocationInvalid");
            };

            if (!before.host_same(after.host)) {
                hop.authorization = "";
                hop.referer = "";
            }

            const method = http.redirect_method(status, hop.method);

            if (method != hop.method) {
                hop.content_type = "";
                hop.payload = "";
                hop.method = method;
            }

            client.url.set(client.location.slice()) catch return error.RequestTooLarge;
        }

        fn attempt(client: *Client, hop: *const Exchange) Error!u16 {
            assert(client.url.count() > 0);
            assert(hop.retry_count <= retry_count_max);

            const url = URL.parse(client.url.slice()) catch return error.ArgumentInvalid;
            const request = try client.request_write(&url, hop);

            for (0..hop.retry_count + 1) |index| {
                if (index > 0) client.sleep_retry();

                const status = client.exchange_once(&url, request) catch |err| switch (err) {
                    error.ConnectFailed, error.ReadFailed, error.WriteFailed => {
                        if (index == hop.retry_count) return err;

                        continue;
                    },
                    else => return err,
                };

                return status;
            }

            unreachable;
        }

        fn sleep_retry(client: *Client) void {
            assert(client.retry_delay_ms <= retry_delay_ms_max);
            assert(client.url.count() > 0);

            if (client.retry_delay_ms == 0) return;

            const delay = std.Io.Duration.fromMilliseconds(client.retry_delay_ms);

            std.Io.sleep(client.io, delay, .awake) catch |err| switch (err) {
                error.Canceled => {},
            };
        }

        fn request_write(client: *Client, url: *const URL, hop: *const Exchange) Error![]const u8 {
            assert(url.host.len > 0);
            assert(hop.payload.len <= payload_bytes_max);

            var writer: std.Io.Writer = .fixed(&client.request_buffer);

            head_write(&writer, url, hop) catch return error.RequestTooLarge;

            if (url.host_garmin()) {
                if (client.jar.cookies.count > 0) {
                    client.jar.header_write(&writer) catch return error.RequestTooLarge;
                }
            }

            writer.writeAll("\r\n") catch return error.RequestTooLarge;
            writer.writeAll(hop.payload) catch return error.RequestTooLarge;

            assert(writer.end > 0);

            return writer.buffered();
        }

        fn exchange_once(client: *Client, url: *const URL, request: []const u8) Error!u16 {
            assert(request.len > 0);
            assert(url.host.len > 0);

            client.diagnostic = .empty;
            client.location = .empty;

            const reader = client.transport.send(client.io, url, request) catch |err| {
                client.diagnostic.cause = client.transport.cause();

                return err;
            };

            defer client.transport.close(client.io);

            var http_reader: std.http.Reader = .{
                .in = reader,
                .interface = undefined,
                .max_head_len = transport.head_bytes_max,
                .side = .response,
                .state = .ready,
            };

            const head = try client.head_receive(&http_reader, url);
            const status: u16 = @backingInt(head.status);

            client.diagnostic.status = status;

            if (http.status_redirect(status)) return status;

            const body = try client.body_receive(&http_reader, &head);

            client.diagnostic.body = body;

            return status;
        }

        fn head_receive(
            client: *Client,
            http_reader: *std.http.Reader,
            url: *const URL,
        ) Error!std.http.Client.Response.Head {
            assert(http_reader.state == .ready);
            assert(url.host.len > 0);

            const bytes = http_reader.receiveHead() catch |err| switch (err) {
                error.HttpHeadersOversize => return error.HeadTooLarge,
                error.HttpConnectionClosing, error.HttpRequestTruncated => {
                    return client.response_invalid(@errorName(err));
                },
                error.ReadFailed => return client.read_failed(),
            };

            if (bytes.len > transport.head_bytes_max) return error.HeadTooLarge;

            const head = std.http.Client.Response.Head.parse(bytes) catch |err| {
                return client.response_invalid(@errorName(err));
            };

            if (head.content_encoding != .identity) {
                return client.response_invalid("ContentEncodingUnsupported");
            }

            if (url.host_garmin()) try client.cookies_store(&head);

            const status: u16 = @backingInt(head.status);

            if (http.status_redirect(status)) {
                const location = head.location orelse {
                    return client.response_invalid("LocationMissing");
                };

                var writer: std.Io.Writer = .fixed(client.location.array.slice_unused());

                http.location_resolve(&writer, url, location) catch {
                    return client.response_invalid("LocationInvalid");
                };

                client.location.array.resize_assume_capacity(@intCast(writer.end));
            }

            return head;
        }

        fn cookies_store(client: *Client, head: *const std.http.Client.Response.Head) Error!void {
            assert(head.bytes.len <= transport.head_bytes_max);
            assert(client.jar.cookies.count <= http.cookie_count_max);

            var iterator = head.iterateHeaders();

            for (0..head.bytes.len + 1) |_| {
                const field = iterator.next() orelse break;

                if (std.ascii.eqlIgnoreCase(field.name, "set-cookie")) {
                    try client.jar.set_cookie(field.value);
                }
            }
        }

        fn body_receive(
            client: *Client,
            http_reader: *std.http.Reader,
            head: *const std.http.Client.Response.Head,
        ) Error![]const u8 {
            assert(http_reader.state == .received_head);
            assert(client.body.len == body_bytes_max);

            const status: u16 = @backingInt(head.status);

            if (status == 204) return "";
            if (status == 304) return "";

            const reader = http_reader.bodyReader(
                &client.transfer,
                head.transfer_encoding,
                head.content_length,
            );

            const length = reader.readSliceShort(&client.body) catch {
                return client.body_failed(http_reader);
            };

            if (length == client.body.len) {
                if (reader.fill(1)) |_| {
                    return error.ResponseTooLarge;
                } else |err| switch (err) {
                    error.EndOfStream => {},
                    error.ReadFailed => return client.body_failed(http_reader),
                }
            }

            if (http_reader.state == .body_remaining_content_length) return client.read_failed();

            assert(length <= body_bytes_max);

            return client.body[0..length];
        }

        fn body_failed(client: *Client, http_reader: *const std.http.Reader) Error {
            assert(client.diagnostic.status != 0);
            assert(http_reader.state != .ready);

            if (http_reader.body_err) |err| return client.response_invalid(@errorName(err));

            return client.read_failed();
        }

        fn read_failed(client: *Client) Error {
            assert(client.body.len == body_bytes_max);
            assert(client.url.count() > 0);

            client.diagnostic.cause = client.transport.cause();

            return error.ReadFailed;
        }

        fn response_invalid(client: *Client, cause: []const u8) Error {
            assert(cause.len > 0);
            assert(client.url.count() > 0);

            client.diagnostic.cause = cause;

            return error.ResponseInvalid;
        }

        fn now(client: *const Client) i64 {
            assert(client.oauth1_token.identifier.count() > 0);

            const result = std.Io.Clock.real.now(client.io).toSeconds();

            assert(result > 0);

            return result;
        }
    };
}

fn head_write(
    writer: *std.Io.Writer,
    url: *const URL,
    hop: *const Exchange,
) std.Io.Writer.Error!void {
    assert(url.target[0] == '/');
    assert(hop.payload.len <= payload_bytes_max);

    try writer.print("{s} {s} HTTP/1.1\r\n", .{ hop.method.text(), url.target });
    try writer.writeAll("Host: ");
    try writer.writeAll(url.host);

    if (!url.port_default()) try writer.print(":{d}", .{url.port});

    try writer.print("\r\nUser-Agent: {s}\r\n", .{hop.user_agent.text()});
    try writer.writeAll("Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n");
    try writer.writeAll(hop.authorization);

    if (hop.referer.len > 0) try writer.print("Referer: {s}\r\n", .{hop.referer});
    if (hop.content_type.len > 0) try writer.print("Content-Type: {s}\r\n", .{hop.content_type});

    const content_length_sent = switch (hop.method) {
        .delete, .get => hop.payload.len > 0,
        .post, .put => true,
    };

    if (content_length_sent) try writer.print("Content-Length: {d}\r\n", .{hop.payload.len});
}

fn query_write(
    writer: *std.Io.Writer,
    base: []const u8,
    parameters: []const oauth1.Parameter,
) std.Io.Writer.Error!void {
    assert(base.len > 0);
    assert(parameters.len > 0);

    try writer.writeAll(base);

    for (parameters, 0..) |parameter, index| {
        try writer.writeByte(if (index == 0) '?' else '&');
        try writer.writeAll(parameter.name);
        try writer.writeByte('=');
        try oauth1.percent_encode(writer, parameter.value);
    }
}

fn status_error(status: u16) Error {
    assert(!http.status_success(status));
    assert(status >= 100);

    return switch (status) {
        400 => error.BadRequest,
        401 => error.Unauthorized,
        403 => error.Forbidden,
        404 => error.NotFound,
        409 => error.Conflict,
        429 => error.TooManyRequests,
        503 => error.Unavailable,
        500...502, 504...599 => error.ServerError,
        else => error.StatusUnexpected,
    };
}

test ClientType {
    const Client = ClientType(transport.Fake);
    const target = "/userprofile-service/userprofile/user-settings";

    const scripts = [_]transport.Fake.Script{.{
        .needle = "GET " ++ target,
        .responses = &.{"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n{\"measurement\":1}"},
    }};

    const tokens_file =
        \\{"format":2,"consumer":{"key":"key","secret":"secret"},
        \\"oauth1":{"token":"token","secret":"token-secret","mfa":null},
        \\"oauth2":{"access":"access","refresh":"refresh","obtained_at":4000000000,
        \\"lifetime_seconds":3600,"refresh_lifetime_seconds":7200},
        \\"profile":{"display_name":"athlete"}}
    ;

    const client = try std.testing.allocator.create(Client);
    defer std.testing.allocator.destroy(client);

    try client.init(std.testing.io, .{
        .consumer_key = "key",
        .consumer_secret = "secret",
        .retry_delay_ms = 0,
        .transport = .{ .scripts = &scripts },
    });

    defer client.deinit();

    try client.restore(tokens_file);

    const options: FetchOptions = .{ .method = .get, .payload = "", .target = target };
    const first = try client.fetch(&options);

    try std.testing.expectEqualStrings("{\"measurement\":1}", first);
    try std.testing.expectEqual(@as(u16, 200), client.diagnostic.status);
    try std.testing.expect(client.transport.logged("Authorization: Bearer access\r\n"));

    const second = try client.fetch(&options);

    try std.testing.expect(first.ptr == second.ptr);
    try std.testing.expect(@intFromPtr(second.ptr) == @intFromPtr(&client.body));
}
