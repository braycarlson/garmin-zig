const std = @import("std");

const api_module = @import("api.zig");
const client_module = @import("client.zig");
const http = @import("http.zig");
const tokens = @import("tokens.zig");
const transport = @import("transport.zig");
const url_module = @import("url.zig");

const assert = std.debug.assert;

pub const APIType = api_module.APIType;
pub const BloodPressure = api_module.BloodPressure;
pub const CapacityError = client_module.CapacityError;
pub const Client = ClientType(Native);
pub const ClientType = client_module.ClientType;
pub const Credentials = client_module.Credentials;
pub const Diagnostic = client_module.Diagnostic;
pub const Error = client_module.Error;
pub const Fake = transport.Fake;
pub const FetchOptions = client_module.FetchOptions;
pub const GearLink = api_module.GearLink;
pub const Login = client_module.Login;
pub const Method = http.Method;
pub const Native = transport.Native;
pub const Page = api_module.Page;
pub const Range = api_module.Range;
pub const Reading = api_module.Reading;
pub const ServiceError = client_module.ServiceError;
pub const SettingsError = client_module.SettingsError;
pub const TransportError = client_module.TransportError;
pub const WeighIn = api_module.WeighIn;

pub const api = APIType(Client);

pub fn message(err: Error) []const u8 {
    assert(@errorName(err).len > 0);
    assert(limits.retry_count_max > 0);

    const result: []const u8 = switch (err) {
        error.ArgumentInvalid => "an argument is empty or holds a byte a URL cannot carry",
        error.BadRequest => "Garmin refused the request as malformed",
        error.CertificatesUnavailable => "the system certificate authorities cannot be read",
        error.CodeInvalid => "the multi-factor authentication code is empty or too long",
        error.CodeRefused => "Garmin refused the multi-factor authentication code",
        error.Conflict => "Garmin refused the request as conflicting with the stored state",
        error.ConnectFailed => "the connection to Garmin could not be opened",
        error.CookieTooLarge => "a cookie passes the size limit",
        error.CookiesExhausted => "Garmin set more cookies than the jar holds",
        error.CredentialTooLong => "the consumer key or secret passes the length limit",
        error.CredentialsInvalid => "the email or the password is empty",
        error.DisplayNameTooLong => "the display name passes the length limit",
        error.Forbidden => "Garmin refused access to the resource",
        error.HeadTooLarge => "a response head passes the size limit",
        error.LoginRefused => "Garmin refused the sign-in",
        error.NotFound => "Garmin has no such resource",
        error.PayloadTooLarge => "a request payload passes the size limit",
        error.ReadFailed => "the response could not be read",
        error.RedirectsExhausted => "Garmin redirected more times than the limit allows",
        error.RequestTooLarge => "a request passes the size limit",
        error.ResponseInvalid => "Garmin answered with a response the client cannot use",
        error.ResponseTooLarge => "a response body passes the size limit",
        error.ServerError => "Garmin failed to answer the request",
        error.StatusUnexpected => "Garmin answered with an unexpected status",
        error.TokenTooLong => "a token passes the length limit",
        error.TokensInvalid => "the token file is malformed or incomplete",
        error.TokensVersionUnknown => "the token file has an unknown format version",
        error.TooManyRequests => "Garmin is rate limiting the requests",
        error.Unauthorized => "Garmin refused the tokens, even after a refresh",
        error.Unavailable => "Garmin is temporarily unavailable",
        error.WriteFailed => "the request could not be written",
    };

    assert(result.len > 0);

    return result;
}

pub const limits = struct {
    pub const activities_page_max: u32 = api_module.activities_page_max;
    pub const body_bytes_max: u32 = client_module.body_bytes_max;
    pub const cookie_bytes_max: u32 = http.cookie_bytes_max;
    pub const cookie_count_max: u32 = http.cookie_count_max;
    pub const display_name_bytes_max: u32 = client_module.display_name_bytes_max;
    pub const gear_activities_max: u32 = api_module.gear_activities_max;
    pub const head_bytes_max: u32 = transport.head_bytes_max;
    pub const payload_bytes_max: u32 = client_module.payload_bytes_max;
    pub const redirect_count_max: u32 = client_module.redirect_count_max;
    pub const request_bytes_max: u32 = transport.request_bytes_max;
    pub const retry_count_max: u32 = client_module.retry_count_max;
    pub const sleep_buffer_minutes_max: u32 = api_module.sleep_buffer_minutes_max;
    pub const timeout_seconds: u32 = transport.timeout_seconds;
    pub const token_file_bytes_max: u32 = tokens.file_bytes_max;
    pub const url_bytes_max: u32 = url_module.bytes_max;
};

test message {
    const names = @typeInfo(Error).error_set.error_names.?;

    inline for (names) |name| {
        const text = message(@field(Error, name));

        try std.testing.expect(text.len > 0);
        try std.testing.expect(std.mem.findScalar(u8, text, '\n') == null);
    }
}
