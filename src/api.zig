const std = @import("std");

const bounded = @import("bounded");
const client_module = @import("client.zig");
const http = @import("http.zig");
const json = @import("json");
const oauth1 = @import("oauth1.zig");
const transport = @import("transport.zig");
const url_module = @import("url.zig");

const assert = std.debug.assert;

const ClientType = client_module.ClientType;
const Method = http.Method;
const Target = bounded.BufferType(url_module.bytes_max);

pub const activities_page_max: u32 = 100;
pub const gear_activities_max: u32 = 1000;
pub const sleep_buffer_minutes_default: u32 = 60;
pub const sleep_buffer_minutes_max: u32 = 12 * 60;

const placeholder_bytes: u32 = 3;
const source_type_manual = "MANUAL";

comptime {
    assert(placeholder_bytes == "{s}".len);
    assert(sleep_buffer_minutes_default <= sleep_buffer_minutes_max);
}

pub const BloodPressure = struct {
    diastolic: i64,
    notes: []const u8,
    pulse: i64,
    systolic: i64,
    timestamp_gmt: []const u8,
    timestamp_local: []const u8,
};

pub const GearLink = struct {
    activity_id: []const u8,
    gear_uuid: []const u8,
};

pub const Page = struct {
    limit: u32,
    start: u32,
};

pub const Range = struct {
    end: []const u8,
    start: []const u8,
};

pub const Reading = struct {
    calendar_date: []const u8,
    version: []const u8,
};

pub const WeighIn = struct {
    date_timestamp: []const u8,
    gmt_timestamp: []const u8,
    unit_key: []const u8,
    value: f64,
};

const BloodPressurePayload = struct {
    measurement_timestamp_local: []const u8,
    measurement_timestamp_gmt: []const u8,
    systolic: i64,
    diastolic: i64,
    pulse: i64,
    source_type: []const u8,
    notes: []const u8,

    pub const json = .{
        .measurement_timestamp_gmt = "measurementTimestampGMT",
        .measurement_timestamp_local = "measurementTimestampLocal",
        .source_type = "sourceType",
    };
};

const Arguments = struct {
    numbers: []const u32,
    texts: []const []const u8,
};

const Operation = struct {
    arguments: Arguments,
    method: Method,
    payload: []const u8,
};

const WeighInPayload = struct {
    date_timestamp: []const u8,
    gmt_timestamp: []const u8,
    unit_key: []const u8,
    source_type: []const u8,
    value: f64,

    pub const json = .{
        .date_timestamp = "dateTimestamp",
        .gmt_timestamp = "gmtTimestamp",
        .source_type = "sourceType",
        .unit_key = "unitKey",
    };
};

pub fn APIType(comptime Client: type) type {
    return struct {
        const Error = client_module.Error;

        pub const account = struct {
            pub fn social_profile(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                return get(client, "/userprofile-service/socialProfile", &.{});
            }

            pub fn user_settings(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                return get(client, "/userprofile-service/userprofile/user-settings", &.{});
            }
        };

        pub const activities = struct {
            pub fn list(client: *Client, page: Page) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(page.limit > 0);
                assert(page.limit <= activities_page_max);

                const template = "/activitylist-service/activities/search/activities" ++
                    "?start={d}&limit={d}";

                return call(client, template, .{
                    .arguments = .{ .numbers = &.{ page.start, page.limit }, .texts = &.{} },
                    .method = .get,
                    .payload = "",
                });
            }

            pub fn count(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                return get(client, "/activitylist-service/activities/count", &.{});
            }

            pub fn types(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                return get(client, "/activity-service/activity/activityTypes", &.{});
            }

            pub fn by_id(client: *Client, activity_id: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(activity_id.len > 0);

                return get(client, "/activity-service/activity/{s}", &.{activity_id});
            }

            pub fn details(client: *Client, activity_id: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(activity_id.len > 0);

                return get(client, "/activity-service/activity/{s}/details", &.{activity_id});
            }

            pub fn splits(client: *Client, activity_id: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(activity_id.len > 0);

                return get(client, "/activity-service/activity/{s}/splits", &.{activity_id});
            }

            pub fn typed_splits(client: *Client, activity_id: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(activity_id.len > 0);

                return get(client, "/activity-service/activity/{s}/typedsplits", &.{activity_id});
            }

            pub fn split_summaries(client: *Client, activity_id: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(activity_id.len > 0);

                const template = "/activity-service/activity/{s}/split_summaries";

                return get(client, template, &.{activity_id});
            }

            pub fn weather(client: *Client, activity_id: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(activity_id.len > 0);

                return get(client, "/activity-service/activity/{s}/weather", &.{activity_id});
            }

            pub fn heart_rate_zones(client: *Client, activity_id: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(activity_id.len > 0);

                return get(client, "/activity-service/activity/{s}/hrTimeInZones", &.{activity_id});
            }

            pub fn power_zones(client: *Client, activity_id: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(activity_id.len > 0);

                const template = "/activity-service/activity/{s}/powerTimeInZones";

                return get(client, template, &.{activity_id});
            }

            pub fn exercise_sets(client: *Client, activity_id: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(activity_id.len > 0);

                return get(client, "/activity-service/activity/{s}/exerciseSets", &.{activity_id});
            }

            pub fn download(client: *Client, activity_id: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(activity_id.len > 0);

                return get(client, "/download-service/files/activity/{s}", &.{activity_id});
            }
        };

        pub const badges = struct {
            pub fn available(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                return get(client, "/badge-service/badge/available", &.{});
            }

            pub fn earned(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                return get(client, "/badge-service/badge/earned", &.{});
            }

            pub fn adhoc_challenges(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                const template = "/adhocchallenge-service/adHocChallenge/historical" ++
                    "?start=1&limit=100";

                return get(client, template, &.{});
            }

            pub fn completed_challenges(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                const template = "/badgechallenge-service/badgeChallenge/completed" ++
                    "?start=1&limit=100";

                return get(client, template, &.{});
            }

            pub fn available_challenges(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                const template = "/badgechallenge-service/badgeChallenge/available" ++
                    "?start=1&limit=100";

                return get(client, template, &.{});
            }

            pub fn non_completed_challenges(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                const template = "/badgechallenge-service/badgeChallenge/non-completed" ++
                    "?start=1&limit=100";

                return get(client, template, &.{});
            }

            pub fn virtual_challenges(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                const template = "/badgechallenge-service/virtualChallenge/inProgress" ++
                    "?start=1&limit=100";

                return get(client, template, &.{});
            }
        };

        pub const body = struct {
            pub fn composition(client: *Client, range: Range) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(range.start.len > 0);
                assert(range.end.len > 0);

                const template = "/weight-service/weight/dateRange?startDate={s}&endDate={s}";

                return get(client, template, &.{ range.start, range.end });
            }

            pub fn weight_day(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                return get(client, "/weight-service/weight/dayview/{s}", &.{date});
            }

            pub fn hydration(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                const template = "/usersummary-service/usersummary/hydration/allData/{s}";

                return get(client, template, &.{date});
            }

            pub fn hydration_daily(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                const template = "/usersummary-service/usersummary/hydration/daily/{s}";

                return get(client, template, &.{date});
            }

            pub fn blood_pressure(client: *Client, range: Range) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(range.start.len > 0);
                assert(range.end.len > 0);

                const template = "/bloodpressure-service/bloodpressure/range/{s}/{s}";

                return get(client, template, &.{ range.start, range.end });
            }

            pub fn weigh_ins(client: *Client, range: Range) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(range.start.len > 0);
                assert(range.end.len > 0);

                const template = "/weight-service/weight/range/{s}/{s}";

                return get(client, template, &.{ range.start, range.end });
            }

            pub fn body_battery(client: *Client, range: Range) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(range.start.len > 0);
                assert(range.end.len > 0);

                const template = "/wellness-service/wellness/bodyBattery/reports/daily" ++
                    "?startDate={s}&endDate={s}";

                return get(client, template, &.{ range.start, range.end });
            }

            pub fn body_battery_events(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                return get(client, "/wellness-service/wellness/bodyBattery/events/{s}", &.{date});
            }
        };

        pub const devices = struct {
            pub fn list(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                return get(client, "/device-service/deviceregistration/devices", &.{});
            }

            pub fn used_last(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                return get(client, "/device-service/deviceservice/mylastused", &.{});
            }

            pub fn settings(client: *Client, device_id: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(device_id.len > 0);

                const template = "/device-service/deviceservice/device-info/settings/{s}";

                return get(client, template, &.{device_id});
            }
        };

        pub const gear = struct {
            pub fn list(client: *Client, user_profile_key: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(user_profile_key.len > 0);

                const template = "/gear-service/gear/filterGear?userProfilePk={s}";

                return get(client, template, &.{user_profile_key});
            }

            pub fn stats(client: *Client, gear_uuid: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(gear_uuid.len > 0);

                return get(client, "/gear-service/gear/stats/{s}", &.{gear_uuid});
            }

            pub fn activities(client: *Client, gear_uuid: []const u8, limit: u32) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(gear_uuid.len > 0);
                assert(limit > 0);
                assert(limit <= gear_activities_max);

                const template = "/activitylist-service/activities/{s}/gear?start=0&limit={d}";

                return call(client, template, .{
                    .arguments = .{ .numbers = &.{limit}, .texts = &.{gear_uuid} },
                    .method = .get,
                    .payload = "",
                });
            }

            pub fn unlink(client: *Client, link: GearLink) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(link.gear_uuid.len > 0);
                assert(link.activity_id.len > 0);

                return call(client, "/gear-service/gear/unlink/{s}/activity/{s}", .{
                    .arguments = .{
                        .numbers = &.{},
                        .texts = &.{ link.gear_uuid, link.activity_id },
                    },
                    .method = .put,
                    .payload = "",
                });
            }
        };

        pub const goals = struct {
            pub fn list(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                const template = "/goal-service/goal/goals" ++
                    "?status=active&start=1&limit=30&sortOrder=asc";

                return get(client, template, &.{});
            }
        };

        pub const metrics = struct {
            pub fn vo2_max(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                const template = "/metrics-service/metrics/maxmet/daily/{s}/{s}";

                return get(client, template, &.{ date, date });
            }

            pub fn training_readiness(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                return get(client, "/metrics-service/metrics/trainingreadiness/{s}", &.{date});
            }

            pub fn training_status(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                const template = "/metrics-service/metrics/trainingstatus/aggregated/{s}";

                return get(client, template, &.{date});
            }

            pub fn endurance_score(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                return get(client, "/metrics-service/metrics/endurancescore/stats", &.{});
            }

            pub fn hill_score(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                return get(client, "/metrics-service/metrics/hillscore/stats", &.{});
            }

            pub fn fitness_age(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                return get(client, "/fitnessage-service/fitnessage/{s}", &.{date});
            }

            pub fn cycling_functional_threshold_power(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                const template = "/biometric-service/biometric/latestFunctionalThresholdPower" ++
                    "/CYCLING";

                return get(client, template, &.{});
            }

            pub fn lactate_threshold(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                const template = "/biometric-service/biometric/powerToWeight/latest/{s}" ++
                    "?sport=Running";

                return get(client, template, &.{date});
            }
        };

        pub const mutations = struct {
            pub fn add_weigh_in(client: *Client, weigh_in: *const WeighIn) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(weigh_in.value > 0);
                assert(weigh_in.unit_key.len > 0);

                var writer: std.Io.Writer = .fixed(&client.payload_buffer);

                weigh_in_encode(&writer, weigh_in) catch |err| return encode_failed(err);

                return call(client, "/weight-service/user-weight", .{
                    .arguments = .{ .numbers = &.{}, .texts = &.{} },
                    .method = .post,
                    .payload = writer.buffered(),
                });
            }

            pub fn delete_weigh_in(client: *Client, reading: Reading) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(reading.calendar_date.len > 0);
                assert(reading.version.len > 0);

                return call(client, "/weight-service/weight/weight/{s}/byversion/{s}", .{
                    .arguments = .{
                        .numbers = &.{},
                        .texts = &.{ reading.calendar_date, reading.version },
                    },
                    .method = .delete,
                    .payload = "",
                });
            }

            pub fn delete_activity(client: *Client, activity_id: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(activity_id.len > 0);

                return call(client, "/activity-service/activity/{s}", .{
                    .arguments = .{ .numbers = &.{}, .texts = &.{activity_id} },
                    .method = .delete,
                    .payload = "",
                });
            }

            pub fn set_blood_pressure(
                client: *Client,
                blood_pressure: *const BloodPressure,
            ) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(blood_pressure.systolic > 0);
                assert(blood_pressure.diastolic > 0);

                var writer: std.Io.Writer = .fixed(&client.payload_buffer);

                blood_pressure_encode(&writer, blood_pressure) catch |err| {
                    return encode_failed(err);
                };

                return call(client, "/bloodpressure-service/bloodpressure", .{
                    .arguments = .{ .numbers = &.{}, .texts = &.{} },
                    .method = .post,
                    .payload = writer.buffered(),
                });
            }

            pub fn delete_blood_pressure(client: *Client, reading: Reading) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(reading.calendar_date.len > 0);
                assert(reading.version.len > 0);

                return call(client, "/bloodpressure-service/bloodpressure/{s}/{s}", .{
                    .arguments = .{
                        .numbers = &.{},
                        .texts = &.{ reading.calendar_date, reading.version },
                    },
                    .method = .delete,
                    .payload = "",
                });
            }
        };

        pub const records = struct {
            pub fn personal_records(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.display_name_text.count() > 0);

                const template = "/personalrecord-service/personalrecord/prs/{s}";

                return get(client, template, &.{client.display_name()});
            }
        };

        pub const stats = struct {
            pub fn floors(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                const template = "/wellness-service/wellness/floorsChartData/daily/{s}";

                return get(client, template, &.{date});
            }

            pub fn daily_steps(client: *Client, range: Range) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(range.start.len > 0);
                assert(range.end.len > 0);

                const template = "/usersummary-service/stats/steps/daily/{s}/{s}";

                return get(client, template, &.{ range.start, range.end });
            }

            pub fn weekly_steps(
                client: *Client,
                end_date: []const u8,
                weeks: u32,
            ) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(end_date.len > 0);
                assert(weeks > 0);

                const template = "/usersummary-service/stats/steps/weekly/{s}/{d}";

                return call(client, template, .{
                    .arguments = .{ .numbers = &.{weeks}, .texts = &.{end_date} },
                    .method = .get,
                    .payload = "",
                });
            }

            pub fn weekly_stress(
                client: *Client,
                end_date: []const u8,
                weeks: u32,
            ) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(end_date.len > 0);
                assert(weeks > 0);

                const template = "/usersummary-service/stats/stress/weekly/{s}/{d}";

                return call(client, template, .{
                    .arguments = .{ .numbers = &.{weeks}, .texts = &.{end_date} },
                    .method = .get,
                    .payload = "",
                });
            }

            pub fn weekly_intensity_minutes(client: *Client, range: Range) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(range.start.len > 0);
                assert(range.end.len > 0);

                const template = "/usersummary-service/stats/im/weekly/{s}/{s}";

                return get(client, template, &.{ range.start, range.end });
            }

            pub fn resting_heart_rate(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                const template = "/userstats-service/wellness/daily/{s}?fromDate={s}&metricId=60";

                return get(client, template, &.{ client.display_name(), date });
            }

            pub fn lifestyle_logging(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                return get(client, "/lifestylelogging-service/dailyLog/{s}", &.{date});
            }
        };

        pub const wellness = struct {
            pub fn daily_summary(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                const template = "/usersummary-service/usersummary/daily/{s}?calendarDate={s}";

                return get(client, template, &.{ client.display_name(), date });
            }

            pub fn steps(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                const template = "/wellness-service/wellness/dailySummaryChart/{s}?date={s}";

                return get(client, template, &.{ client.display_name(), date });
            }

            pub fn heart_rate(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                const template = "/wellness-service/wellness/dailyHeartRate/{s}?date={s}";

                return get(client, template, &.{ client.display_name(), date });
            }

            pub fn heart_rate_for_date(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                return get(client, "/mobile-gateway/heartRate/forDate/{s}", &.{date});
            }

            pub fn sleep(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                return sleep_buffered(client, date, sleep_buffer_minutes_default);
            }

            pub fn sleep_buffered(
                client: *Client,
                date: []const u8,
                buffer_minutes: u32,
            ) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);
                assert(buffer_minutes <= sleep_buffer_minutes_max);

                const template = "/wellness-service/wellness/dailySleepData/{s}" ++
                    "?date={s}&nonSleepBufferMinutes={d}";

                return call(client, template, .{
                    .arguments = .{
                        .numbers = &.{buffer_minutes},
                        .texts = &.{ client.display_name(), date },
                    },
                    .method = .get,
                    .payload = "",
                });
            }

            pub fn hrv(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                return get(client, "/hrv-service/hrv/{s}", &.{date});
            }

            pub fn stress(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                return get(client, "/wellness-service/wellness/dailyStress/{s}", &.{date});
            }

            pub fn spo2(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                return get(client, "/wellness-service/wellness/daily/spo2/{s}", &.{date});
            }

            pub fn respiration(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                return get(client, "/wellness-service/wellness/daily/respiration/{s}", &.{date});
            }

            pub fn intensity_minutes(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                return get(client, "/wellness-service/wellness/daily/im/{s}", &.{date});
            }
        };

        pub const womens_health = struct {
            pub fn menstrual_day(client: *Client, date: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(date.len > 0);

                return get(client, "/periodichealth-service/menstrualcycle/dayview/{s}", &.{date});
            }

            pub fn menstrual_calendar(client: *Client, range: Range) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(range.start.len > 0);
                assert(range.end.len > 0);

                const template = "/periodichealth-service/menstrualcycle/calendar/{s}/{s}";

                return get(client, template, &.{ range.start, range.end });
            }

            pub fn pregnancy(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                const template = "/periodichealth-service/menstrualcycle/pregnancysnapshot";

                return get(client, template, &.{});
            }
        };

        pub const workouts = struct {
            pub fn list(client: *Client) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(client.oauth2_token.access_token.count() > 0);

                const template = "/workout-service/workouts" ++
                    "?start=0&limit=100&myWorkoutsOnly=true&sharedWorkoutsOnly=false";

                return get(client, template, &.{});
            }

            pub fn by_id(client: *Client, workout_id: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(workout_id.len > 0);

                return get(client, "/workout-service/workout/{s}", &.{workout_id});
            }

            pub fn download(client: *Client, workout_id: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(workout_id.len > 0);

                return get(client, "/workout-service/workout/FIT/{s}", &.{workout_id});
            }

            pub fn delete(client: *Client, workout_id: []const u8) Error![]const u8 {
                assert(client.phase == .authorized);
                assert(workout_id.len > 0);

                return call(client, "/workout-service/workout/{s}", .{
                    .arguments = .{ .numbers = &.{}, .texts = &.{workout_id} },
                    .method = .delete,
                    .payload = "",
                });
            }
        };

        fn get(
            client: *Client,
            comptime template: []const u8,
            texts: []const []const u8,
        ) Error![]const u8 {
            comptime assert(template[0] == '/');
            assert(texts.len == comptime std.mem.count(u8, template, "{s}"));

            return call(client, template, .{
                .arguments = .{ .numbers = &.{}, .texts = texts },
                .method = .get,
                .payload = "",
            });
        }

        fn call(
            client: *Client,
            comptime template: []const u8,
            operation: Operation,
        ) Error![]const u8 {
            comptime assert(template[0] == '/');
            assert(client.phase == .authorized);
            assert(operation.payload.len <= client_module.payload_bytes_max);

            client.target = .empty;

            try target_expand(&client.target, template, operation.arguments);

            return client.fetch(&.{
                .method = operation.method,
                .payload = operation.payload,
                .target = client.target.slice(),
            });
        }
    };
}

pub fn target_expand(
    target: *Target,
    template: []const u8,
    arguments: Arguments,
) error{ ArgumentInvalid, RequestTooLarge }!void {
    assert(template[0] == '/');
    assert(std.mem.count(u8, template, "{s}") == arguments.texts.len);
    assert(std.mem.count(u8, template, "{d}") == arguments.numbers.len);

    var numbers = arguments.numbers;
    var texts = arguments.texts;
    var rest = template;

    for (0..template.len) |_| {
        const index = std.mem.findScalar(u8, rest, '{') orelse break;

        target.push(rest[0..index]) catch return error.RequestTooLarge;

        switch (rest[index + 1]) {
            'd' => {
                target.print("{d}", .{numbers[0]}) catch return error.RequestTooLarge;
                numbers = numbers[1..];
            },
            's' => {
                try text_check(texts[0]);

                target.push(texts[0]) catch return error.RequestTooLarge;
                texts = texts[1..];
            },
            else => unreachable,
        }

        rest = rest[index + 3 ..];
    }

    target.push(rest) catch return error.RequestTooLarge;

    assert(numbers.len == 0);
    assert(texts.len == 0);
}

fn text_check(text: []const u8) error{ArgumentInvalid}!void {
    assert(text.len <= std.math.maxInt(u32));
    assert(placeholder_bytes == 3);

    if (text.len == 0) return error.ArgumentInvalid;

    for (text) |byte| {
        if (!oauth1.unreserved(byte)) return error.ArgumentInvalid;
    }
}

pub fn weigh_in_encode(
    writer: *std.Io.Writer,
    weigh_in: *const WeighIn,
) error{ FloatNonFinite, WriteFailed }!void {
    assert(weigh_in.unit_key.len > 0);
    assert(weigh_in.date_timestamp.len > 0);

    const payload: WeighInPayload = .{
        .date_timestamp = weigh_in.date_timestamp,
        .gmt_timestamp = weigh_in.gmt_timestamp,
        .unit_key = weigh_in.unit_key,
        .source_type = source_type_manual,
        .value = weigh_in.value,
    };

    try payload_encode(WeighInPayload, writer, &payload);
}

pub fn blood_pressure_encode(
    writer: *std.Io.Writer,
    blood_pressure: *const BloodPressure,
) error{ FloatNonFinite, WriteFailed }!void {
    assert(blood_pressure.timestamp_local.len > 0);
    assert(blood_pressure.timestamp_gmt.len > 0);

    const payload: BloodPressurePayload = .{
        .measurement_timestamp_local = blood_pressure.timestamp_local,
        .measurement_timestamp_gmt = blood_pressure.timestamp_gmt,
        .systolic = blood_pressure.systolic,
        .diastolic = blood_pressure.diastolic,
        .pulse = blood_pressure.pulse,
        .source_type = source_type_manual,
        .notes = blood_pressure.notes,
    };

    try payload_encode(BloodPressurePayload, writer, &payload);
}

fn payload_encode(
    comptime Payload: type,
    writer: *std.Io.Writer,
    payload: *const Payload,
) error{ FloatNonFinite, WriteFailed }!void {
    comptime assert(@hasDecl(Payload, "json"));
    assert(writer.end == 0);

    var json_writer: json.Writer = .init(writer, .{
        .indent = 2,
        .layout = .compact,
        .non_finite = .refused,
        .notation = .ecmascript,
        .utf8 = .checked,
    });

    try json.encode(Payload, &json_writer, payload, .{ .null_members = .omitted });

    json_writer.finish();
}

fn encode_failed(
    err: error{ FloatNonFinite, WriteFailed },
) error{ ArgumentInvalid, PayloadTooLarge } {
    return switch (err) {
        error.FloatNonFinite => error.ArgumentInvalid,
        error.WriteFailed => error.PayloadTooLarge,
    };
}

const PayloadDocument = json.DocumentType(.{ .node_count_max = 32, .text_bytes_max = 256 });

fn payload_node(payload: *const PayloadDocument, key: []const u8) !json.Node {
    assert(key.len > 0);
    assert(payload.base.node_count > 0);

    return payload.member(payload.root(), key) orelse error.TestMemberMissing;
}

fn payload_text(payload: *const PayloadDocument, key: []const u8) ![]const u8 {
    assert(key.len > 0);
    assert(payload.base.node_count > 0);

    const node = try payload_node(payload, key);

    if (payload.kind_of(node) != .string) return error.TestMemberKind;

    return payload.text_of(node) orelse error.TestMemberKind;
}

fn payload_texts_check(payload: *const PayloadDocument, texts: []const [2][]const u8) !void {
    assert(texts.len > 0);
    assert(payload.base.node_count > 0);

    for (texts) |pair| {
        try std.testing.expectEqualStrings(pair[1], try payload_text(payload, pair[0]));
    }
}

test target_expand {
    const Case = struct {
        arguments: Arguments,
        expected: []const u8,
        template: []const u8,
    };

    const cases = [_]Case{
        .{
            .arguments = .{ .numbers = &.{}, .texts = &.{} },
            .expected = "/activitylist-service/activities/count",
            .template = "/activitylist-service/activities/count",
        },
        .{
            .arguments = .{ .numbers = &.{}, .texts = &.{"12345"} },
            .expected = "/activity-service/activity/12345",
            .template = "/activity-service/activity/{s}",
        },
        .{
            .arguments = .{ .numbers = &.{}, .texts = &.{ "uuid-1", "999" } },
            .expected = "/gear-service/gear/unlink/uuid-1/activity/999",
            .template = "/gear-service/gear/unlink/{s}/activity/{s}",
        },
        .{
            .arguments = .{ .numbers = &.{ 0, 4294967295 }, .texts = &.{"day"} },
            .expected = "/a/day?start=0&limit=4294967295",
            .template = "/a/{s}?start={d}&limit={d}",
        },
    };

    for (cases) |case| {
        var target: Target = .empty;

        try target_expand(&target, case.template, case.arguments);
        try std.testing.expectEqualStrings(case.expected, target.slice());
    }
}

test "a target refuses an argument outside the unreserved bytes" {
    const invalid = [_][]const u8{ "", "a/b", "a?b", "a#b", "a&b", "a%b", "a b" };

    for (invalid) |argument| {
        var target: Target = .empty;

        const result = target_expand(&target, "/activity-service/activity/{s}", .{
            .numbers = &.{},
            .texts = &.{argument},
        });

        try std.testing.expectError(error.ArgumentInvalid, result);
    }
}

test weigh_in_encode {
    const weigh_in: WeighIn = .{
        .date_timestamp = "2026-10-21T07:15:00.00",
        .gmt_timestamp = "2026-10-21T13:15:00.00",
        .unit_key = "kg",
        .value = 72.5,
    };

    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    try weigh_in_encode(&writer, &weigh_in);

    const expected = "{\"dateTimestamp\":\"2026-10-21T07:15:00.00\"," ++
        "\"gmtTimestamp\":\"2026-10-21T13:15:00.00\",\"unitKey\":\"kg\"," ++
        "\"sourceType\":\"MANUAL\",\"value\":72.5}";

    try std.testing.expectEqualStrings(expected, writer.buffered());

    var payload: PayloadDocument = undefined;

    try payload.parse(writer.buffered());

    try payload_texts_check(&payload, &.{
        .{ "dateTimestamp", weigh_in.date_timestamp },
        .{ "gmtTimestamp", weigh_in.gmt_timestamp },
        .{ "unitKey", weigh_in.unit_key },
        .{ "sourceType", "MANUAL" },
    });

    try std.testing.expectEqual(@as(u32, 5), payload.count_of(payload.root()));
    const value = payload.float_of(try payload_node(&payload, "value")) orelse 0;

    try std.testing.expectEqual(weigh_in.value, value);
}

test "a weigh-in writes a whole gram value without an exponent and refuses infinity" {
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    try weigh_in_encode(&writer, &.{
        .date_timestamp = "2026-10-21T07:15:00.00",
        .gmt_timestamp = "2026-10-21T13:15:00.00",
        .unit_key = "g",
        .value = 70000,
    });

    try std.testing.expect(std.mem.endsWith(u8, writer.buffered(), "\"value\":70000}"));

    var refused_buffer: [256]u8 = undefined;
    var refused: std.Io.Writer = .fixed(&refused_buffer);

    const result = weigh_in_encode(&refused, &.{
        .date_timestamp = "2026-10-21T07:15:00.00",
        .gmt_timestamp = "2026-10-21T13:15:00.00",
        .unit_key = "kg",
        .value = std.math.inf(f64),
    });

    try std.testing.expectError(error.FloatNonFinite, result);
}

test blood_pressure_encode {
    const blood_pressure: BloodPressure = .{
        .diastolic = 80,
        .notes = "after \"intervals\"\n\tseated \u{b0}",
        .pulse = 61,
        .systolic = 120,
        .timestamp_gmt = "2026-10-21T13:20:00.000",
        .timestamp_local = "2026-10-21T07:20:00.000",
    };

    var buffer: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    try blood_pressure_encode(&writer, &blood_pressure);

    const expected = "{\"measurementTimestampLocal\":\"2026-10-21T07:20:00.000\"," ++
        "\"measurementTimestampGMT\":\"2026-10-21T13:20:00.000\"," ++
        "\"systolic\":120,\"diastolic\":80,\"pulse\":61,\"sourceType\":\"MANUAL\"," ++
        "\"notes\":\"after \\\"intervals\\\"\\n\\tseated \u{b0}\"}";

    try std.testing.expectEqualStrings(expected, writer.buffered());

    var payload: PayloadDocument = undefined;

    try payload.parse(writer.buffered());

    try payload_texts_check(&payload, &.{
        .{ "measurementTimestampLocal", blood_pressure.timestamp_local },
        .{ "measurementTimestampGMT", blood_pressure.timestamp_gmt },
        .{ "sourceType", "MANUAL" },
        .{ "notes", blood_pressure.notes },
    });

    const integers = [_]struct { []const u8, i64 }{
        .{ "systolic", blood_pressure.systolic },
        .{ "diastolic", blood_pressure.diastolic },
        .{ "pulse", blood_pressure.pulse },
    };

    for (integers) |pair| {
        const integer = payload.integer_of(try payload_node(&payload, pair[0])) orelse 0;

        try std.testing.expectEqual(pair[1], integer);
    }

    try std.testing.expectEqual(@as(u32, 7), payload.count_of(payload.root()));
}

test APIType {
    const Client = ClientType(transport.Fake);
    const API = APIType(Client);

    const scripts = [_]transport.Fake.Script{.{
        .needle = "GET /wellness-service/wellness/dailySleepData/athlete?date=2026-10-21",
        .responses = &.{"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n{\"sleepScore\":81}"},
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

    const body = try API.wellness.sleep(client, "2026-10-21");

    try std.testing.expectEqualStrings("{\"sleepScore\":81}", body);
    try std.testing.expect(client.transport.logged("&nonSleepBufferMinutes=60 HTTP/1.1"));
    try std.testing.expectError(error.ArgumentInvalid, API.wellness.sleep(client, "2026/10/21"));
}
