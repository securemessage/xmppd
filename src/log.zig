//! # Structured Logging Module
//!
//! Provides a timestamped log handler that replaces Zig's default stderr logger.
//! Each log line is prefixed with an ISO-8601 timestamp (millisecond precision)
//! for correlation with client-side test logs and production debugging.
//!
//! ## Output Format
//!
//! ```
//! 2026-06-13T22:08:01.900 info(xmppd): connection 3 session established
//! 2026-06-13T22:08:01.901 warn(router): stanza to offline user dropped
//! ```
//!
//! ## Usage
//!
//! In each binary's root source file (main.zig), add:
//!
//! ```zig
//! pub const std_options = xmppd_log.std_options;
//! ```
//!
//! All existing `std.log.scoped(.scope)` calls will automatically use
//! the timestamped handler — no code changes needed in other files.

const std = @import("std");
const posix = std.posix;

/// Zig standard library options override. Import this in root source files
/// to activate timestamped logging for all `std.log` calls.
pub const std_options: std.Options = .{
    .logFn = timestampedLog,
    .log_level = .info,
};

/// Log handler that prepends ISO-8601 timestamps to every message.
/// Thread-safe: formats into a stack-local buffer, writes atomically via write(2).
fn timestampedLog(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const scope_name = @tagName(scope);
    const level_name = comptime switch (level) {
        .err => "error",
        .warn => "warn",
        .info => "info",
        .debug => "debug",
    };

    // Get wall clock time
    const epoch_secs = std.time.timestamp();
    const millis: u64 = blk: {
        const nanos = std.time.nanoTimestamp();
        break :blk @intCast(@mod(@as(u64, @intCast(nanos)) / std.time.ns_per_ms, 1000));
    };

    // Convert epoch seconds to broken-down time (UTC)
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(epoch_secs) };
    const epoch_day = es.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = es.getDaySeconds();

    const year = year_day.year;
    const month = month_day.month.numeric();
    const day = month_day.day_index + 1;
    const hour = day_secs.getHoursIntoDay();
    const minute = day_secs.getMinutesIntoHour();
    const second = day_secs.getSecondsIntoMinute();

    var buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Timestamp: 2026-06-13T22:08:01.900
    std.fmt.format(w, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3} ", .{
        year, month, day, hour, minute, second, millis,
    }) catch return;

    // Level and scope: info(xmppd):
    w.writeAll(level_name) catch return;
    w.writeByte('(') catch return;
    w.writeAll(scope_name) catch return;
    w.writeAll("): ") catch return;

    // User message
    std.fmt.format(w, format, args) catch return;
    w.writeByte('\n') catch return;

    const output = fbs.getWritten();
    _ = posix.write(posix.STDERR_FILENO, output) catch {};
}
