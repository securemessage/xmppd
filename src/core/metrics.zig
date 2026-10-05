//! M1 (doc §5.2): per-worker instrumentation for the core event loop.
//!
//! One Counters block per worker thread. The owning thread is the only
//! writer and, because SIGUSR1 arrives as EVFILT_SIGNAL on its own kqueue,
//! also the only reader; relaxed atomics cover the rest. Idle cost is
//! zero: counters move only when work happens and the dump runs only on
//! SIGUSR1.
//!
//! Counters that live behind build-module boundaries (delivery_queue,
//! room_mailbox) keep module-local atomics of their own (the S16
//! mailbox_drops pattern); the dump takes them as `Externals`.

const std = @import("std");
const atomic = std.atomic;

const log = std.log.scoped(.metrics);

/// Mirrors room_registry.MAX_WORKERS without importing it.
pub const MAX_WORKERS = 64;

/// log2 microsecond buckets: bucket k holds iterations in [2^k, 2^(k+1)) us.
pub const HIST_BUCKETS = 32;

const Counter = atomic.Value(u64);

/// Counters that live in other build modules and are passed to dump().
pub const Externals = struct {
    room_mailbox_drops: u64 = 0,
    ring_drops_full: u64 = 0,
    ring_drops_payload: u64 = 0,
    envelopes_cross_worker: u64 = 0,
};

pub const Counters = struct {
    stanzas_message: Counter = .init(0),
    stanzas_presence: Counter = .init(0),
    stanzas_iq: Counter = .init(0),
    bytes_in: Counter = .init(0),
    bytes_out: Counter = .init(0),
    wakes: Counter = .init(0),
    loop_iterations: Counter = .init(0),
    kevent_events: Counter = .init(0),
    kevent_changes: Counter = .init(0),
    // Appendix C drop reasons counted at their central choke points.
    drop_send_buffer_full: Counter = .init(0),
    drop_send_closed: Counter = .init(0),
    drop_changelist_full: Counter = .init(0),
    drop_no_route: Counter = .init(0),
    loop_hist_us: [HIST_BUCKETS]Counter = @splat(.init(0)),
};

pub var workers: [MAX_WORKERS]Counters = @splat(.{});

/// Set once per worker thread at run() start; null elsewhere, so bumps
/// from producer threads or tests without a bound worker are no-ops.
pub threadlocal var current: ?*Counters = null;

pub fn bind(worker_id: u16) void {
    if (worker_id < MAX_WORKERS) current = &workers[worker_id];
}

pub inline fn get() ?*Counters {
    return current;
}

/// Record one loop iteration's event-processing time (nanoseconds).
pub fn recordIteration(ns: u64) void {
    const c = current orelse return;
    _ = c.loop_iterations.fetchAdd(1, .monotonic);
    const us = ns / 1000;
    const bucket: usize = if (us == 0) 0 else @min(63 - @clz(us), HIST_BUCKETS - 1);
    _ = c.loop_hist_us[bucket].fetchAdd(1, .monotonic);
}

fn read(c: *const Counter) u64 {
    return c.load(.monotonic);
}

/// Log the worker's counters and loop-time histogram. Called from the
/// worker's own EVFILT_SIGNAL handler, so plain relaxed loads suffice.
pub fn dump(worker_id: u16, ext: Externals) void {
    if (worker_id >= MAX_WORKERS) return;
    const c = &workers[worker_id];
    log.info("worker {d} counters: stanzas msg={d} pres={d} iq={d} bytes in={d} out={d} wakes={d}", .{
        worker_id,          read(&c.stanzas_message), read(&c.stanzas_presence), read(&c.stanzas_iq),
        read(&c.bytes_in),  read(&c.bytes_out),       read(&c.wakes),
    });
    log.info("worker {d} loop: iterations={d} kevent events={d} changes={d} envelopes xworker={d}", .{
        worker_id, read(&c.loop_iterations), read(&c.kevent_events), read(&c.kevent_changes), ext.envelopes_cross_worker,
    });
    log.info("worker {d} drops (App. C): send_buf_full={d} send_closed={d} changelist_full={d} no_route={d} ring_full={d} ring_payload={d} room_mailbox={d}", .{
        worker_id,           read(&c.drop_send_buffer_full), read(&c.drop_send_closed), read(&c.drop_changelist_full),
        read(&c.drop_no_route), ext.ring_drops_full,          ext.ring_drops_payload,   ext.room_mailbox_drops,
    });
    var buf: [HIST_BUCKETS * 24]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();
    var first = true;
    for (&c.loop_hist_us, 0..) |*b, k| {
        const n = read(b);
        if (n == 0) continue;
        if (!first) w.writeAll(" ") catch break;
        first = false;
        if (k == 0)
            w.print("<2us:{d}", .{n}) catch break
        else
            w.print("{d}us:{d}", .{ @as(u64, 1) << @intCast(k), n }) catch break;
    }
    log.info("worker {d} loop us histogram (log2 buckets): {s}", .{ worker_id, fbs.getWritten() });
}

test "recordIteration assigns log2 buckets" {
    bind(MAX_WORKERS - 1);
    defer current = null;
    const c = get().?;
    const base_iter = read(&c.loop_iterations);

    recordIteration(0); // <1us -> bucket 0
    recordIteration(1500); // 1us -> bucket 0
    recordIteration(2500); // 2us -> bucket 1
    recordIteration(1_000_000); // 1000us -> bucket 9
    recordIteration(std.math.maxInt(u64)); // saturates at last bucket

    try std.testing.expectEqual(base_iter + 5, read(&c.loop_iterations));
    try std.testing.expectEqual(@as(u64, 2), read(&c.loop_hist_us[0]));
    try std.testing.expectEqual(@as(u64, 1), read(&c.loop_hist_us[1]));
    try std.testing.expectEqual(@as(u64, 1), read(&c.loop_hist_us[9]));
    try std.testing.expectEqual(@as(u64, 1), read(&c.loop_hist_us[HIST_BUCKETS - 1]));
}

test "bind rejects out-of-range worker ids" {
    current = null;
    bind(MAX_WORKERS);
    try std.testing.expect(current == null);
    bind(3);
    try std.testing.expect(get() == &workers[3]);
    current = null;
}
