//! Detached-session SM expiry wheel (C11).
//!
//! One intrusive doubly-linked list per one-second slot. Insert, unlink and
//! expiry are allocation-free; the wheel itself is worker-local state owned
//! by the single loop thread, so no locking exists or is needed. The worker
//! stages a single one-shot EVFILT_TIMER at `nextDeadline()` and re-arms it
//! after every mutation, replacing the old 30 s periodic sweep of the whole
//! session table: the loop sleeps until the earliest deadline and expiry
//! costs O(due), not O(sessions).
//!
//! Invariants:
//! - Only detached sessions are linked, each at most once
//!   (`Session.sm_expiry_linked` guards insert and unlink).
//! - Every linked deadline is strictly newer than `cursor`: deadlines are
//!   stamped at insert time and `cursor` only advances to past `now`
//!   values, so `expireDue` covering `(cursor, now]` always reaches a
//!   due entry's bucket even after a delayed timer turn.
//! - Bucket lists are sorted by deadline, so a bucket may hold deadlines
//!   a full revolution apart (idle wheel, stalled loop); the head is the
//!   bucket's earliest and `scanMin` is exact regardless of `cursor`.
//! - `expireDue` still checks each entry's real deadline: a session linked
//!   while a drain was running can sit ahead of its tick's due entries and
//!   must not be destroyed early.

const std = @import("std");
const sm_state = @import("sm_state.zig");
const Session = @import("session.zig").Session;

/// One slot per second. Exceeds the longest SM deadline, so every linked
/// entry fits a single revolution and bucket collisions between different
/// deadlines cannot happen among legitimately inserted entries.
pub const SLOT_COUNT: usize = 512;

comptime {
    std.debug.assert(SLOT_COUNT > sm_state.DEFAULT_RESUME_TIMEOUT);
}

pub const Wheel = struct {
    /// Bucket heads, indexed by `deadline mod SLOT_COUNT`. Each bucket's
    /// list is sorted by deadline, so the head is always the bucket's
    /// earliest live deadline even when entries a full revolution apart
    /// share a slot after a delayed timer turn.
    buckets: [SLOT_COUNT]?*Session = .{null} ** SLOT_COUNT,
    /// Newest second already drained. Scans cover `(cursor, now]`.
    cursor: i64 = 0,
    /// Number of linked sessions.
    count: usize = 0,
    /// Earliest linked deadline; meaningless while count == 0. The worker
    /// arms its one-shot timer at this value.
    min_deadline: i64 = 0,

    /// Test instrumentation: bucket heads probed by scanMin, and list
    /// nodes visited by any wheel scan (expireDue's drain is the only
    /// legitimate node walk). Per-wheel fields, not globals: every worker
    /// owns its own wheel, so shared counters would race across loops.
    scan_bucket_probes: usize = 0,
    scan_node_visits: usize = 0,

    fn bucketIndex(deadline: i64) usize {
        return @intCast(@mod(deadline, SLOT_COUNT));
    }

    /// The deadline the worker should arm, or null while the wheel is empty.
    pub fn nextDeadline(self: *const Wheel) ?i64 {
        if (self.count == 0) return null;
        return self.min_deadline;
    }

    /// Link a session at `deadline` (detach time + resume timeout).
    /// Entries a multiple of SLOT_COUNT apart share a bucket, which a
    /// stalled or just-idle wheel can legitimately produce; the sorted
    /// insert keeps the head at the bucket's earliest deadline.
    pub fn insert(self: *Wheel, session: *Session, deadline: i64) void {
        std.debug.assert(!session.sm_expiry_linked);
        const b = bucketIndex(deadline);
        var prev: ?*Session = null;
        var node = self.buckets[b];
        while (node) |entry| {
            if (entry.sm_expiry_deadline > deadline) break;
            prev = entry;
            node = entry.sm_expiry_next;
        }
        session.sm_expiry_deadline = deadline;
        session.sm_expiry_prev = prev;
        session.sm_expiry_next = node;
        if (node) |entry| entry.sm_expiry_prev = session;
        if (prev) |entry| {
            entry.sm_expiry_next = session;
        } else {
            self.buckets[b] = session;
        }
        session.sm_expiry_linked = true;
        self.count += 1;
        if (self.count == 1 or deadline < self.min_deadline) {
            self.min_deadline = deadline;
        }
    }

    /// Remove a session if linked. Returns whether a link was removed so the
    /// caller can mark the timer arm stale; unlinked sessions are a no-op,
    /// which keeps teardown paths unconditional.
    pub fn unlink(self: *Wheel, session: *Session) bool {
        if (!session.sm_expiry_linked) return false;
        const removed_min = session.sm_expiry_deadline <= self.min_deadline;
        self.unlinkImpl(session);
        if (removed_min and self.count > 0) self.min_deadline = self.scanMin();
        return true;
    }

    /// Invoke `callback(ctx, session)` for every linked session whose
    /// deadline has passed. Scans the elapsed tick range `(cursor, now]`,
    /// clamped to one revolution; a full revolution reaches every bucket, so
    /// a loop that overslept the whole wheel still drains everything due.
    /// Each entry's real deadline is checked: an insert that landed on an
    /// unscanned bucket during the drain itself is never due and stays
    /// linked. The next link is captured before the callback runs because
    /// the callback owns the session afterwards (unlink, destroy).
    pub fn expireDue(self: *Wheel, now: i64, ctx: anytype, callback: anytype) void {
        var steps = now - self.cursor;
        if (steps > 0) {
            if (steps > SLOT_COUNT) steps = SLOT_COUNT;
            var i: i64 = 0;
            while (i < steps) : (i += 1) {
                const b = bucketIndex(self.cursor + i + 1);
                var node = self.buckets[b];
                while (node) |session| {
                    self.scan_node_visits += 1;
                    const next = session.sm_expiry_next;
                    if (session.sm_expiry_deadline <= now) {
                        self.unlinkImpl(session);
                        callback(ctx, session);
                    }
                    node = next;
                }
            }
            self.cursor = now;
        }
        if (self.count == 0) {
            self.min_deadline = 0;
        } else {
            self.min_deadline = self.scanMin();
        }
    }

    fn unlinkImpl(self: *Wheel, session: *Session) void {
        const b = bucketIndex(session.sm_expiry_deadline);
        if (session.sm_expiry_prev) |prev| {
            prev.sm_expiry_next = session.sm_expiry_next;
        } else {
            self.buckets[b] = session.sm_expiry_next;
        }
        if (session.sm_expiry_next) |next| next.sm_expiry_prev = session.sm_expiry_prev;
        session.sm_expiry_prev = null;
        session.sm_expiry_next = null;
        session.sm_expiry_linked = false;
        self.count -= 1;
    }

    /// Earliest linked deadline: the absolute minimum over the SLOT_COUNT
    /// bucket heads. Heads carry each bucket's earliest deadline, and the
    /// global minimum does not depend on where the cursor sits, so a min
    /// recompute is exact after an idle wheel or a delayed timer turn
    /// whose live deadlines straddle a bucket wrap. Head checks only, no
    /// node walk: O(buckets), never O(sessions).
    fn scanMin(self: *Wheel) i64 {
        std.debug.assert(self.count > 0);
        var min: i64 = std.math.maxInt(i64);
        for (self.buckets) |head| {
            self.scan_bucket_probes += 1;
            if (head) |entry| {
                if (entry.sm_expiry_deadline < min) min = entry.sm_expiry_deadline;
            }
        }
        std.debug.assert(min != std.math.maxInt(i64));
        return min;
    }
};

fn testSession(allocator: std.mem.Allocator, id: usize) !*Session {
    const session = try allocator.create(Session);
    session.init(-1, id, "localhost", false, allocator);
    return session;
}

fn freeSession(allocator: std.mem.Allocator, session: *Session) void {
    session.deinit();
    allocator.destroy(session);
}

test "wheel: insert links at the deadline bucket and tracks the min" {
    const allocator = std.testing.allocator;
    var wheel: Wheel = .{};
    const s1 = try testSession(allocator, 1);
    defer freeSession(allocator, s1);
    const s2 = try testSession(allocator, 2);
    defer freeSession(allocator, s2);

    wheel.insert(s1, 1000);
    wheel.insert(s2, 1200);
    try std.testing.expectEqual(@as(usize, 2), wheel.count);
    try std.testing.expectEqual(@as(?i64, 1000), wheel.nextDeadline());
    try std.testing.expect(s1.sm_expiry_linked);
    try std.testing.expect(s2.sm_expiry_linked);

    // Removing the min re-arms at the next earliest deadline.
    try std.testing.expect(wheel.unlink(s1));
    try std.testing.expectEqual(@as(?i64, 1200), wheel.nextDeadline());
    try std.testing.expect(!s1.sm_expiry_linked);
    // Guarded: a second unlink is a no-op.
    try std.testing.expect(!wheel.unlink(s1));
    try std.testing.expectEqual(@as(usize, 1), wheel.count);

    try std.testing.expect(wheel.unlink(s2));
    try std.testing.expectEqual(@as(?i64, null), wheel.nextDeadline());
}

test "wheel: expireDue drains due entries once, leaves non-due linked" {
    const allocator = std.testing.allocator;
    var wheel: Wheel = .{};
    const s1 = try testSession(allocator, 1);
    defer freeSession(allocator, s1);
    const s2 = try testSession(allocator, 2);
    defer freeSession(allocator, s2);

    wheel.insert(s1, 1000);
    wheel.insert(s2, 1100);

    const Ctx = struct {
        fired: usize = 0,
        last: ?*Session = null,
    };
    const cb = struct {
        fn run(ctx: *Ctx, session: *Session) void {
            ctx.fired += 1;
            ctx.last = session;
        }
    }.run;

    var ctx: Ctx = .{};
    // Before the deadline nothing fires and the cursor advances.
    wheel.expireDue(999, &ctx, cb);
    try std.testing.expectEqual(@as(usize, 0), ctx.fired);
    try std.testing.expectEqual(@as(usize, 2), wheel.count);

    // At exactly the deadline the entry drains once.
    wheel.expireDue(1000, &ctx, cb);
    try std.testing.expectEqual(@as(usize, 1), ctx.fired);
    try std.testing.expect(ctx.last == s1);
    try std.testing.expect(!s1.sm_expiry_linked);
    try std.testing.expect(s2.sm_expiry_linked);
    try std.testing.expectEqual(@as(?i64, 1100), wheel.nextDeadline());

    // A second drain at the same instant does not refire.
    wheel.expireDue(1000, &ctx, cb);
    try std.testing.expectEqual(@as(usize, 1), ctx.fired);

    // Oversleeping the whole wheel still drains what is due.
    wheel.expireDue(1000 + 2 * SLOT_COUNT, &ctx, cb);
    try std.testing.expectEqual(@as(usize, 2), ctx.fired);
    try std.testing.expect(ctx.last == s2);
    try std.testing.expectEqual(@as(?i64, null), wheel.nextDeadline());
}

test "wheel: callback may destroy the expired session" {
    const allocator = std.testing.allocator;
    var wheel: Wheel = .{};
    const s1 = try testSession(allocator, 1);
    const s2 = try testSession(allocator, 2);
    defer freeSession(allocator, s2);

    wheel.insert(s1, 1000);
    wheel.insert(s2, 1001);

    const Ctx = struct {
        allocator: std.mem.Allocator,
        freed: usize = 0,
    };
    const cb = struct {
        fn run(ctx: *Ctx, session: *Session) void {
            freeSession(ctx.allocator, session);
            ctx.freed += 1;
        }
    }.run;

    var ctx: Ctx = .{ .allocator = allocator };
    wheel.expireDue(1000, &ctx, cb);
    // s1 was freed inside the callback; the drain kept going from the
    // captured next link and left non-due s2 linked.
    try std.testing.expectEqual(@as(usize, 1), ctx.freed);
    try std.testing.expect(s2.sm_expiry_linked);
    try std.testing.expectEqual(@as(?i64, 1001), wheel.nextDeadline());
}

test "wheel: scanMin finds the earliest bucket without visiting nodes" {
    const allocator = std.testing.allocator;
    var wheel: Wheel = .{};

    // N sessions spread across one revolution, linked deadlines all in
    // (cursor, cursor + SLOT_COUNT]: recomputing the minimum is a bucket
    // scan, never a node walk (scan_node_visits stays 0). Deadlines wrap
    // the bucket index so the scan wraps too.
    wheel.cursor = 500;
    const n = 64;
    var sessions: [n]*Session = undefined;
    for (&sessions, 0..) |*s, i| {
        s.* = try testSession(allocator, i + 1);
        wheel.insert(s.*, 501 + @as(i64, @intCast(i)));
    }
    defer for (sessions) |s| freeSession(allocator, s);
    try std.testing.expectEqual(@as(usize, n), wheel.count);

    // Unlinking the current minimum recomputes via scanMin.
    wheel.scan_bucket_probes = 0;
    wheel.scan_node_visits = 0;
    try std.testing.expect(wheel.unlink(sessions[0]));
    try std.testing.expectEqual(@as(?i64, 502), wheel.nextDeadline());
    try std.testing.expectEqual(@as(usize, 0), wheel.scan_node_visits);
    try std.testing.expect(wheel.scan_bucket_probes <= SLOT_COUNT);

    // Unlinking a non-minimum entry does not rescan at all.
    wheel.scan_bucket_probes = 0;
    try std.testing.expect(wheel.unlink(sessions[63]));
    try std.testing.expectEqual(@as(?i64, 502), wheel.nextDeadline());
    try std.testing.expectEqual(@as(usize, 0), wheel.scan_bucket_probes);

    // Expiry draining to a later bucket still lands on the earliest
    // remaining deadline with no node walk.
    const Ctx = struct {};
    const cb = struct {
        fn run(_: *Ctx, _: *Session) void {}
    }.run;
    var ctx: Ctx = .{};
    wheel.scan_node_visits = 0;
    wheel.expireDue(510, &ctx, cb);
    try std.testing.expectEqual(@as(?i64, 511), wheel.nextDeadline());
    // The drain itself walked exactly the nine due nodes (502..510); the
    // scanMin recompute it triggers added no node visits on top.
    try std.testing.expectEqual(@as(usize, 9), wheel.scan_node_visits);
}

test "wheel: scan counters live on the wheel instance, not shared" {
    // Each worker owns its wheel on its loop thread; module-global
    // counters would be a cross-worker data race. The decl-level check
    // fails if the counters ever move back to file scope.
    const wheel_mod = @import("sm_wheel.zig");
    try std.testing.expect(!@hasDecl(wheel_mod, "scan_bucket_probes"));
    try std.testing.expect(!@hasDecl(wheel_mod, "scan_node_visits"));

    const allocator = std.testing.allocator;
    var wheel_a: Wheel = .{};
    var wheel_b: Wheel = .{};
    var sessions_a: [3]*Session = undefined;
    var sessions_b: [2]*Session = undefined;
    for (&sessions_a, 0..) |*s, i| s.* = try testSession(allocator, i + 1);
    defer for (sessions_a) |s| freeSession(allocator, s);
    for (&sessions_b, 0..) |*s, i| s.* = try testSession(allocator, i + 10);
    defer for (sessions_b) |s| freeSession(allocator, s);

    for (sessions_a, 0..) |s, i| wheel_a.insert(s, 100 + @as(i64, @intCast(i)));
    for (sessions_b, 0..) |s, i| wheel_b.insert(s, 100 + @as(i64, @intCast(i)));

    // A min-unlink rescan accounts to the scanning wheel only.
    try std.testing.expect(wheel_a.unlink(sessions_a[0]));
    try std.testing.expect(wheel_a.scan_bucket_probes > 0);
    try std.testing.expectEqual(@as(usize, 0), wheel_b.scan_bucket_probes);
    try std.testing.expect(wheel_b.unlink(sessions_b[0]));
    try std.testing.expect(wheel_b.scan_bucket_probes > 0);
}

test "wheel: min removal before the first expiry is exact across a wrap" {
    const allocator = std.testing.allocator;
    var wheel: Wheel = .{};

    // Cursor has never advanced (startup or a long idle): live deadlines
    // sit far ahead of it and straddle the bucket wrap. A cyclic scan
    // from cursor + 1 would meet the wrapped buckets first and arm the
    // wrong expiry; the absolute minimum is exact.
    const s1 = try testSession(allocator, 1);
    defer freeSession(allocator, s1);
    const s2 = try testSession(allocator, 2);
    defer freeSession(allocator, s2);
    const s3 = try testSession(allocator, 3);
    defer freeSession(allocator, s3);

    wheel.insert(s1, 5100); // bucket 492
    wheel.insert(s2, 5110); // bucket 502
    wheel.insert(s3, 5200); // bucket 80
    try std.testing.expectEqual(@as(?i64, 5100), wheel.nextDeadline());

    try std.testing.expect(wheel.unlink(s1));
    try std.testing.expectEqual(@as(?i64, 5110), wheel.nextDeadline());

    try std.testing.expect(wheel.unlink(s2));
    try std.testing.expectEqual(@as(?i64, 5200), wheel.nextDeadline());
}

test "wheel: min removal after an idle period stays exact" {
    const allocator = std.testing.allocator;
    var wheel: Wheel = .{};

    const Ctx = struct {};
    const cb = struct {
        fn run(_: *Ctx, _: *Session) void {}
    }.run;
    var ctx: Ctx = .{};

    // An idle wheel still turns its timer on unrelated work and leaves
    // the cursor far in the past of the next detach burst.
    wheel.expireDue(5000, &ctx, cb);
    try std.testing.expectEqual(@as(i64, 5000), wheel.cursor);
    try std.testing.expectEqual(@as(?i64, null), wheel.nextDeadline());

    const s1 = try testSession(allocator, 1);
    defer freeSession(allocator, s1);
    const s2 = try testSession(allocator, 2);
    defer freeSession(allocator, s2);
    const s3 = try testSession(allocator, 3);
    defer freeSession(allocator, s3);

    wheel.insert(s1, 5100); // bucket 492
    wheel.insert(s2, 5200); // bucket 80
    wheel.insert(s3, 5220); // bucket 100
    try std.testing.expectEqual(@as(?i64, 5100), wheel.nextDeadline());

    try std.testing.expect(wheel.unlink(s1));
    try std.testing.expectEqual(@as(?i64, 5200), wheel.nextDeadline());

    // All three are due by 6000; the clamped revolution still reaches
    // every bucket and drains them.
    var fired: usize = 0;
    const Ctx2 = struct {
        fired: *usize,
    };
    const cb2 = struct {
        fn run(c: *Ctx2, _: *Session) void {
            c.fired.* += 1;
        }
    }.run;
    var ctx2: Ctx2 = .{ .fired = &fired };
    wheel.expireDue(6000, &ctx2, cb2);
    try std.testing.expectEqual(@as(usize, 2), fired);
    try std.testing.expectEqual(@as(?i64, null), wheel.nextDeadline());
}

test "wheel: deadlines a revolution apart share a bucket and stay ordered" {
    const allocator = std.testing.allocator;
    var wheel: Wheel = .{};

    // A delayed timer turn can legitimately hold deadlines SLOT_COUNT
    // apart: the earlier one goes overdue before the later inserts. Same
    // bucket, sorted list, earliest at the head.
    const s1 = try testSession(allocator, 1);
    defer freeSession(allocator, s1);
    const s2 = try testSession(allocator, 2);
    defer freeSession(allocator, s2);

    wheel.cursor = 5000;
    wheel.insert(s1, 5100); // bucket 492
    wheel.insert(s2, 5100 + SLOT_COUNT); // same bucket, a revolution later
    try std.testing.expectEqual(@as(usize, 2), wheel.count);
    try std.testing.expectEqual(@as(?i64, 5100), wheel.nextDeadline());

    const Ctx = struct {
        fired: usize = 0,
        last: ?*Session = null,
    };
    const cb = struct {
        fn run(c: *Ctx, session: *Session) void {
            c.fired += 1;
            c.last = session;
        }
    }.run;
    var ctx: Ctx = .{};

    // Only the earlier deadline drains at its tick; the revolution-later
    // entry in the same bucket stays linked.
    wheel.expireDue(5100, &ctx, cb);
    try std.testing.expectEqual(@as(usize, 1), ctx.fired);
    try std.testing.expect(ctx.last == s1);
    try std.testing.expect(!s1.sm_expiry_linked);
    try std.testing.expect(s2.sm_expiry_linked);
    try std.testing.expectEqual(@as(?i64, 5100 + SLOT_COUNT), wheel.nextDeadline());

    wheel.expireDue(5100 + SLOT_COUNT, &ctx, cb);
    try std.testing.expectEqual(@as(usize, 2), ctx.fired);
    try std.testing.expectEqual(@as(?i64, null), wheel.nextDeadline());
}
