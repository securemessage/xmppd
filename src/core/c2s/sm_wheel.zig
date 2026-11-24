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
//! - Deadlines live within one revolution of `now` (resume timeout fits in
//!   SLOT_COUNT), so entries in one bucket all share its tick's deadline.
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
    /// Bucket heads, indexed by `deadline mod SLOT_COUNT`.
    buckets: [SLOT_COUNT]?*Session = .{null} ** SLOT_COUNT,
    /// Newest second already drained. Scans cover `(cursor, now]`.
    cursor: i64 = 0,
    /// Number of linked sessions.
    count: usize = 0,
    /// Earliest linked deadline; meaningless while count == 0. The worker
    /// arms its one-shot timer at this value.
    min_deadline: i64 = 0,

    fn bucketIndex(deadline: i64) usize {
        return @intCast(@mod(deadline, SLOT_COUNT));
    }

    /// The deadline the worker should arm, or null while the wheel is empty.
    pub fn nextDeadline(self: *const Wheel) ?i64 {
        if (self.count == 0) return null;
        return self.min_deadline;
    }

    /// Link a session at `deadline` (detach time + resume timeout).
    pub fn insert(self: *Wheel, session: *Session, deadline: i64) void {
        std.debug.assert(!session.sm_expiry_linked);
        const b = bucketIndex(deadline);
        // One bucket holds one deadline: linked deadlines all fall within
        // one revolution of the cursor, so a bucket head stamped with a
        // different deadline would mean the wheel fell behind by more
        // than SLOT_COUNT seconds.
        if (self.buckets[b]) |head| {
            std.debug.assert(head.sm_expiry_deadline == deadline);
        }
        session.sm_expiry_deadline = deadline;
        session.sm_expiry_prev = null;
        session.sm_expiry_next = self.buckets[b];
        if (self.buckets[b]) |head| head.sm_expiry_prev = session;
        self.buckets[b] = session;
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
                    scan_node_visits += 1;
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

    /// Earliest linked deadline. Linked deadlines all fall inside the open
    /// revolution `(cursor, cursor + SLOT_COUNT]` and one bucket holds one
    /// deadline, so the minimum is the first non-empty bucket scanning
    /// forward from `cursor + 1`: at most SLOT_COUNT head checks and no
    /// node walk — O(buckets), never O(sessions).
    fn scanMin(self: *const Wheel) i64 {
        var i: usize = 1;
        while (i <= SLOT_COUNT) : (i += 1) {
            scan_bucket_probes += 1;
            const b = bucketIndex(self.cursor + @as(i64, @intCast(i)));
            if (self.buckets[b]) |head| return head.sm_expiry_deadline;
        }
        unreachable; // count > 0 guarantees a linked entry within the revolution
    }
};

/// Test instrumentation: bucket heads probed by scanMin, and list nodes
/// visited by any wheel scan (expireDue's drain is the only legitimate
/// node walk). A scanMin recompute is head checks only, so a test that
/// snapshots the node counter around one must see no increase.
pub var scan_bucket_probes: usize = 0;
pub var scan_node_visits: usize = 0;

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
    scan_bucket_probes = 0;
    scan_node_visits = 0;
    try std.testing.expect(wheel.unlink(sessions[0]));
    try std.testing.expectEqual(@as(?i64, 502), wheel.nextDeadline());
    try std.testing.expectEqual(@as(usize, 0), scan_node_visits);
    try std.testing.expect(scan_bucket_probes <= SLOT_COUNT);

    // Unlinking a non-minimum entry does not rescan at all.
    scan_bucket_probes = 0;
    try std.testing.expect(wheel.unlink(sessions[63]));
    try std.testing.expectEqual(@as(?i64, 502), wheel.nextDeadline());
    try std.testing.expectEqual(@as(usize, 0), scan_bucket_probes);

    // Expiry draining to a later bucket still lands on the earliest
    // remaining deadline with no node walk.
    const Ctx = struct {};
    const cb = struct {
        fn run(_: *Ctx, _: *Session) void {}
    }.run;
    var ctx: Ctx = .{};
    scan_node_visits = 0;
    wheel.expireDue(510, &ctx, cb);
    try std.testing.expectEqual(@as(?i64, 511), wheel.nextDeadline());
    // The drain itself walked exactly the nine due nodes (502..510); the
    // scanMin recompute it triggers added no node visits on top.
    try std.testing.expectEqual(@as(usize, 9), scan_node_visits);
}
