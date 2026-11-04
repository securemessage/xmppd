//! TimerWheel: lifecycle deadlines on a hierarchical wheel (ADR-8, F2).
//!
//! Four levels of 64 slots at 1 ms ticks (horizon 64^4 ms, about 4.66 h).
//! Entries live in a generational SlotMap, so a cancelled or fired TimerId
//! never cancels a reused entry. Cancel is O(1) unlink; scheduling and
//! expiry order are non-decreasing deadline, FIFO on ties (per-slot chains
//! are appended, expirations are sorted by (deadline, seq)).
//!
//! The owning Loop arms one one-shot EVFILT_TIMER to `nextDeadline` and calls
//! `popExpired` after each wait. `collect` walks only chains whose slot_min
//! can hold a due entry, emits what is due and cascades the rest into the
//! right level, which also refreshes `slot_min` so `nextDeadline` cannot
//! underestimate into a spin.

const std = @import("std");
const Token = @import("token.zig").Token;
const SlotMap = @import("slotmap.zig").SlotMap;

pub const TimerId = Token;
pub const Deadline = struct { timer: TimerId, ctx: Token };

const NIL: u32 = std.math.maxInt(u32);
const timer_entry_kind: u8 = 0x03;

/// Level marker for entries moved to the due list by collect(). Their slot
/// chain is already torn down, so cancel() must not unlink them through
/// lvl/slot/prev/next; it only removes the entry, and popExpired() then
/// skips the stale due-list token.
const due_lvl: u8 = 0xFF;

const LEVELS = 4;
const SLOTS = 64;
const SHIFT = 6; // log2(SLOTS)

const Entry = struct {
    deadline: u64,
    ctx: Token,
    seq: u64,
    prev: u32,
    next: u32,
    lvl: u8,
    slot: u8,
};

pub const TimerWheel = struct {
    entries: SlotMap(Entry),
    heads: [LEVELS][SLOTS]u32,
    tails: [LEVELS][SLOTS]u32,
    occupied: [LEVELS]u64,
    slot_min: [LEVELS][SLOTS]u64,
    due: []TimerId,
    due_len: usize,
    due_pos: usize,
    collected_ms: u64,
    seq: u64,
    cur_ms: u64,
    counters: Counters = .{},

    /// Diagnostics for the collect bound: batches run and chain entries
    /// walked. In steady state scanned stays close to emitted deadlines.
    pub const Counters = struct { collects: u64 = 0, scanned: u64 = 0 };

    /// Owns the entry table (timers_max x 40 B) and the due list; borrows nothing.
    pub fn init(
        self: *TimerWheel,
        gpa: std.mem.Allocator,
        timers_max: u32,
        now_ms: u64,
    ) std.mem.Allocator.Error!void {
        std.debug.assert(timers_max >= 1);
        try self.entries.init(gpa, timers_max, timer_entry_kind);
        errdefer self.entries.deinit(gpa);
        const due = try gpa.alloc(TimerId, timers_max);
        self.* = .{
            .entries = self.entries,
            .heads = undefined,
            .tails = undefined,
            .occupied = .{ 0, 0, 0, 0 },
            .slot_min = undefined,
            .due = due,
            .due_len = 0,
            .due_pos = 0,
            .collected_ms = std.math.maxInt(u64),
            .seq = 0,
            .cur_ms = now_ms,
        };
        for (&self.heads) |*lv| @memset(lv, NIL);
        for (&self.tails) |*lv| @memset(lv, NIL);
        for (&self.slot_min) |*lv| @memset(lv, std.math.maxInt(u64));
    }

    pub fn deinit(self: *TimerWheel, gpa: std.mem.Allocator) void {
        self.entries.deinit(gpa);
        gpa.free(self.due);
        self.* = undefined;
    }

    pub fn schedule(self: *TimerWheel, deadline_ms: u64, ctx: Token) error{TimerTableFull}!TimerId {
        self.seq += 1;
        const token = self.entries.insert(.{
            .deadline = deadline_ms,
            .ctx = ctx,
            .seq = self.seq,
            .prev = NIL,
            .next = NIL,
            .lvl = 0,
            .slot = 0,
        }) catch return error.TimerTableFull;
        self.insertEntry(token.index, deadline_ms);
        return token;
    }

    /// O(1) unlink. False when the id is stale (cancelled or already fired).
    /// True for an entry collected but not yet emitted: the due-list token
    /// goes stale and popExpired() drops it.
    pub fn cancel(self: *TimerWheel, timer: TimerId) bool {
        const e = self.entries.get(timer) orelse return false;
        if (e.lvl != due_lvl) self.unlinkEntry(e);
        _ = self.entries.remove(timer);
        return true;
    }

    /// Earliest armed deadline across the wheel, or null when empty.
    /// `slot_min` only ever underestimates (a cancelled entry leaves a stale
    /// low value), so arming may fire early once; collect() refreshes it.
    pub fn nextDeadline(self: *const TimerWheel) ?u64 {
        var best: u64 = std.math.maxInt(u64);
        for (0..LEVELS) |l| {
            var occ = self.occupied[l];
            while (occ != 0) : (occ &= occ - 1) {
                const s: usize = @intCast(@ctz(occ));
                if (self.slot_min[l][s] < best) best = self.slot_min[l][s];
            }
        }
        if (best == std.math.maxInt(u64)) return null;
        return best;
    }

    /// Collect the due batch once at the start of a wait pass. Entries
    /// scheduled while the batch drains are collected next pass, so one
    /// pass emits a bounded set. A previous batch still draining is kept.
    pub fn collectPass(self: *TimerWheel, now_ms: u64) void {
        if (self.due_pos < self.due_len) return;
        const d = self.nextDeadline() orelse return;
        if (d > now_ms) return;
        self.collect(now_ms);
    }

    /// The next expired entry in deadline order, or null. Lazily cascades the
    /// wheel up to `now_ms` on the first call of each batch.
    pub fn popExpired(self: *TimerWheel, now_ms: u64) ?Deadline {
        // One collect per now_ms: entries scheduled while a batch drains
        // wait for the next pass even when their deadline already passed.
        if (self.due_pos >= self.due_len and self.collected_ms != now_ms)
            self.collect(now_ms);
        while (self.due_pos < self.due_len) {
            const token = self.due[self.due_pos];
            self.due_pos += 1;
            const e = self.entries.get(token) orelse continue; // cancelled while pending
            _ = self.entries.remove(token);
            return .{ .timer = token, .ctx = e.ctx };
        }
        return null;
    }

    /// Emit entries with deadline <= now (sorted below by deadline, FIFO
    /// within a deadline) and cascade the rest. Only chains whose slot_min
    /// says they can contain a due entry are walked: slot_min underestimates
    /// after a cancelled minimum, never overestimates, so a skipped slot
    /// holds nothing due.
    ///
    /// Cost: one collect walks every occupied chain that could hold a due
    /// entry, so the worst batch is O(longest chain), O(timers_max) when all
    /// timers share one chain (a reconnect storm). Amortized cost is ~3
    /// chain entries per fired timer. A stale-low slot_min from a cancelled
    /// minimum costs one full O(chain) rescan that fires nothing; the walk
    /// rebuilds the chain's slot_min, so it is charged once per stale chain,
    /// not once per pass.
    fn collect(self: *TimerWheel, now_ms: u64) void {
        if (now_ms > self.cur_ms) self.cur_ms = now_ms;
        self.collected_ms = now_ms;
        self.due_len = 0;
        self.due_pos = 0;
        self.counters.collects += 1;
        for (0..LEVELS) |l| {
            var occ = self.occupied[l];
            while (occ != 0) : (occ &= occ - 1) {
                const s: usize = @intCast(@ctz(occ));
                if (self.slot_min[l][s] > self.cur_ms) continue;
                var idx = self.heads[l][s];
                self.heads[l][s] = NIL;
                self.tails[l][s] = NIL;
                self.occupied[l] &= ~(@as(u64, 1) << @intCast(s));
                self.slot_min[l][s] = std.math.maxInt(u64);
                while (idx != NIL) {
                    self.counters.scanned += 1;
                    const e = &self.entries.values[idx];
                    const next = e.next;
                    const idx_tok: TimerId = .{
                        .index = idx,
                        .gen = self.entries.gens[idx],
                        .kind = timer_entry_kind,
                    };
                    if (e.deadline <= self.cur_ms) {
                        e.lvl = due_lvl;
                        self.due[self.due_len] = idx_tok;
                        self.due_len += 1;
                    } else {
                        self.insertEntry(idx, e.deadline);
                    }
                    idx = next;
                }
            }
        }
        // Deadline order, FIFO within a deadline.
        const Ctx = struct {
            values: []Entry,
            fn lessThan(values_ctx: @This(), a: TimerId, b: TimerId) bool {
                const ea = values_ctx.values[a.index];
                const eb = values_ctx.values[b.index];
                if (ea.deadline != eb.deadline) return ea.deadline < eb.deadline;
                return ea.seq < eb.seq;
            }
        };
        std.sort.pdq(
            TimerId,
            self.due[0..self.due_len],
            Ctx{ .values = self.entries.values },
            Ctx.lessThan,
        );
    }

    fn levelFor(self: *const TimerWheel, deadline_ms: u64) usize {
        const d = deadline_ms -| self.cur_ms;
        if (d < SLOTS) return 0;
        if (d < SLOTS * SLOTS) return 1;
        if (d < SLOTS * SLOTS * SLOTS) return 2;
        return 3;
    }

    fn slotFor(deadline_ms: u64, lvl: usize) usize {
        return @intCast((deadline_ms >> @intCast(SHIFT * lvl)) & (SLOTS - 1));
    }

    fn insertEntry(self: *TimerWheel, idx: u32, deadline_ms: u64) void {
        const lvl = self.levelFor(deadline_ms);
        const s = slotFor(deadline_ms, lvl);
        const e = &self.entries.values[idx];
        e.lvl = @intCast(lvl);
        e.slot = @intCast(s);
        e.prev = self.tails[lvl][s];
        e.next = NIL;
        if (self.tails[lvl][s] == NIL) {
            self.heads[lvl][s] = idx;
        } else {
            self.entries.values[self.tails[lvl][s]].next = idx;
        }
        self.tails[lvl][s] = idx;
        self.occupied[lvl] |= @as(u64, 1) << @intCast(s);
        if (deadline_ms < self.slot_min[lvl][s]) self.slot_min[lvl][s] = deadline_ms;
    }

    fn unlinkEntry(self: *TimerWheel, e: *Entry) void {
        std.debug.assert(e.lvl != due_lvl and e.lvl < LEVELS);
        const l = e.lvl;
        const s = e.slot;
        if (e.prev == NIL) {
            self.heads[l][s] = e.next;
        } else {
            self.entries.values[e.prev].next = e.next;
        }
        if (e.next == NIL) {
            self.tails[l][s] = e.prev;
        } else {
            self.entries.values[e.next].prev = e.prev;
        }
        if (self.heads[l][s] == NIL) {
            self.occupied[l] &= ~(@as(u64, 1) << @intCast(s));
            self.slot_min[l][s] = std.math.maxInt(u64);
        }
        // slot_min may now underestimate (stale low); collect() refreshes it.
    }
};

// ============================================================================
// Tests
// ============================================================================

test "TimerWheel: expiry order across levels and ties" {
    // Deadlines across wheel levels and one tie emit in deadline order.
    var wheel: TimerWheel = undefined;
    try wheel.init(std.testing.allocator, 16, 1000);
    defer wheel.deinit(std.testing.allocator);

    const far = try wheel.schedule(70000, .{ .index = 3, .gen = 1, .kind = 0xEE });
    const near = try wheel.schedule(1010, .{ .index = 1, .gen = 1, .kind = 0xEE });
    const mid = try wheel.schedule(5000, .{ .index = 2, .gen = 1, .kind = 0xEE });
    const tie = try wheel.schedule(1010, .{ .index = 4, .gen = 1, .kind = 0xEE });

    try std.testing.expectEqual(@as(?u64, 1010), wheel.nextDeadline());
    const d1 = wheel.popExpired(2000).?;
    const d2 = wheel.popExpired(2000).?;
    const d3 = wheel.popExpired(6000).?;
    const d4 = wheel.popExpired(80000).?;
    try std.testing.expect(d1.timer.eql(near));
    try std.testing.expect(d2.timer.eql(tie)); // FIFO tie order
    try std.testing.expect(d3.timer.eql(mid));
    try std.testing.expect(d4.timer.eql(far));
    try std.testing.expect(wheel.popExpired(80000) == null);
}

test "TimerWheel: entries on one slot chain emit in deadline order" {
    // A level-1 slot covers 64 deadlines: schedule the later one first so
    // chain order disagrees with deadline order and only the sort fixes it.
    var wheel: TimerWheel = undefined;
    try wheel.init(std.testing.allocator, 4, 0);
    defer wheel.deinit(std.testing.allocator);

    const late = try wheel.schedule(100, .{ .index = 1, .gen = 1, .kind = 0xEE });
    const early = try wheel.schedule(70, .{ .index = 2, .gen = 1, .kind = 0xEE });

    const d1 = wheel.popExpired(110).?;
    const d2 = wheel.popExpired(110).?;
    try std.testing.expect(d1.timer.eql(early));
    try std.testing.expect(d2.timer.eql(late));
    try std.testing.expect(wheel.popExpired(110) == null);
}

test "TimerWheel: a deadline scheduled while a batch drains emits next collect" {
    // Emission is bounded per pass: a past deadline added mid-drain waits
    // for the next collect instead of extending this one without bound.
    var wheel: TimerWheel = undefined;
    try wheel.init(std.testing.allocator, 4, 0);
    defer wheel.deinit(std.testing.allocator);

    const first = try wheel.schedule(10, .{ .index = 1, .gen = 1, .kind = 0xEE });
    try std.testing.expect(wheel.popExpired(10).?.timer.eql(first));
    try std.testing.expect(wheel.popExpired(10) == null);

    const late = try wheel.schedule(5, .{ .index = 2, .gen = 1, .kind = 0xEE });
    try std.testing.expect(wheel.popExpired(10) == null); // same pass: no collect
    try std.testing.expect(wheel.popExpired(11).?.timer.eql(late));
}

test "TimerWheel: cancel is O(1) and stale ids cannot cancel a reused entry" {
    var wheel: TimerWheel = undefined;
    try wheel.init(std.testing.allocator, 2, 0);
    defer wheel.deinit(std.testing.allocator);

    const a = try wheel.schedule(100, .{ .index = 1, .gen = 1, .kind = 0xEE });
    const b = try wheel.schedule(200, .{ .index = 2, .gen = 1, .kind = 0xEE });
    try std.testing.expect(wheel.cancel(a));
    try std.testing.expect(!wheel.cancel(a)); // already gone
    const c = try wheel.schedule(300, .{ .index = 3, .gen = 1, .kind = 0xEE });
    try std.testing.expect(!wheel.cancel(a)); // stale id, slot may be reused
    try std.testing.expect(wheel.cancel(b));
    try std.testing.expect(wheel.cancel(c));
    try std.testing.expect(wheel.nextDeadline() == null);
}

test "TimerWheel: cancel between collect and emit drops the pending emission" {
    // collect() moves due entries onto the due list; cancelling one before
    // it is emitted must drop it without touching the torn-down slot chain.
    var wheel: TimerWheel = undefined;
    try wheel.init(std.testing.allocator, 8, 0);
    defer wheel.deinit(std.testing.allocator);

    const a = try wheel.schedule(10, .{ .index = 1, .gen = 1, .kind = 0xEE });
    const b = try wheel.schedule(10, .{ .index = 2, .gen = 1, .kind = 0xEE });
    const first = wheel.popExpired(20).?; // collects a and b; a emitted first
    try std.testing.expect(first.timer.eql(a));
    try std.testing.expect(wheel.cancel(b)); // collected, not yet emitted
    try std.testing.expect(wheel.popExpired(20) == null); // b dropped
    try std.testing.expect(!wheel.cancel(b));
}

test "TimerWheel: cancel during fire leaves the slot chain usable" {
    // The collected entry's stale lvl/slot links must not corrupt the slot:
    // a later deadline hashed into the same level-0 slot still fires.
    var wheel: TimerWheel = undefined;
    try wheel.init(std.testing.allocator, 8, 0);
    defer wheel.deinit(std.testing.allocator);

    _ = try wheel.schedule(10, .{ .index = 1, .gen = 1, .kind = 0xEE });
    const b = try wheel.schedule(10, .{ .index = 2, .gen = 1, .kind = 0xEE });
    _ = wheel.popExpired(20); // collect both, emit the first
    try std.testing.expect(wheel.cancel(b)); // cur_ms is now 20
    const c = try wheel.schedule(74, .{ .index = 3, .gen = 1, .kind = 0xEE });
    while (wheel.popExpired(20)) |_| {} // drain the stale due entry for b
    const d = wheel.popExpired(200).?;
    try std.testing.expect(d.timer.eql(c));
    try std.testing.expect(wheel.popExpired(200) == null);
}

test "TimerWheel: TimerTableFull at capacity" {
    var wheel: TimerWheel = undefined;
    try wheel.init(std.testing.allocator, 1, 0);
    defer wheel.deinit(std.testing.allocator);

    _ = try wheel.schedule(10, .{ .index = 1, .gen = 1, .kind = 0xEE });
    const over: TimerId = .{ .index = 2, .gen = 1, .kind = 0xEE };
    try std.testing.expectError(error.TimerTableFull, wheel.schedule(20, over));
}

test "TimerWheel: deadline in the past expires immediately" {
    var wheel: TimerWheel = undefined;
    try wheel.init(std.testing.allocator, 2, 1000);
    defer wheel.deinit(std.testing.allocator);

    const t = try wheel.schedule(500, .{ .index = 1, .gen = 1, .kind = 0xEE });
    const d = wheel.popExpired(1000).?;
    try std.testing.expect(d.timer.eql(t));
}

test "TimerWheel: collect scans only chains that can hold a due entry" {
    // 63 far timers in one level-3 chain and one near timer: popping the
    // near one must walk its chain only, not rescan the whole wheel.
    var wheel: TimerWheel = undefined;
    try wheel.init(std.testing.allocator, 64, 1000);
    defer wheel.deinit(std.testing.allocator);

    for (0..63) |i| {
        _ = try wheel.schedule(10_000_000, .{ .index = @intCast(i + 10), .gen = 1, .kind = 0xEE });
    }
    const near = try wheel.schedule(1005, .{ .index = 1, .gen = 1, .kind = 0xEE });

    const d = wheel.popExpired(1005).?;
    try std.testing.expect(d.timer.eql(near));
    try std.testing.expectEqual(@as(u64, 1), wheel.counters.scanned);
    try std.testing.expect(wheel.popExpired(1005) == null);

    // The far timers still fire at their own deadline; scanning them then
    // walks their single chain.
    var fired: usize = 0;
    while (wheel.popExpired(10_000_000)) |_| fired += 1;
    try std.testing.expectEqual(@as(usize, 63), fired);
}
