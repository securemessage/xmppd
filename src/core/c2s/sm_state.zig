//! # XEP-0198: Stream Management — Resume State
//!
//! Manages the state required for XEP-0198 session resumption:
//! - `SmUnackedQueue` — bounded ring buffer of outbound stanzas awaiting client acknowledgment
//! - SM-ID generation and encoding
//!
//! ## Design
//!
//! When a client enables SM with `resume='true'`, the server generates a unique SM-ID
//! and begins tracking outbound stanzas in a queue. On abnormal disconnect, the session
//! is "detached" (connection resources freed, state preserved). On reconnection, the
//! client presents the SM-ID and its last-received `h` value; the server replays
//! unacknowledged stanzas and the session continues without full re-establishment.
//!
//! ## SM-ID Format
//!
//! 16 bytes: [2 bytes worker_id big-endian][14 bytes random]
//! Hex-encoded to 32 characters. The worker_id prefix enables O(1) routing of
//! resume requests to the correct worker in multi-threaded deployments.

const std = @import("std");
const delivery_queue = @import("delivery_queue");

const log = std.log.scoped(.sm);

/// Maximum number of unacknowledged stanzas buffered per session.
/// Each entry is a reference on a shared refcounted blob (ADR-3). If the
/// queue is full, the oldest unacked stanza is discarded to bound memory
/// usage, and `push()` reports the eviction (T178): XEP-0198 has no gap
/// signaling, so the session must be failed rather than silently losing
/// stanzas.
pub const UNACKED_CAPACITY: u32 = 256;

/// Result of `SmUnackedQueue.push()` and `pushBlob()`.
pub const PushResult = enum {
    /// Stanza buffered without eviction.
    pushed,
    /// Queue was full: the oldest stanza was evicted to make room.
    /// The caller must fail the session (live: resource-constraint stream
    /// error; detached: destroy) because the client can no longer be told
    /// the truth about what was delivered.
    overflow,
    /// Blob production for the stanza copy failed (budget or allocation),
    /// or a detached queue could not move the shared blob's charge onto a
    /// full SM retention budget: stanza not buffered.
    alloc_failed,
};

/// Unacked-queue depth at which the server sends the client an <r/> ack
/// request (T178). XEP-0198 only obliges clients to ack on request, so
/// without this a compliant client may never ack and the overflow policy
/// would kill innocent busy sessions. Half of capacity leaves headroom for
/// one full burst between request and answer.
pub const SM_R_THRESHOLD: u32 = UNACKED_CAPACITY / 2;

/// Default session resume timeout in seconds.
pub const DEFAULT_RESUME_TIMEOUT: u32 = 300;

/// SM-ID length in hex characters (16 bytes = 32 hex chars).
pub const SM_ID_HEX_LEN: usize = 32;

/// Bounded ring buffer of outbound stanzas sent to the client but not yet
/// acknowledged via `<a h='N'/>`. Used to replay stanzas on session resume.
/// Entries are references on shared refcounted blobs (ADR-3), so a stanza
/// that arrived through the delivery ring or a resume handoff is stored
/// once, not copied per recipient.
pub const SmUnackedQueue = struct {
    /// Ring buffer storage: one blob reference per entry.
    entries: [UNACKED_CAPACITY]?*delivery_queue.Blob = .{null} ** UNACKED_CAPACITY,
    /// Index of the oldest unacked entry (next to dequeue on ack).
    head: u32 = 0,
    /// Index of the next write position.
    tail: u32 = 0,
    /// Number of entries currently in the queue.
    count: u32 = 0,
    /// The sm_out_seq value corresponding to the entry at `head`.
    /// This is the sequence number of the oldest unacked stanza.
    base_seq: u32 = 1,
    /// Highest `h` ever acknowledged on this queue (S24). Sequences wrap at
    /// 2^32, so a report counts as forward only when it is within 2^31 ahead
    /// of last_h; a duplicate or backwards report discards nothing.
    last_h: u32 = 0,
    /// Producer budget charged for copies the queue makes itself. While
    /// the session is live this is the owning worker's delivery budget;
    /// `retainOn` points it at the worker's SM retention budget on
    /// detach.
    budget: *delivery_queue.BlobBudget,
    /// True while the queue belongs to a detached session: every new
    /// entry must charge the retention budget, so `pushBlob` moves each
    /// shared blob's charge onto `budget` before retaining it and a full
    /// budget reports `.alloc_failed` (T-265C5A0E).
    detached: bool = false,

    pub fn init(budget: *delivery_queue.BlobBudget) SmUnackedQueue {
        return .{ .budget = budget };
    }

    pub fn deinit(self: *SmUnackedQueue) void {
        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            const idx = (self.head + i) % UNACKED_CAPACITY;
            if (self.entries[idx]) |blob| {
                blob.release();
                self.entries[idx] = null;
            }
        }
        self.count = 0;
        self.head = 0;
        self.tail = 0;
    }

    /// Make room for one entry. Reports `.overflow` when the oldest unacked
    /// stanza had to be evicted (T178): the caller is expected to fail the
    /// session rather than continue with a silently corrupted replay queue.
    fn evictForPush(self: *SmUnackedQueue) PushResult {
        if (self.count != UNACKED_CAPACITY) return .pushed;
        self.discardHead();
        return .overflow;
    }

    /// Copy `stanza` into a fresh blob on the queue's budget and buffer the
    /// reference. Production failures (budget cap, oversize, allocation)
    /// report `.alloc_failed`, the same fail-closed class as before (T178).
    pub fn push(self: *SmUnackedQueue, stanza: []const u8) PushResult {
        const blob = self.budget.produce(stanza) catch {
            log.warn("SM unacked queue: blob refused ({d} bytes)", .{stanza.len});
            return .alloc_failed;
        };
        const result = self.evictForPush();
        self.entries[self.tail] = blob;
        self.tail = (self.tail + 1) % UNACKED_CAPACITY;
        self.count += 1;
        return result;
    }

    /// Buffer a reference on an existing blob instead of copying (C11):
    /// ring-slot payloads and handoff bundles share the one allocation.
    /// A detached queue first moves the blob's charge onto the SM
    /// retention budget, reporting `.alloc_failed` when that budget is
    /// full; a live queue cannot fail beyond the bounded eviction, which
    /// reports `.overflow`.
    pub fn pushBlob(self: *SmUnackedQueue, blob: *delivery_queue.Blob) PushResult {
        const result = self.evictForPush();
        if (self.detached and !blob.transferChargeTo(self.budget)) return .alloc_failed;
        blob.addRef();
        self.entries[self.tail] = blob;
        self.tail = (self.tail + 1) % UNACKED_CAPACITY;
        self.count += 1;
        return result;
    }

    /// Outcome of an <a/> or <resume/> handled-count report (S24).
    pub const AckResult = enum {
        ok,
        /// h claims more handled stanzas than were ever sent; nothing was
        /// discarded and last_h was not touched. XEP-0198 §3: the stream
        /// must fail with handled-count-too-high.
        too_high,
        /// h moved backwards from the previous report; nothing was
        /// discarded. On <resume/> this must fail the resume.
        backwards,
    };

    /// Acknowledge stanzas up to and including sequence number `h`.
    /// Discards all entries with sequence ≤ h.
    pub fn ack(self: *SmUnackedQueue, h: u32) AckResult {
        // A duplicate or backwards report (client bug, replayed SM-ID, or a
        // hostile `<resume h='0'/>` after `<a h='5'/>`) must never discard:
        // the naive `h -% (base_seq -% 1)` wraps above count and discardAll()
        // would empty the replay queue (S24).
        const delta = h -% self.last_h;
        if (delta == 0) return .ok;
        if (delta >= 0x8000_0000) {
            log.warn("SM ack moved backwards (h={d}, last_h={d}); ignoring", .{ h, self.last_h });
            return .backwards;
        }

        // h is the client's report of total stanzas received.
        // base_seq is the sequence of our oldest buffered stanza.
        // Stanzas to discard = h - (base_seq - 1)
        const acked_count = h -% (self.base_seq -% 1);

        // A client reporting more handled stanzas than were sent is lying
        // or out of sync. Emptying the queue and storing the bogus last_h
        // would ignore every later legitimate ack and kill the session at
        // overflow (S24); report it and change nothing instead.
        if (acked_count > self.count) {
            log.warn("SM ack too high (h={d}, {d} unacked from seq {d}); not discarding", .{ h, self.count, self.base_seq });
            return .too_high;
        }

        self.last_h = h;
        if (acked_count == 0) return .ok;

        var i: u32 = 0;
        while (i < acked_count) : (i += 1) {
            self.discardHead();
        }
        return .ok;
    }

    /// Return all unacked stanza entries for replay.
    /// Caller must NOT release the returned blobs; they remain owned by the queue.
    pub fn getUnacked(self: *const SmUnackedQueue) UnackedIterator {
        return .{
            .queue = self,
            .pos = 0,
        };
    }

    /// Number of stanzas currently buffered.
    pub fn pending(self: *const SmUnackedQueue) u32 {
        return self.count;
    }

    /// Detach-time retention move (T-265C5A0E): transfer every retained
    /// blob's charge onto `budget` — the worker's dedicated SM retention
    /// budget — and mark the queue detached so later pushes charge there
    /// too. A detached queue may hold blobs from several producers; each
    /// charge moves individually. Returns false on the first refusal,
    /// leaving earlier transfers in place: the caller then fails the
    /// session so the whole queue reaches a counted drain instead of
    /// pinning producer budgets for the resume tail.
    pub fn retainOn(self: *SmUnackedQueue, budget: *delivery_queue.BlobBudget) bool {
        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            const idx = (self.head + i) % UNACKED_CAPACITY;
            if (self.entries[idx]) |blob| {
                if (!blob.transferChargeTo(budget)) return false;
            }
        }
        self.budget = budget;
        self.detached = true;
        return true;
    }

    fn discardHead(self: *SmUnackedQueue) void {
        if (self.count == 0) return;
        if (self.entries[self.head]) |blob| {
            blob.release();
            self.entries[self.head] = null;
        }
        self.head = (self.head + 1) % UNACKED_CAPACITY;
        self.count -= 1;
        self.base_seq +%= 1;
    }

    fn discardAll(self: *SmUnackedQueue) void {
        while (self.count > 0) {
            self.discardHead();
        }
    }
};

/// Iterator over unacked stanza entries. Yields borrowed blob references;
/// callers read `blob.bytes()` and must not release them.
pub const UnackedIterator = struct {
    queue: *const SmUnackedQueue,
    pos: u32,

    pub fn next(self: *UnackedIterator) ?*delivery_queue.Blob {
        if (self.pos >= self.queue.count) return null;
        const idx = (self.queue.head + self.pos) % UNACKED_CAPACITY;
        self.pos += 1;
        return self.queue.entries[idx];
    }
};

/// Generate a unique SM-ID.
/// Format: [2 bytes worker_id BE][14 bytes random] → 32 hex characters.
pub fn generateSmId(worker_id: u16, out: *[SM_ID_HEX_LEN]u8) void {
    var raw: [16]u8 = undefined;
    raw[0] = @intCast(worker_id >> 8);
    raw[1] = @intCast(worker_id & 0xFF);
    std.crypto.random.bytes(raw[2..]);
    out.* = std.fmt.bytesToHex(raw, .lower);
}

/// Extract worker_id from an SM-ID hex string.
/// Returns null if the SM-ID is malformed.
pub fn workerIdFromSmId(sm_id: []const u8) ?u16 {
    if (sm_id.len != SM_ID_HEX_LEN) return null;
    const high = std.fmt.parseInt(u8, sm_id[0..2], 16) catch return null;
    const low = std.fmt.parseInt(u8, sm_id[2..4], 16) catch return null;
    return (@as(u16, high) << 8) | @as(u16, low);
}

/// Classify an outbound handled-count report when there is no unacked queue
/// (SM enabled without resume) (S24). The sent count is still tracked, so a
/// peer claiming more than was sent must fail the same way the queue path
/// does. Wrap-aware at 2^32, matching `SmUnackedQueue.ack`.
pub fn classifyAck(h: u32, last_h: u32, sent: u32) SmUnackedQueue.AckResult {
    const from_last = h -% last_h;
    if (from_last == 0) return .ok;
    if (from_last >= 0x8000_0000) return .backwards;
    // h is ahead of the last accepted count; it must not exceed what was sent.
    const ahead = h -% sent;
    if (ahead != 0 and ahead < 0x8000_0000) return .too_high;
    return .ok;
}

// ============================================================================
// Tests
// ============================================================================

var test_budget_store: ?delivery_queue.BlobBudget = null;

fn testBudget() *delivery_queue.BlobBudget {
    if (test_budget_store == null) {
        test_budget_store = .{
            .allocator = std.testing.allocator,
            .limit = delivery_queue.BlobBudget.DEFAULT_LIMIT,
        };
    }
    return &test_budget_store.?;
}

test "SmUnackedQueue: push and ack" {
    var queue = SmUnackedQueue.init(testBudget());
    defer queue.deinit();

    _ = queue.push("<message>hello</message>");
    _ = queue.push("<message>world</message>");
    _ = queue.push("<presence/>");

    try std.testing.expectEqual(@as(u32, 3), queue.count);
    try std.testing.expectEqual(@as(u32, 1), queue.base_seq);

    // Ack first 2 stanzas (h=2 means client received stanzas 1 and 2)
    _ = queue.ack(2);
    try std.testing.expectEqual(@as(u32, 1), queue.count);
    try std.testing.expectEqual(@as(u32, 3), queue.base_seq);

    // Remaining entry should be "<presence/>"
    var iter = queue.getUnacked();
    const entry = iter.next() orelse unreachable;
    try std.testing.expectEqualStrings("<presence/>", entry.bytes());
    try std.testing.expect(iter.next() == null);
}

test "SmUnackedQueue: pushBlob shares one allocation, deinit releases it (C11)" {
    // A queue entry is a reference, not a copy: the ring slot's blob and a
    // handoff blob land here with only a refcount bump.
    var producer = delivery_queue.BlobBudget{
        .allocator = std.testing.allocator,
        .limit = delivery_queue.BlobBudget.DEFAULT_LIMIT,
    };
    const blob = try producer.produce("<message>shared</message>");
    defer blob.release();

    var queue = SmUnackedQueue.init(testBudget());
    try std.testing.expectEqual(PushResult.pushed, queue.pushBlob(blob));
    // Producer handle + queue entry share the one allocation.
    try std.testing.expectEqual(@as(u32, 2), blob.refs.load(.monotonic));

    var iter = queue.getUnacked();
    const got = iter.next() orelse unreachable;
    try std.testing.expect(got == blob);
    try std.testing.expectEqualStrings("<message>shared</message>", got.bytes());
    try std.testing.expect(iter.next() == null);

    // deinit releases the queue's reference; the producer handle survives.
    queue.deinit();
    try std.testing.expectEqual(@as(u32, 1), blob.refs.load(.monotonic));
}

test "SmUnackedQueue: retainOn moves charges off the producer budget (T-265C5A0E)" {
    var producer = delivery_queue.BlobBudget{
        .allocator = std.testing.allocator,
        .limit = delivery_queue.BlobBudget.DEFAULT_LIMIT,
    };
    var retention = delivery_queue.BlobBudget{
        .allocator = std.testing.allocator,
        .limit = delivery_queue.BlobBudget.SM_RETENTION_LIMIT,
    };

    // A shared ring blob and a self-produced copy, both producer-charged.
    const blob = try producer.produce("<message>shared</message>");
    var queue = SmUnackedQueue.init(&producer);
    defer queue.deinit();
    try std.testing.expectEqual(PushResult.pushed, queue.pushBlob(blob));
    blob.release(); // the queue now holds the only reference
    try std.testing.expectEqual(PushResult.pushed, queue.push("<presence/>"));

    const charged = producer.bytes_in_flight.load(.monotonic);
    try std.testing.expect(charged > 0);
    try std.testing.expect(queue.retainOn(&retention));
    try std.testing.expectEqual(@as(u64, 0), producer.bytes_in_flight.load(.monotonic));
    try std.testing.expectEqual(charged, retention.bytes_in_flight.load(.monotonic));
    try std.testing.expect(queue.detached);
    try std.testing.expect(queue.budget == &retention);

    // Pushes after the move charge the retention budget too: the shared
    // blob's charge transfers, the copy produces there directly.
    const late = try producer.produce("<message>late</message>");
    try std.testing.expectEqual(PushResult.pushed, queue.pushBlob(late));
    late.release();
    try std.testing.expectEqual(@as(u64, 0), producer.bytes_in_flight.load(.monotonic));
    try std.testing.expectEqual(PushResult.pushed, queue.push("<iq/>"));

    // Ack and teardown releases return every charge to retention.
    _ = queue.ack(4);
    try std.testing.expectEqual(@as(u64, 0), retention.bytes_in_flight.load(.monotonic));
}

test "SmUnackedQueue: a detached queue refuses blob pushes past the retention budget" {
    var producer = delivery_queue.BlobBudget{
        .allocator = std.testing.allocator,
        .limit = delivery_queue.BlobBudget.DEFAULT_LIMIT,
    };
    var retention = delivery_queue.BlobBudget{
        .allocator = std.testing.allocator,
        .limit = 1,
    };

    var queue = SmUnackedQueue.init(&retention);
    queue.detached = true;
    defer queue.deinit();

    const blob = try producer.produce("<message>held</message>");
    defer blob.release();
    try std.testing.expectEqual(PushResult.alloc_failed, queue.pushBlob(blob));
    try std.testing.expectEqual(@as(u32, 0), queue.count);
    // The refused blob's charge never left the producing budget and is
    // returned when the caller's own reference drops.
    try std.testing.expect(producer.bytes_in_flight.load(.monotonic) > 0);
}

test "SmUnackedQueue: overflow discards oldest and reports it (T178)" {
    var queue = SmUnackedQueue.init(testBudget());
    defer queue.deinit();

    // Fill to capacity — every push reports .pushed
    var i: u32 = 0;
    while (i < UNACKED_CAPACITY) : (i += 1) {
        try std.testing.expectEqual(PushResult.pushed, queue.push("x"));
    }
    try std.testing.expectEqual(UNACKED_CAPACITY, queue.count);

    // Push one more — oldest evicted, overflow signaled so the caller can
    // fail the session instead of silently losing stanzas.
    try std.testing.expectEqual(PushResult.overflow, queue.push("new"));
    try std.testing.expectEqual(UNACKED_CAPACITY, queue.count);
    try std.testing.expectEqual(@as(u32, 2), queue.base_seq);

    // The overflow signal fires on EVERY push past capacity — the policy
    // (fail the session) must be applied once, by the first caller that
    // sees it; the queue itself stays bounded and consistent.
    try std.testing.expectEqual(PushResult.overflow, queue.push("newer"));
    try std.testing.expectEqual(UNACKED_CAPACITY, queue.count);
    try std.testing.expectEqual(@as(u32, 3), queue.base_seq);
}

test "SmUnackedQueue: ack all" {
    var queue = SmUnackedQueue.init(testBudget());
    defer queue.deinit();

    _ = queue.push("a");
    _ = queue.push("b");
    _ = queue.push("c");

    _ = queue.ack(3);
    try std.testing.expectEqual(@as(u32, 0), queue.count);
    try std.testing.expectEqual(@as(u32, 4), queue.base_seq);
}

test "SmUnackedQueue: ack above the sent count changes nothing (S24)" {
    var queue = SmUnackedQueue.init(testBudget());
    defer queue.deinit();

    _ = queue.push("a");
    // h greater than the number of stanzas sent is a protocol violation:
    // the queue must NOT be emptied and last_h must NOT advance, or every
    // later legitimate ack is ignored (S24).
    try std.testing.expectEqual(SmUnackedQueue.AckResult.too_high, queue.ack(10));
    try std.testing.expectEqual(@as(u32, 1), queue.count);
    try std.testing.expectEqual(@as(u32, 1), queue.base_seq);
    try std.testing.expectEqual(@as(u32, 0), queue.last_h);

    // A legitimate ack afterwards still works.
    try std.testing.expectEqual(SmUnackedQueue.AckResult.ok, queue.ack(1));
    try std.testing.expectEqual(@as(u32, 0), queue.count);
    try std.testing.expectEqual(@as(u32, 1), queue.last_h);
}

test "SmUnackedQueue: backwards or duplicate h discards nothing (S24)" {
    var queue = SmUnackedQueue.init(testBudget());
    defer queue.deinit();

    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        _ = queue.push("s");
    }

    _ = queue.ack(5);
    try std.testing.expectEqual(@as(u32, 5), queue.count);

    // A replayed `<resume h='0'/>` (or any backwards h) must not touch the
    // replay queue: the ack would wrap acked_count above count and discardAll
    // would drop everything (S24).
    _ = queue.ack(0);
    try std.testing.expectEqual(@as(u32, 5), queue.count);
    try std.testing.expectEqual(@as(u32, 6), queue.base_seq);

    _ = queue.ack(3);
    try std.testing.expectEqual(@as(u32, 5), queue.count);

    // Duplicate of the last h is a no-op, forward progress still works.
    _ = queue.ack(5);
    try std.testing.expectEqual(@as(u32, 5), queue.count);
    _ = queue.ack(10);
    try std.testing.expectEqual(@as(u32, 0), queue.count);
    try std.testing.expectEqual(@as(u32, 11), queue.base_seq);
}

test "SmUnackedQueue: ack across the u32 wrap (S24)" {
    var queue = SmUnackedQueue.init(testBudget());
    defer queue.deinit();

    // Sequences wrap at 2^32: a forward h that numerically decreased must
    // still ack, not be mistaken for backwards.
    queue.base_seq = 0xFFFF_FFF0;
    queue.last_h = 0xFFFF_FFEF;
    var i: u32 = 0;
    while (i < 20) : (i += 1) {
        _ = queue.push("s");
    }

    _ = queue.ack(2); // seqs 0xFFFFFFF0..0xFFFFFFFF, 0, 1, 2 = 19 stanzas
    try std.testing.expectEqual(@as(u32, 1), queue.count);
    try std.testing.expectEqual(@as(u32, 3), queue.base_seq);
    try std.testing.expectEqual(@as(u32, 2), queue.last_h);

    // A genuinely backwards h just under the wrap is still rejected.
    _ = queue.ack(0xFFFF_FFFE);
    try std.testing.expectEqual(@as(u32, 1), queue.count);
}

test "generateSmId: format and worker extraction" {
    var id: [SM_ID_HEX_LEN]u8 = undefined;
    generateSmId(0x0003, &id);
    try std.testing.expectEqual(@as(usize, 32), id.len);

    const extracted = workerIdFromSmId(&id);
    try std.testing.expect(extracted != null);
    try std.testing.expectEqual(@as(u16, 3), extracted.?);
}

test "workerIdFromSmId: invalid length" {
    try std.testing.expect(workerIdFromSmId("short") == null);
    try std.testing.expect(workerIdFromSmId("") == null);
}

test "classifyAck: reports too high and backwards without a queue (S24)" {
    // SM without resume tracks only the sent count and last accepted h, so a
    // report of more than was sent is too_high and a lower one is backwards.
    try std.testing.expectEqual(SmUnackedQueue.AckResult.too_high, classifyAck(10, 0, 8));
    try std.testing.expectEqual(SmUnackedQueue.AckResult.ok, classifyAck(8, 0, 8));
    try std.testing.expectEqual(SmUnackedQueue.AckResult.ok, classifyAck(3, 0, 8));
    try std.testing.expectEqual(SmUnackedQueue.AckResult.ok, classifyAck(5, 5, 8));
    try std.testing.expectEqual(SmUnackedQueue.AckResult.backwards, classifyAck(2, 5, 8));

    // Wrap-aware: a report near the 2^32 boundary still counts as forward.
    try std.testing.expectEqual(SmUnackedQueue.AckResult.too_high, classifyAck(0xFFFF_FFFF, 0xFFFF_FFF0, 0xFFFF_FFF0));
    try std.testing.expectEqual(SmUnackedQueue.AckResult.ok, classifyAck(0xFFFF_FFFF, 0xFFFF_FFF0, 0xFFFF_FFFF));

    // A report that has passed 2^32 is numerically BELOW the sent count but
    // ahead of last_h. A plain `h > sent` comparison accepts it and the peer
    // gets credit for stanzas that were never sent; only the wrap-aware
    // subtraction reports too_high.
    try std.testing.expectEqual(SmUnackedQueue.AckResult.too_high, classifyAck(1, 0xFFFF_FFFD, 0xFFFF_FFFF));
    // Same shape at the low end of the wrap window, and the exact match.
    try std.testing.expectEqual(SmUnackedQueue.AckResult.too_high, classifyAck(3, 0xFFFF_FFFE, 2));
    try std.testing.expectEqual(SmUnackedQueue.AckResult.ok, classifyAck(2, 0xFFFF_FFFE, 2));
    // Backwards across the boundary is still backwards, not a huge forward jump.
    try std.testing.expectEqual(SmUnackedQueue.AckResult.backwards, classifyAck(0xFFFF_FFFC, 0xFFFF_FFFE, 0xFFFF_FFFE));
}

test "SmUnackedQueue: ack above the sent count across the u32 wrap (S24)" {
    var queue = SmUnackedQueue.init(testBudget());
    defer queue.deinit();

    // One stanza outstanding at the top of the sequence space, client already
    // acked up to just below it. An h that has wrapped past 2^32 lands above
    // the sent count while reading as numerically smaller than base_seq.
    queue.base_seq = 0xFFFF_FFFF;
    queue.last_h = 0xFFFF_FFFD;
    _ = queue.push("s");

    try std.testing.expectEqual(SmUnackedQueue.AckResult.too_high, queue.ack(1));
    try std.testing.expectEqual(@as(u32, 1), queue.count);
    try std.testing.expectEqual(@as(u32, 0xFFFF_FFFD), queue.last_h);

    // The honest report still acks, so the rejection above is not a blanket
    // refusal of every wrapped h.
    try std.testing.expectEqual(SmUnackedQueue.AckResult.ok, queue.ack(0xFFFF_FFFF));
    try std.testing.expectEqual(@as(u32, 0), queue.count);
    try std.testing.expectEqual(@as(u32, 0xFFFF_FFFF), queue.last_h);
}
