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

const log = std.log.scoped(.sm);

/// Maximum number of unacknowledged stanzas buffered per session.
/// Each entry is heap-allocated (variable size). If the queue is full,
/// the oldest unacked stanza is discarded to bound memory usage.
pub const UNACKED_CAPACITY: u32 = 256;

/// Default session resume timeout in seconds.
pub const DEFAULT_RESUME_TIMEOUT: u32 = 300;

/// SM-ID length in hex characters (16 bytes = 32 hex chars).
pub const SM_ID_HEX_LEN: usize = 32;

/// A single queued outbound stanza awaiting client acknowledgment.
const UnackedEntry = struct {
    /// Heap-allocated copy of the stanza XML.
    data: []u8,
};

/// Bounded ring buffer of outbound stanzas sent to the client but not yet
/// acknowledged via `<a h='N'/>`. Used to replay stanzas on session resume.
pub const SmUnackedQueue = struct {
    /// Ring buffer storage.
    entries: [UNACKED_CAPACITY]?UnackedEntry = .{null} ** UNACKED_CAPACITY,
    /// Index of the oldest unacked entry (next to dequeue on ack).
    head: u32 = 0,
    /// Index of the next write position.
    tail: u32 = 0,
    /// Number of entries currently in the queue.
    count: u32 = 0,
    /// The sm_out_seq value corresponding to the entry at `head`.
    /// This is the sequence number of the oldest unacked stanza.
    base_seq: u32 = 1,
    /// Allocator used for heap-allocated stanza copies.
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) SmUnackedQueue {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *SmUnackedQueue) void {
        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            const idx = (self.head + i) % UNACKED_CAPACITY;
            if (self.entries[idx]) |entry| {
                self.allocator.free(entry.data);
                self.entries[idx] = null;
            }
        }
        self.count = 0;
        self.head = 0;
        self.tail = 0;
    }

    /// Push a stanza into the queue. If full, the oldest entry is discarded.
    pub fn push(self: *SmUnackedQueue, stanza: []const u8) void {
        if (self.count == UNACKED_CAPACITY) {
            // Queue full — discard oldest to make room
            self.discardHead();
        }

        const copy = self.allocator.alloc(u8, stanza.len) catch {
            log.warn("SM unacked queue: allocation failed ({d} bytes)", .{stanza.len});
            return;
        };
        @memcpy(copy, stanza);

        self.entries[self.tail] = .{ .data = copy };
        self.tail = (self.tail + 1) % UNACKED_CAPACITY;
        self.count += 1;
    }

    /// Acknowledge stanzas up to and including sequence number `h`.
    /// Discards all entries with sequence ≤ h.
    pub fn ack(self: *SmUnackedQueue, h: u32) void {
        // How many stanzas are being acknowledged?
        // h is the client's report of total stanzas received.
        // base_seq is the sequence of our oldest buffered stanza.
        // Stanzas to discard = h - (base_seq - 1)
        const acked_count = h -% (self.base_seq -% 1);

        if (acked_count == 0) return;
        if (acked_count > self.count) {
            // Client acked more than we have buffered — clear everything
            self.discardAll();
            self.base_seq = h +% 1;
            return;
        }

        var i: u32 = 0;
        while (i < acked_count) : (i += 1) {
            self.discardHead();
        }
    }

    /// Return all unacked stanza entries for replay.
    /// Caller must NOT free the returned slices — they remain owned by the queue.
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

    fn discardHead(self: *SmUnackedQueue) void {
        if (self.count == 0) return;
        if (self.entries[self.head]) |entry| {
            self.allocator.free(entry.data);
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

/// Iterator over unacked stanza entries.
pub const UnackedIterator = struct {
    queue: *const SmUnackedQueue,
    pos: u32,

    pub fn next(self: *UnackedIterator) ?[]const u8 {
        if (self.pos >= self.queue.count) return null;
        const idx = (self.queue.head + self.pos) % UNACKED_CAPACITY;
        self.pos += 1;
        if (self.queue.entries[idx]) |entry| {
            return entry.data;
        }
        return null;
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

// ============================================================================
// Tests
// ============================================================================

test "SmUnackedQueue: push and ack" {
    const allocator = std.testing.allocator;
    var queue = SmUnackedQueue.init(allocator);
    defer queue.deinit();

    queue.push("<message>hello</message>");
    queue.push("<message>world</message>");
    queue.push("<presence/>");

    try std.testing.expectEqual(@as(u32, 3), queue.count);
    try std.testing.expectEqual(@as(u32, 1), queue.base_seq);

    // Ack first 2 stanzas (h=2 means client received stanzas 1 and 2)
    queue.ack(2);
    try std.testing.expectEqual(@as(u32, 1), queue.count);
    try std.testing.expectEqual(@as(u32, 3), queue.base_seq);

    // Remaining entry should be "<presence/>"
    var iter = queue.getUnacked();
    const entry = iter.next() orelse unreachable;
    try std.testing.expectEqualStrings("<presence/>", entry);
    try std.testing.expect(iter.next() == null);
}

test "SmUnackedQueue: overflow discards oldest" {
    const allocator = std.testing.allocator;
    var queue = SmUnackedQueue.init(allocator);
    defer queue.deinit();

    // Fill to capacity
    var i: u32 = 0;
    while (i < UNACKED_CAPACITY) : (i += 1) {
        queue.push("x");
    }
    try std.testing.expectEqual(UNACKED_CAPACITY, queue.count);

    // Push one more — oldest should be discarded
    queue.push("new");
    try std.testing.expectEqual(UNACKED_CAPACITY, queue.count);
    try std.testing.expectEqual(@as(u32, 2), queue.base_seq);
}

test "SmUnackedQueue: ack all" {
    const allocator = std.testing.allocator;
    var queue = SmUnackedQueue.init(allocator);
    defer queue.deinit();

    queue.push("a");
    queue.push("b");
    queue.push("c");

    queue.ack(3);
    try std.testing.expectEqual(@as(u32, 0), queue.count);
    try std.testing.expectEqual(@as(u32, 4), queue.base_seq);
}

test "SmUnackedQueue: ack beyond buffered" {
    const allocator = std.testing.allocator;
    var queue = SmUnackedQueue.init(allocator);
    defer queue.deinit();

    queue.push("a");
    // Ack more than we have (client saw stanzas we already dropped)
    queue.ack(10);
    try std.testing.expectEqual(@as(u32, 0), queue.count);
    try std.testing.expectEqual(@as(u32, 11), queue.base_seq);
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
