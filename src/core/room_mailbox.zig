//! # RoomMailbox — Per-room SPSC message buffer
//!
//! A bounded, single-producer-single-consumer ring buffer for per-room actor
//! messages. The owning worker is the sole consumer. The sole producer is the
//! MPSC drain handler (cross-thread messages arrive via the per-worker MPSC,
//! then are pushed into the target room's mailbox).
//!
//! Same-thread operations bypass the mailbox entirely — they are processed
//! inline with zero overhead (fast path).
//!
//! ## Design
//!
//! - Fixed-capacity ring buffer: 16 slots
//! - SPSC (not MPSC) — owning worker holds both room and mailbox; only one
//!   write path per tick (MPSC drain → enqueue)
//! - Backpressure: enqueue returns error.MailboxFull if capacity exhausted
//! - No atomics needed — single-threaded access by owning worker only

const std = @import("std");
const delivery_queue = @import("delivery_queue");

/// Number of mailbox slots per room.
pub const MAILBOX_SLOTS: u8 = 16;

/// Maximum payload size per message (matches MPSC slot payload).
pub const MAX_PAYLOAD_SIZE = delivery_queue.MAX_PAYLOAD_SIZE;

/// Per-room actor message mailbox.
pub const RoomMailbox = struct {
    slots: [MAILBOX_SLOTS][MAX_PAYLOAD_SIZE]u8 = undefined,
    lengths: [MAILBOX_SLOTS]u16 = [_]u16{0} ** MAILBOX_SLOTS,
    head: u8 = 0,
    tail: u8 = 0,
    count: u8 = 0,

    /// Enqueue a serialized actor message into this room's mailbox.
    /// Returns error.MailboxFull if the ring buffer is at capacity.
    pub fn enqueue(self: *RoomMailbox, payload: []const u8) !void {
        if (self.count >= MAILBOX_SLOTS) return error.MailboxFull;
        if (payload.len > MAX_PAYLOAD_SIZE or payload.len == 0) return error.InvalidPayload;

        const slot = self.tail;
        const len: u16 = @intCast(payload.len);
        @memcpy(self.slots[slot][0..len], payload[0..len]);
        self.lengths[slot] = len;
        self.tail = (self.tail + 1) % MAILBOX_SLOTS;
        self.count += 1;
    }

    /// Dequeue one message from this room's mailbox.
    /// Returns the payload slice (pointing into internal buffer) or null if empty.
    /// The returned slice is valid until the next enqueue into the same slot
    /// (i.e., until MAILBOX_SLOTS more messages are enqueued).
    pub fn dequeue(self: *RoomMailbox) ?[]const u8 {
        if (self.count == 0) return null;

        const slot = self.head;
        const len = self.lengths[slot];
        const payload = self.slots[slot][0..len];
        self.head = (self.head + 1) % MAILBOX_SLOTS;
        self.count -= 1;
        return payload;
    }

    /// Check if there are pending messages.
    pub fn hasPending(self: *const RoomMailbox) bool {
        return self.count > 0;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "RoomMailbox: enqueue and dequeue round-trip" {
    var mb = RoomMailbox{};
    const payload = "hello room actor";
    try mb.enqueue(payload);

    try std.testing.expect(mb.hasPending());
    try std.testing.expectEqual(@as(u8, 1), mb.count);

    const out = mb.dequeue().?;
    try std.testing.expectEqualStrings("hello room actor", out);
    try std.testing.expect(!mb.hasPending());
    try std.testing.expectEqual(@as(u8, 0), mb.count);
}

test "RoomMailbox: FIFO ordering" {
    var mb = RoomMailbox{};
    try mb.enqueue("first");
    try mb.enqueue("second");
    try mb.enqueue("third");

    try std.testing.expectEqual(@as(u8, 3), mb.count);
    try std.testing.expectEqualStrings("first", mb.dequeue().?);
    try std.testing.expectEqualStrings("second", mb.dequeue().?);
    try std.testing.expectEqualStrings("third", mb.dequeue().?);
    try std.testing.expect(mb.dequeue() == null);
}

test "RoomMailbox: full mailbox returns error" {
    var mb = RoomMailbox{};
    var i: u8 = 0;
    while (i < MAILBOX_SLOTS) : (i += 1) {
        try mb.enqueue("msg");
    }
    try std.testing.expectEqual(@as(u8, MAILBOX_SLOTS), mb.count);
    try std.testing.expectError(error.MailboxFull, mb.enqueue("overflow"));
}

test "RoomMailbox: wrap-around" {
    var mb = RoomMailbox{};
    // Fill and drain multiple times to exercise wrap-around
    var i: u8 = 0;
    while (i < MAILBOX_SLOTS) : (i += 1) {
        try mb.enqueue("fill");
    }
    // Drain all
    i = 0;
    while (i < MAILBOX_SLOTS) : (i += 1) {
        try std.testing.expect(mb.dequeue() != null);
    }
    try std.testing.expectEqual(@as(u8, 0), mb.count);

    // Now enqueue again — should wrap around
    try mb.enqueue("wrapped-1");
    try mb.enqueue("wrapped-2");
    try std.testing.expectEqualStrings("wrapped-1", mb.dequeue().?);
    try std.testing.expectEqualStrings("wrapped-2", mb.dequeue().?);
}

test "RoomMailbox: dequeue empty returns null" {
    var mb = RoomMailbox{};
    try std.testing.expect(mb.dequeue() == null);
    try std.testing.expect(!mb.hasPending());
}

test "RoomMailbox: empty payload rejected" {
    var mb = RoomMailbox{};
    try std.testing.expectError(error.InvalidPayload, mb.enqueue(""));
}
