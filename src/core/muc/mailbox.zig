//! # RoomMailbox — Per-room actor message deque
//!
//! A bounded FIFO of refcounted blob envelopes (ADR-3). The owning worker is
//! the sole consumer; the MPSC drain handler is the sole producer (SPSC).
//! Items come from the room registry's bounded MemoryPool, and each room
//! carries a byte budget, so a burst of large actor messages is refused by
//! policy instead of growing memory.
//!
//! Same-thread operations bypass the mailbox entirely — they are processed
//! inline with zero overhead (fast path).

const std = @import("std");
const delivery_queue = @import("delivery_queue");

/// Actor messages dropped because a room mailbox was full (S16). The owning
/// worker increments it; the M1 metrics task exports it later.
pub var mailbox_drops = std.atomic.Value(u64).init(0);

/// Per-room byte budget across all queued items.
pub const BYTE_BUDGET: u32 = 256 * 1024;
/// Per-room item cap; one room cannot monopolize the worker's item pool.
pub const MAX_ITEMS: u16 = 64;

/// Per-room actor message mailbox.
pub const RoomMailbox = struct {
    /// Intrusive deque node; allocated from the registry's MemoryPool.
    pub const Item = struct {
        next: ?*Item = null,
        blob: *delivery_queue.Blob,
    };

    head: ?*Item = null,
    tail: ?*Item = null,
    count: u16 = 0,
    bytes: u32 = 0,

    /// Take one reference on `blob` and link it FIFO. Returns
    /// error.MailboxFull at the item cap, over the byte budget, or when
    /// the shared pool is exhausted; the caller runs the S16 policy.
    pub fn enqueue(self: *RoomMailbox, pool: *std.heap.MemoryPool(Item), blob: *delivery_queue.Blob) !void {
        if (self.count >= MAX_ITEMS) return error.MailboxFull;
        if (self.bytes + blob.len > BYTE_BUDGET) return error.MailboxFull;
        const item = pool.create() catch return error.MailboxFull;
        blob.addRef();
        item.* = .{ .blob = blob };
        if (self.tail) |t| {
            t.next = item;
        } else {
            self.head = item;
        }
        self.tail = item;
        self.bytes += blob.len;
        self.count += 1;
    }

    /// Pop the oldest item's blob. The caller owns the returned reference
    /// and must release it. Returns null when empty.
    pub fn dequeue(self: *RoomMailbox, pool: *std.heap.MemoryPool(Item)) ?*delivery_queue.Blob {
        const item = self.head orelse return null;
        self.head = item.next;
        if (self.head == null) self.tail = null;
        const blob = item.blob;
        self.bytes -= blob.len;
        self.count -= 1;
        pool.destroy(item);
        return blob;
    }

    /// Check if there are pending messages.
    pub fn hasPending(self: *const RoomMailbox) bool {
        return self.count > 0;
    }

    /// Release every parked item; called when the room is destroyed.
    pub fn deinit(self: *RoomMailbox, pool: *std.heap.MemoryPool(Item)) void {
        while (self.dequeue(pool)) |blob| blob.release();
        self.head = null;
        self.tail = null;
    }
};

// ============================================================================
// Tests
// ============================================================================

var test_budget_store: ?delivery_queue.BlobBudget = null;
fn testBudget() *delivery_queue.BlobBudget {
    if (test_budget_store == null) {
        test_budget_store = .{ .allocator = std.testing.allocator, .limit = delivery_queue.BlobBudget.DEFAULT_LIMIT };
    }
    return &test_budget_store.?;
}

fn enqueuePayload(mb: *RoomMailbox, pool: *std.heap.MemoryPool(RoomMailbox.Item), payload: []const u8) !void {
    const blob = try testBudget().produce(payload);
    defer blob.release();
    try mb.enqueue(pool, blob);
}

fn dequeueString(mb: *RoomMailbox, pool: *std.heap.MemoryPool(RoomMailbox.Item), buf: []u8) ?[]const u8 {
    const blob = mb.dequeue(pool) orelse return null;
    defer blob.release();
    if (blob.bytes().len > buf.len) return null;
    @memcpy(buf[0..blob.bytes().len], blob.bytes());
    return buf[0..blob.bytes().len];
}

test "RoomMailbox: enqueue and dequeue round-trip" {
    var pool = std.heap.MemoryPool(RoomMailbox.Item).init(std.testing.allocator);
    defer pool.deinit();
    var mb = RoomMailbox{};
    const payload = "hello room actor";
    try enqueuePayload(&mb, &pool, payload);

    try std.testing.expect(mb.hasPending());
    try std.testing.expectEqual(@as(u16, 1), mb.count);

    var buf: [128]u8 = undefined;
    const out = dequeueString(&mb, &pool, &buf).?;
    try std.testing.expectEqualStrings("hello room actor", out);
    try std.testing.expect(!mb.hasPending());
    try std.testing.expectEqual(@as(u16, 0), mb.count);
    try std.testing.expectEqual(@as(u32, 0), mb.bytes);
}

test "RoomMailbox: FIFO ordering" {
    var pool = std.heap.MemoryPool(RoomMailbox.Item).init(std.testing.allocator);
    defer pool.deinit();
    var mb = RoomMailbox{};
    try enqueuePayload(&mb, &pool, "first");
    try enqueuePayload(&mb, &pool, "second");
    try enqueuePayload(&mb, &pool, "third");

    try std.testing.expectEqual(@as(u16, 3), mb.count);
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("first", dequeueString(&mb, &pool, &buf).?);
    try std.testing.expectEqualStrings("second", dequeueString(&mb, &pool, &buf).?);
    try std.testing.expectEqualStrings("third", dequeueString(&mb, &pool, &buf).?);
    try std.testing.expect(mb.dequeue(&pool) == null);
}

test "RoomMailbox: full mailbox returns error" {
    var pool = std.heap.MemoryPool(RoomMailbox.Item).init(std.testing.allocator);
    defer pool.deinit();
    var mb = RoomMailbox{};
    var i: u16 = 0;
    while (i < MAX_ITEMS) : (i += 1) {
        try enqueuePayload(&mb, &pool, "msg");
    }
    try std.testing.expectEqual(@as(u16, MAX_ITEMS), mb.count);
    try std.testing.expectError(error.MailboxFull, enqueuePayload(&mb, &pool, "overflow"));
    mb.deinit(&pool);
}

test "RoomMailbox: byte budget returns error" {
    var pool = std.heap.MemoryPool(RoomMailbox.Item).init(std.testing.allocator);
    defer pool.deinit();
    var mb = RoomMailbox{};
    const payload = try std.testing.allocator.alloc(u8, RoomMailbox.BYTE_BUDGET);
    defer std.testing.allocator.free(payload);
    @memset(payload, 'x');
    try enqueuePayload(&mb, &pool, payload);
    try std.testing.expectError(error.MailboxFull, enqueuePayload(&mb, &pool, "one more"));
    mb.deinit(&pool);
}

test "RoomMailbox: dequeue empty returns null" {
    var pool = std.heap.MemoryPool(RoomMailbox.Item).init(std.testing.allocator);
    defer pool.deinit();
    var mb = RoomMailbox{};
    try std.testing.expect(mb.dequeue(&pool) == null);
    try std.testing.expect(!mb.hasPending());
}
