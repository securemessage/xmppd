//! # Fan-out — Bounded continuation for O(N) delivery
//!
//! Prevents event loop starvation during MUC groupchat fan-out.
//! Delivers to BATCH_SIZE recipients per event loop tick, then yields.
//! Remaining recipients are delivered in subsequent ticks via the
//! pending fan-out queue on the Server struct.
//!
//! ## Pre-built Stanza Optimization
//!
//! For MUC groupchat messages, the only per-recipient difference is the
//! `to` attribute value (XEP-0045 §7.4). The stanza is split into a
//! prefix (everything up to `to='`) and suffix (everything after the
//! recipient JID). Per-occupant delivery becomes three memcpy operations
//! instead of N iterative writeAll calls.
//!
//! ## Escape Hatch
//!
//! If a future XEP requires per-recipient content beyond the `to` attribute,
//! the pre-built path can be bypassed by not queuing a PendingFanout and
//! falling back to per-occupant stanza construction.

const std = @import("std");
const room_registry = @import("room_registry");
const Room = room_registry.Room;
const Occupant = room_registry.Occupant;
const RoomRegistry = room_registry.RoomRegistry;
const ChangeList = @import("event_loop.zig").ChangeList;

const log = std.log.scoped(.fanout);

/// Number of occupants delivered per event loop tick before yielding.
pub const DEFAULT_BATCH_SIZE: u8 = 32;

/// Maximum concurrent pending fan-out operations.
pub const MAX_PENDING: usize = 4;

/// A pending fan-out operation that delivers a pre-built stanza to room
/// occupants across multiple event loop ticks (bounded continuation).
pub const PendingFanout = struct {
    active: bool = false,

    /// Index into room.occupants to resume scanning from on the next tick.
    next_slot: u8 = 0,

    /// Room JID for safe re-lookup (room may have been destroyed between ticks).
    room_jid_buf: [320]u8 = undefined,
    room_jid_len: u16 = 0,

    /// Pre-built stanza prefix: everything up to and including " to='"
    /// Example: "<message from='room@conf/nick' to='"
    prefix_buf: [512]u8 = undefined,
    prefix_len: u16 = 0,

    /// Pre-built stanza suffix: everything after the recipient JID value
    /// Example: "' type='groupchat' id='abc'><body>hello</body></message>"
    suffix_buf: [16500]u8 = undefined,
    suffix_len: u16 = 0,

    pub fn getRoomJid(self: *const PendingFanout) []const u8 {
        return self.room_jid_buf[0..self.room_jid_len];
    }

    pub fn getPrefix(self: *const PendingFanout) []const u8 {
        return self.prefix_buf[0..self.prefix_len];
    }

    pub fn getSuffix(self: *const PendingFanout) []const u8 {
        return self.suffix_buf[0..self.suffix_len];
    }

    /// Mark this slot as complete and available for reuse.
    pub fn complete(self: *PendingFanout) void {
        self.active = false;
    }
};

/// Fixed-size queue of pending fan-out operations.
pub const FanoutQueue = struct {
    slots: [MAX_PENDING]PendingFanout = [_]PendingFanout{.{}} ** MAX_PENDING,
    batch_size: u8 = DEFAULT_BATCH_SIZE,

    /// Allocate a free slot for a new pending fan-out.
    /// Returns null if all slots are in use (fan-out back-pressure).
    pub fn alloc(self: *FanoutQueue) ?*PendingFanout {
        for (&self.slots) |*slot| {
            if (!slot.active) {
                slot.* = .{ .active = true };
                return slot;
            }
        }
        log.warn("fan-out queue full ({d} pending), delivering synchronously", .{MAX_PENDING});
        return null;
    }

    /// Returns true if there are active pending fan-outs to drain.
    pub fn hasPending(self: *const FanoutQueue) bool {
        for (&self.slots) |*slot| {
            if (slot.active) return true;
        }
        return false;
    }
};

/// Build a pre-built stanza prefix for a MUC groupchat message.
/// Returns the number of bytes written, or null on overflow.
///
/// Output: `<message from='room@conf/nick' to='`
pub fn buildPrefix(
    buf: *[512]u8,
    from_str: []const u8,
) ?u16 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    w.writeAll("<message from='") catch return null;
    w.writeAll(from_str) catch return null;
    w.writeAll("' to='") catch return null;
    return @intCast(fbs.pos);
}

/// Build a pre-built stanza suffix for a MUC groupchat message.
/// Returns the number of bytes written, or null on overflow.
///
/// Output: `' type='groupchat' id='abc'><body>hello</body></message>`
///     or: `' type='groupchat' id='abc'/>`  (no inner XML)
pub fn buildSuffix(
    buf: *[16500]u8,
    id_str: []const u8,
    inner_xml: []const u8,
) ?u16 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    w.writeAll("' type='groupchat'") catch return null;
    if (id_str.len > 0) {
        w.writeAll(" id='") catch return null;
        w.writeAll(id_str) catch return null;
        w.writeByte('\'') catch return null;
    }
    if (inner_xml.len == 0) {
        w.writeAll("/>") catch return null;
    } else {
        w.writeByte('>') catch return null;
        w.writeAll(inner_xml) catch return null;
        w.writeAll("</message>") catch return null;
    }
    return @intCast(fbs.pos);
}

/// Deliver a pre-built stanza to a single session by assembling
/// prefix + recipient JID + suffix into a contiguous buffer.
pub fn deliverPrebuilt(
    prefix: []const u8,
    recipient_jid: []const u8,
    suffix: []const u8,
    conn: anytype,
) !void {
    var msg_buf: [20480]u8 = undefined;
    const total = prefix.len + recipient_jid.len + suffix.len;
    if (total > msg_buf.len) return error.StanzaTooLarge;

    @memcpy(msg_buf[0..prefix.len], prefix);
    @memcpy(msg_buf[prefix.len .. prefix.len + recipient_jid.len], recipient_jid);
    @memcpy(msg_buf[prefix.len + recipient_jid.len .. total], suffix);

    try conn.queueSend(msg_buf[0..total]);
}

/// Build a complete stanza from pre-built prefix + recipient JID + suffix into a buffer.
/// Returns the total length, or null if the buffer would overflow.
/// Used for cross-thread MPSC delivery where we need the full stanza as contiguous bytes.
pub fn buildComplete(
    buf: []u8,
    prefix: []const u8,
    recipient_jid: []const u8,
    suffix: []const u8,
) ?usize {
    const total = prefix.len + recipient_jid.len + suffix.len;
    if (total > buf.len) return null;

    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len .. prefix.len + recipient_jid.len], recipient_jid);
    @memcpy(buf[prefix.len + recipient_jid.len .. total], suffix);
    return total;
}

// ============================================================================
// Tests
// ============================================================================

test "buildPrefix produces correct output" {
    var buf: [512]u8 = undefined;
    const len = buildPrefix(&buf, "room@conference.example.com/alice").?;
    const result = buf[0..len];
    try std.testing.expectEqualStrings("<message from='room@conference.example.com/alice' to='", result);
}

test "buildSuffix with body" {
    var buf: [16500]u8 = undefined;
    const len = buildSuffix(&buf, "msg-1", "<body>hello</body>").?;
    const result = buf[0..len];
    try std.testing.expectEqualStrings("' type='groupchat' id='msg-1'><body>hello</body></message>", result);
}

test "buildSuffix empty body" {
    var buf: [16500]u8 = undefined;
    const len = buildSuffix(&buf, "msg-2", "").?;
    const result = buf[0..len];
    try std.testing.expectEqualStrings("' type='groupchat' id='msg-2'/>", result);
}

test "buildSuffix no id" {
    var buf: [16500]u8 = undefined;
    const len = buildSuffix(&buf, "", "<body>test</body>").?;
    const result = buf[0..len];
    try std.testing.expectEqualStrings("' type='groupchat'><body>test</body></message>", result);
}

test "FanoutQueue alloc and complete" {
    var q = FanoutQueue{};
    try std.testing.expect(!q.hasPending());

    const slot1 = q.alloc().?;
    try std.testing.expect(q.hasPending());

    const slot2 = q.alloc().?;
    _ = q.alloc().?;
    _ = q.alloc().?;

    // Queue is full (MAX_PENDING = 4)
    try std.testing.expect(q.alloc() == null);

    slot1.complete();
    try std.testing.expect(q.hasPending()); // slot2 still active

    slot2.complete();
    // Still pending (slots 3 and 4)
}

test "PendingFanout stores room JID" {
    var pf = PendingFanout{ .active = true };
    const jid = "test@conference.example.com";
    @memcpy(pf.room_jid_buf[0..jid.len], jid);
    pf.room_jid_len = @intCast(jid.len);
    try std.testing.expectEqualStrings(jid, pf.getRoomJid());
}
