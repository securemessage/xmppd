//! # Message — Actor message types for xmppd event routing
//!
//! Defines the typed vocabulary for actor-to-actor communication.
//! Messages are the ONLY way actors exchange information — no shared state.
//!
//! ## Two-Tier Design
//!
//! **Tier 1 — Same-thread:** The `Message` tagged union is used directly on the
//! stack. Slices point into the session's read/stanza buffers and are valid for
//! the duration of the event loop tick. Zero allocation.
//!
//! **Tier 2 — Cross-thread:** Messages are serialized into the MPSC ring buffer's
//! fixed 4KB slots via `encode()` / `decode()`. The consumer reads from the slot's
//! own memory. No heap allocation, no shared pointers, no lifetime issues.
//!
//! ## Wire Format
//!
//! ```
//! [1B tag][field0][field1]...
//! ```
//!
//! String fields: `[2B big-endian length][bytes]`
//! Integer fields: `[4B big-endian value]`

const std = @import("std");

const Token = @import("net_token").Token;
const token_kinds = @import("token_kinds");
const log = std.log.scoped(.message);

// ============================================================================
// Message payload structs
// ============================================================================

/// Session lifecycle: a session has been closed/disconnected.
pub const SessionClosed = struct {
    local: []const u8,
    domain: []const u8,
    resource: []const u8,
    worker_id: u16,
    session_token: Token,
};

/// MUC room join/part request.
pub const RoomEvent = struct {
    room_jid: []const u8,
    real_jid: []const u8,
    nick: []const u8,
    worker_id: u16,
    session_token: Token,
};

/// MUC groupchat message to fan out.
pub const RoomMessageEvent = struct {
    room_jid: []const u8,
    from_jid: []const u8,
    inner_xml: []const u8,
    stanza_id: []const u8,
};

/// T177 MUC occupant migration: an SM-resumed session moved to another
/// worker. Routed to the room's owning worker, which updates the canonical
/// occupant record's (worker, token) address in place, with no join
/// presence fan-out and no new-member handling. Identity is the full JID.
pub const RoomOccupantMove = struct {
    room_jid: []const u8,
    real_jid: []const u8,
    /// Worker the occupant record pointed at before the move (for shadow
    /// cleanup on that worker).
    old_worker_id: u16,
    /// Resuming worker.
    new_worker_id: u16,
    /// Generational token of the resumed session on the resuming worker.
    new_token: Token,
};

/// MUC disco query (routed to owning worker).
pub const DiscoRequest = struct {
    room_jid: []const u8,
    iq_id: []const u8,
    reply_to_worker: u16,
    /// Generational token of the requesting session, captured on the
    /// originating worker where that session is live (T173). The reply's
    /// drain-side validation treats a stale token as "session gone".
    reply_to_token: Token,
    /// Full JID of the querying session (for the 'to' attribute in the response).
    reply_to_jid: []const u8,
};

/// Subscription-cache invalidation for one bare JID, broadcast to all workers.
pub const CacheInvalidate = struct {
    bare_jid: []const u8,
};

/// MUC admin action (kick/ban/voice) routed to owning worker.
pub const AdminAction = struct {
    room_jid: []const u8,
    actor_jid: []const u8,
    target_nick: []const u8,
    new_role: []const u8,
    iq_id: []const u8,
    reply_to_worker: u16,
    /// Generational token of the requesting session, captured on the
    /// originating worker where that session is live (T173). The reply's
    /// drain-side validation treats a stale token as "session gone".
    reply_to_token: Token,
};

/// Room directory update broadcast (create/destroy) to all workers.
pub const RoomDirectoryUpdate = struct {
    room_jid: []const u8,
    room_name: []const u8,
    active: bool,
};

/// MUC MAM query routed to owning worker (T112).
pub const MamQuery = struct {
    room_jid: []const u8,
    /// The request's IQ stanza id — responses must carry this. Kept separate
    /// from query_id (the client's MAM queryid); conflating them mis-id's the
    /// IQ result whenever a client sets a queryid (XEP-0313).
    iq_id: []const u8,
    query_id: []const u8,
    start: []const u8,
    end_field: []const u8,
    with: []const u8,
    /// Raw RSM <max/> text; the owning worker parses it (default 50 when
    /// empty or unparsable, matching the local path).
    max: []const u8,
    /// RSM paging anchors (archive ids); empty when absent from the query.
    after_id: []const u8,
    before_id: []const u8,
    reply_to_worker: u16,
    /// Generational token of the querying session, captured on the
    /// originating worker where that session is live (T173). The reply's
    /// drain-side validation treats a stale token as "session gone".
    reply_to_token: Token,
    reply_to_jid: []const u8,
};

/// T177 cross-worker SM resume: request from the worker that received
/// <resume/> to the worker owning the detached session. Small and slot-safe —
/// the unacked queue itself travels via the shared handoff store, not here.
pub const SmResumeRequest = struct {
    /// 32-hex-char SM-ID from the client's previd.
    previd: []const u8,
    /// Client's last-acked h from the <resume/> element.
    h: u32,
    /// Worker holding the new connection.
    req_worker: u16,
    /// Generational token of the resuming session on the requesting worker.
    req_token: Token,
    /// Per-session epoch captured at enqueue (ABA guard on slot reuse).
    req_epoch: u32,
    /// Authenticated identity of the new connection, validated against the
    /// detached session's JID by the owning worker.
    auth_local: []const u8,
    auth_domain: []const u8,
    /// Redirect hops already taken (T177). The SM-ID prefix names the worker
    /// that ISSUED the id; a handed-off session lives elsewhere, so requests
    /// follow redirect breadcrumbs. Bounded — a cycle means stale state.
    hops: u8 = 0,
};

/// T177: owning worker → requesting worker. status "ok" means the state
/// bundle was parked in sm_handoff; any other value is the XEP-0198
/// <failed/> error condition to send the client.
pub const SmResumeReply = struct {
    previd: []const u8,
    req_token: Token,
    req_epoch: u32,
    status: []const u8,
};

/// T154 cross-worker resource takeover: ask the worker holding a full-JID
/// binding to destroy that session (RFC 6120 §7.7.3) so the requesting
/// worker's bind can register. The client waits bind-pending while this
/// round-trips; a new kick round follows if another worker won meanwhile.
pub const SessionKickRequest = struct {
    /// Full-JID identity of the binding to evict.
    local: []const u8,
    domain: []const u8,
    resource: []const u8,
    /// Worker holding the new connection that wants to bind.
    req_worker: u16,
    /// Session token + per-session epoch on the requesting worker (ABA guard).
    req_token: Token,
    req_epoch: u32,
};

/// T154: owner (or previous owner) → requester. The binding, if it existed,
/// is gone by the time this reply is drained; the requester retries its bind.
pub const SessionKickReply = struct {
    req_token: Token,
    req_epoch: u32,
};

// ============================================================================
// Message tagged union
// ============================================================================

pub const Tag = enum(u8) {
    session_closed = 0x02,
    room_join = 0x10,
    room_part = 0x11,
    room_message = 0x12,
    room_disco_info = 0x13,
    room_disco_items = 0x14,
    /// Shadow room update: owning worker → occupant's worker.
    /// Tells the remote worker to add a local occupant to its shadow room
    /// so multicast fan-out can find them.
    shadow_join = 0x15,
    /// Shadow room update: owning worker → occupant's worker.
    /// Tells the remote worker to remove a local occupant from its shadow room.
    shadow_part = 0x16,
    /// Admin action (kick/ban/voice) routed to room's owning worker.
    room_admin = 0x17,
    /// Room directory update broadcast to all workers.
    room_directory_update = 0x18,
    /// MUC MAM query routed to room's owning worker.
    room_mam_query = 0x19,
    /// T177 MUC occupant migration: move an occupant's (worker, session,
    /// generation) triple after a cross-worker SM resume. Runs on the room's
    /// owning worker; dispatches immediately (not via room mailbox).
    room_occupant_move = 0x1b,
    /// Subscription-cache invalidation broadcast to all workers (the
    /// sub_cache is per-worker memory; roster/subscription changes on one
    /// worker must invalidate everywhere).
    invalidate_subscription = 0x1a,
    /// Cross-worker SM resume handoff (T177), flagged via SM_ACTOR_SENTINEL.
    sm_resume_request = 0x40,
    sm_resume_reply = 0x41,
    /// T154 cross-worker resource takeover (RFC 6120 §7.7.3 eviction).
    session_kick_request = 0x42,
    session_kick_reply = 0x43,
};

pub const Message = union(Tag) {
    session_closed: SessionClosed,
    room_join: RoomEvent,
    room_part: RoomEvent,
    room_message: RoomMessageEvent,
    room_disco_info: DiscoRequest,
    room_disco_items: DiscoRequest,
    shadow_join: RoomEvent,
    shadow_part: RoomEvent,
    room_admin: AdminAction,
    room_directory_update: RoomDirectoryUpdate,
    room_mam_query: MamQuery,
    room_occupant_move: RoomOccupantMove,
    invalidate_subscription: CacheInvalidate,
    sm_resume_request: SmResumeRequest,
    sm_resume_reply: SmResumeReply,
    session_kick_request: SessionKickRequest,
    session_kick_reply: SessionKickReply,

    /// Get the wire tag byte for this message.
    pub fn tag(self: Message) u8 {
        return @intFromEnum(std.meta.activeTag(self));
    }
};

// ============================================================================
// Cross-thread binary encoding / decoding
// ============================================================================

/// Maximum encoded message size (must fit in MPSC slot payload: 4080 bytes).
pub const MAX_ENCODED_SIZE: usize = 4080;

/// Encode a Message into a byte buffer for cross-thread delivery.
/// The codec is generated from the union: every variant serializes its
/// fields in declaration order, so the wire format can never drift from
/// the Message type. Returns the byte count, or null if the buffer is
/// too small.
pub fn encode(buf: []u8, msg: Message) ?usize {
    if (buf.len == 0) return null;
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();

    w.writeByte(msg.tag()) catch return null;
    switch (msg) {
        inline else => |ev| {
            inline for (@typeInfo(@TypeOf(ev)).@"struct".fields) |f| {
                writeField(w, @field(ev, f.name)) catch return null;
            }
        },
    }
    return fbs.getWritten().len;
}

/// Decode a Message from a byte buffer (e.g., from an MPSC envelope).
/// The returned Message contains slices pointing into the input `data` buffer.
/// The caller must not modify `data` while the Message is in use.
/// Returns null on any malformed input.
pub fn decode(data: []const u8) ?Message {
    if (data.len < 1) return null;
    var fbs = std.io.fixedBufferStream(data);
    const r = fbs.reader();

    const tag_byte = r.readByte() catch return null;
    const tag_val = std.meta.intToEnum(Tag, tag_byte) catch return null;

    switch (tag_val) {
        inline else => |t| {
            const Payload = std.meta.TagPayload(Message, t);
            var ev: Payload = undefined;
            inline for (@typeInfo(Payload).@"struct".fields) |f| {
                @field(ev, f.name) = readField(f.type, data, &fbs) orelse return null;
            }
            return @unionInit(Message, @tagName(t), ev);
        },
    }
}

/// Serialize one payload field by its Zig type. Strings carry a u16
/// big-endian length; integers are big-endian; Token rides as its u64
/// udata; enums and bools are one byte.
fn writeField(w: anytype, value: anytype) !void {
    const T = @TypeOf(value);
    if (T == Token) return writeU64(w, value.toUdata());
    switch (@typeInfo(T)) {
        .bool => try w.writeByte(@intFromBool(value)),
        .int => |i| {
            switch (i.bits) {
                8 => try w.writeByte(value),
                16 => try writeU16(w, value),
                32 => try writeU32(w, value),
                64 => try writeU64(w, value),
                else => @compileError("unsupported int field width " ++ @typeName(T)),
            }
        },
        .@"enum" => try w.writeByte(@intCast(@intFromEnum(value))),
        .pointer => |p| {
            if (p.size == .slice and p.child == u8) {
                try writeStr(w, value);
            } else {
                @compileError("unsupported field type " ++ @typeName(T));
            }
        },
        else => @compileError("unsupported field type " ++ @typeName(T)),
    }
}

/// Read one payload field by its Zig type; null on malformed input.
fn readField(comptime T: type, data: []const u8, fbs: *std.io.FixedBufferStream([]const u8)) ?T {
    const r = fbs.reader();
    if (T == Token) {
        return Token.fromUdata(readU64(r) orelse return null);
    }
    switch (@typeInfo(T)) {
        .bool => return (r.readByte() catch return null) != 0,
        .int => |i| {
            return switch (i.bits) {
                8 => r.readByte() catch return null,
                16 => readU16(r) orelse return null,
                32 => readU32(r) orelse return null,
                64 => readU64(r) orelse return null,
                else => @compileError("unsupported int field width " ++ @typeName(T)),
            };
        },
        .@"enum" => {
            const b = r.readByte() catch return null;
            return std.meta.intToEnum(T, b) catch return null;
        },
        .pointer => |p| {
            if (p.size == .slice and p.child == u8) {
                return readStr(data, fbs);
            }
            @compileError("unsupported field type " ++ @typeName(T));
        },
        else => @compileError("unsupported field type " ++ @typeName(T)),
    }
}

fn writeStr(w: anytype, s: []const u8) !void {
    const len: u16 = @intCast(@min(s.len, std.math.maxInt(u16)));
    try w.writeByte(@intCast(len >> 8));
    try w.writeByte(@intCast(len & 0xFF));
    try w.writeAll(s[0..len]);
}

fn writeU16(w: anytype, v: u16) !void {
    try w.writeByte(@intCast(v >> 8));
    try w.writeByte(@intCast(v & 0xFF));
}

fn writeU32(w: anytype, v: u32) !void {
    try w.writeByte(@intCast((v >> 24) & 0xFF));
    try w.writeByte(@intCast((v >> 16) & 0xFF));
    try w.writeByte(@intCast((v >> 8) & 0xFF));
    try w.writeByte(@intCast(v & 0xFF));
}

fn writeU64(w: anytype, v: u64) !void {
    var i: u6 = 7;
    while (true) : (i -= 1) {
        try w.writeByte(@intCast((v >> (@as(u6, i) * 8)) & 0xFF));
        if (i == 0) break;
    }
}

fn readStr(data: []const u8, fbs: *std.io.FixedBufferStream([]const u8)) ?[]const u8 {
    const r = fbs.reader();
    const hi = r.readByte() catch return null;
    const lo = r.readByte() catch return null;
    const len: usize = (@as(usize, hi) << 8) | @as(usize, lo);
    const pos = fbs.pos;
    if (pos + len > data.len) return null;
    fbs.pos += len;
    return data[pos .. pos + len];
}

fn readU16(r: anytype) ?u16 {
    const hi = r.readByte() catch return null;
    const lo = r.readByte() catch return null;
    return (@as(u16, hi) << 8) | @as(u16, lo);
}

fn readU32(r: anytype) ?u32 {
    const b = [4]u8{
        r.readByte() catch return null,
        r.readByte() catch return null,
        r.readByte() catch return null,
        r.readByte() catch return null,
    };
    return (@as(u32, b[0]) << 24) | (@as(u32, b[1]) << 16) | (@as(u32, b[2]) << 8) | @as(u32, b[3]);
}

fn readU64(r: anytype) ?u64 {
    var result: u64 = 0;
    var i: u4 = 0;
    while (i < 8) : (i += 1) {
        const byte = r.readByte() catch return null;
        result = (result << 8) | @as(u64, byte);
    }
    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "encode/decode: room_join round-trip" {
    const msg = Message{ .room_join = .{
        .room_jid = "dev@conference.example.com",
        .real_jid = "alice@example.com/Mobile",
        .nick = "alice",
        .worker_id = 2,
        .session_token = .{ .index = 42, .gen = 7, .kind = token_kinds.session },
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    switch (decoded) {
        .room_join => |ev| {
            try std.testing.expectEqualStrings("dev@conference.example.com", ev.room_jid);
            try std.testing.expectEqualStrings("alice@example.com/Mobile", ev.real_jid);
            try std.testing.expectEqualStrings("alice", ev.nick);
            try std.testing.expectEqual(@as(u16, 2), ev.worker_id);
            try std.testing.expectEqual(@as(u32, 42), ev.session_token.index);
            try std.testing.expectEqual(@as(u24, 7), ev.session_token.gen);
        },
        else => return error.WrongTag,
    }
}

test "encode/decode: room_part round-trip" {
    const msg = Message{ .room_part = .{
        .room_jid = "chat@muc.example.com",
        .real_jid = "bob@example.com/Desktop",
        .nick = "bob",
        .worker_id = 0,
        .session_token = .{ .index = 7, .gen = 3, .kind = token_kinds.session },
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    try std.testing.expectEqual(Tag.room_part, std.meta.activeTag(decoded));
}

test "encode/decode: room_message round-trip" {
    const msg = Message{ .room_message = .{
        .room_jid = "dev@conference.example.com",
        .from_jid = "alice@example.com/Mobile",
        .inner_xml = "<body>hello world</body>",
        .stanza_id = "abc-123",
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    switch (decoded) {
        .room_message => |ev| {
            try std.testing.expectEqualStrings("dev@conference.example.com", ev.room_jid);
            try std.testing.expectEqualStrings("<body>hello world</body>", ev.inner_xml);
            try std.testing.expectEqualStrings("abc-123", ev.stanza_id);
        },
        else => return error.WrongTag,
    }
}

test "encode/decode: session_closed round-trip" {
    const msg = Message{ .session_closed = .{
        .local = "bob",
        .domain = "example.com",
        .resource = "Desktop",
        .worker_id = 3,
        .session_token = .{ .index = 55, .gen = 1, .kind = token_kinds.session },
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    try std.testing.expectEqual(Tag.session_closed, std.meta.activeTag(decoded));
}

test "encode/decode: disco_info round-trip" {
    const msg = Message{ .room_disco_info = .{
        .room_jid = "dev@conference.example.com",
        .iq_id = "disco-1",
        .reply_to_worker = 2,
        .reply_to_token = .{ .index = 99, .gen = 7, .kind = token_kinds.session },
        .reply_to_jid = "alice@example.com/Mobile",
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    switch (decoded) {
        .room_disco_info => |ev| {
            try std.testing.expectEqualStrings("dev@conference.example.com", ev.room_jid);
            try std.testing.expectEqualStrings("disco-1", ev.iq_id);
            try std.testing.expectEqual(@as(u16, 2), ev.reply_to_worker);
            try std.testing.expectEqual(@as(u32, 99), ev.reply_to_token.index);
            try std.testing.expectEqual(@as(u24, 7), ev.reply_to_token.gen);
            try std.testing.expectEqualStrings("alice@example.com/Mobile", ev.reply_to_jid);
        },
        else => return error.WrongTag,
    }
}

test "encode: buffer too small returns null" {
    const msg = Message{ .room_join = .{
        .room_jid = "dev@conference.example.com",
        .real_jid = "alice@example.com/Mobile",
        .nick = "alice",
        .worker_id = 0,
        .session_token = .none,
    } };

    var tiny: [4]u8 = undefined;
    try std.testing.expect(encode(&tiny, msg) == null);
}

test "decode: empty buffer returns null" {
    try std.testing.expect(decode("") == null);
}

test "decode: invalid tag returns null" {
    const data = [_]u8{0xFF};
    try std.testing.expect(decode(&data) == null);
}

test "decode: truncated payload returns null" {
    // Tag byte for room_join but no fields
    const data = [_]u8{0x10};
    try std.testing.expect(decode(&data) == null);
}

test "tag method returns correct wire byte" {
    const msg = Message{ .room_join = .{
        .room_jid = "",
        .real_jid = "",
        .nick = "",
        .worker_id = 0,
        .session_token = .none,
    } };
    try std.testing.expectEqual(@as(u8, 0x10), msg.tag());
}

test "encode/decode: shadow_join round-trip" {
    const msg = Message{ .shadow_join = .{
        .room_jid = "dev@conference.example.com",
        .real_jid = "alice@example.com/Mobile",
        .nick = "alice",
        .worker_id = 1,
        .session_token = .{ .index = 33, .gen = 5, .kind = token_kinds.session },
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    switch (decoded) {
        .shadow_join => |ev| {
            try std.testing.expectEqualStrings("dev@conference.example.com", ev.room_jid);
            try std.testing.expectEqualStrings("alice@example.com/Mobile", ev.real_jid);
            try std.testing.expectEqualStrings("alice", ev.nick);
            try std.testing.expectEqual(@as(u16, 1), ev.worker_id);
            try std.testing.expectEqual(@as(u32, 33), ev.session_token.index);
        },
        else => return error.WrongTag,
    }
}

test "encode/decode: shadow_part round-trip" {
    const msg = Message{ .shadow_part = .{
        .room_jid = "chat@conference.example.com",
        .real_jid = "bob@example.com/Desktop",
        .nick = "bob",
        .worker_id = 2,
        .session_token = .{ .index = 77, .gen = 1, .kind = token_kinds.session },
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    try std.testing.expectEqual(Tag.shadow_part, std.meta.activeTag(decoded));
}

test "encode/decode: room_admin round-trip" {
    const msg = Message{ .room_admin = .{
        .room_jid = "dev@conference.example.com",
        .actor_jid = "alice@example.com/Mobile",
        .target_nick = "bob",
        .new_role = "none",
        .iq_id = "admin-1",
        .reply_to_worker = 0,
        .reply_to_token = .{ .index = 5, .gen = 3, .kind = token_kinds.session },
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    switch (decoded) {
        .room_admin => |ev| {
            try std.testing.expectEqualStrings("dev@conference.example.com", ev.room_jid);
            try std.testing.expectEqualStrings("alice@example.com/Mobile", ev.actor_jid);
            try std.testing.expectEqualStrings("bob", ev.target_nick);
            try std.testing.expectEqualStrings("none", ev.new_role);
            try std.testing.expectEqualStrings("admin-1", ev.iq_id);
            try std.testing.expectEqual(@as(u16, 0), ev.reply_to_worker);
            try std.testing.expectEqual(@as(u32, 5), ev.reply_to_token.index);
            try std.testing.expectEqual(@as(u24, 3), ev.reply_to_token.gen);
        },
        else => return error.WrongTag,
    }
}

test "encode/decode: room_directory_update round-trip" {
    const msg = Message{ .room_directory_update = .{
        .room_jid = "dev@conference.example.com",
        .room_name = "Dev Room",
        .active = true,
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    switch (decoded) {
        .room_directory_update => |ev| {
            try std.testing.expectEqualStrings("dev@conference.example.com", ev.room_jid);
            try std.testing.expectEqualStrings("Dev Room", ev.room_name);
            try std.testing.expect(ev.active);
        },
        else => return error.WrongTag,
    }
}

test "encode/decode: invalidate_subscription round-trip" {
    const msg = Message{ .invalidate_subscription = .{ .bare_jid = "alice@example.com" } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    switch (decoded) {
        .invalidate_subscription => |ev| {
            try std.testing.expectEqualStrings("alice@example.com", ev.bare_jid);
        },
        else => return error.WrongTag,
    }
}

test "encode/decode: sm_resume_request round-trip" {
    const msg = Message{ .sm_resume_request = .{
        .previd = "0001abcdef0123456789abcdef01234567",
        .h = 41,
        .req_worker = 3,
        .req_token = .{ .index = 17, .gen = 1, .kind = token_kinds.session },
        .req_epoch = 5,
        .auth_local = "alice",
        .auth_domain = "example.com",
        .hops = 2,
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    switch (decoded) {
        .sm_resume_request => |ev| {
            try std.testing.expectEqualStrings("0001abcdef0123456789abcdef01234567", ev.previd);
            try std.testing.expectEqual(@as(u32, 41), ev.h);
            try std.testing.expectEqual(@as(u16, 3), ev.req_worker);
            try std.testing.expectEqual(@as(u32, 17), ev.req_token.index);
            try std.testing.expectEqual(@as(u32, 5), ev.req_epoch);
            try std.testing.expectEqualStrings("alice", ev.auth_local);
            try std.testing.expectEqualStrings("example.com", ev.auth_domain);
            try std.testing.expectEqual(@as(u8, 2), ev.hops);
        },
        else => return error.WrongTag,
    }
}

test "encode/decode: sm_resume_reply round-trip" {
    const msg = Message{ .sm_resume_reply = .{
        .previd = "0002abcdef0123456789abcdef01234567",
        .req_token = .{ .index = 9, .gen = 1, .kind = token_kinds.session },
        .req_epoch = 2,
        .status = "ok",
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    switch (decoded) {
        .sm_resume_reply => |ev| {
            try std.testing.expectEqualStrings("ok", ev.status);
            try std.testing.expectEqual(@as(u32, 9), ev.req_token.index);
            try std.testing.expectEqual(@as(u32, 2), ev.req_epoch);
        },
        else => return error.WrongTag,
    }
}

test "encode/decode: room_occupant_move round-trip" {
    const msg = Message{ .room_occupant_move = .{
        .room_jid = "dev@conference.example.com",
        .real_jid = "alice@example.com/phone",
        .old_worker_id = 0,
        .new_worker_id = 3,
        .new_token = .{ .index = 271, .gen = 41, .kind = token_kinds.session },
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    switch (decoded) {
        .room_occupant_move => |ev| {
            try std.testing.expectEqualStrings("dev@conference.example.com", ev.room_jid);
            try std.testing.expectEqualStrings("alice@example.com/phone", ev.real_jid);
            try std.testing.expectEqual(@as(u16, 0), ev.old_worker_id);
            try std.testing.expectEqual(@as(u16, 3), ev.new_worker_id);
            try std.testing.expectEqual(@as(u32, 271), ev.new_token.index);
            try std.testing.expectEqual(@as(u24, 41), ev.new_token.gen);
        },
        else => return error.WrongTag,
    }
}

test "encode/decode: session_kick round-trips" {
    const req = Message{ .session_kick_request = .{
        .local = "alice",
        .domain = "example.com",
        .resource = "phone",
        .req_worker = 2,
        .req_token = .{ .index = 17, .gen = 1, .kind = token_kinds.session },
        .req_epoch = 9,
    } };
    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, req).?;
    switch (decode(buf[0..len]).?) {
        .session_kick_request => |ev| {
            try std.testing.expectEqualStrings("alice", ev.local);
            try std.testing.expectEqualStrings("example.com", ev.domain);
            try std.testing.expectEqualStrings("phone", ev.resource);
            try std.testing.expectEqual(@as(u16, 2), ev.req_worker);
            try std.testing.expectEqual(@as(u32, 17), ev.req_token.index);
            try std.testing.expectEqual(@as(u32, 9), ev.req_epoch);
        },
        else => return error.WrongTag,
    }

    const rep = Message{ .session_kick_reply = .{ .req_token = .{ .index = 17, .gen = 1, .kind = token_kinds.session }, .req_epoch = 9 } };
    const len2 = encode(&buf, rep).?;
    switch (decode(buf[0..len2]).?) {
        .session_kick_reply => |ev| {
            try std.testing.expectEqual(@as(u32, 17), ev.req_token.index);
            try std.testing.expectEqual(@as(u32, 9), ev.req_epoch);
        },
        else => return error.WrongTag,
    }
}

test "encode/decode: room_mam_query round-trip" {
    const msg = Message{ .room_mam_query = .{
        .room_jid = "dev@conference.example.com",
        .iq_id = "iq-stanza-7",
        .query_id = "mam-q1",
        .start = "2026-06-01T00:00:00Z",
        .end_field = "",
        .with = "",
        .max = "25",
        .after_id = "arc-1234",
        .before_id = "",
        .reply_to_worker = 1,
        .reply_to_token = .{ .index = 42, .gen = 9, .kind = token_kinds.session },
        .reply_to_jid = "alice@example.com/Mobile",
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    switch (decoded) {
        .room_mam_query => |ev| {
            try std.testing.expectEqualStrings("dev@conference.example.com", ev.room_jid);
            try std.testing.expectEqualStrings("iq-stanza-7", ev.iq_id);
            try std.testing.expectEqualStrings("mam-q1", ev.query_id);
            try std.testing.expectEqualStrings("2026-06-01T00:00:00Z", ev.start);
            try std.testing.expectEqualStrings("25", ev.max);
            try std.testing.expectEqualStrings("arc-1234", ev.after_id);
            try std.testing.expectEqualStrings("", ev.before_id);
            try std.testing.expectEqual(@as(u16, 1), ev.reply_to_worker);
            try std.testing.expectEqual(@as(u32, 42), ev.reply_to_token.index);
            try std.testing.expectEqual(@as(u24, 9), ev.reply_to_token.gen);
            try std.testing.expectEqualStrings("alice@example.com/Mobile", ev.reply_to_jid);
        },
        else => return error.WrongTag,
    }
}

/// Build a plausible value of a payload field type for the codec test.
fn testFieldValue(comptime T: type) T {
    if (T == Token) return Token.init(7, 3, token_kinds.session);
    return switch (@typeInfo(T)) {
        .bool => true,
        .int => 1,
        .@"enum" => @enumFromInt(0),
        .pointer => |p| blk: {
            if (p.size == .slice and p.child == u8) break :blk "field";
            @compileError("unsupported field type " ++ @typeName(T));
        },
        else => @compileError("unsupported field type " ++ @typeName(T)),
    };
}

test "codec round-trips every remaining tag" {
    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    inline for (@typeInfo(Tag).@"enum".fields) |f| {
        const t: Tag = @enumFromInt(f.value);
        const Payload = std.meta.TagPayload(Message, t);
        var ev: Payload = undefined;
        inline for (@typeInfo(Payload).@"struct".fields) |fld| {
            @field(ev, fld.name) = testFieldValue(fld.type);
        }
        const msg = @unionInit(Message, @tagName(t), ev);
        const n = encode(&buf, msg) orelse return error.TestUnexpectedResult;
        const decoded = decode(buf[0..n]) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(t, std.meta.activeTag(decoded));
        try std.testing.expectEqualDeep(ev, @field(decoded, @tagName(t)));
    }
}
