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

const log = std.log.scoped(.message);

// ============================================================================
// Message payload structs
// ============================================================================

/// Session lifecycle: a session has been bound to a JID.
pub const SessionBound = struct {
    local: []const u8,
    domain: []const u8,
    resource: []const u8,
    worker_id: u16,
    session_id: u32,
};

/// Session lifecycle: a session has been closed/disconnected.
pub const SessionClosed = struct {
    local: []const u8,
    domain: []const u8,
    resource: []const u8,
    worker_id: u16,
    session_id: u32,
};

/// Presence state change.
pub const PresenceEvent = struct {
    local: []const u8,
    domain: []const u8,
    resource: []const u8,
    worker_id: u16,
    session_id: u32,
};

/// A stanza (message or presence) to be routed.
pub const StanzaEvent = struct {
    from: []const u8,
    to: []const u8,
    stanza_type: []const u8,
    id: []const u8,
    inner_xml: []const u8,
    kind: StanzaKind,
};

pub const StanzaKind = enum(u8) {
    message = 0,
    presence = 1,
};

/// MUC room join/part request.
pub const RoomEvent = struct {
    room_jid: []const u8,
    real_jid: []const u8,
    nick: []const u8,
    worker_id: u16,
    session_id: u32,
    generation: u32,
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
/// occupant record's (worker, session, generation) triple in place — no
/// join presence fan-out, no new-member handling. Identity is the full JID.
pub const RoomOccupantMove = struct {
    room_jid: []const u8,
    real_jid: []const u8,
    /// Worker the occupant record pointed at before the move (for shadow
    /// cleanup on that worker).
    old_worker_id: u16,
    /// Resuming worker.
    new_worker_id: u16,
    /// Session slot of the resumed connection on the resuming worker.
    new_session_id: u32,
    /// ABA generation from the resuming worker's SessionMap bind.
    new_generation: u32,
};

/// MUC disco query (routed to owning worker).
pub const DiscoRequest = struct {
    room_jid: []const u8,
    iq_id: []const u8,
    reply_to_worker: u16,
    reply_to_session: u32,
    /// ABA generation of the requesting session, captured on the originating
    /// worker where that session is live (T173). The reply's ds.deliver()
    /// validates it — a hardcoded 0 is silently dropped.
    reply_to_generation: u32,
    /// Full JID of the querying session (for the 'to' attribute in the response).
    reply_to_jid: []const u8,
};

/// Subscription-cache invalidation for one bare JID, broadcast to all workers.
pub const CacheInvalidate = struct {
    bare_jid: []const u8,
};

/// PEP publish notification.
pub const PepEvent = struct {
    publisher_local: []const u8,
    publisher_domain: []const u8,
    node: []const u8,
};

/// MUC admin action (kick/ban/voice) routed to owning worker.
pub const AdminAction = struct {
    room_jid: []const u8,
    actor_jid: []const u8,
    target_nick: []const u8,
    new_role: []const u8,
    iq_id: []const u8,
    reply_to_worker: u16,
    reply_to_session: u32,
    /// ABA generation of the requesting session, captured on the originating
    /// worker where that session is live (T173). The reply's ds.deliver()
    /// validates it — a hardcoded 0 is silently dropped.
    reply_to_generation: u32,
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
    reply_to_session: u32,
    /// ABA generation of the querying session, captured on the originating
    /// worker where that session is live (T173). The reply's ds.deliver()
    /// validates it — a hardcoded 0 is silently dropped.
    reply_to_generation: u32,
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
    /// Session slot on the requesting worker.
    req_session: u32,
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
    req_session: u32,
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
    /// Session slot + per-session epoch on the requesting worker (ABA guard).
    req_session: u32,
    req_epoch: u32,
};

/// T154: owner (or previous owner) → requester. The binding, if it existed,
/// is gone by the time this reply is drained; the requester retries its bind.
pub const SessionKickReply = struct {
    req_session: u32,
    req_epoch: u32,
};

/// Archive confirmation.
pub const ArchiveEvent = struct {
    bare_jid: []const u8,
    stanza_id: []const u8,
    timestamp: u64,
};

// ============================================================================
// Message tagged union
// ============================================================================

pub const Tag = enum(u8) {
    session_bound = 0x01,
    session_closed = 0x02,
    presence_available = 0x03,
    presence_unavailable = 0x04,
    message_received = 0x05,
    message_routed = 0x06,
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
    pep_published = 0x20,
    stanza_archived = 0x30,
    /// Cross-worker SM resume handoff (T177), flagged via SM_ACTOR_SENTINEL.
    sm_resume_request = 0x40,
    sm_resume_reply = 0x41,
    /// T154 cross-worker resource takeover (RFC 6120 §7.7.3 eviction).
    session_kick_request = 0x42,
    session_kick_reply = 0x43,
};

pub const Message = union(Tag) {
    session_bound: SessionBound,
    session_closed: SessionClosed,
    presence_available: PresenceEvent,
    presence_unavailable: PresenceEvent,
    message_received: StanzaEvent,
    message_routed: StanzaEvent,
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
    pep_published: PepEvent,
    stanza_archived: ArchiveEvent,
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

/// Encode a Message into a byte buffer for cross-thread MPSC delivery.
/// Returns the number of bytes written, or null if the buffer is too small.
pub fn encode(buf: []u8, msg: Message) ?usize {
    if (buf.len == 0) return null;
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();

    // Tag byte
    w.writeByte(msg.tag()) catch return null;

    switch (msg) {
        inline .session_bound, .session_closed, .presence_available, .presence_unavailable => |ev| {
            writeStr(w, ev.local) catch return null;
            writeStr(w, ev.domain) catch return null;
            writeStr(w, ev.resource) catch return null;
            writeU16(w, ev.worker_id) catch return null;
            writeU32(w, ev.session_id) catch return null;
        },
        inline .room_join, .room_part, .shadow_join, .shadow_part => |ev| {
            writeStr(w, ev.room_jid) catch return null;
            writeStr(w, ev.real_jid) catch return null;
            writeStr(w, ev.nick) catch return null;
            writeU16(w, ev.worker_id) catch return null;
            writeU32(w, ev.session_id) catch return null;
            writeU32(w, ev.generation) catch return null;
        },
        .room_message => |ev| {
            writeStr(w, ev.room_jid) catch return null;
            writeStr(w, ev.from_jid) catch return null;
            writeStr(w, ev.inner_xml) catch return null;
            writeStr(w, ev.stanza_id) catch return null;
        },
        inline .room_disco_info, .room_disco_items => |ev| {
            writeStr(w, ev.room_jid) catch return null;
            writeStr(w, ev.iq_id) catch return null;
            writeU16(w, ev.reply_to_worker) catch return null;
            writeU32(w, ev.reply_to_session) catch return null;
            writeU32(w, ev.reply_to_generation) catch return null;
            writeStr(w, ev.reply_to_jid) catch return null;
        },
        inline .message_received, .message_routed => |ev| {
            writeStr(w, ev.from) catch return null;
            writeStr(w, ev.to) catch return null;
            writeStr(w, ev.stanza_type) catch return null;
            writeStr(w, ev.id) catch return null;
            writeStr(w, ev.inner_xml) catch return null;
            w.writeByte(@intFromEnum(ev.kind)) catch return null;
        },
        .room_admin => |ev| {
            writeStr(w, ev.room_jid) catch return null;
            writeStr(w, ev.actor_jid) catch return null;
            writeStr(w, ev.target_nick) catch return null;
            writeStr(w, ev.new_role) catch return null;
            writeStr(w, ev.iq_id) catch return null;
            writeU16(w, ev.reply_to_worker) catch return null;
            writeU32(w, ev.reply_to_session) catch return null;
            writeU32(w, ev.reply_to_generation) catch return null;
        },
        .room_directory_update => |ev| {
            writeStr(w, ev.room_jid) catch return null;
            writeStr(w, ev.room_name) catch return null;
            w.writeByte(if (ev.active) 1 else 0) catch return null;
        },
        .room_mam_query => |ev| {
            writeStr(w, ev.room_jid) catch return null;
            writeStr(w, ev.iq_id) catch return null;
            writeStr(w, ev.query_id) catch return null;
            writeStr(w, ev.start) catch return null;
            writeStr(w, ev.end_field) catch return null;
            writeStr(w, ev.with) catch return null;
            writeStr(w, ev.max) catch return null;
            writeStr(w, ev.after_id) catch return null;
            writeStr(w, ev.before_id) catch return null;
            writeU16(w, ev.reply_to_worker) catch return null;
            writeU32(w, ev.reply_to_session) catch return null;
            writeU32(w, ev.reply_to_generation) catch return null;
            writeStr(w, ev.reply_to_jid) catch return null;
        },
        .room_occupant_move => |ev| {
            writeStr(w, ev.room_jid) catch return null;
            writeStr(w, ev.real_jid) catch return null;
            writeU16(w, ev.old_worker_id) catch return null;
            writeU16(w, ev.new_worker_id) catch return null;
            writeU32(w, ev.new_session_id) catch return null;
            writeU32(w, ev.new_generation) catch return null;
        },
        .invalidate_subscription => |ev| {
            writeStr(w, ev.bare_jid) catch return null;
        },
        .pep_published => |ev| {
            writeStr(w, ev.publisher_local) catch return null;
            writeStr(w, ev.publisher_domain) catch return null;
            writeStr(w, ev.node) catch return null;
        },
        .stanza_archived => |ev| {
            writeStr(w, ev.bare_jid) catch return null;
            writeStr(w, ev.stanza_id) catch return null;
            writeU64(w, ev.timestamp) catch return null;
        },
        .sm_resume_request => |ev| {
            writeStr(w, ev.previd) catch return null;
            writeU32(w, ev.h) catch return null;
            writeU16(w, ev.req_worker) catch return null;
            writeU32(w, ev.req_session) catch return null;
            writeU32(w, ev.req_epoch) catch return null;
            writeStr(w, ev.auth_local) catch return null;
            writeStr(w, ev.auth_domain) catch return null;
            w.writeByte(ev.hops) catch return null;
        },
        .sm_resume_reply => |ev| {
            writeStr(w, ev.previd) catch return null;
            writeU32(w, ev.req_session) catch return null;
            writeU32(w, ev.req_epoch) catch return null;
            writeStr(w, ev.status) catch return null;
        },
        .session_kick_request => |ev| {
            writeStr(w, ev.local) catch return null;
            writeStr(w, ev.domain) catch return null;
            writeStr(w, ev.resource) catch return null;
            writeU16(w, ev.req_worker) catch return null;
            writeU32(w, ev.req_session) catch return null;
            writeU32(w, ev.req_epoch) catch return null;
        },
        .session_kick_reply => |ev| {
            writeU32(w, ev.req_session) catch return null;
            writeU32(w, ev.req_epoch) catch return null;
        },
    }

    return fbs.pos;
}

/// Decode a Message from a byte buffer (e.g., from an MPSC slot).
/// The returned Message contains slices pointing into the input `data` buffer.
/// The caller must not modify `data` while the Message is in use.
pub fn decode(data: []const u8) ?Message {
    if (data.len < 1) return null;
    var fbs = std.io.fixedBufferStream(data);
    const r = fbs.reader();

    const tag_byte = r.readByte() catch return null;
    const tag_val = std.meta.intToEnum(Tag, tag_byte) catch return null;

    switch (tag_val) {
        .session_bound, .session_closed, .presence_available, .presence_unavailable => {
            const local = readStr(data, &fbs) orelse return null;
            const domain = readStr(data, &fbs) orelse return null;
            const resource = readStr(data, &fbs) orelse return null;
            const worker_id = readU16(r) orelse return null;
            const session_id = readU32(r) orelse return null;
            const ev = PresenceEvent{
                .local = local,
                .domain = domain,
                .resource = resource,
                .worker_id = worker_id,
                .session_id = session_id,
            };
            return switch (tag_val) {
                .session_bound => .{ .session_bound = .{
                    .local = ev.local,
                    .domain = ev.domain,
                    .resource = ev.resource,
                    .worker_id = ev.worker_id,
                    .session_id = ev.session_id,
                } },
                .session_closed => .{ .session_closed = .{
                    .local = ev.local,
                    .domain = ev.domain,
                    .resource = ev.resource,
                    .worker_id = ev.worker_id,
                    .session_id = ev.session_id,
                } },
                .presence_available => .{ .presence_available = ev },
                .presence_unavailable => .{ .presence_unavailable = ev },
                else => unreachable,
            };
        },
        .room_join, .room_part, .shadow_join, .shadow_part => {
            const room_jid = readStr(data, &fbs) orelse return null;
            const real_jid = readStr(data, &fbs) orelse return null;
            const nick = readStr(data, &fbs) orelse return null;
            const worker_id = readU16(r) orelse return null;
            const session_id = readU32(r) orelse return null;
            const generation = readU32(r) orelse return null;
            const ev = RoomEvent{
                .room_jid = room_jid,
                .real_jid = real_jid,
                .nick = nick,
                .worker_id = worker_id,
                .session_id = session_id,
                .generation = generation,
            };
            return switch (tag_val) {
                .room_join => .{ .room_join = ev },
                .room_part => .{ .room_part = ev },
                .shadow_join => .{ .shadow_join = ev },
                .shadow_part => .{ .shadow_part = ev },
                else => unreachable,
            };
        },
        .room_message => {
            const room_jid = readStr(data, &fbs) orelse return null;
            const from_jid = readStr(data, &fbs) orelse return null;
            const inner_xml = readStr(data, &fbs) orelse return null;
            const stanza_id = readStr(data, &fbs) orelse return null;
            return .{ .room_message = .{
                .room_jid = room_jid,
                .from_jid = from_jid,
                .inner_xml = inner_xml,
                .stanza_id = stanza_id,
            } };
        },
        .room_disco_info, .room_disco_items => {
            const room_jid = readStr(data, &fbs) orelse return null;
            const iq_id = readStr(data, &fbs) orelse return null;
            const reply_to_worker = readU16(r) orelse return null;
            const reply_to_session = readU32(r) orelse return null;
            const reply_to_generation = readU32(r) orelse return null;
            const reply_to_jid = readStr(data, &fbs) orelse return null;
            const ev = DiscoRequest{
                .room_jid = room_jid,
                .iq_id = iq_id,
                .reply_to_worker = reply_to_worker,
                .reply_to_session = reply_to_session,
                .reply_to_generation = reply_to_generation,
                .reply_to_jid = reply_to_jid,
            };
            return switch (tag_val) {
                .room_disco_info => .{ .room_disco_info = ev },
                .room_disco_items => .{ .room_disco_items = ev },
                else => unreachable,
            };
        },
        .message_received, .message_routed => {
            const from = readStr(data, &fbs) orelse return null;
            const to = readStr(data, &fbs) orelse return null;
            const stanza_type = readStr(data, &fbs) orelse return null;
            const id = readStr(data, &fbs) orelse return null;
            const inner_xml = readStr(data, &fbs) orelse return null;
            const kind_byte = r.readByte() catch return null;
            const kind = std.meta.intToEnum(StanzaKind, kind_byte) catch return null;
            const ev = StanzaEvent{
                .from = from,
                .to = to,
                .stanza_type = stanza_type,
                .id = id,
                .inner_xml = inner_xml,
                .kind = kind,
            };
            return switch (tag_val) {
                .message_received => .{ .message_received = ev },
                .message_routed => .{ .message_routed = ev },
                else => unreachable,
            };
        },
        .room_admin => {
            const room_jid = readStr(data, &fbs) orelse return null;
            const actor_jid = readStr(data, &fbs) orelse return null;
            const target_nick = readStr(data, &fbs) orelse return null;
            const new_role = readStr(data, &fbs) orelse return null;
            const iq_id = readStr(data, &fbs) orelse return null;
            const reply_to_worker = readU16(r) orelse return null;
            const reply_to_session = readU32(r) orelse return null;
            const reply_to_generation = readU32(r) orelse return null;
            return .{ .room_admin = .{
                .room_jid = room_jid,
                .actor_jid = actor_jid,
                .target_nick = target_nick,
                .new_role = new_role,
                .iq_id = iq_id,
                .reply_to_worker = reply_to_worker,
                .reply_to_session = reply_to_session,
                .reply_to_generation = reply_to_generation,
            } };
        },
        .room_directory_update => {
            const room_jid = readStr(data, &fbs) orelse return null;
            const room_name = readStr(data, &fbs) orelse return null;
            const active_byte = r.readByte() catch return null;
            return .{ .room_directory_update = .{
                .room_jid = room_jid,
                .room_name = room_name,
                .active = active_byte != 0,
            } };
        },
        .room_mam_query => {
            const room_jid = readStr(data, &fbs) orelse return null;
            const iq_id = readStr(data, &fbs) orelse return null;
            const query_id = readStr(data, &fbs) orelse return null;
            const start = readStr(data, &fbs) orelse return null;
            const end_field = readStr(data, &fbs) orelse return null;
            const with = readStr(data, &fbs) orelse return null;
            const max = readStr(data, &fbs) orelse return null;
            const after_id = readStr(data, &fbs) orelse return null;
            const before_id = readStr(data, &fbs) orelse return null;
            const reply_to_worker = readU16(r) orelse return null;
            const reply_to_session = readU32(r) orelse return null;
            const reply_to_generation = readU32(r) orelse return null;
            const reply_to_jid = readStr(data, &fbs) orelse return null;
            return .{ .room_mam_query = .{
                .room_jid = room_jid,
                .iq_id = iq_id,
                .query_id = query_id,
                .start = start,
                .end_field = end_field,
                .with = with,
                .max = max,
                .after_id = after_id,
                .before_id = before_id,
                .reply_to_worker = reply_to_worker,
                .reply_to_session = reply_to_session,
                .reply_to_generation = reply_to_generation,
                .reply_to_jid = reply_to_jid,
            } };
        },
        .invalidate_subscription => {
            const bare_jid = readStr(data, &fbs) orelse return null;
            return .{ .invalidate_subscription = .{ .bare_jid = bare_jid } };
        },
        .room_occupant_move => {
            const room_jid = readStr(data, &fbs) orelse return null;
            const real_jid = readStr(data, &fbs) orelse return null;
            const old_worker_id = readU16(r) orelse return null;
            const new_worker_id = readU16(r) orelse return null;
            const new_session_id = readU32(r) orelse return null;
            const new_generation = readU32(r) orelse return null;
            return .{ .room_occupant_move = .{
                .room_jid = room_jid,
                .real_jid = real_jid,
                .old_worker_id = old_worker_id,
                .new_worker_id = new_worker_id,
                .new_session_id = new_session_id,
                .new_generation = new_generation,
            } };
        },
        .pep_published => {
            const publisher_local = readStr(data, &fbs) orelse return null;
            const publisher_domain = readStr(data, &fbs) orelse return null;
            const node = readStr(data, &fbs) orelse return null;
            return .{ .pep_published = .{
                .publisher_local = publisher_local,
                .publisher_domain = publisher_domain,
                .node = node,
            } };
        },
        .stanza_archived => {
            const bare_jid = readStr(data, &fbs) orelse return null;
            const stanza_id = readStr(data, &fbs) orelse return null;
            const timestamp = readU64(r) orelse return null;
            return .{ .stanza_archived = .{
                .bare_jid = bare_jid,
                .stanza_id = stanza_id,
                .timestamp = timestamp,
            } };
        },
        .sm_resume_request => {
            const previd = readStr(data, &fbs) orelse return null;
            const h = readU32(r) orelse return null;
            const req_worker = readU16(r) orelse return null;
            const req_session = readU32(r) orelse return null;
            const req_epoch = readU32(r) orelse return null;
            const auth_local = readStr(data, &fbs) orelse return null;
            const auth_domain = readStr(data, &fbs) orelse return null;
            const hops = r.readByte() catch return null;
            return .{ .sm_resume_request = .{
                .previd = previd,
                .h = h,
                .req_worker = req_worker,
                .req_session = req_session,
                .req_epoch = req_epoch,
                .auth_local = auth_local,
                .auth_domain = auth_domain,
                .hops = hops,
            } };
        },
        .sm_resume_reply => {
            const previd = readStr(data, &fbs) orelse return null;
            const req_session = readU32(r) orelse return null;
            const req_epoch = readU32(r) orelse return null;
            const status = readStr(data, &fbs) orelse return null;
            return .{ .sm_resume_reply = .{
                .previd = previd,
                .req_session = req_session,
                .req_epoch = req_epoch,
                .status = status,
            } };
        },
        .session_kick_request => {
            const local = readStr(data, &fbs) orelse return null;
            const domain = readStr(data, &fbs) orelse return null;
            const resource = readStr(data, &fbs) orelse return null;
            const req_worker = readU16(r) orelse return null;
            const req_session = readU32(r) orelse return null;
            const req_epoch = readU32(r) orelse return null;
            return .{ .session_kick_request = .{
                .local = local,
                .domain = domain,
                .resource = resource,
                .req_worker = req_worker,
                .req_session = req_session,
                .req_epoch = req_epoch,
            } };
        },
        .session_kick_reply => {
            const req_session = readU32(r) orelse return null;
            const req_epoch = readU32(r) orelse return null;
            return .{ .session_kick_reply = .{
                .req_session = req_session,
                .req_epoch = req_epoch,
            } };
        },
    }
}

// ============================================================================
// Wire format helpers
// ============================================================================

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
        .session_id = 42,
        .generation = 7,
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
            try std.testing.expectEqual(@as(u32, 42), ev.session_id);
            try std.testing.expectEqual(@as(u32, 7), ev.generation);
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
        .session_id = 7,
        .generation = 3,
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

test "encode/decode: session_bound round-trip" {
    const msg = Message{ .session_bound = .{
        .local = "alice",
        .domain = "example.com",
        .resource = "Mobile",
        .worker_id = 1,
        .session_id = 100,
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    switch (decoded) {
        .session_bound => |ev| {
            try std.testing.expectEqualStrings("alice", ev.local);
            try std.testing.expectEqualStrings("example.com", ev.domain);
            try std.testing.expectEqualStrings("Mobile", ev.resource);
            try std.testing.expectEqual(@as(u16, 1), ev.worker_id);
            try std.testing.expectEqual(@as(u32, 100), ev.session_id);
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
        .session_id = 55,
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    try std.testing.expectEqual(Tag.session_closed, std.meta.activeTag(decoded));
}

test "encode/decode: presence_available round-trip" {
    const msg = Message{ .presence_available = .{
        .local = "charlie",
        .domain = "morante.dev",
        .resource = "Thunderbird",
        .worker_id = 0,
        .session_id = 12,
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    try std.testing.expectEqual(Tag.presence_available, std.meta.activeTag(decoded));
    switch (decoded) {
        .presence_available => |ev| {
            try std.testing.expectEqualStrings("charlie", ev.local);
            try std.testing.expectEqualStrings("Thunderbird", ev.resource);
        },
        else => return error.WrongTag,
    }
}

test "encode/decode: disco_info round-trip" {
    const msg = Message{ .room_disco_info = .{
        .room_jid = "dev@conference.example.com",
        .iq_id = "disco-1",
        .reply_to_worker = 2,
        .reply_to_session = 99,
        .reply_to_generation = 7,
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
            try std.testing.expectEqual(@as(u32, 99), ev.reply_to_session);
            try std.testing.expectEqual(@as(u32, 7), ev.reply_to_generation);
            try std.testing.expectEqualStrings("alice@example.com/Mobile", ev.reply_to_jid);
        },
        else => return error.WrongTag,
    }
}

test "encode/decode: message_received round-trip" {
    const msg = Message{ .message_received = .{
        .from = "alice@example.com/Mobile",
        .to = "bob@example.com",
        .stanza_type = "chat",
        .id = "msg-42",
        .inner_xml = "<body>hello</body>",
        .kind = .message,
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    switch (decoded) {
        .message_received => |ev| {
            try std.testing.expectEqualStrings("alice@example.com/Mobile", ev.from);
            try std.testing.expectEqualStrings("bob@example.com", ev.to);
            try std.testing.expectEqualStrings("chat", ev.stanza_type);
            try std.testing.expectEqualStrings("<body>hello</body>", ev.inner_xml);
            try std.testing.expectEqual(StanzaKind.message, ev.kind);
        },
        else => return error.WrongTag,
    }
}

test "encode/decode: stanza_archived round-trip" {
    const msg = Message{ .stanza_archived = .{
        .bare_jid = "alice@example.com",
        .stanza_id = "68af-1-0",
        .timestamp = 1749619200,
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    switch (decoded) {
        .stanza_archived => |ev| {
            try std.testing.expectEqualStrings("alice@example.com", ev.bare_jid);
            try std.testing.expectEqualStrings("68af-1-0", ev.stanza_id);
            try std.testing.expectEqual(@as(u64, 1749619200), ev.timestamp);
        },
        else => return error.WrongTag,
    }
}

test "encode/decode: pep_published round-trip" {
    const msg = Message{ .pep_published = .{
        .publisher_local = "alice",
        .publisher_domain = "example.com",
        .node = "urn:xmpp:avatar:metadata",
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    switch (decoded) {
        .pep_published => |ev| {
            try std.testing.expectEqualStrings("alice", ev.publisher_local);
            try std.testing.expectEqualStrings("urn:xmpp:avatar:metadata", ev.node);
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
        .session_id = 1,
        .generation = 0,
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
        .session_id = 0,
        .generation = 0,
    } };
    try std.testing.expectEqual(@as(u8, 0x10), msg.tag());
}

test "encode/decode: shadow_join round-trip" {
    const msg = Message{ .shadow_join = .{
        .room_jid = "dev@conference.example.com",
        .real_jid = "alice@example.com/Mobile",
        .nick = "alice",
        .worker_id = 1,
        .session_id = 33,
        .generation = 5,
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
            try std.testing.expectEqual(@as(u32, 33), ev.session_id);
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
        .session_id = 77,
        .generation = 0,
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
        .reply_to_session = 5,
        .reply_to_generation = 3,
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
            try std.testing.expectEqual(@as(u32, 5), ev.reply_to_session);
            try std.testing.expectEqual(@as(u32, 3), ev.reply_to_generation);
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
        .req_session = 17,
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
            try std.testing.expectEqual(@as(u32, 17), ev.req_session);
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
        .req_session = 9,
        .req_epoch = 2,
        .status = "ok",
    } };

    var buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const len = encode(&buf, msg).?;
    const decoded = decode(buf[0..len]).?;

    switch (decoded) {
        .sm_resume_reply => |ev| {
            try std.testing.expectEqualStrings("ok", ev.status);
            try std.testing.expectEqual(@as(u32, 9), ev.req_session);
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
        .new_session_id = 271,
        .new_generation = 41,
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
            try std.testing.expectEqual(@as(u32, 271), ev.new_session_id);
            try std.testing.expectEqual(@as(u32, 41), ev.new_generation);
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
        .req_session = 17,
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
            try std.testing.expectEqual(@as(u32, 17), ev.req_session);
            try std.testing.expectEqual(@as(u32, 9), ev.req_epoch);
        },
        else => return error.WrongTag,
    }

    const rep = Message{ .session_kick_reply = .{ .req_session = 17, .req_epoch = 9 } };
    const len2 = encode(&buf, rep).?;
    switch (decode(buf[0..len2]).?) {
        .session_kick_reply => |ev| {
            try std.testing.expectEqual(@as(u32, 17), ev.req_session);
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
        .reply_to_session = 42,
        .reply_to_generation = 9,
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
            try std.testing.expectEqual(@as(u32, 42), ev.reply_to_session);
            try std.testing.expectEqual(@as(u32, 9), ev.reply_to_generation);
            try std.testing.expectEqualStrings("alice@example.com/Mobile", ev.reply_to_jid);
        },
        else => return error.WrongTag,
    }
}
