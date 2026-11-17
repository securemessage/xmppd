//! # c2s session: client connection state machine
//!
//! The per-connection Session and the c2s read/write path moved out of
//! server.zig (ADR-12): stream open, pre-bind policy, SASL, stanza
//! accumulation and dispatch, backpressure, STARTTLS and stream errors.
//! Functions take the worker as `self: *Server`; Session methods stay on the
//! struct.

const std = @import("std");
const posix = std.posix;
const xml = @import("xml");
const xmpp = @import("xmpp");
const sasl = @import("sasl");
const precis = @import("precis_username");
const EventLoop = @import("../worker/loop.zig").EventLoop;
const ChangeList = @import("../worker/loop.zig").ChangeList;
const Connection = @import("../connection.zig").Connection;
pub const connection_mod = @import("../connection.zig");
const Listener = @import("../listener.zig").Listener;
const Event = @import("../worker/loop.zig").Event;

const ssl = @import("ssl");
const net = @import("net");
const IpcClient = @import("ipc_client").IpcClient;
const ipc_protocol = @import("ipc_protocol");
const backend_mod = @import("backend");
const OpBackendMod = @import("op_backend");
pub const OpBackendType = OpBackendMod.Backend;
const generic_roster = @import("roster_store");
const GenericRosterStore = generic_roster.RosterStore(OpBackendType);
const Subscription = generic_roster.Subscription;
const session_map_mod = @import("session_map");
const SessionMap = session_map_mod.SessionMap;
const SessionEntry = session_map_mod.SessionEntry;

const delivery_queue_mod = @import("delivery_queue");
const DeliverySystem = delivery_queue_mod.DeliverySystem;
const offline_store_mod = @import("generic_offline_store");
const GenericOfflineStore = offline_store_mod.GenericOfflineStore;
const OfflinePointer = offline_store_mod.OfflinePointer;
const archive_store_mod = @import("archive_store");
const ArchiveBackendMod = @import("archive_backend");
const ArchiveBackendType = ArchiveBackendMod.Backend;
const archive_queue_mod = @import("archive_queue");
const vcard_store_mod = @import("vcard_store");
const GenericVCardStore = vcard_store_mod.VCardStore(OpBackendType);
const iq_handler = @import("../iq/dispatch.zig");
const muc_handler = @import("../muc/handler.zig");
const presence_handler = @import("../presence/handler.zig");
pub const sub_cache_mod = @import("../subscription_cache.zig");
pub const caps_mod = @import("../caps.zig");
const router = @import("../routing/router.zig");
const session_lifecycle = @import("lifecycle.zig");
const stanza_writer = @import("../stanza/writer.zig");
const stanza_facts = @import("../stanza/facts.zig");
const room_registry_mod = @import("room_registry");
const room_mailbox_mod = @import("room_mailbox");
const RoomRegistry = room_registry_mod.RoomRegistry;
const room_store_mod = @import("room_store");
const GenericRoomStore = room_store_mod.RoomStore(OpBackendType);
const fanout_mod = @import("../muc/fanout.zig");
const FanoutQueue = fanout_mod.FanoutQueue;
const actor_message = @import("../xworker/envelope.zig");
pub const sm_state = @import("sm_state.zig");
const sm_handoff = @import("sm_handoff.zig");
const block_store_mod = @import("block_store");
const metrics = @import("../worker/metrics.zig");
const GenericBlockStore = block_store_mod.BlockStore(OpBackendType);
const pep_store_mod = @import("pep_store");
const GenericPepStore = pep_store_mod.PepStore(OpBackendType);

const server_mod = @import("../worker/worker.zig");
const Server = server_mod.Server;
const c2s_sm = @import("sm.zig");

const log = std.log.scoped(.xmppd);

/// Cold error paths. The helper is noinline and marked cold so the log
/// formatter's stack frame stays out of the per-message callers; the call
/// site holds only the call.
pub noinline fn noteDrop(comptime fmt: []const u8, args: anytype) void {
    @branchHint(.cold);
    log.warn(fmt, args);
}

/// Record one over-long-JID skip on the cold path (S4).
pub noinline fn noteJidOverflow(comptime fmt: []const u8, args: anytype) void {
    @branchHint(.cold);
    router.countJidOverflow();
    log.warn(fmt, args);
}

/// Queue a built stanza to a session. A refused send lands on the cold
/// path: it is logged, and a full write buffer flags the session for
/// overflow teardown (R1), the same classification dispatchStanza uses.
pub fn queueStanzaOrDrop(session: *Session, stanza: []const u8, comptime what: []const u8) void {
    if (session.stanza(stanza) == .failed_closed) noteSendDrop(session, stanza, what);
}

/// The SendResult twin of noteQueueDrop for converted call sites:
/// failed_closed on a live conn is classified by noteQueueOverflow
/// (oversize drop vs slow-reader teardown), on a dead conn it is the
/// old ConnectionClosed path.
pub noinline fn noteSendDrop(session: *Session, stanza: []const u8, comptime what: []const u8) void {
    @branchHint(.cold);
    if (!session.conn.isClosed()) {
        if (noteQueueOverflow(session, stanza)) {
            log.warn("connection {d}: {s} of {d} bytes exceeds the {d}-byte send buffer; dropped, session kept", .{ session.conn.id, what, stanza.len, connection_mod.WRITE_BUF_SIZE });
            return;
        }
        log.warn("connection {d}: {s} could not be queued (WriteBufferFull)", .{ session.conn.id, what });
        return;
    }
    log.warn("connection {d}: {s} could not be queued (ConnectionClosed)", .{ session.conn.id, what });
}

/// Classify and log one refused queueSendStanza on the cold path (R5).
/// WriteBufferFull is two different refusals, split by noteQueueOverflow:
/// a stanza longer than the whole buffer is dropped as oversize and the
/// session lives; a deliverable stanza that cannot fit means a slow reader
/// and flags overflow teardown (R1).
pub noinline fn noteQueueDrop(session: *Session, stanza: []const u8, err: anyerror, comptime what: []const u8) void {
    @branchHint(.cold);
    if (err == error.WriteBufferFull and noteQueueOverflow(session, stanza)) {
        log.warn("connection {d}: {s} of {d} bytes exceeds the {d}-byte send buffer; dropped, session kept", .{ session.conn.id, what, stanza.len, connection_mod.WRITE_BUF_SIZE });
        return;
    }
    log.warn("connection {d}: {s} could not be queued ({s})", .{ session.conn.id, what, @errorName(err) });
}

/// Split a WriteBufferFull refusal in two. A stanza longer than the whole
/// write buffer can never be queued: it is counted as oversize, the session
/// stays up, and an iq result is replaced by a resource-constraint error
/// under the same id. A stanza that would fit an empty buffer means a slow
/// reader: flag the session for the XEP-0198 overflow teardown. Returns
/// true only for the oversize case.
pub fn noteQueueOverflow(session: *Session, stanza: []const u8) bool {
    if (stanza.len <= connection_mod.WRITE_BUF_SIZE) {
        session.sm_overflow = true;
        return false;
    }
    _ = delivery_queue_mod.oversize_queue_drops.fetchAdd(1, .monotonic);
    answerOversizeIq(session, stanza);
    return true;
}

/// Answer a dropped iq result with a resource-constraint error under the
/// same id so the requester is not left waiting. Only 'result' qualifies:
/// an 'error' must never be answered (RFC 6120 section 8.3) and a 'get' or
/// 'set' this side originated has no requester behind the id. The id is
/// copied out before the build because the dropped stanza may sit in
/// write_scratch, which the error reuses. When even the error cannot be
/// queued the buffer is genuinely full, which is the slow-reader case.
pub noinline fn answerOversizeIq(session: *Session, stanza: []const u8) void {
    const id = iqResultId(stanza) orelse return;
    if (id.len > 256) {
        noteDrop("connection {d}: iq result id of {d} bytes; no error reply sent", .{ session.conn.id, id.len });
        return;
    }
    var id_buf: [256]u8 = undefined;
    @memcpy(id_buf[0..id.len], id);
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    const reply = out: {
        // Same 'from' and 'to' rule as iq_handler.writeIqHeader.
        w.writeAll("<iq type='error' from='") catch break :out null;
        xml.escapeWrite(w, if (session.iq_to.len > 0) session.iq_to else session.stream.server_host) catch break :out null;
        w.writeByte('\'') catch break :out null;
        if (session.stream.bound_jid) |bound| {
            w.writeAll(" to='") catch break :out null;
            xml.escapeWrite(w, bound.local) catch break :out null;
            w.writeByte('@') catch break :out null;
            xml.escapeWrite(w, bound.domain) catch break :out null;
            if (bound.resource.len > 0) {
                w.writeByte('/') catch break :out null;
                xml.escapeWrite(w, bound.resource) catch break :out null;
            }
            w.writeByte('\'') catch break :out null;
        }
        w.writeAll(" id='") catch break :out null;
        xml.escapeWrite(w, id_buf[0..id.len]) catch break :out null;
        w.writeAll("'><error type='cancel'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>") catch break :out null;
        break :out fbs.getWritten();
    } orelse {
        noteJidOverflow("iq error reply to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
        return;
    };
    if (session.stanza(reply) == .failed_closed) {
        const closed = session.conn.isClosed();
        if (!closed) session.sm_overflow = true;
        noteDrop("connection {d}: iq error reply could not be queued ({s})", .{ session.conn.id, if (closed) "ConnectionClosed" else "WriteBufferFull" });
    }
}

/// Id of an `<iq type='result' ...>` opening tag, or null. The scan stops
/// at the first '>', which cannot appear inside an escaped attribute.
pub fn iqResultId(stanza: []const u8) ?[]const u8 {
    const head_end = std.mem.indexOfScalar(u8, stanza, '>') orelse return null;
    const head = stanza[0..head_end];
    if (head.len <= 3 or !std.mem.eql(u8, head[0..3], "<iq") or head[3] != ' ') return null;
    const iq_type = headAttr(head, "type") orelse return null;
    if (!std.mem.eql(u8, iq_type, "result")) return null;
    return headAttr(head, "id");
}

/// Value of one ` name='v'` or ` name="v"` attribute inside a tag head.
pub fn headAttr(head: []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i + name.len + 3 <= head.len) : (i += 1) {
        if (head[i] != ' ') continue;
        if (!std.mem.eql(u8, head[i + 1 .. i + 1 + name.len], name)) continue;
        const quote = i + name.len + 2;
        if (head[i + 1 + name.len] != '=' or (head[quote] != '\'' and head[quote] != '"')) continue;
        const end = std.mem.indexOfScalarPos(u8, head, quote + 1, head[quote]) orelse return null;
        return head[quote + 1 .. end];
    }
    return null;
}

/// True when a session's fd is gone but the session still exists: it was
/// detached for SM resume, or closed, after kevent returned this batch.
/// Such an event is stale; acting on it would drive flushSend/recv against
/// fd -1 and could destroy a resumable session (S28).
pub fn isStaleSessionEvent(session: *Session) bool {
    return session.sm_detached or session.conn.isClosed();
}

/// Per-thread scratch for the pre-bind account compare's localpart
/// preparation; the prepared name is copied into acc_buf before use.
pub threadlocal var prebind_precis_scratch: precis.Scratch = undefined;

/// Maximum XML element nesting depth allowed.
/// XMPP stanzas are shallow (stream=1, stanza=2, children=3-5 typically).
/// Anything deeper than this is either malformed or an attack (deep nesting DoS).
/// Connection is terminated with a stream error if exceeded.
pub const MAX_ELEMENT_DEPTH = 50;

comptime {
    // The reader's namespace stacks must outlast any depth we accept (S12).
    std.debug.assert(MAX_ELEMENT_DEPTH <= xml.max_ns_depth);
}

/// Auth IPC exchange state per connection.
pub const AuthState = enum {
    /// No auth exchange in progress.
    none,
    /// Sent AuthRequest to auth daemon, awaiting AuthChallenge or AuthSuccess/Failure.
    awaiting_challenge,
    /// Sent SaslResponse to auth daemon, awaiting AuthSuccess/Failure.
    awaiting_result,
};

/// Which SASL element's text content we're currently accumulating.
pub const SaslCollecting = enum {
    none,
    auth,
    response,
};

/// Which type of stanza is currently being accumulated for forwarding.
pub const StanzaKind = enum {
    none,
    message,
    presence,
    iq,
};

/// Which MAM query text field we're currently collecting.
pub const MamCollecting = enum {
    none,
    /// Collecting text inside <value> element of a <field> in the data form.
    field_value,
    /// Collecting text inside <max> element (RSM page size).
    rsm_max,
    /// Collecting text inside <after> element (RSM after cursor).
    rsm_after,
    /// Collecting text inside <before> element (RSM before cursor).
    rsm_before,
};

/// Per-connection session state. Bundles a Connection with its XML parser,
/// XMPP stream FSM, and SASL state.
pub const Session = struct {
    conn: Connection,
    reader: xml.Reader,
    stream: xmpp.Stream,
    /// Buffer for building XML responses within a single event handler call.
    write_scratch: [4096]u8 = undefined,

    /// Auth daemon IPC exchange state.
    auth_state: AuthState = .none,
    /// Generation counter for IPC correlation — prevents stale auth responses
    /// from applying to a session that reused the same slot.
    auth_ipc_gen: u16 = 0,
    /// Stable copy of authenticated username (IPC message data is transient).
    auth_username_buf: [precis.max_username_octets]u8 = undefined,
    auth_username_len: usize = 0,
    /// Which SASL element we're collecting text content for.
    sasl_collecting: SaslCollecting = .none,
    /// Buffer for accumulating SASL text content (base64 from XML).
    sasl_buf: [4096]u8 = undefined,
    sasl_buf_len: usize = 0,
    /// Mechanism name from the last <auth> element.
    sasl_mechanism: []const u8 = "",

    /// Stanza accumulation for message/presence forwarding.
    /// Child XML content is serialized into stanza_buf between element_start
    /// and element_end at stream-child depth. dispatchStanza() then routes
    /// the reconstructed stanza with rewritten 'from' attribute.
    stanza_kind: StanzaKind = .none,
    stanza_buf: [16384]u8 = undefined,
    stanza_buf_len: usize = 0,
    /// Set when stanza accumulation overflowed stanza_buf. The buffered XML is
    /// then a partial stanza and must never be delivered (E5); the stanza is
    /// failed closed at dispatch instead. Reset with the rest of the stanza
    /// state, so it never carries across stanzas.
    stanza_overflow: bool = false,
    stanza_to: []const u8 = "",
    stanza_id: []const u8 = "",
    stanza_type: []const u8 = "",
    /// F6 ingress preparation scratch: stanza-level to/from attr values are
    /// prepared into session-owned buffers so the folded localpart and the
    /// configured domain spelling stay valid for the stanza's whole life
    /// (reader-arena slices do not). prep_attrs rebuilds the attr table.
    prep_to_buf: [xmpp.max_jid_octets]u8 = undefined,
    prep_from_buf: [xmpp.max_jid_octets]u8 = undefined,
    prep_attrs: [64]xml.Attribute = undefined,

    /// Bind IQ accumulation — deferred until </iq> so <resource> text is parsed.
    bind_iq_id: []const u8 = "",
    /// Session-owned copy of the bind IQ id (T220): the reader slice dies at
    /// the next top-level element and the parked cross-worker kick path needs
    /// the id intact when completeBindAfterKick finally answers.
    bind_iq_id_buf: [256]u8 = undefined,
    bind_iq_id_len: usize = 0,
    bind_resource_buf: [256]u8 = undefined,
    bind_resource_len: usize = 0,
    bind_collecting_resource: bool = false,
    bind_pending: bool = false,

    /// Set when <starttls> arrived with a separate close tag: the upgrade
    /// triggers on </starttls> (T215).
    starttls_close_pending: bool = false,

    /// IQ stanza accumulation — tracks child element namespace for dispatching.
    iq_active: bool = false,
    iq_type: []const u8 = "",
    iq_id: []const u8 = "",
    iq_to: []const u8 = "",
    iq_child_ns: []const u8 = "",
    iq_child_name: []const u8 = "",
    /// PEP node name from <publish node='...'> or <items node='...'> (XEP-0163).
    iq_pep_node: []const u8 = "",
    /// First pubsub-namespaced child of <pubsub> seen this IQ: the set verb
    /// dispatchIq routes on (XEP-0060).
    iq_pubsub_verb: []const u8 = "",
    /// Roster item attributes from <item> inside roster query.
    iq_roster_item_jid: []const u8 = "",
    iq_roster_item_name: []const u8 = "",
    iq_roster_item_sub: []const u8 = "",
    /// Number of <item> elements seen inside a roster set IQ (for multi-item rejection).
    iq_roster_item_count: u8 = 0,
    /// Number of <group> elements seen inside the current roster <item>.
    iq_roster_group_count: u8 = 0,
    /// Whether a zero-length <group/> or <group></group> was seen.
    iq_roster_has_empty_group: bool = false,
    /// Whether duplicate group names were seen within the current <item>.
    iq_roster_has_duplicate_group: bool = false,
    /// Buffer for collecting <group> text content.
    iq_roster_group_text_buf: [256]u8 = undefined,
    iq_roster_group_text_len: usize = 0,
    /// Whether we're currently collecting text inside a <group> element.
    iq_roster_collecting_group: bool = false,
    /// Buffer of group name hashes seen in the current item (for duplicate detection).
    /// Stores FNV-1a hashes of group names — up to 16 groups per item.
    iq_roster_group_hashes: [16]u64 = undefined,
    iq_roster_group_hash_count: u8 = 0,
    /// Accumulated serialized groups: [len_be(2) | text] * N for storage.
    iq_roster_groups_buf: [2048]u8 = undefined,
    iq_roster_groups_len: usize = 0,

    /// F6: session-owned scratch holding the IQ payload JID prepared for the
    /// configured domain. Shared by the roster/block item JID
    /// (iq_roster_item_jid) and the MAM 'with' JID (mam_with): one IQ
    /// dispatch prepares only one of them, so they are never live together.
    iq_jid_prep_buf: [xmpp.max_jid_octets]u8 = undefined,

    /// XEP-0115 §5.3: disco#info query node attribute (for caps verification).
    disco_node: []const u8 = "",

    /// XEP-0115: Accumulated feature bitmap from disco#info response to our caps query.
    caps_disco_features: u64 = 0,

    /// MAM query accumulation (XEP-0313) — populated by handleIqChild.
    mam_query_id: []const u8 = "",
    mam_with: []const u8 = "",
    mam_start: []const u8 = "",
    mam_end: []const u8 = "",
    mam_after: []const u8 = "",
    mam_before: []const u8 = "",
    mam_max: []const u8 = "",
    /// Which MAM text field we're currently collecting (from nested value/max elements).
    mam_collecting: MamCollecting = .none,
    /// Buffer for MAM text content accumulation.
    mam_text_buf: [256]u8 = undefined,
    mam_text_len: usize = 0,
    /// Current <field var='...'> name being parsed inside <x> data form.
    mam_field_var: []const u8 = "",

    /// vCard XML accumulation (for IQ set vcard-temp).
    vcard_collecting: bool = false,
    vcard_buf: [4096]u8 = undefined,
    vcard_buf_len: usize = 0,
    vcard_overflow: bool = false,
    /// Depth at which vcard_collecting was started (to detect the matching close tag).
    vcard_collect_depth: u8 = 0,

    /// PEP item payload accumulation (dynamic — avatars can be 100KB+).
    pep_collecting: bool = false,
    pep_payload: std.ArrayListUnmanaged(u8) = .{},

    /// Presence priority accumulation — tracks <priority> child text during presence stanza.
    pres_priority_collecting: bool = false,
    pres_priority_buf: [8]u8 = undefined,
    pres_priority_len: u8 = 0,

    /// RFC 6121 §3.1.5: Last broadcast presence inner XML (priority, show, status).
    /// Stored on each available presence dispatch so that subscription approval can
    /// forward the full current presence (not just bare `<presence/>`).
    last_presence_inner: [4096]u8 = undefined,
    last_presence_inner_len: usize = 0,

    /// XEP-0280: Message Carbons enabled for this session.
    carbons_enabled: bool = false,

    /// XEP-0352: Client State Indication — false when client is backgrounded/inactive.
    csi_active: bool = true,

    /// XEP-0115: Client's caps `ver` hash from presence (for PEP +notify filtering).
    caps_ver_buf: [caps_mod.MAX_VER_LEN]u8 = undefined,
    caps_ver_len: u8 = 0,

    /// RFC 6121 §2.1.6: Whether this resource has requested the roster (is "interested").
    /// Interested resources receive roster pushes for subscription changes.
    roster_interested: bool = false,

    /// Registration (XEP-0077) text accumulation.
    reg_collecting_password: bool = false,
    reg_password_buf: [256]u8 = undefined,
    reg_password_len: usize = 0,
    reg_collecting_username: bool = false,
    reg_username_buf: [256]u8 = undefined,
    reg_username_len: usize = 0,
    /// Whether the current jabber:x:data <field> in the registration form is
    /// the invite/token field (set on <field>, consumed on <value>).
    reg_invite_field: bool = false,
    reg_collecting_invite: bool = false,
    reg_invite_buf: [256]u8 = undefined,
    reg_invite_len: usize = 0,
    /// Whether a <remove/> element was seen inside jabber:iq:register (account deletion).
    reg_has_remove: bool = false,
    /// IQ id for a pending password change/deletion response (awaiting auth daemon reply).
    /// Points into reg_pending_iq_buf (never the reader arena, S11).
    reg_pending_iq_id: []const u8 = "",
    reg_pending_iq_buf: [256]u8 = undefined,
    reg_pending_iq_len: usize = 0,

    /// XEP-0198: Stream Management state.
    sm_enabled: bool = false,
    /// Inbound stanza counter (stanzas received from client).
    sm_in_h: u32 = 0,
    /// Outbound stanza counter (stanzas sent to client — last acked by client).
    sm_out_h: u32 = 0,
    /// Server's outbound stanza sequence (incremented on each stanza sent to client).
    sm_out_seq: u32 = 0,
    /// Whether resume was negotiated (client sent resume='true' on enable).
    sm_resume_enabled: bool = false,
    /// Hex-encoded SM-ID (32 chars) for resume token.
    sm_id: [sm_state.SM_ID_HEX_LEN]u8 = undefined,
    /// Length of valid SM-ID data (0 = no SM-ID assigned).
    sm_id_len: u8 = 0,
    /// Whether this session is detached (connection closed, awaiting resume).
    sm_detached: bool = false,
    /// Monotonic timestamp (seconds) when the session was detached.
    sm_detach_time: i64 = 0,
    /// Unacked stanza queue for resume replay. Allocated when resume is enabled.
    sm_unacked: ?*sm_state.SmUnackedQueue = null,
    /// S13: offline delivery stalled on a full send buffer (or a store
    /// error). Set until the writable handler drains the tail; new
    /// messages to this session are held in the offline store so they
    /// cannot overtake the tail.
    offline_pending: bool = false,
    /// S13: consecutive offline-drain stalls caused by a store error rather
    /// than a full send buffer. Prompt retries are bounded so a failing store
    /// cannot spin the event loop; a one-shot timer owns the next retry.
    offline_store_stalls: u8 = 0,
    /// Whether the session's one-shot offline retry timer is armed. The flag
    /// rejects a stale timer after the session slot has been reused.
    offline_retry_timer_armed: bool = false,
    /// Sequence of the last offline pointer handed to this session's
    /// connection but not yet deleted. A failed delete returns to this pointer
    /// on the next drain; knowing it was already written means the retry only
    /// redoes the delete instead of sending the stanza again.
    offline_last_sent_sequence: u64 = 0,
    /// Set when outbound delivery cannot preserve integrity, either because
    /// the SM unacked queue overflowed or a live write buffer is full. Reaped
    /// at batch end: live sessions get resource-constraint; detached sessions
    /// are destroyed because they cannot be resumed safely.
    sm_overflow: bool = false,
    /// T178: an <r/> ack request is in flight (sent when the unacked queue
    /// crossed the threshold, cleared on <a/>). Prevents <r/> spam while
    /// waiting for the client — and guarantees that a queue reaching full
    /// capacity belongs to a client that ignored our ack requests.
    sm_r_outstanding: bool = false,

    /// T177: async cross-worker resume in flight. This session received a
    /// <resume/> whose SM-ID belongs to another worker; it stays parked in
    /// features_bind until the owning worker's handoff reply arrives on the
    /// MPSC queue. The epoch is bumped per request so a late reply can never
    /// apply to a different session that reused this slot.
    sm_resume_pending: bool = false,
    sm_resume_epoch: u32 = 0,
    sm_resume_previd: [sm_state.SM_ID_HEX_LEN]u8 = undefined,

    /// T154: async cross-worker resource takeover in flight. The bind hit
    /// AlreadyBound against a session owned by another worker; this session
    /// waits for the session_kick reply, then retries the bind. Epoch is
    /// bumped per kick round (ABA on slot reuse); rounds bound ping-pong
    /// retries against concurrent takers.
    bind_kick_pending: bool = false,
    bind_kick_epoch: u32 = 0,
    bind_kick_rounds: u8 = 0,
    bind_kick_resource_buf: [64]u8 = undefined,
    bind_kick_resource_len: u8 = 0,

    pub fn init(fd: posix.fd_t, id: usize, server_host: []const u8, direct_tls: bool, allocator: std.mem.Allocator) Session {
        var reader = xml.Reader.init(allocator);
        // Pre-auth cap: negotiation elements are small, and an unauthenticated
        // peer must not be able to spend the post-auth budget (H6).
        reader.setMaxItemBytes(xml.max_item_bytes_pre_auth);
        return .{
            .conn = Connection.init(fd, id, allocator),
            .reader = reader,
            .stream = xmpp.Stream.init(server_host, direct_tls),
        };
    }

    pub fn deinit(self: *Session) void {
        if (self.sm_unacked) |queue| {
            queue.deinit();
            self.reader.allocator.destroy(queue);
            self.sm_unacked = null;
        }
        if (self.pep_payload.capacity > 0) self.pep_payload.deinit(self.reader.allocator);
        self.reader.deinit();
        if (!self.conn.isClosed()) self.conn.close();
    }

    pub fn resetSasl(self: *Session) void {
        self.sasl_collecting = .none;
        self.sasl_buf_len = 0;
        self.sasl_mechanism = "";
        self.auth_state = .none;
    }

    /// Encode session slot + auth generation into IPC conn_id.
    /// Upper 16 bits = auth_ipc_gen, lower 16 bits = conn.id.
    /// The auth daemon echoes this back unchanged, allowing us to detect
    /// stale responses from a previous session on a reused slot.
    pub fn ipcConnId(self: *const Session) u32 {
        return (@as(u32, self.auth_ipc_gen) << 16) | @as(u32, @intCast(self.conn.id));
    }

    pub fn resetStanza(self: *Session) void {
        self.stanza_kind = .none;
        self.stanza_buf_len = 0;
        self.stanza_overflow = false;
        self.stanza_to = "";
        self.stanza_id = "";
        self.stanza_type = "";
    }

    /// The outcome of handing one outbound element to the send path
    /// (ADR-2). Only `.failed_closed` is a refusal; noteQueueDrop
    /// classifies it (dead fd vs full ring vs oversize).
    pub const SendResult = enum {
        /// Buffered on the live connection.
        queued,
        /// Detached SM session: counted into the unacked queue with no
        /// fd to write to; delivery happens on resume.
        tracked_detached,
        /// Accepted into the bounded spill behind the ring. Unreachable
        /// at the M2 spill cap (spill_limit == WRITE_BUF_SIZE).
        spilled,
        /// Refused: the conn is closed or the outbox is full. The append
        /// already bumped the per-worker drop counter by reason.
        failed_closed,
    };

    /// Queue a complete outbound stanza (message/presence/iq) and count it
    /// for XEP-0198 (S15). Counting is not optional: `<a h='...'/>` maps by
    /// position, so every stanza sent outside this helper shifts the ack
    /// window and makes a later ack discard a stanza the client never saw.
    /// Nonzas (`<r/>`, `<a/>`, features, SASL elements, stream errors) must
    /// go through nonza().
    ///
    /// Compat !void form of stanza() for call sites not yet converted to
    /// the SendResult API: failed_closed maps back to the pre-Outbox
    /// error pair, while tracked_detached is success — a detached SM
    /// session that buffers for resume is delivering, not dropping.
    pub fn queueSendStanza(self: *Session, data: []const u8) !void {
        switch (self.stanza(data)) {
            .queued, .spilled, .tracked_detached => {},
            .failed_closed => return if (self.conn.isClosed())
                error.ConnectionClosed
            else
                error.WriteBufferFull,
        }
    }

    /// Queue a complete outbound stanza (message/presence/iq) and count it
    /// for XEP-0198 (S15, ADR-2). SM tracking happens before the socket
    /// append: the unacked queue is authoritative, so a stanza the socket
    /// refuses is still counted and replayed rather than silently dropped.
    /// A detached session has no fd; its stanzas go straight to unacked.
    pub fn stanza(self: *Session, data: []const u8) SendResult {
        if (self.sm_detached) {
            self.smTrackOutbound(data);
            return .tracked_detached;
        }
        self.smTrackOutbound(data);
        return sendResult(self.conn.append(data));
    }

    /// Queue a nonza — anything that is not a message/presence/iq stanza:
    /// SM elements, stream features and errors, SASL elements, the stream
    /// close. Never counted for XEP-0198.
    pub fn nonza(self: *Session, data: []const u8) SendResult {
        return sendResult(self.conn.append(data));
    }

    fn sendResult(r: net.AppendResult) SendResult {
        return switch (r) {
            .queued => .queued,
            .spilled => .spilled,
            .failed_closed => .failed_closed,
        };
    }

    /// Track an outbound stanza for SM purposes.
    /// Increments sm_out_seq and buffers the stanza in the unacked queue (if resume enabled).
    /// Call this after successfully queueing a complete stanza (message/presence/iq) to the client.
    /// On queue overflow the session is flagged for failure (T178) and reaped
    /// by session_lifecycle.reapOutboundOverflow at the end of the event batch.
    pub fn smTrackOutbound(self: *Session, stanza_data: []const u8) void {
        if (!self.sm_enabled) return;
        self.sm_out_seq +%= 1;
        if (self.sm_unacked) |queue| {
            switch (queue.push(stanza_data)) {
                .pushed => {},
                // A stanza the client will count but we cannot replay is the
                // same silent-gap class as overflow (S15) — fail the session.
                .alloc_failed, .overflow => {
                    self.sm_overflow = true;
                    log.warn("connection {d} SM unacked queue failure ({d} stanzas) — failing session", .{ self.conn.id, sm_state.UNACKED_CAPACITY });
                },
            }
            // T178: give the client the chance to ack before the queue can
            // fill — XEP-0198 only requires acks when the server requests
            // them, so without <r/> a compliant client (Smack) may never ack
            // and overflow-kill would hit innocent busy sessions. One <r/>
            // outstanding at a time; <r/> is not a stanza (not counted in
            // sm_out_seq). Nothing to request from a detached session.
            if (!self.sm_detached and !self.sm_r_outstanding and
                queue.pending() >= sm_state.SM_R_THRESHOLD)
            {
                if (self.nonza("<r xmlns='urn:xmpp:sm:3'/>") == .failed_closed) return;
                self.sm_r_outstanding = true;
            }
        }
    }
};

pub fn continueTlsHandshake(self: *Server, id: usize, session: *Session, changes: *ChangeList) void {
    const complete = session.conn.continueHandshake() catch {
        log.err("connection {d} TLS handshake failed", .{id});
        session_lifecycle.closeSession(self, id, changes);
        return;
    };

    if (complete) {
        log.info("connection {d} TLS handshake complete", .{id});
        // AGENTS.md: kTLS engagement and cipher must be logged after
        // every handshake; userland fallback is otherwise silent.
        if (session.conn.tls) |*t| {
            log.info("connection {d} tls: {s} cipher={s} ktls tx={} rx={}", .{
                id, t.conn.versionName(), t.conn.cipherName(), t.ktls_tx, t.ktls_rx,
            });
        }
        // Notify the stream FSM that TLS is established
        session.stream.tlsEstablished();
        // Reset XML reader for stream restart after STARTTLS
        session.reader.reset();
        // Clear any stale pre-TLS data from the read buffer
        session.conn.read_start = 0;
        session.conn.read_end = 0;

        // OpenSSL may have buffered application data internally during
        // the handshake (client pipelines Finished + new stream open).
        // handleReadable's TLS drain loop handles this — just ensure
        // kqueue is armed so the next readable event triggers it.
        // If OpenSSL already consumed all socket data, tlsPending() > 0
        // won't help here since handleReadable needs a kqueue trigger.
        // Force an immediate drain to handle the pipelined case.
        if (session.conn.tlsPending() > 0) {
            handleReadable(self, id, changes);
        }
        if (self.sessions[id] != null and !session.conn.isClosed()) {
            changes.addRead(session.conn.fd, id) catch {};
        }
    } else {
        // Re-arm the appropriate kqueue filter. Write interest is
        // one-shot: a persistent filter fires on every kevent while
        // the handshake waits for the client's next flight (S10).
        if (session.conn.tls_state) |state| {
            switch (state) {
                .handshake_want_read => changes.addRead(session.conn.fd, id) catch {},
                .handshake_want_write => changes.addWriteOnce(session.conn.fd, id) catch {},
                .established => {},
            }
        }
    }
}

/// Read and parse all available data from a connection.
///
/// Outer loop drains OpenSSL's internal buffer: after parsing all data from
/// one recv(), if TLS has buffered decrypted bytes (SSL_pending > 0), we
/// recv() again immediately. kqueue only fires on new *socket* data, so
/// without this loop, OpenSSL-buffered data would stall indefinitely.
///
/// The parse loop runs until the parser needs more data (event == null).
/// Per-connection work is naturally bounded by the 8KB read buffer — one
/// recv() produces at most 8KB of XML regardless of element count.
pub fn handleReadable(self: *Server, id: usize, changes: *ChangeList) void {
    const session = self.sessions[id] orelse return;
    if (isStaleSessionEvent(session)) {
        self.stale_event_skips += 1;
        log.debug("connection {d} stale readable event on a detached or closed session, skipped", .{id});
        return;
    }

    while (true) {
        // Read from socket (or OpenSSL's internal buffer via tls.read)
        const n = session.conn.recv() catch |err| {
            switch (err) {
                error.WouldBlock => break,
                else => {
                    log.info("connection {d} recv error: {}", .{ id, err });
                    session_lifecycle.closeSession(self, id, changes);
                    return;
                },
            }
        };

        if (n == 0) {
            log.info("connection {d} closed by peer", .{id});
            session_lifecycle.closeSession(self, id, changes);
            return;
        }

        // Parse all XML events from the read buffer
        const data = session.conn.readableSlice();

        // T160: a TLS ClientHello on the STARTTLS port would otherwise be
        // fed to the XML parser and surface as a misleading
        // InvalidEntityReference. Detect the TLS record header (content
        // type 0x16 = handshake, major version 0x03) on a fresh plaintext
        // stream and close with a clear log line instead.
        if (session.stream.state == .awaiting_stream_open and
            session.conn.tls == null and
            data.len >= 2 and data[0] == 0x16 and data[1] == 0x03)
        {
            log.info("connection {d}: TLS handshake on the STARTTLS port — client is configured for direct TLS, closing", .{id});
            session_lifecycle.forceCloseSession(self, id, changes);
            return;
        }

        // T215: while <proceed/> is queued the peer must wait for the
        // upgrade; any further plaintext, in this segment or a later
        // one, is a protocol violation (RFC 6120 5.4.3.2).
        if (session.stream.state == .starttls_pending) {
            log.info("connection {d} plaintext while STARTTLS pending: policy-violation", .{id});
            sendStreamError(self, session, .policy_violation);
            session.conn.flushSync();
            session_lifecycle.forceCloseSession(self, id, changes);
            return;
        }

        var pos: usize = 0;

        while (true) {
            // The item cap follows authentication: pre-auth elements are
            // negotiation only, and an authenticated client gets a cap no
            // larger than a stanza can be delivered through (H6).
            session.reader.setMaxItemBytes(if (session.stream.isAuthenticated())
                xml.max_item_bytes_authenticated
            else
                xml.max_item_bytes_pre_auth);
            const event = session.reader.next(data, &pos) catch |err| {
                // Client-side protocol violation, not a server fault.
                log.warn("connection {d} XML parse error: {}", .{ id, err });
                // Resource limits are policy violations, not malformed XML.
                sendStreamError(self, session, if (xml.isResourceLimit(err))
                    .policy_violation
                else
                    .not_well_formed);
                // Flush the error and closing tag before teardown.
                session.conn.flushSync();
                session_lifecycle.forceCloseSession(self, id, changes);
                return;
            };

            if (event == null) break; // Need more data

            if (session.reader.depth > MAX_ELEMENT_DEPTH) {
                log.warn("connection {d} exceeded max depth ({d})", .{ id, MAX_ELEMENT_DEPTH });
                sendStreamError(self, session, .policy_violation);
                session_lifecycle.forceCloseSession(self, id, changes);
                return;
            }

            const starttls_was_pending = session.stream.state == .starttls_pending;
            processXmlEvent(self, session, event.?, changes);

            if (self.sessions[id] == null) return;

            // A stanza the accumulation buffer could not hold is already
            // undescribable: the rest of the element would only append to a
            // partial stanza the peer thinks is complete (H6). Fail now
            // instead of waiting for the close tag, so a peer that never
            // closes the stanza cannot hold the session open.
            if (session.stanza_overflow) {
                log.warn("connection {d} stanza exceeds {d} bytes: policy-violation", .{ id, session.stanza_buf.len });
                sendStreamError(self, session, .policy_violation);
                session.conn.flushSync();
                session_lifecycle.forceCloseSession(self, id, changes);
                return;
            }
            // T215: anything past the complete <starttls/> element is
            // plaintext read-ahead — a protocol violation (RFC 6120
            // 5.4.3.2).
            if (!starttls_was_pending and
                session.stream.state == .starttls_pending and
                pos < data.len)
            {
                log.info("connection {d} plaintext read-ahead past <starttls/> — policy-violation", .{id});
                sendStreamError(self, session, .policy_violation);
                session.conn.flushSync();
                session_lifecycle.forceCloseSession(self, id, changes);
                return;
            }
            if (session.conn.isTlsHandshaking()) {
                session.conn.consume(pos);
                return;
            }
        }

        session.conn.consume(pos);

        // If OpenSSL has more decrypted data buffered internally, loop
        // to recv() again — kqueue won't fire for it.
        if (session.conn.tlsPending() == 0) break;
    }

    if (self.sessions[id] == null) return;

    if (session.conn.hasPendingWrite()) {
        _ = session.conn.flushSend() catch {};
        if (session.conn.hasPendingWrite()) {
            changes.addWrite(session.conn.fd, id) catch {};
        }
    }
}

pub fn processXmlEvent(self: *Server, session: *Session, event: xml.Event, changes: *ChangeList) void {
    switch (event) {
        .xml_declaration => {
            // Expected at stream start, no action needed
        },
        .stream_open => |elem| {
            handleStreamOpen(self, session, elem, changes);
        },
        .stream_close => {
            _ = session.stream.handleClose();
            sendRaw(self, session, "</stream:stream>");
            // Flush the closing tag before teardown so the peer receives it.
            if (session.conn.hasPendingWrite()) {
                session.conn.flushSync();
            }
            session_lifecycle.forceCloseSession(self, session.conn.id, changes);
        },
        .element_start => |elem| {
            var e = elem;
            handleElementStart(self, session, &e, changes);
        },
        .element_end => |name| {
            handleElementEnd(self, session, name, changes);
        },
        .text => |text| {
            handleText(self, session, text);
        },
    }
}

pub fn handleStreamOpen(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
    // Extract 'to' attribute
    var to: []const u8 = "";
    for (elem.attributes) |attr| {
        if (std.mem.eql(u8, attr.local_name, "to")) {
            to = attr.value;
            break;
        }
    }

    const action = session.stream.handleStreamOpen(to, "1.0");
    executeAction(self, session, action, changes);
}

/// Verdict of enforcePreBindStanzaPolicy (T182).
pub const PreBindVerdict = enum {
    /// Not a message/IQ (e.g. presence) — pre-bind presence stays
    /// silently ignored; caller continues.
    not_stanza,
    /// Stanza addressed to the server itself or the client's own account
    /// — not processed pre-bind, but answered with a not-authorized
    /// stanza error (IQs must always be answered). Connection stays open.
    server_addressed,
    /// Stanza addressed to a third party — RFC 6120 §7.1: MUST NOT be
    /// processed, stream closed with a not-authorized stream error.
    /// The session is destroyed; the caller must return immediately
    /// without touching the session again.
    third_party_closed,
};

/// RFC 6120 §7.1 (T182): enforce the pre-bind stanza policy for a
/// message/IQ element received before resource binding completes.
/// Third-party-addressed stanzas close the stream with a not-authorized
/// stream error; server/account-addressed stanzas are only classified
/// (the caller answers with a stanza error or proceeds for bind/register).
pub fn enforcePreBindStanzaPolicy(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) PreBindVerdict {
    const is_message = std.mem.eql(u8, elem.local_name, "message");
    const is_iq = std.mem.eql(u8, elem.local_name, "iq");
    if (!is_message and !is_iq) return .not_stanza;

    var to_attr: []const u8 = "";
    for (elem.attributes) |attr| {
        if (std.mem.eql(u8, attr.local_name, "to")) {
            to_attr = attr.value;
            break;
        }
    }

    // Addressed to the server itself (no 'to', or the bare domain) or to
    // the client's own account (its authenticated bare JID)?
    var server_addressed = to_attr.len == 0 or std.ascii.eqlIgnoreCase(to_attr, self.server_host);
    if (!server_addressed) {
        if (session.stream.authenticated_jid) |aj| {
            // The ingress-prepared 'to' carries a prepared localpart, so
            // the account string prepares the authenticated name under
            // the same profile. A prepared username can be 1023 octets
            // and the domain another 1023, so the buffer must hold a
            // full JID, not just FULL_JID_MAX.
            var acc_buf: [xmpp.max_jid_octets]u8 = undefined;
            var account: []const u8 = "";
            if (prebind_precis_scratch.localpart(aj.local)) |prepared| {
                var acc_fbs = std.io.fixedBufferStream(&acc_buf);
                const aw = acc_fbs.writer();
                aw.writeAll(prepared) catch {};
                aw.writeByte('@') catch {};
                aw.writeAll(aj.domain) catch {};
                account = acc_buf[0..acc_fbs.pos];
            } else |_| {}
            const to_bare = if (std.mem.indexOfScalar(u8, to_attr, '/')) |sp| to_attr[0..sp] else to_attr;
            server_addressed = account.len > 0 and std.mem.eql(u8, to_bare, account);
        }
    }
    if (server_addressed) return .server_addressed;

    log.info("connection {d} {s} to a third party before resource binding — closing stream (not-authorized)", .{ session.conn.id, elem.local_name });
    // writeStreamError includes the closing </stream:stream> tag.
    sendStreamError(self, session, .not_authorized);
    // Flush the error and closing tag before teardown so the client sees them.
    session.conn.flushSync();
    session_lifecycle.forceCloseSession(self, session.conn.id, changes);
    return .third_party_closed;
}

/// Answer a pre-bind stanza addressed to the server/own account with a
/// not-authorized stanza error (T182). Stanza error, not stream error —
/// the connection stays open so the client can proceed to bind. Error
/// stanzas are never answered with further errors (RFC 6120 §8.3.1).
pub fn sendPreBindStanzaError(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
    _ = self;
    var to_attr: []const u8 = "";
    var id_attr: []const u8 = "";
    var type_attr: []const u8 = "";
    for (elem.attributes) |attr| {
        if (std.mem.eql(u8, attr.local_name, "to")) {
            to_attr = attr.value;
        } else if (std.mem.eql(u8, attr.local_name, "id")) {
            id_attr = attr.value;
        } else if (std.mem.eql(u8, attr.local_name, "type")) {
            type_attr = attr.value;
        }
    }
    if (std.mem.eql(u8, type_attr, "error")) return;

    const tag_name: []const u8 = if (std.mem.eql(u8, elem.local_name, "iq")) "iq" else "message";
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    const reply_xml = stanza: {
        w.writeByte('<') catch break :stanza null;
        w.writeAll(tag_name) catch break :stanza null;
        w.writeAll(" type='error'") catch break :stanza null;
        if (to_attr.len > 0) {
            w.writeAll(" from='") catch break :stanza null;
            xml.escapeWrite(w, to_attr) catch break :stanza null;
            w.writeByte('\'') catch break :stanza null;
        }
        if (id_attr.len > 0) {
            w.writeAll(" id='") catch break :stanza null;
            xml.escapeWrite(w, id_attr) catch break :stanza null;
            w.writeByte('\'') catch break :stanza null;
        }
        w.writeAll("><error type='auth'><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></") catch break :stanza null;
        w.writeAll(tag_name) catch break :stanza null;
        w.writeByte('>') catch break :stanza null;
        break :stanza fbs.getWritten();
    } orelse {
        noteJidOverflow("pre-bind stanza error to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
        return;
    };
    queueStanzaOrDrop(session, reply_xml, "pre-bind stanza error");
    if (session.conn.hasPendingWrite()) {
        changes.addWrite(session.conn.fd, session.conn.id) catch {};
    }
}

/// F6: fold local-domain to/from attribute values once at stanza ingress
/// into session-owned buffers, then rebuild elem.attributes onto the
/// prepared spellings. Remote-domain JIDs pass through unchanged. Returns
/// false when a value fails preparation: the caller must stop processing
/// the stanza (a jid-malformed reply has already been queued, except for
/// type='error' stanzas which are dropped silently per RFC 6120 §8.3.1).
pub fn prepareStanzaAddresses(self: *Server, session: *Session, elem: *xml.Element, changes: *ChangeList) bool {
    // A table wider than the rebuild buffer cannot be rewritten; the
    // scanner's own attribute cap keeps this unreachable in practice.
    if (elem.attributes.len > session.prep_attrs.len) return true;

    // Scan the type first: an early error must still know whether the
    // stanza itself is type='error', wherever the attribute sits.
    var type_str: []const u8 = "";
    for (elem.attributes) |attr| {
        if (std.mem.eql(u8, attr.local_name, "type")) type_str = attr.value;
    }
    const is_error_stanza = std.mem.eql(u8, type_str, "error");

    for (elem.attributes, 0..) |attr, i| {
        var a = attr;
        const buf = if (std.mem.eql(u8, attr.local_name, "to"))
            &session.prep_to_buf
        else if (std.mem.eql(u8, attr.local_name, "from"))
            &session.prep_from_buf
        else
            null;
        if (buf) |b| {
            a.value = xmpp.prepareLocalDomainJid(attr.value, self.server_host, b) catch {
                if (!session.stream.isActive()) {
                    // RFC 6120 7.1 (T182): a malformed address cannot be
                    // classified, so the pre-bind policy runs on the raw
                    // attributes; third party closes the stream with
                    // not-authorized, server/account-addressed gets the
                    // stanza error, presence stays silently ignored.
                    switch (enforcePreBindStanzaPolicy(self, session, elem.*, changes)) {
                        .third_party_closed, .not_stanza => {},
                        .server_addressed => sendPreBindStanzaError(self, session, elem.*, changes),
                    }
                } else if (!is_error_stanza) {
                    self.sendIngressJidMalformed(session, elem, changes);
                }
                return false;
            };
        }
        session.prep_attrs[i] = a;
    }
    elem.attributes = session.prep_attrs[0..elem.attributes.len];
    return true;
}

pub fn writeJidMalformedReply(buf: []u8, tag_name: []const u8, from: []const u8, to: []const u8, id: []const u8) ?[]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    w.writeByte('<') catch return null;
    w.writeAll(tag_name) catch return null;
    if (from.len > 0) {
        w.writeAll(" from='") catch return null;
        xml.escapeWrite(w, from) catch return null;
        w.writeByte('\'') catch return null;
    }
    if (to.len > 0) {
        w.writeAll(" to='") catch return null;
        xml.escapeWrite(w, to) catch return null;
        w.writeByte('\'') catch return null;
    }
    w.writeAll(" type='error'") catch return null;
    if (id.len > 0) {
        w.writeAll(" id='") catch return null;
        xml.escapeWrite(w, id) catch return null;
        w.writeByte('\'') catch return null;
    }
    w.writeAll("><error type='modify'><jid-malformed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></") catch return null;
    w.writeAll(tag_name) catch return null;
    w.writeByte('>') catch return null;
    return fbs.getWritten();
}

pub fn handleElementStart(self: *Server, session: *Session, elem: *xml.Element, changes: *ChangeList) void {
    // If accumulating a message/presence stanza, serialize child elements into buffer
    if (session.stanza_kind != .none) {
        // Detect <priority> child inside presence stanza for RFC 6121 §4.7.2.3
        if (session.stanza_kind == .presence and std.mem.eql(u8, elem.local_name, "priority")) {
            session.pres_priority_collecting = true;
            session.pres_priority_len = 0;
        }
        accumulateStanzaElement(self, session, elem.*);
        return;
    }

    // F6: prepare local-domain to/from once at stanza ingress so every
    // downstream compare and store key sees the folded localpart and the
    // configured domain spelling. The reader reports a top-level open
    // stanza at depth 2 but restores depth to 1 before emitting a
    // self-closing element, so a self-closing element seen at depth 2 is
    // a stanza child, never a stanza.
    const stanza_top = (session.reader.depth == 2 and !elem.self_closing) or
        (session.reader.depth == 1 and elem.self_closing);
    if (stanza_top and
        (std.mem.eql(u8, elem.local_name, "message") or
            std.mem.eql(u8, elem.local_name, "presence") or
            std.mem.eql(u8, elem.local_name, "iq")))
    {
        if (!prepareStanzaAddresses(self, session, elem, changes)) return;
    }

    const ns = elem.namespace_uri;

    // STARTTLS namespace
    if (std.mem.eql(u8, ns, xml.ns.tls)) {
        if (std.mem.eql(u8, elem.local_name, "starttls")) {
            if (elem.self_closing) {
                const action = session.stream.handleStarttls();
                executeAction(self, session, action, changes);
            } else {
                // <starttls></starttls> form: trigger on the close tag so
                // the read-ahead check (T215) sees a complete element.
                session.starttls_close_pending = true;
            }
        }
        return;
    }

    // SASL namespace
    if (std.mem.eql(u8, ns, xml.ns.sasl)) {
        if (std.mem.eql(u8, elem.local_name, "auth")) {
            handleSaslAuth(self, session, elem.*, changes);
        } else if (std.mem.eql(u8, elem.local_name, "response")) {
            // Start collecting SCRAM response text
            session.sasl_collecting = .response;
            session.sasl_buf_len = 0;
        }
        return;
    }

    // Pre-auth IQ for registration (XEP-0077) — in features_sasl state
    if (session.stream.state == .features_sasl or session.stream.state == .sasl_negotiating) {
        if (std.mem.eql(u8, elem.local_name, "iq") and std.mem.eql(u8, ns, xml.ns.client)) {
            // RFC 6120 §7.1 (T182): a pre-auth stanza addressed to a third
            // party is not processed — the stream is closed instead.
            if (enforcePreBindStanzaPolicy(self, session, elem.*, changes) == .third_party_closed) return;
            // Start IQ accumulation for registration
            iq_handler.handleIq(session, elem.*, self.server_host);
            return;
        }
        // IQ child elements during pre-auth registration
        if (session.iq_active) {
            if (session.vcard_collecting) {
                accumulateVcardElement(self, session, elem.*);
                return;
            }
            self.handleIqChild(session, elem.*);
            return;
        }
    }

    // Bind namespace — defer to </iq> so <resource> text is parsed
    if (std.mem.eql(u8, ns, xml.ns.bind)) {
        if (std.mem.eql(u8, elem.local_name, "bind")) {
            session.bind_pending = true;
            session.bind_resource_len = 0;
            session.bind_collecting_resource = false;
        } else if (std.mem.eql(u8, elem.local_name, "resource") and session.bind_pending) {
            session.bind_collecting_resource = true;
            session.bind_resource_len = 0;
        }
        return;
    }

    // XEP-0198: SM resume at features_bind — client sends <resume/> instead of <bind/>
    if (session.stream.state == .features_bind and std.mem.eql(u8, ns, xml.ns.sm)) {
        if (std.mem.eql(u8, elem.local_name, "resume")) {
            c2s_sm.handleSmResume(self, session, elem.*, changes);
        }
        return;
    }

    // Pre-bind IQ wrapper — capture the IQ id for the bind result
    if (!session.stream.isActive() and session.stream.state == .features_bind) {
        // RFC 6120 §7.1 (T182): a stanza addressed to a third party
        // before resource binding is not processed — the stream closes
        // with a not-authorized stream error. The bind wrapper IQ itself
        // is server-addressed and continues below.
        switch (enforcePreBindStanzaPolicy(self, session, elem.*, changes)) {
            .third_party_closed => return,
            .not_stanza => return, // presence pre-bind: silently ignored
            .server_addressed => {},
        }
        if (std.mem.eql(u8, elem.local_name, "iq")) {
            for (elem.attributes) |attr| {
                if (std.mem.eql(u8, attr.local_name, "id")) {
                    // An id too long to mirror must not be staged
                    // truncated: the client would get back a different
                    // id than it sent (S11).
                    if (attr.value.len > session.bind_iq_id_buf.len) {
                        log.warn("connection {d} bind id exceeds {d} bytes, policy-violation", .{ session.conn.id, session.bind_iq_id_buf.len });
                        sendStreamError(self, session, .policy_violation);
                        session.conn.flushSync();
                        session_lifecycle.forceCloseSession(self, session.conn.id, changes);
                        return;
                    }
                    // Keep a session-owned copy and swap the pointer onto
                    // it: the reader slice is gone by the next stanza and
                    // the cross-worker kick path answers later (T220).
                    const n = attr.value.len;
                    @memcpy(session.bind_iq_id_buf[0..n], attr.value[0..n]);
                    session.bind_iq_id_len = n;
                    session.bind_iq_id = session.bind_iq_id_buf[0..n];
                    break;
                }
            }
        } else if (std.mem.eql(u8, elem.local_name, "message")) {
            // Server/account-addressed message pre-bind — not processed,
            // but answered with a not-authorized stanza error.
            sendPreBindStanzaError(self, session, elem.*, changes);
        }
        return;
    }

    // XEP-0352: Client State Indication — stream-level active/inactive signals
    if (std.mem.eql(u8, ns, xml.ns.csi)) {
        if (std.mem.eql(u8, elem.local_name, "active")) {
            session.csi_active = true;
        } else if (std.mem.eql(u8, elem.local_name, "inactive")) {
            session.csi_active = false;
        }
        return;
    }

    // XEP-0198: Stream Management namespace — handle in active or just-bound state
    if (std.mem.eql(u8, ns, xml.ns.sm)) {
        if (std.mem.eql(u8, elem.local_name, "enable")) {
            if (session.stream.isActive()) {
                c2s_sm.handleSmEnable(self, session, elem.*, changes);
            } else {
                // XEP-0198 §3.1: SM enable before resource bind — reject
                c2s_sm.sendSmFailed(self, session, "unexpected-request", changes);
            }
        } else if (std.mem.eql(u8, elem.local_name, "r") and session.sm_enabled) {
            c2s_sm.handleSmRequest(self, session, changes);
        } else if (std.mem.eql(u8, elem.local_name, "a") and session.sm_enabled) {
            // Client acknowledges our stanzas
            session.sm_r_outstanding = false;
            for (elem.attributes) |attr| {
                if (std.mem.eql(u8, attr.local_name, "h")) {
                    const client_h = std.fmt.parseInt(u32, attr.value, 10) catch {
                        // A malformed handled-count cannot be trusted;
                        // parsing it as 0 would silently desync the ack
                        // window (S24). It cannot be echoed back, so no h
                        // is reported on the error.
                        c2s_sm.sendSmHandledCountError(self, session, null, changes);
                        return;
                    };
                    // S24: validate the report before recording it. With a
                    // resume queue the queue is authoritative (it discards
                    // on success); with SM and no resume there is no queue,
                    // so the sent count is checked here. sm_out_h advances
                    // only for an accepted report, so a duplicate or
                    // backwards h cannot corrupt it.
                    const verdict: sm_state.SmUnackedQueue.AckResult = if (session.sm_unacked) |queue|
                        queue.ack(client_h)
                    else
                        sm_state.classifyAck(client_h, session.sm_out_h, session.sm_out_seq);
                    switch (verdict) {
                        .ok => session.sm_out_h = client_h,
                        // XEP-0198 Example 17: h above the number of
                        // stanzas sent fails the stream.
                        .too_high => {
                            c2s_sm.sendSmHandledCountError(self, session, client_h, changes);
                            return;
                        },
                        // A duplicate or out-of-order report discards
                        // nothing and must not move sm_out_h.
                        .backwards => {},
                    }
                    break;
                }
            }
        } else if (std.mem.eql(u8, elem.local_name, "resume") and session.stream.state == .features_bind) {
            c2s_sm.handleSmResume(self, session, elem.*, changes);
        }
        return;
    }

    // RFC 6120 §7.1 (T182): stanzas received before authentication are not
    // processed. Third-party-addressed message/IQ close the stream with a
    // not-authorized stream error; server/account-addressed ones get a
    // stanza error instead (IQs are answered via dispatchIq's pre-bind
    // gate); presence stays silently ignored.
    if (!session.stream.isActive()) {
        switch (enforcePreBindStanzaPolicy(self, session, elem.*, changes)) {
            .third_party_closed, .not_stanza => return,
            .server_addressed => {
                // Client-namespace IQs were handled above (registration /
                // dispatchIq). A server-addressed message is bounced.
                if (std.mem.eql(u8, elem.local_name, "message")) {
                    sendPreBindStanzaError(self, session, elem.*, changes);
                }
                return;
            },
        }
    }

    // Active state — stanzas (message, presence, iq)
    if (session.stream.isActive()) {
        // If we're inside an IQ stanza, handle child elements
        if (session.iq_active) {
            if (session.vcard_collecting) {
                accumulateVcardElement(self, session, elem.*);
                return;
            }
            self.handleIqChild(session, elem.*);
            return;
        }

        if (std.mem.eql(u8, elem.local_name, "message")) {
            if (session.sm_enabled) session.sm_in_h +%= 1;
            handleMessage(self, session, elem.*, changes);
        } else if (std.mem.eql(u8, elem.local_name, "presence")) {
            if (session.sm_enabled) session.sm_in_h +%= 1;
            handlePresence(self, session, elem.*, changes);
        } else if (std.mem.eql(u8, elem.local_name, "iq")) {
            if (session.sm_enabled) session.sm_in_h +%= 1;
            self.handleIq(session, elem.*, changes);
        }
    }
}

pub fn handleText(self: *Server, session: *Session, text: []const u8) void {
    // Stanza content accumulation (message/presence body text)
    if (session.stanza_kind != .none) {
        // Also capture <priority> text for presence stanzas (RFC 6121 §4.7.2.3)
        if (session.pres_priority_collecting) {
            const remaining = session.pres_priority_buf.len - session.pres_priority_len;
            const to_copy: u8 = @intCast(@min(text.len, remaining));
            if (to_copy > 0) {
                @memcpy(session.pres_priority_buf[session.pres_priority_len .. session.pres_priority_len + to_copy], text[0..to_copy]);
                session.pres_priority_len += to_copy;
            }
        }
        accumulateStanzaText(self, session, text);
        return;
    }

    // Bind resource text accumulation
    if (session.bind_collecting_resource) {
        const remaining = session.bind_resource_buf.len - session.bind_resource_len;
        const to_copy = @min(text.len, remaining);
        if (to_copy > 0) {
            @memcpy(session.bind_resource_buf[session.bind_resource_len .. session.bind_resource_len + to_copy], text[0..to_copy]);
            session.bind_resource_len += to_copy;
        }
        return;
    }

    // vCard XML text accumulation (for vcard-temp SET)
    if (session.vcard_collecting) {
        accumulateVcardText(self, session, text);
        return;
    }

    // Registration text accumulation (XEP-0077)
    if (session.reg_collecting_username) {
        const remaining = session.reg_username_buf.len - session.reg_username_len;
        const to_copy = @min(text.len, remaining);
        if (to_copy > 0) {
            @memcpy(session.reg_username_buf[session.reg_username_len .. session.reg_username_len + to_copy], text[0..to_copy]);
            session.reg_username_len += to_copy;
        }
        return;
    }
    if (session.reg_collecting_password) {
        const remaining = session.reg_password_buf.len - session.reg_password_len;
        const to_copy = @min(text.len, remaining);
        if (to_copy > 0) {
            @memcpy(session.reg_password_buf[session.reg_password_len .. session.reg_password_len + to_copy], text[0..to_copy]);
            session.reg_password_len += to_copy;
        }
        return;
    }
    if (session.reg_collecting_invite) {
        const remaining = session.reg_invite_buf.len - session.reg_invite_len;
        const to_copy = @min(text.len, remaining);
        if (to_copy > 0) {
            @memcpy(session.reg_invite_buf[session.reg_invite_len .. session.reg_invite_len + to_copy], text[0..to_copy]);
            session.reg_invite_len += to_copy;
        }
        return;
    }

    // Roster <group> text accumulation
    if (session.iq_roster_collecting_group) {
        const remaining = session.iq_roster_group_text_buf.len - session.iq_roster_group_text_len;
        const to_copy = @min(text.len, remaining);
        if (to_copy > 0) {
            @memcpy(session.iq_roster_group_text_buf[session.iq_roster_group_text_len .. session.iq_roster_group_text_len + to_copy], text[0..to_copy]);
            session.iq_roster_group_text_len += to_copy;
        }
        return;
    }

    // MAM query text accumulation (field values, RSM elements)
    if (session.mam_collecting != .none) {
        const remaining = session.mam_text_buf.len - session.mam_text_len;
        const to_copy = @min(text.len, remaining);
        if (to_copy > 0) {
            @memcpy(session.mam_text_buf[session.mam_text_len .. session.mam_text_len + to_copy], text[0..to_copy]);
            session.mam_text_len += to_copy;
        }
        return;
    }

    if (session.sasl_collecting == .none) return;

    // Accumulate text into SASL buffer
    const remaining = session.sasl_buf.len - session.sasl_buf_len;
    const to_copy = @min(text.len, remaining);
    if (to_copy > 0) {
        @memcpy(session.sasl_buf[session.sasl_buf_len .. session.sasl_buf_len + to_copy], text[0..to_copy]);
        session.sasl_buf_len += to_copy;
    }
}

pub fn handleElementEnd(self: *Server, session: *Session, name: []const u8, changes: *ChangeList) void {
    // <starttls></starttls> form (T215): upgrade on the close tag.
    if (session.starttls_close_pending) {
        session.starttls_close_pending = false;
        const local = if (std.mem.lastIndexOfScalar(u8, name, ':')) |c| name[c + 1 ..] else name;
        if (std.mem.eql(u8, local, "starttls")) {
            const action = session.stream.handleStarttls();
            executeAction(self, session, action, changes);
            return;
        }
    }
    // Stanza accumulation — child close tag or stanza dispatch
    if (session.stanza_kind != .none) {
        if (session.reader.depth > 1) {
            // Still inside the stanza — accumulate the child close tag
            accumulateStanzaClose(self, session, name);
            // Stop collecting <priority> text on </priority>
            if (session.pres_priority_collecting and std.mem.eql(u8, name, "priority")) {
                session.pres_priority_collecting = false;
            }
        } else {
            // Stanza complete (depth back to stream level): route to targets.
            // The accumulation buffer holds only a partial stanza after
            // overflow; never deliver it. Scanner token caps do not replace
            // this whole-stanza limit.
            if (session.stanza_overflow) {
                log.warn("connection {d} stanza exceeds {d} bytes: policy-violation", .{ session.conn.id, session.stanza_buf.len });
                sendStreamError(self, session, .policy_violation);
                session.conn.flushSync();
                session_lifecycle.forceCloseSession(self, session.conn.id, changes);
                return;
            }
            if (session.stanza_kind == .presence and session.stanza_to.len == 0) {
                // Own presence (no 'to') — update availability + broadcast
                presence_handler.dispatchPresence(self, session, changes);
            } else {
                // Message, IQ, or directed/subscription presence — route to target
                if (session.stanza_kind == .presence and presence_handler.isSubscriptionType(session.stanza_type)) {
                    const ptype = xmpp.PresenceType.fromString(session.stanza_type);
                    const inner_xml = session.stanza_buf[0..session.stanza_buf_len];
                    presence_handler.dispatchSubscription(self, session, ptype, inner_xml, changes);
                } else {
                    dispatchStanza(self, session, changes);
                }
            }
        }
        return;
    }

    // Bind accumulation — stop resource collection, dispatch on </iq>
    if (session.bind_pending) {
        if (session.bind_collecting_resource) {
            session.bind_collecting_resource = false;
        }
        if (session.reader.depth == 1) {
            // </iq> at stream-child level — perform bind with collected resource
            const resource = session.bind_resource_buf[0..session.bind_resource_len];
            if (!session_lifecycle.handleBind(self, session, resource, changes)) {
                return; // session was destroyed (AlreadyBound conflict) — do not touch it
            }
            session.bind_pending = false;
            session.bind_resource_len = 0;
            // T220: if the bind is parked on a cross-worker kick, the IQ id
            // must survive until completeBindAfterKick emits the final
            // result. session_lifecycle clears it on final answer.
            if (!session.bind_kick_pending) {
                session.bind_iq_id = "";
                session.bind_iq_id_len = 0;
            }
            if (session.conn.hasPendingWrite()) {
                changes.addWrite(session.conn.fd, session.conn.id) catch {};
            }
            return;
        }
        return;
    }

    // Pre-bind IQ that was not a bind request — IQs MUST always be
    // answered (RFC 6120 §7.6 / T182): reply not-authorized, stanza
    // error only, the connection stays open.
    if (session.stream.state == .features_bind and session.reader.depth == 1 and session.bind_iq_id.len > 0) {
        iq_handler.sendIqErrorWithType(self, session, session.bind_iq_id, "auth", "not-authorized");
        session.bind_iq_id = "";
        session.bind_iq_id_len = 0;
        if (session.conn.hasPendingWrite()) {
            changes.addWrite(session.conn.fd, session.conn.id) catch {};
        }
        return;
    }

    // SASL text accumulation
    switch (session.sasl_collecting) {
        .auth => {
            processSaslAuthComplete(self, session, changes);
            return;
        },
        .response => {
            processSaslResponseComplete(self, session, changes);
            return;
        },
        .none => {},
    }

    // vCard/PEP XML close tag accumulation
    if (session.iq_active and session.vcard_collecting) {
        if (session.reader.depth > session.vcard_collect_depth) {
            accumulateVcardClose(self, session, name);
        } else {
            // Reached the depth where collecting started — stop.
            // For vCard (depth=2), include the closing tag (stores full <vCard>...</vCard>).
            // For PEP items (depth>2), skip the closing </item> tag (stores inner payload only).
            if (session.vcard_collect_depth <= 2) {
                accumulateVcardClose(self, session, name);
            }
            session.vcard_collecting = false;
        }
    }

    // Roster <group> text — commit on </group>
    if (session.iq_active and session.iq_roster_collecting_group) {
        session.iq_roster_collecting_group = false;
        const group_text = session.iq_roster_group_text_buf[0..session.iq_roster_group_text_len];
        if (group_text.len == 0) {
            session.iq_roster_has_empty_group = true;
        } else {
            // Check for duplicate via FNV-1a hash
            const hash = std.hash.Fnv1a_64.hash(group_text);
            var is_dup = false;
            for (session.iq_roster_group_hashes[0..session.iq_roster_group_hash_count]) |h| {
                if (h == hash) {
                    is_dup = true;
                    break;
                }
            }
            if (is_dup) {
                session.iq_roster_has_duplicate_group = true;
            } else if (session.iq_roster_group_hash_count < session.iq_roster_group_hashes.len) {
                session.iq_roster_group_hashes[session.iq_roster_group_hash_count] = hash;
                session.iq_roster_group_hash_count += 1;
                // Append to serialized groups buffer: [len_be(2) | text]
                const needed = 2 + group_text.len;
                if (session.iq_roster_groups_len + needed <= session.iq_roster_groups_buf.len) {
                    std.mem.writeInt(u16, session.iq_roster_groups_buf[session.iq_roster_groups_len..][0..2], @intCast(group_text.len), .big);
                    @memcpy(session.iq_roster_groups_buf[session.iq_roster_groups_len + 2 .. session.iq_roster_groups_len + needed], group_text);
                    session.iq_roster_groups_len += needed;
                }
            }
        }
    }

    // Registration text — stop collecting on </username>, </password> or </value>
    if (session.iq_active and session.reg_collecting_username) {
        session.reg_collecting_username = false;
    }
    if (session.iq_active and session.reg_collecting_password) {
        session.reg_collecting_password = false;
    }
    if (session.iq_active and session.reg_collecting_invite) {
        session.reg_collecting_invite = false;
    }

    // MAM text accumulation — commit collected text on element close
    if (session.iq_active and session.mam_collecting != .none) {
        iq_handler.commitMamText(session);
    }

    // IQ stanza dispatch — when the IQ closes (depth back to stream child level)
    if (session.iq_active and session.reader.depth == 1) {
        self.dispatchIq(session, changes);
        if (session.conn.hasPendingWrite()) {
            changes.addWrite(session.conn.fd, session.conn.id) catch {};
        }
    }
}

pub fn handleSaslAuth(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
    // Get mechanism from attribute
    var mechanism: []const u8 = "";
    for (elem.attributes) |attr| {
        if (std.mem.eql(u8, attr.local_name, "mechanism")) {
            mechanism = attr.value;
            break;
        }
    }

    // Tell the stream FSM we're starting SASL
    const action = session.stream.handleSaslAuth(mechanism);
    switch (action) {
        .begin_sasl => {
            // Start collecting the initial response text content
            session.sasl_collecting = .auth;
            session.sasl_buf_len = 0;
            session.sasl_mechanism = mechanism;
        },
        else => executeAction(self, session, action, changes),
    }
}

/// Called when </auth> is reached — we have the full base64 payload.
pub fn processSaslAuthComplete(self: *Server, session: *Session, changes: *ChangeList) void {
    session.sasl_collecting = .none;

    if (!self.ipc.connected) {
        log.warn("connection {d} auth request but no auth daemon", .{session.conn.id});
        // Retryable: the reconnect timer re-links the auth daemon.
        const fail_action = session.stream.saslFailure("temporary-auth-failure");
        executeAction(self, session, fail_action, changes);
        return;
    }

    // Decode base64 from XML into raw SASL payload
    const b64_data = session.sasl_buf[0..session.sasl_buf_len];
    var decoded_buf: [3072]u8 = undefined;
    const decoded = stanza_writer.b64Decode(b64_data, &decoded_buf) orelse {
        log.warn("connection {d} invalid base64 in SASL auth", .{session.conn.id});
        const fail_action = session.stream.saslFailure("not-authorized");
        executeAction(self, session, fail_action, changes);
        return;
    };

    // Determine mechanism ID
    const mech_id = ipc_protocol.MechanismId.fromName(session.sasl_mechanism) orelse {
        const fail_action = session.stream.saslFailure("not-authorized");
        executeAction(self, session, fail_action, changes);
        return;
    };

    // Extract channel binding data from TLS session
    const cb = session.conn.getChannelBinding();

    // Increment generation before encoding — the response must carry this gen
    session.auth_ipc_gen +%= 1;

    // Send AuthRequest to auth daemon
    self.ipc.send(.{
        .auth_request = .{
            .conn_id = session.ipcConnId(),
            .mechanism = mech_id,
            .client_ip = session.conn.peerAddr(),
            .cb_type = cb.cb_type,
            .cb_data = cb.data,
            .username = "", // auth daemon extracts from payload
            .payload = decoded,
        },
    }) catch {
        log.err("connection {d} failed to send auth request via IPC", .{session.conn.id});
        const fail_action = session.stream.saslFailure("temporary-auth-failure");
        executeAction(self, session, fail_action, changes);
        return;
    };

    session.auth_state = .awaiting_challenge;

    // Write interest: reconcileIpcWriteInterest (S10).
}

/// Called when </response> is reached — we have the full SCRAM response.
pub fn processSaslResponseComplete(self: *Server, session: *Session, changes: *ChangeList) void {
    session.sasl_collecting = .none;

    if (!self.ipc.connected) {
        const fail_action = session.stream.saslFailure("temporary-auth-failure");
        executeAction(self, session, fail_action, changes);
        return;
    }

    // Decode base64
    const b64_data = session.sasl_buf[0..session.sasl_buf_len];
    var decoded_buf: [3072]u8 = undefined;
    const decoded = stanza_writer.b64Decode(b64_data, &decoded_buf) orelse {
        log.warn("connection {d} invalid base64 in SASL response", .{session.conn.id});
        const fail_action = session.stream.saslFailure("not-authorized");
        executeAction(self, session, fail_action, changes);
        return;
    };

    // Send SaslResponse to auth daemon
    self.ipc.send(.{ .sasl_response = .{
        .conn_id = session.ipcConnId(),
        .payload = decoded,
    } }) catch {
        log.err("connection {d} failed to send SASL response via IPC", .{session.conn.id});
        const fail_action = session.stream.saslFailure("temporary-auth-failure");
        executeAction(self, session, fail_action, changes);
        return;
    };

    session.auth_state = .awaiting_result;

    // Write interest: reconcileIpcWriteInterest (S10).
}

pub fn handleMessage(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
    // Extract attributes for routing (saved for dispatch on stanza close)
    var to_str: []const u8 = "";
    var id_str: []const u8 = "";
    var type_str: []const u8 = "normal";
    for (elem.attributes) |attr| {
        if (std.mem.eql(u8, attr.local_name, "to")) to_str = attr.value;
        if (std.mem.eql(u8, attr.local_name, "id")) id_str = attr.value;
        if (std.mem.eql(u8, attr.local_name, "type")) type_str = attr.value;
    }

    if (to_str.len == 0) return;

    // Start stanza accumulation — child content (body, thread, etc.) will be
    // serialized into stanza_buf. On </message>, dispatchStanza() constructs
    // the full stanza with rewritten 'from' and routes to target session(s).
    session.stanza_kind = .message;
    session.stanza_buf_len = 0;
    session.stanza_to = to_str;
    session.stanza_id = id_str;
    session.stanza_type = type_str;

    // Self-closing message (no children) — dispatch immediately
    if (elem.self_closing) {
        dispatchStanza(self, session, changes);
    }
}

/// Serialize a child element opening tag into the stanza accumulation buffer.
/// On overflow the whole stanza is marked bad and never dispatched (E5).
pub fn accumulateStanzaElement(self: *Server, session: *Session, elem: xml.Element) void {
    _ = self;
    if (session.stanza_overflow) return;
    var fbs = std.io.fixedBufferStream(session.stanza_buf[session.stanza_buf_len..]);
    stanza_writer.writeStanzaOpenTag(fbs.writer(), elem) catch {
        session.stanza_overflow = true;
        return;
    };
    session.stanza_buf_len += fbs.pos;
}

/// Serialize text content (XML-escaped) into the stanza accumulation buffer.
pub fn accumulateStanzaText(self: *Server, session: *Session, text: []const u8) void {
    _ = self;
    if (session.stanza_overflow) return;
    var fbs = std.io.fixedBufferStream(session.stanza_buf[session.stanza_buf_len..]);
    stanza_writer.xmlEscapeWrite(fbs.writer(), text) catch {
        session.stanza_overflow = true;
        return;
    };
    session.stanza_buf_len += fbs.pos;
}

/// Serialize a child element close tag into the stanza accumulation buffer.
pub fn accumulateStanzaClose(self: *Server, session: *Session, name: []const u8) void {
    _ = self;
    if (session.stanza_overflow) return;
    var fbs = std.io.fixedBufferStream(session.stanza_buf[session.stanza_buf_len..]);
    stanza_writer.writeStanzaCloseTag(fbs.writer(), name) catch {
        session.stanza_overflow = true;
        return;
    };
    session.stanza_buf_len += fbs.pos;
}

pub fn writeVcardElement(session: *Session, elem: xml.Element) !usize {
    var fbs = std.io.fixedBufferStream(session.vcard_buf[session.vcard_buf_len..]);
    const w = fbs.writer();

    try w.writeByte('<');
    try w.writeAll(elem.name);

    if (elem.namespace_uri.len > 0 and !std.mem.eql(u8, elem.namespace_uri, xml.ns.client) and
        !std.mem.eql(u8, elem.namespace_uri, "vcard-temp"))
    {
        if (elem.prefix.len > 0) {
            try w.writeAll(" xmlns:");
            try w.writeAll(elem.prefix);
            try w.writeAll("='");
            try xml.escapeWrite(w, elem.namespace_uri);
            try w.writeByte('\'');
        } else {
            try w.writeAll(" xmlns='");
            try xml.escapeWrite(w, elem.namespace_uri);
            try w.writeByte('\'');
        }
    }

    for (elem.attributes) |attr| {
        try w.writeByte(' ');
        try w.writeAll(attr.name);
        try w.writeAll("='");
        try stanza_writer.xmlEscapeWrite(w, attr.value);
        try w.writeByte('\'');
    }

    if (elem.self_closing) {
        try w.writeAll("/>");
    } else {
        try w.writeByte('>');
    }
    return fbs.pos;
}

pub fn accumulateVcardElement(self: *Server, session: *Session, elem: xml.Element) void {
    if (session.pep_collecting) {
        accumulatePepElement(self, session, elem);
        return;
    }
    if (session.vcard_overflow) return;
    const written = writeVcardElement(session, elem) catch {
        session.vcard_overflow = true;
        return;
    };
    session.vcard_buf_len += written;
}

pub fn accumulateVcardText(self: *Server, session: *Session, text: []const u8) void {
    if (session.pep_collecting) {
        accumulatePepText(self, session, text);
        return;
    }
    if (session.vcard_overflow) return;
    var fbs = std.io.fixedBufferStream(session.vcard_buf[session.vcard_buf_len..]);
    stanza_writer.xmlEscapeWrite(fbs.writer(), text) catch {
        session.vcard_overflow = true;
        return;
    };
    session.vcard_buf_len += fbs.pos;
}

pub fn accumulateVcardClose(self: *Server, session: *Session, name: []const u8) void {
    if (session.pep_collecting) {
        accumulatePepClose(self, session, name);
        return;
    }
    if (session.vcard_overflow) return;
    var fbs = std.io.fixedBufferStream(session.vcard_buf[session.vcard_buf_len..]);
    const w = fbs.writer();
    w.writeAll("</") catch {
        session.vcard_overflow = true;
        return;
    };
    w.writeAll(name) catch {
        session.vcard_overflow = true;
        return;
    };
    w.writeByte('>') catch {
        session.vcard_overflow = true;
        return;
    };
    session.vcard_buf_len += fbs.pos;
}

pub fn accumulatePepElement(self: *Server, session: *Session, elem: xml.Element) void {
    const a = self.allocator;
    const w = session.pep_payload.writer(a);
    w.writeByte('<') catch return;
    w.writeAll(elem.name) catch return;

    if (elem.namespace_uri.len > 0 and !std.mem.eql(u8, elem.namespace_uri, xml.ns.client) and
        !std.mem.eql(u8, elem.namespace_uri, xml.ns.pubsub))
    {
        // Escaped: the scanner decodes entities, so a raw write lets a
        // quote close the attribute and inject markup (S1).
        if (elem.prefix.len > 0) {
            w.writeAll(" xmlns:") catch return;
            w.writeAll(elem.prefix) catch return;
            w.writeAll("='") catch return;
            xml.escapeWrite(w, elem.namespace_uri) catch return;
            w.writeByte('\'') catch return;
        } else {
            w.writeAll(" xmlns='") catch return;
            xml.escapeWrite(w, elem.namespace_uri) catch return;
            w.writeByte('\'') catch return;
        }
    }

    for (elem.attributes) |attr| {
        w.writeByte(' ') catch return;
        w.writeAll(attr.name) catch return;
        w.writeAll("='") catch return;
        xml.escapeWrite(w, attr.value) catch return;
        w.writeByte('\'') catch return;
    }

    if (elem.self_closing) {
        w.writeAll("/>") catch return;
    } else {
        w.writeByte('>') catch return;
    }
}

pub fn accumulatePepText(self: *Server, session: *Session, text: []const u8) void {
    xml.escapeWrite(session.pep_payload.writer(self.allocator), text) catch return;
}

pub fn accumulatePepClose(self: *Server, session: *Session, name: []const u8) void {
    const a = self.allocator;
    session.pep_payload.appendSlice(a, "</") catch return;
    session.pep_payload.appendSlice(a, name) catch return;
    session.pep_payload.append(a, '>') catch return;
}

pub fn dispatchStanza(self: *Server, session: *Session, changes: *ChangeList) void {
    router.dispatchStanza(self, session, changes);
}

pub fn handlePresence(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
    presence_handler.handlePresence(self, session, elem, changes);
}

pub fn executeAction(self: *Server, session: *Session, action: xmpp.StreamAction, changes: *ChangeList) void {
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const writer = fbs.writer();

    switch (action) {
        .send_stream_open => |params| {
            xmpp.stream.writeStreamOpen(writer, params) catch return;
            if (session.nonza(fbs.getWritten()) == .failed_closed) return;
            session.stream.response_opened = true;

            // Immediately send features after stream open
            if (session.stream.getFeatures()) |features| {
                var fbs2 = std.io.fixedBufferStream(session.write_scratch[fbs.pos..]);
                xmpp.stream.writeFeatures(fbs2.writer(), self.applyDynamicMechanisms(features)) catch return;
                if (session.nonza(fbs2.getWritten()) == .failed_closed) return;
            }
        },
        .send_features => |features| {
            xmpp.stream.writeFeatures(writer, self.applyDynamicMechanisms(features)) catch return;
            if (session.nonza(fbs.getWritten()) == .failed_closed) return;
        },
        .send_tls_proceed, .start_tls => {
            writer.writeAll("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>") catch return;
            if (session.nonza(fbs.getWritten()) == .failed_closed) return;

            // T215: the handshake starts only after the plaintext
            // <proceed/> has fully flushed; leftover bytes would be
            // written through the TLS record layer. handleWritable
            // completes the upgrade once the buffer drains.
            _ = session.conn.flushSend() catch {};
            if (session.conn.hasPendingWrite()) return;
            // Nothing in this branch touches the session afterwards, and
            // every caller returns on reaching it, so a failed upgrade
            // that frees the session is not read here.
            _ = startTlsUpgrade(self, session, changes);
        },
        .send_sasl_success => |server_final| {
            writer.writeAll("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>") catch return;
            writer.writeAll(server_final) catch return;
            writer.writeAll("</success>") catch return;
            if (session.nonza(fbs.getWritten()) == .failed_closed) return;
            // Reset XML reader and clear read buffer for post-SASL stream restart
            // (same treatment as post-STARTTLS at line ~706)
            session.reader.reset();
            session.conn.read_start = 0;
            session.conn.read_end = 0;
        },
        .send_sasl_failure => |reason| {
            writer.writeAll("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><") catch return;
            writer.writeAll(reason) catch return;
            writer.writeAll("/></failure>") catch return;
            if (session.nonza(fbs.getWritten()) == .failed_closed) return;
        },
        .send_bind_result => |bound_jid| {
            writer.writeAll("<iq type='result'") catch return;
            if (session.bind_iq_id.len > 0) {
                writer.writeAll(" id='") catch return;
                xml.escapeWrite(writer, session.bind_iq_id) catch return;
                writer.writeByte('\'') catch return;
            }
            writer.writeAll("><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>") catch return;
            if (bound_jid.local.len > 0) {
                xml.escapeWrite(writer, bound_jid.local) catch return;
                writer.writeByte('@') catch return;
            }
            xml.escapeWrite(writer, bound_jid.domain) catch return;
            if (bound_jid.resource.len > 0) {
                writer.writeByte('/') catch return;
                xml.escapeWrite(writer, bound_jid.resource) catch return;
            }
            writer.writeAll("</jid></bind></iq>") catch return;
            if (session.stanza(fbs.getWritten()) == .failed_closed) return;
        },
        .send_error => |err| {
            sendStreamError(self, session, err);
        },
        .session_established => {
            // Nothing to send — session is now active
        },
        .close => {
            writer.writeAll("</stream:stream>") catch return;
            if (session.nonza(fbs.getWritten()) == .failed_closed) return;
        },
        .none, .begin_sasl, .send_sasl_challenge => {},
    }
}

pub fn handleWritable(self: *Server, id: usize, changes: *ChangeList) void {
    const session = self.sessions[id] orelse return;
    if (isStaleSessionEvent(session)) {
        self.stale_event_skips += 1;
        log.debug("connection {d} stale writable event on a detached or closed session, skipped", .{id});
        return;
    }

    _ = session.conn.flushSend() catch |err| {
        switch (err) {
            error.WouldBlock => return,
            // The fd is already gone, so there is nothing to flush or
            // close. Preserve the detached session for a possible resume.
            error.ConnectionClosed => return,
            else => {
                session_lifecycle.closeSession(self, id, changes);
                return;
            },
        }
    };

    // If write buffer is drained, stop watching for writability
    if (!session.conn.hasPendingWrite()) {
        changes.removeWrite(session.conn.fd) catch {};
        // T215: a STARTTLS upgrade deferred by backpressure starts now
        // that <proceed/> is fully on the wire. A failed upgrade frees
        // the session, so nothing below may touch it.
        if (session.stream.state == .starttls_pending and !session.conn.isTlsHandshaking()) {
            if (!startTlsUpgrade(self, session, changes)) return;
        }
    }

    // S13: with the buffer at the low-water mark, continue a stalled
    // offline drain; the tail goes out before any newer traffic.
    if (session.offline_pending and
        session.conn.pendingWriteBytes() <= connection_mod.WRITE_SUPPRESS_LOW)
    {
        session_lifecycle.drainOfflinePending(self, session, changes);
    }

    applyReadBackpressure(self, session, changes);
}

/// Begin the TLS handshake once the plaintext <proceed/> is fully
/// flushed (T215). Called from executeAction and handleWritable. A
/// failed upgrade closes the session: it would otherwise sit in
/// starttls_pending forever. Closing frees the session, so false means
/// the caller must stop touching it.
pub fn startTlsUpgrade(self: *Server, session: *Session, changes: *ChangeList) bool {
    if (self.ssl_ctx) |ctx| {
        if (self.fail_next_tls_upgrade) {
            self.fail_next_tls_upgrade = false;
            log.warn("connection {d} TLS upgrade failed", .{session.conn.id});
            session_lifecycle.closeSession(self, session.conn.id, changes);
            return false;
        }
        session.conn.upgradeToTls(ctx) catch {
            log.warn("connection {d} TLS upgrade failed", .{session.conn.id});
            session_lifecycle.closeSession(self, session.conn.id, changes);
            return false;
        };
        log.info("connection {d} starting TLS handshake", .{session.conn.id});
    } else {
        log.warn("connection {d} STARTTLS requested but no TLS configured", .{session.conn.id});
    }
    return true;
}

/// T110 client-side backpressure: while a connection's write buffer
/// holds more than WRITE_SUPPRESS_HIGH bytes, disable its EVFILT_READ so
/// we stop consuming stanzas we cannot forward — TCP windows close and
/// flow control propagates to whoever is flooding us. Re-enable once the
/// buffer drains to WRITE_SUPPRESS_LOW.
///
/// Called from handleWritable: every write-buffer growth path arms the
/// fd's write watch, and EVFILT_WRITE is level-triggered, so this
/// function runs at most one event batch after the buffer crosses the
/// threshold, and keeps running until the buffer is fully drained (which
/// is below the low-water mark — suppression always lifts).
pub fn applyReadBackpressure(self: *Server, session: *Session, changes: *ChangeList) void {
    _ = self;
    const conn = &session.conn;
    if (conn.closed or conn.fd < 0) return;
    const pending = conn.pendingWriteBytes();
    if (!conn.read_suppressed and pending >= connection_mod.WRITE_SUPPRESS_HIGH) {
        conn.read_suppressed = true;
        changes.disableRead(conn.fd) catch {};
    } else if (conn.read_suppressed and pending <= connection_mod.WRITE_SUPPRESS_LOW) {
        conn.read_suppressed = false;
        changes.enableRead(conn.fd) catch {};
    }
}

pub fn sendStreamError(self: *Server, session: *Session, err: xmpp.stream.StreamError) void {
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    // RFC 6120 4.9.1: open the stream before the error, so the client can
    // parse it. `to` is the peer's requested host and is omitted when we
    // never accepted one - echoing our own hostname would claim the client
    // asked for something it did not, and the rejected open is not stored.
    const open_params: ?xmpp.stream.StreamOpenParams = if (session.stream.response_opened) null else .{
        .from = self.server_host,
        .to = null,
        .id = &session.stream.stream_id_hex,
    };
    xmpp.stream.writeStreamError(fbs.writer(), err, open_params) catch return;
    if (session.nonza(fbs.getWritten()) == .failed_closed) return;
    session.stream.response_opened = true;
}

pub fn sendRaw(_: *Server, session: *Session, data: []const u8) void {
    _ = session.nonza(data);
}

/// Helper: fill the connection's write buffer so it has pending bytes that
/// cannot flush at once (unix socketpairs ignore SO_SNDBUF and buffer 64 KiB).
/// Returns true once something is left queued. Test-only; split so the S15
/// ratchet, which greps for raw sends, counts this one site rather than a
/// copy per test.
pub fn fillWriteBuffer(session: *Session) bool {
    var filler: [12000]u8 = undefined;
    @memset(&filler, 'x');
    var fill: usize = 0;
    while (fill < 8) : (fill += 1) {
        session.conn.queueSend(&filler) catch break;
        _ = session.conn.flushSend() catch {};
    }
    return session.conn.hasPendingWrite();
}

/// Helper: create a socketpair for testing.
pub fn makeSocketPair() ![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    return fds;
}

test "Server: read backpressure toggles EVFILT_READ across write-buffer thresholds (T110)" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var change_buf: [32]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // Fill the write buffer past the suppression threshold without flushing.
    var payload: [connection_mod.WRITE_SUPPRESS_HIGH + 128]u8 = @splat('x');
    try session.conn.queueSend(&payload);
    try std.testing.expectEqual(connection_mod.WRITE_SUPPRESS_HIGH + 128, session.conn.pendingWriteBytes());
    try std.testing.expect(!session.conn.read_suppressed);

    applyReadBackpressure(&server, session, &changes);
    try std.testing.expect(session.conn.read_suppressed);
    // Expect an EV.DISABLE change for the READ filter on this fd
    var saw_disable = false;
    for (changes.slice()) |ev| {
        if (ev.ident == session.conn.fd and ev.filter == std.c.EVFILT.READ and (ev.flags & std.c.EV.DISABLE) != 0) saw_disable = true;
    }
    try std.testing.expect(saw_disable);

    // Suppression is sticky in the hysteresis band (between LOW and HIGH)
    changes.reset();
    session.conn.outbox.used = connection_mod.WRITE_SUPPRESS_HIGH - 16;
    applyReadBackpressure(&server, session, &changes);
    try std.testing.expect(session.conn.read_suppressed);
    try std.testing.expectEqual(@as(usize, 0), changes.count());

    // Drained at/below low-water: read watch re-enabled
    changes.reset();
    session.conn.outbox.used = connection_mod.WRITE_SUPPRESS_LOW;
    applyReadBackpressure(&server, session, &changes);
    try std.testing.expect(!session.conn.read_suppressed);
    var saw_enable = false;
    for (changes.slice()) |ev| {
        if (ev.ident == session.conn.fd and ev.filter == std.c.EVFILT.READ and (ev.flags & std.c.EV.ENABLE) != 0) saw_enable = true;
    }
    try std.testing.expect(saw_enable);
}

test "H6: the c2s reader cap follows authentication" {
    const allocator = std.testing.allocator;
    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try allocator.create(Session);
    defer {
        session.deinit();
        allocator.destroy(session);
    }
    session.* = Session.init(fds[0], 1, "localhost", false, allocator);

    // Before auth the reader holds the pre-auth budget, not the 1 MiB default.
    try std.testing.expectEqual(xml.max_item_bytes_pre_auth, session.reader.scan.max_item_bytes);
    try std.testing.expectEqual(
        xml.memoryBudgetFor(xml.max_item_bytes_pre_auth),
        session.reader.max_item_memory,
    );
    try std.testing.expect(session.reader.scan.max_item_bytes < xml.default_max_item_bytes);
}

test "H6: an oversized pre-auth element is a policy violation, not a silent drop" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    const stream_open = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    handleReadable(&server, 1, &changes);
    try std.testing.expect(server.sessions[1] != null);

    // One element larger than the pre-auth cap. It is never authenticated, so
    // the pre-auth cap applies and the stream is failed closed with a
    // policy-violation rather than buffered. Feeds one read event's worth at a
    // time, as the loop does in production.
    _ = try posix.write(fds[1], "<presence><show>");
    var big: [4096]u8 = undefined;
    @memset(&big, 'A');
    var fed: usize = 0;
    while (fed <= xml.max_item_bytes_pre_auth and server.sessions[1] != null) : (fed += big.len) {
        _ = try posix.write(fds[1], &big);
        handleReadable(&server, 1, &changes);
    }

    try std.testing.expect(server.sessions[1] == null);
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "policy-violation") != null);
}

test "H6: a stanza the accumulator can deliver is accepted after auth" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;
    // Authenticated, so the post-auth cap applies.
    session.stream.authenticated = true;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    const stream_open = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    handleReadable(&server, 1, &changes);
    try std.testing.expect(server.sessions[1] != null);

    // A body that fills most of the 16 KiB stanza accumulator: legal today, so
    // the authenticated cap must not reject it (the cap is a memory bound, not
    // a new stanza limit).
    const body_len = 15000;
    var msg: [body_len + 64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&msg);
    const w = fbs.writer();
    try w.writeAll("<message to='localhost' type='chat'><body>");
    @memset(msg[fbs.pos..][0..body_len], 'A');
    fbs.pos += body_len;
    try w.writeAll("</body></message>");
    _ = try posix.write(fds[1], fbs.getWritten());
    handleReadable(&server, 1, &changes);

    try std.testing.expect(server.sessions[1] != null);
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "policy-violation") == null);

    // The loop must have raised the cap once the stream was authenticated;
    // otherwise the session still runs on the pre-auth budget.
    try std.testing.expectEqual(
        xml.max_item_bytes_authenticated,
        session.reader.scan.max_item_bytes,
    );
}

test "H6: a broken stanza closes the stream before its close tag arrives" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;
    // Bound and active: a pre-bind message is refused by the RFC 6120 7.1
    // policy before its accumulation could overflow, so the stanza has to be
    // one the server would otherwise route.
    session.stream.authenticated = true;
    session.stream.state = .active;
    session.stream.authenticated_jid = .{ .local = "alice", .domain = "localhost" };
    session.stream.bound_jid = .{ .local = "alice", .domain = "localhost", .resource = "mobile" };

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    const stream_open = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    handleReadable(&server, 1, &changes);
    try std.testing.expect(server.sessions[1] != null);

    // A stanza whose children pass the 16 KiB accumulator with no
    // </message> ever sent. Each child carries a 200-byte text run, so the
    // accumulator grows about as fast as the reader's own accounting and is
    // what gives out first; the stanza is still incomplete when it does.
    _ = try posix.write(fds[1], "<message to='localhost' type='chat'>");
    var chunk: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&chunk);
    while (fbs.pos + 208 <= chunk.len) {
        try fbs.writer().writeAll("<a>");
        try fbs.writer().writeByteNTimes('x', 200);
        try fbs.writer().writeAll("</a>");
    }
    var fed: usize = 0;
    const limit = 64 * 1024;
    while (fed < limit and server.sessions[1] != null) : (fed += fbs.pos) {
        _ = try posix.write(fds[1], fbs.getWritten());
        handleReadable(&server, 1, &changes);
    }

    // Closed on the accumulator overflow, well before the children ran out and
    // with no close tag ever sent. The accumulator is what a stanza is
    // delivered through, so it must be the bound the peer hits first: reaching
    // the reader's larger item cap instead would mean the session survived the
    // first overflow and kept buffering.
    try std.testing.expect(server.sessions[1] == null);
    try std.testing.expect(fed < limit);
    try std.testing.expect(fed < xml.max_item_bytes_authenticated);

    var buf: [8192]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "policy-violation") != null);
}

test "Server: stream open produces response" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    // Create a direct socketpair to bypass listener
    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    // Manually create a session
    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    // Simulate client sending stream open
    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);

    // Process the readable event
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    handleReadable(&server, 1, &changes);

    // Server should have queued (and, since handleReadable flushes eagerly,
    // likely already sent) a response — flush covers both cases.
    _ = try session.conn.flushSend();
    var buf: [2048]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    const response = buf[0..n];

    // Should contain stream open + features with STARTTLS
    try std.testing.expect(std.mem.indexOf(u8, response, "<stream:stream") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "<stream:features>") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "<starttls") != null);
}

test "Server: stream open with mixed-case 'to' produces response" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='LOCALHOST' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    handleReadable(&server, 1, &changes);

    _ = try session.conn.flushSend();
    var buf: [2048]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    const response = buf[0..n];

    try std.testing.expect(std.mem.indexOf(u8, response, "<stream:stream") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "host-unknown") == null);
}

test "Server: pre-bind stanza to the domain in another case is server-addressed" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    const to_attr = [_]xml.Attribute{
        .{ .name = "to", .value = "LOCALHOST", .prefix = "", .local_name = "to" },
    };
    const elem = xml.Element{
        .name = "message",
        .prefix = "",
        .local_name = "message",
        .namespace_uri = "jabber:client",
        .attributes = &to_attr,
        .self_closing = false,
    };
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    try std.testing.expectEqual(PreBindVerdict.server_addressed, enforcePreBindStanzaPolicy(&server, session, elem, &changes));
}

test "F6: ingress preparation folds the local 'to' before routing" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;

    const target_fds = try makeSocketPair();
    defer posix.close(target_fds[1]);
    const target = try allocator.create(Session);
    target.* = Session.init(target_fds[0], 5, "localhost", false, allocator);
    target.stream.state = .active;
    target.stream.authenticated = true;
    target.stream.bound_jid = xmpp.Jid.parse("naplestb@localhost/desk") catch null;
    // A bodiless message is typing-only under XEP-0352 and is skipped for
    // CSI-inactive sessions.
    target.csi_active = true;
    server.sessions[5] = target;
    _ = try sm.bind(0, 5, "naplestb", "localhost", "desk");
    sm.setPresenceAvailable("naplestb", "localhost", "desk", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    const alice = try allocator.create(Session);
    alice.* = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    alice.stream.state = .active;
    alice.stream.authenticated = true;
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mob") catch null;
    server.sessions[9] = alice;
    // Stand in for the reader state at a self-closing top-level stanza's
    // element_start: depth was incremented and restored before the event.
    alice.reader.depth = 1;

    const attrs = [_]xml.Attribute{
        .{ .name = "to", .value = "NaplesTB@LOCALHOST", .prefix = "", .local_name = "to" },
        .{ .name = "type", .value = "chat", .prefix = "", .local_name = "type" },
        .{ .name = "id", .value = "m1", .prefix = "", .local_name = "id" },
    };
    var elem = xml.Element{
        .name = "message",
        .prefix = "",
        .local_name = "message",
        .namespace_uri = "jabber:client",
        .attributes = &attrs,
        .self_closing = true,
    };
    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    handleElementStart(&server, alice, &elem, &changes);

    // Routed to the folded account and serialized with the prepared spelling.
    _ = target.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(target_fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "to='naplestb@localhost'") != null);
}

test "F6: pre-bind stanza to the folded account is server-addressed" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;
    session.stream.state = .features_bind;
    session.stream.authenticated_jid = .{ .local = "NaplesTB", .domain = "localhost" };
    session.reader.depth = 1;

    const attrs = [_]xml.Attribute{
        .{ .name = "to", .value = "NaplesTB@localhost", .prefix = "", .local_name = "to" },
    };
    var elem = xml.Element{
        .name = "message",
        .prefix = "",
        .local_name = "message",
        .namespace_uri = "jabber:client",
        .attributes = &attrs,
        .self_closing = true,
    };
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    handleElementStart(&server, session, &elem, &changes);

    // Own-account: answered with a stanza error, the stream stays open.
    try std.testing.expect(server.sessions[1] != null);
    _ = try session.conn.flushSend();
    var buf: [2048]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "not-authorized") != null);
}

test "F6: a 320-octet localpart survives the pre-bind account compare" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    var local_upper: [320]u8 = undefined;
    @memset(&local_upper, 'A');
    var to_buf: [512]u8 = undefined;
    const to = try std.fmt.bufPrint(&to_buf, "{s}@localhost", .{&local_upper});

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;
    session.stream.state = .features_bind;
    session.stream.authenticated_jid = .{ .local = &local_upper, .domain = "localhost" };
    session.reader.depth = 1;

    const attrs = [_]xml.Attribute{
        .{ .name = "to", .value = to, .prefix = "", .local_name = "to" },
    };
    var elem = xml.Element{
        .name = "message",
        .prefix = "",
        .local_name = "message",
        .namespace_uri = "jabber:client",
        .attributes = &attrs,
        .self_closing = true,
    };
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    handleElementStart(&server, session, &elem, &changes);

    try std.testing.expect(server.sessions[1] != null);
    _ = try session.conn.flushSend();
    var buf: [2048]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "not-authorized") != null);
}

test "F6: a maximum-length prepared username is not judged third party" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    // 1023-octet localpart + '@localhost' = a 1033-octet bare JID; the
    // account buffer must hold it whole or the write is silently truncated
    // and an own-account stanza closes the stream as third party (LOW-5).
    var local_upper: [1023]u8 = undefined;
    @memset(&local_upper, 'A');
    var to_buf: [1200]u8 = undefined;
    const to = try std.fmt.bufPrint(&to_buf, "{s}@localhost", .{&local_upper});

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;
    session.stream.state = .features_bind;
    session.stream.authenticated_jid = .{ .local = &local_upper, .domain = "localhost" };
    session.reader.depth = 1;

    const attrs = [_]xml.Attribute{
        .{ .name = "to", .value = to, .prefix = "", .local_name = "to" },
    };
    var elem = xml.Element{
        .name = "message",
        .prefix = "",
        .local_name = "message",
        .namespace_uri = "jabber:client",
        .attributes = &attrs,
        .self_closing = true,
    };
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    handleElementStart(&server, session, &elem, &changes);

    // Own-account: stanza error, the stream stays open.
    try std.testing.expect(server.sessions[1] != null);
    _ = try session.conn.flushSend();
    var buf: [2048]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "not-authorized") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "</stream:stream>") == null);
}

test "F6: malformed local 'to' gets jid-malformed for message and iq" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;
    session.stream.state = .active;
    session.stream.authenticated = true;
    session.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mob") catch null;
    session.reader.depth = 1;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    var buf: [2048]u8 = undefined;

    const msg_attrs = [_]xml.Attribute{
        .{ .name = "to", .value = "a@b@c", .prefix = "", .local_name = "to" },
        .{ .name = "type", .value = "chat", .prefix = "", .local_name = "type" },
        .{ .name = "id", .value = "m2", .prefix = "", .local_name = "id" },
    };
    var msg_elem = xml.Element{
        .name = "message",
        .prefix = "",
        .local_name = "message",
        .namespace_uri = "jabber:client",
        .attributes = &msg_attrs,
        .self_closing = true,
    };
    handleElementStart(&server, session, &msg_elem, &changes);
    _ = try session.conn.flushSend();
    var n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "jid-malformed") != null);
    try std.testing.expect(server.sessions[1] != null);

    const iq_attrs = [_]xml.Attribute{
        .{ .name = "to", .value = "x@@y", .prefix = "", .local_name = "to" },
        .{ .name = "type", .value = "get", .prefix = "", .local_name = "type" },
        .{ .name = "id", .value = "i1", .prefix = "", .local_name = "id" },
    };
    var iq_elem = xml.Element{
        .name = "iq",
        .prefix = "",
        .local_name = "iq",
        .namespace_uri = "jabber:client",
        .attributes = &iq_attrs,
        .self_closing = true,
    };
    handleElementStart(&server, session, &iq_elem, &changes);
    _ = try session.conn.flushSend();
    n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "jid-malformed") != null);
    try std.testing.expect(server.sessions[1] != null);
}

/// F6 ingress-routing fixture: a bound naplestb target registered in the
/// session map plus an alice session whose stream opened over a real
/// socketpair. Stanzas are fed as wire bytes through handleReadable so the
/// reader's own depth/self-closing state drives the ingress gate.
pub const F6WirePair = struct {
    target: *Session,
    alice: *Session,
};

pub fn f6WireSetup(allocator: std.mem.Allocator, server: *Server, sm: *SessionMap, target_fds: [2]posix.fd_t, alice_fds: [2]posix.fd_t) !F6WirePair {
    return f6WireSetupBound(allocator, server, sm, target_fds, alice_fds, "naplestb");
}

pub fn f6WireSetupBound(allocator: std.mem.Allocator, server: *Server, sm: *SessionMap, target_fds: [2]posix.fd_t, alice_fds: [2]posix.fd_t, bound_local: []const u8) !F6WirePair {
    server.worker_id = 0;
    server.session_map = sm;
    const target = try allocator.create(Session);
    target.* = Session.init(target_fds[0], 5, "localhost", false, allocator);
    target.stream.state = .active;
    target.stream.authenticated = true;
    target.stream.bound_jid = .{ .local = bound_local, .domain = "localhost", .resource = "desk" };
    target.csi_active = true;
    server.sessions[5] = target;
    _ = try sm.bind(0, 5, bound_local, "localhost", "desk");
    sm.setPresenceAvailable(bound_local, "localhost", "desk", true);

    const alice = try allocator.create(Session);
    alice.* = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    server.sessions[9] = alice;
    var changes_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&changes_buf);
    _ = try posix.write(alice_fds[1], "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>");
    handleReadable(server, 9, &changes);
    _ = alice.conn.flushSend() catch {};
    var drain: [4096]u8 = undefined;
    _ = posix.read(alice_fds[1], &drain) catch 0;
    alice.stream.state = .active;
    alice.stream.authenticated = true;
    alice.stream.authenticated_jid = .{ .local = "alice", .domain = "localhost" };
    alice.stream.bound_jid = .{ .local = "alice", .domain = "localhost", .resource = "mob" };
    return .{ .target = target, .alice = alice };
}

pub fn f6Feed(server: *Server, s: *Session, id: u32, fd: posix.fd_t, bytes: []const u8) !void {
    var changes_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&changes_buf);
    _ = try posix.write(fd, bytes);
    handleReadable(server, id, &changes);
    _ = s.conn.flushSend() catch {};
}

pub fn f6Read(fd: posix.fd_t, buf: []u8) []const u8 {
    const n = posix.read(fd, buf) catch 0;
    return buf[0..n];
}

test "F6: self-closing top-level message with malformed 'to' gets jid-malformed" {
    const allocator = std.testing.allocator;
    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    const tf = try makeSocketPair();
    defer posix.close(tf[1]);
    const af = try makeSocketPair();
    defer posix.close(af[1]);
    const s = try f6WireSetup(allocator, &server, &sm, tf, af);

    var buf: [8192]u8 = undefined;
    try f6Feed(&server, s.alice, 9, af[1], "<message to='a@b@c' type='chat' id='p1'/>");
    const r = f6Read(af[1], &buf);
    try std.testing.expect(std.mem.indexOf(u8, r, "jid-malformed") != null);
    try std.testing.expect(std.mem.indexOf(u8, r, "id='p1'") != null);
}

test "F6: self-closing top-level message to a mixed-case local JID is routed folded" {
    const allocator = std.testing.allocator;
    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    const tf = try makeSocketPair();
    defer posix.close(tf[1]);
    const af = try makeSocketPair();
    defer posix.close(af[1]);
    const s = try f6WireSetup(allocator, &server, &sm, tf, af);

    var buf: [8192]u8 = undefined;
    try f6Feed(&server, s.alice, 9, af[1], "<message to='NaplesTB@LOCALHOST' type='chat' id='b2'/>");
    _ = s.target.conn.flushSend() catch {};
    const r = f6Read(tf[1], &buf);
    try std.testing.expect(std.mem.indexOf(u8, r, "to='naplestb@localhost'") != null);
    try std.testing.expect(std.mem.indexOf(u8, r, "id='b2'") != null);
}

test "F6: a non-ASCII localpart reaches the account under its prepared spelling" {
    const allocator = std.testing.allocator;
    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    const tf = try makeSocketPair();
    defer posix.close(tf[1]);
    const af = try makeSocketPair();
    defer posix.close(af[1]);
    // The target binds the UsernameCaseMapped form of the address, exactly
    // the spelling registration and SASL store and authenticate.
    const s = try f6WireSetupBound(allocator, &server, &sm, tf, af, "\xCE\xBF\xCE\xB4\xCE\xBF\xCF\x83");

    var buf: [8192]u8 = undefined;
    // to='\xCE\x9F\xCE\x94\xCE\x9F\xCE\xA3@localhost' is the typed form
    // U+039F U+0394 U+039F U+03A3, preparing to "οδοσ@localhost".
    try f6Feed(&server, s.alice, 9, af[1], "<message to='\xCE\x9F\xCE\x94\xCE\x9F\xCE\xA3@localhost' type='chat' id='g1'/>");
    _ = s.target.conn.flushSend() catch {};
    const r = f6Read(tf[1], &buf);
    try std.testing.expect(std.mem.indexOf(u8, r, "to='\xCE\xBF\xCE\xB4\xCE\xBF\xCF\x83@localhost'") != null);
    try std.testing.expect(std.mem.indexOf(u8, r, "id='g1'") != null);
}

test "F6: a migrated account receives mail addressed to its legacy spelling" {
    const allocator = std.testing.allocator;
    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    const tf = try makeSocketPair();
    defer posix.close(tf[1]);
    const af = try makeSocketPair();
    defer posix.close(af[1]);
    // After `xmppctl migrate-precis` the account exists only under the
    // prepared key "naplestb"; a stanza addressed with the pre-migration
    // spelling must still reach it.
    const s = try f6WireSetupBound(allocator, &server, &sm, tf, af, "naplestb");

    var buf: [8192]u8 = undefined;
    try f6Feed(&server, s.alice, 9, af[1], "<message to='NaplesTB@localhost' type='chat' id='m9'><body>hi</body></message>");
    _ = s.target.conn.flushSend() catch {};
    const r = f6Read(tf[1], &buf);
    try std.testing.expect(std.mem.indexOf(u8, r, "to='naplestb@localhost'") != null);
    try std.testing.expect(std.mem.indexOf(u8, r, "id='m9'") != null);
}

test "F6: self-closing presence subscribe to a mixed-case local JID is routed folded" {
    const allocator = std.testing.allocator;
    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const db_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(db_path);
    var db = try OpBackendMod.Backend.open(db_path, .{});
    defer db.close();
    var roster = GenericRosterStore.init(&db);
    server.roster = &roster;
    const tf = try makeSocketPair();
    defer posix.close(tf[1]);
    const af = try makeSocketPair();
    defer posix.close(af[1]);
    const s = try f6WireSetup(allocator, &server, &sm, tf, af);

    var buf: [8192]u8 = undefined;
    try f6Feed(&server, s.alice, 9, af[1], "<presence to='NaplesTB@LOCALHOST' type='subscribe'/>");
    _ = s.target.conn.flushSend() catch {};
    const r = f6Read(tf[1], &buf);
    try std.testing.expect(std.mem.indexOf(u8, r, "<presence") != null);
    try std.testing.expect(std.mem.indexOf(u8, r, "type='subscribe'") != null);
    // The pending subscription was filed under the folded contact spelling.
    try std.testing.expect(std.mem.indexOf(u8, r, "to='naplestb@localhost'") != null);
}

test "F6: a self-closing stanza-named child inside an IQ is not prepared" {
    const allocator = std.testing.allocator;
    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    const tf = try makeSocketPair();
    defer posix.close(tf[1]);
    const af = try makeSocketPair();
    defer posix.close(af[1]);
    const s = try f6WireSetup(allocator, &server, &sm, tf, af);

    var buf: [8192]u8 = undefined;
    try f6Feed(&server, s.alice, 9, af[1], "<iq type='get' id='q1'><query xmlns='jabber:iq:roster'/><message to='a@b@c'/></iq>");
    const r = f6Read(af[1], &buf);
    // The child's 'to' is not a stanza address: the IQ must be answered
    // normally, never with a jid-malformed stanza error.
    try std.testing.expect(std.mem.indexOf(u8, r, "jid-malformed") == null);
    try std.testing.expect(std.mem.indexOf(u8, r, "id='q1'") != null);
}

test "F6: type=error stanza with malformed 'to' is dropped without a reply" {
    const allocator = std.testing.allocator;
    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    const tf = try makeSocketPair();
    defer posix.close(tf[1]);
    const af = try makeSocketPair();
    defer posix.close(af[1]);
    const s = try f6WireSetup(allocator, &server, &sm, tf, af);

    var buf: [8192]u8 = undefined;
    try f6Feed(&server, s.alice, 9, af[1], "<message to='a@b@c' type='error' id='e1'><body>x</body></message>");
    const r = f6Read(af[1], &buf);
    // RFC 6120 8.3.1: an error stanza is never answered, even when its own
    // address is malformed.
    try std.testing.expectEqual(@as(usize, 0), r.len);
}

test "F6: presence with malformed 'to' gets a jid-malformed reply to the full JID" {
    const allocator = std.testing.allocator;
    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    const tf = try makeSocketPair();
    defer posix.close(tf[1]);
    const af = try makeSocketPair();
    defer posix.close(af[1]);
    const s = try f6WireSetup(allocator, &server, &sm, tf, af);

    var buf: [8192]u8 = undefined;
    try f6Feed(&server, s.alice, 9, af[1], "<presence to='@localhost' type='subscribe' id='pr1'></presence>");
    const r = f6Read(af[1], &buf);
    try std.testing.expect(std.mem.indexOf(u8, r, "<presence") != null);
    try std.testing.expect(std.mem.indexOf(u8, r, "jid-malformed") != null);
    try std.testing.expect(std.mem.indexOf(u8, r, "to='alice@localhost/mob'") != null);
    // The reply's 'from' echoes the offending address.
    try std.testing.expect(std.mem.indexOf(u8, r, "from='@localhost'") != null);
}

test "F6: a malformed 'from' gets jid-malformed" {
    const allocator = std.testing.allocator;
    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    const tf = try makeSocketPair();
    defer posix.close(tf[1]);
    const af = try makeSocketPair();
    defer posix.close(af[1]);
    const s = try f6WireSetup(allocator, &server, &sm, tf, af);

    var buf: [8192]u8 = undefined;
    try f6Feed(&server, s.alice, 9, af[1], "<message from='a@b@c' to='naplestb@localhost' type='chat' id='m3'/>");
    const r = f6Read(af[1], &buf);
    try std.testing.expect(std.mem.indexOf(u8, r, "jid-malformed") != null);
    try std.testing.expect(std.mem.indexOf(u8, r, "id='m3'") != null);
}

test "F6: jid-malformed reply echoes the offending 'to' in its 'from'" {
    const allocator = std.testing.allocator;
    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    const tf = try makeSocketPair();
    defer posix.close(tf[1]);
    const af = try makeSocketPair();
    defer posix.close(af[1]);
    const s = try f6WireSetup(allocator, &server, &sm, tf, af);

    var buf: [8192]u8 = undefined;
    try f6Feed(&server, s.alice, 9, af[1], "<message to='a@b@c' type='chat' id='m15'/>");
    const r = f6Read(af[1], &buf);
    try std.testing.expect(std.mem.indexOf(u8, r, "jid-malformed") != null);
    try std.testing.expect(std.mem.indexOf(u8, r, "from='a@b@c'") != null);
    try std.testing.expect(std.mem.indexOf(u8, r, "id='m15'") != null);
}

test "F6: pre-auth stanza with a malformed 'to' closes the stream not-authorized (T182)" {
    const allocator = std.testing.allocator;
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    const af = try makeSocketPair();
    defer posix.close(af[1]);
    const alice = try allocator.create(Session);
    alice.* = Session.init(af[0], 9, "localhost", false, allocator);
    server.sessions[9] = alice;

    var changes_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&changes_buf);
    _ = try posix.write(af[1], "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>");
    handleReadable(&server, 9, &changes);
    _ = alice.conn.flushSend() catch {};
    var buf: [8192]u8 = undefined;
    _ = f6Read(af[1], &buf);

    // RFC 6120 7.1 (T182): an unclassifiable address before bind defers to
    // the pre-bind policy; third party, so the stream closes with
    // not-authorized instead of answering jid-malformed.
    _ = try posix.write(af[1], "<message to='@localhost' type='chat' id='f1'><body>x</body></message>");
    handleReadable(&server, 9, &changes);
    try std.testing.expect(server.sessions[9] == null);
    const r = f6Read(af[1], &buf);
    try std.testing.expect(std.mem.indexOf(u8, r, "not-authorized") != null);
}

test "F6: groupchat message to the MUC host in another case stays local" {
    const allocator = std.testing.allocator;
    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var registry = RoomRegistry.init(allocator);
    defer registry.deinit();
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    const tf = try makeSocketPair();
    defer posix.close(tf[1]);
    const af = try makeSocketPair();
    defer posix.close(af[1]);
    const s = try f6WireSetup(allocator, &server, &sm, tf, af);
    server.muc_host = "conference.localhost";
    server.room_registry = &registry;

    var buf: [8192]u8 = undefined;
    try f6Feed(&server, s.alice, 9, af[1], "<message to='Room@CONFERENCE.localhost' type='groupchat' id='m1'><body>hi</body></message>");
    const r = f6Read(af[1], &buf);
    // MUC answers item-not-found for the missing room; a case-sensitive
    // compare would send the stanza to S2S and bounce service-unavailable.
    try std.testing.expect(std.mem.indexOf(u8, r, "item-not-found") != null);
    try std.testing.expect(std.mem.indexOf(u8, r, "service-unavailable") == null);
}

test "F6: directed presence to the MUC host in another case joins the room" {
    const allocator = std.testing.allocator;
    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var registry = RoomRegistry.init(allocator);
    defer registry.deinit();
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    const tf = try makeSocketPair();
    defer posix.close(tf[1]);
    const af = try makeSocketPair();
    defer posix.close(af[1]);
    const s = try f6WireSetup(allocator, &server, &sm, tf, af);
    server.muc_host = "conference.localhost";
    server.room_registry = &registry;

    var buf: [8192]u8 = undefined;
    try f6Feed(&server, s.alice, 9, af[1], "<presence to='Room@CONFERENCE.localhost/Nick'/>");
    const r = f6Read(af[1], &buf);
    // The join creates the room and answers with MUC self-presence
    // (status 110) addressed from the configured host spelling.
    try std.testing.expect(std.mem.indexOf(u8, r, "code='110'") != null);
    try std.testing.expect(std.mem.indexOf(u8, r, "service-unavailable") == null);
}

test "F6: disco info to the MUC host in another case is the conference service" {
    const allocator = std.testing.allocator;
    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    const tf = try makeSocketPair();
    defer posix.close(tf[1]);
    const af = try makeSocketPair();
    defer posix.close(af[1]);
    const s = try f6WireSetup(allocator, &server, &sm, tf, af);
    server.muc_host = "conference.localhost";

    var buf: [8192]u8 = undefined;
    try f6Feed(&server, s.alice, 9, af[1], "<iq to='CONFERENCE.localhost' type='get' id='i1'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>");
    const r = f6Read(af[1], &buf);
    // The MUC service answers with its conference identity; a
    // case-sensitive compare falls to the server identity instead.
    try std.testing.expect(std.mem.indexOf(u8, r, "category='conference'") != null);
    try std.testing.expect(std.mem.indexOf(u8, r, "category='server'") == null);
}

test "F6: Session carries one shared IQ payload prep buffer" {
    // LOW-3: the roster/block item JID and the MAM 'with' JID share
    // iq_jid_prep_buf; a second 3071-octet payload buffer must not return.
    // 80512 covers the 1023-octet auth_username_buf, iq_pubsub_verb and the
    // SslConn DANE fields the shared verifier added (fatal, syscall_errno).
    // 80512 adds the Outbox bookkeeping (ring ptr, spill list, counters)
    // and the Transport/Tls union to the pre-C2 size.
    try std.testing.expect(@sizeOf(Session) <= 80512);
}

test "Server: registration submits are PRECIS-prepared and invalid names get not-acceptable" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    // Stand-in for xmppd-auth on the other end of the IPC socketpair.
    const ipc_fds = try makeSocketPair();
    defer posix.close(ipc_fds[1]);
    server.ipc.fd = ipc_fds[0];
    server.ipc.connected = true;

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // Stream handshake: registration IQs are only taken pre-auth in the
    // features_sasl state.
    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    handleReadable(&server, 1, &changes);
    _ = try session.conn.flushSend();
    var buf: [4096]u8 = undefined;
    const n0 = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n0], "<stream:stream") != null);

    // Registration is a pre-auth IQ taken in the features_sasl state; the
    // test skips the STARTTLS+SASL-feature dance and establishes that
    // precondition directly.
    session.stream.state = .features_sasl;

    // An invalid PRECIS name is rejected at the call site with
    // not-acceptable and never reaches the auth daemon.
    const bad_reg = "<iq type='set' id='r1'><query xmlns='jabber:iq:register'><username>a b</username><password>pw</password></query></iq>";
    _ = try posix.write(fds[1], bad_reg);
    handleReadable(&server, 1, &changes);
    _ = try session.conn.flushSend();
    const n1 = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n1], "<not-acceptable") != null);
    var ipc_buf: [4096]u8 = undefined;
    try std.testing.expect((posix.read(ipc_fds[1], &ipc_buf) catch 0) == 0);

    // RFC 7622 Section 3.3.1 additionally excludes "@" even though the
    // IdentifierClass permits it.
    const excluded_reg = "<iq type='set' id='r1x'><query xmlns='jabber:iq:register'><username>a@b</username><password>pw</password></query></iq>";
    _ = try posix.write(fds[1], excluded_reg);
    handleReadable(&server, 1, &changes);
    _ = try session.conn.flushSend();
    const n1x = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n1x], "<not-acceptable") != null);
    try std.testing.expect((posix.read(ipc_fds[1], &ipc_buf) catch 0) == 0);

    // A valid name is forwarded to the auth daemon in canonical form:
    // "ΟΔΟΣ" (U+039F U+0394 U+039F U+03A3) prepares to "οδοσ" (U+03A3 folds
    // to U+03C3 unconditionally; no final-sigma rule).
    const good_reg = "<iq type='set' id='r2'><query xmlns='jabber:iq:register'><username>\u{039F}\u{0394}\u{039F}\u{03A3}</username><password>pw</password></query></iq>";
    _ = try posix.write(fds[1], good_reg);
    handleReadable(&server, 1, &changes);
    _ = try session.conn.flushSend();

    // One length-prefixed frame lands on the IPC socket: a register_request
    // carrying the prepared name.
    const total = posix.read(ipc_fds[1], &ipc_buf) catch 0;
    try std.testing.expect(total > 4);
    const payload_len = std.mem.readInt(u32, ipc_buf[0..4], .little);
    try std.testing.expectEqual(@as(usize, payload_len), total - 4);
    const msg = try ipc_protocol.decode(ipc_buf[4..total]);
    try std.testing.expect(msg == .register_request);
    try std.testing.expectEqualStrings("\u{03BF}\u{03B4}\u{03BF}\u{03C3}", msg.register_request.username);
}

test "Server: TLS ClientHello on STARTTLS port is closed without XML parse error (T160)" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 3, "localhost", false, std.testing.allocator);
    server.sessions[3] = session;

    // Simulate a direct-TLS client sending a TLS record header (ClientHello)
    const client_hello_prefix = "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03";
    _ = try posix.write(fds[1], client_hello_prefix);

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    handleReadable(&server, 3, &changes);

    // Session must be closed immediately, without feeding bytes to the XML parser
    try std.testing.expect(server.sessions[3] == null);

    // No stream error / features should have been sent to the TLS client
    var buf: [256]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n);
}

test "Server: T215 proceed must fully flush before the TLS upgrade starts" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    // A real cert so the deferred upgrade actually starts (without it the
    // startTlsUpgrade calls could be deleted and the test stayed green).
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const pem_path = try connection_mod.makeTestPem(std.testing.allocator, tmp.dir);
    defer std.testing.allocator.free(pem_path);
    server.ssl_ctx = try ssl.SslContext.initServer(pem_path, pem_path);

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // Drive the stream open so the FSM reaches features_tls.
    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    handleReadable(&server, 1, &changes);

    // Drain the peer side, then fill the kernel send path (unix pairs
    // buffer 64 KiB and ignore SO_SNDBUF): with the socket full the
    // queued <proceed/> cannot flush at once.
    var drain_buf: [16384]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;
    try std.testing.expect(fillWriteBuffer(session));

    _ = try posix.write(fds[1], "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
    handleReadable(&server, 1, &changes);

    // Upgrade deferred: FSM is pending but TLS has NOT started.
    try std.testing.expect(session.stream.state == .starttls_pending);
    try std.testing.expect(session.conn.tls == null);
    try std.testing.expect(session.conn.hasPendingWrite());

    // Drain the peer, then let the write-ready handler finish.
    while (posix.read(fds[1], &drain_buf)) |n| {
        if (n == 0) break;
    } else |_| {}
    handleWritable(&server, 1, &changes);
    try std.testing.expect(!session.conn.hasPendingWrite());

    // Buffer drained: the deferred upgrade has started the handshake.
    try std.testing.expect(session.conn.tls != null);
    try std.testing.expect(session.conn.isTlsHandshaking());
}

test "Server: T215 failed deferred upgrade does not touch the freed session" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    // A real cert so the deferred path is reached at all: without ssl_ctx,
    // startTlsUpgrade only logs and never closes the session.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const pem_path = try connection_mod.makeTestPem(std.testing.allocator, tmp.dir);
    defer std.testing.allocator.free(pem_path);
    server.ssl_ctx = try ssl.SslContext.initServer(pem_path, pem_path);

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    handleReadable(&server, 1, &changes);

    // Park the FSM in starttls_pending with <proceed/> still unflushed, so
    // the upgrade is deferred to handleWritable.
    var drain_buf: [16384]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;
    try std.testing.expect(fillWriteBuffer(session));

    _ = try posix.write(fds[1], "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
    handleReadable(&server, 1, &changes);
    try std.testing.expect(session.stream.state == .starttls_pending);

    // The upgrade will fail, and a failure closes the session and frees it.
    server.fail_next_tls_upgrade = true;

    while (posix.read(fds[1], &drain_buf)) |n| {
        if (n == 0) break;
    } else |_| {}
    handleWritable(&server, 1, &changes);

    // handleWritable must stop at the failed upgrade. Continuing into the
    // offline-pending drain and read-backpressure re-arm would access freed
    // session state.
    try std.testing.expect(server.sessions[1] == null);
    try std.testing.expect(!server.fail_next_tls_upgrade);
}

test "Server: T215 plaintext in a later segment while STARTTLS pending is a policy-violation" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    handleReadable(&server, 1, &changes);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    // <starttls/> alone: the FSM parks in starttls_pending.
    _ = try posix.write(fds[1], "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
    handleReadable(&server, 1, &changes);
    try std.testing.expect(session.stream.state == .starttls_pending);
    try std.testing.expect(server.sessions[1] != null);

    // Plaintext in a LATER segment: the peer must send nothing until the
    // upgrade. Reject and close (RFC 6120 5.4.3.2).
    _ = try posix.write(fds[1], "<message to='a@b'><body>x</body></message>");
    handleReadable(&server, 1, &changes);

    try std.testing.expect(server.sessions[1] == null);
    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (posix.read(fds[1], buf[total..])) |n| {
        if (n == 0) break; // EOF: the server closed its side
        total += n;
    } else |_| {}
    try std.testing.expect(std.mem.indexOf(u8, buf[0..total], "policy-violation") != null);
}

test "Server: T215 plaintext read-ahead past <starttls/> is a policy-violation" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    handleReadable(&server, 1, &changes);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    // <starttls/> followed by more plaintext in the same flight.
    _ = try posix.write(fds[1], "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/><message to='a@b'><body>x</body></message>");
    handleReadable(&server, 1, &changes);

    // Protocol violation: the session is closed with a stream error.
    try std.testing.expect(server.sessions[1] == null);
    const n = posix.read(fds[1], &drain_buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, drain_buf[0..n], "policy-violation") != null);
}

test "Server: S27 nested stream:stream closes with not-well-formed" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    handleReadable(&server, 1, &changes);
    try std.testing.expect(server.sessions[1] != null);

    // A second stream header inside the open stream: protocol violation.
    const nested = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], nested);
    handleReadable(&server, 1, &changes);

    try std.testing.expect(server.sessions[1] == null);
    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (posix.read(fds[1], buf[total..])) |n| {
        if (n == 0) break; // EOF: the server closed its side
        total += n;
    } else |_| {}
    try std.testing.expect(std.mem.indexOf(u8, buf[0..total], "not-well-formed") != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, buf[0..total], "<stream:stream"));
}

/// Feed a bad stream root, then keep feeding stanzas. The connection must
/// close on the root and the reader arena must stay bounded.
pub fn expectBadRootBounded(root: []const u8) !void {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    var drain_buf: [8192]u8 = undefined;

    _ = try posix.write(fds[1], root);
    handleReadable(&server, 1, &changes);
    var err_buf: [4096]u8 = undefined;
    var err_total: usize = 0;
    while (posix.read(fds[1], err_buf[err_total..])) |n| {
        if (n == 0) break;
        err_total += n;
    } else |_| {}
    const err_xml = err_buf[0..err_total];
    try std.testing.expect(std.mem.indexOf(u8, err_xml, "not-well-formed") != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, err_xml, "<stream:stream"));
    try std.testing.expect(std.mem.startsWith(u8, err_xml, "<?xml version='1.0'?><stream:stream"));

    var cap_max: usize = 0;
    var chunk_buf: [4096]u8 = undefined;
    var fed: usize = 0;
    while (fed < 20000) {
        const s = server.sessions[1] orelse break;
        const cap = s.reader.arena.queryCapacity();
        if (cap > cap_max) cap_max = cap;

        var fbs = std.io.fixedBufferStream(&chunk_buf);
        for (0..100) |_| {
            fbs.writer().writeAll("<presence><show>away</show></presence>") catch break;
        }
        const chunk = fbs.getWritten();
        var off: usize = 0;
        while (off < chunk.len) {
            const n = posix.write(fds[1], chunk[off..]) catch break;
            if (n == 0) break;
            off += n;
        }
        handleReadable(&server, 1, &changes);
        while (posix.read(fds[1], &drain_buf)) |n| {
            if (n == 0) break;
        } else |_| break;
        fed += 100;
    }

    // The root is a stream error, so the connection is gone and nothing can
    // keep growing. Both halves matter: a live session with a bounded arena
    // would still be a peer-controlled resource leak.
    try std.testing.expect(server.sessions[1] == null);
    try std.testing.expect(cap_max < 256 * 1024);
}

test "Server: E1 a self-closing stream header closes with not-well-formed" {
    try expectBadRootBounded("<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'/>");
}

test "Server: E1 a stream root with an unbound prefix closes with not-well-formed" {
    try expectBadRootBounded("<stream:stream xmlns='jabber:client'>");
}

test "Server: E1 a non-stream root closes with not-well-formed" {
    try expectBadRootBounded("<foo xmlns='jabber:client'>");
}

test "Server: direct TLS skips STARTTLS features" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    // Create session with direct_tls=true
    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 2, "localhost", true, std.testing.allocator);
    server.sessions[2] = session;

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    handleReadable(&server, 2, &changes);

    _ = try session.conn.flushSend();
    var buf: [2048]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    const response = buf[0..n];

    // Should have SASL mechanisms, NOT STARTTLS
    try std.testing.expect(std.mem.indexOf(u8, response, "<mechanisms") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "SCRAM-SHA-256") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "<starttls") == null);
}

test "S1: PEP accumulator escapes attributes, namespaces and text" {
    const allocator = std.testing.allocator;
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 4);
    defer server.deinit();

    var fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds));
    defer posix.close(fds[1]);

    const session = try allocator.create(Session);
    defer allocator.destroy(session);
    session.* = Session.init(fds[0], 0, server.server_host, false, allocator);
    defer session.deinit();

    // The scanner decodes entities, so these values arrive decoded; a raw
    // re-emit closes the attribute and injects a second stanza (S1).
    const attrs = [_]xml.Attribute{
        .{ .name = "lat", .value = "1'><message from='admin@localhost'><body>pwn</body></message><x a='", .prefix = "", .local_name = "lat" },
    };
    const elem: xml.Element = .{
        .name = "geoloc",
        .prefix = "",
        .local_name = "geoloc",
        .namespace_uri = "urn:x'y",
        .attributes = &attrs,
        .self_closing = false,
    };
    accumulatePepElement(&server, session, elem);
    accumulatePepText(&server, session, "10</lat><evil/>");
    accumulatePepClose(&server, session, "geoloc");

    const payload = session.pep_payload.items;
    try std.testing.expect(std.mem.indexOf(u8, payload, "<message") == null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "<evil/>") == null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "xmlns='urn:x&apos;y'") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "&lt;evil/&gt;") != null);
}

test "S15: queueSendStanza counts the stanza for XEP-0198" {
    const allocator = std.testing.allocator;
    const fds = try makeSocketPair();
    // session.deinit() closes fds[0].
    defer posix.close(fds[1]);
    var session = Session.init(fds[0], 1, "localhost", false, allocator);
    defer session.deinit();
    session.sm_enabled = true;
    // Owned by session.deinit once assigned.
    const queue = try allocator.create(sm_state.SmUnackedQueue);
    queue.* = sm_state.SmUnackedQueue.init(allocator);
    session.sm_unacked = queue;

    const before = session.sm_out_seq;
    try session.queueSendStanza("<message from='a@localhost' to='b@localhost'/>");
    try std.testing.expectEqual(before + 1, session.sm_out_seq);
    try std.testing.expectEqual(@as(u32, 1), queue.pending());
}

test "S15: live router delivery tracks the stanza for XEP-0198" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;

    const target_fds = try makeSocketPair();
    defer posix.close(target_fds[1]);
    const target = try allocator.create(Session);
    target.* = Session.init(target_fds[0], 5, "localhost", false, allocator);
    target.stream.state = .active;
    target.stream.authenticated = true;
    target.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch null;
    target.sm_enabled = true;
    const queue = try allocator.create(sm_state.SmUnackedQueue);
    queue.* = sm_state.SmUnackedQueue.init(allocator);
    target.sm_unacked = queue;
    server.sessions[5] = target;

    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "track1";
    const body = "<body>counted</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    // Delivered live, and counted exactly once.
    _ = target.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(target_fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "<body>counted</body>") != null);
    try std.testing.expectEqual(@as(u32, 1), target.sm_out_seq);
    try std.testing.expectEqual(@as(u32, 1), queue.pending());
}

test "R-385: an oversized queued iq result keeps the session and answers resource-constraint" {
    const allocator = std.testing.allocator;

    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    var session = Session.init(fds[0], 0, server.server_host, false, allocator);
    defer session.deinit();
    session.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    session.iq_to = "localhost";

    // A reply longer than the whole write buffer: queueSend refuses it even
    // with the buffer empty, so this is oversize, not a slow reader.
    const stanza = try allocator.alloc(u8, connection_mod.WRITE_BUF_SIZE + 32);
    defer allocator.free(stanza);
    const head = "<iq type='result' from='localhost' to='alice@localhost/mobile' id='big1'><query>";
    @memcpy(stanza[0..head.len], head);
    @memset(stanza[head.len .. stanza.len - 5], 'x');
    @memcpy(stanza[stanza.len - 5 ..], "</iq>");

    const drops_before = delivery_queue_mod.oversize_queue_drops.load(.monotonic);
    queueStanzaOrDrop(&session, stanza, "oversize iq result");

    try std.testing.expect(!session.sm_overflow);
    try std.testing.expectEqual(drops_before + 1, delivery_queue_mod.oversize_queue_drops.load(.monotonic));

    _ = session.conn.flushSend() catch {};
    var wire: [4096]u8 = undefined;
    const n = posix.read(fds[1], &wire) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, wire[0..n], "type='error'") != null);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..n], "id='big1'") != null);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..n], "resource-constraint") != null);
}

test "R-385: a full buffer on a deliverable stanza still flags overflow teardown" {
    const allocator = std.testing.allocator;

    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    var session = Session.init(fds[0], 0, server.server_host, false, allocator);
    defer session.deinit();

    @memset(session.conn.write_buf[0..connection_mod.WRITE_BUF_SIZE], 'x');
    session.conn.outbox.head = 0;
    session.conn.outbox.used = connection_mod.WRITE_BUF_SIZE;

    const drops_before = delivery_queue_mod.oversize_queue_drops.load(.monotonic);
    queueStanzaOrDrop(&session, "<iq type='result' id='q1'/>", "small iq result");

    try std.testing.expect(session.sm_overflow);
    try std.testing.expectEqual(drops_before, delivery_queue_mod.oversize_queue_drops.load(.monotonic));
}

test "Server: S11 stray close tag closes the stream not-well-formed" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    handleReadable(&server, 1, &changes);
    try std.testing.expect(server.sessions[1] != null);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    // A close tag with no matching open: depth must not desync.
    _ = try posix.write(fds[1], "</junk>");
    handleReadable(&server, 1, &changes);

    try std.testing.expect(server.sessions[1] == null);
    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (posix.read(fds[1], buf[total..])) |n| {
        if (n == 0) break;
        total += n;
    } else |_| {}
    try std.testing.expect(std.mem.indexOf(u8, buf[0..total], "not-well-formed") != null);
}

test "Server: S11 overlong bind id is rejected, not truncated" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    handleReadable(&server, 1, &changes);
    try std.testing.expect(server.sessions[1] != null);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    session.stream.state = .features_bind;
    const long_id = "i" ** 300;
    const iq = "<iq type='set' id='" ++ long_id ++ "'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></iq>";
    _ = try posix.write(fds[1], iq);
    handleReadable(&server, 1, &changes);

    try std.testing.expect(server.sessions[1] == null);
    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (posix.read(fds[1], buf[total..])) |n| {
        if (n == 0) break;
        total += n;
    } else |_| {}
    try std.testing.expect(std.mem.indexOf(u8, buf[0..total], "policy-violation") != null);
}

test "Server: S11 register flow iq ids survive the reader-arena reset" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    handleReadable(&server, 1, &changes);
    var drain_buf: [8192]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    // Registration is handled pre-auth; the TLS-offering state would
    // demand STARTTLS first.
    session.stream.state = .features_sasl;

    _ = try posix.write(fds[1], "<iq type='get' id='reg1'><query xmlns='jabber:iq:register'/></iq>");
    handleReadable(&server, 1, &changes);
    const n1 = posix.read(fds[1], &drain_buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, drain_buf[0..n1], "id='reg1'") != null);

    // The next stanza resets the reader arena the id slice came from; the
    // mirrored id in the reply must still be the client's.
    _ = try posix.write(fds[1], "<iq type='get' id='reg2-longer-id'><query xmlns='jabber:iq:register'/></iq>");
    handleReadable(&server, 1, &changes);
    const n2 = posix.read(fds[1], &drain_buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, drain_buf[0..n2], "id='reg2-longer-id'") != null);
    try std.testing.expect(server.sessions[1] != null);
}

test "Server: E5 an oversized body is not delivered and fails the stream" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    try tmp.dir.makePath("archive");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    const arch_path = try tmp.dir.realpathAlloc(allocator, "archive");
    defer allocator.free(arch_path);

    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var arch_db = try ArchiveBackendMod.Backend.open(arch_path, .{});
    defer arch_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);
    var arch_store = archive_store_mod.ArchiveStore(ArchiveBackendType).init(&arch_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;
    server.archive = &arch_store;

    // bob is online, so anything routed to him reaches his socket.
    const bob_fds = try makeSocketPair();
    defer posix.close(bob_fds[1]);
    const bob = try allocator.create(Session);
    bob.* = Session.init(bob_fds[0], 5, "localhost", false, allocator);
    server.sessions[5] = bob;
    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    // alice sends a message whose body exceeds the accumulation buffer.
    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    const alice = try allocator.create(Session);
    alice.* = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    server.sessions[9] = alice;
    alice.stream.state = .active;
    alice.stream.authenticated = true;
    alice.stream.authenticated_jid = .{ .local = "alice", .domain = "localhost" };
    alice.stream.bound_jid = .{ .local = "alice", .domain = "localhost", .resource = "mobile" };
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // A 20 KiB body overflows accumulation and must reject the whole stanza
    // without routing or storing partial content.
    const body_elem = xml.Element{
        .name = "body",
        .prefix = "",
        .local_name = "body",
        .namespace_uri = "",
        .attributes = &[_]xml.Attribute{},
        .self_closing = false,
    };
    accumulateStanzaElement(&server, alice, body_elem);
    var big: [20000]u8 = undefined;
    @memset(&big, 'A');
    accumulateStanzaText(&server, alice, &big);
    accumulateStanzaClose(&server, alice, "body");
    try std.testing.expect(alice.stanza_overflow);

    // The stanza completes: the partial is not routed, the stream is failed
    // closed, and the session is torn down.
    handleElementEnd(&server, alice, "message", &changes);

    // Nothing reached bob.
    _ = bob.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(bob_fds[1], &buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n);

    // The sender saw a policy-violation (so this is not a silent drop).
    // alice's session is already destroyed; only the socket end is read here.
    var abuf: [4096]u8 = undefined;
    const an = posix.read(alice_fds[1], &abuf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, abuf[0..an], "policy-violation") != null);
    try std.testing.expect(server.sessions[9] == null);
}

test "Server: G4 an oversized vCard is rejected without replacing the stored value" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var vcard_store = GenericVCardStore.init(&op_db);
    const old_vcard = "<vCard xmlns='vcard-temp'><FN>Old</FN></vCard>";
    try vcard_store.set("alice@localhost", old_vcard);

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();
    server.vcard = &vcard_store;

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, allocator);
    server.sessions[1] = session;
    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const stream_open = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    try std.testing.expectEqual(stream_open.len, try posix.write(fds[1], stream_open));
    handleReadable(&server, 1, &changes);
    try std.testing.expect(server.sessions[1] != null);
    session.stream.state = .active;
    session.stream.authenticated = true;
    session.stream.authenticated_jid = .{ .local = "alice", .domain = "localhost" };
    session.stream.bound_jid = .{ .local = "alice", .domain = "localhost", .resource = "mobile" };

    const prefix = "<iq type='set' id='v1'><vCard xmlns='vcard-temp'><FN>";
    const suffix = "</FN></vCard></iq>";
    const payload = try allocator.alloc(u8, 6000);
    defer allocator.free(payload);
    @memcpy(payload[0..prefix.len], prefix);
    @memset(payload[prefix.len..][0 .. payload.len - prefix.len - suffix.len], 'N');
    @memcpy(payload[payload.len - suffix.len ..], suffix);
    try std.testing.expectEqual(payload.len, try posix.write(fds[1], payload));
    for (0..2) |_| handleReadable(&server, 1, &changes);

    _ = session.conn.flushSend() catch {};
    var response: [8192]u8 = undefined;
    const n = posix.read(fds[1], &response) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, response[0..n], "not-acceptable") != null);

    const stored = try vcard_store.get(allocator, "alice@localhost");
    defer if (stored) |value| allocator.free(value);
    try std.testing.expectEqualStrings(old_vcard, stored.?);
}

test "Server: E6 non-whitespace between stanzas closes the stream" {
    const allocator = std.testing.allocator;
    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, allocator);
    server.sessions[1] = session;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // A stream open, then non-whitespace text before any stanza. The text is
    // terminated by the stream close so the scanner emits it as a token.
    const payload = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>GARBAGE</stream:stream>";
    _ = try posix.write(fds[1], payload);
    handleReadable(&server, 1, &changes);

    // The stream is failed closed with a not-well-formed stream error and the
    // session is gone.
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "not-well-formed") != null);
    try std.testing.expect(server.sessions[1] == null);
}

test "Server: E6 an over-long token is a policy-violation" {
    const allocator = std.testing.allocator;
    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, allocator);
    server.sessions[1] = session;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // A stream open, then an element name longer than the 512 KiB scanner cap.
    const prefix = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'><";
    const name_len = 512 * 1024 + 1;
    const data = try allocator.alloc(u8, prefix.len + name_len);
    defer allocator.free(data);
    @memcpy(data[0..prefix.len], prefix);
    @memset(data[prefix.len..], 'a');

    // Feed in chunks. handleReadable performs one recv (8 KiB) per call and
    // the socketpair is non-blocking with a 64 KiB buffer, so write less than
    // one recv's worth and parse after each, letting the scanner accumulate the
    // name across passes until it is rejected.
    var written: usize = 0;
    while (written < data.len and server.sessions[1] != null) {
        const chunk = @min(@as(usize, 4096), data.len - written);
        const n = posix.write(fds[1], data[written..][0..chunk]) catch break;
        if (n == 0) break;
        written += n;
        handleReadable(&server, 1, &changes);
    }

    // A policy-violation (not not-well-formed) closed the stream.
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "policy-violation") != null);
    try std.testing.expect(server.sessions[1] == null);
}

test "Server: S4 jid-malformed subscription escapes the stanza id" {
    const allocator = std.testing.allocator;
    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, server.server_host, false, allocator);
    server.sessions[1] = session;
    session.stream.bound_jid = xmpp.Jid.parse("alice@localhost/res") catch null;
    session.stream.authenticated_jid = session.stream.bound_jid;

    var to_buf: [600]u8 = undefined;
    @memset(&to_buf, 'a');
    @memcpy(to_buf[588..], "@example.org");
    session.stanza_to = &to_buf;
    session.stanza_id = "sess-'&<";

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    presence_handler.dispatchSubscription(&server, session, .subscribe, "", &changes);

    _ = try session.conn.flushSend();
    var buf: [2048]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    const reply = buf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, reply, "type='error'") != null);
    try std.testing.expect(std.mem.indexOf(u8, reply, "jid-malformed") != null);
    try std.testing.expect(std.mem.indexOf(u8, reply, "id='sess-&apos;&amp;&lt;'") != null);
    try std.testing.expect(std.mem.indexOf(u8, reply, "id='sess-'&<'") == null);
}
