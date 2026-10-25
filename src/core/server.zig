//! # Server — XMPP core daemon main loop
//!
//! Ties together the event loop, listener, connections, XML reader, stream FSM,
//! and SASL authentication into a working XMPP server.
//!
//! ## Event loop pattern
//!
//! Uses `ChangeList` + `submitAndPoll()` exclusively — all fd registrations,
//! removals, and modifications are batched into a single `kevent()` syscall
//! per iteration. No convenience `addFd()`/`removeFd()` calls.
//!
//! ```
//! ┌─────────────────────────────────────────────────┐
//! │              Main Event Loop                     │
//! │                                                  │
//! │  changes = ChangeList.init(&buf)                 │
//! │  changes.addRead(listener.fd, ...)   ← initial   │
//! │                                                  │
//! │  loop:                                           │
//! │    events = submitAndPoll(changes, null)          │
//! │    changes.reset()                               │
//! │                                                  │
//! │    for events:                                   │
//! │      listener readable → accept, addRead         │
//! │      conn readable    → recv, parse XML, respond │
//! │      conn writable    → flush write buffer       │
//! │      signal           → shutdown                 │
//! │                                                  │
//! │    (changes accumulate for next submitAndPoll)    │
//! └─────────────────────────────────────────────────┘
//! ```

const std = @import("std");
const posix = std.posix;
const xml = @import("xml");
const xmpp = @import("xmpp");
const sasl = @import("sasl");
const EventLoop = @import("event_loop.zig").EventLoop;
const ChangeList = @import("event_loop.zig").ChangeList;
const Connection = @import("connection.zig").Connection;
const connection_mod = @import("connection.zig");
const Listener = @import("listener.zig").Listener;
const Event = @import("event_loop.zig").Event;

const ssl = @import("ssl");
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
const generic_offline = @import("generic_offline_store");
const GenericOfflineStore = generic_offline.GenericOfflineStore;
const OfflinePointer = generic_offline.OfflinePointer;
const archive_store_mod = @import("archive_store");
const ArchiveBackendMod = @import("archive_backend");
const ArchiveBackendType = ArchiveBackendMod.Backend;
const archive_queue_mod = @import("archive_queue");
const vcard_store_mod = @import("vcard_store");
const GenericVCardStore = vcard_store_mod.VCardStore(OpBackendType);
const iq_handler = @import("iq_handler.zig");
const muc_handler = @import("muc_handler.zig");
const presence_handler = @import("presence_handler.zig");
pub const sub_cache_mod = @import("subscription_cache.zig");
pub const caps_mod = @import("caps.zig");
const router = @import("router.zig");
const session_lifecycle = @import("session_lifecycle.zig");
const room_registry_mod = @import("room_registry");
const room_mailbox_mod = @import("room_mailbox");
const RoomRegistry = room_registry_mod.RoomRegistry;
const room_store_mod = @import("room_store");
const GenericRoomStore = room_store_mod.RoomStore(OpBackendType);
const fanout_mod = @import("fanout.zig");
const FanoutQueue = fanout_mod.FanoutQueue;
const actor_message = @import("message.zig");
pub const sm_state = @import("sm_state.zig");
const sm_handoff = @import("sm_handoff.zig");
const block_store_mod = @import("block_store");
const GenericBlockStore = block_store_mod.BlockStore(OpBackendType);
const pep_store_mod = @import("pep_store");
const GenericPepStore = pep_store_mod.PepStore(OpBackendType);

const log = std.log.scoped(.xmppd);

/// Default maximum simultaneous connections (configurable via init).
pub const DEFAULT_MAX_SESSIONS: usize = 4096;

/// Sentinel value for listener fd in kqueue udata.
const LISTENER_UDATA = std.math.maxInt(usize);

/// Sentinel value for auth IPC fd in kqueue udata.
pub const IPC_AUTH_UDATA = LISTENER_UDATA - 1;

/// Sentinel value for S2S IPC fd in kqueue udata.
pub const IPC_S2S_UDATA = LISTENER_UDATA - 2;

/// Sentinel value for delivery system wake pipe fd in kqueue udata.
const WAKE_PIPE_UDATA = LISTENER_UDATA - 3;

/// Timer ident for periodic SM resume expiry sweep.
const SM_EXPIRY_TIMER_IDENT = LISTENER_UDATA - 4;

/// Timer ident for auth-IPC reconnect retries.
const AUTH_RECONNECT_TIMER_IDENT = LISTENER_UDATA - 5;

/// Timer ident for retrying offline drains stalled on a store error (S13).
const OFFLINE_RETRY_TIMER_IDENT = LISTENER_UDATA - 6;

/// Timer ident for S2S-IPC reconnect retries (S10).
const S2S_RECONNECT_TIMER_IDENT = LISTENER_UDATA - 7;

/// Interval for SM detached session expiry sweep (milliseconds).
const SM_EXPIRY_SWEEP_MS: u32 = 30_000;

/// Interval for retrying stalled offline drains (S13). Shorter than the SM
/// sweep because a held tail is user-visible latency, not a reap deadline.
const OFFLINE_RETRY_SWEEP_MS: u32 = 5_000;

/// Auth-IPC reconnect backoff (milliseconds). One-shot timer, re-armed on
/// failure — constant pacing is deliberate: the auth daemon restarts in
/// O(100ms) under the supervisor, and longer backoffs just extend the
/// no-auth window for the whole worker.
const AUTH_RECONNECT_MS: u32 = 1_000;

/// S2S-IPC reconnect backoff (milliseconds). One-shot timer, re-armed on
/// failure. Same pacing rationale as the auth link.
const S2S_RECONNECT_MS: u32 = 1_000;

/// Build the event loop's changelist, holding back the tail slots the IPC
/// reconcile needs (S10). Every loop iteration ends with that reconcile, so its
/// arm and disarm must survive a batch that event handling filled up.
fn initLoopChangeList(buf: []posix.Kevent) ChangeList {
    var changes = ChangeList.init(buf);
    changes.reserve(IPC_RECONCILE_RESERVED);
    return changes;
}

/// Maximum changelist entries per event loop iteration.
/// Must be large enough to accommodate presence broadcasts, roster pushes,
/// and SM acks across many concurrent connections without silent drops.
const CHANGE_BUF_SIZE = 1024;

/// Tail of the changelist held back for reconcileIpcWriteInterest (S10). The
/// reconcile stages at most two reconnect timers and two writes or removals,
/// one of each kind per IPC link, so four of the eight are ever spent; holding
/// that back means a batch filled by event handling can no longer cost an arm,
/// and a failed arm is what dropped the auth link. The timers are staged on
/// every exit, including the drop path, since nothing else would ever retry a
/// link dropped there. A timer that still cannot be staged leaves its pending
/// flag set for the next iteration.
/// dropIpcAuth's per-session writes stay best-effort as before, since one
/// entry per mid-SASL session cannot be bounded by a fixed tail.
const IPC_RECONCILE_RESERVED = 8;

/// Maximum XML element nesting depth allowed.
/// XMPP stanzas are shallow (stream=1, stanza=2, children=3-5 typically).
/// Anything deeper than this is either malformed or an attack (deep nesting DoS).
/// Connection is terminated with a stream error if exceeded.
const MAX_ELEMENT_DEPTH = 50;

comptime {
    // The reader's namespace stacks must outlast any depth we accept (S12).
    std.debug.assert(MAX_ELEMENT_DEPTH <= xml.max_ns_depth);
}

/// Auth IPC exchange state per connection.
const AuthState = enum {
    /// No auth exchange in progress.
    none,
    /// Sent AuthRequest to auth daemon, awaiting AuthChallenge or AuthSuccess/Failure.
    awaiting_challenge,
    /// Sent SaslResponse to auth daemon, awaiting AuthSuccess/Failure.
    awaiting_result,
};

/// Which SASL element's text content we're currently accumulating.
const SaslCollecting = enum {
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
    auth_username_buf: [256]u8 = undefined,
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
    /// than a full send buffer. A stalled drain with an empty write buffer
    /// has no EVFILT_WRITE left to wake it, so it stages one prompt retry;
    /// this bounds those retries so a persistently failing store cannot spin
    /// the event loop. Past the cap the periodic sweep owns the retry.
    offline_store_stalls: u8 = 0,
    /// T178: set when the unacked queue overflowed (oldest stanza evicted).
    /// XEP-0198 has no gap signaling, so the session must be failed —
    /// reaped by session_lifecycle.reapSmOverflow at the end of the event
    /// batch (live: resource-constraint stream error; detached: destroy).
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
        return .{
            .conn = Connection.init(fd, id),
            .reader = xml.Reader.init(allocator),
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

    fn resetSasl(self: *Session) void {
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

    /// Queue a complete outbound stanza (message/presence/iq) and count it
    /// for XEP-0198 (S15). Counting is not optional: `<a h='...'/>` maps by
    /// position, so every stanza sent outside this helper shifts the ack
    /// window and makes a later ack discard a stanza the client never saw.
    /// Nonzas (`<r/>`, `<a/>`, features, SASL elements, stream errors) must
    /// go through conn.queueSend directly.
    pub fn queueSendStanza(self: *Session, data: []const u8) !void {
        try self.conn.queueSend(data);
        self.smTrackOutbound(data);
    }

    /// Track an outbound stanza for SM purposes.
    /// Increments sm_out_seq and buffers the stanza in the unacked queue (if resume enabled).
    /// Call this after successfully queueing a complete stanza (message/presence/iq) to the client.
    /// On queue overflow the session is flagged for failure (T178) and reaped
    /// by session_lifecycle.reapSmOverflow at the end of the event batch.
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
                self.conn.queueSend("<r xmlns='urn:xmpp:sm:3'/>") catch return;
                self.sm_r_outstanding = true;
            }
        }
    }
};

/// T177: breadcrumb left when a detached session is handed off to another
/// worker. resolved hop-by-hop because the SM-ID prefix never updates.
const SmRedirect = struct {
    worker: u16,
    moved_at: i64,
};

/// Bound on redirect entries per worker; a full map evicts the oldest.
const MAX_SM_REDIRECTS: usize = 256;

/// Bound on redirect hops per request. A cycle means stale state — the
/// client gets item-not-found and full-rebinds.
const MAX_SM_REDIRECT_HOPS: u8 = 8;

/// FNV-1a hash of an SM-ID for map indexing (T127).
/// The XMPP core server.
pub const Server = struct {
    loop: EventLoop,
    listener: Listener,
    allocator: std.mem.Allocator,
    server_host: []const u8,
    running: bool = true,

    /// Process start time (epoch seconds) — XEP-0012 domain uptime answer.
    start_time: i64 = 0,

    /// Session table — indexed by session ID. Heap-allocated, size configurable.
    sessions: []?*Session = &.{},
    max_sessions: usize = DEFAULT_MAX_SESSIONS,

    /// Free-list stack for O(1) session ID allocation (T128).
    free_ids: []usize = &.{},
    free_count: usize = 0,

    /// TLS context — shared across all connections. Null if TLS is not configured.
    ssl_ctx: ?ssl.SslContext = null,

    /// Test seam (T215): when set, the next TLS upgrade fails instead of
    /// starting a handshake, which exercises the teardown that frees the
    /// session. A real `upgradeToTls` failure needs `SSL_new` to run out of
    /// memory, so no test can arrange one otherwise. Never set in production.
    fail_next_tls_upgrade: bool = false,

    /// Test seam (S13): when set, the next offline drain fails its archive
    /// read instead of fetching, which exercises the stall path that must
    /// re-arm the drain. A real archive read error needs a failing storage
    /// backend, so no test can arrange one otherwise. Never set in
    /// production.
    fail_next_offline_archive_read: bool = false,

    /// IPC client for auth daemon communication.
    ipc: IpcClient = .{},
    /// Whether EVFILT_WRITE is armed for the auth/S2S IPC fds. Reconciled
    /// once per loop iteration; see reconcileIpcWriteInterest (S10).
    ipc_write_armed: bool = false,
    /// S10: a reconnect attempt is owed for this link. Set at drop and by a
    /// failed attempt, cleared once the timer is staged. reconcileIpcWrite-
    /// Interest stages it inside its reserved tail, so a batch filled by event
    /// handling cannot cost the only thing that would ever retry the link.
    auth_reconnect_pending: bool = false,

    /// Auth daemon socket path copy (for reconnects, T243). Empty = no
    /// reconnect configured (e.g. configureAuth never ran).
    auth_ipc_path_buf: [108]u8 = undefined,
    auth_ipc_path_len: usize = 0,

    /// IPC client for S2S daemon communication (federation).
    s2s_ipc: IpcClient = .{},
    s2s_write_armed: bool = false,
    /// S10: see auth_reconnect_pending.
    s2s_reconnect_pending: bool = false,

    /// S2S daemon socket path copy (for reconnects, S10). Empty = no
    /// reconnect configured (e.g. configureS2s never ran).
    s2s_ipc_path_buf: [108]u8 = undefined,
    s2s_ipc_path_len: usize = 0,

    /// Session map — unified JID-keyed routing table (thread-safe, replaces both
    /// SessionRegistry and SharedSessionRegistry). Null before configureServer().
    session_map: ?*SessionMap = null,

    /// This worker's thread ID (0..N-1). Used for cross-thread routing decisions.
    worker_id: u16 = 0,

    /// Cross-thread delivery system (MPSC queues + wake pipes).
    /// Null in single-thread mode.
    delivery_system: ?*DeliverySystem = null,

    /// Roster store — per-user contact lists with subscription states.
    roster: ?*GenericRosterStore = null,

    /// Generic offline store — delivery pointers for unavailable recipients.
    offline: ?*GenericOfflineStore(OpBackendType) = null,

    /// Archive store — MAM message archive (stanza payloads). Read path
    /// (queries/history/offline fetch) stays inline; WRITES go through
    /// archive_writer when attached.
    archive: ?*archive_store_mod.ArchiveStore(ArchiveBackendType) = null,

    /// S18: per-worker heap scratch for session-map resolution. Replaces
    /// ~70 KiB stack frames (DEFAULT_MAX_RESOURCES SessionEntry per
    /// lookup). The event loop is single-threaded per worker: bank A
    /// serves dispatchStanza and the chunked batch lookups, bank B the
    /// leaf lookups (sendCarbons runs under dispatchStanza, so they
    /// cannot share a bank). Grown lazily to the session map's resource
    /// cap; chunk banks hold SCRATCH_CHUNK_JIDS * cap entries.
    ///
    /// A bank is handed out through `leaseScratch`, which marks it in use
    /// until released so a nested lookup on the same bank fails an assert
    /// instead of overwriting the outer iteration.
    scratch_entries_a: []SessionEntry = &.{},
    scratch_entries_b: []SessionEntry = &.{},
    scratch_entries_c: []SessionEntry = &.{},
    scratch_ids_a: []usize = &.{},
    scratch_jid_idxs_a: []u16 = &.{},
    scratch_bank_in_use: [3]bool = .{ false, false, false },

    /// S18: per-worker heap scratch for stanza serialization, replacing the
    /// 20 KiB stack buffers that held dispatchStanza, sendCarbons and
    /// broadcastToOwnResources above a 16 KiB frame. BYTE_BANK_COUNT banks of
    /// BYTE_BANK_SIZE are allocated lazily as one block and leased out, so a
    /// function nesting inside another takes a distinct bank rather than
    /// sharing the outer one's bytes. Allocated on the worker heap, not the
    /// stack: a Server value is returned by value from init, so growing the
    /// struct itself would move the cost to every caller's frame.
    byte_scratch: []u8 = &.{},
    byte_scratch_in_use: [BYTE_BANK_COUNT]bool = .{false} ** BYTE_BANK_COUNT,

    /// T87 async archive writer queue. Null in dev/single-process setups
    /// without a writer thread — writers then fall back to inline store()
    /// against `archive`.
    archive_writer: ?*archive_queue_mod.ArchiveWriteQueue = null,

    /// VCard store — per-user vCard XML blobs (XEP-0054).
    vcard: ?*GenericVCardStore = null,

    /// MUC room registry — in-memory rooms and occupants.
    room_registry: ?*RoomRegistry = null,

    /// MUC room store — persistent room configs and affiliations.
    room_store: ?*GenericRoomStore = null,

    /// Block store — per-user block lists (XEP-0191).
    block_store: ?*GenericBlockStore = null,

    /// PEP store — per-user PubSub nodes (XEP-0163).
    pep_store: ?*GenericPepStore = null,

    /// Subscription cache — avoids LMDB prefix scans on presence broadcast (T129).
    sub_cache: sub_cache_mod.SubscriptionCache = .{},

    /// XEP-0115: Entity Capabilities cache — maps client ver hash → feature bitmap.
    caps_cache: caps_mod.CapsCache = .{},

    /// XEP-0115: Server's own caps hash + pre-built <c> element.
    /// Initialized at runtime in configureServer().
    server_caps: caps_mod.ServerCaps = .{},

    /// MUC service hostname (e.g., "conference.example.com").
    muc_host: ?[]const u8 = null,

    /// Pending fan-out queue — bounded continuation for MUC groupchat delivery.
    fanout_queue: FanoutQueue = .{},

    /// Whether OIDC photo import to vCard is enabled ([oidc] import_avatar config flag).
    oidc_import_avatar: bool = false,

    /// Number of currently detached SM sessions (T124 — avoids full sweep when 0).
    detached_count: u16 = 0,

    /// Stale per-session events skipped because the session was detached or
    /// closed after kevent returned this batch (S28). Counted and logged at
    /// debug so a regression here is visible instead of silent.
    stale_event_skips: u64 = 0,

    /// SM-ID → session slot index map for O(1) resume lookup (T127, S17).
    /// AutoHashMapUnmanaged: the old fixed 64-entry open-addressing table
    /// silently failed inserts when full and broke probe chains on remove
    /// (no tombstones) — spurious item-not-found on resume.
    sm_id_map: std.AutoHashMapUnmanaged([sm_state.SM_ID_HEX_LEN]u8, usize) = .{},

    /// T177: SM-ID → worker redirects for sessions handed off to another
    /// worker by a cross-worker resume. The SM-ID prefix permanently names
    /// the worker that ISSUED the id, so a repeat resume of a relocated
    /// session would otherwise route to a worker that no longer holds it.
    /// Breadcrumbs form a chain (A→B→C) resolved hop by hop; entries expire
    /// with the SM resume window. Worker-local memory: only this worker
    /// touches its own map, always on its own event loop.
    sm_redirects: std.AutoHashMapUnmanaged([sm_state.SM_ID_HEX_LEN]u8, SmRedirect) = .{},

    /// Monotonic counter for generating unique stanza IDs (XEP-0359).
    /// Combined with worker_id to ensure uniqueness across threads.
    stanza_id_counter: u32 = 0,

    /// SASL mechanism names received from auth daemon (dynamic advertisement).
    /// Stored as slices into auth_mechanism_name_buf.
    auth_mechanisms: [8][]const u8 = .{""} ** 8,
    auth_mechanism_count: u8 = 0,
    /// Backing storage for mechanism name strings.
    auth_mechanism_name_buf: [256]u8 = undefined,

    /// Wire the backlog allocators once the Server exists (allocator field
    /// is set during init{,FromFd}).
    fn bindIpcAllocators(self: *Server) void {
        self.ipc.alloc = self.allocator;
        self.s2s_ipc.alloc = self.allocator;
    }

    /// Initialize the server.
    ///
    /// - `host` — the XMPP server hostname (e.g., "example.com")
    /// - `address` — bind address (e.g., "0.0.0.0", "127.0.0.1")
    /// - `port` — TCP port (e.g., 5222)
    /// - `allocator` — allocator for session objects
    pub fn init(
        host: []const u8,
        address: []const u8,
        port: u16,
        allocator: std.mem.Allocator,
    ) !Server {
        return initWithMaxSessions(host, address, port, allocator, DEFAULT_MAX_SESSIONS);
    }

    pub fn initWithMaxSessions(
        host: []const u8,
        address: []const u8,
        port: u16,
        allocator: std.mem.Allocator,
        max_sessions: usize,
    ) !Server {
        if (max_sessions >= delivery_queue_mod.MULTICAST_SENTINEL) {
            log.err("max_sessions ({d}) must be < MULTICAST_SENTINEL (0xFFFFFFFF)", .{max_sessions});
            return error.MaxSessionsTooLarge;
        }
        const sessions = try allocator.alloc(?*Session, max_sessions);
        @memset(sessions, null);

        // Pre-populate free-list with all valid IDs (1..max_sessions-1) in reverse order
        const free_ids = try allocator.alloc(usize, max_sessions);
        var fc: usize = 0;
        var idx: usize = max_sessions - 1;
        while (idx >= 1) : (idx -= 1) {
            free_ids[fc] = idx;
            fc += 1;
            if (idx == 1) break;
        }

        const loop = try EventLoop.init(allocator, 256);
        errdefer {
            var l = loop;
            l.deinit();
        }

        // Backlog sized for connect bursts (T32 load driver): 128 overflowed
        // the syncache at a few hundred connects/sec while the worker loop is
        // busy in serial TLS handshakes. listen(2) clamps to
        // kern.ipc.soacceptqueue either way.
        const listener = try Listener.init(address, port, false, 4096);

        var server = Server{
            .loop = loop,
            .listener = listener,
            .sessions = sessions,
            .max_sessions = max_sessions,
            .free_ids = free_ids,
            .free_count = fc,
            .allocator = allocator,
            .server_host = host,
            .start_time = std.time.timestamp(),
        };
        server.bindIpcAllocators();
        return server;
    }

    /// Initialize with a pre-bound listener fd (received from master via fd inheritance).
    /// If `skip_tls` is true, SASL is offered without requiring STARTTLS (for benchmarks/trusted networks).
    pub fn initFromFd(
        host: []const u8,
        fd: std.posix.fd_t,
        allocator: std.mem.Allocator,
        max_sessions: usize,
    ) !Server {
        return initFromFdOpts(host, fd, allocator, max_sessions, false);
    }

    pub fn initFromFdOpts(
        host: []const u8,
        fd: std.posix.fd_t,
        allocator: std.mem.Allocator,
        max_sessions: usize,
        skip_tls: bool,
    ) !Server {
        if (max_sessions >= delivery_queue_mod.MULTICAST_SENTINEL) {
            log.err("max_sessions ({d}) must be < MULTICAST_SENTINEL (0xFFFFFFFF)", .{max_sessions});
            return error.MaxSessionsTooLarge;
        }
        const sessions = try allocator.alloc(?*Session, max_sessions);
        @memset(sessions, null);

        // Pre-populate free-list with all valid IDs (1..max_sessions-1) in reverse order
        const free_ids = try allocator.alloc(usize, max_sessions);
        var fc: usize = 0;
        var idx: usize = max_sessions - 1;
        while (idx >= 1) : (idx -= 1) {
            free_ids[fc] = idx;
            fc += 1;
            if (idx == 1) break;
        }

        const loop = try EventLoop.init(allocator, 256);
        errdefer {
            var l = loop;
            l.deinit();
        }

        const listener = Listener.initFromFd(fd, skip_tls);

        var server = Server{
            .loop = loop,
            .listener = listener,
            .sessions = sessions,
            .max_sessions = max_sessions,
            .free_ids = free_ids,
            .free_count = fc,
            .allocator = allocator,
            .server_host = host,
            .start_time = std.time.timestamp(),
        };
        server.bindIpcAllocators();
        return server;
    }

    /// Connect to the auth daemon IPC socket.
    /// Must be called before `run()`. Without this, SASL auth requests
    /// will receive temporary-auth-failure. The path is retained: when the
    /// daemon dies mid-run the worker reconnects on a 1 s one-shot timer
    /// instead of failing all authentication forever (T243).
    pub fn configureAuth(self: *Server, socket_path: []const u8) !void {
        if (socket_path.len > self.auth_ipc_path_buf.len) return error.PathTooLong;
        @memcpy(self.auth_ipc_path_buf[0..socket_path.len], socket_path);
        self.auth_ipc_path_len = socket_path.len;
        self.ipc.connect(socket_path) catch |err| {
            log.err("failed to connect to auth daemon at {s}: {}", .{ socket_path, err });
            return error.AuthConfigFailed;
        };
        log.info("connected to auth daemon at {s}", .{socket_path});
    }

    fn authIpcPath(self: *const Server) ?[]const u8 {
        if (self.auth_ipc_path_len == 0) return null;
        return self.auth_ipc_path_buf[0..self.auth_ipc_path_len];
    }

    /// S10: record that a reconnect attempt is owed. The timer itself is
    /// staged by reconcileIpcWriteInterest out of its reserved tail, so a
    /// changelist filled by event handling cannot drop the only thing that
    /// would ever retry the link.
    fn armAuthReconnect(self: *Server) void {
        self.auth_reconnect_pending = true;
    }

    /// Auth-IPC link died (EOF, reset, or churn-failure receipt): drop it,
    /// fail every session mid-SASL with a retryable error, purge the fd's
    /// staged changes, and start the reconnect timer.
    fn dropIpcAuth(self: *Server, changes: *ChangeList) void {
        // NB: IpcClient.recv()/flush() clear .connected themselves before
        // returning the error, so keyed on connected we'd never act — and
        // the unclosed fd's EOF knote would spin the loop (measured:
        // ~860k log lines/min). Guard on "we still hold a link" instead.
        if (self.ipc.fd < 0) return;
        const old_fd = self.ipc.fd;
        log.warn("auth daemon IPC lost (fd={d}) — failing in-flight SASL, reconnect armed in {d}ms", .{ old_fd, AUTH_RECONNECT_MS });
        self.ipc.close();
        self.ipc_write_armed = false;
        changes.purgeFd(old_fd);
        // Sessions parked mid-exchange would hang forever without a reply.
        for (self.sessions) |maybe| {
            const session = maybe orelse continue;
            if (session.auth_state == .none) continue;
            session.auth_state = .none;
            session.sasl_collecting = .none;
            self.executeAction(session, session.stream.saslFailure("temporary-auth-failure"), changes);
            if (session.conn.hasPendingWrite()) {
                changes.addWrite(session.conn.fd, session.conn.id) catch {};
            }
        }
        // The mechanism list is re-sent by the daemon on connect; don't
        // advertise a dead daemon's set meanwhile.
        self.auth_mechanism_count = 0;
        self.armAuthReconnect();
    }

    fn tryAuthReconnect(self: *Server, changes: *ChangeList) void {
        if (self.ipc.connected) return;
        const path = self.authIpcPath() orelse return;
        self.ipc.connect(path) catch |err| {
            log.warn("auth daemon reconnect failed: {}, retrying in {d}ms", .{ err, AUTH_RECONNECT_MS });
            self.armAuthReconnect();
            return;
        };
        // Read interest is what drives the handshake reply; without it a
        // connected link never delivers anything and the retry timer is gone,
        // so the failure is invisible and permanent. Treat it as a failed
        // connect: drop the link and owe another attempt (S10).
        changes.addRead(self.ipc.fd, IPC_AUTH_UDATA) catch |err| {
            log.warn("auth daemon reconnect read arm failed ({}), retrying in {d}ms", .{ err, AUTH_RECONNECT_MS });
            const dead_fd = self.ipc.fd;
            self.ipc.close();
            self.ipc_write_armed = false;
            changes.purgeFd(dead_fd);
            self.armAuthReconnect();
            return;
        };
        log.info("auth daemon IPC reconnected ({s})", .{path});
        // Write interest: reconcileIpcWriteInterest (S10).
    }

    fn s2sIpcPath(self: *const Server) ?[]const u8 {
        if (self.s2s_ipc_path_len == 0) return null;
        return self.s2s_ipc_path_buf[0..self.s2s_ipc_path_len];
    }

    /// S10: see armAuthReconnect.
    fn armS2sReconnect(self: *Server) void {
        self.s2s_reconnect_pending = true;
    }

    fn tryS2sReconnect(self: *Server, changes: *ChangeList) void {
        if (self.s2s_ipc.connected) return;
        const path = self.s2sIpcPath() orelse return;
        self.s2s_ipc.connect(path) catch |err| {
            log.warn("S2S daemon reconnect failed: {}, retrying in {d}ms", .{ err, S2S_RECONNECT_MS });
            self.armS2sReconnect();
            return;
        };
        // See tryAuthReconnect: an unarmed link is a dead one, and the retry
        // timer that would have noticed it is already spent (S10).
        changes.addRead(self.s2s_ipc.fd, IPC_S2S_UDATA) catch |err| {
            log.warn("S2S daemon reconnect read arm failed ({}), retrying in {d}ms", .{ err, S2S_RECONNECT_MS });
            const dead_fd = self.s2s_ipc.fd;
            self.s2s_ipc.close();
            self.s2s_write_armed = false;
            changes.purgeFd(dead_fd);
            self.armS2sReconnect();
            return;
        };
        log.info("S2S daemon IPC reconnected ({s})", .{path});
        // Write interest: reconcileIpcWriteInterest (S10).
    }

    /// S2S-IPC link died (recv error, undecodable frame, flush error, or a
    /// kqueue error event): close it, purge the fd's staged changes, and arm
    /// a reconnect. Without the retry a daemon restart leaves federation dead
    /// for this worker's whole lifetime (S10).
    fn dropS2sIpc(self: *Server, changes: *ChangeList) void {
        // IpcClient.recv()/flush() clear .connected before returning, so this
        // is keyed on holding a link, not on .connected (see dropIpcAuth).
        if (self.s2s_ipc.fd < 0) return;
        const dead_fd = self.s2s_ipc.fd;
        log.warn("S2S daemon IPC lost (fd={d}), reconnect armed in {d}ms", .{ dead_fd, S2S_RECONNECT_MS });
        self.s2s_ipc.close();
        self.s2s_write_armed = false;
        changes.purgeFd(dead_fd);
        self.armS2sReconnect();
    }

    /// Configure the roster store (generic backend-backed).
    pub fn configureRoster(self: *Server, roster_store: *GenericRosterStore) void {
        self.roster = roster_store;
        log.info("roster store configured", .{});
    }

    /// Connect to the S2S federation daemon IPC socket.
    /// Optional: without this, stanzas to remote domains are bounced. The
    /// path is retained so a daemon that dies mid-run is reconnected on a
    /// one-shot timer instead of leaving federation dead for the worker's
    /// whole lifetime (S10).
    pub fn configureS2s(self: *Server, socket_path: []const u8) !void {
        if (socket_path.len > self.s2s_ipc_path_buf.len) return error.PathTooLong;
        @memcpy(self.s2s_ipc_path_buf[0..socket_path.len], socket_path);
        self.s2s_ipc_path_len = socket_path.len;
        self.s2s_ipc.connect(socket_path) catch |err| {
            log.err("failed to connect to S2S daemon at {s}: {}", .{ socket_path, err });
            return error.S2sConfigFailed;
        };
        log.info("connected to S2S daemon at {s}", .{socket_path});
    }

    /// Configure the offline + archive stores.
    pub fn configureOffline(self: *Server, offline_store: *GenericOfflineStore(OpBackendType), arch_store: *archive_store_mod.ArchiveStore(ArchiveBackendType)) void {
        self.offline = offline_store;
        self.archive = arch_store;
        log.info("offline + archive stores configured", .{});
    }

    /// Attach the shared T87 archive writer queue.
    pub fn configureArchiveWriter(self: *Server, queue: *archive_queue_mod.ArchiveWriteQueue) void {
        self.archive_writer = queue;
    }

    /// T87: archive a stanza. Enqueues onto the writer thread's queue when
    /// wired (never blocks the event loop on storage); otherwise falls back
    /// to an inline store() (unchanged legacy behavior).
    pub fn archiveStore(self: *Server, owner: []const u8, with: []const u8, stanza_id: []const u8, timestamp: u64, stanza_xml: []const u8) void {
        if (self.archive_writer) |q| {
            q.enqueue(owner, with, stanza_id, timestamp, stanza_xml);
            return;
        }
        if (self.archive) |archive| {
            archive.store(owner, with, stanza_id, timestamp, stanza_xml) catch |err| {
                log.warn("archive store failed for {s}: {s}", .{ owner, @errorName(err) });
            };
        }
    }

    /// Park a message behind a session's draining offline tail. The held bytes
    /// are authoritative; archive metadata is retained only for fallback reads.
    pub fn holdBehindOfflineTail(
        self: *Server,
        target: *Session,
        local: []const u8,
        domain: []const u8,
        from_jid: []const u8,
        stanza_id: []const u8,
        timestamp: u64,
        stanza_xml: []const u8,
    ) bool {
        if (!target.offline_pending) return false;
        const store = self.offline orelse return false;
        var recipient_buf: [router.BARE_JID_MAX]u8 = undefined;
        const recipient = router.buildBareJid(local, domain, &recipient_buf) catch return false;
        return store.storeHeldPointer(recipient, from_jid, stanza_id, timestamp, stanza_xml) catch |err| {
            log.warn("message to {s} could not be held behind the offline tail: {s}", .{ recipient, @errorName(err) });
            return false;
        };
    }

    /// Configure the vCard store (XEP-0054).
    pub fn configureVcard(self: *Server, vcard_store: *GenericVCardStore) void {
        self.vcard = vcard_store;
        log.info("vcard store configured", .{});
    }

    /// Configure the block store (XEP-0191: Blocking Command).
    pub fn configureBlockStore(self: *Server, bs: *GenericBlockStore) void {
        self.block_store = bs;
        log.info("block store configured", .{});
    }

    /// Configure the PEP store (XEP-0163: Personal Eventing Protocol).
    pub fn configurePepStore(self: *Server, ps: *GenericPepStore) void {
        self.pep_store = ps;
        log.info("PEP store configured", .{});
    }

    /// Configure TLS with a certificate and key file.
    /// Must be called before `run()`. Without this, STARTTLS is advertised
    /// but upgrade requests fail.
    pub fn configureTls(self: *Server, cert_path: [*:0]const u8, key_path: [*:0]const u8) !void {
        self.ssl_ctx = ssl.SslContext.initServer(cert_path, key_path) catch {
            return error.TlsConfigFailed;
        };
    }

    pub fn deinit(self: *Server) void {
        // Close all sessions
        for (self.sessions) |session_opt| {
            if (session_opt) |session| {
                session.deinit();
                self.allocator.destroy(session);
            }
        }
        self.allocator.free(self.sessions);
        if (self.free_ids.len > 0) self.allocator.free(self.free_ids);
        if (self.scratch_entries_a.len > 0) self.allocator.free(self.scratch_entries_a);
        if (self.scratch_entries_b.len > 0) self.allocator.free(self.scratch_entries_b);
        if (self.scratch_entries_c.len > 0) self.allocator.free(self.scratch_entries_c);
        if (self.scratch_ids_a.len > 0) self.allocator.free(self.scratch_ids_a);
        if (self.scratch_jid_idxs_a.len > 0) self.allocator.free(self.scratch_jid_idxs_a);
        if (self.byte_scratch.len > 0) self.allocator.free(self.byte_scratch);
        self.sm_id_map.deinit(self.allocator);
        self.sm_redirects.deinit(self.allocator);
        self.listener.deinit();
        self.loop.deinit();
        if (self.ssl_ctx) |*ctx| ctx.deinit();
        if (self.ipc.connected) self.ipc.close();
        if (self.s2s_ipc.connected) self.s2s_ipc.close();
        self.ipc.deinit();
        self.s2s_ipc.deinit();
    }

    /// Presence batching resolves this many bare JIDs per lock hold.
    pub const SCRATCH_CHUNK_JIDS = 32;

    /// One stanza-serialization bank. Sized to the largest stanza buffer in
    /// the tree: the 16384-byte accumulation limit plus room for the attributes
    /// added on the way out.
    pub const BYTE_BANK_SIZE: usize = 20480;

    /// Byte banks cover the deepest live nesting of stanza serialization,
    /// which is sendPepNotification: its shared suffix stays live across the
    /// subscriber list, and each delivery builds one notification on top of
    /// both. Nesting deeper than the pool takes a heap allocation instead of
    /// dropping the stanza.
    pub const BYTE_BANK_COUNT: usize = 3;

    /// Scratch banks are layered by nesting depth so that a lookup made
    /// inside another lookup's iteration cannot overwrite the outer results.
    pub const ScratchBank = enum(u8) {
        /// Stanza routing and the chunked batch lookups.
        a = 0,
        /// Handler-level lookups, nested under bank A.
        b = 1,
        /// Leaf delivery lookups, nested under bank B.
        c = 2,
    };

    /// An in-use claim on one scratch bank. Release with `release`, normally
    /// through `defer`, before the entries slice is allowed to go stale. Do
    /// not copy a lease after acquisition; only its owner may release it.
    pub const ScratchLease = struct {
        server: *Server,
        bank: ScratchBank,
        active: bool = true,
        entries: []SessionEntry,

        pub fn release(self: *ScratchLease) void {
            if (!self.active) return;
            self.active = false;
            self.server.scratch_bank_in_use[@intFromEnum(self.bank)] = false;
            self.entries = &.{};
        }
    };

    /// Claim a scratch bank and return its entries. Safe builds assert when
    /// the bank is already claimed, which is the S18 aliasing bug: the inner
    /// lookup would overwrite the slice the outer loop is iterating.
    pub fn leaseScratch(self: *Server, bank: ScratchBank) ScratchLease {
        self.growScratch(bank);
        const idx = @intFromEnum(bank);
        std.debug.assert(!self.scratch_bank_in_use[idx]);
        self.scratch_bank_in_use[idx] = true;
        return .{
            .server = self,
            .bank = bank,
            .entries = switch (bank) {
                .a => self.scratch_entries_a,
                .b => self.scratch_entries_b,
                .c => self.scratch_entries_c,
            },
        };
    }

    pub fn scratchIdsA(self: *Server) []usize {
        self.growScratch(.a);
        return self.scratch_ids_a;
    }

    pub fn scratchJidIdxsA(self: *Server) []u16 {
        self.growScratch(.a);
        return self.scratch_jid_idxs_a;
    }

    /// Grow only the arrays belonging to `bank`. Growing every bank here would
    /// free and re-allocate the buffers behind an already-handed-out lease.
    fn growScratch(self: *Server, bank: ScratchBank) void {
        const sm = self.session_map orelse return;
        const need: usize = switch (bank) {
            .a => SCRATCH_CHUNK_JIDS * sm.max_resources,
            .b, .c => sm.max_resources,
        };

        if (bank == .a) {
            if (self.scratch_ids_a.len < need) {
                if (self.scratch_ids_a.len > 0) self.allocator.free(self.scratch_ids_a);
                self.scratch_ids_a = self.allocator.alloc(usize, need) catch {
                    log.err("session-map scratch ids alloc of {d} entries failed", .{need});
                    self.scratch_ids_a = &.{};
                    return;
                };
            }
            if (self.scratch_jid_idxs_a.len < need) {
                if (self.scratch_jid_idxs_a.len > 0) self.allocator.free(self.scratch_jid_idxs_a);
                self.scratch_jid_idxs_a = self.allocator.alloc(u16, need) catch {
                    log.err("session-map scratch jid idxs alloc of {d} entries failed", .{need});
                    self.scratch_jid_idxs_a = &.{};
                    return;
                };
            }
        }

        const target: *[]SessionEntry = switch (bank) {
            .a => &self.scratch_entries_a,
            .b => &self.scratch_entries_b,
            .c => &self.scratch_entries_c,
        };
        const label: []const u8 = switch (bank) {
            .a => "A",
            .b => "B",
            .c => "C",
        };
        if (target.len >= need) return;
        if (target.len > 0) self.allocator.free(target.*);
        const grown = self.allocator.alloc(SessionEntry, need) catch {
            log.err("session-map scratch {s} alloc of {d} entries failed", .{ label, need });
            target.* = &.{};
            return;
        };
        target.* = grown;
    }

    /// An in-use claim on one byte-scratch bank. Release with `release`,
    /// normally through `defer`, before the buffer slice is allowed to go
    /// stale. Releasing twice is a no-op, so a lease can be given back early
    /// without also having to drop the `defer`. Do not copy a lease after
    /// acquisition; only its owner may release it.
    pub const ByteLease = struct {
        server: *Server,
        bank: usize = 0,
        /// Set when the buffer is heap-allocated rather than pooled.
        owned: bool = false,
        active: bool = true,
        buf: []u8,

        pub fn release(self: *ByteLease) void {
            if (!self.active) return;
            self.active = false;
            if (self.owned) {
                self.server.allocator.free(self.buf);
            } else {
                self.server.byte_scratch_in_use[self.bank] = false;
            }
            self.buf = &.{};
        }
    };

    /// Claim a byte-scratch buffer and return it. Banks come from a pool so a
    /// serializer running inside another one's live buffer takes a different
    /// bank and cannot overwrite the outer stanza.
    ///
    /// When every bank is already out, the buffer is allocated instead, so a
    /// deeper-than-expected call chain costs an allocation rather than dropping
    /// the stanza. Returns null only if that allocation failed; callers then
    /// drop the stanza, which is the same fail-closed behavior a fixed stack
    /// buffer had when the stanza did not fit.
    pub fn leaseByteScratch(self: *Server) ?ByteLease {
        self.growByteScratch();
        for (0..BYTE_BANK_COUNT) |bank| {
            if (self.byte_scratch_in_use[bank]) continue;
            const start = bank * BYTE_BANK_SIZE;
            const end = start + BYTE_BANK_SIZE;
            if (self.byte_scratch.len < end) break;
            self.byte_scratch_in_use[bank] = true;
            return .{ .server = self, .bank = bank, .buf = self.byte_scratch[start..end] };
        }
        const buf = self.allocator.alloc(u8, BYTE_BANK_SIZE) catch {
            log.err("byte scratch fallback allocation of {d} bytes failed", .{BYTE_BANK_SIZE});
            return null;
        };
        return .{ .server = self, .bank = 0, .owned = true, .buf = buf };
    }

    /// Allocate the byte-scratch block, backing every bank with one
    /// allocation. Runs at most once per Server: no bank can be leased before
    /// the block exists, so the allocation never moves a buffer that is
    /// currently leased out.
    fn growByteScratch(self: *Server) void {
        if (self.byte_scratch.len > 0) return;
        const total = BYTE_BANK_COUNT * BYTE_BANK_SIZE;
        self.byte_scratch = self.allocator.alloc(u8, total) catch {
            log.warn("byte scratch pool alloc of {d} bytes failed; using heap fallback", .{total});
            return;
        };
    }

    /// Run the main event loop. Blocks until SIGTERM or `stop()` is called.
    pub fn run(self: *Server) !void {
        var change_buf: [CHANGE_BUF_SIZE]posix.Kevent = undefined;
        var changes = initLoopChangeList(&change_buf);

        // Initial registration: listener for read
        try changes.addRead(self.listener.fd, LISTENER_UDATA);

        // Register auth IPC fd for reads if connected
        if (self.ipc.connected and self.ipc.fd >= 0) {
            try changes.addRead(self.ipc.fd, IPC_AUTH_UDATA);
        }

        // Register S2S IPC fd for reads if connected
        if (self.s2s_ipc.connected and self.s2s_ipc.fd >= 0) {
            try changes.addRead(self.s2s_ipc.fd, IPC_S2S_UDATA);
        }

        // Register delivery system wake pipe for reads (cross-thread wakeup)
        if (self.delivery_system) |ds| {
            try changes.addRead(ds.getPipeReadFd(self.worker_id), WAKE_PIPE_UDATA);
        }

        // Register periodic timer for SM resume expiry sweep
        try changes.addTimer(SM_EXPIRY_TIMER_IDENT, SM_EXPIRY_SWEEP_MS, false);

        // Register periodic retry for offline drains stalled on a store error
        try changes.addTimer(OFFLINE_RETRY_TIMER_IDENT, OFFLINE_RETRY_SWEEP_MS, false);

        // Auth daemon not connected at boot (standalone run or it crashed
        // before we came up): owe a reconnect attempt (T243).
        if (!self.ipc.connected and self.authIpcPath() != null) {
            self.armAuthReconnect();
        }

        // Same for federation: configured but down at boot means retry, not
        // a permanent no-S2S worker (S10).
        if (!self.s2s_ipc.connected and self.s2sIpcPath() != null) {
            self.armS2sReconnect();
        }

        // Start owed reconnect deadlines before the first wait rather than
        // delaying them until after the first unrelated event.
        self.reconcileIpcWriteInterest(&changes);

        while (self.running) {
            // Mark active before processing events (coalesced signaling)
            if (self.delivery_system) |ds| {
                ds.getState(self.worker_id).setActive();
            }

            // T238 proof obligation (safe builds): nothing staged may
            // reference an fd purged by a same-iteration close.
            changes.assertNoPurgedEntries();
            const events = try self.loop.submitAndPoll(changes.slice(), null);
            changes.reset();

            // Process MPSC wake pipe first (if in event batch) to deliver cross-thread
            // messages before any session-closing events in the same batch.
            for (events) |ev| {
                switch (ev) {
                    .fd_readable => |e| {
                        if (e.udata == WAKE_PIPE_UDATA) {
                            self.handleDeliveryWake(&changes);
                        }
                    },
                    else => {},
                }
            }

            self.dispatchEvents(events, &changes);

            // Drain pending fan-outs (bounded continuation — one batch per slot per tick)
            if (self.fanout_queue.hasPending()) {
                for (&self.fanout_queue.slots) |*slot| {
                    if (slot.active) {
                        _ = muc_handler.drainPendingFanout(self, slot, &changes);
                    }
                }
            }

            // Double-check pattern: mark idle, then re-check for pending deliveries.
            // Prevents lost wakeup when a producer enqueues between our last drain
            // and entering kevent() wait.
            if (self.delivery_system) |ds| {
                ds.getState(self.worker_id).setIdle();
                if (ds.getQueue(self.worker_id).hasPending()) {
                    self.drainDeliveryQueue(&changes);
                    _ = self.drainRoomMailboxes(&changes);
                    // Self-wake only for MPSC queue CAS race (producer reserved
                    // slot but hasn't stored ready=true yet). Room mailboxes
                    // don't need self-wake — they only grow from MPSC deliveries
                    // which have their own pipe-based wakeup.
                    if (ds.getQueue(self.worker_id).hasPending()) {
                        ds.pipes[self.worker_id].wake();
                    }
                } else {
                    // No MPSC pending, but drain room mailboxes opportunistically
                    _ = self.drainRoomMailboxes(&changes);
                }
            }

            // T178: fail sessions whose SM unacked queue overflowed during
            // this batch (any delivery path may have set the flag).
            session_lifecycle.reapSmOverflow(self, &changes);

            // S10: single point of truth for IPC write interest; heals
            // any re-arm lost while handling this batch.
            self.reconcileIpcWriteInterest(&changes);
        }
    }

    /// Stop the server (callable from signal handler or test).
    pub fn stop(self: *Server) void {
        self.running = false;
    }

    // ========================================================================
    // Accept
    // ========================================================================

    // ========================================================================
    // Read handler — XML parsing → stream FSM → response
    // ========================================================================

    // ========================================================================
    // TLS handshake dispatch
    // ========================================================================

    fn handleReadableOrHandshake(self: *Server, id: usize, changes: *ChangeList) void {
        const session = self.sessions[id] orelse return;
        if (session.conn.isTlsHandshaking()) {
            self.continueTlsHandshake(id, session, changes);
            return;
        }
        self.handleReadable(id, changes);
    }

    fn handleWritableOrHandshake(self: *Server, id: usize, changes: *ChangeList) void {
        const session = self.sessions[id] orelse return;
        if (session.conn.isTlsHandshaking()) {
            self.continueTlsHandshake(id, session, changes);
            return;
        }
        self.handleWritable(id, changes);
    }

    /// Route one batch of kqueue events to their handlers. The wake pipe is
    /// drained before this, in a separate pass, so cross-thread deliveries
    /// land ahead of any session-closing event in the same batch.
    fn dispatchEvents(self: *Server, events: []const Event, changes: *ChangeList) void {
        for (events) |ev| {
            switch (ev) {
                .fd_readable => |e| {
                    if (e.udata == LISTENER_UDATA) {
                        session_lifecycle.acceptConnections(self, changes);
                    } else if (e.udata == IPC_AUTH_UDATA) {
                        self.handleIpcReadable(changes);
                    } else if (e.udata == IPC_S2S_UDATA) {
                        self.handleS2sIpcReadable(changes);
                    } else if (e.udata == WAKE_PIPE_UDATA) {
                        // Already handled in the first pass
                    } else {
                        self.handleReadableOrHandshake(e.udata, changes);
                    }
                },
                .fd_writable => |e| {
                    if (e.udata == IPC_AUTH_UDATA) {
                        self.flushIpc(changes);
                    } else if (e.udata == IPC_S2S_UDATA) {
                        self.flushS2sIpc(changes);
                    } else {
                        self.handleWritableOrHandshake(e.udata, changes);
                    }
                },
                .signal => |s| {
                    if (s.signo == posix.SIG.TERM or s.signo == posix.SIG.INT) {
                        self.running = false;
                    }
                },
                .timer => |t| {
                    if (t.ident == SM_EXPIRY_TIMER_IDENT) {
                        session_lifecycle.expireDetachedSessions(self, changes);
                    } else if (t.ident == OFFLINE_RETRY_TIMER_IDENT) {
                        session_lifecycle.retryStalledOfflineDrains(self, changes);
                    } else if (t.ident == AUTH_RECONNECT_TIMER_IDENT) {
                        self.tryAuthReconnect(changes);
                    } else if (t.ident == S2S_RECONNECT_TIMER_IDENT) {
                        self.tryS2sReconnect(changes);
                    }
                },
                .fd_error => |e| {
                    if (e.udata == IPC_AUTH_UDATA) {
                        self.dropIpcAuth(changes);
                    } else if (e.udata == IPC_S2S_UDATA) {
                        self.dropS2sIpc(changes);
                    } else if (e.udata != LISTENER_UDATA and e.udata != WAKE_PIPE_UDATA) {
                        self.handleSessionError(e.udata, changes);
                    }
                },
                else => {},
            }
        }
    }

    /// True when a session's fd is gone but the session still exists: it was
    /// detached for SM resume, or closed, after kevent returned this batch.
    /// Such an event is stale; acting on it drives flushSend/recv against fd
    /// -1, and the resulting error used to destroy a resumable session (S28).
    fn isStaleSessionEvent(session: *Session) bool {
        return session.sm_detached or session.conn.isClosed();
    }

    /// kqueue reported an error on a session fd (EV_ERROR / EV_EOF with an
    /// error). Detached or already-closed sessions are skipped for the same
    /// reason as a stale readable/writable event (S28).
    fn handleSessionError(self: *Server, id: usize, changes: *ChangeList) void {
        if (id >= self.sessions.len) return;
        const session = self.sessions[id] orelse return;
        if (isStaleSessionEvent(session)) {
            self.stale_event_skips += 1;
            log.debug("connection {d} stale error event on a detached or closed session, skipped", .{id});
            return;
        }
        session_lifecycle.closeSession(self, id, changes);
    }

    fn continueTlsHandshake(self: *Server, id: usize, session: *Session, changes: *ChangeList) void {
        const complete = session.conn.continueHandshake() catch {
            log.err("connection {d} TLS handshake failed", .{id});
            session_lifecycle.closeSession(self, id, changes);
            return;
        };

        if (complete) {
            log.info("connection {d} TLS handshake complete", .{id});
            // AGENTS.md: kTLS engagement and cipher must be logged after
            // every handshake; userland fallback is otherwise silent.
            if (session.conn.tls_conn) |*tls| {
                log.info("connection {d} tls: {s} cipher={s} ktls tx={} rx={}", .{
                    id, tls.versionName(), tls.cipherName(), tls.ktlsSend(), tls.ktlsRecv(),
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
                self.handleReadable(id, changes);
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

    // ========================================================================
    // Read handler — XML parsing → stream FSM → response
    // ========================================================================

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
    fn handleReadable(self: *Server, id: usize, changes: *ChangeList) void {
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
                session.conn.tls_conn == null and
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
                self.sendStreamError(session, .policy_violation);
                session.conn.flushSync();
                session_lifecycle.forceCloseSession(self, id, changes);
                return;
            }

            var pos: usize = 0;

            while (true) {
                const event = session.reader.next(data, &pos) catch |err| {
                    // Client-side protocol violation, not a server fault.
                    log.warn("connection {d} XML parse error: {}", .{ id, err });
                    // Resource limits are policy violations, not malformed XML.
                    self.sendStreamError(session, if (err == error.TokenTooLong or
                        err == error.ItemTooLong or
                        err == error.TooManyAttributes)
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
                    self.sendStreamError(session, .policy_violation);
                    session_lifecycle.forceCloseSession(self, id, changes);
                    return;
                }

                const starttls_was_pending = session.stream.state == .starttls_pending;
                self.processXmlEvent(session, event.?, changes);

                if (self.sessions[id] == null) return;
                // T215: anything past the complete <starttls/> element is
                // plaintext read-ahead — a protocol violation (RFC 6120
                // 5.4.3.2).
                if (!starttls_was_pending and
                    session.stream.state == .starttls_pending and
                    pos < data.len)
                {
                    log.info("connection {d} plaintext read-ahead past <starttls/> — policy-violation", .{id});
                    self.sendStreamError(session, .policy_violation);
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

    // ========================================================================
    // XML event → Stream FSM dispatch
    // ========================================================================

    fn processXmlEvent(self: *Server, session: *Session, event: xml.Event, changes: *ChangeList) void {
        switch (event) {
            .xml_declaration => {
                // Expected at stream start, no action needed
            },
            .stream_open => |elem| {
                self.handleStreamOpen(session, elem, changes);
            },
            .stream_close => {
                _ = session.stream.handleClose();
                self.sendRaw(session, "</stream:stream>");
                // Flush the closing tag before teardown so the peer receives it.
                if (session.conn.hasPendingWrite()) {
                    session.conn.flushSync();
                }
                session_lifecycle.forceCloseSession(self, session.conn.id, changes);
            },
            .element_start => |elem| {
                self.handleElementStart(session, elem, changes);
            },
            .element_end => |name| {
                self.handleElementEnd(session, name, changes);
            },
            .text => |text| {
                self.handleText(session, text);
            },
        }
    }

    fn handleStreamOpen(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
        // Extract 'to' attribute
        var to: []const u8 = "";
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "to")) {
                to = attr.value;
                break;
            }
        }

        const action = session.stream.handleStreamOpen(to, "1.0");
        self.executeAction(session, action, changes);
    }

    /// Verdict of enforcePreBindStanzaPolicy (T182).
    const PreBindVerdict = enum {
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
    fn enforcePreBindStanzaPolicy(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) PreBindVerdict {
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
        var server_addressed = to_attr.len == 0 or std.mem.eql(u8, to_attr, self.server_host);
        if (!server_addressed) {
            if (session.stream.authenticated_jid) |aj| {
                var acc_buf: [256]u8 = undefined;
                var acc_fbs = std.io.fixedBufferStream(&acc_buf);
                const aw = acc_fbs.writer();
                aw.writeAll(aj.local) catch {};
                aw.writeByte('@') catch {};
                aw.writeAll(aj.domain) catch {};
                const account = acc_fbs.getWritten();
                const to_bare = if (std.mem.indexOfScalar(u8, to_attr, '/')) |sp| to_attr[0..sp] else to_attr;
                server_addressed = std.mem.eql(u8, to_bare, account);
            }
        }
        if (server_addressed) return .server_addressed;

        log.info("connection {d} {s} to a third party before resource binding — closing stream (not-authorized)", .{ session.conn.id, elem.local_name });
        // writeStreamError includes the closing </stream:stream> tag.
        self.sendStreamError(session, .not_authorized);
        // Flush the error and closing tag before teardown so the client sees them.
        session.conn.flushSync();
        session_lifecycle.forceCloseSession(self, session.conn.id, changes);
        return .third_party_closed;
    }

    /// Answer a pre-bind stanza addressed to the server/own account with a
    /// not-authorized stanza error (T182). Stanza error, not stream error —
    /// the connection stays open so the client can proceed to bind. Error
    /// stanzas are never answered with further errors (RFC 6120 §8.3.1).
    fn sendPreBindStanzaError(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
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
        w.writeByte('<') catch return;
        w.writeAll(tag_name) catch return;
        w.writeAll(" type='error'") catch return;
        if (to_attr.len > 0) {
            w.writeAll(" from='") catch return;
            xml.escapeWrite(w, to_attr) catch return;
            w.writeByte('\'') catch return;
        }
        if (id_attr.len > 0) {
            w.writeAll(" id='") catch return;
            xml.escapeWrite(w, id_attr) catch return;
            w.writeByte('\'') catch return;
        }
        w.writeAll("><error type='auth'><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></") catch return;
        w.writeAll(tag_name) catch return;
        w.writeByte('>') catch return;
        session.queueSendStanza(fbs.getWritten()) catch return;
        if (session.conn.hasPendingWrite()) {
            changes.addWrite(session.conn.fd, session.conn.id) catch {};
        }
    }

    fn handleElementStart(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
        // If accumulating a message/presence stanza, serialize child elements into buffer
        if (session.stanza_kind != .none) {
            // Detect <priority> child inside presence stanza for RFC 6121 §4.7.2.3
            if (session.stanza_kind == .presence and std.mem.eql(u8, elem.local_name, "priority")) {
                session.pres_priority_collecting = true;
                session.pres_priority_len = 0;
            }
            self.accumulateStanzaElement(session, elem);
            return;
        }

        const ns = elem.namespace_uri;

        // STARTTLS namespace
        if (std.mem.eql(u8, ns, xml.ns.tls)) {
            if (std.mem.eql(u8, elem.local_name, "starttls")) {
                if (elem.self_closing) {
                    const action = session.stream.handleStarttls();
                    self.executeAction(session, action, changes);
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
                self.handleSaslAuth(session, elem, changes);
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
                if (self.enforcePreBindStanzaPolicy(session, elem, changes) == .third_party_closed) return;
                // Start IQ accumulation for registration
                iq_handler.handleIq(session, elem, self.server_host);
                return;
            }
            // IQ child elements during pre-auth registration
            if (session.iq_active) {
                if (session.vcard_collecting) {
                    self.accumulateVcardElement(session, elem);
                    return;
                }
                self.handleIqChild(session, elem);
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
                self.handleSmResume(session, elem, changes);
            }
            return;
        }

        // Pre-bind IQ wrapper — capture the IQ id for the bind result
        if (!session.stream.isActive() and session.stream.state == .features_bind) {
            // RFC 6120 §7.1 (T182): a stanza addressed to a third party
            // before resource binding is not processed — the stream closes
            // with a not-authorized stream error. The bind wrapper IQ itself
            // is server-addressed and continues below.
            switch (self.enforcePreBindStanzaPolicy(session, elem, changes)) {
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
                            self.sendStreamError(session, .policy_violation);
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
                self.sendPreBindStanzaError(session, elem, changes);
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
                    self.handleSmEnable(session, elem, changes);
                } else {
                    // XEP-0198 §3.1: SM enable before resource bind — reject
                    self.sendSmFailed(session, "unexpected-request", changes);
                }
            } else if (std.mem.eql(u8, elem.local_name, "r") and session.sm_enabled) {
                self.handleSmRequest(session, changes);
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
                            self.sendSmHandledCountError(session, null, changes);
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
                                self.sendSmHandledCountError(session, client_h, changes);
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
                self.handleSmResume(session, elem, changes);
            }
            return;
        }

        // RFC 6120 §7.1 (T182): stanzas received before authentication are not
        // processed. Third-party-addressed message/IQ close the stream with a
        // not-authorized stream error; server/account-addressed ones get a
        // stanza error instead (IQs are answered via dispatchIq's pre-bind
        // gate); presence stays silently ignored.
        if (!session.stream.isActive()) {
            switch (self.enforcePreBindStanzaPolicy(session, elem, changes)) {
                .third_party_closed, .not_stanza => return,
                .server_addressed => {
                    // Client-namespace IQs were handled above (registration /
                    // dispatchIq). A server-addressed message is bounced.
                    if (std.mem.eql(u8, elem.local_name, "message")) {
                        self.sendPreBindStanzaError(session, elem, changes);
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
                    self.accumulateVcardElement(session, elem);
                    return;
                }
                self.handleIqChild(session, elem);
                return;
            }

            if (std.mem.eql(u8, elem.local_name, "message")) {
                if (session.sm_enabled) session.sm_in_h +%= 1;
                self.handleMessage(session, elem, changes);
            } else if (std.mem.eql(u8, elem.local_name, "presence")) {
                if (session.sm_enabled) session.sm_in_h +%= 1;
                self.handlePresence(session, elem, changes);
            } else if (std.mem.eql(u8, elem.local_name, "iq")) {
                if (session.sm_enabled) session.sm_in_h +%= 1;
                self.handleIq(session, elem, changes);
            }
        }
    }

    // ========================================================================
    // Text content accumulation for SASL elements
    // ========================================================================

    fn handleText(self: *Server, session: *Session, text: []const u8) void {
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
            self.accumulateStanzaText(session, text);
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
            self.accumulateVcardText(session, text);
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

    fn handleElementEnd(self: *Server, session: *Session, name: []const u8, changes: *ChangeList) void {
        // <starttls></starttls> form (T215): upgrade on the close tag.
        if (session.starttls_close_pending) {
            session.starttls_close_pending = false;
            const local = if (std.mem.lastIndexOfScalar(u8, name, ':')) |c| name[c + 1 ..] else name;
            if (std.mem.eql(u8, local, "starttls")) {
                const action = session.stream.handleStarttls();
                self.executeAction(session, action, changes);
                return;
            }
        }
        // Stanza accumulation — child close tag or stanza dispatch
        if (session.stanza_kind != .none) {
            if (session.reader.depth > 1) {
                // Still inside the stanza — accumulate the child close tag
                self.accumulateStanzaClose(session, name);
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
                    self.sendStreamError(session, .policy_violation);
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
                        self.dispatchStanza(session, changes);
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
                self.processSaslAuthComplete(session, changes);
                return;
            },
            .response => {
                self.processSaslResponseComplete(session, changes);
                return;
            },
            .none => {},
        }

        // vCard/PEP XML close tag accumulation
        if (session.iq_active and session.vcard_collecting) {
            if (session.reader.depth > session.vcard_collect_depth) {
                self.accumulateVcardClose(session, name);
            } else {
                // Reached the depth where collecting started — stop.
                // For vCard (depth=2), include the closing tag (stores full <vCard>...</vCard>).
                // For PEP items (depth>2), skip the closing </item> tag (stores inner payload only).
                if (session.vcard_collect_depth <= 2) {
                    self.accumulateVcardClose(session, name);
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

    // ========================================================================
    // SASL handling (via auth daemon IPC)
    // ========================================================================

    fn handleSaslAuth(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
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
            else => self.executeAction(session, action, changes),
        }
    }

    /// Called when </auth> is reached — we have the full base64 payload.
    fn processSaslAuthComplete(self: *Server, session: *Session, changes: *ChangeList) void {
        session.sasl_collecting = .none;

        if (!self.ipc.connected) {
            log.warn("connection {d} auth request but no auth daemon", .{session.conn.id});
            // Retryable: the reconnect timer re-links the auth daemon.
            const fail_action = session.stream.saslFailure("temporary-auth-failure");
            self.executeAction(session, fail_action, changes);
            return;
        }

        // Decode base64 from XML into raw SASL payload
        const b64_data = session.sasl_buf[0..session.sasl_buf_len];
        var decoded_buf: [3072]u8 = undefined;
        const decoded = b64Decode(b64_data, &decoded_buf) orelse {
            log.warn("connection {d} invalid base64 in SASL auth", .{session.conn.id});
            const fail_action = session.stream.saslFailure("not-authorized");
            self.executeAction(session, fail_action, changes);
            return;
        };

        // Determine mechanism ID
        const mech_id = ipc_protocol.MechanismId.fromName(session.sasl_mechanism) orelse {
            const fail_action = session.stream.saslFailure("not-authorized");
            self.executeAction(session, fail_action, changes);
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
            self.executeAction(session, fail_action, changes);
            return;
        };

        session.auth_state = .awaiting_challenge;

        // Write interest: reconcileIpcWriteInterest (S10).
    }

    /// Called when </response> is reached — we have the full SCRAM response.
    fn processSaslResponseComplete(self: *Server, session: *Session, changes: *ChangeList) void {
        session.sasl_collecting = .none;

        if (!self.ipc.connected) {
            const fail_action = session.stream.saslFailure("temporary-auth-failure");
            self.executeAction(session, fail_action, changes);
            return;
        }

        // Decode base64
        const b64_data = session.sasl_buf[0..session.sasl_buf_len];
        var decoded_buf: [3072]u8 = undefined;
        const decoded = b64Decode(b64_data, &decoded_buf) orelse {
            log.warn("connection {d} invalid base64 in SASL response", .{session.conn.id});
            const fail_action = session.stream.saslFailure("not-authorized");
            self.executeAction(session, fail_action, changes);
            return;
        };

        // Send SaslResponse to auth daemon
        self.ipc.send(.{ .sasl_response = .{
            .conn_id = session.ipcConnId(),
            .payload = decoded,
        } }) catch {
            log.err("connection {d} failed to send SASL response via IPC", .{session.conn.id});
            const fail_action = session.stream.saslFailure("temporary-auth-failure");
            self.executeAction(session, fail_action, changes);
            return;
        };

        session.auth_state = .awaiting_result;

        // Write interest: reconcileIpcWriteInterest (S10).
    }

    // ========================================================================
    // IPC response handling — auth daemon responses dispatched to sessions
    // ========================================================================

    fn handleIpcReadable(self: *Server, changes: *ChangeList) void {
        _ = self.ipc.recv() catch |err| {
            log.err("auth daemon IPC recv error: {}", .{err});
            self.dropIpcAuth(changes);
            return;
        };

        // Process all complete messages
        while (true) {
            const msg = self.ipc.nextMessage() catch |err| {
                // A decode error does not consume the frame; keeping the
                // link retries the same bytes forever and wedges every
                // SASL exchange behind it. Drop and reconnect (S10).
                log.warn("auth daemon IPC decode error: {} len={d} consumed={d} — dropping link", .{ err, self.ipc.recv_len, self.ipc.recv_consumed });
                self.dropIpcAuth(changes);
                return;
            };
            if (msg == null) break;
            self.dispatchAuthResponse(msg.?, changes);
        }
    }

    fn flushIpc(self: *Server, changes: *ChangeList) void {
        _ = self.ipc.flush() catch {
            log.err("auth daemon IPC flush error", .{});
            self.dropIpcAuth(changes);
            return;
        };
        // Write interest (arm on backlog, disarm on drain) is reconciled
        // once per loop iteration; see reconcileIpcWriteInterest (S10).
    }

    /// S10: stage the IPC reconnect timers owed this iteration. Called on
    /// every exit of reconcileIpcWriteInterest, including the drop path, since
    /// a link dropped there sets a pending flag that nothing else would stage
    /// and the next submitAndPoll blocks until a timer fires.
    fn stageReconnectTimers(self: *Server, changes: *ChangeList) void {
        if (self.auth_reconnect_pending) {
            // Keep the flag set if the arm could not be staged, so the next
            // iteration retries it rather than losing the only trigger.
            if (changes.addTimer(AUTH_RECONNECT_TIMER_IDENT, AUTH_RECONNECT_MS, true)) |_| {
                self.auth_reconnect_pending = false;
            } else |err| {
                log.warn("auth IPC reconnect timer deferred ({})", .{err});
            }
        }
        if (self.s2s_reconnect_pending) {
            if (changes.addTimer(S2S_RECONNECT_TIMER_IDENT, S2S_RECONNECT_MS, true)) |_| {
                self.s2s_reconnect_pending = false;
            } else |err| {
                log.warn("s2s IPC reconnect timer deferred ({})", .{err});
            }
        }
    }

    /// S10: sole owner of IPC write interest, called once per loop
    /// iteration. Arming scattered across send sites could lose a re-arm
    /// to a full changelist and strand pending frames (the pre-S10
    /// persistent filter spun and hid it); disarming here keeps an idle
    /// link from re-firing writable every kevent. Also the sole owner of the
    /// IPC reconnect timers.
    fn reconcileIpcWriteInterest(self: *Server, changes: *ChangeList) void {
        // Spend the reserved tail: this runs last in every iteration, so a
        // batch filled by event handling must not cost us an arm or a disarm.
        // A lost arm strands pending frames; a lost disarm leaves a persistent
        // filter firing writable every kevent.
        changes.beginReserved();
        // Deferred, LIFO: stageReconnectTimers runs first so a link dropped on
        // the write-arm path below still gets its timer, then endReserved.
        // Both run inside the reserved tail, so a full batch cannot cost the
        // only thing that would ever retry the link.
        defer changes.endReserved();
        defer self.stageReconnectTimers(changes);

        if (self.ipc.connected and self.ipc.fd >= 0) {
            if (self.ipc.hasPendingSend()) {
                if (!self.ipc_write_armed) {
                    changes.addWrite(self.ipc.fd, IPC_AUTH_UDATA) catch |err| {
                        log.err("auth IPC write arm failed ({}) — dropping link", .{err});
                        self.dropIpcAuth(changes);
                        return;
                    };
                    self.ipc_write_armed = true;
                }
            } else if (self.ipc_write_armed) {
                // Keep the flag set if the removal could not be staged, so the
                // next iteration retries it instead of leaking a live filter.
                // Falling through, not returning: the s2s link below still
                // needs reconciling in this iteration.
                if (changes.removeWrite(self.ipc.fd)) |_| {
                    self.ipc_write_armed = false;
                } else |err| {
                    log.warn("auth IPC write disarm deferred ({})", .{err});
                }
            }
        } else {
            self.ipc_write_armed = false;
        }

        if (self.s2s_ipc.connected and self.s2s_ipc.fd >= 0) {
            if (self.s2s_ipc.hasPendingSend()) {
                if (!self.s2s_write_armed) {
                    changes.addWrite(self.s2s_ipc.fd, IPC_S2S_UDATA) catch |err| {
                        log.err("s2s IPC write arm failed ({}) — dropping link", .{err});
                        self.dropS2sIpc(changes);
                        return;
                    };
                    self.s2s_write_armed = true;
                }
            } else if (self.s2s_write_armed) {
                if (changes.removeWrite(self.s2s_ipc.fd)) |_| {
                    self.s2s_write_armed = false;
                } else |err| {
                    log.warn("s2s IPC write disarm deferred ({})", .{err});
                }
            }
        } else {
            self.s2s_write_armed = false;
        }
    }

    /// Override sasl_mechanisms in a FeatureSet with the dynamic list from auth daemon.
    /// If auth hasn't reported yet (count=0), returns features unchanged (falls back to FSM default).
    fn applyDynamicMechanisms(self: *Server, features: xmpp.stream.FeatureSet) xmpp.stream.FeatureSet {
        if (self.auth_mechanism_count == 0) return features;
        if (features.sasl_mechanisms.len == 0) return features;
        var f = features;
        f.sasl_mechanisms = self.auth_mechanisms[0..self.auth_mechanism_count];
        return f;
    }

    fn dispatchAuthResponse(self: *Server, msg: ipc_protocol.Message, changes: *ChangeList) void {
        // Handle MechanismList separately (not per-connection)
        switch (msg) {
            .mechanism_list => |ml| {
                self.auth_mechanism_count = 0;
                var buf_pos: usize = 0;
                for (ml.slice()) |mech_id| {
                    const name = mech_id.toName();
                    if (buf_pos + name.len > self.auth_mechanism_name_buf.len) break;
                    @memcpy(self.auth_mechanism_name_buf[buf_pos .. buf_pos + name.len], name);
                    self.auth_mechanisms[self.auth_mechanism_count] = self.auth_mechanism_name_buf[buf_pos .. buf_pos + name.len];
                    self.auth_mechanism_count += 1;
                    buf_pos += name.len;
                }
                log.info("auth daemon advertises {d} mechanisms", .{self.auth_mechanism_count});
                return;
            },
            else => {},
        }

        const raw_id: u32 = switch (msg) {
            .auth_challenge => |m| m.conn_id,
            .auth_success => |m| m.conn_id,
            .auth_failure => |m| m.conn_id,
            .register_result => |m| m.conn_id,
            .password_change_result => |m| m.conn_id,
            .account_delete_result => |m| m.conn_id,
            else => return,
        };

        // conn_id encodes generation in upper 16 bits, slot index in lower 16
        const expected_gen: u16 = @truncate(raw_id >> 16);
        const conn_id: usize = @intCast(raw_id & 0xFFFF);

        const session = self.sessions[conn_id] orelse {
            log.warn("auth response for unknown connection {d}", .{conn_id});
            return;
        };

        // Reject stale responses from a previous session that reused this slot
        if (session.auth_ipc_gen != expected_gen) {
            log.warn("auth response for connection {d} has stale generation (got {d}, expected {d})", .{ conn_id, expected_gen, session.auth_ipc_gen });
            return;
        }

        switch (msg) {
            .auth_challenge => |m| {
                // Base64-encode the challenge and send as <challenge>
                var fbs = std.io.fixedBufferStream(&session.write_scratch);
                const w = fbs.writer();
                w.writeAll("<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>") catch return;
                b64EncodeWrite(w, m.challenge) catch return;
                w.writeAll("</challenge>") catch return;
                session.conn.queueSend(fbs.getWritten()) catch return;
                session.auth_state = .none;

                if (session.conn.hasPendingWrite()) {
                    changes.addWrite(session.conn.fd, conn_id) catch {};
                }
            },
            .auth_success => |m| {
                // Base64-encode server_final for the <success> element
                var b64_buf: [2048]u8 = undefined;
                var server_final_b64: []const u8 = "";
                if (m.server_final.len > 0) {
                    const encoder = std.base64.standard.Encoder;
                    const enc_len = encoder.calcSize(m.server_final.len);
                    if (enc_len <= b64_buf.len) {
                        server_final_b64 = encoder.encode(b64_buf[0..enc_len], m.server_final);
                    }
                }

                // Copy username into session-owned storage — the IPC recv buffer
                // is transient and will be reused for other connections' auth.
                const ulen = @min(m.username.len, session.auth_username_buf.len);
                @memcpy(session.auth_username_buf[0..ulen], m.username[0..ulen]);
                session.auth_username_len = ulen;
                const stable_username = session.auth_username_buf[0..ulen];

                // OIDC profile photo import: if enabled and the IdP provided a picture URL
                // and the user has no stored vCard, create one with the photo.
                if (self.oidc_import_avatar and m.photo_url.len > 0) {
                    if (self.vcard) |vcard| {
                        // Build bare JID for vCard lookup
                        var jid_buf: [512]u8 = undefined;
                        var jid_fbs = std.io.fixedBufferStream(&jid_buf);
                        const jw = jid_fbs.writer();
                        jw.writeAll(stable_username) catch {};
                        jw.writeByte('@') catch {};
                        jw.writeAll(self.server_host) catch {};
                        const bare_jid = jid_fbs.getWritten();

                        const existing = vcard.get(self.allocator, bare_jid) catch null;
                        if (existing) |data| {
                            self.allocator.free(data);
                        } else {
                            // No existing vCard — create one with OIDC photo
                            var vc_buf: [1024]u8 = undefined;
                            var vc_fbs = std.io.fixedBufferStream(&vc_buf);
                            const vw = vc_fbs.writer();
                            vw.writeAll("<vCard xmlns='vcard-temp'><PHOTO><EXTVAL>") catch {};
                            xml.escapeWrite(vw, m.photo_url) catch {};
                            vw.writeAll("</EXTVAL></PHOTO></vCard>") catch {};
                            vcard.set(bare_jid, vc_fbs.getWritten()) catch {};
                            log.info("OIDC photo imported for '{s}'", .{stable_username});
                        }
                    }
                }

                const success_action = session.stream.saslSuccess(stable_username, server_final_b64);
                self.executeAction(session, success_action, changes);
                session.resetSasl();
                if (session.conn.hasPendingWrite()) {
                    // Flush immediately rather than deferring to kqueue
                    // EVFILT_WRITE which intermittently fails to fire.
                    _ = session.conn.flushSend() catch {};
                    if (session.conn.hasPendingWrite()) {
                        changes.addWrite(session.conn.fd, conn_id) catch {};
                    }
                }
                // OpenSSL may have buffered the client's post-auth stream open
                // internally. kqueue won't fire for data already consumed from
                // the socket. Drain the SSL buffer immediately — same pattern
                // as post-TLS and the S2S post-SASL fix.
                if (session.conn.tls_conn) |*tls| {
                    if (tls.pending() > 0) {
                        self.handleReadable(conn_id, changes);
                    }
                }
            },
            .auth_failure => |m| {
                log.info("connection {d} auth failed: {s}", .{ conn_id, m.reason });
                const fail_action = session.stream.saslFailure(m.reason);
                self.executeAction(session, fail_action, changes);
                session.resetSasl();

                if (session.conn.hasPendingWrite()) {
                    changes.addWrite(session.conn.fd, conn_id) catch {};
                }
            },
            .register_result => |m| {
                const iq_id = session.reg_pending_iq_id;
                session.reg_pending_iq_id = "";

                var fbs = std.io.fixedBufferStream(&session.write_scratch);
                const w = fbs.writer();
                if (m.success) {
                    iq_handler.writeIqHeader(self, w, session, "result", iq_id);
                    w.writeAll("/>") catch return;
                } else {
                    iq_handler.writeIqHeader(self, w, session, "error", iq_id);
                    w.writeAll("><error type='cancel'><") catch return;
                    w.writeAll(m.reason) catch return;
                    w.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>") catch return;
                }
                session.conn.queueSend(fbs.getWritten()) catch return;

                if (session.conn.hasPendingWrite()) {
                    changes.addWrite(session.conn.fd, conn_id) catch {};
                }
            },
            .password_change_result => |m| {
                const iq_id = session.reg_pending_iq_id;
                session.reg_pending_iq_id = "";

                var fbs = std.io.fixedBufferStream(&session.write_scratch);
                const w = fbs.writer();
                if (m.success) {
                    iq_handler.writeIqHeader(self, w, session, "result", iq_id);
                    w.writeAll("/>") catch return;
                } else {
                    iq_handler.writeIqHeader(self, w, session, "error", iq_id);
                    w.writeAll("><error type='modify'><") catch return;
                    w.writeAll(m.reason) catch return;
                    w.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>") catch return;
                }
                session.queueSendStanza(fbs.getWritten()) catch return;

                if (session.conn.hasPendingWrite()) {
                    changes.addWrite(session.conn.fd, conn_id) catch {};
                }
            },
            .account_delete_result => |m| {
                const iq_id = session.reg_pending_iq_id;
                session.reg_pending_iq_id = "";
                session.reg_has_remove = false;

                if (m.success) {
                    // Cascade cleanup in core stores
                    const username = session.auth_username_buf[0..session.auth_username_len];
                    if (username.len > 0) {
                        self.cascadeAccountDelete(username);
                    }

                    // Send IQ result then close the stream
                    var fbs = std.io.fixedBufferStream(&session.write_scratch);
                    const w = fbs.writer();
                    iq_handler.writeIqHeader(self, w, session, "result", iq_id);
                    w.writeAll("/>") catch return;
                    session.queueSendStanza(fbs.getWritten()) catch return;

                    // Close the stream per XEP-0077 §3.2
                    session.conn.queueSend("</stream:stream>") catch {};

                    if (session.conn.hasPendingWrite()) {
                        changes.addWrite(session.conn.fd, conn_id) catch {};
                    }
                } else {
                    var fbs = std.io.fixedBufferStream(&session.write_scratch);
                    const w = fbs.writer();
                    iq_handler.writeIqHeader(self, w, session, "error", iq_id);
                    w.writeAll("><error type='cancel'><") catch return;
                    w.writeAll(m.reason) catch return;
                    w.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>") catch return;
                    session.queueSendStanza(fbs.getWritten()) catch return;

                    if (session.conn.hasPendingWrite()) {
                        changes.addWrite(session.conn.fd, conn_id) catch {};
                    }
                }
            },
            else => {},
        }
    }

    /// Cascade cleanup for a deleted account — remove from all core stores.
    /// Called after auth daemon confirms credential deletion.
    fn cascadeAccountDelete(self: *Server, username: []const u8) void {
        // Build bare JID for store lookups: username@server_host
        var bare_buf: [320]u8 = undefined;
        var bare_fbs = std.io.fixedBufferStream(&bare_buf);
        bare_fbs.writer().writeAll(username) catch return;
        bare_fbs.writer().writeByte('@') catch return;
        bare_fbs.writer().writeAll(self.server_host) catch return;
        const bare_jid = bare_fbs.getWritten();

        // Remove roster entries (iterate + delete each)
        if (self.roster) |roster| {
            const items = roster.getAllItems(self.allocator, bare_jid) catch |err| {
                log.warn("cascade: roster getAllItems failed for {s}: {}", .{ bare_jid, err });
                return;
            };
            for (items) |item| {
                roster.removeItem(bare_jid, item.contact_jid) catch {};
                self.allocator.free(item.contact_jid);
                if (item.entry.name.len > 0) self.allocator.free(item.entry.name);
            }
            self.allocator.free(items);
            self.invalidateSubCache(bare_jid);
        }

        // Remove vCard
        if (self.vcard) |vcard| {
            vcard.delete(bare_jid) catch |err| {
                log.warn("cascade: vcard cleanup failed for {s}: {}", .{ bare_jid, err });
            };
        }

        // Offline + MAM archive cleanup is best-effort.
        // The stores use prefix keys (recipient\x00timestamp), so individual
        // deletion requires iteration. For now we log — a full prefix-delete
        // can be added to the backend trait in a future phase.
        if (self.offline != null) {
            log.info("cascade: offline messages for {s} will expire naturally", .{bare_jid});
        }
        if (self.archive != null) {
            log.info("cascade: MAM archive for {s} will be pruned by retention", .{bare_jid});
        }

        // Session map unbind happens in closeSession() when the connection closes
        // after we send </stream:stream>.

        log.info("cascade cleanup complete for {s}", .{bare_jid});
    }

    // ========================================================================
    // S2S IPC — federation stanza forwarding
    // ========================================================================

    /// Forward a pre-built presence stanza to a remote domain via S2S IPC.
    /// Used by subscription/presence handlers where the stanza XML is already built.
    pub fn forwardPresenceXmlToS2s(self: *Server, session: *Session, from_str: []const u8, to_str: []const u8, stanza_xml: []const u8, changes: *ChangeList) void {
        _ = changes; // Write interest: reconcileIpcWriteInterest (S10).
        if (!self.s2s_ipc.connected) {
            log.info("connection {d} presence to remote {s} — no S2S daemon", .{ session.conn.id, to_str });
            return;
        }

        self.s2s_ipc.send(.{ .s2s_deliver = .{
            .from_jid = from_str,
            .to_jid = to_str,
            .stanza_xml = stanza_xml,
        } }) catch {
            log.err("connection {d} failed to forward presence to S2S", .{session.conn.id});
            return;
        };
        // Write interest: reconcileIpcWriteInterest (S10).
    }

    /// Forward a pre-built presence stanza to a remote domain via S2S IPC.
    /// Variant without a session reference — used by broadcast presence.
    pub fn sendPresenceViaS2s(self: *Server, from_str: []const u8, to_str: []const u8, stanza_xml: []const u8, changes: *ChangeList) void {
        _ = changes; // Write interest: reconcileIpcWriteInterest (S10).
        if (!self.s2s_ipc.connected) return;

        self.s2s_ipc.send(.{ .s2s_deliver = .{
            .from_jid = from_str,
            .to_jid = to_str,
            .stanza_xml = stanza_xml,
        } }) catch return;
        // Write interest: reconcileIpcWriteInterest (S10).
    }

    /// Return a service-unavailable error over the inbound S2S link.
    fn bounceS2sInbound(self: *Server, remote_from: []const u8, local_to: []const u8, tag_name: []const u8, stanza_id: []const u8) void {
        if (!self.s2s_ipc.connected) {
            log.warn("S2S bounce for {s} dropped: no S2S daemon", .{remote_from});
            return;
        }

        var lease = self.leaseByteScratch() orelse return;
        defer lease.release();
        var fbs = std.io.fixedBufferStream(lease.buf);
        writeS2sError(fbs.writer(), tag_name, local_to, remote_from, stanza_id) catch {
            log.warn("S2S bounce for {s} dropped: serialization failed", .{remote_from});
            return;
        };

        self.s2s_ipc.send(.{ .s2s_deliver = .{
            .from_jid = local_to,
            .to_jid = remote_from,
            .stanza_xml = fbs.getWritten(),
        } }) catch {
            log.err("failed to bounce S2S inbound for {s}", .{remote_from});
            return;
        };
        _ = delivery_queue_mod.s2s_bounces.fetchAdd(1, .monotonic);
        // Write interest: reconcileIpcWriteInterest (S10).
    }

    fn handleS2sIpcReadable(self: *Server, changes: *ChangeList) void {
        _ = self.s2s_ipc.recv() catch {
            log.err("S2S daemon IPC recv error", .{});
            self.dropS2sIpc(changes);
            return;
        };

        while (true) {
            const msg = self.s2s_ipc.nextMessage() catch {
                // Same wedge class as the auth link (S10): an unconsumed
                // bad frame would be retried forever.
                log.warn("S2S daemon IPC decode error — dropping link", .{});
                self.dropS2sIpc(changes);
                return;
            };
            if (msg == null) break;
            self.dispatchS2sResponse(msg.?, changes);
        }
    }

    fn flushS2sIpc(self: *Server, changes: *ChangeList) void {
        _ = self.s2s_ipc.flush() catch {
            log.err("S2S daemon IPC flush error", .{});
            self.dropS2sIpc(changes);
            return;
        };
        // Write interest: reconcileIpcWriteInterest (S10).
    }

    fn dispatchS2sResponse(self: *Server, msg: ipc_protocol.Message, changes: *ChangeList) void {
        switch (msg) {
            .s2s_inbound => |m| {
                // Inbound stanza from remote — deliver to local session(s) by
                // writing the stanza XML directly to the target connection(s).
                const to_jid = xmpp.Jid.parse(m.to_jid) catch {
                    log.warn("S2S inbound: invalid to_jid: {s}", .{m.to_jid});
                    return;
                };

                const s2s_sm = self.session_map orelse return;
                var lease_s2s = self.leaseScratch(.b);
                defer lease_s2s.release();
                const s2s_entries = lease_s2s.entries;
                const target_count = if (to_jid.resource.len > 0) blk: {
                    if (s2s_sm.findByFullJid(to_jid.local, to_jid.domain, to_jid.resource)) |e| {
                        s2s_entries[0] = e;
                        break :blk @as(usize, 1);
                    }
                    break :blk @as(usize, 0);
                } else s2s_sm.findAvailableByBareJid(to_jid.local, to_jid.domain, s2s_entries);

                // Single timestamp for all S2S archive operations (T123)
                const s2s_archive_ts: u64 = @intCast(std.time.timestamp());

                if (target_count == 0) {
                    const parts = extractStanzaParts(m.stanza_xml);
                    if (parts.is_message and std.mem.eql(u8, parts.msg_type, "groupchat")) {
                        log.warn("S2S groupchat to {s}: recipient unavailable, bouncing", .{m.to_jid});
                        self.bounceS2sInbound(m.from_jid, m.to_jid, "message", parts.msg_id);
                        return;
                    }
                    if (parts.is_iq) {
                        if (std.mem.eql(u8, parts.msg_type, "get") or std.mem.eql(u8, parts.msg_type, "set")) {
                            log.warn("S2S IQ to {s}: recipient unavailable, bouncing", .{m.to_jid});
                            self.bounceS2sInbound(m.from_jid, m.to_jid, "iq", parts.msg_id);
                        }
                        return;
                    }
                    // An error stanza is never stored and never bounced back, or
                    // two servers could bounce it at each other.
                    if (parts.is_message and !std.mem.eql(u8, parts.msg_type, "error")) {
                        if (self.offline) |store| {
                            var recip_buf: [router.BARE_JID_MAX]u8 = undefined;
                            const recipient_bare = router.buildBareJid(to_jid.local, to_jid.domain, &recip_buf) catch |err| {
                                log.warn("S2S message to {s} has an invalid offline key: {s}", .{ m.to_jid, @errorName(err) });
                                self.bounceS2sInbound(m.from_jid, m.to_jid, "message", parts.msg_id);
                                return;
                            };

                            const stanza_id = if (parts.msg_id.len > 0) parts.msg_id else "s2s-offline";

                            // Payload goes down with the pointer. The archive row is
                            // also written here, but a failed write must not leave a
                            // pointer behind: the drain would find neither copy, drop
                            // the pointer, and the message would vanish (E2b).
                            if (self.archive) |archive| {
                                archive.store(recipient_bare, m.from_jid, stanza_id, s2s_archive_ts, m.stanza_xml) catch |err| {
                                    log.warn("S2S offline archive store failed for {s}: {s}", .{ recipient_bare, @errorName(err) });
                                };
                            }
                            const held = store.storeHeldPointer(recipient_bare, m.from_jid, stanza_id, s2s_archive_ts, m.stanza_xml) catch |err| blk: {
                                // A storage error is logged with its name and still
                                // bounces below, never a silent drop (G7).
                                log.warn("S2S offline hold failed for {s}: {s}", .{ recipient_bare, @errorName(err) });
                                break :blk false;
                            };
                            if (held) {
                                log.info("S2S inbound to {s} stored offline", .{m.to_jid});
                                return;
                            }
                        }
                        // Quota reached, or no offline store at all: tell the remote
                        // sender instead of dropping the stanza on the floor (E2b).
                        log.warn("S2S inbound to {s}: recipient offline and not storable, bouncing", .{m.to_jid});
                        self.bounceS2sInbound(m.from_jid, m.to_jid, "message", parts.msg_id);
                        return;
                    }
                    log.info("S2S inbound to {s}: recipient unavailable, nothing stored", .{m.to_jid});
                    return;
                }

                const live_parts = extractStanzaParts(m.stanza_xml);
                // Archive S2S inbound messages delivered to online recipients (T81)
                if (self.archive != null) {
                    if (live_parts.is_message and std.mem.indexOf(u8, live_parts.inner_xml, "<body") != null) {
                        var recip_buf: [256]u8 = undefined;
                        var recip_fbs = std.io.fixedBufferStream(&recip_buf);
                        recip_fbs.writer().writeAll(to_jid.local) catch {};
                        recip_fbs.writer().writeByte('@') catch {};
                        recip_fbs.writer().writeAll(to_jid.domain) catch {};
                        const recipient_bare = recip_fbs.getWritten();

                        var s2s_sid_buf: [32]u8 = undefined;
                        const s2s_stanza_id = self.generateStanzaId(&s2s_sid_buf);

                        // Archive under recipient bare JID (via the T87 queue when wired)
                        self.archiveStore(recipient_bare, m.from_jid, s2s_stanza_id, s2s_archive_ts, m.stanza_xml);
                    }
                }

                for (s2s_entries[0..target_count]) |entry| {
                    if (entry.worker_id == self.worker_id) {
                        const target_session = self.sessions[entry.local_session_id] orelse continue;
                        if (target_session.offline_pending and live_parts.is_message and !std.mem.eql(u8, live_parts.msg_type, "error")) {
                            const hold_id = if (live_parts.msg_id.len > 0) live_parts.msg_id else "s2s-offline";
                            if (self.holdBehindOfflineTail(target_session, to_jid.local, to_jid.domain, m.from_jid, hold_id, s2s_archive_ts, m.stanza_xml)) continue;
                            log.warn("S2S message to {s} not held, offline queue unavailable or full", .{m.to_jid});
                            continue;
                        }
                        fanout_mod.deliverToSession(target_session, m.stanza_xml, entry.local_session_id, changes);
                    } else if (self.delivery_system) |ds| {
                        ds.deliver(entry.worker_id, entry.local_session_id, entry.generation, m.stanza_xml) catch {
                            _ = delivery_queue_mod.cross_worker_drops.fetchAdd(1, .monotonic);
                        };
                    }
                }
                log.info("S2S inbound from {s} delivered to {d} session(s)", .{ m.from_jid, target_count });
            },
            .s2s_delivery_failed => |m| {
                // Delivery to remote failed — bounce error to original sender
                const from_jid = xmpp.Jid.parse(m.from_jid) catch return;

                const fail_sm = self.session_map orelse return;
                var lease_sender = self.leaseScratch(.b);
                defer lease_sender.release();
                const sender_entries = lease_sender.entries;
                const sender_count = if (from_jid.resource.len > 0) blk: {
                    if (fail_sm.findByFullJid(from_jid.local, from_jid.domain, from_jid.resource)) |e| {
                        sender_entries[0] = e;
                        break :blk @as(usize, 1);
                    }
                    break :blk @as(usize, 0);
                } else fail_sm.findAvailableByBareJid(from_jid.local, from_jid.domain, sender_entries);

                // Build error stanza once for all targets
                var err_buf: [1024]u8 = undefined;
                var err_fbs = std.io.fixedBufferStream(&err_buf);
                const ew = err_fbs.writer();
                ew.writeAll("<message type='error' from='") catch return;
                xml.escapeWrite(ew, m.to_jid) catch return;
                ew.writeAll("' to='") catch return;
                xml.escapeWrite(ew, m.from_jid) catch return;
                ew.writeAll("'><error type='cancel'><") catch return;
                xml.escapeWrite(ew, m.error_type) catch return;
                ew.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>") catch return;
                const err_xml = err_fbs.getWritten();

                for (sender_entries[0..sender_count]) |sentry| {
                    if (sentry.worker_id == self.worker_id) {
                        const sender_session = self.sessions[sentry.local_session_id] orelse continue;
                        fanout_mod.deliverToSession(sender_session, err_xml, sentry.local_session_id, changes);
                    } else if (self.delivery_system) |ds| {
                        ds.deliver(sentry.worker_id, sentry.local_session_id, sentry.generation, err_xml) catch {};
                    }
                }
                log.info("S2S delivery failed: {s} → {s}: {s}", .{ m.from_jid, m.to_jid, m.error_type });
            },
            else => {},
        }
    }

    // ========================================================================
    // Stanza handlers (Phase 7: message routing + presence + IQ)
    // ========================================================================

    fn handleMessage(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
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
            self.dispatchStanza(session, changes);
        }
    }

    // ========================================================================
    // Stanza accumulation + dispatch (full stanza forwarding)
    // ========================================================================

    /// Serialize a child element opening tag into the stanza accumulation buffer.
    /// On overflow the whole stanza is marked bad and never dispatched (E5).
    fn accumulateStanzaElement(self: *Server, session: *Session, elem: xml.Element) void {
        _ = self;
        if (session.stanza_overflow) return;
        var fbs = std.io.fixedBufferStream(session.stanza_buf[session.stanza_buf_len..]);
        writeStanzaOpenTag(fbs.writer(), elem) catch {
            session.stanza_overflow = true;
            return;
        };
        session.stanza_buf_len += fbs.pos;
    }

    /// Serialize text content (XML-escaped) into the stanza accumulation buffer.
    fn accumulateStanzaText(self: *Server, session: *Session, text: []const u8) void {
        _ = self;
        if (session.stanza_overflow) return;
        var fbs = std.io.fixedBufferStream(session.stanza_buf[session.stanza_buf_len..]);
        xmlEscapeWrite(fbs.writer(), text) catch {
            session.stanza_overflow = true;
            return;
        };
        session.stanza_buf_len += fbs.pos;
    }

    /// Serialize a child element close tag into the stanza accumulation buffer.
    fn accumulateStanzaClose(self: *Server, session: *Session, name: []const u8) void {
        _ = self;
        if (session.stanza_overflow) return;
        var fbs = std.io.fixedBufferStream(session.stanza_buf[session.stanza_buf_len..]);
        writeStanzaCloseTag(fbs.writer(), name) catch {
            session.stanza_overflow = true;
            return;
        };
        session.stanza_buf_len += fbs.pos;
    }

    // ========================================================================
    // vCard XML accumulation (for IQ set vcard-temp)
    // ========================================================================

    fn writeVcardElement(session: *Session, elem: xml.Element) !usize {
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
            try xmlEscapeWrite(w, attr.value);
            try w.writeByte('\'');
        }

        if (elem.self_closing) {
            try w.writeAll("/>");
        } else {
            try w.writeByte('>');
        }
        return fbs.pos;
    }

    fn accumulateVcardElement(self: *Server, session: *Session, elem: xml.Element) void {
        if (session.pep_collecting) {
            self.accumulatePepElement(session, elem);
            return;
        }
        if (session.vcard_overflow) return;
        const written = writeVcardElement(session, elem) catch {
            session.vcard_overflow = true;
            return;
        };
        session.vcard_buf_len += written;
    }

    fn accumulateVcardText(self: *Server, session: *Session, text: []const u8) void {
        if (session.pep_collecting) {
            self.accumulatePepText(session, text);
            return;
        }
        if (session.vcard_overflow) return;
        var fbs = std.io.fixedBufferStream(session.vcard_buf[session.vcard_buf_len..]);
        xmlEscapeWrite(fbs.writer(), text) catch {
            session.vcard_overflow = true;
            return;
        };
        session.vcard_buf_len += fbs.pos;
    }

    fn accumulateVcardClose(self: *Server, session: *Session, name: []const u8) void {
        if (session.pep_collecting) {
            self.accumulatePepClose(session, name);
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

    fn accumulatePepElement(self: *Server, session: *Session, elem: xml.Element) void {
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

    fn accumulatePepText(self: *Server, session: *Session, text: []const u8) void {
        xml.escapeWrite(session.pep_payload.writer(self.allocator), text) catch return;
    }

    fn accumulatePepClose(self: *Server, session: *Session, name: []const u8) void {
        const a = self.allocator;
        session.pep_payload.appendSlice(a, "</") catch return;
        session.pep_payload.appendSlice(a, name) catch return;
        session.pep_payload.append(a, '>') catch return;
    }

    fn dispatchStanza(self: *Server, session: *Session, changes: *ChangeList) void {
        router.dispatchStanza(self, session, changes);
    }

    /// Generate a unique XEP-0359 stanza ID. Zero-padded timestamp, worker,
    /// and counter fields keep the representation fixed-width.
    pub fn generateStanzaId(self: *Server, buf: *[32]u8) []const u8 {
        const timestamp: u32 = @truncate(@as(u64, @intCast(std.time.timestamp())));
        const counter = self.stanza_id_counter;
        self.stanza_id_counter +%= 1;

        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        // The fixed-width ID occupies 22 bytes of this 32-byte buffer.
        std.fmt.format(w, "{x:0>8}-{x:0>4}-{x:0>8}", .{ timestamp, self.worker_id, counter }) catch unreachable;
        return fbs.getWritten();
    }

    fn handlePresence(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
        presence_handler.handlePresence(self, session, elem, changes);
    }

    fn handleIq(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
        _ = changes;
        iq_handler.handleIq(session, elem, self.server_host);
    }

    /// Handle child elements inside an IQ stanza (query, item, etc.)
    fn handleIqChild(self: *Server, session: *Session, elem: xml.Element) void {
        _ = self;
        iq_handler.handleIqChild(session, elem);
    }

    /// Dispatch a complete IQ stanza based on accumulated state.
    fn dispatchIq(self: *Server, session: *Session, changes: *ChangeList) void {
        iq_handler.dispatchIq(self, session, changes);
    }

    /// Write an ISO 8601 timestamp from a unix timestamp.
    fn writeTimestamp(_: *Server, writer: anytype, timestamp: i64) !void {
        // Simple UTC timestamp: YYYY-MM-DDThh:mm:ssZ
        const epoch_secs: u64 = @intCast(if (timestamp < 0) 0 else timestamp);
        const epoch = std.time.epoch.EpochSeconds{ .secs = epoch_secs };
        const day = epoch.getDaySeconds();
        const year_day = epoch.getEpochDay().calculateYearDay();
        const month_day = year_day.calculateMonthDay();

        try writer.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
            year_day.year,
            @as(u32, @intFromEnum(month_day.month)),
            @as(u32, month_day.day_index) + 1,
            day.getHoursIntoDay(),
            day.getMinutesIntoHour(),
            day.getSecondsIntoMinute(),
        });
    }

    // ========================================================================
    // Execute StreamAction — write XML responses
    // ========================================================================

    pub fn executeAction(self: *Server, session: *Session, action: xmpp.StreamAction, changes: *ChangeList) void {
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const writer = fbs.writer();

        switch (action) {
            .send_stream_open => |params| {
                xmpp.stream.writeStreamOpen(writer, params) catch return;
                session.conn.queueSend(fbs.getWritten()) catch return;
                session.stream.response_opened = true;

                // Immediately send features after stream open
                if (session.stream.getFeatures()) |features| {
                    var fbs2 = std.io.fixedBufferStream(session.write_scratch[fbs.pos..]);
                    xmpp.stream.writeFeatures(fbs2.writer(), self.applyDynamicMechanisms(features)) catch return;
                    session.conn.queueSend(fbs2.getWritten()) catch return;
                }
            },
            .send_features => |features| {
                xmpp.stream.writeFeatures(writer, self.applyDynamicMechanisms(features)) catch return;
                session.conn.queueSend(fbs.getWritten()) catch return;
            },
            .send_tls_proceed, .start_tls => {
                writer.writeAll("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>") catch return;
                session.conn.queueSend(fbs.getWritten()) catch return;

                // T215: the handshake starts only after the plaintext
                // <proceed/> has fully flushed; leftover bytes would be
                // written through the TLS record layer. handleWritable
                // completes the upgrade once the buffer drains.
                _ = session.conn.flushSend() catch {};
                if (session.conn.hasPendingWrite()) return;
                // Nothing in this branch touches the session afterwards, and
                // every caller returns on reaching it, so a failed upgrade
                // that frees the session is not read here.
                _ = self.startTlsUpgrade(session, changes);
            },
            .send_sasl_success => |server_final| {
                writer.writeAll("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>") catch return;
                writer.writeAll(server_final) catch return;
                writer.writeAll("</success>") catch return;
                session.conn.queueSend(fbs.getWritten()) catch return;
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
                session.conn.queueSend(fbs.getWritten()) catch return;
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
                session.queueSendStanza(fbs.getWritten()) catch return;
            },
            .send_error => |err| {
                self.sendStreamError(session, err);
            },
            .session_established => {
                // Nothing to send — session is now active
            },
            .close => {
                writer.writeAll("</stream:stream>") catch return;
                session.conn.queueSend(fbs.getWritten()) catch return;
            },
            .none, .begin_sasl, .send_sasl_challenge => {},
        }
    }

    // ========================================================================
    // Write handler
    // ========================================================================

    fn handleWritable(self: *Server, id: usize, changes: *ChangeList) void {
        const session = self.sessions[id] orelse return;
        if (isStaleSessionEvent(session)) {
            self.stale_event_skips += 1;
            log.debug("connection {d} stale writable event on a detached or closed session, skipped", .{id});
            return;
        }

        _ = session.conn.flushSend() catch |err| {
            switch (err) {
                error.WouldBlock => return,
                // The fd is already gone, so there is nothing to flush and
                // nothing to close: tearing the session down here destroyed a
                // resumable one (S28).
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
                if (!self.startTlsUpgrade(session, changes)) return;
            }
        }

        // S13: with the buffer at the low-water mark, continue a stalled
        // offline drain; the tail goes out before any newer traffic.
        if (session.offline_pending and
            session.conn.pendingWriteBytes() <= connection_mod.WRITE_SUPPRESS_LOW)
        {
            session_lifecycle.drainOfflinePending(self, session, changes);
        }

        self.applyReadBackpressure(session, changes);
    }

    /// Begin the TLS handshake once the plaintext <proceed/> is fully
    /// flushed (T215). Called from executeAction and handleWritable. A
    /// failed upgrade closes the session: it would otherwise sit in
    /// starttls_pending forever. Closing frees the session, so false means
    /// the caller must stop touching it.
    fn startTlsUpgrade(self: *Server, session: *Session, changes: *ChangeList) bool {
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
    fn applyReadBackpressure(self: *Server, session: *Session, changes: *ChangeList) void {
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

    // ========================================================================
    // Helpers
    // ========================================================================

    pub fn sendStreamError(self: *Server, session: *Session, err: xmpp.stream.StreamError) void {
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const open_params: ?xmpp.stream.StreamOpenParams = if (session.stream.response_opened) null else .{
            .from = self.server_host,
            .to = self.server_host,
            .id = &session.stream.stream_id_hex,
        };
        xmpp.stream.writeStreamError(fbs.writer(), err, open_params) catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
        session.stream.response_opened = true;
    }

    fn sendRaw(_: *Server, session: *Session, data: []const u8) void {
        session.conn.queueSend(data) catch return;
    }

    // ========================================================================
    // Cross-thread delivery (MPSC queue consumer)
    // ========================================================================

    /// Handle EVFILT_READ on the wake pipe — drain pipe bytes, then drain the MPSC queue,
    /// then drain per-room mailboxes.
    fn handleDeliveryWake(self: *Server, changes: *ChangeList) void {
        const ds = self.delivery_system orelse return;
        ds.drainPipe(self.worker_id);
        self.drainDeliveryQueue(changes);
        _ = self.drainRoomMailboxes(changes);
    }

    /// Drain all pending deliveries from this worker's MPSC queue.
    /// Validates generation (ABA protection) before delivering to local sessions.
    fn drainDeliveryQueue(self: *Server, changes: *ChangeList) void {
        const ds = self.delivery_system orelse return;
        const sm = self.session_map orelse return;
        const queue = ds.getQueue(self.worker_id);

        const Ctx = struct {
            server: *Server,
            changes: *ChangeList,
            session_map: *SessionMap,
        };
        const ctx = Ctx{ .server = self, .changes = changes, .session_map = sm };

        _ = queue.drain(ctx, struct {
            fn handle(c: Ctx, local_session_id: u32, generation: u32, payload: []const u8) void {
                // Multicast delivery: fan-out to all local occupants in a room
                if (local_session_id == delivery_queue_mod.MULTICAST_SENTINEL) {
                    c.server.handleMulticastDelivery(payload, c.changes);
                    return;
                }

                // Room actor message: decode and dispatch to local room shard
                if (local_session_id == delivery_queue_mod.ROOM_ACTOR_SENTINEL) {
                    c.server.handleRoomActorMessage(payload, c.changes);
                    return;
                }

                // SM resume handoff actor message (T177)
                if (local_session_id == delivery_queue_mod.SM_ACTOR_SENTINEL) {
                    c.server.handleSmActorMessage(payload, c.changes);
                    return;
                }

                // Unicast: ABA check then deliver to single session
                if (!c.session_map.getGenerationById(c.server.worker_id, local_session_id, generation)) return;

                const target_session = c.server.sessions[local_session_id] orelse return;
                if (target_session.sm_detached) {
                    // T153: no live connection to deliver to — track for resume
                    // replay instead of silently dropping the stanza.
                    target_session.smTrackOutbound(payload);
                    return;
                }
                const parts = extractStanzaParts(payload);
                if (target_session.offline_pending and parts.is_message and !std.mem.eql(u8, parts.msg_type, "error")) {
                    const hold_id = if (parts.msg_id.len > 0) parts.msg_id else "offline";
                    const timestamp: u64 = @intCast(std.time.timestamp());
                    const from_jid = extractAttrValue(payload, "from");
                    const bound = target_session.stream.bound_jid orelse {
                        log.warn("cross-worker message to session {d} has no bound recipient for its offline hold", .{local_session_id});
                        return;
                    };
                    if (c.server.holdBehindOfflineTail(target_session, bound.local, bound.domain, from_jid, hold_id, timestamp, payload)) return;
                    log.warn("cross-worker message to session {d} not held, offline queue unavailable or full", .{local_session_id});
                    return;
                }
                target_session.conn.queueSend(payload) catch return;
                target_session.smTrackOutbound(payload);
                if (target_session.conn.hasPendingWrite()) {
                    c.changes.addWrite(target_session.conn.fd, local_session_id) catch {};
                }
            }
        }.handle);
    }

    /// Handle a multicast delivery from the MPSC queue.
    /// Decodes the payload (room_jid + prefix + suffix), finds the room,
    /// and delivers the pre-built stanza to all local occupants.
    fn handleMulticastDelivery(self: *Server, payload: []const u8, changes: *ChangeList) void {
        const decoded = fanout_mod.decodeMulticastPayload(payload) orelse {
            log.warn("malformed multicast payload ({d} bytes)", .{payload.len});
            return;
        };

        const reg = self.room_registry orelse return;
        const room = reg.findByJid(decoded.room_jid) orelse return;

        // One delivery buffer reused for every local occupant (S18). The
        // prefix and suffix read here live in the decoded multicast payload.
        var deliver_lease = self.leaseByteScratch() orelse return;
        defer deliver_lease.release();

        for (&room.occupants) |*slot| {
            const occ = slot.* orelse continue;
            if (occ.worker_id != self.worker_id) continue;
            if (occ.session_id == room_registry_mod.REMOTE_OCCUPANT) continue;

            const target_session = self.sessions[occ.session_id] orelse continue;
            fanout_mod.deliverPrebuiltToSession(target_session, deliver_lease.buf, decoded.prefix, occ.getRealJid(), decoded.suffix, occ.session_id, changes);
        }
    }

    /// Handle a room actor message from the MPSC queue.
    /// Room-targeted messages (join, part, groupchat, disco) are pushed into the
    /// target room's per-room mailbox for fair scheduling. Non-room messages
    /// (shadow updates, session close) are dispatched immediately.
    fn handleRoomActorMessage(self: *Server, payload: []const u8, changes: *ChangeList) void {
        const msg = actor_message.decode(payload) orelse {
            log.warn("malformed room actor message ({d} bytes)", .{payload.len});
            return;
        };

        switch (msg) {
            .room_join, .room_part, .room_message, .room_disco_info, .room_disco_items, .room_admin, .room_mam_query => {
                // Extract room_jid to find target room's mailbox
                const room_jid = switch (msg) {
                    .room_join, .room_part => |ev| ev.room_jid,
                    .room_message => |ev| ev.room_jid,
                    .room_disco_info, .room_disco_items => |ev| ev.room_jid,
                    .room_admin => |ev| ev.room_jid,
                    .room_mam_query => |ev| ev.room_jid,
                    else => unreachable,
                };
                const reg = self.room_registry orelse return;
                // Find room — for room_join, the room may not exist yet.
                // processRemoteJoin will create it (with proper is_new_room logic).
                var room = reg.findByJid(room_jid);
                if (room == null) {
                    if (std.meta.activeTag(msg) == .room_join) {
                        // Create a minimal room so the mailbox exists for enqueue
                        room = reg.createRoom(room_jid, .{ .persistent = false }) catch return;
                        // Mark that processRemoteJoin should treat this as new
                        room.?.occupant_count = 0;
                    } else {
                        log.debug("room actor msg for unknown room: {s}", .{room_jid});
                        return;
                    }
                }
                const r = room.?;
                r.mailbox.enqueue(payload) catch {
                    _ = room_mailbox_mod.mailbox_drops.fetchAdd(1, .monotonic);
                    log.warn("room mailbox full for {s} — bouncing to sender (S16)", .{room_jid});
                    muc_handler.bounceRoomMailboxFull(self, msg, room_jid, changes);
                };
            },
            .room_directory_update => |ev| {
                muc_handler.handleRoomDirectoryUpdate(self, ev);
            },
            .invalidate_subscription => |ev| {
                // Cross-worker cache invalidation — local invalidate only;
                // do NOT re-broadcast (would cascade).
                self.sub_cache.invalidate(sub_cache_mod.hashBareJid(ev.bare_jid));
            },
            .shadow_join => |ev| {
                muc_handler.handleShadowJoin(self, ev);
            },
            .shadow_part => |ev| {
                muc_handler.handleShadowPart(self, ev);
            },
            .room_occupant_move => |ev| {
                // T177: immediate dispatch (see handleOccupantMove) — the move
                // only mutates a delivery triple, so mailbox ordering with
                // queued join/part/message traffic is not required.
                muc_handler.handleOccupantMove(self, ev);
            },
            .session_closed => |ev| {
                var jid_buf: [256]u8 = undefined;
                var jid_fbs = std.io.fixedBufferStream(&jid_buf);
                const jw = jid_fbs.writer();
                jw.writeAll(ev.local) catch return;
                jw.writeByte('@') catch return;
                jw.writeAll(ev.domain) catch return;
                if (ev.resource.len > 0) {
                    jw.writeByte('/') catch return;
                    jw.writeAll(ev.resource) catch return;
                }
                // local_only=true: this is already a broadcast from the originating
                // worker. Do NOT re-broadcast to avoid infinite cascade.
                muc_handler.handleSessionCloseLocal(self, jid_fbs.getWritten(), changes);
            },
            else => {
                log.warn("unexpected actor message tag in room dispatch: 0x{x:0>2}", .{msg.tag()});
            },
        }
    }

    /// Drain per-room mailboxes with round-robin fair scheduling.
    /// Called after drainDeliveryQueue in the event loop. Processes one message
    /// per room per iteration, bounded to MAX_DRAIN_PER_TICK total messages to
    /// prevent infinite spinning when cross-thread traffic generates responses.
    /// Returns true if there are still pending messages (caller should self-wake).
    fn drainRoomMailboxes(self: *Server, changes: *ChangeList) bool {
        const reg = self.room_registry orelse return false;
        const MAX_DRAIN_PER_TICK: usize = 32;
        var processed: usize = 0;
        var any_pending = false;

        for (&reg.rooms) |*slot| {
            if (processed >= MAX_DRAIN_PER_TICK) {
                any_pending = true;
                break;
            }
            const room = slot.* orelse continue;
            if (!room.active) continue;
            if (!room.mailbox.hasPending()) continue;
            const payload = room.mailbox.dequeue() orelse continue;
            self.processRoomMailboxMessage(room, payload, changes);
            processed += 1;
        }

        // Deferred room cleanup: destroy empty transient rooms AFTER all mailbox
        // processing. This is the single destruction point — avoids ordering
        // conflicts between session_closed (immediate) and room_part (mailbox),
        // and avoids use-after-free of decoded payload slices during processing.
        muc_handler.cleanupEmptyRooms(self);

        // Check if any room still has pending messages
        if (!any_pending) {
            for (&reg.rooms) |*slot| {
                const room = slot.* orelse continue;
                if (room.active and room.mailbox.hasPending()) {
                    any_pending = true;
                    break;
                }
            }
        }
        return any_pending;
    }

    /// Process a single message from a room's mailbox.
    fn processRoomMailboxMessage(self: *Server, room: *room_registry_mod.Room, payload: []const u8, changes: *ChangeList) void {
        const msg = actor_message.decode(payload) orelse return;
        switch (msg) {
            .room_join => |ev| {
                muc_handler.processRemoteJoin(self, ev, changes);
            },
            .room_part => |ev| {
                muc_handler.processRemotePart(self, ev, changes);
            },
            .room_message => |ev| {
                muc_handler.processRemoteGroupchat(self, ev, changes);
            },
            .room_disco_info => |ev| {
                muc_handler.processRemoteDiscoInfo(self, ev, changes);
            },
            .room_disco_items => |ev| {
                muc_handler.processRemoteDiscoItems(self, ev, changes);
            },
            .room_admin => |ev| {
                muc_handler.processRemoteAdminAction(self, ev, changes);
            },
            .room_mam_query => |ev| {
                muc_handler.processRemoteMamQuery(self, ev, changes);
            },
            else => {
                _ = room;
                log.warn("unexpected message in room mailbox: 0x{x:0>2}", .{msg.tag()});
            },
        }
    }

    /// Invalidate a bare JID's subscription-cache entry locally AND on all
    /// other workers. The sub_cache is per-worker memory with a 30s TTL —
    /// a roster/subscription change on one worker must not leave the others
    /// serving a stale subscriber list (cross-worker presence broadcast was
    /// silently skipped: e2e-subscription Test 7 at workers>1).
    pub fn invalidateSubCache(self: *Server, bare_jid: []const u8) void {
        self.sub_cache.invalidate(sub_cache_mod.hashBareJid(bare_jid));
        const wc = self.getWorkerCount();
        if (wc <= 1) return;
        var w: u16 = 0;
        while (w < wc) : (w += 1) {
            if (w == self.worker_id) continue;
            self.enqueueRoomActorMessage(w, .{ .invalidate_subscription = .{ .bare_jid = bare_jid } });
        }
    }

    /// Enqueue a room actor message to the owning worker via MPSC.
    /// Used by muc_handler when a MUC operation lands on a non-owning worker.
    pub fn enqueueRoomActorMessage(self: *Server, target_worker: u16, msg: actor_message.Message) void {
        const ds = self.delivery_system orelse return;
        var buf: [actor_message.MAX_ENCODED_SIZE]u8 = undefined;
        const len = actor_message.encode(&buf, msg) orelse {
            log.warn("room actor message encode failed", .{});
            return;
        };
        ds.deliver(target_worker, delivery_queue_mod.ROOM_ACTOR_SENTINEL, 0, buf[0..len]) catch |err| {
            log.warn("room actor enqueue to worker {d} failed: {}", .{ target_worker, err });
        };
    }

    /// Get the number of workers (for room ownership computation).
    pub fn getWorkerCount(self: *const Server) u16 {
        if (self.delivery_system) |ds| return ds.worker_count;
        return 1;
    }

    /// Encode and enqueue a multicast delivery to each remote worker that has
    /// occupants in the given room. Iterates set bits in worker_mask, excluding self.
    pub fn deliverMulticastToWorkers(self: *Server, room: *const room_registry_mod.Room, prefix: []const u8, suffix: []const u8) void {
        const ds = self.delivery_system orelse return;

        var mcast_buf: [delivery_queue_mod.MAX_PAYLOAD_SIZE]u8 = undefined;
        const mcast_len = fanout_mod.encodeMulticastPayload(&mcast_buf, room.getJid(), prefix, suffix) orelse {
            log.warn("multicast payload too large for room {s}", .{room.getJid()});
            return;
        };
        const mcast_payload = mcast_buf[0..mcast_len];

        // Iterate set bits in worker_mask, excluding self
        var mask = room.worker_mask;
        mask.unset(self.worker_id);
        var mask_it = mask.iterator(.{});
        while (mask_it.next()) |bit| {
            const wid: u16 = @intCast(bit);
            ds.deliver(wid, delivery_queue_mod.MULTICAST_SENTINEL, 0, mcast_payload) catch |err| {
                log.warn("multicast delivery failed to worker {d}: {}", .{ wid, err });
            };
        }
    }

    // ========================================================================
    // XEP-0198: Stream Management
    // ========================================================================

    /// Handle <enable xmlns='urn:xmpp:sm:3'/> — activate SM for this session.
    /// If the client includes resume='true', session resumption is enabled and
    /// an SM-ID is generated for future reconnection.
    fn handleSmEnable(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
        session.sm_enabled = true;
        session.sm_in_h = 0;
        session.sm_out_h = 0;
        session.sm_out_seq = 0;

        // Check for resume='true' attribute
        var resume_requested = false;
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "resume")) {
                resume_requested = std.mem.eql(u8, attr.value, "true");
                break;
            }
        }

        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();

        if (resume_requested) {
            // Generate SM-ID and enable resume
            sm_state.generateSmId(self.worker_id, &session.sm_id);
            session.sm_id_len = sm_state.SM_ID_HEX_LEN;
            session.sm_resume_enabled = true;

            // Allocate unacked stanza queue
            const queue = self.allocator.create(sm_state.SmUnackedQueue) catch {
                log.err("connection {d} failed to allocate SM unacked queue", .{session.conn.id});
                // Fall back to SM without resume
                session.sm_resume_enabled = false;
                session.sm_id_len = 0;
                w.writeAll("<enabled xmlns='urn:xmpp:sm:3'/>") catch return;
                session.conn.queueSend(fbs.getWritten()) catch return;
                if (session.conn.hasPendingWrite()) {
                    changes.addWrite(session.conn.fd, session.conn.id) catch {};
                }
                return;
            };
            queue.* = sm_state.SmUnackedQueue.init(self.allocator);
            session.sm_unacked = queue;

            w.writeAll("<enabled xmlns='urn:xmpp:sm:3' id='") catch return;
            w.writeAll(&session.sm_id) catch return;
            w.writeAll("' resume='true' max='") catch return;
            std.fmt.format(w, "{d}", .{sm_state.DEFAULT_RESUME_TIMEOUT}) catch return;
            w.writeAll("'/>") catch return;

            log.info("connection {d} stream management enabled with resume (id={s})", .{
                session.conn.id, &session.sm_id,
            });
        } else {
            w.writeAll("<enabled xmlns='urn:xmpp:sm:3'/>") catch return;
            log.info("connection {d} stream management enabled", .{session.conn.id});
        }

        session.conn.queueSend(fbs.getWritten()) catch return;
        if (session.conn.hasPendingWrite()) {
            changes.addWrite(session.conn.fd, session.conn.id) catch {};
        }
    }

    /// Handle <resume xmlns='urn:xmpp:sm:3' previd='...' h='N'/> — attempt session resume.
    /// Finds the detached session by SM-ID, verifies the authenticated user matches,
    /// transfers the resumed state to the current session, and replays unacked stanzas.
    fn handleSmResume(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
        var previd: []const u8 = "";
        var h_value: u32 = 0;
        var h_found = false;

        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "previd")) {
                previd = attr.value;
            } else if (std.mem.eql(u8, attr.local_name, "h")) {
                h_value = std.fmt.parseInt(u32, attr.value, 10) catch {
                    // Malformed h must not silently become 0: that would
                    // look like a backwards report and desync the replay
                    // (S24).
                    self.sendSmFailed(session, "bad-request", changes);
                    return;
                };
                h_found = true;
            }
        }

        if (previd.len == 0 or !h_found) {
            self.sendSmFailed(session, "unexpected-request", changes);
            return;
        }

        // T177: SM-IDs embed the owning worker id (sm_state.generateSmId).
        // A resume arriving on the wrong worker goes through the cross-worker
        // handoff instead of failing item-not-found.
        if (self.getWorkerCount() > 1) {
            if (sm_state.workerIdFromSmId(previd)) |owner| {
                if (owner != self.worker_id and owner < self.getWorkerCount()) {
                    self.startCrossWorkerResume(session, previd, h_value, owner, changes);
                    return;
                }
            }
        }

        // Find the detached session with matching SM-ID
        const detached_id = self.findDetachedSession(previd) orelse {
            // T177: prefix routed here but the session was handed off —
            // follow the redirect breadcrumb instead of failing.
            if (self.getWorkerCount() > 1) {
                if (self.smRedirectLookup(previd)) |target| {
                    if (target != self.worker_id and target < self.getWorkerCount()) {
                        self.startCrossWorkerResume(session, previd, h_value, target, changes);
                        return;
                    }
                }
            }
            self.sendSmFailed(session, "item-not-found", changes);
            return;
        };

        const detached = self.sessions[detached_id] orelse {
            self.sendSmFailed(session, "item-not-found", changes);
            return;
        };

        // T178: the detached session's unacked queue overflowed in this event
        // batch — its replay queue is corrupt. Fail the resume as if the
        // session were already gone; reapSmOverflow destroys it at batch end.
        if (detached.sm_overflow) {
            self.sendSmFailed(session, "item-not-found", changes);
            return;
        }

        // Verify the authenticated user matches the detached session's user
        const auth_jid = session.stream.authenticated_jid orelse {
            self.sendSmFailed(session, "not-authorized", changes);
            return;
        };
        const detached_jid = detached.stream.bound_jid orelse {
            self.sendSmFailed(session, "item-not-found", changes);
            return;
        };

        if (!std.mem.eql(u8, auth_jid.local, detached_jid.local) or
            !std.mem.eql(u8, auth_jid.domain, detached_jid.domain))
        {
            self.sendSmFailed(session, "not-authorized", changes);
            return;
        }

        // Process client's h value — ack stanzas the client received before disconnect
        if (detached.sm_unacked) |queue| {
            switch (queue.ack(h_value)) {
                .ok => {},
                // XEP-0198 §4: h above the number sent fails the resume.
                .too_high => {
                    self.sendSmFailed(session, "handled-count-too-high", changes);
                    return;
                },
                // A backwards report means the client lost track of what it
                // already acked; replaying would redeliver stanzas it
                // processed (S24).
                .backwards => {
                    self.sendSmFailed(session, "unexpected-request", changes);
                    return;
                },
            }
        }

        // Snapshot local MUC occupancies (T177): the detached slot is torn
        // down below, so the room list must be captured now. Slices point
        // into Room structs, which stay alive across this handler.
        var move_rooms_buf: [sm_handoff.MAX_BUNDLE_ROOMS][]const u8 = undefined;
        var move_room_count: usize = 0;
        if (self.room_registry) |reg| {
            for (&reg.rooms) |*rslot| {
                const room = rslot.* orelse continue;
                if (!room.active) continue;
                for (&room.occupants) |*occ_slot| {
                    const occ = occ_slot.* orelse continue;
                    if (occ.worker_id == self.worker_id and occ.session_id == detached_id) {
                        if (move_room_count >= move_rooms_buf.len) {
                            log.warn("SM resume: session occupies more than {d} rooms — remaining occupancies will not migrate", .{sm_handoff.MAX_BUNDLE_ROOMS});
                            break;
                        }
                        move_rooms_buf[move_room_count] = room.getJid();
                        move_room_count += 1;
                    }
                }
            }
        }

        // Transfer resumed state to the current session
        session.sm_enabled = true;
        session.sm_in_h = detached.sm_in_h;
        session.sm_out_h = h_value;
        session.sm_out_seq = detached.sm_out_seq;
        session.sm_resume_enabled = detached.sm_resume_enabled;
        session.sm_id = detached.sm_id;
        session.sm_id_len = detached.sm_id_len;
        session.sm_unacked = detached.sm_unacked;
        detached.sm_unacked = null; // Ownership transferred

        // Transfer XMPP session state — copy JID strings into session-owned buffers
        // because the detached session's buffers will be freed below.
        const d_username_len = detached.auth_username_len;
        @memcpy(session.auth_username_buf[0..d_username_len], detached.auth_username_buf[0..d_username_len]);
        session.auth_username_len = d_username_len;
        // Resource from the detached bound JID, not the bind accumulator:
        // bind_resource_len is reset to 0 after a successful bind dispatch
        // (parser accumulator reuse), but bound_jid.resource keeps pointing at
        // the buffer's still-intact contents.
        const d_resource_len = detached_jid.resource.len;
        @memcpy(session.bind_resource_buf[0..d_resource_len], detached_jid.resource);
        session.bind_resource_len = d_resource_len;
        session.stream.bound_jid = .{
            .local = session.auth_username_buf[0..d_username_len],
            .domain = self.server_host,
            .resource = session.bind_resource_buf[0..d_resource_len],
        };
        session.stream.authenticated_jid = .{
            .local = session.auth_username_buf[0..d_username_len],
            .domain = self.server_host,
        };
        session.stream.authenticated = true;
        session.stream.state = .active;
        session.roster_interested = detached.roster_interested;
        session.carbons_enabled = detached.carbons_enabled;
        @memcpy(
            session.last_presence_inner[0..detached.last_presence_inner_len],
            detached.last_presence_inner[0..detached.last_presence_inner_len],
        );
        session.last_presence_inner_len = detached.last_presence_inner_len;

        // Re-bind in session map: unbind old slot, bind new slot with same JID
        var bound_generation: ?u32 = null;
        if (self.session_map) |sm| {
            _ = sm.unbind(detached_jid.local, detached_jid.domain, detached_jid.resource);
            if (sm.bind(self.worker_id, @intCast(session.conn.id), detached_jid.local, detached_jid.domain, detached_jid.resource)) |gen| {
                bound_generation = gen;
            } else |err| {
                log.err("SM resume: session_map re-bind failed for {s}@{s}/{s}: {}", .{
                    detached_jid.local, detached_jid.domain, detached_jid.resource, err,
                });
            }
        }

        // Clean up detached session bookkeeping before destroying
        if (self.detached_count > 0) self.detached_count -= 1;
        self.smIdMapRemove(detached.sm_id[0..detached.sm_id_len]);
        self.smRedirectDrop(previd); // session lives here again

        // Destroy the detached session (slot freed for reuse)
        detached.sm_resume_enabled = false; // Prevent re-detach
        detached.deinit();
        self.allocator.destroy(detached);
        self.sessions[detached_id] = null;

        // Return detached slot to free-list
        if (self.free_count < self.free_ids.len) {
            self.free_ids[self.free_count] = detached_id;
            self.free_count += 1;
        }

        // T177 occupant migration: replay the room moves before <resumed/> —
        // the detached slot was just destroyed, so every room record pointing
        // at it is stale until moved. Doing this before the client learns of
        // the resume guarantees its post-resume traffic is ordered after the
        // moves. Same-worker moves apply in place on the owning worker
        // (possibly remote); roomOwner == self applies synchronously.
        if (move_room_count > 0) {
            if (bound_generation) |gen| {
                self.replayOccupantMoves(session, move_rooms_buf[0..move_room_count], gen, self.worker_id);
            } else {
                log.warn("connection {d} resumed with {d} MUC rooms but no session-map generation — occupant moves skipped", .{
                    session.conn.id, move_room_count,
                });
            }
        }

        // Send <resumed/> to the client
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        w.writeAll("<resumed xmlns='urn:xmpp:sm:3' h='") catch return;
        std.fmt.format(w, "{d}", .{session.sm_in_h}) catch return;
        w.writeAll("' previd='") catch return;
        w.writeAll(session.sm_id[0..session.sm_id_len]) catch return;
        w.writeAll("'/>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;

        // Replay unacked stanzas
        if (session.sm_unacked) |queue| {
            var iter = queue.getUnacked();
            while (iter.next()) |stanza| {
                session.conn.queueSend(stanza) catch break;
            }
        }

        if (session.conn.hasPendingWrite()) {
            _ = session.conn.flushSend() catch {};
            if (session.conn.hasPendingWrite()) {
                changes.addWrite(session.conn.fd, session.conn.id) catch {};
            }
        }

        log.info("connection {d} session resumed (id={s}, replayed {d} stanzas, {d} rooms)", .{
            session.conn.id,
            session.sm_id[0..session.sm_id_len],
            if (session.sm_unacked) |q| q.pending() else 0,
            move_room_count,
        });
    }

    /// T177 step 1 — requesting worker. Park the resuming session and ask the
    /// owning worker (decoded from the SM-ID prefix) to hand off the detached
    /// session's state. Nothing is sent to the client until the reply arrives.
    fn startCrossWorkerResume(self: *Server, session: *Session, previd: []const u8, h_value: u32, owner: u16, changes: *ChangeList) void {
        const auth_jid = session.stream.authenticated_jid orelse {
            self.sendSmFailed(session, "not-authorized", changes);
            return;
        };
        if (session.sm_resume_pending) {
            self.sendSmFailed(session, "unexpected-request", changes);
            return;
        }

        session.sm_resume_pending = true;
        session.sm_resume_epoch +%= 1;
        @memcpy(&session.sm_resume_previd, previd[0..sm_state.SM_ID_HEX_LEN]);

        log.info("connection {d} cross-worker SM resume: previd={s} owned by worker {d}", .{
            session.conn.id, previd, owner,
        });

        self.enqueueSmActor(owner, .{ .sm_resume_request = .{
            .previd = previd,
            .h = h_value,
            .req_worker = self.worker_id,
            .req_session = @intCast(session.conn.id),
            .req_epoch = session.sm_resume_epoch,
            .auth_local = auth_jid.local,
            .auth_domain = auth_jid.domain,
        } }) catch |err| {
            log.warn("cross-worker SM resume: enqueue to worker {d} failed: {}", .{ owner, err });
            session.sm_resume_pending = false;
            self.sendSmFailed(session, "item-not-found", changes);
        };
    }

    /// T177 step 2 — owning worker. Validate, snapshot the detached session
    /// into the handoff store, dismantle the slot, reply.
    ///
    /// Runs on this worker's MPSC drain, after any stanza deliveries that were
    /// queued to the detached slot ahead of this request, so the snapshot
    /// includes them. Stanzas arriving after the unbind fall to the offline
    /// path until the requesting worker re-binds (known micro-window).
    fn handleSmResumeRequest(self: *Server, req: actor_message.SmResumeRequest) void {
        const fail = struct {
            fn send(server: *Server, r: actor_message.SmResumeRequest, status: []const u8, why: []const u8) void {
                log.info("cross-worker SM resume handoff for {s} rejected: {s}", .{ r.previd, why });
                server.enqueueSmActor(r.req_worker, .{ .sm_resume_reply = .{
                    .previd = r.previd,
                    .req_session = r.req_session,
                    .req_epoch = r.req_epoch,
                    .status = status,
                } }) catch {};
            }
        }.send;

        const detached_id = self.findDetachedSession(req.previd) orelse {
            // T177: this worker handed the session off earlier — follow the
            // breadcrumb, preserving the original requester addressing.
            if (req.hops < MAX_SM_REDIRECT_HOPS) {
                if (self.smRedirectLookup(req.previd)) |target| {
                    if (target != self.worker_id and target < self.getWorkerCount()) {
                        log.info("cross-worker SM resume: {s} relocated to worker {d}, forwarding (hop {d})", .{
                            req.previd, target, req.hops + 1,
                        });
                        var fwd = req;
                        fwd.hops += 1;
                        self.enqueueSmActor(target, .{ .sm_resume_request = fwd }) catch
                            return fail(self, req, "item-not-found", "redirect forward failed");
                        return;
                    }
                }
            }
            return fail(self, req, "item-not-found", "no such detached session");
        };
        const detached = self.sessions[detached_id] orelse
            return fail(self, req, "item-not-found", "slot empty");

        if (detached.sm_overflow)
            return fail(self, req, "item-not-found", "unacked queue overflowed");
        if (std.time.timestamp() - detached.sm_detach_time > sm_state.DEFAULT_RESUME_TIMEOUT)
            return fail(self, req, "item-not-found", "resume window expired");
        if (detached.sm_detached == false)
            return fail(self, req, "unexpected-request", "session not detached");

        const dj = detached.stream.bound_jid orelse
            return fail(self, req, "item-not-found", "no bound JID");
        if (!std.mem.eql(u8, dj.local, req.auth_local) or !std.mem.eql(u8, dj.domain, req.auth_domain))
            return fail(self, req, "not-authorized", "JID mismatch");

        // T177 occupant migration: MUC-occupying sessions are now handoff-
        // eligible — the bundle carries the room list and the requesting
        // worker replays occupant moves after it re-binds.

        if (detached.sm_unacked) |q| {
            switch (q.ack(req.h)) {
                .ok => {},
                .too_high => return fail(self, req, "handled-count-too-high", "h above sent count"),
                .backwards => return fail(self, req, "unexpected-request", "h moved backwards"),
            }
        }

        const bundle = sm_handoff.allocator.create(sm_handoff.ResumeBundle) catch
            return fail(self, req, "item-not-found", "bundle alloc failed");
        bundle.* = .{
            .previd = undefined,
            .sm_in_h = detached.sm_in_h,
            .sm_out_seq = detached.sm_out_seq,
            .sm_out_h = req.h,
            .r_outstanding = detached.sm_r_outstanding,
            .roster_interested = detached.roster_interested,
            .carbons_enabled = detached.carbons_enabled,
            .csi_active = detached.csi_active,
            .username = sm_handoff.allocator.dupe(u8, detached.auth_username_buf[0..detached.auth_username_len]) catch {
                sm_handoff.allocator.destroy(bundle);
                return fail(self, req, "item-not-found", "bundle alloc failed");
            },
            .resource = sm_handoff.allocator.dupe(u8, dj.resource) catch {
                sm_handoff.allocator.free(bundle.username);
                sm_handoff.allocator.destroy(bundle);
                return fail(self, req, "item-not-found", "bundle alloc failed");
            },
            .last_presence = sm_handoff.allocator.dupe(u8, detached.last_presence_inner[0..detached.last_presence_inner_len]) catch {
                sm_handoff.allocator.free(bundle.resource);
                sm_handoff.allocator.free(bundle.username);
                sm_handoff.allocator.destroy(bundle);
                return fail(self, req, "item-not-found", "bundle alloc failed");
            },
            .base_seq = if (detached.sm_unacked) |q| q.base_seq else 1,
            .last_h = if (detached.sm_unacked) |q| q.last_h else 0,
            .created = std.time.timestamp(),
        };
        @memcpy(&bundle.previd, req.previd[0..sm_state.SM_ID_HEX_LEN]);

        if (detached.sm_unacked) |q| {
            var iter = q.getUnacked();
            while (iter.next()) |stanza| {
                const copy = sm_handoff.allocator.dupe(u8, stanza) catch {
                    bundle.deinit();
                    sm_handoff.allocator.destroy(bundle);
                    return fail(self, req, "item-not-found", "bundle alloc failed");
                };
                bundle.stanzas.append(sm_handoff.allocator, copy) catch {
                    sm_handoff.allocator.free(copy);
                    bundle.deinit();
                    sm_handoff.allocator.destroy(bundle);
                    return fail(self, req, "item-not-found", "bundle alloc failed");
                };
            }
        }

        // Snapshot the detached session's MUC occupancies into the bundle.
        // Over the cap: refuse the handoff (full re-bind + rejoin fallback,
        // the pre-migration behavior).
        if (!self.gatherSessionRooms(self.worker_id, detached_id, bundle)) {
            bundle.deinit();
            sm_handoff.allocator.destroy(bundle);
            return fail(self, req, "item-not-found", "occupancy exceeds migration cap");
        }

        sm_handoff.put(req.previd, bundle) catch {
            bundle.deinit();
            sm_handoff.allocator.destroy(bundle);
            self.enqueueSmActor(req.req_worker, .{ .sm_resume_reply = .{
                .previd = req.previd,
                .req_session = req.req_session,
                .req_epoch = req.req_epoch,
                .status = "item-not-found",
            } }) catch {};
            return;
        };

        // Dismantle the detached slot: same teardown as a successful local
        // resume (session-map unbind, sm-id map removal, free the slot).
        // MUC occupant records are deliberately LEFT in place — occupancy is
        // keyed by the full JID, which survives the move; the requesting
        // worker replays occupant moves to retarget each record's
        // (worker, session, generation) triple.
        if (self.session_map) |sm| {
            _ = sm.unbind(dj.local, dj.domain, dj.resource);
        }
        if (self.detached_count > 0) self.detached_count -= 1;
        self.smIdMapRemove(detached.sm_id[0..detached.sm_id_len]);
        detached.sm_resume_enabled = false; // Prevent re-detach
        detached.deinit();
        self.allocator.destroy(detached);
        self.sessions[detached_id] = null;
        if (self.free_count < self.free_ids.len) {
            self.free_ids[self.free_count] = detached_id;
            self.free_count += 1;
        }

        // Breadcrumb: the SM-ID prefix still names THIS worker; a repeat
        // resume of the relocated session must find worker req.req_worker.
        self.smRedirectNote(req.previd, req.req_worker);

        log.info("cross-worker SM resume: handed off {s} to worker {d} ({d} stanzas, {d} rooms)", .{
            req.previd, req.req_worker, bundle.stanzas.items.len, bundle.rooms.items.len,
        });

        self.enqueueSmActor(req.req_worker, .{ .sm_resume_reply = .{
            .previd = req.previd,
            .req_session = req.req_session,
            .req_epoch = req.req_epoch,
            .status = "ok",
        } }) catch |err| {
            log.warn("cross-worker SM resume: reply to worker {d} failed: {}", .{ req.req_worker, err });
        };
    }

    /// T177 step 3 — requesting worker. Apply the handed-off state to the
    /// parked session, re-bind it in the session map, send <resumed/> and
    /// replay. The epoch check makes stale replies to a reused slot harmless.
    fn handleSmResumeReply(self: *Server, rep: actor_message.SmResumeReply, changes: *ChangeList) void {
        const session = self.sessions[rep.req_session] orelse {
            // Requesting connection is gone — drop any parked bundle.
            if (sm_handoff.take(rep.previd)) |orphan| sm_handoff.release(orphan);
            return;
        };

        if (!session.sm_resume_pending or
            session.sm_resume_epoch != rep.req_epoch or
            !std.mem.eql(u8, session.sm_resume_previd[0..], rep.previd))
        {
            log.warn("cross-worker SM resume: stale reply for {s} ignored", .{rep.previd});
            if (std.mem.eql(u8, rep.status, "ok")) {
                if (sm_handoff.take(rep.previd)) |orphan| sm_handoff.release(orphan);
            }
            return;
        }
        session.sm_resume_pending = false;

        if (!std.mem.eql(u8, rep.status, "ok")) {
            log.info("connection {d} cross-worker SM resume failed: {s}", .{ session.conn.id, rep.status });
            self.sendSmFailed(session, rep.status, changes);
            return;
        }

        const bundle = sm_handoff.take(rep.previd) orelse {
            self.sendSmFailed(session, "item-not-found", changes);
            return;
        };
        defer sm_handoff.release(bundle);
        self.smRedirectDrop(rep.previd); // session lives here again

        // Rebuild the unacked queue on this worker's allocator.
        const queue = self.allocator.create(sm_state.SmUnackedQueue) catch {
            self.sendSmFailed(session, "item-not-found", changes);
            return;
        };
        queue.* = sm_state.SmUnackedQueue.init(self.allocator);
        queue.base_seq = bundle.base_seq;
        queue.last_h = bundle.last_h;
        var replay_count: u32 = 0;
        for (bundle.stanzas.items) |stanza| {
            switch (queue.push(stanza)) {
                .pushed => replay_count += 1,
                else => {
                    // Source was already ack-trimmed and bounded by
                    // UNACKED_CAPACITY — an overflow here means corruption.
                    log.err("cross-worker SM resume: rebuilt queue overflow", .{});
                    queue.deinit();
                    self.allocator.destroy(queue);
                    self.sendSmFailed(session, "item-not-found", changes);
                    return;
                },
            }
        }

        session.sm_enabled = true;
        session.sm_in_h = bundle.sm_in_h;
        session.sm_out_h = bundle.sm_out_h;
        session.sm_out_seq = bundle.sm_out_seq;
        session.sm_r_outstanding = bundle.r_outstanding;
        session.sm_resume_enabled = true;
        @memcpy(&session.sm_id, &bundle.previd);
        session.sm_id_len = sm_state.SM_ID_HEX_LEN;
        session.sm_unacked = queue;

        @memcpy(session.auth_username_buf[0..bundle.username.len], bundle.username);
        session.auth_username_len = bundle.username.len;
        @memcpy(session.bind_resource_buf[0..bundle.resource.len], bundle.resource);
        session.bind_resource_len = bundle.resource.len;
        session.stream.bound_jid = .{
            .local = session.auth_username_buf[0..session.auth_username_len],
            .domain = self.server_host,
            .resource = session.bind_resource_buf[0..session.bind_resource_len],
        };
        session.stream.authenticated_jid = .{
            .local = session.auth_username_buf[0..session.auth_username_len],
            .domain = self.server_host,
        };
        session.stream.authenticated = true;
        session.stream.state = .active;
        session.roster_interested = bundle.roster_interested;
        session.carbons_enabled = bundle.carbons_enabled;
        session.csi_active = bundle.csi_active;
        @memcpy(session.last_presence_inner[0..bundle.last_presence.len], bundle.last_presence);
        session.last_presence_inner_len = bundle.last_presence.len;

        var bound_generation: ?u32 = null;
        if (self.session_map) |sm| {
            if (sm.bind(self.worker_id, @intCast(session.conn.id), bundle.username, self.server_host, bundle.resource)) |gen| {
                bound_generation = gen;
            } else |err| {
                log.err("cross-worker SM resume: session_map bind failed for {s}@{s}/{s}: {}", .{
                    bundle.username, self.server_host, bundle.resource, err,
                });
            }
        }

        // T177 occupant migration: replay room moves before <resumed/> — SM
        // state applied, SessionMap bind done (generation known); the client
        // has not been told yet, so its post-resume traffic is ordered after
        // the moves. Old worker identity comes from the SM-ID prefix.
        if (bundle.rooms.items.len > 0) {
            if (bound_generation) |gen| {
                const old_worker = sm_state.workerIdFromSmId(&bundle.previd) orelse self.worker_id;
                self.replayOccupantMoves(session, bundle.rooms.items, gen, old_worker);
            } else {
                log.warn("connection {d} resumed with {d} MUC rooms but no session-map generation — occupant moves skipped (client should MAM/rejoin)", .{
                    session.conn.id, bundle.rooms.items.len,
                });
            }
        }

        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        w.writeAll("<resumed xmlns='urn:xmpp:sm:3' h='") catch return;
        std.fmt.format(w, "{d}", .{session.sm_in_h}) catch return;
        w.writeAll("' previd='") catch return;
        w.writeAll(session.sm_id[0..session.sm_id_len]) catch return;
        w.writeAll("'/>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;

        if (session.sm_unacked) |q| {
            var iter = q.getUnacked();
            while (iter.next()) |stanza| {
                session.conn.queueSend(stanza) catch break;
            }
        }

        if (session.conn.hasPendingWrite()) {
            _ = session.conn.flushSend() catch {};
            if (session.conn.hasPendingWrite()) {
                changes.addWrite(session.conn.fd, session.conn.id) catch {};
            }
        }

        log.info("connection {d} cross-worker session resumed (id={s}, replayed {d} stanzas, {d} rooms)", .{
            session.conn.id,
            session.sm_id[0..session.sm_id_len],
            replay_count,
            bundle.rooms.items.len,
        });
    }

    /// Dispatch an SM-handoff/session actor message (MPSC, SM_ACTOR_SENTINEL).
    /// Covers the T177 resume handoff pair and the T154 session_kick pair.
    fn handleSmActorMessage(self: *Server, payload: []const u8, changes: *ChangeList) void {
        const msg = actor_message.decode(payload) orelse {
            log.warn("malformed SM actor message ({d} bytes)", .{payload.len});
            return;
        };
        switch (msg) {
            .sm_resume_request => |ev| self.handleSmResumeRequest(ev),
            .sm_resume_reply => |ev| self.handleSmResumeReply(ev, changes),
            .session_kick_request => |ev| self.handleSessionKickRequest(ev, changes),
            .session_kick_reply => |ev| self.handleSessionKickReply(ev, changes),
            else => log.warn("unexpected tag in SM actor dispatch: 0x{x:0>2}", .{msg.tag()}),
        }
    }

    /// T154 step 1 — requesting worker. The bind hit AlreadyBound against a
    /// session owned by `owner`; park the bind and ask that worker to evict.
    /// Returns false when the kick couldn't even be armed (caller falls back
    /// to conflict + close).
    pub fn startSessionKick(self: *Server, session: *Session, local: []const u8, domain: []const u8, resource: []const u8, owner: u16, changes: *ChangeList) bool {
        _ = changes;
        if (session.bind_kick_pending) return false;
        if (session.bind_kick_rounds >= session_lifecycle.MAX_BIND_KICK_ROUNDS) return false;
        if (resource.len > session.bind_kick_resource_buf.len) return false;

        session.bind_kick_pending = true;
        session.bind_kick_epoch +%= 1;
        session.bind_kick_rounds += 1;
        @memcpy(session.bind_kick_resource_buf[0..resource.len], resource);
        session.bind_kick_resource_len = @intCast(resource.len);

        self.enqueueSmActor(owner, .{ .session_kick_request = .{
            .local = local,
            .domain = domain,
            .resource = resource,
            .req_worker = self.worker_id,
            .req_session = @intCast(session.conn.id),
            .req_epoch = session.bind_kick_epoch,
        } }) catch |err| {
            log.warn("session_kick to worker {d} failed to enqueue: {}", .{ owner, err });
            session.bind_kick_pending = false;
            return false;
        };
        log.info("connection {d} bind parked: kicking {s}@{s}/{s} on worker {d} (round {d})", .{
            session.conn.id, local, domain, resource, owner, session.bind_kick_rounds,
        });
        return true;
    }

    /// T154 step 2 — holding worker. Destroy the session owning the full JID
    /// (RFC 6120 §7.7.3 conflict), then confirm. The destroySession teardown
    /// removes the session-map entry, so the requester's retry bind succeeds.
    fn handleSessionKickRequest(self: *Server, req: actor_message.SessionKickRequest, changes: *ChangeList) void {
        if (self.session_map) |sm| {
            if (sm.findByFullJid(req.local, req.domain, req.resource)) |entry| {
                if (entry.worker_id == self.worker_id) {
                    const old_id: usize = @intCast(entry.local_session_id);
                    if (self.sessions[old_id]) |old| {
                        log.warn("session {d} evicted: resource {s}@{s}/{s} taken by worker {d}", .{
                            old_id, req.local, req.domain, req.resource, req.req_worker,
                        });
                        self.sendStreamError(old, .conflict);
                        old.conn.flushSync(); // deliver the conflict before teardown closes the fd
                        session_lifecycle.forceCloseSession(self, old_id, changes);
                    } else {
                        // Dangling entry with no session — just drop it.
                        _ = sm.unbind(req.local, req.domain, req.resource);
                    }
                }
            }
        }

        self.enqueueSmActor(req.req_worker, .{ .session_kick_reply = .{
            .req_session = req.req_session,
            .req_epoch = req.req_epoch,
        } }) catch |err| {
            log.warn("session_kick reply to worker {d} failed: {}", .{ req.req_worker, err });
        };
    }

    /// T154 step 3 — requesting worker. Epoch-guarded, then retry the bind.
    fn handleSessionKickReply(self: *Server, rep: actor_message.SessionKickReply, changes: *ChangeList) void {
        const session = self.sessions[rep.req_session] orelse return;

        if (!session.bind_kick_pending or session.bind_kick_epoch != rep.req_epoch) {
            log.warn("stale session_kick reply for conn {d} ignored", .{rep.req_session});
            return;
        }
        session.bind_kick_pending = false;

        session_lifecycle.completeBindAfterKick(self, session, changes);
    }

    /// Encode an actor message and enqueue it to a target worker's MPSC queue
    /// under the SM handoff sentinel.
    fn enqueueSmActor(self: *Server, target_worker: u16, msg: actor_message.Message) !void {
        const ds = self.delivery_system orelse return error.NoDeliverySystem;
        var buf: [actor_message.MAX_ENCODED_SIZE]u8 = undefined;
        const len = actor_message.encode(&buf, msg) orelse return error.EncodeFailed;
        try ds.deliver(target_worker, delivery_queue_mod.SM_ACTOR_SENTINEL, 0, buf[0..len]);
    }

    /// Append the JIDs of every MUC room the given session occupies into the
    /// bundle (T177 occupant migration). Every worker's registry carries
    /// occupant records for its own sessions — canonical records for rooms it
    /// owns, shadow copies for rooms owned elsewhere — so a local scan sees
    /// all of them. Only the room JID is bundled: the canonical record on the
    /// room's owning worker keeps the authoritative nick/role/affiliation and
    /// is updated in place by the occupant move. Returns false on alloc
    /// failure or when occupancy exceeds sm_handoff.MAX_BUNDLE_ROOMS (the
    /// caller then falls back to a full re-bind).
    fn gatherSessionRooms(self: *Server, worker_id: u16, session_id: usize, bundle: *sm_handoff.ResumeBundle) bool {
        const reg = self.room_registry orelse return true;
        for (&reg.rooms) |*slot| {
            const room = slot.* orelse continue;
            if (!room.active) continue;
            for (&room.occupants) |*occ_slot| {
                const occ = occ_slot.* orelse continue;
                if (occ.worker_id != worker_id or occ.session_id != session_id) continue;
                if (bundle.rooms.items.len >= sm_handoff.MAX_BUNDLE_ROOMS) return false;
                const copy = sm_handoff.allocator.dupe(u8, room.getJid()) catch return false;
                bundle.rooms.append(sm_handoff.allocator, copy) catch {
                    sm_handoff.allocator.free(copy);
                    return false;
                };
            }
        }
        return true;
    }

    /// T177: replay occupant moves for a successfully resumed session — one
    /// per room's owning worker, which updates the canonical record (and
    /// shadow copies) to the new (worker, session, generation) without any
    /// presence fan-out.
    ///
    /// Ordering: runs after the SessionMap bind (generation known) and before
    /// <resumed/> reaches the client, so traffic the client sends after the
    /// resume is always ordered behind the moves. Rooms owned by THIS worker
    /// are applied synchronously — an async hop would let same-batch room
    /// traffic (a groupchat from another client read in the same kevent
    /// batch) see the pre-move triple and drop the stanza on the stale slot.
    ///
    /// If the resumed connection dies before or while these apply,
    /// destroySession's session_closed broadcast removes the occupant by
    /// full JID everywhere — no ghost occupancy.
    fn replayOccupantMoves(self: *Server, session: *Session, room_jids: []const []const u8, generation: u32, old_worker: u16) void {
        const bound = session.stream.bound_jid orelse return;
        var jid_buf: [320]u8 = undefined;
        var jid_fbs = std.io.fixedBufferStream(&jid_buf);
        const jw = jid_fbs.writer();
        jw.writeAll(bound.local) catch return;
        jw.writeByte('@') catch return;
        jw.writeAll(bound.domain) catch return;
        jw.writeByte('/') catch return;
        jw.writeAll(bound.resource) catch return;
        const real_jid = jid_fbs.getWritten();

        for (room_jids) |room_jid| {
            const move = actor_message.RoomOccupantMove{
                .room_jid = room_jid,
                .real_jid = real_jid,
                .old_worker_id = old_worker,
                .new_worker_id = self.worker_id,
                .new_session_id = @intCast(session.conn.id),
                .new_generation = generation,
            };
            const owner = room_registry_mod.roomOwner(room_jid, self.getWorkerCount());
            if (owner == self.worker_id) {
                muc_handler.handleOccupantMove(self, move);
            } else {
                self.enqueueRoomActorMessage(owner, .{ .room_occupant_move = move });
            }
        }
    }

    /// XEP-0198 §3: an <a/> whose handled-count is malformed or above the
    /// number of stanzas sent fails the stream (S24). A parseable but too-high
    /// `h` is echoed with the count sent (XEP-0198 Example 17); a malformed `h`
    /// cannot be echoed, so the optional attributes are omitted.
    fn sendSmHandledCountError(self: *Server, session: *Session, h: ?u32, changes: *ChangeList) void {
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        w.writeAll("<stream:error><undefined-condition xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>" ++
            "<handled-count-too-high xmlns='urn:xmpp:sm:3'") catch return;
        if (h) |v| {
            w.print(" h='{d}' send-count='{d}'", .{ v, session.sm_out_seq }) catch return;
        }
        w.writeAll("/></stream:error>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
        session.conn.flushSync();
        session_lifecycle.forceCloseSession(self, session.conn.id, changes);
    }

    /// Send SM <failed/> with a specific error condition.
    fn sendSmFailed(self: *Server, session: *Session, condition: []const u8, changes: *ChangeList) void {
        _ = self;
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        w.writeAll("<failed xmlns='urn:xmpp:sm:3'><") catch return;
        w.writeAll(condition) catch return;
        // handled-count-too-high lives in the SM namespace (XEP-0198 §4),
        // the failure conditions in the stanza namespace.
        const ns = if (std.mem.eql(u8, condition, "handled-count-too-high"))
            "urn:xmpp:sm:3"
        else
            "urn:ietf:params:xml:ns:xmpp-stanzas";
        w.writeAll(" xmlns='") catch return;
        w.writeAll(ns) catch return;
        w.writeAll("'/></failed>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
        if (session.conn.hasPendingWrite()) {
            _ = session.conn.flushSend() catch {};
            if (session.conn.hasPendingWrite()) {
                changes.addWrite(session.conn.fd, session.conn.id) catch {};
            }
        }
    }

    /// Find a detached session by SM-ID. O(1) via hash map (T127).
    fn findDetachedSession(self: *Server, sm_id: []const u8) ?usize {
        if (sm_id.len != sm_state.SM_ID_HEX_LEN) return null;
        var key: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
        @memcpy(&key, sm_id[0..sm_state.SM_ID_HEX_LEN]);
        return self.sm_id_map.get(key);
    }

    /// Insert an SM-ID → slot mapping.
    pub fn smIdMapInsert(self: *Server, sm_id: []const u8, slot: usize) void {
        if (sm_id.len != sm_state.SM_ID_HEX_LEN) return;
        var key: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
        @memcpy(&key, sm_id[0..sm_state.SM_ID_HEX_LEN]);
        self.sm_id_map.put(self.allocator, key, slot) catch |err| {
            // An SM-ID that is not findable loses its resume capability.
            log.err("SM-ID map insert failed ({}): detached sessions become unresumable", .{err});
        };
    }

    /// Remove an SM-ID from the map.
    pub fn smIdMapRemove(self: *Server, sm_id: []const u8) void {
        if (sm_id.len != sm_state.SM_ID_HEX_LEN) return;
        var key: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
        @memcpy(&key, sm_id[0..sm_state.SM_ID_HEX_LEN]);
        _ = self.sm_id_map.remove(key);
    }

    /// T177: record that previd's session moved to `worker` (cross-worker
    /// handoff on this worker). Breadcrumbs expire with the SM resume window;
    /// a full map evicts the oldest entry.
    fn smRedirectNote(self: *Server, previd: []const u8, worker: u16) void {
        if (previd.len != sm_state.SM_ID_HEX_LEN) return;
        var key: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
        @memcpy(&key, previd);
        const now = std.time.timestamp();
        self.smRedirectsPurgeExpired(now);
        if (self.sm_redirects.count() >= MAX_SM_REDIRECTS and !self.sm_redirects.contains(key)) {
            var oldest_key: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
            var oldest_ts: i64 = std.math.maxInt(i64);
            var found = false;
            var it = self.sm_redirects.iterator();
            while (it.next()) |kv| {
                if (kv.value_ptr.moved_at < oldest_ts) {
                    oldest_ts = kv.value_ptr.moved_at;
                    oldest_key = kv.key_ptr.*;
                    found = true;
                }
            }
            if (found) _ = self.sm_redirects.remove(oldest_key);
        }
        self.sm_redirects.put(self.allocator, key, .{ .worker = worker, .moved_at = now }) catch {};
    }

    /// Where did previd's session go? null if unknown/expired.
    fn smRedirectLookup(self: *Server, previd: []const u8) ?u16 {
        if (previd.len != sm_state.SM_ID_HEX_LEN) return null;
        var key: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
        @memcpy(&key, previd);
        const entry = self.sm_redirects.getPtr(key) orelse return null;
        if (std.time.timestamp() - entry.moved_at > sm_state.DEFAULT_RESUME_TIMEOUT) {
            _ = self.sm_redirects.remove(key);
            return null;
        }
        return entry.worker;
    }

    /// Drop a redirect for previd (session resumed or destroyed here).
    fn smRedirectDrop(self: *Server, previd: []const u8) void {
        if (previd.len != sm_state.SM_ID_HEX_LEN) return;
        var key: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
        @memcpy(&key, previd);
        _ = self.sm_redirects.remove(key);
    }

    fn smRedirectsPurgeExpired(self: *Server, now: i64) void {
        var stale: [16][sm_state.SM_ID_HEX_LEN]u8 = undefined;
        var stale_count: usize = 0;
        var it = self.sm_redirects.iterator();
        while (it.next()) |kv| {
            if (now - kv.value_ptr.moved_at > sm_state.DEFAULT_RESUME_TIMEOUT) {
                if (stale_count < stale.len) {
                    stale[stale_count] = kv.key_ptr.*;
                    stale_count += 1;
                }
            }
        }
        for (stale[0..stale_count]) |key| _ = self.sm_redirects.remove(key);
    }

    /// Handle <r xmlns='urn:xmpp:sm:3'/> — respond with server's inbound h value.
    /// Flushes immediately to avoid latency from changelist-based deferred writes.
    fn handleSmRequest(self: *Server, session: *Session, changes: *ChangeList) void {
        _ = self;
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        w.writeAll("<a xmlns='urn:xmpp:sm:3' h='") catch return;
        std.fmt.format(w, "{d}", .{session.sm_in_h}) catch return;
        w.writeAll("'/>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
        // Attempt immediate flush — SM acks are latency-critical.
        // If flush leaves pending data (WouldBlock), fall back to kqueue write.
        _ = session.conn.flushSend() catch {};
        if (session.conn.hasPendingWrite()) {
            changes.addWrite(session.conn.fd, session.conn.id) catch {};
        }
    }
};

// ============================================================================
// Base64 helpers for SASL XML payloads
// ============================================================================

/// Re-encode text for XML output. The XML parser decodes entities (&amp; → &),
/// so when serializing parsed content back to XML we must re-encode them.
fn xmlEscapeWrite(writer: anytype, text: []const u8) !void {
    return xml.escapeWrite(writer, text);
}

/// Write a child element opening tag, re-emitting namespace declarations the
/// reader resolved away. Fills the writer until it is out of space, returning
/// the fixed-buffer error so the caller can mark the stanza bad.
fn writeStanzaOpenTag(w: anytype, elem: xml.Element) !void {
    try w.writeByte('<');
    try w.writeAll(elem.name);

    // Reconstruct namespace declaration if element uses a non-default namespace.
    // The reader resolves xmlns declarations into namespace_uri but doesn't
    // include them in the attributes array, so we must re-emit them.
    if (elem.namespace_uri.len > 0 and !std.mem.eql(u8, elem.namespace_uri, xml.ns.client)) {
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
        try xmlEscapeWrite(w, attr.value);
        try w.writeByte('\'');
    }

    if (elem.self_closing) {
        try w.writeAll("/>");
    } else {
        try w.writeByte('>');
    }
}

fn writeStanzaCloseTag(w: anytype, name: []const u8) !void {
    try w.writeAll("</");
    try w.writeAll(name);
    try w.writeByte('>');
}

/// Decode base64 into a fixed buffer. Returns the decoded slice or null on error.
fn b64Decode(input: []const u8, output: []u8) ?[]const u8 {
    if (input.len == 0) return output[0..0];
    const decoder = std.base64.standard.Decoder;
    const upper_bound = decoder.calcSizeUpperBound(input.len) catch return null;
    if (upper_bound > output.len) return null;
    decoder.decode(output[0..upper_bound], input) catch return null;
    // calcSizeUpperBound doesn't account for '=' padding — subtract padding
    // chars to get the actual decoded length.
    var decoded_len = upper_bound;
    if (input[input.len - 1] == '=') decoded_len -= 1;
    if (input.len >= 2 and input[input.len - 2] == '=') decoded_len -= 1;
    return output[0..decoded_len];
}

/// Base64-encode data and write directly to a writer.
fn b64EncodeWrite(writer: anytype, data: []const u8) !void {
    const encoder = std.base64.standard.Encoder;
    var buf: [4096]u8 = undefined;
    const enc_len = encoder.calcSize(data.len);
    if (enc_len > buf.len) return error.BufferTooSmall;
    const encoded = encoder.encode(buf[0..enc_len], data);
    try writer.writeAll(encoded);
}

// ============================================================================
// S2S stanza parsing helpers
// ============================================================================

const StanzaParts = struct {
    is_message: bool,
    is_iq: bool,
    msg_type: []const u8,
    msg_id: []const u8,
    inner_xml: []const u8,
};

/// Extract the inner XML content, type attribute, and id attribute from a
/// complete stanza XML string (e.g., "<message from='a' to='b' type='chat'
/// id='1'><body>hello</body></message>"). Used for S2S offline storage to
/// avoid double-wrapping.
fn extractStanzaParts(stanza: []const u8) StanzaParts {
    var result = StanzaParts{
        .is_message = false,
        .is_iq = false,
        .msg_type = "",
        .msg_id = "",
        .inner_xml = "",
    };

    if (stanza.len < 3 or stanza[0] != '<') return result;

    // Find end of tag name (first space or '>' or '/')
    var i: usize = 1;
    while (i < stanza.len and stanza[i] != ' ' and stanza[i] != '>' and stanza[i] != '/') : (i += 1) {}
    const tag_name = stanza[1..i];
    result.is_message = std.mem.eql(u8, tag_name, "message");
    result.is_iq = std.mem.eql(u8, tag_name, "iq");

    // Find end of opening tag — scan for first '>' that's not inside an attr value
    var in_quote: bool = false;
    var quote_char: u8 = 0;
    var opening_end: usize = 0;
    var self_closing = false;
    var j: usize = i;
    while (j < stanza.len) : (j += 1) {
        if (in_quote) {
            if (stanza[j] == quote_char) in_quote = false;
        } else if (stanza[j] == '\'' or stanza[j] == '"') {
            in_quote = true;
            quote_char = stanza[j];
        } else if (stanza[j] == '>') {
            if (j > 0 and stanza[j - 1] == '/') self_closing = true;
            opening_end = j;
            break;
        }
    }

    if (opening_end == 0) return result;

    // Extract type and id attributes from the opening tag
    const tag_portion = stanza[0 .. opening_end + 1];
    result.msg_type = extractAttrValue(tag_portion, "type");
    result.msg_id = extractAttrValue(tag_portion, "id");

    if (self_closing) {
        result.inner_xml = "";
        return result;
    }

    // Inner XML is everything between '>' of opening tag and '</' of closing tag
    const inner_start = opening_end + 1;

    // Find closing tag: search backwards for "</"
    var k: usize = stanza.len;
    while (k > inner_start + 1) {
        k -= 1;
        if (stanza[k] == '/' and k > 0 and stanza[k - 1] == '<') {
            result.inner_xml = stanza[inner_start .. k - 1];
            return result;
        }
    }

    // No closing tag found — return everything after the opening tag
    result.inner_xml = stanza[inner_start..];
    return result;
}

/// Serialize an S2S service-unavailable bounce. msg_id is the raw on-wire
/// attribute value from extractAttrValue: it is decoded and then escaped once,
/// so an entity in the id is not double-escaped and a quote cannot break the
/// attribute (G7). from/to are plain JIDs and are escaped once. Serialization
/// errors propagate so the caller can log them.
fn writeS2sBounce(w: anytype, local_to: []const u8, remote_from: []const u8, msg_id: []const u8) !void {
    return writeS2sError(w, "message", local_to, remote_from, msg_id);
}

fn writeS2sError(w: anytype, tag_name: []const u8, local_to: []const u8, remote_from: []const u8, stanza_id: []const u8) !void {
    try w.writeByte('<');
    try w.writeAll(tag_name);
    try w.writeAll(" type='error' from='");
    try xml.escapeWrite(w, local_to);
    try w.writeAll("' to='");
    try xml.escapeWrite(w, remote_from);
    try w.writeByte('\'');
    if (stanza_id.len > 0) {
        try w.writeAll(" id='");
        var id_buf: [1024]u8 = undefined;
        var id_fbs = std.io.fixedBufferStream(&id_buf);
        try xml.decodeWrite(id_fbs.writer(), stanza_id);
        try xml.escapeWrite(w, id_fbs.getWritten());
        try w.writeByte('\'');
    }
    try w.writeAll("><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></");
    try w.writeAll(tag_name);
    try w.writeByte('>');
}

/// Extract the value of an attribute from an XML opening tag string.
/// Returns an empty slice if the attribute is not found.
fn extractAttrValue(tag: []const u8, attr_name: []const u8) []const u8 {
    // Search for ' attr_name=' or ' attr_name="'
    var pos: usize = 0;
    while (pos + attr_name.len + 2 < tag.len) {
        if (tag[pos] == ' ' and
            pos + 1 + attr_name.len + 1 < tag.len and
            std.mem.eql(u8, tag[pos + 1 .. pos + 1 + attr_name.len], attr_name) and
            tag[pos + 1 + attr_name.len] == '=')
        {
            const val_start_idx = pos + 1 + attr_name.len + 1;
            if (val_start_idx >= tag.len) return "";
            const quote = tag[val_start_idx];
            if (quote != '\'' and quote != '"') return "";
            const val_start = val_start_idx + 1;
            var val_end = val_start;
            while (val_end < tag.len and tag[val_end] != quote) : (val_end += 1) {}
            return tag[val_start..val_end];
        }
        pos += 1;
    }
    return "";
}

// ============================================================================
// Tests
// ============================================================================

/// Helper: fill the connection's write buffer so it has pending bytes that
/// cannot flush at once (unix socketpairs ignore SO_SNDBUF and buffer 64 KiB).
/// Returns true once something is left queued. Test-only; split so the S15
/// ratchet, which greps for raw sends, counts this one site rather than a
/// copy per test.
fn fillWriteBuffer(session: *Session) bool {
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
fn makeSocketPair() ![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    return fds;
}

test "Server: init and deinit" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    try std.testing.expect(server.listener.fd >= 0);
    try std.testing.expect(server.running);
}
test "Server: S18 scratch banks size to the session map resource cap" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    var sm = SessionMap.init(std.testing.allocator, false, 0);
    defer sm.deinit();
    server.session_map = &sm;

    {
        var lease = server.leaseScratch(.a);
        defer lease.release();
        try std.testing.expectEqual(
            Server.SCRATCH_CHUNK_JIDS * session_map_mod.DEFAULT_MAX_RESOURCES,
            lease.entries.len,
        );
    }
    try std.testing.expectEqual(Server.SCRATCH_CHUNK_JIDS * session_map_mod.DEFAULT_MAX_RESOURCES, server.scratchIdsA().len);
    try std.testing.expectEqual(Server.SCRATCH_CHUNK_JIDS * session_map_mod.DEFAULT_MAX_RESOURCES, server.scratchJidIdxsA().len);
    {
        var lease = server.leaseScratch(.b);
        defer lease.release();
        try std.testing.expectEqual(session_map_mod.DEFAULT_MAX_RESOURCES, lease.entries.len);
    }
    {
        var lease = server.leaseScratch(.c);
        defer lease.release();
        try std.testing.expectEqual(session_map_mod.DEFAULT_MAX_RESOURCES, lease.entries.len);
    }
}

test "Server: S18 byte scratch pool failure uses the heap fallback" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer {
        server.allocator = std.testing.allocator;
        server.deinit();
    }

    var backing: [Server.BYTE_BANK_SIZE * 2]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&backing);
    server.allocator = fixed.allocator();

    var lease = server.leaseByteScratch() orelse return error.ExpectedScratchFallback;
    defer lease.release();
    try std.testing.expect(lease.owned);
    try std.testing.expectEqual(Server.BYTE_BANK_SIZE, lease.buf.len);
    for (server.byte_scratch_in_use) |in_use| try std.testing.expect(!in_use);
}

test "Server: S18 scratch lease release is scoped to the lease" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    var first = server.leaseScratch(.a);
    defer first.release();
    first.release();
    try std.testing.expect(!server.scratch_bank_in_use[0]);

    var second = server.leaseScratch(.a);
    defer second.release();
    try std.testing.expect(server.scratch_bank_in_use[0]);

    first.release();
    try std.testing.expect(server.scratch_bank_in_use[0]);
    try std.testing.expectEqual(@as(usize, 0), first.entries.len);
}

test "Server: S18 byte scratch banks are distinct and reusable" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    // Every bank is handed out separately, so a serializer nested inside
    // another one's live buffer cannot overwrite the outer stanza.
    var a = server.leaseByteScratch().?;
    defer a.release();
    var b = server.leaseByteScratch().?;
    defer b.release();
    var c = server.leaseByteScratch().?;
    defer c.release();

    for ([3]*const Server.ByteLease{ &a, &b, &c }) |lease| {
        try std.testing.expectEqual(Server.BYTE_BANK_SIZE, lease.buf.len);
        try std.testing.expectEqual(false, lease.owned);
    }
    try std.testing.expect(!isOverlapping(a.buf, b.buf));
    try std.testing.expect(!isOverlapping(a.buf, c.buf));
    try std.testing.expect(!isOverlapping(b.buf, c.buf));

    // The block is allocated once and banks are fixed offsets into it, so a
    // lease taken earlier still points at the same bytes.
    const a_ptr = a.buf.ptr;
    const block = server.byte_scratch;
    try std.testing.expectEqual(Server.BYTE_BANK_COUNT * Server.BYTE_BANK_SIZE, block.len);
    try std.testing.expectEqual(@intFromPtr(block.ptr), @intFromPtr(a_ptr));

    // Writes land in the bank that was written, never in a sibling.
    @memset(c.buf, 'C');
    @memset(a.buf, 'A');
    @memset(b.buf, 'B');
    try std.testing.expectEqual(@as(u8, 'C'), c.buf[0]);
    try std.testing.expectEqual(@as(u8, 'A'), a.buf[0]);
    try std.testing.expectEqual(@as(u8, 'B'), b.buf[0]);

    // Exhausting the pool costs an allocation, not the stanza.
    var d = server.leaseByteScratch().?;
    defer d.release();
    try std.testing.expectEqual(true, d.owned);
    try std.testing.expectEqual(Server.BYTE_BANK_SIZE, d.buf.len);
    @memset(d.buf, 'D');
    try std.testing.expectEqual(@as(u8, 'A'), a.buf[1]);

    // A lease released early must not disturb a bank that a later lease has
    // taken over. Releasing `a` frees bank 0, `e` claims it, and `a`'s own
    // deferred release then fires again: bank 0 belongs to `e` and stays
    // claimed. Without the guard a stale release would hand the same bytes to
    // the next lease while `e` is still writing its stanza.
    a.release();
    try std.testing.expectEqual(@as(usize, 0), a.buf.len);
    try std.testing.expectEqual(false, server.byte_scratch_in_use[0]);

    var e = server.leaseByteScratch().?;
    defer e.release();
    try std.testing.expectEqual(false, e.owned);
    try std.testing.expectEqual(0, e.bank);
    @memset(e.buf, 'E');

    a.release();
    try std.testing.expectEqual(true, server.byte_scratch_in_use[0]);
    try std.testing.expectEqual(@as(u8, 'E'), e.buf[0]);

    // The fallback lease is still out, so the reused bank is a pool bank.
    try std.testing.expectEqual(@as(u8, 'D'), d.buf[0]);

    // Releasing the heap fallback repeatedly stays a no-op as well.
    d.release();
    d.release();
    try std.testing.expectEqual(@as(usize, 0), d.buf.len);
}

/// True when two buffers share any byte.
fn isOverlapping(x: []const u8, y: []const u8) bool {
    const xs = @intFromPtr(x.ptr);
    const ys = @intFromPtr(y.ptr);
    return xs < ys + y.len and ys < xs + x.len;
}

test "Server: accept and close session" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    // Get bound port
    var addr: std.c.sockaddr.in = undefined;
    var addr_len: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    _ = std.c.getsockname(server.listener.fd, @ptrCast(&addr), &addr_len);

    // Connect a client
    const client_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(client_fd);

    var connect_addr = std.c.sockaddr.in{
        .port = addr.port,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    posix.connect(client_fd, @ptrCast(&connect_addr), @sizeOf(std.c.sockaddr.in)) catch {};

    std.Thread.sleep(10 * std.time.ns_per_ms);

    // Accept via the server
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    session_lifecycle.acceptConnections(&server, &changes);

    // Should have accepted one connection
    var found: bool = false;
    for (server.sessions) |slot| {
        if (slot != null) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
    try std.testing.expect(changes.count() > 0); // Should have addRead in changelist
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

    server.applyReadBackpressure(session, &changes);
    try std.testing.expect(session.conn.read_suppressed);
    // Expect an EV.DISABLE change for the READ filter on this fd
    var saw_disable = false;
    for (changes.slice()) |ev| {
        if (ev.ident == session.conn.fd and ev.filter == std.c.EVFILT.READ and (ev.flags & std.c.EV.DISABLE) != 0) saw_disable = true;
    }
    try std.testing.expect(saw_disable);

    // Suppression is sticky in the hysteresis band (between LOW and HIGH)
    changes.reset();
    session.conn.write_end = connection_mod.WRITE_SUPPRESS_HIGH - 16;
    server.applyReadBackpressure(session, &changes);
    try std.testing.expect(session.conn.read_suppressed);
    try std.testing.expectEqual(@as(usize, 0), changes.count());

    // Drained at/below low-water: read watch re-enabled
    changes.reset();
    session.conn.write_end = connection_mod.WRITE_SUPPRESS_LOW;
    server.applyReadBackpressure(session, &changes);
    try std.testing.expect(!session.conn.read_suppressed);
    var saw_enable = false;
    for (changes.slice()) |ev| {
        if (ev.ident == session.conn.fd and ev.filter == std.c.EVFILT.READ and (ev.flags & std.c.EV.ENABLE) != 0) saw_enable = true;
    }
    try std.testing.expect(saw_enable);
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
    server.handleReadable(1, &changes);

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
    server.handleReadable(3, &changes);

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
    server.handleReadable(1, &changes);

    // Drain the peer side, then fill the kernel send path (unix pairs
    // buffer 64 KiB and ignore SO_SNDBUF): with the socket full the
    // queued <proceed/> cannot flush at once.
    var drain_buf: [16384]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;
    try std.testing.expect(fillWriteBuffer(session));

    _ = try posix.write(fds[1], "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
    server.handleReadable(1, &changes);

    // Upgrade deferred: FSM is pending but TLS has NOT started.
    try std.testing.expect(session.stream.state == .starttls_pending);
    try std.testing.expect(session.conn.tls_conn == null);
    try std.testing.expect(session.conn.hasPendingWrite());

    // Drain the peer, then let the write-ready handler finish.
    while (posix.read(fds[1], &drain_buf)) |n| {
        if (n == 0) break;
    } else |_| {}
    server.handleWritable(1, &changes);
    try std.testing.expect(!session.conn.hasPendingWrite());

    // Buffer drained: the deferred upgrade has started the handshake.
    try std.testing.expect(session.conn.tls_conn != null);
    try std.testing.expect(session.conn.isTlsHandshaking());
}

test "Server: S28 stale writable event does not destroy a detached session" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;
    defer {
        if (server.sessions[1]) |s| {
            server.sessions[1] = null;
            s.deinit();
            std.testing.allocator.destroy(s);
        }
    }

    // Bytes still buffered: this is the state an SM detach leaves behind, and
    // hasPendingWrite() reporting true here is what armed EVFILT_WRITE.
    // fillWriteBuffer rather than a raw conn.queueSend, which the S15 ratchet
    // deliberately rejects outside its allowlist.
    try std.testing.expect(fillWriteBuffer(session));
    try std.testing.expect(session.conn.write_end > session.conn.write_start);

    // Detach for SM resume: purge the fd, close it, keep the session.
    session.sm_resume_enabled = true;
    session.sm_detached = true;
    session.sm_detach_time = std.time.timestamp();
    session.sm_id_len = sm_state.SM_ID_HEX_LEN;
    const sm_id = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
    @memcpy(&session.sm_id, sm_id);
    server.detached_count = 1;
    server.smIdMapInsert(&session.sm_id, 1);
    session.conn.close();
    try std.testing.expectEqual(@as(posix.fd_t, -1), session.conn.fd);

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // The stale event kevent already returned this batch, for the fd that no
    // longer exists.
    server.handleWritable(1, &changes);

    // The resumable session survives, and the skip was counted rather than
    // silently swallowed.
    try std.testing.expect(server.sessions[1] != null);
    try std.testing.expect(server.sessions[1].?.sm_detached);
    try std.testing.expectEqual(@as(u64, 1), server.stale_event_skips);
    try std.testing.expectEqual(@as(u16, 1), server.detached_count);

    // Same for a stale readable event and a stale error event.
    server.handleReadable(1, &changes);
    try std.testing.expect(server.sessions[1] != null);
    try std.testing.expectEqual(@as(u64, 2), server.stale_event_skips);

    server.handleSessionError(1, &changes);
    try std.testing.expect(server.sessions[1] != null);
    try std.testing.expect(server.sessions[1].?.sm_detached);
    try std.testing.expectEqual(@as(u64, 3), server.stale_event_skips);
    try std.testing.expectEqual(@as(u16, 1), server.detached_count);
}

test "Server: S28 a same-batch kqueue race keeps a detached session resumable" {
    // The real shape of the bug: kevent returns readable and writable for a
    // session fd, the session detaches for SM resume before that batch is
    // dispatched, and the stale events reach the handlers anyway.
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;
    defer {
        if (server.sessions[1]) |s| {
            server.sessions[1] = null;
            s.deinit();
            std.testing.allocator.destroy(s);
        }
    }

    // Arm both filters on the production event loop.
    var change_buf: [32]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    try changes.addRead(session.conn.fd, 1);
    try changes.addWrite(session.conn.fd, 1);

    // Peer data makes the fd readable; a full write buffer keeps it pending.
    _ = try posix.write(fds[1], "<presence/>");
    try std.testing.expect(fillWriteBuffer(session));

    const events = try server.loop.submitAndPoll(changes.slice(), 1000);
    changes.reset();
    try std.testing.expect(events.len > 0);

    // The race window: detach after kevent returned, before dispatch.
    session.sm_resume_enabled = true;
    session.sm_detached = true;
    session.sm_detach_time = std.time.timestamp();
    session.sm_id_len = sm_state.SM_ID_HEX_LEN;
    const sm_id = "b2c3d4e5f60718293a4b5c6d7e8f9001";
    @memcpy(&session.sm_id, sm_id);
    server.detached_count = 1;
    server.smIdMapInsert(&session.sm_id, 1);
    changes.purgeFd(session.conn.fd);
    session.conn.close();

    server.dispatchEvents(events, &changes);

    // The session is still there and still resumable, and the stale events
    // were counted rather than acted on.
    try std.testing.expect(server.sessions[1] != null);
    try std.testing.expect(server.sessions[1].?.sm_detached);
    try std.testing.expect(server.detached_count == 1);
    try std.testing.expect(server.stale_event_skips > 0);
    // A resume can still find it by SM-ID: the stale events left the map alone.
    try std.testing.expectEqual(@as(?usize, 1), server.findDetachedSession(&session.sm_id));
}

test "Server: S28 a stale writable event on a closed live session is skipped" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;
    defer {
        if (server.sessions[1]) |s| {
            server.sessions[1] = null;
            s.deinit();
            std.testing.allocator.destroy(s);
        }
    }

    // Not detached, but closed: the fd is already gone.
    session.conn.close();
    try std.testing.expect(!session.sm_detached);

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.handleWritable(1, &changes);

    try std.testing.expect(server.sessions[1] != null);
    try std.testing.expectEqual(@as(u64, 1), server.stale_event_skips);
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
    server.handleReadable(1, &changes);

    // Park the FSM in starttls_pending with <proceed/> still unflushed, so
    // the upgrade is deferred to handleWritable.
    var drain_buf: [16384]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;
    try std.testing.expect(fillWriteBuffer(session));

    _ = try posix.write(fds[1], "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
    server.handleReadable(1, &changes);
    try std.testing.expect(session.stream.state == .starttls_pending);

    // The upgrade will fail, and a failure closes the session and frees it.
    server.fail_next_tls_upgrade = true;

    while (posix.read(fds[1], &drain_buf)) |n| {
        if (n == 0) break;
    } else |_| {}
    server.handleWritable(1, &changes);

    // handleWritable must stop at the failed upgrade. Continuing into the
    // offline-pending drain and the read-backpressure re-arm below it reads
    // the freed session (segfault observed).
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
    server.handleReadable(1, &changes);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    // <starttls/> alone: the FSM parks in starttls_pending.
    _ = try posix.write(fds[1], "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
    server.handleReadable(1, &changes);
    try std.testing.expect(session.stream.state == .starttls_pending);
    try std.testing.expect(server.sessions[1] != null);

    // Plaintext in a LATER segment: the peer must send nothing until the
    // upgrade. Reject and close (RFC 6120 5.4.3.2).
    _ = try posix.write(fds[1], "<message to='a@b'><body>x</body></message>");
    server.handleReadable(1, &changes);

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
    server.handleReadable(1, &changes);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    // <starttls/> followed by more plaintext in the same flight.
    _ = try posix.write(fds[1], "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/><message to='a@b'><body>x</body></message>");
    server.handleReadable(1, &changes);

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
    server.handleReadable(1, &changes);
    try std.testing.expect(server.sessions[1] != null);

    // A second stream header inside the open stream: protocol violation.
    const nested = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], nested);
    server.handleReadable(1, &changes);

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
fn expectBadRootBounded(root: []const u8) !void {
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
    server.handleReadable(1, &changes);
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
        server.handleReadable(1, &changes);
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
    server.handleReadable(2, &changes);

    _ = try session.conn.flushSend();
    var buf: [2048]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    const response = buf[0..n];

    // Should have SASL mechanisms, NOT STARTTLS
    try std.testing.expect(std.mem.indexOf(u8, response, "<mechanisms") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "SCRAM-SHA-256") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "<starttls") == null);
}

test "extractStanzaParts: message with body" {
    const stanza = "<message from='alice@remote.test' to='bob@local.test' type='chat' id='msg1'><body>hello</body></message>";
    const parts = extractStanzaParts(stanza);
    try std.testing.expect(parts.is_message);
    try std.testing.expectEqualStrings("chat", parts.msg_type);
    try std.testing.expectEqualStrings("msg1", parts.msg_id);
    try std.testing.expectEqualStrings("<body>hello</body>", parts.inner_xml);
}

test "extractStanzaParts: self-closing presence" {
    const stanza = "<presence from='alice@remote.test' to='bob@local.test' type='subscribe'/>";
    const parts = extractStanzaParts(stanza);
    try std.testing.expect(!parts.is_message);
    try std.testing.expectEqualStrings("subscribe", parts.msg_type);
    try std.testing.expectEqualStrings("", parts.inner_xml);
}

test "extractStanzaParts: message with no type" {
    const stanza = "<message from='a@b' to='c@d'><body>hi</body></message>";
    const parts = extractStanzaParts(stanza);
    try std.testing.expect(parts.is_message);
    try std.testing.expectEqualStrings("", parts.msg_type);
    try std.testing.expectEqualStrings("<body>hi</body>", parts.inner_xml);
}

test "extractAttrValue: finds attribute" {
    try std.testing.expectEqualStrings("chat", extractAttrValue("<message type='chat'>", "type"));
    try std.testing.expectEqualStrings("msg1", extractAttrValue("<message from='a' id='msg1' to='b'>", "id"));
    try std.testing.expectEqualStrings("", extractAttrValue("<message from='a'>", "type"));
}

test "cross-thread delivery: enqueue and drain" {
    const allocator = std.testing.allocator;

    // Set up shared infrastructure
    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    // Create a server that acts as worker 1 (the one draining)
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 1;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;

    // Create a target session on worker 1 using a socketpair
    // Local session ID = 5
    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 5, "localhost", false, allocator);
    server.sessions[5] = session;

    // Bind in session map (local_session_id = 5, worker = 1)
    const gen = try sm.bind(1, 5, "bob", "localhost", "desktop");

    // Simulate a cross-thread enqueue FROM worker 0 TO session 5 on worker 1
    const route = sm.findByFullJid("bob", "localhost", "desktop").?;
    try std.testing.expectEqual(@as(u16, 1), route.worker_id);
    try std.testing.expectEqual(@as(u32, 5), route.local_session_id);
    try std.testing.expectEqual(gen, route.generation);

    // Build a stanza and enqueue it (as if worker 0 is sending)
    try delivery_sys.deliver(route.worker_id, route.local_session_id, route.generation, "<message from='alice@localhost/mobile' to='bob@localhost' type='chat'><body>cross-thread!</body></message>");

    // Worker 1 drains its queue
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.drainDeliveryQueue(&changes);

    // The session should now have pending write data
    try std.testing.expect(session.conn.hasPendingWrite());

    // Flush and read from the client side of the socketpair
    _ = try session.conn.flushSend();
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    const received = buf[0..n];

    // Verify the stanza arrived intact
    try std.testing.expect(std.mem.indexOf(u8, received, "cross-thread!") != null);
    try std.testing.expect(std.mem.indexOf(u8, received, "alice@localhost/mobile") != null);
    try std.testing.expect(std.mem.indexOf(u8, received, "bob@localhost") != null);
}

test "cross-thread delivery: generation mismatch drops stanza" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;

    // Bind a session, get its generation, then unbind (simulating disconnect)
    const gen = try sm.bind(0, 3, "alice", "localhost", "mobile");
    _ = sm.unbind("alice", "localhost", "mobile");

    // Enqueue with the OLD generation (stale delivery)
    try delivery_sys.deliver(0, 3, gen, "<message>stale</message>");

    // Drain — should silently drop (generation mismatch)
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.drainDeliveryQueue(&changes);

    // No session at slot 3, so nothing should crash or write
    try std.testing.expect(server.sessions[3] == null);
}

test "S17: SM-ID map holds more than 64 detached sessions" {
    const allocator = std.testing.allocator;
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 256);
    defer server.deinit();

    // 200 inserts: the old 64-entry table silently dropped everything past 64.
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        var id: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
        _ = std.fmt.bufPrint(&id, "{x:0>32}", .{i}) catch unreachable;
        server.smIdMapInsert(&id, i);
    }
    try std.testing.expectEqual(@as(u32, 200), server.sm_id_map.count());

    i = 0;
    while (i < 200) : (i += 1) {
        var id: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
        _ = std.fmt.bufPrint(&id, "{x:0>32}", .{i}) catch unreachable;
        try std.testing.expectEqual(@as(?usize, i), server.findDetachedSession(&id));
    }
}

test "S17: SM-ID map remove does not break later lookups" {
    const allocator = std.testing.allocator;
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 256);
    defer server.deinit();

    // Insert a batch, remove every third entry, then verify the rest are
    // still findable (open addressing without tombstones lost the tail of
    // each probe chain here).
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var id: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
        _ = std.fmt.bufPrint(&id, "{x:0>32}", .{i}) catch unreachable;
        server.smIdMapInsert(&id, i + 1000);
    }
    i = 0;
    while (i < 100) : (i += 3) {
        var id: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
        _ = std.fmt.bufPrint(&id, "{x:0>32}", .{i}) catch unreachable;
        server.smIdMapRemove(&id);
    }
    i = 0;
    while (i < 100) : (i += 1) {
        var id: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
        _ = std.fmt.bufPrint(&id, "{x:0>32}", .{i}) catch unreachable;
        if (i % 3 == 0) {
            try std.testing.expectEqual(@as(?usize, null), server.findDetachedSession(&id));
        } else {
            try std.testing.expectEqual(@as(?usize, i + 1000), server.findDetachedSession(&id));
        }
    }
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
    server.accumulatePepElement(session, elem);
    server.accumulatePepText(session, "10</lat><evil/>");
    server.accumulatePepClose(session, "geoloc");

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

test "S15: raw conn queue ratchet, stanzas go through queueSendStanza" {
    // XEP-0198 acks map stanzas by position, so any stanza sent via raw
    // conn.queueSend shifts the ack window (S15). Nonzas (stream features,
    // SASL, SM elements, stream errors) are the only legitimate raw sends.
    // Counts may only shrink; a new raw site must be justified as a nonza
    // here. The pattern is split so this test does not match itself.
    const needle = "conn.queue" ++ "Send(";
    const cases = .{
        .{ "connection.zig", @embedFile("connection.zig"), 14 }, // Connection layer self-tests; no Session.
        .{ "fanout.zig", @embedFile("fanout.zig"), 1 }, // deliverToSession: tracked via smTrackOutbound.
        .{ "presence_handler.zig", @embedFile("presence_handler.zig"), 0 },
        .{ "router.zig", @embedFile("router.zig"), 2 }, // comment; sendCarbons tracked pair.
        .{ "session_lifecycle.zig", @embedFile("session_lifecycle.zig"), 0 },
        .{ "server.zig", @embedFile("server.zig"), 26 }, // stream/SASL/SM nonzas + queueSendStanza itself.
        .{ "iq_handler.zig", @embedFile("iq_handler.zig"), 0 },
        .{ "muc_handler.zig", @embedFile("muc_handler.zig"), 0 },
        .{ "message.zig", @embedFile("message.zig"), 0 },
        .{ "caps.zig", @embedFile("caps.zig"), 0 },
        // Remaining core files (S15): a raw send added here must be caught
        // like any other, not smuggled in outside the allowlist.
        .{ "archive_queue.zig", @embedFile("archive_queue.zig"), 0 },
        .{ "delivery_queue.zig", @embedFile("delivery_queue.zig"), 0 },
        .{ "event_loop.zig", @embedFile("event_loop.zig"), 0 },
        .{ "listener.zig", @embedFile("listener.zig"), 0 },
        .{ "main.zig", @embedFile("main.zig"), 0 },
        .{ "offline_store.zig", @embedFile("offline_store.zig"), 0 },
        .{ "room_mailbox.zig", @embedFile("room_mailbox.zig"), 0 },
        .{ "room_registry.zig", @embedFile("room_registry.zig"), 0 },
        .{ "roster_store.zig", @embedFile("roster_store.zig"), 0 },
        .{ "session_map.zig", @embedFile("session_map.zig"), 0 },
        .{ "sm_handoff.zig", @embedFile("sm_handoff.zig"), 0 },
        .{ "sm_state.zig", @embedFile("sm_state.zig"), 0 },
        .{ "subscription_cache.zig", @embedFile("subscription_cache.zig"), 0 },
    };
    if (cases.len != 23) {
        log.err("S15 ratchet: covers {d} core files, expected 23", .{cases.len});
        return error.RatchetCoverage;
    }
    inline for (cases) |case| {
        const name = case[0];
        const src = case[1];
        const expected = case[2];
        var count: usize = 0;
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, src, pos, needle)) |hit| {
            count += 1;
            pos = hit + needle.len;
        }
        if (count != expected) {
            log.err("S15 ratchet: {s} has {d} raw sends, allowlist says {d}", .{ name, count, expected });
            return error.RatchetMismatch;
        }
    }
}

test "Server: S13 message held behind a draining offline tail" {
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

    // bob is online but his offline tail is still draining (S13).
    const target_fds = try makeSocketPair();
    defer posix.close(target_fds[1]);
    const target = try allocator.create(Session);
    target.* = Session.init(target_fds[0], 5, "localhost", false, allocator);
    target.offline_pending = true;
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
    alice.stanza_id = "m1";
    const body = "<body>held</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    // Not delivered live: it would overtake the draining tail.
    _ = target.conn.flushSend() catch {};
    var buf: [1024]u8 = undefined;
    const n = posix.read(target_fds[1], &buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n);

    _ = alice.conn.flushSend() catch {};
    const sender_n = posix.read(alice_fds[1], &buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), sender_n);

    // Parked behind the tail instead: one offline pointer whose held copy
    // carries the stanza itself, so the drain does not depend on an archive
    // row the async writer queue may not have committed yet (E2a).
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    const held = try offline_store.getHeldStanza(ptrs[0]);
    try std.testing.expect(held != null);
    if (held) |h| {
        defer allocator.free(h);
        try std.testing.expect(std.mem.indexOf(u8, h, "<body>held</body>") != null);
    }
}

test "Server: G3 cross-worker delivery parks behind a draining offline tail" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

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

    const target_fds = try makeSocketPair();
    defer posix.close(target_fds[1]);
    const target = try allocator.create(Session);
    target.* = Session.init(target_fds[0], 5, "localhost", false, allocator);
    target.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch null;
    target.offline_pending = true;
    server.sessions[5] = target;
    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    const entry = sm.findByFullJid("bob", "localhost", "desktop") orelse return error.MissingSession;

    const payload = "<message from='alice@localhost/mobile' to='bob@localhost' id='q1' type='chat'><body>queued</body></message>";
    try delivery_sys.deliver(0, 5, entry.generation, payload);
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.drainDeliveryQueue(&changes);

    _ = target.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(target_fds[1], &buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n);
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    const pointers = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 1), pointers.len);
    try std.testing.expectEqualStrings("q1", pointers[0].stanza_id);
    const held = try offline_store.getHeldStanza(pointers[0]);
    try std.testing.expect(held != null);
    defer if (held) |xml_bytes| allocator.free(xml_bytes);
    try std.testing.expectEqualStrings(payload, held.?);
}

test "Server: G3 inbound S2S delivery parks behind a draining offline tail" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.offline = &offline_store;

    const target_fds = try makeSocketPair();
    defer posix.close(target_fds[1]);
    const target = try allocator.create(Session);
    target.* = Session.init(target_fds[0], 5, "localhost", false, allocator);
    target.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch null;
    target.offline_pending = true;
    server.sessions[5] = target;
    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    const payload = "<message from='carol@example.com/res' to='bob@localhost' id='s1' type='chat'><body>federated-tail</body></message>";
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = payload,
    } }, &changes);

    _ = target.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(target_fds[1], &buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n);
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    const pointers = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 1), pointers.len);
    try std.testing.expectEqualStrings("s1", pointers[0].stanza_id);
    const held = try offline_store.getHeldStanza(pointers[0]);
    try std.testing.expect(held != null);
    defer if (held) |xml_bytes| allocator.free(xml_bytes);
    try std.testing.expectEqualStrings(payload, held.?);
}

test "Server: G3 type normal parks behind a draining offline tail" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.offline = &offline_store;

    const target_fds = try makeSocketPair();
    defer posix.close(target_fds[1]);
    const target = try allocator.create(Session);
    target.* = Session.init(target_fds[0], 5, "localhost", false, allocator);
    target.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch null;
    target.offline_pending = true;
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
    alice.stanza_type = "normal";
    alice.stanza_id = "n1";
    const body = "<body>normal-tail</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    _ = target.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(target_fds[1], &buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n);
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    const pointers = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 1), pointers.len);
    try std.testing.expectEqualStrings("n1", pointers[0].stanza_id);
    const held = try offline_store.getHeldStanza(pointers[0]);
    try std.testing.expect(held != null);
    defer if (held) |xml_bytes| allocator.free(xml_bytes);
    try std.testing.expect(std.mem.indexOf(u8, held.?, "<body>normal-tail</body>") != null);
}

// S13: a message stored offline for an absent recipient points at an archive
// row that may still be sitting in the async writer queue. The payload is
// stored with the pointer, so the drain delivers it even when the archive row
// was never committed.
test "Server: S13 offline store delivers without a committed archive row" {
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

    // bob has no session at all, so alice's message goes to offline storage.
    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "o1";
    const body = "<body>for later</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));

    // The pointer resolves from its own held payload, with no archive row.
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    const held = try offline_store.getHeldStanza(ptrs[0]);
    try std.testing.expect(held != null);
    if (held) |h| {
        try std.testing.expect(std.mem.indexOf(u8, h, "<body>for later</body>") != null);
        allocator.free(h);
    }

    // bob comes online: the drain delivers it and clears the queue.
    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const bob = try allocator.create(Session);
    bob.* = Session.init(fds[0], 7, "localhost", false, allocator);
    bob.stream.state = .active;
    bob.stream.authenticated = true;
    bob.stream.authenticated_jid = .{ .local = "bob", .domain = "localhost" };
    bob.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "desk" };
    server.sessions[7] = bob;
    server.free_count -= 1;

    session_lifecycle.deliverOfflineMessages(&server, bob, "bob", "localhost", &changes);

    _ = bob.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "<body>for later</body>") != null);
    try std.testing.expect(!bob.offline_pending);
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));
}

// E2d: a stanza whose archived form exceeds the serialization buffer is
// rejected before archive or held storage, never replayed with a missing close.
test "Server: E2d an oversized archive form is not stored offline" {
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

    // bob is offline: the stanza takes the offline-store path.
    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";

    // A near-full body plus an id long enough to push the serialized archive
    // form past BYTE_BANK_SIZE. The id comes off the wire, and the scanner
    // allows an attribute token far larger than the bank.
    const body_prefix = "<body>";
    const body_suffix = "</body>";
    const filler_len = alice.stanza_buf.len - body_prefix.len - body_suffix.len;
    @memcpy(alice.stanza_buf[0..body_prefix.len], body_prefix);
    @memset(alice.stanza_buf[body_prefix.len..][0..filler_len], 'A');
    @memcpy(alice.stanza_buf[body_prefix.len + filler_len ..][0..body_suffix.len], body_suffix);
    alice.stanza_buf_len = alice.stanza_buf.len;

    const id_len = 5000;
    const long_id = try allocator.alloc(u8, id_len);
    defer allocator.free(long_id);
    @memset(long_id, 'x');
    alice.stanza_id = long_id;

    const not_stored_before = delivery_queue_mod.offline_not_stored.load(.monotonic);
    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    // Nothing was stored: a truncated form would have been archived and
    // replayed to bob when he next connects.
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));
    const archived = try arch_store.query("bob@localhost", .{});
    defer {
        for (archived.messages) |msg| {
            allocator.free(msg.stanza_id);
            if (msg.stanza_xml.len > 0) allocator.free(@constCast(msg.stanza_xml));
        }
        allocator.free(archived.messages);
    }
    try std.testing.expectEqual(@as(usize, 0), archived.messages.len);
    try std.testing.expectEqual(not_stored_before + 1, delivery_queue_mod.offline_not_stored.load(.monotonic));
}

// E2b: an inbound S2S stanza for an offline local user is stored with its
// payload, and a full offline queue bounces back over the same link instead of
// dropping the stanza silently.
test "Server: E2b an inbound S2S stanza for an offline user holds its payload" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    try tmp.dir.makePath("archive");
    var dir_path: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_path);
    var sock_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&sock_buf, "{s}/s2s.sock", .{dir});

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

    var listener = try TestIpcListener.init(sock_path);
    defer listener.deinit();

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;
    server.archive = &arch_store;
    try server.configureS2s(sock_path);
    try std.testing.expect(server.s2s_ipc.connected);

    // Accept the daemon side so the bounce frame can be read back. Non-blocking:
    // this test asserts that nothing was sent.
    const daemon_fd = try posix.accept(listener.fd, null, null, posix.SOCK.NONBLOCK);
    defer posix.close(daemon_fd);

    // bob is offline: no session bound anywhere.
    const stanza = "<message from='carol@example.com/res' to='bob@localhost' id='r1' type='chat'><body>federated</body></message>";
    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = stanza,
    } }, &changes);

    // The pointer carries the payload, so a drain cannot depend on the archive
    // row landing first.
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    try std.testing.expectEqual(@as(usize, 1), ptrs.len);

    const held = try offline_store.getHeldStanza(ptrs[0]);
    try std.testing.expect(held != null);
    defer if (held) |h| allocator.free(h);
    try std.testing.expect(std.mem.indexOf(u8, held.?, "<body>federated</body>") != null);

    // Nothing was bounced back to the remote sender.
    _ = server.s2s_ipc.flush() catch {};
    var frame_buf: [4096]u8 = undefined;
    const got = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), got);

    changes.reset();
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = "<message from='carol@example.com/res' to='bob@localhost' id='gc1' type='groupchat'><body>not offline</body></message>",
    } }, &changes);
    _ = server.s2s_ipc.flush() catch {};
    const groupchat_n = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expect(groupchat_n > 0);
    const groupchat_frame = ipc_protocol.readFrame(frame_buf[0..groupchat_n]);
    try std.testing.expect(groupchat_frame != null);
    const groupchat_bounce = switch (try ipc_protocol.decode(groupchat_frame.?.payload)) {
        .s2s_deliver => |d| d,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(std.mem.indexOf(u8, groupchat_bounce.stanza_xml, "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, groupchat_bounce.stanza_xml, "id='gc1'") != null);
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
}

test "Server: E2b a full offline queue bounces the inbound S2S stanza" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    try tmp.dir.makePath("archive");
    var dir_path: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_path);
    var sock_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&sock_buf, "{s}/s2s.sock", .{dir});

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

    var listener = try TestIpcListener.init(sock_path);
    defer listener.deinit();

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;
    server.archive = &arch_store;
    try server.configureS2s(sock_path);

    const daemon_fd = try posix.accept(listener.fd, null, null, posix.SOCK.NONBLOCK);
    defer posix.close(daemon_fd);

    // Fill bob's offline queue to the per-user maximum.
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var id_buf: [16]u8 = undefined;
        const sid = std.fmt.bufPrint(&id_buf, "q{d}", .{i}) catch unreachable;
        const stored = try offline_store.storePointer("bob@localhost", "carol@example.com", sid, 100 + @as(u64, @intCast(i)));
        try std.testing.expect(stored);
    }

    const stanza = "<message from='carol@example.com/res' to='bob@localhost' id='r2' type='chat'><body>too much</body></message>";
    const bounces_before = delivery_queue_mod.s2s_bounces.load(.monotonic);
    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = stanza,
    } }, &changes);

    // The queue stayed exactly at quota: nothing new was accepted.
    try std.testing.expectEqual(@as(usize, 100), try offline_store.countMessages("bob@localhost"));

    // The remote sender learns the stanza was dropped rather than being told
    // it was delivered.
    _ = server.s2s_ipc.flush() catch {};
    var frame_buf: [4096]u8 = undefined;
    const got = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expect(got > 0);
    const frame = ipc_protocol.readFrame(frame_buf[0..got]);
    try std.testing.expect(frame != null);
    const msg = try ipc_protocol.decode(frame.?.payload);
    const delivered = switch (msg) {
        .s2s_deliver => |d| d,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("carol@example.com/res", delivered.to_jid);
    try std.testing.expect(std.mem.indexOf(u8, delivered.stanza_xml, "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, delivered.stanza_xml, "id='r2'") != null);
    try std.testing.expectEqual(bounces_before + 1, delivery_queue_mod.s2s_bounces.load(.monotonic));
}

// E2b: with no offline store the inbound message still bounces rather than
// vanishing, and an inbound error stanza is never bounced back (two servers
// would otherwise trade bounces forever).
test "Server: E2b an unstorable inbound S2S stanza bounces but an error stanza does not" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_path: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_path);
    var sock_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&sock_buf, "{s}/s2s.sock", .{dir});

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();

    var listener = try TestIpcListener.init(sock_path);
    defer listener.deinit();

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    // No offline store, no archive: nothing here can hold the stanza.
    try server.configureS2s(sock_path);

    const daemon_fd = try posix.accept(listener.fd, null, null, posix.SOCK.NONBLOCK);
    defer posix.close(daemon_fd);

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = "<message from='carol@example.com/res' to='bob@localhost' id='r3' type='chat'><body>hello</body></message>",
    } }, &changes);

    _ = server.s2s_ipc.flush() catch {};
    var frame_buf: [4096]u8 = undefined;
    const got = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expect(got > 0);
    const frame = ipc_protocol.readFrame(frame_buf[0..got]);
    try std.testing.expect(frame != null);
    const bounced = switch (try ipc_protocol.decode(frame.?.payload)) {
        .s2s_deliver => |d| d,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(std.mem.indexOf(u8, bounced.stanza_xml, "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, bounced.stanza_xml, "id='r3'") != null);

    // An error stanza for the same offline recipient is dropped without a
    // reply, so the bounce cannot come back as another bounce.
    changes.reset();
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = "<message from='carol@example.com/res' to='bob@localhost' id='r4' type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
    } }, &changes);

    _ = server.s2s_ipc.flush() catch {};
    const second = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), second);

    changes.reset();
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = "<iq from='carol@example.com/res' to='bob@localhost' id='q1' type='get'><query xmlns='jabber:iq:version'/></iq>",
    } }, &changes);
    _ = server.s2s_ipc.flush() catch {};
    const iq_n = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expect(iq_n > 0);
    const iq_frame = ipc_protocol.readFrame(frame_buf[0..iq_n]);
    try std.testing.expect(iq_frame != null);
    const iq_bounce = switch (try ipc_protocol.decode(iq_frame.?.payload)) {
        .s2s_deliver => |d| d,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(std.mem.startsWith(u8, iq_bounce.stanza_xml, "<iq type='error'"));
    try std.testing.expect(std.mem.indexOf(u8, iq_bounce.stanza_xml, "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, iq_bounce.stanza_xml, "id='q1'") != null);

    changes.reset();
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = "<iq from='carol@example.com/res' to='bob@localhost' id='q2' type='result'><query xmlns='jabber:iq:version'/></iq>",
    } }, &changes);
    _ = server.s2s_ipc.flush() catch {};
    const iq_result_n = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), iq_result_n);
}

test "G7: the S2S bounce escapes the id once and from/to once" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    // msg_id is the raw on-wire form: an entity is decoded then escaped once,
    // not double-escaped. from/to are plain JIDs, escaped once.
    try writeS2sBounce(fbs.writer(), "b&b@localhost", "carol@example.com/res", "a&amp;b");
    const out = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, out, "id='a&amp;b'") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "a&amp;amp;") == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "from='b&amp;b@localhost'") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "to='carol@example.com/res'") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "service-unavailable") != null);
}

test "G7: a single quote in the id cannot break the bounce attribute" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeS2sBounce(fbs.writer(), "bob@localhost", "carol@example.com", "x'y");
    const out = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, out, "id='x&apos;y'") != null);
}

// G7: an inbound id carrying an XML entity is bounced with the entity escaped
// exactly once, through the real parse and bounce path (not a double escape).
test "Server: G7 an inbound id with an entity is escaped once in the bounce" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_path: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_path);
    var sock_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&sock_buf, "{s}/s2s.sock", .{dir});

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();

    var listener = try TestIpcListener.init(sock_path);
    defer listener.deinit();

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    // No offline store: the stanza bounces.
    try server.configureS2s(sock_path);

    const daemon_fd = try posix.accept(listener.fd, null, null, posix.SOCK.NONBLOCK);
    defer posix.close(daemon_fd);

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = "<message from='carol@example.com/res' to='bob@localhost' id='a&amp;b' type='chat'><body>hello</body></message>",
    } }, &changes);

    _ = server.s2s_ipc.flush() catch {};
    var frame_buf: [4096]u8 = undefined;
    const got = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expect(got > 0);
    const frame = ipc_protocol.readFrame(frame_buf[0..got]);
    try std.testing.expect(frame != null);
    const bounced = switch (try ipc_protocol.decode(frame.?.payload)) {
        .s2s_deliver => |d| d,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(std.mem.indexOf(u8, bounced.stanza_xml, "id='a&amp;b'") != null);
    try std.testing.expect(std.mem.indexOf(u8, bounced.stanza_xml, "a&amp;amp;") == null);
}

// G7: a storage error (not just a full queue) still bounces the inbound stanza
// instead of returning silently. An over-long recipient makes the offline hold
// fail with KeyTooLong.
test "Server: G7 a storage error on the offline hold still bounces" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    var dir_path: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_path);
    var sock_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&sock_buf, "{s}/s2s.sock", .{dir});
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);

    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();

    var listener = try TestIpcListener.init(sock_path);
    defer listener.deinit();

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;
    try server.configureS2s(sock_path);

    const daemon_fd = try posix.accept(listener.fd, null, null, posix.SOCK.NONBLOCK);
    defer posix.close(daemon_fd);

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const long_to = "bob@" ++ ("d" ** 520);
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = long_to,
        .stanza_xml = "<message from='carol@example.com/res' to='bob@localhost' id='r9' type='chat'><body>hello</body></message>",
    } }, &changes);

    _ = server.s2s_ipc.flush() catch {};
    var frame_buf: [4096]u8 = undefined;
    const got = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expect(got > 0);
    const frame = ipc_protocol.readFrame(frame_buf[0..got]);
    try std.testing.expect(frame != null);
    const bounced = switch (try ipc_protocol.decode(frame.?.payload)) {
        .s2s_deliver => |d| d,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(std.mem.indexOf(u8, bounced.stanza_xml, "service-unavailable") != null);
}

// E2c: the stanza ID is the key tiebreaker within a timestamp
// (owner\x00timestamp_be\x00stanza_id), so its lexicographic order has to match
// the order the IDs were minted in. Unpadded hex broke that at every counter
// boundary, which reordered an offline queue. The counter field is compared
// directly so the test does not depend on the wall clock staying within one
// second.
test "Server: E2c stanza ids sort in generation order across counter boundaries" {
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, std.testing.allocator, 4);
    defer server.deinit();
    server.worker_id = 1;

    // Counters straddling every hex-digit rollover: 9->10, 15->16, 255->256.
    var buf_pool: [6][32]u8 = undefined;
    const counters = [_]u32{ 0, 9, 10, 15, 16, 256 };
    var ids: [6][]const u8 = undefined;

    for (counters, 0..) |counter, i| {
        server.stanza_id_counter = counter;
        ids[i] = server.generateStanzaId(&buf_pool[i]);

        // Fixed shape: 8 hex timestamp, 4 hex worker, 8 hex counter. Every
        // field padded, so lexicographic order tracks numeric order.
        try std.testing.expectEqual(@as(usize, 22), ids[i].len);
        try std.testing.expectEqual(@as(u8, '-'), ids[i][8]);
        try std.testing.expectEqual(@as(u8, '-'), ids[i][13]);
    }

    // The trailing counter field must sort in the order it was minted.
    for (ids[0 .. ids.len - 1], ids[1..]) |earlier, later| {
        const e_counter = earlier[14..];
        const l_counter = later[14..];
        try std.testing.expectEqual(std.math.Order.lt, std.mem.order(u8, e_counter, l_counter));
    }
}

// E2c: generated stanza ids are not offline queue keys. Rows inserted at one
// timestamp must retain insertion order across the id counter's lexical boundary.
test "Server: E2c an offline queue drains in the order it was filled" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 4);
    defer server.deinit();
    server.worker_id = 1;

    // Nine rows at one timestamp, IDs minted across the f->10 boundary where
    // an unpadded counter stops sorting by value.
    const timestamp: u64 = 1_700_000_000;
    var buf_pool: [9][32]u8 = undefined;
    var stored_ids: [9][]const u8 = undefined;
    server.stanza_id_counter = 12;
    for (0..9) |i| {
        stored_ids[i] = server.generateStanzaId(&buf_pool[i]);
        const ok = try offline_store.storePointer("bob@localhost", "alice@localhost/desk", stored_ids[i], timestamp);
        try std.testing.expect(ok);
    }

    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    try std.testing.expectEqual(@as(usize, 9), ptrs.len);

    for (stored_ids, ptrs) |want, got| {
        try std.testing.expectEqualStrings(want, got.stanza_id);
    }
}

test "Server: G2 offline insertion order survives an operational backend reopen" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);

    {
        var op_db = try OpBackendMod.Backend.open(op_path, .{});
        defer op_db.close();
        var store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);
        try std.testing.expect(try store.storeHeldPointer("bob@localhost", "alice@localhost/first", "reused-id", 1000, "<message id='first'/>"));
    }
    {
        var op_db = try OpBackendMod.Backend.open(op_path, .{});
        defer op_db.close();
        var store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);
        try std.testing.expect(try store.storeHeldPointer("bob@localhost", "alice@localhost/second", "reused-id", 1000, "<message id='second'/>"));

        const pointers = try store.getPointers("bob@localhost");
        defer store.freePointers(pointers);
        try std.testing.expectEqual(@as(usize, 2), pointers.len);
        try std.testing.expectEqualStrings("alice@localhost/first", pointers[0].from_jid);
        try std.testing.expectEqualStrings("alice@localhost/second", pointers[1].from_jid);
        try std.testing.expectEqualStrings("reused-id", pointers[0].stanza_id);
        try std.testing.expectEqualStrings("reused-id", pointers[1].stanza_id);
    }
}

test "Server: G2 two workers cannot exceed the shared offline quota" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    try op_db.put("offline", "warmup", "");
    try op_db.delete("offline", "warmup");

    const Store = GenericOfflineStore(OpBackendType);
    const Context = struct {
        store: *Store,
        ready: *std.Thread.Semaphore,
        start: *std.Thread.Semaphore,
        successes: *std.atomic.Value(usize),
        errors: *std.atomic.Value(usize),
        worker: usize,

        fn run(ctx: *@This()) void {
            ctx.ready.post();
            ctx.start.wait();
            for (0..150) |i| {
                var id_buf: [32]u8 = undefined;
                const id = std.fmt.bufPrint(&id_buf, "worker-{d}-message-{d}", .{ ctx.worker, i }) catch unreachable;
                var from_buf: [48]u8 = undefined;
                const from = std.fmt.bufPrint(&from_buf, "alice@localhost/worker-{d}-{d}", .{ ctx.worker, i }) catch unreachable;
                const timestamp: u64 = 10_000 + ctx.worker * 1000 + i;
                const stored = ctx.store.storePointer("bob@localhost", from, id, timestamp) catch {
                    _ = ctx.errors.fetchAdd(1, .monotonic);
                    return;
                };
                if (stored) _ = ctx.successes.fetchAdd(1, .monotonic);
            }
        }
    };

    var first_store = Store.init(&op_db, allocator);
    var second_store = Store.init(&op_db, allocator);
    var ready: std.Thread.Semaphore = .{};
    var start: std.Thread.Semaphore = .{};
    var successes = std.atomic.Value(usize).init(0);
    var errors = std.atomic.Value(usize).init(0);
    var contexts = [2]Context{
        .{ .store = &first_store, .ready = &ready, .start = &start, .successes = &successes, .errors = &errors, .worker = 0 },
        .{ .store = &second_store, .ready = &ready, .start = &start, .successes = &successes, .errors = &errors, .worker = 1 },
    };
    const first_thread = try std.Thread.spawn(.{}, Context.run, .{&contexts[0]});
    const second_thread = try std.Thread.spawn(.{}, Context.run, .{&contexts[1]});
    ready.wait();
    ready.wait();
    start.post();
    start.post();
    first_thread.join();
    second_thread.join();

    try std.testing.expectEqual(@as(usize, 0), errors.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 100), successes.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 100), try first_store.countMessages("bob@localhost"));
}

// S13: the writable handler must resume a stalled offline drain once the
// send buffer drops to the low-water mark. Without this the tail waits for
// the next presence stanza or a reconnect.
test "Server: S13 writable handler resumes the stalled offline drain" {
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

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();
    server.offline = &offline_store;
    server.archive = &arch_store;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, allocator);
    session.stream.state = .active;
    session.stream.authenticated = true;
    session.stream.authenticated_jid = .{ .local = "bob", .domain = "localhost" };
    session.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "res" };
    server.sessions[1] = session;
    server.free_count -= 1;
    // server.deinit() tears down every live session slot.

    // The offline tail bob never received.
    try arch_store.store("bob@localhost", "alice@localhost", "t1", 1001, "<message from='alice@localhost' to='bob@localhost' id='t1'><body>tail</body></message>");
    _ = try offline_store.storePointer("bob@localhost", "alice@localhost", "t1", 1001);
    session.offline_pending = true;

    // Backlog already in the send buffer, above the low-water mark, so the
    // first writable pass cannot yet resume the drain. Goes through the
    // blessed stanza path so the S15 raw-send ratchet is unaffected.
    var filler: [12000]u8 = undefined;
    @memset(&filler, 'f');
    try session.queueSendStanza(&filler);

    // Collect every byte that reaches the peer across all writable passes so
    // ordering can be checked at the end.
    var wire = std.ArrayList(u8){};
    defer wire.deinit(allocator);
    var buf: [65536]u8 = undefined;

    // Keep taking writable passes until the tail is actually on the wire: the
    // drain queues it, but flushing a full send buffer takes several rounds.
    var rounds: usize = 0;
    while (rounds < 64) : (rounds += 1) {
        changes.reset();
        server.handleWritable(1, &changes);
        while (true) {
            const n = posix.read(fds[1], &buf) catch break;
            if (n == 0) break;
            try wire.appendSlice(allocator, buf[0..n]);
        }
        if (!session.offline_pending and !session.conn.hasPendingWrite()) break;
    }

    try std.testing.expect(!session.offline_pending);
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));

    // The tail goes out behind the backlog, never ahead of it.
    const filler_at = std.mem.indexOf(u8, wire.items, "ffff");
    const tail_at = std.mem.indexOf(u8, wire.items, "<body>tail</body>");
    try std.testing.expect(filler_at != null);
    try std.testing.expect(tail_at != null);
    try std.testing.expect(filler_at.? < tail_at.?);
}

// S13: when the offline queue is at quota the held copy cannot be stored.
// Dropping it silently lost the message, so the sender must be told.
test "Server: S13 hold at quota bounces instead of dropping silently" {
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

    // Fill bob's offline queue to MAX_PER_USER so the hold is refused.
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var id_buf: [16]u8 = undefined;
        const sid = std.fmt.bufPrint(&id_buf, "q{d}", .{i}) catch unreachable;
        const stored = try offline_store.storePointer("bob@localhost", "carol@localhost", sid, 100 + @as(u64, @intCast(i)));
        try std.testing.expect(stored);
    }

    // bob is online but his offline tail is still draining.
    const target_fds = try makeSocketPair();
    defer posix.close(target_fds[1]);
    const target = try allocator.create(Session);
    target.* = Session.init(target_fds[0], 5, "localhost", false, allocator);
    target.offline_pending = true;
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
    alice.stanza_id = "m1";
    const body = "<body>bounced</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    const hold_bounces_before = delivery_queue_mod.offline_hold_bounces.load(.monotonic);
    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    // The sender gets a service-unavailable error rather than silence.
    _ = alice.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(alice_fds[1], &buf) catch 0;
    const got = buf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, got, "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "id='m1'") != null);

    // Nothing was held: the queue is still exactly at quota.
    try std.testing.expectEqual(@as(usize, 100), try offline_store.countMessages("bob@localhost"));
    try std.testing.expectEqual(hold_bounces_before + 1, delivery_queue_mod.offline_hold_bounces.load(.monotonic));

    // bob got nothing out of order.
    _ = target.conn.flushSend() catch {};
    var tbuf: [4096]u8 = undefined;
    const tn = posix.read(target_fds[1], &tbuf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), tn);
}

test "Server: R5 S2S cross-worker delivery drops are counted" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;

    _ = try sm.bind(1, 7, "bob", "localhost", "mobile");
    sm.setPresenceAvailable("bob", "localhost", "mobile", true);

    const stanza = try allocator.alloc(u8, 4200);
    defer allocator.free(stanza);
    const prefix = "<message from='carol@example.com/res' to='bob@localhost' id='drop' type='chat'><body>";
    const suffix = "</body></message>";
    @memcpy(stanza[0..prefix.len], prefix);
    @memset(stanza[prefix.len .. stanza.len - suffix.len], 'x');
    @memcpy(stanza[stanza.len - suffix.len ..], suffix);

    const drops_before = delivery_queue_mod.cross_worker_drops.load(.monotonic);
    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = stanza,
    } }, &changes);
    try std.testing.expectEqual(drops_before + 1, delivery_queue_mod.cross_worker_drops.load(.monotonic));
}

test "S14: failed cross-worker resource does not block local delivery" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;

    // bob has a local resource (worker 0, session 5) and a remote one
    // (worker 1, session 7). The stanza exceeds the 4080-byte delivery
    // slot, so the cross-worker enqueue fails.
    const target_fds = try makeSocketPair();
    defer posix.close(target_fds[1]);
    const target = try allocator.create(Session);
    target.* = Session.init(target_fds[0], 5, "localhost", false, allocator);
    server.sessions[5] = target;

    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    _ = try sm.bind(1, 7, "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "m1";
    const body = "<body>" ++ ([_]u8{'x'} ** 5000) ++ "</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    // The local resource still receives the stanza.
    _ = try target.conn.flushSend();
    var buf: [8192]u8 = undefined;
    const n = posix.read(target_fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "<body>") != null);

    // The sender is not bounced: another resource took the message.
    _ = alice.conn.flushSend() catch {};
    var abuf: [1024]u8 = undefined;
    const an = posix.read(alice_fds[1], &abuf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), an);
}

test "S14: oversize cross-worker stanza falls back to the offline store" {
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
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;
    server.archive = &arch_store;

    // bob's only resource lives on worker 1: the direct handoff is the
    // cross-thread enqueue, and the stanza exceeds the delivery slot, so
    // the fallback alone decides what happens to it.
    _ = try sm.bind(1, 7, "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "m1";
    const body = "<body>" ++ ([_]u8{'x'} ** 5000) ++ "</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    // Nothing delivered live; the fallback parked it offline.
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));

    // The sender is not bounced: the message is held, not lost.
    _ = alice.conn.flushSend() catch {};
    var abuf: [1024]u8 = undefined;
    const an = posix.read(alice_fds[1], &abuf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), an);
}

test "S14: oversize cross-worker stanza with no offline store bounces" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;

    // bob remote-only again, but no offline store: the bounce fallback
    // is the only path left.
    _ = try sm.bind(1, 7, "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "m1";
    const body = "<body>" ++ ([_]u8{'x'} ** 5000) ++ "</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    _ = alice.conn.flushSend() catch {};
    var abuf: [2048]u8 = undefined;
    const an = posix.read(alice_fds[1], &abuf) catch 0;
    try std.testing.expect(an > 0);
    try std.testing.expect(std.mem.indexOf(u8, abuf[0..an], "service-unavailable") != null);
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
    server.handleReadable(1, &changes);
    try std.testing.expect(server.sessions[1] != null);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    // A close tag with no matching open: depth must not desync.
    _ = try posix.write(fds[1], "</junk>");
    server.handleReadable(1, &changes);

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
    server.handleReadable(1, &changes);
    try std.testing.expect(server.sessions[1] != null);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    session.stream.state = .features_bind;
    const long_id = "i" ** 300;
    const iq = "<iq type='set' id='" ++ long_id ++ "'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></iq>";
    _ = try posix.write(fds[1], iq);
    server.handleReadable(1, &changes);

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
    server.handleReadable(1, &changes);
    var drain_buf: [8192]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    // Registration is handled pre-auth; the TLS-offering state would
    // demand STARTTLS first.
    session.stream.state = .features_sasl;

    _ = try posix.write(fds[1], "<iq type='get' id='reg1'><query xmlns='jabber:iq:register'/></iq>");
    server.handleReadable(1, &changes);
    const n1 = posix.read(fds[1], &drain_buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, drain_buf[0..n1], "id='reg1'") != null);

    // The next stanza resets the reader arena the id slice came from; the
    // mirrored id in the reply must still be the client's.
    _ = try posix.write(fds[1], "<iq type='get' id='reg2-longer-id'><query xmlns='jabber:iq:register'/></iq>");
    server.handleReadable(1, &changes);
    const n2 = posix.read(fds[1], &drain_buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, drain_buf[0..n2], "id='reg2-longer-id'") != null);
    try std.testing.expect(server.sessions[1] != null);
}

test "Server: S24 a h above the sent count fails the stream" {
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
    server.handleReadable(1, &changes);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    session.stream.state = .active;
    session.sm_enabled = true;
    const queue = try std.testing.allocator.create(sm_state.SmUnackedQueue);
    queue.* = sm_state.SmUnackedQueue.init(std.testing.allocator);
    _ = queue.push("<message/>");
    _ = queue.push("<presence/>");
    session.sm_unacked = queue;

    // 2 stanzas outstanding, client claims 5 handled.
    _ = try posix.write(fds[1], "<a xmlns='urn:xmpp:sm:3' h='5'/>");
    server.handleReadable(1, &changes);

    try std.testing.expect(server.sessions[1] == null);
    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (posix.read(fds[1], buf[total..])) |n| {
        if (n == 0) break;
        total += n;
    } else |_| {}
    try std.testing.expect(std.mem.indexOf(u8, buf[0..total], "undefined-condition") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..total], "handled-count-too-high") != null);
}

test "Server: S24 malformed a h fails the stream" {
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
    server.handleReadable(1, &changes);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    session.stream.state = .active;
    session.sm_enabled = true;

    _ = try posix.write(fds[1], "<a xmlns='urn:xmpp:sm:3' h='five'/>");
    server.handleReadable(1, &changes);

    try std.testing.expect(server.sessions[1] == null);
    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (posix.read(fds[1], buf[total..])) |n| {
        if (n == 0) break;
        total += n;
    } else |_| {}
    try std.testing.expect(std.mem.indexOf(u8, buf[0..total], "handled-count-too-high") != null);
}

test "Server: S24 SM without resume rejects h above the sent count" {
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
    server.handleReadable(1, &changes);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    session.stream.state = .active;
    session.sm_enabled = true;
    // SM without resume has no unacked queue, but the sent count is tracked.
    // Five stanzas sent; the client claims ten handled.
    session.sm_out_seq = 5;
    session.sm_unacked = null;

    _ = try posix.write(fds[1], "<a xmlns='urn:xmpp:sm:3' h='10'/>");
    server.handleReadable(1, &changes);

    try std.testing.expect(server.sessions[1] == null);
    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (posix.read(fds[1], buf[total..])) |n| {
        if (n == 0) break;
        total += n;
    } else |_| {}
    try std.testing.expect(std.mem.indexOf(u8, buf[0..total], "handled-count-too-high") != null);
    // XEP-0198 Example 17: the error reports the offending h and the send count.
    try std.testing.expect(std.mem.indexOf(u8, buf[0..total], "h='10'") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..total], "send-count='5'") != null);
}

test "Server: S24 a backwards or duplicate a h does not corrupt the accepted count" {
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
    server.handleReadable(1, &changes);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    session.stream.state = .active;
    session.sm_enabled = true;
    session.sm_out_seq = 5;
    session.sm_out_h = 3;
    session.sm_unacked = null;

    // A backwards report (h=2 below the accepted 3) must not move sm_out_h.
    _ = try posix.write(fds[1], "<a xmlns='urn:xmpp:sm:3' h='2'/>");
    server.handleReadable(1, &changes);
    try std.testing.expect(server.sessions[1] != null);
    try std.testing.expectEqual(@as(u32, 3), session.sm_out_h);

    // A duplicate of the accepted count is a no-op as well.
    _ = try posix.write(fds[1], "<a xmlns='urn:xmpp:sm:3' h='3'/>");
    server.handleReadable(1, &changes);
    try std.testing.expect(server.sessions[1] != null);
    try std.testing.expectEqual(@as(u32, 3), session.sm_out_h);

    // A forward report within the sent count is accepted and advances sm_out_h.
    _ = try posix.write(fds[1], "<a xmlns='urn:xmpp:sm:3' h='4'/>");
    server.handleReadable(1, &changes);
    try std.testing.expect(server.sessions[1] != null);
    try std.testing.expectEqual(@as(u32, 4), session.sm_out_h);
}

test "Server: S24 backwards and too-high resume h fail without replay" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // Detached session on slot 2: client had acked 5, 3 stanzas outstanding.
    const det_fds = try makeSocketPair();
    defer posix.close(det_fds[1]);
    const detached = try std.testing.allocator.create(Session);
    detached.* = Session.init(det_fds[0], 2, "localhost", false, std.testing.allocator);
    detached.stream.bound_jid = xmpp.Jid.parse("alice@localhost/res") catch null;
    detached.sm_detached = true;
    detached.sm_detach_time = std.time.timestamp();
    const det_queue = try std.testing.allocator.create(sm_state.SmUnackedQueue);
    det_queue.* = sm_state.SmUnackedQueue.init(std.testing.allocator);
    det_queue.base_seq = 6;
    det_queue.last_h = 5;
    _ = det_queue.push("<message/>");
    _ = det_queue.push("<message/>");
    _ = det_queue.push("<message/>");
    detached.sm_unacked = det_queue;
    server.sessions[2] = detached;

    var previd: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
    sm_state.generateSmId(server.worker_id, &previd);
    server.smIdMapInsert(&previd, 2);

    // Fresh connection resuming the detached session.
    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    server.handleReadable(1, &changes);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    session.stream.state = .features_bind;
    session.stream.authenticated_jid = xmpp.Jid.parse("alice@localhost") catch null;

    var resume_buf: [128]u8 = undefined;
    const backwards = std.fmt.bufPrint(&resume_buf, "<resume xmlns='urn:xmpp:sm:3' previd='{s}' h='3'/>", .{previd}) catch unreachable;
    _ = try posix.write(fds[1], backwards);
    server.handleReadable(1, &changes);

    var buf: [4096]u8 = undefined;
    const n1 = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n1], "<failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n1], "unexpected-request") != null);
    // The detached session and its replay queue are untouched.
    try std.testing.expect(server.sessions[2] != null);
    try std.testing.expectEqual(@as(u32, 3), det_queue.count);
    try std.testing.expectEqual(@as(u32, 5), det_queue.last_h);

    const too_high = std.fmt.bufPrint(&resume_buf, "<resume xmlns='urn:xmpp:sm:3' previd='{s}' h='100'/>", .{previd}) catch unreachable;
    _ = try posix.write(fds[1], too_high);
    server.handleReadable(1, &changes);

    const n2 = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n2], "<failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n2], "handled-count-too-high") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n2], "urn:xmpp:sm:3'/></failed>") != null);
    try std.testing.expectEqual(@as(u32, 3), det_queue.count);

    // Malformed h fails instead of parsing as 0.
    const malformed = std.fmt.bufPrint(&resume_buf, "<resume xmlns='urn:xmpp:sm:3' previd='{s}' h='x'/>", .{previd}) catch unreachable;
    _ = try posix.write(fds[1], malformed);
    server.handleReadable(1, &changes);

    const n3 = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n3], "<failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n3], "bad-request") != null);
    try std.testing.expectEqual(@as(u32, 3), det_queue.count);
}

test "Server: S24 cross-worker handoff carries last_h" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();
    sm_handoff.resetForTesting();

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var previd: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
    sm_state.generateSmId(server.worker_id, &previd);

    session.sm_resume_pending = true;
    session.sm_resume_epoch = 7;
    @memcpy(&session.sm_resume_previd, &previd);

    // The owning worker's queue: client had acked 5, 3 stanzas outstanding.
    const bundle = sm_handoff.allocator.create(sm_handoff.ResumeBundle) catch unreachable;
    bundle.* = .{
        .previd = previd,
        .sm_in_h = 0,
        .sm_out_seq = 8,
        .sm_out_h = 3,
        .r_outstanding = false,
        .roster_interested = false,
        .carbons_enabled = false,
        .csi_active = false,
        .username = sm_handoff.allocator.dupe(u8, "alice") catch unreachable,
        .resource = sm_handoff.allocator.dupe(u8, "res") catch unreachable,
        .last_presence = sm_handoff.allocator.dupe(u8, "") catch unreachable,
        .base_seq = 6,
        .last_h = 5,
        .created = std.time.timestamp(),
    };
    bundle.stanzas.append(sm_handoff.allocator, sm_handoff.allocator.dupe(u8, "<message/>") catch unreachable) catch unreachable;
    try sm_handoff.put(&previd, bundle);

    server.handleSmResumeReply(.{
        .previd = &previd,
        .req_session = 1,
        .req_epoch = 7,
        .status = "ok",
    }, &changes);

    const queue = session.sm_unacked.?;
    try std.testing.expectEqual(@as(u32, 5), queue.last_h);
    try std.testing.expectEqual(@as(u32, 6), queue.base_seq);
    try std.testing.expectEqual(@as(u32, 1), queue.count);
    try std.testing.expectEqual(@as(u32, 8), session.sm_out_seq);

    // A backwards <a/> after the handoff discards nothing (the carried
    // last_h is what rejects it).
    try std.testing.expectEqual(sm_state.SmUnackedQueue.AckResult.backwards, queue.ack(3));
    try std.testing.expectEqual(@as(u32, 1), queue.count);
    try std.testing.expectEqual(@as(u32, 5), queue.last_h);
}

/// Test helper: the <resume/> reply status drained off a requesting worker's
/// SM actor queue. The status slice points into the transient MPSC payload, so
/// it is copied out before the drain handler returns.
const CapturedResumeStatus = struct {
    buf: [64]u8 = undefined,
    len: usize = 0,

    fn slice(self: *const CapturedResumeStatus) []const u8 {
        return self.buf[0..self.len];
    }
};

fn captureSmResumeStatus(ds: *DeliverySystem, req_worker: u16, out: *CapturedResumeStatus) void {
    const Ctx = struct { dst: *CapturedResumeStatus };
    _ = ds.getQueue(req_worker).drain(Ctx{ .dst = out }, struct {
        fn handle(c: Ctx, _: u32, _: u32, payload: []const u8) void {
            const msg = actor_message.decode(payload) orelse return;
            switch (msg) {
                .sm_resume_reply => |r| {
                    const n = @min(r.status.len, c.dst.buf.len);
                    @memcpy(c.dst.buf[0..n], r.status[0..n]);
                    c.dst.len = n;
                },
                else => {},
            }
        }
    }.handle);
}

/// Build a detached session on `slot` (acked up to `last_h`, `unacked` stanzas
/// outstanding from `base_seq`) registered under `previd`, ready for a
/// cross-worker resume request. The caller owns the session; on a rejected
/// request it is still there and `server.deinit` frees it.
fn makeDetachedForResume(
    server: *Server,
    slot: usize,
    previd: []const u8,
    base_seq: u32,
    last_h: u32,
    unacked: u32,
    fd: posix.fd_t,
) !*Session {
    const detached = try std.testing.allocator.create(Session);
    detached.* = Session.init(fd, slot, "localhost", false, std.testing.allocator);
    detached.stream.bound_jid = xmpp.Jid.parse("alice@localhost/res") catch null;
    detached.sm_detached = true;
    detached.sm_detach_time = std.time.timestamp();
    detached.sm_resume_enabled = true;
    @memcpy(&detached.sm_id, previd[0..sm_state.SM_ID_HEX_LEN]);
    detached.sm_id_len = sm_state.SM_ID_HEX_LEN;
    const queue = try std.testing.allocator.create(sm_state.SmUnackedQueue);
    queue.* = sm_state.SmUnackedQueue.init(std.testing.allocator);
    queue.base_seq = base_seq;
    queue.last_h = last_h;
    var i: u32 = 0;
    while (i < unacked) : (i += 1) _ = queue.push("<message/>");
    detached.sm_unacked = queue;
    server.sessions[slot] = detached;
    server.smIdMapInsert(previd, slot);
    return detached;
}

test "Server: S24 cross-worker resume validates the reported h before handoff" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();
    server.worker_id = 1;
    var delivery_sys = try DeliverySystem.init(std.testing.allocator, 2);
    defer delivery_sys.deinit();
    server.delivery_system = &delivery_sys;
    sm_handoff.resetForTesting();

    const previd = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const det_fds = try makeSocketPair();
    defer posix.close(det_fds[1]);
    const detached = try makeDetachedForResume(&server, 2, previd, 6, 5, 3, det_fds[0]);
    const det_queue = detached.sm_unacked.?;

    var status = CapturedResumeStatus{};

    // A backwards h must fail the handoff and leave the queue untouched.
    server.handleSmResumeRequest(.{
        .previd = previd,
        .h = 3,
        .req_worker = 1,
        .req_session = 1,
        .req_epoch = 0,
        .auth_local = "alice",
        .auth_domain = "localhost",
        .hops = 0,
    });
    captureSmResumeStatus(&delivery_sys, 1, &status);
    try std.testing.expectEqualStrings("unexpected-request", status.slice());
    try std.testing.expectEqual(@as(usize, 0), sm_handoff.count());
    try std.testing.expect(server.sessions[2] != null);
    try std.testing.expectEqual(@as(u32, 3), det_queue.count);
    try std.testing.expectEqual(@as(u32, 5), det_queue.last_h);

    // An h above the sent count must fail the same way. Only the wrap-aware
    // subtraction catches a report that has passed 2^32 (see the sm_state
    // wrap tests); here the plain overshoot is rejected.
    server.handleSmResumeRequest(.{
        .previd = previd,
        .h = 100,
        .req_worker = 1,
        .req_session = 1,
        .req_epoch = 0,
        .auth_local = "alice",
        .auth_domain = "localhost",
        .hops = 0,
    });
    captureSmResumeStatus(&delivery_sys, 1, &status);
    try std.testing.expectEqualStrings("handled-count-too-high", status.slice());
    try std.testing.expectEqual(@as(usize, 0), sm_handoff.count());
    try std.testing.expectEqual(@as(u32, 3), det_queue.count);
    try std.testing.expectEqual(@as(u32, 5), det_queue.last_h);

    // A valid forward h is the only one that parks a bundle and tears the
    // detached slot down; its last_h carries into the bundle.
    server.handleSmResumeRequest(.{
        .previd = previd,
        .h = 5,
        .req_worker = 1,
        .req_session = 1,
        .req_epoch = 0,
        .auth_local = "alice",
        .auth_domain = "localhost",
        .hops = 0,
    });
    captureSmResumeStatus(&delivery_sys, 1, &status);
    try std.testing.expectEqualStrings("ok", status.slice());
    try std.testing.expect(server.sessions[2] == null);
    const bundle = sm_handoff.take(previd) orelse return error.Missing;
    defer sm_handoff.release(bundle);
    try std.testing.expectEqual(@as(u32, 5), bundle.last_h);
    try std.testing.expectEqual(@as(u32, 6), bundle.base_seq);
    try std.testing.expectEqual(@as(usize, 3), bundle.stanzas.items.len);
}

test "Server: S24 cross-worker resume rejects a wrapped h above the sent count" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();
    server.worker_id = 1;
    var delivery_sys = try DeliverySystem.init(std.testing.allocator, 2);
    defer delivery_sys.deinit();
    server.delivery_system = &delivery_sys;
    sm_handoff.resetForTesting();

    // sent=2 (one stanza outstanding at sequence 2), last_h=0xFFFFFFFE. The
    // client reports h=3: numerically 3 is above the 2 sent but below
    // 0xFFFFFFFE, so a plain `h > sent` check reads it as small and accepts
    // credit for a stanza that was never sent. Only the wrap-aware check
    // (h -% last_h is forward, h -% sent overshoots) rejects it.
    const previd = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const det_fds = try makeSocketPair();
    defer posix.close(det_fds[1]);
    _ = try makeDetachedForResume(&server, 2, previd, 2, 0xFFFF_FFFE, 1, det_fds[0]);

    var status = CapturedResumeStatus{};
    server.handleSmResumeRequest(.{
        .previd = previd,
        .h = 3,
        .req_worker = 1,
        .req_session = 1,
        .req_epoch = 0,
        .auth_local = "alice",
        .auth_domain = "localhost",
        .hops = 0,
    });
    captureSmResumeStatus(&delivery_sys, 1, &status);
    try std.testing.expectEqualStrings("handled-count-too-high", status.slice());
    try std.testing.expectEqual(@as(usize, 0), sm_handoff.count());
    try std.testing.expect(server.sessions[2] != null);
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
    server.accumulateStanzaElement(alice, body_elem);
    var big: [20000]u8 = undefined;
    @memset(&big, 'A');
    server.accumulateStanzaText(alice, &big);
    server.accumulateStanzaClose(alice, "body");
    try std.testing.expect(alice.stanza_overflow);

    // The stanza completes: the partial is not routed, the stream is failed
    // closed, and the session is torn down.
    server.handleElementEnd(alice, "message", &changes);

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

test "Server: G4 a near-limit online stanza is bounced when delivery cannot queue it" {
    const allocator = std.testing.allocator;
    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;

    const bob_fds = try makeSocketPair();
    defer posix.close(bob_fds[1]);
    const bob = try allocator.create(Session);
    bob.* = Session.init(bob_fds[0], 5, "localhost", false, allocator);
    server.sessions[5] = bob;
    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    const alice = try allocator.create(Session);
    alice.* = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    server.sessions[9] = alice;
    alice.stream.bound_jid = .{ .local = "alice", .domain = "localhost", .resource = "mobile" };
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";

    const body_prefix = "<body>";
    const body_suffix = "</body>";
    const filler_len = alice.stanza_buf.len - body_prefix.len - body_suffix.len;
    @memcpy(alice.stanza_buf[0..body_prefix.len], body_prefix);
    @memset(alice.stanza_buf[body_prefix.len..][0..filler_len], 'A');
    @memcpy(alice.stanza_buf[body_prefix.len + filler_len ..][0..body_suffix.len], body_suffix);
    alice.stanza_buf_len = alice.stanza_buf.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, alice, &changes);

    _ = bob.conn.flushSend() catch {};
    var bob_buf: [4096]u8 = undefined;
    const bob_n = posix.read(bob_fds[1], &bob_buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), bob_n);

    _ = alice.conn.flushSend() catch {};
    var alice_buf: [4096]u8 = undefined;
    const alice_n = posix.read(alice_fds[1], &alice_buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, alice_buf[0..alice_n], "service-unavailable") != null);
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
    server.handleReadable(1, &changes);
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
    for (0..2) |_| server.handleReadable(1, &changes);

    _ = session.conn.flushSend() catch {};
    var response: [8192]u8 = undefined;
    const n = posix.read(fds[1], &response) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, response[0..n], "not-acceptable") != null);

    const stored = try vcard_store.get(allocator, "alice@localhost");
    defer if (stored) |value| allocator.free(value);
    try std.testing.expectEqualStrings(old_vcard, stored.?);
}

// E6 (S11): only whitespace is allowed at the stream level between stanzas.
// Non-whitespace there is a stream error (RFC 6120 4.6.1).
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
    server.handleReadable(1, &changes);

    // The stream is failed closed with a not-well-formed stream error and the
    // session is gone.
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "not-well-formed") != null);
    try std.testing.expect(server.sessions[1] == null);
}

// E6 (S11): an over-long token is a resource limit the peer hit, not malformed
// XML, so it maps to a policy-violation stream error (not not-well-formed).
// The scanner cap is 512 KiB, so the name is driven past it in chunks through
// the real parse path.
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
        server.handleReadable(1, &changes);
    }

    // A policy-violation (not not-well-formed) closed the stream.
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "policy-violation") != null);
    try std.testing.expect(server.sessions[1] == null);
}

test "Server: S10 reconcile arms and disarms auth IPC write interest" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    server.ipc.fd = fds[0];
    server.ipc.connected = true;

    var change_buf: [8]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // Unix pairs buffer ~64 KiB: fill the send path, then the IPC send
    // cannot flush fully and a backlog remains.
    var fill_buf: [65536]u8 = undefined;
    @memset(&fill_buf, 'x');
    _ = posix.write(fds[0], &fill_buf) catch 0;
    const big_payload = "P" ** 3000;
    try server.ipc.send(.{ .auth_request = .{
        .conn_id = 7,
        .mechanism = .scram_sha_256,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "u",
        .payload = big_payload,
    } });
    try std.testing.expect(server.ipc.hasPendingSend());

    // Pending backlog: reconcile arms write interest exactly once.
    server.reconcileIpcWriteInterest(&changes);
    try std.testing.expect(server.ipc_write_armed);
    try std.testing.expectEqual(@as(usize, 1), changes.slice().len);
    changes.reset();
    server.reconcileIpcWriteInterest(&changes);
    try std.testing.expectEqual(@as(usize, 0), changes.slice().len);

    // Drain the peer and flush: reconcile disarms the idle link.
    var drain_buf: [8192]u8 = undefined;
    while (server.ipc.hasPendingSend()) {
        _ = posix.read(fds[1], &drain_buf) catch {};
        server.flushIpc(&changes);
    }
    try std.testing.expect(server.ipc.connected);
    server.reconcileIpcWriteInterest(&changes);
    try std.testing.expect(!server.ipc_write_armed);
    try std.testing.expectEqual(@as(usize, 1), changes.slice().len);
    try std.testing.expectEqual(std.c.EV.DELETE, changes.slice()[0].flags);
}

test "S10: IPC write interest lives only in server.zig" {
    // Write interest on either IPC link is armed and disarmed in exactly one
    // place, reconcileIpcWriteInterest. A send site that arms it itself leaves
    // a persistent EVFILT_WRITE with the *_write_armed flag still false, so no
    // later reconcile removes it and the filter fires writable every kevent.
    // The five such arms found in review 31 were deleted; this keeps them out.
    // The patterns are split so this test does not match itself.
    const auth_needle = "IPC_AUTH_" ++ "UDATA";
    const s2s_needle = "IPC_S2S_" ++ "UDATA";
    const cases = .{
        .{ "iq_handler.zig", @embedFile("iq_handler.zig") },
        .{ "router.zig", @embedFile("router.zig") },
        .{ "session_lifecycle.zig", @embedFile("session_lifecycle.zig") },
        .{ "presence_handler.zig", @embedFile("presence_handler.zig") },
        .{ "muc_handler.zig", @embedFile("muc_handler.zig") },
        .{ "message.zig", @embedFile("message.zig") },
        .{ "fanout.zig", @embedFile("fanout.zig") },
        .{ "caps.zig", @embedFile("caps.zig") },
    };
    inline for (cases) |case| {
        const name = case[0];
        const src = case[1];
        var auth_hits: usize = 0;
        var s2s_hits: usize = 0;
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, src, pos, auth_needle)) |hit| {
            auth_hits += 1;
            pos = hit + auth_needle.len;
        }
        pos = 0;
        while (std.mem.indexOfPos(u8, src, pos, s2s_needle)) |hit| {
            s2s_hits += 1;
            pos = hit + s2s_needle.len;
        }
        if (auth_hits != 0 or s2s_hits != 0) {
            log.err("S10: {s} references IPC write-interest udata (auth {d}, s2s {d}); " ++
                "let reconcileIpcWriteInterest arm it", .{ name, auth_hits, s2s_hits });
            return error.IpcWriteInterestOutsideReconciler;
        }
    }
}

test "S10: server.zig arms IPC write interest in exactly one place" {
    // The ratchet above cannot cover this file, which legitimately names the
    // IPC udata constants for read arms and event dispatch. Arming write
    // interest anywhere but reconcileIpcWriteInterest leaves a persistent
    // EVFILT_WRITE with the *_write_armed flag false, so nothing ever removes
    // it and the filter fires writable every kevent. Counting the exact arm
    // expressions confines both write arms to the reconciler.
    // The patterns are split so this test does not match itself.
    const src = @embedFile("server.zig");
    const cases = .{
        .{ "addWrite(self.ipc.fd, IPC_AUTH_" ++ "UDATA)", @as(usize, 1) },
        .{ "addWrite(self.s2s_ipc.fd, IPC_S2S_" ++ "UDATA)", @as(usize, 1) },
    };
    inline for (cases) |case| {
        const needle = case[0];
        const expected = case[1];
        var hits: usize = 0;
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, src, pos, needle)) |hit| {
            hits += 1;
            pos = hit + needle.len;
        }
        if (hits != expected) {
            log.err("S10: server.zig arms {s} {d} times, expected {d}; " ++
                "let reconcileIpcWriteInterest own it", .{ needle, hits, expected });
            return error.IpcWriteArmOutsideReconciler;
        }
    }
}

test "S10: the IPC reconnect timers are armed in exactly one place" {
    // The one-shot reconnect timer is the only thing that retries a dead IPC
    // link, so an arm staged outside the reconciler's reserved tail can be
    // lost to a batch that event handling filled, and the link stays down for
    // the worker's lifetime. Counting the arm sites keeps a second one out.
    // The patterns are split so this test does not match itself.
    const auth_needle = "addTimer(AUTH_RECONNECT_" ++ "TIMER_IDENT";
    const s2s_needle = "addTimer(S2S_RECONNECT_" ++ "TIMER_IDENT";
    const cases = .{
        .{ "server.zig", @embedFile("server.zig"), @as(usize, 1), @as(usize, 1) },
        .{ "connection.zig", @embedFile("connection.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "iq_handler.zig", @embedFile("iq_handler.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "router.zig", @embedFile("router.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "session_lifecycle.zig", @embedFile("session_lifecycle.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "presence_handler.zig", @embedFile("presence_handler.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "muc_handler.zig", @embedFile("muc_handler.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "message.zig", @embedFile("message.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "fanout.zig", @embedFile("fanout.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "caps.zig", @embedFile("caps.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "event_loop.zig", @embedFile("event_loop.zig"), @as(usize, 0), @as(usize, 0) },
    };
    inline for (cases) |case| {
        const name = case[0];
        const src = case[1];
        const auth_expected = case[2];
        const s2s_expected = case[3];
        var auth_hits: usize = 0;
        var s2s_hits: usize = 0;
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, src, pos, auth_needle)) |hit| {
            auth_hits += 1;
            pos = hit + auth_needle.len;
        }
        pos = 0;
        while (std.mem.indexOfPos(u8, src, pos, s2s_needle)) |hit| {
            s2s_hits += 1;
            pos = hit + s2s_needle.len;
        }
        if (auth_hits != auth_expected or s2s_hits != s2s_expected) {
            log.err("S10: {s} arms the reconnect timer {d}/{d} times, expected {d}/{d}; " ++
                "let stageReconnectTimers own it", .{ name, auth_hits, s2s_hits, auth_expected, s2s_expected });
            return error.ReconnectTimerArmOutsideReconciler;
        }
    }

    // An alias must not hide an additional timer arm from the exact-name
    // checks above. Split the needle so this test does not count itself.
    const any_timer_needle = "add" ++ "Timer(";
    const src = @embedFile("server.zig");
    var total: usize = 0;
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, src, pos, any_timer_needle)) |hit| {
        total += 1;
        pos = hit + any_timer_needle.len;
    }
    if (total != 13) {
        log.err("S10: server.zig has {d} timer arms, expected 13", .{total});
        return error.ReconnectTimerAliasOutsideReconciler;
    }
}

test "Server: S10 failed reconnect timer staging keeps retries pending" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    var change_buf: [1]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    try changes.addRead(3, 1);
    server.auth_reconnect_pending = true;
    server.s2s_reconnect_pending = true;

    server.reconcileIpcWriteInterest(&changes);

    try std.testing.expectEqual(@as(usize, 1), changes.count());
    try std.testing.expect(server.auth_reconnect_pending);
    try std.testing.expect(server.s2s_reconnect_pending);
}

test "Server: S10 a reconnect owed by a full batch still gets its timer" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_path: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_path);
    var sock_buf: [server.s2s_ipc_path_buf.len]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&sock_buf, "{s}/absent.sock", .{dir});
    @memcpy(server.s2s_ipc_path_buf[0..sock_path.len], sock_path);
    server.s2s_ipc_path_len = sock_path.len;

    // A batch already at its ordinary limit, built the way the event loop
    // builds it so the tail budget is production's. Two timers are all event
    // handling gets this iteration; the third slot below is reserved.
    var change_buf: [IPC_RECONCILE_RESERVED + 2]posix.Kevent = undefined;
    var changes = initLoopChangeList(&change_buf);
    try changes.addTimer(SM_EXPIRY_TIMER_IDENT, SM_EXPIRY_SWEEP_MS, false);
    try changes.addTimer(OFFLINE_RETRY_TIMER_IDENT, OFFLINE_RETRY_SWEEP_MS, false);
    try std.testing.expectError(error.ChangeListFull, changes.addRead(3, 1));

    // The link dies while the batch is full: the drop stages nothing and owes
    // a retry, then the reconciler spends a reserved slot on the timer.
    server.armS2sReconnect();
    server.reconcileIpcWriteInterest(&changes);
    try std.testing.expectEqual(@as(usize, 3), changes.count());
    try std.testing.expect(!server.s2s_reconnect_pending);

    var timer_found = false;
    for (changes.slice()) |ev| {
        if (ev.filter != std.c.EVFILT.TIMER) continue;
        if (ev.ident != S2S_RECONNECT_TIMER_IDENT) continue;
        try std.testing.expectEqual(@as(i64, S2S_RECONNECT_MS), ev.data);
        try std.testing.expect(ev.flags & std.c.EV.ONESHOT != 0);
        timer_found = true;
    }
    try std.testing.expect(timer_found);
}

test "Server: S10 a reconnect that cannot arm reads drops the link and owes a retry" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_path: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_path);
    var sock_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&sock_buf, "{s}/s2s.sock", .{dir});

    var listener = try TestIpcListener.init(sock_path);
    defer listener.deinit();
    try server.configureS2s(sock_path);
    try std.testing.expect(server.s2s_ipc.connected);

    // Take the link down so the retry below has something to reconnect.
    var drop_buf: [4]posix.Kevent = undefined;
    var drop_changes = ChangeList.init(&drop_buf);
    server.dropS2sIpc(&drop_changes);
    try std.testing.expect(!server.s2s_ipc.connected);
    server.s2s_reconnect_pending = false;

    // A changelist with no room left at all: connect() succeeds, so the link
    // looks up, but the read arm that would ever deliver a frame cannot be
    // staged. Leaving it connected strands federation silently, and the
    // one-shot timer that would have retried is already spent.
    var change_buf: [1]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    try changes.addRead(3, 1);
    try std.testing.expectEqual(@as(usize, 1), changes.count());

    server.tryS2sReconnect(&changes);
    try std.testing.expect(!server.s2s_ipc.connected);
    try std.testing.expectEqual(@as(posix.fd_t, -1), server.s2s_ipc.fd);
    try std.testing.expect(!server.s2s_write_armed);
    try std.testing.expect(server.s2s_reconnect_pending);
}

test "Server: S10 an auth reconnect that cannot arm reads drops the link and owes a retry" {
    // tryAuthReconnect and tryS2sReconnect each carry their own copy of the
    // fail-closed handling, so the auth one needs its own gate: a revert that
    // only touches it would otherwise pass the suite.
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_path: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_path);
    var sock_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&sock_buf, "{s}/auth.sock", .{dir});

    var listener = try TestIpcListener.init(sock_path);
    defer listener.deinit();
    try server.configureAuth(sock_path);
    try std.testing.expect(server.ipc.connected);

    var drop_buf: [4]posix.Kevent = undefined;
    var drop_changes = ChangeList.init(&drop_buf);
    server.dropIpcAuth(&drop_changes);
    try std.testing.expect(!server.ipc.connected);
    server.auth_reconnect_pending = false;

    var change_buf: [1]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    try changes.addRead(3, 1);

    server.tryAuthReconnect(&changes);
    try std.testing.expect(!server.ipc.connected);
    try std.testing.expectEqual(@as(posix.fd_t, -1), server.ipc.fd);
    try std.testing.expect(!server.ipc_write_armed);
    try std.testing.expect(server.auth_reconnect_pending);
}

test "Server: S10 reconcile arms IPC write interest from a full batch" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    server.ipc.fd = fds[0];
    server.ipc.connected = true;

    // Force a send backlog so the reconcile takes the arm path.
    var fill_buf: [65536]u8 = undefined;
    @memset(&fill_buf, 'x');
    _ = posix.write(fds[0], &fill_buf) catch 0;
    try server.ipc.send(.{ .auth_request = .{
        .conn_id = 9,
        .mechanism = .scram_sha_256,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "u",
        .payload = "P" ** 3000,
    } });
    try std.testing.expect(server.ipc.hasPendingSend());

    // A batch already at its ordinary limit: the changelist is built the way
    // the event loop builds it, so its tail budget is production's, and the
    // two slots below are all event handling gets this iteration.
    var change_buf: [IPC_RECONCILE_RESERVED + 2]posix.Kevent = undefined;
    var changes = initLoopChangeList(&change_buf);
    try changes.addTimer(SM_EXPIRY_TIMER_IDENT, SM_EXPIRY_SWEEP_MS, false);
    try changes.addTimer(OFFLINE_RETRY_TIMER_IDENT, OFFLINE_RETRY_SWEEP_MS, false);
    try std.testing.expectEqual(@as(usize, 2), changes.count());
    try std.testing.expectError(error.ChangeListFull, changes.addRead(fds[1], 1));

    // The reconcile still gets a reserved slot, so the arm is not lost and a
    // full batch cannot cost the link.
    server.reconcileIpcWriteInterest(&changes);
    try std.testing.expect(server.ipc.connected);
    try std.testing.expect(server.ipc_write_armed);
    try std.testing.expectEqual(@as(usize, 3), changes.count());
    try std.testing.expectEqual(IPC_AUTH_UDATA, changes.slice()[2].udata);
}

test "Server: S10 a deferred IPC disarm keeps the armed flag set" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    server.ipc.fd = fds[0];
    server.ipc.connected = true;
    // Idle link with interest believed armed: the reconcile must disarm it.
    try std.testing.expect(!server.ipc.hasPendingSend());
    server.ipc_write_armed = true;

    // Every slot spent, reserved tail included, so the removal cannot stage.
    // The filler idents are never submitted, only used to exhaust the budget.
    var change_buf: [IPC_RECONCILE_RESERVED + 2]posix.Kevent = undefined;
    var changes = initLoopChangeList(&change_buf);
    for (0..IPC_RECONCILE_RESERVED + 2) |i| {
        // Spending the reserved tail too, which is the worst case: even the
        // reconcile's own budget is gone, so nothing can be staged at all.
        changes.beginReserved();
        changes.addTimer(SM_EXPIRY_TIMER_IDENT, @intCast(i), false) catch {};
        changes.endReserved();
    }
    try std.testing.expectEqual(change_buf.len, changes.count());

    server.reconcileIpcWriteInterest(&changes);

    // The filter is still live in the kernel, so the flag must stay set and the
    // next iteration must retry. Clearing it here would strand a persistent
    // writable filter that nothing ever removes.
    try std.testing.expect(server.ipc_write_armed);
    try std.testing.expectEqual(change_buf.len, changes.count());

    // With room available the retry lands and the flag clears.
    changes.reset();
    server.reconcileIpcWriteInterest(&changes);
    try std.testing.expect(!server.ipc_write_armed);
    try std.testing.expectEqual(@as(usize, 1), changes.count());
    try std.testing.expectEqual(std.c.EV.DELETE, changes.slice()[0].flags);
}

/// Listening AF_UNIX socket, for exercising a real IPC reconnect.
const TestIpcListener = struct {
    fd: posix.fd_t = -1,
    path: []const u8,

    fn init(path: []const u8) !TestIpcListener {
        var self = TestIpcListener{ .path = path };
        std.fs.cwd().deleteFile(path) catch {};

        const fd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0);
        errdefer posix.close(fd);

        var addr: std.c.sockaddr.un = std.mem.zeroes(std.c.sockaddr.un);
        addr.family = posix.AF.UNIX;
        if (path.len >= addr.path.len) return error.PathTooLong;
        @memcpy(addr.path[0..path.len], path);

        posix.bind(fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.un)) catch |err| {
            posix.close(fd);
            return err;
        };
        errdefer posix.close(fd);
        try posix.listen(fd, 8);

        self.fd = fd;
        return self;
    }

    fn deinit(self: *TestIpcListener) void {
        if (self.fd >= 0) posix.close(self.fd);
        std.fs.cwd().deleteFile(self.path) catch {};
    }
};

test "Server: S10 dropped S2S link arms a reconnect and recovers" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    // A per-test directory: a fixed socket path under /tmp would collide if two
    // workers ran this suite at once.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_path: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_path);
    var sock_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&sock_buf, "{s}/s2s.sock", .{dir});

    var listener = try TestIpcListener.init(sock_path);
    defer listener.deinit();

    // configureS2s retains the path, which is what makes a later retry possible.
    try server.configureS2s(sock_path);
    try std.testing.expect(server.s2s_ipc.connected);
    const retained = server.s2sIpcPath();
    try std.testing.expect(retained != null);
    try std.testing.expectEqualStrings(sock_path, retained.?);

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // Link dies: dropped, fd purged, and a retry owed. The timer is staged by
    // the reconciler out of its reserved tail, not at the drop site, so a drop
    // landing on an already-full batch cannot lose the only retry trigger.
    server.dropS2sIpc(&changes);
    try std.testing.expect(!server.s2s_ipc.connected);
    try std.testing.expectEqual(@as(posix.fd_t, -1), server.s2s_ipc.fd);
    try std.testing.expect(!server.s2s_write_armed);
    try std.testing.expect(server.s2s_reconnect_pending);
    try std.testing.expectEqual(@as(usize, 0), changes.count());

    server.reconcileIpcWriteInterest(&changes);
    try std.testing.expect(!server.s2s_reconnect_pending);
    var timer_found = false;
    for (changes.slice()) |ev| {
        if (ev.filter != std.c.EVFILT.TIMER) continue;
        if (ev.ident != S2S_RECONNECT_TIMER_IDENT) continue;
        try std.testing.expectEqual(@as(i64, S2S_RECONNECT_MS), ev.data);
        try std.testing.expect(ev.flags & std.c.EV.ONESHOT != 0);
        timer_found = true;
    }
    try std.testing.expect(timer_found);

    // A second drop is a no-op, not a second purge of a recycled fd number.
    changes.reset();
    server.dropS2sIpc(&changes);
    try std.testing.expectEqual(@as(usize, 0), changes.count());

    // The daemon is listening again: the retry reconnects and re-arms reads.
    changes.reset();
    server.tryS2sReconnect(&changes);
    try std.testing.expect(server.s2s_ipc.connected);
    try std.testing.expect(server.s2s_ipc.fd >= 0);

    var read_found = false;
    for (changes.slice()) |ev| {
        if (ev.filter != std.c.EVFILT.READ) continue;
        if (ev.udata != IPC_S2S_UDATA) continue;
        read_found = true;
    }
    try std.testing.expect(read_found);
}

test "Server: S10 S2S reconnect with no daemon re-arms and stays down" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    // Nothing listening: the retry must re-arm rather than give up, and must
    // not leave a half-open link that looks connected. The path is under a
    // private temp dir and no socket file is created there.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_path: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_path);
    var sock_buf: [server.s2s_ipc_path_buf.len]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&sock_buf, "{s}/absent.sock", .{dir});
    @memcpy(server.s2s_ipc_path_buf[0..sock_path.len], sock_path);
    server.s2s_ipc_path_len = sock_path.len;

    var change_buf: [8]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.tryS2sReconnect(&changes);

    // The attempt owes another one; the reconciler turns that into a timer.
    try std.testing.expect(!server.s2s_ipc.connected);
    try std.testing.expect(server.s2s_reconnect_pending);
    server.reconcileIpcWriteInterest(&changes);
    var timer_found = false;
    for (changes.slice()) |ev| {
        if (ev.filter == std.c.EVFILT.TIMER and ev.ident == S2S_RECONNECT_TIMER_IDENT) timer_found = true;
    }
    try std.testing.expect(timer_found);
    try std.testing.expect(!server.s2s_reconnect_pending);
}

// G6: the auth half of the reconnect-timer guarantee needs its own gates, or a
// revert that only touches the auth staging or the auth re-arm would pass the
// suite on the strength of the S2S tests alone.
test "Server: G6 an auth reconnect owed by a full batch still gets its timer" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    // A batch already at its ordinary limit, built the way the event loop
    // builds it so the tail budget is production's. The third slot is reserved.
    var change_buf: [IPC_RECONCILE_RESERVED + 2]posix.Kevent = undefined;
    var changes = initLoopChangeList(&change_buf);
    try changes.addTimer(SM_EXPIRY_TIMER_IDENT, SM_EXPIRY_SWEEP_MS, false);
    try changes.addTimer(OFFLINE_RETRY_TIMER_IDENT, OFFLINE_RETRY_SWEEP_MS, false);
    try std.testing.expectError(error.ChangeListFull, changes.addRead(3, 1));

    server.armAuthReconnect();
    server.reconcileIpcWriteInterest(&changes);
    try std.testing.expectEqual(@as(usize, 3), changes.count());
    try std.testing.expect(!server.auth_reconnect_pending);

    var timer_found = false;
    for (changes.slice()) |ev| {
        if (ev.filter != std.c.EVFILT.TIMER) continue;
        if (ev.ident != AUTH_RECONNECT_TIMER_IDENT) continue;
        try std.testing.expectEqual(@as(i64, AUTH_RECONNECT_MS), ev.data);
        try std.testing.expect(ev.flags & std.c.EV.ONESHOT != 0);
        timer_found = true;
    }
    try std.testing.expect(timer_found);
}

test "Server: G6 auth reconnect with no daemon re-arms and stays down" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    // Nothing listening: the retry must re-arm rather than give up, and must
    // not leave a half-open link that looks connected. No socket file exists.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_path: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_path);
    var sock_buf: [server.auth_ipc_path_buf.len]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&sock_buf, "{s}/absent.sock", .{dir});
    @memcpy(server.auth_ipc_path_buf[0..sock_path.len], sock_path);
    server.auth_ipc_path_len = sock_path.len;

    var change_buf: [8]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.tryAuthReconnect(&changes);

    // The failed connect owes another attempt; the reconciler makes it a timer.
    try std.testing.expect(!server.ipc.connected);
    try std.testing.expect(server.auth_reconnect_pending);
    server.reconcileIpcWriteInterest(&changes);
    var timer_found = false;
    for (changes.slice()) |ev| {
        if (ev.filter == std.c.EVFILT.TIMER and ev.ident == AUTH_RECONNECT_TIMER_IDENT) timer_found = true;
    }
    try std.testing.expect(timer_found);
    try std.testing.expect(!server.auth_reconnect_pending);
}

test "Server: S10 auth IPC decode error drops the link" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    server.ipc.fd = fds[0];
    server.ipc.connected = true;

    var change_buf: [8]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // A well-formed frame whose tag does not decode.
    const garbage = [_]u8{ 1, 0, 0, 0, 0xFE };
    _ = try posix.write(fds[1], &garbage);
    server.handleIpcReadable(&changes);

    // The bad frame is never consumed; only dropping the link unwedges it.
    try std.testing.expect(!server.ipc.connected);
    try std.testing.expectEqual(@as(posix.fd_t, -1), server.ipc.fd);
}

test "Server: S10 s2s IPC decode error drops the link" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    server.s2s_ipc.fd = fds[0];
    server.s2s_ipc.connected = true;

    var change_buf: [8]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // A well-formed frame whose tag does not decode.
    const garbage = [_]u8{ 1, 0, 0, 0, 0xFE };
    _ = try posix.write(fds[1], &garbage);
    server.handleS2sIpcReadable(&changes);

    try std.testing.expect(!server.s2s_ipc.connected);
    try std.testing.expectEqual(@as(posix.fd_t, -1), server.s2s_ipc.fd);
}

test "Server: S10 handshake write interest is one-shot" {
    const allocator = std.testing.allocator;
    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const pem_path = try connection_mod.makeTestPem(allocator, tmp.dir);
    defer allocator.free(pem_path);
    server.ssl_ctx = try ssl.SslContext.initServer(pem_path, pem_path);
    var client_ctx = try ssl.SslContext.initClient();
    defer client_ctx.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, allocator);
    server.sessions[1] = session;

    // Small send buffer: the server's first handshake flight cannot go out
    // in one write, so the handshake parks in want_write.
    const sndbuf: c_int = 1024;
    try posix.setsockopt(fds[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&sndbuf));

    var client_tls = try ssl.SslConn.initClient(client_ctx, fds[1], null);
    defer client_tls.deinit();
    _ = client_tls.doHandshake() catch .want_read;

    try session.conn.upgradeToTls(server.ssl_ctx.?);

    // Fill the server->client direction: the handshake flight cannot go
    // out, so the handshake parks in want_write. The filler only pollutes
    // the client's side, which this test never reads again.
    var fill_buf: [65536]u8 = undefined;
    @memset(&fill_buf, 'x');
    while (true) {
        _ = posix.write(fds[0], &fill_buf) catch break;
    }

    var change_buf: [8]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    server.continueTlsHandshake(1, session, &changes);
    try std.testing.expectEqual(connection_mod.TlsState.handshake_want_write, session.conn.tls_state.?);

    // The staged re-arm must be EV_ONESHOT; a persistent filter fires on
    // every kevent while the client's next flight is in flight (S10).
    var found_oneshot = false;
    for (changes.slice()) |ev| {
        if (ev.filter == std.c.EVFILT.WRITE) {
            try std.testing.expect((ev.flags & std.c.EV.ONESHOT) != 0);
            found_oneshot = true;
        }
    }
    try std.testing.expect(found_oneshot);
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

// Force analysis of sibling files whose tests otherwise never run.
test {
    _ = iq_handler;
    _ = router;
}
