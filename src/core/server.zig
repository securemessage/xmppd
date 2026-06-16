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
const vcard_store_mod = @import("vcard_store");
const GenericVCardStore = vcard_store_mod.VCardStore(OpBackendType);
const iq_handler = @import("iq_handler.zig");
const muc_handler = @import("muc_handler.zig");
const presence_handler = @import("presence_handler.zig");
const router = @import("router.zig");
const session_lifecycle = @import("session_lifecycle.zig");
const room_registry_mod = @import("room_registry");
const RoomRegistry = room_registry_mod.RoomRegistry;
const room_store_mod = @import("room_store");
const GenericRoomStore = room_store_mod.RoomStore(OpBackendType);
const fanout_mod = @import("fanout.zig");
const FanoutQueue = fanout_mod.FanoutQueue;
const actor_message = @import("message.zig");
pub const sm_state = @import("sm_state.zig");
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

/// Interval for SM detached session expiry sweep (milliseconds).
const SM_EXPIRY_SWEEP_MS: u32 = 30_000;

/// Maximum changelist entries per event loop iteration.
/// Must be large enough to accommodate presence broadcasts, roster pushes,
/// and SM acks across many concurrent connections without silent drops.
const CHANGE_BUF_SIZE = 1024;

/// Maximum XML element nesting depth allowed.
/// XMPP stanzas are shallow (stream=1, stanza=2, children=3-5 typically).
/// Anything deeper than this is either malformed or an attack (deep nesting DoS).
/// Connection is terminated with a stream error if exceeded.
const MAX_ELEMENT_DEPTH = 50;

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
    stanza_to: []const u8 = "",
    stanza_id: []const u8 = "",
    stanza_type: []const u8 = "",

    /// Bind IQ accumulation — deferred until </iq> so <resource> text is parsed.
    bind_iq_id: []const u8 = "",
    bind_resource_buf: [256]u8 = undefined,
    bind_resource_len: usize = 0,
    bind_collecting_resource: bool = false,
    bind_pending: bool = false,

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
    /// Whether a <remove/> element was seen inside jabber:iq:register (account deletion).
    reg_has_remove: bool = false,
    /// IQ id for a pending password change/deletion response (awaiting auth daemon reply).
    reg_pending_iq_id: []const u8 = "",

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
        self.stanza_to = "";
        self.stanza_id = "";
        self.stanza_type = "";
    }

    /// Track an outbound stanza for SM purposes.
    /// Increments sm_out_seq and buffers the stanza in the unacked queue (if resume enabled).
    /// Call this after successfully queueing a complete stanza (message/presence/iq) to the client.
    pub fn smTrackOutbound(self: *Session, stanza_data: []const u8) void {
        if (!self.sm_enabled) return;
        self.sm_out_seq +%= 1;
        if (self.sm_unacked) |queue| {
            queue.push(stanza_data);
        }
    }
};

/// Entry in the SM-ID → session slot hash map (T127).
const SmIdEntry = struct {
    occupied: bool = false,
    sm_id: [sm_state.SM_ID_HEX_LEN]u8 = undefined,
    slot: usize = 0,
};

/// FNV-1a hash of an SM-ID for map indexing (T127).
fn hashSmId(id: *const [sm_state.SM_ID_HEX_LEN]u8) usize {
    var h: u64 = 0xcbf29ce484222325;
    for (id) |byte| {
        h ^= byte;
        h *%= 0x100000001b3;
    }
    return @intCast(h % 64);
}

/// The XMPP core server.
pub const Server = struct {
    loop: EventLoop,
    listener: Listener,
    allocator: std.mem.Allocator,
    server_host: []const u8,
    running: bool = true,

    /// Session table — indexed by session ID. Heap-allocated, size configurable.
    sessions: []?*Session = &.{},
    max_sessions: usize = DEFAULT_MAX_SESSIONS,

    /// Free-list stack for O(1) session ID allocation (T128).
    free_ids: []usize = &.{},
    free_count: usize = 0,

    /// TLS context — shared across all connections. Null if TLS is not configured.
    ssl_ctx: ?ssl.SslContext = null,

    /// IPC client for auth daemon communication.
    ipc: IpcClient = .{},

    /// IPC client for S2S daemon communication (federation).
    s2s_ipc: IpcClient = .{},

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

    /// Archive store — MAM message archive (stanza payloads).
    archive: ?*archive_store_mod.ArchiveStore(ArchiveBackendType) = null,

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

    /// MUC service hostname (e.g., "conference.example.com").
    muc_host: ?[]const u8 = null,

    /// Pending fan-out queue — bounded continuation for MUC groupchat delivery.
    fanout_queue: FanoutQueue = .{},

    /// Number of currently detached SM sessions (T124 — avoids full sweep when 0).
    detached_count: u16 = 0,

    /// SM-ID → session slot index map for O(1) resume lookup (T127).
    /// Open-addressing table with FNV-1a hash. Capacity must exceed max concurrent detached sessions.
    sm_id_map: [64]SmIdEntry = [_]SmIdEntry{SmIdEntry{}} ** 64,

    /// Monotonic counter for generating unique stanza IDs (XEP-0359).
    /// Combined with worker_id to ensure uniqueness across threads.
    stanza_id_counter: u32 = 0,

    /// SASL mechanism names received from auth daemon (dynamic advertisement).
    /// Stored as slices into auth_mechanism_name_buf.
    auth_mechanisms: [8][]const u8 = .{""} ** 8,
    auth_mechanism_count: u8 = 0,
    /// Backing storage for mechanism name strings.
    auth_mechanism_name_buf: [256]u8 = undefined,

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

        const listener = try Listener.init(address, port, false, 128);

        return Server{
            .loop = loop,
            .listener = listener,
            .sessions = sessions,
            .max_sessions = max_sessions,
            .free_ids = free_ids,
            .free_count = fc,
            .allocator = allocator,
            .server_host = host,
        };
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

        return Server{
            .loop = loop,
            .listener = listener,
            .sessions = sessions,
            .max_sessions = max_sessions,
            .free_ids = free_ids,
            .free_count = fc,
            .allocator = allocator,
            .server_host = host,
        };
    }

    /// Connect to the auth daemon IPC socket.
    /// Must be called before `run()`. Without this, SASL auth requests
    /// will receive temporary-auth-failure.
    pub fn configureAuth(self: *Server, socket_path: []const u8) !void {
        self.ipc.connect(socket_path) catch |err| {
            log.err("failed to connect to auth daemon at {s}: {}", .{ socket_path, err });
            return error.AuthConfigFailed;
        };
        log.info("connected to auth daemon at {s}", .{socket_path});
    }

    /// Configure the roster store (generic backend-backed).
    pub fn configureRoster(self: *Server, roster_store: *GenericRosterStore) void {
        self.roster = roster_store;
        log.info("roster store configured", .{});
    }

    /// Connect to the S2S federation daemon IPC socket.
    /// Optional — without this, stanzas to remote domains are bounced.
    pub fn configureS2s(self: *Server, socket_path: []const u8) !void {
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
        self.listener.deinit();
        self.loop.deinit();
        if (self.ssl_ctx) |*ctx| ctx.deinit();
        if (self.ipc.connected) self.ipc.close();
        if (self.s2s_ipc.connected) self.s2s_ipc.close();
    }

    /// Run the main event loop. Blocks until SIGTERM or `stop()` is called.
    pub fn run(self: *Server) !void {
        var change_buf: [CHANGE_BUF_SIZE]posix.Kevent = undefined;
        var changes = ChangeList.init(&change_buf);

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

        while (self.running) {
            // Mark active before processing events (coalesced signaling)
            if (self.delivery_system) |ds| {
                ds.getState(self.worker_id).setActive();
            }

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

            for (events) |ev| {
                switch (ev) {
                    .fd_readable => |e| {
                        if (e.udata == LISTENER_UDATA) {
                            session_lifecycle.acceptConnections(self, &changes);
                        } else if (e.udata == IPC_AUTH_UDATA) {
                            self.handleIpcReadable(&changes);
                        } else if (e.udata == IPC_S2S_UDATA) {
                            self.handleS2sIpcReadable(&changes);
                        } else if (e.udata == WAKE_PIPE_UDATA) {
                            // Already handled in first pass
                        } else {
                            self.handleReadableOrHandshake(e.udata, &changes);
                        }
                    },
                    .fd_writable => |e| {
                        if (e.udata == IPC_AUTH_UDATA) {
                            self.flushIpc(&changes);
                        } else if (e.udata == IPC_S2S_UDATA) {
                            self.flushS2sIpc(&changes);
                        } else {
                            self.handleWritableOrHandshake(e.udata, &changes);
                        }
                    },
                    .signal => |s| {
                        if (s.signo == posix.SIG.TERM or s.signo == posix.SIG.INT) {
                            self.running = false;
                        }
                    },
                    .timer => |t| {
                        if (t.ident == SM_EXPIRY_TIMER_IDENT) {
                            session_lifecycle.expireDetachedSessions(self, &changes);
                        }
                    },
                    .fd_error => |e| {
                        if (e.udata != LISTENER_UDATA and e.udata != IPC_AUTH_UDATA and e.udata != IPC_S2S_UDATA and e.udata != WAKE_PIPE_UDATA) {
                            session_lifecycle.closeSession(self, e.udata, &changes);
                        }
                    },
                    else => {},
                }
            }

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

    fn continueTlsHandshake(self: *Server, id: usize, session: *Session, changes: *ChangeList) void {
        const complete = session.conn.continueHandshake() catch {
            log.err("connection {d} TLS handshake failed", .{id});
            session_lifecycle.closeSession(self, id, changes);
            return;
        };

        if (complete) {
            log.info("connection {d} TLS handshake complete", .{id});
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
            // Re-arm the appropriate kqueue filter
            if (session.conn.tls_state) |state| {
                switch (state) {
                    .handshake_want_read => changes.addRead(session.conn.fd, id) catch {},
                    .handshake_want_write => changes.addWrite(session.conn.fd, id) catch {},
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
            var pos: usize = 0;

            while (true) {
                const event = session.reader.next(data, &pos) catch |err| {
                    log.err("connection {d} XML parse error: {}", .{ id, err });
                    self.sendStreamError(session, .not_well_formed);
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

                self.processXmlEvent(session, event.?, changes);

                if (self.sessions[id] == null) return;
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
            changes.addWrite(session.conn.fd, id) catch {};
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
        _ = changes;

        // Extract 'to' attribute
        var to: []const u8 = "";
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "to")) {
                to = attr.value;
                break;
            }
        }

        const action = session.stream.handleStreamOpen(to, "1.0");
        self.executeAction(session, action);
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
                const action = session.stream.handleStarttls();
                self.executeAction(session, action);
                // TLS handshake wiring comes in step 5g
            }
            return;
        }

        // SASL namespace
        if (std.mem.eql(u8, ns, xml.ns.sasl)) {
            if (std.mem.eql(u8, elem.local_name, "auth")) {
                self.handleSaslAuth(session, elem);
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

        // Pre-bind IQ wrapper — capture the IQ id for the bind result
        if (!session.stream.isActive() and session.stream.state == .features_bind) {
            if (std.mem.eql(u8, elem.local_name, "iq")) {
                for (elem.attributes) |attr| {
                    if (std.mem.eql(u8, attr.local_name, "id")) {
                        session.bind_iq_id = attr.value;
                        break;
                    }
                }
            }
            return;
        }

        // XEP-0198: Stream Management namespace — handle in active or just-bound state
        if (std.mem.eql(u8, ns, xml.ns.sm)) {
            if (std.mem.eql(u8, elem.local_name, "enable") and session.stream.isActive()) {
                self.handleSmEnable(session, elem, changes);
            } else if (std.mem.eql(u8, elem.local_name, "r") and session.sm_enabled) {
                self.handleSmRequest(session, changes);
            } else if (std.mem.eql(u8, elem.local_name, "a") and session.sm_enabled) {
                // Client acknowledges our stanzas
                for (elem.attributes) |attr| {
                    if (std.mem.eql(u8, attr.local_name, "h")) {
                        const client_h = std.fmt.parseInt(u32, attr.value, 10) catch 0;
                        session.sm_out_h = client_h;
                        if (session.sm_unacked) |queue| {
                            queue.ack(client_h);
                        }
                        break;
                    }
                }
            } else if (std.mem.eql(u8, elem.local_name, "resume") and session.stream.state == .features_bind) {
                self.handleSmResume(session, elem, changes);
            }
            return;
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
                // Stanza complete (depth back to stream level) — route to targets
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
                session_lifecycle.handleBind(self, session, resource);
                session.bind_pending = false;
                session.bind_resource_len = 0;
                session.bind_iq_id = "";
                if (session.conn.hasPendingWrite()) {
                    changes.addWrite(session.conn.fd, session.conn.id) catch {};
                }
                return;
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

        // Registration text — stop collecting on </username> or </password>
        if (session.iq_active and session.reg_collecting_username) {
            session.reg_collecting_username = false;
        }
        if (session.iq_active and session.reg_collecting_password) {
            session.reg_collecting_password = false;
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

    fn handleSaslAuth(self: *Server, session: *Session, elem: xml.Element) void {
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
            else => self.executeAction(session, action),
        }
    }

    /// Called when </auth> is reached — we have the full base64 payload.
    fn processSaslAuthComplete(self: *Server, session: *Session, changes: *ChangeList) void {
        session.sasl_collecting = .none;

        if (!self.ipc.connected) {
            log.warn("connection {d} auth request but no auth daemon", .{session.conn.id});
            const fail_action = session.stream.saslFailure();
            self.executeAction(session, fail_action);
            return;
        }

        // Decode base64 from XML into raw SASL payload
        const b64_data = session.sasl_buf[0..session.sasl_buf_len];
        var decoded_buf: [3072]u8 = undefined;
        const decoded = b64Decode(b64_data, &decoded_buf) orelse {
            log.warn("connection {d} invalid base64 in SASL auth", .{session.conn.id});
            const fail_action = session.stream.saslFailure();
            self.executeAction(session, fail_action);
            return;
        };

        // Determine mechanism ID
        const mech_id = ipc_protocol.MechanismId.fromName(session.sasl_mechanism) orelse {
            const fail_action = session.stream.saslFailure();
            self.executeAction(session, fail_action);
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
            const fail_action = session.stream.saslFailure();
            self.executeAction(session, fail_action);
            return;
        };

        session.auth_state = .awaiting_challenge;

        // Ensure we watch for IPC writes if needed
        if (self.ipc.hasPendingSend()) {
            changes.addWrite(self.ipc.fd, IPC_AUTH_UDATA) catch {};
        }
    }

    /// Called when </response> is reached — we have the full SCRAM response.
    fn processSaslResponseComplete(self: *Server, session: *Session, changes: *ChangeList) void {
        session.sasl_collecting = .none;

        if (!self.ipc.connected) {
            const fail_action = session.stream.saslFailure();
            self.executeAction(session, fail_action);
            return;
        }

        // Decode base64
        const b64_data = session.sasl_buf[0..session.sasl_buf_len];
        var decoded_buf: [3072]u8 = undefined;
        const decoded = b64Decode(b64_data, &decoded_buf) orelse {
            log.warn("connection {d} invalid base64 in SASL response", .{session.conn.id});
            const fail_action = session.stream.saslFailure();
            self.executeAction(session, fail_action);
            return;
        };

        // Send SaslResponse to auth daemon
        self.ipc.send(.{ .sasl_response = .{
            .conn_id = session.ipcConnId(),
            .payload = decoded,
        } }) catch {
            log.err("connection {d} failed to send SASL response via IPC", .{session.conn.id});
            const fail_action = session.stream.saslFailure();
            self.executeAction(session, fail_action);
            return;
        };

        session.auth_state = .awaiting_result;

        if (self.ipc.hasPendingSend()) {
            changes.addWrite(self.ipc.fd, IPC_AUTH_UDATA) catch {};
        }
    }

    // ========================================================================
    // IPC response handling — auth daemon responses dispatched to sessions
    // ========================================================================

    fn handleIpcReadable(self: *Server, changes: *ChangeList) void {
        _ = self.ipc.recv() catch {
            log.err("auth daemon IPC recv error", .{});
            self.ipc.close();
            return;
        };

        // Process all complete messages
        while (true) {
            const msg = self.ipc.nextMessage() catch {
                log.err("auth daemon IPC decode error", .{});
                break;
            };
            if (msg == null) break;
            self.dispatchAuthResponse(msg.?, changes);
        }
    }

    fn flushIpc(self: *Server, changes: *ChangeList) void {
        _ = self.ipc.flush() catch {
            log.err("auth daemon IPC flush error", .{});
            return;
        };
        if (self.ipc.hasPendingSend()) {
            changes.addWrite(self.ipc.fd, IPC_AUTH_UDATA) catch {};
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

                const success_action = session.stream.saslSuccess(stable_username, server_final_b64);
                self.executeAction(session, success_action);
                session.resetSasl();

                if (session.conn.hasPendingWrite()) {
                    changes.addWrite(session.conn.fd, conn_id) catch {};
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
                const fail_action = session.stream.saslFailure();
                self.executeAction(session, fail_action);
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
                session.conn.queueSend(fbs.getWritten()) catch return;

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
                    session.conn.queueSend(fbs.getWritten()) catch return;

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
                    session.conn.queueSend(fbs.getWritten()) catch return;

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

        if (self.s2s_ipc.hasPendingSend()) {
            changes.addWrite(self.s2s_ipc.fd, IPC_S2S_UDATA) catch {};
        }
    }

    /// Forward a pre-built presence stanza to a remote domain via S2S IPC.
    /// Variant without a session reference — used by broadcast presence.
    pub fn sendPresenceViaS2s(self: *Server, from_str: []const u8, to_str: []const u8, stanza_xml: []const u8, changes: *ChangeList) void {
        if (!self.s2s_ipc.connected) return;

        self.s2s_ipc.send(.{ .s2s_deliver = .{
            .from_jid = from_str,
            .to_jid = to_str,
            .stanza_xml = stanza_xml,
        } }) catch return;

        if (self.s2s_ipc.hasPendingSend()) {
            changes.addWrite(self.s2s_ipc.fd, IPC_S2S_UDATA) catch {};
        }
    }

    fn handleS2sIpcReadable(self: *Server, changes: *ChangeList) void {
        _ = self.s2s_ipc.recv() catch {
            log.err("S2S daemon IPC recv error", .{});
            self.s2s_ipc.close();
            return;
        };

        while (true) {
            const msg = self.s2s_ipc.nextMessage() catch {
                log.err("S2S daemon IPC decode error", .{});
                break;
            };
            if (msg == null) break;
            self.dispatchS2sResponse(msg.?, changes);
        }
    }

    fn flushS2sIpc(self: *Server, changes: *ChangeList) void {
        _ = self.s2s_ipc.flush() catch {
            log.err("S2S daemon IPC flush error", .{});
            return;
        };
        if (self.s2s_ipc.hasPendingSend()) {
            changes.addWrite(self.s2s_ipc.fd, IPC_S2S_UDATA) catch {};
        }
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
                var s2s_entries: [16]SessionEntry = undefined;
                const target_count = if (to_jid.resource.len > 0) blk: {
                    if (s2s_sm.findByFullJid(to_jid.local, to_jid.domain, to_jid.resource)) |e| {
                        s2s_entries[0] = e;
                        break :blk @as(usize, 1);
                    }
                    break :blk @as(usize, 0);
                } else s2s_sm.findAvailableByBareJid(to_jid.local, to_jid.domain, &s2s_entries);

                // Single timestamp for all S2S archive operations (T123)
                const s2s_archive_ts: u64 = @intCast(std.time.timestamp());

                if (target_count == 0) {
                    // Try offline storage for messages — only if this is a <message> stanza
                    if (self.offline) |store| {
                        if (self.archive) |archive| {
                            const parts = extractStanzaParts(m.stanza_xml);
                            if (parts.is_message) {
                                var recip_buf: [256]u8 = undefined;
                                var recip_fbs = std.io.fixedBufferStream(&recip_buf);
                                recip_fbs.writer().writeAll(to_jid.local) catch {};
                                recip_fbs.writer().writeByte('@') catch {};
                                recip_fbs.writer().writeAll(to_jid.domain) catch {};
                                const recipient_bare = recip_fbs.getWritten();

                                const stanza_id = if (parts.msg_id.len > 0) parts.msg_id else "s2s-offline";

                                // Store full stanza in archive, pointer in offline
                                archive.store(recipient_bare, m.from_jid, stanza_id, s2s_archive_ts, m.stanza_xml) catch {};
                                if (store.storePointer(recipient_bare, m.from_jid, stanza_id, s2s_archive_ts) catch false) {
                                    log.info("S2S inbound to {s} stored offline", .{m.to_jid});
                                    return;
                                }
                            }
                        }
                    }
                    log.info("S2S inbound to {s} — recipient unavailable, no offline", .{m.to_jid});
                    return;
                }

                // Archive S2S inbound messages delivered to online recipients (T81)
                if (self.archive) |archive| {
                    const parts = extractStanzaParts(m.stanza_xml);
                    if (parts.is_message and std.mem.indexOf(u8, parts.inner_xml, "<body") != null) {
                        var recip_buf: [256]u8 = undefined;
                        var recip_fbs = std.io.fixedBufferStream(&recip_buf);
                        recip_fbs.writer().writeAll(to_jid.local) catch {};
                        recip_fbs.writer().writeByte('@') catch {};
                        recip_fbs.writer().writeAll(to_jid.domain) catch {};
                        const recipient_bare = recip_fbs.getWritten();

                        var s2s_sid_buf: [32]u8 = undefined;
                        const s2s_stanza_id = self.generateStanzaId(&s2s_sid_buf);

                        // Archive under recipient bare JID
                        archive.store(recipient_bare, m.from_jid, s2s_stanza_id, s2s_archive_ts, m.stanza_xml) catch {};
                    }
                }

                for (s2s_entries[0..target_count]) |entry| {
                    if (entry.worker_id == self.worker_id) {
                        const target_session = self.sessions[entry.local_session_id] orelse continue;
                        target_session.conn.queueSend(m.stanza_xml) catch continue;
                        if (target_session.conn.hasPendingWrite()) {
                            changes.addWrite(target_session.conn.fd, entry.local_session_id) catch {};
                        }
                    } else if (self.delivery_system) |ds| {
                        ds.deliver(entry.worker_id, entry.local_session_id, entry.generation, m.stanza_xml) catch {};
                    }
                }
                log.info("S2S inbound from {s} delivered to {d} session(s)", .{ m.from_jid, target_count });
            },
            .s2s_delivery_failed => |m| {
                // Delivery to remote failed — bounce error to original sender
                const from_jid = xmpp.Jid.parse(m.from_jid) catch return;

                const fail_sm = self.session_map orelse return;
                var sender_entries: [16]SessionEntry = undefined;
                const sender_count = if (from_jid.resource.len > 0) blk: {
                    if (fail_sm.findByFullJid(from_jid.local, from_jid.domain, from_jid.resource)) |e| {
                        sender_entries[0] = e;
                        break :blk @as(usize, 1);
                    }
                    break :blk @as(usize, 0);
                } else fail_sm.findAvailableByBareJid(from_jid.local, from_jid.domain, &sender_entries);

                // Build error stanza once for all targets
                var err_buf: [1024]u8 = undefined;
                var err_fbs = std.io.fixedBufferStream(&err_buf);
                const ew = err_fbs.writer();
                ew.writeAll("<message type='error' from='") catch return;
                ew.writeAll(m.to_jid) catch return;
                ew.writeAll("' to='") catch return;
                ew.writeAll(m.from_jid) catch return;
                ew.writeAll("'><error type='cancel'><") catch return;
                ew.writeAll(m.error_type) catch return;
                ew.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>") catch return;
                const err_xml = err_fbs.getWritten();

                for (sender_entries[0..sender_count]) |sentry| {
                    if (sentry.worker_id == self.worker_id) {
                        const sender_session = self.sessions[sentry.local_session_id] orelse continue;
                        sender_session.conn.queueSend(err_xml) catch continue;
                        if (sender_session.conn.hasPendingWrite()) {
                            changes.addWrite(sender_session.conn.fd, sentry.local_session_id) catch {};
                        }
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
    fn accumulateStanzaElement(self: *Server, session: *Session, elem: xml.Element) void {
        _ = self;
        var fbs = std.io.fixedBufferStream(session.stanza_buf[session.stanza_buf_len..]);
        const w = fbs.writer();

        w.writeByte('<') catch return;
        w.writeAll(elem.name) catch return;

        // Reconstruct namespace declaration if element uses a non-default namespace.
        // The reader resolves xmlns declarations into namespace_uri but doesn't
        // include them in the attributes array — we must re-emit them.
        if (elem.namespace_uri.len > 0 and !std.mem.eql(u8, elem.namespace_uri, xml.ns.client)) {
            if (elem.prefix.len > 0) {
                w.writeAll(" xmlns:") catch return;
                w.writeAll(elem.prefix) catch return;
                w.writeAll("='") catch return;
                w.writeAll(elem.namespace_uri) catch return;
                w.writeByte('\'') catch return;
            } else {
                w.writeAll(" xmlns='") catch return;
                w.writeAll(elem.namespace_uri) catch return;
                w.writeByte('\'') catch return;
            }
        }

        for (elem.attributes) |attr| {
            w.writeByte(' ') catch return;
            w.writeAll(attr.name) catch return;
            w.writeAll("='") catch return;
            xmlEscapeWrite(w, attr.value) catch return;
            w.writeByte('\'') catch return;
        }

        if (elem.self_closing) {
            w.writeAll("/>") catch return;
        } else {
            w.writeByte('>') catch return;
        }

        session.stanza_buf_len += fbs.pos;
    }

    /// Serialize text content (XML-escaped) into the stanza accumulation buffer.
    fn accumulateStanzaText(self: *Server, session: *Session, text: []const u8) void {
        _ = self;
        var fbs = std.io.fixedBufferStream(session.stanza_buf[session.stanza_buf_len..]);
        xmlEscapeWrite(fbs.writer(), text) catch return;
        session.stanza_buf_len += fbs.pos;
    }

    /// Serialize a child element close tag into the stanza accumulation buffer.
    fn accumulateStanzaClose(self: *Server, session: *Session, name: []const u8) void {
        _ = self;
        var fbs = std.io.fixedBufferStream(session.stanza_buf[session.stanza_buf_len..]);
        const w = fbs.writer();
        w.writeAll("</") catch return;
        w.writeAll(name) catch return;
        w.writeByte('>') catch return;
        session.stanza_buf_len += fbs.pos;
    }

    // ========================================================================
    // vCard XML accumulation (for IQ set vcard-temp)
    // ========================================================================

    fn accumulateVcardElement(self: *Server, session: *Session, elem: xml.Element) void {
        if (session.pep_collecting) {
            self.accumulatePepElement(session, elem);
            return;
        }
        var fbs = std.io.fixedBufferStream(session.vcard_buf[session.vcard_buf_len..]);
        const w = fbs.writer();

        w.writeByte('<') catch return;
        w.writeAll(elem.name) catch return;

        if (elem.namespace_uri.len > 0 and !std.mem.eql(u8, elem.namespace_uri, xml.ns.client) and
            !std.mem.eql(u8, elem.namespace_uri, "vcard-temp"))
        {
            if (elem.prefix.len > 0) {
                w.writeAll(" xmlns:") catch return;
                w.writeAll(elem.prefix) catch return;
                w.writeAll("='") catch return;
                w.writeAll(elem.namespace_uri) catch return;
                w.writeByte('\'') catch return;
            } else {
                w.writeAll(" xmlns='") catch return;
                w.writeAll(elem.namespace_uri) catch return;
                w.writeByte('\'') catch return;
            }
        }

        for (elem.attributes) |attr| {
            w.writeByte(' ') catch return;
            w.writeAll(attr.name) catch return;
            w.writeAll("='") catch return;
            xmlEscapeWrite(w, attr.value) catch return;
            w.writeByte('\'') catch return;
        }

        if (elem.self_closing) {
            w.writeAll("/>") catch return;
        } else {
            w.writeByte('>') catch return;
        }

        session.vcard_buf_len += fbs.pos;
    }

    fn accumulateVcardText(self: *Server, session: *Session, text: []const u8) void {
        if (session.pep_collecting) {
            self.accumulatePepText(session, text);
            return;
        }
        var fbs = std.io.fixedBufferStream(session.vcard_buf[session.vcard_buf_len..]);
        xmlEscapeWrite(fbs.writer(), text) catch return;
        session.vcard_buf_len += fbs.pos;
    }

    fn accumulateVcardClose(self: *Server, session: *Session, name: []const u8) void {
        if (session.pep_collecting) {
            self.accumulatePepClose(session, name);
            return;
        }
        var fbs = std.io.fixedBufferStream(session.vcard_buf[session.vcard_buf_len..]);
        const w = fbs.writer();
        w.writeAll("</") catch return;
        w.writeAll(name) catch return;
        w.writeByte('>') catch return;
        session.vcard_buf_len += fbs.pos;
    }

    fn accumulatePepElement(self: *Server, session: *Session, elem: xml.Element) void {
        const a = self.allocator;
        session.pep_payload.append(a, '<') catch return;
        session.pep_payload.appendSlice(a, elem.name) catch return;

        if (elem.namespace_uri.len > 0 and !std.mem.eql(u8, elem.namespace_uri, xml.ns.client) and
            !std.mem.eql(u8, elem.namespace_uri, xml.ns.pubsub))
        {
            if (elem.prefix.len > 0) {
                session.pep_payload.appendSlice(a, " xmlns:") catch return;
                session.pep_payload.appendSlice(a, elem.prefix) catch return;
                session.pep_payload.appendSlice(a, "='") catch return;
                session.pep_payload.appendSlice(a, elem.namespace_uri) catch return;
                session.pep_payload.append(a, '\'') catch return;
            } else {
                session.pep_payload.appendSlice(a, " xmlns='") catch return;
                session.pep_payload.appendSlice(a, elem.namespace_uri) catch return;
                session.pep_payload.append(a, '\'') catch return;
            }
        }

        for (elem.attributes) |attr| {
            session.pep_payload.append(a, ' ') catch return;
            session.pep_payload.appendSlice(a, attr.name) catch return;
            session.pep_payload.appendSlice(a, "='") catch return;
            session.pep_payload.appendSlice(a, attr.value) catch return;
            session.pep_payload.append(a, '\'') catch return;
        }

        if (elem.self_closing) {
            session.pep_payload.appendSlice(a, "/>") catch return;
        } else {
            session.pep_payload.append(a, '>') catch return;
        }
    }

    fn accumulatePepText(self: *Server, session: *Session, text: []const u8) void {
        session.pep_payload.appendSlice(self.allocator, text) catch return;
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

    /// Generate a unique stanza ID for XEP-0359. Format: hex(timestamp)-hex(worker_id)-hex(counter).
    /// The ID is unique per server instance (worker_id disambiguates threads, counter disambiguates
    /// within the same second). Written into the provided buffer, returns the slice.
    pub fn generateStanzaId(self: *Server, buf: *[32]u8) []const u8 {
        const timestamp: u32 = @truncate(@as(u64, @intCast(std.time.timestamp())));
        const counter = self.stanza_id_counter;
        self.stanza_id_counter +%= 1;

        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        std.fmt.format(w, "{x}-{x}-{x}", .{ timestamp, self.worker_id, counter }) catch {};
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

    pub fn executeAction(self: *Server, session: *Session, action: xmpp.StreamAction) void {
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const writer = fbs.writer();

        switch (action) {
            .send_stream_open => |params| {
                xmpp.stream.writeStreamOpen(writer, params) catch return;
                session.conn.queueSend(fbs.getWritten()) catch return;

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

                // Flush the proceed XML before upgrading to TLS
                _ = session.conn.flushSend() catch {};

                // Start TLS handshake
                if (self.ssl_ctx) |ctx| {
                    session.conn.upgradeToTls(ctx) catch {
                        log.err("connection {d} TLS upgrade failed", .{session.conn.id});
                        return;
                    };
                    log.info("connection {d} starting TLS handshake", .{session.conn.id});
                } else {
                    log.warn("connection {d} STARTTLS requested but no TLS configured", .{session.conn.id});
                }
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
                    writer.writeAll(session.bind_iq_id) catch return;
                    writer.writeByte('\'') catch return;
                }
                writer.writeAll("><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>") catch return;
                if (bound_jid.local.len > 0) {
                    writer.writeAll(bound_jid.local) catch return;
                    writer.writeByte('@') catch return;
                }
                writer.writeAll(bound_jid.domain) catch return;
                if (bound_jid.resource.len > 0) {
                    writer.writeByte('/') catch return;
                    writer.writeAll(bound_jid.resource) catch return;
                }
                writer.writeAll("</jid></bind></iq>") catch return;
                session.conn.queueSend(fbs.getWritten()) catch return;
            },
            .send_error => |err| {
                xmpp.stream.writeStreamError(writer, err) catch return;
                session.conn.queueSend(fbs.getWritten()) catch return;
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

        _ = session.conn.flushSend() catch |err| {
            switch (err) {
                error.WouldBlock => return,
                else => {
                    session_lifecycle.closeSession(self, id, changes);
                    return;
                },
            }
        };

        // If write buffer is drained, stop watching for writability
        if (!session.conn.hasPendingWrite()) {
            changes.removeWrite(session.conn.fd) catch {};
        }
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    fn sendStreamError(self: *Server, session: *Session, err: xmpp.stream.StreamError) void {
        _ = self;
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        xmpp.stream.writeStreamError(fbs.writer(), err) catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
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

                // Unicast: ABA check then deliver to single session
                if (!c.session_map.getGenerationById(c.server.worker_id, local_session_id, generation)) return;

                const target_session = c.server.sessions[local_session_id] orelse return;
                if (target_session.sm_detached) return; // Detached sessions can't receive
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

        for (&room.occupants) |*slot| {
            const occ = slot.* orelse continue;
            if (occ.worker_id != self.worker_id) continue;
            if (occ.session_id == room_registry_mod.REMOTE_OCCUPANT) continue;

            const target_session = self.sessions[occ.session_id] orelse continue;
            fanout_mod.deliverPrebuilt(decoded.prefix, occ.getRealJid(), decoded.suffix, &target_session.conn) catch continue;
            if (target_session.conn.hasPendingWrite()) {
                changes.addWrite(target_session.conn.fd, occ.session_id) catch {};
            }
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
                    log.warn("room mailbox full for {s}, dropping message", .{room_jid});
                };
            },
            .room_directory_update => |ev| {
                muc_handler.handleRoomDirectoryUpdate(self, ev);
            },
            .shadow_join => |ev| {
                muc_handler.handleShadowJoin(self, ev);
            },
            .shadow_part => |ev| {
                muc_handler.handleShadowPart(self, ev);
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
        var mask = room.worker_mask & ~(@as(u16, 1) << @intCast(self.worker_id));
        while (mask != 0) {
            const bit: u4 = @intCast(@ctz(mask));
            ds.deliver(bit, delivery_queue_mod.MULTICAST_SENTINEL, 0, mcast_payload) catch |err| {
                log.warn("multicast delivery failed to worker {d}: {}", .{ bit, err });
            };
            mask &= mask - 1; // clear lowest set bit
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
                h_value = std.fmt.parseInt(u32, attr.value, 10) catch 0;
                h_found = true;
            }
        }

        if (previd.len == 0 or !h_found) {
            self.sendSmFailed(session, "unexpected-request", changes);
            return;
        }

        // Find the detached session with matching SM-ID
        const detached_id = self.findDetachedSession(previd) orelse {
            self.sendSmFailed(session, "item-not-found", changes);
            return;
        };

        const detached = self.sessions[detached_id] orelse {
            self.sendSmFailed(session, "item-not-found", changes);
            return;
        };

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
            queue.ack(h_value);
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

        // Transfer XMPP session state
        session.stream.bound_jid = detached.stream.bound_jid;
        session.stream.state = .active;
        session.roster_interested = detached.roster_interested;
        session.carbons_enabled = detached.carbons_enabled;
        @memcpy(
            session.last_presence_inner[0..detached.last_presence_inner_len],
            detached.last_presence_inner[0..detached.last_presence_inner_len],
        );
        session.last_presence_inner_len = detached.last_presence_inner_len;

        // Re-bind in session map: unbind old slot, bind new slot with same JID
        if (self.session_map) |sm| {
            _ = sm.unbind(detached_jid.local, detached_jid.domain, detached_jid.resource);
            _ = sm.bind(self.worker_id, @intCast(session.conn.id), detached_jid.local, detached_jid.domain, detached_jid.resource) catch {
                log.err("SM resume: session_map re-bind failed for {s}@{s}/{s}", .{
                    detached_jid.local, detached_jid.domain, detached_jid.resource,
                });
            };
        }

        // Destroy the detached session (slot freed for reuse)
        detached.sm_resume_enabled = false; // Prevent re-detach during destroy
        detached.deinit();
        self.allocator.destroy(detached);
        self.sessions[detached_id] = null;

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
            changes.addWrite(session.conn.fd, session.conn.id) catch {};
        }

        log.info("connection {d} session resumed (id={s}, replayed {d} stanzas)", .{
            session.conn.id,
            session.sm_id[0..session.sm_id_len],
            if (session.sm_unacked) |q| q.pending() else 0,
        });
    }

    /// Send SM <failed/> with a specific error condition.
    fn sendSmFailed(self: *Server, session: *Session, condition: []const u8, changes: *ChangeList) void {
        _ = self;
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        w.writeAll("<failed xmlns='urn:xmpp:sm:3'><") catch return;
        w.writeAll(condition) catch return;
        w.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></failed>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
        if (session.conn.hasPendingWrite()) {
            changes.addWrite(session.conn.fd, session.conn.id) catch {};
        }
    }

    /// Find a detached session by SM-ID. O(1) via hash map (T127).
    fn findDetachedSession(self: *Server, sm_id: []const u8) ?usize {
        if (sm_id.len != sm_state.SM_ID_HEX_LEN) return null;
        const hash = hashSmId(sm_id[0..sm_state.SM_ID_HEX_LEN]);
        var idx = hash % 64;
        var probes: usize = 0;
        while (probes < 64) : (probes += 1) {
            const entry = &self.sm_id_map[idx];
            if (!entry.occupied) return null;
            if (std.mem.eql(u8, &entry.sm_id, sm_id[0..sm_state.SM_ID_HEX_LEN])) return entry.slot;
            idx = (idx + 1) % 64;
        }
        return null;
    }

    /// Insert an SM-ID → slot mapping.
    pub fn smIdMapInsert(self: *Server, sm_id: []const u8, slot: usize) void {
        if (sm_id.len != sm_state.SM_ID_HEX_LEN) return;
        const hash = hashSmId(sm_id[0..sm_state.SM_ID_HEX_LEN]);
        var idx = hash % 64;
        var probes: usize = 0;
        while (probes < 64) : (probes += 1) {
            const entry = &self.sm_id_map[idx];
            if (!entry.occupied) {
                entry.occupied = true;
                @memcpy(&entry.sm_id, sm_id[0..sm_state.SM_ID_HEX_LEN]);
                entry.slot = slot;
                return;
            }
            idx = (idx + 1) % 64;
        }
    }

    /// Remove an SM-ID from the map.
    pub fn smIdMapRemove(self: *Server, sm_id: []const u8) void {
        if (sm_id.len != sm_state.SM_ID_HEX_LEN) return;
        const hash = hashSmId(sm_id[0..sm_state.SM_ID_HEX_LEN]);
        var idx = hash % 64;
        var probes: usize = 0;
        while (probes < 64) : (probes += 1) {
            const entry = &self.sm_id_map[idx];
            if (!entry.occupied) return;
            if (std.mem.eql(u8, &entry.sm_id, sm_id[0..sm_state.SM_ID_HEX_LEN])) {
                entry.occupied = false;
                return;
            }
            idx = (idx + 1) % 64;
        }
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
    for (text) |c| {
        switch (c) {
            '&' => try writer.writeAll("&amp;"),
            '<' => try writer.writeAll("&lt;"),
            '>' => try writer.writeAll("&gt;"),
            '\'' => try writer.writeAll("&apos;"),
            '"' => try writer.writeAll("&quot;"),
            else => try writer.writeByte(c),
        }
    }
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

    // Server should have queued a response
    try std.testing.expect(session.conn.hasPendingWrite());

    // Flush and read from client side
    _ = try session.conn.flushSend();
    var buf: [2048]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    const response = buf[0..n];

    // Should contain stream open + features with STARTTLS
    try std.testing.expect(std.mem.indexOf(u8, response, "<stream:stream") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "<stream:features>") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "<starttls") != null);
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
    var sm = SessionMap.init(allocator, true);
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

    var sm = SessionMap.init(allocator, true);
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
