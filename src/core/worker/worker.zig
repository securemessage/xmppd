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
const precis = @import("precis_username");
const EventLoop = @import("loop.zig").EventLoop;
const ChangeList = @import("loop.zig").ChangeList;
const Connection = @import("../connection.zig").Connection;
pub const connection_mod = @import("../connection.zig");
const Listener = @import("../listener.zig").Listener;
const Event = @import("loop.zig").Event;

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

comptime {
    // The session-map bind bound must stay within the widest router stanza
    // buffer so an over-long bound JID is counted, never clipped (S4).
    std.debug.assert(session_map_mod.MAX_JID_OCTETS <= router.JID_STANZA_MAX);
}
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
const presence_sub = @import("../presence/subscription.zig");
const muc_actor = @import("../muc/actor.zig");
pub const sub_cache_mod = @import("../subscription_cache.zig");
pub const caps_mod = @import("../caps.zig");
const router = @import("../routing/router.zig");
const session_lifecycle = @import("../c2s/lifecycle.zig");
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
pub const sm_state = @import("../c2s/sm_state.zig");
const sm_handoff = @import("../c2s/sm_handoff.zig");
const c2s_session = @import("../c2s/session.zig");
const c2s_sm = @import("../c2s/sm.zig");
const routing_deliver = @import("../routing/deliver.zig");
const block_store_mod = @import("block_store");
const metrics = @import("metrics.zig");
const GenericBlockStore = block_store_mod.BlockStore(OpBackendType);
const pep_store_mod = @import("pep_store");
const GenericPepStore = pep_store_mod.PepStore(OpBackendType);

const log = std.log.scoped(.xmppd);

pub const Session = c2s_session.Session;
pub const StanzaKind = c2s_session.StanzaKind;
pub const MamCollecting = c2s_session.MamCollecting;
const AuthState = c2s_session.AuthState;
const SaslCollecting = c2s_session.SaslCollecting;

const noteDrop = c2s_session.noteDrop;
const noteJidOverflow = c2s_session.noteJidOverflow;
const queueStanzaOrDrop = c2s_session.queueStanzaOrDrop;
pub const noteQueueOverflow = c2s_session.noteQueueOverflow;
const fillWriteBuffer = c2s_session.fillWriteBuffer;
const makeSocketPair = c2s_session.makeSocketPair;
const writeJidMalformedReply = c2s_session.writeJidMalformedReply;
const isStaleSessionEvent = c2s_session.isStaleSessionEvent;

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
/// one of each kind per IPC link, so four of the eight are ever spent. Holding
/// them back prevents event handling from consuming entries required to arm or
/// disarm a link. Timers are staged on every exit, including the drop path,
/// since a link dropped there needs a retry before the next wait. A timer that
/// still cannot be staged leaves its pending flag set for the next iteration.
/// dropIpcAuth's per-session writes stay best-effort because one entry per
/// mid-SASL session cannot be bounded by a fixed tail.
const IPC_RECONCILE_RESERVED = 8;
/// The XMPP core server.
pub const Server = struct {
    loop: EventLoop,
    listener: Listener,
    allocator: std.mem.Allocator,
    server_host: []const u8,
    running: bool = true,

    /// Process start time (epoch seconds). XEP-0012 domain uptime answer.
    start_time: i64 = 0,

    /// Per-process entropy for `mintHoldToken`, drawn once at init. The stanza
    /// id alone is (wall second, worker, counter), so an incarnation that
    /// restarted within the same second as its predecessor would re-mint the
    /// tokens that predecessor already stored, and the store would answer a
    /// new message as already held.
    hold_token_seed: u64 = 0,

    /// Session table — indexed by session ID. Heap-allocated, size configurable.
    sessions: []?*Session = &.{},
    max_sessions: usize = DEFAULT_MAX_SESSIONS,

    /// Free-list stack for O(1) session ID allocation (T128).
    free_ids: []usize = &.{},
    free_count: usize = 0,

    /// Per-worker outbox counters (C2): every accepted Connection binds
    /// its outbox here, so lib/net fail-closed and spill events have one
    /// owner per loop thread.
    net_counters: connection_mod.OutboxCounters = .{},

    /// TLS context — shared across all connections. Null if TLS is not configured.
    ssl_ctx: ?ssl.SslContext = null,

    /// Test seam (T215): when set, the next TLS upgrade fails instead of
    /// starting a handshake, which exercises the teardown that frees the
    /// session. A real `upgradeToTls` failure needs `SSL_new` to run out of
    /// memory, so no test can arrange one otherwise. Never set in production.
    fail_next_tls_upgrade: bool = false,

    /// Runs right after a drain reads its pointer list, so a test can store a
    /// row from a second handle and prove the drain notices it. A real race
    /// needs two worker threads and an interleaving no test can arrange.
    /// Never set in production.
    test_after_offline_pointers: ?*const fn (*Server, []const u8) void = null,

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
    /// Set when a per-session offline retry timer cannot be staged. The
    /// periodic fallback checks this flag before scanning session slots.
    offline_retry_sweep_needed: bool = false,

    /// Archive store — MAM message archive (stanza payloads). Read path
    /// (queries/history/offline fetch) stays inline; WRITES go through
    /// archive_writer when attached.
    archive: ?*archive_store_mod.ArchiveStore(ArchiveBackendType) = null,

    /// S18: per-worker heap scratch for session-map resolution. Bank A
    /// serves stanza routing and chunked batch lookups, bank B handler-level
    /// lookups, and bank C leaf delivery lookups. Heap allocation keeps these
    /// entries out of stack frames; banks grow lazily to the session map's
    /// resource cap, with chunk banks holding SCRATCH_CHUNK_JIDS * cap entries.
    ///
    /// `leaseScratch` marks a bank in use until released so a nested lookup on
    /// the same bank asserts instead of overwriting the outer iteration.
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

    /// Inline archive store failures (no writer thread wired) - for ops
    /// visibility; queue-mode failures are counted on the queue instead.
    archive_store_failed: u64 = 0,

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
    sm_redirects: std.AutoHashMapUnmanaged([sm_state.SM_ID_HEX_LEN]u8, c2s_sm.SmRedirect) = .{},

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
            .hold_token_seed = std.crypto.random.int(u64),
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
            .hold_token_seed = std.crypto.random.int(u64),
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
            c2s_session.executeAction(self, session, session.stream.saslFailure("temporary-auth-failure"), changes);
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
    /// to an inline store().
    pub fn archiveStore(self: *Server, owner: []const u8, with: []const u8, stanza_id: []const u8, timestamp: u64, stanza_xml: []const u8) void {
        if (self.archive_writer) |q| {
            q.enqueue(owner, with, stanza_id, timestamp, stanza_xml);
            return;
        }
        if (self.archive) |archive| {
            archive.store(owner, with, stanza_id, timestamp, stanza_xml) catch |err| {
                self.archive_store_failed += 1;
                // Log the first failure and every power of two after it.
                if (archive_queue_mod.logEveryPowerOfTwo(self.archive_store_failed)) {
                    log.warn("inline archive store failed ({d} total): {}", .{ self.archive_store_failed, err });
                }
            };
        }
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
    /// When every bank is already out, allocate an independent buffer instead
    /// of overwriting a live lease or dropping the stanza. Return null only on
    /// allocation failure; callers then discard the stanza without emitting
    /// partial output.
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

        // M1: per-worker counters live on this thread; SIGUSR1 dumps them.
        metrics.bind(self.worker_id);
        try self.loop.addSignal(posix.SIG.USR1);

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

        // Fallback for offline retry timers that could not be staged.
        try changes.addTimer(OFFLINE_RETRY_TIMER_IDENT, session_lifecycle.OFFLINE_RETRY_DELAY_MS, false);

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
            const staged_changes = changes.count();
            const events = try self.loop.submitAndPoll(changes.slice(), null);
            changes.reset();

            // M1: time event processing only, not the blocked kevent wait.
            var iter_timer = std.time.Timer.start() catch null;

            // Process MPSC wake pipe first (if in event batch) to deliver cross-thread
            // messages before any session-closing events in the same batch.
            for (events) |ev| {
                switch (ev) {
                    .fd_readable => |e| {
                        if (e.udata == WAKE_PIPE_UDATA) {
                            routing_deliver.handleDeliveryWake(self, &changes);
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
                    routing_deliver.drainDeliveryQueue(self, &changes);
                    _ = muc_actor.drainRoomMailboxes(self, &changes);
                    // Self-wake only for MPSC queue CAS race (producer reserved
                    // slot but hasn't stored ready=true yet). Room mailboxes
                    // don't need self-wake — they only grow from MPSC deliveries
                    // which have their own pipe-based wakeup.
                    if (ds.getQueue(self.worker_id).hasPending()) {
                        ds.wakeWorker(self.worker_id);
                    }
                } else {
                    // No MPSC pending, but drain room mailboxes opportunistically
                    _ = muc_actor.drainRoomMailboxes(self, &changes);
                }
            }

            // Fail sessions whose outbound delivery overflowed in this batch.
            session_lifecycle.reapOutboundOverflow(self, &changes);

            // S10: single point of truth for IPC write interest; heals
            // any re-arm lost while handling this batch.
            self.reconcileIpcWriteInterest(&changes);

            if (iter_timer) |*t| metrics.recordIteration(t.read());
            if (metrics.get()) |c| {
                metrics.bump(&c.kevent_events, events.len);
                metrics.bump(&c.kevent_changes, staged_changes);
            }
        }
    }

    /// M1: SIGUSR1 handler — dump this worker's counters (own thread).
    fn dumpMetrics(self: *Server) void {
        metrics.dump(self.worker_id, .{
            .room_mailbox_drops = room_mailbox_mod.mailbox_drops.load(.monotonic),
            .ring_drops_full = delivery_queue_mod.ring_drops_full.load(.monotonic),
            .ring_drops_payload = delivery_queue_mod.ring_drops_payload.load(.monotonic),
            .jid_overflow_drops = router.jid_overflow_drops.load(.monotonic),
            .cross_worker_drops = delivery_queue_mod.cross_worker_drops.load(.monotonic),
            .s2s_bounces = delivery_queue_mod.s2s_bounces.load(.monotonic),
            .offline_not_stored = delivery_queue_mod.offline_not_stored.load(.monotonic),
            .offline_hold_bounces = delivery_queue_mod.offline_hold_bounces.load(.monotonic),
            .offline_drain_drops = delivery_queue_mod.offline_drain_drops.load(.monotonic),
        });
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
            c2s_session.continueTlsHandshake(self, id, session, changes);
            return;
        }
        c2s_session.handleReadable(self, id, changes);
    }

    fn handleWritableOrHandshake(self: *Server, id: usize, changes: *ChangeList) void {
        const session = self.sessions[id] orelse return;
        if (session.conn.isTlsHandshaking()) {
            c2s_session.continueTlsHandshake(self, id, session, changes);
            return;
        }
        c2s_session.handleWritable(self, id, changes);
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
                    } else if (s.signo == posix.SIG.USR1) {
                        self.dumpMetrics();
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
                    } else {
                        session_lifecycle.retryOfflineDrain(self, t.ident, changes);
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

    // ========================================================================
    // Read handler — XML parsing → stream FSM → response
    // ========================================================================

    // ========================================================================
    // XML event → Stream FSM dispatch
    // ========================================================================

    /// F6: jid-malformed reply for a stanza whose to/from failed ingress
    /// preparation. message/iq echo the sender's 'to' and 'id' like
    /// sendPreBindStanzaError; presence also addresses the reply to the
    /// account's full JID, mirroring rejectOversizeSubscriptionTo. noinline:
    /// on the per-stanza path only while inlined it cost one probed frame
    /// inside handleElementStart.
    pub noinline fn sendIngressJidMalformed(self: *Server, session: *Session, elem: *xml.Element, changes: *ChangeList) void {
        _ = self;
        var to_attr: []const u8 = "";
        var id_attr: []const u8 = "";
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "to")) to_attr = attr.value;
            if (std.mem.eql(u8, attr.local_name, "id")) id_attr = attr.value;
        }
        var reply_to: []const u8 = "";
        var full_buf: [router.FULL_JID_MAX]u8 = undefined;
        if (std.mem.eql(u8, elem.local_name, "presence")) {
            const jid = session.stream.bound_jid orelse session.stream.authenticated_jid orelse return;
            var fbs = std.io.fixedBufferStream(&full_buf);
            const w = fbs.writer();
            const built = stanza: {
                w.writeAll(jid.local) catch break :stanza false;
                w.writeByte('@') catch break :stanza false;
                w.writeAll(jid.domain) catch break :stanza false;
                if (jid.resource.len > 0) {
                    w.writeByte('/') catch break :stanza false;
                    w.writeAll(jid.resource) catch break :stanza false;
                }
                break :stanza true;
            };
            if (!built) {
                noteJidOverflow("jid-malformed reply target for connection {d} exceeds {d} bytes; not sent", .{ session.conn.id, router.FULL_JID_MAX });
                return;
            }
            reply_to = fbs.getWritten();
        }
        const stanza = writeJidMalformedReply(&session.write_scratch, elem.local_name, to_attr, reply_to, id_attr) orelse
            // An offending JID that escapes wider than the buffer still gets
            // its answer; the 'from' echo is optional.
            writeJidMalformedReply(&session.write_scratch, elem.local_name, "", reply_to, id_attr) orelse {
            noteJidOverflow("jid-malformed reply to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
            return;
        };
        queueStanzaOrDrop(session, stanza, "jid-malformed reply");
        if (session.conn.hasPendingWrite()) {
            changes.addWrite(session.conn.fd, session.conn.id) catch {};
        }
    }

    // ========================================================================
    // Text content accumulation for SASL elements
    // ========================================================================

    // ========================================================================
    // SASL handling (via auth daemon IPC)
    // ========================================================================

    // ========================================================================
    // IPC response handling — auth daemon responses dispatched to sessions
    // ========================================================================

    fn handleIpcReadable(self: *Server, changes: *ChangeList) void {
        const rr = self.ipc.recv() catch |err| {
            log.err("auth daemon IPC recv error: {}", .{err});
            self.dropIpcAuth(changes);
            return;
        };
        if (rr == .eof) {
            log.warn("auth daemon closed the IPC link - dropping", .{});
            self.dropIpcAuth(changes);
            return;
        }

        // Process all complete messages
        while (true) {
            const msg = self.ipc.nextMessage() catch |err| {
                // A decode error does not consume the frame; keeping the
                // link retries the same bytes forever and wedges every
                // SASL exchange behind it. Drop and reconnect (S10).
                log.warn("auth daemon IPC decode error: {} len={d} consumed={d} — dropping link", .{ err, self.ipc.reader.len, self.ipc.reader.consumed });
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
    /// iteration. Central re-arming keeps a full changelist from stranding
    /// pending frames; disarming here keeps an idle link from re-firing
    /// writable every kevent. Also the sole owner of IPC reconnect timers.
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
    pub fn applyDynamicMechanisms(self: *Server, features: xmpp.stream.FeatureSet) xmpp.stream.FeatureSet {
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
                const challenge_xml = stanza: {
                    w.writeAll("<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>") catch break :stanza null;
                    stanza_writer.b64EncodeWrite(w, m.challenge) catch break :stanza null;
                    w.writeAll("</challenge>") catch break :stanza null;
                    break :stanza fbs.getWritten();
                } orelse {
                    noteDrop("SASL challenge to connection {d} exceeds {d} bytes; dropped", .{ conn_id, session.write_scratch.len });
                    return;
                };
                if (session.nonza(challenge_xml) == .failed_closed) {
                    c2s_session.noteSendDrop(session, challenge_xml, "SASL challenge");
                    return;
                }
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
                    if (self.vcard) |vcard| vcard_import: {
                        // Build bare JID for vCard lookup
                        var jid_buf: [router.BARE_JID_MAX]u8 = undefined;
                        const bare_jid = router.buildBareJid(stable_username, self.server_host, &jid_buf) catch {
                            noteDrop("OIDC photo import skipped: bare JID for '{s}' exceeds {d} bytes", .{ stable_username, router.BARE_JID_MAX });
                            break :vcard_import;
                        };

                        const existing = vcard.get(self.allocator, bare_jid) catch null;
                        if (existing) |data| {
                            self.allocator.free(data);
                        } else {
                            // No existing vCard — create one with OIDC photo
                            var vc_buf: [1024]u8 = undefined;
                            var vc_fbs = std.io.fixedBufferStream(&vc_buf);
                            const vw = vc_fbs.writer();
                            const vcard_xml = stanza: {
                                vw.writeAll("<vCard xmlns='vcard-temp'><PHOTO><EXTVAL>") catch break :stanza null;
                                xml.escapeWrite(vw, m.photo_url) catch break :stanza null;
                                vw.writeAll("</EXTVAL></PHOTO></vCard>") catch break :stanza null;
                                break :stanza vc_fbs.getWritten();
                            } orelse {
                                noteDrop("OIDC photo vCard for '{s}' exceeds {d} bytes; import skipped", .{ stable_username, vc_buf.len });
                                break :vcard_import;
                            };
                            vcard.set(bare_jid, vcard_xml) catch |err| {
                                noteDrop("OIDC photo vCard for '{s}' could not be stored: {s}", .{ stable_username, @errorName(err) });
                                break :vcard_import;
                            };
                            log.info("OIDC photo imported for '{s}'", .{stable_username});
                        }
                    }
                }

                const success_action = session.stream.saslSuccess(stable_username, server_final_b64);
                c2s_session.executeAction(self, session, success_action, changes);
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
                if (session.conn.tls) |*t| {
                    if (t.conn.pending() > 0) {
                        c2s_session.handleReadable(self, conn_id, changes);
                    }
                }
            },
            .auth_failure => |m| {
                log.info("connection {d} auth failed: {s}", .{ conn_id, m.reason });
                const fail_action = session.stream.saslFailure(m.reason);
                c2s_session.executeAction(self, session, fail_action, changes);
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
                const reply_xml = stanza: {
                    if (m.success) {
                        iq_handler.writeIqHeader(self, w, session, "result", iq_id) catch break :stanza null;
                        w.writeAll("/>") catch break :stanza null;
                    } else {
                        iq_handler.writeIqHeader(self, w, session, "error", iq_id) catch break :stanza null;
                        w.writeAll("><error type='cancel'><") catch break :stanza null;
                        w.writeAll(m.reason) catch break :stanza null;
                        w.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>") catch break :stanza null;
                    }
                    break :stanza fbs.getWritten();
                } orelse {
                    noteJidOverflow("register result to connection {d} exceeds {d} bytes; dropped", .{ conn_id, session.write_scratch.len });
                    return;
                };
                if (session.stanza(reply_xml) == .failed_closed) {
                    c2s_session.noteSendDrop(session, reply_xml, "register result");
                    return;
                }

                if (session.conn.hasPendingWrite()) {
                    changes.addWrite(session.conn.fd, conn_id) catch {};
                }
            },
            .password_change_result => |m| {
                const iq_id = session.reg_pending_iq_id;
                session.reg_pending_iq_id = "";

                var fbs = std.io.fixedBufferStream(&session.write_scratch);
                const w = fbs.writer();
                const reply_xml = stanza: {
                    if (m.success) {
                        iq_handler.writeIqHeader(self, w, session, "result", iq_id) catch break :stanza null;
                        w.writeAll("/>") catch break :stanza null;
                    } else {
                        iq_handler.writeIqHeader(self, w, session, "error", iq_id) catch break :stanza null;
                        w.writeAll("><error type='modify'><") catch break :stanza null;
                        w.writeAll(m.reason) catch break :stanza null;
                        w.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>") catch break :stanza null;
                    }
                    break :stanza fbs.getWritten();
                } orelse {
                    noteJidOverflow("password-change result to connection {d} exceeds {d} bytes; dropped", .{ conn_id, session.write_scratch.len });
                    return;
                };
                queueStanzaOrDrop(session, reply_xml, "password-change result");

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
                    const reply_xml = stanza: {
                        iq_handler.writeIqHeader(self, w, session, "result", iq_id) catch break :stanza null;
                        w.writeAll("/>") catch break :stanza null;
                        break :stanza fbs.getWritten();
                    } orelse {
                        noteJidOverflow("account-delete result to connection {d} exceeds {d} bytes; dropped", .{ conn_id, session.write_scratch.len });
                        return;
                    };
                    queueStanzaOrDrop(session, reply_xml, "account-delete result");

                    // Close the stream per XEP-0077 §3.2
                    _ = session.nonza("</stream:stream>");

                    if (session.conn.hasPendingWrite()) {
                        changes.addWrite(session.conn.fd, conn_id) catch {};
                    }
                } else {
                    var fbs = std.io.fixedBufferStream(&session.write_scratch);
                    const w = fbs.writer();
                    const reply_xml = stanza: {
                        iq_handler.writeIqHeader(self, w, session, "error", iq_id) catch break :stanza null;
                        w.writeAll("><error type='cancel'><") catch break :stanza null;
                        w.writeAll(m.reason) catch break :stanza null;
                        w.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>") catch break :stanza null;
                        break :stanza fbs.getWritten();
                    } orelse {
                        noteJidOverflow("account-delete error to connection {d} exceeds {d} bytes; dropped", .{ conn_id, session.write_scratch.len });
                        return;
                    };
                    queueStanzaOrDrop(session, reply_xml, "account-delete error");

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
        var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
        const bare_jid = router.buildBareJid(username, self.server_host, &bare_buf) catch {
            noteDrop("cascade: bare JID for '{s}' exceeds {d} bytes; store cleanup skipped", .{ username, router.BARE_JID_MAX });
            return;
        };

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
            presence_sub.invalidateSubCache(self, bare_jid);
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

    fn handleS2sIpcReadable(self: *Server, changes: *ChangeList) void {
        const rr = self.s2s_ipc.recv() catch {
            log.err("S2S daemon IPC recv error", .{});
            self.dropS2sIpc(changes);
            return;
        };
        if (rr == .eof) {
            log.warn("S2S daemon closed the IPC link - dropping", .{});
            self.dropS2sIpc(changes);
            return;
        }

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

    pub fn dispatchS2sResponse(self: *Server, msg: ipc_protocol.Message, changes: *ChangeList) void {
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
                    const parts = stanza_facts.extractStanzaParts(m.stanza_xml);
                    if (parts.is_message and std.mem.eql(u8, parts.msg_type, "groupchat")) {
                        log.warn("S2S groupchat to {s}: recipient unavailable, bouncing", .{m.to_jid});
                        routing_deliver.bounceS2sInbound(self, m.from_jid, m.to_jid, "message", parts.msg_id);
                        return;
                    }
                    if (parts.is_iq) {
                        if (std.mem.eql(u8, parts.msg_type, "get") or std.mem.eql(u8, parts.msg_type, "set")) {
                            log.warn("S2S IQ to {s}: recipient unavailable, bouncing", .{m.to_jid});
                            routing_deliver.bounceS2sInbound(self, m.from_jid, m.to_jid, "iq", parts.msg_id);
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
                                routing_deliver.bounceS2sInbound(self, m.from_jid, m.to_jid, "message", parts.msg_id);
                                return;
                            };

                            const stanza_id = if (parts.msg_id.len > 0) parts.msg_id else "s2s-offline";

                            // Payload goes down with the pointer. The archive row is
                            // also written here, but a failed write must not leave a
                            // pointer behind: the drain would find neither copy, drop
                            // the pointer, and the message would vanish (E2b).
                            if (self.archive != null) {
                                self.archiveStore(recipient_bare, m.from_jid, stanza_id, s2s_archive_ts, m.stanza_xml);
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
                        routing_deliver.bounceS2sInbound(self, m.from_jid, m.to_jid, "message", parts.msg_id);
                        return;
                    }
                    log.info("S2S inbound to {s}: recipient unavailable, nothing stored", .{m.to_jid});
                    return;
                }

                const live_parts = stanza_facts.extractStanzaParts(m.stanza_xml);
                // Archive S2S inbound messages delivered to online recipients (T81)
                if (self.archive != null) {
                    if (live_parts.is_message and std.mem.indexOf(u8, live_parts.inner_xml, "<body") != null) archive_msg: {
                        var recip_buf: [router.BARE_JID_MAX]u8 = undefined;
                        const recipient_bare = router.buildBareJid(to_jid.local, to_jid.domain, &recip_buf) catch {
                            noteDrop("S2S inbound to {s} archived nowhere: recipient bare JID exceeds {d} bytes", .{ m.to_jid, router.BARE_JID_MAX });
                            break :archive_msg;
                        };

                        var s2s_sid_buf: [32]u8 = undefined;
                        const s2s_stanza_id = self.generateStanzaId(&s2s_sid_buf);

                        // Archive under recipient bare JID (via the T87 queue when wired)
                        self.archiveStore(recipient_bare, m.from_jid, s2s_stanza_id, s2s_archive_ts, m.stanza_xml);
                    }
                }

                var s2s_hold_stored = false;
                // One token per inbound stanza: identical remote stanzas are
                // separate dispatches and must not collapse in the store.
                const s2s_hold_token = self.mintHoldToken();
                for (s2s_entries[0..target_count]) |entry| {
                    if (entry.worker_id == self.worker_id) {
                        const target_session = self.sessions[entry.local_session_id] orelse continue;
                        if (target_session.offline_pending and live_parts.is_message and !std.mem.eql(u8, live_parts.msg_type, "error")) {
                            // One bare JID, one row: every draining resource on
                            // this worker asks, and the store collapses them.
                            if (s2s_hold_stored) continue;
                            const hold_id = if (live_parts.msg_id.len > 0) live_parts.msg_id else "s2s-offline";
                            if (routing_deliver.holdBehindOfflineTail(self, target_session, to_jid.local, to_jid.domain, m.from_jid, hold_id, s2s_archive_ts, m.stanza_xml, s2s_hold_token)) {
                                s2s_hold_stored = true;
                                continue;
                            }
                            // Held neither in the queue nor on the wire: tell
                            // the remote sender instead of dropping (H2).
                            log.warn("S2S message to {s} not held, bouncing to the sender", .{m.to_jid});
                            if (routing_deliver.sendS2sError(self, m.from_jid, m.to_jid, "message", live_parts.msg_id)) {
                                _ = delivery_queue_mod.offline_hold_bounces.fetchAdd(1, .monotonic);
                            }
                            continue;
                        }
                        fanout_mod.deliverToSession(target_session, m.stanza_xml, entry.local_session_id, changes);
                    } else if (self.delivery_system) |ds| {
                        // Carry this dispatch's token: the receiving worker holds
                        // under the same identity, so the store writes one row
                        // whichever worker reaches it first.
                        ds.deliverDelivery(entry.worker_id, entry.local_session_id, entry.generation, m.stanza_xml, s2s_hold_token, s2s_archive_ts, .stanza) catch {
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

    // ========================================================================
    // Stanza accumulation + dispatch (full stanza forwarding)
    // ========================================================================

    // ========================================================================
    // vCard XML accumulation (for IQ set vcard-temp)
    // ========================================================================

    /// Mint the identity of one dispatch, for `holdBehindOfflineTail`. The
    /// stanza id generator gives a value unique per worker and call; the
    /// per-process seed keeps it unique across incarnations too, so a restart
    /// in the same second cannot reproduce a token an older row still holds.
    pub fn mintHoldToken(self: *Server) offline_store_mod.HoldToken {
        var buf: [32]u8 = undefined;
        const id = self.generateStanzaId(&buf);
        var hasher = std.hash.Wyhash.init(0x686f6c64746f6b);
        var seed_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &seed_bytes, self.hold_token_seed, .little);
        hasher.update(&seed_bytes);
        hasher.update(id);
        // Fold out the zero sentinel; a minted token must never look unminted.
        return hasher.final() | 1;
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

    pub fn handleIq(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
        _ = changes;
        iq_handler.handleIq(session, elem, self.server_host);
    }

    /// Handle child elements inside an IQ stanza (query, item, etc.)
    pub fn handleIqChild(self: *Server, session: *Session, elem: xml.Element) void {
        _ = self;
        iq_handler.handleIqChild(session, elem);
    }

    /// Dispatch a complete IQ stanza based on accumulated state.
    pub fn dispatchIq(self: *Server, session: *Session, changes: *ChangeList) void {
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

    // ========================================================================
    // Write handler
    // ========================================================================

    // ========================================================================
    // Helpers
    // ========================================================================

    // ========================================================================
    // XEP-0198: Stream Management
    // ========================================================================
};
// ============================================================================
// Tests
// ============================================================================

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

// Close on the overflow, not on the close tag: a peer that opens an over-long
// stanza and never closes it would otherwise keep its session and the reader's
// arena alive for as long as it stays connected. The stanza arrives in chunks
// so the parser sees it unterminated, the way a hostile peer would send it.
test "Server: the bound localpart keeps the full prepared auth username" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // A prepared localpart may exceed the old 256-octet session buffer. The
    // bound identity must contain all of it, without silent truncation.
    var username: [300]u8 = undefined;
    @memset(&username, 'n');
    server.dispatchAuthResponse(.{ .auth_success = .{
        .conn_id = 1,
        .username = &username,
        .server_final = "",
    } }, &changes);
    session.stream.state = .features_bind;
    _ = session.stream.handleBind("res");
    try std.testing.expectEqualStrings(&username, session.stream.bound_jid.?.local);
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
    try std.testing.expect(session.conn.outbox.used > session.conn.outbox.head);

    // Detach for SM resume: purge the fd, close it, keep the session.
    session.sm_resume_enabled = true;
    session.sm_detached = true;
    session.sm_detach_time = std.time.timestamp();
    session.sm_id_len = sm_state.SM_ID_HEX_LEN;
    const sm_id = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
    @memcpy(&session.sm_id, sm_id);
    server.detached_count = 1;
    c2s_sm.smIdMapInsert(&server, &session.sm_id, 1);
    session.conn.close();
    try std.testing.expectEqual(@as(posix.fd_t, -1), session.conn.fd);

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // The stale event kevent already returned this batch, for the fd that no
    // longer exists.
    c2s_session.handleWritable(&server, 1, &changes);

    // The resumable session survives, and the skip was counted rather than
    // silently swallowed.
    try std.testing.expect(server.sessions[1] != null);
    try std.testing.expect(server.sessions[1].?.sm_detached);
    try std.testing.expectEqual(@as(u64, 1), server.stale_event_skips);
    try std.testing.expectEqual(@as(u16, 1), server.detached_count);

    // Same for a stale readable event and a stale error event.
    c2s_session.handleReadable(&server, 1, &changes);
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
    c2s_sm.smIdMapInsert(&server, &session.sm_id, 1);
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
    try std.testing.expectEqual(@as(?usize, 1), c2s_sm.findDetachedSession(&server, &session.sm_id));
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
    c2s_session.handleWritable(&server, 1, &changes);

    try std.testing.expect(server.sessions[1] != null);
    try std.testing.expectEqual(@as(u64, 1), server.stale_event_skips);
}

test "Server: M1 counters track client traffic through the read path" {
    metrics.bind(9);
    defer metrics.current = null;
    const c = metrics.get().?;
    const base_in = c.bytes_in.load(.monotonic);
    const base_out = c.bytes_out.load(.monotonic);

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
    c2s_session.handleReadable(&server, 1, &changes);
    try std.testing.expect(server.sessions[1] != null);

    // Client bytes were counted on recv; the features reply was counted
    // on flush.
    try std.testing.expect(c.bytes_in.load(.monotonic) >= base_in + stream_open.len);
    try std.testing.expect(c.bytes_out.load(.monotonic) > base_out);

    // The drop counters are bumped at their choke points, not per session.
    const base_full = c.drop_send_buffer_full.load(.monotonic);
    const big = [_]u8{'x'} ** (16384 + 1);
    try std.testing.expectError(error.WriteBufferFull, session.conn.queueSend(&big));
    try std.testing.expectEqual(base_full + 1, c.drop_send_buffer_full.load(.monotonic));
}

test "Server: M1 SIGUSR1 dump runs against a live worker block" {
    metrics.bind(10);
    defer metrics.current = null;
    const c = metrics.get().?;
    metrics.bump(&c.stanzas_message, 3);
    metrics.bump(&c.wakes, 2);
    metrics.recordIteration(500);
    // Exercises the dump formatting against a bound worker; output goes to
    // the test log.
    metrics.dump(10, .{
        .room_mailbox_drops = 1,
        .ring_drops_full = 2,
        .ring_drops_payload = 3,
    });
    try std.testing.expectEqual(@as(u64, 3), c.stanzas_message.load(.monotonic));
}

// The live delivery path enqueues with queueSendWithFlush. Counting the call
// is not enough: the stanza still has to be tracked for XEP-0198, or the ack
// window shifts under the client.
test "S15: raw conn queue ratchet, stanzas go through queueSendStanza" {
    // XEP-0198 acks map stanzas by position, so any stanza sent via raw
    // conn.queueSend shifts the ack window (S15). Nonzas (stream features,
    // SASL, SM elements, stream errors) are the only legitimate raw sends.
    // Counts may only shrink; a new raw site must be justified as a nonza
    // here. `queueSendWithFlush` is the same raw enqueue plus a flush, so it
    // shifts the ack window too and is counted as well. Patterns are split so
    // this test does not match itself.
    const needles = [_][]const u8{
        "conn.queue" ++ "Send(",
        "conn.queue" ++ "SendWithFlush(",
    };
    const cases = .{
        .{ "connection.zig", @embedFile("../connection.zig"), 17 }, // Connection layer self-tests incl. the M1 counter test; no Session.
        .{ "muc/fanout.zig", @embedFile("../muc/fanout.zig"), 1 }, // MockSession.stanza in tests; the live path uses Session.stanza().
        .{ "presence/handler.zig", @embedFile("../presence/handler.zig"), 0 },
        .{ "presence/subscription.zig", @embedFile("../presence/subscription.zig"), 0 },
        .{ "presence/broadcast.zig", @embedFile("../presence/broadcast.zig"), 0 },
        .{ "routing/router.zig", @embedFile("../routing/router.zig"), 0 }, // local delivery goes through stanzaWithFlush().
        .{ "c2s/lifecycle.zig", @embedFile("../c2s/lifecycle.zig"), 0 },
        .{ "worker/worker.zig", @embedFile("worker.zig"), 1 }, // stream/SASL/SM nonzas went through nonza()/stanza(); 1 test filler remains.
        .{ "routing/deliver.zig", @embedFile("../routing/deliver.zig"), 0 }, // the cross-worker drain goes through stanza().
        .{ "c2s/session.zig", @embedFile("../c2s/session.zig"), 2 }, // stream/SASL nonzas went through nonza(); 2 test fillers remain.
        .{ "c2s/sm.zig", @embedFile("../c2s/sm.zig"), 0 }, // SM enable/resume/failed nonzas go through nonza().
        .{ "iq/dispatch.zig", @embedFile("../iq/dispatch.zig"), 0 },
        .{ "iq/carbons.zig", @embedFile("../iq/carbons.zig"), 0 },
        .{ "muc/handler.zig", @embedFile("../muc/handler.zig"), 0 },
        .{ "muc/actor.zig", @embedFile("../muc/actor.zig"), 0 },
        .{ "xworker/envelope.zig", @embedFile("../xworker/envelope.zig"), 0 },
        .{ "caps.zig", @embedFile("../caps.zig"), 0 },
        // Remaining core files (S15): a raw send added here must be caught
        // like any other, not smuggled in outside the allowlist.
        .{ "archive_queue.zig", @embedFile("../archive_queue.zig"), 0 },
        .{ "xworker/ring.zig", @embedFile("../xworker/ring.zig"), 0 },
        .{ "worker/loop.zig", @embedFile("loop.zig"), 0 },
        .{ "routing/address.zig", @embedFile("../routing/address.zig"), 0 },
        .{ "listener.zig", @embedFile("../listener.zig"), 0 },
        .{ "main.zig", @embedFile("../main.zig"), 0 },
        .{ "worker/metrics.zig", @embedFile("metrics.zig"), 0 },
        .{ "offline_store.zig", @embedFile("../offline_store.zig"), 0 },
        .{ "muc/mailbox.zig", @embedFile("../muc/mailbox.zig"), 0 },
        .{ "muc/registry.zig", @embedFile("../muc/registry.zig"), 0 },
        .{ "roster_store.zig", @embedFile("../roster_store.zig"), 0 },
        .{ "session_map.zig", @embedFile("../session_map.zig"), 0 },
        .{ "c2s/sm_handoff.zig", @embedFile("../c2s/sm_handoff.zig"), 0 },
        .{ "c2s/sm_state.zig", @embedFile("../c2s/sm_state.zig"), 0 },
        .{ "subscription_cache.zig", @embedFile("../subscription_cache.zig"), 0 },
        .{ "stanza/facts.zig", @embedFile("../stanza/facts.zig"), 0 },
        .{ "stanza/writer.zig", @embedFile("../stanza/writer.zig"), 0 },
    };
    if (cases.len != 34) {
        log.err("S15 ratchet: covers {d} core files, expected 34", .{cases.len});
        return error.RatchetCoverage;
    }
    inline for (cases) |case| {
        const name = case[0];
        const src = case[1];
        const expected = case[2];
        var count: usize = 0;
        for (needles) |needle| {
            var pos: usize = 0;
            while (std.mem.indexOfPos(u8, src, pos, needle)) |hit| {
                count += 1;
                pos = hit + needle.len;
            }
        }
        if (count != expected) {
            log.err("S15 ratchet: {s} has {d} raw sends, allowlist says {d}", .{ name, count, expected });
            return error.RatchetMismatch;
        }
    }
}

// The MUC fan-out tears down a session whose buffer is genuinely full rather
// than leaving it wedged. c2s delivery now answers the same condition the same
// way, so one stuck peer cannot be told two different stories depending on
// whether the stanza came from a room.
// A buffer the server filled itself earlier in the same pass is not a slow
// reader: everything buffered is deliverable there. queueSendWithFlush makes
// one non-blocking attempt before the caller decides the peer stopped reading.
test "Re-review 5.3: a buffer the server filled itself is flushed, not torn down" {
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
    target.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch null;
    server.sessions[5] = target;
    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    // The buffer is nearly full, but the peer's socket is empty: a flush frees
    // all of it.
    target.conn.outbox.used = connection_mod.WRITE_BUF_SIZE - 16;

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "m1";
    const body = "<body>" ++ ("x" ** 64) ++ "</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    // Delivered, not torn down, and the sender got no bounce. The buffer was
    // pre-filled, so drain every writable pass to reach the stanza at the end.
    try std.testing.expect(!target.sm_overflow);
    var wire = std.ArrayList(u8){};
    defer wire.deinit(allocator);
    var buf: [8192]u8 = undefined;
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        _ = target.conn.flushSend() catch {};
        while (true) {
            const n = posix.read(target_fds[1], &buf) catch break;
            if (n == 0) break;
            try wire.appendSlice(allocator, buf[0..n]);
        }
        if (!target.conn.hasPendingWrite()) break;
    }
    try std.testing.expect(std.mem.indexOf(u8, wire.items, "id='m1'") != null);

    _ = alice.conn.flushSend() catch {};
    const sender_n = posix.read(alice_fds[1], &buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), sender_n);
}

test "Server: a full recipient buffer is marked for teardown like the MUC path" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;

    const target_fds = try makeSocketPair();
    defer posix.close(target_fds[1]);
    // A peer that is not reading: the receive buffer is tiny and the send side
    // is packed until the kernel refuses more, so a flush cannot make progress.
    var tiny: c_int = 1024;
    _ = std.c.setsockopt(target_fds[1], std.c.SOL.SOCKET, std.c.SO.RCVBUF, &tiny, @sizeOf(c_int));
    const target = try allocator.create(Session);
    target.* = Session.init(target_fds[0], 5, "localhost", false, allocator);
    target.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch null;
    server.sessions[5] = target;
    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);
    // Pack the kernel's send side until it refuses more, so the flush below
    // cannot free anything. That is the genuine slow-reader case the teardown
    // is for, as opposed to a buffer the server itself filled.
    {
        const chunk = [_]u8{'x'} ** 4096;
        while (true) {
            _ = posix.write(target.conn.fd, &chunk) catch break;
        }
    }
    @memset(target.conn.write_buf[0..connection_mod.WRITE_BUF_SIZE], 'x');
    target.conn.outbox.head = 0;
    target.conn.outbox.used = connection_mod.WRITE_BUF_SIZE;
    try std.testing.expectError(error.WouldBlock, target.conn.flushSend());

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "m1";
    const body = "<body>" ++ ("x" ** 64) ++ "</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    try std.testing.expect(target.sm_overflow);

    // The sender is told rather than left to guess.
    _ = alice.conn.flushSend() catch {};
    var buf: [1024]u8 = undefined;
    const n = posix.read(alice_fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "service-unavailable") != null);
}

test "Server: a non-archivable message stores offline with no archive" {
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

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    // type='normal' is not archivable, so the held copy is the only copy. It
    // does not need an archive row to exist: requiring one lost the message.
    alice.stanza_type = "normal";
    alice.stanza_id = "n1";
    const body = "<body>plain</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    const held = try offline_store.getHeldStanza(ptrs[0]);
    try std.testing.expect(held != null);
    if (held) |h| {
        defer allocator.free(h);
        try std.testing.expect(std.mem.indexOf(u8, h, "<body>plain</body>") != null);
    }
}

// The tail is per bare JID but the drain flag is per session, so one resource
// draining the tail leaves every other resource of that JID marked pending.
// The empty-tail branch clears the flag, or that session parks every later
// message behind a tail that no longer exists.
test "Re-review 5.2: an empty tail clears offline_pending instead of stranding it" {
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
    target.stream.state = .active;
    target.stream.authenticated = true;
    target.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "desktop" };
    server.sessions[5] = target;
    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    // bob's phone already drained the shared tail; this resource is still
    // marked pending from its own earlier stall.
    target.offline_pending = true;
    target.offline_store_stalls = 3;
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    session_lifecycle.deliverOfflineMessages(&server, target, "bob", "localhost", &changes);

    // The flag is gone, so a later live message is delivered, not parked.
    try std.testing.expect(!target.offline_pending);
    try std.testing.expectEqual(@as(u8, 0), target.offline_store_stalls);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "live1";
    const body = "<body>live</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;
    router.dispatchStanza(&server, &alice, &changes);

    _ = target.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(target_fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "<body>live</body>") != null);
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));
}

// A delete that keeps failing leaves the pointer behind. Recording the
// sequence that reached the wire makes the retry redo only the delete, instead
// of handing the same stanza to the connection again.
// The empty-tail branch clears the flag and the timer together. Leaving the
// timer armed would keep a dead retry in kqueue after the session is healthy.
test "Re-review 6.8: an empty tail cancels the retry timer" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();
    server.offline = &offline_store;

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, allocator);
    session.stream.state = .active;
    session.stream.authenticated = true;
    session.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "desk" };
    server.sessions[1] = session;

    // A stalled drain with its retry timer armed, and a tail that is now empty
    // because another resource drained it.
    session.offline_pending = true;
    session.offline_store_stalls = 4;
    session.offline_retry_timer_armed = true;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    session_lifecycle.deliverOfflineMessages(&server, session, "bob", "localhost", &changes);

    try std.testing.expect(!session.offline_pending);
    try std.testing.expect(!session.offline_retry_timer_armed);
    var timers: usize = 0;
    for (changes.slice()) |ev| {
        if (ev.filter == std.c.EVFILT.TIMER and ev.flags & std.c.EV.DELETE != 0) timers += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), timers);
}

// After the retry's delete lands, no row is outstanding for this session, so
// the recorded sequence must be cleared: it travels in the resume bundle, and
// a stale value would make a resumed drain delete a row without sending it.
test "Re-review 6.8: a successful retry delete clears the recorded sequence" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();
    server.offline = &offline_store;

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, allocator);
    session.stream.state = .active;
    session.stream.authenticated = true;
    server.sessions[1] = session;
    server.free_count -= 1;

    _ = try offline_store.storeHeldPointer("bob@localhost", "alice@localhost", "t1", 1001, "<message id='t1'><body>x</body></message>");
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    try std.testing.expectEqual(@as(usize, 1), ptrs.len);
    const seq = ptrs[0].sequence;

    session.offline_pending = true;
    session.offline_last_sent_sequence = seq;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    session_lifecycle.deliverOfflineMessages(&server, session, "bob", "localhost", &changes);

    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));
    try std.testing.expectEqual(@as(u64, 0), session.offline_last_sent_sequence);
}

// A delivery form between the write buffer and the scratch bank fits the
// serializer but never the socket buffer. That is not a slow reader: the form
// could never be queued for anyone, so it bounces and the recipient stays
// healthy.
test "Re-review 7.6: a form over the write buffer but inside the bank does not mark overflow" {
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
    bob.stream.state = .active;
    bob.stream.authenticated = true;
    bob.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "desk" };
    server.sessions[5] = bob;
    _ = try sm.bind(0, 5, "bob", "localhost", "desk");
    sm.setPresenceAvailable("bob", "localhost", "desk", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.state = .active;
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "band";
    // A full stanza: its delivery form clears the write buffer by the head and
    // tail alone, and still fits the 20 KiB scratch bank.
    @memset(alice.stanza_buf[0..16384], 'x');
    alice.stanza_buf_len = 16384;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    const drops_before = delivery_queue_mod.oversize_queue_drops.load(.monotonic);
    router.dispatchStanza(&server, &alice, &changes);

    try std.testing.expect(!bob.sm_overflow);
    try std.testing.expectEqual(@as(usize, 0), bob.conn.pendingWriteBytes());
    try std.testing.expectEqual(drops_before + 1, delivery_queue_mod.oversize_queue_drops.load(.monotonic));

    _ = alice.conn.flushSend() catch {};
    var wire: [4096]u8 = undefined;
    const n = posix.read(alice_fds[1], &wire) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, wire[0..n], "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..n], "id='band'") != null);
}

test "Re-review 5.4: a stuck delete retry deletes without resending" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();
    server.offline = &offline_store;

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, allocator);
    session.stream.state = .active;
    session.stream.authenticated = true;
    session.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "desk" };
    server.sessions[1] = session;
    server.free_count -= 1;

    _ = try offline_store.storeHeldPointer("bob@localhost", "alice@localhost", "t1", 1001, "<message id='t1'><body>once</body></message>");
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    try std.testing.expectEqual(@as(usize, 1), ptrs.len);

    // The state a failed delete leaves behind: the stanza went out, the row
    // did not. The retry must delete it and must not put it on the wire again.
    session.offline_pending = true;
    session.offline_last_sent_sequence = ptrs[0].sequence;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    session_lifecycle.deliverOfflineMessages(&server, session, "bob", "localhost", &changes);

    _ = session.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n);

    // The delete went through and the retry state is cleared.
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));
    try std.testing.expectEqual(@as(u64, 0), session.offline_last_sent_sequence);
    try std.testing.expect(!session.offline_pending);
}

// A drain that hands a stanza to the connection and then fails its delete has
// to remember which row it already sent, or the retry puts a second copy on the
// wire. Recording the sequence is the only thing that keeps the retry to the
// delete alone, so a drain that forgets it shows up here as two copies.
test "Re-review 6.2: a real delete failure records the sequence, the retry does not resend" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();
    server.offline = &offline_store;

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, allocator);
    session.stream.state = .active;
    session.stream.authenticated = true;
    session.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "desk" };
    server.sessions[1] = session;
    server.free_count -= 1;

    _ = try offline_store.storeHeldPointer("bob@localhost", "alice@localhost", "d1", 1001, "<message id='d1'><body>once</body></message>");
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    try std.testing.expectEqual(@as(usize, 1), ptrs.len);
    const sent_sequence = ptrs[0].sequence;

    // The first delete fails, after the stanza reached the connection.
    offline_store.test_fail_deletes = 1;
    session.offline_pending = true;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    session_lifecycle.deliverOfflineMessages(&server, session, "bob", "localhost", &changes);

    _ = session.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const first = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..first], "<body>once</body>") != null);
    try std.testing.expectEqual(sent_sequence, session.offline_last_sent_sequence);
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));

    // The retry redoes the delete and must not put a second copy on the wire.
    session_lifecycle.deliverOfflineMessages(&server, session, "bob", "localhost", &changes);

    _ = session.conn.flushSend() catch {};
    const second = posix.read(fds[1], &buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), second);
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));
    try std.testing.expectEqual(@as(u64, 0), session.offline_last_sent_sequence);
    try std.testing.expect(!session.offline_pending);
}

test "Server: H4 an inbound S2S message lands behind an existing offline tail" {
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
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.offline = &offline_store;
    server.archive = &arch_store;

    const tail = "<message from='carol@example.com/res' to='bob@localhost' id='tail-0' type='chat'><body>tail</body></message>";
    try std.testing.expect(try offline_store.storeHeldPointer("bob@localhost", "carol@example.com/res", "tail-0", 1000, tail));

    const target_fds = try makeSocketPair();
    defer posix.close(target_fds[1]);
    const target = try allocator.create(Session);
    target.* = Session.init(target_fds[0], 5, "localhost", false, allocator);
    target.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch null;
    target.offline_pending = true;
    server.sessions[5] = target;
    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    const live = "<message from='carol@example.com/res' to='bob@localhost' id='live-1' type='chat'><body>live</body></message>";
    var change_buf: [32]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = live,
    } }, &changes);

    try std.testing.expectEqual(@as(usize, 2), try offline_store.countMessages("bob@localhost"));
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    try std.testing.expectEqual(@as(usize, 2), ptrs.len);
    try std.testing.expectEqualStrings("tail-0", ptrs[0].stanza_id);
    try std.testing.expectEqualStrings("live-1", ptrs[1].stanza_id);

    session_lifecycle.deliverOfflineMessages(&server, target, "bob", "localhost", &changes);
    _ = target.conn.flushSend() catch {};
    var wire = std.ArrayList(u8){};
    defer wire.deinit(allocator);
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = posix.read(target_fds[1], &buf) catch break;
        if (n == 0) break;
        try wire.appendSlice(allocator, buf[0..n]);
    }
    try std.testing.expect(!target.offline_pending);
    const tail_at = std.mem.indexOf(u8, wire.items, "<body>tail</body>");
    const live_at = std.mem.indexOf(u8, wire.items, "<body>live</body>");
    try std.testing.expect(tail_at != null);
    try std.testing.expect(live_at != null);
    try std.testing.expect(tail_at.? < live_at.?);
}

test "Server: H4 a type normal message lands behind an existing offline tail" {
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
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.offline = &offline_store;
    server.archive = &arch_store;

    const tail = "<message from='alice@localhost/mobile' to='bob@localhost' id='tail-0' type='chat'><body>tail</body></message>";
    try std.testing.expect(try offline_store.storeHeldPointer("bob@localhost", "alice@localhost/mobile", "tail-0", 1000, tail));

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
    alice.stanza_id = "live-1";
    const body = "<body>live</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [32]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    try std.testing.expectEqual(@as(usize, 2), try offline_store.countMessages("bob@localhost"));
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    try std.testing.expectEqual(@as(usize, 2), ptrs.len);
    try std.testing.expectEqualStrings("tail-0", ptrs[0].stanza_id);
    try std.testing.expectEqualStrings("live-1", ptrs[1].stanza_id);

    session_lifecycle.deliverOfflineMessages(&server, target, "bob", "localhost", &changes);
    _ = target.conn.flushSend() catch {};
    var wire = std.ArrayList(u8){};
    defer wire.deinit(allocator);
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = posix.read(target_fds[1], &buf) catch break;
        if (n == 0) break;
        try wire.appendSlice(allocator, buf[0..n]);
    }
    try std.testing.expect(!target.offline_pending);
    const tail_at = std.mem.indexOf(u8, wire.items, "<body>tail</body>");
    const live_at = std.mem.indexOf(u8, wire.items, "<body>live</body>");
    try std.testing.expect(tail_at != null);
    try std.testing.expect(live_at != null);
    try std.testing.expect(tail_at.? < live_at.?);
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

test "Server: H3 a resume carries the stalled offline tail" {
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

    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();
    server.offline = &offline_store;
    server.archive = &arch_store;
    sm_handoff.resetForTesting();

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    const previd = "cccccccccccccccccccccccccccccccc";
    session.sm_resume_pending = true;
    session.sm_resume_epoch = 7;
    @memcpy(&session.sm_resume_previd, previd);

    // A stanza waiting in the store for the resumed session.
    _ = try offline_store.storeHeldPointer(
        "alice@localhost",
        "bob@localhost/res",
        "tail-1",
        1000,
        "<message from='bob@localhost/res' to='alice@localhost' id='tail-1'><body>tail</body></message>",
    );

    // Hand the bundle over with the tail still pending.
    const bundle = sm_handoff.allocator.create(sm_handoff.ResumeBundle) catch unreachable;
    bundle.* = .{
        .previd = undefined,
        .sm_in_h = 0,
        .sm_out_seq = 1,
        .sm_out_h = 0,
        .r_outstanding = false,
        .roster_interested = false,
        .carbons_enabled = false,
        .csi_active = false,
        .username = sm_handoff.allocator.dupe(u8, "alice") catch unreachable,
        .resource = sm_handoff.allocator.dupe(u8, "res") catch unreachable,
        .last_presence = sm_handoff.allocator.dupe(u8, "") catch unreachable,
        .base_seq = 1,
        .last_h = 0,
        .offline_pending = true,
        .created = std.time.timestamp(),
    };
    @memcpy(&bundle.previd, previd);
    try sm_handoff.put(previd, bundle);

    c2s_sm.handleSmResumeReply(&server, .{
        .previd = previd,
        .req_session = 1,
        .req_epoch = 7,
        .status = "ok",
    }, &changes);

    // Resume sends no initial presence, so without the carried flag (and the
    // drain restart) the tail would wait for the next login.
    try std.testing.expect(!session.offline_pending);
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("alice@localhost"));
    _ = session.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "<resumed") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "tail-1") != null);
}

// The count runs before anything is armed, so a failure there must stage its
// own retry. Otherwise the session stays pending with no timer, no staged
// write, and no sweep, and the tail waits for the next login.
test "Re-review 6.4: a failed count arms a retry instead of parking the session" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();
    server.offline = &offline_store;

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, allocator);
    session.stream.state = .active;
    session.stream.authenticated = true;
    session.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "desk" };
    server.sessions[1] = session;
    server.free_count -= 1;

    _ = try offline_store.storeHeldPointer("bob@localhost", "alice@localhost", "c1", 1001, "<message id='c1'><body>once</body></message>");

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    offline_store.test_fail_counts = 1;
    session.offline_pending = true;
    session.offline_store_stalls = 0;

    session_lifecycle.deliverOfflineMessages(&server, session, "bob", "localhost", &changes);

    // The stall is recorded and a prompt retry is staged on the connection.
    try std.testing.expect(session.offline_pending);
    try std.testing.expectEqual(@as(u8, 1), session.offline_store_stalls);
    var staged_write = false;
    for (changes.buf[0..changes.len]) |ev| {
        if (ev.filter == std.c.EVFILT.WRITE and ev.udata == session.conn.id) staged_write = true;
    }
    try std.testing.expect(staged_write);

    // With the store recovered the next drain sends the row.
    session_lifecycle.deliverOfflineMessages(&server, session, "bob", "localhost", &changes);
    _ = session.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "<body>once</body>") != null);
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));
    try std.testing.expect(!session.offline_pending);
}

// The drain had handed this row to the connection and then failed its delete.
// Resume must carry that sequence, or it resends the row the client already
// has on top of the SM replay of the same stanza.
test "Re-review 6.3: a cross-worker resume carries the recorded sequence" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();
    server.offline = &offline_store;
    sm_handoff.resetForTesting();

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, allocator);
    server.sessions[1] = session;

    const previd = "dddddddddddddddddddddddddddddddd";
    session.sm_resume_pending = true;
    session.sm_resume_epoch = 3;
    @memcpy(&session.sm_resume_previd, previd);

    _ = try offline_store.storeHeldPointer(
        "alice@localhost",
        "bob@localhost/res",
        "tail-3",
        1000,
        "<message from='bob@localhost/res' to='alice@localhost' id='tail-3'><body>tail</body></message>",
    );
    const ptrs = try offline_store.getPointers("alice@localhost");
    defer offline_store.freePointers(ptrs);
    try std.testing.expectEqual(@as(usize, 1), ptrs.len);
    const sent_sequence = ptrs[0].sequence;

    const bundle = sm_handoff.allocator.create(sm_handoff.ResumeBundle) catch unreachable;
    bundle.* = .{
        .previd = undefined,
        .sm_in_h = 0,
        .sm_out_seq = 1,
        .sm_out_h = 0,
        .r_outstanding = false,
        .roster_interested = false,
        .carbons_enabled = false,
        .csi_active = false,
        .username = sm_handoff.allocator.dupe(u8, "alice") catch unreachable,
        .resource = sm_handoff.allocator.dupe(u8, "res") catch unreachable,
        .last_presence = sm_handoff.allocator.dupe(u8, "") catch unreachable,
        .base_seq = 1,
        .last_h = 0,
        .offline_pending = true,
        .offline_last_sent_sequence = sent_sequence,
        .created = std.time.timestamp(),
    };
    @memcpy(&bundle.previd, previd);
    try sm_handoff.put(previd, bundle);

    c2s_sm.handleSmResumeReply(&server, .{
        .previd = previd,
        .req_session = 1,
        .req_epoch = 3,
        .status = "ok",
    }, &changes);

    // Carried, then consumed by the retry: the row is deleted, not resent.
    try std.testing.expectEqual(@as(u64, 0), session.offline_last_sent_sequence);
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("alice@localhost"));
    _ = session.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "<resumed") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "tail-3") == null);
}

// The local resume path restores the same per-session drain state as the
// cross-worker one, and losing the sequence there resends the stanza too.
test "Re-review 6.3: a local resume carries the recorded sequence" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();
    server.offline = &offline_store;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    _ = try offline_store.storeHeldPointer(
        "alice@localhost",
        "bob@localhost/res",
        "tail-4",
        1000,
        "<message from='bob@localhost/res' to='alice@localhost' id='tail-4'><body>tail</body></message>",
    );
    const ptrs = try offline_store.getPointers("alice@localhost");
    defer offline_store.freePointers(ptrs);
    try std.testing.expectEqual(@as(usize, 1), ptrs.len);
    const sent_sequence = ptrs[0].sequence;

    const det_fds = try makeSocketPair();
    defer posix.close(det_fds[1]);
    const detached = try allocator.create(Session);
    detached.* = Session.init(det_fds[0], 2, "localhost", false, allocator);
    @memcpy(detached.auth_username_buf[0..5], "alice");
    detached.auth_username_len = 5;
    detached.stream.bound_jid = xmpp.Jid.parse("alice@localhost/res") catch null;
    detached.sm_detached = true;
    detached.sm_detach_time = std.time.timestamp();
    detached.sm_resume_enabled = true;
    detached.offline_pending = true;
    detached.offline_last_sent_sequence = sent_sequence;
    const det_queue = try allocator.create(sm_state.SmUnackedQueue);
    det_queue.* = sm_state.SmUnackedQueue.init(allocator);
    det_queue.base_seq = 1;
    detached.sm_unacked = det_queue;
    server.sessions[2] = detached;

    var previd: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
    sm_state.generateSmId(server.worker_id, &previd);
    c2s_sm.smIdMapInsert(&server, &previd, 2);
    server.detached_count = 1;

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, allocator);
    server.sessions[1] = session;

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    c2s_session.handleReadable(&server, 1, &changes);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    session.stream.state = .features_bind;
    session.stream.authenticated_jid = xmpp.Jid.parse("alice@localhost") catch null;
    while (true) {
        const wrote = session.conn.flushSend() catch break;
        while (posix.read(fds[1], &drain_buf)) |dn| {
            if (dn == 0) break;
        } else |_| {}
        if (wrote == 0 or !session.conn.hasPendingWrite()) break;
    }

    var resume_buf: [128]u8 = undefined;
    const resume_xml = std.fmt.bufPrint(&resume_buf, "<resume xmlns='urn:xmpp:sm:3' previd='{s}' h='0'/>", .{previd}) catch unreachable;
    _ = try posix.write(fds[1], resume_xml);
    c2s_session.handleReadable(&server, 1, &changes);

    // The retry deletes the row instead of resending it.
    try std.testing.expectEqual(@as(u64, 0), session.offline_last_sent_sequence);
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("alice@localhost"));
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "<resumed") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "tail-4") == null);
}

test "Server: H3 a local resume carries the stalled offline tail" {
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

    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();
    server.offline = &offline_store;
    server.archive = &arch_store;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // Detached session on slot 2 with an undrained tail.
    const det_fds = try makeSocketPair();
    defer posix.close(det_fds[1]);
    const detached = try allocator.create(Session);
    detached.* = Session.init(det_fds[0], 2, "localhost", false, allocator);
    @memcpy(detached.auth_username_buf[0..5], "alice");
    detached.auth_username_len = 5;
    detached.stream.bound_jid = xmpp.Jid.parse("alice@localhost/res") catch null;
    detached.sm_detached = true;
    detached.sm_detach_time = std.time.timestamp();
    detached.sm_resume_enabled = true;
    detached.offline_pending = true;
    const det_queue = try allocator.create(sm_state.SmUnackedQueue);
    det_queue.* = sm_state.SmUnackedQueue.init(allocator);
    det_queue.base_seq = 1;
    detached.sm_unacked = det_queue;
    server.sessions[2] = detached;

    var previd: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
    sm_state.generateSmId(server.worker_id, &previd);
    c2s_sm.smIdMapInsert(&server, &previd, 2);
    server.detached_count = 1;

    _ = try offline_store.storeHeldPointer(
        "alice@localhost",
        "bob@localhost/res",
        "tail-2",
        1000,
        "<message from='bob@localhost/res' to='alice@localhost' id='tail-2'><body>tail</body></message>",
    );

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, allocator);
    server.sessions[1] = session;

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    c2s_session.handleReadable(&server, 1, &changes);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    session.stream.state = .features_bind;
    session.stream.authenticated_jid = xmpp.Jid.parse("alice@localhost") catch null;
    // Flush the stream-features reply so the offline tail has buffer room.
    while (true) {
        const wrote = session.conn.flushSend() catch break;
        while (posix.read(fds[1], &drain_buf)) |dn| {
            if (dn == 0) break;
        } else |_| {}
        if (wrote == 0 or !session.conn.hasPendingWrite()) break;
    }

    var resume_buf: [128]u8 = undefined;
    const resume_xml = std.fmt.bufPrint(&resume_buf, "<resume xmlns='urn:xmpp:sm:3' previd='{s}' h='0'/>", .{previd}) catch unreachable;
    _ = try posix.write(fds[1], resume_xml);
    c2s_session.handleReadable(&server, 1, &changes);

    try std.testing.expect(!session.offline_pending);
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("alice@localhost"));
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "<resumed") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "tail-2") != null);
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
    try op_db.put(offline_store_mod.NS_OFFLINE, "warmup", "");
    try op_db.delete(offline_store_mod.NS_OFFLINE, "warmup");

    const Store = GenericOfflineStore(OpBackendType);
    const Context = struct {
        store: *Store,
        ready: *std.Thread.Semaphore,
        start: *std.Thread.Semaphore,
        successes: *std.atomic.Value(usize),
        errors: *std.atomic.Value(usize),
        worker: usize,
        /// Message index of each successful store, in the order this worker
        /// made them. The store must hand them back in that order.
        accepted: [150]usize = undefined,
        accepted_len: usize = 0,

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
                if (stored) {
                    _ = ctx.successes.fetchAdd(1, .monotonic);
                    ctx.accepted[ctx.accepted_len] = i;
                    ctx.accepted_len += 1;
                }
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

    // Two workers storing at once must still get one sequence per accepted
    // message, all distinct: a shared counter read and written without the
    // lock hands two rows the same sequence and one overwrites the other.
    const pointers = try first_store.getPointers("bob@localhost");
    defer first_store.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 100), pointers.len);

    var seen = try allocator.alloc(bool, 151);
    defer allocator.free(seen);
    @memset(seen, false);
    for (pointers) |ptr| {
        try std.testing.expect(ptr.sequence != 0);
        try std.testing.expect(ptr.sequence <= 100);
        try std.testing.expect(!seen[ptr.sequence]);
        seen[ptr.sequence] = true;
    }

    // Each worker's own messages must come back in the order it stored them,
    // interleaved with the other worker's but never reordered within a worker.
    for (0..2) |worker| {
        var expected_next: usize = 0;
        const accepted = contexts[worker].accepted[0..contexts[worker].accepted_len];
        var from_buf: [48]u8 = undefined;
        for (pointers) |ptr| {
            const prefix = std.fmt.bufPrint(&from_buf, "alice@localhost/worker-{d}-", .{worker}) catch unreachable;
            if (!std.mem.startsWith(u8, ptr.from_jid, prefix)) continue;
            const index = std.fmt.parseInt(usize, ptr.from_jid[prefix.len..], 10) catch unreachable;
            if (expected_next >= accepted.len) continue;
            try std.testing.expectEqual(accepted[expected_next], index);
            expected_next += 1;
        }
        try std.testing.expectEqual(accepted.len, expected_next);
    }
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
        c2s_session.handleWritable(&server, 1, &changes);
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

// E6 (S11): only whitespace is allowed at the stream level between stanzas.
// Non-whitespace there is a stream error (RFC 6120 4.6.1).
// E6 (S11): an over-long token is a resource limit the peer hit, not malformed
// XML, so it maps to a policy-violation stream error (not not-well-formed).
// The scanner cap is 512 KiB, so the name is driven past it in chunks through
// the real parse path.
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
    // Send sites must not bypass the reconciler's armed-state tracking.
    // The patterns are split so this test does not match itself.
    const auth_needle = "IPC_AUTH_" ++ "UDATA";
    const s2s_needle = "IPC_S2S_" ++ "UDATA";
    const cases = .{
        .{ "iq/dispatch.zig", @embedFile("../iq/dispatch.zig") },
        .{ "iq/carbons.zig", @embedFile("../iq/carbons.zig") },
        .{ "routing/router.zig", @embedFile("../routing/router.zig") },
        .{ "c2s/lifecycle.zig", @embedFile("../c2s/lifecycle.zig") },
        .{ "presence/handler.zig", @embedFile("../presence/handler.zig") },
        .{ "presence/subscription.zig", @embedFile("../presence/subscription.zig") },
        .{ "presence/broadcast.zig", @embedFile("../presence/broadcast.zig") },
        .{ "muc/handler.zig", @embedFile("../muc/handler.zig") },
        .{ "muc/actor.zig", @embedFile("../muc/actor.zig") },
        .{ "xworker/envelope.zig", @embedFile("../xworker/envelope.zig") },
        .{ "muc/fanout.zig", @embedFile("../muc/fanout.zig") },
        .{ "caps.zig", @embedFile("../caps.zig") },
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
    const src = @embedFile("worker.zig");
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
        .{ "worker/worker.zig", @embedFile("worker.zig"), @as(usize, 1), @as(usize, 1) },
        .{ "connection.zig", @embedFile("../connection.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "iq/dispatch.zig", @embedFile("../iq/dispatch.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "iq/carbons.zig", @embedFile("../iq/carbons.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "routing/router.zig", @embedFile("../routing/router.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "c2s/lifecycle.zig", @embedFile("../c2s/lifecycle.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "presence/handler.zig", @embedFile("../presence/handler.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "presence/subscription.zig", @embedFile("../presence/subscription.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "presence/broadcast.zig", @embedFile("../presence/broadcast.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "muc/handler.zig", @embedFile("../muc/handler.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "muc/actor.zig", @embedFile("../muc/actor.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "xworker/envelope.zig", @embedFile("../xworker/envelope.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "muc/fanout.zig", @embedFile("../muc/fanout.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "caps.zig", @embedFile("../caps.zig"), @as(usize, 0), @as(usize, 0) },
        .{ "worker/loop.zig", @embedFile("loop.zig"), @as(usize, 0), @as(usize, 0) },
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
    // checks above: binding the method to a local and calling that through the
    // alias never spells the call form. Count the bare name instead. Split the
    // needle so this test does not count itself.
    const any_timer_needle = "add" ++ "Timer";
    const src = @embedFile("worker.zig");
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
    try changes.addTimer(OFFLINE_RETRY_TIMER_IDENT, session_lifecycle.OFFLINE_RETRY_DELAY_MS, false);
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
    try changes.addTimer(OFFLINE_RETRY_TIMER_IDENT, session_lifecycle.OFFLINE_RETRY_DELAY_MS, false);
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
pub const TestIpcListener = struct {
    fd: posix.fd_t = -1,
    path: []const u8,

    pub fn init(path: []const u8) !TestIpcListener {
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

    pub fn deinit(self: *TestIpcListener) void {
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

// G6: the auth half of the reconnect-timer guarantee is gated on its own, so
// the S2S tests alone cannot cover a regression in auth staging or re-arm.
test "Server: G6 an auth reconnect owed by a full batch still gets its timer" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    // A batch already at its ordinary limit, built the way the event loop
    // builds it so the tail budget is production's. The third slot is reserved.
    var change_buf: [IPC_RECONCILE_RESERVED + 2]posix.Kevent = undefined;
    var changes = initLoopChangeList(&change_buf);
    try changes.addTimer(SM_EXPIRY_TIMER_IDENT, SM_EXPIRY_SWEEP_MS, false);
    try changes.addTimer(OFFLINE_RETRY_TIMER_IDENT, session_lifecycle.OFFLINE_RETRY_DELAY_MS, false);
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

    c2s_session.continueTlsHandshake(&server, 1, session, &changes);
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

test "S13: offline archive failure injection stays out of production" {
    const hook_name = "fail_next_offline" ++ "_archive_read";
    try std.testing.expect(std.mem.indexOf(u8, @embedFile("worker.zig"), hook_name) == null);
    try std.testing.expect(std.mem.indexOf(u8, @embedFile("../c2s/lifecycle.zig"), hook_name) == null);
}

// Force analysis of sibling files whose tests otherwise never run.
test {
    _ = iq_handler;
    _ = router;
    _ = muc_handler;
    _ = presence_handler;
    _ = session_lifecycle;
    _ = @import("../iq/carbons.zig");
}

test "Server: inline archiveStore failure increments archive_store_failed (S31)" {
    const allocator = std.testing.allocator;

    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("archive");
    const path = try tmp.dir.realpathAlloc(allocator, "archive");
    defer allocator.free(path);

    var be = try ArchiveBackendType.open(path, .{});
    defer be.close();

    // An allocator that always fails makes ArchiveStore.store() return
    // OutOfMemory while building the key: the inline path must count it.
    var empty_buf: [0]u8 = .{};
    var fba = std.heap.FixedBufferAllocator.init(&empty_buf);
    var store = archive_store_mod.ArchiveStore(ArchiveBackendType).init(&be, fba.allocator());
    server.archive = &store;

    server.archiveStore("a@localhost", "b@localhost", "s1", 1, "<m/>");
    server.archiveStore("a@localhost", "b@localhost", "s2", 2, "<m/>");
    try std.testing.expectEqual(@as(u64, 2), server.archive_store_failed);
}

test "Server: H8 an inline offline archive failure on the c2s path is counted" {
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

    // A zero-capacity allocator makes every archive store fail with
    // OutOfMemory while building its key.
    var empty_buf: [0]u8 = .{};
    var fba = std.heap.FixedBufferAllocator.init(&empty_buf);
    var arch_store = archive_store_mod.ArchiveStore(ArchiveBackendType).init(&arch_db, fba.allocator());

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.offline = &offline_store;
    server.archive = &arch_store;

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "normal";
    alice.stanza_id = "n1";
    const body = "<body>not archivable</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    // The failed inline store is counted once, and the message still reaches
    // the offline store with its payload.
    try std.testing.expectEqual(@as(u64, 1), server.archive_store_failed);
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    const held = try offline_store.getHeldStanza(ptrs[0]);
    defer if (held) |xml_bytes| allocator.free(xml_bytes);
    try std.testing.expect(held != null);
    try std.testing.expect(std.mem.indexOf(u8, held.?, "<body>not archivable</body>") != null);
}

test "Server: H8 an inline offline archive failure on the S2S path is counted" {
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

    var empty_buf: [0]u8 = .{};
    var fba = std.heap.FixedBufferAllocator.init(&empty_buf);
    var arch_store = archive_store_mod.ArchiveStore(ArchiveBackendType).init(&arch_db, fba.allocator());

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.offline = &offline_store;
    server.archive = &arch_store;

    const inbound = "<message from='carol@example.com/res' to='bob@localhost' id='r9' type='chat'><body>hello</body></message>";
    var change_buf: [32]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = inbound,
    } }, &changes);

    // Counted once, and the stanza is still held: the archive write is not a
    // precondition for the offline copy.
    try std.testing.expectEqual(@as(u64, 1), server.archive_store_failed);
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    const held = try offline_store.getHeldStanza(ptrs[0]);
    defer if (held) |xml_bytes| allocator.free(xml_bytes);
    try std.testing.expect(held != null);
    try std.testing.expectEqualStrings(inbound, held.?);
}

test "every store namespace constant is registered and every registry entry is owned" {
    // Owner constants bind through backend.registered, so one-sided
    // renames are compile errors; this pins the reverse side (a registry
    // entry no owner uses) across the whole set.
    const user_store = @import("user_store");
    const lock_store = @import("lock_store");
    const invite_store = @import("invite_store");
    const last_activity_store = @import("last_activity_store");
    const oidc_identity_store = @import("oidc_identity_store");
    const owners = [_][]const u8{
        user_store.NAMESPACE,
        generic_roster.NAMESPACE,
        vcard_store_mod.NAMESPACE,
        pep_store_mod.NAMESPACE,
        lock_store.NAMESPACE,
        last_activity_store.NAMESPACE,
        invite_store.NAMESPACE,
        block_store_mod.NAMESPACE,
        offline_store_mod.NS_OFFLINE,
        offline_store_mod.NS_OFFLINE_HOLD,
        offline_store_mod.NS_OFFLINE_V2,
        offline_store_mod.NS_OFFLINE_HOLD_V2,
        offline_store_mod.NS_OFFLINE_SEQ,
        offline_store_mod.NS_OFFLINE_HOLD_TOKEN,
        room_store_mod.NS_ROOMS,
        room_store_mod.NS_AFFILIATIONS,
        archive_store_mod.NS_MESSAGES,
        archive_store_mod.NS_BY_CONTACT,
        presence_handler.PENDING_SUB_NS,
        oidc_identity_store.NAMESPACE,
    };
    const registry = backend_mod.canonical_namespaces;
    try std.testing.expectEqual(registry.len, owners.len);
    for (owners) |owned| {
        var seen = false;
        for (registry) |entry| {
            if (std.mem.eql(u8, owned, entry)) seen = true;
        }
        try std.testing.expect(seen);
    }
    for (registry) |entry| {
        var seen = false;
        for (owners) |owned| {
            if (std.mem.eql(u8, owned, entry)) seen = true;
        }
        try std.testing.expect(seen);
    }
}

// A worker that restarts within the same wall second starts its stanza id
// counter from zero again, so without per-process entropy both incarnations
// mint the token the other already stored and the store answers a new message
// as already held.
test "hold token: a second incarnation in the same second mints a new token" {
    const allocator = std.testing.allocator;

    var first = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 8);
    defer first.deinit();
    var second = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 8);
    defer second.deinit();

    try std.testing.expectEqual(@as(u32, 0), first.stanza_id_counter);
    try std.testing.expectEqual(@as(u32, 0), second.stanza_id_counter);

    const a = first.mintHoldToken();
    const b = second.mintHoldToken();
    try std.testing.expect(a != b);
    try std.testing.expect(a != 0);
    try std.testing.expect(b != 0);
}
