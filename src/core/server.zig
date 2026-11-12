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
const EventLoop = @import("event_loop.zig").EventLoop;
const ChangeList = @import("event_loop.zig").ChangeList;
const Connection = @import("connection.zig").Connection;
pub const connection_mod = @import("connection.zig");
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
const iq_handler = @import("iq_handler.zig");
const muc_handler = @import("muc_handler.zig");
const presence_handler = @import("presence_handler.zig");
pub const sub_cache_mod = @import("subscription_cache.zig");
pub const caps_mod = @import("caps.zig");
const router = @import("router.zig");
const session_lifecycle = @import("c2s/lifecycle.zig");
const stanza_writer = @import("stanza/writer.zig");
const stanza_facts = @import("stanza/facts.zig");
const room_registry_mod = @import("room_registry");
const room_mailbox_mod = @import("room_mailbox");
const RoomRegistry = room_registry_mod.RoomRegistry;
const room_store_mod = @import("room_store");
const GenericRoomStore = room_store_mod.RoomStore(OpBackendType);
const fanout_mod = @import("fanout.zig");
const FanoutQueue = fanout_mod.FanoutQueue;
const actor_message = @import("message.zig");
pub const sm_state = @import("c2s/sm_state.zig");
const sm_handoff = @import("c2s/sm_handoff.zig");
const c2s_session = @import("c2s/session.zig");
const c2s_sm = @import("c2s/sm.zig");
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
const noteQueueDrop = c2s_session.noteQueueDrop;
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
            c2s_session.executeAction(self,session, session.stream.saslFailure("temporary-auth-failure"), changes);
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

    /// Park a message behind a session's draining offline tail. The held bytes
    /// are authoritative; archive metadata is retained only for fallback reads.
    ///
    /// Returns true when the message is held, which includes the case where this
    /// dispatch is already held for this bare JID: the tail is per bare JID, so
    /// every draining resource and every worker holding one sees the same
    /// message and must not add a second row for it. `token` identifies the
    /// dispatch, so two messages with identical bytes stay two rows.
    pub fn holdBehindOfflineTail(
        self: *Server,
        target: *Session,
        local: []const u8,
        domain: []const u8,
        from_jid: []const u8,
        stanza_id: []const u8,
        timestamp: u64,
        stanza_xml: []const u8,
        token: offline_store_mod.HoldToken,
    ) bool {
        if (!target.offline_pending) return false;
        const store = self.offline orelse return false;
        var recipient_buf: [router.BARE_JID_MAX]u8 = undefined;
        const recipient = router.buildBareJid(local, domain, &recipient_buf) catch return false;
        const outcome = store.storeHeldPointerOnce(recipient, from_jid, stanza_id, timestamp, stanza_xml, token) catch |err| {
            log.warn("message to {s} could not be held behind the offline tail: {s}", .{ recipient, @errorName(err) });
            return false;
        };
        return switch (outcome) {
            .stored, .already_held => true,
            .full => false,
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
            c2s_session.continueTlsHandshake(self,id, session, changes);
            return;
        }
        c2s_session.handleReadable(self,id, changes);
    }

    fn handleWritableOrHandshake(self: *Server, id: usize, changes: *ChangeList) void {
        const session = self.sessions[id] orelse return;
        if (session.conn.isTlsHandshaking()) {
            c2s_session.continueTlsHandshake(self,id, session, changes);
            return;
        }
        c2s_session.handleWritable(self,id, changes);
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
                session.conn.queueSend(challenge_xml) catch |err| {
                    noteQueueDrop(session, challenge_xml, err, "SASL challenge");
                    return;
                };
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
                c2s_session.executeAction(self,session, success_action, changes);
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
                        c2s_session.handleReadable(self,conn_id, changes);
                    }
                }
            },
            .auth_failure => |m| {
                log.info("connection {d} auth failed: {s}", .{ conn_id, m.reason });
                const fail_action = session.stream.saslFailure(m.reason);
                c2s_session.executeAction(self,session, fail_action, changes);
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
                session.conn.queueSend(reply_xml) catch |err| {
                    noteQueueDrop(session, reply_xml, err, "register result");
                    return;
                };

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
                    session.conn.queueSend("</stream:stream>") catch {};

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
        _ = self.sendS2sError(remote_from, local_to, tag_name, stanza_id);
    }

    /// Serialize and queue a service-unavailable bounce for an inbound S2S
    /// stanza. Returns false when the bounce could not be handed to the S2S
    /// daemon, so callers can count and log the refusal instead of assuming
    /// the sender was told.
    fn sendS2sError(self: *Server, remote_from: []const u8, local_to: []const u8, tag_name: []const u8, stanza_id: []const u8) bool {
        if (!self.s2s_ipc.connected) {
            log.warn("S2S bounce for {s} dropped: no S2S daemon", .{remote_from});
            return false;
        }

        var lease = self.leaseByteScratch() orelse return false;
        defer lease.release();
        var fbs = std.io.fixedBufferStream(lease.buf);
        stanza_writer.writeS2sError(fbs.writer(), tag_name, local_to, remote_from, stanza_id) catch {
            log.warn("S2S bounce for {s} dropped: serialization failed", .{remote_from});
            return false;
        };

        self.s2s_ipc.send(.{ .s2s_deliver = .{
            .from_jid = local_to,
            .to_jid = remote_from,
            .stanza_xml = fbs.getWritten(),
        } }) catch {
            log.err("failed to bounce S2S inbound for {s}", .{remote_from});
            return false;
        };
        _ = delivery_queue_mod.s2s_bounces.fetchAdd(1, .monotonic);
        // Write interest: reconcileIpcWriteInterest (S10).
        return true;
    }

    /// Tell the sender of a cross-worker stanza that it could not be held
    /// behind the recipient's draining offline tail. The sender may live on
    /// another worker, so the bounce is routed through the session map and
    /// the MPSC queue the same way a delivery is.
    fn bounceCrossWorkerUnavailable(
        self: *Server,
        sender_wire: []const u8,
        recipient_bare: []const u8,
        stanza_id: []const u8,
        tag_name: []const u8,
        changes: *ChangeList,
    ) void {
        const sm = self.session_map orelse return;
        // sender_wire is the raw on-wire attribute, still entity-encoded.
        var sender_buf: [512]u8 = undefined;
        var sender_fbs = std.io.fixedBufferStream(&sender_buf);
        xml.decodeWrite(sender_fbs.writer(), sender_wire) catch {
            log.warn("cross-worker bounce dropped: sender attribute does not decode", .{});
            return;
        };
        const sender_full = sender_fbs.getWritten();
        const sender = xmpp.Jid.parse(sender_full) catch {
            log.warn("cross-worker bounce for {s} dropped: unparsable sender", .{sender_full});
            return;
        };
        if (sender.resource.len == 0) {
            log.warn("cross-worker bounce for {s} dropped: sender is a bare JID", .{sender_full});
            return;
        }
        const entry = sm.findByFullJid(sender.local, sender.domain, sender.resource) orelse {
            log.warn("cross-worker bounce for {s} dropped: sender session gone", .{sender_full});
            return;
        };

        var buf: [1024]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        stanza_writer.writeCrossWorkerError(fbs.writer(), tag_name, recipient_bare, sender_full, stanza_id) catch {
            log.warn("cross-worker bounce for {s} dropped: serialization failed", .{sender_full});
            return;
        };
        const stanza = fbs.getWritten();

        if (entry.worker_id == self.worker_id) {
            const session = self.sessions[entry.local_session_id] orelse {
                log.warn("cross-worker bounce for {s} dropped: sender slot empty", .{sender_full});
                return;
            };
            session.queueSendStanza(stanza) catch |err| {
                log.warn("cross-worker bounce for {s} not queued: {s}", .{ sender_full, @errorName(err) });
                return;
            };
            if (session.conn.hasPendingWrite()) {
                changes.addWrite(session.conn.fd, session.conn.id) catch {};
            }
        } else if (self.delivery_system) |ds| {
            ds.deliver(entry.worker_id, entry.local_session_id, entry.generation, stanza) catch {
                _ = delivery_queue_mod.cross_worker_drops.fetchAdd(1, .monotonic);
                log.warn("cross-worker bounce for {s} dropped: delivery queue full", .{sender_full});
                return;
            };
        } else {
            log.warn("cross-worker bounce for {s} dropped: no delivery system", .{sender_full});
            return;
        }
        _ = delivery_queue_mod.offline_hold_bounces.fetchAdd(1, .monotonic);
    }

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
                    const parts = stanza_facts.extractStanzaParts(m.stanza_xml);
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
                        self.bounceS2sInbound(m.from_jid, m.to_jid, "message", parts.msg_id);
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
                            if (self.holdBehindOfflineTail(target_session, to_jid.local, to_jid.domain, m.from_jid, hold_id, s2s_archive_ts, m.stanza_xml, s2s_hold_token)) {
                                s2s_hold_stored = true;
                                continue;
                            }
                            // Held neither in the queue nor on the wire: tell
                            // the remote sender instead of dropping (H2).
                            log.warn("S2S message to {s} not held, bouncing to the sender", .{m.to_jid});
                            if (self.sendS2sError(m.from_jid, m.to_jid, "message", live_parts.msg_id)) {
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
    // Cross-thread delivery (MPSC queue consumer)
    // ========================================================================

    /// Handle EVFILT_READ on the wake pipe — drain pipe bytes, then drain the MPSC queue,
    /// then drain per-room mailboxes.
    fn handleDeliveryWake(self: *Server, changes: *ChangeList) void {
        const ds = self.delivery_system orelse return;
        if (metrics.get()) |c| metrics.bump(&c.wakes, 1);
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
            queue: *delivery_queue_mod.MpscQueue,
        };
        const ctx = Ctx{ .server = self, .changes = changes, .session_map = sm, .queue = queue };

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
                    c2s_sm.handleSmActorMessage(c.server,payload, c.changes);
                    return;
                }

                // Unicast: ABA check then deliver to single session
                if (!c.session_map.getGenerationById(c.server.worker_id, local_session_id, generation)) return;

                const target_session = c.server.sessions[local_session_id] orelse return;
                const parts = stanza_facts.extractStanzaParts(payload);
                // XEP-0280 sections 2 and 7: a carbon copy reaches only a
                // Carbons-enabled resource, live or not at all. The producer
                // tags the slot so the same per-session policy the local
                // carbon path applies (sendCarbons -> deliverToSession,
                // which never holds) applies to a remote target: it is
                // never held behind a draining offline tail, never stored
                // and never bounced.
                const is_carbon = c.queue.current_slot_kind == .carbon;
                if (is_carbon and !target_session.carbons_enabled) return;
                // The hold check comes before the SM-detach check: a detached
                // session may still have an undrained offline tail, and a
                // message pushed into its replay queue would be replayed
                // ahead of that tail (H3). The c2s router orders them the
                // same way.
                if (target_session.offline_pending and !is_carbon and parts.is_message and !std.mem.eql(u8, parts.msg_type, "error")) {
                    const hold_id = if (parts.msg_id.len > 0) parts.msg_id else "offline";
                    // Stamp the producer's receipt time, not the time a busy
                    // consumer worker got to the slot.
                    const timestamp: u64 = if (c.queue.current_slot_receipt_ts != 0)
                        c.queue.current_slot_receipt_ts
                    else
                        @intCast(std.time.timestamp());
                    const from_jid = stanza_facts.extractAttrValue(payload, "from");
                    const bound = target_session.stream.bound_jid orelse {
                        log.warn("cross-worker message to session {d} has no bound recipient for its offline hold", .{local_session_id});
                        return;
                    };
                    // A producer that minted a token (the router, S2S inbound)
                    // has every worker holding a resource of this bare JID
                    // collapse the same dispatch. A producer that did not gets
                    // a token here, so the message is still stored; only the
                    // cross-worker collapse is lost, never the message.
                    const token = if (c.queue.current_slot_token != 0)
                        c.queue.current_slot_token
                    else
                        c.server.mintHoldToken();
                    if (c.server.holdBehindOfflineTail(target_session, bound.local, bound.domain, from_jid, hold_id, timestamp, payload, token)) return;
                    // The stanza can neither be held nor sent without
                    // overtaking the draining tail. Tell the sender rather
                    // than dropping it (H2), as the c2s router does.
                    var recip_buf: [router.BARE_JID_MAX]u8 = undefined;
                    const recipient_bare = router.buildBareJid(bound.local, bound.domain, &recip_buf) catch "";
                    log.warn("cross-worker message to session {d} not held, bouncing to the sender", .{local_session_id});
                    if (recipient_bare.len > 0) {
                        c.server.bounceCrossWorkerUnavailable(from_jid, recipient_bare, parts.msg_id, "message", c.changes);
                    }
                    return;
                }
                if (target_session.sm_detached) {
                    // T153: no live connection to deliver to — track for resume
                    // replay instead of silently dropping the stanza.
                    target_session.smTrackOutbound(payload);
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
                var jid_buf: [router.FULL_JID_MAX]u8 = undefined;
                const real_jid = router.buildFullJid(ev.local, ev.domain, ev.resource, &jid_buf) catch {
                    noteDrop("session_closed for {s}@{s}: full JID exceeds {d} bytes; room cleanup skipped", .{ ev.local, ev.domain, router.FULL_JID_MAX });
                    return;
                };
                // local_only=true: this is already a broadcast from the originating
                // worker. Do NOT re-broadcast to avoid infinite cascade.
                muc_handler.handleSessionCloseLocal(self, real_jid, changes);
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
    try std.testing.expect(session.conn.write_end > session.conn.write_start);

    // Detach for SM resume: purge the fd, close it, keep the session.
    session.sm_resume_enabled = true;
    session.sm_detached = true;
    session.sm_detach_time = std.time.timestamp();
    session.sm_id_len = sm_state.SM_ID_HEX_LEN;
    const sm_id = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
    @memcpy(&session.sm_id, sm_id);
    server.detached_count = 1;
    c2s_sm.smIdMapInsert(&server,&session.sm_id, 1);
    session.conn.close();
    try std.testing.expectEqual(@as(posix.fd_t, -1), session.conn.fd);

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // The stale event kevent already returned this batch, for the fd that no
    // longer exists.
    c2s_session.handleWritable(&server,1, &changes);

    // The resumable session survives, and the skip was counted rather than
    // silently swallowed.
    try std.testing.expect(server.sessions[1] != null);
    try std.testing.expect(server.sessions[1].?.sm_detached);
    try std.testing.expectEqual(@as(u64, 1), server.stale_event_skips);
    try std.testing.expectEqual(@as(u16, 1), server.detached_count);

    // Same for a stale readable event and a stale error event.
    c2s_session.handleReadable(&server,1, &changes);
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
    c2s_sm.smIdMapInsert(&server,&session.sm_id, 1);
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
    try std.testing.expectEqual(@as(?usize, 1), c2s_sm.findDetachedSession(&server,&session.sm_id));
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
    c2s_session.handleWritable(&server,1, &changes);

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
    c2s_session.handleReadable(&server,1, &changes);
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

test "S35: the cross-worker hold stamps the producer receipt time" {
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
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();
    server.worker_id = 1;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 5, "localhost", false, allocator);
    session.stream.state = .features_bind;
    session.stream.authenticated = true;
    session.stream.authenticated_jid = xmpp.Jid{ .local = "bob", .domain = "localhost" };
    session.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "desktop" };
    session.offline_pending = true;
    server.sessions[5] = session;
    const gen = try sm.bind(1, 5, "bob", "localhost", "desktop");

    // The producer tags the slot with its own receipt time; the hold on the
    // consuming worker must store that time, not the time the drain ran.
    try delivery_sys.deliverDelivery(1, 5, gen, "<message from='alice@localhost' to='bob@localhost' id='cw1'><body>held</body></message>", 42, 12345, .stanza);
    server.drainDeliveryQueue(&changes);

    session_lifecycle.drainOfflinePending(&server, session, &changes);

    _ = try session.conn.flushSend();
    var buf: [2048]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    const wire = buf[0..n];
    // 12345 seconds past the epoch, not the consumer-side wall clock.
    try std.testing.expect(std.mem.indexOf(u8, wire, "stamp='1970-01-01T03:25:45Z'") != null);
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
        .{ "connection.zig", @embedFile("connection.zig"), 17 }, // Connection layer self-tests incl. the M1 counter test; no Session.
        .{ "fanout.zig", @embedFile("fanout.zig"), 1 }, // deliverToSession: tracked via smTrackOutbound.
        .{ "presence_handler.zig", @embedFile("presence_handler.zig"), 0 },
        .{ "router.zig", @embedFile("router.zig"), 2 }, // one comment; queueSendWithFlush is tracked.
        .{ "c2s/lifecycle.zig", @embedFile("c2s/lifecycle.zig"), 0 },
        .{ "server.zig", @embedFile("server.zig"), 5 }, // stream/SASL/SM nonzas + M1 counter self-test.
        .{ "c2s/session.zig", @embedFile("c2s/session.zig"), 13 }, // queueSendStanza itself + stream/SASL nonzas.
        .{ "c2s/sm.zig", @embedFile("c2s/sm.zig"), 9 }, // SM enable/resume/failed nonzas.
        .{ "iq_handler.zig", @embedFile("iq_handler.zig"), 0 },
        .{ "muc_handler.zig", @embedFile("muc_handler.zig"), 0 },
        .{ "message.zig", @embedFile("message.zig"), 0 },
        .{ "caps.zig", @embedFile("caps.zig"), 0 },
        // Remaining core files (S15): a raw send added here must be caught
        // like any other, not smuggled in outside the allowlist.
        .{ "archive_queue.zig", @embedFile("archive_queue.zig"), 0 },
        .{ "delivery_queue.zig", @embedFile("delivery_queue.zig"), 0 },
        .{ "event_loop.zig", @embedFile("event_loop.zig"), 0 },
        .{ "jid_bounds.zig", @embedFile("jid_bounds.zig"), 0 },
        .{ "listener.zig", @embedFile("listener.zig"), 0 },
        .{ "main.zig", @embedFile("main.zig"), 0 },
        .{ "metrics.zig", @embedFile("metrics.zig"), 0 },
        .{ "offline_store.zig", @embedFile("offline_store.zig"), 0 },
        .{ "room_mailbox.zig", @embedFile("room_mailbox.zig"), 0 },
        .{ "room_registry.zig", @embedFile("room_registry.zig"), 0 },
        .{ "roster_store.zig", @embedFile("roster_store.zig"), 0 },
        .{ "session_map.zig", @embedFile("session_map.zig"), 0 },
        .{ "c2s/sm_handoff.zig", @embedFile("c2s/sm_handoff.zig"), 0 },
        .{ "c2s/sm_state.zig", @embedFile("c2s/sm_state.zig"), 0 },
        .{ "subscription_cache.zig", @embedFile("subscription_cache.zig"), 0 },
        .{ "stanza/facts.zig", @embedFile("stanza/facts.zig"), 0 },
        .{ "stanza/writer.zig", @embedFile("stanza/writer.zig"), 0 },
    };
    if (cases.len != 29) {
        log.err("S15 ratchet: covers {d} core files, expected 29", .{cases.len});
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

test "Server: an over-long sender bare JID still delivers live" {
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
    server.sessions[5] = target;
    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    // The localpart parses, but local@domain overflows the 512-byte bare JID
    // that keys the archive and the offline store. Dispatch must still deliver
    // live rather than return, or the stanza reaches nobody silently.
    var long_local: [600]u8 = undefined;
    @memset(&long_local, 'l');

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = .{ .local = &long_local, .domain = "localhost", .resource = "mobile" };
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "m1";
    const body = "<body>long</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    _ = target.conn.flushSend() catch {};
    var buf: [2048]u8 = undefined;
    const n = posix.read(target_fds[1], &buf) catch 0;
    try std.testing.expect(n > 0);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "<body>long</body>") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "to='bob@localhost'") != null);

    // The sender got no error: the stanza was delivered.
    _ = alice.conn.flushSend() catch {};
    var abuf: [512]u8 = undefined;
    const an = posix.read(alice_fds[1], &abuf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), an);
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
    target.conn.write_end = connection_mod.WRITE_BUF_SIZE - 16;

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
    target.conn.write_start = 0;
    target.conn.write_end = connection_mod.WRITE_BUF_SIZE;
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

// Two draining resources on one worker ask to hold the same message. The
// store would collapse them, but the second ask must not happen at all: it
// would log a second hold and count a second dispatch.
test "Re-review 6.8: the router holds a bare-JID message once per worker" {
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

    for ([_]struct { id: u32, res: []const u8 }{ .{ .id = 5, .res = "desktop" }, .{ .id = 6, .res = "phone" } }) |r| {
        const fds = try makeSocketPair();
        defer posix.close(fds[1]);
        const sess = try allocator.create(Session);
        sess.* = Session.init(fds[0], r.id, "localhost", false, allocator);
        sess.offline_pending = true;
        server.sessions[r.id] = sess;
        _ = try sm.bind(0, r.id, "bob", "localhost", r.res);
        sm.setPresenceAvailable("bob", "localhost", r.res, true);
    }

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "r1b";
    const body = "<body>one hold</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    // One row, and exactly one store call: the second resource short-circuits
    // on the flag instead of asking the store to collapse it.
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    try std.testing.expectEqual(@as(u32, 1), offline_store.test_hold_calls);
}

// The S2S inbound loop keeps its own per-worker flag for the same reason: two
// draining resources of one bare JID ask once, not twice.
test "Re-review 6.8: the S2S hold asks the store once per worker" {
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

    for ([_]struct { id: u32, res: []const u8 }{ .{ .id = 5, .res = "desktop" }, .{ .id = 6, .res = "phone" } }) |r| {
        const fds = try makeSocketPair();
        defer posix.close(fds[1]);
        const sess = try allocator.create(Session);
        sess.* = Session.init(fds[0], r.id, "localhost", false, allocator);
        sess.offline_pending = true;
        server.sessions[r.id] = sess;
        _ = try sm.bind(0, r.id, "bob", "localhost", r.res);
        sm.setPresenceAvailable("bob", "localhost", r.res, true);
    }

    const stanza = "<message from='carol@example.com/res' to='bob@localhost' id='r1c' type='chat'><body>one hold</body></message>";
    var change_buf: [32]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = stanza,
    } }, &changes);

    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    try std.testing.expectEqual(@as(u32, 1), offline_store.test_hold_calls);
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

// A delivery form can exceed the scratch bank even when the stanza itself fits
// the parser's 16 KiB buffer: a bound JID full of characters that escape to
// five bytes adds more than the bank's headroom. Nothing can be delivered, so
// the sender has to hear it instead of the bytes vanishing.
test "Re-review 6.8: an undeliverable oversized delivery form bounces to the sender" {
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
    // The sender's full JID stays inside the 1 KiB form buffer but every byte
    // of it escapes to five, so the delivery head outgrows the headroom the
    // 20 KiB scratch bank leaves above a 16 KiB stanza.
    var local_buf: [500]u8 = undefined;
    @memset(&local_buf, '&');
    var res_buf: [400]u8 = undefined;
    @memset(&res_buf, '&');
    alice.stream.bound_jid = .{ .local = &local_buf, .domain = "localhost", .resource = &res_buf };
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "big";
    const body_len = 16384;
    @memset(alice.stanza_buf[0..body_len], 'x');
    alice.stanza_buf_len = body_len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    // Nothing was queued for the recipient: there is no delivery form at all.
    try std.testing.expectEqual(@as(usize, 0), bob.conn.pendingWriteBytes());

    // The sender is told instead.
    _ = alice.conn.flushSend() catch {};
    var wire: [4096]u8 = undefined;
    const n = posix.read(alice_fds[1], &wire) catch 0;
    try std.testing.expect(n > 0);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..n], "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..n], "id='big'") != null);
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

// H4: the G3 tests above start with an empty store, so none of them proves
// that a live message lands behind rows that were already queued. Each of
// these starts with a stored row and checks both the pointer order and the
// order the drain puts on the wire.
test "Server: H4 a cross-worker message lands behind an existing offline tail" {
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

    // The row bob never received, stored before anything live arrives.
    const tail = "<message from='alice@localhost/mobile' to='bob@localhost' id='tail-0' type='chat'><body>tail</body></message>";
    try std.testing.expect(try offline_store.storeHeldPointer("bob@localhost", "alice@localhost/mobile", "tail-0", 1000, tail));

    const target_fds = try makeSocketPair();
    defer posix.close(target_fds[1]);
    const target = try allocator.create(Session);
    target.* = Session.init(target_fds[0], 5, "localhost", false, allocator);
    target.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch null;
    target.offline_pending = true;
    server.sessions[5] = target;
    const gen = try sm.bind(0, 5, "bob", "localhost", "desktop");

    const live = "<message from='alice@localhost/mobile' to='bob@localhost' id='live-1' type='chat'><body>live</body></message>";
    try delivery_sys.deliver(0, 5, gen, live);

    var change_buf: [32]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.drainDeliveryQueue(&changes);

    // Both are in the store, and the live one is behind the tail.
    try std.testing.expectEqual(@as(usize, 2), try offline_store.countMessages("bob@localhost"));
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    try std.testing.expectEqual(@as(usize, 2), ptrs.len);
    try std.testing.expectEqualStrings("tail-0", ptrs[0].stanza_id);
    try std.testing.expectEqualStrings("live-1", ptrs[1].stanza_id);

    // The drain puts the tail on the wire first.
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
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));
    const tail_at = std.mem.indexOf(u8, wire.items, "<body>tail</body>");
    const live_at = std.mem.indexOf(u8, wire.items, "<body>live</body>");
    try std.testing.expect(tail_at != null);
    try std.testing.expect(live_at != null);
    try std.testing.expect(tail_at.? < live_at.?);
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
    const groupchat_frame = try ipc_protocol.parseFrame(frame_buf[0..groupchat_n]);
    try std.testing.expect(groupchat_frame != null);
    const groupchat_bounce = switch (try ipc_protocol.decode(groupchat_frame.?.payload)) {
        .s2s_deliver => |d| d,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(std.mem.indexOf(u8, groupchat_bounce.stanza_xml, "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, groupchat_bounce.stanza_xml, "id='gc1'") != null);
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
}

// H2: a message that cannot be held behind a draining offline tail has to
// bounce (and count) on every path, so the sender is never told nothing.
test "Server: H2 a cross-worker hold failure bounces to the sender on the same worker" {
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
    // No offline store at all: the hold cannot succeed.

    // alice (the sender) lives on this worker.
    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    const alice = try allocator.create(Session);
    alice.* = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    server.sessions[9] = alice;
    _ = try sm.bind(0, 9, "alice", "localhost", "mobile");
    const alice_bound = xmpp.Jid.parse("alice@localhost/mobile") catch unreachable;
    alice.stream.bound_jid = alice_bound;

    // bob (the recipient) lives here too, with a draining offline tail.
    const bob_fds = try makeSocketPair();
    defer posix.close(bob_fds[1]);
    const bob = try allocator.create(Session);
    bob.* = Session.init(bob_fds[0], 5, "localhost", false, allocator);
    bob.offline_pending = true;
    bob.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch unreachable;
    server.sessions[5] = bob;
    const bob_gen = try sm.bind(0, 5, "bob", "localhost", "desktop");

    const stanza = "<message from='alice@localhost/mobile' to='bob@localhost' id='h2-1' type='chat'><body>hi</body></message>";
    try delivery_sys.deliver(0, 5, bob_gen, stanza);

    const bounces_before = delivery_queue_mod.offline_hold_bounces.load(.monotonic);
    var change_buf: [32]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.drainDeliveryQueue(&changes);

    // alice is told the message was not accepted.
    const alice_n = try alice.conn.flushSend();
    try std.testing.expect(alice_n > 0);
    var buf: [4096]u8 = undefined;
    const n = posix.read(alice_fds[1], &buf) catch 0;
    const got = buf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, got, "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "id='h2-1'") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "from='bob@localhost'") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "to='alice@localhost/mobile'") != null);

    // bob's socket got nothing: the stanza never overtook his tail.
    _ = bob.conn.flushSend() catch {};
    var bbuf: [4096]u8 = undefined;
    const bn = posix.read(bob_fds[1], &bbuf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), bn);

    try std.testing.expectEqual(bounces_before + 1, delivery_queue_mod.offline_hold_bounces.load(.monotonic));
}

test "Server: H2 a cross-worker hold failure bounces across workers" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    // Worker 1 drains bob's queue; alice lives on worker 0.
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 1;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;

    const bob_fds = try makeSocketPair();
    defer posix.close(bob_fds[1]);
    const bob = try allocator.create(Session);
    bob.* = Session.init(bob_fds[0], 5, "localhost", false, allocator);
    bob.offline_pending = true;
    bob.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch unreachable;
    server.sessions[5] = bob;
    const bob_gen = try sm.bind(1, 5, "bob", "localhost", "desktop");

    _ = try sm.bind(0, 9, "alice", "localhost", "mobile");

    const stanza = "<message from='alice@localhost/mobile' to='bob@localhost' id='h2-2' type='chat'><body>hi</body></message>";
    try delivery_sys.deliver(1, 5, bob_gen, stanza);

    var change_buf: [32]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.drainDeliveryQueue(&changes);

    // bob got nothing.
    _ = bob.conn.flushSend() catch {};
    var bbuf: [4096]u8 = undefined;
    const bn = posix.read(bob_fds[1], &bbuf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), bn);

    // The bounce went back through worker 0's queue, generation-checked.
    const Seen = struct {
        count: usize = 0,
        session_id: u32 = 0,
        payload: []const u8 = "",

        fn handle(self: *@This(), id: u32, _: u32, payload: []const u8) void {
            self.count += 1;
            self.session_id = id;
            self.payload = payload;
        }
    };
    var seen = Seen{};
    _ = delivery_sys.getQueue(0).drain(&seen, Seen.handle);
    try std.testing.expectEqual(@as(usize, 1), seen.count);
    try std.testing.expectEqual(@as(u32, 9), seen.session_id);
    try std.testing.expect(std.mem.indexOf(u8, seen.payload, "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, seen.payload, "id='h2-2'") != null);
}
// H3: a detached session can still have an undrained offline tail. A live
// message must be parked behind that tail, not pushed into the SM replay
// queue, which would replay it ahead of the tail.
test "Server: H3 a cross-worker message to a detached session is held behind its tail" {
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

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const target = try allocator.create(Session);
    target.* = Session.init(fds[0], 5, "localhost", false, allocator);
    target.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch null;
    target.sm_detached = true;
    target.sm_resume_enabled = true;
    target.sm_detach_time = std.time.timestamp();
    target.sm_id_len = sm_state.SM_ID_HEX_LEN;
    const sm_id = "11112222333344445555666677778888";
    @memcpy(&target.sm_id, sm_id);
    target.offline_pending = true;
    const queue = try allocator.create(sm_state.SmUnackedQueue);
    queue.* = sm_state.SmUnackedQueue.init(allocator);
    queue.base_seq = 1;
    target.sm_unacked = queue;
    server.sessions[5] = target;
    server.detached_count = 1;
    c2s_sm.smIdMapInsert(&server,&target.sm_id, 5);
    const bob_gen = try sm.bind(0, 5, "bob", "localhost", "desktop");

    const payload = "<message from='alice@localhost/mobile' to='bob@localhost' id='h3-1' type='chat'><body>live</body></message>";
    try delivery_sys.deliver(0, 5, bob_gen, payload);

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.drainDeliveryQueue(&changes);

    // Nothing went into the replay queue: that would have replayed ahead of
    // the undrained tail.
    try std.testing.expectEqual(@as(u32, 0), queue.count);
    // Parked in the offline store instead.
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    const held = try offline_store.getHeldStanza(ptrs[0]);
    try std.testing.expect(held != null);
    if (held) |h| {
        defer allocator.free(h);
        try std.testing.expect(std.mem.indexOf(u8, h, "<body>live</body>") != null);
    }
    // The flag survives: the tail is still outstanding.
    try std.testing.expect(target.offline_pending);
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

    c2s_sm.handleSmResumeReply(&server,.{
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

    c2s_sm.handleSmResumeReply(&server,.{
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
    c2s_sm.smIdMapInsert(&server,&previd, 2);
    server.detached_count = 1;

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, allocator);
    server.sessions[1] = session;

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    c2s_session.handleReadable(&server,1, &changes);
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
    c2s_session.handleReadable(&server,1, &changes);

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
    c2s_sm.smIdMapInsert(&server,&previd, 2);
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
    c2s_session.handleReadable(&server,1, &changes);
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
    c2s_session.handleReadable(&server,1, &changes);

    try std.testing.expect(!session.offline_pending);
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("alice@localhost"));
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "<resumed") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "tail-2") != null);
}

test "Server: H2 an unstorable S2S hold behind a draining tail bounces" {
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

    // bob is online but his offline tail is still draining, and his queue is
    // at quota so the hold cannot succeed.
    const bob_fds = try makeSocketPair();
    defer posix.close(bob_fds[1]);
    const bob = try allocator.create(Session);
    bob.* = Session.init(bob_fds[0], 5, "localhost", false, allocator);
    bob.offline_pending = true;
    server.sessions[5] = bob;
    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var id_buf: [16]u8 = undefined;
        const sid = std.fmt.bufPrint(&id_buf, "q{d}", .{i}) catch unreachable;
        const stored = try offline_store.storePointer("bob@localhost", "carol@example.com", sid, 100 + @as(u64, @intCast(i)));
        try std.testing.expect(stored);
    }

    const stanza = "<message from='carol@example.com/res' to='bob@localhost' id='h2-3' type='chat'><body>federated</body></message>";
    const bounces_before = delivery_queue_mod.s2s_bounces.load(.monotonic);
    var change_buf: [32]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = stanza,
    } }, &changes);

    // The remote sender learns the stanza was refused.
    _ = server.s2s_ipc.flush() catch {};
    var frame_buf: [4096]u8 = undefined;
    const got = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expect(got > 0);
    const frame = try ipc_protocol.parseFrame(frame_buf[0..got]);
    try std.testing.expect(frame != null);
    const bounced = switch (try ipc_protocol.decode(frame.?.payload)) {
        .s2s_deliver => |d| d,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("carol@example.com/res", bounced.to_jid);
    try std.testing.expect(std.mem.indexOf(u8, bounced.stanza_xml, "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, bounced.stanza_xml, "id='h2-3'") != null);
    try std.testing.expectEqual(bounces_before + 1, delivery_queue_mod.s2s_bounces.load(.monotonic));

    // Nothing was stored on top of the full queue, and bob's socket stayed
    // empty: the stanza did not overtake his tail.
    try std.testing.expectEqual(@as(usize, 100), try offline_store.countMessages("bob@localhost"));
    _ = bob.conn.flushSend() catch {};
    var bbuf: [4096]u8 = undefined;
    const bn = posix.read(bob_fds[1], &bbuf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), bn);
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
    const frame = try ipc_protocol.parseFrame(frame_buf[0..got]);
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
    const frame = try ipc_protocol.parseFrame(frame_buf[0..got]);
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
    const iq_frame = try ipc_protocol.parseFrame(frame_buf[0..iq_n]);
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
    try stanza_writer.writeS2sBounce(fbs.writer(), "b&b@localhost", "carol@example.com/res", "a&amp;b");
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
    try stanza_writer.writeS2sBounce(fbs.writer(), "bob@localhost", "carol@example.com", "x'y");
    const out = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, out, "id='x&apos;y'") != null);
}

// G7: an inbound id carrying an XML entity is escaped exactly once through the
// real parse and bounce path.
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
    const frame = try ipc_protocol.parseFrame(frame_buf[0..got]);
    try std.testing.expect(frame != null);
    const bounced = switch (try ipc_protocol.decode(frame.?.payload)) {
        .s2s_deliver => |d| d,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(std.mem.indexOf(u8, bounced.stanza_xml, "id='a&amp;b'") != null);
    try std.testing.expect(std.mem.indexOf(u8, bounced.stanza_xml, "a&amp;amp;") == null);
}

// G7: a storage error, not only a full queue, bounces the inbound stanza. An
// over-long recipient makes the offline hold fail with KeyTooLong.
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
    const frame = try ipc_protocol.parseFrame(frame_buf[0..got]);
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
        c2s_session.handleWritable(&server,1, &changes);
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

// The owning worker's snapshot decides what the resumed session believes it
// has already drained. A bundle built without the drain sequence makes the
// requesting worker resend a tail the resumed client already has.
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
        .{ "iq_handler.zig", @embedFile("iq_handler.zig") },
        .{ "router.zig", @embedFile("router.zig") },
        .{ "c2s/lifecycle.zig", @embedFile("c2s/lifecycle.zig") },
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
        .{ "c2s/lifecycle.zig", @embedFile("c2s/lifecycle.zig"), @as(usize, 0), @as(usize, 0) },
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
    // checks above: binding the method to a local and calling that through the
    // alias never spells the call form. Count the bare name instead. Split the
    // needle so this test does not count itself.
    const any_timer_needle = "add" ++ "Timer";
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

    c2s_session.continueTlsHandshake(&server,1, session, &changes);
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
    try std.testing.expect(std.mem.indexOf(u8, @embedFile("server.zig"), hook_name) == null);
    try std.testing.expect(std.mem.indexOf(u8, @embedFile("c2s/lifecycle.zig"), hook_name) == null);
}

// Force analysis of sibling files whose tests otherwise never run.
test {
    _ = iq_handler;
    _ = router;
    _ = muc_handler;
    _ = presence_handler;
    _ = session_lifecycle;
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

// N1: the offline tail is per bare JID, but the hold decision is per session,
// so every draining resource asks to hold the same message. The store keeps one
// row per dispatch, and that row reaches whichever resource drains first. The
// other resource finds the tail empty and gets nothing: the tail is shared, not
// per resource.
test "N1: two draining resources hold a bare-JID message once" {
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

    const desktop_fds = try makeSocketPair();
    defer posix.close(desktop_fds[1]);
    const desktop = try allocator.create(Session);
    desktop.* = Session.init(desktop_fds[0], 5, "localhost", false, allocator);
    desktop.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch unreachable;
    desktop.offline_pending = true;
    server.sessions[5] = desktop;
    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.* = Session.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.bound_jid = xmpp.Jid.parse("bob@localhost/phone") catch unreachable;
    phone.offline_pending = true;
    server.sessions[6] = phone;
    _ = try sm.bind(0, 6, "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch unreachable;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "n1-1";
    const body = "<body>held once</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    // One message, one row, however many resources are draining it.
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));

    // The tail is per bare JID, so exactly one resource receives the message:
    // the first to drain. The second finds the tail empty and sends nothing.
    var delivered_copies: usize = 0;
    for ([_]*Session{ desktop, phone }) |session| {
        session_lifecycle.deliverOfflineMessages(&server, session, "bob", "localhost", &changes);
        _ = session.conn.flushSend() catch {};
        var wire: [8192]u8 = undefined;
        const fd = if (session == desktop) desktop_fds[1] else phone_fds[1];
        const got = posix.read(fd, &wire) catch 0;
        delivered_copies += std.mem.count(u8, wire[0..got], "<body>held once</body>");
    }
    try std.testing.expectEqual(@as(usize, 1), delivered_copies);
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));
}

// N1: the same collapse has to hold across workers. The tail is one bare JID
// row, so a resource of bob on each worker both ask to hold the same message
// and the store must write it once, whichever worker wins the race.
// Two identical messages must stay two rows. A message with no server
// stanza-id (type='normal', no id) serializes identically on both dispatches,
// so only the token minted per dispatch can tell them apart.
test "N1: two identical stanza-less messages to a draining bare JID are two rows" {
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

    const desktop_fds = try makeSocketPair();
    defer posix.close(desktop_fds[1]);
    const desktop = try allocator.create(Session);
    desktop.* = Session.init(desktop_fds[0], 5, "localhost", false, allocator);
    desktop.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch null;
    desktop.offline_pending = true;
    server.sessions[5] = desktop;
    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch unreachable;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "normal";
    const body = "<body>otr</body>";

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // Two dispatches, byte-identical: type='normal' gets no stanza-id and the
    // client sent no id.
    var round: usize = 0;
    while (round < 2) : (round += 1) {
        // dispatchStanza consumes the parsed stanza, so each round rebuilds the
        // identical one from scratch.
        alice.stanza_kind = .message;
        alice.stanza_to = "bob@localhost";
        alice.stanza_type = "normal";
        alice.stanza_id = "";
        @memcpy(alice.stanza_buf[0..body.len], body);
        alice.stanza_buf_len = body.len;
        router.dispatchStanza(&server, &alice, &changes);
    }

    const got_rows = try offline_store.countMessages("bob@localhost");
    try std.testing.expectEqual(@as(usize, 2), got_rows);
}

// Cross-worker dedupe relies on the local and the cross-worker forms being
// byte-identical: the token identifies the dispatch, so a difference in the
// serialized bytes would make one message look like two or make the two
// holders disagree about what is on the wire.
test "Router: the local and cross-worker delivery forms are byte-identical" {
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

    // bob has one resource here and one on worker 1, so this dispatch takes
    // both the local send and the cross-worker enqueue.
    const local_fds = try makeSocketPair();
    defer posix.close(local_fds[1]);
    const local = try allocator.create(Session);
    local.* = Session.init(local_fds[0], 5, "localhost", false, allocator);
    local.stream.state = .active;
    local.stream.authenticated = true;
    local.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desk") catch null;
    server.sessions[5] = local;
    _ = try sm.bind(0, 5, "bob", "localhost", "desk");
    sm.setPresenceAvailable("bob", "localhost", "desk", true);

    const remote_fds = try makeSocketPair();
    defer posix.close(remote_fds[1]);
    const remote = try allocator.create(Session);
    remote.* = Session.init(remote_fds[0], 6, "localhost", false, allocator);
    remote.stream.state = .active;
    remote.stream.authenticated = true;
    remote.stream.bound_jid = xmpp.Jid.parse("bob@localhost/phone") catch null;
    server.sessions[6] = remote;
    _ = try sm.bind(1, 6, "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    // A JID that needs escaping, so the two forms would differ if either
    // serializer handled it differently.
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "normal";
    alice.stanza_id = "a&b<c>";
    const body = "<body>same bytes</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    _ = local.conn.flushSend() catch {};
    var wire: [8192]u8 = undefined;
    const wire_len = posix.read(local_fds[1], &wire) catch 0;
    try std.testing.expect(wire_len > 0);

    var captured = struct {
        buf: [8192]u8 = undefined,
        len: usize = 0,
        fn onDelivery(self: *@This(), _: u32, _: u32, payload: []const u8) void {
            @memcpy(self.buf[0..payload.len], payload);
            self.len = payload.len;
        }
    }{};
    const queue = delivery_sys.getQueue(1);
    _ = queue.drain(&captured, @TypeOf(captured).onDelivery);
    try std.testing.expect(captured.len > 0);

    try std.testing.expectEqualStrings(wire[0..wire_len], captured.buf[0..captured.len]);
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

// The same dispatch identity must survive the c2s router's hop through the
// delivery slot: the receiving worker reads the token off the slot instead of
// minting its own.
test "c2s: one routed message to two draining workers holds one row" {
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
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var w1 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w1.deinit();
    w1.worker_id = 1;
    w1.session_map = &sm;
    w1.delivery_system = &delivery_sys;
    w1.offline = &offline_store;

    const desk_fds = try makeSocketPair();
    defer posix.close(desk_fds[1]);
    const desk = try allocator.create(Session);
    desk.* = Session.init(desk_fds[0], 5, "localhost", false, allocator);
    desk.offline_pending = true;
    desk.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "desktop" };
    w1.sessions[5] = desk;
    _ = try sm.bind(1, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    var w0 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;
    w0.offline = &offline_store;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.* = Session.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.offline_pending = true;
    phone.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "phone" };
    w0.sessions[6] = phone;
    _ = try sm.bind(0, 6, "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "c2s-one";
    const body = "<body>one row</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var w1_changes_buf: [64]posix.Kevent = undefined;
    var w1_changes = ChangeList.init(&w1_changes_buf);
    router.dispatchStanza(&w1, &alice, &w1_changes);

    var w0_changes_buf: [32]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    w0.drainDeliveryQueue(&w0_changes);

    // Count the routed message only. T-D689B13D: a <received> carbon to a
    // resource that got the original is never produced, and a carbon is
    // never held behind an offline tail, so no second row can appear.
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    var message_rows: usize = 0;
    for (ptrs) |ptr| {
        const held = try offline_store.getHeldStanza(ptr) orelse continue;
        defer allocator.free(held);
        if (std.mem.indexOf(u8, held, "urn:xmpp:carbons:2") != null) continue;
        if (std.mem.indexOf(u8, held, "from='alice@localhost/mobile' to='bob@localhost'") != null) message_rows += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), message_rows);
}

// An S2S dispatch that reaches one resource locally and another on a second
// worker must hold one row. The remote worker learns the dispatch identity
// from the delivery slot; a fresh token there would store the stanza twice.
test "S2S: one inbound stanza to two draining workers holds one row" {
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
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    // Worker 1 receives the stanza and owns the first resource of the bare JID.
    var w1 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w1.deinit();
    w1.worker_id = 1;
    w1.session_map = &sm;
    w1.delivery_system = &delivery_sys;
    w1.offline = &offline_store;

    const desk_fds = try makeSocketPair();
    defer posix.close(desk_fds[1]);
    const desk = try allocator.create(Session);
    desk.* = Session.init(desk_fds[0], 5, "localhost", false, allocator);
    desk.offline_pending = true;
    desk.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "desktop" };
    w1.sessions[5] = desk;
    _ = try sm.bind(1, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    // Worker 0 owns the second resource, so the second target is remote.
    var w0 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;
    w0.offline = &offline_store;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.* = Session.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.offline_pending = true;
    phone.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "phone" };
    w0.sessions[6] = phone;
    _ = try sm.bind(0, 6, "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const stanza = "<message from='carol@example.com/res' to='bob@localhost' id='h1' type='chat'><body>cross</body></message>";
    var w1_changes_buf: [32]posix.Kevent = undefined;
    var w1_changes = ChangeList.init(&w1_changes_buf);
    w1.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = stanza,
    } }, &w1_changes);

    var w0_changes_buf: [32]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    w0.drainDeliveryQueue(&w0_changes);

    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
}

// A bare-JID dispatch routes the message to bob's phone on the other worker
// and queues a <received> carbon for it in the same drain. The phone never
// enabled carbons, so the consumer drops the copy and the wire carries only
// the routed stanza (XEP-0280 section 2).
test "carbons: a phone with carbons off on another worker gets only the routed message" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var w0 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;

    var w1 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w1.deinit();
    w1.worker_id = 1;
    w1.session_map = &sm;
    w1.delivery_system = &delivery_sys;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.* = Session.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.state = .active;
    phone.stream.authenticated = true;
    phone.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "phone" };
    w1.sessions[6] = phone;
    _ = try sm.bind(1, 6, "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-off";
    const body = "<body>once</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var w0_changes_buf: [64]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    router.dispatchStanza(&w0, &alice, &w0_changes);

    var w1_changes_buf: [32]posix.Kevent = undefined;
    var w1_changes = ChangeList.init(&w1_changes_buf);
    w1.drainDeliveryQueue(&w1_changes);

    _ = phone.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const wire_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expect(wire_len > 0);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, wire[0..wire_len], "<message"));
    try std.testing.expect(std.mem.indexOf(u8, wire[0..wire_len], "urn:xmpp:carbons:2") == null);
}

// The message went to bob's desktop full JID, so the phone on the other
// worker did not receive it under RFC 6121 rules: its <received> carbon is
// the only stanza the cross-worker path owes it. A carbon is an outer
// <message> wrapping a <forwarded> inner one, so the wire carries exactly
// two <message opens for the single copy.
test "carbons: a Carbons-enabled resource on another worker gets exactly one carbon" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var w0 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;

    const desk_fds = try makeSocketPair();
    defer posix.close(desk_fds[1]);
    const desk = try allocator.create(Session);
    desk.* = Session.init(desk_fds[0], 5, "localhost", false, allocator);
    desk.stream.state = .active;
    desk.stream.authenticated = true;
    desk.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "desktop" };
    w0.sessions[5] = desk;
    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    var w1 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w1.deinit();
    w1.worker_id = 1;
    w1.session_map = &sm;
    w1.delivery_system = &delivery_sys;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.* = Session.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.state = .active;
    phone.stream.authenticated = true;
    phone.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "phone" };
    phone.carbons_enabled = true;
    w1.sessions[6] = phone;
    _ = try sm.bind(1, 6, "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost/desktop";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-on";
    const body = "<body>copy me</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var w0_changes_buf: [64]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    router.dispatchStanza(&w0, &alice, &w0_changes);

    var w1_changes_buf: [32]posix.Kevent = undefined;
    var w1_changes = ChangeList.init(&w1_changes_buf);
    w1.drainDeliveryQueue(&w1_changes);

    _ = phone.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const wire_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expect(wire_len > 0);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, wire[0..wire_len], "<received xmlns='urn:xmpp:carbons:2'"));
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, wire[0..wire_len], "<message"));
    try std.testing.expect(std.mem.indexOf(u8, wire[0..wire_len], "copy me") != null);
}

// The same dispatch, but the phone never enabled carbons: it was not a
// delivery target, so the producer queued a carbon for it, and the
// receiving worker applies carbons_enabled and drops it on the floor.
test "carbons: a cross-worker carbon to a disabled resource is dropped" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var w0 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;

    const desk_fds = try makeSocketPair();
    defer posix.close(desk_fds[1]);
    const desk = try allocator.create(Session);
    desk.* = Session.init(desk_fds[0], 5, "localhost", false, allocator);
    desk.stream.state = .active;
    desk.stream.authenticated = true;
    desk.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "desktop" };
    w0.sessions[5] = desk;
    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    var w1 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w1.deinit();
    w1.worker_id = 1;
    w1.session_map = &sm;
    w1.delivery_system = &delivery_sys;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.* = Session.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.state = .active;
    phone.stream.authenticated = true;
    phone.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "phone" };
    phone.carbons_enabled = false;
    w1.sessions[6] = phone;
    _ = try sm.bind(1, 6, "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost/desktop";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-drop";
    const body = "<body>not for you</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var w0_changes_buf: [64]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    router.dispatchStanza(&w0, &alice, &w0_changes);

    var w1_changes_buf: [32]posix.Kevent = undefined;
    var w1_changes = ChangeList.init(&w1_changes_buf);
    w1.drainDeliveryQueue(&w1_changes);

    _ = phone.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const wire_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expectEqual(@as(usize, 0), wire_len);
}

// A carbon is delivered live or not at all: while the phone drains its
// offline tail, the original (held for the desktop's tail) is the only row
// the store ever sees. The carbon itself reaches the phone's wire; it is
// never held behind the tail and never bounced.
test "carbons: a draining worker delivers the carbon live and stores no carbon row" {
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
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var w0 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;
    w0.offline = &offline_store;

    const desk_fds = try makeSocketPair();
    defer posix.close(desk_fds[1]);
    const desk = try allocator.create(Session);
    desk.* = Session.init(desk_fds[0], 5, "localhost", false, allocator);
    desk.offline_pending = true;
    desk.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "desktop" };
    w0.sessions[5] = desk;
    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    var w1 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w1.deinit();
    w1.worker_id = 1;
    w1.session_map = &sm;
    w1.delivery_system = &delivery_sys;
    w1.offline = &offline_store;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.* = Session.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.offline_pending = true;
    phone.carbons_enabled = true;
    phone.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "phone" };
    w1.sessions[6] = phone;
    _ = try sm.bind(1, 6, "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost/desktop";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-drain";
    const body = "<body>held for desk</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var w0_changes_buf: [64]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    router.dispatchStanza(&w0, &alice, &w0_changes);

    var w1_changes_buf: [32]posix.Kevent = undefined;
    var w1_changes = ChangeList.init(&w1_changes_buf);
    w1.drainDeliveryQueue(&w1_changes);

    // The carbon went out live; the draining tail never owned it.
    _ = phone.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const wire_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expect(wire_len > 0);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..wire_len], "urn:xmpp:carbons:2") != null);

    // Only the routed message is held, for the desktop's tail. No row
    // anywhere carries the carbon namespace.
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    var carbon_rows: usize = 0;
    for (ptrs) |ptr| {
        const held = try offline_store.getHeldStanza(ptr) orelse continue;
        defer allocator.free(held);
        if (std.mem.indexOf(u8, held, "urn:xmpp:carbons:2") != null) carbon_rows += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    try std.testing.expectEqual(@as(usize, 0), carbon_rows);
}

// The bare-JID message already reached the phone under RFC 6121 delivery
// rules, so a <received> carbon would hand it the same stanza twice. The
// producer skips delivered resources before the worker split, so the rule
// holds wherever the resource lives (XEP-0280 section 7).
test "carbons: a delivered resource gets no received copy on the same dispatch" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var w0 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;

    var w1 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w1.deinit();
    w1.worker_id = 1;
    w1.session_map = &sm;
    w1.delivery_system = &delivery_sys;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.* = Session.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.state = .active;
    phone.stream.authenticated = true;
    phone.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "phone" };
    phone.carbons_enabled = true;
    w1.sessions[6] = phone;
    _ = try sm.bind(1, 6, "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-dupe";
    const body = "<body>no dupe</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var w0_changes_buf: [64]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    router.dispatchStanza(&w0, &alice, &w0_changes);

    var w1_changes_buf: [32]posix.Kevent = undefined;
    var w1_changes = ChangeList.init(&w1_changes_buf);
    w1.drainDeliveryQueue(&w1_changes);

    _ = phone.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const wire_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expect(wire_len > 0);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, wire[0..wire_len], "<message"));
    try std.testing.expect(std.mem.indexOf(u8, wire[0..wire_len], "urn:xmpp:carbons:2") == null);
}

// Same rule on the local branch: a phone with carbons on the sending
// worker also already received the bare-JID original.
test "carbons: the local received-carbon path skips a resource that got the original" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var w0 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.* = Session.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.state = .active;
    phone.stream.authenticated = true;
    phone.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "phone" };
    phone.carbons_enabled = true;
    w0.sessions[6] = phone;
    _ = try sm.bind(0, 6, "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-dupe-local";
    const body = "<body>no dupe</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var w0_changes_buf: [64]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    router.dispatchStanza(&w0, &alice, &w0_changes);

    _ = phone.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const wire_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expect(wire_len > 0);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, wire[0..wire_len], "<message"));
    try std.testing.expect(std.mem.indexOf(u8, wire[0..wire_len], "urn:xmpp:carbons:2") == null);
}

// The delivered set is what the delivery loop actually handed the stanza
// to, not a recompute of the routing rule. A CSI-inactive phone is skipped
// for a typing-only message, so it never saw the original: a <received>
// carbon to it is the only copy it gets, on the bare-JID fan-out and on a
// full-JID dispatch alike.
test "carbons: a resource the delivery loop skipped still gets the received carbon" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();

    var w0 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.* = Session.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.state = .active;
    phone.stream.authenticated = true;
    phone.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "phone" };
    phone.carbons_enabled = true;
    phone.csi_active = false;
    w0.sessions[6] = phone;
    _ = try sm.bind(0, 6, "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const laptop_fds = try makeSocketPair();
    defer posix.close(laptop_fds[1]);
    const laptop = try allocator.create(Session);
    laptop.* = Session.init(laptop_fds[0], 5, "localhost", false, allocator);
    laptop.stream.state = .active;
    laptop.stream.authenticated = true;
    laptop.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "laptop" };
    laptop.carbons_enabled = true;
    w0.sessions[5] = laptop;
    _ = try sm.bind(0, 5, "bob", "localhost", "laptop");
    sm.setPresenceAvailable("bob", "localhost", "laptop", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-csi";
    const body = "<composing xmlns='http://jabber.org/protocol/chatstates'/>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var changes_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&changes_buf);
    router.dispatchStanza(&w0, &alice, &changes);

    // Bare JID: the laptop got the original and no carbon; the phone was
    // skipped in delivery so the carbon is its only copy.
    _ = laptop.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const laptop_len = posix.read(laptop_fds[1], &wire) catch 0;
    try std.testing.expect(laptop_len > 0);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, wire[0..laptop_len], "<message"));
    try std.testing.expect(std.mem.indexOf(u8, wire[0..laptop_len], "urn:xmpp:carbons:2") == null);

    _ = phone.conn.flushSend() catch 0;
    const phone_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expect(phone_len > 0);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..phone_len], "<received xmlns='urn:xmpp:carbons:2'>") != null);

    // Full JID to the same skipped phone: the routed set is not the
    // delivered set here either, so the phone again gets the carbon.
    // dispatchStanza resets the stanza fields, so rebuild them all.
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost/phone";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-csi-full";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;
    router.dispatchStanza(&w0, &alice, &changes);

    _ = phone.conn.flushSend() catch 0;
    const full_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expect(full_len > 0);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..full_len], "<received xmlns='urn:xmpp:carbons:2'>") != null);
}

// The private hint only counts as a top-level child of the stanza. The
// same strings nested inside a <forwarded/> payload are content, not a
// hint, so the carbon still flows to a resource that never saw the
// original.
test "carbons: a nested private-looking payload does not suppress the carbon" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();

    var w0 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.* = Session.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.state = .active;
    phone.stream.authenticated = true;
    phone.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "phone" };
    phone.carbons_enabled = true;
    w0.sessions[6] = phone;
    _ = try sm.bind(0, 6, "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const watch_fds = try makeSocketPair();
    defer posix.close(watch_fds[1]);
    const watch = try allocator.create(Session);
    watch.* = Session.init(watch_fds[0], 5, "localhost", false, allocator);
    watch.stream.state = .active;
    watch.stream.authenticated = true;
    watch.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "watch" };
    watch.carbons_enabled = true;
    w0.sessions[5] = watch;
    _ = try sm.bind(0, 5, "bob", "localhost", "watch");
    sm.setPresenceAvailable("bob", "localhost", "watch", true);
    sm.setPriority("bob", "localhost", "watch", -1);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-nested";
    const body = "<body>see this</body><forwarded xmlns='urn:xmpp:forward:0'><message from='mallory@x/a' to='bob@localhost/phone'><private xmlns='urn:xmpp:carbons:2'/></message></forwarded>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var changes_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&changes_buf);
    router.dispatchStanza(&w0, &alice, &changes);

    _ = watch.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const watch_len = posix.read(watch_fds[1], &wire) catch 0;
    try std.testing.expect(watch_len > 0);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..watch_len], "<received xmlns='urn:xmpp:carbons:2'>") != null);
}

// A <private/> child asks the server not to carbon copy the message at all
// (XEP-0280 section 6), and a <no-copy/> hint does the same (XEP-0334).
// Both suppress the copy on the cross-worker path, so the phone's wire
// stays empty.
test "carbons: private and no-copy hints suppress the cross-worker carbon" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var w0 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;

    const desk_fds = try makeSocketPair();
    defer posix.close(desk_fds[1]);
    const desk = try allocator.create(Session);
    desk.* = Session.init(desk_fds[0], 5, "localhost", false, allocator);
    desk.stream.state = .active;
    desk.stream.authenticated = true;
    desk.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "desktop" };
    w0.sessions[5] = desk;
    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    var w1 = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w1.deinit();
    w1.worker_id = 1;
    w1.session_map = &sm;
    w1.delivery_system = &delivery_sys;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.* = Session.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.state = .active;
    phone.stream.authenticated = true;
    phone.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "phone" };
    phone.carbons_enabled = true;
    w1.sessions[6] = phone;
    _ = try sm.bind(1, 6, "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice = Session.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_type = "chat";

    const inners = [_][]const u8{
        "<body>shh</body><private xmlns='urn:xmpp:carbons:2'/>",
        "<body>shh</body><no-copy xmlns='urn:xmpp:hints'/>",
    };
    var w0_changes_buf: [64]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    var w1_changes_buf: [32]posix.Kevent = undefined;
    var w1_changes = ChangeList.init(&w1_changes_buf);

    for (inners, 0..) |inner, round| {
        alice.stanza_to = "bob@localhost/desktop";
        alice.stanza_id = if (round == 0) "carb-priv" else "carb-nocopy";
        @memcpy(alice.stanza_buf[0..inner.len], inner);
        alice.stanza_buf_len = inner.len;
        router.dispatchStanza(&w0, &alice, &w0_changes);
        w1.drainDeliveryQueue(&w1_changes);
    }

    _ = phone.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const wire_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expectEqual(@as(usize, 0), wire_len);
}

test "N1: two workers draining one bare JID hold a message once" {
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
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;

    // One draining resource of bob per worker, same bare JID.
    server.worker_id = 0;
    const desk_fds = try makeSocketPair();
    defer posix.close(desk_fds[1]);
    const desk = try allocator.create(Session);
    desk.* = Session.init(desk_fds[0], 5, "localhost", false, allocator);
    desk.offline_pending = true;
    server.sessions[5] = desk;
    _ = try sm.bind(0, 5, "bob", "localhost", "desktop");

    server.worker_id = 1;
    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.* = Session.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.offline_pending = true;
    server.sessions[6] = phone;
    _ = try sm.bind(1, 6, "bob", "localhost", "phone");

    const stanza = "<message from='alice@localhost/mobile' to='bob@localhost' type='chat' id='n1-2'><body>cross</body></message>";
    const ts: u64 = 1700000000;

    // Both workers hold the same dispatch under the one token the producer
    // minted, so the store writes one row whichever worker wins.
    const token = server.mintHoldToken();
    try std.testing.expect(server.holdBehindOfflineTail(desk, "bob", "localhost", "alice@localhost/mobile", "n1-2", ts, stanza, token));
    try std.testing.expect(server.holdBehindOfflineTail(phone, "bob", "localhost", "alice@localhost/mobile", "n1-2", ts, stanza, token));

    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
}

// ============================================================================
// Pubsub feature dispatch coverage (forge #22, S33)
// ============================================================================

/// Build the xml.Element the reader would produce for a start tag.
fn testElem(local_name: []const u8, ns: []const u8, attrs: []const xml.Attribute) xml.Element {
    return .{
        .name = local_name,
        .prefix = "",
        .local_name = local_name,
        .namespace_uri = ns,
        .attributes = attrs,
        .self_closing = false,
    };
}

fn testAttr(local_name: []const u8, value: []const u8) xml.Attribute {
    return .{ .name = local_name, .value = value, .prefix = "", .local_name = local_name };
}

/// Drive one IQ through the real dispatch path: handleIq for the stanza,
/// handleIqChild for each child element, then dispatchIq. When `item_payload`
/// is set it is appended to pep_payload after the <item> child, the way the
/// server's collection path fills it. Returns the bytes written to the peer.
fn driveTestIq(
    server: *Server,
    session: *Session,
    changes: *ChangeList,
    peer_fd: posix.fd_t,
    iq_type: []const u8,
    id: []const u8,
    children: []const xml.Element,
    item_payload: ?[]const u8,
    out: []u8,
) ![]const u8 {
    const iq_attrs = [_]xml.Attribute{
        testAttr("type", iq_type),
        testAttr("id", id),
    };
    iq_handler.handleIq(session, testElem("iq", xml.ns.client, &iq_attrs), server.server_host);
    for (children) |elem| {
        iq_handler.handleIqChild(session, elem);
        if (item_payload) |payload| {
            if (std.mem.eql(u8, elem.local_name, "item") and
                std.mem.eql(u8, elem.namespace_uri, xml.ns.pubsub))
            {
                try session.pep_payload.appendSlice(session.reader.allocator, payload);
            }
        }
    }
    iq_handler.dispatchIq(server, session, changes);
    _ = session.conn.flushSend() catch {};
    const n = posix.read(peer_fd, out) catch 0;
    return out[0..n];
}

/// The pubsub element a probe drives for each advertised pubsub#* feature.
/// publish exercises handlePepPublish, whose store upsert covers auto-create
/// and whose roster fan-out is the auto-subscribe model; items exercises
/// handlePepItems, whose returned copy also proves persistent-items.
const PubsubProbe = struct {
    feature: []const u8,
    verb: []const u8,
};

const PUBSUB_PROBES = [_]PubsubProbe{
    .{ .feature = "http://jabber.org/protocol/pubsub#publish", .verb = "publish" },
    .{ .feature = "http://jabber.org/protocol/pubsub#auto-create", .verb = "publish" },
    .{ .feature = "http://jabber.org/protocol/pubsub#auto-subscribe", .verb = "publish" },
    .{ .feature = "http://jabber.org/protocol/pubsub#persistent-items", .verb = "items" },
    .{ .feature = "http://jabber.org/protocol/pubsub#retrieve-items", .verb = "items" },
};

test "Server: every advertised pubsub feature is dispatched" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var pep_store = GenericPepStore.init(&op_db);

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 8);
    defer server.deinit();
    server.pep_store = &pep_store;

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    var session = Session.init(fds[0], 1, "localhost", false, allocator);
    defer session.deinit();
    session.stream.bound_jid = xmpp.Jid.parse("alice@localhost/res") catch null;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    var wire: [8192]u8 = undefined;

    // disco#info get: collect the pubsub#* features the server advertises.
    var feat_buf: [16][128]u8 = undefined;
    var feats: [16][]const u8 = undefined;
    var feat_count: usize = 0;
    {
        const children = [_]xml.Element{testElem("query", xml.ns.disco_info, &.{})};
        const resp = try driveTestIq(&server, &session, &changes, fds[1], "get", "disco-1", &children, null, &wire);
        try std.testing.expect(std.mem.indexOf(u8, resp, "type='result'") != null);
        try std.testing.expect(std.mem.indexOf(u8, resp, "<identity category='pubsub' type='pep'/>") != null);
        var rest = resp;
        while (std.mem.indexOf(u8, rest, "<feature var='")) |i| {
            const start = i + "<feature var='".len;
            const end = std.mem.indexOfScalarPos(u8, rest, start, '\'') orelse break;
            const f = rest[start..end];
            if (std.mem.startsWith(u8, f, "http://jabber.org/protocol/pubsub#")) {
                @memcpy(feat_buf[feat_count][0..f.len], f);
                feats[feat_count] = feat_buf[feat_count][0..f.len];
                feat_count += 1;
            }
            rest = rest[end..];
        }
    }
    try std.testing.expect(feat_count > 0);

    // For every advertised pubsub#* feature, drive the representative IQ
    // through the real dispatch. A feature with no probe fails the test, and
    // deleting the pubsub dispatch branch turns every probe into a
    // service-unavailable error.
    const node = "urn:test:probe";
    const publish_children = [_]xml.Element{
        testElem("pubsub", xml.ns.pubsub, &.{}),
        testElem("publish", xml.ns.pubsub, &.{testAttr("node", node)}),
        testElem("item", xml.ns.pubsub, &.{testAttr("id", "i1")}),
    };
    const items_children = [_]xml.Element{
        testElem("pubsub", xml.ns.pubsub, &.{}),
        testElem("items", xml.ns.pubsub, &.{testAttr("node", node)}),
    };
    const payload = "<data xmlns='urn:test'>v1</data>";

    for (feats[0..feat_count], 0..) |feature, i| {
        const probe = for (PUBSUB_PROBES) |p| {
            if (std.mem.eql(u8, p.feature, feature)) break p;
        } else {
            std.debug.print("pubsub feature advertised with no probe: {s}\n", .{feature});
            return error.PubsubFeatureUndispatched;
        };

        var id_buf: [16]u8 = undefined;
        if (std.mem.eql(u8, probe.verb, "publish")) {
            const id = try std.fmt.bufPrint(&id_buf, "pub-{d}", .{i});
            const resp = try driveTestIq(&server, &session, &changes, fds[1], "set", id, &publish_children, payload, &wire);
            try std.testing.expect(std.mem.indexOf(u8, resp, "type='result'") != null);
            const stored = try pep_store.getItem(allocator, "alice@localhost", node, "i1");
            try std.testing.expect(stored != null);
            defer allocator.free(stored.?);
            try std.testing.expect(std.mem.indexOf(u8, stored.?, "v1") != null);
        } else {
            const set_id = try std.fmt.bufPrint(&id_buf, "pub-{d}", .{i});
            const set_resp = try driveTestIq(&server, &session, &changes, fds[1], "set", set_id, &publish_children, payload, &wire);
            try std.testing.expect(std.mem.indexOf(u8, set_resp, "type='result'") != null);
            const get_id = try std.fmt.bufPrint(&id_buf, "items-{d}", .{i});
            const resp = try driveTestIq(&server, &session, &changes, fds[1], "get", get_id, &items_children, null, &wire);
            try std.testing.expect(std.mem.indexOf(u8, resp, "type='result'") != null);
            try std.testing.expect(std.mem.indexOf(u8, resp, "<items") != null);
            try std.testing.expect(std.mem.indexOf(u8, resp, "v1") != null);
        }
    }
}

test "Server: pubsub set routes on the verb, not blindly to publish" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var pep_store = GenericPepStore.init(&op_db);

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 8);
    defer server.deinit();
    server.pep_store = &pep_store;

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    var session = Session.init(fds[0], 1, "localhost", false, allocator);
    defer session.deinit();
    session.stream.bound_jid = xmpp.Jid.parse("alice@localhost/res") catch null;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    var wire: [8192]u8 = undefined;

    const node = "urn:test:verbs";
    const publish_children = [_]xml.Element{
        testElem("pubsub", xml.ns.pubsub, &.{}),
        testElem("publish", xml.ns.pubsub, &.{testAttr("node", node)}),
        testElem("item", xml.ns.pubsub, &.{testAttr("id", "i1")}),
    };
    const payload = "<data xmlns='urn:test'>v1</data>";

    // A real publish first: the stored item must survive the verb probes.
    var resp = try driveTestIq(&server, &session, &changes, fds[1], "set", "pub-0", &publish_children, payload, &wire);
    try std.testing.expect(std.mem.indexOf(u8, resp, "type='result'") != null);

    // <items> in a set is not a write verb: bad-request, and the stored item
    // keeps its payload (the review probe: a verb-blind dispatch upserts an
    // empty item).
    const items_set = [_]xml.Element{
        testElem("pubsub", xml.ns.pubsub, &.{}),
        testElem("items", xml.ns.pubsub, &.{testAttr("node", node)}),
    };
    resp = try driveTestIq(&server, &session, &changes, fds[1], "set", "items-0", &items_set, null, &wire);
    try std.testing.expect(std.mem.indexOf(u8, resp, "type='error'") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "bad-request") != null);
    const stored = try pep_store.getItem(allocator, "alice@localhost", node, "i1");
    try std.testing.expect(stored != null);
    defer allocator.free(stored.?);
    try std.testing.expect(std.mem.indexOf(u8, stored.?, "v1") != null);

    // Recognized but unimplemented verbs answer feature-not-implemented with
    // the XEP-0060 <unsupported> feature token.
    const unsupported_cases = [_]struct { verb: []const u8, feature: []const u8 }{
        .{ .verb = "subscribe", .feature = "subscribe" },
        .{ .verb = "unsubscribe", .feature = "subscribe" },
        .{ .verb = "retract", .feature = "retract-items" },
        .{ .verb = "create", .feature = "create-nodes" },
        .{ .verb = "delete", .feature = "delete-nodes" },
        .{ .verb = "purge", .feature = "purge-nodes" },
        .{ .verb = "configure", .feature = "config-node" },
        .{ .verb = "options", .feature = "subscription-options" },
    };
    for (unsupported_cases, 0..) |case, i| {
        var id_buf: [16]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buf, "verb-{d}", .{i});
        const children = [_]xml.Element{
            testElem("pubsub", xml.ns.pubsub, &.{}),
            testElem(case.verb, xml.ns.pubsub, &.{testAttr("node", node)}),
        };
        resp = try driveTestIq(&server, &session, &changes, fds[1], "set", id, &children, null, &wire);
        try std.testing.expect(std.mem.indexOf(u8, resp, "type='error'") != null);
        try std.testing.expect(std.mem.indexOf(u8, resp, "feature-not-implemented") != null);
        var feat_buf: [64]u8 = undefined;
        const needle = try std.fmt.bufPrint(&feat_buf, "feature='{s}'", .{case.feature});
        try std.testing.expect(std.mem.indexOf(u8, resp, needle) != null);
        try std.testing.expect(std.mem.indexOf(u8, resp, "pubsub#errors") != null);
    }

    // The retract probe above must not have deleted the stored item.
    const still = try pep_store.getItem(allocator, "alice@localhost", node, "i1");
    try std.testing.expect(still != null);
    defer allocator.free(still.?);
    try std.testing.expect(std.mem.indexOf(u8, still.?, "v1") != null);
}
