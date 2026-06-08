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
const SessionRegistry = @import("session_registry").SessionRegistry;
const shared_registry_mod = @import("shared_registry");
const SharedSessionRegistry = shared_registry_mod.SharedSessionRegistry;
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
const room_registry_mod = @import("room_registry");
const RoomRegistry = room_registry_mod.RoomRegistry;
const fanout_mod = @import("fanout.zig");
const FanoutQueue = fanout_mod.FanoutQueue;

const log = std.log.scoped(.xmppd);

/// Default maximum simultaneous connections (configurable via init).
pub const DEFAULT_MAX_SESSIONS: usize = 4096;

/// Sentinel value for listener fd in kqueue udata.
const LISTENER_UDATA = std.math.maxInt(usize);

/// Sentinel value for auth IPC fd in kqueue udata.
pub const IPC_AUTH_UDATA = LISTENER_UDATA - 1;

/// Sentinel value for S2S IPC fd in kqueue udata.
const IPC_S2S_UDATA = LISTENER_UDATA - 2;

/// Sentinel value for delivery system wake pipe fd in kqueue udata.
const WAKE_PIPE_UDATA = LISTENER_UDATA - 3;

/// Maximum changelist entries per event loop iteration.
const CHANGE_BUF_SIZE = 256;

/// Maximum XML events processed per connection per event loop tick.
/// Prevents a single client from monopolizing the event loop by sending
/// thousands of tiny XML elements packed into one TCP segment.
/// After this limit, control returns to the event loop; remaining data
/// stays in the read buffer and kqueue will fire fd_readable again.
const MAX_EVENTS_PER_TICK = 100;

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
const StanzaKind = enum {
    none,
    message,
    presence,
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
    /// Roster item attributes from <item> inside roster query.
    iq_roster_item_jid: []const u8 = "",
    iq_roster_item_name: []const u8 = "",
    iq_roster_item_sub: []const u8 = "",

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

    fn init(fd: posix.fd_t, id: usize, server_host: []const u8, direct_tls: bool, allocator: std.mem.Allocator) Session {
        return .{
            .conn = Connection.init(fd, id),
            .reader = xml.Reader.init(allocator),
            .stream = xmpp.Stream.init(server_host, direct_tls),
        };
    }

    fn deinit(self: *Session) void {
        self.reader.deinit();
        if (!self.conn.isClosed()) self.conn.close();
    }

    fn resetSasl(self: *Session) void {
        self.sasl_collecting = .none;
        self.sasl_buf_len = 0;
        self.sasl_mechanism = "";
        self.auth_state = .none;
    }

    fn resetStanza(self: *Session) void {
        self.stanza_kind = .none;
        self.stanza_buf_len = 0;
        self.stanza_to = "";
        self.stanza_id = "";
        self.stanza_type = "";
    }
};

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
    next_id: usize = 1, // 0 reserved

    /// TLS context — shared across all connections. Null if TLS is not configured.
    ssl_ctx: ?ssl.SslContext = null,

    /// IPC client for auth daemon communication.
    ipc: IpcClient = .{},

    /// IPC client for S2S daemon communication (federation).
    s2s_ipc: IpcClient = .{},

    /// Session registry — maps bound JIDs to session IDs (used when workers == 1).
    registry: SessionRegistry = .{},

    /// Shared session registry — cross-thread routing table (used when workers > 1).
    /// Null in single-thread mode (zero overhead path).
    shared_registry: ?*SharedSessionRegistry = null,

    /// This worker's thread ID (0..N-1). Used for cross-thread routing decisions.
    worker_id: u16 = 0,

    /// Base offset for mapping local session IDs to global shared registry slots.
    /// Worker N's global ID = session_id_base + local_id.
    /// Set by configureServer() to worker_id * max_sessions.
    session_id_base: u32 = 0,

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

    /// MUC service hostname (e.g., "conference.example.com").
    muc_host: ?[]const u8 = null,

    /// Pending fan-out queue — bounded continuation for MUC groupchat delivery.
    fanout_queue: FanoutQueue = .{},

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
        const sessions = try allocator.alloc(?*Session, max_sessions);
        @memset(sessions, null);

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
            .allocator = allocator,
            .server_host = host,
        };
    }

    /// Initialize with a pre-bound listener fd (received from master via fd inheritance).
    pub fn initFromFd(
        host: []const u8,
        fd: std.posix.fd_t,
        allocator: std.mem.Allocator,
        max_sessions: usize,
    ) !Server {
        const sessions = try allocator.alloc(?*Session, max_sessions);
        @memset(sessions, null);

        const loop = try EventLoop.init(allocator, 256);
        errdefer {
            var l = loop;
            l.deinit();
        }

        const listener = Listener.initFromFd(fd, false);

        return Server{
            .loop = loop,
            .listener = listener,
            .sessions = sessions,
            .max_sessions = max_sessions,
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

        while (self.running) {
            // Mark active before processing events (coalesced signaling)
            if (self.delivery_system) |ds| {
                ds.getState(self.worker_id).setActive();
            }

            const events = try self.loop.submitAndPoll(changes.slice(), null);
            changes.reset();

            for (events) |ev| {
                switch (ev) {
                    .fd_readable => |e| {
                        if (e.udata == LISTENER_UDATA) {
                            self.acceptConnections(&changes);
                        } else if (e.udata == IPC_AUTH_UDATA) {
                            self.handleIpcReadable(&changes);
                        } else if (e.udata == IPC_S2S_UDATA) {
                            self.handleS2sIpcReadable(&changes);
                        } else if (e.udata == WAKE_PIPE_UDATA) {
                            self.handleDeliveryWake(&changes);
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
                    .fd_error => |e| {
                        if (e.udata != LISTENER_UDATA and e.udata != IPC_AUTH_UDATA and e.udata != IPC_S2S_UDATA and e.udata != WAKE_PIPE_UDATA) {
                            self.closeSession(e.udata, &changes);
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

    fn acceptConnections(self: *Server, changes: *ChangeList) void {
        // Drain all pending connections
        while (true) {
            const id = self.allocateId() orelse {
                log.warn("connection limit reached ({d})", .{self.max_sessions});
                break;
            };

            var conn = self.listener.accept(id) catch |err| {
                switch (err) {
                    error.WouldBlock => break, // No more pending
                    else => {
                        log.err("accept failed: {}", .{err});
                        break;
                    },
                }
            };

            // Create session
            const session = self.allocator.create(Session) catch {
                log.err("out of memory for session", .{});
                conn.close();
                self.freeId(id);
                break;
            };
            session.* = Session.init(conn.fd, id, self.server_host, self.listener.direct_tls, self.allocator);
            // Transfer the fd (don't double-close)
            session.conn = conn;
            self.sessions[id] = session;

            // Register for read events — batched into changelist
            changes.addRead(conn.fd, id) catch {
                log.err("changelist full on accept", .{});
                session.deinit();
                self.allocator.destroy(session);
                self.sessions[id] = null;
                break;
            };

            log.info("accepted connection id={d} fd={d}", .{ id, conn.fd });
        }
    }

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
            self.closeSession(id, changes);
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
            // kqueue won't fire for data already consumed from the socket.
            // Drain in a loop — handleReadable returns on WouldBlock.
            self.handleReadable(id, changes);

            // If the session is still alive, ensure kqueue monitors the fd.
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

    fn handleReadable(self: *Server, id: usize, changes: *ChangeList) void {
        const session = self.sessions[id] orelse return;

        // Read from socket
        const n = session.conn.recv() catch |err| {
            switch (err) {
                error.WouldBlock => return,
                else => {
                    log.info("connection {d} recv error: {}", .{ id, err });
                    self.closeSession(id, changes);
                    return;
                },
            }
        };

        if (n == 0) {
            // EOF
            log.info("connection {d} closed by peer", .{id});
            self.closeSession(id, changes);
            return;
        }

        // Parse XML events from the read buffer.
        // Capped at MAX_EVENTS_PER_TICK to ensure fair scheduling across
        // all connections — a single client cannot monopolize the event loop.
        const data = session.conn.readableSlice();
        var pos: usize = 0;
        var events_processed: usize = 0;

        while (events_processed < MAX_EVENTS_PER_TICK) {
            const event = session.reader.next(data, &pos) catch |err| {
                log.err("connection {d} XML parse error: {}", .{ id, err });
                self.sendStreamError(session, .not_well_formed);
                self.closeSession(id, changes);
                return;
            };

            if (event == null) break; // Need more data

            // Depth limit check — defend against deep nesting DoS
            if (session.reader.depth > MAX_ELEMENT_DEPTH) {
                log.warn("connection {d} exceeded max depth ({d})", .{ id, MAX_ELEMENT_DEPTH });
                self.sendStreamError(session, .policy_violation);
                self.closeSession(id, changes);
                return;
            }

            self.processXmlEvent(session, event.?, changes);
            events_processed += 1;

            // Session may have been closed/freed by processXmlEvent (stream
            // error, close, etc.) — check the slot, not the stale pointer.
            if (self.sessions[id] == null) return;
            // After STARTTLS upgrade, stop processing pre-TLS buffer
            if (session.conn.isTlsHandshaking()) break;
        }

        // Consume processed bytes
        session.conn.consume(pos);

        // If we have pending writes, register for write events
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
                self.closeSession(session.conn.id, changes);
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
                iq_handler.handleIq(session, elem);
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
                self.handleMessage(session, elem, changes);
            } else if (std.mem.eql(u8, elem.local_name, "presence")) {
                self.handlePresence(session, elem, changes);
            } else if (std.mem.eql(u8, elem.local_name, "iq")) {
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
            } else {
                // Stanza complete (depth back to stream level) — route to targets
                self.dispatchStanza(session, changes);
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
                self.handleBind(session, resource, changes);
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

        // vCard XML close tag accumulation
        if (session.iq_active and session.vcard_collecting) {
            if (session.reader.depth > 2) {
                self.accumulateVcardClose(session, name);
            } else {
                // </vCard> reached — write closing tag and stop collecting
                self.accumulateVcardClose(session, name);
                session.vcard_collecting = false;
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

        // Send AuthRequest to auth daemon
        self.ipc.send(.{
            .auth_request = .{
                .conn_id = @intCast(session.conn.id),
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
            .conn_id = @intCast(session.conn.id),
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

        const conn_id: usize = switch (msg) {
            .auth_challenge => |m| m.conn_id,
            .auth_success => |m| m.conn_id,
            .auth_failure => |m| m.conn_id,
            .register_result => |m| m.conn_id,
            .password_change_result => |m| m.conn_id,
            .account_delete_result => |m| m.conn_id,
            else => return,
        };

        const session = self.sessions[conn_id] orelse {
            log.warn("auth response for unknown connection {d}", .{conn_id});
            return;
        };

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

        // Session registry unbind happens automatically when the connection closes
        // after we send </stream:stream>.

        log.info("cascade cleanup complete for {s}", .{bare_jid});
    }

    // ========================================================================
    // S2S IPC — federation stanza forwarding
    // ========================================================================

    /// Forward a stanza to a remote domain via the S2S daemon IPC.
    /// Serializes the full stanza XML and sends an S2sDeliver message.
    fn forwardToS2s(self: *Server, session: *Session, from_str: []const u8, to_str: []const u8, type_str: []const u8, id_str: []const u8, inner_xml: []const u8, changes: *ChangeList) void {
        if (!self.s2s_ipc.connected) {
            log.info("connection {d} stanza to remote {s} — no S2S daemon", .{ session.conn.id, to_str });
            self.sendServiceUnavailable(session, id_str, to_str, from_str);
            if (session.conn.hasPendingWrite()) {
                changes.addWrite(session.conn.fd, session.conn.id) catch {};
            }
            return;
        }

        const tag_name: []const u8 = switch (session.stanza_kind) {
            .message => "message",
            .presence => "presence",
            .none => return,
        };

        // Serialize the full stanza XML into a buffer
        var stanza_buf: [20480]u8 = undefined;
        var stanza_fbs = std.io.fixedBufferStream(&stanza_buf);
        const sw = stanza_fbs.writer();

        sw.writeByte('<') catch return;
        sw.writeAll(tag_name) catch return;
        sw.writeAll(" from='") catch return;
        sw.writeAll(from_str) catch return;
        sw.writeAll("' to='") catch return;
        sw.writeAll(to_str) catch return;
        sw.writeByte('\'') catch return;
        if (type_str.len > 0) {
            if (!(session.stanza_kind == .message and std.mem.eql(u8, type_str, "normal"))) {
                sw.writeAll(" type='") catch return;
                sw.writeAll(type_str) catch return;
                sw.writeByte('\'') catch return;
            }
        }
        if (id_str.len > 0) {
            sw.writeAll(" id='") catch return;
            sw.writeAll(id_str) catch return;
            sw.writeByte('\'') catch return;
        }
        if (inner_xml.len == 0) {
            sw.writeAll("/>") catch return;
        } else {
            sw.writeByte('>') catch return;
            sw.writeAll(inner_xml) catch return;
            sw.writeAll("</") catch return;
            sw.writeAll(tag_name) catch return;
            sw.writeByte('>') catch return;
        }

        const stanza_xml = stanza_fbs.getWritten();

        self.s2s_ipc.send(.{ .s2s_deliver = .{
            .from_jid = from_str,
            .to_jid = to_str,
            .stanza_xml = stanza_xml,
        } }) catch {
            log.err("connection {d} failed to forward stanza to S2S daemon", .{session.conn.id});
            self.sendServiceUnavailable(session, id_str, to_str, from_str);
            if (session.conn.hasPendingWrite()) {
                changes.addWrite(session.conn.fd, session.conn.id) catch {};
            }
            return;
        };

        if (self.s2s_ipc.hasPendingSend()) {
            changes.addWrite(self.s2s_ipc.fd, IPC_S2S_UDATA) catch {};
        }

        log.info("connection {d} stanza to remote {s} forwarded via S2S", .{ session.conn.id, to_str });
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

                var target_ids: [16]usize = undefined;
                const target_count = if (to_jid.resource.len > 0) blk: {
                    if (self.registry.findByFullJid(to_jid.local, to_jid.domain, to_jid.resource)) |entry| {
                        target_ids[0] = entry.id;
                        break :blk @as(usize, 1);
                    }
                    break :blk @as(usize, 0);
                } else self.registry.findAvailableByBareJid(to_jid.local, to_jid.domain, &target_ids);

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

                                const timestamp: u64 = @intCast(std.time.timestamp());
                                const stanza_id = if (parts.msg_id.len > 0) parts.msg_id else "s2s-offline";

                                // Store full stanza in archive, pointer in offline
                                archive.store(recipient_bare, m.from_jid, stanza_id, timestamp, m.stanza_xml) catch {};
                                if (store.storePointer(recipient_bare, m.from_jid, stanza_id, timestamp) catch false) {
                                    log.info("S2S inbound to {s} stored offline", .{m.to_jid});
                                    return;
                                }
                            }
                        }
                    }
                    log.info("S2S inbound to {s} — recipient unavailable, no offline", .{m.to_jid});
                    return;
                }

                for (target_ids[0..target_count]) |tid| {
                    const target_session = self.sessions[tid] orelse continue;
                    target_session.conn.queueSend(m.stanza_xml) catch continue;
                    if (target_session.conn.hasPendingWrite()) {
                        changes.addWrite(target_session.conn.fd, tid) catch {};
                    }
                }
                log.info("S2S inbound from {s} delivered to {d} local session(s)", .{ m.from_jid, target_count });
            },
            .s2s_delivery_failed => |m| {
                // Delivery to remote failed — bounce error to original sender
                const from_jid = xmpp.Jid.parse(m.from_jid) catch return;

                var sender_ids: [16]usize = undefined;
                const sender_count = if (from_jid.resource.len > 0) blk: {
                    if (self.registry.findByFullJid(from_jid.local, from_jid.domain, from_jid.resource)) |entry| {
                        sender_ids[0] = entry.id;
                        break :blk @as(usize, 1);
                    }
                    break :blk @as(usize, 0);
                } else self.registry.findAvailableByBareJid(from_jid.local, from_jid.domain, &sender_ids);

                for (sender_ids[0..sender_count]) |sid| {
                    const sender_session = self.sessions[sid] orelse continue;
                    var err_buf: [1024]u8 = undefined;
                    var err_fbs = std.io.fixedBufferStream(&err_buf);
                    const ew = err_fbs.writer();
                    ew.writeAll("<message type='error' from='") catch continue;
                    ew.writeAll(m.to_jid) catch continue;
                    ew.writeAll("' to='") catch continue;
                    ew.writeAll(m.from_jid) catch continue;
                    ew.writeAll("'><error type='cancel'><") catch continue;
                    ew.writeAll(m.error_type) catch continue;
                    ew.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>") catch continue;
                    sender_session.conn.queueSend(err_fbs.getWritten()) catch continue;
                    if (sender_session.conn.hasPendingWrite()) {
                        changes.addWrite(sender_session.conn.fd, sid) catch {};
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
        _ = self;
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
        _ = self;
        var fbs = std.io.fixedBufferStream(session.vcard_buf[session.vcard_buf_len..]);
        xmlEscapeWrite(fbs.writer(), text) catch return;
        session.vcard_buf_len += fbs.pos;
    }

    fn accumulateVcardClose(self: *Server, session: *Session, name: []const u8) void {
        _ = self;
        var fbs = std.io.fixedBufferStream(session.vcard_buf[session.vcard_buf_len..]);
        const w = fbs.writer();
        w.writeAll("</") catch return;
        w.writeAll(name) catch return;
        w.writeByte('>') catch return;
        session.vcard_buf_len += fbs.pos;
    }

    /// Route a fully accumulated stanza to target session(s).
    /// Reconstructs the opening tag with the sender's full JID as 'from',
    /// appends the accumulated child XML, and closes the stanza.
    fn dispatchStanza(self: *Server, session: *Session, changes: *ChangeList) void {
        defer session.resetStanza();

        const to_str = session.stanza_to;
        const id_str = session.stanza_id;
        const type_str = session.stanza_type;
        const inner_xml = session.stanza_buf[0..session.stanza_buf_len];

        if (to_str.len == 0) return;

        // Parse target JID
        const to_jid = xmpp.Jid.parse(to_str) catch {
            log.warn("connection {d} stanza with invalid 'to': {s}", .{ session.conn.id, to_str });
            return;
        };

        // Get the sender's bound JID
        const from_jid = session.stream.bound_jid orelse return;

        // Build the from string (full JID: local@domain/resource)
        var from_buf: [256]u8 = undefined;
        var from_fbs = std.io.fixedBufferStream(&from_buf);
        const from_w = from_fbs.writer();
        from_w.writeAll(from_jid.local) catch return;
        from_w.writeByte('@') catch return;
        from_w.writeAll(from_jid.domain) catch return;
        if (from_jid.resource.len > 0) {
            from_w.writeByte('/') catch return;
            from_w.writeAll(from_jid.resource) catch return;
        }
        const from_str = from_fbs.getWritten();

        // MUC domain? Route to MUC handler for groupchat fan-out.
        if (self.muc_host) |muc_host| {
            if (std.mem.eql(u8, to_jid.domain, muc_host)) {
                if (session.stanza_kind == .message and std.mem.eql(u8, type_str, "groupchat")) {
                    muc_handler.handleMucGroupchat(self, session, to_jid.local, inner_xml, id_str, changes);
                }
                // Presence to MUC is handled separately in handlePresence dispatch
                return;
            }
        }

        // Remote domain? Forward via S2S IPC instead of local delivery.
        if (!std.mem.eql(u8, to_jid.domain, self.server_host)) {
            self.forwardToS2s(session, from_str, to_str, type_str, id_str, inner_xml, changes);
            return;
        }

        // Route: find target session(s).
        // Multi-worker path uses shared registry (cross-thread aware routing).
        // Single-worker path uses local registry (zero overhead).
        const RoutingInfo = shared_registry_mod.RoutingResult;
        var routing_buf: [16]RoutingInfo = undefined;
        var local_ids: [16]usize = undefined;
        var target_count: usize = 0;

        var remote_delivered: bool = false;

        if (self.shared_registry) |sr| {
            // Multi-worker: lookup via shared registry, returns (session_id, worker_id, generation)
            const route_count = if (to_jid.resource.len > 0) blk: {
                if (sr.findByFullJid(to_jid.local, to_jid.domain, to_jid.resource)) |r| {
                    routing_buf[0] = r;
                    break :blk @as(usize, 1);
                }
                break :blk @as(usize, 0);
            } else sr.findAvailableByBareJid(to_jid.local, to_jid.domain, &routing_buf);

            // Split into local (same worker) and remote (cross-thread MPSC)
            for (routing_buf[0..route_count]) |route| {
                if (route.worker_id == self.worker_id) {
                    // Local delivery — add to local_ids for normal forwarding below
                    if (target_count < local_ids.len) {
                        local_ids[target_count] = route.session_id;
                        target_count += 1;
                    }
                } else {
                    // Cross-thread delivery: serialize stanza and enqueue via MPSC
                    self.enqueueCrossThreadStanza(
                        route,
                        from_str,
                        to_str,
                        type_str,
                        id_str,
                        inner_xml,
                        session.stanza_kind,
                    );
                    remote_delivered = true;
                }
            }
        } else {
            // Single-worker: use local registry (no shared infrastructure overhead)
            target_count = if (to_jid.resource.len > 0) blk: {
                if (self.registry.findByFullJid(to_jid.local, to_jid.domain, to_jid.resource)) |entry| {
                    local_ids[0] = entry.id;
                    break :blk @as(usize, 1);
                }
                break :blk @as(usize, 0);
            } else self.registry.findAvailableByBareJid(to_jid.local, to_jid.domain, &local_ids);
        }

        if (target_count == 0 and !remote_delivered) {
            // Only messages get offline storage (not presence stanzas)
            if (session.stanza_kind == .message) {
                if (self.offline) |store| {
                    if (self.archive) |archive| {
                        // Build recipient bare JID
                        var recip_buf: [256]u8 = undefined;
                        var recip_fbs = std.io.fixedBufferStream(&recip_buf);
                        recip_fbs.writer().writeAll(to_jid.local) catch {};
                        recip_fbs.writer().writeByte('@') catch {};
                        recip_fbs.writer().writeAll(to_jid.domain) catch {};
                        const recipient_bare = recip_fbs.getWritten();

                        // Build full stanza XML for archive
                        var stanza_buf: [20480]u8 = undefined;
                        var stanza_fbs = std.io.fixedBufferStream(&stanza_buf);
                        const sw = stanza_fbs.writer();
                        sw.writeAll("<message from='") catch {};
                        sw.writeAll(from_str) catch {};
                        sw.writeAll("' to='") catch {};
                        sw.writeAll(to_str) catch {};
                        sw.writeByte('\'') catch {};
                        if (type_str.len > 0) {
                            sw.writeAll(" type='") catch {};
                            sw.writeAll(type_str) catch {};
                            sw.writeByte('\'') catch {};
                        }
                        if (id_str.len > 0) {
                            sw.writeAll(" id='") catch {};
                            sw.writeAll(id_str) catch {};
                            sw.writeByte('\'') catch {};
                        }
                        if (inner_xml.len == 0) {
                            sw.writeAll("/>") catch {};
                        } else {
                            sw.writeByte('>') catch {};
                            sw.writeAll(inner_xml) catch {};
                            sw.writeAll("</message>") catch {};
                        }
                        const full_stanza = stanza_fbs.getWritten();

                        // Generate stanza ID
                        const timestamp: u64 = @intCast(std.time.timestamp());
                        const stanza_id = if (id_str.len > 0) id_str else "offline";

                        // Store payload in archive, pointer in offline
                        archive.store(recipient_bare, from_str, stanza_id, timestamp, full_stanza) catch {};
                        if (store.storePointer(recipient_bare, from_str, stanza_id, timestamp) catch false) {
                            log.info("connection {d} message to {s} stored offline", .{ session.conn.id, to_str });
                            return;
                        }
                    }
                }
            }
            // No offline store configured or store full — bounce
            log.info("connection {d} message to {s} — recipient unavailable", .{ session.conn.id, to_str });
            self.sendServiceUnavailable(session, id_str, to_str, from_str);
            if (session.conn.hasPendingWrite()) {
                changes.addWrite(session.conn.fd, session.conn.id) catch {};
            }
            return;
        }

        const tag_name: []const u8 = switch (session.stanza_kind) {
            .message => "message",
            .presence => "presence",
            .none => return,
        };

        // Forward to each local target session
        for (local_ids[0..target_count]) |tid| {
            const target_session = self.sessions[tid] orelse continue;
            // 20KB buffer: opening tag attrs + 16KB inner XML + closing tag
            var msg_buf: [20480]u8 = undefined;
            var msg_fbs = std.io.fixedBufferStream(&msg_buf);
            const mw = msg_fbs.writer();

            // Opening tag with rewritten 'from'
            mw.writeByte('<') catch continue;
            mw.writeAll(tag_name) catch continue;
            mw.writeAll(" from='") catch continue;
            mw.writeAll(from_str) catch continue;
            mw.writeAll("' to='") catch continue;
            mw.writeAll(to_str) catch continue;
            mw.writeByte('\'') catch continue;
            // Omit type='normal' for messages (it's the default)
            if (type_str.len > 0) {
                if (!(session.stanza_kind == .message and std.mem.eql(u8, type_str, "normal"))) {
                    mw.writeAll(" type='") catch continue;
                    mw.writeAll(type_str) catch continue;
                    mw.writeByte('\'') catch continue;
                }
            }
            if (id_str.len > 0) {
                mw.writeAll(" id='") catch continue;
                mw.writeAll(id_str) catch continue;
                mw.writeByte('\'') catch continue;
            }

            if (inner_xml.len == 0) {
                // No children — self-close
                mw.writeAll("/>") catch continue;
            } else {
                // Emit children and close tag
                mw.writeByte('>') catch continue;
                mw.writeAll(inner_xml) catch continue;
                mw.writeAll("</") catch continue;
                mw.writeAll(tag_name) catch continue;
                mw.writeByte('>') catch continue;
            }

            target_session.conn.queueSend(msg_fbs.getWritten()) catch continue;
            if (target_session.conn.hasPendingWrite()) {
                changes.addWrite(target_session.conn.fd, tid) catch {};
            }
        }
    }

    fn handlePresence(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
        var type_str: []const u8 = "";
        var to_str: []const u8 = "";
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "type")) type_str = attr.value;
            if (std.mem.eql(u8, attr.local_name, "to")) to_str = attr.value;
        }

        // Directed presence to MUC domain → MUC join/part
        if (to_str.len > 0) {
            if (self.muc_host) |muc_host| {
                const to_jid = xmpp.Jid.parse(to_str) catch return;
                if (std.mem.eql(u8, to_jid.domain, muc_host)) {
                    muc_handler.handleMucPresence(self, session, to_jid.local, to_jid.resource, type_str, changes);
                    return;
                }
            }
        }

        const ptype = xmpp.PresenceType.fromString(type_str);
        const bound = session.stream.bound_jid orelse return;

        switch (ptype) {
            .available => {
                // Initial presence — mark session as available, broadcast to subscribers
                self.registry.setPresenceAvailable(session.conn.id, true);
                if (self.shared_registry) |sr| sr.setPresenceAvailable(self.globalSessionId(session.conn.id), true);
                self.broadcastPresence(bound.local, bound.domain, bound.resource, changes);

                // Send presence probes to contacts we're subscribed to
                self.sendPresenceProbes(session, bound.local, bound.domain, changes);

                // Deliver any offline messages queued for this user
                self.deliverOfflineMessages(session, bound.local, bound.domain, changes);

                log.info("connection {d} now available: {s}@{s}/{s}", .{
                    session.conn.id, bound.local, bound.domain, bound.resource,
                });
            },
            .unavailable => {
                self.registry.setPresenceAvailable(session.conn.id, false);
                if (self.shared_registry) |sr| sr.setPresenceAvailable(self.globalSessionId(session.conn.id), false);
                self.broadcastUnavailable(bound.local, bound.domain, bound.resource, changes);
            },
            .subscribe => {
                self.handleSubscribe(session, elem, changes);
            },
            .subscribed => {
                self.handleSubscribed(session, elem, changes);
            },
            .unsubscribe => {
                self.handleUnsubscribe(session, elem, changes);
            },
            .unsubscribed => {
                self.handleUnsubscribed(session, elem, changes);
            },
            else => {},
        }
    }

    // ========================================================================
    // Subscription state machine (RFC 6121 Section 3)
    // ========================================================================

    /// Handle <presence type='subscribe' to='contact@host'/> — outbound subscription request.
    fn handleSubscribe(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
        const roster = self.roster orelse return;
        const bound = session.stream.bound_jid orelse return;

        var to_str: []const u8 = "";
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "to")) to_str = attr.value;
        }
        if (to_str.len == 0) return;

        // Build owner bare JID
        var bare_buf: [256]u8 = undefined;
        var bare_fbs = std.io.fixedBufferStream(&bare_buf);
        bare_fbs.writer().writeAll(bound.local) catch return;
        bare_fbs.writer().writeByte('@') catch return;
        bare_fbs.writer().writeAll(bound.domain) catch return;
        const owner_bare = bare_fbs.getWritten();

        // Update owner's roster: set ask='subscribe'
        if (roster.getItem(self.allocator, owner_bare, to_str) catch null) |existing| {
            defer if (existing.name.len > 0) self.allocator.free(existing.name);
            roster.setItem(owner_bare, to_str, "", existing.subscription, true) catch return;
        } else {
            roster.setItem(owner_bare, to_str, "", Subscription.none, true) catch return;
        }

        // Forward subscribe to the target (if online)
        const to_jid = xmpp.Jid.parse(to_str) catch return;
        var target_ids: [16]usize = undefined;
        const target_count = self.registry.findByBareJid(to_jid.local, to_jid.domain, &target_ids);

        var from_buf: [256]u8 = undefined;
        var from_fbs = std.io.fixedBufferStream(&from_buf);
        from_fbs.writer().writeAll(owner_bare) catch return;
        const from_str = from_fbs.getWritten();

        for (target_ids[0..target_count]) |tid| {
            const target_session = self.sessions[tid] orelse continue;
            var pres_buf: [512]u8 = undefined;
            var pres_fbs = std.io.fixedBufferStream(&pres_buf);
            const pw = pres_fbs.writer();
            pw.writeAll("<presence from='") catch continue;
            pw.writeAll(from_str) catch continue;
            pw.writeAll("' to='") catch continue;
            pw.writeAll(to_str) catch continue;
            pw.writeAll("' type='subscribe'/>") catch continue;
            target_session.conn.queueSend(pres_fbs.getWritten()) catch continue;
            if (target_session.conn.hasPendingWrite()) {
                changes.addWrite(target_session.conn.fd, tid) catch {};
            }
        }

        log.info("{s} subscribing to {s}", .{ owner_bare, to_str });
    }

    /// Handle <presence type='subscribed' to='contact@host'/> — approve inbound subscription.
    fn handleSubscribed(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
        const roster = self.roster orelse return;
        const bound = session.stream.bound_jid orelse return;

        var to_str: []const u8 = "";
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "to")) to_str = attr.value;
        }
        if (to_str.len == 0) return;

        // Build owner bare JID
        var bare_buf: [256]u8 = undefined;
        var bare_fbs = std.io.fixedBufferStream(&bare_buf);
        bare_fbs.writer().writeAll(bound.local) catch return;
        bare_fbs.writer().writeByte('@') catch return;
        bare_fbs.writer().writeAll(bound.domain) catch return;
        const owner_bare = bare_fbs.getWritten();

        // Update our roster: contact's subscription gains "from" direction
        if (roster.getItem(self.allocator, owner_bare, to_str) catch null) |existing| {
            defer if (existing.name.len > 0) self.allocator.free(existing.name);
            const new_sub: Subscription = switch (existing.subscription) {
                .none => .from,
                .to => .both,
                else => existing.subscription,
            };
            roster.setItem(owner_bare, to_str, "", new_sub, false) catch return;
        } else {
            roster.setItem(owner_bare, to_str, "", .from, false) catch return;
        }

        // Update contact's roster: their subscription gains "to" direction
        if (roster.getItem(self.allocator, to_str, owner_bare) catch null) |existing| {
            defer if (existing.name.len > 0) self.allocator.free(existing.name);
            const new_sub: Subscription = switch (existing.subscription) {
                .none => .to,
                .from => .both,
                else => existing.subscription,
            };
            roster.setItem(to_str, owner_bare, "", new_sub, false) catch {};
        } else {
            roster.setItem(to_str, owner_bare, "", .to, false) catch {};
        }

        // Forward subscribed to the target (if online)
        const to_jid = xmpp.Jid.parse(to_str) catch return;
        var target_ids: [16]usize = undefined;
        const target_count = self.registry.findByBareJid(to_jid.local, to_jid.domain, &target_ids);

        for (target_ids[0..target_count]) |tid| {
            const target_session = self.sessions[tid] orelse continue;
            var pres_buf: [512]u8 = undefined;
            var pres_fbs = std.io.fixedBufferStream(&pres_buf);
            const pw = pres_fbs.writer();
            pw.writeAll("<presence from='") catch continue;
            pw.writeAll(owner_bare) catch continue;
            pw.writeAll("' to='") catch continue;
            pw.writeAll(to_str) catch continue;
            pw.writeAll("' type='subscribed'/>") catch continue;
            target_session.conn.queueSend(pres_fbs.getWritten()) catch continue;
            if (target_session.conn.hasPendingWrite()) {
                changes.addWrite(target_session.conn.fd, tid) catch {};
            }
        }

        // Also send our current presence to the newly subscribed contact
        if (self.registry.get(session.conn.id)) |entry| {
            if (entry.presence_available) {
                self.broadcastPresence(bound.local, bound.domain, bound.resource, changes);
            }
        }

        log.info("{s} approved subscription from {s}", .{ owner_bare, to_str });
    }

    /// Handle <presence type='unsubscribe' to='contact@host'/> — cancel outbound subscription.
    fn handleUnsubscribe(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
        const roster = self.roster orelse return;
        const bound = session.stream.bound_jid orelse return;

        var to_str: []const u8 = "";
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "to")) to_str = attr.value;
        }
        if (to_str.len == 0) return;

        var bare_buf: [256]u8 = undefined;
        var bare_fbs = std.io.fixedBufferStream(&bare_buf);
        bare_fbs.writer().writeAll(bound.local) catch return;
        bare_fbs.writer().writeByte('@') catch return;
        bare_fbs.writer().writeAll(bound.domain) catch return;
        const owner_bare = bare_fbs.getWritten();

        // Update our roster: remove "to" direction
        if (roster.getItem(self.allocator, owner_bare, to_str) catch null) |existing| {
            defer if (existing.name.len > 0) self.allocator.free(existing.name);
            const new_sub: Subscription = switch (existing.subscription) {
                .to => .none,
                .both => .from,
                else => existing.subscription,
            };
            roster.setItem(owner_bare, to_str, "", new_sub, false) catch {};
        }

        // Update contact's roster: remove "from" direction
        if (roster.getItem(self.allocator, to_str, owner_bare) catch null) |existing| {
            defer if (existing.name.len > 0) self.allocator.free(existing.name);
            const new_sub: Subscription = switch (existing.subscription) {
                .from => .none,
                .both => .to,
                else => existing.subscription,
            };
            roster.setItem(to_str, owner_bare, "", new_sub, false) catch {};
        }

        // Forward unsubscribe
        const to_jid = xmpp.Jid.parse(to_str) catch return;
        var target_ids: [16]usize = undefined;
        const target_count = self.registry.findByBareJid(to_jid.local, to_jid.domain, &target_ids);
        for (target_ids[0..target_count]) |tid| {
            const target_session = self.sessions[tid] orelse continue;
            var pres_buf: [512]u8 = undefined;
            var pres_fbs = std.io.fixedBufferStream(&pres_buf);
            const pw = pres_fbs.writer();
            pw.writeAll("<presence from='") catch continue;
            pw.writeAll(owner_bare) catch continue;
            pw.writeAll("' to='") catch continue;
            pw.writeAll(to_str) catch continue;
            pw.writeAll("' type='unsubscribe'/>") catch continue;
            target_session.conn.queueSend(pres_fbs.getWritten()) catch continue;
            if (target_session.conn.hasPendingWrite()) {
                changes.addWrite(target_session.conn.fd, tid) catch {};
            }
        }

        log.info("{s} unsubscribing from {s}", .{ owner_bare, to_str });
    }

    /// Handle <presence type='unsubscribed' to='contact@host'/> — deny/revoke inbound subscription.
    fn handleUnsubscribed(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
        const roster = self.roster orelse return;
        const bound = session.stream.bound_jid orelse return;

        var to_str: []const u8 = "";
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "to")) to_str = attr.value;
        }
        if (to_str.len == 0) return;

        var bare_buf: [256]u8 = undefined;
        var bare_fbs = std.io.fixedBufferStream(&bare_buf);
        bare_fbs.writer().writeAll(bound.local) catch return;
        bare_fbs.writer().writeByte('@') catch return;
        bare_fbs.writer().writeAll(bound.domain) catch return;
        const owner_bare = bare_fbs.getWritten();

        // Update our roster: remove "from" direction
        if (roster.getItem(self.allocator, owner_bare, to_str) catch null) |existing| {
            defer if (existing.name.len > 0) self.allocator.free(existing.name);
            const new_sub: Subscription = switch (existing.subscription) {
                .from => .none,
                .both => .to,
                else => existing.subscription,
            };
            roster.setItem(owner_bare, to_str, "", new_sub, existing.ask) catch {};
        }

        // Update contact's roster: remove "to" direction
        if (roster.getItem(self.allocator, to_str, owner_bare) catch null) |existing| {
            defer if (existing.name.len > 0) self.allocator.free(existing.name);
            const new_sub: Subscription = switch (existing.subscription) {
                .to => .none,
                .both => .from,
                else => existing.subscription,
            };
            roster.setItem(to_str, owner_bare, "", new_sub, false) catch {};
        }

        // Forward unsubscribed
        const to_jid = xmpp.Jid.parse(to_str) catch return;
        var target_ids: [16]usize = undefined;
        const target_count = self.registry.findByBareJid(to_jid.local, to_jid.domain, &target_ids);
        for (target_ids[0..target_count]) |tid| {
            const target_session = self.sessions[tid] orelse continue;
            var pres_buf: [512]u8 = undefined;
            var pres_fbs = std.io.fixedBufferStream(&pres_buf);
            const pw = pres_fbs.writer();
            pw.writeAll("<presence from='") catch continue;
            pw.writeAll(owner_bare) catch continue;
            pw.writeAll("' to='") catch continue;
            pw.writeAll(to_str) catch continue;
            pw.writeAll("' type='unsubscribed'/>") catch continue;
            target_session.conn.queueSend(pres_fbs.getWritten()) catch continue;
            if (target_session.conn.hasPendingWrite()) {
                changes.addWrite(target_session.conn.fd, tid) catch {};
            }
        }

        log.info("{s} denied/revoked subscription from {s}", .{ owner_bare, to_str });
    }

    fn handleIq(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
        _ = self;
        _ = changes;
        iq_handler.handleIq(session, elem);
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

    /// Broadcast available presence to all roster subscribers.
    fn broadcastPresence(self: *Server, local: []const u8, domain: []const u8, resource: []const u8, changes: *ChangeList) void {
        const roster = self.roster orelse return;

        // Build the from JID string
        var from_buf: [256]u8 = undefined;
        var from_fbs = std.io.fixedBufferStream(&from_buf);
        const fw = from_fbs.writer();
        fw.writeAll(local) catch return;
        fw.writeByte('@') catch return;
        fw.writeAll(domain) catch return;
        fw.writeByte('/') catch return;
        fw.writeAll(resource) catch return;
        const from_str = from_fbs.getWritten();

        // Build bare JID for roster lookup
        var bare_buf: [256]u8 = undefined;
        var bare_fbs = std.io.fixedBufferStream(&bare_buf);
        bare_fbs.writer().writeAll(local) catch return;
        bare_fbs.writer().writeByte('@') catch return;
        bare_fbs.writer().writeAll(domain) catch return;
        const bare_jid = bare_fbs.getWritten();

        // Find subscribers (contacts with "from" or "both" in our roster)
        const subscriber_jids = roster.getPresenceSubscribers(self.allocator, bare_jid) catch return;
        defer {
            for (subscriber_jids) |s| self.allocator.free(s);
            self.allocator.free(subscriber_jids);
        }
        // Build presence stanza
        var pres_buf: [512]u8 = undefined;
        var pres_fbs = std.io.fixedBufferStream(&pres_buf);
        const pw = pres_fbs.writer();
        pw.writeAll("<presence from='") catch return;
        pw.writeAll(from_str) catch return;
        pw.writeAll("'/>") catch return;
        const presence_xml = pres_fbs.getWritten();

        // Deliver to each subscriber that has an active session
        for (subscriber_jids) |sub_bare_jid| {
            // Parse the subscriber bare JID to get local/domain
            const at_pos = std.mem.indexOf(u8, sub_bare_jid, "@") orelse continue;
            const sub_local = sub_bare_jid[0..at_pos];
            const sub_domain = sub_bare_jid[at_pos + 1 ..];

            if (self.shared_registry) |sr| {
                // Multi-worker: use shared registry for cross-thread routing
                var routing_buf: [16]shared_registry_mod.RoutingResult = undefined;
                const route_count = sr.findAvailableByBareJid(sub_local, sub_domain, &routing_buf);
                for (routing_buf[0..route_count]) |route| {
                    if (route.worker_id == self.worker_id) {
                        const target_session = self.sessions[route.session_id] orelse continue;
                        target_session.conn.queueSend(presence_xml) catch continue;
                        if (target_session.conn.hasPendingWrite()) {
                            changes.addWrite(target_session.conn.fd, route.session_id) catch {};
                        }
                    } else {
                        // Cross-thread: enqueue pre-built presence XML
                        if (self.delivery_system) |ds| {
                            ds.deliver(route.worker_id, route.session_id, route.generation, presence_xml) catch {};
                        }
                    }
                }
            } else {
                // Single-worker: local registry only
                var target_ids: [16]usize = undefined;
                const target_count = self.registry.findAvailableByBareJid(sub_local, sub_domain, &target_ids);
                for (target_ids[0..target_count]) |tid| {
                    const target_session = self.sessions[tid] orelse continue;
                    target_session.conn.queueSend(presence_xml) catch continue;
                    if (target_session.conn.hasPendingWrite()) {
                        changes.addWrite(target_session.conn.fd, tid) catch {};
                    }
                }
            }
        }
    }

    /// Broadcast unavailable presence to roster subscribers.
    fn broadcastUnavailable(self: *Server, local: []const u8, domain: []const u8, resource: []const u8, changes: *ChangeList) void {
        const roster = self.roster orelse return;

        var from_buf: [256]u8 = undefined;
        var from_fbs = std.io.fixedBufferStream(&from_buf);
        const fw = from_fbs.writer();
        fw.writeAll(local) catch return;
        fw.writeByte('@') catch return;
        fw.writeAll(domain) catch return;
        fw.writeByte('/') catch return;
        fw.writeAll(resource) catch return;
        const from_str = from_fbs.getWritten();

        var bare_buf: [256]u8 = undefined;
        var bare_fbs = std.io.fixedBufferStream(&bare_buf);
        bare_fbs.writer().writeAll(local) catch return;
        bare_fbs.writer().writeByte('@') catch return;
        bare_fbs.writer().writeAll(domain) catch return;
        const bare_jid = bare_fbs.getWritten();

        const subscriber_jids = roster.getPresenceSubscribers(self.allocator, bare_jid) catch return;
        defer {
            for (subscriber_jids) |s| self.allocator.free(s);
            self.allocator.free(subscriber_jids);
        }

        var pres_buf: [512]u8 = undefined;
        var pres_fbs = std.io.fixedBufferStream(&pres_buf);
        const pw = pres_fbs.writer();
        pw.writeAll("<presence from='") catch return;
        pw.writeAll(from_str) catch return;
        pw.writeAll("' type='unavailable'/>") catch return;
        const presence_xml = pres_fbs.getWritten();

        for (subscriber_jids) |sub_bare_jid| {
            const at_pos = std.mem.indexOf(u8, sub_bare_jid, "@") orelse continue;
            const sub_local = sub_bare_jid[0..at_pos];
            const sub_domain = sub_bare_jid[at_pos + 1 ..];

            if (self.shared_registry) |sr| {
                // Multi-worker: use shared registry for cross-thread routing
                var routing_buf: [16]shared_registry_mod.RoutingResult = undefined;
                const route_count = sr.findAvailableByBareJid(sub_local, sub_domain, &routing_buf);
                for (routing_buf[0..route_count]) |route| {
                    if (route.worker_id == self.worker_id) {
                        const target_session = self.sessions[route.session_id] orelse continue;
                        target_session.conn.queueSend(presence_xml) catch continue;
                        if (target_session.conn.hasPendingWrite()) {
                            changes.addWrite(target_session.conn.fd, route.session_id) catch {};
                        }
                    } else {
                        // Cross-thread: enqueue pre-built presence XML
                        if (self.delivery_system) |ds| {
                            ds.deliver(route.worker_id, route.session_id, route.generation, presence_xml) catch {};
                        }
                    }
                }
            } else {
                // Single-worker: local registry only
                var target_ids: [16]usize = undefined;
                const target_count = self.registry.findAvailableByBareJid(sub_local, sub_domain, &target_ids);
                for (target_ids[0..target_count]) |tid| {
                    const target_session = self.sessions[tid] orelse continue;
                    target_session.conn.queueSend(presence_xml) catch continue;
                    if (target_session.conn.hasPendingWrite()) {
                        changes.addWrite(target_session.conn.fd, tid) catch {};
                    }
                }
            }
        }

        log.info("{s}@{s}/{s} now unavailable", .{ local, domain, resource });
    }

    /// Send presence probes to contacts we're subscribed to (to get their current status).
    fn sendPresenceProbes(self: *Server, session: *Session, local: []const u8, domain: []const u8, changes: *ChangeList) void {
        _ = changes;
        const roster = self.roster orelse return;

        var bare_buf: [256]u8 = undefined;
        var bare_fbs = std.io.fixedBufferStream(&bare_buf);
        bare_fbs.writer().writeAll(local) catch return;
        bare_fbs.writer().writeByte('@') catch return;
        bare_fbs.writer().writeAll(domain) catch return;
        const bare_jid = bare_fbs.getWritten();

        // Get contacts whose presence we should receive (to/both)
        const contact_jids = roster.getPresenceSubscriptions(self.allocator, bare_jid) catch return;
        defer {
            for (contact_jids) |s| self.allocator.free(s);
            self.allocator.free(contact_jids);
        }

        // For each subscribed contact, check if they're online and send their presence
        for (contact_jids) |contact_bare| {
            const at_pos = std.mem.indexOf(u8, contact_bare, "@") orelse continue;
            const contact_local = contact_bare[0..at_pos];
            const contact_domain = contact_bare[at_pos + 1 ..];

            // If the contact has available sessions, send their presence to us
            var target_ids: [16]usize = undefined;
            const target_count = self.registry.findAvailableByBareJid(contact_local, contact_domain, &target_ids);
            if (target_count > 0) {
                // Send presence from contact to our session
                var pres_buf: [512]u8 = undefined;
                var pres_fbs = std.io.fixedBufferStream(&pres_buf);
                const pw = pres_fbs.writer();
                pw.writeAll("<presence from='") catch continue;
                pw.writeAll(contact_bare) catch continue;
                pw.writeAll("'/>") catch continue;
                session.conn.queueSend(pres_fbs.getWritten()) catch continue;
            }
        }
    }

    /// Send a service-unavailable error for a message that can't be delivered.
    fn sendServiceUnavailable(self: *Server, session: *Session, id_str: []const u8, to_str: []const u8, from_str: []const u8) void {
        _ = self;
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        w.writeAll("<message type='error'") catch return;
        if (id_str.len > 0) {
            w.writeAll(" id='") catch return;
            w.writeAll(id_str) catch return;
            w.writeByte('\'') catch return;
        }
        w.writeAll(" from='") catch return;
        w.writeAll(to_str) catch return;
        w.writeAll("' to='") catch return;
        w.writeAll(from_str) catch return;
        w.writeAll("'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
    }

    /// Deliver queued offline messages to a user who just became available.
    /// Uses the generic offline store (pointers) + archive store (payloads).
    fn deliverOfflineMessages(self: *Server, session: *Session, local: []const u8, domain: []const u8, changes: *ChangeList) void {
        const store = self.offline orelse return;
        const archive = self.archive orelse return;

        // Build bare JID for lookup
        var bare_buf: [256]u8 = undefined;
        var bare_fbs = std.io.fixedBufferStream(&bare_buf);
        bare_fbs.writer().writeAll(local) catch return;
        bare_fbs.writer().writeByte('@') catch return;
        bare_fbs.writer().writeAll(domain) catch return;
        const bare_jid = bare_fbs.getWritten();

        const count = store.countMessages(bare_jid) catch return;
        if (count == 0) return;

        // Retrieve pointers and deliver messages from archive
        const pointers = store.getPointers(bare_jid) catch return;
        defer store.freePointers(pointers);

        var delivered: usize = 0;
        for (pointers) |ptr| {
            // Fetch stanza XML from archive
            const stanza_xml = archive.getMessage(ptr.recipient, ptr.timestamp, ptr.stanza_id) catch continue;
            if (stanza_xml) |xml_data| {
                defer self.allocator.free(xml_data);
                session.conn.queueSend(xml_data) catch continue;
                delivered += 1;
            }
        }

        if (session.conn.hasPendingWrite()) {
            changes.addWrite(session.conn.fd, session.conn.id) catch {};
        }

        // Clear all delivered pointers
        store.clearAll(bare_jid) catch {};
        log.info("delivered {d} offline messages to {s}", .{ delivered, bare_jid });
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

    fn handleBind(self: *Server, session: *Session, resource: []const u8, _: *ChangeList) void {
        const action = session.stream.handleBind(resource);
        self.executeAction(session, action);

        if (session.stream.isActive()) {
            if (session.stream.bound_jid) |bound| {
                // Register in session registry (local — always)
                self.registry.bind(session.conn.id, bound.local, bound.domain, bound.resource) catch |err| {
                    log.err("connection {d} registry bind failed: {}", .{ session.conn.id, err });
                    return;
                };
                // Register in shared registry (cross-thread — when workers > 1)
                if (self.shared_registry) |sr| {
                    sr.bind(self.globalSessionId(session.conn.id), self.worker_id, bound.local, bound.domain, bound.resource) catch |err| {
                        log.err("connection {d} shared registry bind failed (rolling back local): {}", .{ session.conn.id, err });
                        _ = self.registry.unbind(session.conn.id);
                        return;
                    };
                }
                log.info("connection {d} session established: {s}@{s}/{s}", .{
                    session.conn.id, bound.local, bound.domain, bound.resource,
                });
            }
        }
    }

    // ========================================================================
    // Execute StreamAction — write XML responses
    // ========================================================================

    fn executeAction(self: *Server, session: *Session, action: xmpp.StreamAction) void {
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
                // Reset XML reader for post-SASL stream restart
                session.reader.reset();
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
                    self.closeSession(id, changes);
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

    /// Handle EVFILT_READ on the wake pipe — drain pipe bytes, then drain the MPSC queue.
    fn handleDeliveryWake(self: *Server, changes: *ChangeList) void {
        const ds = self.delivery_system orelse return;
        ds.drainPipe(self.worker_id);
        self.drainDeliveryQueue(changes);
    }

    /// Serialize a stanza and enqueue for cross-thread delivery via MPSC.
    fn enqueueCrossThreadStanza(
        self: *Server,
        route: shared_registry_mod.RoutingResult,
        from_str: []const u8,
        to_str: []const u8,
        type_str: []const u8,
        id_str: []const u8,
        inner_xml: []const u8,
        kind: StanzaKind,
    ) void {
        const ds = self.delivery_system orelse return;

        const tag_name: []const u8 = switch (kind) {
            .message => "message",
            .presence => "presence",
            .none => return,
        };

        // Serialize the full stanza into a buffer (must fit in MAX_PAYLOAD_SIZE)
        var buf: [delivery_queue_mod.MAX_PAYLOAD_SIZE]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        const w = fbs.writer();

        w.writeByte('<') catch return;
        w.writeAll(tag_name) catch return;
        w.writeAll(" from='") catch return;
        w.writeAll(from_str) catch return;
        w.writeAll("' to='") catch return;
        w.writeAll(to_str) catch return;
        w.writeByte('\'') catch return;
        if (type_str.len > 0) {
            if (!(kind == .message and std.mem.eql(u8, type_str, "normal"))) {
                w.writeAll(" type='") catch return;
                w.writeAll(type_str) catch return;
                w.writeByte('\'') catch return;
            }
        }
        if (id_str.len > 0) {
            w.writeAll(" id='") catch return;
            w.writeAll(id_str) catch return;
            w.writeByte('\'') catch return;
        }
        if (inner_xml.len == 0) {
            w.writeAll("/>") catch return;
        } else {
            w.writeByte('>') catch return;
            w.writeAll(inner_xml) catch return;
            w.writeAll("</") catch return;
            w.writeAll(tag_name) catch return;
            w.writeByte('>') catch return;
        }

        ds.deliver(route.worker_id, route.session_id, route.generation, fbs.getWritten()) catch |err| {
            log.warn("cross-thread delivery failed to worker {d} session {d}: {}", .{ route.worker_id, route.session_id, err });
        };
    }

    /// Drain all pending deliveries from this worker's MPSC queue.
    /// Validates generation (ABA protection) before delivering to local sessions.
    fn drainDeliveryQueue(self: *Server, changes: *ChangeList) void {
        const ds = self.delivery_system orelse return;
        const sr = self.shared_registry orelse return;
        const queue = ds.getQueue(self.worker_id);

        const Ctx = struct {
            server: *Server,
            changes: *ChangeList,
            registry: *SharedSessionRegistry,
            base: u32,
        };
        const ctx = Ctx{ .server = self, .changes = changes, .registry = sr, .base = self.session_id_base };

        _ = queue.drain(ctx, struct {
            fn handle(c: Ctx, session_id: u32, generation: u32, payload: []const u8) void {
                // ABA check: verify session is still bound with same generation
                const current_gen = c.registry.getGeneration(session_id) orelse return;
                if (current_gen != generation) return;

                // Convert global session ID back to local index for sessions[] lookup.
                // global = session_id_base + local → local = global - base
                const local_id = session_id - c.base;
                const target_session = c.server.sessions[local_id] orelse return;
                target_session.conn.queueSend(payload) catch return;
                if (target_session.conn.hasPendingWrite()) {
                    c.changes.addWrite(target_session.conn.fd, local_id) catch {};
                }
            }
        }.handle);
    }

    fn closeSession(self: *Server, id: usize, changes: *ChangeList) void {
        const session = self.sessions[id] orelse return;

        // Remove from all MUC rooms (broadcasts unavailable to room occupants)
        muc_handler.handleSessionClose(self, id, changes);

        // Unregister from shared registry (cross-thread — increments generation for ABA)
        if (self.shared_registry) |sr| {
            _ = sr.unbind(self.globalSessionId(id));
        }

        // Unregister from local session registry and broadcast unavailable presence
        if (self.registry.unbind(id)) |bound| {
            if (bound.presence_available) {
                self.broadcastUnavailable(bound.local, bound.domain, bound.resource, changes);
            }
        }

        // Remove from kqueue (closing fd does this implicitly, but be explicit)
        changes.removeRead(session.conn.fd) catch {};
        changes.removeWrite(session.conn.fd) catch {};

        session.deinit();
        self.allocator.destroy(session);
        self.sessions[id] = null;
    }

    /// Convert a local session ID to a global shared registry slot.
    /// Each worker's sessions are offset: global = session_id_base + local_id.
    fn globalSessionId(self: *const Server, local_id: usize) u32 {
        return self.session_id_base + @as(u32, @intCast(local_id));
    }

    fn allocateId(self: *Server) ?usize {
        // Linear scan for a free slot
        var i: usize = 0;
        while (i < self.max_sessions) : (i += 1) {
            const id = (self.next_id + i) % self.max_sessions;
            if (id == 0) continue; // Skip slot 0
            if (self.sessions[id] == null) {
                self.next_id = (id + 1) % self.max_sessions;
                return id;
            }
        }
        return null;
    }

    fn freeId(_: *Server, _: usize) void {
        // No-op — slot is freed in closeSession by setting to null
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
    server.acceptConnections(&changes);

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

    // Set up shared infrastructure (128 total slots for 2 workers × 64 each)
    var shared_reg = try SharedSessionRegistry.init(allocator, 128);
    defer shared_reg.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    // Create a server that acts as worker 1 (the one draining)
    // Worker 1 owns global slots 64..127 (base = 1 * 64 = 64)
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 1;
    server.session_id_base = 64; // worker 1 × 64 per_worker_sessions
    server.shared_registry = &shared_reg;
    server.delivery_system = &delivery_sys;

    // Create a target session on worker 1 using a socketpair
    // Local session ID = 5, global = 64 + 5 = 69
    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 5, "localhost", false, allocator);
    server.sessions[5] = session;

    // Bind in shared registry using GLOBAL session ID
    const global_id = server.globalSessionId(5);
    try std.testing.expectEqual(@as(u32, 69), global_id);
    try shared_reg.bind(global_id, 1, "bob", "localhost", "desktop");

    // Simulate a cross-thread enqueue FROM worker 0 TO session 69 on worker 1
    const route = shared_reg.findByFullJid("bob", "localhost", "desktop").?;
    try std.testing.expectEqual(@as(u16, 1), route.worker_id);
    try std.testing.expectEqual(@as(u32, 69), route.session_id);

    // Build a stanza and enqueue it (as if worker 0 is sending)
    try delivery_sys.deliver(route.worker_id, route.session_id, route.generation, "<message from='alice@localhost/mobile' to='bob@localhost' type='chat'><body>cross-thread!</body></message>");

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

    var shared_reg = try SharedSessionRegistry.init(allocator, 64);
    defer shared_reg.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();
    server.worker_id = 0;
    server.shared_registry = &shared_reg;
    server.delivery_system = &delivery_sys;

    // Bind a session, get its generation, then unbind (simulating disconnect)
    try shared_reg.bind(3, 0, "alice", "localhost", "mobile");
    const old_gen = shared_reg.findByFullJid("alice", "localhost", "mobile").?.generation;
    _ = shared_reg.unbind(3);

    // Enqueue with the OLD generation (stale delivery)
    try delivery_sys.deliver(0, 3, old_gen, "<message>stale</message>");

    // Drain — should silently drop (generation mismatch)
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.drainDeliveryQueue(&changes);

    // No session at slot 3, so nothing should crash or write
    try std.testing.expect(server.sessions[3] == null);
}
