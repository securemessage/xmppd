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
const RosterStore = @import("roster_store").RosterStore;
const SessionRegistry = @import("session_registry").SessionRegistry;
const offline_store_mod = @import("offline_store");
const OfflineStore = offline_store_mod.OfflineStore;
const OfflineMessage = offline_store_mod.OfflineMessage;

const log = std.log.scoped(.xmppd);

/// Maximum simultaneous connections.
const MAX_SESSIONS = 1024;

/// Sentinel value for listener fd in kqueue udata.
const LISTENER_UDATA = std.math.maxInt(usize);

/// Sentinel value for auth IPC fd in kqueue udata.
const IPC_AUTH_UDATA = LISTENER_UDATA - 1;

/// Sentinel value for S2S IPC fd in kqueue udata.
const IPC_S2S_UDATA = LISTENER_UDATA - 2;

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

/// Per-connection session state. Bundles a Connection with its XML parser,
/// XMPP stream FSM, and SASL state.
const Session = struct {
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
    iq_child_ns: []const u8 = "",
    iq_child_name: []const u8 = "",
    /// Roster item attributes from <item> inside roster query.
    iq_roster_item_jid: []const u8 = "",
    iq_roster_item_name: []const u8 = "",
    iq_roster_item_sub: []const u8 = "",

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

    /// Session table — indexed by session ID.
    sessions: [MAX_SESSIONS]?*Session = [_]?*Session{null} ** MAX_SESSIONS,
    next_id: usize = 1, // 0 reserved

    /// TLS context — shared across all connections. Null if TLS is not configured.
    ssl_ctx: ?ssl.SslContext = null,

    /// IPC client for auth daemon communication.
    ipc: IpcClient = .{},

    /// IPC client for S2S daemon communication (federation).
    s2s_ipc: IpcClient = .{},

    /// Session registry — maps bound JIDs to session IDs.
    registry: SessionRegistry = .{},

    /// Roster store — per-user contact lists with subscription states.
    roster: ?*RosterStore = null,

    /// Offline message store — messages for unavailable recipients.
    offline: ?*OfflineStore = null,

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
        const loop = try EventLoop.init(allocator, 256);
        errdefer {
            var l = loop;
            l.deinit();
        }

        const listener = try Listener.init(address, port, false, 128);

        return Server{
            .loop = loop,
            .listener = listener,
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

    /// Configure the roster store. The roster file lives in the same
    /// directory as the user database.
    pub fn configureRoster(self: *Server, roster_store: *RosterStore) void {
        self.roster = roster_store;
        log.info("roster store configured ({d} items)", .{roster_store.items.items.len});
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

    /// Configure the offline message store.
    pub fn configureOffline(self: *Server, offline_store: *OfflineStore) void {
        self.offline = offline_store;
        log.info("offline store configured ({d} pending messages)", .{offline_store.messages.items.len});
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
        for (&self.sessions) |*slot| {
            if (slot.*) |session| {
                session.deinit();
                self.allocator.destroy(session);
                slot.* = null;
            }
        }
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

        while (self.running) {
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
                        if (e.udata != LISTENER_UDATA and e.udata != IPC_AUTH_UDATA and e.udata != IPC_S2S_UDATA) {
                            self.closeSession(e.udata, &changes);
                        }
                    },
                    else => {},
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
                log.warn("connection limit reached ({d})", .{MAX_SESSIONS});
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

        // Send AuthRequest to auth daemon
        self.ipc.send(.{
            .auth_request = .{
                .conn_id = @intCast(session.conn.id),
                .mechanism = mech_id,
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

    fn dispatchAuthResponse(self: *Server, msg: ipc_protocol.Message, changes: *ChangeList) void {
        const conn_id: usize = switch (msg) {
            .auth_challenge => |m| m.conn_id,
            .auth_success => |m| m.conn_id,
            .auth_failure => |m| m.conn_id,
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
            else => {},
        }
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
                    // Try offline storage for messages
                    if (self.offline) |store| {
                        var recip_buf: [256]u8 = undefined;
                        var recip_fbs = std.io.fixedBufferStream(&recip_buf);
                        recip_fbs.writer().writeAll(to_jid.local) catch {};
                        recip_fbs.writer().writeByte('@') catch {};
                        recip_fbs.writer().writeAll(to_jid.domain) catch {};
                        const recipient_bare = recip_fbs.getWritten();

                        // For S2S inbound, stanza_xml is the complete stanza —
                        // store it using the from/to from the IPC message.
                        if (store.storeMessage(recipient_bare, m.from_jid, "", "", m.stanza_xml)) {
                            log.info("S2S inbound to {s} stored offline", .{m.to_jid});
                            return;
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

        // Remote domain? Forward via S2S IPC instead of local delivery.
        if (!std.mem.eql(u8, to_jid.domain, self.server_host)) {
            self.forwardToS2s(session, from_str, to_str, type_str, id_str, inner_xml, changes);
            return;
        }

        // Route: find target session(s)
        var target_ids: [16]usize = undefined;
        const target_count = if (to_jid.resource.len > 0) blk: {
            if (self.registry.findByFullJid(to_jid.local, to_jid.domain, to_jid.resource)) |entry| {
                target_ids[0] = entry.id;
                break :blk @as(usize, 1);
            }
            break :blk @as(usize, 0);
        } else self.registry.findAvailableByBareJid(to_jid.local, to_jid.domain, &target_ids);

        if (target_count == 0) {
            // Only messages get offline storage (not presence stanzas)
            if (session.stanza_kind == .message) {
                if (self.offline) |store| {
                    // Build recipient bare JID
                    var recip_buf: [256]u8 = undefined;
                    var recip_fbs = std.io.fixedBufferStream(&recip_buf);
                    recip_fbs.writer().writeAll(to_jid.local) catch {};
                    recip_fbs.writer().writeByte('@') catch {};
                    recip_fbs.writer().writeAll(to_jid.domain) catch {};
                    const recipient_bare = recip_fbs.getWritten();

                    if (store.storeMessage(recipient_bare, from_str, type_str, id_str, inner_xml)) {
                        log.info("connection {d} message to {s} stored offline", .{ session.conn.id, to_str });
                        return;
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

        // Forward to each target session
        for (target_ids[0..target_count]) |tid| {
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
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "type")) {
                type_str = attr.value;
                break;
            }
        }

        const ptype = xmpp.PresenceType.fromString(type_str);
        const bound = session.stream.bound_jid orelse return;

        switch (ptype) {
            .available => {
                // Initial presence — mark session as available, broadcast to subscribers
                self.registry.setPresenceAvailable(session.conn.id, true);
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
        const Subscription = @import("roster_store").Subscription;

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
        if (roster.getItemMut(owner_bare, to_str)) |item| {
            item.ask = "subscribe";
        } else {
            roster.setItem(owner_bare, to_str, "", Subscription.none, "subscribe") catch return;
        }
        roster.save() catch {};

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
        const Subscription = @import("roster_store").Subscription;

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
        if (roster.getItemMut(owner_bare, to_str)) |item| {
            item.subscription = switch (item.subscription) {
                .none => Subscription.from,
                .to => Subscription.both,
                else => item.subscription,
            };
            item.ask = "";
        } else {
            roster.setItem(owner_bare, to_str, "", Subscription.from, "") catch return;
        }

        // Update contact's roster: their subscription gains "to" direction
        if (roster.getItemMut(to_str, owner_bare)) |item| {
            item.subscription = switch (item.subscription) {
                .none => Subscription.to,
                .from => Subscription.both,
                else => item.subscription,
            };
            item.ask = "";
        } else {
            roster.setItem(to_str, owner_bare, "", Subscription.to, "") catch {};
        }
        roster.save() catch {};

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
        const Subscription = @import("roster_store").Subscription;

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
        if (roster.getItemMut(owner_bare, to_str)) |item| {
            item.subscription = switch (item.subscription) {
                .to => Subscription.none,
                .both => Subscription.from,
                else => item.subscription,
            };
        }

        // Update contact's roster: remove "from" direction
        if (roster.getItemMut(to_str, owner_bare)) |item| {
            item.subscription = switch (item.subscription) {
                .from => Subscription.none,
                .both => Subscription.to,
                else => item.subscription,
            };
        }
        roster.save() catch {};

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
        const Subscription = @import("roster_store").Subscription;

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
        if (roster.getItemMut(owner_bare, to_str)) |item| {
            item.subscription = switch (item.subscription) {
                .from => Subscription.none,
                .both => Subscription.to,
                else => item.subscription,
            };
        }

        // Update contact's roster: remove "to" direction
        if (roster.getItemMut(to_str, owner_bare)) |item| {
            item.subscription = switch (item.subscription) {
                .to => Subscription.none,
                .both => Subscription.from,
                else => item.subscription,
            };
            item.ask = "";
        }
        roster.save() catch {};

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
        // Start IQ accumulation — dispatch happens on element_end at stanza depth
        session.iq_active = true;
        session.iq_child_ns = "";
        session.iq_child_name = "";
        session.iq_roster_item_jid = "";
        session.iq_roster_item_name = "";
        session.iq_roster_item_sub = "";

        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "type")) session.iq_type = attr.value;
            if (std.mem.eql(u8, attr.local_name, "id")) session.iq_id = attr.value;
        }
    }

    /// Handle child elements inside an IQ stanza (query, item, etc.)
    fn handleIqChild(self: *Server, session: *Session, elem: xml.Element) void {
        _ = self;
        const ns = elem.namespace_uri;

        if (std.mem.eql(u8, elem.local_name, "query")) {
            session.iq_child_ns = ns;
            session.iq_child_name = elem.local_name;
        } else if (std.mem.eql(u8, elem.local_name, "item") and std.mem.eql(u8, ns, xml.ns.roster)) {
            // Roster item inside <query xmlns='jabber:iq:roster'>
            for (elem.attributes) |attr| {
                if (std.mem.eql(u8, attr.local_name, "jid")) session.iq_roster_item_jid = attr.value;
                if (std.mem.eql(u8, attr.local_name, "name")) session.iq_roster_item_name = attr.value;
                if (std.mem.eql(u8, attr.local_name, "subscription")) session.iq_roster_item_sub = attr.value;
            }
        } else if (std.mem.eql(u8, elem.local_name, "ping") and std.mem.eql(u8, ns, xml.ns.ping)) {
            session.iq_child_ns = ns;
            session.iq_child_name = elem.local_name;
        } else if (session.iq_child_ns.len == 0) {
            // First child element determines the IQ payload namespace
            session.iq_child_ns = ns;
            session.iq_child_name = elem.local_name;
        }
    }

    /// Dispatch a complete IQ stanza based on accumulated state.
    fn dispatchIq(self: *Server, session: *Session, changes: *ChangeList) void {
        defer {
            session.iq_active = false;
            session.iq_type = "";
            session.iq_id = "";
            session.iq_child_ns = "";
            session.iq_child_name = "";
            session.iq_roster_item_jid = "";
            session.iq_roster_item_name = "";
            session.iq_roster_item_sub = "";
        }

        const iq_type = session.iq_type;
        const iq_id = session.iq_id;
        const child_ns = session.iq_child_ns;

        // Roster query
        if (std.mem.eql(u8, child_ns, xml.ns.roster)) {
            if (std.mem.eql(u8, iq_type, "get")) {
                self.handleRosterGet(session, iq_id, changes);
                return;
            } else if (std.mem.eql(u8, iq_type, "set")) {
                self.handleRosterSet(session, iq_id, changes);
                return;
            }
        }

        // Service Discovery — disco#info (XEP-0030)
        if (std.mem.eql(u8, child_ns, xml.ns.disco_info) and std.mem.eql(u8, iq_type, "get")) {
            var fbs = std.io.fixedBufferStream(&session.write_scratch);
            const w = fbs.writer();
            w.writeAll("<iq type='result'") catch return;
            if (iq_id.len > 0) {
                w.writeAll(" id='") catch return;
                w.writeAll(iq_id) catch return;
                w.writeByte('\'') catch return;
            }
            w.writeAll("><query xmlns='http://jabber.org/protocol/disco#info'>") catch return;
            w.writeAll("<identity category='server' type='im' name='xmppd'/>") catch return;
            w.writeAll("<feature var='http://jabber.org/protocol/disco#info'/>") catch return;
            w.writeAll("<feature var='http://jabber.org/protocol/disco#items'/>") catch return;
            w.writeAll("<feature var='urn:xmpp:ping'/>") catch return;
            w.writeAll("<feature var='jabber:iq:roster'/>") catch return;
            w.writeAll("<feature var='vcard-temp'/>") catch return;
            w.writeAll("<feature var='jabber:iq:version'/>") catch return;
            w.writeAll("<feature var='msgoffline'/>") catch return;
            w.writeAll("</query></iq>") catch return;
            session.conn.queueSend(fbs.getWritten()) catch return;
            return;
        }

        // Service Discovery — disco#items (XEP-0030)
        if (std.mem.eql(u8, child_ns, xml.ns.disco_items) and std.mem.eql(u8, iq_type, "get")) {
            var fbs = std.io.fixedBufferStream(&session.write_scratch);
            const w = fbs.writer();
            w.writeAll("<iq type='result'") catch return;
            if (iq_id.len > 0) {
                w.writeAll(" id='") catch return;
                w.writeAll(iq_id) catch return;
                w.writeByte('\'') catch return;
            }
            w.writeAll("><query xmlns='http://jabber.org/protocol/disco#items'/></iq>") catch return;
            session.conn.queueSend(fbs.getWritten()) catch return;
            return;
        }

        // XMPP Ping (XEP-0199)
        if (std.mem.eql(u8, child_ns, xml.ns.ping) and std.mem.eql(u8, iq_type, "get")) {
            var fbs = std.io.fixedBufferStream(&session.write_scratch);
            const w = fbs.writer();
            w.writeAll("<iq type='result'") catch return;
            if (iq_id.len > 0) {
                w.writeAll(" id='") catch return;
                w.writeAll(iq_id) catch return;
                w.writeByte('\'') catch return;
            }
            w.writeAll("/>") catch return;
            session.conn.queueSend(fbs.getWritten()) catch return;
            return;
        }

        // Legacy session establishment (urn:ietf:params:xml:ns:xmpp-session)
        if (std.mem.eql(u8, child_ns, xml.ns.session) or
            (std.mem.eql(u8, iq_type, "set") and child_ns.len == 0))
        {
            var fbs = std.io.fixedBufferStream(&session.write_scratch);
            const w = fbs.writer();
            w.writeAll("<iq type='result'") catch return;
            if (iq_id.len > 0) {
                w.writeAll(" id='") catch return;
                w.writeAll(iq_id) catch return;
                w.writeByte('\'') catch return;
            }
            w.writeAll("/>") catch return;
            session.conn.queueSend(fbs.getWritten()) catch return;
            return;
        }

        // vCard-temp (XEP-0054) — return empty vCard
        if (std.mem.eql(u8, child_ns, xml.ns.vcard_temp) and std.mem.eql(u8, iq_type, "get")) {
            var fbs = std.io.fixedBufferStream(&session.write_scratch);
            const w = fbs.writer();
            w.writeAll("<iq type='result'") catch return;
            if (iq_id.len > 0) {
                w.writeAll(" id='") catch return;
                w.writeAll(iq_id) catch return;
                w.writeByte('\'') catch return;
            }
            w.writeAll("><vCard xmlns='vcard-temp'/></iq>") catch return;
            session.conn.queueSend(fbs.getWritten()) catch return;
            return;
        }

        // Software Version (XEP-0092)
        if (std.mem.eql(u8, child_ns, xml.ns.version) and std.mem.eql(u8, iq_type, "get")) {
            var fbs = std.io.fixedBufferStream(&session.write_scratch);
            const w = fbs.writer();
            w.writeAll("<iq type='result'") catch return;
            if (iq_id.len > 0) {
                w.writeAll(" id='") catch return;
                w.writeAll(iq_id) catch return;
                w.writeByte('\'') catch return;
            }
            w.writeAll("><query xmlns='jabber:iq:version'>") catch return;
            w.writeAll("<name>xmppd</name>") catch return;
            w.writeAll("<version>0.1.0</version>") catch return;
            w.writeAll("<os>FreeBSD</os>") catch return;
            w.writeAll("</query></iq>") catch return;
            session.conn.queueSend(fbs.getWritten()) catch return;
            return;
        }

        // Unknown IQ — return empty result for 'get', ack for 'set'
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        w.writeAll("<iq type='result'") catch return;
        if (iq_id.len > 0) {
            w.writeAll(" id='") catch return;
            w.writeAll(iq_id) catch return;
            w.writeByte('\'') catch return;
        }
        w.writeAll("/>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
    }

    /// Handle IQ roster get — return the user's roster.
    fn handleRosterGet(self: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
        _ = changes;
        const roster = self.roster orelse {
            // No roster configured — return empty roster
            var fbs = std.io.fixedBufferStream(&session.write_scratch);
            const w = fbs.writer();
            w.writeAll("<iq type='result'") catch return;
            if (iq_id.len > 0) {
                w.writeAll(" id='") catch return;
                w.writeAll(iq_id) catch return;
                w.writeByte('\'') catch return;
            }
            w.writeAll("><query xmlns='jabber:iq:roster'/></iq>") catch return;
            session.conn.queueSend(fbs.getWritten()) catch return;
            return;
        };

        const bound = session.stream.bound_jid orelse return;

        // Build bare JID for roster lookup
        var bare_buf: [256]u8 = undefined;
        var bare_fbs = std.io.fixedBufferStream(&bare_buf);
        bare_fbs.writer().writeAll(bound.local) catch return;
        bare_fbs.writer().writeByte('@') catch return;
        bare_fbs.writer().writeAll(bound.domain) catch return;
        const bare_jid = bare_fbs.getWritten();

        // Build roster response
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        w.writeAll("<iq type='result'") catch return;
        if (iq_id.len > 0) {
            w.writeAll(" id='") catch return;
            w.writeAll(iq_id) catch return;
            w.writeByte('\'') catch return;
        }
        w.writeAll("><query xmlns='jabber:iq:roster'>") catch return;

        // Add each roster item
        for (roster.items.items) |item| {
            if (!std.mem.eql(u8, item.owner, bare_jid)) continue;
            w.writeAll("<item jid='") catch return;
            w.writeAll(item.jid) catch return;
            w.writeByte('\'') catch return;
            if (item.name.len > 0) {
                w.writeAll(" name='") catch return;
                w.writeAll(item.name) catch return;
                w.writeByte('\'') catch return;
            }
            w.writeAll(" subscription='") catch return;
            w.writeAll(item.subscription.toString()) catch return;
            w.writeByte('\'') catch return;
            if (item.ask.len > 0) {
                w.writeAll(" ask='") catch return;
                w.writeAll(item.ask) catch return;
                w.writeByte('\'') catch return;
            }
            w.writeAll("/>") catch return;
        }

        w.writeAll("</query></iq>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
    }

    /// Handle IQ roster set — add/update/remove a roster item.
    fn handleRosterSet(self: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
        _ = changes;
        const roster = self.roster orelse {
            self.sendIqError(session, iq_id, "item-not-found");
            return;
        };

        const bound = session.stream.bound_jid orelse return;
        const item_jid = session.iq_roster_item_jid;
        if (item_jid.len == 0) {
            self.sendIqError(session, iq_id, "bad-request");
            return;
        }

        // Build bare JID for roster lookup
        var bare_buf: [256]u8 = undefined;
        var bare_fbs = std.io.fixedBufferStream(&bare_buf);
        bare_fbs.writer().writeAll(bound.local) catch return;
        bare_fbs.writer().writeByte('@') catch return;
        bare_fbs.writer().writeAll(bound.domain) catch return;
        const bare_jid = bare_fbs.getWritten();

        const item_sub = session.iq_roster_item_sub;
        const Subscription = @import("roster_store").Subscription;

        if (std.mem.eql(u8, item_sub, "remove")) {
            // Remove roster item
            _ = roster.removeItem(bare_jid, item_jid);
            roster.save() catch {};
        } else {
            // Add or update
            const sub = if (roster.getItem(bare_jid, item_jid)) |existing|
                existing.subscription
            else
                Subscription.none;
            roster.setItem(bare_jid, item_jid, session.iq_roster_item_name, sub, "") catch {
                self.sendIqError(session, iq_id, "internal-server-error");
                return;
            };
            roster.save() catch {};
        }

        // Ack with result
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        w.writeAll("<iq type='result'") catch return;
        if (iq_id.len > 0) {
            w.writeAll(" id='") catch return;
            w.writeAll(iq_id) catch return;
            w.writeByte('\'') catch return;
        }
        w.writeAll("/>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
    }

    fn sendIqError(self: *Server, session: *Session, iq_id: []const u8, condition: []const u8) void {
        _ = self;
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        w.writeAll("<iq type='error'") catch return;
        if (iq_id.len > 0) {
            w.writeAll(" id='") catch return;
            w.writeAll(iq_id) catch return;
            w.writeByte('\'') catch return;
        }
        w.writeAll("><error type='cancel'><") catch return;
        w.writeAll(condition) catch return;
        w.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
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
        var subscriber_jids: [128][]const u8 = undefined;
        const sub_count = roster.getPresenceSubscribers(bare_jid, &subscriber_jids);

        // Build presence stanza
        var pres_buf: [512]u8 = undefined;
        var pres_fbs = std.io.fixedBufferStream(&pres_buf);
        const pw = pres_fbs.writer();
        pw.writeAll("<presence from='") catch return;
        pw.writeAll(from_str) catch return;
        pw.writeAll("'/>") catch return;
        const presence_xml = pres_fbs.getWritten();

        // Deliver to each subscriber that has an active session
        for (subscriber_jids[0..sub_count]) |sub_bare_jid| {
            // Parse the subscriber bare JID to get local/domain
            const at_pos = std.mem.indexOf(u8, sub_bare_jid, "@") orelse continue;
            const sub_local = sub_bare_jid[0..at_pos];
            const sub_domain = sub_bare_jid[at_pos + 1 ..];

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

        var subscriber_jids: [128][]const u8 = undefined;
        const sub_count = roster.getPresenceSubscribers(bare_jid, &subscriber_jids);

        var pres_buf: [512]u8 = undefined;
        var pres_fbs = std.io.fixedBufferStream(&pres_buf);
        const pw = pres_fbs.writer();
        pw.writeAll("<presence from='") catch return;
        pw.writeAll(from_str) catch return;
        pw.writeAll("' type='unavailable'/>") catch return;
        const presence_xml = pres_fbs.getWritten();

        for (subscriber_jids[0..sub_count]) |sub_bare_jid| {
            const at_pos = std.mem.indexOf(u8, sub_bare_jid, "@") orelse continue;
            const sub_local = sub_bare_jid[0..at_pos];
            const sub_domain = sub_bare_jid[at_pos + 1 ..];

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
        var contact_jids: [128][]const u8 = undefined;
        const count = roster.getPresenceSubscriptions(bare_jid, &contact_jids);

        // For each subscribed contact, check if they're online and send their presence
        for (contact_jids[0..count]) |contact_bare| {
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
    fn deliverOfflineMessages(self: *Server, session: *Session, local: []const u8, domain: []const u8, changes: *ChangeList) void {
        const store = self.offline orelse return;

        // Build bare JID for lookup
        var bare_buf: [256]u8 = undefined;
        var bare_fbs = std.io.fixedBufferStream(&bare_buf);
        bare_fbs.writer().writeAll(local) catch return;
        bare_fbs.writer().writeByte('@') catch return;
        bare_fbs.writer().writeAll(domain) catch return;
        const bare_jid = bare_fbs.getWritten();

        const count = store.countMessages(bare_jid);
        if (count == 0) return;

        // Retrieve and deliver messages (max 100 per user)
        var msg_buf: [100]OfflineMessage = undefined;
        const msg_count = store.getMessages(bare_jid, &msg_buf);

        for (msg_buf[0..msg_count]) |msg| {
            // Build the full <message> stanza for delivery
            var out_buf: [20480]u8 = undefined;
            var out_fbs = std.io.fixedBufferStream(&out_buf);
            const w = out_fbs.writer();

            w.writeAll("<message from='") catch continue;
            w.writeAll(msg.from) catch continue;
            w.writeAll("' to='") catch continue;
            w.writeAll(bare_jid) catch continue;
            w.writeByte('\'') catch continue;
            if (msg.msg_type.len > 0 and !std.mem.eql(u8, msg.msg_type, "normal")) {
                w.writeAll(" type='") catch continue;
                w.writeAll(msg.msg_type) catch continue;
                w.writeByte('\'') catch continue;
            }
            if (msg.msg_id.len > 0) {
                w.writeAll(" id='") catch continue;
                w.writeAll(msg.msg_id) catch continue;
                w.writeByte('\'') catch continue;
            }

            if (msg.inner_xml.len == 0) {
                w.writeAll("/>") catch continue;
            } else {
                w.writeByte('>') catch continue;
                w.writeAll(msg.inner_xml) catch continue;
                // Add delay stamp (XEP-0203) to indicate this is a delayed message
                w.writeAll("<delay xmlns='urn:xmpp:delay' from='") catch continue;
                w.writeAll(self.server_host) catch continue;
                w.writeAll("' stamp='") catch continue;
                self.writeTimestamp(w, msg.timestamp) catch continue;
                w.writeAll("'/>") catch continue;
                w.writeAll("</message>") catch continue;
            }

            session.conn.queueSend(out_fbs.getWritten()) catch continue;
        }

        if (session.conn.hasPendingWrite()) {
            changes.addWrite(session.conn.fd, session.conn.id) catch {};
        }

        // Clear delivered messages
        store.clearMessages(bare_jid);
        log.info("delivered {d} offline messages to {s}", .{ msg_count, bare_jid });
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
                // Register in session registry
                self.registry.bind(session.conn.id, bound.local, bound.domain, bound.resource) catch |err| {
                    log.err("connection {d} registry bind failed: {}", .{ session.conn.id, err });
                    return;
                };
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
                    xmpp.stream.writeFeatures(fbs2.writer(), features) catch return;
                    session.conn.queueSend(fbs2.getWritten()) catch return;
                }
            },
            .send_features => |features| {
                xmpp.stream.writeFeatures(writer, features) catch return;
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

    fn closeSession(self: *Server, id: usize, changes: *ChangeList) void {
        const session = self.sessions[id] orelse return;

        // Unregister from session registry and broadcast unavailable presence
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

    fn allocateId(self: *Server) ?usize {
        // Linear scan for a free slot
        var i: usize = 0;
        while (i < MAX_SESSIONS) : (i += 1) {
            const id = (self.next_id + i) % MAX_SESSIONS;
            if (id == 0) continue; // Skip slot 0
            if (self.sessions[id] == null) {
                self.next_id = (id + 1) % MAX_SESSIONS;
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
