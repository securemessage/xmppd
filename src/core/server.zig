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

const log = std.log.scoped(.xmppd);

/// Maximum simultaneous connections.
const MAX_SESSIONS = 1024;

/// Sentinel value for listener fd in kqueue udata.
const LISTENER_UDATA = std.math.maxInt(usize);

/// Sentinel value for auth IPC fd in kqueue udata.
const IPC_AUTH_UDATA = LISTENER_UDATA - 1;

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
    /// Which SASL element we're collecting text content for.
    sasl_collecting: SaslCollecting = .none,
    /// Buffer for accumulating SASL text content (base64 from XML).
    sasl_buf: [4096]u8 = undefined,
    sasl_buf_len: usize = 0,
    /// Mechanism name from the last <auth> element.
    sasl_mechanism: []const u8 = "",

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

    /// Session registry — maps bound JIDs to session IDs.
    registry: SessionRegistry = .{},

    /// Roster store — per-user contact lists with subscription states.
    roster: ?*RosterStore = null,

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
                        } else {
                            self.handleReadableOrHandshake(e.udata, &changes);
                        }
                    },
                    .fd_writable => |e| {
                        if (e.udata == IPC_AUTH_UDATA) {
                            self.flushIpc(&changes);
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
                        if (e.udata != LISTENER_UDATA and e.udata != IPC_AUTH_UDATA) {
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
            // Try reading immediately to drain any buffered TLS app data.
            self.handleReadable(id, changes);

            // If the session is still alive and we didn't get data yet,
            // ensure kqueue will notify us when new data arrives.
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

            if (session.conn.isClosed()) break;
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
            .element_end => {
                self.handleElementEnd(session, changes);
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

        // Bind namespace
        if (std.mem.eql(u8, ns, xml.ns.bind)) {
            if (std.mem.eql(u8, elem.local_name, "bind")) {
                self.handleBind(session, elem, changes);
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
        _ = self;
        if (session.sasl_collecting == .none) return;

        // Accumulate text into SASL buffer
        const remaining = session.sasl_buf.len - session.sasl_buf_len;
        const to_copy = @min(text.len, remaining);
        if (to_copy > 0) {
            @memcpy(session.sasl_buf[session.sasl_buf_len .. session.sasl_buf_len + to_copy], text[0..to_copy]);
            session.sasl_buf_len += to_copy;
        }
    }

    fn handleElementEnd(self: *Server, session: *Session, changes: *ChangeList) void {
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

                const success_action = session.stream.saslSuccess(m.username, server_final_b64);
                self.executeAction(session, success_action);
                session.resetSasl();

                if (session.conn.hasPendingWrite()) {
                    changes.addWrite(session.conn.fd, conn_id) catch {};
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
    // Stanza handlers (Phase 7: message routing + presence + IQ)
    // ========================================================================

    fn handleMessage(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
        // Extract 'to' attribute for routing
        var to_str: []const u8 = "";
        var id_str: []const u8 = "";
        var type_str: []const u8 = "normal";
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "to")) to_str = attr.value;
            if (std.mem.eql(u8, attr.local_name, "id")) id_str = attr.value;
            if (std.mem.eql(u8, attr.local_name, "type")) type_str = attr.value;
        }

        if (to_str.len == 0) {
            // Messages without 'to' are handled by the server (ignored for now)
            return;
        }

        // Parse target JID
        const to_jid = xmpp.Jid.parse(to_str) catch {
            log.warn("connection {d} message with invalid 'to': {s}", .{ session.conn.id, to_str });
            return;
        };

        // Get the sender's bound JID
        const from_jid = session.stream.bound_jid orelse return;

        // Build the from string
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

        // Route: find target session(s)
        // If full JID specified, deliver to that resource; otherwise deliver to all available
        var target_ids: [16]usize = undefined;
        const target_count = if (to_jid.resource.len > 0)
            // Full JID — find specific resource
            blk: {
                if (self.registry.findByFullJid(to_jid.local, to_jid.domain, to_jid.resource)) |entry| {
                    target_ids[0] = entry.id;
                    break :blk @as(usize, 1);
                }
                break :blk @as(usize, 0);
            } else
            // Bare JID — deliver to all available resources
            self.registry.findAvailableByBareJid(to_jid.local, to_jid.domain, &target_ids);

        if (target_count == 0) {
            // TODO: offline message storage. For now, bounce with error.
            log.info("connection {d} message to {s} — recipient unavailable", .{ session.conn.id, to_str });
            self.sendServiceUnavailable(session, id_str, to_str, from_str);
            if (session.conn.hasPendingWrite()) {
                changes.addWrite(session.conn.fd, session.conn.id) catch {};
            }
            return;
        }

        // Forward the message to target session(s) — rewrite 'from' to sender's full JID
        for (target_ids[0..target_count]) |tid| {
            const target_session = self.sessions[tid] orelse continue;
            var msg_buf: [4096]u8 = undefined;
            var msg_fbs = std.io.fixedBufferStream(&msg_buf);
            const mw = msg_fbs.writer();
            mw.writeAll("<message from='") catch continue;
            mw.writeAll(from_str) catch continue;
            mw.writeAll("' to='") catch continue;
            mw.writeAll(to_str) catch continue;
            mw.writeByte('\'') catch continue;
            if (!std.mem.eql(u8, type_str, "normal")) {
                mw.writeAll(" type='") catch continue;
                mw.writeAll(type_str) catch continue;
                mw.writeByte('\'') catch continue;
            }
            if (id_str.len > 0) {
                mw.writeAll(" id='") catch continue;
                mw.writeAll(id_str) catch continue;
                mw.writeByte('\'') catch continue;
            }
            // For now, self-close (we don't yet accumulate body).
            // TODO: Phase 7 refinement — accumulate full stanza XML and forward verbatim
            mw.writeAll("/>") catch continue;
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

    fn handleBind(self: *Server, session: *Session, _: xml.Element, _: *ChangeList) void {
        // Extract requested resource from bind element
        // TODO: parse <resource>name</resource> child element
        const action = session.stream.handleBind("");
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
                writer.writeAll("<iq type='result' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>") catch return;
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

/// Decode base64 into a fixed buffer. Returns the decoded slice or null on error.
fn b64Decode(input: []const u8, output: []u8) ?[]const u8 {
    const decoder = std.base64.standard.Decoder;
    const upper_bound = decoder.calcSizeUpperBound(input.len) catch return null;
    if (upper_bound > output.len) return null;
    decoder.decode(output[0..upper_bound], input) catch return null;
    return output[0..upper_bound];
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
