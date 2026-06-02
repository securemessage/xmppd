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

const log = std.log.scoped(.xmppd);

/// Maximum simultaneous connections.
const MAX_SESSIONS = 1024;

/// Sentinel value for listener fd in kqueue udata.
const LISTENER_UDATA = std.math.maxInt(usize);

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

/// Per-connection session state. Bundles a Connection with its XML parser,
/// XMPP stream FSM, and SASL state.
const Session = struct {
    conn: Connection,
    reader: xml.Reader,
    stream: xmpp.Stream,
    scram: ?sasl.ScramServer = null,
    /// Buffer for building XML responses within a single event handler call.
    write_scratch: [4096]u8 = undefined,

    fn init(fd: posix.fd_t, id: usize, server_host: []const u8, direct_tls: bool, allocator: std.mem.Allocator) Session {
        return .{
            .conn = Connection.init(fd, id),
            .reader = xml.Reader.init(allocator),
            .stream = xmpp.Stream.init(server_host, direct_tls),
        };
    }

    fn deinit(self: *Session) void {
        self.reader.deinit();
        if (self.scram) |*s| s.deinit();
        if (!self.conn.isClosed()) self.conn.close();
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

    /// Hardcoded test credentials (Phase 5 only — auth daemon in Phase 6).
    test_creds: sasl.StoredCredentials,

    /// TLS context — shared across all connections. Null if TLS is not configured.
    ssl_ctx: ?ssl.SslContext = null,

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

        // Derive test credentials for hardcoded user
        const test_salt = [_]u8{0x42} ** 32;
        const test_creds = sasl.StoredCredentials.derive("testpassword", test_salt, 4096);

        return Server{
            .loop = loop,
            .listener = listener,
            .allocator = allocator,
            .server_host = host,
            .test_creds = test_creds,
        };
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
    }

    /// Run the main event loop. Blocks until SIGTERM or `stop()` is called.
    pub fn run(self: *Server) !void {
        var change_buf: [CHANGE_BUF_SIZE]posix.Kevent = undefined;
        var changes = ChangeList.init(&change_buf);

        // Initial registration: listener for read + SIGTERM
        try changes.addRead(self.listener.fd, LISTENER_UDATA);

        while (self.running) {
            const events = try self.loop.submitAndPoll(changes.slice(), null);
            changes.reset();

            for (events) |ev| {
                switch (ev) {
                    .fd_readable => |e| {
                        if (e.udata == LISTENER_UDATA) {
                            self.acceptConnections(&changes);
                        } else {
                            self.handleReadableOrHandshake(e.udata, &changes);
                        }
                    },
                    .fd_writable => |e| {
                        self.handleWritableOrHandshake(e.udata, &changes);
                    },
                    .signal => |s| {
                        if (s.signo == posix.SIG.TERM or s.signo == posix.SIG.INT) {
                            self.running = false;
                        }
                    },
                    .fd_error => |e| {
                        if (e.udata != LISTENER_UDATA) {
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
            // Reset XML reader for stream restart after STARTTLS
            session.reader.reset();
            // Ensure we're watching for reads (client will send new stream open)
            changes.addRead(session.conn.fd, id) catch {};
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
                // Handled by element_start for self-closing; stanza boundaries tracked by depth
            },
            .text => |text| {
                // Accumulate text content for current element (SASL auth/response base64 data)
                _ = text;
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
                // SCRAM response — text content will follow
                // For now, we handle it when we see the full stanza
                // TODO: accumulate text and process on element_end
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

        // Active state — stanzas
        if (session.stream.isActive()) {
            if (std.mem.eql(u8, elem.local_name, "message") or
                std.mem.eql(u8, elem.local_name, "presence") or
                std.mem.eql(u8, elem.local_name, "iq"))
            {
                // Phase 5: just log active stanzas
                log.info("connection {d} active stanza: <{s}>", .{ session.conn.id, elem.local_name });
            }
        }
    }

    // ========================================================================
    // SASL handling (in-process, hardcoded test user)
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
            .begin_sasl => |mech_name| {
                if (std.mem.eql(u8, mech_name, "PLAIN")) {
                    self.handleSaslPlain(session, elem);
                } else if (std.mem.eql(u8, mech_name, "SCRAM-SHA-256")) {
                    self.handleSaslScramInit(session, elem);
                } else {
                    // Unsupported mechanism
                    const fail_action = session.stream.saslFailure();
                    self.executeAction(session, fail_action);
                }
            },
            else => self.executeAction(session, action),
        }
    }

    fn handleSaslPlain(self: *Server, session: *Session, elem: xml.Element) void {
        // For PLAIN, the initial response is in the element content.
        // In a self-closing <auth/> there's no content — that's an error.
        // For now, check if we can find inline base64 in attributes (simplified).
        // TODO: Proper text content accumulation from element_start → text → element_end
        _ = elem;

        // PLAIN auth with hardcoded test user
        // In a real implementation, we'd decode the base64 content.
        // For Phase 5, accept any PLAIN auth as "testuser"
        const success_action = session.stream.saslSuccess("testuser", "");
        self.executeAction(session, success_action);
    }

    fn handleSaslScramInit(self: *Server, session: *Session, _: xml.Element) void {
        // TODO: Decode base64 initial response from element text content
        // For Phase 5, we create the SCRAM server but can't process without
        // the actual base64 text content (requires text accumulation).
        // Send a placeholder failure for now.
        _ = self;
        _ = session.stream.saslFailure();
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const writer = fbs.writer();
        writer.writeAll("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><temporary-auth-failure/></failure>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
    }

    fn handleBind(self: *Server, session: *Session, _: xml.Element, _: *ChangeList) void {
        // Extract requested resource from bind element
        // TODO: parse <resource>name</resource> child element
        const action = session.stream.handleBind("");
        self.executeAction(session, action);

        if (session.stream.isActive()) {
            log.info("connection {d} session established: {s}", .{
                session.conn.id,
                if (session.stream.bound_jid) |jid| jid.local else "unknown",
            });
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
