//! # xmppd-s2s — Server-to-Server federation daemon
//!
//! Separate process that handles S2S (server-to-server) XMPP federation.
//! Communicates with xmppd-core via Unix domain socket IPC.
//!
//! ## Architecture
//!
//! ```
//! xmppd-core ──IPC──→ xmppd-s2s ──TCP/TLS──→ remote XMPP server
//!                           │
//!                    inbound listener (:5269)
//!                           │
//!             remote XMPP server ──TCP/TLS──→ xmppd-s2s ──IPC──→ xmppd-core
//! ```
//!
//! ## Usage
//!
//! ```sh
//! xmppd-s2s --host example.com --port 5269 \
//!           --cert /etc/xmppd/s2s.pem --key /etc/xmppd/s2s.key \
//!           --core-socket /var/run/xmppd/s2s.sock
//! ```
//!
//! ## Signals
//!
//! - SIGTERM/SIGINT: graceful shutdown

const std = @import("std");
const posix = std.posix;
const IpcServer = @import("ipc_server").IpcServer;
const protocol = @import("ipc_protocol");
const event_loop_mod = @import("event_loop");
const EventLoop = event_loop_mod.EventLoop;
const ChangeList = event_loop_mod.ChangeList;
const Event = event_loop_mod.Event;
const xml = @import("xml");
const XmlReader = xml.Reader;
const XmlEvent = xml.Event;
const ssl = @import("ssl");
const SslContext = ssl.SslContext;
const SslConn = ssl.SslConn;
const connector_mod = @import("connector.zig");
const ConnectionPool = connector_mod.ConnectionPool;
const OutboundConnection = connector_mod.OutboundConnection;
const session_mod = @import("session.zig");
const S2sSession = session_mod.S2sSession;
const stream_mod = @import("stream.zig");
const S2sStreamAction = stream_mod.S2sStreamAction;
const StreamError = stream_mod.StreamError;

const log = std.log.scoped(.@"xmppd-s2s");

/// Sentinel udata values for kqueue events.
const LISTENER_UDATA: usize = std.math.maxInt(usize);
const IPC_LISTEN_UDATA: usize = LISTENER_UDATA - 1;
/// Base udata for IPC client connections (16 slots).
const IPC_CLIENT_UDATA_BASE: usize = LISTENER_UDATA - 17;

/// Base udata for inbound S2S sessions.
const INBOUND_UDATA_BASE: usize = 0x10000;

/// Maximum inbound S2S sessions.
const MAX_INBOUND_SESSIONS = 256;

/// The S2S federation daemon.
pub const S2sDaemon = struct {
    allocator: std.mem.Allocator,
    local_domain: []const u8,
    running: bool = true,

    /// IPC server for communication with xmppd-core.
    ipc: IpcServer = .{},

    /// TLS context for inbound connections (server-side).
    tls_ctx: ?SslContext = null,

    /// Outbound connection pool.
    pool: ConnectionPool,

    /// Inbound session table.
    inbound: [MAX_INBOUND_SESSIONS]?*S2sSession = [_]?*S2sSession{null} ** MAX_INBOUND_SESSIONS,
    /// Per-session XML readers (parallel to inbound table).
    readers: [MAX_INBOUND_SESSIONS]?*XmlReader = [_]?*XmlReader{null} ** MAX_INBOUND_SESSIONS,
    next_inbound_id: usize = 0,

    /// Inbound listener fd (-1 if not listening).
    listener_fd: posix.fd_t = -1,

    /// Inbound listener port.
    listener_port: u16 = 5269,

    pub fn init(allocator: std.mem.Allocator, local_domain: []const u8) S2sDaemon {
        return .{
            .allocator = allocator,
            .local_domain = local_domain,
            .pool = ConnectionPool.init(allocator),
        };
    }

    pub fn deinit(self: *S2sDaemon) void {
        // Close all inbound sessions and their readers
        for (&self.inbound, &self.readers) |*slot, *reader_slot| {
            if (reader_slot.*) |reader| {
                reader.deinit();
                self.allocator.destroy(reader);
                reader_slot.* = null;
            }
            if (slot.*) |session| {
                session.deinit();
                self.allocator.destroy(session);
                slot.* = null;
            }
        }

        if (self.tls_ctx) |*ctx| ctx.deinit();
        self.pool.deinit();
        self.ipc.deinit();

        if (self.listener_fd >= 0) {
            posix.close(self.listener_fd);
            self.listener_fd = -1;
        }
    }

    /// Start the inbound listener on the given address and port.
    pub fn listen(self: *S2sDaemon, address: []const u8, port: u16) !void {
        self.listener_port = port;

        const fd = try posix.socket(
            posix.AF.INET,
            posix.SOCK.STREAM | posix.SOCK.NONBLOCK,
            0,
        );
        errdefer posix.close(fd);

        const one: c_int = 1;
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));

        const ip = parseIPv4(address) orelse return error.InvalidAddress;
        var addr = std.c.sockaddr.in{
            .port = std.mem.nativeToBig(u16, port),
            .addr = ip,
        };

        posix.bind(fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch |err| {
            return switch (err) {
                error.AddressInUse => error.AddressInUse,
                error.AccessDenied => error.PermissionDenied,
                else => error.SystemResources,
            };
        };

        posix.listen(fd, 128) catch return error.SystemResources;
        self.listener_fd = fd;
        log.info("S2S listener on {s}:{d}", .{ address, port });
    }

    /// Start the IPC server for xmppd-core connections.
    pub fn startIpc(self: *S2sDaemon, socket_path: []const u8) !void {
        try self.ipc.listen(socket_path);
        log.info("IPC server on {s}", .{socket_path});
    }

    /// Accept a pending inbound S2S connection.
    pub fn acceptInbound(self: *S2sDaemon) !?usize {
        if (self.listener_fd < 0) return null;

        const client_fd = posix.accept(self.listener_fd, null, null, posix.SOCK.NONBLOCK) catch |err| {
            return switch (err) {
                error.WouldBlock => null,
                else => error.SystemResources,
            };
        };

        // Find a free slot
        const slot = self.allocateInboundSlot() orelse {
            posix.close(client_fd);
            log.warn("inbound S2S session limit reached", .{});
            return null;
        };

        const session = self.allocator.create(S2sSession) catch {
            posix.close(client_fd);
            return null;
        };
        session.* = S2sSession.init(client_fd, slot, self.local_domain);
        self.inbound[slot] = session;

        // Create XML reader for this session
        const reader = self.allocator.create(XmlReader) catch {
            session.deinit();
            self.allocator.destroy(session);
            self.inbound[slot] = null;
            return null;
        };
        reader.* = XmlReader.init(self.allocator);
        self.readers[slot] = reader;

        log.info("accepted inbound S2S connection id={d} fd={d}", .{ slot, client_fd });
        return slot;
    }

    /// Process an IPC message from xmppd-core.
    pub fn handleCoreMessage(self: *S2sDaemon, msg: protocol.Message) void {
        switch (msg) {
            .s2s_deliver => |d| {
                self.handleDelivery(d.from_jid, d.to_jid, d.stanza_xml);
            },
            else => {
                log.warn("unexpected IPC message from core", .{});
            },
        }
    }

    /// Handle a stanza delivery request from xmppd-core.
    fn handleDelivery(self: *S2sDaemon, from: []const u8, to: []const u8, stanza_xml: []const u8) void {
        // Extract the target domain from the 'to' JID
        const domain = extractDomain(to);
        if (domain.len == 0) {
            log.warn("delivery request with empty domain: to={s}", .{to});
            self.sendDeliveryFailed(from, to, "invalid-jid");
            return;
        }

        // Get or create outbound connection
        const conn = self.pool.getOrCreate(self.local_domain, domain) catch {
            self.sendDeliveryFailed(from, to, "internal-error");
            return;
        };

        if (conn.isEstablished()) {
            // Connection ready — deliver immediately
            // (In the full implementation, this would write to the connection's socket.
            // For now, the stanza is queued and the event loop handles actual delivery.)
            log.info("delivering stanza to {s} via established connection", .{domain});
        } else if (conn.isFailed()) {
            self.sendDeliveryFailed(from, to, conn.error_msg);
            return;
        }

        // Queue the stanza (whether established or still connecting)
        conn.queueStanza(self.allocator, from, to, stanza_xml) catch {
            self.sendDeliveryFailed(from, to, "internal-error");
        };
    }

    /// Send a delivery failure notification back to xmppd-core.
    fn sendDeliveryFailed(self: *S2sDaemon, from: []const u8, to: []const u8, reason: []const u8) void {
        const msg = protocol.Message{ .s2s_delivery_failed = .{
            .from_jid = from,
            .to_jid = to,
            .error_type = reason,
        } };
        // Send to all connected core clients
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            if (self.ipc.getClient(i)) |client| {
                client.queueSend(msg) catch {
                    log.err("failed to queue delivery-failed to IPC client {d}", .{i});
                };
            }
        }
    }

    /// Close an inbound session.
    pub fn closeInbound(self: *S2sDaemon, slot: usize) void {
        if (slot >= MAX_INBOUND_SESSIONS) return;
        if (self.readers[slot]) |reader| {
            reader.deinit();
            self.allocator.destroy(reader);
            self.readers[slot] = null;
        }
        if (self.inbound[slot]) |session| {
            log.info("closing inbound S2S session id={d}", .{slot});
            session.deinit();
            self.allocator.destroy(session);
            self.inbound[slot] = null;
        }
    }

    /// Get an inbound session by slot index.
    pub fn getInbound(self: *S2sDaemon, slot: usize) ?*S2sSession {
        if (slot >= MAX_INBOUND_SESSIONS) return null;
        return self.inbound[slot];
    }

    /// Count active inbound sessions.
    pub fn inboundCount(self: *const S2sDaemon) usize {
        var count: usize = 0;
        for (self.inbound) |slot| {
            if (slot != null) count += 1;
        }
        return count;
    }

    /// Stop the daemon.
    pub fn stop(self: *S2sDaemon) void {
        self.running = false;
    }

    fn allocateInboundSlot(self: *S2sDaemon) ?usize {
        var i: usize = 0;
        while (i < MAX_INBOUND_SESSIONS) : (i += 1) {
            const idx = (self.next_inbound_id + i) % MAX_INBOUND_SESSIONS;
            if (self.inbound[idx] == null) {
                self.next_inbound_id = (idx + 1) % MAX_INBOUND_SESSIONS;
                return idx;
            }
        }
        return null;
    }
};

/// Extract the domain part from a JID (user@domain/resource → domain).
fn extractDomain(jid: []const u8) []const u8 {
    // Find @ sign
    var domain_start: usize = 0;
    for (jid, 0..) |ch, i| {
        if (ch == '@') {
            domain_start = i + 1;
            break;
        }
    }

    // Find / (resource separator)
    var domain_end = jid.len;
    var i = domain_start;
    while (i < jid.len) : (i += 1) {
        if (jid[i] == '/') {
            domain_end = i;
            break;
        }
    }

    if (domain_start == 0 and domain_end == jid.len) {
        // No @ sign — might be a bare domain
        // Check for / (resource on bare domain)
        for (jid, 0..) |ch, idx| {
            if (ch == '/') return jid[0..idx];
        }
        return jid;
    }

    return jid[domain_start..domain_end];
}

/// Parse an IPv4 address string to network-order u32.
fn parseIPv4(address: []const u8) ?u32 {
    if (address.len == 0 or std.mem.eql(u8, address, "0.0.0.0")) {
        return 0; // INADDR_ANY
    }
    if (std.mem.eql(u8, address, "127.0.0.1")) {
        return std.mem.nativeToBig(u32, 0x7f000001);
    }
    return null;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var host: []const u8 = "localhost";
    var address: []const u8 = "0.0.0.0";
    var port: u16 = 5269;
    var core_socket: ?[]const u8 = null;
    var cert_path: ?[:0]const u8 = null;
    var key_path: ?[:0]const u8 = null;

    _ = args.next(); // Skip argv[0]

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--host")) {
            host = args.next() orelse {
                log.err("--host requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--address") or std.mem.eql(u8, arg, "--bind")) {
            address = args.next() orelse {
                log.err("--address requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--port")) {
            const val = args.next() orelse {
                log.err("--port requires a value", .{});
                return error.InvalidArgs;
            };
            port = std.fmt.parseInt(u16, val, 10) catch {
                log.err("invalid port: {s}", .{val});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--core-socket")) {
            core_socket = args.next() orelse {
                log.err("--core-socket requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--cert")) {
            cert_path = args.next() orelse {
                log.err("--cert requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--key")) {
            key_path = args.next() orelse {
                log.err("--key requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        } else {
            log.warn("unknown argument: {s}", .{arg});
        }
    }

    log.info("xmppd-s2s starting host={s} port={d}", .{ host, port });

    var daemon = S2sDaemon.init(allocator, host);
    defer daemon.deinit();

    // Configure TLS if cert and key are provided
    if (cert_path) |cert| {
        if (key_path) |key| {
            log.info("TLS configured: cert={s} key={s}", .{ cert, key });
            daemon.tls_ctx = SslContext.initServer(cert, key) catch |err| {
                log.err("failed to initialize TLS context: {}", .{err});
                return error.InvalidArgs;
            };
        } else {
            log.err("--cert requires --key", .{});
            return error.InvalidArgs;
        }
    }

    // Start inbound listener
    daemon.listen(address, port) catch |err| {
        log.err("failed to bind S2S listener: {}", .{err});
        return err;
    };

    // Start IPC server for core communication
    if (core_socket) |socket_path| {
        daemon.startIpc(socket_path) catch |err| {
            log.err("failed to start IPC server: {}", .{err});
            return err;
        };
    } else {
        log.warn("no --core-socket specified, running without core IPC", .{});
    }

    // Initialize event loop
    var loop = try EventLoop.init(allocator, 64);
    defer loop.deinit();

    // Register inbound listener
    if (daemon.listener_fd >= 0) {
        try loop.addFd(daemon.listener_fd, .read, LISTENER_UDATA);
    }

    // Register IPC listener for core connections
    if (daemon.ipc.listen_fd >= 0) {
        try loop.addFd(daemon.ipc.listen_fd, .read, IPC_LISTEN_UDATA);
    }

    // Register signals (automatically blocked from default delivery)
    try loop.addSignal(posix.SIG.TERM);
    try loop.addSignal(posix.SIG.INT);

    log.info("xmppd-s2s event loop started", .{});

    // Scratch buffer for batching kqueue changes across iterations.
    // Changes accumulated in iteration N are submitted at the top of iteration N+1
    // via submitAndPoll — one syscall both commits changes AND waits for events.
    var scratch: [32]posix.Kevent = undefined;
    var batch = ChangeList.init(&scratch);

    // Main event loop
    while (daemon.running) {
        const events = loop.submitAndPoll(batch.slice(), null) catch |err| {
            log.err("event loop poll failed: {}", .{err});
            break;
        };
        batch.reset();

        for (events) |ev| {
            switch (ev) {
                .signal => |s| {
                    if (s.signo == posix.SIG.TERM or s.signo == posix.SIG.INT) {
                        log.info("received signal {d}, shutting down", .{s.signo});
                        daemon.stop();
                    }
                },
                .fd_readable => |e| {
                    if (e.udata == LISTENER_UDATA) {
                        // Accept inbound S2S connections
                        while (true) {
                            const slot = daemon.acceptInbound() catch break;
                            if (slot == null) break;

                            const session = daemon.getInbound(slot.?) orelse continue;
                            batch.addRead(session.fd, INBOUND_UDATA_BASE + slot.?) catch break;
                        }
                    } else if (e.udata == IPC_LISTEN_UDATA) {
                        handleIpcAccept(&daemon, &batch);
                    } else if (e.udata >= IPC_CLIENT_UDATA_BASE and e.udata < LISTENER_UDATA) {
                        const ipc_slot = e.udata - IPC_CLIENT_UDATA_BASE;
                        handleIpcReadable(&daemon, &batch, ipc_slot);
                    } else if (e.udata >= INBOUND_UDATA_BASE) {
                        const slot = e.udata - INBOUND_UDATA_BASE;
                        handleInboundReadable(&daemon, &batch, slot);
                    }
                },
                .fd_writable => |e| {
                    if (e.udata >= IPC_CLIENT_UDATA_BASE and e.udata < LISTENER_UDATA) {
                        const ipc_slot = e.udata - IPC_CLIENT_UDATA_BASE;
                        handleIpcWritable(&daemon, &batch, ipc_slot);
                    } else if (e.udata >= INBOUND_UDATA_BASE) {
                        const slot = e.udata - INBOUND_UDATA_BASE;
                        handleInboundWritable(&daemon, &batch, slot);
                    }
                },
                else => {},
            }
        }
    }

    log.info("xmppd-s2s shutdown complete", .{});
}

fn handleInboundReadable(daemon: *S2sDaemon, batch: *ChangeList, slot: usize) void {
    const session = daemon.getInbound(slot) orelse return;

    // If TLS handshake is in progress, drive it instead of parsing XML
    if (session.isTlsHandshaking()) {
        continueTlsHandshake(daemon, batch, slot, session);
        return;
    }

    const reader = daemon.readers[slot] orelse return;

    const n = session.recv() catch |err| {
        switch (err) {
            error.WouldBlock => return,
            else => {
                daemon.closeInbound(slot);
                return;
            },
        }
    };

    if (n == 0) {
        daemon.closeInbound(slot);
        return;
    }

    // Parse XML from the read buffer and drive the S2S stream FSM
    const data = session.readableSlice();
    var pos: usize = 0;

    while (true) {
        const event = reader.next(data, &pos) catch |err| {
            log.warn("inbound S2S id={d} XML parse error: {}", .{ slot, err });
            sendStreamError(session, .not_well_formed);
            if (session.hasPendingWrite()) {
                batch.addWriteOnce(session.fd, INBOUND_UDATA_BASE + slot) catch {};
            }
            // Close after flushing error
            return;
        };
        if (event == null) break;

        processInboundEvent(daemon, session, reader, event.?);

        // Session may have been closed by processInboundEvent
        if (daemon.getInbound(slot) == null) return;

        // After STARTTLS, stop processing pre-TLS buffer
        if (session.isTlsHandshaking()) break;
    }

    // Mark consumed bytes
    if (pos > 0) session.consume(pos);

    // Request one-shot write notification when there's data to flush
    if (session.hasPendingWrite()) {
        batch.addWriteOnce(session.fd, INBOUND_UDATA_BASE + slot) catch {};
    }
}

/// Continue a non-blocking TLS handshake for an inbound session.
fn continueTlsHandshake(daemon: *S2sDaemon, batch: *ChangeList, slot: usize, session: *S2sSession) void {
    const complete = session.continueHandshake() catch {
        log.err("inbound S2S id={d} TLS handshake failed", .{slot});
        daemon.closeInbound(slot);
        return;
    };

    if (complete) {
        log.info("inbound S2S id={d} TLS handshake complete", .{slot});
        // Notify the stream FSM that TLS is established
        session.stream.tlsEstablished();
        // Reset XML reader for stream restart after STARTTLS
        if (daemon.readers[slot]) |reader| reader.reset();
        // Clear any stale pre-TLS data from the read buffer
        session.read_start = 0;
        session.read_end = 0;

        // OpenSSL may have buffered application data internally during
        // the handshake (client pipelines Finished + new stream open).
        // kqueue won't fire for data already consumed from the socket.
        // Try reading immediately to drain any buffered TLS app data.
        handleInboundReadable(daemon, batch, slot);

        // If the session is still alive, ensure kqueue re-arms
        if (daemon.getInbound(slot) != null) {
            batch.addRead(session.fd, INBOUND_UDATA_BASE + slot) catch {};
        }
    } else {
        // Re-arm the appropriate kqueue filter
        if (session.tls_state) |state| {
            switch (state) {
                .handshake_want_read => batch.addRead(session.fd, INBOUND_UDATA_BASE + slot) catch {},
                .handshake_want_write => batch.addWrite(session.fd, INBOUND_UDATA_BASE + slot) catch {},
                .established => {},
            }
        }
    }
}

/// Process a single XML event for an inbound S2S session.
fn processInboundEvent(daemon: *S2sDaemon, session: *S2sSession, reader: *XmlReader, event: XmlEvent) void {
    switch (event) {
        .stream_open => |elem| {
            // Extract 'from' and 'to' attributes
            var from: []const u8 = "";
            var to: []const u8 = "";
            var version: []const u8 = "";
            for (elem.attributes) |attr| {
                if (std.mem.eql(u8, attr.local_name, "from")) from = attr.value;
                if (std.mem.eql(u8, attr.local_name, "to")) to = attr.value;
                if (std.mem.eql(u8, attr.local_name, "version")) version = attr.value;
            }

            session.setRemoteDomain(from);
            const action = session.stream.handleStreamOpen(from, to, version);
            executeAction(daemon, session, action);

            // After stream open response, send features
            if (session.stream.getFeatures()) |_| {
                const features_action = S2sStreamAction{ .send_features = session.stream.getFeatures().? };
                executeAction(daemon, session, features_action);
            }
        },
        .element_start => |elem| {
            // Handle STARTTLS request
            if (std.mem.eql(u8, elem.namespace_uri, xml.ns.tls) and
                std.mem.eql(u8, elem.local_name, "starttls"))
            {
                const action = session.stream.handleStarttls();
                executeAction(daemon, session, action);
            }
            // Handle SASL auth
            else if (std.mem.eql(u8, elem.namespace_uri, xml.ns.sasl) and
                std.mem.eql(u8, elem.local_name, "auth"))
            {
                // Check mechanism attribute
                var mechanism: []const u8 = "";
                for (elem.attributes) |attr| {
                    if (std.mem.eql(u8, attr.local_name, "mechanism")) mechanism = attr.value;
                }
                if (std.mem.eql(u8, mechanism, "EXTERNAL")) {
                    const action = session.stream.handleSaslExternal();
                    executeAction(daemon, session, action);
                    // After successful SASL, the remote will restart the stream
                    if (session.stream.isEstablished()) {
                        reader.reset();
                    }
                } else {
                    // Unsupported mechanism
                    sendStreamError(session, .not_authorized);
                }
            }
        },
        .stream_close => {
            _ = session.stream.handleClose();
            // Send closing </stream:stream>
            session.queueWrite("</stream:stream>") catch {};
        },
        .xml_declaration => {},
        .element_end => {},
        .text => {},
    }
}

/// Execute an S2sStreamAction by building and queuing the appropriate XML response.
fn executeAction(daemon: *S2sDaemon, session: *S2sSession, action: S2sStreamAction) void {
    var buf: [2048]u8 = undefined;

    switch (action) {
        .send_stream_open => {
            const response = session.buildStreamOpenResponse(&buf) catch {
                log.err("failed to build stream open response", .{});
                return;
            };
            session.queueWrite(response) catch {};
        },
        .send_features => {
            const features = session.buildFeatures(&buf) catch {
                log.err("failed to build features", .{});
                return;
            };
            session.queueWrite(features) catch {};
        },
        .send_tls_proceed => {
            const proceed = session.buildTlsProceed(&buf) catch return;
            session.queueWrite(proceed) catch {};

            // Flush the proceed XML before upgrading to TLS
            _ = session.flushWrite() catch {};

            // Start TLS handshake
            if (daemon.tls_ctx) |ctx| {
                session.upgradeToTls(ctx) catch {
                    log.err("inbound S2S id={d} TLS upgrade failed", .{session.id});
                    return;
                };
                log.info("inbound S2S id={d} starting TLS handshake", .{session.id});
            } else {
                log.warn("inbound S2S id={d} STARTTLS requested but no TLS configured", .{session.id});
            }
        },
        .send_sasl_success => {
            const success = session.buildSaslSuccess(&buf) catch return;
            session.queueWrite(success) catch {};
            log.info("inbound S2S authenticated: remote={s}", .{session.getRemoteDomain()});
        },
        .send_sasl_failure => |reason| {
            const failure = session.buildSaslFailure(&buf, reason) catch return;
            session.queueWrite(failure) catch {};
        },
        .send_error => |err| {
            const error_xml = session.buildStreamError(&buf, err.toString()) catch return;
            session.queueWrite(error_xml) catch {};
        },
        .stream_established => {
            log.info("inbound S2S stream established: remote={s}", .{session.getRemoteDomain()});
        },
        .close => {
            session.queueWrite("</stream:stream>") catch {};
        },
        .none => {},
        .start_tls => {},
        .send_starttls => {},
        .send_sasl_external => {},
        .begin_dialback => {},
    }
}

/// Send a stream error and close.
fn sendStreamError(session: *S2sSession, err: StreamError) void {
    var buf: [512]u8 = undefined;
    const error_xml = session.buildStreamError(&buf, err.toString()) catch return;
    session.queueWrite(error_xml) catch {};
}

fn handleInboundWritable(daemon: *S2sDaemon, batch: *ChangeList, slot: usize) void {
    const session = daemon.getInbound(slot) orelse return;

    // If TLS handshake wants to write, drive the handshake
    if (session.isTlsHandshaking()) {
        continueTlsHandshake(daemon, batch, slot, session);
        return;
    }

    _ = session.flushWrite() catch {
        daemon.closeInbound(slot);
        return;
    };

    // If still more to write, re-register for another one-shot write event
    if (session.hasPendingWrite()) {
        batch.addWriteOnce(session.fd, INBOUND_UDATA_BASE + slot) catch {};
    }
}

// ============================================================================
// IPC event handlers
// ============================================================================

/// Accept a new IPC connection from xmppd-core.
fn handleIpcAccept(daemon: *S2sDaemon, batch: *ChangeList) void {
    const slot = daemon.ipc.accept() catch return;
    if (slot == null) return;

    const client = daemon.ipc.getClient(slot.?) orelse return;
    batch.addRead(client.fd, IPC_CLIENT_UDATA_BASE + slot.?) catch {};
    log.info("core connected via IPC slot={d}", .{slot.?});
}

/// Handle readable data on an IPC client connection.
fn handleIpcReadable(daemon: *S2sDaemon, batch: *ChangeList, ipc_slot: usize) void {
    const client = daemon.ipc.getClient(ipc_slot) orelse return;

    const n = client.recv() catch {
        daemon.ipc.closeClient(ipc_slot);
        return;
    };
    if (n == 0) {
        // EOF — core disconnected
        log.info("core disconnected from IPC slot={d}", .{ipc_slot});
        daemon.ipc.closeClient(ipc_slot);
        return;
    }

    // Process all complete messages in the buffer
    while (true) {
        const msg = client.nextMessage() catch {
            log.err("IPC decode error on slot={d}", .{ipc_slot});
            daemon.ipc.closeClient(ipc_slot);
            return;
        };
        if (msg == null) break;
        daemon.handleCoreMessage(msg.?);
    }

    // If there's IPC response data to send, request write notification
    if (client.hasPendingSend()) {
        batch.addWriteOnce(client.fd, IPC_CLIENT_UDATA_BASE + ipc_slot) catch {};
    }
}

/// Handle writable IPC client connection (flush pending send data).
fn handleIpcWritable(daemon: *S2sDaemon, batch: *ChangeList, ipc_slot: usize) void {
    const client = daemon.ipc.getClient(ipc_slot) orelse return;

    _ = client.flush() catch {
        daemon.ipc.closeClient(ipc_slot);
        return;
    };

    if (client.hasPendingSend()) {
        batch.addWriteOnce(client.fd, IPC_CLIENT_UDATA_BASE + ipc_slot) catch {};
    }
}

fn printUsage() void {
    const usage =
        \\Usage: xmppd-s2s [OPTIONS]
        \\
        \\Options:
        \\  --host HOST         Local XMPP domain (default: localhost)
        \\  --address ADDR      Bind address (default: 0.0.0.0)
        \\  --port PORT         S2S listener port (default: 5269)
        \\  --core-socket PATH  IPC socket for xmppd-core communication
        \\  --cert PATH         TLS certificate file (PEM)
        \\  --key PATH          TLS private key file (PEM)
        \\  --help, -h          Show this help
        \\
    ;
    var buf: [0]u8 = .{};
    var stdout = std.fs.File.stdout().writer(&buf);
    stdout.interface.writeAll(usage) catch {};
}

// ============================================================================
// Tests
// ============================================================================

test "extractDomain: user@domain" {
    try std.testing.expectEqualStrings("b.example", extractDomain("alice@b.example"));
}

test "extractDomain: user@domain/resource" {
    try std.testing.expectEqualStrings("b.example", extractDomain("alice@b.example/res"));
}

test "extractDomain: bare domain" {
    try std.testing.expectEqualStrings("b.example", extractDomain("b.example"));
}

test "extractDomain: bare domain with resource" {
    try std.testing.expectEqualStrings("b.example", extractDomain("b.example/res"));
}

test "S2sDaemon: init and deinit" {
    const alloc = std.testing.allocator;
    var daemon = S2sDaemon.init(alloc, "a.example");
    defer daemon.deinit();

    try std.testing.expectEqual(@as(usize, 0), daemon.pool.count());
    try std.testing.expectEqual(@as(usize, 0), daemon.inboundCount());
    try std.testing.expect(daemon.running);
}

test "S2sDaemon: listen on high port" {
    const alloc = std.testing.allocator;
    var daemon = S2sDaemon.init(alloc, "a.example");
    defer daemon.deinit();

    try daemon.listen("127.0.0.1", 0);
    try std.testing.expect(daemon.listener_fd >= 0);
}

test "S2sDaemon: accept inbound" {
    const alloc = std.testing.allocator;
    var daemon = S2sDaemon.init(alloc, "a.example");
    defer daemon.deinit();

    try daemon.listen("127.0.0.1", 0);

    // Get the bound port
    var addr: std.c.sockaddr.in = undefined;
    var addr_len: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    _ = std.c.getsockname(daemon.listener_fd, @ptrCast(&addr), &addr_len);

    // Connect a client
    const client_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(client_fd);

    var connect_addr = std.c.sockaddr.in{
        .port = addr.port,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    posix.connect(client_fd, @ptrCast(&connect_addr), @sizeOf(std.c.sockaddr.in)) catch |err| {
        if (err != error.WouldBlock) return err;
    };

    std.Thread.sleep(10 * std.time.ns_per_ms);

    const slot = try daemon.acceptInbound();
    try std.testing.expect(slot != null);
    try std.testing.expectEqual(@as(usize, 1), daemon.inboundCount());

    const session = daemon.getInbound(slot.?);
    try std.testing.expect(session != null);
    try std.testing.expect(session.?.fd >= 0);
}

test "S2sDaemon: closeInbound" {
    const alloc = std.testing.allocator;
    var daemon = S2sDaemon.init(alloc, "a.example");
    defer daemon.deinit();

    try daemon.listen("127.0.0.1", 0);

    var addr: std.c.sockaddr.in = undefined;
    var addr_len: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    _ = std.c.getsockname(daemon.listener_fd, @ptrCast(&addr), &addr_len);

    const client_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(client_fd);

    var connect_addr = std.c.sockaddr.in{
        .port = addr.port,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    posix.connect(client_fd, @ptrCast(&connect_addr), @sizeOf(std.c.sockaddr.in)) catch |err| {
        if (err != error.WouldBlock) return err;
    };

    std.Thread.sleep(10 * std.time.ns_per_ms);

    const slot = (try daemon.acceptInbound()) orelse return error.NoSlot;
    try std.testing.expectEqual(@as(usize, 1), daemon.inboundCount());

    daemon.closeInbound(slot);
    try std.testing.expectEqual(@as(usize, 0), daemon.inboundCount());
}

test "S2sDaemon: stop" {
    const alloc = std.testing.allocator;
    var daemon = S2sDaemon.init(alloc, "a.example");
    defer daemon.deinit();

    try std.testing.expect(daemon.running);
    daemon.stop();
    try std.testing.expect(!daemon.running);
}
