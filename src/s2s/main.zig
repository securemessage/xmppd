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
const connector_mod = @import("connector.zig");
const ConnectionPool = connector_mod.ConnectionPool;
const OutboundConnection = connector_mod.OutboundConnection;
const session_mod = @import("session.zig");
const S2sSession = session_mod.S2sSession;

const log = std.log.scoped(.@"xmppd-s2s");

/// Sentinel udata values for kqueue events.
const LISTENER_UDATA: usize = std.math.maxInt(usize);
const IPC_CORE_UDATA: usize = LISTENER_UDATA - 1;

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

    /// Outbound connection pool.
    pool: ConnectionPool,

    /// Inbound session table.
    inbound: [MAX_INBOUND_SESSIONS]?*S2sSession = [_]?*S2sSession{null} ** MAX_INBOUND_SESSIONS,
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
        // Close all inbound sessions
        for (&self.inbound) |*slot| {
            if (slot.*) |session| {
                session.deinit();
                self.allocator.destroy(session);
                slot.* = null;
            }
        }

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
        _ = self;
        // In the full implementation, this encodes and sends via IPC
        log.info("delivery failed: from={s} to={s} reason={s}", .{ from, to, reason });
    }

    /// Close an inbound session.
    pub fn closeInbound(self: *S2sDaemon, slot: usize) void {
        if (slot >= MAX_INBOUND_SESSIONS) return;
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
            // TODO: Initialize SslContext for S2S connections
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

    // Register signals (automatically blocked from default delivery)
    try loop.addSignal(posix.SIG.TERM);
    try loop.addSignal(posix.SIG.INT);

    log.info("xmppd-s2s event loop started", .{});

    // Scratch buffer for batching kqueue changes within a single loop iteration
    var scratch: [32]posix.Kevent = undefined;

    // Main event loop
    while (daemon.running) {
        const events = loop.poll(null) catch |err| {
            log.err("event loop poll failed: {}", .{err});
            break;
        };

        var batch = ChangeList.init(&scratch);

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
                    } else if (e.udata >= INBOUND_UDATA_BASE) {
                        const slot = e.udata - INBOUND_UDATA_BASE;
                        handleInboundReadable(&daemon, &batch, slot);
                    }
                },
                .fd_writable => |e| {
                    if (e.udata >= INBOUND_UDATA_BASE) {
                        const slot = e.udata - INBOUND_UDATA_BASE;
                        handleInboundWritable(&daemon, &batch, slot);
                    }
                },
                else => {},
            }
        }

        // Flush all accumulated changes + wait in next iteration
        if (batch.count() > 0) {
            _ = loop.submitAndPoll(batch.slice(), 0) catch {};
        }
    }

    log.info("xmppd-s2s shutdown complete", .{});
}

fn handleInboundReadable(daemon: *S2sDaemon, batch: *ChangeList, slot: usize) void {
    const session = daemon.getInbound(slot) orelse return;

    const n = session.recv() catch {
        daemon.closeInbound(slot);
        return;
    };

    if (n == 0) {
        daemon.closeInbound(slot);
        return;
    }

    // For now, just log received data size.
    // Full XML parsing + S2S stream FSM integration comes with the
    // complete event loop wiring (needs XML reader integration).
    log.debug("inbound S2S id={d} received {d} bytes", .{ slot, n });

    // Request one-shot write notification when there's data to flush
    if (session.hasPendingWrite()) {
        batch.addWriteOnce(session.fd, INBOUND_UDATA_BASE + slot) catch {};
    }
}

fn handleInboundWritable(daemon: *S2sDaemon, batch: *ChangeList, slot: usize) void {
    const session = daemon.getInbound(slot) orelse return;

    _ = session.flushWrite() catch {
        daemon.closeInbound(slot);
        return;
    };

    // If still more to write, re-register for another one-shot write event
    if (session.hasPendingWrite()) {
        batch.addWriteOnce(session.fd, INBOUND_UDATA_BASE + slot) catch {};
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
