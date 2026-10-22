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
const xmppd_log = @import("xmppd_log");
pub const std_options = xmppd_log.std_options;

const posix = std.posix;
const ipc_server_mod = @import("ipc_server");
const IpcServer = ipc_server_mod.IpcServer;
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
const dns = @import("dns");
const connector_mod = @import("connector.zig");
const ConnectionPool = connector_mod.ConnectionPool;
const OutboundConnection = connector_mod.OutboundConnection;
const session_mod = @import("session.zig");
const S2sSession = session_mod.S2sSession;
const stream_mod = @import("stream.zig");
const S2sStreamAction = stream_mod.S2sStreamAction;
const StreamError = stream_mod.StreamError;
const dialback = @import("dialback.zig");

const log = std.log.scoped(.@"xmppd-s2s");

/// Sentinel udata values for kqueue events.
const LISTENER_UDATA: usize = std.math.maxInt(usize);
const IPC_LISTEN_UDATA: usize = LISTENER_UDATA - 1;
/// Base udata for IPC client connections (one udata per IPC slot).
const IPC_CLIENT_UDATA_BASE: usize = LISTENER_UDATA - (ipc_server_mod.MAX_IPC_CLIENTS + 1);

/// Base udata for inbound S2S sessions.
const INBOUND_UDATA_BASE: usize = 0x10000;
/// Base udata for outbound S2S connections.
const OUTBOUND_UDATA_BASE: usize = 0x20000;

/// Maximum inbound S2S sessions.
const MAX_INBOUND_SESSIONS = 256;
/// Maximum outbound S2S connections.
const MAX_OUTBOUND_CONNS = 128;

/// The S2S federation daemon.
pub const S2sDaemon = struct {
    allocator: std.mem.Allocator,
    local_domain: []const u8,
    running: bool = true,

    /// IPC server for communication with xmppd-core.
    /// Heap-allocated: the struct is ~2 MB since MAX_IPC_CLIENTS went
    /// 16 -> 80, too big to embed in this (already large) struct (T161).
    ipc: *IpcServer,

    /// TLS context for inbound connections (server-side).
    tls_ctx: ?SslContext = null,

    /// Dialback secret (XEP-0220) — generated at startup, never disclosed.
    dialback_secret: [dialback.SECRET_LEN]u8 = undefined,

    /// Outbound connection pool (maps domain → OutboundConnection).
    pool: ConnectionPool,

    /// Outbound slot table — maps slot indices to pool entries for kqueue dispatch.
    /// Parallel to outbound_readers.
    outbound: [MAX_OUTBOUND_CONNS]?*OutboundConnection = [_]?*OutboundConnection{null} ** MAX_OUTBOUND_CONNS,
    outbound_readers: [MAX_OUTBOUND_CONNS]?*XmlReader = [_]?*XmlReader{null} ** MAX_OUTBOUND_CONNS,
    next_outbound_id: usize = 0,

    /// Round-robin index for IPC inbound stanza delivery.
    next_ipc_rr: usize = 0,

    /// TLS context for outbound connections (client-side).
    tls_client_ctx: ?SslContext = null,

    /// Inbound session table.
    inbound: [MAX_INBOUND_SESSIONS]?*S2sSession = [_]?*S2sSession{null} ** MAX_INBOUND_SESSIONS,
    /// Per-session XML readers (parallel to inbound table).
    readers: [MAX_INBOUND_SESSIONS]?*XmlReader = [_]?*XmlReader{null} ** MAX_INBOUND_SESSIONS,
    /// Per-slot generation counters: bumped on closeInbound so a stale
    /// dialback callback can never land on a reused slot (S2).
    inbound_gens: [MAX_INBOUND_SESSIONS]u32 = [_]u32{0} ** MAX_INBOUND_SESSIONS,
    next_inbound_id: usize = 0,

    /// Inbound listener fd (-1 if not listening).
    listener_fd: posix.fd_t = -1,

    /// Served MUC host for the to= check on inbound stanzas (S2):
    /// the master forwards [muc] host as --muc-host; conference traffic is
    /// served locally even though it is a different domain.
    muc_host: ?[]const u8 = null,

    /// Test seam (T277 regression): when set, performOutboundDane
    /// applies this verdict without a TLSA query or chain verification, so
    /// the DANE-failed teardown path can run without live DNS and TLS.
    /// Always null in production.
    dane_verdict_override: ?connector_mod.DaneStatus = null,

    /// Inbound listener port.
    listener_port: u16 = 5269,

    pub fn init(allocator: std.mem.Allocator, local_domain: []const u8) !S2sDaemon {
        const ipc = try allocator.create(IpcServer);
        ipc.* = IpcServer.init(allocator);
        var d = S2sDaemon{
            .allocator = allocator,
            .local_domain = local_domain,
            .ipc = ipc,
            .pool = ConnectionPool.init(allocator),
        };
        d.dialback_secret = dialback.generateSecret();
        return d;
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

        // Clean up outbound readers (connections owned by pool)
        for (&self.outbound_readers, &self.outbound) |*reader_slot, *ob_slot| {
            if (reader_slot.*) |reader| {
                reader.deinit();
                self.allocator.destroy(reader);
                reader_slot.* = null;
            }
            ob_slot.* = null;
        }

        if (self.tls_ctx) |*ctx| ctx.deinit();
        if (self.tls_client_ctx) |*ctx| ctx.deinit();
        self.pool.deinit();
        self.ipc.deinit();
        self.allocator.destroy(self.ipc);

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

        // Disable Nagle — S2S stanzas should be sent immediately.
        // TCP_NODELAY = 1 (netinet/tcp.h), IPPROTO_TCP = 6
        const nodelay_one: c_int = 1;
        posix.setsockopt(client_fd, 6, 1, std.mem.asBytes(&nodelay_one)) catch {};

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
    pub fn handleCoreMessage(self: *S2sDaemon, batch: *ChangeList, msg: protocol.Message) void {
        switch (msg) {
            .s2s_deliver => |d| {
                self.handleDelivery(batch, d.from_jid, d.to_jid, d.stanza_xml);
            },
            else => {
                log.warn("unexpected IPC message from core", .{});
            },
        }
    }

    /// Handle a stanza delivery request from xmppd-core.
    /// If an established connection exists, deliver immediately.
    /// Otherwise, initiate a new outbound connection (DNS → TCP → TLS → auth).
    fn handleDelivery(self: *S2sDaemon, batch: *ChangeList, from: []const u8, to: []const u8, stanza_xml: []const u8) void {
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

        // Queue the stanza first (delivery happens when connection is established)
        conn.queueStanza(self.allocator, from, to, stanza_xml) catch {
            self.sendDeliveryFailed(from, to, "internal-error");
            return;
        };

        if (conn.isEstablished()) {
            // Connection ready — flush queued stanzas
            self.flushOutboundStanzas(batch, conn);
        } else if (conn.isFailed()) {
            self.sendDeliveryFailed(from, to, conn.error_msg);
        } else if (conn.state == .connecting and conn.fd < 0) {
            // New connection — initiate DNS + TCP connect
            self.initiateOutbound(batch, conn, domain);
        }
        // else: connection is in progress (TLS, auth, etc.) — stanza is queued
    }

    /// Initiate an outbound connection: DNS SRV → TCP connect → kqueue registration.
    fn initiateOutbound(self: *S2sDaemon, batch: *ChangeList, conn: *OutboundConnection, domain: []const u8) void {
        // DNS SRV resolution (blocking — acceptable for initial impl)
        const targets = dns.resolver.resolveXmpp(self.allocator, domain, true) catch {
            log.err("DNS SRV resolution failed for {s}", .{domain});
            conn.fail("dns-resolution-failed");
            return;
        };
        defer {
            // Free all target hosts except the one we kept (index 0)
            for (targets[1..]) |t| self.allocator.free(t.host);
            self.allocator.free(targets);
        }

        if (targets.len == 0) {
            log.warn("no SRV targets for {s}", .{domain});
            conn.fail("no-srv-records");
            return;
        }

        // Try the first target — transfer ownership of host string to connection
        const target = targets[0];
        conn.target_host = target.host; // ownership transferred, not freed in defer
        conn.target_port = target.port;
        conn.is_direct_tls = target.is_direct_tls;

        log.info("connecting to {s}:{d} for domain {s} (direct_tls={any})", .{
            target.host, target.port, domain, target.is_direct_tls,
        });

        // Non-blocking TCP connect
        const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0) catch {
            conn.fail("socket-creation-failed");
            return;
        };

        // Resolve hostname to IP (simple A record via getaddrinfo)
        var addr = std.c.sockaddr.in{
            .port = std.mem.nativeToBig(u16, target.port),
            .addr = 0,
        };

        // For test infrastructure, handle known addresses
        if (parseIPv4(target.host)) |ip| {
            addr.addr = ip;
        } else {
            // Use getaddrinfo for hostname resolution
            const ip = resolveHostnameIPv4(target.host) catch {
                posix.close(sock);
                conn.fail("hostname-resolution-failed");
                return;
            };
            addr.addr = ip;
        }

        // Disable Nagle — S2S stanzas should be sent immediately.
        // TCP_NODELAY = 1 (netinet/tcp.h), IPPROTO_TCP = 6
        const nodelay_one: c_int = 1;
        posix.setsockopt(sock, 6, 1, std.mem.asBytes(&nodelay_one)) catch {};

        // Non-blocking connect
        posix.connect(sock, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch |err| {
            switch (err) {
                error.WouldBlock => {}, // Expected — connect in progress
                else => {
                    posix.close(sock);
                    conn.fail("tcp-connect-failed");
                    return;
                },
            }
        };

        conn.fd = sock;

        // Allocate an outbound slot for kqueue dispatch
        const slot = self.allocateOutboundSlot() orelse {
            posix.close(sock);
            conn.fd = -1;
            conn.fail("outbound-slots-exhausted");
            return;
        };
        self.outbound[slot] = conn;

        // Create XML reader for this outbound connection
        const reader = self.allocator.create(XmlReader) catch {
            self.outbound[slot] = null;
            posix.close(sock);
            conn.fd = -1;
            conn.fail("internal-error");
            return;
        };
        reader.* = XmlReader.init(self.allocator);
        self.outbound_readers[slot] = reader;

        // Register for one-shot write event (connect completion signals writable)
        batch.addWriteOnce(sock, OUTBOUND_UDATA_BASE + slot) catch {};
    }

    /// Flush queued stanzas on an established outbound connection.
    /// Every flushed PendingStanza frees all three owned slices; a full
    /// write buffer keeps the unconsumed tail queued and arms a one-shot
    /// write event so the writable edge resumes it. The event is armed for
    /// a kept tail OR unsent buffered bytes: a drain that empties the
    /// write buffer into kernel sendspace leaves hasPendingWrite() false
    /// and would strand the tail until the next stanza (T275). A stanza
    /// that can never fit the write buffer is failed to the sender instead
    /// of wedging the queue.
    fn flushOutboundStanzas(self: *S2sDaemon, batch: *ChangeList, conn: *OutboundConnection) void {
        const items = conn.pending_stanzas.items;
        var i: usize = 0;
        var kept: usize = 0;
        var stalled = false;
        while (i < items.len) : (i += 1) {
            const stanza = items[i];
            if (stanza.xml.len > conn.write_buf.len) {
                log.warn("outbound stanza too large for {s} ({d} bytes); delivery-failed", .{ conn.remote_domain, stanza.xml.len });
                self.sendDeliveryFailed(stanza.from_jid, stanza.to_jid, "stanza-too-large");
                stanza.deinit(self.allocator);
                continue;
            }
            if (!stalled) {
                if (conn.queueWrite(stanza.xml)) {
                    stanza.deinit(self.allocator);
                    continue;
                } else |_| {
                    // Backpressure, not a drop: the tail stays in order and
                    // the writable edge retries it (the structural answer is
                    // X1's bounded queue with delivery-failed, T278).
                    log.warn("outbound write buffer full for {s}: {d} stanza(s) stay queued", .{ conn.remote_domain, items.len - i });
                    stalled = true;
                }
            }
            items[kept] = stanza;
            kept += 1;
        }
        conn.pending_stanzas.items.len = kept;
        _ = conn.flushWrite() catch {
            log.err("outbound write failed for {s}", .{conn.remote_domain});
        };
        if (kept > 0 or conn.hasPendingWrite()) {
            if (self.findOutboundSlot(conn)) |slot| {
                batch.addWriteOnce(conn.fd, OUTBOUND_UDATA_BASE + slot) catch {};
            }
        }
    }

    /// Find the outbound slot for a given connection pointer.
    fn findOutboundSlot(self: *S2sDaemon, conn: *OutboundConnection) ?usize {
        for (self.outbound, 0..) |slot, i| {
            if (slot) |c| {
                if (c == conn) return i;
            }
        }
        return null;
    }

    /// Close an outbound connection slot. Purges its staged kevent entries
    /// first: a same-iteration accept can reuse the fd number (T238/T277).
    /// Every exchange the conn still carries is answered before teardown,
    /// so a read error, EOF, parse error or write failure never leaves the
    /// submitting stream waiting for a verdict that can no longer arrive.
    fn closeOutbound(self: *S2sDaemon, batch: *ChangeList, slot: usize) void {
        if (slot >= MAX_OUTBOUND_CONNS) return;
        if (self.outbound[slot]) |conn| {
            for (0..conn.db_pending.len) |idx| {
                if (conn.db_pending[idx].in_use) handleDbVerifyResponse(self, batch, conn, idx, false);
            }
        }
        if (self.outbound[slot]) |conn| {
            batch.purgeFd(conn.fd);
        }
        if (self.outbound_readers[slot]) |reader| {
            reader.deinit();
            self.allocator.destroy(reader);
            self.outbound_readers[slot] = null;
        }
        if (self.outbound[slot]) |conn| {
            log.info("closing outbound S2S to {s}", .{conn.remote_domain});
            self.pool.remove(conn.remote_domain);
        }
        self.outbound[slot] = null;
    }

    fn allocateOutboundSlot(self: *S2sDaemon) ?usize {
        var i: usize = 0;
        while (i < MAX_OUTBOUND_CONNS) : (i += 1) {
            const idx = (self.next_outbound_id + i) % MAX_OUTBOUND_CONNS;
            if (self.outbound[idx] == null) {
                self.next_outbound_id = (idx + 1) % MAX_OUTBOUND_CONNS;
                return idx;
            }
        }
        return null;
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
        while (i < ipc_server_mod.MAX_IPC_CLIENTS) : (i += 1) {
            if (self.ipc.getClient(i)) |client| {
                client.queueSend(msg) catch {
                    log.err("failed to queue delivery-failed to IPC client {d}", .{i});
                };
            }
        }
    }

    /// Close an inbound session. Purges its staged kevent entries first:
    /// a same-iteration accept can reuse the fd number (T238/T277).
    pub fn closeInbound(self: *S2sDaemon, batch: *ChangeList, slot: usize) void {
        if (slot >= MAX_INBOUND_SESSIONS) return;
        if (self.inbound[slot]) |session| {
            batch.purgeFd(session.fd);
        }
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
        self.inbound_gens[slot] +%= 1;
    }

    /// Get an inbound session by slot index.
    pub fn getInbound(self: *S2sDaemon, slot: usize) ?*S2sSession {
        if (slot >= MAX_INBOUND_SESSIONS) return null;
        return self.inbound[slot];
    }

    /// Whether a host is one we serve: the local domain or the MUC host
    /// (S2: conference.<host> is a valid dialback/stream target).
    pub fn servesHost(self: *const S2sDaemon, host: []const u8) bool {
        if (host.len == 0) return false;
        if (std.ascii.eqlIgnoreCase(host, self.local_domain)) return true;
        if (self.muc_host) |m| {
            if (std.ascii.eqlIgnoreCase(host, m)) return true;
        }
        return false;
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
    // Try to parse dotted-decimal IPv4
    var octets: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var i: usize = 0;
    while (i < address.len and octet_idx < 4) {
        var val: u16 = 0;
        var digits: usize = 0;
        while (i < address.len and address[i] != '.') : (i += 1) {
            if (address[i] < '0' or address[i] > '9') return null;
            val = val * 10 + @as(u16, address[i] - '0');
            digits += 1;
        }
        if (digits == 0 or val > 255) return null;
        octets[octet_idx] = @intCast(val);
        octet_idx += 1;
        if (i < address.len and address[i] == '.') i += 1;
    }
    if (octet_idx != 4) return null;
    return @as(u32, octets[0]) | (@as(u32, octets[1]) << 8) | (@as(u32, octets[2]) << 16) | (@as(u32, octets[3]) << 24);
}

/// Resolve a hostname to an IPv4 address using getaddrinfo.
fn resolveHostnameIPv4(hostname: []const u8) !u32 {
    // Null-terminate the hostname for C API
    var name_buf: [256]u8 = undefined;
    if (hostname.len >= name_buf.len) return error.NameTooLong;
    @memcpy(name_buf[0..hostname.len], hostname);
    name_buf[hostname.len] = 0;

    var hints: std.c.addrinfo = std.mem.zeroes(std.c.addrinfo);
    hints.family = posix.AF.INET;
    hints.socktype = posix.SOCK.STREAM;

    var result: ?*std.c.addrinfo = null;
    const rc = std.c.getaddrinfo(@ptrCast(&name_buf), null, &hints, &result);
    if (@intFromEnum(rc) != 0 or result == null) return error.ResolutionFailed;
    defer std.c.freeaddrinfo(result.?);

    const addr_in: *const std.c.sockaddr.in = @ptrCast(@alignCast(result.?.addr.?));
    return addr_in.addr;
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
    var listen_fd: ?posix.fd_t = null;
    var muc_host: ?[]const u8 = null;

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
        } else if (std.mem.eql(u8, arg, "--muc-host")) {
            muc_host = args.next() orelse {
                log.err("--muc-host requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--listen-fd")) {
            const val = args.next() orelse {
                log.err("--listen-fd requires a value", .{});
                return error.InvalidArgs;
            };
            listen_fd = std.fmt.parseInt(posix.fd_t, val, 10) catch {
                log.err("invalid fd number: {s}", .{val});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--config") or std.mem.eql(u8, arg, "-c")) {
            // Consume and ignore — passed by master but not used by S2S
            _ = args.next();
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        } else {
            log.warn("unknown argument: {s}", .{arg});
        }
    }

    log.info("xmppd-s2s starting host={s} port={d} listen_fd={any}", .{ host, port, listen_fd });

    var daemon = try S2sDaemon.init(allocator, host);
    defer daemon.deinit();
    daemon.muc_host = muc_host;

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

    // Initialize client TLS context for outbound connections (with our cert for SASL EXTERNAL)
    const client_cert: ?[*:0]const u8 = if (cert_path) |p| p.ptr else null;
    const client_key: ?[*:0]const u8 = if (key_path) |p| p.ptr else null;
    daemon.tls_client_ctx = SslContext.initClientWithCert(client_cert, client_key) catch |err| {
        log.err("failed to initialize client TLS context: {}", .{err});
        return err;
    };

    // Start inbound listener (from pre-bound fd or bind ourselves)
    if (listen_fd) |fd| {
        daemon.listener_fd = fd;
        daemon.listener_port = port;
        log.info("S2S using inherited listener fd={d} port={d}", .{ fd, port });
    } else {
        daemon.listen(address, port) catch |err| {
            log.err("failed to bind S2S listener: {}", .{err});
            return err;
        };
    }

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
                    } else if (e.udata >= OUTBOUND_UDATA_BASE and e.udata < IPC_CLIENT_UDATA_BASE) {
                        const slot = e.udata - OUTBOUND_UDATA_BASE;
                        handleOutboundReadable(&daemon, &batch, slot);
                    } else if (e.udata >= INBOUND_UDATA_BASE and e.udata < OUTBOUND_UDATA_BASE) {
                        const slot = e.udata - INBOUND_UDATA_BASE;
                        handleInboundReadable(&daemon, &batch, slot);
                    }
                },
                .fd_writable => |e| {
                    if (e.udata >= IPC_CLIENT_UDATA_BASE and e.udata < LISTENER_UDATA) {
                        const ipc_slot = e.udata - IPC_CLIENT_UDATA_BASE;
                        handleIpcWritable(&daemon, &batch, ipc_slot);
                    } else if (e.udata >= OUTBOUND_UDATA_BASE and e.udata < IPC_CLIENT_UDATA_BASE) {
                        const slot = e.udata - OUTBOUND_UDATA_BASE;
                        handleOutboundWritable(&daemon, &batch, slot);
                    } else if (e.udata >= INBOUND_UDATA_BASE and e.udata < OUTBOUND_UDATA_BASE) {
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
                daemon.closeInbound(batch, slot);
                return;
            },
        }
    };

    if (n == 0) {
        daemon.closeInbound(batch, slot);
        return;
    }

    // T250: while a <proceed/> is parked behind a partial flush, NO plaintext
    // event may run: even one parsed event would cross the TLS record boundary
    // as clear text. Any byte received while pending is a protocol error.
    if (session.tls_upgrade_pending) {
        log.warn("inbound S2S id={d}: {d} plaintext bytes while TLS upgrade pending: stream policy-violation", .{ slot, session.read_end - session.read_start });
        sendStreamError(session, .policy_violation);
        _ = session.flushWrite() catch {};
        daemon.closeInbound(batch, slot);
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

        processInboundEvent(daemon, session, reader, event.?, batch);

        // Session may have been closed by processInboundEvent
        if (daemon.getInbound(slot) == null) return;

        // After STARTTLS, stop processing pre-TLS buffer: also when the
        // upgrade merely pends behind a partially-flushed <proceed/> (T250).
        if (session.isTlsHandshaking() or session.tls_upgrade_pending) break;
    }

    // Mark consumed bytes
    if (pos > 0) session.consume(pos);

    // STARTTLS read-ahead hygiene (T250): plaintext bytes beyond <proceed/>
    // mean the peer spoke before receiving it; they are a protocol error,
    // never silently discarded at handshake completion.
    if ((session.isTlsHandshaking() or session.tls_upgrade_pending) and session.read_start < session.read_end) {
        log.warn("inbound S2S id={d}: {d} plaintext bytes after <proceed/>: stream policy-violation", .{ slot, session.read_end - session.read_start });
        sendStreamError(session, .policy_violation);
        _ = session.flushWrite() catch {};
        daemon.closeInbound(batch, slot);
        return;
    }

    // After SASL success, flush <success/> and drain any OpenSSL-buffered
    // post-auth stream data. Same pattern as post-TLS handshake (line 843):
    // OpenSSL may have internally consumed socket bytes during SSL_write,
    // buffering Prosody's post-auth stream open without triggering kqueue.
    if (session.stream.state == .awaiting_stream_open_tls and session.stream.authenticated) {
        _ = session.flushWrite() catch {};
        handleInboundReadable(daemon, batch, slot);
        if (daemon.getInbound(slot) != null) {
            batch.addRead(session.fd, INBOUND_UDATA_BASE + slot) catch {};
        }
        return;
    }

    // Request one-shot write notification when there's data to flush
    if (session.hasPendingWrite()) {
        batch.addWriteOnce(session.fd, INBOUND_UDATA_BASE + slot) catch {};
    }
}

/// Continue a non-blocking TLS handshake for an inbound session.
fn continueTlsHandshake(daemon: *S2sDaemon, batch: *ChangeList, slot: usize, session: *S2sSession) void {
    const complete = session.continueHandshake() catch {
        log.err("inbound S2S id={d} TLS handshake failed", .{slot});
        daemon.closeInbound(batch, slot);
        return;
    };

    if (complete) {
        // Q11: offload fallback is silent, so engagement, version and cipher
        // are logged once per handshake (tokens: ktls, ktls-tx, ktls-rx, sw).
        if (session.tls_conn) |*tls| {
            const mode: []const u8 = if (tls.ktlsSend() and tls.ktlsRecv()) "ktls" else if (tls.ktlsSend()) "ktls-tx" else if (tls.ktlsRecv()) "ktls-rx" else "sw";
            log.info("inbound S2S id={d} TLS handshake complete version={s} cipher={s} mode={s}", .{ slot, tls.versionName(), tls.cipherName(), mode });
        } else {
            log.info("inbound S2S id={d} TLS handshake complete mode=none", .{slot});
        }
        // Notify the stream FSM that TLS is established
        session.stream.tlsEstablished();
        // Reset XML reader for stream restart after STARTTLS
        if (daemon.readers[slot]) |reader| reader.reset();
        // Invariant: no plaintext can outlive <proceed/> (T250 rejects any
        // leftover with policy-violation); the zeroing stays as a start
        // state guard.
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
                // One-shot: a writable idle TLS socket is ALWAYS writable;
                // a persistent arm would spin kevent at 100% CPU (S10).
                .handshake_want_write => batch.addWriteOnce(session.fd, INBOUND_UDATA_BASE + slot) catch {},
                .established => {},
            }
        }
    }
}

/// Process a single XML event for an inbound S2S session.
fn processInboundEvent(daemon: *S2sDaemon, session: *S2sSession, reader: *XmlReader, event: XmlEvent, batch: *ChangeList) void {
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

            // S2: the peer may never re-identify on a restart. Post-auth the
            // header from= must already be authenticated; pre-auth (post-TLS)
            // it must not change from the pinned origin.
            if (!session.stream_open_seen) {
                session.stream_open_seen = true;
                session.setRemoteDomain(from);
            } else if (!session.restartFromAllowed(from)) {
                log.warn("inbound S2S id={d} stream restart with unauthenticated from={s} (peer pinned {s})", .{ session.id, from, session.getRemoteDomain() });
                sendStreamError(session, .invalid_from);
                _ = session.flushWrite() catch {};
                daemon.closeInbound(batch, session.id);
                return;
            } else if (session.auth_domain_count > 0) {
                // Authenticated domain may differ from the first open (dialback
                // multiplexing); the tracked identity follows it.
                session.setRemoteDomain(from);
            }
            // The header to= selects which served host this stream addresses;
            // replies echo it as their from= (S2). An unserved host
            // fails the stream.
            if (to.len > 0) {
                if (!daemon.servesHost(to)) {
                    log.warn("inbound S2S id={d} stream addressed to unserved host {s}", .{ session.id, to });
                    sendStreamError(session, .host_unknown);
                    _ = session.flushWrite() catch {};
                    daemon.closeInbound(batch, session.id);
                    return;
                }
                session.setServedHost(to);
            }
            const action = session.stream.handleStreamOpen(from, to, version);
            executeAction(daemon, session, action, batch);

            // After post-TLS stream open, perform DANE verification on peer cert
            if (session.stream.state == .features_auth and session.tls_conn != null and from.len > 0) {
                performInboundDane(daemon, session, from);
            }

            // After stream open response, send features
            if (session.stream.getFeatures()) |_| {
                const features_action = S2sStreamAction{ .send_features = session.stream.getFeatures().? };
                executeAction(daemon, session, features_action, batch);
            } else if (session.stream.isEstablished()) {
                // Post-auth stream: send empty features
                session.queueWrite("<stream:features/>") catch {};
                log.info("inbound S2S stream established: remote={s}", .{session.getRemoteDomain()});
            }
        },
        .element_start => |elem| {
            // If accumulating a stanza, serialize child elements into inner buffer
            if (session.stanza_active) {
                session.accumulateElement(elem, reader);
                return;
            }

            // On established sessions, detect stanza elements and start accumulation
            if (session.stream.isEstablished()) {
                if (std.mem.eql(u8, elem.local_name, "message") or
                    std.mem.eql(u8, elem.local_name, "presence") or
                    std.mem.eql(u8, elem.local_name, "iq"))
                {
                    session.startStanza(elem);
                    if (elem.self_closing) {
                        dispatchInboundStanza(daemon, session, batch);
                    }
                    return;
                }
            }

            // Handle STARTTLS request
            if (std.mem.eql(u8, elem.namespace_uri, xml.ns.tls) and
                std.mem.eql(u8, elem.local_name, "starttls"))
            {
                const action = session.stream.handleStarttls();
                executeAction(daemon, session, action, batch);
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
                    executeAction(daemon, session, action, batch);
                    // After successful SASL, the remote will restart the stream.
                    // State is awaiting_stream_open_tls (reused for post-SASL restart).
                    if (session.stream.state == .awaiting_stream_open_tls) {
                        reader.reset();
                    }
                } else {
                    // Unsupported mechanism
                    sendStreamError(session, .not_authorized);
                }
            }
            // Handle dialback verify callback: <db:verify from='...' to='...' id='...'>KEY</db:verify>
            else if (std.mem.eql(u8, elem.local_name, "verify") and
                std.mem.eql(u8, elem.namespace_uri, xml.ns.dialback))
            {
                var from: []const u8 = "";
                var to: []const u8 = "";
                var verify_id: []const u8 = "";
                for (elem.attributes) |attr| {
                    if (std.mem.eql(u8, attr.local_name, "from")) from = attr.value;
                    if (std.mem.eql(u8, attr.local_name, "to")) to = attr.value;
                    if (std.mem.eql(u8, attr.local_name, "id")) verify_id = attr.value;
                }
                session.startDbVerify(from, to, verify_id);
            }
            // Handle inbound dialback result (remote initiates dialback to us)
            else if (std.mem.eql(u8, elem.local_name, "result") and
                std.mem.eql(u8, elem.namespace_uri, xml.ns.dialback))
            {
                // Check if this is a result with type (response) or without (key submission)
                var result_type: []const u8 = "";
                var db_from: []const u8 = "";
                var db_to: []const u8 = "";
                for (elem.attributes) |attr| {
                    if (std.mem.eql(u8, attr.local_name, "type")) result_type = attr.value;
                    if (std.mem.eql(u8, attr.local_name, "from")) db_from = attr.value;
                    if (std.mem.eql(u8, attr.local_name, "to")) db_to = attr.value;
                }
                if (result_type.len == 0) {
                    // Key submission — start capturing the key text
                    session.startDbResult(db_from, db_to);
                    log.info("inbound dialback key submission from {s}", .{db_from});
                }
            }
        },
        .stream_close => {
            _ = session.stream.handleClose();
            // Send closing </stream:stream>
            session.queueWrite("</stream:stream>") catch {};
        },
        .xml_declaration => {},
        .element_end => |name| {
            // Stanza accumulation — child close tag or stanza dispatch
            if (session.stanza_active) {
                if (reader.depth > 1) {
                    session.accumulateClose(name);
                } else {
                    dispatchInboundStanza(daemon, session, batch);
                }
                return;
            }
            // db:result close — key text is fully captured, initiate callback
            if (session.db_result_pending and
                (std.mem.eql(u8, name, "result") or std.mem.eql(u8, name, "db:result")))
            {
                session.db_result_pending = false;
                initiateDialbackCallback(daemon, batch, session);
                return;
            }
        },
        .text => |text_content| {
            // Stanza content accumulation
            if (session.stanza_active) {
                session.accumulateText(text_content);
                return;
            }
            // Capture db:result key text (dialback key submission)
            if (session.db_result_pending) {
                const remaining = session.db_result_key_buf.len - session.db_result_key_len;
                const to_copy = @min(text_content.len, remaining);
                if (to_copy > 0) {
                    @memcpy(
                        session.db_result_key_buf[session.db_result_key_len .. session.db_result_key_len + to_copy],
                        text_content[0..to_copy],
                    );
                    session.db_result_key_len += to_copy;
                }
                return;
            }
            // Handle db:verify key text
            if (session.db_verify_pending) {
                const from = session.getDbVerifyFrom();
                const to = session.getDbVerifyTo();
                const verify_id = session.getDbVerifyId();
                // The db:verify to= names the authoritative host; only a host
                // we serve can answer, and the answer echoes it (S2).
                if (!daemon.servesHost(to)) {
                    log.warn("dialback verify: addressed to unserved host {s}; failing stream", .{to});
                    session.db_verify_pending = false;
                    sendStreamError(session, .host_unknown);
                    _ = session.flushWrite() catch {};
                    daemon.closeInbound(batch, session.id);
                    return;
                }
                const valid = dialback.verifyKey(
                    &daemon.dialback_secret,
                    from,
                    to,
                    verify_id,
                    text_content,
                );
                var resp_buf: [512]u8 = undefined;
                const resp = dialback.buildDbVerifyResponse(
                    &resp_buf,
                    to,
                    from,
                    verify_id,
                    valid,
                ) catch return;
                session.queueWrite(resp) catch {};
                session.db_verify_pending = false;
                if (valid) {
                    log.info("dialback verify: valid key from {s} for stream {s}", .{ from, verify_id });
                } else {
                    log.warn("dialback verify: invalid key from {s} for stream {s}", .{ from, verify_id });
                }
            }
        },
    }
}

/// Domainpart of a JID (RFC 7622 §3.1): cut at the resource separator
/// FIRST, then split off the localpart. Cutting at '@' first would let
/// "victim.example/x@them.example" resolve to "them.example" (S2).
fn jidDomain(jid: []const u8) []const u8 {
    const bare = if (std.mem.indexOfScalar(u8, jid, '/')) |slash| jid[0..slash] else jid;
    if (std.mem.indexOfScalar(u8, bare, '@')) |at| return bare[at + 1 ..];
    return bare;
}

/// RFC 6120 §4.9.3.9 / §4.9.3.6: an inbound stanza's from= domain must be
/// authenticated for the session (dialback or EXTERNAL+DANE; auth_ok is the
/// caller's set lookup), and to= must be a host we serve (bare domain or the
/// MUC host).
fn validateInboundAddress(local_domain: []const u8, muc_host: ?[]const u8, auth_ok: bool, from: []const u8, to: []const u8) ?StreamError {
    const from_dom = jidDomain(from);
    if (from_dom.len == 0 or !auth_ok) return .invalid_from;
    const to_dom = jidDomain(to);
    if (to_dom.len == 0) return .host_unknown;
    if (std.ascii.eqlIgnoreCase(to_dom, local_domain)) return null;
    if (muc_host) |m| {
        if (std.ascii.eqlIgnoreCase(to_dom, m)) return null;
    }
    return .host_unknown;
}

/// Forward a fully accumulated inbound stanza to xmppd-core via IPC.
///
/// closeInbound frees the session; every reject path resets the stanza
/// accumulator before closing, so no deferred reset can touch freed
/// memory (S2).
fn dispatchInboundStanza(daemon: *S2sDaemon, session: *S2sSession, batch: *ChangeList) void {
    const from = session.getStanzaFrom();
    const to = session.getStanzaTo();

    // A stanza whose children overflowed the accumulator must not forward:
    // truncated XML is malformed input for the receiver (S1). The lane
    // stays open; the stanza is counted and gone.
    if (session.stanzaBroken()) {
        log.warn("inbound S2S id={d} stanza dropped: inner accumulation overflowed (from={s} to={s})", .{ session.id, from, to });
        session.resetStanza();
        return;
    }

    if (from.len == 0 or to.len == 0) {
        // RFC 6120 §4.9.3.10: missing from/to on an established stream.
        log.warn("inbound stanza missing from/to (improper-addressing)", .{});
        sendStreamError(session, .improper_addressing);
        _ = session.flushWrite() catch {};
        session.resetStanza();
        daemon.closeInbound(batch, session.id);
        return;
    }

    // Authenticated-domain and served-host checks before anything is
    // forwarded (T351/S2): without them any federated peer could speak as
    // any local user. from= must name a domain the session authenticated
    // for (DANE+EXTERNAL or dialback), not whatever the header claims.
    if (validateInboundAddress(daemon.local_domain, daemon.muc_host, session.isAuthenticatedDomain(jidDomain(from)), from, to)) |err| {
        log.warn("inbound S2S stanza rejected ({s}): from={s} to={s} (peer pinned {s})", .{ err.toString(), from, to, session.getRemoteDomain() });
        sendStreamError(session, err);
        _ = session.flushWrite() catch {};
        session.resetStanza();
        daemon.closeInbound(batch, session.id);
        return;
    }

    // Build the complete stanza XML
    var stanza_buf: [20480]u8 = undefined;
    const stanza_xml = session.buildStanzaXml(&stanza_buf) catch {
        log.warn("inbound stanza too large, dropping", .{});
        session.resetStanza();
        return;
    };
    defer session.resetStanza();

    log.info("forwarding inbound {s} from {s} to {s}", .{ session.getStanzaTag(), from, to });

    // Send to ONE core IPC client (round-robin). The receiving worker uses
    // the shared SessionMap to route — if the target is on a different worker,
    // it delivers via MPSC. Sending to all workers would cause N duplicates.
    const msg = protocol.Message{ .s2s_inbound = .{
        .from_jid = from,
        .to_jid = to,
        .stanza_xml = stanza_xml,
    } };

    // Find next connected client via round-robin
    var attempts: usize = 0;
    while (attempts < ipc_server_mod.MAX_IPC_CLIENTS) : (attempts += 1) {
        const idx = daemon.next_ipc_rr % ipc_server_mod.MAX_IPC_CLIENTS;
        daemon.next_ipc_rr = (daemon.next_ipc_rr + 1) % ipc_server_mod.MAX_IPC_CLIENTS;
        if (daemon.ipc.getClient(idx)) |client| {
            client.queueSend(msg) catch {
                log.err("failed to queue inbound stanza to IPC client {d}", .{idx});
                continue;
            };
            if (client.hasPendingSend()) {
                batch.addWriteOnce(client.fd, IPC_CLIENT_UDATA_BASE + idx) catch {};
            }
            break;
        }
    }
}

/// Initiate a dialback verification callback: open an outbound connection to
/// the origin domain and send db:verify with the received key.
fn initiateDialbackCallback(daemon: *S2sDaemon, batch: *ChangeList, session: *S2sSession) void {
    const origin = session.getDbResultFrom();
    const key = session.getDbResultKey();
    const stream_id = session.getStreamId();

    if (origin.len == 0 or key.len == 0) {
        log.warn("dialback callback: missing origin or key", .{});
        return;
    }
    // S2: the db:result to= must be a host we serve (the local domain or
    // the MUC host); an unserved target would be verified on our account.
    const target = session.getDbResultTo();
    if (!daemon.servesHost(target)) {
        log.warn("dialback callback: db:result to={s} is not a served host ({s})", .{ target, daemon.local_domain });
        sendStreamError(session, .invalid_from);
        _ = session.flushWrite() catch {};
        daemon.closeInbound(batch, session.id);
        return;
    }
    // S1: the captured key re-enters an outbound stream verbatim; only a
    // HMAC hex shape can ever be legitimate (entity-decoded markup in a
    // db:result is rejected, not forwarded).
    if (!dialback.isValidKeyHex(key)) {
        log.warn("dialback callback: invalid key shape from {s} ({d} bytes); answering type=invalid", .{ origin, key.len });
        var resp_buf: [512]u8 = undefined;
        const resp = dialback.buildDbResultResponse(&resp_buf, target, origin, false) catch return;
        session.queueWrite(resp) catch {};
        if (session.hasPendingWrite()) {
            batch.addWriteOnce(session.fd, INBOUND_UDATA_BASE + session.id) catch {};
        }
        return;
    }

    log.info("initiating dialback callback to {s} for stream {s}", .{ origin, stream_id });

    // Store the dialback state on the inbound session
    session.inbound_dialback.receiveResult(origin, stream_id, key);

    // Get or create an outbound connection to the origin domain
    const conn = daemon.pool.getOrCreate(daemon.local_domain, origin) catch {
        log.err("dialback callback: failed to create outbound connection to {s}", .{origin});
        return;
    };

    // Register the callback keyed by (stream id, origin) with the slot
    // generation: each concurrent db:result for the same origin keeps its
    // own pending verify (S2).
    if (conn.addPendingVerify(session.id, daemon.inbound_gens[session.id], stream_id, origin, target, key) == null) {
        log.warn("dialback callback: pending-verify table full for {s}; answering type=invalid", .{origin});
        var resp_buf: [512]u8 = undefined;
        const resp = dialback.buildDbResultResponse(&resp_buf, target, origin, false) catch return;
        session.queueWrite(resp) catch {};
        if (session.hasPendingWrite()) {
            batch.addWriteOnce(session.fd, INBOUND_UDATA_BASE + session.id) catch {};
        }
        return;
    }

    if (conn.canSendDbVerify()) {
        // Post-TLS auth phase already reached: send db:verify immediately
        if (!sendDbVerifyOnCallback(daemon, batch, conn)) {
            if (daemon.findOutboundSlot(conn)) |slot| daemon.closeOutbound(batch, slot);
        }
    } else if (conn.state == .connecting and conn.fd < 0) {
        // New connection: initiate DNS + TCP connect
        daemon.initiateOutbound(batch, conn, origin);
    }
    // else: connection is in progress; db:verify goes out at the post-TLS
    // features edge
}

/// Send db:verify stanzas for every registered callback that has not been
/// sent yet on this outbound connection. Returns false when the write
/// failed: the exchanges the connection carried are answered invalid and
/// the caller tears it down, so a submitting stream is never left waiting
/// for a verdict that can no longer arrive. Verifies that could not be
/// queued (full write buffer) stay unsent and go out from the writable
/// edge.
fn sendDbVerifyOnCallback(daemon: *S2sDaemon, batch: *ChangeList, conn: *OutboundConnection) bool {
    for (&conn.db_pending, 0..) |*p, idx| {
        if (!p.in_use or p.verify_sent) continue;
        const key = p.key();
        const sid = p.streamId();
        if (key.len == 0 or sid.len == 0) {
            // An exchange without key or stream id can never produce a
            // db:verify; leaving it would spin the writable re-arm.
            log.warn("dialback callback: exchange without key or stream id; answering invalid", .{});
            handleDbVerifyResponse(daemon, batch, conn, idx, false);
            continue;
        }

        var buf: [512]u8 = undefined;
        const verify_xml = dialback.buildDbVerify(
            &buf,
            if (p.target().len > 0) p.target() else daemon.local_domain,
            conn.remote_domain,
            sid,
            key,
        ) catch {
            // Unbuildable exchange: answered invalid and cleared like a
            // write failure. An unsent entry would stay forever and re-arm
            // the one-shot write on every edge.
            log.warn("dialback callback: db:verify for stream {s} cannot be built; answering invalid", .{sid});
            handleDbVerifyResponse(daemon, batch, conn, idx, false);
            continue;
        };

        conn.queueWrite(verify_xml) catch {
            log.warn("dialback callback: write buffer full, db:verify for stream {s} waits for the writable edge", .{sid});
            continue;
        };
        p.verify_sent = true;
        log.info("dialback callback: sent db:verify to {s} for stream {s}", .{ conn.remote_domain, sid });
    }
    if (conn.hasPendingWrite()) {
        _ = conn.flushWrite() catch {
            log.warn("dialback callback: db:verify write to {s} failed; answering pending exchanges invalid", .{conn.remote_domain});
            for (0..conn.db_pending.len) |idx| {
                if (conn.db_pending[idx].in_use) handleDbVerifyResponse(daemon, batch, conn, idx, false);
            }
            conn.fail("write-failed");
            return false;
        };
    }
    // Buffered bytes under backpressure and verifies that could not be
    // queued both resume from the writable edge.
    if (conn.hasPendingWrite() or conn.hasUnsentVerify()) {
        if (daemon.findOutboundSlot(conn)) |slot| {
            batch.addWriteOnce(conn.fd, OUTBOUND_UDATA_BASE + slot) catch {
                // Nothing is armed: the queued verifies would never go
                // out. Fail the exchanges instead of losing them.
                log.warn("dialback callback: cannot arm the writable edge for {s}; answering pending exchanges invalid", .{conn.remote_domain});
                for (0..conn.db_pending.len) |i| {
                    if (conn.db_pending[i].in_use) handleDbVerifyResponse(daemon, batch, conn, i, false);
                }
                conn.fail("write-failed");
                return false;
            };
        }
    }
    return true;
}

/// Handle a db:verify verdict that matched a pending callback entry.
/// Answers db:result on the original inbound session, addressed to the
/// verified origin, and only while the slot still holds the session that
/// submitted the key (generation check) (S2).
fn handleDbVerifyResponse(daemon: *S2sDaemon, batch: *ChangeList, conn: *OutboundConnection, idx: usize, valid: bool) void {
    const pending = &conn.db_pending[idx];
    const inbound_slot = pending.inbound_slot;
    const gen = pending.inbound_gen;
    // Copy the origin and served target out before the entry is cleared.
    var origin_buf: [256]u8 = undefined;
    const origin_len = pending.origin_len;
    @memcpy(origin_buf[0..origin_len], pending.origin_buf[0..origin_len]);
    const origin = origin_buf[0..origin_len];
    var target_buf: [256]u8 = undefined;
    const target_len = pending.target_len;
    @memcpy(target_buf[0..target_len], pending.target_buf[0..target_len]);
    const target = target_buf[0..target_len];
    conn.clearPendingVerify(idx);

    const session = daemon.getInbound(inbound_slot) orelse {
        log.warn("dialback callback: inbound session {d} gone", .{inbound_slot});
        return;
    };
    if (daemon.inbound_gens[inbound_slot] != gen) {
        log.warn("dialback callback: inbound slot {d} was reused since the db:result; discarding verdict for {s}", .{ inbound_slot, origin });
        return;
    }

    // S2: bind the authenticated identity to the VERIFIED origin, not to
    // whatever the header claimed at stream open. The record happens BEFORE
    // the answer: a full domain set means the verdict cannot be honored and
    // the answer must be invalid, never a valid the session will not accept.
    var accepted = valid;
    if (valid and !session.addAuthenticatedDomain(origin)) accepted = false;

    // Send db:result response on the original inbound connection, from the
    // host the db:result named and to the verified origin (not the
    // header-claimed remote domain).
    var resp_buf: [512]u8 = undefined;
    const resp = dialback.buildDbResultResponse(
        &resp_buf,
        if (target.len > 0) target else daemon.local_domain,
        origin,
        accepted,
    ) catch return;

    session.queueWrite(resp) catch return;
    if (session.hasPendingWrite()) {
        batch.addWriteOnce(session.fd, INBOUND_UDATA_BASE + inbound_slot) catch {};
    }

    if (accepted) {
        session.inbound_dialback.setValid();
        session.stream.setAuthenticated();
        log.info("dialback callback: {s} verified, inbound session {d} authenticated", .{ origin, inbound_slot });
    } else {
        session.inbound_dialback.setInvalid();
        log.warn("dialback callback: {s} rejected for inbound session {d}", .{ origin, inbound_slot });
    }
}

/// Execute an S2sStreamAction by building and queuing the appropriate XML response.
fn executeAction(daemon: *S2sDaemon, session: *S2sSession, action: S2sStreamAction, batch: ?*ChangeList) void {
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

            // Only upgrade once the plaintext buffer is fully flushed: a
            // partially sent <proceed/> would otherwise leak into the TLS
            // record stream (T250). A partial flush (no error) defers the
            // upgrade to the writable handler; a write error closes.
            const flushed = session.flushWrite() catch {
                log.err("inbound S2S id={d} write error at STARTTLS proceed", .{session.id});
                if (batch) |b| daemon.closeInbound(b, session.id);
                return;
            };
            if (flushed) {
                if (daemon.tls_ctx) |ctx| {
                    session.upgradeToTls(ctx) catch {
                        log.err("inbound S2S id={d} TLS upgrade failed", .{session.id});
                        return;
                    };
                    log.info("inbound S2S id={d} starting TLS handshake", .{session.id});
                } else {
                    log.warn("inbound S2S id={d} STARTTLS requested but no TLS configured", .{session.id});
                }
            } else {
                if (daemon.tls_ctx) |ctx| {
                    session.tls_upgrade_pending = true;
                    session.pending_tls_ctx = ctx;
                } else {
                    log.warn("inbound S2S id={d} STARTTLS requested but no TLS configured", .{session.id});
                }
            }
        },
        .send_sasl_success => {
            // S2: SASL EXTERNAL accepted (the FSM only reaches here after
            // DANE verified): the verified domain joins the authenticated
            // set. When the set is full the identity cannot be recorded and
            // the exchange fails instead of succeeding unrecorded.
            if (!session.promoteDaneCandidate()) {
                log.warn("inbound S2S id={d}: authenticated-domain set full; SASL EXTERNAL rejected", .{session.id});
                const failure = session.buildSaslFailure(&buf, "policy") catch return;
                session.queueWrite(failure) catch {};
                return;
            }
            const success = session.buildSaslSuccess(&buf) catch return;
            session.queueWrite(success) catch {};
            _ = session.flushWrite() catch {};
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
        daemon.closeInbound(batch, slot);
        return;
    };

    // A <proceed/> whose flush had fallen short now drained: run the
    // deferred TLS upgrade (T250).
    if (session.tls_upgrade_pending and !session.hasPendingWrite()) {
        session.tls_upgrade_pending = false;
        if (session.pending_tls_ctx) |ctx| {
            session.pending_tls_ctx = null;
            session.upgradeToTls(ctx) catch {
                log.err("inbound S2S id={d} deferred TLS upgrade failed", .{session.id});
                daemon.closeInbound(batch, slot);
                return;
            };
            log.info("inbound S2S id={d} starting TLS handshake (deferred)", .{session.id});
            batch.addRead(session.fd, INBOUND_UDATA_BASE + slot) catch {};
        }
        return;
    }

    // If still more to write, re-register for another one-shot write event
    if (session.hasPendingWrite()) {
        batch.addWriteOnce(session.fd, INBOUND_UDATA_BASE + slot) catch {};
    }
}

// ============================================================================
// Outbound connection event handlers
// ============================================================================

/// Handle a writable event on an outbound connection.
/// First writable event means TCP connect completed. Then drive the stream protocol.
fn handleOutboundWritable(daemon: *S2sDaemon, batch: *ChangeList, slot: usize) void {
    if (slot >= MAX_OUTBOUND_CONNS) return;
    const conn = daemon.outbound[slot] orelse return;

    switch (conn.state) {
        .connecting => {
            // TCP connect completed — check for errors
            var err_opt: c_int = 0;
            var optlen: posix.socklen_t = @sizeOf(c_int);
            const rc = std.c.getsockopt(conn.fd, posix.SOL.SOCKET, posix.SO.ERROR, std.mem.asBytes(&err_opt), &optlen);
            if (rc != 0 or err_opt != 0) {
                log.err("outbound TCP connect failed for {s}", .{conn.remote_domain});
                conn.fail("tcp-connect-failed");
                daemon.closeOutbound(batch, slot);
                return;
            }

            log.info("outbound TCP connected to {s}:{d}", .{ conn.target_host, conn.target_port });
            conn.tcpConnected();

            if (conn.is_direct_tls) {
                // Direct TLS — start handshake immediately
                startOutboundTls(daemon, batch, slot, conn);
            } else {
                // STARTTLS path — send stream open first via write buffer
                var buf: [2048]u8 = undefined;
                const stream_open = conn.buildStreamOpen(&buf) catch return;
                conn.queueWrite(stream_open) catch {
                    conn.fail("write-failed");
                    daemon.closeOutbound(batch, slot);
                    return;
                };
                _ = conn.flushWrite() catch {
                    conn.fail("write-failed");
                    daemon.closeOutbound(batch, slot);
                    return;
                };
                // Wait for remote stream open + features
                batch.addRead(conn.fd, OUTBOUND_UDATA_BASE + slot) catch {};
                if (conn.hasPendingWrite()) {
                    batch.addWriteOnce(conn.fd, OUTBOUND_UDATA_BASE + slot) catch {};
                }
            }
        },
        .tls_handshake => {
            // TLS handshake wants to write
            continueOutboundTls(daemon, batch, slot, conn);
        },
        else => {
            // Flush pending write buffer
            _ = conn.flushWrite() catch {
                conn.fail("write-failed");
                daemon.closeOutbound(batch, slot);
                return;
            };
            // db:verify stanzas that could not be queued earlier go out on
            // this writable edge, but only once the stream is past the
            // post-TLS features: earlier the key would travel in cleartext.
            if (conn.hasUnsentVerify() and conn.canSendDbVerify() and
                !sendDbVerifyOnCallback(daemon, batch, conn))
            {
                daemon.closeOutbound(batch, slot);
                return;
            }
            // T275: resume a kept stanza tail on the writable edge
            // even when no new stanza arrives; an idle link stranded it.
            if (conn.state == .established and !conn.hasPendingWrite() and conn.pendingCount() > 0) {
                daemon.flushOutboundStanzas(batch, conn);
            }
            if (conn.hasPendingWrite()) {
                batch.addWriteOnce(conn.fd, OUTBOUND_UDATA_BASE + slot) catch {};
            }
        },
    }
}

/// Handle a readable event on an outbound connection.
fn handleOutboundReadable(daemon: *S2sDaemon, batch: *ChangeList, slot: usize) void {
    if (slot >= MAX_OUTBOUND_CONNS) return;
    const conn = daemon.outbound[slot] orelse return;

    if (conn.isTlsHandshaking()) {
        continueOutboundTls(daemon, batch, slot, conn);
        return;
    }

    const n = conn.recv() catch |err| {
        switch (err) {
            error.WouldBlock => return,
            else => {
                conn.fail("read-failed");
                daemon.closeOutbound(batch, slot);
                return;
            },
        }
    };
    if (n == 0) {
        log.info("outbound connection to {s} closed by peer", .{conn.remote_domain});
        daemon.closeOutbound(batch, slot);
        return;
    }

    // Parse XML from the persistent read buffer
    const reader = daemon.outbound_readers[slot] orelse return;
    const data = conn.readableSlice();
    var pos: usize = 0;

    while (true) {
        const event = reader.next(data, &pos) catch {
            conn.fail("xml-parse-error");
            daemon.closeOutbound(batch, slot);
            return;
        };
        if (event == null) break;

        processOutboundEvent(daemon, batch, slot, conn, reader, event.?);

        // Connection may have been closed
        if (daemon.outbound[slot] == null) return;

        // After STARTTLS, stop processing pre-TLS buffer (T250).
        if (conn.isTlsHandshaking()) break;
    }

    // Mark consumed bytes
    if (pos > 0) conn.consume(pos);

    // STARTTLS read-ahead hygiene (T250): plaintext past <proceed/> means
    // the remote spoke before we started TLS: protocol violation, close.
    if (conn.isTlsHandshaking() and conn.read_start < conn.read_end) {
        log.warn("outbound to {s}: {d} plaintext bytes after <proceed/>: policy violation, closing", .{ conn.remote_domain, conn.read_end - conn.read_start });
        conn.fail("policy-violation");
        daemon.closeOutbound(batch, slot);
        return;
    }

    // Request write notification if there's data to flush
    if (conn.hasPendingWrite()) {
        batch.addWriteOnce(conn.fd, OUTBOUND_UDATA_BASE + slot) catch {};
    }
}

/// Process a single XML event from a remote server on an outbound connection.
fn processOutboundEvent(
    daemon: *S2sDaemon,
    batch: *ChangeList,
    slot: usize,
    conn: *OutboundConnection,
    reader: *XmlReader,
    event: XmlEvent,
) void {
    switch (event) {
        .stream_open => |elem| {
            // Extract remote stream ID and from
            var from: []const u8 = "";
            var id: []const u8 = "";
            for (elem.attributes) |attr| {
                if (std.mem.eql(u8, attr.local_name, "from")) from = attr.value;
                if (std.mem.eql(u8, attr.local_name, "id")) id = attr.value;
            }
            conn.handleRemoteStreamOpen(from, id);
        },
        .element_start => |elem| {
            // <starttls> features
            if (std.mem.eql(u8, elem.namespace_uri, xml.ns.tls)) {
                if (std.mem.eql(u8, elem.local_name, "proceed")) {
                    log.info("outbound STARTTLS proceed from {s}", .{conn.remote_domain});
                    reader.reset();
                    if (conn.handleStarttlsProceed()) {
                        startOutboundTls(daemon, batch, slot, conn);
                    } else {
                        // Pending local bytes at <proceed/>: they were queued
                        // after <starttls/>, so sending them now would push
                        // plaintext into the TLS record layer. Close (T250).
                        log.warn("outbound {s}: plaintext queued after <starttls/> at <proceed/>", .{conn.remote_domain});
                        daemon.closeOutbound(batch, slot);
                    }
                }
            }
            // <stream:features> children
            else if (std.mem.eql(u8, elem.local_name, "mechanisms") and
                std.mem.eql(u8, elem.namespace_uri, xml.ns.sasl))
            {
                // Will parse mechanisms from child elements
            } else if (std.mem.eql(u8, elem.local_name, "mechanism") and
                std.mem.eql(u8, elem.namespace_uri, xml.ns.sasl))
            {
                // Individual mechanism — text content in next event
            } else if (std.mem.eql(u8, elem.local_name, "starttls") and
                std.mem.eql(u8, elem.namespace_uri, xml.ns.tls))
            {
                // Remote offers STARTTLS
            } else if (std.mem.eql(u8, elem.local_name, "success") and
                std.mem.eql(u8, elem.namespace_uri, xml.ns.sasl))
            {
                log.info("outbound SASL success from {s}", .{conn.remote_domain});
                conn.handleAuthSuccess();

                // Stream restart after SASL — must open new stream
                reader.reset();
                var rst_buf: [2048]u8 = undefined;
                const stream_open = conn.buildStreamOpen(&rst_buf) catch return;
                conn.queueWrite(stream_open) catch return;
                _ = conn.flushWrite() catch return;
            } else if (std.mem.eql(u8, elem.local_name, "failure") and
                std.mem.eql(u8, elem.namespace_uri, xml.ns.sasl))
            {
                log.warn("outbound SASL failure from {s}", .{conn.remote_domain});
                conn.handleAuthFailure();
                daemon.closeOutbound(batch, slot);
            }
            // Handle dialback result response: <db:result type='valid'/>
            else if (std.mem.eql(u8, elem.local_name, "result") and
                std.mem.eql(u8, elem.namespace_uri, xml.ns.dialback))
            {
                var result_type: []const u8 = "";
                var r_id: []const u8 = "";
                var r_from: []const u8 = "";
                var r_to: []const u8 = "";
                for (elem.attributes) |attr| {
                    if (std.mem.eql(u8, attr.local_name, "type")) result_type = attr.value;
                    if (std.mem.eql(u8, attr.local_name, "id")) r_id = attr.value;
                    if (std.mem.eql(u8, attr.local_name, "from")) r_from = attr.value;
                    if (std.mem.eql(u8, attr.local_name, "to")) r_to = attr.value;
                }
                // XEP-0185: the verdict on our db:verify is a typed db:result
                // echoing the id. Complete the matching callback entry only;
                // an unmatched verdict never authenticates anything here.
                if (result_type.len > 0) {
                    if (conn.findPendingVerify(r_id, r_from, r_to)) |idx| {
                        log.info("dialback callback: db:result verdict type={s} from {s}", .{ result_type, conn.remote_domain });
                        handleDbVerifyResponse(daemon, batch, conn, idx, std.mem.eql(u8, result_type, "valid"));
                        return;
                    }
                    // The verdict on the dialback key this connection sent:
                    // it authenticates the connection only while that
                    // exchange is outstanding.
                    if (conn.takePendingAssertion(r_from, r_to)) {
                        if (std.mem.eql(u8, result_type, "valid")) {
                            log.info("outbound dialback verified by {s}", .{conn.remote_domain});
                            conn.handleAuthSuccess();
                            daemon.flushOutboundStanzas(batch, conn);
                        } else {
                            log.warn("outbound dialback rejected by {s}: type={s}", .{ conn.remote_domain, result_type });
                            conn.handleAuthFailure();
                            daemon.closeOutbound(batch, slot);
                        }
                        return;
                    }
                    log.warn("dialback: unmatched db:result verdict type={s} from {s} (id={s} from={s} to={s}); ignored", .{ result_type, conn.remote_domain, r_id, r_from, r_to });
                }
            }
            // Handle db:verify response (dialback callback path)
            else if (std.mem.eql(u8, elem.local_name, "verify") and
                std.mem.eql(u8, elem.namespace_uri, xml.ns.dialback))
            {
                var verify_type: []const u8 = "";
                var v_id: []const u8 = "";
                var v_from: []const u8 = "";
                var v_to: []const u8 = "";
                for (elem.attributes) |attr| {
                    if (std.mem.eql(u8, attr.local_name, "type")) verify_type = attr.value;
                    if (std.mem.eql(u8, attr.local_name, "id")) v_id = attr.value;
                    if (std.mem.eql(u8, attr.local_name, "from")) v_from = attr.value;
                    if (std.mem.eql(u8, attr.local_name, "to")) v_to = attr.value;
                }
                if (verify_type.len == 0) return;
                // Correlate by id/from/to before acting (S2): a verdict
                // that names no pending exchange is ignored.
                const idx = conn.findPendingVerify(v_id, v_from, v_to) orelse {
                    log.warn("dialback callback: unmatched db:verify verdict from {s} (id={s} from={s} to={s}); ignored", .{ conn.remote_domain, v_id, v_from, v_to });
                    return;
                };
                const valid = std.mem.eql(u8, verify_type, "valid");
                log.info("dialback callback: db:verify response type={s} from {s}", .{ verify_type, conn.remote_domain });
                handleDbVerifyResponse(daemon, batch, conn, idx, valid);
            }
        },
        .element_end => |name| {
            // End of <stream:features> — decide what to do
            if (std.mem.eql(u8, name, "features") or std.mem.eql(u8, name, "stream:features")) {
                // Post-auth features: connection is established, flush queued stanzas
                if (conn.state == .established) {
                    log.info("outbound S2S to {s} fully established", .{conn.remote_domain});
                    daemon.flushOutboundStanzas(batch, conn);
                    return;
                }

                // Dialback callback: after TLS+features, send db:verify
                // instead of auth. Pre-TLS features must fall through to
                // STARTTLS first: the key never travels in cleartext.
                if (conn.hasPendingVerify() and conn.canSendDbVerify()) {
                    if (!sendDbVerifyOnCallback(daemon, batch, conn)) {
                        daemon.closeOutbound(batch, slot);
                    }
                    return;
                }

                const action = conn.handleRemoteFeatures(
                    conn.stream.dane_verified,
                    !conn.stream.dane_verified,
                );
                switch (action) {
                    .send_starttls => {
                        var act_buf: [256]u8 = undefined;
                        const starttls = conn.buildStarttls(&act_buf) catch return;
                        conn.queueWrite(starttls) catch return;
                        _ = conn.flushWrite() catch return;
                    },
                    .send_sasl_external => {
                        var act_buf: [512]u8 = undefined;
                        const ext = conn.buildSaslExternal(&act_buf) catch return;
                        conn.queueWrite(ext) catch return;
                        _ = conn.flushWrite() catch return;
                    },
                    .begin_dialback => {
                        const stream_id = conn.getRemoteStreamId();
                        if (stream_id.len == 0) {
                            log.err("outbound dialback for {s}: no remote stream ID", .{conn.remote_domain});
                            return;
                        }
                        const key_hex = dialback.computeKeyHex(
                            &daemon.dialback_secret,
                            conn.remote_domain,
                            conn.local_domain,
                            stream_id,
                        );
                        var db_buf: [512]u8 = undefined;
                        const db_result = dialback.buildDbResult(
                            &db_buf,
                            conn.local_domain,
                            conn.remote_domain,
                            &key_hex,
                        ) catch return;
                        conn.queueWrite(db_result) catch return;
                        _ = conn.flushWrite() catch return;
                        conn.db_assertion_pending = true;
                        log.info("outbound dialback key sent to {s}", .{conn.remote_domain});
                    },
                    .none => {},
                }
            }
        },
        .stream_close => {
            log.info("outbound stream closed by {s}", .{conn.remote_domain});
            daemon.closeOutbound(batch, slot);
        },
        .xml_declaration => {},
        .text => {},
    }
}

/// Start an outbound TLS handshake using the client context.
fn startOutboundTls(daemon: *S2sDaemon, batch: *ChangeList, slot: usize, conn: *OutboundConnection) void {
    const ctx = daemon.tls_client_ctx orelse {
        conn.fail("no-client-tls-context");
        daemon.closeOutbound(batch, slot);
        return;
    };

    conn.upgradeToTls(ctx) catch {
        conn.fail("tls-init-failed");
        daemon.closeOutbound(batch, slot);
        return;
    };

    conn.state = .tls_handshake;
    continueOutboundTls(daemon, batch, slot, conn);
}

/// Continue a non-blocking outbound TLS handshake.
fn continueOutboundTls(daemon: *S2sDaemon, batch: *ChangeList, slot: usize, conn: *OutboundConnection) void {
    const complete = conn.continueHandshake() catch {
        log.err("outbound TLS handshake failed for {s}", .{conn.remote_domain});
        conn.fail("tls-handshake-failed");
        daemon.closeOutbound(batch, slot);
        return;
    };

    if (complete) {
        // Q11: offload fallback is silent, so engagement, version and cipher
        // are logged once per handshake (tokens: ktls, ktls-tx, ktls-rx, sw).
        if (conn.tls_conn) |*tls| {
            const mode: []const u8 = if (tls.ktlsSend() and tls.ktlsRecv()) "ktls" else if (tls.ktlsSend()) "ktls-tx" else if (tls.ktlsRecv()) "ktls-rx" else "sw";
            log.info("outbound TLS handshake complete for {s} version={s} cipher={s} mode={s}", .{ conn.remote_domain, tls.versionName(), tls.cipherName(), mode });
        } else {
            log.info("outbound TLS handshake complete for {s} mode=none", .{conn.remote_domain});
        }
        conn.tlsHandshakeComplete();

        // Reset XML reader for post-TLS stream restart
        if (daemon.outbound_readers[slot]) |reader| reader.reset();
        // Invariant per T250: no plaintext may outlive <proceed/>
        // (leftovers are rejected with policy-violation); zero for safety.
        conn.read_start = 0;
        conn.read_end = 0;

        // DANE verification. performOutboundDane may closeOutbound (frees
        // conn and clears the slot): read the slot table afterwards, never
        // the possibly-freed pointer (T277).
        performOutboundDane(daemon, batch, slot, conn);

        // If DANE failed, connection was closed
        if (daemon.outbound[slot] == null) return;

        // Send post-TLS stream open
        var buf: [2048]u8 = undefined;
        const stream_open = conn.buildStreamOpen(&buf) catch return;
        conn.queueWrite(stream_open) catch {
            conn.fail("write-failed");
            daemon.closeOutbound(batch, slot);
            return;
        };
        _ = conn.flushWrite() catch {
            conn.fail("write-failed");
            daemon.closeOutbound(batch, slot);
            return;
        };

        // Wait for remote stream open + features
        batch.addRead(conn.fd, OUTBOUND_UDATA_BASE + slot) catch {};
        if (conn.hasPendingWrite()) {
            batch.addWriteOnce(conn.fd, OUTBOUND_UDATA_BASE + slot) catch {};
        }
    } else {
        // Re-arm the appropriate kqueue filter for next handshake step
        if (conn.tls_state) |state| {
            switch (state) {
                .handshake_want_read => batch.addRead(conn.fd, OUTBOUND_UDATA_BASE + slot) catch {},
                // One-shot: same persistent-write spin trap as the inbound
                // hold (S10).
                .handshake_want_write => batch.addWriteOnce(conn.fd, OUTBOUND_UDATA_BASE + slot) catch {},
                .established => {},
            }
        }
    }
}

/// Perform DANE verification after outbound TLS handshake.
fn performOutboundDane(daemon: *S2sDaemon, batch: *ChangeList, slot: usize, conn: *OutboundConnection) void {
    // Test seam: a forced verdict skips the live TLSA query and chain
    // verification (T277 regression rig); production leaves it null.
    if (daemon.dane_verdict_override) |verdict| {
        conn.setDaneResult(verdict);
        if (conn.isFailed()) {
            daemon.closeOutbound(batch, slot);
        }
        return;
    }

    const dane_mod = @import("dane.zig");

    // Query TLSA records for the target host/port
    const tlsa_records = dns.resolver.queryTlsa(daemon.allocator, conn.target_port, conn.target_host) catch |err| {
        log.warn("TLSA query failed for {s}:{d}: {}", .{ conn.target_host, conn.target_port, err });
        conn.setDaneResult(.no_records);
        return;
    };
    defer {
        for (tlsa_records) |rec| daemon.allocator.free(rec.association_data);
        daemon.allocator.free(tlsa_records);
    }

    if (tlsa_records.len == 0) {
        log.info("no TLSA records for {s}:{d} — will use dialback", .{ conn.target_host, conn.target_port });
        conn.setDaneResult(.no_records);
        return;
    }

    // Extract peer certificate chain from TLS connection
    if (conn.tls_conn) |*tls| {
        const leaf_der = tls.getPeerCertDer(daemon.allocator) catch {
            conn.setDaneResult(.no_records);
            return;
        };
        if (leaf_der == null) {
            log.warn("no peer certificate for {s}", .{conn.remote_domain});
            conn.setDaneResult(.no_records);
            return;
        }
        defer daemon.allocator.free(leaf_der.?);

        const chain_der = tls.getPeerChainDer(daemon.allocator) catch {
            conn.setDaneResult(.no_records);
            return;
        };
        defer {
            for (chain_der) |cert| daemon.allocator.free(cert);
            daemon.allocator.free(chain_der);
        }

        // Convert dns.TlsaRecord → dane.DnsTlsaRecord for the bridge
        var dane_records = daemon.allocator.alloc(dane_mod.DnsTlsaRecord, tlsa_records.len) catch {
            conn.setDaneResult(.no_records);
            return;
        };
        defer daemon.allocator.free(dane_records);
        for (tlsa_records, 0..) |rec, i| {
            dane_records[i] = .{
                .usage = rec.usage,
                .selector = rec.selector,
                .matching_type = rec.matching_type,
                .association_data = rec.association_data,
            };
        }

        const status = dane_mod.verifyDane(daemon.allocator, leaf_der.?, chain_der, dane_records);
        log.info("DANE result for {s}: {s}", .{
            conn.remote_domain,
            switch (status) {
                .verified => "verified",
                .no_records => "no-records",
                .failed => "FAILED",
                .pending => "pending",
            },
        });
        conn.setDaneResult(status);

        if (conn.isFailed()) {
            daemon.closeOutbound(batch, slot);
        }
    } else {
        conn.setDaneResult(.no_records);
    }
}

/// Perform DANE verification for an inbound S2S session.
/// Called after post-TLS stream open reveals the remote domain.
/// Queries TLSA for the standard S2S port of the remote domain and
/// verifies against the presented peer certificate.
fn performInboundDane(daemon: *S2sDaemon, session: *S2sSession, remote_domain: []const u8) void {
    const dane_mod = @import("dane.zig");

    // The candidate promotes into the session's authenticated set only if
    // the SASL EXTERNAL exchange succeeds (S2).
    session.setDaneCandidate(remote_domain);

    // Resolve the remote's SRV to find their actual S2S port for TLSA query
    const targets = dns.resolver.resolveXmpp(daemon.allocator, remote_domain, true) catch {
        session.stream.setDaneVerified(false);
        return;
    };
    defer {
        for (targets) |t| daemon.allocator.free(t.host);
        daemon.allocator.free(targets);
    }
    const tlsa_port: u16 = if (targets.len > 0) targets[0].port else 5269;
    const tlsa_host = if (targets.len > 0) targets[0].host else remote_domain;

    const tlsa_records = dns.resolver.queryTlsa(daemon.allocator, tlsa_port, tlsa_host) catch {
        session.stream.setDaneVerified(false);
        return;
    };
    defer {
        for (tlsa_records) |rec| daemon.allocator.free(rec.association_data);
        if (tlsa_records.len > 0) daemon.allocator.free(tlsa_records);
    }

    if (tlsa_records.len == 0) {
        log.info("inbound DANE: no TLSA records for {s}", .{remote_domain});
        session.stream.setDaneVerified(false);
        return;
    }

    // Get peer cert from the TLS session
    if (session.tls_conn) |*tls| {
        const leaf_der = tls.getPeerCertDer(daemon.allocator) catch {
            session.stream.setDaneVerified(false);
            return;
        };
        if (leaf_der == null) {
            log.info("inbound DANE: no peer certificate from {s}", .{remote_domain});
            session.stream.setDaneVerified(false);
            return;
        }
        defer daemon.allocator.free(leaf_der.?);

        const chain_der = tls.getPeerChainDer(daemon.allocator) catch {
            session.stream.setDaneVerified(false);
            return;
        };
        defer {
            for (chain_der) |cert| daemon.allocator.free(cert);
            daemon.allocator.free(chain_der);
        }

        // Convert and verify
        var dane_records = daemon.allocator.alloc(dane_mod.DnsTlsaRecord, tlsa_records.len) catch {
            session.stream.setDaneVerified(false);
            return;
        };
        defer daemon.allocator.free(dane_records);
        for (tlsa_records, 0..) |rec, i| {
            dane_records[i] = .{
                .usage = rec.usage,
                .selector = rec.selector,
                .matching_type = rec.matching_type,
                .association_data = rec.association_data,
            };
        }

        const status = dane_mod.verifyDane(daemon.allocator, leaf_der.?, chain_der, dane_records);
        const verified = (status == .verified);
        session.stream.setDaneVerified(verified);
        log.info("inbound DANE for {s}: {s}", .{
            remote_domain,
            if (verified) "verified" else "not verified (will offer dialback)",
        });
    } else {
        session.stream.setDaneVerified(false);
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

/// Close an IPC client lane with full hygiene: purges its staged kevent
/// entries first (T277). A same-iteration accept may reuse the fd number,
/// and still-staged add/remove entries would attach to the new socket.
fn closeIpcClientLane(daemon: *S2sDaemon, batch: *ChangeList, ipc_slot: usize) void {
    const client = daemon.ipc.getClient(ipc_slot) orelse return;
    batch.purgeFd(client.fd);
    daemon.ipc.closeClient(ipc_slot);
}

/// Handle readable data on an IPC client connection.
fn handleIpcReadable(daemon: *S2sDaemon, batch: *ChangeList, ipc_slot: usize) void {
    const client = daemon.ipc.getClient(ipc_slot) orelse return;

    const n = client.recv() catch {
        closeIpcClientLane(daemon, batch, ipc_slot);
        return;
    };
    if (n == 0) {
        // EOF — core disconnected
        log.info("core disconnected from IPC slot={d}", .{ipc_slot});
        closeIpcClientLane(daemon, batch, ipc_slot);
        return;
    }

    // Process all complete messages in the buffer
    while (true) {
        const msg = client.nextMessage() catch {
            log.err("IPC decode error on slot={d}", .{ipc_slot});
            closeIpcClientLane(daemon, batch, ipc_slot);
            return;
        };
        if (msg == null) break;
        daemon.handleCoreMessage(batch, msg.?);
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
        closeIpcClientLane(daemon, batch, ipc_slot);
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
        \\  --muc-host HOST     Served MUC domain for the to= check (from master's [muc] host)
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
    var daemon = try S2sDaemon.init(alloc, "a.example");
    defer daemon.deinit();

    try std.testing.expectEqual(@as(usize, 0), daemon.pool.count());
    try std.testing.expectEqual(@as(usize, 0), daemon.inboundCount());
    try std.testing.expect(daemon.running);
}

test "S2sDaemon: listen on high port" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "a.example");
    defer daemon.deinit();

    try daemon.listen("127.0.0.1", 0);
    try std.testing.expect(daemon.listener_fd >= 0);
}

test "S2sDaemon: accept inbound" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "a.example");
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
    var daemon = try S2sDaemon.init(alloc, "a.example");
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

    var scratch: [8]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    daemon.closeInbound(&cl, slot);
    try std.testing.expectEqual(@as(usize, 0), daemon.inboundCount());
}

/// Test allocator that poisons freed chunks, so a write-after-free is
/// visible by reading through the old pointer (S2, reject path).
const PoisonOnFreeAllocator = struct {
    inner: std.mem.Allocator,
    /// Freed chunks quarantined instead of handed back to the backing
    /// allocator: the poison fill stays checkable while this allocator
    /// still owns the bytes. Reading a chunk after the real free is
    /// undefined, so tests check through here.
    quarantine: [MAX_QUARANTINE]Quarantined = undefined,
    quarantine_len: usize = 0,
    /// Poison snapshot of the frees seen so far, captured at free time.
    biggest_freed_len: usize = 0,
    poisoned_prefix: [8]u8 = [_]u8{0} ** 8,
    poisoned_bytes: usize = 0,

    const MAX_QUARANTINE = 64;
    const Quarantined = struct {
        ptr: [*]u8,
        len: usize,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    };

    fn allocator(self: *PoisonOnFreeAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = allocFn,
            .resize = resizeFn,
            .remap = remapFn,
            .free = freeFn,
        } };
    }
    fn allocFn(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *PoisonOnFreeAllocator = @ptrCast(@alignCast(ctx));
        return self.inner.rawAlloc(len, alignment, ret_addr);
    }
    fn resizeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *PoisonOnFreeAllocator = @ptrCast(@alignCast(ctx));
        return self.inner.rawResize(memory, alignment, new_len, ret_addr);
    }
    fn remapFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *PoisonOnFreeAllocator = @ptrCast(@alignCast(ctx));
        return self.inner.rawRemap(memory, alignment, new_len, ret_addr);
    }
    fn freeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *PoisonOnFreeAllocator = @ptrCast(@alignCast(ctx));
        @memset(memory, 0xA5);
        self.poisoned_bytes += memory.len;
        if (memory.len >= self.biggest_freed_len) {
            self.biggest_freed_len = memory.len;
            const n = @min(memory.len, self.poisoned_prefix.len);
            @memcpy(self.poisoned_prefix[0..n], memory[0..n]);
        }
        if (self.quarantine_len == self.quarantine.len) {
            self.inner.rawFree(memory, alignment, ret_addr);
            return;
        }
        self.quarantine[self.quarantine_len] = .{
            .ptr = memory.ptr,
            .len = memory.len,
            .alignment = alignment,
            .ret_addr = ret_addr,
        };
        self.quarantine_len += 1;
    }

    /// Check every quarantined chunk is still poison-filled: a write
    /// through a stale pointer after its free would show here.
    fn checkQuarantine(self: *PoisonOnFreeAllocator) !void {
        for (self.quarantine[0..self.quarantine_len]) |q| {
            if (!std.mem.allEqual(u8, q.ptr[0..q.len], 0xA5)) return error.FreedMemoryWasWritten;
        }
    }

    /// Return every quarantined chunk to the backing allocator.
    fn releaseQuarantine(self: *PoisonOnFreeAllocator) void {
        for (self.quarantine[0..self.quarantine_len]) |q| {
            self.inner.rawFree(q.ptr[0..q.len], q.alignment, q.ret_addr);
        }
        self.quarantine_len = 0;
    }
};

test "S2sDaemon: stanza reject path resets before closeInbound frees" {
    // resetStanza must run BEFORE closeInbound destroys the session here:
    // DebugAllocator re-poisons with its own magic, so wrap c_allocator to
    // observe the right order on the chunk.
    var pf = PoisonOnFreeAllocator{ .inner = std.heap.c_allocator };
    const alloc = pf.allocator();
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer {
        daemon.deinit();
        pf.releaseQuarantine();
    }

    try daemon.listen("127.0.0.1", 0);
    var addr: std.c.sockaddr.in = undefined;
    var addr_len: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    _ = std.c.getsockname(daemon.listener_fd, @ptrCast(&addr), &addr_len);
    const client_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(client_fd);
    const connect_addr = std.c.sockaddr.in{ .port = addr.port, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    posix.connect(client_fd, @ptrCast(&connect_addr), @sizeOf(std.c.sockaddr.in)) catch |err| {
        if (err != error.WouldBlock) return err;
    };
    std.Thread.sleep(10 * std.time.ns_per_ms);

    const slot = (try daemon.acceptInbound()) orelse return error.NoSlot;
    const session = daemon.getInbound(slot).?;

    // A from= with nothing authenticated rejects (invalid_from).
    session.startStanza(.{
        .name = "message",
        .prefix = "",
        .local_name = "message",
        .namespace_uri = "jabber:server",
        .attributes = &.{
            .{ .name = "from", .local_name = "from", .prefix = "", .value = "eve@evil.example" },
            .{ .name = "to", .local_name = "to", .prefix = "", .value = "juliet@us.example" },
        },
        .self_closing = true,
    });

    var scratch: [8]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    dispatchInboundStanza(&daemon, session, &cl);
    try std.testing.expect(daemon.getInbound(slot) == null); // rejected and closed

    // The session chunk is still poison-filled: if resetStanza had run
    // after the free it would have written stanza_active to false through
    // the stale pointer, and the quarantined fill would show it.
    try std.testing.expect(pf.biggest_freed_len >= @sizeOf(S2sSession));
    try pf.checkQuarantine();
}

test "S2sDaemon: flushOutboundStanzas frees from/to/xml and keeps the overflow tail (T275)" {
    // std.testing.allocator reports any leak at teardown: flushed stanzas
    // must free from_jid/to_jid, and a full write buffer must keep the
    // tail queued in order.
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds) != 0)
        return error.SocketPairFailed;
    defer posix.close(fds[1]);

    const conn = try daemon.pool.getOrCreate("us.example", "them.example");
    conn.fd = fds[0];
    conn.handleAuthSuccess(); // mark established without the protocol dance

    const pad = try alloc.alloc(u8, 9000);
    defer alloc.free(pad);
    @memset(pad, 'x');
    const big = try std.fmt.allocPrint(alloc, "<message from='a@us.example' to='b@them.example'><body>{s}</body></message>", .{pad});
    defer alloc.free(big);

    try conn.queueStanza(alloc, "a@us.example", "b@them.example", "<message to='b@them.example'><body>small</body></message>");
    try conn.queueStanza(alloc, "a@us.example", "b@them.example", big);
    try conn.queueStanza(alloc, "a@us.example", "b@them.example", big); // third does not fit the 16 KiB buffer

    var scratch: [8]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    daemon.flushOutboundStanzas(&cl, conn);
    // One stanza must survive queued for the next flush, in order.
    try std.testing.expectEqual(@as(usize, 1), conn.pendingCount());
    try std.testing.expectEqualStrings("b@them.example", conn.pending_stanzas.items[0].to_jid);
}

test "S2sDaemon: a kept tail resumes on the writable edge of an idle link (T275)" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds) != 0)
        return error.SocketPairFailed;
    defer posix.close(fds[1]);

    const conn = try daemon.pool.getOrCreate("us.example", "them.example");
    conn.fd = fds[0];
    conn.handleAuthSuccess();
    daemon.outbound[0] = conn; // writable-edge dispatch finds it by slot

    const pad = try alloc.alloc(u8, 9000);
    defer alloc.free(pad);
    @memset(pad, 'x');
    const big = try std.fmt.allocPrint(alloc, "<message to='b@them.example'><body>{s}</body></message>", .{pad});
    defer alloc.free(big);

    try conn.queueStanza(alloc, "a@us.example", "b@them.example", "<message to='b@them.example'><body>small</body></message>");
    try conn.queueStanza(alloc, "a@us.example", "b@them.example", big);
    try conn.queueStanza(alloc, "a@us.example", "b@them.example", big);

    var scratch: [8]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    daemon.flushOutboundStanzas(&cl, conn);
    try std.testing.expectEqual(@as(usize, 1), conn.pendingCount()); // tail kept

    // The drained socket left hasPendingWrite() false, so the kept tail
    // must arm its own one-shot write event: without the event the tail is
    // stranded until the next stanza arrives (T275).
    try std.testing.expect(!conn.hasPendingWrite());
    try std.testing.expectEqual(@as(usize, 1), cl.count());
    const ev = cl.slice()[0];
    try std.testing.expect(ev.filter == std.c.EVFILT.WRITE);
    try std.testing.expect(ev.flags & std.c.EV.ONESHOT != 0);
    try std.testing.expectEqual(@as(@TypeOf(ev.ident), @intCast(fds[0])), ev.ident);
    try std.testing.expectEqual(@as(@TypeOf(ev.udata), OUTBOUND_UDATA_BASE), ev.udata);

    // Drain the peer so the next flush has room, then fire the writable
    // edge with NO new stanza arriving: the tail must resume by itself.
    var rbuf: [20480]u8 = undefined;
    _ = drainPeer(fds[1], &rbuf);
    handleOutboundWritable(&daemon, &cl, 0);
    try std.testing.expectEqual(@as(usize, 0), conn.pendingCount());
    const got = rbuf[0..drainPeer(fds[1], &rbuf)];
    try std.testing.expect(std.mem.indexOf(u8, got, "b@them.example") != null);
}

test "S2sDaemon: an oversize stanza is delivery-failed instead of wedging the queue (T275)" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds) != 0)
        return error.SocketPairFailed;
    defer posix.close(fds[1]);

    const conn = try daemon.pool.getOrCreate("us.example", "them.example");
    conn.fd = fds[0];
    conn.handleAuthSuccess();

    // A stanza that can never fit the 16 KiB write buffer, queued ahead of
    // a deliverable one: it must fail delivery and let the follower out.
    const huge_pad = try alloc.alloc(u8, 20000);
    defer alloc.free(huge_pad);
    @memset(huge_pad, 'y');
    const huge = try std.fmt.allocPrint(alloc, "<message to='b@them.example'><body>{s}</body></message>", .{huge_pad});
    defer alloc.free(huge);

    try conn.queueStanza(alloc, "a@us.example", "b@them.example", huge);
    try conn.queueStanza(alloc, "a@us.example", "b@them.example", "<message to='b@them.example'><body>after</body></message>");

    // A connected core client makes the delivery-failure notice observable.
    const client = &daemon.ipc.clients[0];
    client.* = .{};
    client.fd = -1; // buffer-only; never flushed
    client.alloc = alloc;
    client.active = true;

    var scratch: [8]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    daemon.flushOutboundStanzas(&cl, conn);

    // The queue drains: oversize failed to the sender, the follower went out.
    try std.testing.expectEqual(@as(usize, 0), conn.pendingCount());
    var rbuf: [4096]u8 = undefined;
    const got = rbuf[0..drainPeer(fds[1], &rbuf)];
    try std.testing.expect(std.mem.indexOf(u8, got, "after") != null);

    // The bounce reached the core client as a delivery-failed notice.
    const frame = protocol.readFrame(client.send_list.items[client.send_start..]) orelse return error.NoDeliveryFailedNotice;
    const notice = try protocol.decode(frame.payload);
    try std.testing.expectEqualStrings("stanza-too-large", notice.s2s_delivery_failed.error_type);
    try std.testing.expectEqualStrings("a@us.example", notice.s2s_delivery_failed.from_jid);
    try std.testing.expectEqualStrings("b@them.example", notice.s2s_delivery_failed.to_jid);
}

test "S2sDaemon: stop" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "a.example");
    defer daemon.deinit();

    try std.testing.expect(daemon.running);
    daemon.stop();
    try std.testing.expect(!daemon.running);
}

test "S2sDaemon: inbound address validation enforces authenticated domain and served host (T351)" {
    const local = "us.example";
    const muc = "conference.us.example";

    // Happy: authenticated from= to our domain (full and bare forms).
    try std.testing.expect(validateInboundAddress(local, muc, true, "romeo@them.example/orchard", "juliet@us.example/capulet") == null);
    try std.testing.expect(validateInboundAddress(local, muc, true, "them.example", "us.example") == null);

    // from= with a domain but the session has no authentication for any of
    // it (auth_ok=false covers forging peers AND never-authenticated ones).
    try std.testing.expectEqual(StreamError.invalid_from, validateInboundAddress(local, muc, false, "user@them.example", "juliet@us.example").?);
    // A bare "from=naked" IS a valid domain JID; it is only rejected because
    // nothing authenticates it (auth_ok=false comes from the session set).
    try std.testing.expectEqual(StreamError.invalid_from, validateInboundAddress(local, muc, false, "naked", "juliet@us.example").?);
    // Truly empty from= is a format rejection regardless.
    try std.testing.expectEqual(StreamError.invalid_from, validateInboundAddress(local, muc, true, "", "juliet@us.example").?);

    // Right sender, wrong destination domain (we do not serve it).
    try std.testing.expectEqual(StreamError.host_unknown, validateInboundAddress(local, muc, true, "romeo@them.example", "someone@else.example").?);
    try std.testing.expectEqual(StreamError.host_unknown, validateInboundAddress(local, muc, true, "romeo@them.example/c", "someone@else.example/x").?);

    // The MUC host is served for federation (conference.<host>); without a
    // muc_host configured it gets host-unknown.
    try std.testing.expect(validateInboundAddress(local, muc, true, "romeo@them.example", "r@conference.us.example") == null);
    try std.testing.expectEqual(StreamError.host_unknown, validateInboundAddress(local, null, true, "romeo@them.example", "r@conference.us.example").?);

    // Compares are case-insensitive.
    try std.testing.expect(validateInboundAddress(local, "CONFERENCE.us.example", true, "romeo@them.example", "r@Conference.US.example") == null);
    try std.testing.expect(validateInboundAddress(local, muc, true, "romeo@them.example", "juliet@US.example") == null);
}

test "S2sDaemon: jidDomain cuts at the resource separator before the localpart" {
    try std.testing.expectEqualStrings("them.example", jidDomain("user@them.example"));
    try std.testing.expectEqualStrings("them.example", jidDomain("user@them.example/orchard"));
    try std.testing.expectEqualStrings("them.example", jidDomain("them.example"));
    try std.testing.expectEqualStrings("them.example", jidDomain("them.example/orchard"));
    // Slash-first is the point: a forged domain must not survive inside the
    // resourcepart.
    try std.testing.expectEqualStrings("victim.example", jidDomain("victim.example/x@them.example"));
    try std.testing.expectEqualStrings("", jidDomain("/x"));
    try std.testing.expectEqualStrings("", jidDomain("user@/x"));
    try std.testing.expectEqualStrings("", jidDomain(""));
}

test "S2sDaemon: IPC lane close purges staged kevent entries before closeClient (T277)" {
    // Repro of the T238-class bug: closeClient on an IPC lane queued the fd
    // at + IPC_CLIENT_UDATA_BASE in a staged changelist; the same iteration
    // could then accept a fresh core connection reusing the fd number and
    // fire these entries on it. The fix (closeIpcClientLane) calls purgeFd
    // first; this test shows the outside-observable behavior: starting
    // points are staged write events, end state is zero remaining entries
    // for the dead fd.
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    // Listen on a temp socket and connect an IPC client directly.
    const path = "/tmp/xmppd-s2s-ipc-test.sock";
    std.fs.cwd().deleteFile(path) catch {};
    defer std.fs.cwd().deleteFile(path) catch {};
    try daemon.ipc.listen(path);
    defer daemon.ipc.deinit();

    const cli = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(cli);
    var uaddr: std.c.sockaddr.un = std.mem.zeroes(std.c.sockaddr.un);
    uaddr.family = posix.AF.UNIX;
    @memcpy(uaddr.path[0..path.len], path);
    posix.connect(cli, @ptrCast(&uaddr), @sizeOf(std.c.sockaddr.un)) catch |err| {
        if (err != error.WouldBlock) return err;
    };
    std.Thread.sleep(10 * std.time.ns_per_ms);

    const slot = (try daemon.ipc.accept()) orelse return error.NoClient;
    const client = daemon.ipc.getClient(slot) orelse return error.NoClient;
    const fd = client.fd;

    // Recreate the staged-entries state the T277 report saw: EV_ADD for the
    // IPC fd in the changelist while the lane is about to die.
    var scratch: [8]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    try cl.addWriteOnce(fd, IPC_CLIENT_UDATA_BASE + slot);
    // entries.length is implementation-internal; only behavior matters.

    closeIpcClientLane(&daemon, &cl, slot);

    // The accepted client must be closed (no dangling IPC lane)...
    try std.testing.expect(daemon.ipc.getClient(slot) == null);
    // ...and no staged entries must remain pointing at its fd.
    var i: usize = 0;
    while (i < cl.len) : (i += 1) {
        try std.testing.expect(cl.buf[i].ident != @as(usize, @intCast(fd)));
    }
}

// --- Test rig: drive processInboundEvent / processOutboundEvent directly ----

/// Create an inbound session in `slot` over a UNIX socketpair. Returns the
/// session and the peer fd; the test speaks the peer side.
fn makeTestInbound(alloc: std.mem.Allocator, daemon: *S2sDaemon, slot: usize) !struct { session: *S2sSession, peer_fd: posix.fd_t } {
    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds) != 0)
        return error.SocketPairFailed;
    errdefer posix.close(fds[0]);
    errdefer posix.close(fds[1]);
    const session = try alloc.create(S2sSession);
    session.* = S2sSession.init(fds[0], slot, daemon.local_domain);
    daemon.inbound[slot] = session;
    const reader = try alloc.create(XmlReader);
    errdefer alloc.destroy(reader);
    reader.* = XmlReader.init(alloc);
    daemon.readers[slot] = reader;
    return .{ .session = session, .peer_fd = fds[1] };
}

/// Read whatever is currently available on a non-blocking peer fd.
fn drainPeer(fd: posix.fd_t, buf: []u8) usize {
    var total: usize = 0;
    while (total < buf.len) {
        const n = posix.read(fd, buf[total..]) catch return total;
        if (n == 0) return total;
        total += n;
    }
    return total;
}

fn testAttr(name: []const u8, value: []const u8) xml.Attribute {
    return .{ .name = name, .value = value, .prefix = "", .local_name = name };
}

/// Feed a db:result key submission through processInboundEvent the way the
/// reader loop would (element_start, text, element_end).
fn submitDbResult(daemon: *S2sDaemon, session: *S2sSession, cl: *ChangeList, from: []const u8, to: []const u8, key: []const u8) void {
    const reader = daemon.readers[session.id].?;
    var attrs = [_]xml.Attribute{ testAttr("from", from), testAttr("to", to) };
    const elem = xml.Element{
        .name = "db:result",
        .prefix = "db",
        .local_name = "result",
        .namespace_uri = xml.ns.dialback,
        .attributes = &attrs,
        .self_closing = false,
    };
    processInboundEvent(daemon, session, reader, .{ .element_start = elem }, cl);
    processInboundEvent(daemon, session, reader, .{ .text = key }, cl);
    processInboundEvent(daemon, session, reader, .{ .element_end = "db:result" }, cl);
}

/// Feed a db:verify verdict through processOutboundEvent on a callback conn.
fn feedVerifyVerdict(daemon: *S2sDaemon, conn: *OutboundConnection, cl: *ChangeList, reader: *XmlReader, verdict: []const u8, id: []const u8, from: []const u8, to: []const u8) void {
    var attrs = [_]xml.Attribute{ testAttr("type", verdict), testAttr("id", id), testAttr("from", from), testAttr("to", to) };
    const elem = xml.Element{
        .name = "db:verify",
        .prefix = "db",
        .local_name = "verify",
        .namespace_uri = xml.ns.dialback,
        .attributes = &attrs,
        .self_closing = true,
    };
    processOutboundEvent(daemon, cl, 0, conn, reader, .{ .element_start = elem });
}

// --- T277 regression rig: real TLS handshake over loopback ----------

/// Self-signed throwaway cert for "localhost" via the openssl CLI (no key
/// material in the tree). error.SkipZigTest when the tool is missing.
fn genS2sTestCert(dir: std.fs.Dir) !void {
    const r = std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &.{ "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1", "-keyout", "key.pem", "-out", "cert.pem" },
        .cwd_dir = dir,
        .max_output_bytes = 4096,
    }) catch return error.SkipZigTest;
    defer std.testing.allocator.free(r.stdout);
    defer std.testing.allocator.free(r.stderr);
    switch (r.term) {
        .Exited => |code| {
            if (code != 0) return error.SkipZigTest;
        },
        else => return error.SkipZigTest,
    }
}

/// Connected non-blocking TCP loopback pair (AF_UNIX socketpairs do not
/// enforce SO_SNDBUF on FreeBSD).
fn makeS2sTestTcpPair() ![2]posix.fd_t {
    const listen_fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return error.SocketFailed;
    defer posix.close(listen_fd);
    var addr: std.c.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch return error.BindFailed;
    posix.listen(listen_fd, 1) catch return error.ListenFailed;
    var alen: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    posix.getsockname(listen_fd, @ptrCast(&addr), &alen) catch return error.GetSockNameFailed;

    const client_fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0) catch return error.SocketFailed;
    errdefer posix.close(client_fd);
    posix.connect(client_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch |err| switch (err) {
        error.WouldBlock => {},
        else => return error.ConnectFailed,
    };
    const server_fd = posix.accept(listen_fd, null, null, posix.SOCK.NONBLOCK) catch return error.AcceptFailed;
    errdefer posix.close(server_fd);
    return .{ client_fd, server_fd };
}

test "S2sDaemon: a DANE-failed outbound conn is never read after teardown (T277)" {
    // Poison-on-free makes any post-closeOutbound read of the conn visible.
    // The caller must consult the slot table (daemon.outbound[slot]), never
    // the conn pointer performOutboundDane may have freed. The verdict
    // override is the test seam; everything else is the real
    // handshake-complete path.
    var pf = PoisonOnFreeAllocator{ .inner = std.heap.c_allocator };
    const alloc = pf.allocator();
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer {
        daemon.deinit();
        pf.releaseQuarantine();
    }

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genS2sTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/cert.pem", .{base}, 0);
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/key.pem", .{base}, 0);
    defer std.testing.allocator.free(key_path);

    // kTLS stays off on both ends: two kTLS peers over lo0 hit FreeBSD
    // PR 296498 (EBADMSG). This rig is entirely userland TLS.
    var server_ctx = try SslContext.initServer(cert_path, key_path);
    defer server_ctx.deinit();
    server_ctx.disableKtls();
    var client_ctx = try SslContext.initClient();
    defer client_ctx.deinit();
    client_ctx.disableKtls();

    const fds = try makeS2sTestTcpPair();
    var peer = try SslConn.init(server_ctx, fds[1]);
    defer {
        peer.shutdown();
        peer.deinit();
        posix.close(fds[1]);
    }

    const conn = try daemon.pool.getOrCreate("us.example", "them.example");
    conn.fd = fds[0]; // conn.deinit closes it via closeOutbound below
    conn.tls_conn = try SslConn.initClient(client_ctx, fds[0], "localhost");
    conn.tls_state = .handshake_want_read;
    conn.state = .tls_handshake;

    const reader = try alloc.create(XmlReader);
    reader.* = XmlReader.init(alloc);
    daemon.outbound_readers[7] = reader; // closeOutbound frees it
    daemon.outbound[7] = conn;

    // Complete the handshake on both ends, then run the real post-handshake
    // path with the DANE verdict forced to failed.
    var c_done = false;
    var p_done = false;
    const deadline = std.time.milliTimestamp() + 5000;
    while ((!c_done or !p_done) and std.time.milliTimestamp() < deadline) {
        if (!c_done) c_done = try conn.continueHandshake();
        if (!p_done) p_done = (try peer.doHandshake()) == .complete;
    }
    try std.testing.expect(c_done and p_done);
    try std.testing.expect(conn.tls_state == .established);

    daemon.dane_verdict_override = .failed;
    var scratch: [8]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    continueOutboundTls(&daemon, &cl, 7, conn);

    // Teardown went through the slot table, and the conn chunk was freed
    // poison-filled. The fill is checked inside the poisoning allocator
    // while it still owns the bytes: reading a chunk after the real free
    // is undefined.
    try std.testing.expect(daemon.outbound[7] == null);
    try std.testing.expect(pf.biggest_freed_len >= @sizeOf(OutboundConnection));
    try std.testing.expect(std.mem.allEqual(u8, &pf.poisoned_prefix, 0xA5));
    try pf.checkQuarantine();
}

/// An established callback connection on a socketpair: db:verify is written
/// to the returned peer fd instead of the network, so no DNS happens.
fn makeTestCallbackConn(daemon: *S2sDaemon, origin: []const u8) !struct { conn: *OutboundConnection, peer_fd: posix.fd_t } {
    const conn = try daemon.pool.getOrCreate(daemon.local_domain, origin);
    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds) != 0)
        return error.SocketPairFailed;
    errdefer posix.close(fds[1]);
    conn.fd = fds[0]; // owned by the conn now; pool.deinit closes it
    conn.handleAuthSuccess(); // skip the protocol dance
    return .{ .conn = conn, .peer_fd = fds[1] };
}

test "S2sDaemon: dialback verdicts correlate by stream id and origin" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    const cb = try makeTestCallbackConn(&daemon, "them.example");
    defer posix.close(cb.peer_fd);

    const in1 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in1.peer_fd);
    const in2 = try makeTestInbound(alloc, &daemon, 2);
    defer posix.close(in2.peer_fd);

    var scratch: [16]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);

    const key1 = "1111111111111111111111111111111111111111111111111111111111111111";
    const key2 = "2222222222222222222222222222222222222222222222222222222222222222";
    // Two sessions claim the same origin; the second submission must not
    // overwrite the first one's callback state.
    submitDbResult(&daemon, in1.session, &cl, "them.example", "us.example", key1);
    submitDbResult(&daemon, in2.session, &cl, "them.example", "us.example", key2);
    try std.testing.expectEqual(@as(usize, 2), cb.conn.pendingVerifyCount());

    // One db:verify per pending entry, each naming its own stream id.
    var vbuf: [2048]u8 = undefined;
    const verifies = vbuf[0..drainPeer(cb.peer_fd, &vbuf)];
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, verifies, "<db:verify"));
    try std.testing.expect(std.mem.indexOf(u8, verifies, in1.session.getStreamId()) != null);
    try std.testing.expect(std.mem.indexOf(u8, verifies, in2.session.getStreamId()) != null);

    var reader = XmlReader.init(alloc);
    defer reader.deinit();

    // A verdict naming no pending entry authenticates nobody.
    feedVerifyVerdict(&daemon, cb.conn, &cl, &reader, "valid", "no-such-stream", "them.example", "us.example");
    try std.testing.expect(!in1.session.isAuthenticatedDomain("them.example"));
    try std.testing.expect(!in2.session.isAuthenticatedDomain("them.example"));

    // Right id, wrong from=: still no match.
    feedVerifyVerdict(&daemon, cb.conn, &cl, &reader, "valid", in2.session.getStreamId(), "other.example", "us.example");
    try std.testing.expect(!in2.session.isAuthenticatedDomain("them.example"));

    // Right id/from/to for session 2: only session 2 authenticates.
    feedVerifyVerdict(&daemon, cb.conn, &cl, &reader, "valid", in2.session.getStreamId(), "them.example", "us.example");
    try std.testing.expect(in2.session.isAuthenticatedDomain("them.example"));
    try std.testing.expect(!in1.session.isAuthenticatedDomain("them.example"));

    // The db:result answer goes to session 2, addressed to the verified
    // origin; session 1's socket stays silent. The rig has no kqueue, so
    // flush the queued write like handleInboundWritable would.
    _ = try in2.session.flushWrite();
    var rbuf: [1024]u8 = undefined;
    const resp = rbuf[0..drainPeer(in2.peer_fd, &rbuf)];
    try std.testing.expect(std.mem.indexOf(u8, resp, "to='them.example'") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "type='valid'") != null);
    try std.testing.expectEqual(@as(usize, 0), drainPeer(in1.peer_fd, &rbuf));

    // Session 1's entry survived the other verdict and still resolves.
    feedVerifyVerdict(&daemon, cb.conn, &cl, &reader, "invalid", in1.session.getStreamId(), "them.example", "us.example");
    try std.testing.expect(!in1.session.isAuthenticatedDomain("them.example"));
    try std.testing.expect(in1.session.inbound_dialback.isFailed());
    try std.testing.expectEqual(@as(usize, 0), cb.conn.pendingVerifyCount());
}

test "S2sDaemon: dialback verdict for a reused inbound slot is discarded" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    const cb = try makeTestCallbackConn(&daemon, "them.example");
    defer posix.close(cb.peer_fd);

    const in1 = try makeTestInbound(alloc, &daemon, 1);
    var scratch: [16]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);

    const key = "3333333333333333333333333333333333333333333333333333333333333333";
    submitDbResult(&daemon, in1.session, &cl, "them.example", "us.example", key);
    const old_sid = try alloc.dupe(u8, in1.session.getStreamId());
    defer alloc.free(old_sid);

    // The submitter disconnects; its slot is reused by a different peer.
    daemon.closeInbound(&cl, 1);
    posix.close(in1.peer_fd);
    const in2 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in2.peer_fd);

    var reader = XmlReader.init(alloc);
    defer reader.deinit();

    // The stale verdict must not land on the new occupant of slot 1.
    feedVerifyVerdict(&daemon, cb.conn, &cl, &reader, "valid", old_sid, "them.example", "us.example");
    try std.testing.expect(!in2.session.isAuthenticatedDomain("them.example"));
    try std.testing.expect(!in2.session.isEstablished());
    var rbuf: [512]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), drainPeer(in2.peer_fd, &rbuf));
    try std.testing.expectEqual(@as(usize, 0), cb.conn.pendingVerifyCount());
}

/// A connected outbound connection on a socketpair, still unauthenticated:
/// the test drives the dialback exchange directly, so no DNS happens. The
/// conn fd is owned by the pool (daemon.deinit closes it).
fn makeTestOutboundConn(daemon: *S2sDaemon, origin: []const u8) !struct { conn: *OutboundConnection, peer_fd: posix.fd_t } {
    const conn = try daemon.pool.getOrCreate(daemon.local_domain, origin);
    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds) != 0)
        return error.SocketPairFailed;
    errdefer posix.close(fds[1]);
    conn.fd = fds[0]; // owned by the conn now; pool.deinit closes it
    return .{ .conn = conn, .peer_fd = fds[1] };
}

/// Feed a typed db:result verdict through processOutboundEvent: the answer
/// either to our own dialback key (from/to echo) or, with an id, to our
/// db:verify.
fn feedDbResultVerdict(daemon: *S2sDaemon, conn: *OutboundConnection, cl: *ChangeList, reader: *XmlReader, verdict: []const u8, from: []const u8, to: []const u8) void {
    var attrs = [_]xml.Attribute{ testAttr("type", verdict), testAttr("from", from), testAttr("to", to) };
    const elem = xml.Element{
        .name = "db:result",
        .prefix = "db",
        .local_name = "result",
        .namespace_uri = xml.ns.dialback,
        .attributes = &attrs,
        .self_closing = true,
    };
    processOutboundEvent(daemon, cl, 0, conn, reader, .{ .element_start = elem });
}

test "S2sDaemon: a typed db:result verdict with no dialback key sent authenticates nothing" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    const ob = try makeTestOutboundConn(&daemon, "them.example");
    defer posix.close(ob.peer_fd);

    var scratch: [8]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    var reader = XmlReader.init(alloc);
    defer reader.deinit();

    // This connection never asserted a dialback key: no verdict, echoed
    // from/to or bare, may stand in for one.
    feedDbResultVerdict(&daemon, ob.conn, &cl, &reader, "valid", "them.example", "us.example");
    try std.testing.expect(!ob.conn.isEstablished());
    feedDbResultVerdict(&daemon, ob.conn, &cl, &reader, "valid", "", "");
    try std.testing.expect(!ob.conn.isEstablished());
    try std.testing.expect(!ob.conn.stream.authenticated);
    try std.testing.expect(!ob.conn.db_assertion_pending);
}

test "S2sDaemon: a typed db:result verdict answers the dialback key this connection sent" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    const ob = try makeTestOutboundConn(&daemon, "them.example");
    defer posix.close(ob.peer_fd);

    var scratch: [8]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    var reader = XmlReader.init(alloc);
    defer reader.deinit();

    // Post-TLS stream restart: the features reply picks dialback (no DANE)
    // and sends our key over this connection.
    ob.conn.stream.state = .awaiting_stream_open_tls;
    ob.conn.handleRemoteStreamOpen("them.example", "streamid-77");
    processOutboundEvent(&daemon, &cl, 0, ob.conn, &reader, .{ .element_end = "features" });
    try std.testing.expect(ob.conn.db_assertion_pending);

    var kbuf: [1024]u8 = undefined;
    const key_xml = kbuf[0..drainPeer(ob.peer_fd, &kbuf)];
    try std.testing.expect(std.mem.indexOf(u8, key_xml, "<db:result") != null);
    try std.testing.expect(std.mem.indexOf(u8, key_xml, "from='us.example'") != null);
    try std.testing.expect(std.mem.indexOf(u8, key_xml, "to='them.example'") != null);

    // The verdict answering that key authenticates the connection and
    // completes the exchange.
    feedDbResultVerdict(&daemon, ob.conn, &cl, &reader, "valid", "them.example", "us.example");
    try std.testing.expect(ob.conn.isEstablished());
    try std.testing.expect(!ob.conn.db_assertion_pending);

    // The completed exchange stays complete: a replayed verdict is not a
    // second exchange to answer.
    feedDbResultVerdict(&daemon, ob.conn, &cl, &reader, "valid", "them.example", "us.example");
    try std.testing.expect(!ob.conn.db_assertion_pending);
}

test "S2sDaemon: a failed db:verify write answers the exchange invalid" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    const cb = try makeTestCallbackConn(&daemon, "them.example");
    defer posix.close(cb.peer_fd);

    const in1 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in1.peer_fd);

    // The callback connection is dead before its db:verify can go out: the
    // write fails, and the exchange is answered instead of leaving the
    // submitting stream to wait for a verdict that can never arrive.
    posix.close(cb.conn.fd);
    cb.conn.fd = -1;

    var scratch: [16]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    const key = "4444444444444444444444444444444444444444444444444444444444444444";
    submitDbResult(&daemon, in1.session, &cl, "them.example", "us.example", key);

    try std.testing.expect(cb.conn.isFailed());
    try std.testing.expectEqualStrings("write-failed", cb.conn.error_msg);
    try std.testing.expectEqual(@as(usize, 0), cb.conn.pendingVerifyCount());
    try std.testing.expect(!in1.session.isAuthenticatedDomain("them.example"));

    // The submitting stream is told the key did not verify.
    _ = try in1.session.flushWrite();
    var rbuf: [1024]u8 = undefined;
    const resp = rbuf[0..drainPeer(in1.peer_fd, &rbuf)];
    try std.testing.expect(std.mem.indexOf(u8, resp, "type='invalid'") != null);
}

test "S2sDaemon: a failed db:verify write tears the outbound conn out of its slot" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    var cb = try makeTestCallbackConn(&daemon, "them.example");
    defer if (cb.peer_fd >= 0) posix.close(cb.peer_fd);
    daemon.outbound[0] = cb.conn;

    const in1 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in1.peer_fd);

    posix.close(cb.conn.fd);
    cb.conn.fd = -1;

    var scratch: [16]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    const key = "abababababababababababababababababababababababababababababababab";
    submitDbResult(&daemon, in1.session, &cl, "them.example", "us.example", key);

    // The conn failed AND left its slot: a stale pointer there would be
    // freed by the next getOrCreate and read again by the next dispatch.
    try std.testing.expect(daemon.outbound[0] == null);

    const session = daemon.getInbound(1) orelse return error.TestUnexpectedResult;
    _ = try session.flushWrite();
    var rbuf: [1024]u8 = undefined;
    const resp = rbuf[0..drainPeer(in1.peer_fd, &rbuf)];
    try std.testing.expect(std.mem.indexOf(u8, resp, "type='invalid'") != null);
}

test "S2sDaemon: a full changelist fails the pending exchanges instead of losing them" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    const cb = try makeTestCallbackConn(&daemon, "them.example");
    defer posix.close(cb.peer_fd);
    daemon.outbound[0] = cb.conn;

    const in1 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in1.peer_fd);

    // Room for the whole write buffer to drain in one flush.
    const big: c_int = 1 << 20;
    try posix.setsockopt(cb.conn.fd, posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&big));

    // Fill the conn write buffer: the verify cannot be queued when the
    // submission arrives and needs the writable edge.
    var filler: [8192]u8 = undefined;
    @memset(&filler, 'x');
    while (true) cb.conn.queueWrite(&filler) catch break;

    // Fill the changelist too: the writable edge cannot be armed, and the
    // exchange must fail loudly instead of waiting for an edge that never
    // gets staged.
    var scratch: [2]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    try cl.addRead(9001, 0);
    try cl.addRead(9002, 0);

    const key = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    submitDbResult(&daemon, in1.session, &cl, "them.example", "us.example", key);

    // The exchange is answered and the conn leaves its slot.
    try std.testing.expect(daemon.outbound[0] == null);
    const session = daemon.getInbound(1) orelse return error.TestUnexpectedResult;
    _ = try session.flushWrite();
    var rbuf: [1024]u8 = undefined;
    const resp = rbuf[0..drainPeer(in1.peer_fd, &rbuf)];
    try std.testing.expect(std.mem.indexOf(u8, resp, "type='invalid'") != null);
    try std.testing.expect(!session.isAuthenticatedDomain("them.example"));
}

test "S2sDaemon: a db:verify that could not be queued goes out on the writable edge" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    const cb = try makeTestCallbackConn(&daemon, "them.example");
    defer posix.close(cb.peer_fd);
    daemon.outbound[0] = cb.conn; // writable dispatch resolves the slot

    // Room for the whole write buffer to drain in one flush.
    const big: c_int = 1 << 20;
    try posix.setsockopt(cb.conn.fd, posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&big));

    const in1 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in1.peer_fd);

    // Fill the conn write buffer: the verify cannot be queued when the
    // submission arrives and must survive until the writable edge.
    var filler: [8192]u8 = undefined;
    @memset(&filler, 'x');
    while (true) cb.conn.queueWrite(&filler) catch break;

    var scratch: [16]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    const key = "5555555555555555555555555555555555555555555555555555555555555555";
    submitDbResult(&daemon, in1.session, &cl, "them.example", "us.example", key);
    try std.testing.expect(cb.conn.hasUnsentVerify());
    try std.testing.expectEqual(@as(usize, 1), cb.conn.pendingVerifyCount());

    // The one-shot writable edge is armed for the conn, so the resume
    // actually arrives even with nothing else to trigger it.
    var armed = false;
    for (cl.slice()) |ev| {
        if (ev.filter == std.c.EVFILT.WRITE and
            ev.ident == @as(@TypeOf(ev.ident), @intCast(cb.conn.fd)) and
            (ev.flags & std.c.EV.ONESHOT) != 0) armed = true;
    }
    try std.testing.expect(armed);

    // The writable edge drains the buffer and queues the verify.
    handleOutboundWritable(&daemon, &cl, 0);
    try std.testing.expect(!cb.conn.hasUnsentVerify());

    var vbuf: [32768]u8 = undefined;
    const out = vbuf[0..drainPeer(cb.peer_fd, &vbuf)];
    try std.testing.expect(std.mem.indexOf(u8, out, "<db:verify") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, key) != null);
}

test "S2sDaemon: a db:verify registered while connecting stays off the wire until the post-TLS features" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    // Callback conn with no protocol state yet: connecting, no TLS, no
    // stream, no features.
    const conn = try daemon.pool.getOrCreate(daemon.local_domain, "them.example");
    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds) != 0)
        return error.SocketPairFailed;
    defer posix.close(fds[1]);
    conn.fd = fds[0]; // owned by the conn now; pool.deinit closes it
    daemon.outbound[0] = conn;
    try std.testing.expectEqual(connector_mod.OutboundState.connecting, conn.state);

    const in1 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in1.peer_fd);

    var scratch: [16]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    const key = "7777777777777777777777777777777777777777777777777777777777777777";
    submitDbResult(&daemon, in1.session, &cl, "them.example", "us.example", key);
    try std.testing.expect(conn.hasUnsentVerify());
    try std.testing.expectEqual(@as(usize, 1), conn.pendingVerifyCount());

    var wire: [32768]u8 = undefined;
    var total: usize = 0;

    // Registered while connecting: nothing may be written yet. The key
    // would travel in cleartext.
    total += drainPeer(fds[1], wire[total..]);

    // TCP completes and the stream opens in the clear. The writable edge
    // here must not carry the verify either.
    conn.tcpConnected();
    handleOutboundWritable(&daemon, &cl, 0);
    total += drainPeer(fds[1], wire[total..]);
    try std.testing.expectEqual(@as(usize, 0), total);
    try std.testing.expect(conn.hasUnsentVerify());

    // Pre-TLS features: still no verify. STARTTLS is offered instead, so
    // the exchange is not stalled waiting for an edge that never comes.
    var reader = XmlReader.init(alloc);
    defer reader.deinit();
    processOutboundEvent(&daemon, &cl, 0, conn, &reader, .{ .element_end = "features" });
    total += drainPeer(fds[1], wire[total..]);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..total], "<starttls") != null);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..total], "<db:verify") == null);
    try std.testing.expect(conn.hasUnsentVerify());

    // Post-TLS stream restart reaches the auth phase; the features edge
    // sends the verify.
    conn.tlsHandshakeComplete();
    conn.setDaneResult(.no_records);
    conn.handleRemoteStreamOpen("them.example", "remote-sid-1");
    try std.testing.expectEqual(connector_mod.OutboundState.authenticating, conn.state);
    processOutboundEvent(&daemon, &cl, 0, conn, &reader, .{ .element_end = "features" });
    total += drainPeer(fds[1], wire[total..]);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..total], "<db:verify") != null);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..total], key) != null);
    try std.testing.expect(!conn.hasUnsentVerify());
}

test "S2sDaemon: a callback conn torn down with pending exchanges answers them invalid" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    var cb = try makeTestCallbackConn(&daemon, "them.example");
    defer if (cb.peer_fd >= 0) posix.close(cb.peer_fd);
    daemon.outbound[0] = cb.conn;

    const in1 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in1.peer_fd);

    var scratch: [16]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    const key = "8888888888888888888888888888888888888888888888888888888888888888";
    submitDbResult(&daemon, in1.session, &cl, "them.example", "us.example", key);

    var wire: [4096]u8 = undefined;
    const sent = wire[0..drainPeer(cb.peer_fd, &wire)];
    try std.testing.expect(std.mem.indexOf(u8, sent, "<db:verify") != null);
    try std.testing.expectEqual(@as(usize, 1), cb.conn.pendingVerifyCount());

    // The peer goes away while the verdict is still in flight: the conn is
    // torn down and the exchange must be answered, not left waiting.
    posix.close(cb.peer_fd);
    cb.peer_fd = -1;
    handleOutboundReadable(&daemon, &cl, 0);
    try std.testing.expect(daemon.outbound[0] == null);

    const session = daemon.getInbound(1) orelse return error.TestUnexpectedResult;
    _ = try session.flushWrite();
    var rbuf: [1024]u8 = undefined;
    const resp = rbuf[0..drainPeer(in1.peer_fd, &rbuf)];
    try std.testing.expect(std.mem.indexOf(u8, resp, "type='invalid'") != null);
    try std.testing.expect(!session.isAuthenticatedDomain("them.example"));
}

test "S2sDaemon: an exchange whose db:verify cannot be built is answered invalid and cleared" {
    // A long served host and a long origin overflow the fixed db:verify
    // buffer: the exchange can never be sent, and must die immediately
    // instead of spinning the writable re-arm forever.
    var host_buf: [225]u8 = undefined;
    @memset(host_buf[0..220], 'a');
    @memcpy(host_buf[220..], ".test");
    const long_host = host_buf[0..];
    var origin_buf: [185]u8 = undefined;
    @memset(origin_buf[0..180], 'b');
    @memcpy(origin_buf[180..], ".test");
    const long_origin = origin_buf[0..];

    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, long_host);
    defer daemon.deinit();

    var cb = try makeTestCallbackConn(&daemon, long_origin);
    defer if (cb.peer_fd >= 0) posix.close(cb.peer_fd);
    daemon.outbound[0] = cb.conn;

    const in1 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in1.peer_fd);

    var scratch: [16]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    const key = "9999999999999999999999999999999999999999999999999999999999999999";
    submitDbResult(&daemon, in1.session, &cl, long_origin, long_host, key);

    // The entry is answered invalid and cleared: nothing waits and nothing
    // re-arms.
    try std.testing.expect(!cb.conn.hasUnsentVerify());
    try std.testing.expectEqual(@as(usize, 0), cb.conn.pendingVerifyCount());
    const session = daemon.getInbound(1) orelse return error.TestUnexpectedResult;
    _ = try session.flushWrite();
    var rbuf: [1024]u8 = undefined;
    const resp = rbuf[0..drainPeer(in1.peer_fd, &rbuf)];
    try std.testing.expect(std.mem.indexOf(u8, resp, "type='invalid'") != null);
    try std.testing.expect(!session.isAuthenticatedDomain(long_origin));
}

test "S2sDaemon: a full domain set answers a valid dialback verdict invalid" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    const cb = try makeTestCallbackConn(&daemon, "them.example");
    defer posix.close(cb.peer_fd);

    const in1 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in1.peer_fd);

    // The authenticated-domain set holds 8: fill it before the verdict.
    var n: usize = 0;
    while (n < 8) : (n += 1) {
        var dbuf: [32]u8 = undefined;
        const d = try std.fmt.bufPrint(&dbuf, "d{d}.example", .{n});
        try std.testing.expect(in1.session.addAuthenticatedDomain(d));
    }

    var scratch: [16]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    const key = "4444444444444444444444444444444444444444444444444444444444444444";
    submitDbResult(&daemon, in1.session, &cl, "them.example", "us.example", key);

    var reader = XmlReader.init(alloc);
    defer reader.deinit();
    feedVerifyVerdict(&daemon, cb.conn, &cl, &reader, "valid", in1.session.getStreamId(), "them.example", "us.example");

    // The verdict cannot be honored (the set has no room for the origin):
    // the answer must be invalid, and nothing about the session turns
    // authenticated.
    try std.testing.expect(!in1.session.isAuthenticatedDomain("them.example"));
    try std.testing.expect(in1.session.inbound_dialback.isFailed());
    _ = try in1.session.flushWrite();
    var rbuf: [1024]u8 = undefined;
    const resp = rbuf[0..drainPeer(in1.peer_fd, &rbuf)];
    try std.testing.expect(std.mem.indexOf(u8, resp, "type='invalid'") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "type='valid'") == null);
}

test "S2sDaemon: SASL EXTERNAL with a full domain set fails instead of succeeding" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    const in1 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in1.peer_fd);

    var n: usize = 0;
    while (n < 8) : (n += 1) {
        var dbuf: [32]u8 = undefined;
        const d = try std.fmt.bufPrint(&dbuf, "d{d}.example", .{n});
        try std.testing.expect(in1.session.addAuthenticatedDomain(d));
    }
    in1.session.setDaneCandidate("them.example");

    var scratch: [8]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    executeAction(&daemon, in1.session, .send_sasl_success, &cl);

    // The identity cannot be recorded, so the exchange fails instead of
    // succeeding unrecorded.
    _ = try in1.session.flushWrite();
    var rbuf: [1024]u8 = undefined;
    const resp = rbuf[0..drainPeer(in1.peer_fd, &rbuf)];
    try std.testing.expect(std.mem.indexOf(u8, resp, "<failure") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "<success") == null);
    try std.testing.expect(!in1.session.isAuthenticatedDomain("them.example"));
}

test "S2sDaemon: stream restart with unauthenticated from= is rejected" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    const in1 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in1.peer_fd);
    var scratch: [16]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);

    // First open pinned the origin.
    in1.session.stream_open_seen = true;
    in1.session.setRemoteDomain("them.example");

    // A restart that re-identifies the peer as another domain must fail the
    // stream with invalid-from and close it.
    var attrs = [_]xml.Attribute{ testAttr("from", "victim.example"), testAttr("to", "us.example"), testAttr("version", "1.0") };
    const elem = xml.Element{
        .name = "stream:stream",
        .prefix = "stream",
        .local_name = "stream",
        .namespace_uri = "http://etherx.jabber.org/streams",
        .attributes = &attrs,
        .self_closing = false,
    };
    processInboundEvent(&daemon, in1.session, daemon.readers[1].?, .{ .stream_open = elem }, &cl);

    try std.testing.expect(daemon.getInbound(1) == null);
    var rbuf: [1024]u8 = undefined;
    const resp = rbuf[0..drainPeer(in1.peer_fd, &rbuf)];
    try std.testing.expect(std.mem.indexOf(u8, resp, "invalid-from") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "</stream:stream>") != null);
}

test "S2sDaemon: stanza from unauthenticated domain on established session is rejected" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    const in1 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in1.peer_fd);
    var scratch: [16]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);
    in1.session.stream.setAuthenticated();

    // from= names a domain this session never authenticated for.
    var attrs = [_]xml.Attribute{ testAttr("from", "eve@evil.example"), testAttr("to", "juliet@us.example") };
    const elem = xml.Element{
        .name = "message",
        .prefix = "",
        .local_name = "message",
        .namespace_uri = "jabber:server",
        .attributes = &attrs,
        .self_closing = true,
    };
    processInboundEvent(&daemon, in1.session, daemon.readers[1].?, .{ .element_start = elem }, &cl);
    try std.testing.expect(daemon.getInbound(1) == null);
    var rbuf: [1024]u8 = undefined;
    const resp = rbuf[0..drainPeer(in1.peer_fd, &rbuf)];
    try std.testing.expect(std.mem.indexOf(u8, resp, "invalid-from") != null);

    // Positive control: an authenticated domain passes the set lookup and
    // the session stays open.
    const in2 = try makeTestInbound(alloc, &daemon, 2);
    defer posix.close(in2.peer_fd);
    in2.session.stream.setAuthenticated();
    _ = in2.session.addAuthenticatedDomain("them.example");
    var attrs2 = [_]xml.Attribute{ testAttr("from", "romeo@them.example/orchard"), testAttr("to", "juliet@us.example") };
    const elem2 = xml.Element{
        .name = "message",
        .prefix = "",
        .local_name = "message",
        .namespace_uri = "jabber:server",
        .attributes = &attrs2,
        .self_closing = true,
    };
    processInboundEvent(&daemon, in2.session, daemon.readers[2].?, .{ .element_start = elem2 }, &cl);
    try std.testing.expect(daemon.getInbound(2) != null);
}

test "S2sDaemon: plaintext bytes while the inbound TLS upgrade pends fail the stream (T250)" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    const in1 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in1.peer_fd);
    var scratch: [16]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);

    // A <proceed/> is parked behind a partial flush; the peer speaks anyway.
    // Well-formed XML on purpose: without the guard it parses as an ignored
    // event and the session stays open.
    in1.session.tls_upgrade_pending = true;
    _ = try posix.write(in1.peer_fd, "<message to='juliet@us.example'/>");

    handleInboundReadable(&daemon, &cl, 1);

    try std.testing.expect(daemon.getInbound(1) == null);
    var rbuf: [1024]u8 = undefined;
    const resp = rbuf[0..drainPeer(in1.peer_fd, &rbuf)];
    try std.testing.expect(std.mem.indexOf(u8, resp, "policy-violation") != null);
}

test "S2sDaemon: db:result addressed to a host we do not serve is rejected" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();

    const in1 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in1.peer_fd);
    var scratch: [16]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);

    const key = "4444444444444444444444444444444444444444444444444444444444444444";
    submitDbResult(&daemon, in1.session, &cl, "them.example", "other.example", key);

    // The to= check must fail the stream before any callback is registered.
    try std.testing.expect(daemon.getInbound(1) == null);
    var rbuf: [1024]u8 = undefined;
    const resp = rbuf[0..drainPeer(in1.peer_fd, &rbuf)];
    try std.testing.expect(std.mem.indexOf(u8, resp, "invalid-from") != null);
}

fn testStreamOpenElem(from: []const u8, to: []const u8, attrs: []xml.Attribute) xml.Element {
    attrs[0] = testAttr("from", from);
    attrs[1] = testAttr("to", to);
    attrs[2] = testAttr("version", "1.0");
    return xml.Element{
        .name = "stream:stream",
        .prefix = "stream",
        .local_name = "stream",
        .namespace_uri = "http://etherx.jabber.org/streams",
        .attributes = attrs,
        .self_closing = false,
    };
}

test "S2sDaemon: MUC host is served on stream open; replies echo the requested host" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();
    daemon.muc_host = "conference.us.example";

    var scratch: [16]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);

    // Stream open addressed to the MUC host is accepted and answered as it.
    const in1 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in1.peer_fd);
    var attrs1 = [_]xml.Attribute{ testAttr("from", ""), testAttr("to", ""), testAttr("version", "") };
    const open1 = testStreamOpenElem("them.example", "conference.us.example", &attrs1);
    processInboundEvent(&daemon, in1.session, daemon.readers[1].?, .{ .stream_open = open1 }, &cl);
    try std.testing.expect(daemon.getInbound(1) != null);
    _ = try in1.session.flushWrite();
    var rbuf: [2048]u8 = undefined;
    const resp1 = rbuf[0..drainPeer(in1.peer_fd, &rbuf)];
    try std.testing.expect(std.mem.indexOf(u8, resp1, "from='conference.us.example'") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp1, "to='them.example'") != null);

    // A stream addressed to a host we do not serve fails with host-unknown.
    const in2 = try makeTestInbound(alloc, &daemon, 2);
    defer posix.close(in2.peer_fd);
    var attrs2 = [_]xml.Attribute{ testAttr("from", ""), testAttr("to", ""), testAttr("version", "") };
    const open2 = testStreamOpenElem("them.example", "other.example", &attrs2);
    processInboundEvent(&daemon, in2.session, daemon.readers[2].?, .{ .stream_open = open2 }, &cl);
    try std.testing.expect(daemon.getInbound(2) == null);
    var rbuf2: [2048]u8 = undefined;
    const resp2 = rbuf2[0..drainPeer(in2.peer_fd, &rbuf2)];
    try std.testing.expect(std.mem.indexOf(u8, resp2, "host-unknown") != null);
}

test "S2sDaemon: db:result for the MUC host completes and answers as that host" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();
    daemon.muc_host = "conference.us.example";

    const cb = try makeTestCallbackConn(&daemon, "them.example");
    defer posix.close(cb.peer_fd);
    const in1 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in1.peer_fd);
    var scratch: [16]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);

    const key = "5555555555555555555555555555555555555555555555555555555555555555";
    submitDbResult(&daemon, in1.session, &cl, "them.example", "conference.us.example", key);
    // Accepted and pending.
    try std.testing.expect(daemon.getInbound(1) != null);

    // The db:verify speaks as the MUC host.
    var vbuf: [1024]u8 = undefined;
    const verifies = vbuf[0..drainPeer(cb.peer_fd, &vbuf)];
    try std.testing.expect(std.mem.indexOf(u8, verifies, "from='conference.us.example'") != null);
    try std.testing.expect(std.mem.indexOf(u8, verifies, "to='them.example'") != null);

    // The verdict echoes the MUC host as to= and completes the exchange.
    var reader = XmlReader.init(alloc);
    defer reader.deinit();
    feedVerifyVerdict(&daemon, cb.conn, &cl, &reader, "valid", in1.session.getStreamId(), "them.example", "conference.us.example");
    // The processing may close and free the session: reach it through the
    // slot table, never the rig pointer.
    try std.testing.expect(daemon.getInbound(1) != null);
    try std.testing.expect(daemon.getInbound(1).?.isAuthenticatedDomain("them.example"));
    _ = try daemon.getInbound(1).?.flushWrite();
    var rbuf: [1024]u8 = undefined;
    const resp = rbuf[0..drainPeer(in1.peer_fd, &rbuf)];
    try std.testing.expect(std.mem.indexOf(u8, resp, "from='conference.us.example'") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "to='them.example'") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "type='valid'") != null);
    try std.testing.expectEqual(@as(usize, 0), cb.conn.pendingVerifyCount());

    // A verdict addressed to the local domain matches no MUC-host entry.
    submitDbResult(&daemon, in1.session, &cl, "them.example", "conference.us.example", key);
    try std.testing.expect(daemon.getInbound(1) != null);
    feedVerifyVerdict(&daemon, cb.conn, &cl, &reader, "valid", daemon.getInbound(1).?.getStreamId(), "them.example", "us.example");
    try std.testing.expectEqual(@as(usize, 1), cb.conn.pendingVerifyCount());
}

test "S2sDaemon: db:verify for the MUC host is answered as that host" {
    const alloc = std.testing.allocator;
    var daemon = try S2sDaemon.init(alloc, "us.example");
    defer daemon.deinit();
    daemon.muc_host = "conference.us.example";

    var scratch: [16]posix.Kevent = undefined;
    var cl = ChangeList.init(&scratch);

    // We are the authoritative host; the key binds (verifier, MUC host, sid).
    const in1 = try makeTestInbound(alloc, &daemon, 1);
    defer posix.close(in1.peer_fd);
    const sid = in1.session.getStreamId();
    const key = dialback.computeKeyHex(&daemon.dialback_secret, "them.example", "conference.us.example", sid);

    var attrs = [_]xml.Attribute{ testAttr("from", "them.example"), testAttr("to", "conference.us.example"), testAttr("id", sid) };
    const elem = xml.Element{
        .name = "db:verify",
        .prefix = "db",
        .local_name = "verify",
        .namespace_uri = xml.ns.dialback,
        .attributes = &attrs,
        .self_closing = false,
    };
    processInboundEvent(&daemon, in1.session, daemon.readers[1].?, .{ .element_start = elem }, &cl);
    // The processing may close and free the session: everything after it
    // reaches the session through the slot table, never the rig pointer.
    try std.testing.expect(daemon.getInbound(1) != null);
    processInboundEvent(&daemon, daemon.getInbound(1).?, daemon.readers[1].?, .{ .text = &key }, &cl);
    try std.testing.expect(daemon.getInbound(1) != null);
    _ = try daemon.getInbound(1).?.flushWrite();
    var rbuf: [1024]u8 = undefined;
    const resp = rbuf[0..drainPeer(in1.peer_fd, &rbuf)];
    try std.testing.expect(std.mem.indexOf(u8, resp, "from='conference.us.example'") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "to='them.example'") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "type='valid'") != null);

    // A db:verify for a host we do not serve fails the stream.
    const in2 = try makeTestInbound(alloc, &daemon, 2);
    defer posix.close(in2.peer_fd);
    var attrs2 = [_]xml.Attribute{ testAttr("from", "them.example"), testAttr("to", "other.example"), testAttr("id", "x") };
    const elem2 = xml.Element{
        .name = "db:verify",
        .prefix = "db",
        .local_name = "verify",
        .namespace_uri = xml.ns.dialback,
        .attributes = &attrs2,
        .self_closing = false,
    };
    processInboundEvent(&daemon, in2.session, daemon.readers[2].?, .{ .element_start = elem2 }, &cl);
    processInboundEvent(&daemon, in2.session, daemon.readers[2].?, .{ .text = "6666666666666666666666666666666666666666666666666666666666666666" }, &cl);
    try std.testing.expect(daemon.getInbound(2) == null);
    var rbuf2: [1024]u8 = undefined;
    const resp2 = rbuf2[0..drainPeer(in2.peer_fd, &rbuf2)];
    try std.testing.expect(std.mem.indexOf(u8, resp2, "host-unknown") != null);
}
