//! # S2S Outbound Connector — Non-blocking connection establishment
//!
//! Manages outbound S2S connections from this server to remote XMPP domains.
//! Each connection goes through a multi-step establishment process:
//!
//! 1. DNS SRV resolution (`_xmpp-server._tcp.domain`)
//! 2. TCP connect (non-blocking)
//! 3. TLS handshake (STARTTLS or direct TLS)
//! 4. DANE/TLSA validation
//! 5. Stream open (`<stream:stream xmlns='jabber:server'>`)
//! 6. Authentication (SASL EXTERNAL if DANE passed, else dialback)
//!
//! The connector is designed to be driven by a kqueue event loop in the
//! `xmppd-s2s` binary. State transitions happen in response to socket
//! readability/writability events.

const std = @import("std");
const posix = std.posix;
const stream_mod = @import("stream.zig");
const S2sStream = stream_mod.S2sStream;
const S2sStreamState = stream_mod.S2sStreamState;
const S2sStreamAction = stream_mod.S2sStreamAction;
const Role = stream_mod.Role;
const ssl_mod = @import("ssl");
const SslConn = ssl_mod.SslConn;
const SslContext = ssl_mod.SslContext;
const session_mod = @import("session.zig");
const TlsState = session_mod.TlsState;

/// Outbound connection establishment state.
pub const OutboundState = enum {
    /// DNS SRV lookup complete, attempting TCP connect.
    connecting,
    /// TCP connected, initiating TLS (STARTTLS or direct).
    tls_handshake,
    /// TLS established, DANE/TLSA check in progress.
    dane_check,
    /// Sent stream open, waiting for remote stream header.
    stream_open,
    /// Negotiating STARTTLS before TLS handshake.
    starttls_negotiation,
    /// Authenticating (EXTERNAL or dialback).
    authenticating,
    /// Fully established — stanzas can flow.
    established,
    /// Connection failed permanently.
    failed,
};

/// Result of DANE verification for the connection.
pub const DaneStatus = enum {
    /// DANE-EE or DANE-TA match — use SASL EXTERNAL.
    verified,
    /// No TLSA records — fall back to dialback.
    no_records,
    /// TLSA records exist but didn't match — reject.
    failed,
    /// Not yet checked.
    pending,
};

/// An outbound S2S connection to a remote domain.
pub const OutboundConnection = struct {
    /// Remote domain we're connecting to.
    remote_domain: []const u8,
    /// Local domain (us).
    local_domain: []const u8,
    /// Current connection state.
    state: OutboundState,
    /// The S2S stream FSM for this connection.
    stream: S2sStream,
    /// Socket file descriptor (-1 if not yet connected).
    fd: posix.fd_t = -1,
    /// Target host we connected to (from SRV resolution).
    target_host: []const u8 = "",
    /// Target port.
    target_port: u16 = 0,
    /// Whether this is a direct TLS connection (from _xmpps-server SRV).
    is_direct_tls: bool = false,
    /// DANE verification status.
    dane_status: DaneStatus = .pending,
    /// Stanzas queued for delivery while connection is establishing.
    pending_stanzas: PendingQueue,
    /// Allocator used for pending stanzas.
    alloc: std.mem.Allocator,
    /// Stream ID assigned by the remote server.
    remote_stream_id: [64]u8 = undefined,
    remote_stream_id_len: usize = 0,
    /// Error message if state == .failed.
    error_msg: []const u8 = "",
    /// STARTTLS proceed received but our own write buffer had not drained:
    /// the handshake starts when handleOutboundWritable finishes flushing
    /// (T250).
    tls_upgrade_pending: bool = false,
    /// If set, this outbound connection is a dialback verification callback.
    /// The value is the inbound session slot that initiated the callback.
    /// After db:verify response, the result is sent back on that inbound session.
    db_callback_inbound_slot: ?usize = null,
    /// The key and stream ID for the pending db:verify request.
    db_callback_key_buf: [128]u8 = undefined,
    db_callback_key_len: usize = 0,
    db_callback_stream_id_buf: [64]u8 = undefined,
    db_callback_stream_id_len: usize = 0,
    /// TLS connection — null for plain TCP, set after STARTTLS or direct TLS.
    tls_conn: ?SslConn = null,
    /// TLS handshake state for kqueue integration.
    tls_state: ?TlsState = null,
    /// Persistent read buffer (survives across kqueue events).
    read_buf: [READ_BUF_SIZE]u8 = undefined,
    read_start: usize = 0,
    read_end: usize = 0,
    /// Write buffer for TLS-aware output.
    write_buf: [WRITE_BUF_SIZE]u8 = undefined,
    write_start: usize = 0,
    write_end: usize = 0,
    /// Length of the pinned TLS write starting at write_start. While > 0,
    /// flushWrite retries exactly that slice: OpenSSL retains the caller
    /// buffer across WANT_READ/WANT_WRITE (AGENTS.md identical pointer and
    /// length rule), so bytes queued after the stall wait behind it (S23).
    pinned_tls_len: usize = 0,

    const READ_BUF_SIZE = 8192;
    const WRITE_BUF_SIZE = 16384;
    const PendingQueue = std.ArrayList(PendingStanza);

    pub fn init(
        allocator: std.mem.Allocator,
        local_domain: []const u8,
        remote_domain: []const u8,
    ) !OutboundConnection {
        // Copy the domain — callers hand slices that borrow the IPC recv
        // buffer; the pool key depends on it being stable (T275).
        const domain = try allocator.dupe(u8, remote_domain);
        return .{
            .remote_domain = domain,
            .local_domain = local_domain,
            .state = .connecting,
            .stream = S2sStream.init(.initiating, local_domain),
            .pending_stanzas = PendingQueue{},
            .alloc = allocator,
        };
    }

    pub fn deinit(self: *OutboundConnection, allocator: std.mem.Allocator) void {
        for (self.pending_stanzas.items) |stanza| {
            stanza.deinit(allocator);
        }
        self.pending_stanzas.deinit(allocator);
        allocator.free(self.remote_domain);
        if (self.target_host.len > 0) {
            allocator.free(self.target_host);
            self.target_host = "";
        }
        if (self.tls_conn) |*tls| {
            tls.shutdown();
            tls.deinit();
            self.tls_conn = null;
        }
        if (self.fd >= 0) {
            posix.close(self.fd);
            self.fd = -1;
        }
    }

    /// Whether TLS handshake is in progress.
    pub fn isTlsHandshaking(self: *const OutboundConnection) bool {
        if (self.tls_state) |s| {
            return s != .established;
        }
        return false;
    }

    /// Upgrade this connection to TLS using the client-side context.
    /// Initiates a non-blocking handshake.
    pub fn upgradeToTls(self: *OutboundConnection, ctx: SslContext) !void {
        // Build null-terminated SNI hostname
        var hostname_buf: [256:0]u8 = undefined;
        if (self.remote_domain.len >= hostname_buf.len) return error.HostnameTooLong;
        @memcpy(hostname_buf[0..self.remote_domain.len], self.remote_domain);
        hostname_buf[self.remote_domain.len] = 0;

        self.tls_conn = SslConn.initClient(ctx, self.fd, &hostname_buf) catch return error.TlsInitFailed;
        self.tls_state = .handshake_want_read;
    }

    /// Continue a non-blocking TLS handshake.
    /// Returns true when the handshake is complete.
    pub fn continueHandshake(self: *OutboundConnection) !bool {
        if (self.tls_conn) |*tls| {
            const result = tls.doHandshake() catch return error.HandshakeFailed;
            switch (result) {
                .complete => {
                    self.tls_state = .established;
                    return true;
                },
                .want_read => {
                    self.tls_state = .handshake_want_read;
                    return false;
                },
                .want_write => {
                    self.tls_state = .handshake_want_write;
                    return false;
                },
            }
        }
        return error.NoTlsConnection;
    }

    /// Receive data from the socket into the persistent read buffer.
    /// Returns number of bytes read, 0 for EOF.
    pub fn recv(self: *OutboundConnection) !usize {
        // Compact if needed
        if (self.read_start > 0) {
            const remaining = self.read_end - self.read_start;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.read_buf[0..remaining], self.read_buf[self.read_start..self.read_end]);
            }
            self.read_end = remaining;
            self.read_start = 0;
        }
        if (self.read_end >= self.read_buf.len) return error.BufferFull;

        const buf = self.read_buf[self.read_end..];

        if (self.tls_conn) |*tls| {
            const result = tls.read(buf) catch |err| {
                return switch (err) {
                    ssl_mod.SslError.ConnectionClosed => @as(usize, 0),
                    else => error.ConnectionReset,
                };
            };
            return switch (result) {
                .ok => |n| blk: {
                    self.read_end += n;
                    break :blk n;
                },
                .want_read => error.WouldBlock,
                .want_write => error.WouldBlock,
            };
        }

        const n = posix.read(self.fd, buf) catch |err| {
            return switch (err) {
                error.WouldBlock => error.WouldBlock,
                else => error.ConnectionReset,
            };
        };
        if (n == 0) return 0; // EOF
        self.read_end += n;
        return n;
    }

    /// Get the readable portion of the read buffer.
    pub fn readableSlice(self: *const OutboundConnection) []const u8 {
        return self.read_buf[self.read_start..self.read_end];
    }

    /// Mark bytes as consumed from the read buffer.
    pub fn consume(self: *OutboundConnection, n: usize) void {
        self.read_start += n;
    }

    /// Queue data to the write buffer.
    pub fn queueWrite(self: *OutboundConnection, data: []const u8) !void {
        const available = self.write_buf.len - self.write_end;
        if (data.len > available) return error.BufferFull;
        @memcpy(self.write_buf[self.write_end .. self.write_end + data.len], data);
        self.write_end += data.len;
    }

    /// Flush the write buffer to the socket (TLS-aware).
    /// Returns true if all data was flushed.
    ///
    /// When a TLS write stalls, this retries only the pinned prefix; bytes
    /// queued after the stall are flushed by later calls once the pin
    /// releases. The TLS record layer never sees a slice that differs from
    /// the stalled one in pointer or length (S23).
    pub fn flushWrite(self: *OutboundConnection) !bool {
        if (self.write_start >= self.write_end) return true;

        const flush_end = if (self.pinned_tls_len > 0)
            self.write_start + self.pinned_tls_len
        else
            self.write_end;
        const data = self.write_buf[self.write_start..flush_end];

        if (self.tls_conn) |*tls| {
            const result = tls.write(data) catch return error.ConnectionReset;
            switch (result) {
                .ok => |n| {
                    self.write_start += n;
                    self.pinned_tls_len -|= n;
                    if (self.write_start >= self.write_end) {
                        self.write_start = 0;
                        self.write_end = 0;
                        self.pinned_tls_len = 0;
                        return true;
                    }
                    return false;
                },
                .want_read, .want_write => {
                    // OpenSSL retains the caller buffer across the retry;
                    // pin the exact slice and let nothing grow it.
                    self.pinned_tls_len = data.len;
                    return false;
                },
            }
        }

        const n = posix.write(self.fd, data) catch |err| {
            return switch (err) {
                error.WouldBlock => false,
                else => error.ConnectionReset,
            };
        };
        self.write_start += n;
        if (self.write_start >= self.write_end) {
            self.write_start = 0;
            self.write_end = 0;
            return true;
        }
        return false;
    }

    /// Whether there is pending write data.
    pub fn hasPendingWrite(self: *const OutboundConnection) bool {
        return self.write_start < self.write_end;
    }

    /// Queue a stanza for delivery once the connection is established.
    /// from/to/xml are all copied: the caller's slices borrow the IPC recv
    /// buffer whose next frame rewrites them (T275).
    pub fn queueStanza(self: *OutboundConnection, allocator: std.mem.Allocator, from: []const u8, to: []const u8, xml: []const u8) !void {
        const from_copy = try allocator.dupe(u8, from);
        errdefer allocator.free(from_copy);
        const to_copy = try allocator.dupe(u8, to);
        errdefer allocator.free(to_copy);
        const xml_copy = try allocator.dupe(u8, xml);
        errdefer allocator.free(xml_copy);
        try self.pending_stanzas.append(allocator, .{
            .from_jid = from_copy,
            .to_jid = to_copy,
            .xml = xml_copy,
        });
    }

    /// Check if the connection is ready to deliver stanzas.
    pub fn isEstablished(self: *const OutboundConnection) bool {
        return self.state == .established;
    }

    /// Check if the connection has permanently failed.
    pub fn isFailed(self: *const OutboundConnection) bool {
        return self.state == .failed;
    }

    /// Transition to the TLS handshake phase after TCP connect completes.
    pub fn tcpConnected(self: *OutboundConnection) void {
        if (self.is_direct_tls) {
            self.state = .tls_handshake;
        } else {
            // For STARTTLS, we first open the stream and negotiate
            self.state = .stream_open;
        }
    }

    /// Transition after TLS handshake completes.
    pub fn tlsHandshakeComplete(self: *OutboundConnection) void {
        self.stream.tlsEstablished();
        self.state = .dane_check;
    }

    /// Set the DANE verification result and transition state.
    pub fn setDaneResult(self: *OutboundConnection, status: DaneStatus) void {
        self.dane_status = status;
        switch (status) {
            .verified => {
                self.stream.setDaneVerified(true);
                // After DANE, open the post-TLS stream
                self.state = .stream_open;
            },
            .no_records => {
                self.stream.setDaneVerified(false);
                self.state = .stream_open;
            },
            .failed => {
                self.state = .failed;
                self.error_msg = "dane-verification-failed";
            },
            .pending => {},
        }
    }

    /// Process a received stream open from the remote server.
    pub fn handleRemoteStreamOpen(self: *OutboundConnection, from: []const u8, id: []const u8) void {
        // Store the remote stream ID (needed for dialback)
        const copy_len = @min(id.len, self.remote_stream_id.len);
        @memcpy(self.remote_stream_id[0..copy_len], id[0..copy_len]);
        self.remote_stream_id_len = copy_len;

        _ = self.stream.handleStreamOpen(from, self.local_domain, "1.0");

        // If we're in features_auth state after post-TLS stream open,
        // choose auth method
        if (self.stream.state == .features_auth) {
            self.state = .authenticating;
        }
    }

    /// Process received stream features (post-TLS: auth mechanisms).
    pub fn handleRemoteFeatures(self: *OutboundConnection, has_external: bool, has_dialback: bool) OutboundAction {
        _ = has_dialback;
        if (self.stream.state == .features_auth) {
            const action = self.stream.chooseAuthMethod();
            self.state = .authenticating;
            return switch (action) {
                .send_sasl_external => .send_sasl_external,
                .begin_dialback => .begin_dialback,
                else => .none,
            };
        }
        // Pre-TLS features — should contain STARTTLS
        if (self.stream.state == .features_tls or self.state == .stream_open) {
            if (!self.is_direct_tls) {
                self.state = .starttls_negotiation;
                return .send_starttls;
            }
        }
        _ = has_external;
        return .none;
    }

    /// STARTTLS proceed received — by the time <proceed/> arrives, all bytes
    /// through the <starttls/> request are by definition on the wire (the
    /// peer could not have seen it otherwise; T250 review). Anything left in
    /// the local write buffer was queued after <starttls/>; flushing it now
    /// would push plaintext into the TLS record layer, so fail instead.
    pub fn handleStarttlsProceed(self: *OutboundConnection) bool {
        if (self.hasPendingWrite()) {
            self.fail("plaintext-after-starttls");
            return false;
        }
        self.state = .tls_handshake;
        return true;
    }

    /// SASL success received — connection is authenticated.
    pub fn handleAuthSuccess(self: *OutboundConnection) void {
        self.stream.setAuthenticated();
        self.state = .established;
    }

    /// SASL failure or auth rejected.
    pub fn handleAuthFailure(self: *OutboundConnection) void {
        self.state = .failed;
        self.error_msg = "authentication-failed";
    }

    /// Mark the connection as failed with a reason.
    pub fn fail(self: *OutboundConnection, reason: []const u8) void {
        self.state = .failed;
        self.error_msg = reason;
    }

    /// Get the stream open XML to send to the remote server.
    /// remote_domain was peer-supplied at queue time (T275 duped it, but the
    /// incoming bytes may still be entity-decoded specials — escape (S1).
    pub fn buildStreamOpen(self: *const OutboundConnection, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();
        try writer.writeAll("<?xml version='1.0'?><stream:stream xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams' xmlns:db='jabber:server:dialback' from='");
        try @import("session.zig").xmlEscapeWrite(writer, self.local_domain);
        try writer.writeAll("' to='");
        try @import("session.zig").xmlEscapeWrite(writer, self.remote_domain);
        try writer.writeAll("' version='1.0'>");
        return fbs.getWritten();
    }

    /// Get the SASL EXTERNAL auth XML.
    pub fn buildSaslExternal(self: *const OutboundConnection, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();
        // Encode our domain as the authorization identity (base64)
        try writer.writeAll("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>");
        // Base64 encode the local domain
        const encoder = std.base64.standard.Encoder;
        const encoded_len = encoder.calcSize(self.local_domain.len);
        var b64_buf: [256]u8 = undefined;
        if (encoded_len > b64_buf.len) return error.NoSpaceLeft;
        const encoded = encoder.encode(&b64_buf, self.local_domain);
        try writer.writeAll(encoded);
        try writer.writeAll("</auth>");
        return fbs.getWritten();
    }

    /// Get the STARTTLS request XML.
    pub fn buildStarttls(_: *const OutboundConnection, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();
        try writer.writeAll("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
        return fbs.getWritten();
    }

    /// Get the number of pending stanzas.
    pub fn pendingCount(self: *const OutboundConnection) usize {
        return self.pending_stanzas.items.len;
    }

    /// Get the remote stream ID.
    pub fn getRemoteStreamId(self: *const OutboundConnection) []const u8 {
        return self.remote_stream_id[0..self.remote_stream_id_len];
    }
};

/// A stanza queued for delivery. Owns all three slices.
pub const PendingStanza = struct {
    from_jid: []const u8,
    to_jid: []const u8,
    xml: []const u8,

    pub fn deinit(self: PendingStanza, allocator: std.mem.Allocator) void {
        allocator.free(self.from_jid);
        allocator.free(self.to_jid);
        allocator.free(self.xml);
    }
};

/// Actions the connector tells the event loop to perform.
pub const OutboundAction = enum {
    /// Send STARTTLS request to remote.
    send_starttls,
    /// Send SASL EXTERNAL auth.
    send_sasl_external,
    /// Begin dialback protocol.
    begin_dialback,
    /// No action needed.
    none,
};

/// Connection pool — maps remote domains to outbound connections.
pub const ConnectionPool = struct {
    connections: std.StringHashMap(*OutboundConnection),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ConnectionPool {
        return .{
            .connections = std.StringHashMap(*OutboundConnection).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ConnectionPool) void {
        var it = self.connections.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.connections.deinit();
    }

    /// Get or create a connection for a remote domain.
    /// Returns the connection (may be in any state — caller checks).
    pub fn getOrCreate(
        self: *ConnectionPool,
        local_domain: []const u8,
        remote_domain: []const u8,
    ) !*OutboundConnection {
        if (self.connections.get(remote_domain)) |conn| {
            // If the existing connection has failed, remove and create fresh
            if (conn.isFailed()) {
                _ = self.connections.remove(remote_domain);
                conn.deinit(self.allocator);
                self.allocator.destroy(conn);
            } else {
                return conn;
            }
        }

        const conn = try self.allocator.create(OutboundConnection);
        conn.* = OutboundConnection.init(self.allocator, local_domain, remote_domain) catch |err| {
            self.allocator.destroy(conn);
            return err;
        };
        // The map key is the connection's own duped domain (T275): one
        // owner, freed at deinit; a caller-borrowed slice never reaches it.
        self.connections.put(conn.remote_domain, conn) catch |err| {
            conn.deinit(self.allocator);
            self.allocator.destroy(conn);
            return err;
        };
        return conn;
    }

    /// Remove a connection from the pool (e.g., on permanent failure or idle timeout).
    pub fn remove(self: *ConnectionPool, remote_domain: []const u8) void {
        if (self.connections.fetchRemove(remote_domain)) |kv| {
            kv.value.deinit(self.allocator);
            self.allocator.destroy(kv.value);
        }
    }

    /// Get an existing connection if one exists and is established.
    pub fn getEstablished(self: *ConnectionPool, remote_domain: []const u8) ?*OutboundConnection {
        const conn = self.connections.get(remote_domain) orelse return null;
        if (conn.isEstablished()) return conn;
        return null;
    }

    /// Number of active connections.
    pub fn count(self: *const ConnectionPool) usize {
        return self.connections.count();
    }
};

// ============================================================================
// Tests
// ============================================================================

test "OutboundConnection: init and basic state" {
    const alloc = std.testing.allocator;
    var conn = try OutboundConnection.init(alloc, "a.example", "b.example");
    defer conn.deinit(alloc);

    try std.testing.expectEqual(OutboundState.connecting, conn.state);
    try std.testing.expectEqualStrings("a.example", conn.local_domain);
    try std.testing.expectEqualStrings("b.example", conn.remote_domain);
    try std.testing.expect(!conn.isEstablished());
    try std.testing.expect(!conn.isFailed());
}

test "OutboundConnection: TCP connected → stream open (STARTTLS path)" {
    const alloc = std.testing.allocator;
    var conn = try OutboundConnection.init(alloc, "a.example", "b.example");
    defer conn.deinit(alloc);

    conn.is_direct_tls = false;
    conn.tcpConnected();
    try std.testing.expectEqual(OutboundState.stream_open, conn.state);
}

test "OutboundConnection: TCP connected → TLS handshake (direct TLS path)" {
    const alloc = std.testing.allocator;
    var conn = try OutboundConnection.init(alloc, "a.example", "b.example");
    defer conn.deinit(alloc);

    conn.is_direct_tls = true;
    conn.tcpConnected();
    try std.testing.expectEqual(OutboundState.tls_handshake, conn.state);
}

test "OutboundConnection: full DANE-verified lifecycle" {
    const alloc = std.testing.allocator;
    var conn = try OutboundConnection.init(alloc, "a.example", "b.example");
    defer conn.deinit(alloc);

    // Direct TLS path
    conn.is_direct_tls = true;
    conn.tcpConnected();
    try std.testing.expectEqual(OutboundState.tls_handshake, conn.state);

    conn.tlsHandshakeComplete();
    try std.testing.expectEqual(OutboundState.dane_check, conn.state);

    conn.setDaneResult(.verified);
    try std.testing.expectEqual(OutboundState.stream_open, conn.state);
    try std.testing.expect(conn.stream.dane_verified);

    // Simulate remote stream open
    conn.handleRemoteStreamOpen("b.example", "stream-id-123");
    try std.testing.expectEqualStrings("stream-id-123", conn.getRemoteStreamId());

    // Features received — should choose EXTERNAL
    const action = conn.handleRemoteFeatures(true, false);
    try std.testing.expectEqual(OutboundAction.send_sasl_external, action);
    try std.testing.expectEqual(OutboundState.authenticating, conn.state);

    // Auth success
    conn.handleAuthSuccess();
    try std.testing.expect(conn.isEstablished());
}

test "OutboundConnection: <proceed/> with plaintext beyond <starttls/> fails the connection (T250 review)" {
    const alloc = std.testing.allocator;

    // TCP loopback pair with a tiny send buffer (unix socketpairs ignore
    // SO_SNDBUF on FreeBSD): queue the <starttls/> request plus a tail.
    const fds = try makeTestTcpPair();
    defer posix.close(fds[1]); // fds[0] goes out via conn.deinit below

    const sndbuf: c_int = 2048;
    var actual_sndbuf: c_int = 0;
    var optlen: posix.socklen_t = @sizeOf(c_int);
    try posix.setsockopt(fds[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&sndbuf));
    if (std.c.getsockopt(fds[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&actual_sndbuf), &optlen) != 0)
        return error.SkipZigTest;

    var conn = try OutboundConnection.init(alloc, "a.example", "b.example");
    defer conn.deinit(alloc);
    conn.fd = fds[0];
    conn.tcpConnected();
    conn.state = .starttls_negotiation;

    // Queue the <starttls/> request... under backpressure something lingers.
    var buf: [2048]u8 = undefined;
    const msg = try conn.buildStarttls(&buf);
    try conn.queueWrite(msg);

    // And bytes that were queued AFTER <starttls/> (the protocol error).
    try conn.queueWrite("<message to='them.example'><body>oops</body></message>");
    try std.testing.expect(conn.hasPendingWrite());

    // <proceed/> arrives: the connection must fail, no upgrade begins.
    try std.testing.expect(!conn.handleStarttlsProceed());
    try std.testing.expect(conn.isFailed());
    try std.testing.expectEqualStrings("plaintext-after-starttls", conn.error_msg);
}

test "OutboundConnection: STARTTLS lifecycle with no DANE" {
    const alloc = std.testing.allocator;
    var conn = try OutboundConnection.init(alloc, "a.example", "b.example");
    defer conn.deinit(alloc);

    conn.is_direct_tls = false;
    conn.tcpConnected();
    try std.testing.expectEqual(OutboundState.stream_open, conn.state);

    // Remote stream opens, we get features with starttls required
    conn.handleRemoteStreamOpen("b.example", "sid-456");
    const starttls_action = conn.handleRemoteFeatures(false, false);
    try std.testing.expectEqual(OutboundAction.send_starttls, starttls_action);
    try std.testing.expectEqual(OutboundState.starttls_negotiation, conn.state);

    // Proceed received
    _ = conn.handleStarttlsProceed();
    try std.testing.expectEqual(OutboundState.tls_handshake, conn.state);

    // TLS done, DANE check
    conn.tlsHandshakeComplete();
    try std.testing.expectEqual(OutboundState.dane_check, conn.state);

    // No TLSA records — fall back to dialback
    conn.setDaneResult(.no_records);
    try std.testing.expectEqual(OutboundState.stream_open, conn.state);

    // Post-TLS stream open
    conn.handleRemoteStreamOpen("b.example", "sid-789");

    // Features with dialback
    const action = conn.handleRemoteFeatures(false, true);
    try std.testing.expectEqual(OutboundAction.begin_dialback, action);
    try std.testing.expectEqual(OutboundState.authenticating, conn.state);
}

test "OutboundConnection: DANE failure rejects connection" {
    const alloc = std.testing.allocator;
    var conn = try OutboundConnection.init(alloc, "a.example", "b.example");
    defer conn.deinit(alloc);

    conn.is_direct_tls = true;
    conn.tcpConnected();
    conn.tlsHandshakeComplete();
    conn.setDaneResult(.failed);
    try std.testing.expect(conn.isFailed());
    try std.testing.expectEqualStrings("dane-verification-failed", conn.error_msg);
}

test "OutboundConnection: queue and count pending stanzas" {
    const alloc = std.testing.allocator;
    var conn = try OutboundConnection.init(alloc, "a.example", "b.example");
    defer conn.deinit(alloc);

    try conn.queueStanza(alloc, "alice@a.example", "bob@b.example", "<message><body>hi</body></message>");
    try conn.queueStanza(alloc, "carol@a.example", "dave@b.example", "<message><body>hey</body></message>");
    try std.testing.expectEqual(@as(usize, 2), conn.pendingCount());
}

test "OutboundConnection: buildStreamOpen" {
    const alloc = std.testing.allocator;
    var conn = try OutboundConnection.init(alloc, "a.example", "b.example");
    defer conn.deinit(alloc);

    var buf: [1024]u8 = undefined;
    const xml = try conn.buildStreamOpen(&buf);
    try std.testing.expect(std.mem.indexOf(u8, xml, "xmlns='jabber:server'") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "from='a.example'") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "to='b.example'") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "version='1.0'") != null);
}

test "OutboundConnection: buildSaslExternal" {
    const alloc = std.testing.allocator;
    var conn = try OutboundConnection.init(alloc, "a.example", "b.example");
    defer conn.deinit(alloc);

    var buf: [1024]u8 = undefined;
    const xml = try conn.buildSaslExternal(&buf);
    try std.testing.expect(std.mem.indexOf(u8, xml, "mechanism='EXTERNAL'") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "urn:ietf:params:xml:ns:xmpp-sasl") != null);
    // Should contain base64 of "a.example"
    try std.testing.expect(std.mem.indexOf(u8, xml, "YS5leGFtcGxl") != null);
}

test "OutboundConnection: buildStarttls" {
    const alloc = std.testing.allocator;
    var conn = try OutboundConnection.init(alloc, "a.example", "b.example");
    defer conn.deinit(alloc);

    var buf: [256]u8 = undefined;
    const xml = try conn.buildStarttls(&buf);
    try std.testing.expect(std.mem.indexOf(u8, xml, "urn:ietf:params:xml:ns:xmpp-tls") != null);
}

test "ConnectionPool: init/deinit" {
    const alloc = std.testing.allocator;
    var pool = ConnectionPool.init(alloc);
    defer pool.deinit();

    try std.testing.expectEqual(@as(usize, 0), pool.count());
}

test "ConnectionPool: getOrCreate creates new connection" {
    const alloc = std.testing.allocator;
    var pool = ConnectionPool.init(alloc);
    defer pool.deinit();

    const conn = try pool.getOrCreate("a.example", "b.example");
    try std.testing.expectEqualStrings("b.example", conn.remote_domain);
    try std.testing.expectEqual(@as(usize, 1), pool.count());

    // Same domain returns same connection
    const conn2 = try pool.getOrCreate("a.example", "b.example");
    try std.testing.expectEqual(conn, conn2);
    try std.testing.expectEqual(@as(usize, 1), pool.count());
}

test "ConnectionPool: getOrCreate replaces failed connection" {
    const alloc = std.testing.allocator;
    var pool = ConnectionPool.init(alloc);
    defer pool.deinit();

    const conn = try pool.getOrCreate("a.example", "b.example");
    conn.fail("test-failure");
    try std.testing.expect(conn.isFailed());

    // Getting the same domain should create a fresh connection
    const conn2 = try pool.getOrCreate("a.example", "b.example");
    try std.testing.expect(!conn2.isFailed());
    try std.testing.expectEqual(OutboundState.connecting, conn2.state);
}

test "ConnectionPool: remove" {
    const alloc = std.testing.allocator;
    var pool = ConnectionPool.init(alloc);
    defer pool.deinit();

    _ = try pool.getOrCreate("a.example", "b.example");
    try std.testing.expectEqual(@as(usize, 1), pool.count());

    pool.remove("b.example");
    try std.testing.expectEqual(@as(usize, 0), pool.count());
}

// --- S23: pinned TLS write retry under backpressure -----------------------

/// Self-signed throwaway cert+key for "localhost" via the openssl CLI (no
/// key material in the tree). error.SkipZigTest when the tool is missing.
fn genTestTlsCert(dir: std.fs.Dir) !void {
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

/// Drive both ends of a non-blocking TLS pair until the handshake finishes.
fn driveTestTlsHandshake(server: *SslConn, client: *SslConn) !void {
    const deadline = std.time.milliTimestamp() + 5000;
    var s_done = false;
    var c_done = false;
    while ((!s_done or !c_done) and std.time.milliTimestamp() < deadline) {
        if (!s_done) s_done = (try server.doHandshake()) == .complete;
        if (!c_done) c_done = (try client.doHandshake()) == .complete;
    }
    if (!s_done or !c_done) return error.TlsHandshakeTimeout;
}

/// Connected non-blocking TCP loopback pair for TLS test rigs. AF_UNIX
/// socketpairs do not enforce SO_SNDBUF strictly on stream sockets, so the
/// backpressure rig needs real TCP; both ends run userland TLS (PR 296498).
fn makeTestTcpPair() ![2]posix.fd_t {
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

    // nodelay keeps the interleaved drive loop free of delayed-ACK stalls.
    const nodelay: c_int = 1;
    try posix.setsockopt(client_fd, 6, 1, std.mem.asBytes(&nodelay)); // IPPROTO_TCP, TCP_NODELAY
    try posix.setsockopt(server_fd, 6, 1, std.mem.asBytes(&nodelay));
    return .{ client_fd, server_fd };
}

test "OutboundConnection: stalled TLS write pins its slice; bytes queued behind it still arrive (S23)" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestTlsCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(alloc, "{s}/cert.pem", .{base}, 0);
    defer alloc.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(alloc, "{s}/key.pem", .{base}, 0);
    defer alloc.free(key_path);

    const fds = try makeTestTcpPair();
    // The listener side is only a scripted TLS server for this rig.
    defer posix.close(fds[1]);

    // Tiny send buffer on the connection side forces TLS write backpressure.
    const head_len = 8192;
    const sndbuf: c_int = 2048;
    try posix.setsockopt(fds[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&sndbuf));
    var actual_sndbuf: c_int = 0;
    var optlen: posix.socklen_t = @sizeOf(c_int);
    if (std.c.getsockopt(fds[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&actual_sndbuf), &optlen) != 0)
        return error.SkipZigTest;
    // One ~8 KiB TLS record must not fit, or the rig cannot stall the write.
    if (actual_sndbuf >= head_len) return error.SkipZigTest;

    // kTLS stays off on both ends: two kTLS peers over lo0 hit FreeBSD
    // PR 296498 (EBADMSG). This rig is entirely userland TLS.
    var client_ctx = try SslContext.initClient();
    defer client_ctx.deinit();
    client_ctx.disableKtls();
    var server_ctx = try SslContext.initServer(cert_path, key_path);
    defer server_ctx.deinit();
    server_ctx.disableKtls();

    var conn = try OutboundConnection.init(alloc, "a.example", "b.example");
    defer conn.deinit(alloc); // also closes fds[0]
    conn.fd = fds[0];
    conn.tls_conn = try SslConn.initClient(client_ctx, fds[0], null);
    conn.tls_state = .established;
    var server = try SslConn.init(server_ctx, fds[1]);
    defer server.deinit();
    try driveTestTlsHandshake(&server, &conn.tls_conn.?);

    // Q11: the accessors behind the post-handshake kTLS log line.
    {
        const tls = &(conn.tls_conn orelse unreachable);
        try std.testing.expect(tls.versionName().len > 0);
        try std.testing.expect(tls.cipherName().len > 0);
        _ = tls.ktlsSend();
        _ = tls.ktlsRecv();
    }

    var head: [head_len]u8 = undefined;
    for (&head, 0..) |*b, i| b.* = @truncate(i);
    const tail = "TAIL-AFTER-PINNED-WRITE";

    // First flush exceeds the send buffer: it must stall and pin the slice.
    try conn.queueWrite(&head);
    try std.testing.expect(!(try conn.flushWrite()));
    try std.testing.expectEqual(@as(usize, head_len), conn.pinned_tls_len);

    // Queue while pinned: the tail must wait behind the pinned slice, not
    // grow the retry.
    try conn.queueWrite(tail);

    var received: [head_len + tail.len]u8 = undefined;
    var got: usize = 0;
    var chunk: [4096]u8 = undefined;
    const deadline = std.time.milliTimestamp() + 5000;
    while (got < received.len and std.time.milliTimestamp() < deadline) {
        if (conn.hasPendingWrite()) {
            _ = conn.flushWrite() catch return error.FlushFailed;
        }
        const rr = server.read(&chunk) catch return error.PeerReadFailed;
        switch (rr) {
            .ok => |n| {
                @memcpy(received[got .. got + n], chunk[0..n]);
                got += n;
            },
            .want_read, .want_write => {},
        }
    }
    try std.testing.expectEqual(received.len, got);
    try std.testing.expect(std.mem.eql(u8, &head, received[0..head_len]));
    try std.testing.expectEqualStrings(tail, received[head_len..][0..tail.len]);
    try std.testing.expectEqual(@as(usize, 0), conn.pinned_tls_len);
    try std.testing.expect(!conn.hasPendingWrite());
}

test "ConnectionPool: getEstablished" {
    const alloc = std.testing.allocator;
    var pool = ConnectionPool.init(alloc);
    defer pool.deinit();

    const conn = try pool.getOrCreate("a.example", "b.example");
    try std.testing.expect(pool.getEstablished("b.example") == null);

    // Simulate full establishment
    conn.is_direct_tls = true;
    conn.tcpConnected();
    conn.tlsHandshakeComplete();
    conn.setDaneResult(.verified);
    conn.handleRemoteStreamOpen("b.example", "sid");
    _ = conn.handleRemoteFeatures(true, false);
    conn.handleAuthSuccess();

    try std.testing.expect(pool.getEstablished("b.example") != null);
}
