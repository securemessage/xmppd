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

    const PendingQueue = std.ArrayList(PendingStanza);

    pub fn init(
        allocator: std.mem.Allocator,
        local_domain: []const u8,
        remote_domain: []const u8,
    ) OutboundConnection {
        return .{
            .remote_domain = remote_domain,
            .local_domain = local_domain,
            .state = .connecting,
            .stream = S2sStream.init(.initiating, local_domain),
            .pending_stanzas = PendingQueue{},
            .alloc = allocator,
        };
    }

    pub fn deinit(self: *OutboundConnection, allocator: std.mem.Allocator) void {
        for (self.pending_stanzas.items) |stanza| {
            allocator.free(stanza.xml);
        }
        self.pending_stanzas.deinit(allocator);
        if (self.fd >= 0) {
            posix.close(self.fd);
            self.fd = -1;
        }
    }

    /// Queue a stanza for delivery once the connection is established.
    pub fn queueStanza(self: *OutboundConnection, allocator: std.mem.Allocator, from: []const u8, to: []const u8, xml: []const u8) !void {
        const xml_copy = try allocator.dupe(u8, xml);
        errdefer allocator.free(xml_copy);
        try self.pending_stanzas.append(allocator, .{
            .from_jid = from,
            .to_jid = to,
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

    /// STARTTLS proceed received — start TLS handshake.
    pub fn handleStarttlsProceed(self: *OutboundConnection) void {
        self.state = .tls_handshake;
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
    pub fn buildStreamOpen(self: *const OutboundConnection, buf: []u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();
        try writer.writeAll("<?xml version='1.0'?><stream:stream xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams' xmlns:db='jabber:server:dialback' from='");
        try writer.writeAll(self.local_domain);
        try writer.writeAll("' to='");
        try writer.writeAll(self.remote_domain);
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

/// A stanza queued for delivery.
pub const PendingStanza = struct {
    from_jid: []const u8,
    to_jid: []const u8,
    xml: []const u8,
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
        conn.* = OutboundConnection.init(self.allocator, local_domain, remote_domain);
        try self.connections.put(remote_domain, conn);
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
    var conn = OutboundConnection.init(alloc, "a.example", "b.example");
    defer conn.deinit(alloc);

    try std.testing.expectEqual(OutboundState.connecting, conn.state);
    try std.testing.expectEqualStrings("a.example", conn.local_domain);
    try std.testing.expectEqualStrings("b.example", conn.remote_domain);
    try std.testing.expect(!conn.isEstablished());
    try std.testing.expect(!conn.isFailed());
}

test "OutboundConnection: TCP connected → stream open (STARTTLS path)" {
    const alloc = std.testing.allocator;
    var conn = OutboundConnection.init(alloc, "a.example", "b.example");
    defer conn.deinit(alloc);

    conn.is_direct_tls = false;
    conn.tcpConnected();
    try std.testing.expectEqual(OutboundState.stream_open, conn.state);
}

test "OutboundConnection: TCP connected → TLS handshake (direct TLS path)" {
    const alloc = std.testing.allocator;
    var conn = OutboundConnection.init(alloc, "a.example", "b.example");
    defer conn.deinit(alloc);

    conn.is_direct_tls = true;
    conn.tcpConnected();
    try std.testing.expectEqual(OutboundState.tls_handshake, conn.state);
}

test "OutboundConnection: full DANE-verified lifecycle" {
    const alloc = std.testing.allocator;
    var conn = OutboundConnection.init(alloc, "a.example", "b.example");
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

test "OutboundConnection: STARTTLS lifecycle with no DANE" {
    const alloc = std.testing.allocator;
    var conn = OutboundConnection.init(alloc, "a.example", "b.example");
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
    conn.handleStarttlsProceed();
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
    var conn = OutboundConnection.init(alloc, "a.example", "b.example");
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
    var conn = OutboundConnection.init(alloc, "a.example", "b.example");
    defer conn.deinit(alloc);

    try conn.queueStanza(alloc, "alice@a.example", "bob@b.example", "<message><body>hi</body></message>");
    try conn.queueStanza(alloc, "carol@a.example", "dave@b.example", "<message><body>hey</body></message>");
    try std.testing.expectEqual(@as(usize, 2), conn.pendingCount());
}

test "OutboundConnection: buildStreamOpen" {
    const alloc = std.testing.allocator;
    var conn = OutboundConnection.init(alloc, "a.example", "b.example");
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
    var conn = OutboundConnection.init(alloc, "a.example", "b.example");
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
    var conn = OutboundConnection.init(alloc, "a.example", "b.example");
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
