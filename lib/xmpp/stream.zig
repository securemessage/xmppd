const std = @import("std");
const xml = @import("xml");
const jid_mod = @import("jid.zig");
const Jid = jid_mod.Jid;

/// XMPP stream state machine per RFC 6120.
///
/// Models the server-side lifecycle of an XMPP stream:
/// TCP connect → stream open → STARTTLS → stream reset →
/// SASL auth → stream reset → resource bind → session active
pub const StreamState = enum {
    /// Waiting for initial <stream:stream> from client
    awaiting_stream_open,
    /// Stream opened, advertising features (TLS required)
    features_tls,
    /// STARTTLS negotiated, waiting for TLS handshake to complete
    starttls_pending,
    /// TLS established, stream reset expected
    awaiting_stream_open_tls,
    /// Stream reopened post-TLS, advertising features (SASL)
    features_sasl,
    /// SASL negotiation in progress
    sasl_negotiating,
    /// SASL completed, stream reset expected
    awaiting_stream_open_authenticated,
    /// Authenticated stream, advertising features (bind)
    features_bind,
    /// Resource binding in progress
    binding,
    /// Session fully established — stanzas can flow
    active,
    /// Stream is closing
    closing,
    /// Stream closed / error
    closed,
};

/// Stream errors per RFC 6120 Section 4.9.
pub const StreamError = enum {
    bad_format,
    bad_namespace_prefix,
    connection_timeout,
    host_gone,
    host_unknown,
    improper_addressing,
    internal_server_error,
    invalid_from,
    invalid_namespace,
    not_authorized,
    not_well_formed,
    policy_violation,
    remote_connection_failed,
    reset,
    resource_constraint,
    restricted_xml,
    system_shutdown,
    undefined_condition,
    unsupported_encoding,
    unsupported_feature,
    unsupported_stanza_type,
    unsupported_version,

    pub fn toString(self: StreamError) []const u8 {
        return switch (self) {
            .bad_format => "bad-format",
            .bad_namespace_prefix => "bad-namespace-prefix",
            .connection_timeout => "connection-timeout",
            .host_gone => "host-gone",
            .host_unknown => "host-unknown",
            .improper_addressing => "improper-addressing",
            .internal_server_error => "internal-server-error",
            .invalid_from => "invalid-from",
            .invalid_namespace => "invalid-namespace",
            .not_authorized => "not-authorized",
            .not_well_formed => "not-well-formed",
            .policy_violation => "policy-violation",
            .remote_connection_failed => "remote-connection-failed",
            .reset => "reset",
            .resource_constraint => "resource-constraint",
            .restricted_xml => "restricted-xml",
            .system_shutdown => "system-shutdown",
            .undefined_condition => "undefined-condition",
            .unsupported_encoding => "unsupported-encoding",
            .unsupported_feature => "unsupported-feature",
            .unsupported_stanza_type => "unsupported-stanza-type",
            .unsupported_version => "unsupported-version",
        };
    }
};

/// Actions the stream state machine tells the daemon to perform.
pub const StreamAction = union(enum) {
    /// Send the server's stream opening tag
    send_stream_open: StreamOpenParams,
    /// Send stream features
    send_features: FeatureSet,
    /// Initiate STARTTLS handshake on the socket
    start_tls,
    /// Send STARTTLS <proceed/>
    send_tls_proceed,
    /// Begin SASL negotiation with the given mechanism
    begin_sasl: []const u8,
    /// Send SASL challenge to client
    send_sasl_challenge: []const u8,
    /// Send SASL success
    send_sasl_success: []const u8,
    /// Send SASL failure
    send_sasl_failure: []const u8,
    /// Send IQ result for resource bind
    send_bind_result: Jid,
    /// Send a stream error and close
    send_error: StreamError,
    /// Stream is ready for stanzas
    session_established,
    /// Close the stream
    close,
    /// No action needed (internal transition)
    none,
};

/// Parameters for the server's stream opening response.
pub const StreamOpenParams = struct {
    from: []const u8,
    to: []const u8,
    id: []const u8,
    version: []const u8 = "1.0",
};

/// Which features to advertise.
pub const FeatureSet = struct {
    starttls: bool = false,
    starttls_required: bool = false,
    sasl_mechanisms: []const []const u8 = &.{},
    bind: bool = false,
    sm: bool = false,
    csi: bool = false,
};

/// Server-side XMPP stream state machine.
pub const Stream = struct {
    state: StreamState = .awaiting_stream_open,
    /// The server's hostname
    server_host: []const u8,
    /// Whether TLS is already active (direct TLS connection)
    tls_active: bool = false,
    /// Whether SASL authentication succeeded
    authenticated: bool = false,
    /// The authenticated user's JID (set after SASL)
    authenticated_jid: ?Jid = null,
    /// The bound full JID (after resource binding)
    bound_jid: ?Jid = null,
    /// Stream ID (generated per stream)
    stream_id: [16]u8 = undefined,
    /// Hex-encoded stream ID (persisted for pointer stability)
    stream_id_hex: [32]u8 = undefined,

    pub fn init(server_host: []const u8, direct_tls: bool) Stream {
        var s = Stream{
            .server_host = server_host,
            .tls_active = direct_tls,
        };
        s.regenerateStreamId();
        // If already on TLS, skip the TLS negotiation phase
        if (direct_tls) {
            s.state = .awaiting_stream_open;
        }
        return s;
    }

    /// Generate a new random stream ID (RFC 6120 §4.7.3).
    fn regenerateStreamId(self: *Stream) void {
        std.crypto.random.bytes(&self.stream_id);
        self.stream_id_hex = std.fmt.bytesToHex(self.stream_id, .lower);
    }

    /// Process a stream open from the client.
    /// Returns the action(s) the daemon should perform.
    pub fn handleStreamOpen(self: *Stream, to: []const u8, version: []const u8) StreamAction {
        _ = version;

        // Validate the 'to' attribute matches our hostname
        if (!std.mem.eql(u8, to, self.server_host)) {
            return .{ .send_error = .host_unknown };
        }

        // RFC 6120 §4.7.3: each stream restart MUST use a new unique stream ID
        self.regenerateStreamId();

        switch (self.state) {
            .awaiting_stream_open => {
                if (self.tls_active) {
                    // Already on TLS, go to SASL
                    self.state = .features_sasl;
                } else {
                    self.state = .features_tls;
                }
                return .{ .send_stream_open = .{
                    .from = self.server_host,
                    .to = to,
                    .id = &self.stream_id_hex,
                } };
            },
            .awaiting_stream_open_tls => {
                self.state = .features_sasl;
                return .{ .send_stream_open = .{
                    .from = self.server_host,
                    .to = to,
                    .id = &self.stream_id_hex,
                } };
            },
            .awaiting_stream_open_authenticated => {
                self.state = .features_bind;
                return .{ .send_stream_open = .{
                    .from = self.server_host,
                    .to = to,
                    .id = &self.stream_id_hex,
                } };
            },
            else => {
                return .{ .send_error = .not_well_formed };
            },
        }
    }

    /// Get the features to advertise for the current state.
    pub fn getFeatures(self: *const Stream) ?FeatureSet {
        return switch (self.state) {
            .features_tls => FeatureSet{
                .starttls = true,
                .starttls_required = true,
            },
            .features_sasl => FeatureSet{
                .sasl_mechanisms = &.{ "SCRAM-SHA-256", "PLAIN" },
            },
            .features_bind => FeatureSet{
                .bind = true,
                .sm = true,
                .csi = true,
            },
            else => null,
        };
    }

    /// Handle a STARTTLS request from the client.
    pub fn handleStarttls(self: *Stream) StreamAction {
        if (self.state != .features_tls) {
            return .{ .send_error = .not_authorized };
        }
        self.state = .starttls_pending;
        return .send_tls_proceed;
    }

    /// Called after TLS handshake completes successfully.
    pub fn tlsEstablished(self: *Stream) void {
        self.tls_active = true;
        self.state = .awaiting_stream_open_tls;
    }

    /// Handle SASL auth initiation from client.
    pub fn handleSaslAuth(self: *Stream, mechanism: []const u8) StreamAction {
        if (self.state != .features_sasl) {
            return .{ .send_error = .not_authorized };
        }
        self.state = .sasl_negotiating;
        return .{ .begin_sasl = mechanism };
    }

    /// Handle SASL response from client (intermediate challenge-response).
    pub fn handleSaslResponse(self: *Stream, _: []const u8) StreamAction {
        if (self.state != .sasl_negotiating) {
            return .{ .send_error = .not_authorized };
        }
        // The actual SASL processing is done by the auth daemon.
        // This just validates state.
        return .none;
    }

    /// Called when SASL authentication succeeds.
    pub fn saslSuccess(self: *Stream, username: []const u8, server_final: []const u8) StreamAction {
        self.authenticated = true;
        self.authenticated_jid = Jid{
            .local = username,
            .domain = self.server_host,
        };
        self.state = .awaiting_stream_open_authenticated;
        return .{ .send_sasl_success = server_final };
    }

    /// Called when SASL authentication fails.
    pub fn saslFailure(self: *Stream) StreamAction {
        self.state = .features_sasl;
        return .{ .send_sasl_failure = "not-authorized" };
    }

    /// Handle resource bind request.
    pub fn handleBind(self: *Stream, requested_resource: []const u8) StreamAction {
        if (self.state != .features_bind) {
            return .{ .send_error = .not_authorized };
        }

        const auth_jid = self.authenticated_jid orelse {
            return .{ .send_error = .not_authorized };
        };

        // Use requested resource or generate one
        const resource = if (requested_resource.len > 0) requested_resource else "default";

        self.bound_jid = Jid{
            .local = auth_jid.local,
            .domain = auth_jid.domain,
            .resource = resource,
        };

        self.state = .active;
        return .{ .send_bind_result = self.bound_jid.? };
    }

    /// Check if the stream is fully established and can route stanzas.
    pub fn isActive(self: *const Stream) bool {
        return self.state == .active;
    }

    /// Check if TLS is active on this stream.
    pub fn isTlsActive(self: *const Stream) bool {
        return self.tls_active;
    }

    /// Check if the stream is authenticated.
    pub fn isAuthenticated(self: *const Stream) bool {
        return self.authenticated;
    }

    /// Handle stream close from client.
    pub fn handleClose(self: *Stream) StreamAction {
        self.state = .closed;
        return .close;
    }
};

/// Generate the server's stream opening XML.
pub fn writeStreamOpen(writer: anytype, params: StreamOpenParams) !void {
    try writer.writeAll("<?xml version='1.0'?>");
    try writer.writeAll("<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'");
    try writer.writeAll(" from='");
    try writer.writeAll(params.from);
    try writer.writeAll("' to='");
    try writer.writeAll(params.to);
    try writer.writeAll("' id='");
    try writer.writeAll(params.id);
    try writer.writeAll("' version='");
    try writer.writeAll(params.version);
    try writer.writeAll("'>");
}

/// Generate stream features XML.
pub fn writeFeatures(writer: anytype, features: FeatureSet) !void {
    try writer.writeAll("<stream:features>");

    if (features.starttls) {
        try writer.writeAll("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>");
        if (features.starttls_required) {
            try writer.writeAll("<required/>");
        }
        try writer.writeAll("</starttls>");
    }

    if (features.sasl_mechanisms.len > 0) {
        try writer.writeAll("<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>");
        for (features.sasl_mechanisms) |mech| {
            try writer.writeAll("<mechanism>");
            try writer.writeAll(mech);
            try writer.writeAll("</mechanism>");
        }
        try writer.writeAll("</mechanisms>");
    }

    if (features.bind) {
        try writer.writeAll("<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>");
        // Legacy session (RFC 3921) — marked optional for backward compatibility.
        // Some clients (Profanity/libstrophe) expect this element in bind features.
        try writer.writeAll("<session xmlns='urn:ietf:params:xml:ns:xmpp-session'><optional/></session>");
    }

    if (features.sm) {
        try writer.writeAll("<sm xmlns='urn:xmpp:sm:3'/>");
    }

    if (features.csi) {
        try writer.writeAll("<csi xmlns='urn:xmpp:csi:0'/>");
    }

    try writer.writeAll("</stream:features>");
}

/// Generate a stream error XML.
pub fn writeStreamError(writer: anytype, err: StreamError) !void {
    try writer.writeAll("<stream:error><");
    try writer.writeAll(err.toString());
    try writer.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>");
    try writer.writeAll("</stream:stream>");
}

// --- Tests ---

test "Stream: full lifecycle (STARTTLS path)" {
    var stream = Stream.init("example.com", false);

    // Initial state
    try std.testing.expectEqual(StreamState.awaiting_stream_open, stream.state);
    try std.testing.expect(!stream.isTlsActive());

    // Client opens stream
    const action1 = stream.handleStreamOpen("example.com", "1.0");
    try std.testing.expect(action1 == .send_stream_open);
    try std.testing.expectEqual(StreamState.features_tls, stream.state);

    // Features should offer STARTTLS
    const features1 = stream.getFeatures().?;
    try std.testing.expect(features1.starttls);
    try std.testing.expect(features1.starttls_required);

    // Client requests STARTTLS
    const action2 = stream.handleStarttls();
    try std.testing.expect(action2 == .send_tls_proceed);
    try std.testing.expectEqual(StreamState.starttls_pending, stream.state);

    // TLS handshake completes
    stream.tlsEstablished();
    try std.testing.expect(stream.isTlsActive());
    try std.testing.expectEqual(StreamState.awaiting_stream_open_tls, stream.state);

    // Client reopens stream (post-TLS)
    const action3 = stream.handleStreamOpen("example.com", "1.0");
    try std.testing.expect(action3 == .send_stream_open);
    try std.testing.expectEqual(StreamState.features_sasl, stream.state);

    // Features should offer SASL
    const features2 = stream.getFeatures().?;
    try std.testing.expect(features2.sasl_mechanisms.len > 0);

    // Client initiates SASL
    const action4 = stream.handleSaslAuth("SCRAM-SHA-256");
    try std.testing.expect(action4 == .begin_sasl);
    try std.testing.expectEqual(StreamState.sasl_negotiating, stream.state);

    // SASL succeeds
    const action5 = stream.saslSuccess("alice", "v=serverproof");
    try std.testing.expect(action5 == .send_sasl_success);
    try std.testing.expect(stream.isAuthenticated());
    try std.testing.expectEqual(StreamState.awaiting_stream_open_authenticated, stream.state);

    // Client reopens stream (post-SASL)
    const action6 = stream.handleStreamOpen("example.com", "1.0");
    try std.testing.expect(action6 == .send_stream_open);
    try std.testing.expectEqual(StreamState.features_bind, stream.state);

    // Features should offer bind
    const features3 = stream.getFeatures().?;
    try std.testing.expect(features3.bind);

    // Client requests resource binding
    const action7 = stream.handleBind("mobile");
    try std.testing.expect(action7 == .send_bind_result);
    try std.testing.expect(stream.isActive());
    try std.testing.expectEqualStrings("alice", stream.bound_jid.?.local);
    try std.testing.expectEqualStrings("mobile", stream.bound_jid.?.resource);
}

test "Stream: direct TLS path (skips STARTTLS)" {
    var stream = Stream.init("example.com", true);

    try std.testing.expect(stream.isTlsActive());

    // Client opens stream (already on TLS)
    const action1 = stream.handleStreamOpen("example.com", "1.0");
    try std.testing.expect(action1 == .send_stream_open);
    // Should go directly to SASL features
    try std.testing.expectEqual(StreamState.features_sasl, stream.state);

    const features = stream.getFeatures().?;
    try std.testing.expect(features.sasl_mechanisms.len > 0);
    try std.testing.expect(!features.starttls);
}

test "Stream: wrong hostname" {
    var stream = Stream.init("example.com", false);
    const action = stream.handleStreamOpen("wrong.com", "1.0");
    try std.testing.expect(action == .send_error);
    try std.testing.expectEqual(StreamError.host_unknown, action.send_error);
}

test "Stream: SASL failure allows retry" {
    var stream = Stream.init("example.com", true);
    _ = stream.handleStreamOpen("example.com", "1.0");
    _ = stream.handleSaslAuth("PLAIN");

    const action = stream.saslFailure();
    try std.testing.expect(action == .send_sasl_failure);
    // Should return to features_sasl state for retry
    try std.testing.expectEqual(StreamState.features_sasl, stream.state);
}

test "writeStreamOpen" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try writeStreamOpen(fbs.writer(), .{
        .from = "example.com",
        .to = "alice",
        .id = "session123",
    });

    const result = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, result, "<?xml version='1.0'?>") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "from='example.com'") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "id='session123'") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "xmlns:stream='http://etherx.jabber.org/streams'") != null);
}

test "writeFeatures: TLS required" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try writeFeatures(fbs.writer(), .{
        .starttls = true,
        .starttls_required = true,
    });

    const result = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, result, "<stream:features>") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "<starttls") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "<required/>") != null);
}

test "writeFeatures: SASL mechanisms" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try writeFeatures(fbs.writer(), .{
        .sasl_mechanisms = &.{ "SCRAM-SHA-256", "PLAIN" },
    });

    const result = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, result, "<mechanism>SCRAM-SHA-256</mechanism>") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "<mechanism>PLAIN</mechanism>") != null);
}

test "writeStreamError" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try writeStreamError(fbs.writer(), .host_unknown);
    const result = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, result, "<stream:error>") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "<host-unknown") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "</stream:stream>") != null);
}

test "StreamError.toString" {
    try std.testing.expectEqualStrings("not-well-formed", StreamError.not_well_formed.toString());
    try std.testing.expectEqualStrings("host-unknown", StreamError.host_unknown.toString());
    try std.testing.expectEqualStrings("internal-server-error", StreamError.internal_server_error.toString());
}
