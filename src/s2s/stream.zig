//! # S2S Stream FSM — jabber:server stream state machine
//!
//! Models server-to-server XMPP stream negotiation per RFC 6120 Section 5+8.
//! S2S streams differ from C2S:
//!
//! - Namespace: `jabber:server` (not `jabber:client`)
//! - No resource binding — auth is per-domain
//! - Two roles: **initiating** (outbound) and **receiving** (inbound)
//! - Auth methods: SASL EXTERNAL (with DANE) or XEP-0220 Dialback
//!
//! ## Initiating (outbound) lifecycle
//!
//! ```
//! connect → stream_open → tls_negotiation → stream_reset →
//! features_auth → (EXTERNAL or dialback) → established
//! ```
//!
//! ## Receiving (inbound) lifecycle
//!
//! ```
//! accept → stream_open → tls_negotiation → stream_reset →
//! await_auth → (verify EXTERNAL/DANE or dialback) → established
//! ```

const std = @import("std");

/// S2S stream role — determines which side we're on.
pub const Role = enum {
    /// We initiated the connection (outbound).
    initiating,
    /// We received the connection (inbound listener).
    receiving,
};

/// S2S stream state.
pub const S2sStreamState = enum {
    /// Waiting for initial <stream:stream>.
    awaiting_stream_open,
    /// Stream opened, advertising features (TLS required).
    features_tls,
    /// STARTTLS negotiated, TLS handshake in progress.
    starttls_pending,
    /// TLS established, expecting stream restart.
    awaiting_stream_open_tls,
    /// Post-TLS stream opened, advertising auth features.
    features_auth,
    /// SASL EXTERNAL or dialback negotiation in progress.
    authenticating,
    /// Authenticated, stream is established — stanzas can flow.
    established,
    /// Stream is closing.
    closing,
    /// Closed or errored.
    closed,
};

/// Actions the S2S stream FSM tells the daemon to perform.
pub const S2sStreamAction = union(enum) {
    /// Send our stream open response.
    send_stream_open: StreamOpenParams,
    /// Send stream features (TLS or auth).
    send_features: S2sFeatureSet,
    /// Send STARTTLS <proceed/>.
    send_tls_proceed,
    /// Start TLS handshake on the socket.
    start_tls,
    /// Request STARTTLS from remote (initiating role).
    send_starttls,
    /// Begin SASL EXTERNAL auth (initiating role after DANE verified).
    send_sasl_external,
    /// Send SASL success (receiving role, EXTERNAL verified).
    send_sasl_success,
    /// Send SASL failure.
    send_sasl_failure: []const u8,
    /// Begin dialback protocol.
    begin_dialback,
    /// Send a stream error and close.
    send_error: StreamError,
    /// S2S stream is ready for stanza delivery.
    stream_established,
    /// Close the stream.
    close,
    /// No action needed.
    none,
};

pub const StreamOpenParams = struct {
    from: []const u8,
    to: []const u8,
    id: []const u8,
};

pub const StreamError = enum {
    host_unknown,
    not_authorized,
    invalid_namespace,
    not_well_formed,
    policy_violation,
    internal_server_error,
    unsupported_version,

    pub fn toString(self: StreamError) []const u8 {
        return switch (self) {
            .host_unknown => "host-unknown",
            .not_authorized => "not-authorized",
            .invalid_namespace => "invalid-namespace",
            .not_well_formed => "not-well-formed",
            .policy_violation => "policy-violation",
            .internal_server_error => "internal-server-error",
            .unsupported_version => "unsupported-version",
        };
    }
};

pub const S2sFeatureSet = struct {
    starttls_required: bool = false,
    sasl_external: bool = false,
    dialback: bool = false,
};

/// S2S XMPP stream state machine.
pub const S2sStream = struct {
    role: Role,
    state: S2sStreamState = .awaiting_stream_open,
    local_domain: []const u8,
    remote_domain: []const u8 = "",
    stream_id: []const u8 = "",

    /// Whether DANE verification succeeded on the TLS connection.
    /// Determines if SASL EXTERNAL is offered/used.
    dane_verified: bool = false,

    /// Whether the peer is authenticated (EXTERNAL or dialback).
    authenticated: bool = false,

    pub fn init(role: Role, local_domain: []const u8) S2sStream {
        return .{
            .role = role,
            .local_domain = local_domain,
        };
    }

    /// Handle an incoming <stream:stream> open.
    ///
    /// For **receiving**: respond with our stream open + features.
    /// For **initiating**: process the remote server's stream open.
    pub fn handleStreamOpen(self: *S2sStream, from: []const u8, _: []const u8, _: []const u8) S2sStreamAction {
        switch (self.state) {
            .awaiting_stream_open => {
                if (self.role == .receiving) {
                    // Inbound connection — remote tells us who they are
                    self.remote_domain = from;
                    self.state = .features_tls;
                    return .{ .send_stream_open = .{
                        .from = self.local_domain,
                        .to = from,
                        .id = "s2s-placeholder-id",
                    } };
                } else {
                    // Outbound — we receive the remote's stream open reply
                    self.remote_domain = from;
                    // Wait for features
                    return .none;
                }
            },
            .awaiting_stream_open_tls => {
                // Post-TLS or post-SASL stream restart
                if (self.role == .receiving) {
                    if (self.authenticated) {
                        // Post-SASL restart — stream is now fully established
                        self.state = .established;
                    } else {
                        self.state = .features_auth;
                    }
                    return .{ .send_stream_open = .{
                        .from = self.local_domain,
                        .to = self.remote_domain,
                        .id = "s2s-placeholder-id",
                    } };
                } else {
                    // Outbound — wait for features
                    if (self.authenticated) {
                        self.state = .established;
                    } else {
                        self.state = .features_auth;
                    }
                    return .none;
                }
            },
            else => return .{ .send_error = .not_well_formed },
        }
    }

    /// Get the feature set for the current state.
    pub fn getFeatures(self: *const S2sStream) ?S2sFeatureSet {
        return switch (self.state) {
            .features_tls => .{ .starttls_required = true },
            .features_auth => .{
                .sasl_external = self.dane_verified,
                .dialback = !self.dane_verified,
            },
            else => null,
        };
    }

    /// Handle STARTTLS request from peer (receiving role).
    pub fn handleStarttls(self: *S2sStream) S2sStreamAction {
        if (self.state != .features_tls) return .{ .send_error = .not_well_formed };
        self.state = .starttls_pending;
        return .send_tls_proceed;
    }

    /// Called after TLS handshake completes.
    pub fn tlsEstablished(self: *S2sStream) void {
        self.state = .awaiting_stream_open_tls;
    }

    /// Mark DANE verification result (call after TLS handshake + TLSA check).
    pub fn setDaneVerified(self: *S2sStream, verified: bool) void {
        self.dane_verified = verified;
    }

    /// Handle SASL EXTERNAL auth from peer (receiving role).
    pub fn handleSaslExternal(self: *S2sStream) S2sStreamAction {
        if (self.state != .features_auth) return .{ .send_error = .not_well_formed };

        if (self.dane_verified) {
            self.authenticated = true;
            // After SASL success, remote will restart the stream
            self.state = .awaiting_stream_open_tls; // Reuse: expects stream restart
            return .send_sasl_success;
        } else {
            return .{ .send_sasl_failure = "not-authorized" };
        }
    }

    /// For initiating role: after features received, decide auth method.
    pub fn chooseAuthMethod(self: *S2sStream) S2sStreamAction {
        if (self.state != .features_auth) return .none;

        self.state = .authenticating;
        if (self.dane_verified) {
            return .send_sasl_external;
        } else {
            return .begin_dialback;
        }
    }

    /// Mark stream as authenticated (after successful EXTERNAL or dialback).
    pub fn setAuthenticated(self: *S2sStream) void {
        self.authenticated = true;
        self.state = .established;
    }

    /// Whether the stream is in established state (ready for stanzas).
    pub fn isEstablished(self: *const S2sStream) bool {
        return self.state == .established;
    }

    /// Handle stream close.
    pub fn handleClose(self: *S2sStream) S2sStreamAction {
        self.state = .closed;
        return .close;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "S2sStream: receiving role — full lifecycle" {
    var s = S2sStream.init(.receiving, "a.example");

    // Inbound stream open from remote
    const open_action = s.handleStreamOpen("b.example", "a.example", "1.0");
    switch (open_action) {
        .send_stream_open => |p| {
            try std.testing.expectEqualStrings("a.example", p.from);
            try std.testing.expectEqualStrings("b.example", p.to);
        },
        else => return error.UnexpectedAction,
    }
    try std.testing.expectEqual(S2sStreamState.features_tls, s.state);
    try std.testing.expectEqualStrings("b.example", s.remote_domain);

    // Features should require TLS
    const features = s.getFeatures() orelse return error.NoFeatures;
    try std.testing.expect(features.starttls_required);

    // STARTTLS request
    const tls_action = s.handleStarttls();
    try std.testing.expectEqual(S2sStreamAction.send_tls_proceed, tls_action);

    // TLS established
    s.tlsEstablished();
    try std.testing.expectEqual(S2sStreamState.awaiting_stream_open_tls, s.state);

    // Stream restart after TLS — DANE verified
    s.setDaneVerified(true);
    const open2_action = s.handleStreamOpen("b.example", "a.example", "1.0");
    switch (open2_action) {
        .send_stream_open => {},
        else => return error.UnexpectedAction,
    }
    try std.testing.expectEqual(S2sStreamState.features_auth, s.state);

    // Auth features should offer EXTERNAL
    const auth_features = s.getFeatures() orelse return error.NoFeatures;
    try std.testing.expect(auth_features.sasl_external);
    try std.testing.expect(!auth_features.dialback);

    // SASL EXTERNAL auth
    const auth_action = s.handleSaslExternal();
    try std.testing.expectEqual(S2sStreamAction.send_sasl_success, auth_action);
    try std.testing.expect(s.authenticated);
    try std.testing.expectEqual(S2sStreamState.awaiting_stream_open_tls, s.state);

    // Post-auth stream restart
    const open3_action = s.handleStreamOpen("b.example", "a.example", "1.0");
    switch (open3_action) {
        .send_stream_open => {},
        else => return error.UnexpectedAction,
    }
    try std.testing.expect(s.isEstablished());
}

test "S2sStream: initiating role — DANE auth flow" {
    var s = S2sStream.init(.initiating, "a.example");

    // We receive remote's stream open reply
    const action = s.handleStreamOpen("b.example", "a.example", "1.0");
    try std.testing.expectEqual(S2sStreamAction.none, action);

    // Simulate receiving TLS feature (not modeled here — we just advance state)
    // After TLS, stream restarts
    s.state = .starttls_pending;
    s.tlsEstablished();
    s.setDaneVerified(true);

    const open2_action = s.handleStreamOpen("b.example", "a.example", "1.0");
    try std.testing.expectEqual(S2sStreamAction.none, open2_action);
    try std.testing.expectEqual(S2sStreamState.features_auth, s.state);

    // Choose auth method — should be EXTERNAL since DANE verified
    const auth_action = s.chooseAuthMethod();
    try std.testing.expectEqual(S2sStreamAction.send_sasl_external, auth_action);

    // Auth succeeds (remote sends <success/>)
    s.setAuthenticated();
    try std.testing.expect(s.isEstablished());
}

test "S2sStream: receiving role — no DANE, dialback offered" {
    var s = S2sStream.init(.receiving, "a.example");

    _ = s.handleStreamOpen("b.example", "a.example", "1.0");
    _ = s.handleStarttls();
    s.tlsEstablished();
    s.setDaneVerified(false);
    _ = s.handleStreamOpen("b.example", "a.example", "1.0");

    const auth_features = s.getFeatures() orelse return error.NoFeatures;
    try std.testing.expect(!auth_features.sasl_external);
    try std.testing.expect(auth_features.dialback);
}

test "S2sStream: SASL EXTERNAL fails without DANE" {
    var s = S2sStream.init(.receiving, "a.example");

    _ = s.handleStreamOpen("b.example", "a.example", "1.0");
    _ = s.handleStarttls();
    s.tlsEstablished();
    s.setDaneVerified(false);
    _ = s.handleStreamOpen("b.example", "a.example", "1.0");

    const auth_action = s.handleSaslExternal();
    switch (auth_action) {
        .send_sasl_failure => |reason| {
            try std.testing.expectEqualStrings("not-authorized", reason);
        },
        else => return error.UnexpectedAction,
    }
    try std.testing.expect(!s.isEstablished());
}

test "S2sStream: close" {
    var s = S2sStream.init(.receiving, "a.example");
    _ = s.handleStreamOpen("b.example", "a.example", "1.0");
    const action = s.handleClose();
    try std.testing.expectEqual(S2sStreamAction.close, action);
    try std.testing.expectEqual(S2sStreamState.closed, s.state);
}
