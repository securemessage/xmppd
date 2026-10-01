//! # xmppc Client Stream — client-side XMPP stream FSM (RFC 6120 + XEP-0198)
//!
//! Pure state machine modelling the CLIENT half of the XMPP stream lifecycle:
//!
//!     stream open -> [STARTTLS -> TLS -> server re-opens stream]
//!                 -> SASL -> client re-opens stream -> bind -> [session]
//!                 -> [SM enable/resume] -> active
//!
//! This is the client counterpart of `lib/xmpp/stream.zig` (server-side, not to be
//! refactored). It holds no I/O and no allocator: the `Session` feeds it high-level
//! protocol events (`ServerEvent`) and executes the `ClientAction`s it emits.
//!
//! `<stream:features>` is consumed as ONE `ServerEvent` (the reader reassembles the
//! feature block), so the FSM never has to track "which feature element arrived next".
//!
//! Stream Management (XEP-0198) enable + resume are part of establishment here; the
//! ongoing `r`/`h` ack bookkeeping lives in `sm.zig`.

const std = @import("std");
const xmpp = @import("xmpp");
const Jid = xmpp.Jid;

/// Client-side stream lifecycle states.
pub const ClientState = enum {
    /// Not yet connected (Session has not opened the socket).
    idle,
    /// TCP connected; we sent `<stream:stream>`, awaiting the server header+features.
    awaiting_stream_header,
    /// Sent `<starttls/>`; awaiting `<proceed/>`.
    awaiting_starttls_proceed,
    /// `<proceed/>` received; the TLS handshake is driven by the Session.
    tls_handshaking,
    /// Post-TLS; awaiting the server's fresh `<stream:stream>` header+features.
    awaiting_stream_header_tls,
    /// SASL `<auth>`/`<response>` exchange in progress.
    sasl_negotiating,
    /// SASL succeeded; awaiting the server's fresh header+features before bind.
    awaiting_stream_header_auth,
    /// Sent the bind IQ; awaiting its `<result>`.
    awaiting_bind_result,
    /// Sent the (optional) session IQ; awaiting its `<result>`.
    awaiting_session_result,
    /// SM enable/resume stanza sent; awaiting `<enabled>`/`<resumed>`/`<failed>`.
    sm_negotiating,
    /// Fully established — stanzas flow.
    active,
    /// Terminated (clean or failed).
    closed,
};

/// The contents of a `<stream:features>` block (the only place the server tells
/// us what to do next). The reader reassembles these child elements into one event.
pub const Features = struct {
    /// `<starttls/>` advertised (pre-TLS).
    starttls: bool = false,
    /// `<starttls><required/></starttls>`.
    starttls_required: bool = false,
    /// Advertised SASL mechanism names, in server priority order.
    mechanisms: []const []const u8 = &.{},
    /// `<bind/>` advertised (post-auth).
    bind: bool = false,
    /// `<session/>` advertised. The session IQ (RFC 6120 §8.7) is only REQUIRED
    /// when this is true AND `session_optional` is false. Most servers emit
    /// `<session><optional/></session>` alongside `<bind/>`, meaning "no session
    /// IQ needed" — in that case `session` is true but `session_optional` is also
    /// true, so the client must NOT send one.
    session: bool = false,
    /// True if the `<session/>` element contained an `<optional/>` child.
    session_optional: bool = false,
    /// `<sm/>` (XEP-0198) advertised.
    stream_mgmt: bool = false,
};

/// A protocol event the client receives from the server and feeds to the FSM.
pub const ServerEvent = union(enum) {
    /// Server's `<stream:stream>` header.
    stream_header: StreamHeader,
    /// A complete `<stream:features>` block.
    features: Features,
    /// `<proceed/>` — STARTTLS approved, start the TLS handshake.
    starttls_proceed,
    /// `<failure/>` (STARTTLS) — server rejected STARTTLS.
    starttls_failure,
    /// The Session finished the TLS handshake on the socket.
    tls_established,
    /// `<challenge>base64</challenge>` from SASL.
    sasl_challenge: []const u8,
    /// `<success>base64</success>` — SASL accepted.
    sasl_success: []const u8,
    /// `<failure>base64</failure>` — SASL rejected.
    sasl_failure: SaslFailure,
    /// A complete IQ stanza, matched by id, of the type we sent.
    iq_result: IqResult,
    /// SM enable/resume outcome (XEP-0198): `<enabled>` (id=sm id when
    /// resuming), `<resumed>`, or `<failed>`.
    sm_result: SmResult,
    /// `<stream:stream>` error condition.
    stream_error: StreamError,
    /// The server closed the stream (`</stream:stream>`).
    stream_closed,
};

/// The SM enable/resume outcome. `failed` carries the XEP-0198 condition.
pub const SmResult = union(enum) {
    /// `<enabled>` — SM activated. `id` is the SM session id when the server
    /// granted resumption (empty otherwise).
    enabled: []const u8,
    /// `<resumed>` — a prior session was resumed; `id` is its SM id.
    resumed: []const u8,
    /// `<failed>` — SM could not be enabled/resumed; `condition` is the raw
    /// XEP-0198 condition (e.g. "item-not-found").
    failed: []const u8,
};

/// The server's stream-header fields we care about.
pub const StreamHeader = struct {
    id: []const u8 = "",
    to: []const u8 = "",
    from: []const u8 = "",
    stream_ns: []const u8 = "",
    client_ns: []const u8 = "",
    version: []const u8 = "",
};

/// A SASL `<failure>` with its base64 payload and RFC 4959 condition.
pub const SaslFailure = struct {
    payload: []const u8,
    condition: []const u8 = "",
};

/// A matched IQ result (bind / session). SM is not an IQ — see `SmResult`.
pub const IqResult = struct {
    id: []const u8,
    /// For bind: the bound full JID (from `<bind><jid>`).
    bound_jid: ?Jid = null,
    is_error: bool = false,
};

/// Stream error conditions (RFC 6120 §4.7). `other` carries the raw condition.
pub const StreamError = struct {
    condition: Condition,
    raw: []const u8 = "",

    pub const Condition = enum {
        bad_format,
        bad_namespace_prefix,
        conflict,
        connection_timeout,
        host_gone,
        host_unknown,
        improper_addressing,
        internal_server_error,
        invalid_from,
        invalid_ns,
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
        other,

        pub fn fromString(s: []const u8) Condition {
            if (std.mem.eql(u8, s, "bad-format")) return .bad_format;
            if (std.mem.eql(u8, s, "bad-namespace-prefix")) return .bad_namespace_prefix;
            if (std.mem.eql(u8, s, "conflict")) return .conflict;
            if (std.mem.eql(u8, s, "connection-timeout")) return .connection_timeout;
            if (std.mem.eql(u8, s, "host-gone")) return .host_gone;
            if (std.mem.eql(u8, s, "host-unknown")) return .host_unknown;
            if (std.mem.eql(u8, s, "improper-addressing")) return .improper_addressing;
            if (std.mem.eql(u8, s, "internal-server-error")) return .internal_server_error;
            if (std.mem.eql(u8, s, "invalid-from")) return .invalid_from;
            if (std.mem.eql(u8, s, "invalid-namespace")) return .invalid_ns;
            if (std.mem.eql(u8, s, "not-authorized")) return .not_authorized;
            if (std.mem.eql(u8, s, "not-well-formed")) return .not_well_formed;
            if (std.mem.eql(u8, s, "policy-violation")) return .policy_violation;
            if (std.mem.eql(u8, s, "remote-connection-failed")) return .remote_connection_failed;
            if (std.mem.eql(u8, s, "reset")) return .reset;
            if (std.mem.eql(u8, s, "resource-constraint")) return .resource_constraint;
            if (std.mem.eql(u8, s, "restricted-xml")) return .restricted_xml;
            if (std.mem.eql(u8, s, "system-shutdown")) return .system_shutdown;
            if (std.mem.eql(u8, s, "undefined-condition")) return .undefined_condition;
            if (std.mem.eql(u8, s, "unsupported-encoding")) return .unsupported_encoding;
            if (std.mem.eql(u8, s, "unsupported-feature")) return .unsupported_feature;
            if (std.mem.eql(u8, s, "unsupported-stanza-type")) return .unsupported_stanza_type;
            if (std.mem.eql(u8, s, "unsupported-version")) return .unsupported_version;
            return .other;
        }
    };
};

/// What the Session must do in response to an FSM transition.
pub const ClientAction = union(enum) {
    /// Send the client `<stream:stream>` (initial, or the post-auth re-open).
    send_stream_open,
    /// Send `<starttls/>`.
    send_starttls,
    /// Begin (or continue) the TLS handshake on the socket.
    begin_tls,
    /// Send the SASL `<auth>` initial message for the named mechanism.
    /// The Session builds the base64 initial response from its credentials.
    send_sasl_auth: []const u8,
    /// Send the next SASL `<response>` (the Session computes the base64 from the
    /// most recent `<challenge>` via the SASL coordinator).
    send_sasl_response,
    /// Send the resource-bind IQ.
    send_bind,
    /// Send the session-establishment IQ.
    send_session,
    /// Send the SM `<enable resume='true'/>` stanza (fresh session, XEP-0198).
    send_sm_enable,
    /// Send the SM `<resume previd=... h=.../>` stanza (resume a prior session).
    send_sm_resume,
    /// The stream is ready; stanzas may flow.
    established,
    /// Send `</stream:stream>` and close.
    close,
    /// No I/O required (internal bookkeeping only).
    none,
};

/// Client-side stream state machine.
pub const ClientStream = struct {
    state: ClientState = .idle,
    /// The server's stream id (from the most recent stream header).
    stream_id: []const u8 = "",
    /// Server JID/domain we connected to (from stream header `from`).
    server_jid: []const u8 = "",
    /// The bound full JID (after the bind result).
    bound_jid: ?Jid = null,
    /// The chosen SASL mechanism name (from the advertised list).
    sasl_mechanism: []const u8 = "",
    /// Reason for failure (set when the stream closes via an error).
    failure_reason: []const u8 = "",
    /// True after the SM `<enable>`/`<resume>` was acknowledged.
    sm_enabled: bool = false,
    /// True if the active SM session was resumed (vs. a fresh enable).
    sm_resumed: bool = false,
    /// The server's SM session id (h) for the active session.
    sm_id: []const u8 = "",
    /// The SM session id to attempt to resume ("" = no resume, fresh enable).
    /// The Session sets this from the previous session's `sm_id` on reconnect.
    resume_id: []const u8 = "",
    /// The most recent `<stream:features>` block (retained for the bind/session/SM
    /// decisions that follow it).
    feats: Features = .{},

    /// Begin the connection: transition to awaiting the stream header and emit
    /// the stream-open action. The Session performs the TCP connect before
    /// calling this (the stream only starts once the socket is up).
    pub fn openStream(self: *ClientStream) ClientAction {
        if (self.state != .idle) return .none;
        self.state = .awaiting_stream_header;
        return .send_stream_open;
    }

    /// Feed a server event; returns the action to take.
    pub fn feed(self: *ClientStream, ev: ServerEvent) ClientAction {
        switch (self.state) {
            .idle => return .none,
            .awaiting_stream_header, .awaiting_stream_header_tls, .awaiting_stream_header_auth =>
                return self.feedEstablishing(ev),
            .awaiting_starttls_proceed => return self.feedAwaitingStarttls(ev),
            .tls_handshaking => return self.feedTlsHandshaking(ev),
            .sasl_negotiating => return self.feedSasl(ev),
            .awaiting_bind_result => return self.feedBind(ev),
            .awaiting_session_result => return self.feedSession(ev),
            .sm_negotiating => return self.feedSm(ev),
            .active => return self.feedActive(ev),
            .closed => return .none,
        }
    }

    fn feedEstablishing(self: *ClientStream, ev: ServerEvent) ClientAction {
        switch (ev) {
            .stream_header => |hdr| {
                self.stream_id = hdr.id;
                self.server_jid = hdr.from;
                // Header received; the <stream:features> block follows.
                return .none;
            },
            .features => |f| {
                self.feats = f;
                return self.actOnFeatures();
            },
            .stream_error => |err| {
                self.fail(err.raw);
                return .close;
            },
            .stream_closed => {
                self.fail("stream-closed-early");
                return .close;
            },
            else => return .none,
        }
    }

    /// Decide what to do based on the current state + the features block we just
    /// received. The same features block means different things pre-TLS
    /// (starttls), post-TLS (mechanisms), and post-auth (bind/session/sm).
    fn actOnFeatures(self: *ClientStream) ClientAction {
        switch (self.state) {
            .awaiting_stream_header => {
                // Pre-TLS: offer STARTTLS if advertised; otherwise (direct TLS or a
                // no-TLS test server) go straight to SASL.
                if (self.feats.starttls) {
                    self.state = .awaiting_starttls_proceed;
                    return .send_starttls;
                }
                if (self.feats.mechanisms.len > 0) {
                    self.state = .sasl_negotiating;
                    self.sasl_mechanism = self.feats.mechanisms[0];
                    return .{ .send_sasl_auth = self.sasl_mechanism };
                }
                self.fail("no-features");
                return .close;
            },
            .awaiting_stream_header_tls => {
                if (self.feats.mechanisms.len > 0) {
                    self.state = .sasl_negotiating;
                    self.sasl_mechanism = self.feats.mechanisms[0];
                    return .{ .send_sasl_auth = self.sasl_mechanism };
                }
                self.fail("no-mechanisms");
                return .close;
            },
            .awaiting_stream_header_auth => {
                // Resuming (XEP-0198): <resume/> goes out immediately after
                // the post-auth stream re-open, BEFORE bind — a bind first
                // evicts the detached session server-side.
                if (self.resume_id.len > 0 and self.feats.stream_mgmt) {
                    self.state = .sm_negotiating;
                    return self.smAction();
                }
                if (self.feats.bind) {
                    self.state = .awaiting_bind_result;
                    return .send_bind;
                }
                if (self.sessionRequired()) {
                    self.state = .awaiting_session_result;
                    return .send_session;
                }
                self.fail("no-bind");
                return .close;
            },
            else => return .none,
        }
    }

    fn feedAwaitingStarttls(self: *ClientStream, ev: ServerEvent) ClientAction {
        switch (ev) {
            .starttls_proceed => {
                self.state = .tls_handshaking;
                return .begin_tls;
            },
            .starttls_failure => {
                self.fail("starttls-rejected");
                return .close;
            },
            .stream_error => |err| {
                self.fail(err.raw);
                return .close;
            },
            else => return .none,
        }
    }

    fn feedTlsHandshaking(self: *ClientStream, ev: ServerEvent) ClientAction {
        switch (ev) {
            .tls_established => {
                // TLS is up. Per XEP-0383 / RFC 6120 the client restarts the
                // stream: it re-sends <stream:stream>, and the server responds
                // with a fresh header + <stream:features> (mechanisms). Same
                // stream-restart the client performs after SASL success.
                self.state = .awaiting_stream_header_tls;
                return .send_stream_open;
            },
            .stream_error => |err| {
                self.fail(err.raw);
                return .close;
            },
            .stream_closed => {
                self.fail("tls-failed");
                return .close;
            },
            else => return .none,
        }
    }

    fn feedSasl(self: *ClientStream, ev: ServerEvent) ClientAction {
        switch (ev) {
            .sasl_challenge => {
                // The Session feeds the challenge to the SASL coordinator and
                // emits the next <response>.
                return .send_sasl_response;
            },
            .sasl_success => {
                // Authenticated. Per RFC 6120 the client opens a fresh
                // <stream:stream> (stream reset).
                self.state = .awaiting_stream_header_auth;
                return .send_stream_open;
            },
            .sasl_failure => |f| {
                self.fail(f.condition);
                return .close;
            },
            .stream_error => |err| {
                self.fail(err.raw);
                return .close;
            },
            else => return .none,
        }
    }

    fn feedBind(self: *ClientStream, ev: ServerEvent) ClientAction {
        switch (ev) {
            .iq_result => |iq| {
                if (iq.is_error) {
                    self.fail("bind-error");
                    return .close;
                }
                self.bound_jid = iq.bound_jid;
                return self.afterBind();
            },
            .stream_error => |err| {
                self.fail(err.raw);
                return .close;
            },
            else => return .none,
        }
    }

    fn feedSession(self: *ClientStream, ev: ServerEvent) ClientAction {
        switch (ev) {
            .iq_result => |iq| {
                if (iq.is_error) {
                    self.fail("session-error");
                    return .close;
                }
                if (self.feats.stream_mgmt) {
                    self.state = .sm_negotiating;
                    return self.smAction();
                }
                self.state = .active;
                return .established;
            },
            .stream_error => |err| {
                self.fail(err.raw);
                return .close;
            },
            else => return .none,
        }
    }

    fn feedSm(self: *ClientStream, ev: ServerEvent) ClientAction {
        switch (ev) {
            .sm_result => |r| switch (r) {
                .enabled => |id| {
                    self.sm_enabled = true;
                    self.sm_resumed = false;
                    self.sm_id = id;
                    self.state = .active;
                    return .established;
                },
                .resumed => |id| {
                    self.sm_enabled = true;
                    self.sm_resumed = true;
                    self.sm_id = id;
                    self.state = .active;
                    return .established;
                },
                .failed => |cond| {
                    // SM not honoured; a client MAY proceed without it (XEP-0198).
                    self.sm_enabled = false;
                    self.sm_resumed = false;
                    _ = cond;
                    self.failure_reason = "sm-failed";
                    self.state = .active;
                    return .established;
                },
            },
            .stream_error => |err| {
                self.fail(err.raw);
                return .close;
            },
            else => return .none,
        }
    }

    fn feedActive(self: *ClientStream, ev: ServerEvent) ClientAction {
        // In the active state the FSM only cares about stream-level events;
        // stanzas are dispatched by the Session, not the FSM.
        switch (ev) {
            .stream_error => |err| {
                self.fail(err.raw);
                return .close;
            },
            .stream_closed => {
                self.state = .closed;
                return .none;
            },
            else => return .none,
        }
    }

    /// After a successful bind: optionally session, then SM, then active.
    fn afterBind(self: *ClientStream) ClientAction {
        if (self.sessionRequired()) {
            self.state = .awaiting_session_result;
            return .send_session;
        }
        if (self.feats.stream_mgmt) {
            self.state = .sm_negotiating;
            return self.smAction();
        }
        self.state = .active;
        return .established;
    }

    /// Whether the session-establishment IQ (RFC 6120 §8.7) is REQUIRED. It is
    /// required only when the server advertised `<session/>` WITHOUT
    /// `<optional/>`. When optional (the xmppd default), the stream is active
    /// immediately after bind.
    fn sessionRequired(self: *const ClientStream) bool {
        return self.feats.session and !self.feats.session_optional;
    }

    fn smAction(self: *ClientStream) ClientAction {
        if (self.resume_id.len > 0) return .send_sm_resume;
        return .send_sm_enable;
    }

    fn fail(self: *ClientStream, reason: []const u8) void {
        if (self.state != .closed) {
            self.failure_reason = reason;
            self.state = .closed;
        }
    }

    pub fn isActive(self: *const ClientStream) bool {
        return self.state == .active;
    }

    pub fn isClosed(self: *const ClientStream) bool {
        return self.state == .closed;
    }
};

// --- Tests ---

test "client stream: full STARTTLS + SCRAM + bind + SM happy path" {
    var s = ClientStream{};
    try std.testing.expectEqual(ClientState.idle, s.state);

    const a0 = s.openStream();
    try std.testing.expect(a0 == .send_stream_open);
    try std.testing.expectEqual(ClientState.awaiting_stream_header, s.state);

    // Server header, then features (pre-TLS: STARTTLS)
    _ = s.feed(.{ .stream_header = .{ .id = "s1", .from = "example.com" } });
    try std.testing.expectEqualStrings("s1", s.stream_id);

    const a1 = s.feed(.{ .features = .{ .starttls = true, .starttls_required = true } });
    try std.testing.expect(a1 == .send_starttls);
    try std.testing.expectEqual(ClientState.awaiting_starttls_proceed, s.state);

    // proceed -> begin TLS
    const a2 = s.feed(.starttls_proceed);
    try std.testing.expect(a2 == .begin_tls);
    try std.testing.expectEqual(ClientState.tls_handshaking, s.state);

    // TLS handshake completes (driven by the Session). Per RFC 6120 §4.6 the
    // client restarts the stream: it re-sends <stream:stream> itself.
    const a3 = s.feed(.tls_established);
    try std.testing.expect(a3 == .send_stream_open);
    try std.testing.expectEqual(ClientState.awaiting_stream_header_tls, s.state);

    // Post-TLS header + features (mechanisms)
    _ = s.feed(.{ .stream_header = .{ .id = "s2", .from = "example.com" } });
    const mechs = [_][]const u8{ "SCRAM-SHA-256", "PLAIN" };
    const a4 = s.feed(.{ .features = .{ .mechanisms = &mechs } });
    try std.testing.expectEqualStrings("SCRAM-SHA-256", a4.send_sasl_auth);
    try std.testing.expectEqual(ClientState.sasl_negotiating, s.state);
    try std.testing.expectEqualStrings("SCRAM-SHA-256", s.sasl_mechanism);

    // SCRAM: server challenge -> client response
    const a5 = s.feed(.{ .sasl_challenge = "YIIC4wG..." });
    try std.testing.expect(a5 == .send_sasl_response);

    // Server success -> client re-opens the stream
    const a6 = s.feed(.{ .sasl_success = "" });
    try std.testing.expect(a6 == .send_stream_open);
    try std.testing.expectEqual(ClientState.awaiting_stream_header_auth, s.state);

    // Post-auth header + features (bind + sm)
    _ = s.feed(.{ .stream_header = .{ .id = "s3", .from = "example.com" } });
    const a7 = s.feed(.{ .features = .{ .bind = true, .stream_mgmt = true } });
    try std.testing.expect(a7 == .send_bind);
    try std.testing.expectEqual(ClientState.awaiting_bind_result, s.state);

    // Bind result -> SM enable
    const bound = Jid.parse("alice@example.com/phone") catch unreachable;
    const a8 = s.feed(.{ .iq_result = .{ .id = "bind1", .bound_jid = bound } });
    try std.testing.expect(a8 == .send_sm_enable);
    try std.testing.expectEqual(ClientState.sm_negotiating, s.state);

    // SM enable result -> established
    const a9 = s.feed(.{ .sm_result = .{ .enabled = "42" } });
    try std.testing.expect(a9 == .established);
    try std.testing.expectEqual(ClientState.active, s.state);
    try std.testing.expect(s.sm_enabled);
    try std.testing.expect(!s.sm_resumed);
    try std.testing.expectEqualStrings("42", s.sm_id);
}

test "client stream: bind only (no SM) goes straight to active" {
    var s = ClientStream{};
    _ = s.openStream();
    _ = s.feed(.{ .stream_header = .{ .id = "s1", .from = "example.com" } });
    const mechs = [_][]const u8{ "PLAIN" };
    // Pre-TLS, server advertises mechanisms directly (no STARTTLS)
    _ = s.feed(.{ .features = .{ .mechanisms = &mechs } });
    _ = s.feed(.{ .sasl_success = "" });
    _ = s.feed(.{ .stream_header = .{ .id = "s2", .from = "example.com" } });
    const a = s.feed(.{ .features = .{ .bind = true } });
    try std.testing.expect(a == .send_bind);
    const bound = Jid.parse("alice@example.com/phone") catch unreachable;
    const b = s.feed(.{ .iq_result = .{ .id = "bind1", .bound_jid = bound } });
    try std.testing.expect(b == .established);
    try std.testing.expectEqual(ClientState.active, s.state);
    try std.testing.expect(!s.sm_enabled);
}

test "client stream: session optional (xmppd default) skips the session IQ" {
    var s = ClientStream{};
    _ = s.openStream();
    _ = s.feed(.{ .stream_header = .{ .id = "s1" } });
    const mechs = [_][]const u8{ "PLAIN" };
    _ = s.feed(.{ .features = .{ .mechanisms = &mechs } });
    _ = s.feed(.{ .sasl_success = "" });
    _ = s.feed(.{ .stream_header = .{ .id = "s2" } });
    // xmppd always emits <session><optional/></session> alongside <bind/>
    const a = s.feed(.{ .features = .{ .bind = true, .session = true, .session_optional = true } });
    try std.testing.expect(a == .send_bind);
    const bound = Jid.parse("alice@example.com/phone") catch unreachable;
    // No session IQ: straight to SM enable (SM not advertised here) -> active.
    const b = s.feed(.{ .iq_result = .{ .id = "bind1", .bound_jid = bound } });
    try std.testing.expect(b == .established);
    try std.testing.expectEqual(ClientState.active, s.state);
}

test "client stream: SM resume when resume_id is set" {
    var s = ClientStream{};
    s.resume_id = "prev-session-id";
    _ = s.openStream();
    _ = s.feed(.{ .stream_header = .{ .id = "s1" } });
    const mechs = [_][]const u8{ "SCRAM-SHA-256" };
    _ = s.feed(.{ .features = .{ .mechanisms = &mechs } });
    _ = s.feed(.{ .sasl_success = "" });
    _ = s.feed(.{ .stream_header = .{ .id = "s2" } });
    // Resuming: <resume/> is sent immediately after the post-auth stream
    // re-open, BEFORE bind (a bind first would evict the detached session).
    const a = s.feed(.{ .features = .{ .bind = true, .stream_mgmt = true } });
    try std.testing.expect(a == .send_sm_resume);
    try std.testing.expectEqual(ClientState.sm_negotiating, s.state);
    const b = s.feed(.{ .sm_result = .{ .resumed = "prev-session-id" } });
    try std.testing.expect(b == .established);
    try std.testing.expect(s.sm_resumed);
    try std.testing.expectEqualStrings("prev-session-id", s.sm_id);
}

test "client stream: session IQ between bind and SM" {
    var s = ClientStream{};
    _ = s.openStream();
    _ = s.feed(.{ .stream_header = .{ .id = "s1" } });
    const mechs = [_][]const u8{ "PLAIN" };
    _ = s.feed(.{ .features = .{ .mechanisms = &mechs } });
    _ = s.feed(.{ .sasl_success = "" });
    _ = s.feed(.{ .stream_header = .{ .id = "s2" } });
    const a = s.feed(.{ .features = .{ .bind = true, .session = true, .stream_mgmt = true } });
    try std.testing.expect(a == .send_bind);
    const bound = Jid.parse("alice@example.com/phone") catch unreachable;
    const b = s.feed(.{ .iq_result = .{ .id = "bind1", .bound_jid = bound } });
    try std.testing.expect(b == .send_session);
    const c = s.feed(.{ .iq_result = .{ .id = "sess1" } });
    try std.testing.expect(c == .send_sm_enable);
    const d = s.feed(.{ .sm_result = .{ .enabled = "9" } });
    try std.testing.expect(d == .established);
    try std.testing.expectEqual(ClientState.active, s.state);
}

test "client stream: SASL failure closes" {
    var s = ClientStream{};
    _ = s.openStream();
    _ = s.feed(.{ .stream_header = .{ .id = "s1" } });
    const mechs = [_][]const u8{ "PLAIN" };
    _ = s.feed(.{ .features = .{ .mechanisms = &mechs } });
    const a = s.feed(.{ .sasl_failure = .{ .payload = "", .condition = "not-authorized" } });
    try std.testing.expect(a == .close);
    try std.testing.expectEqual(ClientState.closed, s.state);
    try std.testing.expectEqualStrings("not-authorized", s.failure_reason);
}

test "client stream: stream error during handshake closes" {
    var s = ClientStream{};
    _ = s.openStream();
    _ = s.feed(.{ .stream_header = .{ .id = "s1" } });
    const a = s.feed(.{ .stream_error = .{ .condition = .conflict, .raw = "conflict" } });
    try std.testing.expect(a == .close);
    try std.testing.expectEqual(ClientState.closed, s.state);
}

test "client stream: bind IQ error closes" {
    var s = ClientStream{};
    _ = s.openStream();
    _ = s.feed(.{ .stream_header = .{ .id = "s1" } });
    const mechs = [_][]const u8{ "PLAIN" };
    _ = s.feed(.{ .features = .{ .mechanisms = &mechs } });
    _ = s.feed(.{ .sasl_success = "" });
    _ = s.feed(.{ .stream_header = .{ .id = "s2" } });
    _ = s.feed(.{ .features = .{ .bind = true } });
    const a = s.feed(.{ .iq_result = .{ .id = "bind1", .is_error = true } });
    try std.testing.expect(a == .close);
    try std.testing.expectEqual(ClientState.closed, s.state);
}

test "client stream: clean stream close in active state" {
    var s = ClientStream{};
    _ = s.openStream();
    _ = s.feed(.{ .stream_header = .{ .id = "s1" } });
    const mechs = [_][]const u8{ "PLAIN" };
    _ = s.feed(.{ .features = .{ .mechanisms = &mechs } });
    _ = s.feed(.{ .sasl_success = "" });
    _ = s.feed(.{ .stream_header = .{ .id = "s2" } });
    _ = s.feed(.{ .features = .{ .bind = true } });
    const bound = Jid.parse("alice@example.com/phone") catch unreachable;
    _ = s.feed(.{ .iq_result = .{ .id = "bind1", .bound_jid = bound } });
    try std.testing.expect(s.isActive());
    const a = s.feed(.stream_closed);
    try std.testing.expect(a == .none);
    try std.testing.expect(s.isClosed());
}

test "StreamError.fromString" {
    try std.testing.expectEqual(StreamError.Condition.conflict, StreamError.Condition.fromString("conflict"));
    try std.testing.expectEqual(StreamError.Condition.not_authorized, StreamError.Condition.fromString("not-authorized"));
    try std.testing.expectEqual(StreamError.Condition.other, StreamError.Condition.fromString("weird-thing"));
}
