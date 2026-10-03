//! # xmppc Parser — XML reader events -> stream.ServerEvent
//!!
//! Pure protocol state machine: it owns no sockets and no TLS. The Session
//! feeds xml.Reader events in; complete protocol items surface one at a time
//! via `pending` (stream header / features block / SASL challenge/success
//! failure / IQ result / SM enabled-resumed-failed / stream error / close).
//!
//! No dependency on Engine or Session: the parser is testable from raw text.

const std = @import("std");
const xml = @import("xml");
const xmpp = @import("xmpp");
const stream = @import("stream.zig");

const Jid = xmpp.Jid;
const Reader = xml.Reader;

const SASL_RAW_MAX = 1024; // comfortably covers any legal SCRAM/PLAIN message

/// Decode base64 into a caller-owned fixed buffer (no heap on the hot path).
fn b64decInto(out: []u8, input: []const u8) ![]const u8 {
    const dec = std.base64.standard.Decoder;
    const len = try dec.calcSizeForSlice(input);
    if (len > out.len) return error.SaslMessageTooLong;
    try dec.decode(out[0..len], input);
    return out[0..len];
}

pub const Attribute = xml.Attribute;

pub const StanzaChild = struct {
    /// Qualified name as seen on the wire (prefix included when present).
    name: []const u8,
    local_name: []const u8,
    ns: []const u8,
    attrs: []const xml.Attribute,
    /// Concatenated direct text of the child ("" when none). Valid until
    /// the parser processes the NEXT stanza after dispatch.
    text: []const u8,
};

/// A captured application stanza (message/presence/iq at stream-top level).
///
/// Lifetime: all slices borrow the xml Reader arena (attributes, names) or
/// the parser's rolling text buffer (child text). They are valid from the
/// stanza's close until the next stanza close is processed — in practice:
/// for the duration of the consumer's Event callback. Copy what you keep.
///
/// Capture is one level deep: elements nested below a direct child are not
/// recorded (the consumers driving this API carry flat payloads).
pub const Stanza = struct {
    pub const Kind = enum { message, presence, iq };
    kind: Kind,
    type: []const u8 = "",
    id: []const u8 = "",
    from: []const u8 = "",
    to: []const u8 = "",
    children: []const StanzaChild = &.{},
};

pub const Parser = struct {
    allocator: std.mem.Allocator,

    // Features block
    in_features: bool = false,
    feats: stream.Features = .{},
    mech_names: std.ArrayListUnmanaged([]const u8) = .{},
    in_mechanism: bool = false,

    // SASL stanza payloads (base64 text)
    sasl_kind: enum { none, auth, challenge, success, failure } = .none,
    sasl_text: std.ArrayListUnmanaged(u8) = .{},
    sasl_cond: []const u8 = "",
    sasl_challenge_buf: [SASL_RAW_MAX]u8 = undefined,
    sasl_challenge_len: usize = 0,
    sasl_success_buf: [SASL_RAW_MAX]u8 = undefined,
    sasl_success_len: usize = 0,

    // IQ stanza (bind/session result)
    in_iq: bool = false,
    iq_type: []const u8 = "",
    iq_id: []const u8 = "",
    iq_is_bind: bool = false,
    iq_is_session: bool = false,
    iq_is_error: bool = false,
    in_jid: bool = false,
    jid_text: std.ArrayListUnmanaged(u8) = .{},

    // SM bare stanzas
    sm_kind: enum { none, enabled, resumed, failed } = .none,
    sm_id: []const u8 = "",
    sm_failed_cond: []const u8 = "",

    // Stream error
    in_stream_error: bool = false,
    stream_err_cond: []const u8 = "",

    // Application stanza capture (message/presence/iq at top level).
    // build_depth counts open elements below the stream tag.
    build_depth: u32 = 0,
    st_kind: Stanza.Kind = .message,
    in_stanza: bool = false,
    st_type: []const u8 = "",
    st_id: []const u8 = "",
    st_from: []const u8 = "",
    st_to: []const u8 = "",
    st_children: std.ArrayListUnmanaged(StanzaChild) = .{},
    st_child_open: bool = false,
    st_child_text_start: usize = 0,
    st_text: std.ArrayListUnmanaged(u8) = .{},

    /// The next ServerEvent to feed the FSM (one at a time).
    pending: ?stream.ServerEvent = null,
    /// A completed application stanza, drained by the Session's parse loop.
    pending_stanza: ?Stanza = null,

    pub fn init(allocator: std.mem.Allocator) Parser {
        return .{ .allocator = allocator };
    }

    pub fn saslChallengeRaw(self: *const Parser) ?[]const u8 {
        if (self.sasl_challenge_len == 0) return null;
        return self.sasl_challenge_buf[0..self.sasl_challenge_len];
    }
    pub fn saslSuccessRaw(self: *const Parser) ?[]const u8 {
        if (self.sasl_success_len == 0) return null;
        return self.sasl_success_buf[0..self.sasl_success_len];
    }

    pub fn deinit(self: *Parser, allocator: std.mem.Allocator) void {
        for (self.mech_names.items) |name| allocator.free(name);
        self.mech_names.deinit(self.allocator);
        self.sasl_text.deinit(self.allocator);
        self.jid_text.deinit(self.allocator);
        self.st_children.deinit(self.allocator);
        self.st_text.deinit(self.allocator);
    }

    pub fn reset(self: *Parser) void {
        self.in_features = false;
        self.feats = .{};
        // Each name is individually duped; freeing here mirrors deinit().
        for (self.mech_names.items) |name| self.allocator.free(name);
        self.mech_names.clearRetainingCapacity();
        self.in_mechanism = false;
        self.sasl_kind = .none;
        self.sasl_text.clearRetainingCapacity();
        self.sasl_cond = "";
        self.sasl_challenge_len = 0;
        self.sasl_success_len = 0;
        self.pending = null;
        self.in_iq = false;
        self.iq_type = "";
        self.iq_id = "";
        self.iq_is_bind = false;
        self.iq_is_session = false;
        self.iq_is_error = false;
        self.in_jid = false;
        self.jid_text.clearRetainingCapacity();
        self.sm_kind = .none;
        self.sm_id = "";
        self.sm_failed_cond = "";
        self.in_stream_error = false;
        self.stream_err_cond = "";
        self.build_depth = 0;
        self.in_stanza = false;
        self.st_child_open = false;
        self.st_children.clearRetainingCapacity();
        self.st_text.clearRetainingCapacity();
        self.pending_stanza = null;
    }

    pub fn onReaderEvent(self: *Parser, ev: xml.Event) bool {
        switch (ev) {
            .xml_declaration => return true,
            .stream_open => |el| {
                var hdr = stream.StreamHeader{};
                for (el.attributes) |a| {
                    if (std.mem.eql(u8, a.local_name, "id")) {
                        hdr.id = a.value;
                    } else if (std.mem.eql(u8, a.local_name, "to")) {
                        hdr.to = a.value;
                    } else if (std.mem.eql(u8, a.local_name, "from")) {
                        hdr.from = a.value;
                    } else if (std.mem.eql(u8, a.local_name, "version")) {
                        hdr.version = a.value;
                    }
                }
                self.reset();
                self.pending = .{ .stream_header = hdr };
                return true;
            },
            .stream_close => {
                self.pending = .stream_closed;
                return true;
            },
            .element_start => |el| {
                // build_depth counts open elements below the stream tag:
                // 0 = opening a top-level item, 1 = opening a stanza child.
                defer {
                    if (!el.self_closing) self.build_depth += 1;
                }
                // The reader emits NO element_end for self-closing elements
                // (net depth stays at zero) — settle them inline, or a
                // self-closing <success/>/<failure/> would leave the SASL
                // collection state dangling until some later closed element
                // settled it under the wrong name (or never).
                const ok = self.onElementStart(el);
                if (!ok) return false;
                if (el.self_closing and self.sasl_kind != .none) {
                    return self.onElementEnd(el.local_name);
                }
                return true;
            },
            .element_end => |name| {
                defer {
                    if (self.build_depth > 0) self.build_depth -= 1;
                }
                return self.onElementEnd(name);
            },
            .text => |t| return self.onText(t),
        }
    }

    fn onElementStart(self: *Parser, el: xml.Element) bool {
        const ns = el.namespace_uri;
        const name = el.local_name;
        const closed = el.self_closing;

        // --- Features block (children of <stream:features>) ---
        // Checked BEFORE the protocol-stanza blocks below, because
        // <starttls/>, <mechanisms/>, <mechanism/> and <sm/> share their
        // namespaces with the stanzas they advertise; while inside the
        // features block they are feature declarations, not stanzas.
        if (self.in_features) {
            if (std.mem.eql(u8, name, "starttls") and std.mem.eql(u8, ns, xml.ns.tls)) {
                self.feats.starttls = true;
                return true;
            }
            if (std.mem.eql(u8, name, "required") and std.mem.eql(u8, ns, xml.ns.tls)) {
                self.feats.starttls_required = true;
                return true;
            }
            if (std.mem.eql(u8, name, "mechanisms") and std.mem.eql(u8, ns, xml.ns.sasl)) {
                // Container; <mechanism> children are collected below.
                return true;
            }
            if (std.mem.eql(u8, name, "mechanism") and std.mem.eql(u8, ns, xml.ns.sasl)) {
                self.in_mechanism = true;
                self.sasl_text.clearRetainingCapacity();
                return true;
            }
            if (std.mem.eql(u8, name, "bind") and std.mem.eql(u8, ns, xml.ns.bind)) {
                self.feats.bind = true;
                return true;
            }
            if (std.mem.eql(u8, name, "session") and std.mem.eql(u8, ns, xml.ns.session)) {
                self.feats.session = true;
                return true;
            }
            if (std.mem.eql(u8, name, "optional")) {
                self.feats.session_optional = true;
                return true;
            }
            if (std.mem.eql(u8, name, "sm") and std.mem.eql(u8, ns, xml.ns.sm)) {
                self.feats.stream_mgmt = true;
                return true;
            }
            // Unknown feature child (e.g. <c/> for MUC user): ignored.
            return true;
        }

        // --- Features opener ---
        if (std.mem.eql(u8, name, "features") and std.mem.eql(u8, ns, xml.ns.streams)) {
            self.in_features = true;
            self.mech_names.clearRetainingCapacity();
            self.feats = .{};
            return true;
        }

        // --- Legacy bind/session result flags, any depth inside an IQ
        // (e.g. <jid> nests inside <bind>). Runs in parallel with the
        // generic capture; the FSM needs those flags during establishment.
        if (self.in_iq) {
            if (std.mem.eql(u8, name, "bind") and std.mem.eql(u8, ns, xml.ns.bind)) {
                self.iq_is_bind = true;
            } else if (std.mem.eql(u8, name, "session") and std.mem.eql(u8, ns, xml.ns.session)) {
                self.iq_is_session = true;
            } else if (std.mem.eql(u8, name, "error") and std.mem.eql(u8, ns, xml.ns.stanzas)) {
                self.iq_is_error = true;
            } else if (std.mem.eql(u8, name, "jid")) {
                self.in_jid = true;
                self.jid_text.clearRetainingCapacity();
            }
        }

        // --- Application stanza child (depth 2: inside an open stanza) ---
        if (self.in_stanza and self.build_depth == 1) {
            self.beginStanzaChild(el);
            if (closed) self.endStanzaChild();
            return true;
        }
        // Anything deeper than a direct child (or anything in a protocol IQ)
        // is not captured.
        if (self.in_stanza or self.in_iq) return true;

        // --- Application stanza open (message/presence/iq, top level) ---
        if (self.build_depth == 0 and std.mem.eql(u8, ns, xml.ns.client) and
            (std.mem.eql(u8, name, "message") or std.mem.eql(u8, name, "presence") or std.mem.eql(u8, name, "iq")))
        {
            self.beginStanza(name, el);
            if (closed) {
                self.finishStanza();
                return true;
            }
            // IQ falls through so the legacy iq opener still arms in_iq.
            if (!std.mem.eql(u8, name, "iq")) return true;
        }

        // --- Stream Management (XEP-0198): bare stanzas, no IQ. ---
        // The reader emits only element_start (self_closing=true) for the
        // self-closing forms, so the closed cases are settled here; the
        // non-self-closing forms are settled in onElementEnd.
        if (std.mem.eql(u8, ns, xml.ns.sm)) {
            if (std.mem.eql(u8, name, "enabled")) {
                for (el.attributes) |a| {
                    if (std.mem.eql(u8, a.local_name, "id")) self.sm_id = a.value;
                }
                self.sm_kind = .enabled;
                if (closed) {
                    self.pending = .{ .sm_result = .{ .enabled = self.sm_id } };
                    self.sm_id = "";
                    self.sm_kind = .none;
                }
                return true;
            }
            if (std.mem.eql(u8, name, "resumed")) {
                for (el.attributes) |a| {
                    if (std.mem.eql(u8, a.local_name, "previd")) self.sm_id = a.value;
                }
                self.sm_kind = .resumed;
                if (closed) {
                    self.pending = .{ .sm_result = .{ .resumed = self.sm_id } };
                    self.sm_id = "";
                    self.sm_kind = .none;
                }
                return true;
            }
            if (std.mem.eql(u8, name, "failed")) {
                self.sm_failed_cond = "";
                self.sm_kind = .failed;
                if (closed) {
                    self.pending = .{ .sm_result = .{ .failed = self.sm_failed_cond } };
                    self.sm_failed_cond = "";
                    self.sm_kind = .none;
                }
                return true;
            }
            // A self-closing condition child of <failed> (e.g. <item-not-found/>).
            if (self.sm_kind == .failed and closed) {
                self.sm_failed_cond = name;
                return true;
            }
            return true;
        }

        // --- SASL stanza (accumulate base64 payload) ---
        if (self.sasl_kind != .none) {
            if (self.sasl_kind == .failure and std.mem.eql(u8, ns, xml.ns.sasl)) {
                self.sasl_cond = name;
            }
            return true;
        }

        // --- IQ stanza opener ---
        if (std.mem.eql(u8, name, "iq") and std.mem.eql(u8, ns, xml.ns.client)) {
            self.in_iq = true;
            self.iq_is_bind = false;
            self.iq_is_session = false;
            self.iq_is_error = false;
            self.in_jid = false;
            for (el.attributes) |a| {
                if (std.mem.eql(u8, a.local_name, "type")) self.iq_type = a.value;
                if (std.mem.eql(u8, a.local_name, "id")) self.iq_id = a.value;
            }
            return true;
        }

        // --- Stream error ---
        if (std.mem.eql(u8, name, "error") and std.mem.eql(u8, ns, xml.ns.streams)) {
            self.in_stream_error = true;
            self.stream_err_cond = "";
            return true;
        }
        if (self.in_stream_error) {
            self.stream_err_cond = name;
            self.pending = .{ .stream_error = .{ .condition = stream.StreamError.Condition.fromString(name), .raw = name } };
            self.in_stream_error = false;
            return true;
        }

        // --- SASL stanza openers ---
        if (std.mem.eql(u8, ns, xml.ns.sasl)) {
            self.sasl_text.clearRetainingCapacity();
            self.sasl_cond = "";
            if (std.mem.eql(u8, name, "auth")) {
                self.sasl_kind = .auth;
            } else if (std.mem.eql(u8, name, "challenge")) {
                self.sasl_kind = .challenge;
            } else if (std.mem.eql(u8, name, "success")) {
                self.sasl_kind = .success;
            } else if (std.mem.eql(u8, name, "failure")) {
                self.sasl_kind = .failure;
            }
            return true;
        }

        // --- STARTTLS ---
        if (std.mem.eql(u8, ns, xml.ns.tls)) {
            if (std.mem.eql(u8, name, "proceed")) {
                self.pending = .starttls_proceed;
            } else if (std.mem.eql(u8, name, "failure")) {
                self.pending = .starttls_failure;
            }
            return true;
        }

        return true;
    }

    /// The close token's `name` may carry a prefix (`stream:features`); reduce
    /// to the local part for comparison.
    fn localOf(name: []const u8) []const u8 {
        if (std.mem.lastIndexOfScalar(u8, name, ':')) |i| return name[i + 1 ..];
        return name;
    }

    fn onElementEnd(self: *Parser, name: []const u8) bool {
        const local = localOf(name);
        // Application stanza child close.
        if (self.in_stanza and self.build_depth == 2) {
            self.endStanzaChild();
            return true;
        }
        // Application stanza close. A protocol IQ that produced an FSM event
        // (bind/session result) is consumed by that channel and NOT also
        // dispatched as a stanza.
        if (self.in_stanza and self.build_depth == 1) {
            if (self.in_iq) {
                if (std.mem.eql(u8, self.iq_type, "result")) {
                    var res = stream.IqResult{ .id = self.iq_id };
                    res.is_error = self.iq_is_error;
                    if (self.iq_is_bind and !self.iq_is_error) {
                        const jt = std.mem.trim(u8, self.jid_text.items, " \t\r\n");
                        res.bound_jid = Jid.parse(jt) catch null;
                    }
                    self.pending = .{ .iq_result = res };
                }
            }
            self.finishStanza();
            return true;
        }
        // SASL stanza closes
        switch (self.sasl_kind) {
            .none => {},
            .auth => self.sasl_kind = .none,
            .challenge => {
                const b64 = std.mem.trim(u8, self.sasl_text.items, " \t\r\n");
                const raw = b64decInto(&self.sasl_challenge_buf, b64) catch return false;
                self.sasl_challenge_len = raw.len;
                self.pending = .{ .sasl_challenge = raw };
                self.sasl_kind = .none;
            },
            .success => {
                // base64 server-final; the Session verifies via SaslClient.
                const b64 = std.mem.trim(u8, self.sasl_text.items, " \t\r\n");
                const raw = b64decInto(&self.sasl_success_buf, b64) catch return false;
                self.sasl_success_len = raw.len;
                self.pending = .{ .sasl_success = raw };
                self.sasl_kind = .none;
            },
            .failure => {
                const cond = self.sasl_cond;
                self.sasl_cond = "";
                self.pending = .{ .sasl_failure = .{ .payload = "", .condition = cond } };
                self.sasl_kind = .none;
            },
        }

        // Mechanism name close (features block)
        if (self.in_mechanism and std.mem.eql(u8, local, "mechanism")) {
            const mtext = std.mem.trim(u8, self.sasl_text.items, " \t\r\n");
            const dup = self.allocator.dupe(u8, mtext) catch return false;
            self.mech_names.append(self.allocator, dup) catch return false;
            self.in_mechanism = false;
            return true;
        }

        // SM stanza closes
        switch (self.sm_kind) {
            .none => {},
            .enabled => {
                if (std.mem.eql(u8, local, "enabled")) {
                    self.pending = .{ .sm_result = .{ .enabled = self.sm_id } };
                    self.sm_id = "";
                    self.sm_kind = .none;
                }
            },
            .resumed => {
                if (std.mem.eql(u8, local, "resumed")) {
                    self.pending = .{ .sm_result = .{ .resumed = self.sm_id } };
                    self.sm_id = "";
                    self.sm_kind = .none;
                }
            },
            .failed => {
                if (std.mem.eql(u8, local, "failed")) {
                    self.pending = .{ .sm_result = .{ .failed = self.sm_failed_cond } };
                    self.sm_failed_cond = "";
                    self.sm_kind = .none;
                }
            },
        }

        // Features block close
        if (self.in_features and std.mem.eql(u8, local, "features")) {
            self.emitFeatures();
            return true;
        }
        return true;
    }

    fn onText(self: *Parser, t: []const u8) bool {
        if (self.in_jid) {
            self.jid_text.appendSlice(self.allocator, t) catch return false;
            // fall through: the stanza child collects it too
        }
        if (self.in_stanza and self.st_child_open) {
            self.st_text.appendSlice(self.allocator, t) catch return false;
            return true;
        }
        if (self.in_jid) return true;
        if (self.in_mechanism) {
            self.sasl_text.appendSlice(self.allocator, t) catch return false;
            return true;
        }
        if (self.sasl_kind != .none) {
            self.sasl_text.appendSlice(self.allocator, t) catch return false;
            return true;
        }
        return true;
    }

    // ------------------------------------------------------------------
    // Application stanza capture
    // ------------------------------------------------------------------

    fn beginStanza(self: *Parser, name: []const u8, el: xml.Element) void {
        self.in_stanza = true;
        self.st_kind = if (std.mem.eql(u8, name, "message"))
            .message
        else if (std.mem.eql(u8, name, "presence"))
            .presence
        else
            .iq;
        self.st_type = "";
        self.st_id = "";
        self.st_from = "";
        self.st_to = "";
        for (el.attributes) |a| {
            if (std.mem.eql(u8, a.local_name, "type")) {
                self.st_type = a.value;
            } else if (std.mem.eql(u8, a.local_name, "id")) {
                self.st_id = a.value;
            } else if (std.mem.eql(u8, a.local_name, "from")) {
                self.st_from = a.value;
            } else if (std.mem.eql(u8, a.local_name, "to")) {
                self.st_to = a.value;
            }
        }
        self.st_children.clearRetainingCapacity();
        self.st_text.clearRetainingCapacity();
        self.st_child_open = false;
    }

    fn beginStanzaChild(self: *Parser, el: xml.Element) void {
        // On allocation failure the child is dropped, not the stanza: a
        // partial capture is better than a parse failure.
        self.st_children.append(self.allocator, .{
            .name = el.name,
            .local_name = el.local_name,
            .ns = el.namespace_uri,
            .attrs = el.attributes,
            .text = "",
        }) catch return;
        self.st_child_text_start = self.st_text.items.len;
        self.st_child_open = !el.self_closing;
    }

    fn endStanzaChild(self: *Parser) void {
        if (self.st_children.items.len == 0) return;
        const child = &self.st_children.items[self.st_children.items.len - 1];
        child.text = self.st_text.items[self.st_child_text_start..];
        self.st_child_open = false;
    }

    /// Close the stanza collector. Protocol IQs that produced an FSM event
    /// (bind/session results) are NOT also surfaced as stanzas.
    fn finishStanza(self: *Parser) void {
        const consumed_by_fsm = self.st_kind == .iq and self.pending != null;
        if (!consumed_by_fsm) {
            if (self.st_child_open) self.endStanzaChild();
            self.pending_stanza = .{
                .kind = self.st_kind,
                .type = self.st_type,
                .id = self.st_id,
                .from = self.st_from,
                .to = self.st_to,
                .children = self.st_children.items,
            };
        }
        self.in_stanza = false;
        self.st_child_open = false;
        // Legacy bind/session tracking state
        self.in_iq = false;
        self.iq_is_bind = false;
        self.iq_is_session = false;
        self.iq_is_error = false;
        self.in_jid = false;
        self.jid_text.clearRetainingCapacity();
    }

    fn emitFeatures(self: *Parser) void {
        if (!self.in_features) return;
        self.in_features = false;
        self.in_mechanism = false;
        var f = self.feats;
        f.mechanisms = self.mech_names.items;
        self.feats = .{};
        self.pending = .{ .features = f };
    }
};

// ============================================================================
// Tests (unit; end-to-end lives in test/xmppc/smoke.zig + xmppd rig)
// ============================================================================
//
// These drive the real xml.Reader through the same event sequence the
// Session's parse loop produces (stream_open, element_start, text,
// element_end) rather than hand-constructed Elements.

test "parser: pre-TLS features → starttls" {
    const allocator = std.testing.allocator;
    const input =
        "<?xml version='1.0'?>" ++
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s1' from='localhost' version='1.0'>" ++
        "<stream:features>" ++
        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>" ++
        "</stream:features>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var got_header = false;
    var got_feats: ?stream.Features = null;
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch unreachable;
        if (ev == null) break;
        if (!parser.onReaderEvent(ev.?)) unreachable;
        if (parser.pending) |sev| {
            parser.pending = null;
            switch (sev) {
                .stream_header => got_header = true,
                .features => |f| got_feats = f,
                else => {},
            }
        }
    }
    try std.testing.expect(got_header);
    try std.testing.expect(got_feats != null);
    try std.testing.expect(got_feats.?.starttls);
    try std.testing.expect(got_feats.?.starttls_required);
    try std.testing.expect(!got_feats.?.bind);
}

test "parser: post-auth features (bind+session-optional+sm)" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s2' from='localhost'>" ++
        "<stream:features>" ++
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>" ++
        "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'><optional/></session>" ++
        "<sm xmlns='urn:xmpp:sm:3'/>" ++
        "</stream:features>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var got_feats: ?stream.Features = null;
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch unreachable;
        if (ev == null) break;
        if (!parser.onReaderEvent(ev.?)) unreachable;
        if (parser.pending) |sev| {
            parser.pending = null;
            if (sev == .features) got_feats = sev.features;
        }
    }
    try std.testing.expect(got_feats != null);
    try std.testing.expect(got_feats.?.bind);
    try std.testing.expect(got_feats.?.session);
    try std.testing.expect(got_feats.?.session_optional);
    try std.testing.expect(got_feats.?.stream_mgmt);
    try std.testing.expect(!got_feats.?.starttls);
}

test "parser: mechanisms list accumulates" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s3' from='localhost'>" ++
        "<stream:features>" ++
        "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" ++
        "<mechanism>SCRAM-SHA-256</mechanism>" ++
        "<mechanism>PLAIN</mechanism>" ++
        "</mechanisms>" ++
        "</stream:features>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var got_feats: ?stream.Features = null;
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch unreachable;
        if (ev == null) break;
        if (!parser.onReaderEvent(ev.?)) unreachable;
        if (parser.pending) |sev| {
            parser.pending = null;
            if (sev == .features) got_feats = sev.features;
        }
    }
    try std.testing.expect(got_feats != null);
    const m = got_feats.?.mechanisms;
    try std.testing.expectEqual(@as(usize, 2), m.len);
    try std.testing.expectEqualStrings("SCRAM-SHA-256", m[0]);
    try std.testing.expectEqualStrings("PLAIN", m[1]);
}

test "parser: bind result IQ → bound_jid" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s4' from='localhost'>" ++
        "<iq type='result' id='bind1'>" ++
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>" ++
        "<jid>alice@example.com/phone</jid>" ++
        "</bind>" ++
        "</iq>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var got: ?stream.IqResult = null;
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch unreachable;
        if (ev == null) break;
        if (!parser.onReaderEvent(ev.?)) unreachable;
        if (parser.pending) |sev| {
            parser.pending = null;
            if (sev == .iq_result) got = sev.iq_result;
        }
    }
    try std.testing.expect(got != null);
    try std.testing.expectEqualStrings("bind1", got.?.id);
    try std.testing.expect(got.?.bound_jid != null);
    try std.testing.expectEqualStrings("alice", got.?.bound_jid.?.local);
    try std.testing.expectEqualStrings("example.com", got.?.bound_jid.?.domain);
    try std.testing.expectEqualStrings("phone", got.?.bound_jid.?.resource);
}

test "parser: SM enabled" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s5' from='localhost'>" ++
        "<enabled xmlns='urn:xmpp:sm:3' id='sm42' resume='true' max='300'/>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var got: ?stream.SmResult = null;
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch unreachable;
        if (ev == null) break;
        if (!parser.onReaderEvent(ev.?)) unreachable;
        if (parser.pending) |sev| {
            parser.pending = null;
            if (sev == .sm_result) got = sev.sm_result;
        }
    }
    try std.testing.expect(got != null);
    switch (got.?) {
        .enabled => |id| try std.testing.expectEqualStrings("sm42", id),
        else => return error.TestFail,
    }
}

test "parser: self-closing SASL success settles immediately" {
    // Regression: the reader emits only element_start for <success/> (never
    // element_end); previously the SASL success event hung until an unrelated
    // closing tag. Real xmppd sends paired tags, so only self-closing peers
    // (or batching) ever hit this — found via the socketpair harness.
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s1' from='localhost'>" ++
        "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var got_success = false;
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch unreachable;
        if (ev == null) break;
        if (!parser.onReaderEvent(ev.?)) unreachable;
        if (parser.pending) |sev| {
            parser.pending = null;
            if (sev == .sasl_success) got_success = true;
        }
    }
    try std.testing.expect(got_success);
}

test "parser: SM resumed" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s6' from='localhost'>" ++
        "<resumed xmlns='urn:xmpp:sm:3' h='0' previd='prev-id'/>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var got: ?stream.SmResult = null;
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch unreachable;
        if (ev == null) break;
        if (!parser.onReaderEvent(ev.?)) unreachable;
        if (parser.pending) |sev| {
            parser.pending = null;
            if (sev == .sm_result) got = sev.sm_result;
        }
    }
    try std.testing.expect(got != null);
    switch (got.?) {
        .resumed => |id| try std.testing.expectEqualStrings("prev-id", id),
        else => return error.TestFail,
    }
}

test "parser: message stanza captured with children" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s7' from='localhost'>" ++
        "<message from='bob@localhost/x' to='alice@localhost' type='chat' id='m1'>" ++
        "<body>hello</body>" ++
        "<sonya xmlns='urn:sonya:message:0' kind='directive' session='sess-1'/>" ++
        "<thread>t-1</thread>" ++
        "</message>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var stanzas: usize = 0;
    var got: ?Stanza = null;
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch unreachable;
        if (ev == null) break;
        if (!parser.onReaderEvent(ev.?)) unreachable;
        if (parser.pending_stanza) |st| {
            parser.pending_stanza = null;
            stanzas += 1;
            got = st;
        }
        // No FSM event may be produced by application stanzas.
        try std.testing.expect(parser.pending == null or parser.pending.? == .stream_header);
    }
    try std.testing.expectEqual(@as(usize, 1), stanzas);
    const st = got.?;
    try std.testing.expect(st.kind == .message);
    try std.testing.expectEqualStrings("chat", st.type);
    try std.testing.expectEqualStrings("bob@localhost/x", st.from);
    try std.testing.expectEqualStrings("alice@localhost", st.to);
    try std.testing.expectEqualStrings("m1", st.id);
    try std.testing.expectEqual(@as(usize, 3), st.children.len);
    try std.testing.expectEqualStrings("body", st.children[0].local_name);
    try std.testing.expectEqualStrings("hello", st.children[0].text);
    try std.testing.expectEqualStrings("urn:sonya:message:0", st.children[1].ns);
    try std.testing.expectEqualStrings("directive", st.children[1].attrs[0].value);
    try std.testing.expectEqualStrings("thread", st.children[2].local_name);
    try std.testing.expectEqualStrings("t-1", st.children[2].text);
}

test "parser: self-closing presence captured empty; protocol iq not surfaced as stanza" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s8' from='localhost'>" ++
        "<presence from='bob@localhost/x' type='unavailable'/>" ++
        "<iq type='result' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>alice@localhost/smoke</jid></bind></iq>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var stanzas: usize = 0;
    var got: ?Stanza = null;
    var iqs: usize = 0;
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch unreachable;
        if (ev == null) break;
        if (!parser.onReaderEvent(ev.?)) unreachable;
        if (parser.pending_stanza) |st| {
            parser.pending_stanza = null;
            stanzas += 1;
            got = st;
        }
        if (parser.pending) |sev| {
            parser.pending = null;
            if (sev == .iq_result) iqs += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), stanzas);
    try std.testing.expectEqual(@as(usize, 1), iqs); // protocol iq stays on the FSM channel
    const st = got.?;
    try std.testing.expect(st.kind == .presence);
    try std.testing.expectEqualStrings("unavailable", st.type);
    try std.testing.expectEqual(@as(usize, 0), st.children.len);
}

test "parser: two stanzas in one buffer both captured" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s9' from='localhost'>" ++
        "<presence from='a@b/x'/>" ++
        "<message from='a@b/y' id='m2'><body>two</body></message>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var kinds: [2]Stanza.Kind = undefined;
    var n: usize = 0;
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch unreachable;
        if (ev == null) break;
        if (!parser.onReaderEvent(ev.?)) unreachable;
        if (parser.pending_stanza) |st| {
            parser.pending_stanza = null;
            kinds[n] = st.kind;
            n += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expect(kinds[0] == .presence);
    try std.testing.expect(kinds[1] == .message);
}
