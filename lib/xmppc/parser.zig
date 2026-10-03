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
    /// Copied per stanza; NOT aliased to the reader's reused attr list.
    attrs: []const Attribute,
    /// Concatenated subtree text of the child ("" when none). Valid until
    /// the parser processes the NEXT stanza after dispatch.
    text: []const u8,
};

/// Private build-time record: offsets instead of slices so that backing
/// lists may still grow while the stanza is being captured.
const ChildBuilder = struct {
    name: []const u8,
    local_name: []const u8,
    ns: []const u8,
    attrs_start: usize,
    attrs_len: usize,
    text_start: usize,
    text_len: usize,
};

/// A captured application stanza (message/presence/iq at stream-top level).
///
/// Lifetime: attrs/names borrow the xml Reader arena (reset when the NEXT
/// top-level stanza begins); child text borrows the parser's rolling
/// buffer (cleared at the same point). So: copy what you keep before
/// returning from the Event callback.
///
/// Child `text` is the concatenated text of the child's whole subtree
/// (e.g. XHTML-IM `<html><body><p>x</p>` appears as `"x"` on `html`).
/// Capture is one level of elements deep, EXCEPT inside a MAM result
/// wrapper: `<message><result xmlns='urn:xmpp:mam:2'><forwarded …><message>`
/// is unwrapped — the archived stanza surfaces as the Stanza (with
/// `archive` set), and the result wrapper itself produces nothing.
pub const Stanza = struct {
    pub const Kind = enum { message, presence, iq };
    kind: Kind,
    type: []const u8 = "",
    id: []const u8 = "",
    from: []const u8 = "",
    to: []const u8 = "",
    children: []const StanzaChild = &.{},
    /// Exact wire bytes of the stanza, open tag through close tag (empty
    /// when the producer supplied no spans). Nested structure lost by the
    /// flat child capture (e.g. XEP-0313 result>forwarded>message) can be
    /// re-parsed from this. Valid until the NEXT stanza is dispatched,
    /// same lifetime as children. (Note: MAM result wrappers are unwrapped
    /// structurally into `archive` + the inner stanza; `raw` stays the
    /// escape hatch for anything else.)
    raw: []const u8 = "",
    /// Non-null when this stanza was delivered from a message archive:
    /// the <result> id (RSM cursor / dedupe key), echoed queryid, and the
    /// XEP-0297 <delay> stamp.
    archive: ?ArchiveMeta = null,
};

pub const ArchiveMeta = struct {
    id: []const u8 = "",
    query: []const u8 = "",
    stamp: []const u8 = "",
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
    iq_is_bind: bool = false,
    iq_is_session: bool = false,
    iq_is_error: bool = false,
    in_jid: bool = false,
    jid_text: std.ArrayListUnmanaged(u8) = .{},

    // SM bare stanzas
    sm_kind: enum { none, enabled, resumed, failed } = .none,
    sm_id: []const u8 = "",
    sm_resumed_h: u32 = 0,
    sm_failed_cond: []const u8 = "",

    // Stream error
    in_stream_error: bool = false,
    stream_err_cond: []const u8 = "",

    // Application stanza capture (message/presence/iq at top level).
    // build_depth counts open elements below the stream tag.
    build_depth: u32 = 0,
    /// Depth at which children of the in-progress stanza open (1 for a
    /// top-level stanza; one deeper per tunnel layer for forwarded ones).
    st_child_depth: u32 = 1,
    st_archive: ?ArchiveMeta = null,
    // MAM/forward tunnel state (XEP-0313 <result> + XEP-0297 <forwarded>):
    // armed while the wrapper is open so the inner stanza replaces the
    // outer capture.
    tun_armed: bool = false,
    tun_forwarded: bool = false,
    tun_result_id: []const u8 = "",
    tun_result_query: []const u8 = "",
    tun_stamp: []const u8 = "",
    st_kind: Stanza.Kind = .message,
    in_stanza: bool = false,
    st_type: []const u8 = "",
    st_id: []const u8 = "",
    st_from: []const u8 = "",
    st_to: []const u8 = "",
    // Builders, private: offsets into st_attrs / st_text are resolved into
    // public StanzaChild slices only in finishStanza, once both backing
    // lists are final for the stanza (no realloc can move data under an
    // already-handed-out slice).
    st_children_b: std.ArrayListUnmanaged(ChildBuilder) = .{},
    st_attrs: std.ArrayListUnmanaged(Attribute) = .{},
    st_children_out: std.ArrayListUnmanaged(StanzaChild) = .{},
    st_child_open: bool = false,
    st_text: std.ArrayListUnmanaged(u8) = .{},
    // Raw wire bytes of the open stanza, accumulated from the per-event
    // spans onReaderEvent is given; empty when spans are not supplied.
    st_raw: std.ArrayListUnmanaged(u8) = .{},
    cur_span: ?[]const u8 = null,

    /// Set by the Session when the stream becomes active; bind1/sess1
    /// iq-result routing to the FSM applies only during establishment.
    after_establishment: bool = false,

    /// XEP-0198 bookkeeping: completed top-level stanzas since reset
    /// (wrapping u32 'h'); and a queued ack request to answer with <a/>.
    sm_stanza_count: u32 = 0,
    pending_sm_r: bool = false,
    /// Inbound `<a h='N'/>` (ack of OUR outbound stanzas), drained by the
    /// Session into the engine's unacked queue (T-9BC4D065).
    pending_sm_a: ?u32 = null,

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
        self.st_children_b.deinit(self.allocator);
        self.st_attrs.deinit(self.allocator);
        self.st_children_out.deinit(self.allocator);
        self.st_text.deinit(self.allocator);
        self.st_raw.deinit(self.allocator);
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
        self.st_child_depth = 1;
        self.st_archive = null;
        self.tun_armed = false;
        self.tun_forwarded = false;
        self.tun_result_id = "";
        self.tun_result_query = "";
        self.tun_stamp = "";
        self.st_children_b.clearRetainingCapacity();
        self.st_attrs.clearRetainingCapacity();
        self.st_children_out.clearRetainingCapacity();
        self.st_text.clearRetainingCapacity();
        self.st_raw.clearRetainingCapacity();
        self.pending_stanza = null;
    }

    pub fn onReaderEvent(self: *Parser, ev: xml.Event, span: ?[]const u8) bool {
        self.cur_span = span;
        // Raw capture: any event arriving while a stanza is open is part of
        // its wire bytes. The opener is appended by beginStanza instead, so
        // its span lands after the clear.
        if (span) |s| {
            // In-stanza text spans may end with the '<' of the next tag
            // (scanner lookahead); appending them verbatim keeps the byte
            // chain whole. Between stanzas the reader swallows whitespace,
            // so beginStanza restores the opener's '<' itself.
            if (self.in_stanza) self.st_raw.appendSlice(self.allocator, s) catch {};
        }
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

        // --- MAM result-wrapper tunnel (XEP-0313 + XEP-0297) -------------
        // <message><result xmlns='urn:xmpp:mam:2'><forwarded …><message>…
        // is unwrapped: the archived stanza is captured as if it had
        // arrived directly, carrying the result's id/queryid and the delay
        // stamp in Stanza.archive. The wrapper counts once for XEP-0198 and
        // never surfaces.
        if (self.in_stanza and self.st_kind == .message and self.st_child_depth == 1 and
            !self.tun_armed and self.build_depth == 1 and
            std.mem.eql(u8, name, "result") and std.mem.eql(u8, ns, "urn:xmpp:mam:2"))
        {
            self.tun_armed = true;
            for (el.attributes) |a| {
                if (std.mem.eql(u8, a.local_name, "id")) {
                    self.tun_result_id = a.value;
                } else if (std.mem.eql(u8, a.local_name, "queryid")) {
                    self.tun_result_query = a.value;
                }
            }
            // The wrapper IS the wire stanza: count it now; its close gets
            // no finishStanza once the tunnel owns the capture (and an
            // empty wrapper delivers nothing).
            self.sm_stanza_count +%= 1;
            return true;
        }
        if (self.tun_armed and !self.tun_forwarded and self.build_depth == 2 and
            std.mem.eql(u8, name, "forwarded") and std.mem.eql(u8, ns, "urn:xmpp:forward:0"))
        {
            self.tun_forwarded = true;
            if (closed) self.tun_forwarded = false;
            return true;
        }
        if (self.tun_armed and self.tun_forwarded and self.build_depth == 3) {
            if (std.mem.eql(u8, name, "delay")) {
                for (el.attributes) |a| {
                    if (std.mem.eql(u8, a.local_name, "stamp")) self.tun_stamp = a.value;
                }
                return true;
            }
            // Note: no namespace gate here. The archived stanza is spliced
            // verbatim, and <forwarded> redeclares the default namespace to
            // urn:xmpp:forward:0 — peer messages are not required to carry
            // their own xmlns, so position (inside <forwarded>) + name is
            // the accept rule.
            if (std.mem.eql(u8, name, "message") or std.mem.eql(u8, name, "presence") or std.mem.eql(u8, name, "iq")) {
                self.beginStanza(name, el);
                self.st_archive = .{
                    .id = self.tun_result_id,
                    .query = self.tun_result_query,
                    .stamp = self.tun_stamp,
                };
                if (closed) self.finishStanza();
                return true;
            }
            return true;
        }

        // --- Application stanza child: one level below the open stanza ---
        if (self.in_stanza and self.build_depth == self.st_child_depth) {
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
                var h: u32 = 0;
                for (el.attributes) |a| {
                    if (std.mem.eql(u8, a.local_name, "previd")) self.sm_id = a.value;
                    // h = count of OUR stanzas the server handled before the
                    // disconnect; the engine drops that many from the unacked
                    // queue before replay (T-9BC4D065).
                    if (std.mem.eql(u8, a.local_name, "h")) h = std.fmt.parseInt(u32, a.value, 10) catch 0;
                }
                self.sm_kind = .resumed;
                if (closed) {
                    self.pending = .{ .sm_result = .{ .resumed = .{ .id = self.sm_id, .h = h } } };
                    self.sm_id = "";
                    self.sm_kind = .none;
                } else {
                    self.sm_resumed_h = h;
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
            // Ack request: answer with <a h=.../> (Session drains this).
            if (std.mem.eql(u8, name, "r")) {
                self.pending_sm_r = true;
                return true;
            }
            // Ack of OUR outbound stanzas (T-9BC4D065): the Session drains
            // this into the engine's unacked queue. Both the self-closing
            // and explicit-close forms are settled here since 'h' rides on
            // the open tag.
            if (std.mem.eql(u8, name, "a")) {
                for (el.attributes) |a| {
                    if (std.mem.eql(u8, a.local_name, "h"))
                        self.pending_sm_a = std.fmt.parseInt(u32, a.value, 10) catch null;
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
        // Kind/attrs/id are collected by beginStanza already; this block only
        // arms the legacy bind/session child flag tracking.
        if (std.mem.eql(u8, name, "iq") and std.mem.eql(u8, ns, xml.ns.client)) {
            self.in_iq = true;
            self.iq_is_bind = false;
            self.iq_is_session = false;
            self.iq_is_error = false;
            self.in_jid = false;
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
        if (self.in_stanza and self.build_depth == self.st_child_depth + 1) {
            self.endStanzaChild();
            return true;
        }
        // Application stanza close. finishStanza routes protocol-shaped IQ
        // results (bind/session) to the FSM and surfaces everything else.
        if (self.in_stanza and self.build_depth == self.st_child_depth) {
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
                    self.pending = .{ .sm_result = .{ .resumed = .{ .id = self.sm_id, .h = self.sm_resumed_h } } };
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
        self.st_children_b.clearRetainingCapacity();
        self.st_attrs.clearRetainingCapacity();
        self.st_children_out.clearRetainingCapacity();
        self.st_text.clearRetainingCapacity();
        self.st_child_open = false;
        self.st_raw.clearRetainingCapacity();
        // The span includes the opening '<' only when the scanner chained
        // from the previous tag in one read; after (possibly swallowed)
        // whitespace it starts at the tag name and the '<' is restored here.
        if (self.cur_span) |s| {
            if (s.len > 0 and s[0] != '<') self.st_raw.append(self.allocator, '<') catch {};
            self.st_raw.appendSlice(self.allocator, s) catch {};
        }
        // Children open one level below the element passed in (top-level
        // stanza: depth 1; forwarded inner stanza: wherever the tunnel
        // was entered).
        self.st_child_depth = self.build_depth + 1;
    }

    fn beginStanzaChild(self: *Parser, el: xml.Element) void {
        // Attr copies stop the aliasing of Reader.attrs (reused for every
        // element); the strings they point at are reader-arena stable.
        const attrs_start = self.st_attrs.items.len;
        self.st_attrs.appendSlice(self.allocator, el.attributes) catch return;
        self.st_children_b.append(self.allocator, .{
            .name = el.name,
            .local_name = el.local_name,
            .ns = el.namespace_uri,
            .attrs_start = attrs_start,
            .attrs_len = self.st_attrs.items.len - attrs_start,
            .text_start = self.st_text.items.len,
            .text_len = 0,
        }) catch return;
        self.st_child_open = !el.self_closing;
    }

    fn endStanzaChild(self: *Parser) void {
        if (self.st_children_b.items.len == 0) return;
        const child = &self.st_children_b.items[self.st_children_b.items.len - 1];
        child.text_len = self.st_text.items.len - child.text_start;
        self.st_child_open = false;
    }

    /// Close the stanza collector. A protocol-shaped IQ result
    /// (bind/session) goes to the FSM and nothing else; every other stanza
    /// surfaces to the application. Both close paths (end tag and
    /// self-closing) come through here (fixes the self-closing
    /// iq type='result' case, e.g. sess1 without a <session/> payload).
    fn finishStanza(self: *Parser) void {
        if (self.st_child_open) self.endStanzaChild();
        // Tunnel bookkeeping: a wrapper was armed but no inner stanza ever
        // opened -> deliver nothing (its wire count already happened at arm
        // time). A completed inner stanza must not count again.
        const tunneled = self.st_archive != null;
        const empty_wrapper = self.tun_armed and !tunneled;
        self.tun_armed = false;
        self.tun_forwarded = false;
        self.tun_result_id = "";
        self.tun_result_query = "";
        self.tun_stamp = "";
        const is_result = std.mem.eql(u8, self.st_type, "result");
        // bind/session establishment results are FSM traffic; after the
        // stream is active the ids bind1/sess1 have no special meaning and
        // every iq result surfaces to the application.
        const shaped = !self.after_establishment and
            (self.iq_is_bind or self.iq_is_session or
                std.mem.eql(u8, self.st_id, "bind1") or std.mem.eql(u8, self.st_id, "sess1"));
        // Every completed top-level stanza counts for XEP-0198 'h'.
        if (!tunneled and !empty_wrapper) self.sm_stanza_count +%= 1;
        if (!empty_wrapper) {
            if (self.st_kind == .iq and is_result and shaped) {
                var res = stream.IqResult{ .id = self.st_id };
                res.is_error = self.iq_is_error;
                if (self.iq_is_bind and !self.iq_is_error) {
                    const jt = std.mem.trim(u8, self.jid_text.items, " \t\r\n");
                    res.bound_jid = Jid.parse(jt) catch null;
                }
                self.pending = .{ .iq_result = res };
            } else {
                // Materialize public children: backing lists are final now,
                // so building slices here cannot dangle.
                self.st_children_out.clearRetainingCapacity();
                for (self.st_children_b.items) |b| {
                    self.st_children_out.append(self.allocator, .{
                        .name = b.name,
                        .local_name = b.local_name,
                        .ns = b.ns,
                        .attrs = self.st_attrs.items[b.attrs_start .. b.attrs_start + b.attrs_len],
                        .text = self.st_text.items[b.text_start .. b.text_start + b.text_len],
                    }) catch continue;
                }
                self.pending_stanza = .{
                    .kind = self.st_kind,
                    .type = self.st_type,
                    .id = self.st_id,
                    .from = self.st_from,
                    .to = self.st_to,
                    .children = self.st_children_out.items,
                    .raw = self.st_raw.items,
                    .archive = self.st_archive,
                };
            }
        }
        self.in_stanza = false;
        self.st_child_open = false;
        self.st_child_depth = 1;
        self.st_archive = null;
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

/// Feed one reader event to the parser with its exact byte span, the same
/// contract the Session's parse loop fulfills for raw stanza capture.
fn drive(parser: *Parser, reader: *Reader, input: []const u8, pos: *usize) bool {
    const start = pos.*;
    const ev = reader.next(input, pos) catch unreachable;
    if (ev == null) return false;
    if (!parser.onReaderEvent(ev.?, input[start..pos.*])) unreachable;
    return true;
}

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
        if (!drive(&parser, &reader, input, &pos)) break;
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
        if (!drive(&parser, &reader, input, &pos)) break;
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
        if (!drive(&parser, &reader, input, &pos)) break;
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
        if (!drive(&parser, &reader, input, &pos)) break;
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
        if (!drive(&parser, &reader, input, &pos)) break;
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
        if (!drive(&parser, &reader, input, &pos)) break;
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
        if (!drive(&parser, &reader, input, &pos)) break;
        if (parser.pending) |sev| {
            parser.pending = null;
            if (sev == .sm_result) got = sev.sm_result;
        }
    }
    try std.testing.expect(got != null);
    switch (got.?) {
        .resumed => |r| {
            try std.testing.expectEqualStrings("prev-id", r.id);
            try std.testing.expectEqual(@as(u32, 0), r.h);
        },
        else => return error.TestFail,
    }
}

test "parser: SM ack captured in pending_sm_a (T-9BC4D065)" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s7' from='localhost'>" ++
        "<a xmlns='urn:xmpp:sm:3' h='7'/>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var pos: usize = 0;
    while (true) {
        if (!drive(&parser, &reader, input, &pos)) break;
    }
    try std.testing.expectEqual(@as(?u32, 7), parser.pending_sm_a);
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
        if (!drive(&parser, &reader, input, &pos)) break;
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
    var got_kind: ?Stanza.Kind = null;
    var got_children: usize = 0;
    var typ_buf: [32]u8 = undefined;
    var typ_len: usize = 0;
    var iqs: usize = 0;
    var pos: usize = 0;
    while (true) {
        if (!drive(&parser, &reader, input, &pos)) break;
        if (parser.pending_stanza) |st| {
            parser.pending_stanza = null;
            stanzas += 1;
            got_kind = st.kind;
            got_children = st.children.len;
            @memcpy(typ_buf[0..st.type.len], st.type);
            typ_len = st.type.len;
        }
        if (parser.pending) |sev| {
            parser.pending = null;
            if (sev == .iq_result) iqs += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), stanzas);
    try std.testing.expectEqual(@as(usize, 1), iqs); // protocol iq stays on the FSM channel
    try std.testing.expect(got_kind.? == .presence);
    try std.testing.expectEqualStrings("unavailable", typ_buf[0..typ_len]);
    try std.testing.expectEqual(@as(usize, 0), got_children);
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
        if (!drive(&parser, &reader, input, &pos)) break;
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

test "parser: child attrs survive later siblings (reader attr-list reuse)" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s10' from='localhost'>" ++
        "<message id='m1'><first xmlns='urn:x' k='FIRST'/><second xmlns='urn:x' k='SECOND'/></message>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var got: ?Stanza = null;
    var pos: usize = 0;
    while (true) {
        if (!drive(&parser, &reader, input, &pos)) break;
        if (parser.pending_stanza) |st| {
            parser.pending_stanza = null;
            got = st;
            // What a consumer snapshot would see DURING the dispatch:
            try std.testing.expectEqualStrings("FIRST", st.children[0].attrs[0].value);
            try std.testing.expectEqualStrings("SECOND", st.children[1].attrs[0].value);
        }
    }
    try std.testing.expect(got != null);
}

test "parser: child text survives rolling-buffer growth" {
    const allocator = std.testing.allocator;
    const body = "B" ** 60;
    const thread = "T" ** 200;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s11' from='localhost'>" ++
        "<message id='m1'><body>" ++ body ++ "</body><thread>" ++ thread ++ "</thread></message>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var pos: usize = 0;
    while (true) {
        if (!drive(&parser, &reader, input, &pos)) break;
        if (parser.pending_stanza) |st| {
            parser.pending_stanza = null;
            // st_text grew past its initial capacity between the two
            // children; offsets (not slices) must have carried across.
            try std.testing.expectEqualStrings(body, st.children[0].text);
            try std.testing.expectEqualStrings(thread, st.children[1].text);
        }
    }
}

test "parser: application iq result surfaces; protocol iq stays with the FSM" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s12' from='localhost'>" ++
        // application result (disco answer) — must become a stanza
        "<iq type='result' id='disco1' from='localhost'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='server'/></query></iq>" ++
        // self-closing protocol result (server answered sess1 with nothing) — must feed the FSM
        "<iq type='result' id='sess1'/>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var stanzas: usize = 0;
    var iq_results: usize = 0;
    // Snapshot during dispatch: payload slices die on the next stanza
    // (reader arena reset / parser buffer reuse), per the Stanza contract.
    var got_kind: ?Stanza.Kind = null;
    var id_buf: [64]u8 = undefined;
    var id_len: usize = 0;
    var pos: usize = 0;
    while (true) {
        if (!drive(&parser, &reader, input, &pos)) break;
        if (parser.pending_stanza) |st| {
            parser.pending_stanza = null;
            stanzas += 1;
            got_kind = st.kind;
            @memcpy(id_buf[0..st.id.len], st.id);
            id_len = st.id.len;
            try std.testing.expectEqualStrings("query", st.children[0].local_name);
            try std.testing.expectEqualStrings("http://jabber.org/protocol/disco#info", st.children[0].ns);
        }
        if (parser.pending) |sev| {
            parser.pending = null;
            if (sev == .iq_result) iq_results += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), stanzas);
    try std.testing.expectEqual(@as(usize, 1), iq_results);
    try std.testing.expect(got_kind.? == .iq);
    try std.testing.expectEqualStrings("disco1", id_buf[0..id_len]);
}

test "parser: stanza raw wire bytes captured" {
    const allocator = std.testing.allocator;
    // MAM wrapper: the tunnel surfaces the ARCHIVED stanza once, whose raw
    // is the inner stanza's exact wire bytes (the wrapper's metadata
    // surfaces via Stanza.archive instead).
    const stanza1_raw =
        "<message from='dev@conference.localhost/alice' type='groupchat'>" ++
        "<body>backlog &lt;3</body></message>";
    const stanza1 =
        "<message from='dev@conference.localhost' to='bob@localhost/kumiko'>" ++
        "<result xmlns='urn:xmpp:mam:2' queryid='q1' id='u-42'>" ++
        "<forwarded xmlns='urn:xmpp:forward:0'>" ++
        "<delay xmlns='urn:xmpp:delay' stamp='2026-09-30T18:22:10Z'/>" ++
        stanza1_raw ++
        "</forwarded></result></message>";
    const stanza2 = "<presence from='dev@conference.localhost/alice'/>";
    const input = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s9' from='localhost'>" ++
        stanza1 ++ " \r\n" ++ stanza2;
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var raws: usize = 0;
    var pos: usize = 0;
    while (true) {
        if (!drive(&parser, &reader, input, &pos)) break;
        if (parser.pending_stanza) |st| {
            parser.pending_stanza = null;
            raws += 1;
            if (raws == 1) {
                try std.testing.expectEqualStrings(stanza1_raw, st.raw);
                try std.testing.expect(st.archive != null);
                try std.testing.expectEqualStrings("u-42", st.archive.?.id);
            } else {
                try std.testing.expectEqualStrings(stanza2, st.raw);
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 2), raws);
}

test "parser: MAM result wrapper unwraps to the archived stanza" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s20' from='localhost'>" ++
        "<message from='alice@localhost' to='alice@localhost'>" ++
        "<result xmlns='urn:xmpp:mam:2' queryid='bridge-catchup' id='arc-42'>" ++
        "<forwarded xmlns='urn:xmpp:forward:0'>" ++
        "<delay xmlns='urn:xmpp:delay' stamp='2026-10-03T06:00:00Z'/>" ++
        "<message from='bob@localhost/x' to='alice@localhost' type='chat' id='m99'>" ++
        "<body>from the archive</body>" ++
        "<sonya xmlns='urn:sonya:message:0' kind='notice'/>" ++
        "<thread>t-7</thread>" ++
        "</message>" ++
        "</forwarded>" ++
        "</result>" ++
        "</message>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var stanzas_text: [3][]const u8 = .{ "", "", "" };
    var got: usize = 0;
    var arc_id: []const u8 = "";
    var arc_query: []const u8 = "";
    var arc_stamp: []const u8 = "";
    var got_id: []const u8 = "";
    var got_from: []const u8 = "";
    var got_type: []const u8 = "";
    var got_sonya_ns: []const u8 = "";
    var got_kind_attr: []const u8 = "";
    var pos: usize = 0;
    while (true) {
        if (!drive(&parser, &reader, input, &pos)) break;
        if (parser.pending_stanza) |st| {
            // Snapshot: slices die at the next stanza.
            parser.pending_stanza = null;
            got += 1;
            got_type = std.heap.page_allocator.dupe(u8, st.type) catch return;
            got_from = std.heap.page_allocator.dupe(u8, st.from) catch return;
            got_id = std.heap.page_allocator.dupe(u8, st.id) catch return;
            try std.testing.expect(st.archive != null);
            arc_id = std.heap.page_allocator.dupe(u8, st.archive.?.id) catch return;
            arc_query = std.heap.page_allocator.dupe(u8, st.archive.?.query) catch return;
            arc_stamp = std.heap.page_allocator.dupe(u8, st.archive.?.stamp) catch return;
            try std.testing.expectEqual(@as(usize, 3), st.children.len);
            try std.testing.expectEqualStrings("body", st.children[0].local_name);
            stanzas_text[0] = std.heap.page_allocator.dupe(u8, st.children[0].text) catch return;
            got_sonya_ns = std.heap.page_allocator.dupe(u8, st.children[1].ns) catch return;
            got_kind_attr = std.heap.page_allocator.dupe(u8, st.children[1].attrs[0].value) catch return;
            stanzas_text[2] = std.heap.page_allocator.dupe(u8, st.children[2].text) catch return;
        }
        // The wrapper carries no bind/session shape; nothing FSM-side.
        try std.testing.expect(parser.pending == null or parser.pending.? == .stream_header);
    }
    try std.testing.expectEqual(@as(usize, 1), got);
    try std.testing.expectEqualStrings("from the archive", stanzas_text[0]);
    try std.testing.expectEqualStrings("urn:sonya:message:0", got_sonya_ns);
    try std.testing.expectEqualStrings("notice", got_kind_attr);
    try std.testing.expectEqualStrings("t-7", stanzas_text[2]);
    try std.testing.expectEqualStrings("arc-42", arc_id);
    try std.testing.expectEqualStrings("bridge-catchup", arc_query);
    try std.testing.expectEqualStrings("2026-10-03T06:00:00Z", arc_stamp);
    try std.testing.expectEqualStrings("chat", got_type);
    try std.testing.expectEqualStrings("bob@localhost/x", got_from);
    try std.testing.expectEqualStrings("m99", got_id);
}

test "parser: MAM wrappers and wire stanzas interleave without loss" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s21' from='localhost'>" ++
        "<message from='a@x/1' id='w1'><body>live one</body></message>" ++
        "<message><result xmlns='urn:xmpp:mam:2' id='arc-1'><forwarded xmlns='urn:xmpp:forward:0'>" ++
        "<message from='b@x' id='a1'><body>archived one</body></message>" ++
        "</forwarded></result></message>" ++
        "<message from='a@x/2' id='w2'><body>live two</body></message>" ++
        "<message><result xmlns='urn:xmpp:mam:2' id='arc-2'/></message>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var ids: [4][]u8 = undefined;
    var archived: [4]bool = undefined;
    var n: usize = 0;
    var pos: usize = 0;
    while (true) {
        if (!drive(&parser, &reader, input, &pos)) break;
        if (parser.pending_stanza) |st| {
            parser.pending_stanza = null;
            ids[n] = std.heap.page_allocator.dupe(u8, st.id) catch return;
            archived[n] = st.archive != null;
            n += 1;
        }
        try std.testing.expect(parser.pending == null or parser.pending.? == .stream_header);
    }
    // Live 1, archived 1, live 2; the empty result wrapper delivers nothing.
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqualStrings("w1", ids[0]);
    try std.testing.expect(!archived[0]);
    try std.testing.expectEqualStrings("a1", ids[1]); // inner stanza's own id wins
    try std.testing.expect(archived[1]);
    try std.testing.expectEqualStrings("w2", ids[2]);
    try std.testing.expect(!archived[2]);
}
