//! StanzaWriter: streaming XMPP stanza serializer over std.Io.Writer.
//!
//! One StanzaWriter emits one stanza into a caller-provided writer. Element
//! and attribute names are checked against the XML QName production
//! (NCName with an optional 'prefix:'; ASCII subset). Attribute values and
//! text are validated against the XML Char production and always escaped
//! for the five escapables (`& < > ' "`). Only reader-validated markup may
//! pass through rawSpan; the ValidatedSpan type carries that proof.
//!
//! The writer owns nothing and never allocates: every byte goes to the
//! caller's writer. When that writer fills or fails, a sticky failure is
//! latched, later emits are dropped, and finish() reports error.Overflow
//! once, so partial output can never count as success. The Overflow
//! contract: a fixed caller buffer then holds a truncated prefix, and
//! with a streaming outbox the early bytes may already be gone - callers
//! discard the buffer or fail the stream, never emit it.

const std = @import("std");
const scanner_mod = @import("scanner.zig");

/// Errors for malformed caller input (operating errors, not asserts).
pub const Error = error{
    /// elementClose name does not match the innermost open element.
    MismatchedClose,
    /// Element or attribute name outside the XML Name production.
    InvalidName,
    /// Value bytes are not well-formed UTF-8.
    InvalidUtf8,
    /// Value contains bytes outside the XML Char production: NUL, C0
    /// controls other than tab/LF/CR, or the noncharacters U+FFFE/U+FFFF.
    InvalidCharacter,
    /// rawSpan input is not well-formed XML, or is forbidden inside an
    /// XMPP stream (comments, PIs, declarations, DTDs: RFC 6120 11.1;
    /// CDATA is also rejected as an implementation restriction).
    NotWellFormed,
};

/// finish() reports the latched output failure once.
pub const FinishError = error{Overflow};

pub const max_name_len = 256;
/// Open-element depth bound: far beyond any real stanza, small enough
/// that the name stack stays cheap to return by value.
pub const max_depth = 64;

const vec_len = std.simd.suggestVectorLength(u8) orelse 16;
const ByteVec = @Vector(vec_len, u8);
const BitMask = std.meta.Int(.unsigned, vec_len);

const v_amp: ByteVec = @splat('&');
const v_lt: ByteVec = @splat('<');
const v_gt: ByteVec = @splat('>');
const v_apos: ByteVec = @splat('\'');
const v_quot: ByteVec = @splat('"');
const v_ctrl: ByteVec = @splat(0x20);
const v_ef: ByteVec = @splat(0xEF);

/// Per-tag bound on attributes and on namespace declarations; a span
/// that needs more is hostile, not real.
const span_max_attrs = 32;
const span_max_decls = 64;

/// A half-open byte range into the caller's span input. Names,
/// prefixes and URIs tracked while validating are ranges over those
/// bytes, never slices into the scanner's token arena: a scanner may
/// reset that arena between sibling elements and free anything a slice
/// still points at, while the caller's bytes outlive the whole pass.
const SpanRange = struct { start: usize, end: usize };

const SpanQName = struct { prefix: SpanRange, local: SpanRange };

const SpanAttr = struct { name: SpanRange };
const SpanDecl = struct { depth: usize, prefix: SpanRange, uri: SpanRange };

fn spanSlice(bytes: []const u8, r: SpanRange) []const u8 {
    return bytes[r.start..r.end];
}

/// 'prefix:local' split at the first colon; an empty range means the
/// name carries no prefix.
fn spanQName(bytes: []const u8, r: SpanRange) SpanQName {
    if (std.mem.indexOfScalar(u8, bytes[r.start..r.end], ':')) |colon| {
        return .{
            .prefix = .{ .start = r.start, .end = r.start + colon },
            .local = .{ .start = r.start + colon + 1, .end = r.end },
        };
    }
    return .{ .prefix = .{ .start = r.start, .end = r.start }, .local = r };
}

fn isSpanWs(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\r';
}

/// The element name range after a '<' at `lt`: through the first
/// whitespace or '>', or a '/' immediately followed by '>'.
fn spanTagName(bytes: []const u8, lt: usize) SpanRange {
    var end = lt + 1;
    while (end < bytes.len) : (end += 1) {
        const c = bytes[end];
        if (isSpanWs(c) or c == '>') break;
        if (c == '/' and end + 1 < bytes.len and bytes[end + 1] == '>') break;
    }
    return .{ .start = lt + 1, .end = end };
}

/// The attribute name region after `from`: the first non-whitespace
/// byte through the '=' delimiter, less whitespace between the name
/// and '=' (which a bare 'S = S' allows). Also reports the '=' offset
/// so callers can locate the quoted value.
fn spanAttrHead(bytes: []const u8, from: usize) ?struct { name: SpanRange, eq: usize } {
    const start = std.mem.indexOfNonePos(u8, bytes, from, " \t\n\r") orelse return null;
    const eq = std.mem.indexOfScalarPos(u8, bytes, start, '=') orelse return null;
    var end = eq;
    while (end > start and isSpanWs(bytes[end - 1])) end -= 1;
    return .{ .name = .{ .start = start, .end = end }, .eq = eq };
}

/// A prefix is usable when it is declared in scope or is the
/// always-bound xml: prefix.
fn spanPrefixOk(bytes: []const u8, prefix: []const u8, decls: []const SpanDecl) bool {
    if (std.mem.eql(u8, prefix, "xml")) return true;
    for (decls) |d| {
        if (std.mem.eql(u8, spanSlice(bytes, d.prefix), prefix)) return true;
    }
    return false;
}

fn isXmlChar(c: u21) bool {
    return c == 0x9 or c == 0xA or c == 0xD or
        (c >= 0x20 and c <= 0xD7FF) or
        (c >= 0xE000 and c <= 0xFFFD) or
        (c >= 0x10000 and c <= 0x10FFFF);
}

/// Every &#...; reference in the raw span must name a legal XML Char
/// and end in ';'. Checked on the raw bytes because the scanner's u8
/// decode cannot express references above U+00FF; those still error
/// downstream until S21 lands a u21 decode.
fn spanCheckCharrefs(bytes: []const u8) Error!void {
    var i: usize = 0;
    while (i + 2 < bytes.len) : (i += 1) {
        if (bytes[i] != '&' or bytes[i + 1] != '#') continue;
        var j = i + 2;
        var value: u21 = 0;
        var digits: usize = 0;
        if (j < bytes.len and (bytes[j] == 'x' or bytes[j] == 'X')) {
            j += 1;
            while (j < bytes.len and std.ascii.isHex(bytes[j])) : (j += 1) {
                const c = std.ascii.toLower(bytes[j]);
                const digit: u21 = if (std.ascii.isDigit(c)) c - '0' else c - 'a' + 10;
                value = std.math.mul(u21, value, 16) catch return error.NotWellFormed;
                value = std.math.add(u21, value, digit) catch return error.NotWellFormed;
                digits += 1;
            }
        } else {
            while (j < bytes.len and std.ascii.isDigit(bytes[j])) : (j += 1) {
                value = std.math.mul(u21, value, 10) catch return error.NotWellFormed;
                value = std.math.add(u21, value, bytes[j] - '0') catch return error.NotWellFormed;
                digits += 1;
            }
        }
        if (digits == 0 or j >= bytes.len or bytes[j] != ';') return error.NotWellFormed;
        if (!isXmlChar(value)) return error.NotWellFormed;
    }
}

const stream_ns = "http://etherx.jabber.org/streams";
const xml_ns = "http://www.w3.org/XML/1998/namespace";
const xmlns_ns = "http://www.w3.org/2000/xmlns/";

/// Stream-level elements must never ride inside a stanza-level span,
/// and the check is the resolved namespace URI, not a literal prefix:
/// any binding of the stream namespace makes the element a stream
/// element, whatever prefix (or none) it was written with.
fn spanStreamDecl(uri: []const u8) bool {
    return std.mem.eql(u8, uri, stream_ns);
}

/// Resolve a prefix against the in-scope declarations; an empty
/// prefix resolves against the default namespace declaration. The
/// newest declaration wins, matching in-scope shadowing.
fn spanResolvePrefix(bytes: []const u8, prefix: []const u8, decls: []const SpanDecl) ?[]const u8 {
    var i = decls.len;
    while (i > 0) {
        i -= 1;
        if (std.mem.eql(u8, spanSlice(bytes, decls[i].prefix), prefix))
            return spanSlice(bytes, decls[i].uri);
    }
    return null;
}

/// Lexical pass over the raw span bytes, independent of the scanner:
/// attributes must be name='v' or name="v" separated by whitespace
/// (unquoted values, a '<' where the quote belongs, and adjacent
/// attributes are all malformed), a '<' is illegal inside the quoted
/// value itself (an entity-produced '<' like &lt; stays legal, which
/// is exactly why this runs on the source bytes), ']]>' is illegal
/// in text, and xmlns:xmlns may never be declared.
fn spanCheckLex(bytes: []const u8) Error!void {
    const LexState = enum { text, tag_name, before_attr, attr_name, attr_eq, attr_value, after_attr, close_name };
    var state: LexState = .text;
    var quote: u8 = 0;
    var attr_first: usize = 0;
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        const c = bytes[i];
        switch (state) {
            .text => {
                if (c == '<') {
                    state = .tag_name;
                    if (i + 1 < bytes.len and bytes[i + 1] == '/') state = .close_name;
                } else if (std.mem.startsWith(u8, bytes[i..], "]]>")) {
                    return error.NotWellFormed;
                }
            },
            .close_name => {
                if (c == '>') state = .text;
            },
            .tag_name => {
                if (c == '>') {
                    state = .text;
                } else if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
                    state = .before_attr;
                }
            },
            .before_attr => {
                if (c == ' ' or c == '\t' or c == '\n' or c == '\r') continue;
                if (c == '>') {
                    state = .text;
                } else if (c == '/') {
                    // '/>' ends the tag; anything else after '/' is not.
                    if (i + 1 >= bytes.len or bytes[i + 1] != '>') return error.NotWellFormed;
                } else {
                    attr_first = i;
                    state = .attr_name;
                }
            },
            .attr_name => {
                if (c == '=') {
                    // xmlns:xmlns can never be declared.
                    const name = bytes[attr_first..i];
                    if (std.mem.eql(u8, name, "xmlns:xmlns")) return error.NotWellFormed;
                    state = .attr_eq;
                } else if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
                    // Whitespace inside name= : the '=' may follow.
                    var j = i;
                    while (j < bytes.len and (bytes[j] == ' ' or bytes[j] == '\t' or bytes[j] == '\n' or bytes[j] == '\r')) j += 1;
                    if (j >= bytes.len or bytes[j] != '=') return error.NotWellFormed;
                    const name = bytes[attr_first..i];
                    if (std.mem.eql(u8, name, "xmlns:xmlns")) return error.NotWellFormed;
                    i = j;
                    state = .attr_eq;
                } else if (c == '/' or c == '>') {
                    // A bare name with no value is not an attribute.
                    return error.NotWellFormed;
                }
            },
            .attr_eq => {
                if (c == ' ' or c == '\t' or c == '\n' or c == '\r') continue;
                if (c != '\'' and c != '"') return error.NotWellFormed;
                quote = c;
                state = .attr_value;
            },
            .attr_value => {
                if (c == '<') return error.NotWellFormed;
                // Another attribute must follow whitespace; an adjacent
                // name is malformed markup.
                if (c == quote) state = .after_attr;
            },
            .after_attr => {
                if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
                    state = .before_attr;
                } else if (c == '>') {
                    state = .text;
                } else if (c == '/' and i + 1 < bytes.len and bytes[i + 1] == '>') {
                    state = .text;
                } else {
                    return error.NotWellFormed;
                }
            },
        }
    }
    // Ending mid-construct is the scanner's problem, not this pass's.
}

/// The URI a checked attribute prefix expands to; xml is always bound.
fn spanAttrUri(bytes: []const u8, prefix: []const u8, decls: []const SpanDecl) []const u8 {
    if (std.mem.eql(u8, prefix, "xml")) return xml_ns;
    return spanResolvePrefix(bytes, prefix, decls) orelse "";
}

/// Element and attribute prefixes are only resolved once the start
/// tag ends: an xmlns on the same tag is already in scope for its own
/// tag name and every attribute on it.
fn spanCheckPrefixes(
    bytes: []const u8,
    elem_prefix: []const u8,
    attrs: []const SpanAttr,
    decls: []const SpanDecl,
) Error!void {
    // The stream prefix is rejected outright: whatever it is bound
    // to, xmppd's reader classifies by the literal prefix and would
    // see stream events inside a forwarded stanza.
    if (std.mem.eql(u8, elem_prefix, "stream")) return error.NotWellFormed;
    if (elem_prefix.len > 0 and !spanPrefixOk(bytes, elem_prefix, decls))
        return error.NotWellFormed;
    // The element is a stream element whenever its resolved namespace
    // is the stream namespace, whatever prefix wrote it.
    if (spanResolvePrefix(bytes, elem_prefix, decls)) |uri| {
        if (spanStreamDecl(uri)) return error.NotWellFormed;
    }
    for (attrs) |a| {
        const a_prefix = spanSlice(bytes, spanQName(bytes, a.name).prefix);
        if (std.mem.eql(u8, a_prefix, "xmlns")) continue;
        if (std.mem.eql(u8, a_prefix, "stream")) return error.NotWellFormed;
        if (a_prefix.len > 0 and !spanPrefixOk(bytes, a_prefix, decls))
            return error.NotWellFormed;
    }
    // Attribute uniqueness is by expanded name: two prefixes bound to
    // the same URI collide when their local names match, so comparing
    // qualified names alone is not enough.
    for (attrs, 0..) |a, i| {
        const aq = spanQName(bytes, a.name);
        const a_prefix = spanSlice(bytes, aq.prefix);
        if (a_prefix.len == 0 or std.mem.eql(u8, a_prefix, "xmlns")) continue;
        const a_uri = spanAttrUri(bytes, a_prefix, decls);
        for (attrs[i + 1 ..]) |b| {
            const bq = spanQName(bytes, b.name);
            const b_prefix = spanSlice(bytes, bq.prefix);
            if (b_prefix.len == 0 or std.mem.eql(u8, b_prefix, "xmlns")) continue;
            if (!std.mem.eql(u8, spanSlice(bytes, aq.local), spanSlice(bytes, bq.local))) continue;
            if (std.mem.eql(u8, a_uri, spanAttrUri(bytes, b_prefix, decls)))
                return error.NotWellFormed;
        }
    }
}

/// Markup bytes proven valid by the validating reader (XML Char, UTF-8,
/// balanced elements). rawSpan emits them verbatim; the type exists so
/// that raw bytes cannot reach the output without that validation.
pub const ValidatedSpan = struct {
    bytes: []const u8,

    /// The only constructor, and it validates: XML Char plus a full
    /// well-formedness pass through lib/xml/scanner. Beyond balanced
    /// elements it rejects everything RFC 6120 section 11.1 forbids in
    /// a stream (comments, PIs, declarations, DTDs) plus CDATA, elements
    /// in the stream namespace, the stream prefix under any binding,
    /// any declaration of the stream namespace, Namespaces in XML
    /// violations (xmlns:xml rebinding, the XML and XMLNS URIs bound
    /// elsewhere, xmlns:p='', duplicate attributes by expanded name),
    /// invalid names, malformed attribute syntax, ']]>' in text,
    /// xmlns:xmlns, duplicate attributes, a '<' inside an attribute
    /// value, non-Char character references, undeclared prefixes other
    /// than xml:, and truncated input. A
    /// dedicated zero-cost reader-produced constructor arrives with
    /// C5; until then callers pay one scan per span.
    pub fn fromReader(alloc: std.mem.Allocator, bytes: []const u8) Error!ValidatedSpan {
        try validateChars(bytes);
        try spanCheckCharrefs(bytes);
        // '<!' can only begin a comment or a forbidden construct: '<'
        // is already illegal inside attribute values and text, so the
        // raw scan is exact.
        if (std.mem.indexOf(u8, bytes, "<!") != null) return error.NotWellFormed;
        try spanCheckLex(bytes);
        var sc = scanner_mod.Scanner.init(alloc);
        defer sc.deinit();
        var pos: usize = 0;
        var depth: usize = 0;
        var names: [max_depth]SpanRange = undefined;
        var attrs: [span_max_attrs]SpanAttr = undefined;
        var attr_count: usize = 0;
        var decls: [span_max_decls]SpanDecl = undefined;
        var decl_count: usize = 0;
        var pending_name: SpanRange = .{ .start = 0, .end = 0 };
        // tag_cursor is where the next tag's '<' is searched from;
        // attr_cursor is where the next attribute name may start.
        var tag_cursor: usize = 0;
        var attr_cursor: usize = 0;
        while (true) {
            const tok = sc.next(bytes, &pos) catch return error.NotWellFormed;
            if (tok == null) break;
            switch (tok.?.type) {
                .element_open => {
                    if (depth >= max_depth) return error.NotWellFormed;
                    const lt = std.mem.indexOfScalarPos(u8, bytes, tag_cursor, '<') orelse
                        return error.NotWellFormed;
                    const name = spanTagName(bytes, lt);
                    if (!isValidName(spanSlice(bytes, name))) return error.NotWellFormed;
                    pending_name = name;
                    attr_cursor = name.end;
                    attr_count = 0;
                },
                .attribute, .namespace_decl => {
                    const head = spanAttrHead(bytes, attr_cursor) orelse
                        return error.NotWellFormed;
                    if (attr_count >= span_max_attrs) return error.NotWellFormed;
                    if (!isValidName(spanSlice(bytes, head.name))) return error.NotWellFormed;
                    for (attrs[0..attr_count]) |p| {
                        if (std.mem.eql(u8, spanSlice(bytes, p.name), spanSlice(bytes, head.name)))
                            return error.NotWellFormed;
                    }
                    attrs[attr_count] = .{ .name = head.name };
                    attr_count += 1;
                    attr_cursor = pos;
                    const dname = spanSlice(bytes, head.name);
                    // xmlns and xmlns:* are namespace declarations.
                    // Classify on the source name, not the token type:
                    // an entity in the value can clobber the name the
                    // scanner carries on the token.
                    if (std.mem.eql(u8, dname, "xmlns") or std.mem.startsWith(u8, dname, "xmlns:")) {
                        if (decl_count >= span_max_decls) return error.NotWellFormed;
                        var prefix: SpanRange = .{ .start = head.name.end, .end = head.name.end };
                        if (std.mem.indexOfScalar(u8, dname, ':')) |colon| {
                            prefix = .{ .start = head.name.start + colon + 1, .end = head.name.end };
                        }
                        // The 'stream' prefix is reserved for the stream
                        // element: inside a stanza-level span it is
                        // rejected whatever it is bound to. The stream
                        // namespace may never be declared here at all;
                        // the decoded value is compared so an
                        // entity-encoded URI cannot slip past.
                        if (std.mem.eql(u8, spanSlice(bytes, prefix), "stream"))
                            return error.NotWellFormed;
                        if (spanStreamDecl(tok.?.value)) return error.NotWellFormed;
                        // Namespaces in XML: a non-empty prefix may not
                        // be unbound (xmlns:p='' is NS 1.0 illegal), the
                        // xml prefix may only bind its own fixed URI,
                        // and nothing else may bind the XML or XMLNS
                        // namespace names, default included.
                        const declared = spanSlice(bytes, prefix);
                        if (declared.len > 0 and tok.?.value.len == 0)
                            return error.NotWellFormed;
                        if (std.mem.eql(u8, declared, "xml")) {
                            if (!std.mem.eql(u8, tok.?.value, xml_ns))
                                return error.NotWellFormed;
                        } else if (std.mem.eql(u8, tok.?.value, xml_ns) or
                            std.mem.eql(u8, tok.?.value, xmlns_ns))
                        {
                            return error.NotWellFormed;
                        }
                        // The stored URI is the raw range between the
                        // value quotes; pos-1 is the closing quote.
                        const oq = std.mem.indexOfAnyPos(u8, bytes, head.eq + 1, "'\"") orelse
                            return error.NotWellFormed;
                        if (oq >= pos - 1) return error.NotWellFormed;
                        const uri: SpanRange = .{ .start = oq + 1, .end = pos - 1 };
                        decls[decl_count] = .{ .depth = depth, .prefix = prefix, .uri = uri };
                        decl_count += 1;
                    }
                },
                .element_open_end => {
                    try spanCheckPrefixes(
                        bytes,
                        spanSlice(bytes, spanQName(bytes, pending_name).prefix),
                        attrs[0..attr_count],
                        decls[0..decl_count],
                    );
                    names[depth] = pending_name;
                    depth += 1;
                    tag_cursor = pos;
                },
                .element_self_close => {
                    try spanCheckPrefixes(
                        bytes,
                        spanSlice(bytes, spanQName(bytes, pending_name).prefix),
                        attrs[0..attr_count],
                        decls[0..decl_count],
                    );
                    // Declarations inside this tag die with it.
                    while (decl_count > 0 and decls[decl_count - 1].depth == depth) decl_count -= 1;
                    tag_cursor = pos;
                },
                .element_close => {
                    if (depth == 0) return error.NotWellFormed;
                    const lt = std.mem.indexOfScalarPos(u8, bytes, tag_cursor, '<') orelse
                        return error.NotWellFormed;
                    // The close name runs from '</' to '>'; trailing
                    // whitespace before '>' is legal and ignored.
                    var end = pos - 1;
                    while (end > lt + 2 and isSpanWs(bytes[end - 1])) end -= 1;
                    const name: SpanRange = .{ .start = lt + 2, .end = end };
                    if (!isValidName(spanSlice(bytes, name))) return error.NotWellFormed;
                    depth -= 1;
                    if (!std.mem.eql(u8, spanSlice(bytes, names[depth]), spanSlice(bytes, name)))
                        return error.NotWellFormed;
                    while (decl_count > 0 and decls[decl_count - 1].depth == depth) decl_count -= 1;
                    tag_cursor = pos;
                },
                .text => {},
                .xml_declaration, .eof => return error.NotWellFormed,
            }
        }
        // A clean stop means the scanner sits in content state with no
        // open element; anything else is a truncated construct.
        if (sc.state != .content or depth != 0) return error.NotWellFormed;
        return .{ .bytes = bytes };
    }
};

pub const StanzaWriter = struct {
    out: *std.Io.Writer,
    /// Latched when the underlying writer reports WriteFailed; once set, no
    /// further bytes are emitted and finish() reports error.Overflow.
    failed: bool = false,
    /// True between elementOpen and elementOpenEnd/elementSelfClose.
    in_start_tag: bool = false,
    /// Open element names, so elementClose can refuse a mismatched
    /// `</other>` instead of emitting it. Callers' names outlive the
    /// writer, so the stack borrows slices instead of copying bytes.
    name_stack: [max_depth][]const u8 = undefined,
    /// Escaping context for the current typed value: attribute values
    /// also escape tab/LF/CR as char refs so a parser cannot turn them
    /// into spaces; text escapes CR so it does not normalize to LF.
    escape_mode: EscapeMode = .text,
    /// Open element depth.
    depth: u16 = 0,

    pub fn init(out: *std.Io.Writer) StanzaWriter {
        return .{ .out = out };
    }

    /// Emits `<name`, opening a start tag. Attributes follow until
    /// elementOpenEnd or elementSelfClose. The name slice is borrowed:
    /// it is kept on the element stack for the later elementClose
    /// match, so it must outlive the writer.
    pub fn elementOpen(self: *StanzaWriter, name: []const u8) Error!void {
        assert(!self.in_start_tag);
        assert(self.depth < max_depth);
        validateName(name) catch |e| {
            self.failed = true;
            return e;
        };
        self.emitByte('<');
        self.emit(name);
        self.in_start_tag = true;
        self.name_stack[self.depth] = name;
        self.depth += 1;
    }

    /// ` name='value'` inside an open start tag. The value is typed:
    /// strings are validated and escaped, integers formatted, enums written
    /// by tag name, bools as "true"/"false", optionals recurse on the
    /// payload (null writes an empty value).
    pub fn attr(self: *StanzaWriter, name: []const u8, value: anytype) Error!void {
        assert(self.in_start_tag);
        validateName(name) catch |e| {
            self.failed = true;
            return e;
        };
        validateValue(value) catch |e| {
            self.failed = true;
            return e;
        };
        self.emitByte(' ');
        self.emit(name);
        self.emit("='");
        self.escape_mode = .attr;
        defer self.escape_mode = .text;
        self.emitTyped(value) catch |e| {
            self.failed = true;
            return e;
        };
        self.emitByte('\'');
    }

    /// attr that omits the attribute entirely when the optional is
    /// null (C1 needs it for absent `id`/`type`).
    pub fn attrOpt(self: *StanzaWriter, name: []const u8, value: anytype) Error!void {
        const inner = switch (@typeInfo(@TypeOf(value))) {
            .optional => value orelse return,
            else => value,
        };
        try self.attr(name, inner);
    }

    /// ` xmlns='uri'` convenience for the common default-namespace
    /// attribute (C1).
    pub fn xmlns(self: *StanzaWriter, uri: []const u8) Error!void {
        try self.attr("xmlns", uri);
    }

    /// Emits `>`, ending an open start tag.
    pub fn elementOpenEnd(self: *StanzaWriter) void {
        assert(self.in_start_tag);
        self.emitByte('>');
        self.in_start_tag = false;
    }

    /// Emits `/>`, ending an open start tag and its element.
    pub fn elementSelfClose(self: *StanzaWriter) void {
        assert(self.in_start_tag);
        assert(self.depth > 0);
        self.emit("/>");
        self.in_start_tag = false;
        self.depth -= 1;
    }

    /// `</name>`.
    pub fn elementClose(self: *StanzaWriter, name: []const u8) Error!void {
        assert(!self.in_start_tag);
        assert(self.depth > 0);
        validateName(name) catch |e| {
            self.failed = true;
            return e;
        };
        const open = self.name_stack[self.depth - 1];
        if (!std.mem.eql(u8, open, name)) {
            self.failed = true;
            return error.MismatchedClose;
        }
        self.emit("</");
        self.emit(name);
        self.emitByte('>');
        self.depth -= 1;
    }

    /// Character data, validated and escaped. Same typed values as attr.
    pub fn text(self: *StanzaWriter, value: anytype) Error!void {
        assert(!self.in_start_tag);
        assert(self.depth > 0);
        validateValue(value) catch |e| {
            self.failed = true;
            return e;
        };
        self.emitTyped(value) catch |e| {
            self.failed = true;
            return e;
        };
    }

    /// Reader-validated markup emitted verbatim, escaping nothing. The
    /// ValidatedSpan type is the enforcement: no plain slice may be
    /// passed, and a span must ride inside an element, never stand
    /// alone at the top level where it could pose as a second stanza.
    pub fn rawSpan(self: *StanzaWriter, span: ValidatedSpan) void {
        assert(!self.in_start_tag);
        assert(self.depth > 0);
        self.emit(span.bytes);
    }

    /// Reports the latched output failure once. Asserts the stanza is
    /// complete (all elements closed) when nothing failed.
    pub fn finish(self: *StanzaWriter) FinishError!void {
        if (self.failed) return error.Overflow;
        assert(self.depth == 0);
        assert(!self.in_start_tag);
    }

    fn emit(self: *StanzaWriter, bytes: []const u8) void {
        if (self.failed) return;
        self.out.writeAll(bytes) catch {
            self.failed = true;
        };
    }

    fn emitByte(self: *StanzaWriter, b: u8) void {
        if (self.failed) return;
        self.out.writeByte(b) catch {
            self.failed = true;
        };
    }

    fn emitFmt(self: *StanzaWriter, comptime fmt: []const u8, args: anytype) void {
        if (self.failed) return;
        self.out.print(fmt, args) catch {
            self.failed = true;
        };
    }

    fn emitEscaped(self: *StanzaWriter, s: []const u8, mode: EscapeMode) void {
        if (self.failed) return;
        writeEscaped(self.out, s, mode) catch {
            self.failed = true;
        };
    }

    /// Validation-only twin of emitTyped: every rejection is decided
    /// before a single output byte is emitted for this value.
    fn validateValue(value: anytype) Error!void {
        const T = @TypeOf(value);
        switch (@typeInfo(T)) {
            .optional => {
                if (value) |v| try validateValue(v);
            },
            .bool, .int, .comptime_int => {},
            .@"enum" => try validateChars(@tagName(value)),
            .pointer => {
                comptime {
                    if (!isStringArg(T)) {
                        @compileError("StanzaWriter: unsupported value type " ++ @typeName(T));
                    }
                }
                const s: []const u8 = value;
                try validateChars(s);
            },
            else => @compileError("StanzaWriter: unsupported value type " ++ @typeName(T)),
        }
    }

    fn emitTyped(self: *StanzaWriter, value: anytype) Error!void {
        const T = @TypeOf(value);
        switch (@typeInfo(T)) {
            .optional => {
                if (value) |v| try self.emitTyped(v);
            },
            .bool => self.emit(if (value) "true" else "false"),
            .int, .comptime_int => self.emitFmt("{d}", .{value}),
            .@"enum" => {
                // validateValue already ran before any byte was emitted.
                self.emitEscaped(@tagName(value), self.escape_mode);
            },
            .pointer => {
                comptime {
                    if (!isStringArg(T)) {
                        @compileError("StanzaWriter: unsupported value type " ++ @typeName(T));
                    }
                }
                self.emitEscaped(value, self.escape_mode);
            },
            else => @compileError("StanzaWriter: unsupported value type " ++ @typeName(T)),
        }
    }
};

/// True for `[]const u8`-compatible arguments: u8 slices and pointers to
/// u8 arrays, which covers string literals.
fn isStringArg(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => |p| (p.size == .slice and p.child == u8) or
            (p.size == .one and switch (@typeInfo(p.child)) {
                .array => |a| a.child == u8,
                else => false,
            }),
        else => false,
    };
}

fn isNcNameStart(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or c == '_';
}

fn isNcNameChar(c: u8) bool {
    return isNcNameStart(c) or (c >= '0' and c <= '9') or c == '-' or c == '.';
}

/// XML QName restricted to ASCII: NCName, optionally 'prefix:local'.
/// Bare colons anywhere else are rejected (":a", "a:", "a:b:c").
pub fn isValidName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_len) return false;
    var parts: usize = 0;
    var start: usize = 0;
    var i: usize = 0;
    while (i <= name.len) : (i += 1) {
        if (i == name.len or name[i] == ':') {
            const part = name[start..i];
            parts += 1;
            if (parts > 2 or part.len == 0) return false;
            if (!isNcNameStart(part[0])) return false;
            for (part[1..]) |c| {
                if (!isNcNameChar(c)) return false;
            }
            start = i + 1;
        }
    }
    return true;
}

fn validateName(name: []const u8) Error!void {
    if (!isValidName(name)) return error.InvalidName;
}

/// Validates UTF-8 well-formedness and the XML Char production
/// (#x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]).
/// Vector scan finds C0 bytes and 0xEF lead bytes; each is checked scalar.
/// 0xEF is the lead byte of U+F000..U+FFFF sequences, so only its U+FFFE
/// and U+FFFF encodings (EF BF BE, EF BF BF) are rejected; utf8ValidateSlice
/// has already ruled out surrogates and values above U+10FFFF.
pub fn validateChars(s: []const u8) Error!void {
    if (!std.unicode.utf8ValidateSlice(s)) return error.InvalidUtf8;
    var i: usize = 0;
    while (i + vec_len <= s.len) : (i += vec_len) {
        const chunk: ByteVec = s[i..][0..vec_len].*;
        const suspect = (chunk < v_ctrl) | (chunk == v_ef);
        var mask: BitMask = @bitCast(suspect);
        while (mask != 0) {
            const idx: usize = @ctz(mask);
            const c = s[i + idx];
            if (c < 0x20) {
                if (c != '\t' and c != '\n' and c != '\r') return error.InvalidCharacter;
            } else {
                // 0xEF leads a valid three-byte sequence, so both
                // continuation bytes are present.
                if (s[i + idx + 1] == 0xBF and (s[i + idx + 2] == 0xBE or s[i + idx + 2] == 0xBF)) {
                    return error.InvalidCharacter;
                }
            }
            mask &= mask - 1;
        }
    }
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c < 0x20) {
            if (c != '\t' and c != '\n' and c != '\r') return error.InvalidCharacter;
        } else if (c == 0xEF) {
            if (s[i + 1] == 0xBF and (s[i + 2] == 0xBE or s[i + 2] == 0xBF)) {
                return error.InvalidCharacter;
            }
        }
    }
}

/// Escaping context: inside a start-tag attribute, tab/LF/CR would be
/// normalized to spaces by any conformant parser, so they are escaped as
/// numeric references; in text only CR needs that protection.
pub const EscapeMode = enum { attr, text };

/// Writes `s` to `w` with the XML escapables replaced by entities (plus
/// the mode's whitespace references). SIMD run-copy: each vector locates
/// escapable bytes and the clean run before each is copied in a single
/// writeAll.
pub fn writeEscaped(w: *std.Io.Writer, s: []const u8, mode: EscapeMode) std.Io.Writer.Error!void {
    var run_start: usize = 0;
    var i: usize = 0;
    while (i + vec_len <= s.len) : (i += vec_len) {
        const chunk: ByteVec = s[i..][0..vec_len].*;
        var mask = escapeMask(chunk, mode);
        while (mask != 0) {
            const idx: usize = @ctz(mask);
            const hit = i + idx;
            try w.writeAll(s[run_start..hit]);
            try w.writeAll(entityFor(s[hit]));
            run_start = hit + 1;
            mask &= mask - 1;
        }
    }
    while (i < s.len) : (i += 1) {
        if (isEscapable(s[i], mode)) {
            try w.writeAll(s[run_start..i]);
            try w.writeAll(entityFor(s[i]));
            run_start = i + 1;
        }
    }
    try w.writeAll(s[run_start..]);
}

const v_tab: ByteVec = @splat('\t');
const v_lf: ByteVec = @splat('\n');
const v_cr: ByteVec = @splat('\r');

fn escapeMask(chunk: ByteVec, mode: EscapeMode) BitMask {
    var hits = (chunk == v_amp) | (chunk == v_lt) | (chunk == v_gt) |
        (chunk == v_apos) | (chunk == v_quot);
    if (mode == .attr) {
        hits = hits | (chunk == v_tab) | (chunk == v_lf) | (chunk == v_cr);
    } else {
        hits = hits | (chunk == v_cr);
    }
    return @bitCast(hits);
}

fn isEscapable(c: u8, mode: EscapeMode) bool {
    if (c == '&' or c == '<' or c == '>' or c == '\'' or c == '"') return true;
    if (mode == .attr) return c == '\t' or c == '\n' or c == '\r';
    return c == '\r';
}

fn entityFor(c: u8) []const u8 {
    return switch (c) {
        '&' => "&amp;",
        '<' => "&lt;",
        '>' => "&gt;",
        '\'' => "&apos;",
        '"' => "&quot;",
        '\t' => "&#9;",
        '\n' => "&#10;",
        '\r' => "&#13;",
        else => unreachable,
    };
}

const assert = std.debug.assert;

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

/// Scalar reference escaper: the differential oracle for writeEscaped.
fn refEscape(w: *std.Io.Writer, s: []const u8, mode: EscapeMode) std.Io.Writer.Error!void {
    for (s) |c| {
        switch (c) {
            '&' => try w.writeAll("&amp;"),
            '<' => try w.writeAll("&lt;"),
            '>' => try w.writeAll("&gt;"),
            '\'' => try w.writeAll("&apos;"),
            '"' => try w.writeAll("&quot;"),
            '\t' => if (mode == .attr) try w.writeAll("&#9;") else try w.writeByte(c),
            '\n' => if (mode == .attr) try w.writeAll("&#10;") else try w.writeByte(c),
            '\r' => try w.writeAll("&#13;"),
            else => try w.writeByte(c),
        }
    }
}

const StanzaType = enum { chat, normal, groupchat };

/// Emits one fixed sample stanza used by the output and overflow tests.
fn writeSample(x: *StanzaWriter) Error!void {
    try x.elementOpen("message");
    try x.attr("from", "alice@example.test");
    try x.attr("to", "bob@example.test");
    try x.attr("type", StanzaType.chat);
    x.elementOpenEnd();
    try x.elementOpen("body");
    x.elementOpenEnd();
    try x.text("Hi & bye <now> \"quoted\" 'q'");
    try x.elementClose("body");
    try x.elementClose("message");
}

test "elements, typed attributes and escaped text serialize correctly" {
    // Goal: verify exact wire bytes for the whole API surface.
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try writeSample(&x);
    try x.finish();

    try testing.expectEqualStrings(
        "<message from='alice@example.test' to='bob@example.test' type='chat'>" ++
            "<body>Hi &amp; bye &lt;now&gt; &quot;quoted&quot; &apos;q&apos;</body></message>",
        w.buffered(),
    );
}

test "typed attribute values: int, bool, enum, optional" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try x.elementOpen("iq");
    try x.attr("n", @as(u32, 42));
    try x.attr("flag", true);
    try x.attr("type", StanzaType.normal);
    const none: ?[]const u8 = null;
    try x.attr("empty", none);
    x.elementSelfClose();
    try x.finish();

    try testing.expectEqualStrings(
        "<iq n='42' flag='true' type='normal' empty=''/>",
        w.buffered(),
    );
}

test "injection: quote in attribute value cannot terminate it" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try x.elementOpen("s");
    try x.attr("a", "x' onload='evil");
    try x.attr("b", "y\" z=\"");
    x.elementOpenEnd();
    try x.text("ok");
    try x.elementClose("s");
    try x.finish();

    try testing.expectEqualStrings(
        "<s a='x&apos; onload=&apos;evil' b='y&quot; z=&quot;'>ok</s>",
        w.buffered(),
    );
}

test "injection: </ and ]]> in text are escaped" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try x.elementOpen("t");
    x.elementOpenEnd();
    try x.text("a</t><evil/>]]>");
    try x.elementClose("t");
    try x.finish();

    try testing.expectEqualStrings("<t>a&lt;/t&gt;&lt;evil/&gt;]]&gt;</t>", w.buffered());
}

test "NUL, control characters and invalid UTF-8 are rejected" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);
    try x.elementOpen("t");
    x.elementOpenEnd();

    try testing.expectError(error.InvalidCharacter, x.text("a\x00b"));
    try testing.expectError(error.InvalidCharacter, x.text("\x01\x02"));
    try testing.expectError(error.InvalidCharacter, x.text("\x0b")); // vertical tab
    try testing.expectError(error.InvalidUtf8, x.text("\xff\xfe"));
    try testing.expectError(error.InvalidUtf8, x.text("ok\xc0")); // truncated lead byte
    // U+FFFE and U+FFFF are valid UTF-8 but outside the XML Char production.
    try testing.expectError(error.InvalidCharacter, x.text("\xef\xbf\xbe"));
    try testing.expectError(error.InvalidCharacter, x.text("\xef\xbf\xbf"));
    // A rejected input latches the writer: the stanza can no longer
    // report success at finish().
    try testing.expectError(error.Overflow, x.finish());
}

test "element and attribute names are validated" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try testing.expectError(error.InvalidName, x.elementOpen("bad name"));
    try testing.expectError(error.InvalidName, x.elementOpen("1digit"));
    try testing.expectError(error.InvalidName, x.elementOpen(""));

    try x.elementOpen("ns:tag");
    try testing.expectError(error.InvalidName, x.attr("na'me", "v"));
    try testing.expectError(error.InvalidName, x.attr("=x", "v"));
    try x.attr("xml:lang", "en");
    x.elementSelfClose();
    // The earlier name rejections are latched: finish() fails.
    try testing.expectError(error.Overflow, x.finish());
}

test "SIMD escaper matches scalar reference, 100000 random inputs" {
    // Goal: differential proof that writeEscaped equals the per-byte
    // reference on arbitrary input, fixed seed for reproducibility.
    var prng = std.Random.DefaultPrng.init(0xF4_1001);
    const rand = prng.random();
    // Alphabet biased toward escapables so hits are dense.
    const alphabet = "ab&<>'\"cd\n\t\r&<>'\"ef&<>'\"gh&<>'\"";
    var input_buf: [300]u8 = undefined;
    var want_buf: [2048]u8 = undefined;
    var got_buf: [2048]u8 = undefined;

    var iter: usize = 0;
    while (iter < 100_000) : (iter += 1) {
        const len = rand.uintLessThan(usize, input_buf.len + 1);
        for (input_buf[0..len]) |*b| {
            b.* = alphabet[rand.uintLessThan(usize, alphabet.len)];
        }
        const input = input_buf[0..len];

        var wwant: std.Io.Writer = .fixed(&want_buf);
        try refEscape(&wwant, input, .text);
        var wgot: std.Io.Writer = .fixed(&got_buf);
        try writeEscaped(&wgot, input, .text);
        try testing.expectEqualStrings(wwant.buffered(), wgot.buffered());

        var wwant2: std.Io.Writer = .fixed(&want_buf);
        try refEscape(&wwant2, input, .attr);
        var wgot2: std.Io.Writer = .fixed(&got_buf);
        try writeEscaped(&wgot2, input, .attr);
        try testing.expectEqualStrings(wwant2.buffered(), wgot2.buffered());
    }
}

test "overflow at every byte boundary fails once at finish" {
    // Goal: any prefix capacity must surface as exactly one Overflow at
    // finish(); a full-size buffer must produce the exact stanza.
    var full_buf: [512]u8 = undefined;
    var wfull: std.Io.Writer = .fixed(&full_buf);
    var xfull = StanzaWriter.init(&wfull);
    try writeSample(&xfull);
    try xfull.finish();
    const expected = wfull.buffered();

    var cap: usize = 0;
    while (cap <= expected.len) : (cap += 1) {
        var buf: [512]u8 = undefined;
        var w: std.Io.Writer = .fixed(buf[0..cap]);
        var x = StanzaWriter.init(&w);
        try writeSample(&x);
        // After failure the writer stays latched: further calls drop bytes
        // and finish() reports the single sticky error.
        if (cap < expected.len) {
            try testing.expectError(error.Overflow, x.finish());
        } else {
            try x.finish();
            try testing.expectEqualStrings(expected, w.buffered());
        }
    }
}

test "writer latches failure and drops later output" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try x.elementOpen("message");
    try x.attr("to", "a@b.c"); // overflows inside the attribute
    x.elementOpenEnd();
    try x.text("more text that cannot fit");

    try testing.expectError(error.Overflow, x.finish());
    // Sticky: a second finish reports the same single failure.
    try testing.expectError(error.Overflow, x.finish());
}

test "StanzaWriter performs zero heap allocations" {
    // Goal: prove the no-allocator contract. The API takes no allocator, so
    // the only proof is structural (no Allocator field anywhere in the
    // writer state) plus behavioral (a full stanza into a caller buffer).
    comptime {
        for (@typeInfo(StanzaWriter).@"struct".fields) |f| {
            std.debug.assert(f.type != std.mem.Allocator);
        }
    }

    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);
    try x.elementOpen("presence");
    try x.attr("from", "a@b.c/r");
    x.elementSelfClose();
    try x.finish();
    try testing.expectEqualStrings("<presence from='a@b.c/r'/>", w.buffered());
}

test "a rejected attribute emits nothing and latches finish() (L1)" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try x.elementOpen("m");
    try testing.expectError(error.InvalidCharacter, x.attr("a", "bad\x00"));
    // Nothing of the attribute reached the output: no name, no quote.
    try testing.expectEqualStrings("<m", w.buffered());
    // The rejection is sticky: finish() cannot report success.
    try testing.expectError(error.Overflow, x.finish());

    // Same for a bad close-tag name and bad text.
    var w2: std.Io.Writer = .fixed(&buf);
    var y = StanzaWriter.init(&w2);
    try y.elementOpen("m");
    y.elementOpenEnd();
    try testing.expectError(error.InvalidName, y.elementClose("bad name"));
    try testing.expectEqualStrings("<m>", w2.buffered());
    try testing.expectError(error.Overflow, y.finish());
}

test "ValidatedSpan rejects malformed or unvalidated markup (L2)" {
    // Rejected: control byte smuggled inside markup, unbalanced tags,
    // mismatched close name, truncated element.
    try testing.expectError(error.InvalidCharacter, ValidatedSpan.fromReader(
        testing.allocator,
        "</m><iq type='set'>\x00",
    ));
    try testing.expectError(
        error.NotWellFormed,
        ValidatedSpan.fromReader(testing.allocator, "<a></b>"),
    );
    try testing.expectError(
        error.NotWellFormed,
        ValidatedSpan.fromReader(testing.allocator, "<a>"),
    );
    try testing.expectError(
        error.NotWellFormed,
        ValidatedSpan.fromReader(testing.allocator, "</a>"),
    );

    // Accepted: balanced elements and bare text both scan cleanly.
    _ = try ValidatedSpan.fromReader(testing.allocator, "<c><d t='1'/>x</c>");
    _ = try ValidatedSpan.fromReader(testing.allocator, "plain text &amp; entities");

    // And a rejected span cannot reach the output at all.
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);
    try x.elementOpen("iq");
    x.elementOpenEnd();
    try testing.expectError(error.InvalidCharacter, ValidatedSpan.fromReader(
        testing.allocator,
        "</m><iq type='set'>\x00",
    ));
    try x.elementClose("iq");
    try x.finish();
    try testing.expectEqualStrings("<iq></iq>", w.buffered());
}

test "attribute whitespace and text CR escape as char refs (L3)" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try x.elementOpen("m");
    try x.attr("a", "t\tn\n r\rs");
    x.elementOpenEnd();
    try x.text("l1\rl2\nl3");
    try x.elementClose("m");
    try x.finish();

    try testing.expectEqualStrings(
        "<m a='t&#9;n&#10; r&#13;s'>l1&#13;l2\nl3</m>",
        w.buffered(),
    );
}

/// A writer whose drain fails once, then accepts everything. Pins the
/// sticky-failure mutation where a later successful write clears `failed`.
const FailOnceWriter = struct {
    w: std.Io.Writer,
    failed_once: bool = false,
    accepted: usize = 0,

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *FailOnceWriter = @fieldParentPtr("w", w);
        if (!self.failed_once) {
            self.failed_once = true;
            return error.WriteFailed;
        }
        var n: usize = 0;
        for (data) |d| n += d.len * splat;
        self.accepted += n;
        return n;
    }

    fn make() FailOnceWriter {
        return .{ .w = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} } };
    }
};

test "a transient writer failure stays latched through later writes (L4)" {
    var fo = FailOnceWriter.make();
    var x = StanzaWriter.init(&fo.w);

    // First emit hits the one-shot WriteFailed; every later emit goes
    // through fine, but finish() must still report the failure.
    try x.elementOpen("m");
    try x.attr("a", "still-written");
    x.elementOpenEnd();
    try x.text("accepted bytes");
    try x.elementClose("m");

    // Correct latching drops every later byte (accepted stays 0); a
    // mutation that clears `failed` on a good write would both emit
    // them and let finish() pass.
    try testing.expectEqual(@as(usize, 0), fo.accepted);
    try testing.expectError(error.Overflow, x.finish());
    try testing.expectError(error.Overflow, x.finish());
}

test "rejection at every byte position across lengths 0..67 (L4)" {
    // Goal: the vector path and the scalar tail must both reject; a bad
    // byte anywhere, at any length, for each rejection class.
    const bads = [_]u8{ 0x00, 0x01, 0x1F, 0xFF, 0x80, 0xC0 };
    var s: [70]u8 = undefined;
    var len: usize = 0;
    while (len <= 67) : (len += 1) {
        const base = s[0..len];
        @memset(base, 'a');
        for (0..len) |pos| {
            for (bads) |bad| {
                base[pos] = bad;
                if (bad < 0x20) {
                    try testing.expectError(error.InvalidCharacter, validateChars(base));
                } else {
                    try testing.expectError(error.InvalidUtf8, validateChars(base));
                }
                base[pos] = 'a';
            }
            // Noncharacters U+FFFE/U+FFFF embedded at this position.
            if (pos + 3 <= len) {
                @memcpy(base[pos .. pos + 3], "\xef\xbf\xbe");
                try testing.expectError(error.InvalidCharacter, validateChars(base));
                base[pos + 2] = 0xbf;
                try testing.expectError(error.InvalidCharacter, validateChars(base));
                @memcpy(base[pos .. pos + 3], "aaa");
            }
        }
        // The clean baseline itself is always accepted.
        try validateChars(base);
    }
}

test "elementClose refuses a mismatched close name" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try x.elementOpen("message");
    x.elementOpenEnd();
    try x.elementOpen("body");
    x.elementOpenEnd();
    try testing.expectError(error.MismatchedClose, x.elementClose("iq"));
    // Latched like every other rejection.
    try testing.expectError(error.Overflow, x.finish());
    try testing.expectEqualStrings("<message><body>", w.buffered());
}

test "names must be QName: at most one colon, NCName on each side" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try testing.expectError(error.InvalidName, x.elementOpen(":a"));
    try testing.expectError(error.InvalidName, x.elementOpen("a:"));
    try testing.expectError(error.InvalidName, x.elementOpen("a:b:c"));
    try testing.expectError(error.InvalidName, x.elementOpen("xmlns:"));
    // First character rules still apply inside each part.
    try testing.expectError(error.InvalidName, x.elementOpen("a:1b"));
    try testing.expectError(error.Overflow, x.finish());

    var w2: std.Io.Writer = .fixed(&buf);
    var y = StanzaWriter.init(&w2);
    try y.elementOpen("stream:stream");
    try y.attrOpt("type", @as(?[]const u8, null)); // omitted entirely
    try y.attrOpt("id", @as(?[]const u8, "s1"));
    try y.xmlns("jabber:client");
    y.elementSelfClose();
    try y.finish();
    try testing.expectEqualStrings(
        "<stream:stream id='s1' xmlns='jabber:client'/>",
        w2.buffered(),
    );
}

test "a name at the 256-byte limit writes; one over is rejected (L5)" {
    var buf: [600]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    // 256 bytes is the largest legal name: it must round-trip without
    // crashing the name stack (the old fixed-byte stack overflowed).
    var long_name: [256]u8 = undefined;
    @memset(&long_name, 'n');
    try x.elementOpen(&long_name);
    x.elementSelfClose();
    try x.finish();

    var w2: std.Io.Writer = .fixed(&buf);
    var y = StanzaWriter.init(&w2);
    var over_name: [257]u8 = undefined;
    @memset(&over_name, 'n');
    try testing.expectError(error.InvalidName, y.elementOpen(&over_name));
    try testing.expectError(error.Overflow, y.finish());
}

test "ValidatedSpan rejects every forbidden or malformed probe (L6)" {
    const bad = [_][]const u8{
        "<a", // truncated element
        "<a/><", // truncated after a complete element
        "<!-- c --><a/>", // comment before the element
        "<a/><!-- c -->", // trailing comment
        "<?xml version='1.0'?><a/>", // xml declaration
        "<a><?pi data?></a>", // processing instruction
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams'></stream:stream>",
        "<stream:error/>",
        "<x:stream xmlns:x='http://etherx.jabber.org/streams'/>",
        "<error xmlns='http://etherx.jabber.org/streams'/>",
        "<a><f:error xmlns:f='http://etherx.jabber.org/streams'/></a>",
        "<a>&#0;</a>", // character reference to a non-Char
        "<a>&#x1;</a>",
        "<a x='1<'/>", // '<' inside an attribute value
        "<a x=<'1'/>", // '<' where the quote belongs
        "<a x=1/>", // unquoted attribute value
        "<a x='1'y='2'/>", // adjacent attributes
        "<a>x ]]> y</a>", // ']]>' in text
        "<a xmlns:xmlns='urn:x'/>", // xmlns:xmlns is never declarable
        "<a x='1' x='2'/>", // duplicate attribute
        "<1a/>", // invalid element name
        "<a 1b='v'/>", // invalid attribute name
        "<u:a xmlns:v='urn:v'/>", // undeclared element prefix
        "<a u:b='1'/>", // undeclared attribute prefix
        "<a></b>", // mismatched close
        "</a>", // stray close
        "<a>", // unbalanced element
        "<a xmlns:u='urn:u' xmlns:u='urn:v'/>", // duplicate declaration
    };
    for (bad) |probe| {
        try testing.expectError(
            error.NotWellFormed,
            ValidatedSpan.fromReader(testing.allocator, probe),
        );
    }

    const good = [_][]const u8{
        "<c><d t='1'/>x</c>",
        "plain text &amp; entities",
        "<u:a xmlns:u='urn:u' u:b='1' xml:lang='en'><u:c/></u:a>",
        "<e xmlns='urn:d' x='v'/>",
        "<a>text &amp; &#233;tities</a>",
    };
    for (good) |probe| {
        _ = try ValidatedSpan.fromReader(testing.allocator, probe);
    }
}

test "a literal '<' in an attribute value is rejected" {
    // The '<' check runs on the source bytes: an entity-produced '<'
    // like &lt; is well-formed and becomes acceptable once the scanner
    // entity fix lands; a literal '<' inside the quotes never is.
    try testing.expectError(
        error.NotWellFormed,
        ValidatedSpan.fromReader(testing.allocator, "<a x='<'/>"),
    );
    try testing.expectError(
        error.NotWellFormed,
        ValidatedSpan.fromReader(testing.allocator, "<a x=\"a<b\"/>"),
    );
}

test "span names, prefixes and URIs are caller byte ranges (R4-1)" {
    // Sibling elements at depth <= 1: a scanner that resets its token
    // arena at each '<' frees token slices kept across next(), so the
    // span check tracks ranges into the caller's bytes instead. These
    // siblings exercise that reset path whichever scanner is present.
    _ = try ValidatedSpan.fromReader(testing.allocator, "<a><b/><c/></a>");
    _ = try ValidatedSpan.fromReader(testing.allocator, "<a/><b/>");
    _ = try ValidatedSpan.fromReader(testing.allocator, "<a xmlns:p='urn:u'><b/><p:c x='1'/><d/></a>");
    _ = try ValidatedSpan.fromReader(testing.allocator, "<a xmlns:p='urn:u'><b xmlns:p='urn:v'/><p:c/></a>");

    // A mismatched close is still caught against the recorded range.
    try testing.expectError(error.NotWellFormed, ValidatedSpan.fromReader(testing.allocator, "<a></b>"));
    try testing.expectError(error.NotWellFormed, ValidatedSpan.fromReader(testing.allocator, "<a><b/><c/></d>"));

    // Whitespace the tag grammar allows is legal input; names derived
    // from the source bytes accept it regardless of how the scanner
    // buffers names.
    _ = try ValidatedSpan.fromReader(testing.allocator, "<a></a >");
    _ = try ValidatedSpan.fromReader(testing.allocator, "<a x = '1'/>");
    _ = try ValidatedSpan.fromReader(testing.allocator, "<a x =\t'1'/>");
    _ = try ValidatedSpan.fromReader(testing.allocator, "<a x='&lt;'/>");
    _ = try ValidatedSpan.fromReader(testing.allocator, "<a x='a&lt;b'/>");
    _ = try ValidatedSpan.fromReader(testing.allocator, "<a x='&#60;'/>");

    // A '/' only closes the tag when '>' follows it; otherwise it is
    // name content and the name is invalid.
    try testing.expectError(error.NotWellFormed, ValidatedSpan.fromReader(testing.allocator, "<a//>"));
    try testing.expectError(error.NotWellFormed, ValidatedSpan.fromReader(testing.allocator, "<a/b x='1'/>"));
}

test "spans reject the stream prefix and stream namespace declarations (R4-2)" {
    // xmppd's reader classifies stream elements by the literal 'stream'
    // prefix, so a span may not carry that prefix whatever it is bound
    // to, and may not declare the stream namespace at all (used or not).
    const bad = [_][]const u8{
        "<stream:stream xmlns:stream='urn:evil'></stream:stream>",
        "<stream:features xmlns:stream='urn:evil'/>",
        "<stream:error xmlns:stream='urn:x'/>",
        "<stream:x/>",
        "<a><stream:features xmlns:stream='urn:x'/></a>",
        "<a xmlns:stream='urn:x'><b/></a>",
        "<a xmlns:s='http://etherx.jabber.org/streams'><b/></a>",
        "<a xmlns:s='http://etherx.jabber.org/streams'><s:b xmlns:s='urn:x'/></a>",
        "<a xmlns:s='http://etherx.jabber.org/streams' s:x='1'/>",
        "<a xmlns='http://etherx.jabber.org/streams'><b/></a>",
        "<a><b/><c xmlns:s='http://etherx.jabber.org/streams'/></a>",
        "<a xmlns:s='http://etherx.jabber.org/str&#101;ams'/>",
    };
    for (bad) |probe| {
        try testing.expectError(
            error.NotWellFormed,
            ValidatedSpan.fromReader(testing.allocator, probe),
        );
    }
    // Ordinary prefixes and namespaces are unaffected.
    _ = try ValidatedSpan.fromReader(testing.allocator, "<a xmlns:s='urn:x'><s:b/></a>");
    _ = try ValidatedSpan.fromReader(testing.allocator, "<a xmlns='urn:x'><b/></a>");
}

test "spans enforce Namespaces in XML constraints (R4-3)" {
    // A strict peer parser drops the stream on any of these.
    const bad = [_][]const u8{
        "<a xmlns:xml='urn:x'/>", // the xml prefix may not be rebound
        "<a xmlns:xml='http://www.w3.org/2000/xmlns/'/>",
        "<a xmlns:q='http://www.w3.org/XML/1998/namespace'/>", // xml URI bound elsewhere
        "<a xmlns='http://www.w3.org/XML/1998/namespace'/>",
        "<a xmlns:q='http://www.w3.org/2000/xmlns/'/>", // xmlns URI bound at all
        "<a xmlns='http://www.w3.org/2000/xmlns/'/>",
        "<a xmlns:p=''/>", // prefix undeclare is NS 1.0 illegal
        "<a xmlns:p=\"\"/>",
        "<a xmlns:p='urn:u' xmlns:q='urn:u' p:x='1' q:x='2'/>", // dup expanded name
    };
    for (bad) |probe| {
        try testing.expectError(
            error.NotWellFormed,
            ValidatedSpan.fromReader(testing.allocator, probe),
        );
    }
    const good = [_][]const u8{
        "<a xmlns:xml='http://www.w3.org/XML/1998/namespace'/>",
        "<a xmlns:p='urn:u' xmlns:q='urn:v' p:x='1' q:x='2'/>",
        "<a xml:lang='en' xml:space='preserve'/>",
        "<a xmlns=''/>",
    };
    for (good) |probe| {
        _ = try ValidatedSpan.fromReader(testing.allocator, probe);
    }
}

test "ValidatedSpan accepts depth 64 and rejects depth 65" {
    var buf: [512]u8 = undefined;
    var pos: usize = 0;
    for (0..64) |d| {
        buf[pos] = '<';
        buf[pos + 1] = 'a' + @as(u8, @intCast(d % 26));
        buf[pos + 2] = '>';
        pos += 3;
    }
    for (0..64) |d| {
        buf[pos] = '<';
        buf[pos + 1] = '/';
        buf[pos + 2] = 'a' + @as(u8, @intCast((63 - d) % 26));
        buf[pos + 3] = '>';
        pos += 4;
    }
    _ = try ValidatedSpan.fromReader(testing.allocator, buf[0..pos]);

    // One more level of nesting exceeds the name stack bound.
    var deep: [512]u8 = undefined;
    pos = 0;
    for (0..65) |d| {
        deep[pos] = '<';
        deep[pos + 1] = 'a' + @as(u8, @intCast(d % 26));
        deep[pos + 2] = '>';
        pos += 3;
    }
    try testing.expectError(
        error.NotWellFormed,
        ValidatedSpan.fromReader(testing.allocator, deep[0..pos]),
    );
}

test "legal tab, LF, CR and multi-byte UTF-8 are accepted (L7)" {
    // At least vec_len bytes so the SIMD path proves it does not
    // reject the whitespace characters it scans as suspects.
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var x = StanzaWriter.init(&w);

    try x.elementOpen("m");
    x.elementOpenEnd();
    // Over 128 bytes so the SIMD suspect scan runs at full width.
    try x.text("tab\there line\nfeed cr\r and multi-byte \xc3\xa9\xf0\x9f\x98\x80 chars, padded past the vector width with plain ascii words to keep scanning");
    try x.elementClose("m");
    try x.finish();

    try testing.expectEqualStrings(
        "<m>tab\there line\nfeed cr&#13; and multi-byte \xc3\xa9\xf0\x9f\x98\x80 chars, padded past the vector width with plain ascii words to keep scanning</m>",
        w.buffered(),
    );
}
