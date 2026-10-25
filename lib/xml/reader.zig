const std = @import("std");
pub const scanner = @import("scanner.zig");

pub const Scanner = scanner.Scanner;
pub const Token = scanner.Token;
pub const TokenType = scanner.TokenType;

/// XMPP namespace URIs
pub const ns = struct {
    pub const streams = "http://etherx.jabber.org/streams";
    pub const client = "jabber:client";
    pub const server = "jabber:server";
    pub const tls = "urn:ietf:params:xml:ns:xmpp-tls";
    pub const sasl = "urn:ietf:params:xml:ns:xmpp-sasl";
    pub const bind = "urn:ietf:params:xml:ns:xmpp-bind";
    pub const session = "urn:ietf:params:xml:ns:xmpp-session";
    pub const stanzas = "urn:ietf:params:xml:ns:xmpp-stanzas";
    pub const roster = "jabber:iq:roster";
    pub const disco_info = "http://jabber.org/protocol/disco#info";
    pub const disco_items = "http://jabber.org/protocol/disco#items";
    pub const muc = "http://jabber.org/protocol/muc";
    pub const muc_user = "http://jabber.org/protocol/muc#user";
    pub const muc_admin = "http://jabber.org/protocol/muc#admin";
    pub const muc_owner = "http://jabber.org/protocol/muc#owner";
    pub const ping = "urn:xmpp:ping";
    pub const carbons = "urn:xmpp:carbons:2";
    pub const mam = "urn:xmpp:mam:2";
    pub const sm = "urn:xmpp:sm:3";
    pub const vcard_temp = "vcard-temp";
    pub const version = "jabber:iq:version";
    pub const delay = "urn:xmpp:delay";
    pub const dialback = "jabber:server:dialback";
    pub const db = "urn:xmpp:features:dialback";
    pub const register = "jabber:iq:register";
    pub const register_feature = "http://jabber.org/features/iq-register";
    pub const blocking = "urn:xmpp:blocking";
    pub const pubsub = "http://jabber.org/protocol/pubsub";
    pub const pubsub_owner = "http://jabber.org/protocol/pubsub#owner";
    pub const pubsub_event = "http://jabber.org/protocol/pubsub#event";
    pub const last = "jabber:iq:last";
    pub const csi = "urn:xmpp:csi:0";
};

/// An XML element with its attributes and namespace context.
pub const Element = struct {
    name: []const u8,
    prefix: []const u8,
    local_name: []const u8,
    namespace_uri: []const u8,
    attributes: []const Attribute,
    self_closing: bool,
};

/// An attribute on an element.
pub const Attribute = struct {
    name: []const u8,
    value: []const u8,
    prefix: []const u8,
    local_name: []const u8,
};

/// Events emitted by the XMPP stream reader.
pub const Event = union(enum) {
    /// Stream opened (the `<stream:stream>` tag with its attributes)
    stream_open: Element,
    /// Stream closed (`</stream:stream>`)
    stream_close,
    /// An element has started (stanza or child element)
    element_start: Element,
    /// An element has ended
    element_end: []const u8,
    /// Text content within an element
    text: []const u8,
    /// XML declaration received
    xml_declaration,
};

/// Streaming XMPP XML reader.
///
/// Wraps the low-level scanner to produce higher-level events suitable
/// for XMPP stream processing. Tracks namespace context and element depth.
///
/// Event payload lifetime: `element_start`, `element_end` and `text` payloads
/// are borrowed from the stanza arena and stay valid until the next root or
/// top-level `element_open` resets it. Consumers must copy anything retained
/// across items. The stream root name and namespace context live in `ns_arena`
/// and survive stanza resets until `reset()`.
/// Maximum number of namespace prefix bindings (XMPP uses very few)
const max_ns_bindings = 16;

/// Maximum element nesting the namespace tracking supports. Servers
/// enforce their own (smaller) stanza depth limit; the mark and default-ns
/// stacks are sized from this and fail with error.TooDeep as a backstop,
/// so push and pop can never desync (S12).
pub const max_ns_depth = 64;

/// Retained capacity limits for the two arenas after a reset, so one
/// oversized stanza (or stream header) cannot pin a large buffer for the
/// life of the connection (S26). Sized well above the server's stanza cap.
const max_arena_retain = 64 * 1024;
const max_ns_arena_retain = 4 * 1024;
const max_attributes_per_element = 64;

const NsBinding = struct {
    prefix: []const u8,
    uri: []const u8,
};

pub const Reader = struct {
    scan: Scanner,
    /// Current element depth (0 = outside stream, 1 = inside stream, 2+ = inside stanza)
    depth: u32 = 0,
    /// Accumulated attributes for the current element being opened
    attrs: std.ArrayList(Attribute) = .{},
    attribute_count: u32 = 0,
    /// Namespace prefix-to-URI bindings for the current scope
    ns_bindings: [max_ns_bindings]NsBinding = undefined,
    ns_binding_count: u32 = 0,
    /// Element-scoped marks: element_open pushes the current binding count;
    /// the matching close restores it. A redeclared prefix on a nested
    /// stanza then shadows the outer one only for that element's lifetime
    /// (T232); `resolveNamespace` always prefers the newest binding.
    ns_marks: [max_ns_depth]u32 = undefined,
    ns_mark_depth: u32 = 0,
    /// Default namespace URI
    default_ns: []const u8 = "",
    /// Namespace stack — saves default_ns on element_open, restores on element_close.
    /// Sized to max_ns_depth so any depth a consumer allows stays synced (S12).
    ns_stack: [max_ns_depth][]const u8 = undefined,
    ns_stack_depth: u32 = 0,
    /// Open-element name stack: element_open_end pushes, element_close pops
    /// and must match. A close with no match is stray or mismatched and a
    /// not-well-formed error (S11).
    elem_names: [max_ns_depth][]const u8 = undefined,
    elem_depth: u32 = 0,
    /// Whether we're inside the stream element
    stream_opened: bool = false,
    /// Arena for element/attribute data; reset at every top-level stanza
    /// open so a long-lived stream does not accumulate tokens (S11).
    arena: std.heap.ArenaAllocator,
    /// Arena for stream-level (depth 0) namespace declarations; these must
    /// survive the per-stanza reset for the life of the stream.
    ns_arena: std.heap.ArenaAllocator,
    /// Allocator for dynamic collections
    allocator: std.mem.Allocator,
    /// Name of the element currently being assembled
    current_element_name: []const u8 = "",
    current_element_prefix: []const u8 = "",
    current_element_local: []const u8 = "",

    pub fn init(allocator: std.mem.Allocator) Reader {
        return .{
            .scan = Scanner.init(allocator),
            .arena = std.heap.ArenaAllocator.init(allocator),
            .ns_arena = std.heap.ArenaAllocator.init(allocator),
            .allocator = allocator,
        };
    }

    pub fn setMaxItemBytes(self: *Reader, max_bytes: usize) void {
        self.scan.setMaxItemBytes(max_bytes);
    }

    pub fn deinit(self: *Reader) void {
        self.scan.deinit();
        self.attrs.deinit(self.allocator);
        self.arena.deinit();
        self.ns_arena.deinit();
    }

    /// Feed input data and get the next XMPP stream event.
    /// Returns null if more data is needed.
    pub fn next(self: *Reader, input: []const u8, pos: *usize) !?Event {
        while (true) {
            const token = try self.scan.next(input, pos) orelse return null;

            switch (token.type) {
                .xml_declaration => {
                    return Event.xml_declaration;
                },
                .element_open => {
                    if (self.depth <= 1) {
                        // Every root or top-level stanza starts a new item.
                        // Reset by depth even for a rejected root; the stream
                        // root name and namespace context remain in ns_arena.
                        // Bound retained capacity independently of stanza size.
                        _ = self.arena.reset(.{ .retain_with_limit = max_arena_retain });
                    }
                    self.current_element_name = try self.arenaDupe(token.name);
                    self.current_element_prefix = try self.arenaDupe(token.prefix);
                    self.current_element_local = try self.arenaDupe(token.local_name);
                    self.attrs.clearRetainingCapacity();
                    self.attribute_count = 0;
                    // Scope mark: the matching close restores this many bindings.
                    // Both stacks advance in lockstep; full is a hard error,
                    // never a silent skip (S12).
                    if (self.ns_mark_depth >= self.ns_marks.len or
                        self.ns_stack_depth >= self.ns_stack.len) return error.TooDeep;
                    self.ns_marks[self.ns_mark_depth] = self.ns_binding_count;
                    self.ns_mark_depth += 1;
                    // Push current default namespace before this element's xmlns decls modify it
                    self.ns_stack[self.ns_stack_depth] = self.default_ns;
                    self.ns_stack_depth += 1;
                },
                .namespace_decl => {
                    try self.accountAttribute();
                    const uri = try self.nsDupe(token.value);
                    if (token.prefix.len == 0) {
                        // Default namespace
                        self.default_ns = uri;
                    } else {
                        const prefix = try self.nsDupe(token.prefix);
                        if (self.ns_binding_count >= max_ns_bindings) return error.TooManyNsBindings;
                        self.ns_bindings[self.ns_binding_count] = .{
                            .prefix = prefix,
                            .uri = uri,
                        };
                        self.ns_binding_count += 1;
                    }
                },
                .attribute => {
                    try self.accountAttribute();
                    try self.attrs.append(self.allocator, .{
                        .name = try self.arenaDupe(token.name),
                        .value = try self.arenaDupe(token.value),
                        .prefix = try self.arenaDupe(token.prefix),
                        .local_name = try self.arenaDupe(token.local_name),
                    });
                },
                .element_open_end => {
                    const elem = self.buildElement(false);
                    const is_stream_elem = std.mem.eql(u8, elem.namespace_uri, "http://etherx.jabber.org/streams") and
                        std.mem.eql(u8, self.current_element_local, "stream");
                    // A root must be an open stream element: a non-stream
                    // root, or a stream root whose prefix is unbound, is not
                    // an XMPP stream and is a stream error (E1).
                    if (self.depth == 0 and !is_stream_elem) return error.InvalidStreamRoot;
                    self.depth += 1;
                    if (self.elem_depth >= self.elem_names.len) return error.TooDeep;
                    // The root name is matched again at its close, which comes
                    // after every per-stanza reset. The stanza arena reuses that
                    // slot for the next stanza's first token, so the root goes to
                    // ns_arena, which lives until reset() (S11).
                    self.elem_names[self.elem_depth] = if (self.elem_depth == 0)
                        try self.ns_arena.allocator().dupe(u8, self.current_element_name)
                    else
                        self.current_element_name;
                    self.elem_depth += 1;
                    // For non-self-closing elements, namespace is restored on element_close

                    // The stream root is matched by namespace + local name, not
                    // by the literal "stream" prefix, so a differently-prefixed
                    // stream element is still recognized and any nested one is
                    // rejected (S27).
                    if (is_stream_elem) {
                        if (self.depth != 1) {
                            // Nested inside an open stream: protocol
                            // violation (S27).
                            return error.NestedStreamElement;
                        }
                        self.stream_opened = true;
                        return Event{ .stream_open = elem };
                    }

                    return Event{ .element_start = elem };
                },
                .element_self_close => {
                    // A self-closing root is never a valid stream open (E1).
                    if (self.depth == 0) return error.InvalidStreamRoot;
                    self.depth += 1;
                    const elem = self.buildElement(true);

                    // Only a streams-namespace <stream:stream> is a stream
                    // open; any other stream-prefixed child (a legal empty
                    // <stream:features/>) is an ordinary element (S27).
                    if (std.mem.eql(u8, elem.namespace_uri, "http://etherx.jabber.org/streams") and
                        std.mem.eql(u8, self.current_element_local, "stream"))
                    {
                        // Nested inside an open stream: protocol violation (S27).
                        return error.NestedStreamElement;
                    }

                    self.depth -= 1;
                    // Scope ends immediately: pop the ns mark and default ns.
                    if (self.ns_mark_depth > 0) {
                        self.ns_mark_depth -= 1;
                        self.ns_binding_count = self.ns_marks[self.ns_mark_depth];
                    }
                    // Restore the parent's default namespace — self-closing element's
                    // xmlns scope ends immediately.
                    if (self.ns_stack_depth > 0) {
                        self.ns_stack_depth -= 1;
                        self.default_ns = self.ns_stack[self.ns_stack_depth];
                    }
                    return Event{ .element_start = elem };
                },
                .element_close => {
                    // The close must match the innermost open element: a
                    // stray or mismatched close would otherwise desync depth
                    // and defeat the per-stanza arena reset (S11).
                    if (self.elem_depth == 0 or
                        !std.mem.eql(u8, self.elem_names[self.elem_depth - 1], token.name))
                    {
                        return error.MismatchedCloseTag;
                    }
                    self.elem_depth -= 1;
                    self.depth -= 1;
                    // Pop the ns scope mark: any prefix bound inside this
                    // element's tag disappears with the element.
                    if (self.ns_mark_depth > 0) {
                        self.ns_mark_depth -= 1;
                        self.ns_binding_count = self.ns_marks[self.ns_mark_depth];
                    }
                    // Restore the parent's default namespace
                    if (self.ns_stack_depth > 0) {
                        self.ns_stack_depth -= 1;
                        self.default_ns = self.ns_stack[self.ns_stack_depth];
                    }

                    // Stream close: the validated root close (the name check
                    // above matched elem_names[0]). Detected by closing the
                    // root while a stream is open, not by the literal prefix,
                    // so a differently-prefixed stream root closes cleanly (S27).
                    if (self.elem_depth == 0 and self.stream_opened) {
                        self.stream_opened = false;
                        return Event.stream_close;
                    }

                    return Event{ .element_end = try self.arenaDupe(token.name) };
                },
                .text => {
                    if (token.name.len > 0) {
                        if (self.depth >= 2) {
                            return Event{ .text = try self.arenaDupe(token.name) };
                        }
                        // The scanner drops depth-1 whitespace. Any text token
                        // emitted here contains non-whitespace, which RFC 6120
                        // 4.6.1 forbids at stream level.
                        return error.StreamLevelText;
                    }
                },
                .eof => return null,
            }
        }
    }

    /// Get the current stanza depth (0 = stream level, 1 = stanza level, 2+ = inside stanza)
    pub fn stanzaDepth(self: *const Reader) u32 {
        if (self.depth == 0) return 0;
        return self.depth - 1;
    }

    /// Resolve a namespace prefix to its URI. Newest binding wins: a
    /// redeclared prefix on a nested element correctly shadows the outer
    /// one until its scope closes (T232).
    pub fn resolveNamespace(self: *const Reader, prefix: []const u8) []const u8 {
        if (prefix.len == 0) return self.default_ns;
        var i = self.ns_binding_count;
        while (i > 0) {
            i -= 1;
            if (std.mem.eql(u8, self.ns_bindings[i].prefix, prefix)) {
                return self.ns_bindings[i].uri;
            }
        }
        return "";
    }

    fn buildElement(self: *Reader, self_closing: bool) Element {
        const namespace_uri = self.resolveNamespace(self.current_element_prefix);
        return Element{
            .name = self.current_element_name,
            .prefix = self.current_element_prefix,
            .local_name = self.current_element_local,
            .namespace_uri = namespace_uri,
            .attributes = self.attrs.items,
            .self_closing = self_closing,
        };
    }

    fn arenaDupe(self: *Reader, s: []const u8) ![]const u8 {
        return try self.arena.allocator().dupe(u8, s);
    }

    /// Dupe namespace strings: declarations on the stream element (depth 0)
    /// go to the long-lived ns_arena so they survive the per-stanza reset;
    /// stanza-level declarations die with the stanza.
    fn nsDupe(self: *Reader, s: []const u8) ![]const u8 {
        const a = if (self.depth == 0) self.ns_arena.allocator() else self.arena.allocator();
        return try a.dupe(u8, s);
    }

    fn accountAttribute(self: *Reader) !void {
        if (self.attribute_count >= max_attributes_per_element) return error.TooManyAttributes;
        self.attribute_count += 1;
    }

    /// Reset the reader for a new stream (e.g., after STARTTLS or SASL reset).
    /// Clears both the Reader state and the underlying Scanner so a fresh
    /// XML stream can be parsed from scratch.
    pub fn reset(self: *Reader) void {
        self.depth = 0;
        self.elem_depth = 0;
        self.stream_opened = false;
        self.default_ns = "";
        self.ns_stack_depth = 0;
        self.ns_binding_count = 0;
        self.ns_mark_depth = 0;
        self.current_element_name = "";
        self.current_element_prefix = "";
        self.current_element_local = "";
        self.attrs.clearRetainingCapacity();
        self.attribute_count = 0;
        _ = self.arena.reset(.{ .retain_with_limit = max_arena_retain });
        _ = self.ns_arena.reset(.{ .retain_with_limit = max_ns_arena_retain });
        self.scan.reset();
    }
};

// --- Tests ---

/// Write `value` XML-escaped, suitable for attribute values (quoted with
/// either quote style) and character data: & < > ' " are entity-encoded.
/// The scanner decodes entities on read, so parsed content must be
/// re-encoded when re-emitted; writing decoded values raw enables stanza
/// injection via quote breakout (S1).
pub fn escapeWrite(writer: anytype, value: []const u8) !void {
    for (value) |c| {
        switch (c) {
            '&' => try writer.writeAll("&amp;"),
            '<' => try writer.writeAll("&lt;"),
            '>' => try writer.writeAll("&gt;"),
            '\'' => try writer.writeAll("&apos;"),
            '"' => try writer.writeAll("&quot;"),
            else => try writer.writeByte(c),
        }
    }
}

/// Decode the five predefined entities and numeric character references,
/// writing the decoded bytes. The inverse of escapeWrite, for content that
/// was captured from escaped XML text (for example an accumulated stanza
/// buffer) and must be stored decoded. Malformed or unknown references and
/// code points outside the XML Char production are rejected.
pub fn decodeWrite(writer: anytype, value: []const u8) !void {
    var i: usize = 0;
    while (i < value.len) {
        const c = value[i];
        if (c != '&') {
            try writer.writeByte(c);
            i += 1;
            continue;
        }
        const semi = std.mem.indexOfScalarPos(u8, value, i, ';') orelse return error.InvalidEntityReference;
        const name = value[i + 1 .. semi];
        if (std.mem.eql(u8, name, "amp")) {
            try writer.writeByte('&');
        } else if (std.mem.eql(u8, name, "lt")) {
            try writer.writeByte('<');
        } else if (std.mem.eql(u8, name, "gt")) {
            try writer.writeByte('>');
        } else if (std.mem.eql(u8, name, "apos")) {
            try writer.writeByte('\'');
        } else if (std.mem.eql(u8, name, "quot")) {
            try writer.writeByte('"');
        } else if (name.len > 1 and name[0] == '#') {
            const cp: u21 = if (name.len > 2 and (name[1] == 'x' or name[1] == 'X'))
                std.fmt.parseInt(u21, name[2..], 16) catch return error.InvalidEntityReference
            else
                std.fmt.parseInt(u21, name[1..], 10) catch return error.InvalidEntityReference;
            if (!scanner.isXmlChar(cp)) return error.InvalidEntityReference;
            var buf: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(cp, &buf) catch return error.InvalidEntityReference;
            try writer.writeAll(buf[0..n]);
        } else {
            return error.InvalidEntityReference;
        }
        i = semi + 1;
    }
}

test "reader: stream restart mid-buffer after reset" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    // SUCCESS + post-auth stream open in ONE input buffer — what lands on the
    // wire when a server batches them. The XMPP flow is: stream open, success
    // parsed, reset() called (stream restart), scan continues from the cursor.
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s1' version='1.0'>" ++
        "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" ++
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='localhost' id='s2' version='1.0'>" ++
        "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>";
    var pos: usize = 0;

    const e0 = (try reader.next(input, &pos)).?; // <stream:stream>
    try std.testing.expect(e0 == .stream_open);
    const e1 = (try reader.next(input, &pos)).?; // <success/>
    try std.testing.expect(e1 == .element_start);
    // reset() models the XMPP stream-restart the Session performs right after
    // consuming the success: depth, scope and stream_opened all start over.
    reader.reset();
    const pos_after_success = pos;

    const e2 = (try reader.next(input, &pos)) orelse return error.LostAfterReset;
    try std.testing.expect(e2 == .stream_open);
    try std.testing.expect(pos > pos_after_success);

    const e3 = (try reader.next(input, &pos)) orelse return error.LostFeatures;
    try std.testing.expect(e3 == .element_start); // <stream:features>
}

test "reader: namespace prefix bindings are element-scoped (T232)" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    // The same prefix redeclared on a later stanza must resolve to the NEW
    // URI — and a redeclaration nested inside an element must not leak past
    // that element's close.
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>" ++
        "<message xmlns:x='urn:first'><x:a/></message>" ++
        "<message xmlns:x='urn:second'><x:a/></message>" ++
        "<message><outer xmlns:y='urn:inner'><y:b/></outer><c/></message>";
    var pos: usize = 0;

    var uris = std.ArrayList([]const u8){};
    defer {
        for (uris.items) |u| allocator.free(u);
        uris.deinit(allocator);
    }
    while (true) {
        const ev = (try reader.next(input, &pos)) orelse break;
        switch (ev) {
            .element_start => |el| {
                if (std.mem.eql(u8, el.prefix, "x") or std.mem.eql(u8, el.prefix, "y")) {
                    // The uri borrows the stanza arena, which dies at the next
                    // stanza's open, so copy it.
                    try uris.append(allocator, try allocator.dupe(u8, el.namespace_uri));
                }
            },
            else => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 3), uris.items.len);
    try std.testing.expectEqualStrings("urn:first", uris.items[0]);
    try std.testing.expectEqualStrings("urn:second", uris.items[1]);
    try std.testing.expectEqualStrings("urn:inner", uris.items[2]);
}

test "namespace resolution on master stream: redeclared prefix resolves newest-first" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const input = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>" ++
        "<a xmlns:p='urn:one'><p:b xmlns:p='urn:two'/></a>";
    var pos: usize = 0;
    _ = (try reader.next(input, &pos)).?; // <stream:stream>
    _ = (try reader.next(input, &pos)).?; // <a ...>
    const b = (try reader.next(input, &pos)).?; // <p:b/> self-closing
    try std.testing.expect(b == .element_start);
    try std.testing.expectEqualStrings("urn:two", b.element_start.namespace_uri);
    _ = (try reader.next(input, &pos)).?; // </a>

    // Stack unwound: post-scope the prefix is gone, so it resolves to no
    // namespace again. The root's own bindings stay for the life of the stream.
    try std.testing.expectEqualStrings("", reader.resolveNamespace("p"));
    try std.testing.expectEqual(@as(u32, 1), reader.ns_binding_count);
}

test "reader: parse stream opening" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const input = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='example.com' version='1.0'>";
    var pos: usize = 0;

    const ev1 = (try reader.next(input, &pos)).?;
    try std.testing.expect(ev1 == .xml_declaration);

    const ev2 = (try reader.next(input, &pos)).?;
    try std.testing.expect(ev2 == .stream_open);
    try std.testing.expectEqualStrings("stream:stream", ev2.stream_open.name);
    try std.testing.expectEqualStrings("http://etherx.jabber.org/streams", ev2.stream_open.namespace_uri);
    try std.testing.expect(reader.stream_opened);
    try std.testing.expectEqualStrings("jabber:client", reader.default_ns);
}

test "reader: S27 nested stream:stream is a protocol error" {
    const allocator = std.testing.allocator;
    const stream = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>";

    // Non-self-closing nested form.
    {
        var reader = Reader.init(allocator);
        defer reader.deinit();
        var pos: usize = 0;
        _ = try reader.next(stream, &pos);
        const nested = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>";
        pos = 0;
        try std.testing.expectError(error.NestedStreamElement, reader.next(nested, &pos));
    }

    // Self-closing nested form.
    {
        var reader = Reader.init(allocator);
        defer reader.deinit();
        var pos: usize = 0;
        _ = try reader.next(stream, &pos);
        const nested = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'/>";
        pos = 0;
        try std.testing.expectError(error.NestedStreamElement, reader.next(nested, &pos));
    }

    // Nested inside a stanza.
    {
        var reader = Reader.init(allocator);
        defer reader.deinit();
        var pos: usize = 0;
        _ = try reader.next(stream, &pos);
        const nested = "<message><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'/></message>";
        pos = 0;
        _ = (try reader.next(nested, &pos)).?; // <message>
        try std.testing.expectError(error.NestedStreamElement, reader.next(nested, &pos));
    }
}

test "reader: S27 nested stream element with a foreign prefix is rejected" {
    const allocator = std.testing.allocator;
    const stream = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>";

    // Non-self-closing nested form with a different prefix bound to the streams namespace.
    {
        var reader = Reader.init(allocator);
        defer reader.deinit();
        var pos: usize = 0;
        _ = try reader.next(stream, &pos);
        const nested = "<x:stream xmlns:x='http://etherx.jabber.org/streams'>";
        pos = 0;
        try std.testing.expectError(error.NestedStreamElement, reader.next(nested, &pos));
    }

    // Self-closing nested form with a different prefix.
    {
        var reader = Reader.init(allocator);
        defer reader.deinit();
        var pos: usize = 0;
        _ = try reader.next(stream, &pos);
        const nested = "<x:stream xmlns:x='http://etherx.jabber.org/streams'/>";
        pos = 0;
        try std.testing.expectError(error.NestedStreamElement, reader.next(nested, &pos));
    }
}

test "reader: S27 stream root with a foreign prefix opens and closes cleanly" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const input = "<x:stream xmlns='jabber:client' xmlns:x='http://etherx.jabber.org/streams'>" ++
        "<presence/>" ++
        "</x:stream>";
    var pos: usize = 0;

    const ev1 = (try reader.next(input, &pos)).?;
    try std.testing.expect(ev1 == .stream_open);
    try std.testing.expectEqualStrings("stream", ev1.stream_open.local_name);
    try std.testing.expectEqualStrings("http://etherx.jabber.org/streams", ev1.stream_open.namespace_uri);
    try std.testing.expect(reader.stream_opened);

    const ev2 = (try reader.next(input, &pos)).?;
    try std.testing.expect(ev2 == .element_start);
    try std.testing.expectEqualStrings("presence", ev2.element_start.local_name);

    // The foreign-prefixed root close is still a stream close, not an element end.
    const ev3 = (try reader.next(input, &pos)).?;
    try std.testing.expect(ev3 == .stream_close);
    try std.testing.expect(!reader.stream_opened);
}

test "reader: S27 self-closing stream child is an ordinary element" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const input = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>" ++
        "<stream:features/>" ++
        "<presence/>";
    var pos: usize = 0;

    const ev1 = (try reader.next(input, &pos)).?;
    try std.testing.expect(ev1 == .stream_open);

    // A legal empty stream child: element event, not a second stream_open,
    // and depth is popped so the stanza arena reset still fires.
    const ev2 = (try reader.next(input, &pos)).?;
    try std.testing.expect(ev2 == .element_start);
    try std.testing.expectEqualStrings("features", ev2.element_start.local_name);
    try std.testing.expect(ev2.element_start.self_closing);
    try std.testing.expectEqual(@as(usize, 1), reader.depth);

    const ev3 = (try reader.next(input, &pos)).?;
    try std.testing.expect(ev3 == .element_start);
    try std.testing.expectEqualStrings("presence", ev3.element_start.local_name);
    try std.testing.expectEqual(@as(usize, 1), reader.depth);
}

test "reader: E1 a self-closing stream header is a stream error" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    // A stream element cannot be empty: it wraps every stanza. Treating it as
    // an ordinary element leaves the reader at depth 0 with the rest of the
    // feed accumulating in the arena (E1).
    const input = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'/>";
    var pos: usize = 0;
    try std.testing.expectError(error.InvalidStreamRoot, reader.next(input, &pos));
}

test "reader: E1 a stream root with an unbound prefix is a stream error" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    // The prefix resolves to no namespace, so the root is not the streams
    // root and must not open the stream (E1).
    const input = "<stream:stream xmlns='jabber:client'>";
    var pos: usize = 0;
    try std.testing.expectError(error.InvalidStreamRoot, reader.next(input, &pos));
    try std.testing.expect(!reader.stream_opened);
}

test "reader: E1 a non-stream root is a stream error" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const input = "<foo xmlns='jabber:client'><bar/></foo>";
    var pos: usize = 0;
    try std.testing.expectError(error.InvalidStreamRoot, reader.next(input, &pos));
    try std.testing.expect(!reader.stream_opened);
}

test "reader: G5 ignored root errors cannot grow the stanza arena" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    // Keep parsing after every invalid root. Depth alone must bound each item.
    const input = "<presence/>";
    for (0..20_000) |_| {
        var pos: usize = 0;
        _ = reader.next(input, &pos) catch {};
    }
    try std.testing.expect(reader.arena.queryCapacity() <= max_arena_retain);
}

test "reader: G5 attributes per element are capped" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    var pos: usize = 0;
    _ = try reader.next("<foo", &pos);
    for (0..100_000) |i| {
        var buf: [64]u8 = undefined;
        const attr = try std.fmt.bufPrint(&buf, " a{d}='v'", .{i});
        pos = 0;
        _ = reader.next(attr, &pos) catch |err| {
            try std.testing.expectEqual(error.TooManyAttributes, err);
            try std.testing.expect(reader.arena.queryCapacity() <= max_arena_retain);
            return;
        };
    }
    return error.ExpectedTooManyAttributes;
}

test "reader: G5 namespace declarations count toward the attribute cap" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    var pos: usize = 0;
    _ = try reader.next("<foo", &pos);
    for (0..100_000) |_| {
        pos = 0;
        _ = reader.next(" xmlns='urn:example'", &pos) catch |err| {
            try std.testing.expectEqual(error.TooManyAttributes, err);
            try std.testing.expect(reader.ns_arena.queryCapacity() <= max_ns_arena_retain);
            return;
        };
    }
    return error.ExpectedTooManyAttributes;
}

test "reader: G5 an unterminated item has a whole-item byte cap" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    try drainAll(&reader, "<stream:stream xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams'>");
    try drainAll(&reader, "<iq>");
    for (0..300_000) |_| {
        var pos: usize = 0;
        _ = reader.next("<a/>", &pos) catch |err| {
            try std.testing.expectEqual(error.ItemTooLong, err);
            return;
        };
    }
    return error.ExpectedItemTooLong;
}

test "reader: parse message stanza" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    // Simulate already inside a stream
    const stream = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>";
    var pos: usize = 0;
    _ = try reader.next(stream, &pos);

    const stanza = "<message to='bob@example.com' from='alice@example.com' type='chat'><body>Hello!</body></message>";
    pos = 0;

    const ev1 = (try reader.next(stanza, &pos)).?;
    try std.testing.expect(ev1 == .element_start);
    try std.testing.expectEqualStrings("message", ev1.element_start.name);
    try std.testing.expect(ev1.element_start.attributes.len == 3);

    const ev2 = (try reader.next(stanza, &pos)).?;
    try std.testing.expect(ev2 == .element_start);
    try std.testing.expectEqualStrings("body", ev2.element_start.name);

    const ev3 = (try reader.next(stanza, &pos)).?;
    try std.testing.expect(ev3 == .text);
    try std.testing.expectEqualStrings("Hello!", ev3.text);

    const ev4 = (try reader.next(stanza, &pos)).?;
    try std.testing.expect(ev4 == .element_end);

    const ev5 = (try reader.next(stanza, &pos)).?;
    try std.testing.expect(ev5 == .element_end);
}

test "reader: self-closing presence" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const stream = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>";
    var pos: usize = 0;
    _ = try reader.next(stream, &pos);

    const stanza = "<presence/>";
    pos = 0;

    const ev1 = (try reader.next(stanza, &pos)).?;
    try std.testing.expect(ev1 == .element_start);
    try std.testing.expectEqualStrings("presence", ev1.element_start.name);
    try std.testing.expect(ev1.element_start.self_closing);
}

test "reader: namespace resolution" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const input = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>";
    var pos: usize = 0;
    _ = try reader.next(input, &pos);

    try std.testing.expectEqualStrings("jabber:client", reader.resolveNamespace(""));
    try std.testing.expectEqualStrings("http://etherx.jabber.org/streams", reader.resolveNamespace("stream"));
}

test "reader: arena stays bounded over 200k stanzas on a long-lived stream (S11)" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const stream_open = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>";
    var pos: usize = 0;
    _ = try reader.next(stream_open, &pos);

    const stanza = "<message id='m1' from='a@b/c' to='d@e' xmlns:x='urn:stanza-scoped'><body>payload</body><x:a/></message>";
    // Warmup: one full stanza so the arena retains its steady-state capacity.
    pos = 0;
    while (try reader.next(stanza, &pos)) |_| {}
    const cap_after_first = reader.arena.queryCapacity();
    try std.testing.expect(cap_after_first > 0);

    // 200k stanzas later the capacity must be exactly the same: the
    // per-stanza reset keeps a long-lived stream flat (S11 regression test).
    for (0..200_000) |_| {
        pos = 0;
        while (try reader.next(stanza, &pos)) |_| {}
    }
    try std.testing.expectEqual(cap_after_first, reader.arena.queryCapacity());
    // The stanza-scoped x binding was unwound by the element close; only the
    // stream-level bindings (default ns, stream prefix) survive the resets.
    try std.testing.expectEqual(@as(u32, 1), reader.ns_binding_count);
    try std.testing.expectEqualStrings("jabber:client", reader.default_ns);
    try std.testing.expectEqualStrings("http://etherx.jabber.org/streams", reader.resolveNamespace("stream"));
    try std.testing.expectEqualStrings("", reader.resolveNamespace("x"));
}

/// Drains every event in `input`.
fn drainAll(reader: *Reader, input: []const u8) !void {
    var pos: usize = 0;
    while (try reader.next(input, &pos)) |_| {}
}

test "reader: c2s stream close after stanzas still matches the root name (S11)" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    try drainAll(&reader, "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>");
    try std.testing.expect(reader.stream_opened);

    // Each stanza resets the per-stanza arena, which hands the root name's
    // slot to the next stanza's first token. "message" is shorter than
    // "stream:stream", so a root read from that arena comes back corrupted
    // and the clean close below is rejected as mismatched.
    for (0..3) |_| {
        try drainAll(&reader, "<message to='b@x'><body>hi</body></message>");
    }

    var close_pos: usize = 0;
    const close = try reader.next("</stream:stream>", &close_pos);
    try std.testing.expect(close.? == .stream_close);
    try std.testing.expect(!reader.stream_opened);
    try std.testing.expectEqual(@as(u32, 0), reader.elem_depth);
}

test "reader: s2s stream close after stanzas still matches the root name (S11)" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    try drainAll(&reader, "<stream:stream xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams'>");
    try std.testing.expect(reader.stream_opened);

    for (0..3) |_| {
        try drainAll(&reader, "<message from='a@x' to='b@y'><body>hi</body></message>");
    }

    var close_pos: usize = 0;
    const close = try reader.next("</stream:stream>", &close_pos);
    try std.testing.expect(close.? == .stream_close);
    try std.testing.expect(!reader.stream_opened);
}

test "reader: root name survives an arena reset past the retain limit (S11)" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    try drainAll(&reader, "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>");

    // A stanza past max_arena_retain makes the next reset free the backing
    // buffer instead of reusing it, so the root name in elem_names[0] dangles
    // unless it was copied into ns_arena.
    var big = std.ArrayList(u8){};
    defer big.deinit(allocator);
    try big.appendSlice(allocator, "<message><body>");
    try big.appendNTimes(allocator, 'x', 96 * 1024);
    try big.appendSlice(allocator, "</body></message>");
    try drainAll(&reader, big.items);

    // A small stanza so the freed buffer is not immediately reclaimed.
    try drainAll(&reader, "<presence/>");

    var close_pos: usize = 0;
    const close = try reader.next("</stream:stream>", &close_pos);
    try std.testing.expect(close.? == .stream_close);
}

test "reader: deep nesting within the stacks keeps ns context synced (S12)" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const stream_open = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>";
    var pos: usize = 0;
    _ = try reader.next(stream_open, &pos);

    // 40 nested elements, each redeclaring the default ns: within the
    // 64-entry stacks and the server's 50-depth limit.
    var buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();
    w.writeAll("<message>") catch unreachable;
    for (0..40) |i| {
        w.print("<e{d} xmlns='urn:deep-{d}'>", .{ i, i }) catch unreachable;
    }
    for (0..40) |i| {
        w.print("</e{d}>", .{39 - i}) catch unreachable;
    }
    w.writeAll("</message><presence/>") catch unreachable;
    const input = fbs.getWritten();

    pos = 0;
    var saw_presence = false;
    while (try reader.next(input, &pos)) |ev| {
        if (ev == .element_start and std.mem.eql(u8, ev.element_start.local_name, "presence")) {
            saw_presence = true;
            // The stream's default ns must be intact after 40 push/pop pairs.
            try std.testing.expectEqualStrings("jabber:client", ev.element_start.namespace_uri);
        }
    }
    try std.testing.expect(saw_presence);
    try std.testing.expectEqual(@as(u32, 1), reader.ns_stack_depth); // stream level only
    try std.testing.expectEqual(@as(u32, 1), reader.ns_mark_depth);
    try std.testing.expectEqualStrings("jabber:client", reader.default_ns);
}

test "reader: nesting past the stacks is a hard TooDeep error (S12)" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const stream_open = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>";
    var pos: usize = 0;
    _ = try reader.next(stream_open, &pos);

    var buf: [8192]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();
    w.writeAll("<message>") catch unreachable;
    for (0..max_ns_depth + 1) |i| {
        w.print("<e{d}>", .{i}) catch unreachable;
    }
    const input = fbs.getWritten();

    pos = 0;
    var got_too_deep = false;
    while (true) {
        const ev = reader.next(input, &pos) catch |err| switch (err) {
            error.TooDeep => {
                got_too_deep = true;
                break;
            },
            else => return err,
        } orelse break;
        _ = ev;
    }
    try std.testing.expect(got_too_deep);
}

test "escapeWrite encodes the five escapables (S1)" {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try escapeWrite(fbs.writer(), "a&b<c>d'e\"f");
    try std.testing.expectEqualStrings("a&amp;b&lt;c&gt;d&apos;e&quot;f", fbs.getWritten());
}

test "scanner tests" {
    _ = scanner;
}

test "reader: S11 mismatched close tag is not-well-formed" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const input = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>" ++
        "<message to='a@b'><body>hi</body></iq>";
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch |err| {
            try std.testing.expectEqual(error.MismatchedCloseTag, err);
            return;
        };
        if (ev == null) return error.ExpectedError;
    }
}

test "reader: S11 stray close tag at stream level is not-well-formed" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const input = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>" ++
        "</junk>";
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch |err| {
            try std.testing.expectEqual(error.MismatchedCloseTag, err);
            return;
        };
        if (ev == null) return error.ExpectedError;
    }
}

test "reader: S11 inter-stanza whitespace is skipped, not accumulated" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const padding = " " ** (128 * 1024);
    const input = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>" ++
        "<presence/>" ++ padding ++ "<presence/>";
    var pos: usize = 0;
    var presences: usize = 0;
    // Whitespace between stanzas never becomes a token, so neither the reader
    // arena nor the scanner's own token buffers grow with its length (S11).
    while (reader.next(input, &pos) catch return error.UnexpectedError) |ev| {
        switch (ev) {
            .text => return error.ExpectedNoWhitespaceText,
            .element_start => |el| {
                if (std.mem.eql(u8, el.local_name, "presence")) presences += 1;
            },
            else => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 2), presences);
    try std.testing.expect(reader.arena.queryCapacity() <= max_arena_retain);
    try std.testing.expect(reader.scan.buf.capacity <= scanner.max_token_retain);
    try std.testing.expect(reader.scan.token_arena.queryCapacity() <= scanner.max_token_arena_retain);
}

test "reader: S11 an overlong text run is a hard error, not unbounded growth" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const stream_open = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>";
    var pos: usize = 0;
    _ = try reader.next(stream_open, &pos);

    const head = "<message><body>";
    const run = try allocator.alloc(u8, scanner.max_token_bytes + 1);
    defer allocator.free(run);
    @memset(run, 'a');
    const input = try std.mem.concat(allocator, u8, &.{ head, run });
    defer allocator.free(input);

    pos = 0;
    while (true) {
        _ = reader.next(input, &pos) catch |err| {
            try std.testing.expectEqual(error.TokenTooLong, err);
            // Nothing above the cap was ever retained for the stream.
            try std.testing.expect(reader.scan.buf.capacity <= scanner.max_token_retain);
            return;
        };
        if (pos >= input.len) break;
    }
    return error.ExpectedTokenTooLong;
}

test "reader: S11 2 MiB of inter-stanza whitespace pins no buffer" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const stream_open = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>";
    var pos: usize = 0;
    _ = try reader.next(stream_open, &pos);
    try drainAll(&reader, "<presence/>");

    // The peer never sends the next '<', so no stanza boundary ever arrives to
    // reset anything. This used to pin 2.87 MB on the connection.
    const ws = try allocator.alloc(u8, 2 * 1024 * 1024);
    defer allocator.free(ws);
    @memset(ws, ' ');
    pos = 0;
    while (pos < ws.len) {
        if (try reader.next(ws, &pos)) |ev| switch (ev) {
            .text => return error.ExpectedNoWhitespaceText,
            else => return error.ExpectedNoEvent,
        };
    }
    try std.testing.expect(reader.scan.buf.capacity <= scanner.max_token_retain);
    try std.testing.expect(reader.scan.token_arena.queryCapacity() <= scanner.max_token_arena_retain);
    try std.testing.expect(reader.arena.queryCapacity() <= max_arena_retain);
}

test "reader: S11 the scanner token arena stays flat over a long stream" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const stream_open = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>";
    var pos: usize = 0;
    _ = try reader.next(stream_open, &pos);

    const stanza = "<message id='m1' from='a@b/c'><body>payload</body></message>";
    pos = 0;
    while (try reader.next(stanza, &pos)) |_| {}
    const cap_after_first = reader.scan.token_arena.queryCapacity();
    try std.testing.expect(cap_after_first > 0);

    for (0..20_000) |_| {
        pos = 0;
        while (try reader.next(stanza, &pos)) |_| {}
    }
    // The reader arena already stays flat; the scanner arena behind it must too.
    try std.testing.expectEqual(cap_after_first, reader.scan.token_arena.queryCapacity());
    try std.testing.expect(cap_after_first <= scanner.max_token_arena_retain);
}

test "reader: S26 one giant stanza does not inflate the arena for the stream" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const body = "x" ** (256 * 1024);
    const input = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>" ++
        "<message to='a@b'><body>" ++ body ++ "</body></message>" ++
        "<presence/>";
    var pos: usize = 0;
    var saw_small_capacity = false;
    while (true) {
        const ev = reader.next(input, &pos) catch return error.UnexpectedError;
        if (ev == null) return error.ExpectedPresence;
        if (ev.? == .element_start and std.mem.eql(u8, ev.?.element_start.name, "presence")) {
            // The giant message is gone; retained arena capacity must be
            // bounded, not sized for the biggest stanza ever seen.
            saw_small_capacity = reader.arena.queryCapacity() <= max_arena_retain;
            break;
        }
    }
    try std.testing.expect(saw_small_capacity);
}

test "reader: S11 comments are rejected as restricted XML" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    const input = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>" ++
        "<!-- hello --><presence/>";
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch |err| {
            try std.testing.expectEqual(error.ForbiddenXmlConstruct, err);
            return;
        };
        if (ev == null) return error.ExpectedError;
    }
}

test "reader: event spans never overshoot the segment end under adversarial splits" {
    const allocator = std.testing.allocator;
    const doc = "<?xml version='1.0'?>" ++
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>" ++
        "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>" ++
        "<iq type='set' id='b1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>r&amp;x</resource></bind></iq>" ++
        "<message to='a@b' from='c@d'><body>hello &lt;world&gt;</body></message>" ++
        "<presence/>";

    // A payload slice that starts inside the segment must also end inside
    // it: a span may borrow from the input or from the arena, never
    // overshoot the input end.
    const SpanChecker = struct {
        fn check(s: []const u8, input: []const u8) !void {
            if (s.len == 0) return;
            const base = @intFromPtr(input.ptr);
            const p = @intFromPtr(s.ptr);
            if (p >= base and p < base + input.len) {
                try std.testing.expect(p + s.len <= base + input.len);
            }
        }
        fn event(ev: Event, input: []const u8) !void {
            switch (ev) {
                .stream_open, .element_start => |el| {
                    try check(el.name, input);
                    try check(el.namespace_uri, input);
                    for (el.attributes) |attr| {
                        try check(attr.name, input);
                        try check(attr.value, input);
                    }
                },
                .element_end => |name| try check(name, input),
                .text => |txt| try check(txt, input),
                else => {},
            }
        }
    };

    // Replay the server's consume pattern byte by byte (the most
    // adversarial segmentation): accumulate one more byte per step,
    // parse with pos = 0, then consume the parsed prefix. pos must
    // never pass the segment end.
    var reader = Reader.init(allocator);
    defer reader.deinit();

    var consumed: usize = 0;
    var step: usize = 1;
    while (step <= doc.len) : (step += 1) {
        const input = doc[consumed..step];
        var pos: usize = 0;
        while (true) {
            const ev = try reader.next(input, &pos);
            try std.testing.expect(pos <= input.len);
            if (ev == null) break;
            try SpanChecker.event(ev.?, input);
        }
        consumed += pos;
    }
    try std.testing.expectEqual(doc.len, consumed);
}
