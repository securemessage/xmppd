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
/// Event payload lifetime: `element_start`, `element_end` and `text`
/// payloads are borrowed from the stanza arena and stay valid until the
/// next top-level stanza begins (depth-1 `element_open`), which resets the
/// arena (S11). Consumers must copy anything they keep across stanzas.
/// Namespace context declared on the stream element itself lives in the
/// separate `ns_arena` and survives stanza resets until `reset()`.
/// Maximum number of namespace prefix bindings (XMPP uses very few)
const max_ns_bindings = 16;

/// Maximum element nesting the namespace tracking supports. Servers
/// enforce their own (smaller) stanza depth limit; the mark and default-ns
/// stacks are sized from this and fail with error.TooDeep as a backstop,
/// so push and pop can never desync (S12).
pub const max_ns_depth = 64;

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
                    if (self.stream_opened and self.depth == 1) {
                        // New top-level stanza: everything the reader
                        // produced for the previous stanza dies here. The
                        // stream-level namespace context lives in ns_arena
                        // and survives (S11).
                        _ = self.arena.reset(.retain_capacity);
                    }
                    self.current_element_name = try self.arenaDupe(token.name);
                    self.current_element_prefix = try self.arenaDupe(token.prefix);
                    self.current_element_local = try self.arenaDupe(token.local_name);
                    self.attrs.clearRetainingCapacity();
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
                    try self.attrs.append(self.allocator, .{
                        .name = try self.arenaDupe(token.name),
                        .value = try self.arenaDupe(token.value),
                        .prefix = try self.arenaDupe(token.prefix),
                        .local_name = try self.arenaDupe(token.local_name),
                    });
                },
                .element_open_end => {
                    self.depth += 1;
                    const elem = self.buildElement(false);
                    // For non-self-closing elements, namespace is restored on element_close

                    // The stream:stream element is special
                    if (self.depth == 1 and std.mem.eql(u8, self.current_element_prefix, "stream")) {
                        self.stream_opened = true;
                        return Event{ .stream_open = elem };
                    }

                    return Event{ .element_start = elem };
                },
                .element_self_close => {
                    self.depth += 1;
                    const elem = self.buildElement(true);

                    // Self-closing at depth 1 would be unusual for stream but handle it
                    if (std.mem.eql(u8, self.current_element_prefix, "stream")) {
                        return Event{ .stream_open = elem };
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
                    if (self.depth > 0) {
                        self.depth -= 1;
                    }
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

                    // Stream close
                    if (std.mem.eql(u8, token.prefix, "stream") and
                        std.mem.eql(u8, token.local_name, "stream"))
                    {
                        self.stream_opened = false;
                        return Event.stream_close;
                    }

                    return Event{ .element_end = try self.arenaDupe(token.name) };
                },
                .text => {
                    if (token.name.len > 0) {
                        return Event{ .text = try self.arenaDupe(token.name) };
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

    /// Reset the reader for a new stream (e.g., after STARTTLS or SASL reset).
    /// Clears both the Reader state and the underlying Scanner so a fresh
    /// XML stream can be parsed from scratch.
    pub fn reset(self: *Reader) void {
        self.depth = 0;
        self.stream_opened = false;
        self.default_ns = "";
        self.ns_stack_depth = 0;
        self.ns_binding_count = 0;
        self.ns_mark_depth = 0;
        self.current_element_name = "";
        self.current_element_prefix = "";
        self.current_element_local = "";
        self.attrs.clearRetainingCapacity();
        _ = self.arena.reset(.retain_capacity);
        _ = self.ns_arena.reset(.retain_capacity);
        self.scan.reset();
    }
};

// --- Tests ---

test "reader: stream restart mid-buffer after reset" {
    const allocator = std.testing.allocator;
    var reader = Reader.init(allocator);
    defer reader.deinit();

    // SUCCESS + post-auth stream open in ONE input buffer — what lands on the
    // wire when a server batches them. The XMPP flow is: success parsed,
    // reset() called (stream restart), scan continues from the cursor.
    const input =
        "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" ++
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='localhost' id='s2' version='1.0'>" ++
        "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>";
    var pos: usize = 0;

    const e1 = (try reader.next(input, &pos)).?; // <success/>
    try std.testing.expect(e1 == .element_start);
    // A reader-level stream was never opened here; reset() models the XMPP
    // stream-restart the Session performs right after consuming the success.
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
        "<message xmlns:x='urn:first'><x:a/></message>" ++
        "<message xmlns:x='urn:second'><x:a/></message>" ++
        "<message><outer xmlns:y='urn:inner'><y:b/></outer><c/></message>";
    var pos: usize = 0;

    var uris = std.ArrayList([]const u8){};
    defer uris.deinit(allocator);
    while (true) {
        const ev = (try reader.next(input, &pos)) orelse break;
        switch (ev) {
            .element_start => |el| {
                if (std.mem.eql(u8, el.prefix, "x") or std.mem.eql(u8, el.prefix, "y")) {
                    try uris.append(allocator, el.namespace_uri);
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

    const input = "<a xmlns:p='urn:one'><p:b xmlns:p='urn:two'/></a>";
    var pos: usize = 0;
    _ = (try reader.next(input, &pos)).?; // <a ...>
    const b = (try reader.next(input, &pos)).?; // <p:b/> self-closing
    try std.testing.expect(b == .element_start);
    try std.testing.expectEqualStrings("urn:two", b.element_start.namespace_uri);
    _ = (try reader.next(input, &pos)).?; // </a>

    // Stack unwound: post-scope the prefix is gone.
    try std.testing.expectEqual(@as(u32, 0), reader.ns_binding_count);
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

test "scanner tests" {
    _ = scanner;
}
