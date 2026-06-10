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
    pub const blocking = "urn:xmpp:blocking";
    pub const pubsub = "http://jabber.org/protocol/pubsub";
    pub const pubsub_event = "http://jabber.org/protocol/pubsub#event";
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
/// Maximum number of namespace prefix bindings (XMPP uses very few)
const max_ns_bindings = 16;

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
    /// Default namespace URI
    default_ns: []const u8 = "",
    /// Namespace stack — saves default_ns on element_open, restores on element_close.
    /// XMPP stanzas are shallow (depth rarely exceeds 5–6), so 16 entries suffice.
    ns_stack: [16][]const u8 = undefined,
    ns_stack_depth: u32 = 0,
    /// Whether we're inside the stream element
    stream_opened: bool = false,
    /// Arena for element/attribute data
    arena: std.heap.ArenaAllocator,
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
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Reader) void {
        self.scan.deinit();
        self.attrs.deinit(self.allocator);
        self.arena.deinit();
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
                    self.current_element_name = try self.arenaDupe(token.name);
                    self.current_element_prefix = try self.arenaDupe(token.prefix);
                    self.current_element_local = try self.arenaDupe(token.local_name);
                    self.attrs.clearRetainingCapacity();
                    // Push current default namespace before this element's xmlns decls modify it
                    if (self.ns_stack_depth < self.ns_stack.len) {
                        self.ns_stack[self.ns_stack_depth] = self.default_ns;
                        self.ns_stack_depth += 1;
                    }
                },
                .namespace_decl => {
                    const uri = try self.arenaDupe(token.value);
                    if (token.prefix.len == 0) {
                        // Default namespace
                        self.default_ns = uri;
                    } else {
                        const prefix = try self.arenaDupe(token.prefix);
                        if (self.ns_binding_count < max_ns_bindings) {
                            self.ns_bindings[self.ns_binding_count] = .{
                                .prefix = prefix,
                                .uri = uri,
                            };
                            self.ns_binding_count += 1;
                        }
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

    /// Resolve a namespace prefix to its URI.
    pub fn resolveNamespace(self: *const Reader, prefix: []const u8) []const u8 {
        if (prefix.len == 0) return self.default_ns;
        var i: u32 = 0;
        while (i < self.ns_binding_count) : (i += 1) {
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

    /// Reset the reader for a new stream (e.g., after STARTTLS or SASL reset).
    /// Clears both the Reader state and the underlying Scanner so a fresh
    /// XML stream can be parsed from scratch.
    pub fn reset(self: *Reader) void {
        self.depth = 0;
        self.stream_opened = false;
        self.default_ns = "";
        self.ns_stack_depth = 0;
        self.ns_binding_count = 0;
        self.current_element_name = "";
        self.current_element_prefix = "";
        self.current_element_local = "";
        self.attrs.clearRetainingCapacity();
        _ = self.arena.reset(.retain_capacity);
        self.scan.reset();
    }
};

// --- Tests ---

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

test "scanner tests" {
    _ = scanner;
}
