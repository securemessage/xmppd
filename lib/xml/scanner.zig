const std = @import("std");

/// Token types produced by the XML scanner.
pub const TokenType = enum {
    /// `<?xml ... ?>`
    xml_declaration,
    /// Opening tag: `<name` (attributes follow as separate tokens)
    element_open,
    /// Closing tag: `</name>`
    element_close,
    /// Self-closing tag end: `/>`
    element_self_close,
    /// End of opening tag: `>`
    element_open_end,
    /// Attribute: `name="value"` or `name='value'`
    attribute,
    /// Text content between tags
    text,
    /// Namespace declaration: `xmlns:prefix="uri"` or `xmlns="uri"`
    namespace_decl,
    /// End of input
    eof,
};

/// A token produced by the scanner.
pub const Token = struct {
    type: TokenType,
    /// For element_open/element_close: the tag name (may include prefix:local)
    /// For attribute/namespace_decl: the attribute name
    /// For text: the text content
    name: []const u8 = "",
    /// For attribute/namespace_decl: the attribute value
    /// For element_open: unused
    value: []const u8 = "",
    /// Namespace prefix (empty for default namespace)
    prefix: []const u8 = "",
    /// Local name (without prefix)
    local_name: []const u8 = "",
};

/// Scanner states.
const State = enum {
    /// Outside any tag, reading text content
    content,
    /// After `<`, determining tag type
    tag_start,
    /// Reading an opening tag name
    tag_name,
    /// Inside an opening tag, reading attributes
    tag_attributes,
    /// Reading attribute name
    attr_name,
    /// After `=`, before attribute value quote
    attr_value_start,
    /// Reading attribute value
    attr_value,
    /// After `</`, reading closing tag name
    close_tag_name,
    /// After `?` in `<?xml`, reading declaration
    xml_decl,
    /// After `<!`, waiting for `--` to confirm comment
    bang_start,
    /// Reading a comment `<!-- ... -->`
    comment,
    /// Reading an entity reference (`&...;`) in text content
    entity_content,
    /// Reading an entity reference (`&...;`) in attribute value
    entity_attr,
};

/// Streaming XML scanner for XMPP streams.
///
/// Designed for XMPP's streaming model where `<stream:stream>` is opened
/// and never closed until disconnect. Produces tokens incrementally as
/// bytes are fed in.
pub const Scanner = struct {
    state: State = .content,
    buf: std.ArrayList(u8) = .{},
    /// Secondary buffer for attribute values
    val_buf: std.ArrayList(u8) = .{},
    /// The quote character for the current attribute value
    quote_char: u8 = 0,
    /// Track if we just saw a `/` that might precede `>`
    saw_slash: bool = false,
    /// Pending tokens queue (for multi-token emissions like element + attrs)
    pending: std.ArrayList(Token) = .{},
    /// Stored token data (owned copies for returned tokens)
    token_arena: std.heap.ArenaAllocator,
    /// Allocator for dynamic buffers
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Scanner {
        return .{
            .token_arena = std.heap.ArenaAllocator.init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Scanner) void {
        self.buf.deinit(self.allocator);
        self.val_buf.deinit(self.allocator);
        self.pending.deinit(self.allocator);
        self.token_arena.deinit();
    }

    /// Reset the arena between logical processing units to prevent unbounded growth.
    pub fn resetArena(self: *Scanner) void {
        _ = self.token_arena.reset(.retain_capacity);
    }

    /// Full reset for stream restart (e.g., after STARTTLS or SASL success).
    /// Clears all accumulated state so the scanner can parse a fresh XML stream.
    pub fn reset(self: *Scanner) void {
        self.state = .content;
        self.buf.clearRetainingCapacity();
        self.val_buf.clearRetainingCapacity();
        self.quote_char = 0;
        self.saw_slash = false;
        self.pending.clearRetainingCapacity();
        _ = self.token_arena.reset(.retain_capacity);
    }

    const ally = struct {
        inline fn get(self: *Scanner) std.mem.Allocator {
            return self.allocator;
        }
    };

    /// Feed bytes into the scanner and extract the next token.
    /// Returns null if more data is needed.
    pub fn next(self: *Scanner, input: []const u8, pos: *usize) !?Token {
        // If we have pending tokens, return them first
        if (self.pending.items.len > 0) {
            const token = self.pending.orderedRemove(0);
            return token;
        }

        const a = self.allocator;

        while (pos.* < input.len) {
            const c = input[pos.*];
            pos.* += 1;

            switch (self.state) {
                .content => {
                    if (c == '<') {
                        if (self.buf.items.len > 0) {
                            // Emit text token
                            const text = try self.dupeAndClear(&self.buf);
                            self.state = .tag_start;
                            return Token{
                                .type = .text,
                                .name = text,
                            };
                        }
                        self.state = .tag_start;
                    } else if (c == '&') {
                        // Entity reference in text content
                        self.state = .entity_content;
                    } else {
                        try self.buf.append(a, c);
                    }
                },
                .tag_start => {
                    if (c == '/') {
                        self.state = .close_tag_name;
                    } else if (c == '?') {
                        self.state = .xml_decl;
                    } else if (c == '!') {
                        // Must be followed by `--` for a comment.
                        // DOCTYPE, ENTITY, CDATA are forbidden in XMPP (RFC 6120 §11.1).
                        self.state = .bang_start;
                    } else {
                        try self.buf.append(a, c);
                        self.state = .tag_name;
                    }
                },
                .tag_name => {
                    if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
                        self.state = .tag_attributes;
                        const name = try self.dupeAndClear(&self.buf);
                        const parsed = splitPrefixLocal(name);
                        return Token{
                            .type = .element_open,
                            .name = name,
                            .prefix = parsed.prefix,
                            .local_name = parsed.local,
                        };
                    } else if (c == '>') {
                        self.state = .content;
                        const name = try self.dupeAndClear(&self.buf);
                        const parsed = splitPrefixLocal(name);
                        if (self.saw_slash) {
                            // Self-closing: <tag/>
                            self.saw_slash = false;
                            try self.pending.append(a, Token{ .type = .element_self_close });
                        } else {
                            try self.pending.append(a, Token{ .type = .element_open_end });
                        }
                        return Token{
                            .type = .element_open,
                            .name = name,
                            .prefix = parsed.prefix,
                            .local_name = parsed.local,
                        };
                    } else if (c == '/') {
                        self.saw_slash = true;
                    } else {
                        if (self.saw_slash) {
                            // Wasn't a self-close, put slash back
                            try self.buf.append(a, '/');
                            self.saw_slash = false;
                        }
                        try self.buf.append(a, c);
                    }
                },
                .tag_attributes => {
                    if (c == '>') {
                        if (self.saw_slash) {
                            self.saw_slash = false;
                            self.state = .content;
                            return Token{ .type = .element_self_close };
                        }
                        self.state = .content;
                        return Token{ .type = .element_open_end };
                    } else if (c == '/') {
                        self.saw_slash = true;
                    } else if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
                        // Skip whitespace between attributes
                    } else {
                        // Start of attribute name
                        self.saw_slash = false;
                        try self.buf.append(a, c);
                        self.state = .attr_name;
                    }
                },
                .attr_name => {
                    if (c == '=') {
                        self.state = .attr_value_start;
                    } else {
                        try self.buf.append(a, c);
                    }
                },
                .attr_value_start => {
                    if (c == '"' or c == '\'') {
                        self.quote_char = c;
                        self.state = .attr_value;
                    }
                },
                .attr_value => {
                    if (c == self.quote_char) {
                        self.state = .tag_attributes;
                        const attr_name = try self.dupeAndClear(&self.buf);
                        const attr_value = try self.dupeAndClear(&self.val_buf);

                        // Determine if this is a namespace declaration
                        if (std.mem.eql(u8, attr_name, "xmlns")) {
                            return Token{
                                .type = .namespace_decl,
                                .name = attr_name,
                                .value = attr_value,
                                .prefix = "",
                                .local_name = "",
                            };
                        } else if (std.mem.startsWith(u8, attr_name, "xmlns:")) {
                            return Token{
                                .type = .namespace_decl,
                                .name = attr_name,
                                .value = attr_value,
                                .prefix = attr_name[6..],
                                .local_name = "",
                            };
                        } else {
                            const parsed = splitPrefixLocal(attr_name);
                            return Token{
                                .type = .attribute,
                                .name = attr_name,
                                .value = attr_value,
                                .prefix = parsed.prefix,
                                .local_name = parsed.local,
                            };
                        }
                    } else if (c == '&') {
                        // Entity reference in attribute value
                        self.buf.clearRetainingCapacity();
                        self.state = .entity_attr;
                    } else {
                        try self.val_buf.append(a, c);
                    }
                },
                .close_tag_name => {
                    if (c == '>') {
                        self.state = .content;
                        const name = try self.dupeAndClear(&self.buf);
                        const parsed = splitPrefixLocal(name);
                        return Token{
                            .type = .element_close,
                            .name = name,
                            .prefix = parsed.prefix,
                            .local_name = parsed.local,
                        };
                    } else {
                        try self.buf.append(a, c);
                    }
                },
                .xml_decl => {
                    if (c == '?') {
                        // Next char should be '>'
                        self.saw_slash = true;
                    } else if (c == '>' and self.saw_slash) {
                        self.saw_slash = false;
                        self.state = .content;
                        _ = try self.dupeAndClear(&self.buf);
                        return Token{ .type = .xml_declaration };
                    } else {
                        self.saw_slash = false;
                        try self.buf.append(a, c);
                    }
                },
                .bang_start => {
                    // After `<!`, expect `--` for comment start.
                    // Anything else (DOCTYPE, ENTITY, CDATA) is forbidden in XMPP.
                    try self.buf.append(a, c);
                    if (self.buf.items.len == 2) {
                        if (self.buf.items[0] == '-' and self.buf.items[1] == '-') {
                            // Valid comment start `<!--`
                            self.buf.clearRetainingCapacity();
                            self.state = .comment;
                        } else {
                            // Forbidden: <!DOCTYPE, <!ENTITY, <![CDATA[, etc.
                            // RFC 6120 §11.1: "a server MUST NOT process XML entity
                            // references" and DTDs are forbidden.
                            return error.ForbiddenXmlConstruct;
                        }
                    }
                },
                .comment => {
                    // Consume comment until `-->`
                    if (c == '>' and self.buf.items.len >= 2 and
                        self.buf.items[self.buf.items.len - 1] == '-' and
                        self.buf.items[self.buf.items.len - 2] == '-')
                    {
                        self.buf.clearRetainingCapacity();
                        self.state = .content;
                    } else {
                        try self.buf.append(a, c);
                    }
                },
                .entity_content => {
                    // Reading entity name after `&` in text content.
                    // Uses val_buf to accumulate entity name (buf holds text content).
                    if (c == ';') {
                        const decoded = try resolveEntity(self.val_buf.items);
                        try self.buf.append(a, decoded);
                        self.val_buf.clearRetainingCapacity();
                        self.state = .content;
                    } else if (self.val_buf.items.len > 8) {
                        return error.InvalidEntityReference;
                    } else {
                        try self.val_buf.append(a, c);
                    }
                },
                .entity_attr => {
                    // Reading entity name after `&` in attribute value.
                    // Uses buf to accumulate entity name (val_buf holds attr value).
                    if (c == ';') {
                        const decoded = try resolveEntity(self.buf.items);
                        self.buf.clearRetainingCapacity();
                        try self.val_buf.append(a, decoded);
                        self.state = .attr_value;
                    } else if (self.buf.items.len > 8) {
                        return error.InvalidEntityReference;
                    } else {
                        try self.buf.append(a, c);
                    }
                },
            }
        }

        return null; // Need more data
    }

    fn dupeAndClear(self: *Scanner, list: *std.ArrayList(u8)) ![]const u8 {
        const arena_alloc = self.token_arena.allocator();
        const result = try arena_alloc.dupe(u8, list.items);
        list.clearRetainingCapacity();
        return result;
    }

    const PrefixLocal = struct {
        prefix: []const u8,
        local: []const u8,
    };

    fn splitPrefixLocal(name: []const u8) PrefixLocal {
        if (std.mem.indexOfScalar(u8, name, ':')) |colon| {
            return .{
                .prefix = name[0..colon],
                .local = name[colon + 1 ..],
            };
        }
        return .{
            .prefix = "",
            .local = name,
        };
    }
};

/// Resolve an XML entity reference name to its character value.
///
/// Supports the 5 predefined XML entities (required by all XML parsers)
/// and numeric character references (&#NNN; and &#xHH;).
///
/// Custom/undeclared entity references return error — XMPP forbids DTDs
/// so there is no mechanism to define custom entities (RFC 6120 §11.1).
fn resolveEntity(name: []const u8) !u8 {
    // Predefined XML entities
    if (std.mem.eql(u8, name, "amp")) return '&';
    if (std.mem.eql(u8, name, "lt")) return '<';
    if (std.mem.eql(u8, name, "gt")) return '>';
    if (std.mem.eql(u8, name, "apos")) return '\'';
    if (std.mem.eql(u8, name, "quot")) return '"';

    // Numeric character reference: &#NNN; (decimal)
    if (name.len > 1 and name[0] == '#') {
        if (name[1] == 'x' or name[1] == 'X') {
            // Hexadecimal: &#xHH;
            const val = std.fmt.parseInt(u8, name[2..], 16) catch return error.InvalidEntityReference;
            return val;
        } else {
            // Decimal: &#NNN;
            const val = std.fmt.parseInt(u8, name[1..], 10) catch return error.InvalidEntityReference;
            return val;
        }
    }

    // Unknown entity — forbidden in XMPP (no DTD to define custom entities)
    return error.InvalidEntityReference;
}

// --- Tests ---

test "scan simple element" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    const input = "<message to=\"alice@example.com\">Hello</message>";
    var pos: usize = 0;

    const tok1 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.element_open, tok1.type);
    try std.testing.expectEqualStrings("message", tok1.name);

    const tok2 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.attribute, tok2.type);
    try std.testing.expectEqualStrings("to", tok2.name);
    try std.testing.expectEqualStrings("alice@example.com", tok2.value);

    const tok3 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.element_open_end, tok3.type);

    const tok4 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.text, tok4.type);
    try std.testing.expectEqualStrings("Hello", tok4.name);

    const tok5 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.element_close, tok5.type);
    try std.testing.expectEqualStrings("message", tok5.name);
}

test "scan XMPP stream opening" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    const input = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='example.com' version='1.0'>";
    var pos: usize = 0;

    const tok1 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.xml_declaration, tok1.type);

    const tok2 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.element_open, tok2.type);
    try std.testing.expectEqualStrings("stream:stream", tok2.name);
    try std.testing.expectEqualStrings("stream", tok2.prefix);
    try std.testing.expectEqualStrings("stream", tok2.local_name);

    const tok3 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.namespace_decl, tok3.type);
    try std.testing.expectEqualStrings("xmlns", tok3.name);
    try std.testing.expectEqualStrings("jabber:client", tok3.value);

    const tok4 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.namespace_decl, tok4.type);
    try std.testing.expectEqualStrings("xmlns:stream", tok4.name);
    try std.testing.expectEqualStrings("http://etherx.jabber.org/streams", tok4.value);
    try std.testing.expectEqualStrings("stream", tok4.prefix);

    const tok5 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.attribute, tok5.type);
    try std.testing.expectEqualStrings("to", tok5.name);
    try std.testing.expectEqualStrings("example.com", tok5.value);

    const tok6 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.attribute, tok6.type);
    try std.testing.expectEqualStrings("version", tok6.name);
    try std.testing.expectEqualStrings("1.0", tok6.value);

    const tok7 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.element_open_end, tok7.type);
}

test "scan self-closing element" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    const input = "<presence/>";
    var pos: usize = 0;

    const tok1 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.element_open, tok1.type);
    try std.testing.expectEqualStrings("presence", tok1.name);

    const tok2 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.element_self_close, tok2.type);
}

test "scan namespace-prefixed stanza" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    const input = "<iq type='result' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>user@example.com/resource</jid></bind></iq>";
    var pos: usize = 0;

    const tok1 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.element_open, tok1.type);
    try std.testing.expectEqualStrings("iq", tok1.name);

    const tok2 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.attribute, tok2.type);
    try std.testing.expectEqualStrings("type", tok2.name);
    try std.testing.expectEqualStrings("result", tok2.value);

    const tok3 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.attribute, tok3.type);
    try std.testing.expectEqualStrings("id", tok3.name);
    try std.testing.expectEqualStrings("bind1", tok3.value);

    const tok4 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.element_open_end, tok4.type);

    const tok5 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.element_open, tok5.type);
    try std.testing.expectEqualStrings("bind", tok5.name);

    const tok6 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.namespace_decl, tok6.type);
    try std.testing.expectEqualStrings("urn:ietf:params:xml:ns:xmpp-bind", tok6.value);

    const tok7 = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.element_open_end, tok7.type);
}

test "entity decoding: predefined entities in text" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    const input = "<body>A &amp; B &lt; C &gt; D</body>";
    var pos: usize = 0;

    _ = (try scanner.next(input, &pos)).?; // element_open "body"
    _ = (try scanner.next(input, &pos)).?; // element_open_end

    const tok = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.text, tok.type);
    try std.testing.expectEqualStrings("A & B < C > D", tok.name);
}

test "entity decoding: numeric character reference" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    const input = "<x>&#65;&#x42;</x>"; // &#65; = 'A', &#x42; = 'B'
    var pos: usize = 0;

    _ = (try scanner.next(input, &pos)).?; // element_open
    _ = (try scanner.next(input, &pos)).?; // element_open_end

    const tok = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.text, tok.type);
    try std.testing.expectEqualStrings("AB", tok.name);
}

test "entity decoding: entities in attribute values" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    const input = "<x attr='a&amp;b'/>";
    var pos: usize = 0;

    _ = (try scanner.next(input, &pos)).?; // element_open
    const attr_tok = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.attribute, attr_tok.type);
    try std.testing.expectEqualStrings("a&b", attr_tok.value);
}

test "entity decoding: unknown entity rejected" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    const input = "<body>&custom;</body>";
    var pos: usize = 0;

    _ = (try scanner.next(input, &pos)).?; // element_open
    _ = (try scanner.next(input, &pos)).?; // element_open_end

    const result = scanner.next(input, &pos);
    try std.testing.expectError(error.InvalidEntityReference, result);
}

test "DOCTYPE rejected (RFC 6120 section 11.1)" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    const input = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>";
    var pos: usize = 0;

    const result = scanner.next(input, &pos);
    try std.testing.expectError(error.ForbiddenXmlConstruct, result);
}

test "CDATA rejected" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    const input = "<body><![CDATA[test]]></body>";
    var pos: usize = 0;

    _ = (try scanner.next(input, &pos)).?; // element_open "body"
    _ = (try scanner.next(input, &pos)).?; // element_open_end

    const result = scanner.next(input, &pos);
    try std.testing.expectError(error.ForbiddenXmlConstruct, result);
}

test "XML comment allowed" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    const input = "<!-- this is a comment --><presence/>";
    var pos: usize = 0;

    // Comment is consumed silently, next token should be the element
    const tok = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.element_open, tok.type);
    try std.testing.expectEqualStrings("presence", tok.name);
}
