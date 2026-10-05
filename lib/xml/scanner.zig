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
    /// After an attribute name, skipping whitespace before `=`
    attr_name_ws,
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
    /// Entity name accumulator for `&...;` references, kept separate from
    /// buf and val_buf: buf holds the attribute name and val_buf the value
    /// while a reference is read inside an attribute value.
    ent_buf: std.ArrayList(u8) = .{},
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
        self.ent_buf.deinit(self.allocator);
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
        self.ent_buf.clearRetainingCapacity();
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
                        if (!isValidXmlName(self.buf.items)) return error.InvalidName;
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
                        if (!isValidXmlName(self.buf.items)) return error.InvalidName;
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
                        if (!isValidXmlName(self.buf.items)) return error.InvalidName;
                        self.state = .attr_value_start;
                    } else if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
                        // Whitespace before '=' is legal XML; do not fold it
                        // into the attribute name.
                        self.state = .attr_name_ws;
                    } else {
                        try self.buf.append(a, c);
                    }
                },
                .attr_name_ws => {
                    if (c == '=') {
                        if (!isValidXmlName(self.buf.items)) return error.InvalidName;
                        self.state = .attr_value_start;
                    } else if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
                        // Skip whitespace between name and '='
                    } else {
                        return error.InvalidName;
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
                            // An empty prefix is not a valid NCName.
                            if (attr_name.len == 6) return error.InvalidName;
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
                        // Entity reference in attribute value; buf still
                        // holds the attribute name, so the entity name is
                        // accumulated in ent_buf instead.
                        self.state = .entity_attr;
                    } else {
                        try self.val_buf.append(a, c);
                    }
                },
                .close_tag_name => {
                    if (c == '>') {
                        self.state = .content;
                        if (!isValidXmlName(self.buf.items)) return error.InvalidName;
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
                    // After `<!`: comments, DOCTYPE, ENTITY and CDATA are all
                    // forbidden in XMPP (RFC 6120 §11.1 restricted XML).
                    try self.buf.append(a, c);
                    if (self.buf.items.len == 2) {
                        return error.ForbiddenXmlConstruct;
                    }
                },
                .entity_content => {
                    // Reading entity name after `&` in text content; the
                    // decoded character is appended to buf (the text).
                    if (c == ';') {
                        try resolveEntityInto(self.ent_buf.items, &self.buf, a);
                        self.ent_buf.clearRetainingCapacity();
                        self.state = .content;
                    } else if (self.ent_buf.items.len > 11) {
                        return error.InvalidEntityReference;
                    } else {
                        try self.ent_buf.append(a, c);
                    }
                },
                .entity_attr => {
                    // Reading entity name after `&` in an attribute value;
                    // the decoded character is appended to val_buf.
                    if (c == ';') {
                        try resolveEntityInto(self.ent_buf.items, &self.val_buf, a);
                        self.ent_buf.clearRetainingCapacity();
                        self.state = .attr_value;
                    } else if (self.ent_buf.items.len > 11) {
                        return error.InvalidEntityReference;
                    } else {
                        try self.ent_buf.append(a, c);
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

/// Resolve an XML entity reference and append its UTF-8 encoding to `out`.
///
/// Supports the 5 predefined XML entities (required by all XML parsers)
/// and numeric character references (&#NNN; and &#xHH;). Numeric values
/// must satisfy the XML 1.0 Char production and are UTF-8 encoded (S21:
/// previously truncated to a lone low byte, producing invalid UTF-8).
///
/// Custom/undeclared entity references return error — XMPP forbids DTDs
/// so there is no mechanism to define custom entities (RFC 6120 §11.1).
fn resolveEntityInto(name: []const u8, out: *std.ArrayList(u8), a: std.mem.Allocator) !void {
    // Predefined XML entities
    if (std.mem.eql(u8, name, "amp")) return out.append(a, '&');
    if (std.mem.eql(u8, name, "lt")) return out.append(a, '<');
    if (std.mem.eql(u8, name, "gt")) return out.append(a, '>');
    if (std.mem.eql(u8, name, "apos")) return out.append(a, '\'');
    if (std.mem.eql(u8, name, "quot")) return out.append(a, '"');

    // Numeric character reference: &#NNN; (decimal) or &#xHH; (hex). The
    // CharRef production is digits only: no sign, no separators. Leading
    // zeros are legal, so parse digit by digit with an overflow check
    // instead of a length-limited parseInt.
    if (name.len > 1 and name[0] == '#') {
        const hex = name[1] == 'x' or name[1] == 'X';
        const digits = if (hex) name[2..] else name[1..];
        if (digits.len == 0) return error.InvalidEntityReference;
        var val: u32 = 0;
        for (digits) |d| {
            const digit: u32 = if (hex)
                std.fmt.charToDigit(d, 16) catch return error.InvalidEntityReference
            else
                std.fmt.charToDigit(d, 10) catch return error.InvalidEntityReference;
            val = std.math.mul(u32, val, if (hex) @as(u32, 16) else 10) catch return error.InvalidEntityReference;
            val = std.math.add(u32, val, digit) catch return error.InvalidEntityReference;
        }
        if (val > 0x10FFFF) return error.InvalidEntityReference;
        const cp: u21 = @intCast(val);
        if (!isXmlChar(cp)) return error.InvalidEntityReference;
        var buf: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(cp, &buf) catch return error.InvalidEntityReference;
        try out.appendSlice(a, buf[0..n]);
        return;
    }

    // Unknown entity — forbidden in XMPP (no DTD to define custom entities)
    return error.InvalidEntityReference;
}

/// XML 1.0 (Fifth Edition) Char production: #x9 | #xA | #xD |
/// [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
pub fn isXmlChar(cp: u21) bool {
    return cp == 0x9 or cp == 0xA or cp == 0xD or
        (cp >= 0x20 and cp <= 0xD7FF) or
        (cp >= 0xE000 and cp <= 0xFFFD) or
        (cp >= 0x10000 and cp <= 0x10FFFF);
}

/// XML 1.0 NameStartChar, ASCII range enforced byte-wise; bytes >= 0x80 are
/// accepted as UTF-8 name characters (full Unicode range tables are out of
/// scope for a tokenizer). ':' stays valid so prefixed names parse.
fn isNameStartChar(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or
        c == '_' or c == ':' or c >= 0x80;
}

/// XML 1.0 NameChar (see isNameStartChar for the non-ASCII policy).
fn isNameChar(c: u8) bool {
    return isNameStartChar(c) or (c >= '0' and c <= '9') or c == '-' or c == '.';
}

/// A name token is re-emitted verbatim in accumulated XML, so anything
/// outside the XML Name production (quotes, '<', ...) must be rejected here
/// or it can inject markup downstream (S21).
fn isValidXmlName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (!isNameStartChar(name[0])) return false;
    for (name[1..]) |c| {
        if (!isNameChar(c)) return false;
    }
    return true;
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

test "entity decoding: numeric refs are UTF-8 encoded, not truncated (S21)" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    // &#233; = U+00E9 'é' (0xC3 0xA9), &#x1F600; = U+1F600 (4 bytes).
    // &#x42; stays a single ASCII byte. Mixed with an attribute value.
    const input = "<x attr='&#233;'>a&#233;b&#x1F600;c&#x42;</x>";
    var pos: usize = 0;

    _ = (try scanner.next(input, &pos)).?; // element_open
    const attr_tok = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.attribute, attr_tok.type);
    try std.testing.expectEqualStrings("\xc3\xa9", attr_tok.value);

    _ = (try scanner.next(input, &pos)).?; // element_open_end
    const tok = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.text, tok.type);
    try std.testing.expectEqualStrings("a\xc3\xa9b\xf0\x9f\x98\x80cB", tok.name);
    try std.testing.expect(std.unicode.utf8ValidateSlice(tok.name));
}

test "entity decoding: non-Char numeric refs rejected (S21)" {
    const cases = [_][]const u8{
        "<x>&#0;</x>", // NUL is not an XML Char
        "<x>&#1;</x>", // C0 control
        "<x>&#xB;</x>", // vertical tab
        "<x>&#xD800;</x>", // UTF-16 surrogate half
        "<x>&#xFFFE;</x>", // noncharacter
        "<x>&#x110000;</x>", // beyond Unicode range
    };
    for (cases) |input| {
        const allocator = std.testing.allocator;
        var scanner = Scanner.init(allocator);
        defer scanner.deinit();

        var pos: usize = 0;
        _ = (try scanner.next(input, &pos)).?; // element_open
        _ = (try scanner.next(input, &pos)).?; // element_open_end
        try std.testing.expectError(error.InvalidEntityReference, scanner.next(input, &pos));
    }
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

test "XML comments are rejected as restricted XML" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    // RFC 6120 §11.1 restricted XML forbids comments.
    const input = "<!-- this is a comment --><presence/>";
    var pos: usize = 0;
    try std.testing.expectError(error.ForbiddenXmlConstruct, scanner.next(input, &pos));
}

test "S21: names outside the XML Name production are rejected" {
    const allocator = std.testing.allocator;

    const cases = [_][]const u8{
        // '<' inside an element name would be re-emitted verbatim and could
        // open a new element downstream.
        "<foo<bar a='1'/>",
        // Quote inside an attribute name.
        "<a b'c='1'/>",
        // Quote inside a close tag name.
        "</a'>",
        // Empty xmlns prefix.
        "<a xmlns:='urn:x'/>",
    };
    for (cases) |input| {
        var scanner = Scanner.init(allocator);
        defer scanner.deinit();
        var pos: usize = 0;
        var got_error = false;
        for (0..8) |_| {
            _ = scanner.next(input, &pos) catch |err| {
                try std.testing.expectEqual(error.InvalidName, err);
                got_error = true;
                break;
            } orelse break;
        }
        try std.testing.expect(got_error);
    }
}

test "S21: legal names still parse, including utf8 and whitespace before =" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();
    const input = "<stream:stream xml:lang ='en' data-x.y_z='\xc3\xa9'/>";
    var pos: usize = 0;

    const open_tok = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.element_open, open_tok.type);
    try std.testing.expectEqualStrings("stream:stream", open_tok.name);

    const lang = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.attribute, lang.type);
    try std.testing.expectEqualStrings("xml:lang", lang.name);
    try std.testing.expectEqualStrings("en", lang.value);

    const data = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.attribute, data.type);
    try std.testing.expectEqualStrings("data-x.y_z", data.name);
}

test "S21: entity in attribute value keeps the attribute name" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    const input = "<x id='a&amp;b' xmlns='urn:a&amp;b'/>";
    var pos: usize = 0;

    const open_tok = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.element_open, open_tok.type);
    try std.testing.expectEqualStrings("x", open_tok.name);

    const attr = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.attribute, attr.type);
    try std.testing.expectEqualStrings("id", attr.name);
    try std.testing.expectEqualStrings("a&b", attr.value);

    // An entity inside xmlns still counts as a namespace declaration.
    const ns = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.namespace_decl, ns.type);
    try std.testing.expectEqualStrings("xmlns", ns.name);
    try std.testing.expectEqualStrings("urn:a&b", ns.value);
}

test "S21: numeric char refs are strict digits, leading zeros allowed" {
    const allocator = std.testing.allocator;

    const bad = [_][]const u8{
        "&#+65;", // sign is not part of the CharRef production
        "&#1_0_0;", // underscores are not digits
        "&#x4+1;",
        "&#;",
    };
    for (bad) |ref| {
        var scanner = Scanner.init(allocator);
        defer scanner.deinit();
        var buf: [64]u8 = undefined;
        const input = std.fmt.bufPrint(&buf, "<x>{s}</x>", .{ref}) catch unreachable;
        var pos: usize = 0;
        _ = (try scanner.next(input, &pos)).?; // <x>
        _ = (try scanner.next(input, &pos)).?; // element_open_end
        try std.testing.expectError(error.InvalidEntityReference, scanner.next(input, &pos));
    }

    var scanner = Scanner.init(allocator);
    defer scanner.deinit();
    const input = "<x>&#0065;&#x41;</x>";
    var pos: usize = 0;
    _ = (try scanner.next(input, &pos)).?; // <x>
    _ = (try scanner.next(input, &pos)).?; // element_open_end
    const text = (try scanner.next(input, &pos)).?;
    try std.testing.expectEqual(TokenType.text, text.type);
    try std.testing.expectEqualStrings("AA", text.name);
}

