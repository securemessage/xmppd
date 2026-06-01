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
    /// Reading a comment `<!-- ... -->`
    comment,
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
                        // Comment or CDATA — for XMPP we only handle comments
                        self.state = .comment;
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
