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

/// Ceiling on one scanner token: an element or attribute name, an attribute
/// value, or a text run. Without it a peer can make the server allocate
/// without limit for a stanza it never finishes (S11). Overshoot is at most
/// one decoded entity, which appends up to four bytes.
pub const max_token_bytes = 512 * 1024;

/// Capacity the token buffers keep after an oversized token is consumed, so
/// one large stanza cannot pin its buffer for the life of the connection.
pub const max_token_retain = 4 * 1024;

/// Capacity the token arena keeps across a per-stanza reset, matching the
/// reader's own retain limit (S26).
pub const max_token_arena_retain = 64 * 1024;

/// Default ceiling on all bytes in one stream header or top-level stanza.
/// It exceeds the per-token cap so token errors keep their existing boundary.
pub const default_max_item_bytes = 2 * max_token_bytes;

/// Streaming XML scanner for XMPP streams.
///
/// Designed for XMPP's streaming model where `<stream:stream>` is opened
/// and never closed until disconnect. Produces tokens incrementally as
/// bytes are fed in.
pub const Scanner = struct {
    state: State = .content,
    /// Element nesting depth, counted the same way the reader counts it: 0
    /// outside the stream root, 1 between stanzas, 2+ inside a stanza. It
    /// exists so inter-stanza whitespace is never accumulated and so the
    /// token arena can be reset at each stanza boundary (S11).
    depth: u32 = 0,
    max_item_bytes: usize = default_max_item_bytes,
    item_bytes: usize = 0,
    item_active: bool = false,
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
    /// Retained capacity is bounded so one oversized token cannot pin a large
    /// buffer for the life of the connection (S11).
    pub fn resetArena(self: *Scanner) void {
        _ = self.token_arena.reset(.{ .retain_with_limit = max_token_arena_retain });
    }

    /// Full reset for stream restart (e.g., after STARTTLS or SASL success).
    /// Clears all accumulated state so the scanner can parse a fresh XML stream.
    pub fn reset(self: *Scanner) void {
        self.state = .content;
        self.depth = 0;
        self.buf.clearRetainingCapacity();
        self.val_buf.clearRetainingCapacity();
        self.ent_buf.clearRetainingCapacity();
        self.quote_char = 0;
        self.saw_slash = false;
        self.item_bytes = 0;
        self.item_active = false;
        self.pending.clearRetainingCapacity();
        _ = self.token_arena.reset(.retain_capacity);
    }

    pub fn setMaxItemBytes(self: *Scanner, max_bytes: usize) void {
        self.max_item_bytes = max_bytes;
    }

    const ally = struct {
        inline fn get(self: *Scanner) std.mem.Allocator {
            return self.allocator;
        }
    };

    /// Feed bytes into the scanner and extract the next token.
    /// Returns null if more data is needed.
    ///
    /// Every token passes through here on its way out, which is the one place
    /// `depth` is maintained (S11).
    pub fn next(self: *Scanner, input: []const u8, pos: *usize) !?Token {
        const token = try self.nextToken(input, pos) orelse return null;
        switch (token.type) {
            .xml_declaration => {
                if (self.depth <= 1) self.item_active = false;
            },
            .element_open_end => {
                const was_stream_root = self.depth == 0;
                self.depth += 1;
                if (was_stream_root) self.item_active = false;
            },
            // Opens and closes in one token, so the net depth change is zero,
            // matching the reader's own bookkeeping.
            .element_self_close => {
                if (self.depth <= 1) self.item_active = false;
            },
            .element_close => {
                if (self.depth > 0) self.depth -= 1;
                if (self.depth <= 1) self.item_active = false;
            },
            else => {},
        }
        return token;
    }

    fn nextToken(self: *Scanner, input: []const u8, pos: *usize) !?Token {
        // If we have pending tokens, return them first
        if (self.pending.items.len > 0) {
            const token = self.pending.orderedRemove(0);
            return token;
        }

        const a = self.allocator;

        while (pos.* < input.len) {
            const c = input[pos.*];
            pos.* += 1;

            if (self.state == .content and c == '<' and self.depth <= 1) {
                self.item_bytes = 0;
                self.item_active = true;
            }
            if (self.item_active) {
                if (self.item_bytes >= self.max_item_bytes) return error.ItemTooLong;
                self.item_bytes += 1;
            }

            switch (self.state) {
                .content => {
                    if (c == '<') {
                        // Stanza boundary. Every token of the previous stanza
                        // has been consumed by now: the reader dupes each one
                        // into its own arena, and the one exception, forwarded
                        // inter-stanza text, is consumed before the next call.
                        // The token arena dies here with a bounded retain so a
                        // long-lived stream does not accumulate tokens (S11).
                        if (self.depth <= 1) self.resetArena();
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
                        // Whitespace between stanzas is never accumulated: a
                        // peer must not be able to grow the buffer without
                        // bound by never sending the next '<' (S11). A run
                        // that already holds non-whitespace content keeps its
                        // trailing spaces so text is not corrupted.
                        if (self.depth <= 1 and self.buf.items.len == 0 and isSpace(c)) continue;
                        try self.appendCapped(&self.buf, c);
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
                        try self.appendCapped(&self.buf, c);
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
                            try self.appendCapped(&self.buf, '/');
                            self.saw_slash = false;
                        }
                        try self.appendCapped(&self.buf, c);
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
                        try self.appendCapped(&self.buf, c);
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
                        try self.appendCapped(&self.buf, c);
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
                        try self.appendCapped(&self.val_buf, c);
                    }
                },
                .close_tag_name => {
                    if (c == '>') {
                        self.state = .content;
                        // A close tag is "Name S?": trailing whitespace before
                        // '>' is legal (</a >), so trim it before validating.
                        // Anything else after the name (</a b>) stays in the
                        // run and fails the name check.
                        const raw = self.buf.items;
                        var end = raw.len;
                        while (end > 0 and isSpace(raw[end - 1])) : (end -= 1) {}
                        if (!isValidXmlName(raw[0..end])) return error.InvalidName;
                        const name = try self.token_arena.allocator().dupe(u8, raw[0..end]);
                        self.releaseTokenBuf(&self.buf);
                        const parsed = splitPrefixLocal(name);
                        return Token{
                            .type = .element_close,
                            .name = name,
                            .prefix = parsed.prefix,
                            .local_name = parsed.local,
                        };
                    } else {
                        try self.appendCapped(&self.buf, c);
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
                        try self.appendCapped(&self.buf, c);
                    }
                },
                .bang_start => {
                    // After `<!`: comments, DOCTYPE, ENTITY and CDATA are all
                    // forbidden in XMPP (RFC 6120 §11.1 restricted XML).
                    try self.appendCapped(&self.buf, c);
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

    /// Append one byte to a token buffer, enforcing max_token_bytes. The
    /// ceiling bounds what a peer can make the server allocate for a token it
    /// never terminates (S11).
    fn appendCapped(self: *Scanner, list: *std.ArrayList(u8), byte: u8) !void {
        if (list.items.len >= max_token_bytes) {
            // Rejecting the token must not leave its bytes pinned either.
            self.releaseTokenBuf(list);
            return error.TokenTooLong;
        }
        try list.append(self.allocator, byte);
    }

    fn isSpace(c: u8) bool {
        return c == ' ' or c == '\t' or c == '\n' or c == '\r';
    }

    /// Drop the token's bytes and release capacity above max_token_retain, so
    /// one oversized token does not pin its buffer for the life of the
    /// connection. The shrink runs while the length still exceeds the limit:
    /// shrinkAndFree requires the new length to fit the current one.
    fn releaseTokenBuf(self: *Scanner, list: *std.ArrayList(u8)) void {
        if (list.items.len > max_token_retain) {
            list.shrinkAndFree(self.allocator, max_token_retain);
        }
        list.clearRetainingCapacity();
    }

    fn dupeAndClear(self: *Scanner, list: *std.ArrayList(u8)) ![]const u8 {
        const arena_alloc = self.token_arena.allocator();
        const result = try arena_alloc.dupe(u8, list.items);
        self.releaseTokenBuf(list);
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
    // instead of a length-limited parseInt. The hex marker is a literal
    // lowercase 'x' (XML 1.0 production 66), so &#XHH; is not a CharRef.
    if (name.len > 1 and name[0] == '#') {
        const hex = name[1] == 'x';
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

test "scanner: close tag allows trailing whitespace but not attributes" {
    const allocator = std.testing.allocator;

    // </a > is a legal close tag (Name S?); the name is "a".
    {
        var scanner = Scanner.init(allocator);
        defer scanner.deinit();
        const input = "<x></a >";
        var pos: usize = 0;
        _ = (try scanner.next(input, &pos)).?; // element_open
        _ = (try scanner.next(input, &pos)).?; // element_open_end
        const close = (try scanner.next(input, &pos)).?;
        try std.testing.expectEqual(TokenType.element_close, close.type);
        try std.testing.expectEqualStrings("a", close.name);
    }

    // </a b> is not a legal close tag (attributes are not allowed).
    {
        var scanner = Scanner.init(allocator);
        defer scanner.deinit();
        const input = "<x></a b>";
        var pos: usize = 0;
        _ = (try scanner.next(input, &pos)).?; // element_open
        _ = (try scanner.next(input, &pos)).?; // element_open_end
        try std.testing.expectError(error.InvalidName, scanner.next(input, &pos));
    }
}

test "scanner: close tag allows trailing tab CR and LF" {
    const allocator = std.testing.allocator;
    const inputs = [_][]const u8{ "<x></a\t>", "<x></a\r>", "<x></a\n>" };

    for (inputs) |input| {
        var scanner = Scanner.init(allocator);
        defer scanner.deinit();
        var pos: usize = 0;
        _ = (try scanner.next(input, &pos)).?;
        _ = (try scanner.next(input, &pos)).?;
        const close = (try scanner.next(input, &pos)).?;
        try std.testing.expectEqual(TokenType.element_close, close.type);
        try std.testing.expectEqualStrings("a", close.name);
    }
}

test "scanner: uppercase hex CharRef is rejected (&#X41;)" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    // XML 1.0 production 66 spells the hex marker as a literal lowercase 'x',
    // so &#X41; is not a CharRef even though &#x41; is.
    const input = "<x>&#X41;</x>";
    var pos: usize = 0;
    _ = (try scanner.next(input, &pos)).?; // element_open
    _ = (try scanner.next(input, &pos)).?; // element_open_end
    try std.testing.expectError(error.InvalidEntityReference, scanner.next(input, &pos));
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

// --- S11: token size cap and inter-stanza growth ---

/// Feed `input` to a fresh scanner and return the first error, or null if it
/// parsed cleanly.
fn scanExpectingError(allocator: std.mem.Allocator, input: []const u8) ?anyerror {
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();
    var pos: usize = 0;
    while (pos < input.len) {
        _ = scanner.next(input, &pos) catch |err| return err;
    }
    return null;
}

test "S11: an overlong text run is rejected instead of growing without limit" {
    const allocator = std.testing.allocator;
    const run = try allocator.alloc(u8, max_token_bytes + 1);
    defer allocator.free(run);
    @memset(run, 'a');

    // Text sits inside an element so it is stanza content, not skippable
    // inter-stanza whitespace.
    const prefix = "<message><body>";
    const input = try std.mem.concat(allocator, u8, &.{ prefix, run, "</body></message>" });
    defer allocator.free(input);

    try std.testing.expectEqual(@as(?anyerror, error.TokenTooLong), scanExpectingError(allocator, input));
}

test "S11: a text run exactly at the cap still parses" {
    const allocator = std.testing.allocator;
    const run = try allocator.alloc(u8, max_token_bytes);
    defer allocator.free(run);
    @memset(run, 'a');

    const prefix = "<message><body>";
    const input = try std.mem.concat(allocator, u8, &.{ prefix, run, "</body></message>" });
    defer allocator.free(input);

    var scanner = Scanner.init(allocator);
    defer scanner.deinit();
    var pos: usize = 0;
    var text: ?Token = null;
    while (pos < input.len) {
        const token = try scanner.next(input, &pos) orelse break;
        if (token.type == .text) text = token;
    }
    try std.testing.expect(text != null);
    try std.testing.expectEqual(@as(usize, max_token_bytes), text.?.name.len);
}

test "S11: an overlong attribute value is rejected" {
    const allocator = std.testing.allocator;
    const run = try allocator.alloc(u8, max_token_bytes + 1);
    defer allocator.free(run);
    @memset(run, 'a');

    const input = try std.mem.concat(allocator, u8, &.{ "<message to='", run, "'/>" });
    defer allocator.free(input);

    try std.testing.expectEqual(@as(?anyerror, error.TokenTooLong), scanExpectingError(allocator, input));
}

test "S11: an overlong element name is rejected" {
    const allocator = std.testing.allocator;
    const run = try allocator.alloc(u8, max_token_bytes + 1);
    defer allocator.free(run);
    @memset(run, 'a');

    const input = try std.mem.concat(allocator, u8, &.{ "<", run, ">" });
    defer allocator.free(input);

    try std.testing.expectEqual(@as(?anyerror, error.TokenTooLong), scanExpectingError(allocator, input));
}

test "S11: an overlong close-tag name is rejected" {
    const allocator = std.testing.allocator;
    const run = try allocator.alloc(u8, max_token_bytes + 1);
    defer allocator.free(run);
    @memset(run, 'a');

    const input = try std.mem.concat(allocator, u8, &.{ "</", run, ">" });
    defer allocator.free(input);

    try std.testing.expectEqual(@as(?anyerror, error.TokenTooLong), scanExpectingError(allocator, input));
}

test "S11: an overlong attribute name is rejected" {
    const allocator = std.testing.allocator;
    const run = try allocator.alloc(u8, max_token_bytes + 1);
    defer allocator.free(run);
    @memset(run, 'a');

    const input = try std.mem.concat(allocator, u8, &.{ "<message ", run, "='v'/>" });
    defer allocator.free(input);

    try std.testing.expectEqual(@as(?anyerror, error.TokenTooLong), scanExpectingError(allocator, input));
}

test "S11: 2 MiB of inter-stanza whitespace does not grow the token buffers" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    var pos: usize = 0;
    _ = try scanner.next("<stream:stream>", &pos);
    _ = try scanner.next("<presence/>", &pos);
    try std.testing.expectEqual(@as(u32, 1), scanner.depth);

    // Whitespace a peer streams between stanzas without ever sending the next
    // '<' used to accumulate in buf for the life of the connection.
    const ws = try allocator.alloc(u8, 2 * 1024 * 1024);
    defer allocator.free(ws);
    @memset(ws, ' ');
    pos = 0;
    var saw_text = false;
    while (pos < ws.len) {
        const token = try scanner.next(ws, &pos) orelse continue;
        if (token.type == .text) saw_text = true;
    }
    try std.testing.expect(!saw_text);
    try std.testing.expect(scanner.buf.items.len == 0);
    try std.testing.expect(scanner.buf.capacity <= max_token_retain);
}

test "S11: whitespace inside a stanza is preserved" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    // Skipping is scoped to the stanza level only; message content must keep
    // its spaces or a stanza is silently rewritten.
    const input = "<message><body> a b </body></message>";
    var pos: usize = 0;
    while (pos < input.len) {
        const token = try scanner.next(input, &pos) orelse break;
        if (token.type == .text) {
            try std.testing.expectEqualStrings(" a b ", token.name);
            return;
        }
    }
    return error.ExpectedText;
}

test "S11: the token arena stays bounded over many stanzas" {
    const allocator = std.testing.allocator;
    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    var pos: usize = 0;
    _ = try scanner.next("<stream:stream>", &pos);

    const stanza = "<message id='m1'><body>payload</body></message>";
    for (0..2_000) |_| {
        pos = 0;
        while (pos < stanza.len) {
            _ = try scanner.next(stanza, &pos) orelse break;
        }
    }
    // Every token of a stanza is duped out of this arena, so it dies at the
    // next stanza boundary instead of growing for the life of the stream.
    try std.testing.expect(scanner.token_arena.queryCapacity() <= max_token_arena_retain);
}
