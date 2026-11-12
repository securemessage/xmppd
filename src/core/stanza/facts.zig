//! Stanza fact extraction: tag/kind/attribute parsing for serialized stanzas.
//! Extracted from server.zig (ADR-12).

const std = @import("std");

// ============================================================================
// S2S stanza parsing helpers
// ============================================================================

pub const StanzaParts = struct {
    is_message: bool,
    is_iq: bool,
    msg_type: []const u8,
    msg_id: []const u8,
    inner_xml: []const u8,
};

/// Extract the inner XML content, type attribute, and id attribute from a
/// complete stanza XML string (e.g., "<message from='a' to='b' type='chat'
/// id='1'><body>hello</body></message>"). Used for S2S offline storage to
/// avoid double-wrapping.
pub fn extractStanzaParts(stanza: []const u8) StanzaParts {
    var result = StanzaParts{
        .is_message = false,
        .is_iq = false,
        .msg_type = "",
        .msg_id = "",
        .inner_xml = "",
    };

    if (stanza.len < 3 or stanza[0] != '<') return result;

    // Find end of tag name (first space or '>' or '/')
    var i: usize = 1;
    while (i < stanza.len and stanza[i] != ' ' and stanza[i] != '>' and stanza[i] != '/') : (i += 1) {}
    const tag_name = stanza[1..i];
    result.is_message = std.mem.eql(u8, tag_name, "message");
    result.is_iq = std.mem.eql(u8, tag_name, "iq");

    // Find end of opening tag — scan for first '>' that's not inside an attr value
    var in_quote: bool = false;
    var quote_char: u8 = 0;
    var opening_end: usize = 0;
    var self_closing = false;
    var j: usize = i;
    while (j < stanza.len) : (j += 1) {
        if (in_quote) {
            if (stanza[j] == quote_char) in_quote = false;
        } else if (stanza[j] == '\'' or stanza[j] == '"') {
            in_quote = true;
            quote_char = stanza[j];
        } else if (stanza[j] == '>') {
            if (j > 0 and stanza[j - 1] == '/') self_closing = true;
            opening_end = j;
            break;
        }
    }

    if (opening_end == 0) return result;

    // Extract type and id attributes from the opening tag
    const tag_portion = stanza[0 .. opening_end + 1];
    result.msg_type = extractAttrValue(tag_portion, "type");
    result.msg_id = extractAttrValue(tag_portion, "id");

    if (self_closing) {
        result.inner_xml = "";
        return result;
    }

    // Inner XML is everything between '>' of opening tag and '</' of closing tag
    const inner_start = opening_end + 1;

    // Find closing tag: search backwards for "</"
    var k: usize = stanza.len;
    while (k > inner_start + 1) {
        k -= 1;
        if (stanza[k] == '/' and k > 0 and stanza[k - 1] == '<') {
            result.inner_xml = stanza[inner_start .. k - 1];
            return result;
        }
    }

    // No closing tag found — return everything after the opening tag
    result.inner_xml = stanza[inner_start..];
    return result;
}

/// Extract the value of an attribute from an XML opening tag string.
/// Returns an empty slice if the attribute is not found.
pub fn extractAttrValue(tag: []const u8, attr_name: []const u8) []const u8 {
    // Search for ' attr_name=' or ' attr_name="'
    var pos: usize = 0;
    while (pos + attr_name.len + 2 < tag.len) {
        if (tag[pos] == ' ' and
            pos + 1 + attr_name.len + 1 < tag.len and
            std.mem.eql(u8, tag[pos + 1 .. pos + 1 + attr_name.len], attr_name) and
            tag[pos + 1 + attr_name.len] == '=')
        {
            const val_start_idx = pos + 1 + attr_name.len + 1;
            if (val_start_idx >= tag.len) return "";
            const quote = tag[val_start_idx];
            if (quote != '\'' and quote != '"') return "";
            const val_start = val_start_idx + 1;
            var val_end = val_start;
            while (val_end < tag.len and tag[val_end] != quote) : (val_end += 1) {}
            return tag[val_start..val_end];
        }
        pos += 1;
    }
    return "";
}

test "extractStanzaParts: message with body" {
    const stanza = "<message from='alice@remote.test' to='bob@local.test' type='chat' id='msg1'><body>hello</body></message>";
    const parts = extractStanzaParts(stanza);
    try std.testing.expect(parts.is_message);
    try std.testing.expectEqualStrings("chat", parts.msg_type);
    try std.testing.expectEqualStrings("msg1", parts.msg_id);
    try std.testing.expectEqualStrings("<body>hello</body>", parts.inner_xml);
}

test "extractStanzaParts: self-closing presence" {
    const stanza = "<presence from='alice@remote.test' to='bob@local.test' type='subscribe'/>";
    const parts = extractStanzaParts(stanza);
    try std.testing.expect(!parts.is_message);
    try std.testing.expectEqualStrings("subscribe", parts.msg_type);
    try std.testing.expectEqualStrings("", parts.inner_xml);
}

test "extractStanzaParts: message with no type" {
    const stanza = "<message from='a@b' to='c@d'><body>hi</body></message>";
    const parts = extractStanzaParts(stanza);
    try std.testing.expect(parts.is_message);
    try std.testing.expectEqualStrings("", parts.msg_type);
    try std.testing.expectEqualStrings("<body>hi</body>", parts.inner_xml);
}

test "extractAttrValue: finds attribute" {
    try std.testing.expectEqualStrings("chat", extractAttrValue("<message type='chat'>", "type"));
    try std.testing.expectEqualStrings("msg1", extractAttrValue("<message from='a' id='msg1' to='b'>", "id"));
    try std.testing.expectEqualStrings("", extractAttrValue("<message from='a'>", "type"));
}
