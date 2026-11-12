//! Stanza serialization helpers: XML escaping, element open/close tag writers,
//! base64 for SASL payloads, and the S2S/cross-worker error-stanza writers.
//! Extracted from server.zig (ADR-12).

const std = @import("std");
const xml = @import("xml");


// ============================================================================
// Base64 helpers for SASL XML payloads
// ============================================================================

/// Re-encode text for XML output. The XML parser decodes entities (&amp; → &),
/// so when serializing parsed content back to XML we must re-encode them.
pub fn xmlEscapeWrite(writer: anytype, text: []const u8) !void {
    return xml.escapeWrite(writer, text);
}

/// Write a child element opening tag, re-emitting namespace declarations the
/// reader resolved away. Fills the writer until it is out of space, returning
/// the fixed-buffer error so the caller can mark the stanza bad.
pub fn writeStanzaOpenTag(w: anytype, elem: xml.Element) !void {
    try w.writeByte('<');
    try w.writeAll(elem.name);

    // Reconstruct namespace declaration if element uses a non-default namespace.
    // The reader resolves xmlns declarations into namespace_uri but doesn't
    // include them in the attributes array, so we must re-emit them.
    if (elem.namespace_uri.len > 0 and !std.mem.eql(u8, elem.namespace_uri, xml.ns.client)) {
        if (elem.prefix.len > 0) {
            try w.writeAll(" xmlns:");
            try w.writeAll(elem.prefix);
            try w.writeAll("='");
            try xml.escapeWrite(w, elem.namespace_uri);
            try w.writeByte('\'');
        } else {
            try w.writeAll(" xmlns='");
            try xml.escapeWrite(w, elem.namespace_uri);
            try w.writeByte('\'');
        }
    }

    for (elem.attributes) |attr| {
        try w.writeByte(' ');
        try w.writeAll(attr.name);
        try w.writeAll("='");
        try xmlEscapeWrite(w, attr.value);
        try w.writeByte('\'');
    }

    if (elem.self_closing) {
        try w.writeAll("/>");
    } else {
        try w.writeByte('>');
    }
}

pub fn writeStanzaCloseTag(w: anytype, name: []const u8) !void {
    try w.writeAll("</");
    try w.writeAll(name);
    try w.writeByte('>');
}

/// Decode base64 into a fixed buffer. Returns the decoded slice or null on error.
pub fn b64Decode(input: []const u8, output: []u8) ?[]const u8 {
    if (input.len == 0) return output[0..0];
    const decoder = std.base64.standard.Decoder;
    const upper_bound = decoder.calcSizeUpperBound(input.len) catch return null;
    if (upper_bound > output.len) return null;
    decoder.decode(output[0..upper_bound], input) catch return null;
    // calcSizeUpperBound doesn't account for '=' padding — subtract padding
    // chars to get the actual decoded length.
    var decoded_len = upper_bound;
    if (input[input.len - 1] == '=') decoded_len -= 1;
    if (input.len >= 2 and input[input.len - 2] == '=') decoded_len -= 1;
    return output[0..decoded_len];
}

/// Base64-encode data and write directly to a writer.
pub fn b64EncodeWrite(writer: anytype, data: []const u8) !void {
    const encoder = std.base64.standard.Encoder;
    var buf: [4096]u8 = undefined;
    const enc_len = encoder.calcSize(data.len);
    if (enc_len > buf.len) return error.BufferTooSmall;
    const encoded = encoder.encode(buf[0..enc_len], data);
    try writer.writeAll(encoded);
}

/// attribute value from extractAttrValue: it is decoded and then escaped once,
/// so an entity in the id is not double-escaped and a quote cannot break the
/// attribute (G7). from/to are plain JIDs and are escaped once. Serialization
/// errors propagate so the caller can log them.
pub fn writeS2sBounce(w: anytype, local_to: []const u8, remote_from: []const u8, msg_id: []const u8) !void {
    return writeS2sError(w, "message", local_to, remote_from, msg_id);
}

/// Serialize a service-unavailable bounce for a stanza whose sender lives on
/// the local server. Mirrors `writeS2sError`: the id is decoded and escaped
/// once so an entity in the id is not double-escaped (G7).
pub fn writeCrossWorkerError(w: anytype, tag_name: []const u8, recipient: []const u8, sender: []const u8, stanza_id: []const u8) !void {
    try w.writeByte('<');
    try w.writeAll(tag_name);
    try w.writeAll(" type='error' from='");
    try xml.escapeWrite(w, recipient);
    try w.writeAll("' to='");
    try xml.escapeWrite(w, sender);
    try w.writeByte('\'');
    if (stanza_id.len > 0) {
        try w.writeAll(" id='");
        var id_buf: [1024]u8 = undefined;
        var id_fbs = std.io.fixedBufferStream(&id_buf);
        try xml.decodeWrite(id_fbs.writer(), stanza_id);
        try xml.escapeWrite(w, id_fbs.getWritten());
        try w.writeByte('\'');
    }
    try w.writeAll("><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></");
    try w.writeAll(tag_name);
    try w.writeByte('>');
}

pub fn writeS2sError(w: anytype, tag_name: []const u8, local_to: []const u8, remote_from: []const u8, stanza_id: []const u8) !void {
    try w.writeByte('<');
    try w.writeAll(tag_name);
    try w.writeAll(" type='error' from='");
    try xml.escapeWrite(w, local_to);
    try w.writeAll("' to='");
    try xml.escapeWrite(w, remote_from);
    try w.writeByte('\'');
    if (stanza_id.len > 0) {
        try w.writeAll(" id='");
        var id_buf: [1024]u8 = undefined;
        var id_fbs = std.io.fixedBufferStream(&id_buf);
        try xml.decodeWrite(id_fbs.writer(), stanza_id);
        try xml.escapeWrite(w, id_fbs.getWritten());
        try w.writeByte('\'');
    }
    try w.writeAll("><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></");
    try w.writeAll(tag_name);
    try w.writeByte('>');
}

