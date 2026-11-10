const std = @import("std");

/// TLS configuration and STARTTLS negotiation for XMPP.
///
/// This module wraps libressl/libcrypto for TLS operations.
/// It provides:
/// - Certificate loading and validation
/// - STARTTLS upgrade of an existing TCP connection
/// - XMPP stream feature advertisement
///
/// TLSA parsing and matching live in the shared `pacyworld/dane-zig` module
/// (`dane`); `lib/tls/ssl.zig` is the only place that bridges it to OpenSSL.

/// TLS verification mode.
pub const VerifyMode = enum {
    /// DANE-first: TLSA → PKIX fallback
    dane_first,
    /// PKIX only: standard CA validation
    pkix_only,
    /// No verification (testing only!)
    none,
};

/// Generate the XMPP STARTTLS stream feature XML.
pub fn starttlsFeatureXml(writer: anytype, required: bool) !void {
    try writer.writeAll("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>");
    if (required) {
        try writer.writeAll("<required/>");
    }
    try writer.writeAll("</starttls>");
}

/// Generate the STARTTLS proceed response.
pub fn starttlsProceedXml(writer: anytype) !void {
    try writer.writeAll("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
}

/// Generate the STARTTLS failure response.
pub fn starttlsFailureXml(writer: anytype) !void {
    try writer.writeAll("<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
}

// --- Tests ---

test "STARTTLS feature XML" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try starttlsFeatureXml(fbs.writer(), true);
    const result = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, result, "xmlns='urn:ietf:params:xml:ns:xmpp-tls'") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "<required/>") != null);
}

test "STARTTLS proceed XML" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try starttlsProceedXml(fbs.writer());
    const result = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, result, "<proceed") != null);
}
