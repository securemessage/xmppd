const std = @import("std");
pub const scram = @import("scram.zig");
pub const plain = @import("plain.zig");

pub const ScramServer = scram.ScramServer;
pub const ScramClient = scram.ScramClient;
pub const StoredCredentials = scram.StoredCredentials;
pub const PlainCredentials = plain.PlainCredentials;

/// Supported SASL mechanisms.
pub const Mechanism = enum {
    scram_sha_256,
    plain,
    external,

    pub fn name(self: Mechanism) []const u8 {
        return switch (self) {
            .scram_sha_256 => "SCRAM-SHA-256",
            .plain => "PLAIN",
            .external => "EXTERNAL",
        };
    }

    pub fn fromName(s: []const u8) ?Mechanism {
        if (std.mem.eql(u8, s, "SCRAM-SHA-256")) return .scram_sha_256;
        if (std.mem.eql(u8, s, "PLAIN")) return .plain;
        if (std.mem.eql(u8, s, "EXTERNAL")) return .external;
        return null;
    }
};

/// Result of an authentication attempt.
pub const AuthResult = union(enum) {
    /// Authentication succeeded. Contains the authenticated JID localpart.
    success: []const u8,
    /// Challenge to send back to the client (SCRAM intermediate step).
    challenge: []const u8,
    /// Authentication failed.
    failure: []const u8,
};

/// Generate the XMPP SASL mechanisms advertisement XML.
/// Used in stream features to tell the client what mechanisms are available.
pub fn mechanismsXml(writer: anytype, mechanisms: []const Mechanism) !void {
    try writer.writeAll("<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>");
    for (mechanisms) |mech| {
        try writer.writeAll("<mechanism>");
        try writer.writeAll(mech.name());
        try writer.writeAll("</mechanism>");
    }
    try writer.writeAll("</mechanisms>");
}

/// Default recommended mechanism order (strongest first).
pub const recommended_mechanisms = [_]Mechanism{
    .scram_sha_256,
    .plain,
};

// --- Tests ---

test "Mechanism name roundtrip" {
    try std.testing.expectEqual(Mechanism.scram_sha_256, Mechanism.fromName("SCRAM-SHA-256").?);
    try std.testing.expectEqual(Mechanism.plain, Mechanism.fromName("PLAIN").?);
    try std.testing.expectEqual(Mechanism.external, Mechanism.fromName("EXTERNAL").?);
    try std.testing.expect(Mechanism.fromName("BOGUS") == null);
}

test "mechanismsXml output" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const mechanisms = [_]Mechanism{ .scram_sha_256, .plain };
    try mechanismsXml(fbs.writer(), &mechanisms);
    const result = fbs.getWritten();

    try std.testing.expect(std.mem.indexOf(u8, result, "xmlns='urn:ietf:params:xml:ns:xmpp-sasl'") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "<mechanism>SCRAM-SHA-256</mechanism>") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "<mechanism>PLAIN</mechanism>") != null);
}

test {
    _ = scram;
    _ = plain;
}
