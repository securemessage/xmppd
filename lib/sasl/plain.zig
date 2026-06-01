const std = @import("std");

/// SASL PLAIN mechanism per RFC 4616.
///
/// Message format: [authzid] NUL authcid NUL passwd
///
/// PLAIN should ONLY be used over TLS. The server implementation
/// receives the decoded message and extracts credentials.

pub const PlainCredentials = struct {
    /// Authorization identity (empty = same as authcid)
    authzid: []const u8,
    /// Authentication identity (username)
    authcid: []const u8,
    /// Password (plaintext)
    password: []const u8,
};

/// Parse a SASL PLAIN message (already base64-decoded).
/// Returns the extracted credentials.
pub fn parse(message: []const u8) !PlainCredentials {
    // Format: [authzid] \0 authcid \0 passwd
    const first_nul = std.mem.indexOfScalar(u8, message, 0) orelse return error.InvalidMessage;
    const rest = message[first_nul + 1 ..];
    const second_nul = std.mem.indexOfScalar(u8, rest, 0) orelse return error.InvalidMessage;

    const authzid = message[0..first_nul];
    const authcid = rest[0..second_nul];
    const password = rest[second_nul + 1 ..];

    if (authcid.len == 0) return error.EmptyUsername;
    if (password.len == 0) return error.EmptyPassword;

    return PlainCredentials{
        .authzid = authzid,
        .authcid = authcid,
        .password = password,
    };
}

/// Build a SASL PLAIN message (for client-side / testing).
pub fn build(alloc: std.mem.Allocator, authzid: []const u8, authcid: []const u8, password: []const u8) ![]const u8 {
    const total_len = authzid.len + 1 + authcid.len + 1 + password.len;
    const buf = try alloc.alloc(u8, total_len);

    var offset: usize = 0;
    @memcpy(buf[offset .. offset + authzid.len], authzid);
    offset += authzid.len;
    buf[offset] = 0;
    offset += 1;
    @memcpy(buf[offset .. offset + authcid.len], authcid);
    offset += authcid.len;
    buf[offset] = 0;
    offset += 1;
    @memcpy(buf[offset .. offset + password.len], password);

    return buf;
}

// --- Tests ---

test "parse PLAIN message" {
    // "\0testuser\0testpass"
    const msg = "\x00testuser\x00testpass";
    const creds = try parse(msg);
    try std.testing.expectEqualStrings("", creds.authzid);
    try std.testing.expectEqualStrings("testuser", creds.authcid);
    try std.testing.expectEqualStrings("testpass", creds.password);
}

test "parse PLAIN with authzid" {
    const msg = "admin\x00testuser\x00testpass";
    const creds = try parse(msg);
    try std.testing.expectEqualStrings("admin", creds.authzid);
    try std.testing.expectEqualStrings("testuser", creds.authcid);
    try std.testing.expectEqualStrings("testpass", creds.password);
}

test "parse PLAIN empty username fails" {
    const msg = "\x00\x00password";
    try std.testing.expectError(error.EmptyUsername, parse(msg));
}

test "parse PLAIN empty password fails" {
    const msg = "\x00user\x00";
    try std.testing.expectError(error.EmptyPassword, parse(msg));
}

test "parse PLAIN missing NUL fails" {
    try std.testing.expectError(error.InvalidMessage, parse("no-nulls-here"));
}

test "build and parse roundtrip" {
    const alloc = std.testing.allocator;
    const msg = try build(alloc, "", "alice", "secret123");
    defer alloc.free(msg);

    const creds = try parse(msg);
    try std.testing.expectEqualStrings("", creds.authzid);
    try std.testing.expectEqualStrings("alice", creds.authcid);
    try std.testing.expectEqualStrings("secret123", creds.password);
}
