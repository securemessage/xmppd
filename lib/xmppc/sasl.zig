//! # xmppc Client SASL — mechanism coordinator (RFC 6120 §12)
//!
//! Wraps the shared `lib/sasl` primitives (SCRAM-SHA-256 client proof path and
//! the PLAIN builder) behind one mechanism-agnostic interface the `Session`
//! drives from its stream FSM.
//!
//! All methods exchange RAW (unencoded) byte strings. Base64 is a transport
//! detail of the XMPP XML: the `Session` base64-encodes the returned messages
//! into `<auth>`/`<response>` and base64-decodes the `<challenge>`/`<success>`
//! text before calling back in.
//!
//! This module owns no sockets and no TLS; it is pure credential handling.

const std = @import("std");
const sasl = @import("sasl");

/// A client-side SASL mechanism instance.
pub const SaslClient = struct {
    mechanism: []const u8,
    allocator: std.mem.Allocator,
    /// SCRAM state (populated only for SCRAM-SHA-256).
    scram: ?sasl.ScramClient = null,
    /// PLAIN initial message (raw `\0authcid\0password`), for PLAIN only.
    plain_msg: []const u8 = "",
    /// True once the exchange is complete (SCRAM: after verifyServerFinal).
    complete: bool = false,

    /// Create a client for `mechanism` (e.g. "SCRAM-SHA-256" or "PLAIN").
    pub fn init(
        allocator: std.mem.Allocator,
        mechanism: []const u8,
        username: []const u8,
        password: []const u8,
    ) !SaslClient {
        var self = SaslClient{
            .mechanism = mechanism,
            .allocator = allocator,
        };
        errdefer self.deinit();

        if (std.mem.eql(u8, mechanism, "SCRAM-SHA-256")) {
            self.scram = sasl.ScramClient.init(allocator, username, password);
        } else if (std.mem.eql(u8, mechanism, "PLAIN")) {
            self.plain_msg = try sasl.plain.build(allocator, "", username, password);
        } else {
            return error.UnsupportedMechanism;
        }
        return self;
    }

    pub fn deinit(self: *SaslClient) void {
        if (self.scram) |*sc| sc.deinit();
        if (self.plain_msg.len > 0) self.allocator.free(self.plain_msg);
    }

    /// The RAW initial client message (base64-encode it into `<auth>`).
    pub fn initial(self: *SaslClient) ![]const u8 {
        if (self.scram) |*sc| return sc.clientFirst() catch return error.SaslInit;
        return self.plain_msg;
    }

    /// Given the RAW (base64-decoded) server challenge, return the RAW next
    /// client message, or `null` when the mechanism has no further client step.
    /// PLAIN is single-shot (the server answers `<success>` directly). SCRAM
    /// returns the client-final-message here; the subsequent `<success>` is
    /// verified via `verifyServerFinal`.
    pub fn handleChallenge(self: *SaslClient, challenge_raw: []const u8) !?[]const u8 {
        if (self.scram) |*sc| return try sc.handleServerFirst(challenge_raw);
        return null;
    }

    /// Verify the server signature (SCRAM server-final). No-op for PLAIN.
    pub fn verifyServerFinal(self: *SaslClient, final_raw: []const u8) !void {
        if (self.scram) |*sc| {
            try sc.handleServerFinal(final_raw);
            self.complete = sc.isComplete();
        }
    }

    pub fn isComplete(self: *const SaslClient) bool {
        return self.complete;
    }
};

// --- Tests ---

test "PLAIN initial decodes to authcid/pass" {
    const alloc = std.testing.allocator;
    var c = try SaslClient.init(alloc, "PLAIN", "alice", "secret");
    defer c.deinit();
    const raw = try c.initial();
    try std.testing.expectEqualStrings("\x00alice\x00secret", raw);
}

test "SCRAM client initial is well-formed" {
    const alloc = std.testing.allocator;
    var c = try SaslClient.init(alloc, "SCRAM-SHA-256", "alice", "secret");
    defer c.deinit();
    const raw = try c.initial();
    try std.testing.expect(std.mem.startsWith(u8, raw, "n,,n=alice,r="));
}

test "SCRAM full exchange against the server verifies" {
    const alloc = std.testing.allocator;
    const salt = [_]u8{0xAB} ** 32;
    const creds = sasl.StoredCredentials.derive("secret", salt, 4096);

    var client = try SaslClient.init(alloc, "SCRAM-SHA-256", "alice", "secret");
    defer client.deinit();
    const client_first = try client.initial();

    var server = sasl.ScramServer.init(alloc);
    defer server.deinit();
    const username = try server.handleClientFirst(client_first);
    try std.testing.expectEqualStrings("alice", username);
    server.setCredentials(creds);
    const server_first = try server.serverFirst();

    const client_final = (try client.handleChallenge(server_first)).?;
    const server_final = try server.handleClientFinal(client_final);
    try std.testing.expect(server.isComplete());

    try client.verifyServerFinal(server_final);
    try std.testing.expect(client.isComplete());
}

test "SCRAM wrong password fails at the server" {
    const alloc = std.testing.allocator;
    const salt = [_]u8{0xCD} ** 32;
    const creds = sasl.StoredCredentials.derive("correct", salt, 4096);

    var client = try SaslClient.init(alloc, "SCRAM-SHA-256", "alice", "wrong");
    defer client.deinit();
    const client_first = try client.initial();

    var server = sasl.ScramServer.init(alloc);
    defer server.deinit();
    _ = try server.handleClientFirst(client_first);
    server.setCredentials(creds);
    const server_first = try server.serverFirst();
    const client_final = (try client.handleChallenge(server_first)).?;

    try std.testing.expectError(error.AuthenticationFailed, server.handleClientFinal(client_final));
}

test "unsupported mechanism errors" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(error.UnsupportedMechanism, SaslClient.init(alloc, "EXTERNAL", "a", "b"));
}
