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

    /// What handleChallenge needs next.
    pub const Challenge = union(enum) {
        /// Send this as the next client message ("" = empty <response/>).
        message: []const u8,
        /// Nothing to send; await <success> (PLAIN, or client-final sent).
        none,
        /// SCRAM: Hi() is expensive — derive the SaltedPassword off the
        /// event loop (Engine.queueDerive) and resume with finishChallenge.
        derive: Derive,
    };

    /// Parameters for one SaltedPassword derivation (Hi(password, salt, i)).
    pub const Derive = struct {
        salt: [sasl.ScramClient.max_salt_len]u8,
        salt_len: usize,
        iterations: u32,
    };

    /// Given the RAW (base64-decoded) server challenge, return what happens
    /// next. PLAIN is single-shot (.none; the server answers <success>
    /// directly). SCRAM returns .derive for the first challenge (the client
    /// parks until finishChallenge). A server that sends server-final as a
    /// second challenge (RFC 6120 6.4.6) gets it verified here and an empty
    /// response; its <success> is then empty.
    pub fn handleChallenge(self: *SaslClient, challenge_raw: []const u8) !Challenge {
        if (self.scram) |*sc| {
            if (sc.awaitingServerFinal()) {
                try sc.handleServerFinal(challenge_raw);
                self.complete = true;
                return .{ .message = "" };
            }
            try sc.parseServerFirst(challenge_raw);
            var d = Derive{
                .salt = undefined,
                .salt_len = sc.salt_raw_len,
                .iterations = sc.iteration_count,
            };
            @memcpy(d.salt[0..d.salt_len], sc.salt_raw[0..d.salt_len]);
            return .{ .derive = d };
        }
        return .none;
    }

    /// Finish a parked SCRAM step once the SaltedPassword is available;
    /// returns the RAW client-final-message.
    pub fn finishChallenge(self: *SaslClient, salted_password: [32]u8) ![]const u8 {
        const sc = if (self.scram) |*sc| sc else return error.InvalidState;
        return sc.clientFinal(salted_password);
    }

    /// The password a pending Derive applies to (SCRAM only, else null).
    pub fn derivePassword(self: *const SaslClient) ?[]const u8 {
        if (self.scram) |*sc| return sc.password;
        return null;
    }

    /// Verify the SCRAM server signature carried in `<success>`. Fails unless
    /// the signature checks out, or was already verified from a challenge and
    /// `<success>` is empty. No-op for PLAIN.
    pub fn verifyServerFinal(self: *SaslClient, final_raw: []const u8) !void {
        if (self.scram) |*sc| {
            if (self.complete and final_raw.len == 0) return;
            try sc.handleServerFinal(final_raw);
            self.complete = sc.isComplete();
        }
    }

    pub fn isComplete(self: *const SaslClient) bool {
        return self.complete;
    }
};

// --- Tests ---

/// Drive one SCRAM challenge synchronously (parse + inline derive + final),
/// the way a non-event-loop caller would.
fn driveScram(client: *SaslClient, password: []const u8, server_first: []const u8) ![]const u8 {
    return switch (try client.handleChallenge(server_first)) {
        .derive => |d| blk: {
            var salted: [32]u8 = undefined;
            sasl.scram.pbkdf2(password, d.salt[0..d.salt_len], d.iterations, &salted);
            break :blk try client.finishChallenge(salted);
        },
        .message => |m| m,
        .none => error.UnexpectedNone,
    };
}

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

    const client_final = try driveScram(&client, "secret", server_first);
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
    const client_final = try driveScram(&client, "wrong", server_first);

    try std.testing.expectError(error.AuthenticationFailed, server.handleClientFinal(client_final));
}

test "SCRAM: <success> without server-final is rejected" {
    const alloc = std.testing.allocator;
    const salt = [_]u8{0xAB} ** 32;
    const creds = sasl.StoredCredentials.derive("secret", salt, 4096);

    var client = try SaslClient.init(alloc, "SCRAM-SHA-256", "alice", "secret");
    defer client.deinit();
    var server = sasl.ScramServer.init(alloc);
    defer server.deinit();
    _ = try server.handleClientFirst(try client.initial());
    server.setCredentials(creds);
    _ = try driveScram(&client, "secret", try server.serverFirst());

    // An attacker skipping the proof with an empty <success/> must not pass.
    try std.testing.expectError(error.ServerAuthFailed, client.verifyServerFinal(""));
    try std.testing.expect(!client.isComplete());
}

test "SCRAM: server-final delivered as a challenge, then empty <success>" {
    const alloc = std.testing.allocator;
    const salt = [_]u8{0xAB} ** 32;
    const creds = sasl.StoredCredentials.derive("secret", salt, 4096);

    var client = try SaslClient.init(alloc, "SCRAM-SHA-256", "alice", "secret");
    defer client.deinit();
    var server = sasl.ScramServer.init(alloc);
    defer server.deinit();
    _ = try server.handleClientFirst(try client.initial());
    server.setCredentials(creds);
    const client_final = try driveScram(&client, "secret", try server.serverFirst());
    const server_final = try server.handleClientFinal(client_final);

    const resp = switch (try client.handleChallenge(server_final)) {
        .message => |m| m,
        else => return error.UnexpectedDerive,
    };
    try std.testing.expectEqualStrings("", resp);
    try client.verifyServerFinal("");
    try std.testing.expect(client.isComplete());
}

test "unsupported mechanism errors" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(error.UnsupportedMechanism, SaslClient.init(alloc, "EXTERNAL", "a", "b"));
}
