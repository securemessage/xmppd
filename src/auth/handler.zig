//! # Auth Handler — SASL authentication request processor
//!
//! Handles IPC auth requests from xmppd-core. Maintains per-connection
//! SCRAM state for multi-step exchanges.
//!
//! ## Flow
//!
//! **PLAIN:** AuthRequest → lookup → AuthSuccess/AuthFailure (one step)
//!
//! **SCRAM-SHA-256:** AuthRequest → ScramServer.handleClientFirst → AuthChallenge
//!                    SaslResponse → ScramServer.handleClientFinal → AuthSuccess/AuthFailure

const std = @import("std");
const sasl = @import("sasl");
const protocol = @import("ipc_protocol");

const log = std.log.scoped(.auth_handler);

/// Maximum concurrent SCRAM exchanges (one per XMPP connection doing auth).
const MAX_SCRAM_SESSIONS = 256;

/// Per-connection SCRAM state. Keyed by conn_id.
const ScramSession = struct {
    conn_id: u32,
    server: sasl.ScramServer,
    active: bool = false,

    fn deinit(self: *ScramSession) void {
        self.server.deinit();
        self.active = false;
    }
};

pub fn AuthHandler(comptime Store: type) type {
    return struct {
        store: *Store,
        allocator: std.mem.Allocator,
        /// Active SCRAM sessions indexed by slot.
        scram_sessions: [MAX_SCRAM_SESSIONS]ScramSession = undefined,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, store: *Store) Self {
            var handler = Self{
                .store = store,
                .allocator = allocator,
                .scram_sessions = undefined,
            };
            for (&handler.scram_sessions) |*s| {
                s.active = false;
            }
            return handler;
        }

        pub fn deinit(self: *Self) void {
            for (&self.scram_sessions) |*s| {
                if (s.active) s.deinit();
            }
        }

        /// Process an incoming IPC message and return a response message.
        pub fn handleMessage(self: *Self, msg: protocol.Message) ?protocol.Message {
            return switch (msg) {
                .auth_request => |req| self.handleAuthRequest(req),
                .sasl_response => |resp| self.handleSaslResponse(resp),
                else => null,
            };
        }

        fn handleAuthRequest(self: *Self, req: protocol.AuthRequest) protocol.Message {
            return switch (req.mechanism) {
                .plain => self.handlePlainAuth(req),
                .scram_sha_256 => self.handleScramInit(req),
            };
        }

        fn handlePlainAuth(self: *Self, req: protocol.AuthRequest) protocol.Message {
            // PLAIN payload format: [authzid]\0authcid\0passwd
            // We only use authcid (username) and passwd
            const payload = req.payload;

            // Find the two NUL separators
            var nul1: ?usize = null;
            var nul2: ?usize = null;
            for (payload, 0..) |byte, i| {
                if (byte == 0) {
                    if (nul1 == null) {
                        nul1 = i;
                    } else {
                        nul2 = i;
                        break;
                    }
                }
            }

            const authcid_start = (nul1 orelse return authFailure(req.conn_id, "invalid-encoding")) + 1;
            const authcid_end = nul2 orelse return authFailure(req.conn_id, "invalid-encoding");
            const passwd_start = authcid_end + 1;

            if (authcid_start >= payload.len or passwd_start >= payload.len) {
                return authFailure(req.conn_id, "invalid-encoding");
            }

            const username = payload[authcid_start..authcid_end];
            const password = payload[passwd_start..];

            // Look up user
            const maybe_creds = self.store.lookup(self.allocator, username) catch {
                return authFailure(req.conn_id, "temporary-auth-failure");
            };
            const creds = maybe_creds orelse {
                log.info("PLAIN auth failed: user '{s}' not found", .{username});
                return authFailure(req.conn_id, "not-authorized");
            };

            // Verify by deriving with the same salt and comparing
            const test_creds = sasl.StoredCredentials.derive(password, creds.salt, creds.iteration_count);
            if (!std.mem.eql(u8, &test_creds.stored_key, &creds.stored_key)) {
                log.info("PLAIN auth failed: wrong password for '{s}'", .{username});
                return authFailure(req.conn_id, "not-authorized");
            }

            log.info("PLAIN auth success: '{s}'", .{username});
            return protocol.Message{ .auth_success = .{
                .conn_id = req.conn_id,
                .username = username,
                .server_final = "",
            } };
        }

        fn handleScramInit(self: *Self, req: protocol.AuthRequest) protocol.Message {
            // Find or create a SCRAM session for this conn_id
            const slot = self.findOrCreateScramSlot(req.conn_id) orelse {
                return authFailure(req.conn_id, "temporary-auth-failure");
            };

            var session = &self.scram_sessions[slot];
            session.server = sasl.ScramServer.init(self.allocator);
            session.conn_id = req.conn_id;
            session.active = true;

            // Process client-first-message
            const username = session.server.handleClientFirst(req.payload) catch {
                session.deinit();
                return authFailure(req.conn_id, "invalid-encoding");
            };

            // Look up credentials
            const maybe_creds = self.store.lookup(self.allocator, username) catch {
                session.deinit();
                return authFailure(req.conn_id, "temporary-auth-failure");
            };
            const creds = maybe_creds orelse {
                log.info("SCRAM auth failed: user '{s}' not found", .{username});
                session.deinit();
                return authFailure(req.conn_id, "not-authorized");
            };

            session.server.setCredentials(creds);

            // Generate server-first-message
            const server_first = session.server.serverFirst() catch {
                session.deinit();
                return authFailure(req.conn_id, "temporary-auth-failure");
            };

            log.info("SCRAM challenge sent for '{s}' conn={d}", .{ username, req.conn_id });

            return protocol.Message{ .auth_challenge = .{
                .conn_id = req.conn_id,
                .challenge = server_first,
            } };
        }

        fn handleSaslResponse(self: *Self, resp: protocol.SaslResponse) protocol.Message {
            // Find the SCRAM session for this conn_id
            const slot = self.findScramSlot(resp.conn_id) orelse {
                return authFailure(resp.conn_id, "not-authorized");
            };

            var session = &self.scram_sessions[slot];

            // Process client-final-message
            const server_final = session.server.handleClientFinal(resp.payload) catch {
                log.info("SCRAM auth failed: proof verification for conn={d}", .{resp.conn_id});
                const username = session.server.username;
                _ = username;
                session.deinit();
                return authFailure(resp.conn_id, "not-authorized");
            };

            const username = session.server.username;
            log.info("SCRAM auth success: '{s}' conn={d}", .{ username, resp.conn_id });

            // Keep session alive briefly for the username reference, then clean up
            const result = protocol.Message{ .auth_success = .{
                .conn_id = resp.conn_id,
                .username = username,
                .server_final = server_final,
            } };

            // Don't deinit yet — the username/server_final slices are borrowed from the arena.
            // They'll be valid until the next message for this slot.

            return result;
        }

        /// Clean up a SCRAM session after the response has been sent.
        pub fn cleanupSession(self: *Self, conn_id: u32) void {
            if (self.findScramSlot(conn_id)) |slot| {
                self.scram_sessions[slot].deinit();
            }
        }

        fn findOrCreateScramSlot(self: *Self, conn_id: u32) ?usize {
            // First try to find existing
            for (&self.scram_sessions, 0..) |*s, i| {
                if (s.active and s.conn_id == conn_id) return i;
            }
            // Then find a free slot
            for (&self.scram_sessions, 0..) |*s, i| {
                if (!s.active) return i;
            }
            return null;
        }

        fn findScramSlot(self: *Self, conn_id: u32) ?usize {
            for (&self.scram_sessions, 0..) |*s, i| {
                if (s.active and s.conn_id == conn_id) return i;
            }
            return null;
        }
    };
}

fn authFailure(conn_id: u32, reason: []const u8) protocol.Message {
    return protocol.Message{ .auth_failure = .{
        .conn_id = conn_id,
        .reason = reason,
    } };
}

// ============================================================================
// Tests
// ============================================================================

const backend_mod = @import("backend");
const user_store_mod = @import("user_store");
const MemoryBackend = backend_mod.MemoryBackend;
const TestUserStore = user_store_mod.UserStore(MemoryBackend);
const TestHandler = AuthHandler(TestUserStore);

test "AuthHandler: PLAIN auth success" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    // Build PLAIN payload: \0alice\0secret123
    var plain_payload: [20]u8 = undefined;
    plain_payload[0] = 0; // authzid empty
    const user = "alice";
    @memcpy(plain_payload[1 .. 1 + user.len], user);
    plain_payload[1 + user.len] = 0;
    const pass = "secret123";
    @memcpy(plain_payload[2 + user.len .. 2 + user.len + pass.len], pass);

    const result = handler.handleMessage(.{ .auth_request = .{
        .conn_id = 1,
        .mechanism = .plain,
        .username = "alice",
        .payload = plain_payload[0 .. 2 + user.len + pass.len],
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("alice", result.auth_success.username);
}

test "AuthHandler: PLAIN auth wrong password" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "bob", "correct");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    // Build PLAIN payload with wrong password
    var plain_payload: [15]u8 = undefined;
    plain_payload[0] = 0;
    @memcpy(plain_payload[1..4], "bob");
    plain_payload[4] = 0;
    @memcpy(plain_payload[5..10], "wrong");

    const result = handler.handleMessage(.{ .auth_request = .{
        .conn_id = 2,
        .mechanism = .plain,
        .username = "bob",
        .payload = plain_payload[0..10],
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("not-authorized", result.auth_failure.reason);
}

test "AuthHandler: SCRAM-SHA-256 full exchange" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "testuser", "testpassword");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    // Client side
    var client = sasl.ScramClient.init(allocator, "testuser", "testpassword");
    defer client.deinit();
    const client_first = try client.clientFirst();

    // Step 1: AuthRequest with client-first-message
    const challenge_msg = handler.handleMessage(.{ .auth_request = .{
        .conn_id = 5,
        .mechanism = .scram_sha_256,
        .username = "testuser",
        .payload = client_first,
    } }) orelse return error.NoResponse;

    // Should get a challenge
    const challenge = challenge_msg.auth_challenge.challenge;
    try std.testing.expect(challenge.len > 0);

    // Step 2: Client processes challenge, generates client-final
    const client_final = try client.handleServerFirst(challenge);

    // Step 3: SaslResponse with client-final-message
    const success_msg = handler.handleMessage(.{ .sasl_response = .{
        .conn_id = 5,
        .payload = client_final,
    } }) orelse return error.NoResponse;

    // Should succeed
    try std.testing.expectEqualStrings("testuser", success_msg.auth_success.username);
    try std.testing.expect(success_msg.auth_success.server_final.len > 0);

    // Verify server final
    try client.handleServerFinal(success_msg.auth_success.server_final);
    try std.testing.expect(client.isComplete());

    handler.cleanupSession(5);
}

test "AuthHandler: SCRAM unknown user" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var client = sasl.ScramClient.init(allocator, "ghost", "whatever");
    defer client.deinit();
    const client_first = try client.clientFirst();

    const result = handler.handleMessage(.{ .auth_request = .{
        .conn_id = 10,
        .mechanism = .scram_sha_256,
        .username = "ghost",
        .payload = client_first,
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("not-authorized", result.auth_failure.reason);
}
