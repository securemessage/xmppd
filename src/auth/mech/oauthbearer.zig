//! # OAUTHBEARER mechanism
//!
//! One-step bearer-token auth for the IdP-delegating store: parses the
//! RFC 7628 initial response, validates the token through
//! Store.validateToken, and binds the prepared localpart of the identity
//! the IdP returns.

const std = @import("std");
const protocol = @import("ipc_protocol");
const policy_mod = @import("policy");
const handler_mod = @import("../handler.zig");

const log = std.log.scoped(.auth_handler);
const localpartOf = policy_mod.localpartOf;
const authFailure = handler_mod.authFailure;

/// Handle OAUTHBEARER mechanism — delegates to Store.validateToken.
/// The SASL initial response is RFC 7628 format:
///   gs2-header kvsep "auth=Bearer " token kvsep kvsep
///   n,,\x01auth=Bearer TOKEN\x01\x01
pub fn handleOAuthBearerAuth(comptime Store: type, self: *handler_mod.AuthHandler(Store), req: protocol.AuthRequest) protocol.Message {
    const caps = handler_mod.AuthHandler(Store).capabilities;
    const auth_precis_scratch = &handler_mod.auth_precis_scratch;
    if (comptime !caps.validate_token) {
        return authFailure(req.conn_id, .mechanism_not_supported);
    }

    // Count the IP attempt before the IdP call: a locked IP must not
    // spend token-validation work.
    if (self.policy.admitIp(req.client_ip)) |reason| {
        log.info("OAUTHBEARER rejected before token validation: {s}", .{reason.text()});
        return authFailure(req.conn_id, reason);
    }

    // Extract bearer token from RFC 7628 OAUTHBEARER initial response
    const payload = req.payload;
    if (payload.len == 0) {
        return authFailure(req.conn_id, .invalid_encoding);
    }

    // Find "auth=Bearer " after the first \x01 separator
    const bearer_prefix = "auth=Bearer ";
    const token = blk: {
        if (std.mem.indexOf(u8, payload, bearer_prefix)) |pos| {
            const start = pos + bearer_prefix.len;
            // Token ends at the next \x01 separator
            const rest = payload[start..];
            const end = std.mem.indexOfScalar(u8, rest, 0x01) orelse rest.len;
            break :blk rest[0..end];
        }
        // Fallback: treat entire payload as token (for simple clients)
        break :blk payload;
    };
    if (token.len == 0) {
        return authFailure(req.conn_id, .invalid_encoding);
    }

    const result = self.store.validateToken(self.allocator, token) catch {
        return authFailure(req.conn_id, .temporary_auth_failure);
    };

    if (result) |validated_user| {
        // Policy and the bound JID use the prepared localpart of the
        // IdP-verified identity, never the full IdP-qualified string.
        const identity = auth_precis_scratch.localpart(
            localpartOf(validated_user),
        ) catch {
            log.info("OAUTHBEARER failed: invalid returned identity", .{});
            self.policy.recordOutcome("", req.client_ip, .failure);
            return authFailure(req.conn_id, .not_authorized);
        };
        if (self.policy.admitAccount(identity)) |reason| {
            return authFailure(req.conn_id, reason);
        }
        log.info("OAUTHBEARER auth success: '{s}'", .{identity});
        self.policy.recordOutcome(identity, req.client_ip, .success);
        const photo_url = if (comptime caps.photo_url)
            self.store.getPhotoUrl()
        else
            "";
        return protocol.Message{ .auth_success = .{
            .conn_id = req.conn_id,
            .username = identity,
            .server_final = "",
            .photo_url = photo_url,
        } };
    } else {
        log.info("OAUTHBEARER auth failed", .{});
        self.policy.recordOutcome(req.username, req.client_ip, .failure);
        return authFailure(req.conn_id, .not_authorized);
    }
}

// ============================================================================
// Tests
// ============================================================================

const testkit = @import("../testkit.zig");
const backend_mod = @import("backend");
const lock_store_mod = @import("lock_store");
const MemoryBackend = backend_mod.MemoryBackend;
const TestIdpStore = testkit.TestIdpStore;
const TestIdpHandler = testkit.TestIdpHandler;
const handleSync = testkit.handleSync;
const plainPayload = testkit.plainPayload;
const plainRequest = testkit.plainRequest;
const RateLimiter = @import("rate_limiter").RateLimiter;
const LockStoreChecker = handler_mod.LockStoreChecker;
test "AuthHandler: OAUTHBEARER admits the identity the IdP returns" {
    const allocator = std.testing.allocator;

    var store = TestIdpStore{ .token_user = "bob@idp.example" };
    var handler = TestIdpHandler.init(allocator, &store);
    defer handler.deinit();

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 43,
        .mechanism = .oauthbearer,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = "n,,\x01auth=Bearer tok123\x01\x01",
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("bob", result.auth_success.username);
}

test "AuthHandler: OAUTHBEARER binds the prepared localpart" {
    const allocator = std.testing.allocator;

    var store = TestIdpStore{ .token_user = "NaplesTB@idp.example" };
    var handler = TestIdpHandler.init(allocator, &store);
    defer handler.deinit();

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 46,
        .mechanism = .oauthbearer,
        .client_ip = "10.0.0.46",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = "n,,\x01auth=Bearer tok123\x01\x01",
    } }) orelse return error.NoResponse;
    try std.testing.expectEqualStrings("naplestb", result.auth_success.username);
}

test "AuthHandler: invalid IdP identities get not-authorized with IP-only charge" {
    const allocator = std.testing.allocator;

    var store = TestIdpStore{
        .password_user = "bad name@idp.example",
        .password_secret = "right",
        .token_user = "bad name@idp.example",
    };
    var limiter = try RateLimiter.init(allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 1,
        .ip_lockout_threshold = 1,
    });
    defer limiter.deinit();
    var handler = TestIdpHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var buf: [64]u8 = undefined;
    const plain = handleSync(&handler, plainRequest(47, "10.0.0.47", plainPayload(&buf, "alice", "right"))) orelse return error.NoResponse;
    try std.testing.expectEqualStrings("not-authorized", plain.auth_failure.reason);
    try std.testing.expect(handler.policy.admitAccount("bad name") == null);
    try std.testing.expectEqual(.policy_violation, handler.policy.admitIp("10.0.0.47") orelse return error.ExpectedDenial);

    const oauth = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 48,
        .mechanism = .oauthbearer,
        .client_ip = "10.0.0.48",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = "n,,\x01auth=Bearer tok123\x01\x01",
    } }) orelse return error.NoResponse;
    try std.testing.expectEqualStrings("not-authorized", oauth.auth_failure.reason);
    try std.testing.expectEqual(.policy_violation, handler.policy.admitIp("10.0.0.48") orelse return error.ExpectedDenial);
}

test "AuthHandler: a lock on the IdP identity rejects OAUTHBEARER" {
    const allocator = std.testing.allocator;

    var lock_db = try MemoryBackend.open("", .{});
    defer lock_db.close();
    var locks = lock_store_mod.LockStore(MemoryBackend).init(&lock_db);
    try locks.lock("bob", .permanent);

    var store = TestIdpStore{ .token_user = "Bob@idp.example" };
    var handler = TestIdpHandler.init(allocator, &store);
    defer handler.deinit();
    var lock_checker: LockStoreChecker(MemoryBackend) = undefined;
    lock_checker.init(&locks, allocator);
    handler.setLockChecker(lock_checker.checker);

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 44,
        .mechanism = .oauthbearer,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = "n,,\x01auth=Bearer tok456\x01\x01",
    } }) orelse return error.NoResponse;
    if (result != .auth_failure) return error.ExpectedAuthFailure;

    try std.testing.expectEqualStrings("account-disabled", result.auth_failure.reason);
}

test "AuthHandler: OAUTHBEARER denies a locked IP before validating the token" {
    const allocator = std.testing.allocator;

    var store = TestIdpStore{ .token_user = "bob@idp.example" };

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 1,
    });
    defer limiter.deinit();
    limiter.recordOutcome("anyone", "10.0.0.7", false);

    var handler = TestIdpHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 130,
        .mechanism = .oauthbearer,
        .client_ip = "10.0.0.7",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = "n,,\x01auth=Bearer tok\x01\x01",
    } }) orelse return error.NoResponse;
    if (result != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("policy-violation", result.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 0), store.token_calls);
}
