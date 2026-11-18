//! # PLAIN mechanism
//!
//! One-step password auth: parses the [authzid]\0authcid\0passwd payload,
//! admits the IP and account keys, then validates through the IdP-backed
//! store (validatePassword) or the local credential store, inline or
//! deferred on the crypto pool (T121).

const std = @import("std");
const sasl = @import("sasl");
const precis = @import("precis_username");
const protocol = @import("ipc_protocol");
const policy_mod = @import("policy");
const crypto_pool_mod = @import("crypto_pool");
const handler_mod = @import("../handler.zig");

const log = std.log.scoped(.auth_handler);
const localpartOf = policy_mod.localpartOf;
const authFailure = handler_mod.authFailure;

/// A PLAIN auth parked while the crypto pool derives its key (T121). Owned
/// by the handler; all memory comes from the handler's allocator and is only
/// touched on the event-loop thread.
pub const PendingPlain = struct {
    slot: u32,
    /// Accept-generation of the IPC client slot at request time — guards
    /// against a deferred reply landing on a different core connection that
    /// reused the slot.
    slot_gen: u32,
    conn_id: u32,
    username: []u8,
    client_ip: []u8,
};

/// Queued PLAIN jobs for this account, keyed by the folded localpart.
/// Counts in-flight crypto-pool work against the lockout threshold.
pub fn pendingFor(comptime Store: type, self: *handler_mod.AuthHandler(Store), username: []const u8) usize {
    var current_buf: [policy_mod.account_key_max]u8 = undefined;
    const current = policy_mod.accountKey(username, &current_buf);
    var count: usize = 0;
    var it = self.pending_plain.iterator();
    while (it.next()) |kv| {
        var key_buf: [policy_mod.account_key_max]u8 = undefined;
        const key = policy_mod.accountKey(kv.value_ptr.username, &key_buf);
        if (std.mem.eql(u8, key, current)) count += 1;
    }
    return count;
}

/// Render the reply for a finished crypto job (T121), or null if the
/// job id is unknown (stale/abandoned). Rate-limit bookkeeping runs
/// here on the loop thread, same as the inline path.
pub fn takeCryptoReply(comptime Store: type, self: *handler_mod.AuthHandler(Store), completion: crypto_pool_mod.Completion) ?handler_mod.DeferredReply {
    const kv = self.pending_plain.fetchRemove(completion.id) orelse return null;
    const pend = kv.value;
    defer self.allocator.free(pend.client_ip);

    if (completion.ok) {
        log.info("PLAIN auth success: '{s}'", .{pend.username});
        self.policy.recordOutcome(pend.username, pend.client_ip, .success);
        return .{
            .slot = pend.slot,
            .slot_gen = pend.slot_gen,
            .owned_username = pend.username,
            .msg = .{ .auth_success = .{
                .conn_id = pend.conn_id,
                .username = pend.username,
                .server_final = "",
            } },
        };
    }

    log.info("PLAIN auth failed: wrong password for '{s}'", .{pend.username});
    self.policy.recordOutcome(pend.username, pend.client_ip, .failure);
    self.allocator.free(pend.username);
    return .{
        .slot = pend.slot,
        .slot_gen = pend.slot_gen,
        .msg = authFailure(pend.conn_id, .not_authorized),
    };
}

pub fn handlePlainAuth(comptime Store: type, self: *handler_mod.AuthHandler(Store), req: protocol.AuthRequest, slot: u32, slot_gen: u32) handler_mod.HandleResult {
    const caps = handler_mod.AuthHandler(Store).capabilities;
    const auth_precis_scratch = &handler_mod.auth_precis_scratch;
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

    const authcid_start = (nul1 orelse return .{ .reply = authFailure(req.conn_id, .invalid_encoding) }) + 1;
    const authcid_end = nul2 orelse return .{ .reply = authFailure(req.conn_id, .invalid_encoding) };
    const passwd_start = authcid_end + 1;

    if (authcid_start >= payload.len or passwd_start >= payload.len) {
        return .{ .reply = authFailure(req.conn_id, .invalid_encoding) };
    }

    const username = payload[authcid_start..authcid_end];
    const password = payload[passwd_start..];

    // Count the IP attempt before any lookup or KDF.
    if (self.policy.admitIp(req.client_ip)) |reason| {
        return .{ .reply = authFailure(req.conn_id, reason) };
    }

    // If the store supports validatePassword (OIDC/IdP delegation), use that
    if (comptime caps.validate_password) {
        // Prepare the supplied name for its lock pre-check. An
        // unpreparable name gets the wrong-password reply and an
        // IP-only charge, never a store-error oracle or an IdP call.
        const typed_username = auth_precis_scratch.localpart(localpartOf(username)) catch {
            log.info("PLAIN auth failed (IdP): invalid supplied name", .{});
            self.policy.recordOutcome("", req.client_ip, .failure);
            return .{ .reply = authFailure(req.conn_id, .not_authorized) };
        };
        if (self.policy.check(typed_username, req.client_ip)) |reason| {
            return .{ .reply = authFailure(req.conn_id, reason) };
        }

        const result = self.store.validatePassword(self.allocator, username, password) catch {
            return .{ .reply = authFailure(req.conn_id, .temporary_auth_failure) };
        };
        if (result) |validated_user| {
            // S3: locks and the bound JID use the prepared localpart
            // of the identity the IdP handed back, never its domain.
            var typed_account_buf: [precis.max_username_octets]u8 = undefined;
            @memcpy(typed_account_buf[0..typed_username.len], typed_username);
            const typed_stable = typed_account_buf[0..typed_username.len];
            const identity = auth_precis_scratch.localpart(
                localpartOf(validated_user),
            ) catch {
                log.info("PLAIN auth failed (IdP): invalid returned identity", .{});
                self.policy.recordOutcome("", req.client_ip, .failure);
                return .{ .reply = authFailure(req.conn_id, .not_authorized) };
            };
            // The pre-check ran on the typed name, which the IdP may
            // resolve to a different identity. Check the identity's
            // own lock now and answer it exactly like a wrong
            // password, so a right password for a locked identity is
            // indistinguishable from a wrong one.
            if (self.policy.check(identity, "")) |reason| {
                if (reason == .account_disabled) {
                    log.info("PLAIN auth failed (IdP): '{s}' maps to a locked identity", .{username});
                    // Same bookkeeping as a wrong password: the typed
                    // name and the IP, never the locked identity.
                    self.policy.recordOutcome(typed_stable, req.client_ip, .failure);
                    return .{ .reply = authFailure(req.conn_id, .not_authorized) };
                }
                return .{ .reply = authFailure(req.conn_id, reason) };
            }
            if (self.policy.admitAccount(identity)) |reason| {
                return .{ .reply = authFailure(req.conn_id, reason) };
            }
            log.info("PLAIN auth success (IdP): '{s}' as '{s}'", .{ typed_stable, identity });
            self.policy.recordOutcome(identity, req.client_ip, .success);
            return .{ .reply = protocol.Message{ .auth_success = .{
                .conn_id = req.conn_id,
                .username = identity,
                .server_final = "",
            } } };
        } else {
            log.info("PLAIN auth failed (IdP): '{s}'", .{typed_username});
            self.policy.recordOutcome(typed_username, req.client_ip, .failure);
            return .{ .reply = authFailure(req.conn_id, .not_authorized) };
        }
    }

    // Traditional credential lookup + SCRAM derive
    if (comptime caps.lookup) {
        // The users namespace is keyed by RFC 7622 localparts. A name
        // that fails preparation can never match an account: answer
        // exactly like a wrong password, charge only the IP key, and
        // create no account key. Buffer contract of xmppLocalpart:
        // buf 6x input.len, scratch 3x input.len each.
        const account_username = auth_precis_scratch.localpart(
            username,
        ) catch {
            log.info("PLAIN auth failed: invalid account name", .{});
            self.policy.recordOutcome("", req.client_ip, .failure);
            return .{ .reply = authFailure(req.conn_id, .not_authorized) };
        };

        // Count the account attempt and enforce the lock before the
        // lookup and KDF. A crypto-pool job also counts against the
        // lockout threshold while it is in flight.
        const account_reason = if (self.crypto_pool != null)
            self.policy.admitAccountPending(account_username, self.pendingFor(account_username))
        else
            self.policy.admitAccount(account_username);
        if (account_reason) |reason| {
            return .{ .reply = authFailure(req.conn_id, reason) };
        }

        const maybe_creds = self.store.lookup(self.allocator, account_username) catch {
            return .{ .reply = authFailure(req.conn_id, .temporary_auth_failure) };
        };
        const creds = maybe_creds orelse {
            log.info("PLAIN auth failed: user '{s}' not found", .{account_username});
            self.policy.recordOutcome(account_username, req.client_ip, .failure);
            return .{ .reply = authFailure(req.conn_id, .not_authorized) };
        };

        // T121: with a pool attached, the loop returns immediately and
        // the derive runs on a pool thread; the reply is rendered by
        // takeCryptoReply when the completion wakes the loop. The pool
        // deep-copies the password — payload's backing buffer dies
        // with this dispatch.
        if (self.crypto_pool) |pool| {
            const job_id = pool.put(password, creds.salt, creds.iteration_count, creds.stored_key) catch {
                return .{ .reply = authFailure(req.conn_id, .temporary_auth_failure) };
            };
            const username_owned = self.allocator.dupe(u8, account_username) catch {
                log.err("pending auth alloc failed; job {d} completes orphaned", .{job_id});
                return .{ .reply = authFailure(req.conn_id, .temporary_auth_failure) };
            };
            const ip_owned = self.allocator.dupe(u8, req.client_ip) catch {
                self.allocator.free(username_owned);
                log.err("pending auth alloc failed; job {d} completes orphaned", .{job_id});
                return .{ .reply = authFailure(req.conn_id, .temporary_auth_failure) };
            };
            self.pending_plain.put(self.allocator, job_id, .{
                .slot = slot,
                .slot_gen = slot_gen,
                .conn_id = req.conn_id,
                .username = username_owned,
                .client_ip = ip_owned,
            }) catch {
                self.allocator.free(username_owned);
                self.allocator.free(ip_owned);
                return .{ .reply = authFailure(req.conn_id, .temporary_auth_failure) };
            };
            return .deferred;
        }

        // No pool: verify inline by deriving with the same salt.
        // A password that fails OpaqueString prep cannot match a
        // prepped stored credential: treat as a failed auth.
        const test_creds = sasl.StoredCredentials.derive(password, creds.salt, creds.iteration_count) catch {
            log.info("PLAIN auth failed: wrong password for '{s}'", .{account_username});
            self.policy.recordOutcome(account_username, req.client_ip, .failure);
            return .{ .reply = authFailure(req.conn_id, .not_authorized) };
        };
        // T211 follow-up: constant-time compare for StoredKey.
        if (!std.crypto.timing_safe.eql([32]u8, test_creds.stored_key, creds.stored_key)) {
            log.info("PLAIN auth failed: wrong password for '{s}'", .{account_username});
            self.policy.recordOutcome(account_username, req.client_ip, .failure);
            return .{ .reply = authFailure(req.conn_id, .not_authorized) };
        }

        log.info("PLAIN auth success: '{s}'", .{account_username});
        self.policy.recordOutcome(account_username, req.client_ip, .success);
        return .{ .reply = protocol.Message{ .auth_success = .{
            .conn_id = req.conn_id,
            .username = account_username,
            .server_final = "",
        } } };
    }

    return .{ .reply = authFailure(req.conn_id, .mechanism_not_supported) };
}

// ============================================================================
// Tests
// ============================================================================

const testkit = @import("../testkit.zig");
const backend_mod = @import("backend");
const oidc_ids = @import("oidc_identity_store");
const user_store_mod = @import("user_store");
const MemoryBackend = backend_mod.MemoryBackend;
const TestUserStore = user_store_mod.UserStore(MemoryBackend);
const TestHandler = handler_mod.AuthHandler(TestUserStore);
const TestCryptoPool = crypto_pool_mod.CryptoPool;
const handleSync = testkit.handleSync;
const waitForPoolWake = testkit.waitForPoolWake;
const TestIdpStore = testkit.TestIdpStore;
const TestIdpHandler = testkit.TestIdpHandler;
const plainPayload = testkit.plainPayload;
const plainRequest = testkit.plainRequest;
const RateLimiter = @import("rate_limiter").RateLimiter;
const lock_store_mod = @import("lock_store");
const LockChecker = handler_mod.LockChecker;
const LockCheckResult = handler_mod.LockCheckResult;
const LockStoreChecker = handler_mod.LockStoreChecker;
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

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 1,
        .mechanism = .plain,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "alice",
        .payload = plain_payload[0 .. 2 + user.len + pass.len],
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("alice", result.auth_success.username);
}

test "AuthHandler: PLAIN prepares the authcid for lookup and the bound identity" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "naplestb", "pw");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var buf: [64]u8 = undefined;
    const result = handleSync(&handler, plainRequest(6, "10.0.0.6", plainPayload(&buf, "NaplesTB", "pw"))) orelse return error.NoResponse;

    // The stored key and the identity returned for the bound JID are both
    // the prepared localpart, not the typed spelling.
    try std.testing.expectEqualStrings("naplestb", result.auth_success.username);
}

test "AuthHandler: PLAIN invalid names are indistinguishable from a wrong password" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    // Even a legacy raw row must not make an invalid name match an account.
    try store.addUser(allocator, "bad name", "pw");
    var limiter = try RateLimiter.init(allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 1,
        .ip_lockout_threshold = 1,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var bad_buf: [64]u8 = undefined;
    const bad = handleSync(&handler, plainRequest(7, "10.0.0.7", plainPayload(&bad_buf, "bad name", "pw"))) orelse return error.NoResponse;
    try std.testing.expect(bad == .auth_failure);
    var wrong_buf: [64]u8 = undefined;
    const wrong = handleSync(&handler, plainRequest(8, "10.0.0.8", plainPayload(&wrong_buf, "ghost", "pw"))) orelse return error.NoResponse;
    try std.testing.expectEqualStrings("not-authorized", bad.auth_failure.reason);
    try std.testing.expectEqualStrings(wrong.auth_failure.reason, bad.auth_failure.reason);

    // No account key was created for the invalid name, but its attempt was
    // charged to the IP key.
    try std.testing.expect(handler.policy.admitAccount("bad name") == null);
    try std.testing.expectEqual(.policy_violation, handler.policy.admitIp("10.0.0.7") orelse return error.ExpectedDenial);
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

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 2,
        .mechanism = .plain,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "bob",
        .payload = plain_payload[0..10],
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("not-authorized", result.auth_failure.reason);
}

test "AuthHandler: locked account rejected at PLAIN regardless of credentials (T352)" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "lockeduser", "secret123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var dummy: u8 = 0;
    handler.setLockChecker(.{ .ctx = @ptrCast(&dummy), .checkFn = struct {
        fn f(_: *anyopaque, username: []const u8) LockCheckResult {
            return if (std.mem.eql(u8, username, "lockeduser")) .locked else .unlocked;
        }
    }.f });

    var payload: [25]u8 = undefined;
    payload[0] = 0;
    @memcpy(payload[1..11], "lockeduser");
    payload[11] = 0;
    @memcpy(payload[12..21], "secret123");

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 1,
        .mechanism = .plain,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = payload[0..21],
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("account-disabled", result.auth_failure.reason);
}

test "AuthHandler: lock store error fails closed (T352)" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var dummy: u8 = 0;
    handler.setLockChecker(.{ .ctx = @ptrCast(&dummy), .checkFn = struct {
        fn f(_: *anyopaque, _: []const u8) LockCheckResult {
            return .store_error;
        }
    }.f });

    var payload: [16]u8 = undefined;
    payload[0] = 0;
    @memcpy(payload[1..6], "alice");
    payload[6] = 0;
    @memcpy(payload[7..16], "secret123");

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 2,
        .mechanism = .plain,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = payload[0..16],
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("temporary-auth-failure", result.auth_failure.reason);
}

test "AuthHandler: locks catch case variants and full-JID authcids are invalid" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");

    // A real LockStore on its own backend: xmppctl locks the canonical name
    // and every variant of it must hit the same row.
    var lock_db = try MemoryBackend.open("", .{});
    defer lock_db.close();
    var locks = lock_store_mod.LockStore(MemoryBackend).init(&lock_db);
    try locks.lock("alice", .permanent);

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();
    var lock_checker: LockStoreChecker(MemoryBackend) = undefined;
    lock_checker.init(&locks, allocator);
    handler.setLockChecker(lock_checker.checker);

    // Case variant of the locked name, correct password.
    {
        var payload: [16]u8 = undefined;
        payload[0] = 0;
        @memcpy(payload[1..6], "Alice");
        payload[6] = 0;
        @memcpy(payload[7..16], "secret123");
        const result = handleSync(&handler, .{ .auth_request = .{
            .conn_id = 21,
            .mechanism = .plain,
            .client_ip = "127.0.0.1",
            .cb_type = 0,
            .cb_data = "",
            .username = "",
            .payload = payload[0..16],
        } }) orelse return error.NoResponse;
        try std.testing.expectEqualStrings("account-disabled", result.auth_failure.reason);
    }
    // A full JID is not an authcid localpart: U+0040 fails RFC 7622
    // preparation, so the reply is the same as for a wrong password rather
    // than an account-lock oracle.
    {
        const user = "ALICE@us.example";
        const pass = "secret123";
        var payload: [64]u8 = undefined;
        payload[0] = 0;
        @memcpy(payload[1 .. 1 + user.len], user);
        payload[1 + user.len] = 0;
        @memcpy(payload[2 + user.len .. 2 + user.len + pass.len], pass);
        const result = handleSync(&handler, .{ .auth_request = .{
            .conn_id = 22,
            .mechanism = .plain,
            .client_ip = "127.0.0.1",
            .cb_type = 0,
            .cb_data = "",
            .username = "",
            .payload = payload[0 .. 2 + user.len + pass.len],
        } }) orelse return error.NoResponse;
        try std.testing.expectEqualStrings("not-authorized", result.auth_failure.reason);
    }
}

test "AuthHandler: IdP PLAIN admits the localpart of the returned identity" {
    const allocator = std.testing.allocator;

    var store = TestIdpStore{ .password_user = "alice@idp.example" };
    var handler = TestIdpHandler.init(allocator, &store);
    defer handler.deinit();

    const user = "alice";
    const pass = "anypassword";
    var payload: [64]u8 = undefined;
    payload[0] = 0;
    @memcpy(payload[1 .. 1 + user.len], user);
    payload[1 + user.len] = 0;
    @memcpy(payload[2 + user.len .. 2 + user.len + pass.len], pass);

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 41,
        .mechanism = .plain,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = payload[0 .. 2 + user.len + pass.len],
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("alice", result.auth_success.username);
}

test "AuthHandler: a lock on the IdP identity rejects PLAIN" {
    const allocator = std.testing.allocator;

    var lock_db = try MemoryBackend.open("", .{});
    defer lock_db.close();
    var locks = lock_store_mod.LockStore(MemoryBackend).init(&lock_db);
    try locks.lock("alice", .permanent);

    // The IdP hands the identity back with a domain and mixed case: the
    // admission check runs on its localpart, not on the requested name.
    var store = TestIdpStore{ .password_user = "Alice@idp.example" };
    var handler = TestIdpHandler.init(allocator, &store);
    defer handler.deinit();
    var lock_checker: LockStoreChecker(MemoryBackend) = undefined;
    lock_checker.init(&locks, allocator);
    handler.setLockChecker(lock_checker.checker);

    const user = "alicework";
    const pass = "anypassword";
    var payload: [64]u8 = undefined;
    payload[0] = 0;
    @memcpy(payload[1 .. 1 + user.len], user);
    payload[1 + user.len] = 0;
    @memcpy(payload[2 + user.len .. 2 + user.len + pass.len], pass);

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 42,
        .mechanism = .plain,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = payload[0 .. 2 + user.len + pass.len],
    } }) orelse return error.NoResponse;
    if (result != .auth_failure) return error.ExpectedAuthFailure;

    // alicework is an alias for the locked alice: reply exactly as for a
    // wrong password, not with a lock reason that reveals the password.
    try std.testing.expectEqualStrings("not-authorized", result.auth_failure.reason);
}

test "AuthHandler: IdP PLAIN prepares the supplied and returned identities" {
    const allocator = std.testing.allocator;

    var store = TestIdpStore{
        .password_user = "NaplesTB@idp.example",
        .password_secret = "right",
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

    var bad_buf: [64]u8 = undefined;
    const bad = handleSync(&handler, plainRequest(44, "10.0.0.44", plainPayload(&bad_buf, "bad name", "wrong"))) orelse return error.NoResponse;
    try std.testing.expectEqualStrings("not-authorized", bad.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 0), store.password_calls);
    try std.testing.expect(handler.policy.admitAccount("bad name") == null);
    try std.testing.expectEqual(.policy_violation, handler.policy.admitIp("10.0.0.44") orelse return error.ExpectedDenial);

    var good_buf: [64]u8 = undefined;
    const good = handleSync(&handler, plainRequest(45, "10.0.0.45", plainPayload(&good_buf, "alice", "right"))) orelse return error.NoResponse;
    try std.testing.expectEqualStrings("naplestb", good.auth_success.username);
}

test "AuthHandler: IdP PLAIN accepts an email or JID authcid" {
    const allocator = std.testing.allocator;

    var store = TestIdpStore{
        .password_user = "alice@idp.example",
        .password_secret = "right",
    };
    var handler = TestIdpHandler.init(allocator, &store);
    defer handler.deinit();

    var buf: [96]u8 = undefined;
    const result = handleSync(&handler, plainRequest(49, "10.0.0.49", plainPayload(&buf, "alice@idp.example", "right"))) orelse return error.NoResponse;

    // The IdP receives the raw login, while the lock key and bound JID use
    // only its prepared localpart.
    try std.testing.expectEqualStrings("alice", result.auth_success.username);
    try std.testing.expectEqual(@as(u32, 1), store.password_calls);
}

test "AuthHandler: unlimited attempts when rate limiter is not attached" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "hammer", "pass");

    // No setRateLimiter call — the [auth] rate_limit = false configuration.
    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var payload: [12]u8 = undefined;
    payload[0] = 0;
    const user = "hammer";
    @memcpy(payload[1 .. 1 + user.len], user);
    payload[1 + user.len] = 0;
    const pass = "pass";
    @memcpy(payload[2 + user.len .. 2 + user.len + pass.len], pass);
    const auth_b64 = payload[0 .. 2 + user.len + pass.len];

    // Far beyond the default per-IP limit (20); every attempt must succeed.
    var i: u32 = 0;
    while (i < 30) : (i += 1) {
        const result = handleSync(&handler, .{ .auth_request = .{
            .conn_id = 100 + i,
            .mechanism = .plain,
            .client_ip = "127.0.0.1",
            .cb_type = 0,
            .cb_data = "",
            .username = "hammer",
            .payload = auth_b64,
        } }) orelse return error.NoResponse;
        try std.testing.expectEqualStrings("hammer", result.auth_success.username);
    }
}

test "AuthHandler: PLAIN auth defers to crypto pool and completes (T121)" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "dave", "pw123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var pool = TestCryptoPool{ .allocator = std.testing.allocator };
    try pool.start(2);
    defer pool.stop();
    handler.enableCryptoPool(&pool);

    var buf: [16]u8 = undefined;
    const res = handleSync(&handler, plainRequest(42, "10.0.0.9", plainPayload(&buf, "Dave", "pw123")));
    // With a pool attached the sync helper reports no immediate reply...
    try std.testing.expect(res == null);
    // ...because the request went deferred.
    try std.testing.expectEqual(@as(usize, 1), handler.pending_plain.count());

    var completion: ?crypto_pool_mod.Completion = null;
    const deadline = std.time.milliTimestamp() + 10000;
    while (completion == null and std.time.milliTimestamp() < deadline) {
        completion = pool.popCompletion();
        if (completion == null) std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    try std.testing.expect(completion != null);

    var reply = handler.takeCryptoReply(completion.?).?;
    defer reply.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 0), reply.slot);
    try std.testing.expectEqual(@as(u32, 1), reply.slot_gen);
    try std.testing.expectEqualStrings("dave", reply.msg.auth_success.username);
    try std.testing.expectEqual(@as(u32, 42), reply.msg.auth_success.conn_id);
    try std.testing.expectEqual(@as(usize, 0), handler.pending_plain.count());
}

test "AuthHandler: PLAIN per-account rate limit engages on parsed username" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "carol", "pw");

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 2,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var buf: [16]u8 = undefined;
    const req = plainPayload(&buf, "carol", "pw");

    // First two attempts pass the rate check (auth itself succeeds)
    try std.testing.expectEqualStrings("carol", (handleSync(&handler, plainRequest(1, "10.9.0.1", req)) orelse return error.NoResponse).auth_success.username);
    try std.testing.expectEqualStrings("carol", (handleSync(&handler, plainRequest(2, "10.9.0.1", req)) orelse return error.NoResponse).auth_success.username);

    // Third exceeds max_per_account = 2
    const third = handleSync(&handler, plainRequest(3, "10.9.0.1", req)) orelse return error.NoResponse;
    try std.testing.expectEqualStrings("policy-violation", third.auth_failure.reason);
}

test "AuthHandler: PLAIN account lockout engages on parsed username" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "dave", "rightpw");

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 2,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var buf: [20]u8 = undefined;
    const wrong = plainPayload(&buf, "dave", "wrongpw");

    // Two consecutive failures hit the lockout threshold
    _ = handleSync(&handler, plainRequest(10, "10.9.0.2", wrong));
    _ = handleSync(&handler, plainRequest(11, "10.9.0.2", wrong));

    const locked = handleSync(&handler, plainRequest(12, "10.9.0.3", wrong)) orelse return error.NoResponse;
    try std.testing.expectEqualStrings("account-disabled", locked.auth_failure.reason);
}

test "AuthHandler: PLAIN crypto-pool admission counts before the job" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "dave", "pw123");

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 3,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var pool = TestCryptoPool{ .allocator = std.testing.allocator };
    try pool.start(2);
    defer pool.stop();
    handler.enableCryptoPool(&pool);

    var buf: [24]u8 = undefined;
    const payload = plainPayload(&buf, "dave", "wrongpw");

    // Three attempts are counted and deferred; the fourth is denied before
    // a job is queued.
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        try std.testing.expect(handleSync(&handler, plainRequest(120 + i, "10.0.0.9", payload)) == null);
    }
    try std.testing.expectEqual(@as(usize, 3), handler.pending_plain.count());

    const fourth = handleSync(&handler, plainRequest(123, "10.0.0.9", payload)) orelse return error.NoResponse;
    if (fourth != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("policy-violation", fourth.auth_failure.reason);
}

test "AuthHandler: PLAIN counts the IP before the lookup" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 1,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var buf: [24]u8 = undefined;
    const payload = plainPayload(&buf, "alice", "secret123");

    const first = handleSync(&handler, plainRequest(170, "10.0.0.11", payload)) orelse return error.NoResponse;
    if (first != .auth_success) return error.ExpectedAuthSuccess;

    const second = handleSync(&handler, plainRequest(171, "10.0.0.11", payload)) orelse return error.NoResponse;
    if (second != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("policy-violation", second.auth_failure.reason);
}

test "AuthHandler: PLAIN-IdP rejects a locked supplied name before the IdP" {
    const allocator = std.testing.allocator;

    var lock_db = try MemoryBackend.open("", .{});
    defer lock_db.close();
    var locks = lock_store_mod.LockStore(MemoryBackend).init(&lock_db);
    try locks.lock("alice", .permanent);

    var store = TestIdpStore{
        .password_user = "alice@idp.example",
        .password_secret = "right",
    };
    var handler = TestIdpHandler.init(allocator, &store);
    defer handler.deinit();
    var lock_checker: LockStoreChecker(MemoryBackend) = undefined;
    lock_checker.init(&locks, allocator);
    handler.setLockChecker(lock_checker.checker);

    var buf: [64]u8 = undefined;
    const right_reply = handleSync(&handler, plainRequest(200, "127.0.0.1", plainPayload(&buf, "alice", "right"))) orelse return error.NoResponse;
    const wrong_reply = handleSync(&handler, plainRequest(200, "127.0.0.1", plainPayload(&buf, "alice", "wrong"))) orelse return error.NoResponse;

    if (right_reply != .auth_failure or wrong_reply != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualDeep(right_reply, wrong_reply);
    try std.testing.expectEqualStrings("account-disabled", right_reply.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 0), store.password_calls);
}

test "AuthHandler: crypto-pool pending jobs count against the lockout threshold" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "dave", "pw123");

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 2,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var pool = TestCryptoPool{ .allocator = std.testing.allocator };
    try pool.start(2);
    defer pool.stop();
    handler.enableCryptoPool(&pool);

    var buf: [24]u8 = undefined;
    const payload = plainPayload(&buf, "dave", "wrongpw");

    var i: u32 = 0;
    while (i < 2) : (i += 1) {
        try std.testing.expect(handleSync(&handler, plainRequest(310 + i, "10.0.0.30", payload)) == null);
    }
    try std.testing.expectEqual(@as(usize, 2), handler.pending_plain.count());

    // Two jobs are in flight, equal to the lockout threshold: the next
    // attempt must not be queued.
    const third = handleSync(&handler, plainRequest(312, "10.0.0.30", payload)) orelse return error.NoResponse;
    if (third != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("policy-violation", third.auth_failure.reason);
    try std.testing.expectEqual(@as(usize, 2), handler.pending_plain.count());
}

test "AuthHandler: a PLAIN prep failure completes and replies" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "dave", "pw123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var pool = TestCryptoPool{ .allocator = std.testing.allocator };
    try pool.start(2);
    defer pool.stop();
    handler.enableCryptoPool(&pool);

    var buf: [32]u8 = undefined;
    const payload = plainPayload(&buf, "dave", "x\x07y");
    try std.testing.expect(handleSync(&handler, plainRequest(400, "10.0.0.40", payload)) == null);
    try std.testing.expectEqual(@as(usize, 1), handler.pending_plain.count());

    try waitForPoolWake(&pool);
    const completion = pool.popCompletion() orelse return error.NoCompletion;
    try std.testing.expect(!completion.ok);

    var reply = handler.takeCryptoReply(completion) orelse return error.NoReply;
    defer reply.deinit(allocator);
    if (reply.msg != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("not-authorized", reply.msg.auth_failure.reason);
    try std.testing.expectEqual(@as(usize, 0), handler.pending_plain.count());
}

test "AuthHandler: a locked IdP alias gets the wrong-password reply" {
    const allocator = std.testing.allocator;

    var lock_db = try MemoryBackend.open("", .{});
    defer lock_db.close();
    var locks = lock_store_mod.LockStore(MemoryBackend).init(&lock_db);
    try locks.lock("alice", .permanent);

    var store = TestIdpStore{
        .password_user = "alice@idp.example",
        .password_secret = "right",
    };
    var handler = TestIdpHandler.init(allocator, &store);
    defer handler.deinit();
    var lock_checker: LockStoreChecker(MemoryBackend) = undefined;
    lock_checker.init(&locks, allocator);
    handler.setLockChecker(lock_checker.checker);

    var buf: [64]u8 = undefined;
    const right_reply = handleSync(&handler, plainRequest(410, "127.0.0.1", plainPayload(&buf, "a.smith", "right"))) orelse return error.NoResponse;
    const wrong_reply = handleSync(&handler, plainRequest(410, "127.0.0.1", plainPayload(&buf, "a.smith", "wrong"))) orelse return error.NoResponse;

    if (right_reply != .auth_failure or wrong_reply != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualDeep(right_reply, wrong_reply);
    try std.testing.expectEqualStrings("not-authorized", right_reply.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 2), store.password_calls);
}

test "AuthHandler: an alias failure charges the typed name" {
    const allocator = std.testing.allocator;

    var store = TestIdpStore{
        .password_user = "alice@idp.example",
        .password_secret = "right",
    };

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 1,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    // A temporary lock on the identity, which the alias path resolves to.
    limiter.recordOutcome("alice", "10.0.0.1", false);

    var handler = TestIdpHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var buf: [64]u8 = undefined;
    const reply = handleSync(&handler, plainRequest(415, "10.0.0.2", plainPayload(&buf, "a.smith", "right"))) orelse return error.NoResponse;
    if (reply != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("not-authorized", reply.auth_failure.reason);

    // The wrong-password bookkeeping charged a.smith; the handler must not
    // return here without charging the typed name.
    try std.testing.expectEqual(.account_disabled, handler.policy.check("a.smith", "") orelse return error.ExpectedDenial);
}

test "AuthHandler: an alias failure does not charge the locked identity" {
    const allocator = std.testing.allocator;

    var lock_db = try MemoryBackend.open("", .{});
    defer lock_db.close();
    var locks = lock_store_mod.LockStore(MemoryBackend).init(&lock_db);
    try locks.lock("alice", .permanent);

    var store = TestIdpStore{
        .password_user = "alice@idp.example",
        .password_secret = "right",
    };

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 1,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();

    var handler = TestIdpHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    var lock_checker: LockStoreChecker(MemoryBackend) = undefined;
    lock_checker.init(&locks, allocator);
    handler.setLockChecker(lock_checker.checker);
    defer handler.deinit();

    var buf: [64]u8 = undefined;
    const reply = handleSync(&handler, plainRequest(416, "10.0.0.9", plainPayload(&buf, "a.smith", "right"))) orelse return error.NoResponse;
    if (reply != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("not-authorized", reply.auth_failure.reason);

    // The locked identity is left alone: once the permanent lock is lifted,
    // no limiter failure may remain on it, or a failure arrived through the
    // alias and re-armed the identity's lock.
    try locks.unlock(allocator, "alice");
    try std.testing.expect(handler.policy.check("alice", "") == null);
}

test "AuthHandler: an alias failure charges the IP once" {
    const allocator = std.testing.allocator;

    var lock_db = try MemoryBackend.open("", .{});
    defer lock_db.close();
    var locks = lock_store_mod.LockStore(MemoryBackend).init(&lock_db);
    try locks.lock("alice", .permanent);

    var store = TestIdpStore{
        .password_user = "alice@idp.example",
        .password_secret = "right",
    };

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 2,
    });
    defer limiter.deinit();

    var handler = TestIdpHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    var lock_checker: LockStoreChecker(MemoryBackend) = undefined;
    lock_checker.init(&locks, allocator);
    handler.setLockChecker(lock_checker.checker);
    defer handler.deinit();

    var buf: [64]u8 = undefined;
    const reply = handleSync(&handler, plainRequest(417, "10.0.0.7", plainPayload(&buf, "a.smith", "right"))) orelse return error.NoResponse;
    if (reply != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("not-authorized", reply.auth_failure.reason);

    // One alias failure charged the IP exactly once: with an IP lockout
    // threshold of two, a second charge would have locked the egress.
    try std.testing.expect(handler.policy.check("", "10.0.0.7") == null);
}

test "AuthHandler: a failed crypto-pool completion leaves no pending entry" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "dave", "pw123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var pool = TestCryptoPool{ .allocator = std.testing.allocator };
    try pool.start(2);
    defer pool.stop();
    handler.enableCryptoPool(&pool);

    var buf: [24]u8 = undefined;
    const payload = plainPayload(&buf, "dave", "wrongpw");
    try std.testing.expect(handleSync(&handler, plainRequest(420, "10.0.0.50", payload)) == null);
    try std.testing.expectEqual(@as(usize, 1), handler.pending_plain.count());

    try waitForPoolWake(&pool);
    const completion = pool.popCompletion() orelse return error.NoCompletion;
    try std.testing.expect(!completion.ok);

    var reply = handler.takeCryptoReply(completion) orelse return error.NoReply;
    defer reply.deinit(allocator);
    if (reply.msg != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("not-authorized", reply.msg.auth_failure.reason);
    try std.testing.expectEqual(@as(usize, 0), handler.pending_plain.count());
}

test "AuthHandler: PLAIN-IdP pre-check sees a temporary lock" {
    const allocator = std.testing.allocator;

    var store = TestIdpStore{
        .password_user = "alice@idp.example",
        .password_secret = "right",
    };

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 1,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    limiter.recordOutcome("alice", "10.0.0.1", false);

    var handler = TestIdpHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var buf: [64]u8 = undefined;
    const right_reply = handleSync(&handler, plainRequest(430, "10.0.0.2", plainPayload(&buf, "alice", "right"))) orelse return error.NoResponse;
    const wrong_reply = handleSync(&handler, plainRequest(430, "10.0.0.2", plainPayload(&buf, "alice", "wrong"))) orelse return error.NoResponse;

    if (right_reply != .auth_failure or wrong_reply != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualDeep(right_reply, wrong_reply);
    try std.testing.expectEqualStrings("account-disabled", right_reply.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 0), store.password_calls);
}

test "AuthHandler: a permanently locked IdP identity rejects the Kelvin-sign alias" {
    const allocator = std.testing.allocator;

    var lock_db = try MemoryBackend.open("", .{});
    defer lock_db.close();
    var locks = lock_store_mod.LockStore(MemoryBackend).init(&lock_db);
    try locks.lock("kate", .permanent);

    var store = TestIdpStore{
        .password_user = "kate@idp.example",
        .password_secret = "right",
    };
    var handler = TestIdpHandler.init(allocator, &store);
    defer handler.deinit();
    var lock_checker: LockStoreChecker(MemoryBackend) = undefined;
    lock_checker.init(&locks, allocator);
    handler.setLockChecker(lock_checker.checker);

    // "<U+212A>ate" and "kate" are the same identity: the pre-check must
    // see the permanent lock through the folded key and reject before the
    // IdP call, so the right password gets the same reply as the wrong one.
    var buf: [64]u8 = undefined;
    const right_reply = handleSync(&handler, plainRequest(440, "127.0.0.1", plainPayload(&buf, "\u{212A}ate", "right"))) orelse return error.NoResponse;
    const wrong_reply = handleSync(&handler, plainRequest(440, "127.0.0.1", plainPayload(&buf, "\u{212A}ate", "wrong"))) orelse return error.NoResponse;

    if (right_reply != .auth_failure or wrong_reply != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualDeep(right_reply, wrong_reply);
    try std.testing.expectEqualStrings("account-disabled", right_reply.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 0), store.password_calls);
}
