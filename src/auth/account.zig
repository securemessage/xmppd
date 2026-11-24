//! # Account management: registration, password change, delete
//!
//! The IPC account operations: in-band registration gated by
//! RegistrationConfig and an optional invite validator, password change
//! with credential-cache invalidation, and account delete. Each operation
//! gates on the matching store capability (add_user, change_password,
//! remove_user).

const std = @import("std");
const protocol = @import("ipc_protocol");
const handler_mod = @import("handler.zig");

const log = std.log.scoped(.auth_handler);

/// Interface for invite code validation. The auth daemon sets this to
/// a closure over the InviteStore.
pub const InviteValidator = struct {
    ctx: *anyopaque,
    validateFn: *const fn (ctx: *anyopaque, code: []const u8) bool,

    pub fn validate(self: InviteValidator, code: []const u8) bool {
        return self.validateFn(self.ctx, code);
    }
};

/// Registration configuration.
pub const RegistrationConfig = struct {
    enabled: bool = false,
    require_invite: bool = true,
};

pub fn handlePasswordChange(comptime Store: type, self: *handler_mod.AuthHandler(Store), req: protocol.PasswordChangeRequest) protocol.Message {
    const caps = handler_mod.AuthHandler(Store).capabilities;
    const auth_precis_scratch = &handler_mod.auth_precis_scratch;
    if (req.username.len == 0 or req.new_password.len == 0) {
        return protocol.Message{ .password_change_result = .{
            .conn_id = req.conn_id,
            .success = false,
            .reason = "bad-request",
        } };
    }

    if (comptime !caps.change_password) {
        return protocol.Message{ .password_change_result = .{
            .conn_id = req.conn_id,
            .success = false,
            .reason = "not-allowed",
        } };
    }

    // Resolve the account through the one RFC 7622 localpart function.
    const account_username = auth_precis_scratch.localpart(
        req.username,
    ) catch {
        return protocol.Message{ .password_change_result = .{
            .conn_id = req.conn_id,
            .success = false,
            .reason = "not-acceptable",
        } };
    };

    self.store.changePassword(self.allocator, account_username, req.new_password) catch |err| {
        const reason: []const u8 = switch (err) {
            error.UserNotFound => "item-not-found",
            else => "internal-server-error",
        };
        log.info("password change failed for '{s}': {s}", .{ account_username, reason });
        return protocol.Message{ .password_change_result = .{
            .conn_id = req.conn_id,
            .success = false,
            .reason = reason,
        } };
    };

    self.cacheInvalidate(account_username);
    log.info("password changed for '{s}'", .{account_username});
    return protocol.Message{ .password_change_result = .{
        .conn_id = req.conn_id,
        .success = true,
        .reason = "",
    } };
}

pub fn handleAccountDelete(comptime Store: type, self: *handler_mod.AuthHandler(Store), req: protocol.AccountDeleteRequest) protocol.Message {
    const caps = handler_mod.AuthHandler(Store).capabilities;
    const auth_precis_scratch = &handler_mod.auth_precis_scratch;
    if (req.username.len == 0) {
        return protocol.Message{ .account_delete_result = .{
            .conn_id = req.conn_id,
            .success = false,
            .reason = "bad-request",
        } };
    }

    if (comptime !caps.remove_user) {
        return protocol.Message{ .account_delete_result = .{
            .conn_id = req.conn_id,
            .success = false,
            .reason = "not-allowed",
        } };
    }

    // Resolve the account through the one RFC 7622 localpart function.
    const account_username = auth_precis_scratch.localpart(
        req.username,
    ) catch {
        return protocol.Message{ .account_delete_result = .{
            .conn_id = req.conn_id,
            .success = false,
            .reason = "not-acceptable",
        } };
    };

    // Remove from UserStore (ignore UserNotFound, may be external auth)
    self.store.removeUser(self.allocator, account_username) catch |err| {
        switch (err) {
            error.UserNotFound => {},
            else => {
                log.err("account delete failed for '{s}': store error", .{account_username});
                return protocol.Message{ .account_delete_result = .{
                    .conn_id = req.conn_id,
                    .success = false,
                    .reason = "internal-server-error",
                } };
            },
        }
    };

    // Remove from LockStore (if lock_checker is configured, the LockStore exists)
    // The lock checker holds a reference to LockStore. We use a dedicated
    // delete callback for cleanup. For now, locks are cleaned via xmppctl unlock
    // or naturally don't apply once the account is gone.

    log.info("account deleted (auth): '{s}'", .{account_username});
    return protocol.Message{ .account_delete_result = .{
        .conn_id = req.conn_id,
        .success = true,
        .reason = "",
    } };
}

pub fn handleRegisterRequest(comptime Store: type, self: *handler_mod.AuthHandler(Store), req: protocol.RegisterRequest) protocol.Message {
    const caps = handler_mod.AuthHandler(Store).capabilities;
    const auth_precis_scratch = &handler_mod.auth_precis_scratch;
    const regResult = protocol.RegisterResult;

    // OIDC backends don't support registration
    if (comptime !caps.add_user) {
        return protocol.Message{ .register_result = regResult{
            .conn_id = req.conn_id,
            .success = false,
            .reason = "not-allowed",
        } };
    }

    // Privileged admin requests (xmppctl) bypass registration policy.
    // The marker remains a convention between local daemons; the
    // socket itself is now peer-credential checked at accept (T258),
    // so only root or the daemon uid may even open it.
    const is_admin = std.mem.eql(u8, req.client_ip, "ctl");

    // Check if registration is enabled (skip for admin)
    if (!is_admin and !self.reg_config.enabled) {
        return protocol.Message{ .register_result = regResult{
            .conn_id = req.conn_id,
            .success = false,
            .reason = "not-allowed",
        } };
    }

    // Count and rate limit registration attempts (skip for admin).
    // Registration outcomes are not authentication outcomes.
    if (!is_admin) {
        if (self.policy.admitIp(req.client_ip)) |reason| {
            return protocol.Message{ .register_result = regResult{
                .conn_id = req.conn_id,
                .success = false,
                .reason = reason.text(),
            } };
        }
    }

    // Validate input
    if (req.username.len == 0 or req.password.len == 0) {
        return protocol.Message{ .register_result = regResult{
            .conn_id = req.conn_id,
            .success = false,
            .reason = "bad-request",
        } };
    }

    // RFC 7622 Section 3.3: store and compare canonical localparts
    // only. Core prepares the name before the IPC hop; preparing
    // again is idempotent (RFC 8264 Section 7 stability), and the
    // xmppctl admin path arrives raw. Buffer contract of
    // xmppLocalpart: buf 6x input.len, scratch 3x input.len each;
    // input over max_input_octets is rejected by the profile itself.
    const canon_username = auth_precis_scratch.localpart(
        req.username,
    ) catch {
        log.info("registration rejected: '{s}' is not a valid UsernameCaseMapped name", .{req.username});
        return protocol.Message{ .register_result = regResult{
            .conn_id = req.conn_id,
            .success = false,
            .reason = "not-acceptable",
        } };
    };

    // Validate invitation code if required (skip for admin)
    if (!is_admin and self.reg_config.require_invite) {
        if (req.invite_code.len == 0) {
            return protocol.Message{ .register_result = regResult{
                .conn_id = req.conn_id,
                .success = false,
                .reason = "not-allowed",
            } };
        }
        if (self.invite_validator) |validator| {
            if (!validator.validate(req.invite_code)) {
                log.info("registration rejected: invalid invite code for '{s}'", .{req.username});
                return protocol.Message{ .register_result = regResult{
                    .conn_id = req.conn_id,
                    .success = false,
                    .reason = "not-allowed",
                } };
            }
        } else {
            // No validator configured but invites required: reject
            return protocol.Message{ .register_result = regResult{
                .conn_id = req.conn_id,
                .success = false,
                .reason = "not-allowed",
            } };
        }
    }

    // Create the user (canonical name: conflicts are canonical-name
    // conflicts).
    self.store.addUser(self.allocator, canon_username, req.password) catch |err| {
        // A bound localpart is taken by the OIDC subject; the
        // client-visible failure is the same as a taken name.
        const reason: []const u8 = if (err == error.UserExists or err == error.OidcBound)
            "conflict"
        else
            "internal-server-error";
        log.info("registration failed for '{s}': {s}", .{ canon_username, reason });
        return protocol.Message{ .register_result = regResult{
            .conn_id = req.conn_id,
            .success = false,
            .reason = reason,
        } };
    };

    log.info("user registered: '{s}'", .{canon_username});
    return protocol.Message{ .register_result = regResult{
        .conn_id = req.conn_id,
        .success = true,
        .reason = "",
    } };
}

// ============================================================================
// Tests
// ============================================================================

const testkit = @import("testkit.zig");
const backend_mod = @import("backend");
const oidc_ids = @import("oidc_identity_store");
const user_store_mod = @import("user_store");
const MemoryBackend = backend_mod.MemoryBackend;
const TestUserStore = user_store_mod.UserStore(MemoryBackend);
const TestHandler = handler_mod.AuthHandler(TestUserStore);
const handleSync = testkit.handleSync;
const plainPayload = testkit.plainPayload;
const plainRequest = testkit.plainRequest;
const RateLimiter = @import("rate_limiter").RateLimiter;
test "AuthHandler: denied registrations do not count as auth failures" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 2,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store, .{});
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    // Registration is disabled (the default): two denied registrations from
    // the same IP must not count as authentication failures.
    var i: u32 = 0;
    while (i < 2) : (i += 1) {
        const reply = handleSync(&handler, .{ .register_request = .{
            .conn_id = 150 + i,
            .username = "newuser",
            .password = "pw",
            .invite_code = "",
            .client_ip = "10.0.0.9",
        } }) orelse return error.NoResponse;
        if (reply != .register_result) return error.UnexpectedReply;
        try std.testing.expect(!reply.register_result.success);
        try std.testing.expectEqualStrings("not-allowed", reply.register_result.reason);
    }

    var buf: [24]u8 = undefined;
    const success = handleSync(&handler, plainRequest(152, "10.0.0.9", plainPayload(&buf, "alice", "secret123"))) orelse return error.NoResponse;
    if (success != .auth_success) return error.ExpectedAuthSuccess;
    try std.testing.expectEqualStrings("alice", success.auth_success.username);
}

test "AuthHandler: registration counts the IP before adding a user" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 1,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store, .{});
    handler.setRateLimiter(&limiter);
    handler.reg_config = .{ .enabled = true, .require_invite = false };
    defer handler.deinit();

    const first = handleSync(&handler, .{ .register_request = .{
        .conn_id = 180,
        .username = "new1",
        .password = "pw",
        .invite_code = "",
        .client_ip = "10.0.0.12",
    } }) orelse return error.NoResponse;
    if (first != .register_result or !first.register_result.success) return error.ExpectedRegisterSuccess;

    const second = handleSync(&handler, .{ .register_request = .{
        .conn_id = 181,
        .username = "new2",
        .password = "pw",
        .invite_code = "",
        .client_ip = "10.0.0.12",
    } }) orelse return error.NoResponse;
    if (second != .register_result) return error.UnexpectedReply;
    try std.testing.expect(!second.register_result.success);
    try std.testing.expectEqualStrings("policy-violation", second.register_result.reason);
}

test "AuthHandler: registration stores the PRECIS canonical name" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    var limiter = try RateLimiter.init(allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 2,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store, .{});
    handler.setRateLimiter(&limiter);
    handler.reg_config = .{ .enabled = true, .require_invite = false };
    defer handler.deinit();

    // "ΟΔΟΣ" prepares to "οδοσ": U+03A3 folds to U+03C3 unconditionally (no
    // final-sigma rule), so the account is stored under the canonical name
    // and the typed name is not a key of its own.
    const reply = handleSync(&handler, .{ .register_request = .{
        .conn_id = 300,
        .username = "\u{039F}\u{0394}\u{039F}\u{03A3}",
        .password = "pw",
        .invite_code = "",
        .client_ip = "10.0.0.20",
    } }) orelse return error.NoResponse;
    if (reply != .register_result or !reply.register_result.success) return error.ExpectedRegisterSuccess;

    try std.testing.expect((try store.lookup(allocator, "\u{03BF}\u{03B4}\u{03BF}\u{03C3}")) != null);
    try std.testing.expect((try store.lookup(allocator, "\u{039F}\u{0394}\u{039F}\u{03A3}")) == null);
}

test "AuthHandler: registration conflict is on the canonical name" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    var limiter = try RateLimiter.init(allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 2,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store, .{});
    handler.setRateLimiter(&limiter);
    handler.reg_config = .{ .enabled = true, .require_invite = false };
    defer handler.deinit();

    // Case variants of one name collide on the canonical form.
    const first = handleSync(&handler, .{ .register_request = .{
        .conn_id = 310,
        .username = "Alice",
        .password = "pw",
        .invite_code = "",
        .client_ip = "10.0.0.21",
    } }) orelse return error.NoResponse;
    if (first != .register_result or !first.register_result.success) return error.ExpectedRegisterSuccess;

    for ([_][]const u8{ "alice", "ALICE" }) |variant| {
        const dup = handleSync(&handler, .{ .register_request = .{
            .conn_id = 311,
            .username = variant,
            .password = "pw",
            .invite_code = "",
            .client_ip = "10.0.0.21",
        } }) orelse return error.NoResponse;
        if (dup != .register_result) return error.UnexpectedReply;
        try std.testing.expect(!dup.register_result.success);
        try std.testing.expectEqualStrings("conflict", dup.register_result.reason);
    }

    // The Kelvin sign folds to 'k': U+212A and "k" are one account name.
    const kelvin = handleSync(&handler, .{ .register_request = .{
        .conn_id = 312,
        .username = "\u{212A}",
        .password = "pw",
        .invite_code = "",
        .client_ip = "10.0.0.22",
    } }) orelse return error.NoResponse;
    if (kelvin != .register_result or !kelvin.register_result.success) return error.ExpectedRegisterSuccess;
    try std.testing.expect((try store.lookup(allocator, "k")) != null);

    const kdup = handleSync(&handler, .{ .register_request = .{
        .conn_id = 313,
        .username = "k",
        .password = "pw",
        .invite_code = "",
        .client_ip = "10.0.0.22",
    } }) orelse return error.NoResponse;
    if (kdup != .register_result) return error.UnexpectedReply;
    try std.testing.expect(!kdup.register_result.success);
    try std.testing.expectEqualStrings("conflict", kdup.register_result.reason);
}

test "AuthHandler: registration of an OIDC-bound localpart is refused" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    // A reverse-index row ('l' ++ localpart) binds the name to a subject.
    try db.put(oidc_ids.NAMESPACE, "lbound-lp", "row");

    var store = TestUserStore.init(&db);
    var limiter = try RateLimiter.init(allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 2,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store, .{});
    handler.setRateLimiter(&limiter);
    handler.reg_config = .{ .enabled = true, .require_invite = false };
    defer handler.deinit();

    const reply = handleSync(&handler, .{ .register_request = .{
        .conn_id = 320,
        .username = "bound-lp",
        .password = "pw",
        .invite_code = "",
        .client_ip = "10.0.0.30",
    } }) orelse return error.NoResponse;
    if (reply != .register_result) return error.UnexpectedReply;
    try std.testing.expect(!reply.register_result.success);
    try std.testing.expectEqualStrings("conflict", reply.register_result.reason);
    // No account credential was created under the bound name.
    try std.testing.expect((try store.lookup(allocator, "bound-lp")) == null);
}

test "AuthHandler: password change resolves the RFC 7622 account name" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "naplestb", "oldpw");
    var handler = TestHandler.init(allocator, &store, .{});
    defer handler.deinit();

    const changed = handleSync(&handler, .{ .password_change_request = .{
        .conn_id = 330,
        .username = "NaplesTB",
        .new_password = "newpw",
    } }) orelse return error.NoResponse;
    try std.testing.expect(changed.password_change_result.success);

    var buf: [64]u8 = undefined;
    const login = handleSync(&handler, plainRequest(331, "10.0.0.31", plainPayload(&buf, "NAPLESTB", "newpw"))) orelse return error.NoResponse;
    try std.testing.expectEqualStrings("naplestb", login.auth_success.username);

    const invalid = handleSync(&handler, .{ .password_change_request = .{
        .conn_id = 332,
        .username = "bad name",
        .new_password = "pw",
    } }) orelse return error.NoResponse;
    try std.testing.expect(!invalid.password_change_result.success);
    try std.testing.expectEqualStrings("not-acceptable", invalid.password_change_result.reason);
}

test "AuthHandler: account delete resolves the RFC 7622 account name" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "naplestb", "pw");
    try store.addUser(allocator, "bad name", "pw");
    var handler = TestHandler.init(allocator, &store, .{});
    defer handler.deinit();

    const deleted = handleSync(&handler, .{ .account_delete_request = .{
        .conn_id = 340,
        .username = "NaplesTB",
    } }) orelse return error.NoResponse;
    try std.testing.expect(deleted.account_delete_result.success);
    try std.testing.expect((try store.lookup(allocator, "naplestb")) == null);

    // An invalid name cannot delete even an exact raw legacy row.
    const invalid = handleSync(&handler, .{ .account_delete_request = .{
        .conn_id = 341,
        .username = "bad name",
    } }) orelse return error.NoResponse;
    try std.testing.expect(!invalid.account_delete_result.success);
    try std.testing.expectEqualStrings("not-acceptable", invalid.account_delete_result.reason);
    try std.testing.expect((try store.lookup(allocator, "bad name")) != null);
}

test "AuthHandler: registration rejects PRECIS-invalid names with not-acceptable" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    var limiter = try RateLimiter.init(allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 2,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store, .{});
    handler.setRateLimiter(&limiter);
    handler.reg_config = .{ .enabled = true, .require_invite = false };
    defer handler.deinit();

    // Spaces and symbols fail the IdentifierClass; "@" is PVALID there but
    // excluded from XMPP localparts by RFC 7622 Section 3.3.1.
    for ([_][]const u8{ "a b", "\u{2603}", "\u{00A0}x", "a@b" }) |bad| {
        const reply = handleSync(&handler, .{ .register_request = .{
            .conn_id = 320,
            .username = bad,
            .password = "pw",
            .invite_code = "",
            .client_ip = "10.0.0.23",
        } }) orelse return error.NoResponse;
        if (reply != .register_result) return error.UnexpectedReply;
        try std.testing.expect(!reply.register_result.success);
        try std.testing.expectEqualStrings("not-acceptable", reply.register_result.reason);
    }
    try std.testing.expect((try store.lookup(allocator, "a b")) == null);

    // Printable ASCII punctuation is PVALID (RFC 8264 section 8.2 ASCII7):
    // "a!" is a valid account name and registers.
    const ok = handleSync(&handler, .{ .register_request = .{
        .conn_id = 321,
        .username = "a!",
        .password = "pw",
        .invite_code = "",
        .client_ip = "10.0.0.23",
    } }) orelse return error.NoResponse;
    if (ok != .register_result or !ok.register_result.success) return error.ExpectedRegisterSuccess;

    // An empty name stays a bad request (the form-level check runs first).
    const empty = handleSync(&handler, .{ .register_request = .{
        .conn_id = 322,
        .username = "",
        .password = "pw",
        .invite_code = "",
        .client_ip = "10.0.0.23",
    } }) orelse return error.NoResponse;
    if (empty != .register_result) return error.UnexpectedReply;
    try std.testing.expect(!empty.register_result.success);
    try std.testing.expectEqualStrings("bad-request", empty.register_result.reason);
}
