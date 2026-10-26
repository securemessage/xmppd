//! # Auth policy: one admission gate for every mechanism
//!
//! `admitIp` counts the IP attempt before any identity is known;
//! `admitAccount` counts the account attempt and runs the permanent lock
//! check once the identity is parsed; `admitAccountPending` also counts
//! in-flight crypto-pool jobs against the lockout threshold. `check`
//! re-runs only the permanent and temporary locks, without counting or
//! consulting the windows, for the SCRAM client-final and the IdP
//! pre-check. `recordOutcome` records only the result of an attempt
//! already counted at admission.
//!
//! Account keys are the case-folded identity localpart, the same key the
//! permanent lock store uses. Store errors and an untrackable key fail
//! closed; a denied admission always carries a SASL failure reason.

const std = @import("std");
const rate_limiter = @import("rate_limiter");
const lock_store_mod = @import("lock_store");

const log = std.log.scoped(.auth_policy);

pub const Outcome = enum { success, failure };

/// Three-state lock verdict (T352/S3): a store error must NOT be mapped to
/// "unlocked": that is fail-open on exactly the path that protects
/// permanently locked accounts.
pub const LockCheckResult = enum {
    unlocked,
    locked,
    store_error,
};

/// Normalize an IdP-issued identity to its localpart for lock storage: the
/// IdP's own claim ("Alice@morante.dev", "alice") resolves to the row the
/// admission check enforces for every other mechanism (S3).
pub fn localpartOf(identity: []const u8) []const u8 {
    const cut = if (std.mem.indexOfScalar(u8, identity, '@')) |p| identity[0..p] else identity;
    return cut;
}

/// Interface for permanent lock checking. The auth daemon sets this to
/// a closure over the LockStore.
pub const LockChecker = struct {
    ctx: *anyopaque,
    checkFn: *const fn (ctx: *anyopaque, username: []const u8) LockCheckResult,

    pub fn check(self: LockChecker, username: []const u8) LockCheckResult {
        return self.checkFn(self.ctx, username);
    }
};

/// Standard LockChecker adapter over a LockStore (shared by xmppd-auth and
/// xmppd-auth-oidc so both enforce the same permanent locks).
pub fn makeLockChecker(comptime Backend: type, ls: *lock_store_mod.LockStore(Backend), alloc: std.mem.Allocator) LockChecker {
    const S = struct {
        const Ctx = struct {
            lock_store: *lock_store_mod.LockStore(Backend),
            allocator: std.mem.Allocator,
        };
        var ctx: Ctx = undefined;

        fn check(_: *anyopaque, username: []const u8) LockCheckResult {
            const result = ctx.lock_store.isLocked(ctx.allocator, username) catch return .store_error;
            return if (result != null) .locked else .unlocked;
        }
    };
    S.ctx = .{ .lock_store = ls, .allocator = alloc };
    return .{
        .ctx = @ptrCast(&S.ctx),
        .checkFn = &S.check,
    };
}

/// Longest supported account key, the limiter's key bound.
pub const account_key_max = rate_limiter.max_key_len;

/// Canonical account key: the identity localpart, ASCII-lowercased.
pub fn accountKey(identity: []const u8, buf: *[account_key_max]u8) []const u8 {
    const local = localpartOf(identity);
    if (local.len > buf.len) return local;
    for (local, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..local.len];
}

fn permanentLockReason(checker: LockChecker, username: []const u8) ?[]const u8 {
    switch (checker.check(localpartOf(username))) {
        .locked => {
            log.info("auth rejected: account '{s}' is permanently locked", .{username});
            return "account-disabled";
        },
        .store_error => {
            log.warn("lock store error checking '{s}': failing closed", .{username});
            return "temporary-auth-failure";
        },
        .unlocked => return null,
    }
}

pub const Policy = struct {
    limiter: ?*rate_limiter.RateLimiter = null,
    lock_checker: ?LockChecker = null,

    /// Count one IP attempt and check the IP lock and window. Runs before
    /// the identity is known, so in-flight work is bounded. Returns null
    /// when admitted.
    pub fn admitIp(self: Policy, client_ip: []const u8) ?[]const u8 {
        const limiter = self.limiter orelse return null;
        return switch (limiter.admitIp(client_ip)) {
            .allowed => null,
            .locked, .rate_limited => blk: {
                log.info("auth rejected: IP '{s}' is rate limited", .{client_ip});
                break :blk "policy-violation";
            },
            .unavailable => blk: {
                log.warn("rate state cannot track the request: failing closed", .{});
                break :blk "temporary-auth-failure";
            },
        };
    }

    /// Count one account attempt, then check the permanent lock and the
    /// account lock and window. Returns null when admitted.
    pub fn admitAccount(self: Policy, username: []const u8) ?[]const u8 {
        if (username.len == 0) return null;
        if (self.lock_checker) |checker| {
            if (permanentLockReason(checker, username)) |reason| return reason;
        }

        const limiter = self.limiter orelse return null;
        var buf: [account_key_max]u8 = undefined;
        const account = accountKey(username, &buf);
        return switch (limiter.admitAccount(account)) {
            .allowed => null,
            .locked => blk: {
                log.info("auth rejected: account '{s}' is locked", .{username});
                break :blk "account-disabled";
            },
            .rate_limited => blk: {
                log.info("auth rejected: account '{s}' is rate limited", .{username});
                break :blk "policy-violation";
            },
            .unavailable => blk: {
                log.warn("rate state cannot track the request: failing closed", .{});
                break :blk "temporary-auth-failure";
            },
        };
    }

    /// Count one account attempt and enforce the lock and window, with
    /// in-flight crypto-pool jobs counted as possible failures. Denies when
    /// failures plus pending already reach the lockout threshold.
    pub fn admitAccountPending(self: Policy, username: []const u8, pending: usize) ?[]const u8 {
        if (username.len == 0) return null;
        if (self.lock_checker) |checker| {
            if (permanentLockReason(checker, username)) |reason| return reason;
        }

        const limiter = self.limiter orelse return null;
        var buf: [account_key_max]u8 = undefined;
        const account = accountKey(username, &buf);
        return switch (limiter.admitAccountPending(account, pending)) {
            .allowed => null,
            .locked => blk: {
                log.info("auth rejected: account '{s}' is locked", .{username});
                break :blk "account-disabled";
            },
            .rate_limited => blk: {
                log.info("auth rejected: account '{s}' is rate limited", .{username});
                break :blk "policy-violation";
            },
            .unavailable => blk: {
                log.warn("rate state cannot track the request: failing closed", .{});
                break :blk "temporary-auth-failure";
            },
        };
    }

    /// Count one attempt for both keys. One-shot callers only; mechanisms
    /// call admitIp and then admitAccount so each key is counted once.
    pub fn admit(self: Policy, username: []const u8, client_ip: []const u8) ?[]const u8 {
        if (self.admitIp(client_ip)) |reason| return reason;
        return self.admitAccount(username);
    }

    /// Re-check only the permanent and temporary locks, without counting or
    /// consulting the rate windows. Used at SCRAM client-final before proof
    /// verification and before IdP password validation, so a locked account
    /// gets the same reply whether or not the password is right and an
    /// in-flight attempt is not denied by a filled window.
    pub fn check(self: Policy, username: []const u8, client_ip: []const u8) ?[]const u8 {
        if (username.len > 0) {
            if (self.lock_checker) |checker| {
                if (permanentLockReason(checker, username)) |reason| return reason;
            }
        }

        const limiter = self.limiter orelse return null;
        var buf: [account_key_max]u8 = undefined;
        const account = if (username.len > 0) accountKey(username, &buf) else "";
        return switch (limiter.checkLock(account, client_ip)) {
            .allowed => null,
            .account_locked => blk: {
                log.info("auth rejected: account '{s}' is locked", .{username});
                break :blk "account-disabled";
            },
            .ip_locked => blk: {
                log.info("auth rejected: IP '{s}' is locked", .{client_ip});
                break :blk "policy-violation";
            },
        };
    }

    /// Record the outcome of an attempt already counted at admission.
    pub fn recordOutcome(self: Policy, username: []const u8, client_ip: []const u8, outcome: Outcome) void {
        const limiter = self.limiter orelse return;
        var buf: [account_key_max]u8 = undefined;
        const account = if (username.len > 0) accountKey(username, &buf) else "";
        limiter.recordOutcome(account, client_ip, outcome == .success);
    }

    /// Charge one failed alias login to the typed name and the IdP identity,
    /// and the IP once. The caller has established that the folded keys
    /// differ and the identity is locked.
    pub fn recordAliasFailure(self: Policy, typed: []const u8, identity: []const u8, client_ip: []const u8) void {
        const limiter = self.limiter orelse return;
        var typed_buf: [account_key_max]u8 = undefined;
        var identity_buf: [account_key_max]u8 = undefined;
        limiter.recordAccountFailure(accountKey(typed, &typed_buf));
        limiter.recordAccountFailure(accountKey(identity, &identity_buf));
        limiter.recordOutcome("", client_ip, false);
    }
};

test "Policy: no checks configured admits" {
    const policy = Policy{};
    try std.testing.expect(policy.admit("alice", "10.0.0.1") == null);
    policy.recordOutcome("alice", "10.0.0.1", .failure);
}

test "Policy: a locked account is denied and a store error fails closed" {
    const S = struct {
        var result: LockCheckResult = .unlocked;
        fn check(_: *anyopaque, _: []const u8) LockCheckResult {
            return result;
        }
    };
    var dummy: u8 = 0;
    const policy = Policy{ .lock_checker = .{ .ctx = @ptrCast(&dummy), .checkFn = &S.check } };

    S.result = .unlocked;
    try std.testing.expect(policy.admit("alice", "") == null);

    S.result = .locked;
    try std.testing.expectEqualStrings("account-disabled", policy.admit("alice", "").?);

    S.result = .store_error;
    try std.testing.expectEqualStrings("temporary-auth-failure", policy.admit("alice", "").?);
}

test "Policy: the lock is keyed by the identity localpart" {
    const S = struct {
        var seen: []const u8 = "";
        fn check(_: *anyopaque, username: []const u8) LockCheckResult {
            seen = username;
            return .unlocked;
        }
    };
    var dummy: u8 = 0;
    const policy = Policy{ .lock_checker = .{ .ctx = @ptrCast(&dummy), .checkFn = &S.check } };
    _ = policy.admit("Alice@morante.dev", "");
    try std.testing.expectEqualStrings("Alice", S.seen);
}

test "Policy: admission counts the account and IP keys once" {
    var limiter = try rate_limiter.RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 1,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    const policy = Policy{ .limiter = &limiter };

    try std.testing.expect(policy.admit("alice", "10.0.0.1") == null);
    try std.testing.expectEqualStrings("policy-violation", policy.admit("alice", "10.0.0.1") orelse return error.ExpectedDenial);
    try std.testing.expect(policy.admit("bob", "10.0.0.1") == null);

    var other = try rate_limiter.RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 1,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer other.deinit();
    const ip_policy = Policy{ .limiter = &other };
    try std.testing.expect(ip_policy.admitIp("10.0.0.9") == null);
    try std.testing.expectEqualStrings("policy-violation", ip_policy.admitIp("10.0.0.9").?);
}

test "Policy: a re-check does not count a second account attempt" {
    var limiter = try rate_limiter.RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 1,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    const policy = Policy{ .limiter = &limiter };

    try std.testing.expect(policy.admitAccount("alice") == null);
    try std.testing.expect(policy.check("alice", "") == null);
    try std.testing.expectEqualStrings("policy-violation", policy.admitAccount("alice") orelse return error.ExpectedDenial);
}

test "Policy: an alias failure charges both accounts and the IP once" {
    var limiter = try rate_limiter.RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 1,
        .ip_lockout_threshold = 2,
    });
    defer limiter.deinit();
    const policy = Policy{ .limiter = &limiter };

    policy.recordAliasFailure("a.smith", "alice@idp.example", "10.0.0.1");

    try std.testing.expectEqualStrings("account-disabled", policy.check("a.smith", "") orelse return error.ExpectedDenial);
    try std.testing.expectEqualStrings("account-disabled", policy.check("alice", "") orelse return error.ExpectedDenial);
    // One IP failure, below the threshold of two; a second charge would lock.
    try std.testing.expect(policy.check("other", "10.0.0.1") == null);
}

test "Policy: check folds case against a temporary lock" {
    var limiter = try rate_limiter.RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 1,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    const policy = Policy{ .limiter = &limiter };

    policy.recordOutcome("alice", "10.0.0.1", .failure);

    // The folded ALICE@x must hit the same temporary lock as alice.
    try std.testing.expectEqualStrings("account-disabled", policy.check("ALICE@x", "10.0.0.2") orelse return error.ExpectedDenial);
}

test "Policy: account keys fold case and domain to one localpart" {
    var limiter = try rate_limiter.RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 2,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    const policy = Policy{ .limiter = &limiter };

    policy.recordOutcome("Alice@example", "10.0.0.1", .failure);
    policy.recordOutcome("ALICE", "10.0.0.2", .failure);

    // Both failures keyed the same folded localpart: alice is locked.
    try std.testing.expectEqualStrings("account-disabled", policy.admit("alice", "10.0.0.3") orelse return error.ExpectedDenial);
}
