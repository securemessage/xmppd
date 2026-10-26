//! # Rate Limiter v2: bounded per-account and per-IP admission
//!
//! Fixed-size open-addressed tables (one per account, one per IP). Each
//! entry stores the key bytes (not just a hash), a tumbling window counter
//! and a consecutive-failure lockout. Expired entries become tombstones on
//! the probe path and are reused; when a table is full of live entries the
//! oldest unlocked entry is evicted, and a table where every entry is
//! locked still rejects new keys (fail closed).
//!
//! Attempts are counted at admission, so work already in flight is bounded.
//! The outcome updates only the failure counter and lockout. Windows are
//! tumbling and fixed, so a boundary can pass up to twice the per-window
//! limit. A failure after a lock expires re-locks at once: expiry does not
//! reset the consecutive-failure count.
//!
//! State is intentionally ephemeral: a daemon restart clears every lock.

const std = @import("std");

const log = std.log.scoped(.rate_limiter);

/// Number of entries per table (power of two).
pub const table_size = 1024;

/// Longest tracked key. Account names and IP strings above this bound are
/// rejected by admission (fail closed) rather than folded into a hash.
pub const max_key_len = 511;

const State = enum(u2) {
    empty,
    occupied,
    tombstone,
};

const RateEntry = struct {
    state: State = .empty,
    /// Key bytes, so a hash collision cannot alias two accounts or IPs.
    key: [max_key_len]u8 = undefined,
    key_len: u16 = 0,
    hash: u64 = 0,
    /// Tumbling window: start second and attempts in it.
    window_start: u32 = 0,
    count: u16 = 0,
    /// Consecutive failures and this entry's lock expiry.
    failures: u16 = 0,
    locked_until: u32 = 0,
    /// Last attempt or outcome, for eviction.
    last_seen: u32 = 0,
};

pub const Decision = enum {
    allowed,
    account_locked,
    ip_locked,
    account_rate_limited,
    ip_rate_limited,
    unavailable,
};

const KeyDecision = enum {
    allowed,
    locked,
    rate_limited,
    unavailable,
};

/// Lock verdicts for a re-check that must not consult the rate windows.
pub const LockDecision = enum {
    allowed,
    account_locked,
    ip_locked,
};

/// Rate limiting policy. Defaults are the configured defaults; the CLI help
/// and doc/CONFIGURATION.md carry the same numbers.
pub const RatePolicy = struct {
    max_per_account: u32 = 60,
    max_per_ip: u32 = 200,
    window_seconds: u32 = 120,
    lockout_duration: u32 = 300,
    lockout_threshold: u16 = 10,
    /// Per-IP failures before the IP lock engages. Separate from the account
    /// threshold so one failed account does not block a NAT egress after ten
    /// attempts.
    ip_lockout_threshold: u16 = 20,
};

pub const RateLimiter = struct {
    account_table: []RateEntry,
    ip_table: []RateEntry,
    policy: RatePolicy,
    allocator: std.mem.Allocator,
    /// Last second the full-table warning was logged; keeps a flood of
    /// untrackable keys from flooding the log.
    last_unavailable_log: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, policy: RatePolicy) !RateLimiter {
        var p = policy;
        // A zero window would reset the counter on every call and disable the
        // limit silently.
        p.window_seconds = @max(1, p.window_seconds);
        p.max_per_account = @min(p.max_per_account, @as(u32, std.math.maxInt(u16)));
        p.max_per_ip = @min(p.max_per_ip, @as(u32, std.math.maxInt(u16)));

        const account = try allocator.alloc(RateEntry, table_size);
        errdefer allocator.free(account);
        const ip = try allocator.alloc(RateEntry, table_size);
        @memset(account, .{});
        @memset(ip, .{});
        return .{ .account_table = account, .ip_table = ip, .policy = p, .allocator = allocator };
    }

    pub fn deinit(self: *RateLimiter) void {
        self.allocator.free(self.account_table);
        self.allocator.free(self.ip_table);
    }

    /// Count one attempt for both keys and check them.
    pub fn admit(self: *RateLimiter, username: []const u8, client_ip: []const u8) Decision {
        return self.admitAt(username, client_ip, currentEpoch());
    }

    /// Count one attempt for both keys at an explicit time (tests).
    pub fn admitAt(self: *RateLimiter, username: []const u8, client_ip: []const u8, now: u32) Decision {
        if (username.len > 0) {
            switch (self.admitKey(self.account_table, username, self.policy.max_per_account, now, .count)) {
                .allowed => {},
                .locked => return .account_locked,
                .rate_limited => return .account_rate_limited,
                .unavailable => return .unavailable,
            }
        }
        if (client_ip.len > 0) {
            switch (self.admitKey(self.ip_table, client_ip, self.policy.max_per_ip, now, .count)) {
                .allowed => {},
                .locked => return .ip_locked,
                .rate_limited => return .ip_rate_limited,
                .unavailable => return .unavailable,
            }
        }
        return .allowed;
    }

    /// Count one IP attempt only. Mechanisms admit the IP before the
    /// identity is known, then admit the account once it is.
    pub fn admitIp(self: *RateLimiter, client_ip: []const u8) Decision {
        return self.admitIpAt(client_ip, currentEpoch());
    }

    pub fn admitIpAt(self: *RateLimiter, client_ip: []const u8, now: u32) Decision {
        if (client_ip.len == 0) return .allowed;
        return switch (self.admitKey(self.ip_table, client_ip, self.policy.max_per_ip, now, .count)) {
            .allowed => .allowed,
            .locked => .ip_locked,
            .rate_limited => .ip_rate_limited,
            .unavailable => .unavailable,
        };
    }

    /// Count one account attempt only.
    pub fn admitAccount(self: *RateLimiter, username: []const u8) Decision {
        return self.admitAccountAt(username, currentEpoch());
    }

    pub fn admitAccountAt(self: *RateLimiter, username: []const u8, now: u32) Decision {
        if (username.len == 0) return .allowed;
        return switch (self.admitKey(self.account_table, username, self.policy.max_per_account, now, .count)) {
            .allowed => .allowed,
            .locked => .account_locked,
            .rate_limited => .account_rate_limited,
            .unavailable => .unavailable,
        };
    }

    /// Re-check both keys without counting. Used at SCRAM client-final so an
    /// attempt already counted at client-first can still complete.
    pub fn check(self: *RateLimiter, username: []const u8, client_ip: []const u8) Decision {
        return self.checkAt(username, client_ip, currentEpoch());
    }

    pub fn checkAt(self: *RateLimiter, username: []const u8, client_ip: []const u8, now: u32) Decision {
        if (username.len > 0) {
            switch (self.admitKey(self.account_table, username, self.policy.max_per_account, now, .check)) {
                .allowed => {},
                .locked => return .account_locked,
                .rate_limited => return .account_rate_limited,
                .unavailable => return .unavailable,
            }
        }
        if (client_ip.len > 0) {
            switch (self.admitKey(self.ip_table, client_ip, self.policy.max_per_ip, now, .check)) {
                .allowed => {},
                .locked => return .ip_locked,
                .rate_limited => return .ip_rate_limited,
                .unavailable => return .unavailable,
            }
        }
        return .allowed;
    }

    /// Re-check only the account and IP locks, without consulting the
    /// windows. Used at SCRAM client-final and before IdP validation, where
    /// an in-flight attempt must not be denied merely because other attempts
    /// filled the window.
    pub fn checkLock(self: *RateLimiter, username: []const u8, client_ip: []const u8) LockDecision {
        return self.checkLockAt(username, client_ip, currentEpoch());
    }

    pub fn checkLockAt(self: *RateLimiter, username: []const u8, client_ip: []const u8, now: u32) LockDecision {
        if (username.len > 0) {
            if (self.find(self.account_table, username)) |entry| {
                if (entry.locked_until > now) return .account_locked;
            }
        }
        if (client_ip.len > 0) {
            if (self.find(self.ip_table, client_ip)) |entry| {
                if (entry.locked_until > now) return .ip_locked;
            }
        }
        return .allowed;
    }

    /// Record the outcome of an attempt already counted at admission.
    /// Success clears only the account failure counter; the IP failure
    /// counter is never cleared by a success.
    pub fn recordOutcome(self: *RateLimiter, username: []const u8, client_ip: []const u8, success: bool) void {
        self.recordOutcomeAt(username, client_ip, success, currentEpoch());
    }

    pub fn recordOutcomeAt(self: *RateLimiter, username: []const u8, client_ip: []const u8, success: bool, now: u32) void {
        if (username.len > 0) {
            self.recordKey(
                self.account_table,
                username,
                success,
                self.policy.lockout_threshold,
                now,
                true,
            );
        }
        if (client_ip.len > 0) {
            self.recordKey(
                self.ip_table,
                client_ip,
                success,
                self.policy.ip_lockout_threshold,
                now,
                false,
            );
        }
    }

    const AdmitMode = enum { count, check };

    fn admitKey(self: *RateLimiter, table: []RateEntry, key: []const u8, max: u32, now: u32, mode: AdmitMode) KeyDecision {
        if (key.len > max_key_len) return .unavailable;
        if (mode == .check) {
            const entry = self.find(table, key) orelse return .allowed;
            if (entry.locked_until > now) return .locked;
            self.rollWindow(entry, now);
            if (entry.count > max) return .rate_limited;
            return .allowed;
        }

        const entry = self.findOrCreate(table, key, now) orelse {
            self.noteFull(now);
            return .unavailable;
        };
        if (entry.locked_until > now) return .locked;
        self.rollWindow(entry, now);
        entry.count +|= 1;
        entry.last_seen = now;
        if (entry.count > max) return .rate_limited;
        return .allowed;
    }

    fn recordKey(
        self: *RateLimiter,
        table: []RateEntry,
        key: []const u8,
        success: bool,
        threshold: u16,
        now: u32,
        clear_on_success: bool,
    ) void {
        if (key.len > max_key_len) {
            log.warn("rate key is {d} bytes, above the {d}-byte bound; denying admission separately", .{ key.len, max_key_len });
            return;
        }
        const entry = self.findOrCreate(table, key, now) orelse {
            self.noteFull(now);
            return;
        };
        self.rollWindow(entry, now);
        entry.last_seen = now;
        if (success) {
            if (clear_on_success) {
                entry.failures = 0;
                entry.locked_until = 0;
            }
        } else {
            entry.failures +|= 1;
            if (entry.failures >= threshold) {
                entry.locked_until = now + self.policy.lockout_duration;
            }
        }
    }

    fn rollWindow(self: *RateLimiter, entry: *RateEntry, now: u32) void {
        if (now < entry.window_start or now - entry.window_start >= self.policy.window_seconds) {
            entry.window_start = now;
            entry.count = 0;
        }
    }

    fn noteFull(self: *RateLimiter, now: u32) void {
        if (self.last_unavailable_log != 0 and now >= self.last_unavailable_log and
            now - self.last_unavailable_log < self.policy.window_seconds) return;
        self.last_unavailable_log = now;
        log.warn("rate table full of live entries and every entry is locked; new key cannot be tracked", .{});
    }

    fn evictAfter(self: *RateLimiter) u32 {
        const longest = @max(self.policy.window_seconds, self.policy.lockout_duration);
        return @max(longest, 1) * 2;
    }

    fn isExpired(self: *RateLimiter, entry: *const RateEntry, now: u32) bool {
        if (entry.locked_until > now) return false;
        if (now < entry.last_seen) return true;
        return now - entry.last_seen >= self.evictAfter();
    }

    fn find(self: *RateLimiter, table: []RateEntry, key: []const u8) ?*RateEntry {
        _ = self;
        const hash = hashKey(key);
        var idx = @as(usize, @intCast(hash & (table_size - 1)));
        var probes: usize = 0;
        while (probes < table_size) : (probes += 1) {
            const entry = &table[idx];
            switch (entry.state) {
                .empty => return null,
                .occupied => {
                    if (entry.hash == hash and @as(usize, entry.key_len) == key.len and
                        std.mem.eql(u8, entry.key[0..entry.key_len], key)) return entry;
                },
                .tombstone => {},
            }
            idx = (idx + 1) & (table_size - 1);
        }
        return null;
    }

    fn findOrCreate(self: *RateLimiter, table: []RateEntry, key: []const u8, now: u32) ?*RateEntry {
        const hash = hashKey(key);
        var idx = @as(usize, @intCast(hash & (table_size - 1)));
        var first_tombstone: ?usize = null;
        var probes: usize = 0;

        while (probes < table_size) : (probes += 1) {
            const entry = &table[idx];
            switch (entry.state) {
                .empty => return self.insertAt(table, first_tombstone orelse idx, key, hash, now),
                .tombstone => {
                    if (first_tombstone == null) first_tombstone = idx;
                },
                .occupied => {
                    if (entry.hash == hash and @as(usize, entry.key_len) == key.len and
                        std.mem.eql(u8, entry.key[0..entry.key_len], key)) return entry;
                    if (self.isExpired(entry, now)) {
                        entry.state = .tombstone;
                        if (first_tombstone == null) first_tombstone = idx;
                    }
                },
            }
            idx = (idx + 1) & (table_size - 1);
        }
        if (first_tombstone) |slot| return self.insertAt(table, slot, key, hash, now);

        // The table is full of live entries. Reclaim the oldest entry that is
        // not locked; a lock must survive the flood that created it. If every
        // entry is locked the key is untrackable and admission fails closed.
        var victim: ?usize = null;
        var oldest: u32 = std.math.maxInt(u32);
        for (table, 0..) |*entry, i| {
            if (entry.state != .occupied) continue;
            if (entry.locked_until > now) continue;
            if (entry.last_seen <= oldest) {
                oldest = entry.last_seen;
                victim = i;
            }
        }
        if (victim) |slot| {
            table[slot].state = .tombstone;
            return self.insertAt(table, slot, key, hash, now);
        }
        return null;
    }

    fn insertAt(self: *RateLimiter, table: []RateEntry, idx: usize, key: []const u8, hash: u64, now: u32) *RateEntry {
        _ = self;
        const entry = &table[idx];
        entry.* = .{
            .state = .occupied,
            .key_len = @intCast(key.len),
            .hash = hash,
            .window_start = now,
            .last_seen = now,
        };
        @memcpy(entry.key[0..key.len], key);
        return entry;
    }
};

/// Hash a key for the probe start. The key bytes decide identity; the hash
/// only picks the first slot.
fn hashKey(key: []const u8) u64 {
    const h = std.hash.Wyhash.hash(0xdeadbeef_cafebabe, key);
    return if (h == 0) 1 else h;
}

fn currentEpoch() u32 {
    const ts = std.time.timestamp();
    return @intCast(@as(u64, @bitCast(ts)) & 0xFFFFFFFF);
}

pub fn testCurrentEpoch() u32 {
    return currentEpoch();
}

// ============================================================================
// Tests
// ============================================================================

fn testLimiter(policy: RatePolicy) !RateLimiter {
    return RateLimiter.init(std.testing.allocator, policy);
}

test "RateLimiter: allows initial attempts" {
    var limiter = try testLimiter(.{
        .max_per_account = 3,
        .max_per_ip = 10,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 5,
    });
    defer limiter.deinit();

    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("alice", "10.0.0.1", 100));
}

test "RateLimiter: each admit counts the account attempt" {
    var limiter = try testLimiter(.{
        .max_per_account = 3,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
    });
    defer limiter.deinit();

    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("alice", "10.0.0.1", 100));
    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("alice", "10.0.0.1", 100));
    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("alice", "10.0.0.1", 100));
    try std.testing.expectEqual(Decision.account_rate_limited, limiter.admitAt("alice", "10.0.0.1", 100));
}

test "RateLimiter: each admit counts the IP attempt" {
    var limiter = try testLimiter(.{
        .max_per_account = 100,
        .max_per_ip = 2,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();

    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("user1", "10.0.0.1", 100));
    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("user2", "10.0.0.1", 100));
    try std.testing.expectEqual(Decision.ip_rate_limited, limiter.admitAt("user3", "10.0.0.1", 100));
}

test "RateLimiter: temporary lockout after failures" {
    var limiter = try testLimiter(.{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 3,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();

    limiter.recordOutcomeAt("alice", "10.0.0.1", false, 100);
    limiter.recordOutcomeAt("alice", "10.0.0.2", false, 100);
    limiter.recordOutcomeAt("alice", "10.0.0.3", false, 100);

    try std.testing.expectEqual(Decision.account_locked, limiter.admitAt("alice", "10.0.0.5", 100));
}

test "RateLimiter: per-IP lockout engages" {
    var limiter = try testLimiter(.{
        .max_per_account = 100,
        .max_per_ip = 1000,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 3,
    });
    defer limiter.deinit();

    limiter.recordOutcomeAt("user1", "10.0.0.1", false, 100);
    limiter.recordOutcomeAt("user2", "10.0.0.1", false, 100);
    limiter.recordOutcomeAt("user3", "10.0.0.1", false, 100);

    try std.testing.expectEqual(Decision.ip_locked, limiter.admitAt("user4", "10.0.0.1", 100));
}

test "RateLimiter: a success clears the account failure counter" {
    var limiter = try testLimiter(.{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 3,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();

    limiter.recordOutcomeAt("alice", "10.0.0.1", false, 100);
    limiter.recordOutcomeAt("alice", "10.0.0.2", false, 100);
    limiter.recordOutcomeAt("alice", "10.0.0.3", true, 100);
    limiter.recordOutcomeAt("alice", "10.0.0.4", false, 100);
    limiter.recordOutcomeAt("alice", "10.0.0.5", false, 100);

    // Two failures since the success stay below the threshold of three.
    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("alice", "10.0.0.9", 100));
}

test "RateLimiter: a success never clears the IP failure counter" {
    var limiter = try testLimiter(.{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 2,
    });
    defer limiter.deinit();

    limiter.recordOutcomeAt("alice", "10.0.0.1", false, 100);
    // A successful account login from the same IP must not erase the IP's
    // failure history.
    limiter.recordOutcomeAt("alice", "10.0.0.1", true, 100);
    limiter.recordOutcomeAt("bob", "10.0.0.1", false, 100);

    try std.testing.expectEqual(Decision.ip_locked, limiter.admitAt("carol", "10.0.0.1", 100));
}

test "RateLimiter: different accounts are independent" {
    var limiter = try testLimiter(.{
        .max_per_account = 2,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();

    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("alice", "10.0.0.1", 100));
    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("alice", "10.0.0.2", 100));
    try std.testing.expectEqual(Decision.account_rate_limited, limiter.admitAt("alice", "10.0.0.3", 100));
    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("bob", "10.0.0.3", 100));
}

test "RateLimiter: default policy engages at its own limits" {
    var limiter = try testLimiter(.{});
    defer limiter.deinit();
    const policy = RatePolicy{};

    var i: u32 = 0;
    while (i < policy.max_per_ip) : (i += 1) {
        try std.testing.expectEqual(Decision.allowed, limiter.admitAt("", "10.1.2.3", 1000));
    }
    try std.testing.expectEqual(Decision.ip_rate_limited, limiter.admitAt("", "10.1.2.3", 1000));

    i = 0;
    while (i < policy.max_per_account) : (i += 1) {
        try std.testing.expectEqual(Decision.allowed, limiter.admitAt("user", "10.9.8.7", 1000));
    }
    try std.testing.expectEqual(Decision.account_rate_limited, limiter.admitAt("user", "10.9.8.7", 1000));
}

test "RateLimiter: empty key is ignored" {
    var limiter = try testLimiter(.{});
    defer limiter.deinit();

    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("", "", 100));
    limiter.recordOutcomeAt("", "", false, 100);
    limiter.recordOutcomeAt("", "", true, 100);
}

test "RateLimiter: the window expires" {
    var limiter = try testLimiter(.{
        .max_per_account = 2,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();

    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("alice", "", 1000));
    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("alice", "", 1000));
    try std.testing.expectEqual(Decision.account_rate_limited, limiter.admitAt("alice", "", 1000));
    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("alice", "", 1061));
}

test "RateLimiter: a re-check does not count a second attempt" {
    var limiter = try testLimiter(.{
        .max_per_account = 1,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();

    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("alice", "", 100));
    try std.testing.expectEqual(Decision.allowed, limiter.checkAt("alice", "", 100));
    try std.testing.expectEqual(Decision.account_rate_limited, limiter.admitAt("alice", "", 100));
}

test "RateLimiter: a lock-only check ignores the window" {
    var limiter = try testLimiter(.{
        .max_per_account = 1,
        .max_per_ip = 1,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();

    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("alice", "10.0.0.1", 100));
    try std.testing.expectEqual(Decision.account_rate_limited, limiter.admitAt("alice", "10.0.0.1", 100));
    try std.testing.expectEqual(Decision.account_rate_limited, limiter.checkAt("alice", "10.0.0.1", 100));
    try std.testing.expectEqual(LockDecision.allowed, limiter.checkLockAt("alice", "10.0.0.1", 100));

    const account = limiter.find(limiter.account_table, "alice").?;
    account.locked_until = 200;
    try std.testing.expectEqual(LockDecision.account_locked, limiter.checkLockAt("alice", "10.0.0.1", 100));

    account.locked_until = 0;
    const ip = limiter.find(limiter.ip_table, "10.0.0.1").?;
    ip.locked_until = 200;
    try std.testing.expectEqual(LockDecision.ip_locked, limiter.checkLockAt("alice", "10.0.0.1", 100));
}

test "RateLimiter: a full table evicts the oldest unlocked entry" {
    var limiter = try testLimiter(.{
        .max_per_account = 1000,
        .max_per_ip = 1000,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();

    var buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < table_size) : (i += 1) {
        const key = try std.fmt.bufPrint(&buf, "user-{d}", .{i});
        try std.testing.expectEqual(Decision.allowed, limiter.admitAt(key, "", 1000));
    }

    // Keep every entry inside the eviction horizon, with user-0 oldest.
    for (limiter.account_table) |*entry| {
        if (entry.state == .occupied) entry.last_seen = 1100;
    }
    limiter.find(limiter.account_table, "user-0").?.last_seen = 1000;
    limiter.find(limiter.account_table, "user-1").?.last_seen = 1001;

    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("new", "", 1100));
    try std.testing.expect(limiter.find(limiter.account_table, "user-0") == null);
    try std.testing.expect(limiter.find(limiter.account_table, "new") != null);
}

test "RateLimiter: a full table where every entry is locked fails closed" {
    var limiter = try testLimiter(.{
        .max_per_account = 1000,
        .max_per_ip = 1000,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();

    var buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < table_size) : (i += 1) {
        const key = try std.fmt.bufPrint(&buf, "user-{d}", .{i});
        _ = limiter.admitAt(key, "", 1000);
    }
    for (limiter.account_table) |*entry| {
        if (entry.state == .occupied) entry.locked_until = 1200;
    }

    try std.testing.expectEqual(Decision.unavailable, limiter.admitAt("new", "", 1100));
}

test "RateLimiter: a lock outlives plain counters during eviction" {
    var limiter = try testLimiter(.{
        .max_per_account = 1000,
        .max_per_ip = 1000,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();

    var buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < table_size) : (i += 1) {
        const key = try std.fmt.bufPrint(&buf, "user-{d}", .{i});
        _ = limiter.admitAt(key, "", 1000);
    }
    for (limiter.account_table) |*entry| {
        if (entry.state == .occupied) entry.last_seen = 1100;
    }
    // user-0 is the oldest, but it is locked. user-1 is the oldest entry
    // that may be reclaimed.
    const locked = limiter.find(limiter.account_table, "user-0").?;
    locked.last_seen = 1000;
    locked.locked_until = 1200;
    limiter.find(limiter.account_table, "user-1").?.last_seen = 1001;

    try std.testing.expectEqual(Decision.allowed, limiter.admitAt("new", "", 1100));
    try std.testing.expect(limiter.find(limiter.account_table, "user-0") != null);
    try std.testing.expect(limiter.find(limiter.account_table, "user-1") == null);
    try std.testing.expect(limiter.find(limiter.account_table, "new") != null);
}

test "RateLimiter: the full-table warning is rate limited" {
    var limiter = try testLimiter(.{
        .max_per_account = 1000,
        .max_per_ip = 1000,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();

    var buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < table_size) : (i += 1) {
        const key = try std.fmt.bufPrint(&buf, "user-{d}", .{i});
        _ = limiter.admitAt(key, "", 1000);
    }
    for (limiter.account_table) |*entry| {
        if (entry.state == .occupied) entry.locked_until = 5000;
    }

    limiter.recordOutcomeAt("x", "", true, 2000);
    try std.testing.expectEqual(@as(u32, 2000), limiter.last_unavailable_log);
    limiter.recordOutcomeAt("y", "", true, 2010);
    try std.testing.expectEqual(@as(u32, 2000), limiter.last_unavailable_log);
    limiter.recordOutcomeAt("z", "", true, 2060);
    try std.testing.expectEqual(@as(u32, 2060), limiter.last_unavailable_log);
}

test "RateLimiter: key bytes distinguish equal hashes" {
    var limiter = try testLimiter(.{});
    defer limiter.deinit();

    // Force a collision-shaped entry: same hash as "bob", different bytes.
    const idx = @as(usize, @intCast(hashKey("bob") & (table_size - 1)));
    var entry = &limiter.account_table[idx];
    entry.* = .{
        .state = .occupied,
        .hash = hashKey("bob"),
        .key_len = @intCast("alice".len),
        .window_start = 100,
        .last_seen = 100,
    };
    @memcpy(entry.key[0.."alice".len], "alice");

    // "bob" must not be served from alice's entry.
    try std.testing.expect(limiter.find(limiter.account_table, "bob") == null);
    const created = limiter.findOrCreate(limiter.account_table, "bob", 100) orelse return error.NoEntry;
    try std.testing.expectEqualStrings("bob", created.key[0..@as(usize, created.key_len)]);
}
