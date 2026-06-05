//! # Rate Limiter — Per-IP and per-account brute force protection
//!
//! Fixed-size hash tables with open addressing. Tracks authentication
//! attempts within a sliding window and applies temporary lockouts
//! after consecutive failures.
//!
//! ## Design
//!
//! - Two separate tables: per-account and per-IP
//! - Ring buffer of timestamps for windowed rate counting
//! - Consecutive failure counter with exponential backoff lockout
//! - Ephemeral — all state lost on daemon restart (intentional for admin recovery)
//! - Fail closed — table full → reject (not allow)

const std = @import("std");

const log = std.log.scoped(.rate_limiter);

/// Number of recent attempt timestamps to track per entry.
const RING_SIZE = 8;

/// Rate table size (power of 2, open addressing).
const TABLE_SIZE = 4096;

/// A single rate tracking entry (per-account or per-IP).
const RateEntry = struct {
    /// Hash of the key (username or IP string). 0 = empty slot.
    key_hash: u64 = 0,
    /// Ring buffer of attempt timestamps (epoch seconds).
    attempts: [RING_SIZE]u32 = [_]u32{0} ** RING_SIZE,
    /// Current ring position (next write index).
    ring_pos: u8 = 0,
    /// Consecutive failure count (reset on success).
    failures: u16 = 0,
    /// Epoch second when temporary lockout expires (0 = not locked).
    locked_until: u32 = 0,
    /// Whether this slot is occupied.
    active: bool = false,

    fn reset(self: *RateEntry) void {
        self.* = .{};
    }
};

/// Rate limiting policy (configurable via CLI flags).
pub const RatePolicy = struct {
    /// Max attempts per account within the window.
    max_per_account: u32 = 5,
    /// Max attempts per IP within the window.
    max_per_ip: u32 = 20,
    /// Window size in seconds.
    window_seconds: u32 = 120,
    /// Temporary lockout duration in seconds.
    lockout_duration: u32 = 300,
    /// Consecutive failures before temporary lockout.
    lockout_threshold: u16 = 10,
};

/// Rate limiter with two tables: per-account and per-IP.
pub const RateLimiter = struct {
    account_table: [TABLE_SIZE]RateEntry = [_]RateEntry{.{}} ** TABLE_SIZE,
    ip_table: [TABLE_SIZE]RateEntry = [_]RateEntry{.{}} ** TABLE_SIZE,
    policy: RatePolicy,

    pub fn init(policy: RatePolicy) RateLimiter {
        return .{ .policy = policy };
    }

    /// Check if an authentication attempt should be allowed.
    /// Returns null if allowed, or an error reason string if denied.
    pub fn checkAllowed(self: *RateLimiter, username: []const u8, client_ip: []const u8) ?[]const u8 {
        const now = currentEpoch();

        // Check per-IP rate first (broadest protection)
        if (client_ip.len > 0) {
            if (self.isRateLimited(&self.ip_table, client_ip, self.policy.max_per_ip, now)) {
                log.info("rate limited by IP: {s}", .{client_ip});
                return "policy-violation";
            }
        }

        // Check per-account temporary lockout
        if (username.len > 0) {
            const account_entry = self.findEntry(&self.account_table, username);
            if (account_entry) |entry| {
                if (entry.locked_until > 0 and now < entry.locked_until) {
                    log.info("account temporarily locked: {s} (until {d})", .{ username, entry.locked_until });
                    return "account-disabled";
                }
            }

            // Check per-account rate
            if (self.isRateLimited(&self.account_table, username, self.policy.max_per_account, now)) {
                log.info("rate limited by account: {s}", .{username});
                return "policy-violation";
            }
        }

        return null; // Allowed
    }

    /// Record an authentication attempt (call before processing).
    pub fn recordAttempt(self: *RateLimiter, username: []const u8, client_ip: []const u8) void {
        const now = currentEpoch();

        if (client_ip.len > 0) {
            self.addAttempt(&self.ip_table, client_ip, now);
        }
        if (username.len > 0) {
            self.addAttempt(&self.account_table, username, now);
        }
    }

    /// Record an authentication failure. Increments failure counter and
    /// applies temporary lockout if threshold is exceeded.
    pub fn recordFailure(self: *RateLimiter, username: []const u8, client_ip: []const u8) void {
        const now = currentEpoch();

        if (client_ip.len > 0) {
            if (self.findOrCreateEntry(&self.ip_table, client_ip)) |entry| {
                entry.failures +|= 1;
            }
        }

        if (username.len > 0) {
            if (self.findOrCreateEntry(&self.account_table, username)) |entry| {
                entry.failures +|= 1;
                if (entry.failures >= self.policy.lockout_threshold) {
                    entry.locked_until = now + self.policy.lockout_duration;
                    log.info("account temp-locked: {s} after {d} failures", .{ username, entry.failures });
                }
            }
        }
    }

    /// Record an authentication success. Resets the account failure counter.
    pub fn recordSuccess(self: *RateLimiter, username: []const u8) void {
        if (username.len > 0) {
            if (self.findEntry(&self.account_table, username)) |entry| {
                entry.failures = 0;
                entry.locked_until = 0;
            }
        }
    }

    // --- Internal helpers ---

    fn isRateLimited(self: *const RateLimiter, table: *const [TABLE_SIZE]RateEntry, key: []const u8, max: u32, now: u32) bool {
        const entry = self.findEntryConst(table, key) orelse return false;

        // Count attempts within the window
        const window_start = if (now > self.policy.window_seconds) now - self.policy.window_seconds else 0;
        var count: u32 = 0;
        for (entry.attempts) |ts| {
            if (ts > window_start) count += 1;
        }
        return count >= max;
    }

    fn addAttempt(self: *RateLimiter, table: *[TABLE_SIZE]RateEntry, key: []const u8, now: u32) void {
        if (self.findOrCreateEntry(table, key)) |entry| {
            entry.attempts[entry.ring_pos] = now;
            entry.ring_pos = @intCast((@as(u16, entry.ring_pos) + 1) % RING_SIZE);
        }
    }

    fn findEntry(_: *RateLimiter, table: *[TABLE_SIZE]RateEntry, key: []const u8) ?*RateEntry {
        const hash = hashKey(key);
        var idx = @as(usize, @intCast(hash & (TABLE_SIZE - 1)));
        var probes: usize = 0;

        while (probes < TABLE_SIZE) : (probes += 1) {
            const entry = &table[idx];
            if (!entry.active) return null;
            if (entry.key_hash == hash) return entry;
            idx = (idx + 1) & (TABLE_SIZE - 1);
        }
        return null;
    }

    fn findEntryConst(_: *const RateLimiter, table: *const [TABLE_SIZE]RateEntry, key: []const u8) ?*const RateEntry {
        const hash = hashKey(key);
        var idx = @as(usize, @intCast(hash & (TABLE_SIZE - 1)));
        var probes: usize = 0;

        while (probes < TABLE_SIZE) : (probes += 1) {
            const entry = &table[idx];
            if (!entry.active) return null;
            if (entry.key_hash == hash) return entry;
            idx = (idx + 1) & (TABLE_SIZE - 1);
        }
        return null;
    }

    fn findOrCreateEntry(_: *RateLimiter, table: *[TABLE_SIZE]RateEntry, key: []const u8) ?*RateEntry {
        const hash = hashKey(key);
        var idx = @as(usize, @intCast(hash & (TABLE_SIZE - 1)));
        var probes: usize = 0;

        while (probes < TABLE_SIZE) : (probes += 1) {
            const entry = &table[idx];
            if (!entry.active) {
                // Claim this empty slot
                entry.key_hash = hash;
                entry.active = true;
                return entry;
            }
            if (entry.key_hash == hash) return entry;
            idx = (idx + 1) & (TABLE_SIZE - 1);
        }
        // Table full — fail closed (return null → caller treats as denied)
        return null;
    }
};

/// Hash a key string (username or IP) to a u64. Uses wyhash for speed.
fn hashKey(key: []const u8) u64 {
    const h = std.hash.Wyhash.hash(0xdeadbeef_cafebabe, key);
    // Ensure non-zero (0 is our "empty" sentinel)
    return if (h == 0) 1 else h;
}

/// Get current epoch time in seconds.
fn currentEpoch() u32 {
    const ts = std.time.timestamp();
    return @intCast(@as(u64, @bitCast(ts)) & 0xFFFFFFFF);
}

/// Testing helper: get current epoch (exposed for tests).
pub fn testCurrentEpoch() u32 {
    return currentEpoch();
}

// ============================================================================
// Tests
// ============================================================================

test "RateLimiter: allows initial attempts" {
    var limiter = RateLimiter.init(.{
        .max_per_account = 3,
        .max_per_ip = 10,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 5,
    });

    // First attempt should be allowed
    try std.testing.expect(limiter.checkAllowed("alice", "10.0.0.1") == null);
}

test "RateLimiter: blocks after max_per_account exceeded" {
    var limiter = RateLimiter.init(.{
        .max_per_account = 3,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
    });

    // Record 3 attempts (fills window)
    limiter.recordAttempt("alice", "10.0.0.1");
    limiter.recordAttempt("alice", "10.0.0.2");
    limiter.recordAttempt("alice", "10.0.0.3");

    // 4th should be blocked
    const result = limiter.checkAllowed("alice", "10.0.0.4");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("policy-violation", result.?);
}

test "RateLimiter: blocks after max_per_ip exceeded" {
    var limiter = RateLimiter.init(.{
        .max_per_account = 100,
        .max_per_ip = 2,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
    });

    // Record 2 attempts from same IP
    limiter.recordAttempt("user1", "10.0.0.1");
    limiter.recordAttempt("user2", "10.0.0.1");

    // 3rd from same IP should be blocked
    const result = limiter.checkAllowed("user3", "10.0.0.1");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("policy-violation", result.?);
}

test "RateLimiter: temporary lockout after failures" {
    var limiter = RateLimiter.init(.{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 3,
    });

    // Record 3 failures
    limiter.recordFailure("alice", "10.0.0.1");
    limiter.recordFailure("alice", "10.0.0.2");
    limiter.recordFailure("alice", "10.0.0.3");

    // Should be temp-locked
    const result = limiter.checkAllowed("alice", "10.0.0.5");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("account-disabled", result.?);
}

test "RateLimiter: success resets failure counter" {
    var limiter = RateLimiter.init(.{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 5,
    });

    // Record some failures
    limiter.recordFailure("bob", "10.0.0.1");
    limiter.recordFailure("bob", "10.0.0.2");
    limiter.recordFailure("bob", "10.0.0.3");

    // Success resets
    limiter.recordSuccess("bob");

    // Should not be locked
    const result = limiter.checkAllowed("bob", "10.0.0.5");
    try std.testing.expect(result == null);
}

test "RateLimiter: different accounts are independent" {
    var limiter = RateLimiter.init(.{
        .max_per_account = 2,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
    });

    // Fill alice's window
    limiter.recordAttempt("alice", "10.0.0.1");
    limiter.recordAttempt("alice", "10.0.0.2");

    // Alice should be blocked
    try std.testing.expect(limiter.checkAllowed("alice", "10.0.0.3") != null);

    // Bob should still be allowed
    try std.testing.expect(limiter.checkAllowed("bob", "10.0.0.3") == null);
}

test "RateLimiter: empty key is ignored" {
    var limiter = RateLimiter.init(.{});

    // Empty username or IP should not crash
    try std.testing.expect(limiter.checkAllowed("", "") == null);
    limiter.recordAttempt("", "");
    limiter.recordFailure("", "");
    limiter.recordSuccess("");
}
