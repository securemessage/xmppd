//! # SubscriptionCache — in-memory cache for roster presence lookups (T129)
//!
//! Caches the results of `getPresenceSubscribersFixed` and
//! `getPresenceSubscriptionsFixed` to avoid repeated LMDB prefix scans
//! on every presence broadcast, unavailable, and probe.
//!
//! A user with 100 contacts would otherwise require 100 LMDB reads +
//! deserializations per status change. With the cache, a status change
//! within the TTL window is a single FNV-1a hash + memcpy.
//!
//! ## Design
//!
//! - Two fixed-size arrays (subscribers + subscriptions), 64 entries each
//! - FNV-1a hash of bare JID for direct-mapped indexing (same as T120 credential cache)
//! - Packed JID format per entry: [u16be len | jid bytes] × count
//! - 30-second TTL — stale entry evicted on next access
//! - Invalidated on roster mutation (caller responsibility)
//!
//! ## Cache sizing
//!
//! Each entry holds up to 2048 bytes of packed JID data (~50 contacts at
//! 40 bytes each). Larger rosters fall through to LMDB on every call.
//! Total memory: 64 × ~2060 × 2 = ~257 KB per worker.

const std = @import("std");

const CACHE_SIZE: usize = 64; // power of 2 for fast modulo
const TTL_SECONDS: i64 = 30;
const JID_BUF_SIZE: usize = 2048;

const Entry = struct {
    bare_jid_hash: u64 = 0,
    timestamp: i64 = 0,
    occupied: bool = false,
    count: u16 = 0,
    data_len: u16 = 0,
    data: [JID_BUF_SIZE]u8 = undefined,
};

pub const SubscriptionCache = struct {
    subscribers: [CACHE_SIZE]Entry = [_]Entry{.{}} ** CACHE_SIZE,
    subscriptions: [CACHE_SIZE]Entry = [_]Entry{.{}} ** CACHE_SIZE,

    /// Look up cached presence subscribers (from/both).
    /// On hit, unpacks JIDs into caller's buffers and returns count.
    /// Returns null on cache miss or expiry.
    pub fn lookupSubscribers(self: *SubscriptionCache, bare_jid_hash: u64, now: i64, jid_buf: []u8, out: [][]const u8) ?usize {
        return lookup(&self.subscribers, bare_jid_hash, now, jid_buf, out);
    }

    /// Look up cached presence subscriptions (to/both).
    pub fn lookupSubscriptions(self: *SubscriptionCache, bare_jid_hash: u64, now: i64, jid_buf: []u8, out: [][]const u8) ?usize {
        return lookup(&self.subscriptions, bare_jid_hash, now, jid_buf, out);
    }

    /// Store a subscriber list in cache after an LMDB scan.
    pub fn storeSubscribers(self: *SubscriptionCache, bare_jid_hash: u64, now: i64, jids: []const []const u8) void {
        store(&self.subscribers, bare_jid_hash, now, jids);
    }

    /// Store a subscription list in cache after an LMDB scan.
    pub fn storeSubscriptions(self: *SubscriptionCache, bare_jid_hash: u64, now: i64, jids: []const []const u8) void {
        store(&self.subscriptions, bare_jid_hash, now, jids);
    }

    /// Invalidate all cache entries for a bare JID hash.
    /// Call this on any roster mutation (setItem, removeItem).
    pub fn invalidate(self: *SubscriptionCache, bare_jid_hash: u64) void {
        const idx = bare_jid_hash & (CACHE_SIZE - 1);
        self.subscribers[idx].occupied = false;
        self.subscriptions[idx].occupied = false;
    }

    fn lookup(table: *[CACHE_SIZE]Entry, bare_jid_hash: u64, now: i64, jid_buf: []u8, out: [][]const u8) ?usize {
        const entry = &table[bare_jid_hash & (CACHE_SIZE - 1)];
        if (!entry.occupied or entry.bare_jid_hash != bare_jid_hash) return null;
        if (now - entry.timestamp > TTL_SECONDS) {
            entry.occupied = false;
            return null;
        }
        return unpack(entry.data[0..entry.data_len], entry.count, jid_buf, out);
    }

    fn store(table: *[CACHE_SIZE]Entry, bare_jid_hash: u64, now: i64, jids: []const []const u8) void {
        var buf: [JID_BUF_SIZE]u8 = undefined;
        var offset: usize = 0;

        for (jids) |jid| {
            const needed = 2 + jid.len;
            if (offset + needed > JID_BUF_SIZE) return; // roster too large to cache
            std.mem.writeInt(u16, buf[offset..][0..2], @intCast(jid.len), .big);
            @memcpy(buf[offset + 2 ..][0..jid.len], jid);
            offset += needed;
        }

        const entry = &table[bare_jid_hash & (CACHE_SIZE - 1)];
        entry.bare_jid_hash = bare_jid_hash;
        entry.timestamp = now;
        entry.occupied = true;
        entry.count = @intCast(jids.len);
        entry.data_len = @intCast(offset);
        @memcpy(entry.data[0..offset], buf[0..offset]);
    }
};

/// Unpack a packed JID buffer into caller-provided slice buffers.
/// Packed format: [u16be len | jid bytes] × count.
fn unpack(data: []const u8, count: u16, jid_buf: []u8, out: [][]const u8) usize {
    var offset: usize = 0;
    var buf_offset: usize = 0;
    var i: usize = 0;

    while (i < count) : (i += 1) {
        if (offset + 2 > data.len) break;
        const jid_len = std.mem.readInt(u16, data[offset..][0..2], .big);
        offset += 2;
        if (offset + jid_len > data.len) break;
        if (buf_offset + jid_len > jid_buf.len or i >= out.len) break;

        @memcpy(jid_buf[buf_offset..][0..jid_len], data[offset..][0..jid_len]);
        out[i] = jid_buf[buf_offset..][0..jid_len];
        buf_offset += jid_len;
        offset += jid_len;
    }

    return i;
}

/// FNV-1a hash of a bare JID string for cache indexing.
pub fn hashBareJid(jid: []const u8) u64 {
    var h: u64 = 0xcbf29ce484222325;
    for (jid) |byte| {
        h ^= byte;
        h *%= 0x00000100000001B3;
    }
    return h;
}

// ============================================================================
// Tests
// ============================================================================

test "SubscriptionCache: store and lookup hit" {
    var cache: SubscriptionCache = .{};
    const now: i64 = 1000;
    const hash = hashBareJid("alice@localhost");

    const jids: [3][]const u8 = .{ "bob@localhost", "carol@localhost", "dave@localhost" };
    cache.storeSubscribers(hash, now, &jids);

    var jid_buf: [1024]u8 = undefined;
    var out: [16][]const u8 = undefined;
    const count = cache.lookupSubscribers(hash, now, &jid_buf, &out) orelse unreachable;

    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualStrings("bob@localhost", out[0]);
    try std.testing.expectEqualStrings("carol@localhost", out[1]);
    try std.testing.expectEqualStrings("dave@localhost", out[2]);
}

test "SubscriptionCache: cache miss returns null" {
    var cache: SubscriptionCache = .{};
    const hash = hashBareJid("alice@localhost");

    var jid_buf: [1024]u8 = undefined;
    var out: [16][]const u8 = undefined;
    try std.testing.expect(cache.lookupSubscribers(hash, 1000, &jid_buf, &out) == null);
}

test "SubscriptionCache: TTL expiry" {
    var cache: SubscriptionCache = .{};
    const hash = hashBareJid("alice@localhost");
    const jids: [1][]const u8 = .{"bob@localhost"};

    cache.storeSubscribers(hash, 1000, &jids);

    var jid_buf: [1024]u8 = undefined;
    var out: [16][]const u8 = undefined;

    // Within TTL
    try std.testing.expect(cache.lookupSubscribers(hash, 1029, &jid_buf, &out) != null);
    // Expired
    try std.testing.expect(cache.lookupSubscribers(hash, 1031, &jid_buf, &out) == null);
}

test "SubscriptionCache: invalidate clears both tables" {
    var cache: SubscriptionCache = .{};
    const hash = hashBareJid("alice@localhost");
    const jids: [1][]const u8 = .{"bob@localhost"};

    cache.storeSubscribers(hash, 1000, &jids);
    cache.storeSubscriptions(hash, 1000, &jids);

    var jid_buf: [1024]u8 = undefined;
    var out: [16][]const u8 = undefined;
    try std.testing.expect(cache.lookupSubscribers(hash, 1000, &jid_buf, &out) != null);
    try std.testing.expect(cache.lookupSubscriptions(hash, 1000, &jid_buf, &out) != null);

    cache.invalidate(hash);
    try std.testing.expect(cache.lookupSubscribers(hash, 1000, &jid_buf, &out) == null);
    try std.testing.expect(cache.lookupSubscriptions(hash, 1000, &jid_buf, &out) == null);
}

test "SubscriptionCache: subscribers and subscriptions are independent" {
    var cache: SubscriptionCache = .{};
    const hash = hashBareJid("alice@localhost");

    const subs: [2][]const u8 = .{ "bob@localhost", "carol@localhost" };
    const to: [1][]const u8 = .{"eve@localhost"};

    cache.storeSubscribers(hash, 1000, &subs);
    cache.storeSubscriptions(hash, 1000, &to);

    var jid_buf: [1024]u8 = undefined;
    var out: [16][]const u8 = undefined;

    const sub_count = cache.lookupSubscribers(hash, 1000, &jid_buf, &out) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 2), sub_count);
    try std.testing.expectEqualStrings("bob@localhost", out[0]);

    const to_count = cache.lookupSubscriptions(hash, 1000, &jid_buf, &out) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 1), to_count);
    try std.testing.expectEqualStrings("eve@localhost", out[0]);
}

test "SubscriptionCache: empty JID list round-trips" {
    var cache: SubscriptionCache = .{};
    const hash = hashBareJid("alice@localhost");
    const jids: [0][]const u8 = .{};

    cache.storeSubscribers(hash, 1000, &jids);

    var jid_buf: [1024]u8 = undefined;
    var out: [16][]const u8 = undefined;
    const count = cache.lookupSubscribers(hash, 1000, &jid_buf, &out) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 0), count);
}

test "SubscriptionCache: hash collision evicts old entry" {
    var cache: SubscriptionCache = .{};
    // Two different JIDs that map to the same slot (hash & 63)
    const hash1: u64 = 100;
    const hash2: u64 = 100 + CACHE_SIZE; // same slot

    const jids1: [1][]const u8 = .{"bob@localhost"};
    const jids2: [1][]const u8 = .{"carol@localhost"};

    cache.storeSubscribers(hash1, 1000, &jids1);
    cache.storeSubscribers(hash2, 1000, &jids2);

    var jid_buf: [1024]u8 = undefined;
    var out: [16][]const u8 = undefined;

    // hash1 is evicted — different hash, returns null
    try std.testing.expect(cache.lookupSubscribers(hash1, 1000, &jid_buf, &out) == null);
    // hash2 is current
    const count = cache.lookupSubscribers(hash2, 1000, &jid_buf, &out) orelse unreachable;
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqualStrings("carol@localhost", out[0]);
}
