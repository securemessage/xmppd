//! Bounded per-worker pool of parked SCRAM exchange state (ADR-6).
//!
//! Protocol v2 parks the pieces of one SCRAM exchange on the core between
//! client-first and client-final: the raw n= name (params-cache key), the
//! client-first bare, the client nonce, the issued server-first and the
//! channel binding. Keeping that state inline in Session cost ~2 KiB of
//! Session for a mechanism only a fraction of connections use; a session
//! now carries a u32 token into this pool instead.
//!
//! Slots are leased by token: high 16 bits are a generation bumped at every
//! release, low 16 bits the slot index, so a token replayed after its slot
//! was reissued resolves to null rather than to someone else's exchange.
//! A full pool refuses the acquire: the caller maps that to
//! temporary-auth-failure and counts it; slots are never stolen from a
//! live exchange.

const std = @import("std");

/// Sentinel for "this session parks no exchange".
pub const TOKEN_NONE: u32 = 0xFFFF_FFFF;

pub const ScramExchange = struct {
    /// Token generation; bumped on release so stale tokens miss.
    gen: u16 = 0,
    in_use: bool = false,
    /// gs2 channel binding flag from client-first ('n', 'y' or 'p').
    gs2_flag: u8 = 0,
    /// The escaped n= name: params-request username and params-cache key.
    user_buf: [256]u8 = undefined,
    user_len: usize = 0,
    /// client-first-message-bare verbatim.
    bare_buf: [1024]u8 = undefined,
    bare_len: usize = 0,
    /// The r= client nonce, prefix of the combined nonce in server-first.
    cnonce_buf: [256]u8 = undefined,
    cnonce_len: usize = 0,
    /// The server-first-message this core issued (sent to the daemon for
    /// verification verbatim; it is part of the AuthMessage).
    sfirst_buf: [512]u8 = undefined,
    sfirst_len: usize = 0,
    /// Channel binding captured at exchange start.
    cb_type: u8 = 0,
    cb_buf: [32]u8 = undefined,
    cb_len: usize = 0,

    /// Rewind for a new exchange on an already-leased slot.
    pub fn reset(self: *ScramExchange) void {
        const gen = self.gen;
        self.* = .{};
        self.gen = gen;
        self.in_use = true;
    }
};

pub const ScramExchangePool = struct {
    slots: []ScramExchange = &.{},
    /// Stack of free slot indices; free_count entries are live.
    free: []u16 = &.{},
    free_count: usize = 0,

    /// Allocate `capacity` slots; every slot starts free with generation 0.
    /// Capacity above u16's index space is refused: tokens cannot name it.
    pub fn init(self: *ScramExchangePool, allocator: std.mem.Allocator, capacity: usize) !void {
        if (capacity > std.math.maxInt(u16) + 1) return error.CapacityTooLarge;
        self.slots = try allocator.alloc(ScramExchange, capacity);
        errdefer allocator.free(self.slots);
        self.free = try allocator.alloc(u16, capacity);
        self.free_count = capacity;
        for (self.slots, 0..) |*s, i| {
            s.* = .{};
            self.free[capacity - 1 - i] = @intCast(i);
        }
    }

    pub fn deinit(self: *ScramExchangePool, allocator: std.mem.Allocator) void {
        if (self.slots.len > 0) allocator.free(self.slots);
        if (self.free.len > 0) allocator.free(self.free);
        self.* = .{};
    }

    /// Lease a slot; null when the pool is exhausted or absent.
    pub fn acquire(self: *ScramExchangePool) ?u32 {
        if (self.free_count == 0) return null;
        self.free_count -= 1;
        const idx = self.free[self.free_count];
        const s = &self.slots[idx];
        s.reset();
        return (@as(u32, s.gen) << 16) | idx;
    }

    /// Resolve a token to its slot; null for a stale generation, a free
    /// slot or an out-of-range index.
    pub fn get(self: *ScramExchangePool, token: u32) ?*ScramExchange {
        if (token == TOKEN_NONE) return null;
        const idx: usize = @intCast(token & 0xFFFF);
        if (idx >= self.slots.len) return null;
        const s = &self.slots[idx];
        if (!s.in_use or s.gen != @as(u16, @truncate(token >> 16))) return null;
        return s;
    }

    /// Return the slot named by a token to the freelist. A stale or
    /// out-of-range token is a caller bug; the assert keeps it loud in
    /// checked builds while the release itself stays idempotent.
    pub fn release(self: *ScramExchangePool, token: u32) void {
        const s = self.get(token) orelse {
            std.debug.assert(token == TOKEN_NONE);
            return;
        };
        s.in_use = false;
        s.gen +%= 1;
        self.free[self.free_count] = @intCast(token & 0xFFFF);
        self.free_count += 1;
    }
};

test "pool: acquire, generation-checked get, release and reuse" {
    const allocator = std.testing.allocator;
    var pool: ScramExchangePool = .{};
    try pool.init(allocator, 2);
    defer pool.deinit(allocator);

    const t0 = pool.acquire().?;
    const t1 = pool.acquire().?;
    try std.testing.expect(pool.acquire() == null);

    const e0 = pool.get(t0).?;
    e0.user_len = 4;
    try std.testing.expect(pool.get(t1) != null);

    pool.release(t0);
    // The released token no longer resolves; a double release asserts.
    try std.testing.expect(pool.get(t0) == null);

    const t2 = pool.acquire().?;
    try std.testing.expectEqual(t0 & 0xFFFF, t2 & 0xFFFF);
    try std.testing.expect(t2 != t0);
    const e2 = pool.get(t2).?;
    // Reused slot is rewound: no state from the previous exchange leaks.
    try std.testing.expectEqual(@as(usize, 0), e2.user_len);

    pool.release(t1);
    pool.release(t2);
    try std.testing.expectEqual(@as(usize, 2), pool.free_count);
}
