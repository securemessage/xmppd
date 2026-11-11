//! SlotMap(T): fixed-capacity table addressed by generational Tokens (ADR-4).
//!
//! One SlotMap per owning thread. Slots start at generation 1; `remove` bumps
//! the generation, so a token minted before a free can never resolve to the
//! value later stored in the same slot. A slot whose generation would wrap
//! past maxInt(u24) is retired instead of reused, which removes the last ABA
//! window. Freed slots join a FIFO ring so indices are reused as late as
//! possible.
//!
//! Capacity is fixed at init; insert beyond it fails with error.Full and
//! callers must handle that (admission control), never grow silently.

const std = @import("std");
const Token = @import("token.zig").Token;

pub fn SlotMap(comptime T: type) type {
    return struct {
        const Self = @This();

        pub const Error = error{Full};

        /// Generation when a slot is retired. A token with this generation
        /// never matches a live value again.
        pub const gen_max = std.math.maxInt(u24);

        values: []T,
        gens: []u24,
        free: []u32, // FIFO ring of freed indices
        free_head: u32,
        free_tail: u32,
        free_count: u32,
        pool: u32, // next never-issued index
        live_count: u32,
        kind: u8,

        /// Owns `values`, `gens` and `free` (all `slot_count_max` long); deinit frees them.
        pub fn init(
            self: *Self,
            gpa: std.mem.Allocator,
            slot_count_max: u32,
            kind: u8,
        ) std.mem.Allocator.Error!void {
            std.debug.assert(slot_count_max >= 1 and slot_count_max <= std.math.maxInt(u32) - 1);
            const values = try gpa.alloc(T, slot_count_max);
            errdefer gpa.free(values);
            const gens = try gpa.alloc(u24, slot_count_max);
            errdefer gpa.free(gens);
            const free = try gpa.alloc(u32, slot_count_max);
            @memset(gens, 1);
            self.* = .{
                .values = values,
                .gens = gens,
                .free = free,
                .free_head = 0,
                .free_tail = 0,
                .free_count = 0,
                .pool = 0,
                .live_count = 0,
                .kind = kind,
            };
        }

        pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
            gpa.free(self.values);
            gpa.free(self.gens);
            gpa.free(self.free);
            self.* = undefined;
        }

        /// Store `value` in a free or never-issued slot. Returns its token.
        pub fn insert(self: *Self, value: T) Error!Token {
            var index: u32 = undefined;
            if (self.pool < self.values.len) {
                index = self.pool;
                self.pool += 1;
            } else if (self.free_count > 0) {
                index = self.free[self.free_head];
                self.free_head = @intCast((self.free_head + 1) % self.free.len);
                self.free_count -= 1;
            } else {
                return error.Full;
            }
            self.values[index] = value;
            self.live_count += 1;
            std.debug.assert(self.gens[index] > 0 and self.gens[index] < gen_max);
            return .{ .index = index, .gen = self.gens[index], .kind = self.kind };
        }

        /// Borrow the live value for `token`; null when the token is stale,
        /// from another kind or out of range.
        pub fn get(self: *Self, token: Token) ?*T {
            if (!self.matches(token)) return null;
            return &self.values[token.index];
        }

        pub fn getConst(self: *const Self, token: Token) ?*const T {
            if (!self.matches(token)) return null;
            return &self.values[token.index];
        }

        /// Remove and return the live value; null when stale. Bumps the slot's
        /// generation; the slot returns to the free ring unless the generation
        /// would reach gen_max, in which case it is retired.
        pub fn remove(self: *Self, token: Token) ?T {
            if (!self.matches(token)) return null;
            const index = token.index;
            const old = self.values[index];
            self.live_count -= 1;
            if (self.gens[index] + 1 < gen_max) {
                self.gens[index] += 1;
                self.free[self.free_tail] = index;
                self.free_tail = @intCast((self.free_tail + 1) % self.free.len);
                self.free_count += 1;
            } else {
                self.gens[index] = gen_max;
            }
            return old;
        }

        /// Whether the slot for `token` currently holds a value (index, gen
        /// and kind all match). Slots at or beyond `pool` were never issued,
        /// and a `gen_max` token can only be forged: a live slot's generation
        /// is always below it and retired slots are never re-issued.
        fn matches(self: *const Self, token: Token) bool {
            if (token.kind != self.kind) return false;
            if (token.index >= self.pool) return false;
            if (token.gen == gen_max) return false;
            return self.gens[token.index] == token.gen;
        }

        pub fn count(self: *const Self) u32 {
            return self.live_count;
        }

        /// Usable capacity: total slots minus those retired by generation
        /// exhaustion.
        pub fn capacity(self: *const Self) u32 {
            const used: u32 = self.live_count + self.free_count;
            var retired: u32 = 0;
            for (self.gens[0..self.pool]) |gen| {
                if (gen == gen_max) retired += 1;
            }
            std.debug.assert(used + retired <= self.values.len);
            return @intCast(self.values.len - retired);
        }
    };
}

test "SlotMap: insert, get, remove" {
    // Small map round trip: value in, pointer out, value back on remove.
    var map: SlotMap(u32) = undefined;
    try map.init(std.testing.allocator, 4, 1);
    defer map.deinit(std.testing.allocator);

    const t = try map.insert(42);
    try std.testing.expectEqual(@as(u32, 1), map.count());
    try std.testing.expectEqual(@as(u32, 42), map.get(t).?.*);
    try std.testing.expectEqual(@as(u32, 42), map.remove(t).?);
    try std.testing.expectEqual(@as(u32, 0), map.count());
}

test "SlotMap: stale token never resolves to a reused slot" {
    // Free slot 0, reissue the same index, then prove the old token is dead.
    var map: SlotMap(u32) = undefined;
    try map.init(std.testing.allocator, 2, 1);
    defer map.deinit(std.testing.allocator);

    const first = try map.insert(1);
    _ = try map.insert(2);
    _ = map.remove(first);
    const second = try map.insert(3);
    try std.testing.expectEqual(first.index, second.index);
    try std.testing.expect(second.gen > first.gen);
    try std.testing.expect(map.get(first) == null);
    try std.testing.expect(map.remove(first) == null);
    try std.testing.expectEqual(@as(u32, 3), map.get(second).?.*);
}

test "SlotMap: wrong kind and out-of-range index never resolve" {
    var map: SlotMap(u32) = undefined;
    try map.init(std.testing.allocator, 2, 1);
    defer map.deinit(std.testing.allocator);

    const t = try map.insert(7);
    try std.testing.expect(map.get(.{ .index = t.index, .gen = t.gen, .kind = 2 }) == null);
    try std.testing.expect(map.get(.{ .index = 99, .gen = t.gen, .kind = 1 }) == null);
    try std.testing.expect(map.get(.none) == null);
}

test "SlotMap: forged tokens for never-issued and retired slots never resolve" {
    // Indices at or beyond pool hold only the initial generation, so a
    // forged token could pass the generation check without the pool bound.
    var map: SlotMap(u32) = undefined;
    try map.init(std.testing.allocator, 4, 1);
    defer map.deinit(std.testing.allocator);

    const live = try map.insert(7);
    const forged: Token = .{ .index = 3, .gen = 1, .kind = 1 };
    try std.testing.expect(map.get(forged) == null);
    try std.testing.expect(map.remove(forged) == null);
    try std.testing.expectEqual(@as(u32, 1), map.count());

    // A forged gen_max token names a retired generation; it must not match
    // even where a slot was really retired.
    const forged_max: Token = .{ .index = live.index, .gen = SlotMap(u32).gen_max, .kind = 1 };
    try std.testing.expect(map.get(forged_max) == null);
    map.gens[live.index] = SlotMap(u32).gen_max - 1;
    _ = map.remove(.{ .index = live.index, .gen = map.gens[live.index], .kind = 1 });
    try std.testing.expectEqual(SlotMap(u32).gen_max, map.gens[live.index]);
    try std.testing.expect(map.get(forged_max) == null);
    const next = try map.insert(9); // pool advances past the retired slot
    try std.testing.expectEqual(@as(u32, 1), next.index);
}

test "SlotMap: Full at capacity, freed slots refill" {
    var map: SlotMap(u32) = undefined;
    try map.init(std.testing.allocator, 2, 1);
    defer map.deinit(std.testing.allocator);

    const a = try map.insert(1);
    _ = try map.insert(2);
    try std.testing.expectError(error.Full, map.insert(3));
    _ = map.remove(a);
    _ = try map.insert(3);
    try std.testing.expectEqual(@as(u32, 2), map.count());
}

test "SlotMap: generation exhaustion retires the slot" {
    // Force the generation to the brink; the next remove must retire the
    // slot instead of wrapping to a generation a stale token could match.
    var map: SlotMap(u32) = undefined;
    try map.init(std.testing.allocator, 1, 1);
    defer map.deinit(std.testing.allocator);

    const t = try map.insert(1);
    map.gens[t.index] = SlotMap(u32).gen_max - 1;
    const stale: Token = .{ .index = t.index, .gen = map.gens[t.index], .kind = t.kind };
    _ = map.remove(stale);
    try std.testing.expectEqual(SlotMap(u32).gen_max, map.gens[t.index]);
    try std.testing.expectError(error.Full, map.insert(2));
    try std.testing.expect(map.get(stale) == null);
}

test "SlotMap: free ring is FIFO" {
    // Two freed slots come back in free order, not stack order.
    var map: SlotMap(u32) = undefined;
    try map.init(std.testing.allocator, 3, 1);
    defer map.deinit(std.testing.allocator);

    const a = try map.insert(1);
    const b = try map.insert(2);
    const c = try map.insert(3);
    _ = map.remove(b);
    _ = map.remove(a);
    _ = map.remove(c);
    const r1 = try map.insert(10);
    const r2 = try map.insert(20);
    const r3 = try map.insert(30);
    try std.testing.expectEqual(b.index, r1.index);
    try std.testing.expectEqual(a.index, r2.index);
    try std.testing.expectEqual(c.index, r3.index);
}
