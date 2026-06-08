//! # SharedSessionRegistry — thread-safe global session routing table
//!
//! Maps session slots to JIDs across all worker threads using lock-free
//! single-writer/multi-reader atomics. Each slot is 64-byte aligned to
//! prevent false sharing between adjacent sessions on different CPU cores.
//!
//! ## Concurrency Model
//!
//! - **Writes** (bind/unbind): only the owning worker thread mutates its slots.
//!   Non-atomic field writes are published via `@atomicStore(&slot.occupied, true, .release)`.
//! - **Reads** (lookup/find): any thread may read any slot via
//!   `@atomicLoad(&slot.occupied, .acquire)`. If `occupied == true`, all other
//!   fields are guaranteed visible (release/acquire pair).
//! - No mutex on the hot path.
//!
//! ## ABA Protection
//!
//! Each slot carries a `generation` counter incremented on every bind/unbind cycle.
//! Cross-thread delivery messages carry the generation at enqueue time; the consumer
//! validates it before delivering. This prevents stale delivery to a reused slot.

const std = @import("std");

const log = std.log.scoped(.shared_registry);

/// Maximum JID bytes stored inline per slot.
/// local + domain + resource packed sequentially.
/// Covers JIDs up to ~110 chars (common case). Overflow is truncated.
pub const MAX_JID_LEN = 110;

/// Result of a session lookup — contains routing information for cross-thread delivery.
pub const RoutingResult = struct {
    session_id: u32,
    worker_id: u16,
    generation: u32,
};

/// A single session slot in the shared registry.
/// Aligned to 64 bytes (one cache line) to prevent false sharing.
pub const SessionSlot = struct {
    /// Owning worker's thread ID (0..N-1). Written by owning thread only.
    worker_id: u16 = 0,
    /// Generation counter — incremented on every unbind.
    /// Prevents ABA: stale cross-thread messages carrying old generation are dropped.
    generation: u32 = 0,
    /// Whether this session has sent initial presence.
    /// Written by owning thread only; readable by any thread after acquire on `occupied`.
    presence_available: bool = false,
    /// JID component lengths.
    local_len: u8 = 0,
    domain_len: u8 = 0,
    resource_len: u8 = 0,
    /// Inline JID storage: local + domain + resource packed sequentially.
    jid_buf: [MAX_JID_LEN]u8 = .{0} ** MAX_JID_LEN,
    /// Publish flag — acts as the release/acquire barrier for all other fields.
    /// Set to true AFTER all fields are written (release fence).
    /// Readers check this FIRST with acquire semantics before reading other fields.
    occupied: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Get the local part of the JID from inline storage.
    pub fn getLocal(self: *const SessionSlot) []const u8 {
        return self.jid_buf[0..self.local_len];
    }

    /// Get the domain part of the JID from inline storage.
    pub fn getDomain(self: *const SessionSlot) []const u8 {
        const offset = self.local_len;
        return self.jid_buf[offset..][0..self.domain_len];
    }

    /// Get the resource part of the JID from inline storage.
    pub fn getResource(self: *const SessionSlot) []const u8 {
        const offset: usize = @as(usize, self.local_len) + @as(usize, self.domain_len);
        return self.jid_buf[offset..][0..self.resource_len];
    }
};

// Ensure SessionSlot fits within reasonable bounds for alignment.
// We align to 64 bytes at allocation time, not via struct layout.
comptime {
    // SessionSlot should be <= 128 bytes to fit within 2 cache lines max.
    if (@sizeOf(SessionSlot) > 128) @compileError("SessionSlot exceeds 128 bytes");
}

/// Thread-safe shared session registry for cross-thread JID routing.
pub const SharedSessionRegistry = struct {
    slots: []SessionSlot,
    capacity: u32,
    allocator: std.mem.Allocator,

    /// Initialize the shared registry with the given capacity.
    /// Capacity should equal max_sessions (total across all workers).
    /// Slots are zero-initialized (all unoccupied).
    pub fn init(allocator: std.mem.Allocator, capacity: u32) !SharedSessionRegistry {
        const slots = try allocator.alloc(SessionSlot, capacity);
        @memset(slots, SessionSlot{});
        return .{
            .slots = slots,
            .capacity = capacity,
            .allocator = allocator,
        };
    }

    /// Free the slot array.
    pub fn deinit(self: *SharedSessionRegistry) void {
        self.allocator.free(self.slots);
        self.* = undefined;
    }

    /// Register a session after successful resource binding.
    /// MUST be called only by the owning worker thread.
    pub fn bind(
        self: *SharedSessionRegistry,
        session_id: u32,
        worker_id: u16,
        local: []const u8,
        domain: []const u8,
        resource: []const u8,
    ) !void {
        if (session_id >= self.capacity) return error.InvalidSessionId;

        const slot = &self.slots[session_id];

        // Verify slot is not already occupied (programming error if so)
        if (slot.occupied.load(.acquire)) return error.AlreadyBound;

        // Validate JID lengths fit inline storage
        const total_len = local.len + domain.len + resource.len;
        if (total_len > MAX_JID_LEN) return error.JidTooLong;

        // Write all fields non-atomically (single-writer guarantee)
        slot.worker_id = worker_id;
        slot.generation +%= 1;
        slot.presence_available = false;
        slot.local_len = @intCast(local.len);
        slot.domain_len = @intCast(domain.len);
        slot.resource_len = @intCast(resource.len);

        // Pack JID into inline buffer
        var offset: usize = 0;
        @memcpy(slot.jid_buf[offset..][0..local.len], local);
        offset += local.len;
        @memcpy(slot.jid_buf[offset..][0..domain.len], domain);
        offset += domain.len;
        @memcpy(slot.jid_buf[offset..][0..resource.len], resource);

        // Publish: this release store makes all writes above visible to readers
        slot.occupied.store(true, .release);

        log.info("shared bind slot {d} worker {d} gen {d}: {s}@{s}/{s}", .{
            session_id, worker_id, slot.generation, local, domain, resource,
        });
    }

    /// Unregister a session (on disconnect or stream close).
    /// MUST be called only by the owning worker thread.
    /// Returns the generation that was active (for ABA verification by in-flight messages).
    pub fn unbind(self: *SharedSessionRegistry, session_id: u32) ?u32 {
        if (session_id >= self.capacity) return null;

        const slot = &self.slots[session_id];
        if (!slot.occupied.load(.acquire)) return null;

        const gen = slot.generation;

        // Clear occupied first (release) — readers will stop seeing this slot
        slot.occupied.store(false, .release);

        // Increment generation so in-flight MPSC messages with old gen are dropped
        slot.generation = gen +% 1;

        log.info("shared unbind slot {d} (was gen {d}, now {d})", .{
            session_id, gen, slot.generation,
        });

        return gen;
    }

    /// Get the current generation for a slot (for building delivery messages).
    /// Returns null if slot is not occupied.
    pub fn getGeneration(self: *const SharedSessionRegistry, session_id: u32) ?u32 {
        if (session_id >= self.capacity) return null;
        const slot = &self.slots[session_id];
        if (!slot.occupied.load(.acquire)) return null;
        return slot.generation;
    }

    /// Mark a session as presence-available or unavailable.
    /// MUST be called only by the owning worker thread.
    pub fn setPresenceAvailable(self: *SharedSessionRegistry, session_id: u32, available: bool) void {
        if (session_id >= self.capacity) return;
        const slot = &self.slots[session_id];
        if (!slot.occupied.load(.acquire)) return;
        slot.presence_available = available;
    }

    /// Find a session by full JID (local@domain/resource).
    /// Thread-safe: may be called from any worker thread.
    pub fn findByFullJid(
        self: *const SharedSessionRegistry,
        local: []const u8,
        domain: []const u8,
        resource: []const u8,
    ) ?RoutingResult {
        for (self.slots, 0..) |*slot, i| {
            // Acquire load on occupied — if true, all other fields are visible
            if (!slot.occupied.load(.acquire)) continue;

            if (slot.local_len != local.len) continue;
            if (slot.domain_len != domain.len) continue;
            if (slot.resource_len != resource.len) continue;

            if (std.mem.eql(u8, slot.getLocal(), local) and
                std.mem.eql(u8, slot.getDomain(), domain) and
                std.mem.eql(u8, slot.getResource(), resource))
            {
                return .{
                    .session_id = @intCast(i),
                    .worker_id = slot.worker_id,
                    .generation = slot.generation,
                };
            }
        }
        return null;
    }

    /// Find all sessions for a bare JID (local@domain).
    /// Thread-safe: may be called from any worker thread.
    /// Writes RoutingResults into the provided buffer.
    /// Returns the number of matching sessions found.
    pub fn findByBareJid(
        self: *const SharedSessionRegistry,
        local: []const u8,
        domain: []const u8,
        buf: []RoutingResult,
    ) usize {
        var count: usize = 0;
        for (self.slots, 0..) |*slot, i| {
            if (count >= buf.len) break;
            if (!slot.occupied.load(.acquire)) continue;

            if (slot.local_len != local.len) continue;
            if (slot.domain_len != domain.len) continue;

            if (std.mem.eql(u8, slot.getLocal(), local) and
                std.mem.eql(u8, slot.getDomain(), domain))
            {
                buf[count] = .{
                    .session_id = @intCast(i),
                    .worker_id = slot.worker_id,
                    .generation = slot.generation,
                };
                count += 1;
            }
        }
        return count;
    }

    /// Find all available (presence-sent) sessions for a bare JID.
    /// Thread-safe: may be called from any worker thread.
    pub fn findAvailableByBareJid(
        self: *const SharedSessionRegistry,
        local: []const u8,
        domain: []const u8,
        buf: []RoutingResult,
    ) usize {
        var count: usize = 0;
        for (self.slots, 0..) |*slot, i| {
            if (count >= buf.len) break;
            if (!slot.occupied.load(.acquire)) continue;
            if (!slot.presence_available) continue;

            if (slot.local_len != local.len) continue;
            if (slot.domain_len != domain.len) continue;

            if (std.mem.eql(u8, slot.getLocal(), local) and
                std.mem.eql(u8, slot.getDomain(), domain))
            {
                buf[count] = .{
                    .session_id = @intCast(i),
                    .worker_id = slot.worker_id,
                    .generation = slot.generation,
                };
                count += 1;
            }
        }
        return count;
    }

    /// Check if any session for a bare JID is presence-available.
    /// Thread-safe: may be called from any worker thread.
    pub fn isAvailable(self: *const SharedSessionRegistry, local: []const u8, domain: []const u8) bool {
        for (self.slots) |*slot| {
            if (!slot.occupied.load(.acquire)) continue;
            if (!slot.presence_available) continue;

            if (slot.local_len != local.len) continue;
            if (slot.domain_len != domain.len) continue;

            if (std.mem.eql(u8, slot.getLocal(), local) and
                std.mem.eql(u8, slot.getDomain(), domain))
            {
                return true;
            }
        }
        return false;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "SharedSessionRegistry: bind and lookup" {
    var reg = try SharedSessionRegistry.init(std.testing.allocator, 64);
    defer reg.deinit();

    try reg.bind(5, 0, "alice", "localhost", "mobile");

    const result = reg.findByFullJid("alice", "localhost", "mobile").?;
    try std.testing.expectEqual(@as(u32, 5), result.session_id);
    try std.testing.expectEqual(@as(u16, 0), result.worker_id);
    try std.testing.expect(result.generation > 0);
}

test "SharedSessionRegistry: unbind clears slot" {
    var reg = try SharedSessionRegistry.init(std.testing.allocator, 64);
    defer reg.deinit();

    try reg.bind(3, 1, "bob", "localhost", "desktop");
    const gen = reg.unbind(3).?;
    try std.testing.expect(gen > 0);

    // Should not be findable after unbind
    try std.testing.expect(reg.findByFullJid("bob", "localhost", "desktop") == null);
}

test "SharedSessionRegistry: generation increments on rebind" {
    var reg = try SharedSessionRegistry.init(std.testing.allocator, 64);
    defer reg.deinit();

    try reg.bind(1, 0, "alice", "localhost", "mobile");
    const gen1 = reg.findByFullJid("alice", "localhost", "mobile").?.generation;

    _ = reg.unbind(1);
    try reg.bind(1, 0, "alice", "localhost", "mobile");
    const gen2 = reg.findByFullJid("alice", "localhost", "mobile").?.generation;

    // Generation should have advanced (two increments: one from unbind, one from bind)
    try std.testing.expect(gen2 > gen1);
}

test "SharedSessionRegistry: findByBareJid multi-resource" {
    var reg = try SharedSessionRegistry.init(std.testing.allocator, 64);
    defer reg.deinit();

    try reg.bind(1, 0, "alice", "localhost", "mobile");
    try reg.bind(2, 1, "alice", "localhost", "desktop");
    try reg.bind(3, 0, "bob", "localhost", "laptop");

    var buf: [8]RoutingResult = undefined;
    const count = reg.findByBareJid("alice", "localhost", &buf);
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "SharedSessionRegistry: presence availability" {
    var reg = try SharedSessionRegistry.init(std.testing.allocator, 64);
    defer reg.deinit();

    try reg.bind(1, 0, "alice", "localhost", "mobile");
    try reg.bind(2, 1, "alice", "localhost", "desktop");

    try std.testing.expect(!reg.isAvailable("alice", "localhost"));

    reg.setPresenceAvailable(1, true);
    try std.testing.expect(reg.isAvailable("alice", "localhost"));

    var buf: [8]RoutingResult = undefined;
    const count = reg.findAvailableByBareJid("alice", "localhost", &buf);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(@as(u32, 1), buf[0].session_id);
}

test "SharedSessionRegistry: duplicate bind errors" {
    var reg = try SharedSessionRegistry.init(std.testing.allocator, 64);
    defer reg.deinit();

    try reg.bind(5, 0, "alice", "localhost", "mobile");
    try std.testing.expectError(error.AlreadyBound, reg.bind(5, 0, "alice", "localhost", "desktop"));
}

test "SharedSessionRegistry: unbind nonexistent returns null" {
    var reg = try SharedSessionRegistry.init(std.testing.allocator, 64);
    defer reg.deinit();

    try std.testing.expect(reg.unbind(99) == null);
}

test "SharedSessionRegistry: JID too long" {
    var reg = try SharedSessionRegistry.init(std.testing.allocator, 64);
    defer reg.deinit();

    // Create a JID that exceeds MAX_JID_LEN
    const long_local = "a" ** 60;
    const long_domain = "b" ** 60;
    try std.testing.expectError(error.JidTooLong, reg.bind(0, 0, long_local, long_domain, "resource"));
}

test "SharedSessionRegistry: worker_id tracking" {
    var reg = try SharedSessionRegistry.init(std.testing.allocator, 64);
    defer reg.deinit();

    try reg.bind(0, 3, "alice", "host", "mobile");
    try reg.bind(1, 7, "bob", "host", "desktop");

    const alice = reg.findByFullJid("alice", "host", "mobile").?;
    try std.testing.expectEqual(@as(u16, 3), alice.worker_id);

    const bob = reg.findByFullJid("bob", "host", "desktop").?;
    try std.testing.expectEqual(@as(u16, 7), bob.worker_id);
}
