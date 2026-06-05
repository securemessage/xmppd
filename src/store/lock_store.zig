//! # LockStore — Permanent account lock storage
//!
//! Stores permanent account locks in a StorageBackend. Locks persist across
//! daemon restarts and work for both local and future external auth users.
//!
//! ## Binary format (5 bytes)
//!
//! ```
//! | lock_type (1) | locked_epoch (4 BE) |
//! ```
//!
//! Namespace: `locks`, Key: `username`
//!
//! ## Lock types
//!
//! - 0x01: permanent (via xmppctl lock)
//! - 0x02: reserved for future use

const std = @import("std");
const backend_mod = @import("backend");

const log = std.log.scoped(.lock_store);

const NAMESPACE = "locks";
const LOCK_VALUE_SIZE = 5; // lock_type(1) + epoch(4)

/// Lock type identifiers.
pub const LockType = enum(u8) {
    permanent = 0x01,
    reserved = 0x02,
};

/// A lock record.
pub const LockRecord = struct {
    lock_type: LockType,
    locked_epoch: u32,
};

pub fn LockStore(comptime Backend: type) type {
    comptime backend_mod.assertBackend(Backend);

    return struct {
        backend: *Backend,

        const Self = @This();

        pub fn init(b: *Backend) Self {
            return .{ .backend = b };
        }

        /// Check if a username is locked. Returns the lock record if locked, null otherwise.
        pub fn isLocked(self: *Self, allocator: std.mem.Allocator, username: []const u8) !?LockRecord {
            const raw = self.backend.get(allocator, NAMESPACE, username) catch |err| {
                log.err("lock_store lookup failed for '{s}': {}", .{ username, err });
                return err;
            };
            const data = raw orelse return null;
            defer allocator.free(data);

            if (data.len < LOCK_VALUE_SIZE) return null; // Corrupt entry
            return deserialize(data[0..LOCK_VALUE_SIZE]);
        }

        /// Lock an account. Overwrites any existing lock.
        pub fn lock(self: *Self, username: []const u8, lock_type: LockType) !void {
            const now = currentEpoch();
            const value = serialize(lock_type, now);
            try self.backend.put(NAMESPACE, username, &value);
            log.info("locked account: {s} (type={d})", .{ username, @intFromEnum(lock_type) });
        }

        /// Unlock an account. No-op if not locked.
        pub fn unlock(self: *Self, allocator: std.mem.Allocator, username: []const u8) !void {
            const existing = try self.backend.get(allocator, NAMESPACE, username);
            if (existing) |v| {
                allocator.free(v);
                try self.backend.delete(NAMESPACE, username);
                log.info("unlocked account: {s}", .{username});
            }
        }

        /// Remove lock entry (used during account deletion cascade).
        pub fn remove(self: *Self, allocator: std.mem.Allocator, username: []const u8) !void {
            return self.unlock(allocator, username);
        }
    };
}

fn serialize(lock_type: LockType, epoch: u32) [LOCK_VALUE_SIZE]u8 {
    var buf: [LOCK_VALUE_SIZE]u8 = undefined;
    buf[0] = @intFromEnum(lock_type);
    std.mem.writeInt(u32, buf[1..5], epoch, .big);
    return buf;
}

fn deserialize(data: *const [LOCK_VALUE_SIZE]u8) LockRecord {
    return .{
        .lock_type = std.meta.intToEnum(LockType, data[0]) catch .permanent,
        .locked_epoch = std.mem.readInt(u32, data[1..5], .big),
    };
}

fn currentEpoch() u32 {
    const ts = std.time.timestamp();
    return @intCast(@as(u64, @bitCast(ts)) & 0xFFFFFFFF);
}

// ============================================================================
// Tests
// ============================================================================

test "LockStore: lock and check" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = LockStore(MemoryBackend).init(&db);

    // Not locked initially
    const result1 = try store.isLocked(allocator, "alice");
    try std.testing.expect(result1 == null);

    // Lock
    try store.lock("alice", .permanent);

    // Now locked
    const result2 = try store.isLocked(allocator, "alice");
    try std.testing.expect(result2 != null);
    try std.testing.expectEqual(LockType.permanent, result2.?.lock_type);
    try std.testing.expect(result2.?.locked_epoch > 0);
}

test "LockStore: unlock" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = LockStore(MemoryBackend).init(&db);

    try store.lock("bob", .permanent);
    try store.unlock(allocator, "bob");

    const result = try store.isLocked(allocator, "bob");
    try std.testing.expect(result == null);
}

test "LockStore: unlock non-existent is no-op" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = LockStore(MemoryBackend).init(&db);

    // Should not error
    try store.unlock(allocator, "ghost");
}

test "LockStore: multiple users independent" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = LockStore(MemoryBackend).init(&db);

    try store.lock("alice", .permanent);

    // alice is locked, bob is not
    try std.testing.expect((try store.isLocked(allocator, "alice")) != null);
    try std.testing.expect((try store.isLocked(allocator, "bob")) == null);
}
