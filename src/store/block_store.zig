//! # BlockStore — per-user block list storage (XEP-0191)
//!
//! Stores per-user block lists in a StorageBackend. Blocked JIDs receive
//! no presence and their stanzas are silently dropped.
//!
//! ## Key format
//!
//! Namespace `blocklist`: key = `user\x00blocked_jid` (bare JIDs)
//!
//! ## Value format
//!
//! Empty (presence of key = blocked). A single zero byte is stored as
//! the value since some backends require non-empty values.

const std = @import("std");
const backend_mod = @import("backend");

const log = std.log.scoped(.block_store);

const NAMESPACE = "blocklist";

pub fn BlockStore(comptime Backend: type) type {
    comptime backend_mod.assertBackend(Backend);

    return struct {
        backend: *Backend,

        const Self = @This();

        pub fn init(b: *Backend) Self {
            return .{ .backend = b };
        }

        /// Check if `blocked_jid` is on `user`'s block list.
        pub fn isBlocked(self: *Self, allocator: std.mem.Allocator, user: []const u8, blocked_jid: []const u8) !bool {
            var key_buf: [512]u8 = undefined;
            const key = compositeKey(&key_buf, user, blocked_jid);
            const raw = try self.backend.get(allocator, NAMESPACE, key);
            if (raw) |v| {
                allocator.free(v);
                return true;
            }
            return false;
        }

        /// Add `blocked_jid` to `user`'s block list.
        pub fn block(self: *Self, user: []const u8, blocked_jid: []const u8) !void {
            var key_buf: [512]u8 = undefined;
            const key = compositeKey(&key_buf, user, blocked_jid);
            try self.backend.put(NAMESPACE, key, &[_]u8{0});
        }

        /// Remove `blocked_jid` from `user`'s block list.
        pub fn unblock(self: *Self, user: []const u8, blocked_jid: []const u8) !void {
            var key_buf: [512]u8 = undefined;
            const key = compositeKey(&key_buf, user, blocked_jid);
            try self.backend.delete(NAMESPACE, key);
        }

        /// Get all blocked JIDs for a user.
        /// Caller owns the returned slice and each element; free with freeBlockList.
        pub fn getBlockList(self: *Self, allocator: std.mem.Allocator, user: []const u8) ![][]const u8 {
            var prefix_buf: [256]u8 = undefined;
            const prefix = userPrefix(&prefix_buf, user);

            var iter = try self.backend.iterator(NAMESPACE, prefix);
            defer iter.deinit();

            var list: std.ArrayListUnmanaged([]const u8) = .{};
            errdefer {
                for (list.items) |item| allocator.free(item);
                list.deinit(allocator);
            }

            while (iter.next()) |kv| {
                // Extract blocked JID from composite key (after user\x00)
                const blocked = kv.key[user.len + 1 ..];
                try list.append(allocator, try allocator.dupe(u8, blocked));
            }

            return list.toOwnedSlice(allocator);
        }

        /// Free a block list returned by getBlockList.
        pub fn freeBlockList(allocator: std.mem.Allocator, items: []const []const u8) void {
            for (items) |item| allocator.free(item);
            allocator.free(items);
        }

        /// Remove all block list entries for a user (used during account deletion cascade).
        pub fn removeAll(self: *Self, allocator: std.mem.Allocator, user: []const u8) !void {
            const items = try self.getBlockList(allocator, user);
            defer freeBlockList(allocator, items);

            for (items) |blocked_jid| {
                self.unblock(user, blocked_jid) catch {};
            }
        }
    };
}

fn compositeKey(buf: []u8, user: []const u8, blocked_jid: []const u8) []const u8 {
    const len = user.len + 1 + blocked_jid.len;
    @memcpy(buf[0..user.len], user);
    buf[user.len] = 0;
    @memcpy(buf[user.len + 1 .. len], blocked_jid);
    return buf[0..len];
}

fn userPrefix(buf: []u8, user: []const u8) []const u8 {
    @memcpy(buf[0..user.len], user);
    buf[user.len] = 0;
    return buf[0 .. user.len + 1];
}

// ============================================================================
// Tests
// ============================================================================

const MemoryBackend = backend_mod.MemoryBackend;
const TestStore = BlockStore(MemoryBackend);

test "BlockStore: block and isBlocked" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    // Not blocked initially
    try std.testing.expect(!try store.isBlocked(allocator, "alice@localhost", "bob@localhost"));

    // Block
    try store.block("alice@localhost", "bob@localhost");

    // Now blocked
    try std.testing.expect(try store.isBlocked(allocator, "alice@localhost", "bob@localhost"));
}

test "BlockStore: unblock" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.block("alice@localhost", "bob@localhost");
    try store.unblock("alice@localhost", "bob@localhost");

    try std.testing.expect(!try store.isBlocked(allocator, "alice@localhost", "bob@localhost"));
}

test "BlockStore: getBlockList" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.block("alice@localhost", "bob@localhost");
    try store.block("alice@localhost", "carol@localhost");
    // Different user — should not appear in alice's list
    try store.block("bob@localhost", "alice@localhost");

    const list = try store.getBlockList(allocator, "alice@localhost");
    defer TestStore.freeBlockList(allocator, list);

    try std.testing.expectEqual(@as(usize, 2), list.len);
}

test "BlockStore: getBlockList empty" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    const list = try store.getBlockList(allocator, "alice@localhost");
    defer TestStore.freeBlockList(allocator, list);

    try std.testing.expectEqual(@as(usize, 0), list.len);
}

test "BlockStore: multiple users independent" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.block("alice@localhost", "bob@localhost");

    try std.testing.expect(try store.isBlocked(allocator, "alice@localhost", "bob@localhost"));
    try std.testing.expect(!try store.isBlocked(allocator, "bob@localhost", "alice@localhost"));
}

test "BlockStore: removeAll" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.block("alice@localhost", "bob@localhost");
    try store.block("alice@localhost", "carol@localhost");

    try store.removeAll(allocator, "alice@localhost");

    try std.testing.expect(!try store.isBlocked(allocator, "alice@localhost", "bob@localhost"));
    try std.testing.expect(!try store.isBlocked(allocator, "alice@localhost", "carol@localhost"));
}

test "BlockStore: block is idempotent" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.block("alice@localhost", "bob@localhost");
    try store.block("alice@localhost", "bob@localhost"); // second call should not error

    try std.testing.expect(try store.isBlocked(allocator, "alice@localhost", "bob@localhost"));

    const list = try store.getBlockList(allocator, "alice@localhost");
    defer TestStore.freeBlockList(allocator, list);
    // Should still have exactly 1 entry (not duplicated)
    try std.testing.expectEqual(@as(usize, 1), list.len);
}
