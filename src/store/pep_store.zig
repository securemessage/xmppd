//! # PepStore — Personal Eventing Protocol storage (XEP-0163)
//!
//! Stores per-user PEP node items in a StorageBackend. PEP is simplified
//! PubSub scoped to a user's bare JID, used for avatars, OMEMO, bookmarks, etc.
//!
//! ## Key format
//!
//! Namespace `pep`: key = `user_bare_jid\x00node_name\x00item_id`
//!
//! ## Value format
//!
//! Raw XML payload of the published item.
//!
//! ## Design notes
//!
//! PEP nodes are implicit — created on first publish. Each item within a node
//! is identified by an item_id. Most PEP nodes use a single item (max_items=1)
//! which is replaced on each publish. For V1, we don't enforce max_items — the
//! latest publish overwrites the item with the same ID.

const std = @import("std");
const backend_mod = @import("backend");

const log = std.log.scoped(.pep_store);

const NAMESPACE = "pep";

pub fn PepStore(comptime Backend: type) type {
    comptime backend_mod.assertBackend(Backend);

    return struct {
        backend: *Backend,

        const Self = @This();

        pub fn init(b: *Backend) Self {
            return .{ .backend = b };
        }

        /// Publish (create or replace) an item in a PEP node.
        pub fn publish(self: *Self, user: []const u8, node: []const u8, item_id: []const u8, payload: []const u8) !void {
            var key_buf: [1024]u8 = undefined;
            const key = compositeKey(&key_buf, user, node, item_id);
            try self.backend.put(NAMESPACE, key, payload);
        }

        /// Get a single item from a PEP node by item ID.
        /// Caller owns the returned slice.
        pub fn getItem(self: *Self, allocator: std.mem.Allocator, user: []const u8, node: []const u8, item_id: []const u8) !?[]u8 {
            var key_buf: [1024]u8 = undefined;
            const key = compositeKey(&key_buf, user, node, item_id);
            return self.backend.get(allocator, NAMESPACE, key);
        }

        /// Get all items from a PEP node. Returns item IDs and their payloads.
        /// Caller owns the returned slice and must free with freeItems.
        pub fn getItems(self: *Self, allocator: std.mem.Allocator, user: []const u8, node: []const u8) ![]PepItem {
            var prefix_buf: [768]u8 = undefined;
            const prefix = nodePrefix(&prefix_buf, user, node);

            var iter = try self.backend.iterator(NAMESPACE, prefix);
            defer iter.deinit();

            var list: std.ArrayListUnmanaged(PepItem) = .{};
            errdefer {
                for (list.items) |item| {
                    allocator.free(item.id);
                    allocator.free(item.payload);
                }
                list.deinit(allocator);
            }

            while (iter.next()) |kv| {
                // Extract item_id: after user\x00node\x00
                const after_prefix = kv.key[prefix.len..];
                try list.append(allocator, .{
                    .id = try allocator.dupe(u8, after_prefix),
                    .payload = try allocator.dupe(u8, kv.value),
                });
            }

            return list.toOwnedSlice(allocator);
        }

        /// A PEP item with its ID and payload.
        pub const PepItem = struct {
            id: []const u8,
            payload: []const u8,
        };

        /// Free items returned by getItems.
        pub fn freeItems(allocator: std.mem.Allocator, items: []const PepItem) void {
            for (items) |item| {
                allocator.free(item.id);
                allocator.free(item.payload);
            }
            allocator.free(items);
        }

        /// Delete a specific item from a PEP node.
        pub fn deleteItem(self: *Self, user: []const u8, node: []const u8, item_id: []const u8) !void {
            var key_buf: [1024]u8 = undefined;
            const key = compositeKey(&key_buf, user, node, item_id);
            try self.backend.delete(NAMESPACE, key);
        }

        /// Delete all items in a PEP node.
        pub fn deleteNode(self: *Self, allocator: std.mem.Allocator, user: []const u8, node: []const u8) !void {
            const items = try self.getItems(allocator, user, node);
            defer freeItems(allocator, items);

            for (items) |item| {
                var key_buf: [1024]u8 = undefined;
                const key = compositeKey(&key_buf, user, node, item.id);
                self.backend.delete(NAMESPACE, key) catch {};
            }
        }

        /// Remove all PEP data for a user (account deletion cascade).
        pub fn removeAll(self: *Self, allocator: std.mem.Allocator, user: []const u8) !void {
            var prefix_buf: [256]u8 = undefined;
            @memcpy(prefix_buf[0..user.len], user);
            prefix_buf[user.len] = 0;
            const prefix = prefix_buf[0 .. user.len + 1];

            var iter = try self.backend.iterator(NAMESPACE, prefix);
            defer iter.deinit();

            // Collect keys first (can't modify during iteration)
            var keys: std.ArrayListUnmanaged([]const u8) = .{};
            defer {
                for (keys.items) |k| allocator.free(k);
                keys.deinit(allocator);
            }

            while (iter.next()) |kv| {
                try keys.append(allocator, try allocator.dupe(u8, kv.key));
            }

            for (keys.items) |key| {
                self.backend.delete(NAMESPACE, key) catch {};
            }
        }
    };
}

fn compositeKey(buf: []u8, user: []const u8, node: []const u8, item_id: []const u8) []const u8 {
    const len = user.len + 1 + node.len + 1 + item_id.len;
    @memcpy(buf[0..user.len], user);
    buf[user.len] = 0;
    @memcpy(buf[user.len + 1 .. user.len + 1 + node.len], node);
    buf[user.len + 1 + node.len] = 0;
    @memcpy(buf[user.len + 1 + node.len + 1 .. len], item_id);
    return buf[0..len];
}

fn nodePrefix(buf: []u8, user: []const u8, node: []const u8) []const u8 {
    const len = user.len + 1 + node.len + 1;
    @memcpy(buf[0..user.len], user);
    buf[user.len] = 0;
    @memcpy(buf[user.len + 1 .. user.len + 1 + node.len], node);
    buf[user.len + 1 + node.len] = 0;
    return buf[0..len];
}

// ============================================================================
// Tests
// ============================================================================

const MemoryBackend = backend_mod.MemoryBackend;
const TestStore = PepStore(MemoryBackend);

test "PepStore: publish and getItem" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.publish("alice@localhost", "urn:xmpp:avatar:metadata", "current", "<metadata/>");

    const item = try store.getItem(allocator, "alice@localhost", "urn:xmpp:avatar:metadata", "current");
    defer if (item) |v| allocator.free(v);
    try std.testing.expect(item != null);
    try std.testing.expectEqualStrings("<metadata/>", item.?);
}

test "PepStore: getItem missing" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    const item = try store.getItem(allocator, "alice@localhost", "nonexistent", "item1");
    try std.testing.expect(item == null);
}

test "PepStore: publish replaces existing" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.publish("alice@localhost", "urn:xmpp:avatar:data", "current", "<data>old</data>");
    try store.publish("alice@localhost", "urn:xmpp:avatar:data", "current", "<data>new</data>");

    const item = try store.getItem(allocator, "alice@localhost", "urn:xmpp:avatar:data", "current");
    defer if (item) |v| allocator.free(v);
    try std.testing.expectEqualStrings("<data>new</data>", item.?);
}

test "PepStore: getItems" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.publish("alice@localhost", "storage:bookmarks", "bm1", "<conference/>");
    try store.publish("alice@localhost", "storage:bookmarks", "bm2", "<conference2/>");
    // Different node — should not appear
    try store.publish("alice@localhost", "urn:xmpp:avatar:data", "current", "<data/>");

    const items = try store.getItems(allocator, "alice@localhost", "storage:bookmarks");
    defer TestStore.freeItems(allocator, items);

    try std.testing.expectEqual(@as(usize, 2), items.len);
}

test "PepStore: deleteItem" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.publish("alice@localhost", "urn:xmpp:avatar:data", "current", "<data/>");
    try store.deleteItem("alice@localhost", "urn:xmpp:avatar:data", "current");

    const item = try store.getItem(allocator, "alice@localhost", "urn:xmpp:avatar:data", "current");
    try std.testing.expect(item == null);
}

test "PepStore: deleteNode" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.publish("alice@localhost", "storage:bookmarks", "bm1", "<conf1/>");
    try store.publish("alice@localhost", "storage:bookmarks", "bm2", "<conf2/>");

    try store.deleteNode(allocator, "alice@localhost", "storage:bookmarks");

    const items = try store.getItems(allocator, "alice@localhost", "storage:bookmarks");
    defer TestStore.freeItems(allocator, items);
    try std.testing.expectEqual(@as(usize, 0), items.len);
}

test "PepStore: multiple users independent" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.publish("alice@localhost", "urn:xmpp:avatar:data", "current", "<alice-avatar/>");
    try store.publish("bob@localhost", "urn:xmpp:avatar:data", "current", "<bob-avatar/>");

    const alice_item = try store.getItem(allocator, "alice@localhost", "urn:xmpp:avatar:data", "current");
    defer if (alice_item) |v| allocator.free(v);
    try std.testing.expectEqualStrings("<alice-avatar/>", alice_item.?);

    const bob_item = try store.getItem(allocator, "bob@localhost", "urn:xmpp:avatar:data", "current");
    defer if (bob_item) |v| allocator.free(v);
    try std.testing.expectEqualStrings("<bob-avatar/>", bob_item.?);
}

test "PepStore: removeAll" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.publish("alice@localhost", "urn:xmpp:avatar:data", "current", "<data/>");
    try store.publish("alice@localhost", "storage:bookmarks", "bm1", "<conf/>");

    try store.removeAll(allocator, "alice@localhost");

    const item1 = try store.getItem(allocator, "alice@localhost", "urn:xmpp:avatar:data", "current");
    try std.testing.expect(item1 == null);
    const item2 = try store.getItem(allocator, "alice@localhost", "storage:bookmarks", "bm1");
    try std.testing.expect(item2 == null);
}
