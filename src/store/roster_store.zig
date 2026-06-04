//! # RosterStore — generic roster storage
//!
//! Stores per-user roster items (contacts + subscription state) in a
//! StorageBackend. Uses prefix scanning for presence fan-out queries.
//!
//! ## Key format
//!
//! Namespace `rosters`: key = `owner\x00contact`
//!
//! ## Binary value format
//!
//! ```
//! | subscription (1) | ask (1) | name_len_be (2) | name (variable) |
//! ```
//!
//! Subscription: 0=none, 1=to, 2=from, 3=both, 4=remove
//! Ask: 0=none, 1=subscribe (pending outbound request)

const std = @import("std");
const backend_mod = @import("backend");

const log = std.log.scoped(.roster_store);

const NAMESPACE = "rosters";

pub const Subscription = enum(u8) {
    none = 0,
    to = 1,
    from = 2,
    both = 3,
    remove = 4,

    pub fn fromString(s: []const u8) Subscription {
        if (std.mem.eql(u8, s, "to")) return .to;
        if (std.mem.eql(u8, s, "from")) return .from;
        if (std.mem.eql(u8, s, "both")) return .both;
        if (std.mem.eql(u8, s, "remove")) return .remove;
        return .none;
    }

    pub fn toString(self: Subscription) []const u8 {
        return switch (self) {
            .none => "none",
            .to => "to",
            .from => "from",
            .both => "both",
            .remove => "remove",
        };
    }
};

pub const RosterEntry = struct {
    subscription: Subscription = .none,
    ask: bool = false,
    name: []const u8 = "",
};

pub fn RosterStore(comptime Backend: type) type {
    comptime backend_mod.assertBackend(Backend);

    return struct {
        backend: *Backend,

        const Self = @This();

        pub fn init(b: *Backend) Self {
            return .{ .backend = b };
        }

        pub fn deinit(self: *Self) void {
            _ = self;
        }

        /// Get a roster item by owner + contact JID.
        pub fn getItem(self: *Self, allocator: std.mem.Allocator, owner: []const u8, contact: []const u8) !?RosterEntry {
            var key_buf: [512]u8 = undefined;
            const key = compositeKey(&key_buf, owner, contact);

            const raw = try self.backend.get(allocator, NAMESPACE, key) orelse return null;
            defer allocator.free(raw);
            return try deserializeEntry(allocator, raw);
        }

        /// Set or update a roster item.
        pub fn setItem(self: *Self, owner: []const u8, contact: []const u8, name: []const u8, subscription: Subscription, ask: bool) !void {
            var key_buf: [512]u8 = undefined;
            const key = compositeKey(&key_buf, owner, contact);

            var val_buf: [512]u8 = undefined;
            const val = serializeEntry(&val_buf, name, subscription, ask);
            try self.backend.put(NAMESPACE, key, val);
        }

        /// Remove a roster item.
        pub fn removeItem(self: *Self, owner: []const u8, contact: []const u8) !void {
            var key_buf: [512]u8 = undefined;
            const key = compositeKey(&key_buf, owner, contact);
            try self.backend.delete(NAMESPACE, key);
        }

        /// Check if subscriber has a subscription allowing them to see owner's presence.
        pub fn isSubscribedToPresence(self: *Self, allocator: std.mem.Allocator, owner: []const u8, subscriber: []const u8) !bool {
            const entry = try self.getItem(allocator, owner, subscriber) orelse return false;
            if (entry.name.len > 0) allocator.free(entry.name);
            return entry.subscription == .from or entry.subscription == .both;
        }

        /// Get JIDs subscribed to owner's presence (subscription = from or both).
        /// Caller owns the returned slice and its elements.
        pub fn getPresenceSubscribers(self: *Self, allocator: std.mem.Allocator, owner: []const u8) ![][]const u8 {
            return self.scanBySubscription(allocator, owner, .{ .from = true, .both = true });
        }

        /// Get JIDs the owner is subscribed to (subscription = to or both).
        /// Caller owns the returned slice and its elements.
        pub fn getPresenceSubscriptions(self: *Self, allocator: std.mem.Allocator, owner: []const u8) ![][]const u8 {
            return self.scanBySubscription(allocator, owner, .{ .to = true, .both = true });
        }

        /// A roster item with its contact JID for enumeration.
        pub const RosterItem = struct {
            contact_jid: []const u8,
            entry: RosterEntry,
        };

        /// Get all roster items for an owner.
        /// Caller owns the returned slice and must free each item's contact_jid
        /// and name (if non-empty), then free the slice itself.
        pub fn getAllItems(self: *Self, allocator: std.mem.Allocator, owner: []const u8) ![]RosterItem {
            var prefix_buf: [256]u8 = undefined;
            const prefix = ownerPrefix(&prefix_buf, owner);

            var iter = try self.backend.iterator(NAMESPACE, prefix);
            defer iter.deinit();

            var list: std.ArrayListUnmanaged(RosterItem) = .{};
            errdefer {
                for (list.items) |item| {
                    allocator.free(item.contact_jid);
                    if (item.entry.name.len > 0) allocator.free(item.entry.name);
                }
                list.deinit(allocator);
            }

            while (iter.next()) |kv| {
                const contact = kv.key[owner.len + 1 ..];
                const entry = deserializeEntry(allocator, kv.value) catch continue;

                list.append(allocator, .{
                    .contact_jid = allocator.dupe(u8, contact) catch {
                        if (entry.name.len > 0) allocator.free(entry.name);
                        continue;
                    },
                    .entry = entry,
                }) catch {
                    if (entry.name.len > 0) allocator.free(entry.name);
                    continue;
                };
            }

            return list.toOwnedSlice(allocator);
        }

        /// Free a slice returned by getAllItems.
        pub fn freeAllItems(allocator: std.mem.Allocator, items: []const RosterItem) void {
            for (items) |item| {
                allocator.free(item.contact_jid);
                if (item.entry.name.len > 0) allocator.free(item.entry.name);
            }
            allocator.free(items);
        }

        /// Count roster items for an owner.
        pub fn countForOwner(self: *Self, owner: []const u8) !usize {
            var prefix_buf: [256]u8 = undefined;
            const prefix = ownerPrefix(&prefix_buf, owner);

            var iter = try self.backend.iterator(NAMESPACE, prefix);
            defer iter.deinit();

            var count: usize = 0;
            while (iter.next()) |_| count += 1;
            return count;
        }

        // -- Internal --

        const SubFilter = struct {
            from: bool = false,
            to: bool = false,
            both: bool = false,
        };

        fn scanBySubscription(self: *Self, allocator: std.mem.Allocator, owner: []const u8, filter: SubFilter) ![][]const u8 {
            var prefix_buf: [256]u8 = undefined;
            const prefix = ownerPrefix(&prefix_buf, owner);

            var iter = try self.backend.iterator(NAMESPACE, prefix);
            defer iter.deinit();

            var list: std.ArrayListUnmanaged([]const u8) = .{};
            errdefer {
                for (list.items) |item| allocator.free(item);
                list.deinit(allocator);
            }

            while (iter.next()) |entry| {
                const data = deserializeEntry(allocator, entry.value) catch continue;
                defer if (data.name.len > 0) allocator.free(data.name);

                const match = (filter.from and data.subscription == .from) or
                    (filter.to and data.subscription == .to) or
                    (filter.both and data.subscription == .both);

                if (match) {
                    // Extract contact JID from composite key (after owner\x00)
                    const contact = entry.key[owner.len + 1 ..];
                    try list.append(allocator, try allocator.dupe(u8, contact));
                }
            }

            return try list.toOwnedSlice(allocator);
        }
    };
}

// ============================================================================
// Key/Value helpers
// ============================================================================

fn compositeKey(buf: []u8, owner: []const u8, contact: []const u8) []const u8 {
    const len = owner.len + 1 + contact.len;
    @memcpy(buf[0..owner.len], owner);
    buf[owner.len] = 0;
    @memcpy(buf[owner.len + 1 .. len], contact);
    return buf[0..len];
}

fn ownerPrefix(buf: []u8, owner: []const u8) []const u8 {
    @memcpy(buf[0..owner.len], owner);
    buf[owner.len] = 0;
    return buf[0 .. owner.len + 1];
}

fn serializeEntry(buf: []u8, name: []const u8, subscription: Subscription, ask: bool) []const u8 {
    buf[0] = @intFromEnum(subscription);
    buf[1] = if (ask) 1 else 0;
    std.mem.writeInt(u16, buf[2..4], @intCast(name.len), .big);
    @memcpy(buf[4 .. 4 + name.len], name);
    return buf[0 .. 4 + name.len];
}

pub fn deserializeEntry(allocator: std.mem.Allocator, data: []const u8) !RosterEntry {
    if (data.len < 4) return error.InvalidFormat;
    const sub_byte = data[0];
    const ask_byte = data[1];
    const name_len = std.mem.readInt(u16, data[2..4], .big);
    if (data.len < 4 + name_len) return error.InvalidFormat;

    const name_slice = data[4 .. 4 + name_len];
    return .{
        .subscription = @enumFromInt(if (sub_byte <= 4) sub_byte else 0),
        .ask = ask_byte != 0,
        .name = if (name_len > 0) try allocator.dupe(u8, name_slice) else "",
    };
}

// ============================================================================
// Tests
// ============================================================================

const MemoryBackend = backend_mod.MemoryBackend;
const TestStore = RosterStore(MemoryBackend);

test "RosterStore: setItem and getItem" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.setItem("alice@localhost", "bob@localhost", "Bob", .both, false);

    const entry = try store.getItem(std.testing.allocator, "alice@localhost", "bob@localhost");
    try std.testing.expect(entry != null);
    const e = entry.?;
    defer if (e.name.len > 0) std.testing.allocator.free(e.name);
    try std.testing.expectEqual(Subscription.both, e.subscription);
    try std.testing.expectEqualStrings("Bob", e.name);
    try std.testing.expect(!e.ask);
}

test "RosterStore: getItem missing" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    const entry = try store.getItem(std.testing.allocator, "alice@localhost", "nobody@localhost");
    try std.testing.expect(entry == null);
}

test "RosterStore: update existing item" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.setItem("alice@localhost", "bob@localhost", "Bob", .none, true);
    try store.setItem("alice@localhost", "bob@localhost", "Bob", .to, false);

    const entry = (try store.getItem(std.testing.allocator, "alice@localhost", "bob@localhost")).?;
    defer if (entry.name.len > 0) std.testing.allocator.free(entry.name);
    try std.testing.expectEqual(Subscription.to, entry.subscription);
    try std.testing.expect(!entry.ask);
}

test "RosterStore: removeItem" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.setItem("alice@localhost", "bob@localhost", "Bob", .both, false);
    try store.removeItem("alice@localhost", "bob@localhost");

    const entry = try store.getItem(std.testing.allocator, "alice@localhost", "bob@localhost");
    try std.testing.expect(entry == null);
}

test "RosterStore: countForOwner" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.setItem("alice@localhost", "bob@localhost", "", .both, false);
    try store.setItem("alice@localhost", "carol@localhost", "", .to, false);
    try store.setItem("bob@localhost", "alice@localhost", "", .both, false);

    try std.testing.expectEqual(@as(usize, 2), try store.countForOwner("alice@localhost"));
    try std.testing.expectEqual(@as(usize, 1), try store.countForOwner("bob@localhost"));
    try std.testing.expectEqual(@as(usize, 0), try store.countForOwner("nobody@localhost"));
}

test "RosterStore: isSubscribedToPresence" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.setItem("alice@localhost", "bob@localhost", "", .both, false);
    try store.setItem("alice@localhost", "carol@localhost", "", .to, false);
    try store.setItem("alice@localhost", "dave@localhost", "", .from, false);

    try std.testing.expect(try store.isSubscribedToPresence(std.testing.allocator, "alice@localhost", "bob@localhost"));
    try std.testing.expect(!try store.isSubscribedToPresence(std.testing.allocator, "alice@localhost", "carol@localhost"));
    try std.testing.expect(try store.isSubscribedToPresence(std.testing.allocator, "alice@localhost", "dave@localhost"));
}

test "RosterStore: getPresenceSubscribers" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.setItem("alice@localhost", "bob@localhost", "", .both, false);
    try store.setItem("alice@localhost", "carol@localhost", "", .to, false);
    try store.setItem("alice@localhost", "dave@localhost", "", .from, false);

    const subs = try store.getPresenceSubscribers(std.testing.allocator, "alice@localhost");
    defer {
        for (subs) |s| std.testing.allocator.free(s);
        std.testing.allocator.free(subs);
    }
    // bob (both) + dave (from) = 2
    try std.testing.expectEqual(@as(usize, 2), subs.len);
}

test "RosterStore: getPresenceSubscriptions" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.setItem("alice@localhost", "bob@localhost", "", .both, false);
    try store.setItem("alice@localhost", "carol@localhost", "", .to, false);
    try store.setItem("alice@localhost", "dave@localhost", "", .from, false);

    const subs = try store.getPresenceSubscriptions(std.testing.allocator, "alice@localhost");
    defer {
        for (subs) |s| std.testing.allocator.free(s);
        std.testing.allocator.free(subs);
    }
    // bob (both) + carol (to) = 2
    try std.testing.expectEqual(@as(usize, 2), subs.len);
}

test "RosterStore: ask flag roundtrip" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.setItem("alice@localhost", "bob@localhost", "", .none, true);

    const entry = (try store.getItem(std.testing.allocator, "alice@localhost", "bob@localhost")).?;
    defer if (entry.name.len > 0) std.testing.allocator.free(entry.name);
    try std.testing.expect(entry.ask);
    try std.testing.expectEqual(Subscription.none, entry.subscription);
}

test "Subscription: fromString/toString roundtrip" {
    try std.testing.expectEqual(Subscription.none, Subscription.fromString("none"));
    try std.testing.expectEqual(Subscription.to, Subscription.fromString("to"));
    try std.testing.expectEqual(Subscription.from, Subscription.fromString("from"));
    try std.testing.expectEqual(Subscription.both, Subscription.fromString("both"));
    try std.testing.expectEqual(Subscription.remove, Subscription.fromString("remove"));
    try std.testing.expectEqualStrings("both", Subscription.both.toString());
}
