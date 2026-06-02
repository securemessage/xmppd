//! # RosterStore — flat-file roster storage
//!
//! Stores per-user roster items with subscription states in a simple text format:
//!
//! ```
//! # owner_jid|contact_jid|name|subscription|ask
//! alice@localhost|bob@localhost|Bob|both|
//! alice@localhost|carol@localhost|Carol|from|subscribe
//! bob@localhost|alice@localhost|Alice|both|
//! ```
//!
//! Fields:
//!   - owner_jid: bare JID of the roster owner
//!   - contact_jid: bare JID of the contact
//!   - name: display name (may be empty)
//!   - subscription: none, to, from, both, remove
//!   - ask: empty or "subscribe" (pending outbound subscription request)
//!
//! Loaded into memory at startup, modified in-memory, and written back
//! atomically (write temp + rename) on mutations.
//!
//! The roster file lives in the same directory as the user database.

const std = @import("std");

const log = std.log.scoped(.roster_store);

/// Subscription state per RFC 6121 Section 3.1.2.
pub const Subscription = enum {
    none,
    to,
    from,
    both,
    remove,

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

/// A single roster item (contact entry).
pub const RosterItem = struct {
    /// Bare JID of the roster owner (e.g., "alice@localhost").
    owner: []const u8,
    /// Bare JID of the contact (e.g., "bob@localhost").
    jid: []const u8,
    /// Display name (optional, may be empty).
    name: []const u8 = "",
    /// Subscription state.
    subscription: Subscription = .none,
    /// Pending ask state ("subscribe" if outbound sub request pending).
    ask: []const u8 = "",
};

/// Roster store — all users' roster items in memory.
pub const RosterStore = struct {
    items: std.ArrayListUnmanaged(RosterItem),
    /// Arena allocator for string data.
    arena: std.heap.ArenaAllocator,
    /// Backing allocator (for ArrayListUnmanaged).
    allocator: std.mem.Allocator,
    /// Path to the roster file.
    path: []const u8,

    pub fn init(allocator: std.mem.Allocator, path: []const u8) RosterStore {
        return .{
            .items = .{},
            .arena = std.heap.ArenaAllocator.init(allocator),
            .allocator = allocator,
            .path = path,
        };
    }

    pub fn deinit(self: *RosterStore) void {
        self.items.deinit(self.allocator);
        self.arena.deinit();
    }

    /// Load roster from file. Creates an empty store if the file doesn't exist.
    pub fn load(self: *RosterStore) !void {
        self.items.clearRetainingCapacity();
        _ = self.arena.reset(.retain_capacity);

        const file = std.fs.cwd().openFile(self.path, .{}) catch |err| {
            if (err == error.FileNotFound) {
                log.info("roster store not found at {s}, starting empty", .{self.path});
                return;
            }
            return err;
        };
        defer file.close();

        const alloc = self.arena.allocator();
        const contents = try file.readToEndAlloc(alloc, 4 * 1024 * 1024);

        var lines = std.mem.splitScalar(u8, contents, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            const item = parseLine(trimmed) catch |err| {
                log.warn("skipping malformed roster line: {}", .{err});
                continue;
            };
            try self.items.append(self.allocator, item);
        }

        log.info("loaded {d} roster items from {s}", .{ self.items.items.len, self.path });
    }

    /// Save the entire roster atomically (write temp + rename).
    pub fn save(self: *RosterStore) !void {
        // Build the temp path
        var tmp_buf: [1024]u8 = undefined;
        const tmp_path = std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{self.path}) catch return error.PathTooLong;

        // Build file content in memory (roster is small — typically <100KB)
        var content_buf: [262144]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&content_buf);
        const writer = fbs.writer();

        writer.writeAll("# owner|contact|name|subscription|ask\n") catch return error.WriteFailed;

        for (self.items.items) |item| {
            if (item.subscription == .remove) continue; // Don't persist removed items
            writer.writeAll(item.owner) catch return error.WriteFailed;
            writer.writeByte('|') catch return error.WriteFailed;
            writer.writeAll(item.jid) catch return error.WriteFailed;
            writer.writeByte('|') catch return error.WriteFailed;
            writer.writeAll(item.name) catch return error.WriteFailed;
            writer.writeByte('|') catch return error.WriteFailed;
            writer.writeAll(item.subscription.toString()) catch return error.WriteFailed;
            writer.writeByte('|') catch return error.WriteFailed;
            writer.writeAll(item.ask) catch return error.WriteFailed;
            writer.writeByte('\n') catch return error.WriteFailed;
        }

        // Write to temp file
        const file = std.fs.cwd().createFile(tmp_path, .{}) catch return error.WriteFailed;
        defer file.close();
        file.writeAll(fbs.getWritten()) catch return error.WriteFailed;

        // Atomic rename
        std.fs.cwd().rename(tmp_path, self.path) catch |err| {
            log.err("failed to rename {s} to {s}: {}", .{ tmp_path, self.path, err });
            return err;
        };
    }

    /// Get all roster items for a given owner (bare JID).
    pub fn getRoster(self: *const RosterStore, owner: []const u8) []const RosterItem {
        // Return a slice view — caller iterates self.items filtering by owner
        // For efficiency with many users, we'd index by owner. For now, linear scan.
        _ = self;
        _ = owner;
        // We can't return a filtered slice directly, so this is used via getItems + filter
        return &.{};
    }

    /// Get a specific roster item by owner + contact JID.
    pub fn getItem(self: *const RosterStore, owner: []const u8, contact: []const u8) ?*const RosterItem {
        for (self.items.items) |*item| {
            if (std.mem.eql(u8, item.owner, owner) and std.mem.eql(u8, item.jid, contact)) {
                return item;
            }
        }
        return null;
    }

    /// Get a mutable reference to a roster item.
    pub fn getItemMut(self: *RosterStore, owner: []const u8, contact: []const u8) ?*RosterItem {
        for (self.items.items) |*item| {
            if (std.mem.eql(u8, item.owner, owner) and std.mem.eql(u8, item.jid, contact)) {
                return item;
            }
        }
        return null;
    }

    /// Set or update a roster item. Creates if it doesn't exist.
    pub fn setItem(self: *RosterStore, owner: []const u8, contact: []const u8, name: []const u8, subscription: Subscription, ask: []const u8) !void {
        const alloc = self.arena.allocator();

        // Check if item already exists
        for (self.items.items) |*item| {
            if (std.mem.eql(u8, item.owner, owner) and std.mem.eql(u8, item.jid, contact)) {
                // Update in place
                item.name = if (name.len > 0) try alloc.dupe(u8, name) else item.name;
                item.subscription = subscription;
                item.ask = if (ask.len > 0) try alloc.dupe(u8, ask) else "";
                return;
            }
        }

        // Create new item
        try self.items.append(self.allocator, .{
            .owner = try alloc.dupe(u8, owner),
            .jid = try alloc.dupe(u8, contact),
            .name = if (name.len > 0) try alloc.dupe(u8, name) else "",
            .subscription = subscription,
            .ask = if (ask.len > 0) try alloc.dupe(u8, ask) else "",
        });
    }

    /// Remove a roster item.
    pub fn removeItem(self: *RosterStore, owner: []const u8, contact: []const u8) bool {
        for (self.items.items, 0..) |item, i| {
            if (std.mem.eql(u8, item.owner, owner) and std.mem.eql(u8, item.jid, contact)) {
                _ = self.items.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Count items for a given owner.
    pub fn countForOwner(self: *const RosterStore, owner: []const u8) usize {
        var count: usize = 0;
        for (self.items.items) |item| {
            if (std.mem.eql(u8, item.owner, owner)) count += 1;
        }
        return count;
    }

    /// Check if a contact has a subscription that allows them to see the owner's presence.
    /// "from" or "both" means the contact is subscribed TO the owner's presence.
    pub fn isSubscribedToPresence(self: *const RosterStore, owner: []const u8, subscriber: []const u8) bool {
        for (self.items.items) |item| {
            if (std.mem.eql(u8, item.owner, owner) and std.mem.eql(u8, item.jid, subscriber)) {
                return item.subscription == .from or item.subscription == .both;
            }
        }
        return false;
    }

    /// Get all JIDs that are subscribed to the owner's presence (subscription = from or both).
    /// Returns items from the owner's roster where the contact has a "from" or "both" subscription.
    /// Caller should iterate items and check subscription.
    pub fn getPresenceSubscribers(self: *const RosterStore, owner: []const u8, buf: [][]const u8) usize {
        var count: usize = 0;
        for (self.items.items) |item| {
            if (count >= buf.len) break;
            if (std.mem.eql(u8, item.owner, owner)) {
                if (item.subscription == .from or item.subscription == .both) {
                    buf[count] = item.jid;
                    count += 1;
                }
            }
        }
        return count;
    }

    /// Get all JIDs the owner is subscribed to (subscription = to or both).
    /// These are contacts whose presence the owner should receive.
    pub fn getPresenceSubscriptions(self: *const RosterStore, owner: []const u8, buf: [][]const u8) usize {
        var count: usize = 0;
        for (self.items.items) |item| {
            if (count >= buf.len) break;
            if (std.mem.eql(u8, item.owner, owner)) {
                if (item.subscription == .to or item.subscription == .both) {
                    buf[count] = item.jid;
                    count += 1;
                }
            }
        }
        return count;
    }
};

/// Parse a single line: "owner|contact|name|subscription|ask"
fn parseLine(line: []const u8) !RosterItem {
    var fields: [5][]const u8 = undefined;
    var count: usize = 0;
    var iter = std.mem.splitScalar(u8, line, '|');
    while (iter.next()) |field| {
        if (count >= 5) return error.TooManyFields;
        fields[count] = field;
        count += 1;
    }
    if (count < 4) return error.TooFewFields;

    return .{
        .owner = fields[0],
        .jid = fields[1],
        .name = if (count > 2) fields[2] else "",
        .subscription = Subscription.fromString(fields[3]),
        .ask = if (count > 4) fields[4] else "",
    };
}

// ============================================================================
// Tests
// ============================================================================

test "Subscription fromString/toString roundtrip" {
    try std.testing.expectEqual(Subscription.none, Subscription.fromString("none"));
    try std.testing.expectEqual(Subscription.to, Subscription.fromString("to"));
    try std.testing.expectEqual(Subscription.from, Subscription.fromString("from"));
    try std.testing.expectEqual(Subscription.both, Subscription.fromString("both"));
    try std.testing.expectEqual(Subscription.remove, Subscription.fromString("remove"));
    try std.testing.expectEqual(Subscription.none, Subscription.fromString("bogus"));

    try std.testing.expectEqualStrings("none", Subscription.none.toString());
    try std.testing.expectEqualStrings("both", Subscription.both.toString());
}

test "parseLine valid" {
    const item = try parseLine("alice@localhost|bob@localhost|Bob|both|");
    try std.testing.expectEqualStrings("alice@localhost", item.owner);
    try std.testing.expectEqualStrings("bob@localhost", item.jid);
    try std.testing.expectEqualStrings("Bob", item.name);
    try std.testing.expectEqual(Subscription.both, item.subscription);
    try std.testing.expectEqualStrings("", item.ask);
}

test "parseLine with ask" {
    const item = try parseLine("alice@localhost|carol@localhost|Carol|none|subscribe");
    try std.testing.expectEqualStrings("carol@localhost", item.jid);
    try std.testing.expectEqual(Subscription.none, item.subscription);
    try std.testing.expectEqualStrings("subscribe", item.ask);
}

test "parseLine too few fields" {
    try std.testing.expectError(error.TooFewFields, parseLine("alice@localhost|bob@localhost|Bob"));
}

test "RosterStore: init, setItem, getItem" {
    var store = RosterStore.init(std.testing.allocator, "/tmp/test-roster.db");
    defer store.deinit();

    try store.setItem("alice@localhost", "bob@localhost", "Bob", .both, "");
    try store.setItem("alice@localhost", "carol@localhost", "Carol", .to, "");
    try store.setItem("bob@localhost", "alice@localhost", "Alice", .both, "");

    try std.testing.expectEqual(@as(usize, 3), store.items.items.len);

    const item = store.getItem("alice@localhost", "bob@localhost").?;
    try std.testing.expectEqualStrings("Bob", item.name);
    try std.testing.expectEqual(Subscription.both, item.subscription);

    try std.testing.expect(store.getItem("alice@localhost", "nobody@localhost") == null);
}

test "RosterStore: update existing item" {
    var store = RosterStore.init(std.testing.allocator, "/tmp/test-roster.db");
    defer store.deinit();

    try store.setItem("alice@localhost", "bob@localhost", "Bob", .none, "subscribe");
    try store.setItem("alice@localhost", "bob@localhost", "Bob", .to, "");

    try std.testing.expectEqual(@as(usize, 1), store.items.items.len);
    const item = store.getItem("alice@localhost", "bob@localhost").?;
    try std.testing.expectEqual(Subscription.to, item.subscription);
    try std.testing.expectEqualStrings("", item.ask);
}

test "RosterStore: removeItem" {
    var store = RosterStore.init(std.testing.allocator, "/tmp/test-roster.db");
    defer store.deinit();

    try store.setItem("alice@localhost", "bob@localhost", "Bob", .both, "");
    try store.setItem("alice@localhost", "carol@localhost", "Carol", .to, "");

    try std.testing.expect(store.removeItem("alice@localhost", "bob@localhost"));
    try std.testing.expectEqual(@as(usize, 1), store.items.items.len);
    try std.testing.expect(!store.removeItem("alice@localhost", "nobody@localhost"));
}

test "RosterStore: countForOwner" {
    var store = RosterStore.init(std.testing.allocator, "/tmp/test-roster.db");
    defer store.deinit();

    try store.setItem("alice@localhost", "bob@localhost", "", .both, "");
    try store.setItem("alice@localhost", "carol@localhost", "", .to, "");
    try store.setItem("bob@localhost", "alice@localhost", "", .both, "");

    try std.testing.expectEqual(@as(usize, 2), store.countForOwner("alice@localhost"));
    try std.testing.expectEqual(@as(usize, 1), store.countForOwner("bob@localhost"));
    try std.testing.expectEqual(@as(usize, 0), store.countForOwner("nobody@localhost"));
}

test "RosterStore: presence subscribers" {
    var store = RosterStore.init(std.testing.allocator, "/tmp/test-roster.db");
    defer store.deinit();

    // Alice's roster: bob=both, carol=to (carol doesn't get alice's presence)
    try store.setItem("alice@localhost", "bob@localhost", "", .both, "");
    try store.setItem("alice@localhost", "carol@localhost", "", .to, "");
    try store.setItem("alice@localhost", "dave@localhost", "", .from, "");

    try std.testing.expect(store.isSubscribedToPresence("alice@localhost", "bob@localhost"));
    try std.testing.expect(!store.isSubscribedToPresence("alice@localhost", "carol@localhost"));
    try std.testing.expect(store.isSubscribedToPresence("alice@localhost", "dave@localhost"));

    var buf: [16][]const u8 = undefined;
    const count = store.getPresenceSubscribers("alice@localhost", &buf);
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "RosterStore: presence subscriptions (contacts whose presence I receive)" {
    var store = RosterStore.init(std.testing.allocator, "/tmp/test-roster.db");
    defer store.deinit();

    try store.setItem("alice@localhost", "bob@localhost", "", .both, "");
    try store.setItem("alice@localhost", "carol@localhost", "", .to, "");
    try store.setItem("alice@localhost", "dave@localhost", "", .from, "");

    var buf: [16][]const u8 = undefined;
    const count = store.getPresenceSubscriptions("alice@localhost", &buf);
    // "to" and "both" — alice is subscribed to bob and carol
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "RosterStore: save and load roundtrip" {
    const path = "/tmp/xmppd-roster-test.db";

    // Clean up
    std.fs.cwd().deleteFile(path) catch {};
    defer std.fs.cwd().deleteFile(path) catch {};

    // Create and save
    {
        var store = RosterStore.init(std.testing.allocator, path);
        defer store.deinit();

        try store.setItem("alice@localhost", "bob@localhost", "Bob", .both, "");
        try store.setItem("alice@localhost", "carol@localhost", "Carol", .none, "subscribe");
        try store.setItem("bob@localhost", "alice@localhost", "Alice", .both, "");
        try store.save();
    }

    // Load into a fresh store
    {
        var store = RosterStore.init(std.testing.allocator, path);
        defer store.deinit();
        try store.load();

        try std.testing.expectEqual(@as(usize, 3), store.items.items.len);

        const item = store.getItem("alice@localhost", "bob@localhost").?;
        try std.testing.expectEqualStrings("Bob", item.name);
        try std.testing.expectEqual(Subscription.both, item.subscription);

        const item2 = store.getItem("alice@localhost", "carol@localhost").?;
        try std.testing.expectEqualStrings("subscribe", item2.ask);
    }
}

test "RosterStore: load nonexistent file" {
    var store = RosterStore.init(std.testing.allocator, "/tmp/nonexistent-roster-xyz.db");
    defer store.deinit();
    try store.load(); // Should not error
    try std.testing.expectEqual(@as(usize, 0), store.items.items.len);
}
