//! # Archive Store (XEP-0313 MAM)
//!
//! Stores and retrieves message archives for XEP-0313 (MAM).
//! Provides paginated read with RSM (Result Set Management) cursors,
//! filtering by conversation partner, and timestamp-based retention.
//!
//! ## Key Schema (per design doc §7)
//!
//! - `messages` namespace: `bare_jid\x00timestamp_be(8)\x00stanza_id` → stanza XML
//! - `by_contact` namespace: `bare_jid\x00with_jid\x00timestamp_be(8)` → stanza_id
//!
//! Timestamps are big-endian u64 for lexicographic = chronological ordering.

const std = @import("std");
const backend = @import("backend");

const NS_MESSAGES = "messages";
const NS_BY_CONTACT = "by_contact";

/// A stored archive message with metadata.
pub const ArchivedMessage = struct {
    stanza_id: []const u8,
    timestamp: u64,
    stanza_xml: []const u8,
};

/// Query parameters for MAM retrieval (XEP-0313 + RSM).
pub const QueryOptions = struct {
    /// Filter by conversation partner (with attribute).
    with: ?[]const u8 = null,

    /// Start timestamp (inclusive). Messages on or after this time.
    start: ?u64 = null,

    /// End timestamp (inclusive). Messages on or before this time.
    end: ?u64 = null,

    /// RSM: retrieve items after this stanza_id.
    after_id: ?[]const u8 = null,

    /// RSM: retrieve items before this stanza_id.
    before_id: ?[]const u8 = null,

    /// Maximum number of results to return.
    max: u32 = 50,

    /// Direction: false = forward (oldest first), true = backward (newest first).
    /// When before_id is set without after_id, defaults to backward.
    backward: bool = false,
};

/// Result of a paginated MAM query.
pub const QueryResult = struct {
    messages: []ArchivedMessage,
    /// True if there are more results beyond this page.
    complete: bool,
};

/// Generic archive store parameterized on a StorageBackend.
pub fn ArchiveStore(comptime Backend: type) type {
    comptime {
        backend.assertBackend(Backend);
    }

    return struct {
        const Self = @This();
        db: *Backend,
        allocator: std.mem.Allocator,

        pub fn init(db: *Backend, allocator: std.mem.Allocator) Self {
            return .{ .db = db, .allocator = allocator };
        }

        /// Store a message in the archive.
        pub fn store(
            self: *Self,
            owner: []const u8,
            with: []const u8,
            stanza_id: []const u8,
            timestamp: u64,
            stanza_xml: []const u8,
        ) !void {
            // Build primary key: owner\x00timestamp_be(8)\x00stanza_id
            const primary_key = try self.buildPrimaryKey(owner, timestamp, stanza_id);
            defer self.allocator.free(primary_key);

            // Build contact index key: owner\x00with\x00timestamp_be(8)
            const contact_key = try self.buildContactKey(owner, with, timestamp);
            defer self.allocator.free(contact_key);

            // Atomic write: message + contact index
            var batch = try self.db.writeBatch();
            try batch.put(NS_MESSAGES, primary_key, stanza_xml);
            try batch.put(NS_BY_CONTACT, contact_key, stanza_id);
            try batch.commit();
        }

        /// Query the archive with RSM pagination.
        pub fn query(
            self: *Self,
            owner: []const u8,
            opts: QueryOptions,
        ) !QueryResult {
            // If filtering by contact, use the by_contact index
            if (opts.with) |with| {
                return self.queryByContact(owner, with, opts);
            }

            // Full archive scan for this owner
            return self.queryAll(owner, opts);
        }

        /// Retrieve a single message by stanza_id (for offline delivery).
        pub fn getMessage(
            self: *Self,
            owner: []const u8,
            timestamp: u64,
            stanza_id: []const u8,
        ) !?[]u8 {
            const key = try self.buildPrimaryKey(owner, timestamp, stanza_id);
            defer self.allocator.free(key);
            return self.db.get(self.allocator, NS_MESSAGES, key);
        }

        /// Delete messages older than the given timestamp (retention).
        pub fn deleteOlderThan(
            self: *Self,
            owner: []const u8,
            before_timestamp: u64,
        ) !u32 {
            // Scan messages for this owner, delete those before the cutoff
            const prefix = try self.buildOwnerPrefix(owner);
            defer self.allocator.free(prefix);

            var iter = try self.db.iterator(NS_MESSAGES, prefix);
            defer iter.deinit();

            var keys_to_delete = std.ArrayListUnmanaged([]u8){};
            defer {
                for (keys_to_delete.items) |k| self.allocator.free(k);
                keys_to_delete.deinit(self.allocator);
            }

            while (iter.next()) |entry| {
                const ts = self.extractTimestamp(entry.key, owner.len + 1) orelse continue;
                if (ts < before_timestamp) {
                    const k = try self.allocator.dupe(u8, entry.key);
                    try keys_to_delete.append(self.allocator, k);
                }
            }

            if (keys_to_delete.items.len == 0) return 0;

            var batch = try self.db.writeBatch();
            for (keys_to_delete.items) |k| {
                try batch.delete(NS_MESSAGES, k);
            }
            try batch.commit();

            return @intCast(keys_to_delete.items.len);
        }

        // -- Internal query helpers --

        fn queryAll(self: *Self, owner: []const u8, opts: QueryOptions) !QueryResult {
            const prefix = try self.buildOwnerPrefix(owner);
            defer self.allocator.free(prefix);

            var iter = try self.db.iterator(NS_MESSAGES, prefix);
            defer iter.deinit();

            return self.collectResults(&iter, owner, opts);
        }

        fn queryByContact(self: *Self, owner: []const u8, with: []const u8, opts: QueryOptions) !QueryResult {
            // Scan the by_contact index: owner\x00with\x00
            const prefix = try self.buildContactPrefix(owner, with);
            defer self.allocator.free(prefix);

            var iter = try self.db.iterator(NS_BY_CONTACT, prefix);
            defer iter.deinit();

            // Collect stanza_ids from the index, then fetch messages
            var messages = std.ArrayListUnmanaged(ArchivedMessage){};
            var skipping = opts.after_id != null;
            var count: u32 = 0;

            while (iter.next()) |entry| {
                const ts = self.extractTimestamp(entry.key, owner.len + 1 + with.len + 1) orelse continue;

                // Time range filter
                if (opts.start) |start| {
                    if (ts < start) continue;
                }
                if (opts.end) |end| {
                    if (ts > end) continue;
                }

                const stanza_id = entry.value;

                // RSM after_id: skip until we pass the target
                if (skipping) {
                    if (opts.after_id) |after| {
                        if (std.mem.eql(u8, stanza_id, after)) {
                            skipping = false;
                        }
                    }
                    continue;
                }

                // RSM before_id: stop when we hit it
                if (opts.before_id) |before| {
                    if (std.mem.eql(u8, stanza_id, before)) {
                        return .{ .messages = try messages.toOwnedSlice(self.allocator), .complete = true };
                    }
                }

                if (count >= opts.max) {
                    // More results exist
                    return .{ .messages = try messages.toOwnedSlice(self.allocator), .complete = false };
                }

                // Fetch the actual stanza
                const primary_key = try self.buildPrimaryKey(owner, ts, stanza_id);
                defer self.allocator.free(primary_key);
                const xml = try self.db.get(self.allocator, NS_MESSAGES, primary_key);

                try messages.append(self.allocator, .{
                    .stanza_id = try self.allocator.dupe(u8, stanza_id),
                    .timestamp = ts,
                    .stanza_xml = xml orelse "",
                });
                count += 1;
            }

            return .{ .messages = try messages.toOwnedSlice(self.allocator), .complete = true };
        }

        fn collectResults(self: *Self, iter: *Backend.Iterator, owner: []const u8, opts: QueryOptions) !QueryResult {
            var messages = std.ArrayListUnmanaged(ArchivedMessage){};
            var skipping = opts.after_id != null;
            var count: u32 = 0;

            while (iter.next()) |entry| {
                const ts = self.extractTimestamp(entry.key, owner.len + 1) orelse continue;

                // Time range filter
                if (opts.start) |start| {
                    if (ts < start) continue;
                }
                if (opts.end) |end| {
                    if (ts > end) continue;
                }

                // Extract stanza_id from key: after owner\x00timestamp(8)\x00
                const id_offset = owner.len + 1 + 8 + 1;
                if (entry.key.len <= id_offset) continue;
                const stanza_id = entry.key[id_offset..];

                // RSM after_id: skip until we pass the target
                if (skipping) {
                    if (opts.after_id) |after| {
                        if (std.mem.eql(u8, stanza_id, after)) {
                            skipping = false;
                        }
                    }
                    continue;
                }

                // RSM before_id: stop when we hit it
                if (opts.before_id) |before| {
                    if (std.mem.eql(u8, stanza_id, before)) {
                        return .{ .messages = try messages.toOwnedSlice(self.allocator), .complete = true };
                    }
                }

                if (count >= opts.max) {
                    return .{ .messages = try messages.toOwnedSlice(self.allocator), .complete = false };
                }

                try messages.append(self.allocator, .{
                    .stanza_id = try self.allocator.dupe(u8, stanza_id),
                    .timestamp = ts,
                    .stanza_xml = try self.allocator.dupe(u8, entry.value),
                });
                count += 1;
            }

            return .{ .messages = try messages.toOwnedSlice(self.allocator), .complete = true };
        }

        // -- Key builders --

        fn buildPrimaryKey(self: *Self, owner: []const u8, timestamp: u64, stanza_id: []const u8) ![]u8 {
            // owner\x00timestamp_be(8)\x00stanza_id
            const len = owner.len + 1 + 8 + 1 + stanza_id.len;
            const key = try self.allocator.alloc(u8, len);
            var pos: usize = 0;
            @memcpy(key[pos..][0..owner.len], owner);
            pos += owner.len;
            key[pos] = 0;
            pos += 1;
            std.mem.writeInt(u64, key[pos..][0..8], timestamp, .big);
            pos += 8;
            key[pos] = 0;
            pos += 1;
            @memcpy(key[pos..][0..stanza_id.len], stanza_id);
            return key;
        }

        fn buildContactKey(self: *Self, owner: []const u8, with: []const u8, timestamp: u64) ![]u8 {
            // owner\x00with\x00timestamp_be(8)
            const len = owner.len + 1 + with.len + 1 + 8;
            const key = try self.allocator.alloc(u8, len);
            var pos: usize = 0;
            @memcpy(key[pos..][0..owner.len], owner);
            pos += owner.len;
            key[pos] = 0;
            pos += 1;
            @memcpy(key[pos..][0..with.len], with);
            pos += with.len;
            key[pos] = 0;
            pos += 1;
            std.mem.writeInt(u64, key[pos..][0..8], timestamp, .big);
            return key;
        }

        fn buildOwnerPrefix(self: *Self, owner: []const u8) ![]u8 {
            // owner\x00
            const key = try self.allocator.alloc(u8, owner.len + 1);
            @memcpy(key[0..owner.len], owner);
            key[owner.len] = 0;
            return key;
        }

        fn buildContactPrefix(self: *Self, owner: []const u8, with: []const u8) ![]u8 {
            // owner\x00with\x00
            const len = owner.len + 1 + with.len + 1;
            const key = try self.allocator.alloc(u8, len);
            var pos: usize = 0;
            @memcpy(key[pos..][0..owner.len], owner);
            pos += owner.len;
            key[pos] = 0;
            pos += 1;
            @memcpy(key[pos..][0..with.len], with);
            pos += with.len;
            key[pos] = 0;
            return key;
        }

        fn extractTimestamp(_: *Self, key: []const u8, offset: usize) ?u64 {
            if (key.len < offset + 8) return null;
            return std.mem.readInt(u64, key[offset..][0..8], .big);
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const MemoryBackend = backend.MemoryBackend;

fn freeQueryResult(allocator: std.mem.Allocator, result: *QueryResult) void {
    for (result.messages) |msg| {
        allocator.free(msg.stanza_id);
        if (msg.stanza_xml.len > 0) allocator.free(@constCast(msg.stanza_xml));
    }
    allocator.free(result.messages);
}

test "ArchiveStore: store and retrieve" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = ArchiveStore(MemoryBackend).init(&db, std.testing.allocator);

    try store.store("alice@example.com", "bob@example.com", "msg-001", 1000, "<message>hello</message>");
    try store.store("alice@example.com", "bob@example.com", "msg-002", 2000, "<message>world</message>");

    var result = try store.query("alice@example.com", .{});
    defer freeQueryResult(std.testing.allocator, &result);

    try std.testing.expectEqual(@as(usize, 2), result.messages.len);
    try std.testing.expect(result.complete);
}

test "ArchiveStore: getMessage" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = ArchiveStore(MemoryBackend).init(&db, std.testing.allocator);

    try store.store("alice@example.com", "bob@example.com", "msg-001", 1000, "<message>hello</message>");

    const xml = try store.getMessage("alice@example.com", 1000, "msg-001");
    defer if (xml) |x| std.testing.allocator.free(x);
    try std.testing.expectEqualStrings("<message>hello</message>", xml.?);

    const missing = try store.getMessage("alice@example.com", 9999, "nonexistent");
    try std.testing.expect(missing == null);
}

test "ArchiveStore: query with max limit" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = ArchiveStore(MemoryBackend).init(&db, std.testing.allocator);

    try store.store("alice@example.com", "bob@example.com", "msg-001", 1000, "<m>1</m>");
    try store.store("alice@example.com", "bob@example.com", "msg-002", 2000, "<m>2</m>");
    try store.store("alice@example.com", "bob@example.com", "msg-003", 3000, "<m>3</m>");

    var result = try store.query("alice@example.com", .{ .max = 2 });
    defer freeQueryResult(std.testing.allocator, &result);

    try std.testing.expectEqual(@as(usize, 2), result.messages.len);
    try std.testing.expect(!result.complete);
}

test "ArchiveStore: query with time range" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = ArchiveStore(MemoryBackend).init(&db, std.testing.allocator);

    try store.store("alice@example.com", "bob@example.com", "msg-001", 1000, "<m>1</m>");
    try store.store("alice@example.com", "bob@example.com", "msg-002", 2000, "<m>2</m>");
    try store.store("alice@example.com", "bob@example.com", "msg-003", 3000, "<m>3</m>");

    var result = try store.query("alice@example.com", .{ .start = 1500, .end = 2500 });
    defer freeQueryResult(std.testing.allocator, &result);

    try std.testing.expectEqual(@as(usize, 1), result.messages.len);
    try std.testing.expectEqual(@as(u64, 2000), result.messages[0].timestamp);
}

test "ArchiveStore: query by contact" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = ArchiveStore(MemoryBackend).init(&db, std.testing.allocator);

    try store.store("alice@example.com", "bob@example.com", "msg-001", 1000, "<m>bob1</m>");
    try store.store("alice@example.com", "carol@example.com", "msg-002", 2000, "<m>carol1</m>");
    try store.store("alice@example.com", "bob@example.com", "msg-003", 3000, "<m>bob2</m>");

    var result = try store.query("alice@example.com", .{ .with = "bob@example.com" });
    defer freeQueryResult(std.testing.allocator, &result);

    try std.testing.expectEqual(@as(usize, 2), result.messages.len);
}

test "ArchiveStore: deleteOlderThan" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = ArchiveStore(MemoryBackend).init(&db, std.testing.allocator);

    try store.store("alice@example.com", "bob@example.com", "msg-001", 1000, "<m>1</m>");
    try store.store("alice@example.com", "bob@example.com", "msg-002", 2000, "<m>2</m>");
    try store.store("alice@example.com", "bob@example.com", "msg-003", 3000, "<m>3</m>");

    const deleted = try store.deleteOlderThan("alice@example.com", 2500);
    try std.testing.expectEqual(@as(u32, 2), deleted);

    // Only msg-003 should remain
    const msg = try store.getMessage("alice@example.com", 3000, "msg-003");
    defer if (msg) |m| std.testing.allocator.free(m);
    try std.testing.expect(msg != null);

    const gone = try store.getMessage("alice@example.com", 1000, "msg-001");
    try std.testing.expect(gone == null);
}

test "ArchiveStore: separate owners" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = ArchiveStore(MemoryBackend).init(&db, std.testing.allocator);

    try store.store("alice@example.com", "bob@example.com", "msg-001", 1000, "<m>alice</m>");
    try store.store("bob@example.com", "alice@example.com", "msg-002", 1000, "<m>bob</m>");

    var result_alice = try store.query("alice@example.com", .{});
    defer freeQueryResult(std.testing.allocator, &result_alice);
    try std.testing.expectEqual(@as(usize, 1), result_alice.messages.len);

    var result_bob = try store.query("bob@example.com", .{});
    defer freeQueryResult(std.testing.allocator, &result_bob);
    try std.testing.expectEqual(@as(usize, 1), result_bob.messages.len);
}
