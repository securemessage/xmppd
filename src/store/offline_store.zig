//! # Generic OfflineStore (Step 10g)
//!
//! Stores offline message delivery pointers in the operational storage backend.
//! Actual stanza payloads live in the archive (ArchiveStore) — this store only
//! tracks which messages are pending delivery.
//!
//! ## Key Schema
//!
//! Namespace: `offline`
//! Key: `recipient_bare_jid\x00timestamp_be(8)\x00stanza_id`
//! Value: `from_jid` (sender's full JID — needed to reconstruct the <message>)
//!
//! ## Lifecycle
//!
//! 1. Message arrives for unavailable user
//! 2. Stanza stored in ArchiveStore (normal MAM write)
//! 3. Pointer stored here: (recipient, timestamp, stanza_id) → from_jid
//! 4. User reconnects → scan pointers → fetch from archive → deliver → delete pointers

const std = @import("std");
const backend = @import("backend");

const NS_OFFLINE = "offline";

/// Maximum offline messages per user.
const MAX_PER_USER = 100;

/// An offline delivery pointer — references a message in the archive.
pub const OfflinePointer = struct {
    /// Bare JID of the intended recipient.
    recipient: []const u8,
    /// Unix timestamp when the message was queued.
    timestamp: u64,
    /// Stanza ID (matches the key in ArchiveStore).
    stanza_id: []const u8,
    /// Full JID of the original sender.
    from_jid: []const u8,
};

/// Generic offline store parameterized on a StorageBackend.
pub fn GenericOfflineStore(comptime Backend: type) type {
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

        /// Store a delivery pointer for an offline message.
        /// Returns false if the user's queue is full.
        pub fn storePointer(
            self: *Self,
            recipient: []const u8,
            from_jid: []const u8,
            stanza_id: []const u8,
            timestamp: u64,
        ) !bool {
            // Check per-user limit
            const count = try self.countMessages(recipient);
            if (count >= MAX_PER_USER) return false;

            const key = try self.buildKey(recipient, timestamp, stanza_id);
            defer self.allocator.free(key);

            try self.db.put(NS_OFFLINE, key, from_jid);
            return true;
        }

        /// Count pending offline messages for a recipient.
        pub fn countMessages(self: *Self, recipient: []const u8) !usize {
            const prefix = try self.buildRecipientPrefix(recipient);
            defer self.allocator.free(prefix);

            var iter = try self.db.iterator(NS_OFFLINE, prefix);
            defer iter.deinit();

            var count: usize = 0;
            while (iter.next()) |_| {
                count += 1;
            }
            return count;
        }

        /// Get all pending offline pointers for a recipient.
        /// Caller owns the returned slice and each pointer's fields.
        pub fn getPointers(self: *Self, recipient: []const u8) ![]OfflinePointer {
            const prefix = try self.buildRecipientPrefix(recipient);
            defer self.allocator.free(prefix);

            var iter = try self.db.iterator(NS_OFFLINE, prefix);
            defer iter.deinit();

            var pointers = std.ArrayListUnmanaged(OfflinePointer){};
            while (iter.next()) |entry| {
                // Parse key: recipient\x00timestamp_be(8)\x00stanza_id
                const ts = self.extractTimestamp(entry.key, recipient.len + 1) orelse continue;
                const id_offset = recipient.len + 1 + 8 + 1;
                if (entry.key.len <= id_offset) continue;
                const stanza_id = entry.key[id_offset..];

                try pointers.append(self.allocator, .{
                    .recipient = try self.allocator.dupe(u8, recipient),
                    .timestamp = ts,
                    .stanza_id = try self.allocator.dupe(u8, stanza_id),
                    .from_jid = try self.allocator.dupe(u8, entry.value),
                });
            }

            return try pointers.toOwnedSlice(self.allocator);
        }

        /// Delete a specific offline pointer after successful delivery.
        pub fn deletePointer(
            self: *Self,
            recipient: []const u8,
            timestamp: u64,
            stanza_id: []const u8,
        ) !void {
            const key = try self.buildKey(recipient, timestamp, stanza_id);
            defer self.allocator.free(key);
            try self.db.delete(NS_OFFLINE, key);
        }

        /// Delete all offline pointers for a recipient (after full delivery).
        pub fn clearAll(self: *Self, recipient: []const u8) !void {
            const prefix = try self.buildRecipientPrefix(recipient);
            defer self.allocator.free(prefix);

            var iter = try self.db.iterator(NS_OFFLINE, prefix);
            defer iter.deinit();

            // Collect keys to delete
            var keys = std.ArrayListUnmanaged([]u8){};
            defer {
                for (keys.items) |k| self.allocator.free(k);
                keys.deinit(self.allocator);
            }

            while (iter.next()) |entry| {
                try keys.append(self.allocator, try self.allocator.dupe(u8, entry.key));
            }

            if (keys.items.len == 0) return;

            var batch = try self.db.writeBatch();
            for (keys.items) |k| {
                try batch.delete(NS_OFFLINE, k);
            }
            try batch.commit();
        }

        /// Free a slice of OfflinePointers returned by getPointers.
        pub fn freePointers(self: *Self, pointers: []OfflinePointer) void {
            for (pointers) |p| {
                self.allocator.free(@constCast(p.recipient));
                self.allocator.free(@constCast(p.stanza_id));
                self.allocator.free(@constCast(p.from_jid));
            }
            self.allocator.free(pointers);
        }

        // -- Internal --

        fn buildKey(self: *Self, recipient: []const u8, timestamp: u64, stanza_id: []const u8) ![]u8 {
            // recipient\x00timestamp_be(8)\x00stanza_id
            const len = recipient.len + 1 + 8 + 1 + stanza_id.len;
            const key = try self.allocator.alloc(u8, len);
            var pos: usize = 0;
            @memcpy(key[pos..][0..recipient.len], recipient);
            pos += recipient.len;
            key[pos] = 0;
            pos += 1;
            std.mem.writeInt(u64, key[pos..][0..8], timestamp, .big);
            pos += 8;
            key[pos] = 0;
            pos += 1;
            @memcpy(key[pos..][0..stanza_id.len], stanza_id);
            return key;
        }

        fn buildRecipientPrefix(self: *Self, recipient: []const u8) ![]u8 {
            const key = try self.allocator.alloc(u8, recipient.len + 1);
            @memcpy(key[0..recipient.len], recipient);
            key[recipient.len] = 0;
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

test "GenericOfflineStore: store and retrieve pointers" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = GenericOfflineStore(MemoryBackend).init(&db, std.testing.allocator);

    const ok1 = try store.storePointer("bob@example.com", "alice@example.com/phone", "msg-001", 1000);
    try std.testing.expect(ok1);
    const ok2 = try store.storePointer("bob@example.com", "carol@example.com/laptop", "msg-002", 2000);
    try std.testing.expect(ok2);

    const pointers = try store.getPointers("bob@example.com");
    defer store.freePointers(pointers);

    try std.testing.expectEqual(@as(usize, 2), pointers.len);
}

test "GenericOfflineStore: per-user limit" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = GenericOfflineStore(MemoryBackend).init(&db, std.testing.allocator);

    // Fill to limit
    var i: u64 = 0;
    while (i < MAX_PER_USER) : (i += 1) {
        var id_buf: [16]u8 = undefined;
        const id = std.fmt.bufPrint(&id_buf, "msg-{d:0>4}", .{i}) catch unreachable;
        const ok = try store.storePointer("bob@example.com", "alice@example.com/d", id, 1000 + i);
        try std.testing.expect(ok);
    }

    // Next one should fail
    const overflow = try store.storePointer("bob@example.com", "alice@example.com/d", "overflow", 9999);
    try std.testing.expect(!overflow);

    // Different user should work
    const other = try store.storePointer("carol@example.com", "alice@example.com/d", "ok", 1000);
    try std.testing.expect(other);
}

test "GenericOfflineStore: deletePointer" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = GenericOfflineStore(MemoryBackend).init(&db, std.testing.allocator);

    _ = try store.storePointer("bob@example.com", "alice@example.com/d", "msg-001", 1000);
    _ = try store.storePointer("bob@example.com", "alice@example.com/d", "msg-002", 2000);

    try store.deletePointer("bob@example.com", 1000, "msg-001");

    const count = try store.countMessages("bob@example.com");
    try std.testing.expectEqual(@as(usize, 1), count);
}

test "GenericOfflineStore: clearAll" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = GenericOfflineStore(MemoryBackend).init(&db, std.testing.allocator);

    _ = try store.storePointer("bob@example.com", "alice@example.com/d", "msg-001", 1000);
    _ = try store.storePointer("bob@example.com", "carol@example.com/d", "msg-002", 2000);
    _ = try store.storePointer("alice@example.com", "bob@example.com/d", "msg-003", 3000);

    try store.clearAll("bob@example.com");

    const bob_count = try store.countMessages("bob@example.com");
    try std.testing.expectEqual(@as(usize, 0), bob_count);

    // Alice's message should still be there
    const alice_count = try store.countMessages("alice@example.com");
    try std.testing.expectEqual(@as(usize, 1), alice_count);
}

test "GenericOfflineStore: countMessages" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = GenericOfflineStore(MemoryBackend).init(&db, std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), try store.countMessages("bob@example.com"));

    _ = try store.storePointer("bob@example.com", "alice@example.com/d", "msg-001", 1000);
    _ = try store.storePointer("bob@example.com", "alice@example.com/d", "msg-002", 2000);

    try std.testing.expectEqual(@as(usize, 2), try store.countMessages("bob@example.com"));
}
