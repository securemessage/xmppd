//! # Generic OfflineStore (Step 10g)
//!
//! Stores offline message delivery pointers in the operational storage backend.
//! Archive rows and optional held payloads carry the stanza bytes.
//!
//! ## Key Schema
//!
//! Current namespace: `offline_v2`
//! Key: `recipient_bare_jid\x00sequence_be(8)`
//! Value: `timestamp_be(8) || stanza_id_len_be(4) || stanza_id || from_jid`
//!
//! Legacy `offline` timestamp/id rows remain readable and drain before v2 rows.
//!
//! ## Lifecycle
//!
//! 1. Message arrives for unavailable user
//! 2. Stanza stored in ArchiveStore (normal MAM write)
//! 3. Pointer stored here: (recipient, sequence) -> archive metadata and sender
//! 4. User reconnects -> scan pointers -> fetch held payload or archive row -> deliver -> delete pointers

const std = @import("std");
const backend = @import("backend");
/// LMDB key size limit (MDB_MAXKEYSIZE); mirrors store/keys.zig.
const MAX_KEY_LEN = 511;

/// Full-prefix test for an iterator result. The LMDB and RocksDB iterators
/// clip the scan prefix to 256 bytes, while v2 keys accept recipients up to
/// 502 bytes, so a long recipient's scan also returns the rows of every
/// recipient that shares its first 256 bytes. Every consumer of an iterator
/// therefore re-checks the untruncated prefix before counting, parsing or
/// collecting a key.
fn keyHasPrefix(key: []const u8, prefix: []const u8) bool {
    return std.mem.startsWith(u8, key, prefix);
}

pub const NS_OFFLINE = backend.registered("offline");
pub const NS_OFFLINE_HOLD = backend.registered("offline_hold");
pub const NS_OFFLINE_V2 = backend.registered("offline_v2");
pub const NS_OFFLINE_HOLD_V2 = backend.registered("offline_hold_v2");
pub const NS_OFFLINE_SEQ = backend.registered("offline_seq");

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
    /// Server-minted insertion order. Zero identifies a legacy timestamp row.
    sequence: u64 = 0,
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
            return self.storeInternal(recipient, from_jid, stanza_id, timestamp, null);
        }

        /// Store a delivery pointer together with the stanza payload it
        /// delivers. Returns false if the user's queue is full.
        pub fn storeHeldPointer(
            self: *Self,
            recipient: []const u8,
            from_jid: []const u8,
            stanza_id: []const u8,
            timestamp: u64,
            stanza_xml: []const u8,
        ) !bool {
            return self.storeInternal(recipient, from_jid, stanza_id, timestamp, stanza_xml);
        }

        /// Read back a payload stored by `storeHeldPointer`. Null when this
        /// pointer carries no held copy.
        pub fn getHeldStanza(self: *Self, ptr: OfflinePointer) !?[]u8 {
            self.db.compound_mutex.lock();
            defer self.db.compound_mutex.unlock();
            const is_v2 = ptr.sequence != 0;
            const key = if (is_v2)
                try self.buildV2Key(ptr.recipient, ptr.sequence)
            else
                try self.buildLegacyKey(ptr.recipient, ptr.timestamp, ptr.stanza_id);
            defer self.allocator.free(key);
            return self.db.get(self.allocator, if (is_v2) NS_OFFLINE_HOLD_V2 else NS_OFFLINE_HOLD, key);
        }

        /// Count pending offline messages for a recipient.
        pub fn countMessages(self: *Self, recipient: []const u8) !usize {
            self.db.compound_mutex.lock();
            defer self.db.compound_mutex.unlock();
            return self.countMessagesLocked(recipient);
        }

        /// Get all pending offline pointers for a recipient. Legacy rows sort
        /// first by timestamp and id; sequenced rows follow in insertion order.
        /// Caller owns the returned slice and each pointer's fields.
        pub fn getPointers(self: *Self, recipient: []const u8) ![]OfflinePointer {
            self.db.compound_mutex.lock();
            defer self.db.compound_mutex.unlock();
            const prefix = try self.buildRecipientPrefix(recipient);
            defer self.allocator.free(prefix);

            var pointers = std.ArrayListUnmanaged(OfflinePointer){};
            errdefer self.deinitPointerList(&pointers);
            try self.appendLegacyPointers(recipient, prefix, &pointers);
            const legacy_count = pointers.items.len;
            try self.appendV2Pointers(recipient, prefix, &pointers);
            std.sort.heap(OfflinePointer, pointers.items[0..legacy_count], {}, legacyBefore);
            std.sort.heap(OfflinePointer, pointers.items[legacy_count..], {}, sequenceBefore);
            return try pointers.toOwnedSlice(self.allocator);
        }

        /// Delete a specific offline pointer after successful delivery.
        /// Also drops any held payload stored with it.
        pub fn deletePointer(self: *Self, ptr: OfflinePointer) !void {
            self.db.compound_mutex.lock();
            defer self.db.compound_mutex.unlock();
            const is_v2 = ptr.sequence != 0;
            const key = if (is_v2)
                try self.buildV2Key(ptr.recipient, ptr.sequence)
            else
                try self.buildLegacyKey(ptr.recipient, ptr.timestamp, ptr.stanza_id);
            defer self.allocator.free(key);

            var batch = try self.db.writeBatch();
            errdefer batch.abort();
            try batch.delete(if (is_v2) NS_OFFLINE_HOLD_V2 else NS_OFFLINE_HOLD, key);
            try batch.delete(if (is_v2) NS_OFFLINE_V2 else NS_OFFLINE, key);
            try batch.commit();
        }

        /// Delete all offline pointers for a recipient (after full delivery).
        pub fn clearAll(self: *Self, recipient: []const u8) !void {
            self.db.compound_mutex.lock();
            defer self.db.compound_mutex.unlock();
            const prefix = try self.buildRecipientPrefix(recipient);
            defer self.allocator.free(prefix);

            var keys = std.ArrayListUnmanaged(StoredKey){};
            defer {
                for (keys.items) |item| self.allocator.free(item.key);
                keys.deinit(self.allocator);
            }
            try self.collectKeys(NS_OFFLINE, prefix, false, &keys);
            try self.collectKeys(NS_OFFLINE_V2, prefix, true, &keys);
            if (keys.items.len == 0) return;

            var batch = try self.db.writeBatch();
            {
                // Abort only delete failures; commit destroys the batch on
                // both success and failure.
                errdefer batch.abort();
                for (keys.items) |item| {
                    try batch.delete(if (item.is_v2) NS_OFFLINE_HOLD_V2 else NS_OFFLINE_HOLD, item.key);
                    try batch.delete(if (item.is_v2) NS_OFFLINE_V2 else NS_OFFLINE, item.key);
                }
            }
            try batch.commit();
        }

        /// Free a slice of OfflinePointers returned by getPointers.
        pub fn freePointers(self: *Self, pointers: []OfflinePointer) void {
            for (pointers) |ptr| self.freePointer(ptr);
            self.allocator.free(pointers);
        }

        // -- Internal --

        const StoredKey = struct { key: []u8, is_v2: bool };

        fn storeInternal(
            self: *Self,
            recipient: []const u8,
            from_jid: []const u8,
            stanza_id: []const u8,
            timestamp: u64,
            stanza_xml: ?[]const u8,
        ) !bool {
            self.db.compound_mutex.lock();
            defer self.db.compound_mutex.unlock();
            if (try self.countMessagesLocked(recipient) >= MAX_PER_USER) return false;

            const sequence = try self.nextSequenceLocked(recipient);
            const key = try self.buildV2Key(recipient, sequence);
            defer self.allocator.free(key);
            const value = try self.buildValue(from_jid, stanza_id, timestamp);
            defer self.allocator.free(value);
            var sequence_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &sequence_bytes, sequence, .big);

            var batch = try self.db.writeBatch();
            errdefer batch.abort();
            try batch.put(NS_OFFLINE_SEQ, recipient, &sequence_bytes);
            try batch.put(NS_OFFLINE_V2, key, value);
            if (stanza_xml) |xml| try batch.put(NS_OFFLINE_HOLD_V2, key, xml);
            try batch.commit();
            return true;
        }

        fn nextSequenceLocked(self: *Self, recipient: []const u8) !u64 {
            const raw = try self.db.get(self.allocator, NS_OFFLINE_SEQ, recipient);
            defer if (raw) |value| self.allocator.free(value);
            const previous = if (raw) |value| blk: {
                if (value.len != 8) return error.InvalidOfflineSequence;
                break :blk std.mem.readInt(u64, value[0..8], .big);
            } else 0;
            if (previous == std.math.maxInt(u64)) return error.OfflineSequenceExhausted;
            return previous + 1;
        }

        fn countMessagesLocked(self: *Self, recipient: []const u8) !usize {
            const prefix = try self.buildRecipientPrefix(recipient);
            defer self.allocator.free(prefix);
            const legacy = try self.countNamespace(NS_OFFLINE, prefix);
            return legacy + try self.countNamespace(NS_OFFLINE_V2, prefix);
        }

        fn countNamespace(self: *Self, ns: []const u8, prefix: []const u8) !usize {
            var iter = try self.db.iterator(ns, prefix);
            defer iter.deinit();
            var count: usize = 0;
            while (iter.next()) |entry| {
                if (!keyHasPrefix(entry.key, prefix)) continue;
                count += 1;
            }
            return count;
        }

        fn collectKeys(self: *Self, ns: []const u8, prefix: []const u8, is_v2: bool, keys: *std.ArrayListUnmanaged(StoredKey)) !void {
            var iter = try self.db.iterator(ns, prefix);
            defer iter.deinit();
            while (iter.next()) |entry| {
                if (!keyHasPrefix(entry.key, prefix)) continue;
                const key = try self.allocator.dupe(u8, entry.key);
                errdefer self.allocator.free(key);
                try keys.append(self.allocator, .{ .key = key, .is_v2 = is_v2 });
            }
        }

        fn appendLegacyPointers(self: *Self, recipient: []const u8, prefix: []const u8, pointers: *std.ArrayListUnmanaged(OfflinePointer)) !void {
            var iter = try self.db.iterator(NS_OFFLINE, prefix);
            defer iter.deinit();
            while (iter.next()) |entry| {
                const ptr = (try self.parseLegacyPointer(recipient, entry)) orelse continue;
                errdefer self.freePointer(ptr);
                try pointers.append(self.allocator, ptr);
            }
        }

        fn appendV2Pointers(self: *Self, recipient: []const u8, prefix: []const u8, pointers: *std.ArrayListUnmanaged(OfflinePointer)) !void {
            var iter = try self.db.iterator(NS_OFFLINE_V2, prefix);
            defer iter.deinit();
            while (iter.next()) |entry| {
                const ptr = (try self.parseV2Pointer(recipient, entry)) orelse continue;
                errdefer self.freePointer(ptr);
                try pointers.append(self.allocator, ptr);
            }
        }

        fn parseLegacyPointer(self: *Self, recipient: []const u8, entry: backend.Entry) !?OfflinePointer {
            const id_offset = recipient.len + 1 + 8 + 1;
            if (entry.key.len < id_offset) return null;
            if (!keyHasPrefix(entry.key, recipient)) return null;
            if (entry.key[recipient.len] != 0) return null;
            const owned_recipient = try self.allocator.dupe(u8, recipient);
            errdefer self.allocator.free(owned_recipient);
            const stanza_id = try self.allocator.dupe(u8, entry.key[id_offset..]);
            errdefer self.allocator.free(stanza_id);
            const from_jid = try self.allocator.dupe(u8, entry.value);
            return .{
                .recipient = owned_recipient,
                .timestamp = std.mem.readInt(u64, entry.key[recipient.len + 1 ..][0..8], .big),
                .stanza_id = stanza_id,
                .from_jid = from_jid,
                .sequence = 0,
            };
        }

        fn parseV2Pointer(self: *Self, recipient: []const u8, entry: backend.Entry) !?OfflinePointer {
            if (entry.key.len != recipient.len + 1 + 8 or entry.value.len < 12) return null;
            if (!keyHasPrefix(entry.key, recipient)) return null;
            if (entry.key[recipient.len] != 0) return null;
            const id_len = std.mem.readInt(u32, entry.value[8..12], .big);
            if (entry.value.len - 12 < id_len) return null;
            const id_end = 12 + @as(usize, id_len);
            const sequence = std.mem.readInt(u64, entry.key[recipient.len + 1 ..][0..8], .big);
            if (sequence == 0) return null;

            const owned_recipient = try self.allocator.dupe(u8, recipient);
            errdefer self.allocator.free(owned_recipient);
            const stanza_id = try self.allocator.dupe(u8, entry.value[12..id_end]);
            errdefer self.allocator.free(stanza_id);
            const from_jid = try self.allocator.dupe(u8, entry.value[id_end..]);
            return .{
                .recipient = owned_recipient,
                .timestamp = std.mem.readInt(u64, entry.value[0..8], .big),
                .stanza_id = stanza_id,
                .from_jid = from_jid,
                .sequence = sequence,
            };
        }

        fn legacyBefore(_: void, a: OfflinePointer, b: OfflinePointer) bool {
            if (a.timestamp != b.timestamp) return a.timestamp < b.timestamp;
            return std.mem.lessThan(u8, a.stanza_id, b.stanza_id);
        }

        fn sequenceBefore(_: void, a: OfflinePointer, b: OfflinePointer) bool {
            return a.sequence < b.sequence;
        }

        fn freePointer(self: *Self, ptr: OfflinePointer) void {
            self.allocator.free(@constCast(ptr.recipient));
            self.allocator.free(@constCast(ptr.stanza_id));
            self.allocator.free(@constCast(ptr.from_jid));
        }

        fn deinitPointerList(self: *Self, pointers: *std.ArrayListUnmanaged(OfflinePointer)) void {
            for (pointers.items) |ptr| self.freePointer(ptr);
            pointers.deinit(self.allocator);
        }

        fn buildLegacyKey(self: *Self, recipient: []const u8, timestamp: u64, stanza_id: []const u8) ![]u8 {
            const len = recipient.len + 1 + 8 + 1 + stanza_id.len;
            if (len > MAX_KEY_LEN) return error.KeyTooLong;
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

        fn buildV2Key(self: *Self, recipient: []const u8, sequence: u64) ![]u8 {
            const len = recipient.len + 1 + 8;
            if (len > MAX_KEY_LEN) return error.KeyTooLong;
            const key = try self.allocator.alloc(u8, len);
            @memcpy(key[0..recipient.len], recipient);
            key[recipient.len] = 0;
            std.mem.writeInt(u64, key[recipient.len + 1 ..][0..8], sequence, .big);
            return key;
        }

        fn buildValue(self: *Self, from_jid: []const u8, stanza_id: []const u8, timestamp: u64) ![]u8 {
            if (stanza_id.len > std.math.maxInt(u32)) return error.ValueTooLong;
            const id_end = std.math.add(usize, 12, stanza_id.len) catch return error.ValueTooLong;
            const len = std.math.add(usize, id_end, from_jid.len) catch return error.ValueTooLong;
            const value = try self.allocator.alloc(u8, len);
            std.mem.writeInt(u64, value[0..8], timestamp, .big);
            std.mem.writeInt(u32, value[8..12], @intCast(stanza_id.len), .big);
            @memcpy(value[12..id_end], stanza_id);
            @memcpy(value[id_end..], from_jid);
            return value;
        }

        fn buildRecipientPrefix(self: *Self, recipient: []const u8) ![]u8 {
            if (recipient.len + 1 > MAX_KEY_LEN) return error.KeyTooLong;
            const key = try self.allocator.alloc(u8, recipient.len + 1);
            @memcpy(key[0..recipient.len], recipient);
            key[recipient.len] = 0;
            return key;
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const MemoryBackend = backend.MemoryBackend;
const FailBatchBackend = backend.FailBatchBackend;

test "GenericOfflineStore: a failed clearAll batch aborts the write txn" {
    const allocator = std.testing.allocator;
    const entry = backend.Entry{ .key = "bob@us.example\x00msg-1", .value = "ptr" };

    var db = try FailBatchBackend.open("", .{});
    db.iter_entries = &.{entry};
    var store = GenericOfflineStore(FailBatchBackend).init(&db, allocator);

    // The map-full failure must propagate AND the errdefer must end the
    // batch: a leaked write txn pins the backend's writer lock.
    try std.testing.expectError(error.MapFull, store.clearAll("bob@us.example"));
    try std.testing.expectEqual(@as(usize, 1), db.aborted);
    try std.testing.expectEqual(@as(usize, 0), db.committed);
}

test "GenericOfflineStore: a failed clearAll commit is not aborted again" {
    const allocator = std.testing.allocator;
    const entry = backend.Entry{ .key = "bob@us.example\x00msg-1", .value = "ptr" };

    var db = try FailBatchBackend.open("", .{});
    db.fail_ops = false;
    db.fail_commit = true;
    db.iter_entries = &.{entry};
    var store = GenericOfflineStore(FailBatchBackend).init(&db, allocator);

    // mdb_txn_commit aborts its txn on failure: the batch is already ended
    // and abort() must not run after it (it would free env->me_txn0).
    try std.testing.expectError(error.MapFull, store.clearAll("bob@us.example"));
    try std.testing.expectEqual(@as(usize, 1), db.commit_attempts);
    try std.testing.expectEqual(@as(usize, 0), db.committed);
    try std.testing.expectEqual(@as(usize, 0), db.aborted);
    try std.testing.expectEqual(@as(usize, 0), db.abort_after_commit);
}

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

    const pointers = try store.getPointers("bob@example.com");
    defer store.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 2), pointers.len);
    try store.deletePointer(pointers[0]);

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

test "OfflineStore: S4 over-long recipient is rejected with KeyTooLong" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = GenericOfflineStore(MemoryBackend).init(&db, std.testing.allocator);

    var long_recipient: [600]u8 = undefined;
    @memset(&long_recipient, 'a');
    try std.testing.expectError(error.KeyTooLong, store.storePointer(&long_recipient, "bob@localhost", "s1", 1));
}

// S13: the payload stored alongside a pointer is what the drain reads when
// the archive row is not committed yet, so it must survive round-trips and be
// removed with the pointer it belongs to.
test "GenericOfflineStore: held payload round-trips and is deleted with its pointer" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = GenericOfflineStore(MemoryBackend).init(&db, allocator);

    const stanza = "<message from='alice@example.com' to='bob@example.com'><body>held</body></message>";
    try std.testing.expect(try store.storeHeldPointer("bob@example.com", "alice@example.com/d", "h1", 1000, stanza));

    try std.testing.expectEqual(@as(usize, 1), try store.countMessages("bob@example.com"));
    const first = try store.getPointers("bob@example.com");
    defer store.freePointers(first);
    const got = try store.getHeldStanza(first[0]);
    try std.testing.expect(got != null);
    if (got) |g| {
        try std.testing.expectEqualStrings(stanza, g);
        allocator.free(g);
    }

    try store.deletePointer(first[0]);
    try std.testing.expectEqual(@as(usize, 0), try store.countMessages("bob@example.com"));
    try std.testing.expect(try store.getHeldStanza(first[0]) == null);

    try std.testing.expect(try store.storeHeldPointer("bob@example.com", "alice@example.com/d", "h2", 2000, stanza));
    try std.testing.expect(try store.storeHeldPointer("bob@example.com", "carol@example.com/d", "h3", 3000, stanza));
    const rest = try store.getPointers("bob@example.com");
    defer store.freePointers(rest);
    try std.testing.expectEqual(@as(usize, 2), rest.len);
    try store.clearAll("bob@example.com");
    try std.testing.expectEqual(@as(usize, 0), try store.countMessages("bob@example.com"));
    try std.testing.expect(try store.getHeldStanza(rest[0]) == null);
    try std.testing.expect(try store.getHeldStanza(rest[1]) == null);
}

// S13: a pointer-only entry carries no payload, so getHeldStanza reports null
// and the caller falls back to the archive.
test "GenericOfflineStore: pointer-only entry has no held payload" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = GenericOfflineStore(MemoryBackend).init(&db, allocator);

    try std.testing.expect(try store.storePointer("bob@example.com", "alice@example.com/d", "p1", 1000));
    const pointers = try store.getPointers("bob@example.com");
    defer store.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 1), pointers.len);
    try std.testing.expect(try store.getHeldStanza(pointers[0]) == null);
}

// S13: the held pointer honors the same per-user quota as a plain pointer, and
// stores nothing when it refuses. The caller bounces instead of dropping.
test "GenericOfflineStore: held pointer honors the per-user quota" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = GenericOfflineStore(MemoryBackend).init(&db, allocator);

    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var id_buf: [16]u8 = undefined;
        const sid = std.fmt.bufPrint(&id_buf, "q{d}", .{i}) catch unreachable;
        try std.testing.expect(try store.storePointer("bob@example.com", "alice@example.com/d", sid, 1000 + @as(u64, @intCast(i))));
    }
    try std.testing.expectEqual(@as(usize, 100), try store.countMessages("bob@example.com"));

    // At quota: refused, and no payload is left behind.
    try std.testing.expect(!(try store.storeHeldPointer("bob@example.com", "alice@example.com/d", "over", 9000, "<message/>")));
    try std.testing.expectEqual(@as(usize, 100), try store.countMessages("bob@example.com"));
    var held_iter = try db.iterator(NS_OFFLINE_HOLD_V2, "bob@example.com\x00");
    defer held_iter.deinit();
    try std.testing.expect(held_iter.next() == null);
}

test "OfflineStore: S4 over-long recipient is rejected with KeyTooLong on the held path" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = GenericOfflineStore(MemoryBackend).init(&db, std.testing.allocator);

    var long_recipient: [600]u8 = undefined;
    @memset(&long_recipient, 'a');
    try std.testing.expectError(error.KeyTooLong, store.storeHeldPointer(&long_recipient, "bob@localhost", "s1", 1, "<message/>"));
}

test "GenericOfflineStore: G2 empty stanza ids remain distinct and ordered" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = GenericOfflineStore(MemoryBackend).init(&db, allocator);

    try std.testing.expect(try store.storeHeldPointer("bob@example.com", "alice@example.com/one", "", 1000, "<message id='one'/>"));
    try std.testing.expect(try store.storeHeldPointer("bob@example.com", "alice@example.com/two", "", 1000, "<message id='two'/>"));

    const pointers = try store.getPointers("bob@example.com");
    defer store.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 2), pointers.len);
    try std.testing.expectEqualStrings("alice@example.com/one", pointers[0].from_jid);
    try std.testing.expectEqualStrings("alice@example.com/two", pointers[1].from_jid);
    try std.testing.expectEqual(@as(u64, 1000), pointers[0].timestamp);
    try std.testing.expectEqualStrings("", pointers[0].stanza_id);
    try std.testing.expectEqualStrings("", pointers[1].stanza_id);
}

test "GenericOfflineStore: G2 stores sharing a backend preserve insertion order" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var first = GenericOfflineStore(MemoryBackend).init(&db, allocator);
    var second = GenericOfflineStore(MemoryBackend).init(&db, allocator);

    for (0..8) |i| {
        var from_a_buf: [32]u8 = undefined;
        const from_a = try std.fmt.bufPrint(&from_a_buf, "alice@example.com/a-{d}", .{i});
        var from_b_buf: [32]u8 = undefined;
        const from_b = try std.fmt.bufPrint(&from_b_buf, "alice@example.com/b-{d}", .{i});
        try std.testing.expect(try first.storePointer("bob@example.com", from_a, "reused-id", 2000));
        try std.testing.expect(try second.storePointer("bob@example.com", from_b, "reused-id", 2000));
    }

    const pointers = try first.getPointers("bob@example.com");
    defer first.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 16), pointers.len);
    for (0..8) |i| {
        var expected_a_buf: [32]u8 = undefined;
        const expected_a = try std.fmt.bufPrint(&expected_a_buf, "alice@example.com/a-{d}", .{i});
        var expected_b_buf: [32]u8 = undefined;
        const expected_b = try std.fmt.bufPrint(&expected_b_buf, "alice@example.com/b-{d}", .{i});
        try std.testing.expectEqualStrings(expected_a, pointers[i * 2].from_jid);
        try std.testing.expectEqualStrings(expected_b, pointers[i * 2 + 1].from_jid);
    }
}
