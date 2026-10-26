//! # GenericOfflineStore against the real key-value backends
//!
//! The in-store tests run on `MemoryBackend`, whose iterator matches the
//! untruncated prefix. LMDB and RocksDB both clip the iterator scan prefix to
//! 256 bytes, so a recipient longer than that also sees the rows of every
//! recipient sharing its first 256 bytes. This root file drives the same store
//! over both real backends so that behavior is covered, and gives each run its
//! own temp directory so two suites never collide on a fixed path.

const std = @import("std");
const offline_store_mod = @import("generic_offline_store");

const lmdb_backend = @import("lmdb_backend");
const rocksdb_backend = @import("rocksdb_backend");

/// Two recipients with the same first 256 bytes and a different tail. The
/// shared head is longer than the iterator's prefix buffer, so a scan for one
/// of them also visits the other's rows.
const long_a = ("a" ** 290) ++ "first";
const long_b = ("a" ** 290) ++ "other";

comptime {
    std.debug.assert(long_a.len == long_b.len);
    std.debug.assert(std.mem.eql(u8, long_a[0..256], long_b[0..256]));
    std.debug.assert(!std.mem.eql(u8, long_a, long_b));
}

fn runLongRecipientCase(comptime Backend: type) !void {
    const Store = offline_store_mod.GenericOfflineStore(Backend);
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("offline");
    const path = try tmp.dir.realpathAlloc(alloc, "offline");
    defer alloc.free(path);

    var db = try Backend.open(path, .{});
    defer db.close();
    var store = Store.init(&db, alloc);

    try std.testing.expect(try store.storePointer(long_a, "sender@test.dev/r", "a-1", 1000));
    try std.testing.expect(try store.storePointer(long_b, "sender@test.dev/r", "b-1", 1001));
    try std.testing.expect(try store.storePointer(long_b, "sender@test.dev/r", "b-2", 1002));

    // Counts are per recipient, not per shared prefix.
    try std.testing.expectEqual(@as(usize, 1), try store.countMessages(long_a));
    try std.testing.expectEqual(@as(usize, 2), try store.countMessages(long_b));

    // A drain of one recipient only sees its own rows.
    const pointers_a = try store.getPointers(long_a);
    defer store.freePointers(pointers_a);
    try std.testing.expectEqual(@as(usize, 1), pointers_a.len);
    try std.testing.expectEqualStrings(long_a, pointers_a[0].recipient);
    try std.testing.expectEqualStrings("a-1", pointers_a[0].stanza_id);

    const pointers_b = try store.getPointers(long_b);
    defer store.freePointers(pointers_b);
    try std.testing.expectEqual(@as(usize, 2), pointers_b.len);
    for (pointers_b) |ptr| {
        try std.testing.expectEqualStrings(long_b, ptr.recipient);
    }

    // Clearing one recipient leaves the other's rows intact.
    try store.clearAll(long_a);
    try std.testing.expectEqual(@as(usize, 0), try store.countMessages(long_a));
    try std.testing.expectEqual(@as(usize, 2), try store.countMessages(long_b));
}

test "GenericOfflineStore/LMDB: long recipients differing after byte 256 keep separate rows (H1)" {
    try runLongRecipientCase(lmdb_backend.Backend);
}

test "GenericOfflineStore/RocksDB: long recipients differing after byte 256 keep separate rows (H1)" {
    try runLongRecipientCase(rocksdb_backend.Backend);
}

test "GenericOfflineStore: the fixture pairs really do share their first 256 bytes (H1)" {
    // If the two recipients stop sharing the first 256 bytes, the cases above
    // would pass on a store that never compares past the iterator prefix.
    try std.testing.expect(std.mem.eql(u8, long_a[0..256], long_b[0..256]));
    try std.testing.expect(!std.mem.startsWith(u8, long_b, long_a));
}
