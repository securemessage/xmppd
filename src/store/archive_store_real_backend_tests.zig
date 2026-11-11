//! # ArchiveStore by_contact v2 keys against the real key-value backends
//!
//! The in-store tests run on MemoryBackend. This root file drives the
//! same-second overwrite regression (S32) and the migrate-archive rekey
//! and rebuild over LMDB, RocksDB and SQLite so the ordered, persisted
//! keyspace proves the same thing the in-memory model does.

const std = @import("std");
const backend_mod = @import("backend");
const archive_store_mod = @import("archive_store");
const migrate_archive = @import("migrate_archive");

const lmdb_backend = @import("lmdb_backend");
const rocksdb_backend = @import("rocksdb_backend");
const sqlite_backend = @import("sqlite_backend");

const NS_BY_CONTACT = backend_mod.registered("by_contact");
const NS_MESSAGES = backend_mod.registered("messages");

const alloc = std.testing.allocator;

fn freeQueryResult(result: *archive_store_mod.QueryResult) void {
    for (result.messages) |msg| {
        alloc.free(msg.stanza_id);
        if (msg.stanza_xml.len > 0) alloc.free(@constCast(msg.stanza_xml));
    }
    alloc.free(result.messages);
}

/// S32: two messages from one contact inside one second must both come
/// back from a `with` query, in stanza-id order, and still be there after
/// the backend is closed and reopened.
fn dbPath(tmp: *std.testing.TmpDir, comptime wants_file: bool) ![]u8 {
    const dir = try tmp.dir.realpathAlloc(alloc, "archive");
    if (!wants_file) return dir;
    defer alloc.free(dir);
    return std.fs.path.join(alloc, &.{ dir, "archive.db" });
}

fn sameSecondCase(comptime Backend: type, comptime wants_file: bool) !void {
    const Store = archive_store_mod.ArchiveStore(Backend);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("archive");
    const path = try dbPath(&tmp, wants_file);
    defer alloc.free(path);

    var be = try Backend.open(path, .{});
    var store = Store.init(&be, alloc);
    try store.store("alice@test.dev", "bob@test.dev", "m-001", 1700000000, "<m>first</m>");
    try store.store("alice@test.dev", "bob@test.dev", "m-002", 1700000000, "<m>second</m>");
    be.close();

    var be2 = try Backend.open(path, .{});
    defer be2.close();
    var store2 = Store.init(&be2, alloc);

    var result = try store2.query("alice@test.dev", .{ .with = "bob@test.dev" });
    defer freeQueryResult(&result);
    try std.testing.expectEqual(@as(usize, 2), result.messages.len);
    try std.testing.expectEqualStrings("m-001", result.messages[0].stanza_id);
    try std.testing.expectEqualStrings("m-002", result.messages[1].stanza_id);
}

test "ArchiveStore/LMDB: S32 same-second contact messages both return, in order" {
    try sameSecondCase(lmdb_backend.Backend, false);
}

test "ArchiveStore/RocksDB: S32 same-second contact messages both return, in order" {
    try sameSecondCase(rocksdb_backend.Backend, false);
}

test "ArchiveStore/SQLite: S32 same-second contact messages both return, in order" {
    try sameSecondCase(sqlite_backend.Backend, true);
}

fn putV1Contact(db: anytype, owner: []const u8, with: []const u8, timestamp: u64, stanza_id: []const u8) !void {
    var key: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&key);
    const w = fbs.writer();
    try w.writeAll(owner);
    try w.writeByte(0);
    try w.writeAll(with);
    try w.writeByte(0);
    var tsb: [8]u8 = undefined;
    std.mem.writeInt(u64, &tsb, timestamp, .big);
    try w.writeAll(&tsb);
    try db.put(NS_BY_CONTACT, fbs.getWritten(), stanza_id);
}

fn putMessage(db: anytype, owner: []const u8, timestamp: u64, stanza_id: []const u8, stanza_xml: []const u8) !void {
    var key: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&key);
    const w = fbs.writer();
    try w.writeAll(owner);
    try w.writeByte(0);
    var tsb: [8]u8 = undefined;
    std.mem.writeInt(u64, &tsb, timestamp, .big);
    try w.writeAll(&tsb);
    try w.writeByte(0);
    try w.writeAll(stanza_id);
    try db.put(NS_MESSAGES, fbs.getWritten(), stanza_xml);
}

/// The migration rekeys surviving v1 rows, rebuilds the index row the v1
/// overwrite lost, and leaves a second plan empty.
fn migrateCase(comptime Backend: type, comptime wants_file: bool) !void {
    const Store = archive_store_mod.ArchiveStore(Backend);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("archive");
    const path = try dbPath(&tmp, wants_file);
    defer alloc.free(path);
    try tmp.dir.makePath("journal");
    const journal = try tmp.dir.realpathAlloc(alloc, "journal");
    defer alloc.free(journal);

    const chat = "<message from='alice@test.dev/r1' to='bob@test.dev' type='chat' id='c1'><body>x</body></message>";

    var be = try Backend.open(path, .{});
    var store = Store.init(&be, alloc);

    // bob's recipient copy with a surviving v1 index row.
    try putMessage(&be, "bob@test.dev", 1000, "m-001", chat);
    try putV1Contact(&be, "bob@test.dev", "alice@test.dev", 1000, "m-001");

    // Two of alice's sender copies share the second: m-003 is the v1
    // survivor, m-002's index row was overwritten before the fix.
    try putMessage(&be, "alice@test.dev", 1000, "m-003", chat);
    try putV1Contact(&be, "alice@test.dev", "bob@test.dev", 1000, "m-003");
    try putMessage(&be, "alice@test.dev", 1000, "m-002", chat);

    const domains = [_][]const u8{"test.dev"};
    var plan = try migrate_archive.planMigration(alloc, &be, &domains);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 0), plan.issues.items.len);
    // rekey bob m-001, rekey alice m-003, rebuild alice m-002.
    try std.testing.expectEqual(@as(usize, 3), plan.ops.items.len);

    try migrate_archive.applyPlan(alloc, &be, &plan, journal);

    // store() wrote alice m-003's index row with the new key already; the
    // v1 survivor key is gone and the lost m-002 row is back. The scan
    // must end before the query below: an open iterator and a nested get
    // would be two live read txns on one thread, which LMDB rejects.
    {
        var v1_count: usize = 0;
        var iter = try be.iterator(NS_BY_CONTACT, "alice@test.dev\x00");
        defer iter.deinit();
        while (iter.next()) |entry| {
            if (entry.key.len == "alice@test.dev".len + 1 + "bob@test.dev".len + 1 + 8) v1_count += 1;
        }
        try std.testing.expectEqual(@as(usize, 0), v1_count);
    }

    var result = try store.query("alice@test.dev", .{ .with = "bob@test.dev" });
    defer freeQueryResult(&result);
    try std.testing.expectEqual(@as(usize, 2), result.messages.len);

    // A second plan finds nothing left to do.
    var plan2 = try migrate_archive.planMigration(alloc, &be, &domains);
    defer plan2.deinit();
    try std.testing.expectEqual(@as(usize, 0), plan2.ops.items.len);

    be.close();
}

test "migrate-archive/LMDB: rekey survivors and rebuild lost rows" {
    try migrateCase(lmdb_backend.Backend, false);
}

test "migrate-archive/RocksDB: rekey survivors and rebuild lost rows" {
    try migrateCase(rocksdb_backend.Backend, false);
}

test "migrate-archive/SQLite: rekey survivors and rebuild lost rows" {
    try migrateCase(sqlite_backend.Backend, true);
}
