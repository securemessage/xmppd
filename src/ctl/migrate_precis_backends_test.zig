const std = @import("std");
const backend_mod = @import("backend");
const migrate = @import("migrate_precis");
const user_store_mod = @import("user_store");
const roster_store_mod = @import("roster_store");
const archive_store_mod = @import("archive_store");
const lock_store_mod = @import("lock_store");
const block_store_mod = @import("block_store");
const vcard_store_mod = @import("vcard_store");
const pep_store_mod = @import("pep_store");
const last_activity_store_mod = @import("last_activity_store");
const offline_store_mod = @import("offline_store");
const room_store_mod = @import("room_store");
const LmdbBackend = @import("lmdb_backend").Backend;
const RocksDbBackend = @import("rocksdb_backend").Backend;

const NS_USERS = backend_mod.registered("users");
const NS_LOCKS = backend_mod.registered("locks");
const NS_ROSTERS = backend_mod.registered("rosters");
const NS_BLOCKLIST = backend_mod.registered("blocklist");
const NS_VCARDS = backend_mod.registered("vcards");
const NS_PEP = backend_mod.registered("pep");
const NS_LASTACT = backend_mod.registered("lastact");
const NS_OFFLINE = backend_mod.registered("offline");
const NS_ROOM_AFFILIATIONS = backend_mod.registered("room_affiliations");
const NS_PENDING_SUB = backend_mod.registered("pending_sub");
const NS_MESSAGES = backend_mod.registered("messages");
const NS_BY_CONTACT = backend_mod.registered("by_contact");

test "migrate-precis plans and applies on real LMDB and RocksDB" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const auth_path = try std.fs.path.join(allocator, &.{ base, "auth" });
    defer allocator.free(auth_path);
    const op_path = try std.fs.path.join(allocator, &.{ base, "op" });
    defer allocator.free(op_path);
    const archive_path = try std.fs.path.join(allocator, &.{ base, "archive" });
    defer allocator.free(archive_path);

    var auth = try LmdbBackend.open(auth_path, .{});
    defer auth.close();
    var op = try LmdbBackend.open(op_path, .{});
    defer op.close();
    var archive = try RocksDbBackend.open(archive_path, .{});
    defer archive.close();

    // Seed through the same stores that construct production keys.
    var users = user_store_mod.UserStore(LmdbBackend).init(&auth);
    try users.addUser(allocator, "NaplesTB", "pw");
    var roster = roster_store_mod.RosterStore(LmdbBackend).init(&op);
    try roster.setItem("NaplesTB@us.example", "friend@us.example", "", .both, false);
    var archive_store = archive_store_mod.ArchiveStore(RocksDbBackend).init(&archive, allocator);
    try archive_store.store("NaplesTB@us.example", "friend@remote.example", "id1", 1, "<message><body>private</body></message>");

    const domains = [_][]const u8{"us.example"};
    var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 0), plan.issues.items.len);
    try applyGuarded(&auth, &op, &archive, &plan, base, allocator);

    const users_value = try auth.get(allocator, NS_USERS, "naplestb");
    defer if (users_value) |value| allocator.free(value);
    try std.testing.expect(users_value != null);
    const roster_value = try op.get(allocator, NS_ROSTERS, "naplestb@us.example\x00friend@us.example");
    defer if (roster_value) |value| allocator.free(value);
    try std.testing.expect(roster_value != null);
    const archive_value = try archive.get(allocator, NS_MESSAGES, "naplestb@us.example\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00id1");
    defer if (archive_value) |value| allocator.free(value);
    try std.testing.expectEqualStrings("<message><body>private</body></message>", archive_value.?);
}

test "migrate-precis uses production key models for every namespace" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;
    var auth = try MemoryBackend.open("", .{});
    defer auth.close();
    var op = try MemoryBackend.open("", .{});
    defer op.close();
    var archive = try MemoryBackend.open("", .{});
    defer archive.close();

    var users = user_store_mod.UserStore(MemoryBackend).init(&auth);
    try users.addUser(allocator, "NaplesTB", "pw");
    // A pre-PRECIS lock row is intentionally seeded directly: current lock
    // writes are already canonical, so no public API can produce this legacy row.
    try auth.put(NS_LOCKS, "NaplesTB", "\x01\x00\x00\x00\x00");

    var roster = roster_store_mod.RosterStore(MemoryBackend).init(&op);
    try roster.setItem("NaplesTB@us.example", "friend@us.example", "", .both, false);
    try roster.setItem("NaplesTB@us.example", "Friend@remote.example", "", .both, false);
    try roster.setItem("NaplesTB@us.example", "remote.example", "", .both, false);
    try roster.setItem("NaplesTB@us.example", "remote.example/resource", "", .both, false);
    var blocks = block_store_mod.BlockStore(MemoryBackend).init(&op);
    try blocks.block("NaplesTB@us.example", "blocked@us.example");
    var vcards = vcard_store_mod.VCardStore(MemoryBackend).init(&op);
    try vcards.set("NaplesTB@us.example", "<vCard/>");
    var pep = pep_store_mod.PepStore(MemoryBackend).init(&op);
    try pep.publish("NaplesTB@us.example", "node", "item", "<item/>");
    try last_activity_store_mod.record(&op, "NaplesTB@us.example", 42);
    var offline = offline_store_mod.GenericOfflineStore(MemoryBackend).init(&op, allocator);
    _ = try offline.storePointer("NaplesTB@us.example", "NaplesTB@us.example/res", "id1", 1);
    var rooms = room_store_mod.RoomStore(MemoryBackend).init(&op, allocator);
    try rooms.setAffiliation("room@conference.us.example", "NaplesTB@us.example", .owner);
    // presence_handler's pending-subscription writer is private to core; its
    // documented key/value shape is the one fixture without a public store API.
    try op.put(NS_PENDING_SUB, "NaplesTB@us.example\x00friend@us.example", "<presence from='NaplesTB@us.example'/>");
    var archive_store = archive_store_mod.ArchiveStore(MemoryBackend).init(&archive, allocator);
    try archive_store.store("NaplesTB@us.example", "Friend@remote.example", "id1", 1, "<message from='NaplesTB@us.example/res'/>");

    const domains = [_][]const u8{"us.example"};
    var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 15), plan.renames.items.len);
    try std.testing.expectEqual(@as(usize, 0), plan.issues.items.len);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const journal_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(journal_dir);
    try migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{ .journal_dir = journal_dir });

    try std.testing.expect((try users.lookup(allocator, "naplestb")) != null);
    try expectRow(&auth, NS_LOCKS, "naplestb", "\x01\x00\x00\x00\x00");
    try std.testing.expect((try roster.getItem(allocator, "naplestb@us.example", "friend@us.example")) != null);
    try std.testing.expect((try roster.getItem(allocator, "naplestb@us.example", "Friend@remote.example")) != null);
    // Domain-only contacts and domain/resource are not account localparts.
    try std.testing.expect((try roster.getItem(allocator, "naplestb@us.example", "remote.example")) != null);
    try std.testing.expect((try roster.getItem(allocator, "naplestb@us.example", "remote.example/resource")) != null);
    try std.testing.expect(try blocks.isBlocked(allocator, "naplestb@us.example", "blocked@us.example"));
    try expectRow(&op, NS_VCARDS, "naplestb@us.example", "<vCard/>");
    try expectRow(&op, NS_PEP, "naplestb@us.example\x00node\x00item", "<item/>");
    try std.testing.expectEqual(@as(?u64, 42), try last_activity_store_mod.get(allocator, &op, "naplestb@us.example"));
    const pointers = try offline.getPointers("naplestb@us.example");
    defer offline.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 1), pointers.len);
    try std.testing.expectEqualStrings("naplestb@us.example/res", pointers[0].from_jid);
    try std.testing.expectEqual(room_store_mod.Affiliation.owner, try rooms.getAffiliation("room@conference.us.example", "naplestb@us.example"));
    try expectRow(&op, NS_PENDING_SUB, "naplestb@us.example\x00friend@us.example", "<presence from='NaplesTB@us.example'/>");
    try expectRow(&archive, NS_MESSAGES, "naplestb@us.example\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00id1", "<message from='NaplesTB@us.example/res'/>");
    try expectRow(&archive, NS_BY_CONTACT, "naplestb@us.example\x00Friend@remote.example\x00\x00\x00\x00\x00\x00\x00\x00\x01", "id1");

    try tmp.dir.access("migrate-precis.plan", .{});
    try tmp.dir.access("migrate-precis.journal", .{});
    var second = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer second.deinit();
    try std.testing.expectEqual(@as(usize, 0), second.renames.items.len);
    try std.testing.expectEqual(@as(usize, 0), second.issues.items.len);
}

test "migrate-precis treats users plus their prepared lock as one account" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;
    var auth = try MemoryBackend.open("", .{});
    defer auth.close();
    var op = try MemoryBackend.open("", .{});
    defer op.close();
    var archive = try MemoryBackend.open("", .{});
    defer archive.close();

    var users = user_store_mod.UserStore(MemoryBackend).init(&auth);
    try users.addUser(allocator, "NaplesTB", "pw");
    var locks = lock_store_mod.LockStore(MemoryBackend).init(&auth);
    try locks.lock("naplestb", .permanent);

    const domains = [_][]const u8{"us.example"};
    var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 0), plan.issues.items.len);
    try migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{});
    try std.testing.expect((try users.lookup(allocator, "naplestb")) != null);
    try std.testing.expect((try locks.isLocked(allocator, "naplestb")) != null);

    var second = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer second.deinit();
    try std.testing.expectEqual(@as(usize, 0), second.issues.items.len);
    try std.testing.expectEqual(@as(usize, 0), second.renames.items.len);
}

test "migrate-precis rewrites references without inventing collisions" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;
    var auth = try MemoryBackend.open("", .{});
    defer auth.close();
    var op = try MemoryBackend.open("", .{});
    defer op.close();
    var archive = try MemoryBackend.open("", .{});
    defer archive.close();

    var users = user_store_mod.UserStore(MemoryBackend).init(&auth);
    try users.addUser(allocator, "NaplesTB", "pw");
    try users.addUser(allocator, "alice", "pw");
    var roster = roster_store_mod.RosterStore(MemoryBackend).init(&op);
    try roster.setItem("alice@us.example", "naplestb@us.example", "", .both, false);
    var archive_store = archive_store_mod.ArchiveStore(MemoryBackend).init(&archive, allocator);
    try archive_store.store("alice@us.example", "naplestb@us.example", "id1", 1, "<message/>");

    const domains = [_][]const u8{"us.example"};
    var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 0), plan.issues.items.len);
    try migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{});
    try std.testing.expect((try users.lookup(allocator, "naplestb")) != null);
    try std.testing.expect((try roster.getItem(allocator, "alice@us.example", "naplestb@us.example")) != null);
    try expectRow(&archive, NS_BY_CONTACT, "alice@us.example\x00naplestb@us.example\x00\x00\x00\x00\x00\x00\x00\x00\x01", "id1");

    var second = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer second.deinit();
    try std.testing.expectEqual(@as(usize, 0), second.issues.items.len);
    try std.testing.expectEqual(@as(usize, 0), second.renames.items.len);
}

test "migrate-precis detects identity collisions on data and raw deletion cascades" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;
    var auth = try MemoryBackend.open("", .{});
    defer auth.close();
    var op = try MemoryBackend.open("", .{});
    defer op.close();
    var archive = try MemoryBackend.open("", .{});
    defer archive.close();

    var users = user_store_mod.UserStore(MemoryBackend).init(&auth);
    try users.addUser(allocator, "Bob", "pw-a");
    try users.addUser(allocator, "bob", "pw-b");
    try auth.put(NS_LOCKS, "bob", "\x01\x00\x00\x00\x00");
    var roster = roster_store_mod.RosterStore(MemoryBackend).init(&op);
    try roster.setItem("Bob@us.example", "friend@us.example", "", .both, false);
    try roster.setItem("carol@us.example", "Bob@us.example", "", .both, false);
    var blocks = block_store_mod.BlockStore(MemoryBackend).init(&op);
    try blocks.block("Bob@us.example", "spam@remote.example");
    var vcards = vcard_store_mod.VCardStore(MemoryBackend).init(&op);
    try vcards.set("Bob@us.example", "<vCard><FN>Bob private</FN></vCard>");
    try vcards.set("bob@us.example", "<vCard><FN>bob public</FN></vCard>");
    var pep = pep_store_mod.PepStore(MemoryBackend).init(&op);
    try pep.publish("Bob@us.example", "node", "item", "<item/>");
    try last_activity_store_mod.record(&op, "Bob@us.example", 42);
    var offline = offline_store_mod.GenericOfflineStore(MemoryBackend).init(&op, allocator);
    _ = try offline.storePointer("carol@us.example", "Bob@us.example/res", "id-x", 1);
    var rooms = room_store_mod.RoomStore(MemoryBackend).init(&op, allocator);
    try rooms.setAffiliation("room@conference.us.example", "Bob@us.example", .owner);
    try op.put(NS_PENDING_SUB, "carol@us.example\x00Bob@us.example", "<presence/>");
    var archive_store = archive_store_mod.ArchiveStore(MemoryBackend).init(&archive, allocator);
    try archive_store.store("Bob@us.example", "friend@us.example", "id-b1", 1, "<message><body>Bob private history</body></message>");

    const domains = [_][]const u8{"us.example"};
    var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer plan.deinit();
    // The collision is not confined to the users row: Bob's roster, vCard,
    // archive and other account-bearing rows all disagree with bob's identity.
    try std.testing.expect(plan.issues.items.len >= 4);
    try std.testing.expectError(error.MigrationBlocked, migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{}));

    try migrate.deleteRawAccount(allocator, &auth, &op, &archive, &domains, "Bob");
    try std.testing.expect((try users.lookup(allocator, "Bob")) == null);
    try std.testing.expect((try users.lookup(allocator, "bob")) != null);
    try std.testing.expect((try roster.getItem(allocator, "Bob@us.example", "friend@us.example")) == null);
    try std.testing.expect((try roster.getItem(allocator, "carol@us.example", "Bob@us.example")) == null);
    try std.testing.expect(!try blocks.isBlocked(allocator, "Bob@us.example", "spam@remote.example"));
    try std.testing.expect((try vcards.get(allocator, "Bob@us.example")) == null);
    const public_vcard = try vcards.get(allocator, "bob@us.example");
    defer if (public_vcard) |value| allocator.free(value);
    try std.testing.expect(public_vcard != null);
    try std.testing.expect((try pep.getItem(allocator, "Bob@us.example", "node", "item")) == null);
    try std.testing.expectEqual(@as(?u64, null), try last_activity_store_mod.get(allocator, &op, "Bob@us.example"));
    const carol_pointers = try offline.getPointers("carol@us.example");
    defer offline.freePointers(carol_pointers);
    try std.testing.expectEqual(@as(usize, 0), carol_pointers.len);
    try std.testing.expectEqual(room_store_mod.Affiliation.none, try rooms.getAffiliation("room@conference.us.example", "Bob@us.example"));
    try expectMissing(&op, NS_PENDING_SUB, "carol@us.example\x00Bob@us.example");
    try expectMissing(&archive, NS_MESSAGES, "Bob@us.example\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00id-b1");
    try expectMissing(&auth, NS_LOCKS, "bob");

    // No Bob data can fold into bob's account after the cascade.
    var after = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer after.deinit();
    try std.testing.expectEqual(@as(usize, 0), after.issues.items.len);
    try migrate.applyPlan(allocator, &auth, &op, &archive, &after, .{});
    try expectMissing(&archive, NS_MESSAGES, "bob@us.example\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00id-b1");
}

fn expectMissing(backend: anytype, namespace: []const u8, key: []const u8) !void {
    const stored = try backend.get(std.testing.allocator, namespace, key);
    defer if (stored) |bytes| std.testing.allocator.free(bytes);
    try std.testing.expect(stored == null);
}

fn expectRow(backend: anytype, namespace: []const u8, key: []const u8, value: []const u8) !void {
    const stored = try backend.get(std.testing.allocator, namespace, key);
    defer if (stored) |bytes| std.testing.allocator.free(bytes);
    try std.testing.expect(stored != null);
    try std.testing.expectEqualStrings(value, stored.?);
}

fn applyGuarded(auth: anytype, op: anytype, archive: anytype, plan: *const migrate.Plan, journal_dir: []const u8, allocator: std.mem.Allocator) !void {
    try migrate.applyPlan(allocator, auth, op, archive, plan, .{ .journal_dir = journal_dir });
}
