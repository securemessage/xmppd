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

test "the LMDB offline lock catches an idle holder before env open" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "lmdb-readers" });
    defer allocator.free(path);
    try tmp.dir.makePath("lmdb-readers");

    // The child opens its own environment (so it owns its own shared lock)
    // and signals readiness before idling without any read transaction.
    const pipe_fds = try std.posix.pipe();
    const pid = try std.posix.fork();
    if (pid == 0) {
        std.posix.close(pipe_fds[0]);
        var child_env = LmdbBackend.open(path, .{}) catch std.posix.exit(1);
        defer child_env.close();
        _ = std.posix.write(pipe_fds[1], "x") catch std.posix.exit(1);
        std.posix.close(pipe_fds[1]);
        std.Thread.sleep(500 * std.time.ns_per_ms);
        std.posix.exit(0);
    }
    std.posix.close(pipe_fds[1]);
    var ready: [1]u8 = undefined;
    _ = try std.posix.read(pipe_fds[0], &ready);
    std.posix.close(pipe_fds[0]);

    var child_alive = true;
    defer if (child_alive) {
        _ = std.c.kill(pid, std.c.SIG.TERM);
        _ = std.posix.waitpid(pid, 0);
    };

    try std.testing.expectError(error.DaemonsRunning, LmdbBackend.openOffline(path, .{}));
    _ = std.c.kill(pid, std.c.SIG.TERM);
    _ = std.posix.waitpid(pid, 0);
    child_alive = false;
    var auth = try LmdbBackend.openOffline(path, .{});
    auth.close();
}

test "the LMDB offline lock survives env open and blocks a second writer" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "lmdb-lockretain" });
    defer allocator.free(path);
    try tmp.dir.makePath("lmdb-lockretain");

    var seed = try LmdbBackend.open(path, .{});
    seed.close();

    var auth = try LmdbBackend.openOffline(path, .{});
    var open = true;
    defer if (open) auth.close();
    // Closing a second descriptor after env open would release the lock;
    // a child must still be refused while the offline env is open.
    try std.testing.expectEqual(@as(u8, 'B'), try childExclusiveLockProbe(path));
    auth.close();
    open = false;
    try std.testing.expectEqual(@as(u8, 'A'), try childExclusiveLockProbe(path));
}

/// Child probe: 'A' when it acquired the byte-0 lock, 'B' when refused.
fn childExclusiveLockProbe(path: []const u8) !u8 {
    var lock_path_buf: [4096]u8 = undefined;
    const lock_path = try std.fmt.bufPrint(&lock_path_buf, "{s}/lock.mdb", .{path});
    const pipe_fds = try std.posix.pipe();
    const pid = try std.posix.fork();
    if (pid == 0) {
        std.posix.close(pipe_fds[0]);
        var file = std.fs.cwd().openFile(lock_path, .{ .mode = .read_write }) catch std.posix.exit(2);
        defer file.close();
        var lock: std.posix.Flock = .{
            .start = 0,
            .len = 1,
            .pid = 0,
            .type = std.c.F.WRLCK,
            .whence = 0,
            .sysid = 0,
        };
        const rc = std.c.fcntl(file.handle, std.c.F.SETLK, &lock);
        const byte: u8 = if (rc == 0) 'A' else 'B';
        _ = std.posix.write(pipe_fds[1], &.{byte}) catch {};
        std.posix.close(pipe_fds[1]);
        std.posix.exit(0);
    }
    std.posix.close(pipe_fds[1]);
    var result: [1]u8 = undefined;
    const count = try std.posix.read(pipe_fds[0], &result);
    std.posix.close(pipe_fds[0]);
    _ = std.posix.waitpid(pid, 0);
    if (count != 1) return error.ProbeFailed;
    return result[0];
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

test "migrate-precis merges data-only spellings and later old-spelling mail" {
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
    var offline = offline_store_mod.GenericOfflineStore(MemoryBackend).init(&op, allocator);
    _ = try offline.storePointer("naplestb@us.example", "alice@us.example/res", "id0", 1);
    var archive_store = archive_store_mod.ArchiveStore(MemoryBackend).init(&archive, allocator);
    try archive_store.store("naplestb@us.example", "alice@us.example", "id0", 1, "<message><body>first</body></message>");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const journal_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(journal_dir);

    const domains = [_][]const u8{"us.example"};
    var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer plan.deinit();
    try std.testing.expect(!plan.hasBlockingIssues());
    try migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{ .journal_dir = journal_dir });

    // Until F6 lands core still files new mail under the typed spelling.
    _ = try offline.storePointer("NaplesTB@us.example", "alice@us.example/res", "id1", 2);
    try archive_store.store("NaplesTB@us.example", "alice@us.example", "id1", 2, "<message><body>second</body></message>");

    var after = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer after.deinit();
    try std.testing.expect(!after.hasBlockingIssues());
    try std.testing.expect(after.renames.items.len > 0);
    try migrate.applyPlan(allocator, &auth, &op, &archive, &after, .{ .journal_dir = journal_dir });

    const pointers = try offline.getPointers("naplestb@us.example");
    defer offline.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 2), pointers.len);
    try expectRow(&archive, NS_MESSAGES, "naplestb@us.example\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00id1", "<message><body>second</body></message>");

    var clean = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer clean.deinit();
    try std.testing.expectEqual(@as(usize, 0), clean.renames.items.len);
    try std.testing.expect(!clean.hasBlockingIssues());
}

test "migrate-precis merges ghost data-only spellings with no users row" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;
    var auth = try MemoryBackend.open("", .{});
    defer auth.close();
    var op = try MemoryBackend.open("", .{});
    defer op.close();
    var archive = try MemoryBackend.open("", .{});
    defer archive.close();

    var offline = offline_store_mod.GenericOfflineStore(MemoryBackend).init(&op, allocator);
    _ = try offline.storePointer("Spam@us.example", "alice@us.example/res", "id1", 1);
    _ = try offline.storePointer("spam@us.example", "alice@us.example/res", "id2", 2);

    const domains = [_][]const u8{"us.example"};
    var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer plan.deinit();
    try std.testing.expect(!plan.hasBlockingIssues());
    try migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{});

    const pointers = try offline.getPointers("spam@us.example");
    defer offline.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 2), pointers.len);
    try std.testing.expect((try auth.get(allocator, NS_USERS, "spam")) == null);
}

test "migrate-precis deduplicates roster contacts and keeps the prepared row" {
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
    try roster.setItem("alice@us.example", "NaplesTB@us.example", "old", .both, false);
    try roster.setItem("alice@us.example", "naplestb@us.example", "new", .both, false);

    const domains = [_][]const u8{"us.example"};
    var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer plan.deinit();
    try std.testing.expect(!plan.hasBlockingIssues());
    var deduplicated: usize = 0;
    for (plan.issues.items) |issue| {
        if (issue.kind == .deduplicated) deduplicated += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), deduplicated);
    try migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{});

    const kept = try roster.getItem(allocator, "alice@us.example", "naplestb@us.example");
    defer if (kept) |entry| if (entry.name.len > 0) allocator.free(entry.name);
    try std.testing.expect(kept != null);
    try std.testing.expectEqualStrings("new", kept.?.name);
    try std.testing.expect((try roster.getItem(allocator, "alice@us.example", "NaplesTB@us.example")) == null);
}

test "migrate-precis forced rename frees its target for another account" {
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

    const domains = [_][]const u8{"us.example"};
    var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, .{
        .old_localpart = "bob",
        .new_localpart = "bob2",
    });
    defer plan.deinit();
    try std.testing.expect(!plan.hasBlockingIssues());
    try migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{});

    try std.testing.expect((try users.lookup(allocator, "Bob")) == null);
    try std.testing.expect((try users.lookup(allocator, "bob")) != null);
    try std.testing.expect((try users.lookup(allocator, "bob2")) != null);
}

test "migrate-precis forced rename moves references into the freed key" {
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
    var roster = roster_store_mod.RosterStore(MemoryBackend).init(&op);
    try roster.setItem("carol@us.example", "Bob@us.example", "Bob (real)", .both, false);
    try roster.setItem("carol@us.example", "bob@us.example", "bob (other)", .both, false);
    try roster.setItem("carol@us.example", "BOB@us.example", "stale", .both, false);
    var rooms = room_store_mod.RoomStore(MemoryBackend).init(&op, allocator);
    try rooms.setAffiliation("room@conference.us.example", "Bob@us.example", .owner);
    try rooms.setAffiliation("room@conference.us.example", "bob@us.example", .member);

    const domains = [_][]const u8{"us.example"};
    var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, .{
        .old_localpart = "bob",
        .new_localpart = "bob2",
    });
    defer plan.deinit();
    try std.testing.expect(!plan.hasBlockingIssues());
    var deduplicated: usize = 0;
    for (plan.issues.items) |issue| {
        if (issue.kind == .deduplicated) deduplicated += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), deduplicated);
    try migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{});

    const real = try roster.getItem(allocator, "carol@us.example", "bob@us.example");
    defer if (real) |entry| if (entry.name.len > 0) allocator.free(entry.name);
    try std.testing.expect(real != null);
    try std.testing.expectEqualStrings("Bob (real)", real.?.name);
    const other = try roster.getItem(allocator, "carol@us.example", "bob2@us.example");
    defer if (other) |entry| if (entry.name.len > 0) allocator.free(entry.name);
    try std.testing.expect(other != null);
    try std.testing.expectEqualStrings("bob (other)", other.?.name);
    try std.testing.expect((try roster.getItem(allocator, "carol@us.example", "BOB@us.example")) == null);
    try std.testing.expectEqual(room_store_mod.Affiliation.owner, try rooms.getAffiliation("room@conference.us.example", "bob@us.example"));
    try std.testing.expectEqual(room_store_mod.Affiliation.member, try rooms.getAffiliation("room@conference.us.example", "bob2@us.example"));

    var clean = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer clean.deinit();
    try std.testing.expectEqual(@as(usize, 0), clean.renames.items.len);
    try std.testing.expect(!clean.hasBlockingIssues());
}

test "migrate-precis keeps account-owned data without a users row as a collision" {
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
    var vcards = vcard_store_mod.VCardStore(MemoryBackend).init(&op);
    try vcards.set("naplestb@us.example", "<vCard/>");

    const domains = [_][]const u8{"us.example"};
    var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer plan.deinit();
    try std.testing.expect(plan.hasBlockingIssues());
}

test "migrate-precis treats subscribers, MUC members and offline senders as references" {
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
    try op.put(NS_PENDING_SUB, "alice@us.example\x00naplestb@us.example", "<presence/>");
    var rooms = room_store_mod.RoomStore(MemoryBackend).init(&op, allocator);
    try rooms.setAffiliation("room@conference.us.example", "naplestb@us.example", .member);
    var offline = offline_store_mod.GenericOfflineStore(MemoryBackend).init(&op, allocator);
    _ = try offline.storePointer("alice@us.example", "naplestb@us.example/res", "id1", 1);

    const domains = [_][]const u8{"us.example"};
    var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer plan.deinit();
    try std.testing.expect(!plan.hasBlockingIssues());
    try migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{});

    try expectRow(&op, NS_PENDING_SUB, "alice@us.example\x00naplestb@us.example", "<presence/>");
    try std.testing.expectEqual(room_store_mod.Affiliation.member, try rooms.getAffiliation("room@conference.us.example", "naplestb@us.example"));
    const pointers = try offline.getPointers("alice@us.example");
    defer offline.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 1), pointers.len);
    try std.testing.expectEqualStrings("naplestb@us.example/res", pointers[0].from_jid);
}

test "deluser --raw accepts a data-only spelling and keeps the account" {
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
    try auth.put(NS_LOCKS, "naplestb", "\x01\x00\x00\x00\x00");
    var offline = offline_store_mod.GenericOfflineStore(MemoryBackend).init(&op, allocator);
    _ = try offline.storePointer("naplestb@us.example", "alice@us.example/res", "id1", 1);

    const domains = [_][]const u8{"us.example"};
    try migrate.deleteRawAccount(allocator, &auth, &op, &archive, &domains, "naplestb");
    try std.testing.expect((try users.lookup(allocator, "NaplesTB")) != null);
    try expectRow(&auth, NS_LOCKS, "naplestb", "\x01\x00\x00\x00\x00");
    const pointers = try offline.getPointers("naplestb@us.example");
    defer offline.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 0), pointers.len);
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
    // The prepared lock belongs to the surviving account, not to Bob.
    try expectRow(&auth, NS_LOCKS, "bob", "\x01\x00\x00\x00\x00");

    // No Bob data can fold into bob's account after the cascade.
    var after = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer after.deinit();
    try std.testing.expectEqual(@as(usize, 0), after.issues.items.len);
    try migrate.applyPlan(allocator, &auth, &op, &archive, &after, .{});
    try expectMissing(&archive, NS_MESSAGES, "bob@us.example\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00id-b1");
}

const NoDeleteBackend = struct {
    inner: backend_mod.MemoryBackend,

    pub const Iterator = backend_mod.MemoryBackend.Iterator;

    pub fn open(path: []const u8, opts: backend_mod.OpenOptions) !NoDeleteBackend {
        return .{ .inner = try backend_mod.MemoryBackend.open(path, opts) };
    }

    pub fn close(self: *NoDeleteBackend) void {
        self.inner.close();
    }

    pub fn get(self: *NoDeleteBackend, allocator: std.mem.Allocator, ns: []const u8, key: []const u8) !?[]u8 {
        return self.inner.get(allocator, ns, key);
    }

    pub fn put(self: *NoDeleteBackend, ns: []const u8, key: []const u8, value: []const u8) !void {
        try self.inner.put(ns, key, value);
    }

    pub fn delete(self: *NoDeleteBackend, ns: []const u8, key: []const u8) !void {
        _ = self;
        _ = ns;
        _ = key;
    }

    pub fn iterator(self: *NoDeleteBackend, ns: []const u8, prefix: []const u8) !backend_mod.MemoryBackend.Iterator {
        return self.inner.iterator(ns, prefix);
    }

    pub const WriteBatch = struct {
        inner: backend_mod.MemoryBackend.WriteBatch,

        pub fn put(self: *WriteBatch, ns: []const u8, key: []const u8, value: []const u8) !void {
            try self.inner.put(ns, key, value);
        }

        pub fn delete(self: *WriteBatch, ns: []const u8, key: []const u8) !void {
            _ = self;
            _ = ns;
            _ = key;
        }

        pub fn commit(self: *WriteBatch) !void {
            try self.inner.commit();
        }

        pub fn abort(self: *WriteBatch) void {
            self.inner.abort();
        }
    };

    pub fn writeBatch(self: *NoDeleteBackend) !WriteBatch {
        return .{ .inner = try self.inner.writeBatch() };
    }
};

test "deluser --raw reports data that remains after an incomplete cascade" {
    const allocator = std.testing.allocator;
    var auth = try NoDeleteBackend.open("", .{});
    defer auth.close();
    var op = try NoDeleteBackend.open("", .{});
    defer op.close();
    var archive = try NoDeleteBackend.open("", .{});
    defer archive.close();

    var users = user_store_mod.UserStore(NoDeleteBackend).init(&auth);
    try users.addUser(allocator, "Bob", "pw");
    const domains = [_][]const u8{"us.example"};
    try std.testing.expectError(error.DataRemaining, migrate.deleteRawAccount(allocator, &auth, &op, &archive, &domains, "Bob"));
}

const FailingCommitBackend = struct {
    inner: backend_mod.MemoryBackend,

    pub const Iterator = backend_mod.MemoryBackend.Iterator;

    pub fn open(path: []const u8, opts: backend_mod.OpenOptions) !FailingCommitBackend {
        return .{ .inner = try backend_mod.MemoryBackend.open(path, opts) };
    }

    pub fn close(self: *FailingCommitBackend) void {
        self.inner.close();
    }

    pub fn get(self: *FailingCommitBackend, allocator: std.mem.Allocator, ns: []const u8, key: []const u8) !?[]u8 {
        return self.inner.get(allocator, ns, key);
    }

    pub fn put(self: *FailingCommitBackend, ns: []const u8, key: []const u8, value: []const u8) !void {
        try self.inner.put(ns, key, value);
    }

    pub fn delete(self: *FailingCommitBackend, ns: []const u8, key: []const u8) !void {
        try self.inner.delete(ns, key);
    }

    pub fn iterator(self: *FailingCommitBackend, ns: []const u8, prefix: []const u8) !backend_mod.MemoryBackend.Iterator {
        return self.inner.iterator(ns, prefix);
    }

    pub const WriteBatch = struct {
        inner: backend_mod.MemoryBackend.WriteBatch,

        pub fn put(self: *WriteBatch, ns: []const u8, key: []const u8, value: []const u8) !void {
            try self.inner.put(ns, key, value);
        }

        pub fn delete(self: *WriteBatch, ns: []const u8, key: []const u8) !void {
            try self.inner.delete(ns, key);
        }

        pub fn commit(self: *WriteBatch) !void {
            _ = self;
            return error.InjectedCommitFailure;
        }

        pub fn abort(self: *WriteBatch) void {
            self.inner.abort();
        }
    };

    pub fn writeBatch(self: *FailingCommitBackend) !WriteBatch {
        return .{ .inner = try self.inner.writeBatch() };
    }
};

test "migrate-precis op commit failure leaves auth unchanged" {
    const allocator = std.testing.allocator;
    var auth = try backend_mod.MemoryBackend.open("", .{});
    defer auth.close();
    var op = try FailingCommitBackend.open("", .{});
    defer op.close();
    var archive = try backend_mod.MemoryBackend.open("", .{});
    defer archive.close();

    var users = user_store_mod.UserStore(backend_mod.MemoryBackend).init(&auth);
    try users.addUser(allocator, "Bob", "pw-a");
    try users.addUser(allocator, "bob", "pw-b");
    var roster = roster_store_mod.RosterStore(FailingCommitBackend).init(&op);
    try roster.setItem("carol@us.example", "Bob@us.example", "Bob (real)", .both, false);

    const domains = [_][]const u8{"us.example"};
    var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, .{
        .old_localpart = "bob",
        .new_localpart = "bob2",
    });
    defer plan.deinit();
    try std.testing.expect(!plan.hasBlockingIssues());
    try std.testing.expectError(error.InjectedCommitFailure, migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{}));
    const bob_row = try auth.get(allocator, NS_USERS, "Bob");
    defer if (bob_row) |value| allocator.free(value);
    try std.testing.expect(bob_row != null);
    const bob2_row = try auth.get(allocator, NS_USERS, "bob2");
    defer if (bob2_row) |value| allocator.free(value);
    try std.testing.expect(bob2_row == null);
    const old_roster = try op.get(allocator, NS_ROSTERS, "carol@us.example\x00Bob@us.example");
    defer if (old_roster) |value| allocator.free(value);
    try std.testing.expect(old_roster != null);
    const new_roster = try op.get(allocator, NS_ROSTERS, "carol@us.example\x00bob@us.example");
    defer if (new_roster) |value| allocator.free(value);
    try std.testing.expect(new_roster == null);
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
