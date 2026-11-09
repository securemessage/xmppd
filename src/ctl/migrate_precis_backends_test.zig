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
const NS_OFFLINE_V2 = backend_mod.registered("offline_v2");
const NS_OFFLINE_SEQ = backend_mod.registered("offline_seq");
const NS_ROOM_AFFILIATIONS = backend_mod.registered("room_affiliations");
const NS_PENDING_SUB = backend_mod.registered("pending_sub");
const NS_MESSAGES = backend_mod.registered("messages");
const NS_BY_CONTACT = backend_mod.registered("by_contact");

fn legacyOfflineKey(
    allocator: std.mem.Allocator,
    owner: []const u8,
    timestamp: u64,
    stanza_id: []const u8,
) ![]u8 {
    const key = try allocator.alloc(u8, owner.len + 1 + 8 + 1 + stanza_id.len);
    @memcpy(key[0..owner.len], owner);
    key[owner.len] = 0;
    std.mem.writeInt(u64, key[owner.len + 1 ..][0..8], timestamp, .big);
    key[owner.len + 1 + 8] = 0;
    @memcpy(key[owner.len + 1 + 8 + 1 ..], stanza_id);
    return key;
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
    // a child must still be refused while the offline env is open. The read
    // probe pins the post-open exclusive re-take: a downgraded shared lock
    // would let a second reader in.
    try std.testing.expectEqual(@as(u8, 'B'), try childLockProbe(path, std.c.F.WRLCK));
    try std.testing.expectEqual(@as(u8, 'B'), try childLockProbe(path, std.c.F.RDLCK));
    auth.close();
    open = false;
    try std.testing.expectEqual(@as(u8, 'A'), try childLockProbe(path, std.c.F.WRLCK));
    try std.testing.expectEqual(@as(u8, 'A'), try childLockProbe(path, std.c.F.RDLCK));
}

test "a daemon starting during an offline hold must be restarted" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fs.path.join(allocator, &.{ base, "lmdb-lateopen" });
    defer allocator.free(path);
    try tmp.dir.makePath("lmdb-lateopen");

    var seed = try LmdbBackend.open(path, .{});
    seed.close();

    var auth = try LmdbBackend.openOffline(path, .{});
    var open = true;
    defer if (open) auth.close();

    const pid = try std.posix.fork();
    if (pid == 0) {
        var env = LmdbBackend.open(path, .{}) catch std.posix.exit(2);
        defer env.close();
        env.put(NS_LOCKS, "late", "1") catch std.posix.exit(3);
        std.posix.exit(0);
    }
    // The child is blocked in mdb_env_open while the offline lock is held.
    std.Thread.sleep(250 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(c_int, 0), std.c.kill(pid, 0));
    auth.close();
    open = false;
    _ = std.posix.waitpid(pid, 0);

    // The late opener may fail with EINVAL after the closer destroys LMDB's
    // shared mutexes; either way it must not have written.
    var check = try LmdbBackend.open(path, .{});
    defer check.close();
    const marker = try check.get(allocator, NS_LOCKS, "late");
    defer if (marker) |value| allocator.free(value);
    try std.testing.expect(marker == null);
}

/// Child probe: 'A' when it acquired the byte-0 lock, 'B' when refused.
fn childLockProbe(path: []const u8, lock_type: i16) !u8 {
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
            .type = lock_type,
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
    try std.testing.expectEqual(@as(usize, 16), plan.renames.items.len);
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
    try users.addUser(allocator, "carol", "pw-c");
    var roster = roster_store_mod.RosterStore(MemoryBackend).init(&op);
    try roster.setItem("carol@us.example", "Bob@us.example", "Bob (real)", .both, false);
    try roster.setItem("carol@us.example", "bob@us.example", "bob (other)", .both, false);
    try roster.setItem("carol@us.example", "BOB@us.example", "stale", .both, false);
    var blocks = block_store_mod.BlockStore(MemoryBackend).init(&op);
    try blocks.block("carol@us.example", "Bob@us.example");
    try blocks.block("carol@us.example", "BOB@us.example");
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
    try std.testing.expectEqual(@as(usize, 2), deduplicated);
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
    try std.testing.expect(try blocks.isBlocked(allocator, "carol@us.example", "bob@us.example"));
    try std.testing.expectEqual(room_store_mod.Affiliation.owner, try rooms.getAffiliation("room@conference.us.example", "bob@us.example"));
    try std.testing.expectEqual(room_store_mod.Affiliation.member, try rooms.getAffiliation("room@conference.us.example", "bob2@us.example"));

    var clean = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer clean.deinit();
    try std.testing.expectEqual(@as(usize, 0), clean.renames.items.len);
    try std.testing.expect(!clean.hasBlockingIssues());
}

test "migrate-precis merges same-second archive and duplicate subscription rows" {
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
    var archive_store = archive_store_mod.ArchiveStore(MemoryBackend).init(&archive, allocator);
    try archive_store.store("NaplesTB@us.example", "alice@us.example", "id1", 1, "<message><body>one</body></message>");
    try archive_store.store("naplestb@us.example", "alice@us.example", "id2", 1, "<message><body>two</body></message>");
    try op.put(NS_PENDING_SUB, "NaplesTB@us.example\x00remote@remote.example", "<presence>one</presence>");
    try op.put(NS_PENDING_SUB, "naplestb@us.example\x00remote@remote.example", "<presence>two</presence>");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const journal_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(journal_dir);

    const domains = [_][]const u8{"us.example"};
    var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer plan.deinit();
    try std.testing.expect(!plan.hasBlockingIssues());
    try migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{ .journal_dir = journal_dir });

    try expectRow(&op, NS_PENDING_SUB, "naplestb@us.example\x00remote@remote.example", "<presence>two</presence>");
    try expectRow(&archive, NS_BY_CONTACT, "naplestb@us.example\x00alice@us.example\x00\x00\x00\x00\x00\x00\x00\x00\x01", "id2");
    try expectRow(&archive, NS_MESSAGES, "naplestb@us.example\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00id1", "<message><body>one</body></message>");
    try expectRow(&archive, NS_MESSAGES, "naplestb@us.example\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00id2", "<message><body>two</body></message>");
}

test "migrate-precis missing auth source fails before the op commit" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;
    var auth = try MemoryBackend.open("", .{});
    defer auth.close();
    var op = try MemoryBackend.open("", .{});
    defer op.close();
    var archive = try MemoryBackend.open("", .{});
    defer archive.close();

    var users = user_store_mod.UserStore(MemoryBackend).init(&auth);
    try users.addUser(allocator, "Bob", "pw");
    try users.addUser(allocator, "bob", "pw");
    var roster = roster_store_mod.RosterStore(MemoryBackend).init(&op);
    try roster.setItem("carol@us.example", "Bob@us.example", "Bob", .both, false);

    const domains = [_][]const u8{"us.example"};
    var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, .{
        .old_localpart = "bob",
        .new_localpart = "bob2",
    });
    defer plan.deinit();
    const before = try op.get(allocator, NS_ROSTERS, "carol@us.example\x00Bob@us.example");
    defer if (before) |value| allocator.free(value);
    try std.testing.expect(before != null);
    try auth.delete(NS_USERS, "Bob");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dir);
    try std.testing.expectError(error.MissingSourceRow, migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{ .journal_dir = dir }));
    const after = try op.get(allocator, NS_ROSTERS, "carol@us.example\x00Bob@us.example");
    defer if (after) |value| allocator.free(value);
    try std.testing.expect(after != null);
    try std.testing.expectEqualSlices(u8, before.?, after.?);
}

test "migrate-precis auth dependency cycle fails before the op commit" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;
    var auth = try MemoryBackend.open("", .{});
    defer auth.close();
    var op = try MemoryBackend.open("", .{});
    defer op.close();
    var archive = try MemoryBackend.open("", .{});
    defer archive.close();
    try auth.put(NS_USERS, "a", "1");
    try auth.put(NS_USERS, "b", "2");
    try op.put(NS_ROSTERS, "carol@us.example\x00a@us.example", "old");

    var plan = migrate.Plan.init(allocator);
    defer plan.deinit();
    const a_old = try allocator.dupe(u8, "a");
    const a_new = try allocator.dupe(u8, "b");
    const b_old = try allocator.dupe(u8, "b");
    const b_new = try allocator.dupe(u8, "a");
    const op_old = try allocator.dupe(u8, "carol@us.example\x00a@us.example");
    const op_new = try allocator.dupe(u8, "carol@us.example\x00b@us.example");
    try plan.renames.append(allocator, .{ .db = .auth, .namespace = NS_USERS, .old_key = a_old, .new_key = a_new, .new_value = null, .same_key = false, .value_len = 0 });
    try plan.renames.append(allocator, .{ .db = .auth, .namespace = NS_USERS, .old_key = b_old, .new_key = b_new, .new_value = null, .same_key = false, .value_len = 0 });
    try plan.renames.append(allocator, .{ .db = .op, .namespace = NS_ROSTERS, .old_key = op_old, .new_key = op_new, .new_value = null, .same_key = false, .value_len = 3 });
    plan.rename_bytes = 6;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dir);
    try std.testing.expectError(error.RenameCycle, migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{ .journal_dir = dir }));
    try expectRow(&op, NS_ROSTERS, "carol@us.example\x00a@us.example", "old");
}

test "migrate-precis rekeys colliding offline and archive rows with different values" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;
    const Shape = enum { legacy, v2 };
    for ([_]Shape{ .legacy, .v2 }) |shape| {
        for ([_][]const u8{ "offline", "1", "offline-mig-1" }) |stanza_id| {
            var auth = try MemoryBackend.open("", .{});
            defer auth.close();
            var op = try MemoryBackend.open("", .{});
            defer op.close();
            var archive = try MemoryBackend.open("", .{});
            defer archive.close();

            var users = user_store_mod.UserStore(MemoryBackend).init(&auth);
            try users.addUser(allocator, "NaplesTB", "pw");
            try users.addUser(allocator, "alice", "pw");
            var offline = offline_store_mod.GenericOfflineStore(MemoryBackend).init(&op, allocator);
            switch (shape) {
                .legacy => {
                    const key_real = try std.fmt.allocPrint(allocator, "NaplesTB@us.example\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00{s}", .{stanza_id});
                    defer allocator.free(key_real);
                    const key_spam = try std.fmt.allocPrint(allocator, "naplestb@us.example\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00{s}", .{stanza_id});
                    defer allocator.free(key_spam);
                    try op.put(NS_OFFLINE, key_real, "alice@us.example/res");
                    try op.put(NS_OFFLINE, key_spam, "remote@remote.example/res");
                },
                .v2 => {
                    _ = try offline.storePointer("NaplesTB@us.example", "alice@us.example/res", stanza_id, 1);
                    _ = try offline.storePointer("naplestb@us.example", "remote@remote.example/res", stanza_id, 1);
                },
            }
            var archive_store = archive_store_mod.ArchiveStore(MemoryBackend).init(&archive, allocator);
            try archive_store.store("NaplesTB@us.example", "alice@us.example", stanza_id, 1, "<message><body>REAL ACCOUNT MSG</body></message>");
            try archive_store.store("naplestb@us.example", "remote@remote.example", stanza_id, 1, "<message><body>spam to lowercase spelling</body></message>");

            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            const journal_dir = try tmp.dir.realpathAlloc(allocator, ".");
            defer allocator.free(journal_dir);

            const domains = [_][]const u8{"us.example"};
            var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
            defer plan.deinit();
            try std.testing.expect(!plan.hasBlockingIssues());
            var rekeyed: usize = 0;
            for (plan.issues.items) |issue| if (issue.kind == .rekeyed) {
                rekeyed += 1;
            };
            try std.testing.expect(rekeyed >= 2);
            try migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{ .journal_dir = journal_dir });

            const pointers = try offline.getPointers("naplestb@us.example");
            defer offline.freePointers(pointers);
            try std.testing.expectEqual(@as(usize, 2), pointers.len);
            var saw_real_sender = false;
            var saw_spam_sender = false;
            for (pointers) |pointer| {
                if (std.mem.eql(u8, pointer.from_jid, "alice@us.example/res")) saw_real_sender = true;
                if (std.mem.eql(u8, pointer.from_jid, "remote@remote.example/res")) saw_spam_sender = true;
            }
            try std.testing.expect(saw_real_sender and saw_spam_sender);
            for (pointers) |pointer| {
                const held = try offline.getHeldStanza(pointer);
                defer if (held) |value| allocator.free(value);
                try std.testing.expect(held == null);
                const body = try archive_store.getMessage("naplestb@us.example", pointer.timestamp, pointer.stanza_id);
                defer if (body) |value| allocator.free(value);
                try std.testing.expect(body != null);
                if (std.mem.eql(u8, pointer.from_jid, "alice@us.example/res")) {
                    try std.testing.expect(std.mem.indexOf(u8, body.?, "REAL ACCOUNT MSG") != null);
                } else {
                    try std.testing.expect(std.mem.indexOf(u8, body.?, "spam to lowercase spelling") != null);
                }
            }
            var by_contact = try archive.iterator(NS_BY_CONTACT, "naplestb@us.example\x00alice@us.example\x00");
            defer by_contact.deinit();
            var saw_alice_index = false;
            while (by_contact.next()) |entry| {
                const body = try archive_store.getMessage("naplestb@us.example", 1, entry.value);
                defer if (body) |value| allocator.free(value);
                if (body != null and std.mem.indexOf(u8, body.?, "REAL ACCOUNT MSG") != null) saw_alice_index = true;
            }
            try std.testing.expect(saw_alice_index);

            var messages = try archive.iterator(NS_MESSAGES, "naplestb@us.example\x00");
            defer messages.deinit();
            var saw_real_body = false;
            var saw_spam_body = false;
            while (messages.next()) |entry| {
                if (std.mem.indexOf(u8, entry.value, "REAL ACCOUNT MSG") != null) saw_real_body = true;
                if (std.mem.indexOf(u8, entry.value, "spam to lowercase spelling") != null) saw_spam_body = true;
            }
            try std.testing.expect(saw_real_body and saw_spam_body);
        }
    }
}

test "migrate-precis merges held offline queues in receipt order" {
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
    _ = try offline.storeHeldPointer("naplestb@us.example", "spam@remote.example/x", "spam", 1, "<message><body>spam</body></message>");
    _ = try offline.storeHeldPointer("NaplesTB@us.example", "alice@us.example/a", "alice1", 1, "<message><body>alice1</body></message>");
    _ = try offline.storeHeldPointer("NaplesTB@us.example", "alice@us.example/a", "alice2", 2, "<message><body>alice2</body></message>");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const journal_dir = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(journal_dir);

    const domains = [_][]const u8{"us.example"};
    var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer plan.deinit();
    try std.testing.expect(!plan.hasBlockingIssues());
    try migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{ .journal_dir = journal_dir });

    const pointers = try offline.getPointers("naplestb@us.example");
    defer offline.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 3), pointers.len);
    try std.testing.expectEqualStrings("spam@remote.example/x", pointers[0].from_jid);
    try std.testing.expectEqualStrings("alice@us.example/a", pointers[1].from_jid);
    try std.testing.expectEqualStrings("alice@us.example/a", pointers[2].from_jid);
    const expected = [_][]const u8{
        "<message><body>spam</body></message>",
        "<message><body>alice1</body></message>",
        "<message><body>alice2</body></message>",
    };
    for (pointers, expected) |pointer, want| {
        const held = try offline.getHeldStanza(pointer);
        defer if (held) |value| allocator.free(value);
        try std.testing.expect(held != null);
        try std.testing.expectEqualStrings(want, held.?);
    }
}

test "deluser --raw on a data-only spelling touches only owned rows" {
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
    try auth.put(NS_LOCKS, "naplestb", "\x01\x00\x00\x00\x00");
    var roster = roster_store_mod.RosterStore(MemoryBackend).init(&op);
    try roster.setItem("alice@us.example", "naplestb@us.example", "Naples", .both, false);
    var rooms = room_store_mod.RoomStore(MemoryBackend).init(&op, allocator);
    try rooms.setAffiliation("room@conference.us.example", "naplestb@us.example", .admin);
    var offline = offline_store_mod.GenericOfflineStore(MemoryBackend).init(&op, allocator);
    _ = try offline.storePointer("naplestb@us.example", "alice@us.example/res", "id1", 1);
    var archive_store = archive_store_mod.ArchiveStore(MemoryBackend).init(&archive, allocator);
    try archive_store.store("naplestb@us.example", "alice@us.example", "id1", 1, "<message><body>owned</body></message>");
    try archive_store.store("alice@us.example", "naplestb@us.example", "id2", 1, "<message><body>reference</body></message>");

    const domains = [_][]const u8{"us.example"};
    const kind = try migrate.deleteRawAccount(allocator, &auth, &op, &archive, &domains, "naplestb");
    try std.testing.expectEqual(migrate.RawDeleteKind.data_only, kind);

    const contact = try roster.getItem(allocator, "alice@us.example", "naplestb@us.example");
    defer if (contact) |entry| {
        if (entry.name.len > 0) allocator.free(entry.name);
        if (entry.groups.len > 0) allocator.free(entry.groups);
    };
    try std.testing.expect(contact != null);
    try std.testing.expectEqual(room_store_mod.Affiliation.admin, try rooms.getAffiliation("room@conference.us.example", "naplestb@us.example"));
    try expectRow(&auth, NS_LOCKS, "naplestb", "\x01\x00\x00\x00\x00");
    try expectRow(&archive, NS_BY_CONTACT, "alice@us.example\x00naplestb@us.example\x00\x00\x00\x00\x00\x00\x00\x00\x01", "id2");
    try expectMissing(&op, NS_OFFLINE_SEQ, "naplestb@us.example");
    try expectMissing(&op, NS_OFFLINE_V2, "naplestb@us.example\x00\x00\x00\x00\x00\x00\x00\x00\x01");
    const pointers = try offline.getPointers("naplestb@us.example");
    defer offline.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 0), pointers.len);
    try expectMissing(&archive, NS_MESSAGES, "naplestb@us.example\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00id1");
    try expectMissing(&archive, NS_BY_CONTACT, "naplestb@us.example\x00alice@us.example\x00\x00\x00\x00\x00\x00\x00\x00\x01");
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
    _ = try migrate.deleteRawAccount(allocator, &auth, &op, &archive, &domains, "naplestb");
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

    _ = try migrate.deleteRawAccount(allocator, &auth, &op, &archive, &domains, "Bob");
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
    compound_mutex: std.Thread.Mutex = .{},

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
    compound_mutex: std.Thread.Mutex = .{},
    fail_at: usize = 1,
    commit_count: usize = 0,

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
        fail_at: usize,
        commit_count: *usize,

        pub fn put(self: *WriteBatch, ns: []const u8, key: []const u8, value: []const u8) !void {
            try self.inner.put(ns, key, value);
        }

        pub fn delete(self: *WriteBatch, ns: []const u8, key: []const u8) !void {
            try self.inner.delete(ns, key);
        }

        pub fn commit(self: *WriteBatch) !void {
            self.commit_count.* += 1;
            if (self.commit_count.* == self.fail_at) return error.InjectedCommitFailure;
            try self.inner.commit();
        }

        pub fn abort(self: *WriteBatch) void {
            self.inner.abort();
        }
    };

    pub fn writeBatch(self: *FailingCommitBackend) !WriteBatch {
        return .{
            .inner = try self.inner.writeBatch(),
            .fail_at = self.fail_at,
            .commit_count = &self.commit_count,
        };
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

fn dumpBackend(allocator: std.mem.Allocator, backend: anytype) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .{};
    errdefer out.deinit(allocator);
    for (backend_mod.canonical_namespaces) |ns| {
        var iter = try backend.iterator(ns, "");
        defer iter.deinit();
        while (iter.next()) |entry| {
            try out.appendSlice(allocator, ns);
            try out.append(allocator, 0);
            try out.appendSlice(allocator, entry.key);
            try out.append(allocator, 0);
            try out.appendSlice(allocator, entry.value);
            try out.append(allocator, '\n');
        }
    }
    return out.toOwnedSlice(allocator);
}

fn seedBobref(allocator: std.mem.Allocator, auth: anytype, op: anytype, archive: anytype) !void {
    try auth.put(NS_USERS, "Bob", "pw-a");
    try auth.put(NS_USERS, "bob", "pw-b");
    try auth.put(NS_USERS, "carol", "pw-c");
    var roster = roster_store_mod.RosterStore(@TypeOf(op.*)).init(op);
    try roster.setItem("carol@us.example", "Bob@us.example", "Bob (real)", .both, false);
    try roster.setItem("carol@us.example", "bob@us.example", "bob (other)", .both, false);
    try roster.setItem("carol@us.example", "BOB@us.example", "stale", .both, false);
    var rooms = room_store_mod.RoomStore(@TypeOf(op.*)).init(op, allocator);
    try rooms.setAffiliation("room@conference.us.example", "Bob@us.example", .owner);
    try rooms.setAffiliation("room@conference.us.example", "bob@us.example", .member);
    var archive_store = archive_store_mod.ArchiveStore(@TypeOf(archive.*)).init(archive, allocator);
    try archive_store.store("Bob@us.example", "friend@us.example", "id-b1", 1, "<message><body>Bob private</body></message>");
}

test "migrate-precis resume converges after op, auth and archive commit failures" {
    const allocator = std.testing.allocator;
    const FailKind = enum { op, op_batch2, auth, archive };
    const domains = [_][]const u8{"us.example"};

    for ([_]FailKind{ .op, .auth, .archive, .op_batch2 }) |fail_kind| {
        var expected_tmp = std.testing.tmpDir(.{});
        defer expected_tmp.cleanup();
        const expected_base = try expected_tmp.dir.realpathAlloc(allocator, ".");
        defer allocator.free(expected_base);
        var expected_auth = try backend_mod.MemoryBackend.open("", .{});
        defer expected_auth.close();
        var expected_op = try backend_mod.MemoryBackend.open("", .{});
        defer expected_op.close();
        var expected_archive = try backend_mod.MemoryBackend.open("", .{});
        defer expected_archive.close();
        try seedBobref(allocator, &expected_auth, &expected_op, &expected_archive);
        var expected_plan = try migrate.planMigration(allocator, &expected_auth, &expected_op, &expected_archive, &domains, .{
            .old_localpart = "bob",
            .new_localpart = "bob2",
        });
        defer expected_plan.deinit();
        try migrate.applyPlan(allocator, &expected_auth, &expected_op, &expected_archive, &expected_plan, .{ .journal_dir = expected_base });
        const expected_dump = try dumpBackend(allocator, &expected_auth);
        defer allocator.free(expected_dump);
        const expected_op_dump = try dumpBackend(allocator, &expected_op);
        defer allocator.free(expected_op_dump);
        const expected_archive_dump = try dumpBackend(allocator, &expected_archive);
        defer allocator.free(expected_archive_dump);

        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const base = try tmp.dir.realpathAlloc(allocator, ".");
        defer allocator.free(base);
        var auth = try FailingCommitBackend.open("", .{});
        defer auth.close();
        var op = try FailingCommitBackend.open("", .{});
        defer op.close();
        var archive = try FailingCommitBackend.open("", .{});
        defer archive.close();
        auth.fail_at = 0;
        op.fail_at = 0;
        archive.fail_at = 0;
        try seedBobref(allocator, &auth, &op, &archive);
        var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, .{
            .old_localpart = "bob",
            .new_localpart = "bob2",
        });
        defer plan.deinit();

        auth.commit_count = 0;
        op.commit_count = 0;
        archive.commit_count = 0;
        auth.fail_at = 0;
        op.fail_at = 0;
        archive.fail_at = 0;
        var apply_options = migrate.ApplyOptions{ .journal_dir = base };
        switch (fail_kind) {
            .op => op.fail_at = 1,
            .op_batch2 => {
                op.fail_at = 2;
                apply_options.single_txn_budget = 0;
            },
            .auth => auth.fail_at = 1,
            .archive => archive.fail_at = 1,
        }
        try std.testing.expectError(error.InjectedCommitFailure, migrate.applyPlan(allocator, &auth, &op, &archive, &plan, apply_options));
        try std.testing.expect(try migrate.recoveryPending(allocator, base));

        auth.fail_at = 0;
        op.fail_at = 0;
        archive.fail_at = 0;
        auth.commit_count = 0;
        op.commit_count = 0;
        archive.commit_count = 0;
        _ = try migrate.resumeMigration(allocator, &auth, &op, &archive, base);
        try std.testing.expect(!try migrate.recoveryPending(allocator, base));

        const auth_dump = try dumpBackend(allocator, &auth);
        defer allocator.free(auth_dump);
        const op_dump = try dumpBackend(allocator, &op);
        defer allocator.free(op_dump);
        const archive_dump = try dumpBackend(allocator, &archive);
        defer allocator.free(archive_dump);
        try std.testing.expectEqualStrings(expected_dump, auth_dump);
        try std.testing.expectEqualStrings(expected_op_dump, op_dump);
        try std.testing.expectEqualStrings(expected_archive_dump, archive_dump);
    }
}

test "migrate-precis resume converges for a plain mixed migration after an auth failure" {
    const allocator = std.testing.allocator;
    const domains = [_][]const u8{"us.example"};

    var expected_tmp = std.testing.tmpDir(.{});
    defer expected_tmp.cleanup();
    const expected_base = try expected_tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(expected_base);
    var expected_auth = try backend_mod.MemoryBackend.open("", .{});
    defer expected_auth.close();
    var expected_op = try backend_mod.MemoryBackend.open("", .{});
    defer expected_op.close();
    var expected_archive = try backend_mod.MemoryBackend.open("", .{});
    defer expected_archive.close();
    try expected_auth.put(NS_USERS, "NaplesTB", "pw");
    var expected_roster = roster_store_mod.RosterStore(backend_mod.MemoryBackend).init(&expected_op);
    try expected_roster.setItem("NaplesTB@us.example", "friend@us.example", "", .both, false);
    var expected_archive_store = archive_store_mod.ArchiveStore(backend_mod.MemoryBackend).init(&expected_archive, allocator);
    try expected_archive_store.store("NaplesTB@us.example", "friend@us.example", "id1", 1, "<message/>");
    var expected_plan = try migrate.planMigration(allocator, &expected_auth, &expected_op, &expected_archive, &domains, null);
    defer expected_plan.deinit();
    try migrate.applyPlan(allocator, &expected_auth, &expected_op, &expected_archive, &expected_plan, .{ .journal_dir = expected_base });

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    var auth = try FailingCommitBackend.open("", .{});
    defer auth.close();
    var op = try FailingCommitBackend.open("", .{});
    defer op.close();
    var archive = try FailingCommitBackend.open("", .{});
    defer archive.close();
    auth.fail_at = 0;
    op.fail_at = 0;
    archive.fail_at = 0;
    try auth.put(NS_USERS, "NaplesTB", "pw");
    var roster = roster_store_mod.RosterStore(FailingCommitBackend).init(&op);
    try roster.setItem("NaplesTB@us.example", "friend@us.example", "", .both, false);
    var archive_store = archive_store_mod.ArchiveStore(FailingCommitBackend).init(&archive, allocator);
    try archive_store.store("NaplesTB@us.example", "friend@us.example", "id1", 1, "<message/>");
    var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
    defer plan.deinit();

    auth.commit_count = 0;
    op.commit_count = 0;
    archive.commit_count = 0;
    auth.fail_at = 1;
    try std.testing.expectError(error.InjectedCommitFailure, migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{ .journal_dir = base }));
    auth.fail_at = 0;
    auth.commit_count = 0;
    op.commit_count = 0;
    archive.commit_count = 0;
    _ = try migrate.resumeMigration(allocator, &auth, &op, &archive, base);

    const expected_auth_dump = try dumpBackend(allocator, &expected_auth);
    defer allocator.free(expected_auth_dump);
    const expected_op_dump = try dumpBackend(allocator, &expected_op);
    defer allocator.free(expected_op_dump);
    const expected_archive_dump = try dumpBackend(allocator, &expected_archive);
    defer allocator.free(expected_archive_dump);
    const auth_dump = try dumpBackend(allocator, &auth);
    defer allocator.free(auth_dump);
    const op_dump = try dumpBackend(allocator, &op);
    defer allocator.free(op_dump);
    const archive_dump = try dumpBackend(allocator, &archive);
    defer allocator.free(archive_dump);
    try std.testing.expectEqualStrings(expected_auth_dump, auth_dump);
    try std.testing.expectEqualStrings(expected_op_dump, op_dump);
    try std.testing.expectEqualStrings(expected_archive_dump, archive_dump);
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

test "migrate-precis reports malformed offline_v2 rows" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;
    const Malformed = enum { short_value, id_past_end };
    for ([_]Malformed{ .short_value, .id_past_end }) |malformed| {
        var auth = try MemoryBackend.open("", .{});
        defer auth.close();
        var op = try MemoryBackend.open("", .{});
        defer op.close();
        var archive = try MemoryBackend.open("", .{});
        defer archive.close();

        const owner = "naplestb@us.example";
        const key_prefix = try std.fmt.allocPrint(allocator, "{s}\x00", .{owner});
        defer allocator.free(key_prefix);
        const key = try allocator.alloc(u8, key_prefix.len + 8);
        defer allocator.free(key);
        @memcpy(key[0..key_prefix.len], key_prefix);
        std.mem.writeInt(u64, key[key_prefix.len..][0..8], 1, .big);

        switch (malformed) {
            .short_value => try op.put(NS_OFFLINE_V2, key, &[_]u8{0} ** 5),
            .id_past_end => {
                var value: [12]u8 = undefined;
                @memset(value[0..8], 0);
                std.mem.writeInt(u32, value[8..12], 10, .big);
                try op.put(NS_OFFLINE_V2, key, &value);
            },
        }

        const domains = [_][]const u8{"us.example"};
        var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
        defer plan.deinit();
        try std.testing.expect(plan.hasBlockingIssues());
        var found = false;
        for (plan.issues.items) |issue| {
            if (issue.kind == .invalid_value and
                std.mem.eql(u8, issue.namespace, NS_OFFLINE_V2) and
                std.mem.eql(u8, issue.key, key))
            {
                found = true;
            }
        }
        try std.testing.expect(found);
        try std.testing.expectError(error.MigrationBlocked, migrate.applyPlan(
            allocator,
            &auth,
            &op,
            &archive,
            &plan,
            .{},
        ));
    }
}

test "migrate-precis separates two source spellings folding to one target" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;
    const Mode = enum { offline_only, with_archive };
    for ([_]Mode{ .offline_only, .with_archive }) |mode| {
        var auth = try MemoryBackend.open("", .{});
        defer auth.close();
        var op = try MemoryBackend.open("", .{});
        defer op.close();
        var archive = try MemoryBackend.open("", .{});
        defer archive.close();

        var offline = offline_store_mod.GenericOfflineStore(MemoryBackend).init(&op, allocator);
        const timestamp: u64 = 1_700_000_000;
        const key_upper = try legacyOfflineKey(allocator, "NaplesTB@us.example", timestamp, "offline");
        defer allocator.free(key_upper);
        const key_caps = try legacyOfflineKey(allocator, "NAPLESTB@us.example", timestamp, "offline");
        defer allocator.free(key_caps);
        try op.put(NS_OFFLINE, key_upper, "alice@us.example/res");
        try op.put(NS_OFFLINE, key_caps, "bob@us.example/res");

        var archive_store = archive_store_mod.ArchiveStore(MemoryBackend).init(&archive, allocator);
        if (mode == .with_archive) {
            try archive_store.store("NaplesTB@us.example", "alice@us.example", "offline", timestamp, "<message><body>NAPLES</body></message>");
            try archive_store.store("NAPLESTB@us.example", "bob@us.example", "offline", timestamp, "<message><body>UPPER</body></message>");
        }

        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const journal_dir = try tmp.dir.realpathAlloc(allocator, ".");
        defer allocator.free(journal_dir);

        const domains = [_][]const u8{"us.example"};
        var plan = try migrate.planMigration(allocator, &auth, &op, &archive, &domains, null);
        defer plan.deinit();
        try std.testing.expect(!plan.hasBlockingIssues());
        try migrate.applyPlan(allocator, &auth, &op, &archive, &plan, .{ .journal_dir = journal_dir });

        const pointers = try offline.getPointers("naplestb@us.example");
        defer offline.freePointers(pointers);
        try std.testing.expectEqual(@as(usize, 2), pointers.len);
        try std.testing.expect(!std.mem.eql(u8, pointers[0].stanza_id, pointers[1].stanza_id));
        var saw_alice = false;
        var saw_bob = false;
        for (pointers) |pointer| {
            if (std.mem.eql(u8, pointer.from_jid, "alice@us.example/res")) {
                saw_alice = true;
                if (mode == .with_archive) {
                    const body = try archive_store.getMessage("naplestb@us.example", pointer.timestamp, pointer.stanza_id);
                    defer if (body) |value| allocator.free(value);
                    try std.testing.expect(body != null);
                    try std.testing.expect(std.mem.indexOf(u8, body.?, "NAPLES") != null);
                }
            }
            if (std.mem.eql(u8, pointer.from_jid, "bob@us.example/res")) {
                saw_bob = true;
                if (mode == .with_archive) {
                    const body = try archive_store.getMessage("naplestb@us.example", pointer.timestamp, pointer.stanza_id);
                    defer if (body) |value| allocator.free(value);
                    try std.testing.expect(body != null);
                    try std.testing.expect(std.mem.indexOf(u8, body.?, "UPPER") != null);
                }
            }
        }
        try std.testing.expect(saw_alice and saw_bob);

        if (mode == .with_archive) {
            var by_contact = try archive.iterator(NS_BY_CONTACT, "naplestb@us.example\x00");
            defer by_contact.deinit();
            var saw_upper = false;
            var saw_naples = false;
            while (by_contact.next()) |entry| {
                const body = try archive_store.getMessage("naplestb@us.example", timestamp, entry.value);
                defer if (body) |value| allocator.free(value);
                if (body) |value| {
                    if (std.mem.indexOf(u8, value, "UPPER") != null) saw_upper = true;
                    if (std.mem.indexOf(u8, value, "NAPLES") != null) saw_naples = true;
                }
            }
            try std.testing.expect(saw_upper and saw_naples);
        }
    }
}
