const std = @import("std");
const backend_mod = @import("backend");
const migrate = @import("migrate_precis");
const user_store_mod = @import("user_store");
const roster_store_mod = @import("roster_store");
const archive_store_mod = @import("archive_store");
const LmdbBackend = @import("lmdb_backend").Backend;
const RocksDbBackend = @import("rocksdb_backend").Backend;

const NS_USERS = backend_mod.registered("users");
const NS_ROSTERS = backend_mod.registered("rosters");
const NS_MESSAGES = backend_mod.registered("messages");

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
    const archive_value = try archive.get(allocator, NS_MESSAGES, "naplestb@us.example\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00id1");
    defer if (archive_value) |value| allocator.free(value);
    try std.testing.expectEqualStrings("<message><body>private</body></message>", archive_value.?);
}

fn applyGuarded(auth: anytype, op: anytype, archive: anytype, plan: *const migrate.Plan, journal_dir: []const u8, allocator: std.mem.Allocator) !void {
    try migrate.applyPlan(allocator, auth, op, archive, plan, .{ .journal_dir = journal_dir });
}
