//! # SQLite Storage Backend
//!
//! Implements the StorageBackend trait using SQLite3's C API.
//! Namespaces map to tables, created lazily on first access.
//! WAL mode enabled for concurrent read access.
//! Links against system libsqlite3 (in FreeBSD base).

const std = @import("std");
const backend = @import("backend");
const c = @cImport(@cInclude("sqlite3.h"));

const log = std.log.scoped(.sqlite_store);

const MAX_TABLES = 16;

const TableCacheEntry = struct {
    name_buf: [64]u8,
    name_len: u8,
};

pub const Backend = SqliteBackend;

pub const SqliteBackend = struct {
    db: *c.sqlite3,
    table_cache: [MAX_TABLES]TableCacheEntry,
    table_count: u32,

    comptime {
        backend.assertBackend(SqliteBackend);
    }

    pub fn open(path: []const u8, opts: backend.OpenOptions) !SqliteBackend {
        _ = opts;

        var path_z: [4096]u8 = undefined;
        if (path.len >= path_z.len) return error.NameTooLong;
        @memcpy(path_z[0..path.len], path);
        path_z[path.len] = 0;

        var db: ?*c.sqlite3 = null;
        const rc = c.sqlite3_open(@ptrCast(path_z[0..path.len :0]), &db);
        if (rc != c.SQLITE_OK or db == null) {
            if (db) |d| _ = c.sqlite3_close(d);
            log.err("sqlite3_open failed: rc={d}", .{rc});
            return error.SqliteOpenFailed;
        }

        // Enable WAL mode for concurrent reads
        _ = execSimple(db.?, "PRAGMA journal_mode=WAL");
        // Busy timeout 5 seconds
        _ = c.sqlite3_busy_timeout(db.?, 5000);

        return .{
            .db = db.?,
            .table_cache = undefined,
            .table_count = 0,
        };
    }

    pub fn close(self: *SqliteBackend) void {
        _ = c.sqlite3_close(self.db);
    }

    pub fn get(self: *SqliteBackend, allocator: std.mem.Allocator, ns: []const u8, key: []const u8) !?[]u8 {
        try self.ensureTable(ns);

        // SELECT value FROM <ns> WHERE key = ?
        var sql_buf: [256]u8 = undefined;
        const sql = std.fmt.bufPrint(&sql_buf, "SELECT value FROM \"{s}\" WHERE key = ?", .{ns}) catch
            return error.NameTooLong;
        var sql_z: [256]u8 = undefined;
        @memcpy(sql_z[0..sql.len], sql);
        sql_z[sql.len] = 0;

        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, @ptrCast(sql_z[0..sql.len :0]), @intCast(sql.len), &stmt, null);
        if (rc != c.SQLITE_OK or stmt == null) return error.SqlitePrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        rc = c.sqlite3_bind_blob(stmt.?, 1, key.ptr, @intCast(key.len), c.SQLITE_STATIC);
        if (rc != c.SQLITE_OK) return error.SqliteBindFailed;

        rc = c.sqlite3_step(stmt.?);
        if (rc == c.SQLITE_DONE) return null; // not found
        if (rc != c.SQLITE_ROW) return error.SqliteStepFailed;

        const blob_ptr = c.sqlite3_column_blob(stmt.?, 0);
        const blob_len: usize = @intCast(c.sqlite3_column_bytes(stmt.?, 0));
        if (blob_ptr == null or blob_len == 0) return null;

        const result = try allocator.alloc(u8, blob_len);
        @memcpy(result, @as([*]const u8, @ptrCast(blob_ptr))[0..blob_len]);
        return result;
    }

    pub fn put(self: *SqliteBackend, ns: []const u8, key: []const u8, value: []const u8) !void {
        try self.ensureTable(ns);

        var sql_buf: [256]u8 = undefined;
        const sql = std.fmt.bufPrint(&sql_buf, "INSERT OR REPLACE INTO \"{s}\" (key, value) VALUES (?, ?)", .{ns}) catch
            return error.NameTooLong;
        var sql_z: [256]u8 = undefined;
        @memcpy(sql_z[0..sql.len], sql);
        sql_z[sql.len] = 0;

        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, @ptrCast(sql_z[0..sql.len :0]), @intCast(sql.len), &stmt, null);
        if (rc != c.SQLITE_OK or stmt == null) return error.SqlitePrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        rc = c.sqlite3_bind_blob(stmt.?, 1, key.ptr, @intCast(key.len), c.SQLITE_STATIC);
        if (rc != c.SQLITE_OK) return error.SqliteBindFailed;
        rc = c.sqlite3_bind_blob(stmt.?, 2, value.ptr, @intCast(value.len), c.SQLITE_STATIC);
        if (rc != c.SQLITE_OK) return error.SqliteBindFailed;

        rc = c.sqlite3_step(stmt.?);
        if (rc != c.SQLITE_DONE) return error.SqliteStepFailed;
    }

    pub fn delete(self: *SqliteBackend, ns: []const u8, key: []const u8) !void {
        try self.ensureTable(ns);

        var sql_buf: [256]u8 = undefined;
        const sql = std.fmt.bufPrint(&sql_buf, "DELETE FROM \"{s}\" WHERE key = ?", .{ns}) catch
            return error.NameTooLong;
        var sql_z: [256]u8 = undefined;
        @memcpy(sql_z[0..sql.len], sql);
        sql_z[sql.len] = 0;

        var stmt: ?*c.sqlite3_stmt = null;
        var rc = c.sqlite3_prepare_v2(self.db, @ptrCast(sql_z[0..sql.len :0]), @intCast(sql.len), &stmt, null);
        if (rc != c.SQLITE_OK or stmt == null) return error.SqlitePrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);

        rc = c.sqlite3_bind_blob(stmt.?, 1, key.ptr, @intCast(key.len), c.SQLITE_STATIC);
        if (rc != c.SQLITE_OK) return error.SqliteBindFailed;

        rc = c.sqlite3_step(stmt.?);
        if (rc != c.SQLITE_DONE) return error.SqliteStepFailed;
    }

    pub fn iterator(self: *SqliteBackend, ns: []const u8, prefix: []const u8) !Iterator {
        try self.ensureTable(ns);

        var sql_buf: [256]u8 = undefined;
        var sql_z: [256]u8 = undefined;
        var stmt: ?*c.sqlite3_stmt = null;
        var rc: c_int = undefined;

        // Compute upper bound: prefix with last byte incremented for range query.
        // If prefix is empty or all 0xFF, use an unbounded query (>= prefix, ORDER BY key).
        var upper: [256]u8 = undefined;
        var upper_len: usize = prefix.len;
        var has_upper = false;

        if (prefix.len > 0 and prefix.len <= 256) {
            @memcpy(upper[0..prefix.len], prefix);
            var i = upper_len;
            while (i > 0) {
                i -= 1;
                if (upper[i] < 0xFF) {
                    upper[i] += 1;
                    upper_len = i + 1;
                    has_upper = true;
                    break;
                }
            }
        }

        if (has_upper) {
            const sql = std.fmt.bufPrint(&sql_buf, "SELECT key, value FROM \"{s}\" WHERE key >= ? AND key < ? ORDER BY key", .{ns}) catch
                return error.NameTooLong;
            @memcpy(sql_z[0..sql.len], sql);
            sql_z[sql.len] = 0;

            rc = c.sqlite3_prepare_v2(self.db, @ptrCast(sql_z[0..sql.len :0]), @intCast(sql.len), &stmt, null);
            if (rc != c.SQLITE_OK or stmt == null) return error.SqlitePrepareFailed;

            // Use SQLITE_TRANSIENT — prefix and upper are on the caller's stack
            const transient: c.sqlite3_destructor_type = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
            rc = c.sqlite3_bind_blob(stmt.?, 1, prefix.ptr, @intCast(prefix.len), transient);
            if (rc != c.SQLITE_OK) {
                _ = c.sqlite3_finalize(stmt);
                return error.SqliteBindFailed;
            }
            rc = c.sqlite3_bind_blob(stmt.?, 2, &upper, @intCast(upper_len), transient);
            if (rc != c.SQLITE_OK) {
                _ = c.sqlite3_finalize(stmt);
                return error.SqliteBindFailed;
            }
        } else {
            // No upper bound (empty prefix or all-0xFF) — return all from prefix
            const sql = std.fmt.bufPrint(&sql_buf, "SELECT key, value FROM \"{s}\" WHERE key >= ? ORDER BY key", .{ns}) catch
                return error.NameTooLong;
            @memcpy(sql_z[0..sql.len], sql);
            sql_z[sql.len] = 0;

            rc = c.sqlite3_prepare_v2(self.db, @ptrCast(sql_z[0..sql.len :0]), @intCast(sql.len), &stmt, null);
            if (rc != c.SQLITE_OK or stmt == null) return error.SqlitePrepareFailed;

            const transient2: c.sqlite3_destructor_type = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
            rc = c.sqlite3_bind_blob(stmt.?, 1, prefix.ptr, @intCast(prefix.len), transient2);
            if (rc != c.SQLITE_OK) {
                _ = c.sqlite3_finalize(stmt);
                return error.SqliteBindFailed;
            }
        }

        return .{ .stmt = stmt.? };
    }

    pub fn writeBatch(self: *SqliteBackend) !WriteBatch {
        _ = execSimple(self.db, "BEGIN IMMEDIATE");
        return .{ .backend = self, .committed = false, .table_count_at_start = self.table_count };
    }

    // -- Iterator --

    pub const Iterator = struct {
        stmt: *c.sqlite3_stmt,

        pub fn next(self: *Iterator) ?backend.Entry {
            const rc = c.sqlite3_step(self.stmt);
            if (rc != c.SQLITE_ROW) return null;

            const key_ptr = c.sqlite3_column_blob(self.stmt, 0);
            const key_len: usize = @intCast(c.sqlite3_column_bytes(self.stmt, 0));
            const val_ptr = c.sqlite3_column_blob(self.stmt, 1);
            const val_len: usize = @intCast(c.sqlite3_column_bytes(self.stmt, 1));

            if (key_ptr == null) return null;

            return .{
                .key = @as([*]const u8, @ptrCast(key_ptr))[0..key_len],
                .value = if (val_ptr) |v| @as([*]const u8, @ptrCast(v))[0..val_len] else "",
            };
        }

        pub fn deinit(self: *Iterator) void {
            _ = c.sqlite3_finalize(self.stmt);
        }
    };

    // -- WriteBatch --

    pub const WriteBatch = struct {
        backend: *SqliteBackend,
        committed: bool,
        table_count_at_start: u32,

        pub fn put(self: *WriteBatch, ns: []const u8, key: []const u8, value: []const u8) !void {
            try self.backend.put(ns, key, value);
        }

        pub fn delete(self: *WriteBatch, ns: []const u8, key: []const u8) !void {
            try self.backend.delete(ns, key);
        }

        pub fn commit(self: *WriteBatch) !void {
            _ = execSimple(self.backend.db, "COMMIT");
            self.committed = true;
        }

        pub fn abort(self: *WriteBatch) void {
            if (!self.committed) {
                _ = execSimple(self.backend.db, "ROLLBACK");
                // Rollback may have undone CREATE TABLE statements made inside
                // the transaction. Reset table cache to the state before BEGIN.
                self.backend.table_count = self.table_count_at_start;
            }
        }
    };

    // -- Internal --

    fn ensureTable(self: *SqliteBackend, ns: []const u8) !void {
        // Check cache
        for (self.table_cache[0..self.table_count]) |entry| {
            if (std.mem.eql(u8, entry.name_buf[0..entry.name_len], ns))
                return;
        }

        if (self.table_count >= MAX_TABLES) return error.TooManyTables;
        if (ns.len > 64) return error.NameTooLong;

        // CREATE TABLE IF NOT EXISTS
        var sql_buf: [256]u8 = undefined;
        const sql = std.fmt.bufPrint(&sql_buf, "CREATE TABLE IF NOT EXISTS \"{s}\" (key BLOB PRIMARY KEY, value BLOB NOT NULL)", .{ns}) catch
            return error.NameTooLong;
        var sql_z: [256]u8 = undefined;
        @memcpy(sql_z[0..sql.len], sql);
        sql_z[sql.len] = 0;

        const rc = c.sqlite3_exec(self.db, @ptrCast(sql_z[0..sql.len :0]), null, null, null);
        if (rc != c.SQLITE_OK) {
            log.err("CREATE TABLE failed for namespace '{s}': rc={d}", .{ ns, rc });
            return error.SqliteExecFailed;
        }

        var entry = &self.table_cache[self.table_count];
        @memcpy(entry.name_buf[0..ns.len], ns);
        entry.name_len = @intCast(ns.len);
        self.table_count += 1;
    }

    fn execSimple(db: *c.sqlite3, sql: [*:0]const u8) c_int {
        return c.sqlite3_exec(db, sql, null, null, null);
    }
};

// ============================================================================
// Tests
// ============================================================================

fn cleanDb(path: []const u8) void {
    std.fs.cwd().deleteFile(path) catch {};
    // WAL/SHM files may exist alongside the DB
    var wal_buf: [256]u8 = undefined;
    var shm_buf: [256]u8 = undefined;
    const wal = std.fmt.bufPrint(&wal_buf, "{s}-wal", .{path}) catch return;
    const shm = std.fmt.bufPrint(&shm_buf, "{s}-shm", .{path}) catch return;
    std.fs.cwd().deleteFile(wal) catch {};
    std.fs.cwd().deleteFile(shm) catch {};
}

test "SqliteBackend: open and close" {
    const path = "/tmp/xmppd-test-sqlite-open.db";
    cleanDb(path);
    defer cleanDb(path);
    var db = try SqliteBackend.open(path, .{});
    db.close();
}

test "SqliteBackend: put and get" {
    const path = "/tmp/xmppd-test-sqlite-putget.db";
    cleanDb(path);
    defer cleanDb(path);
    var db = try SqliteBackend.open(path, .{});
    defer db.close();

    try db.put("users", "alice", "creds_alice");
    try db.put("users", "bob", "creds_bob");

    const val = try db.get(std.testing.allocator, "users", "alice");
    defer if (val) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("creds_alice", val.?);

    const missing = try db.get(std.testing.allocator, "users", "charlie");
    try std.testing.expect(missing == null);
}

test "SqliteBackend: delete" {
    const path = "/tmp/xmppd-test-sqlite-delete.db";
    cleanDb(path);
    defer cleanDb(path);
    var db = try SqliteBackend.open(path, .{});
    defer db.close();

    try db.put("users", "alice", "creds");
    try db.delete("users", "alice");

    const val = try db.get(std.testing.allocator, "users", "alice");
    try std.testing.expect(val == null);

    // Deleting non-existent key should not error
    try db.delete("users", "nonexistent");
}

test "SqliteBackend: overwrite value" {
    const path = "/tmp/xmppd-test-sqlite-overwrite.db";
    cleanDb(path);
    defer cleanDb(path);
    var db = try SqliteBackend.open(path, .{});
    defer db.close();

    try db.put("users", "alice", "old");
    try db.put("users", "alice", "new");

    const val = try db.get(std.testing.allocator, "users", "alice");
    defer if (val) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("new", val.?);
}

test "SqliteBackend: separate namespaces" {
    const path = "/tmp/xmppd-test-sqlite-ns.db";
    cleanDb(path);
    defer cleanDb(path);
    var db = try SqliteBackend.open(path, .{});
    defer db.close();

    try db.put("users", "alice", "user_data");
    try db.put("rosters", "alice", "roster_data");

    const u = try db.get(std.testing.allocator, "users", "alice");
    defer if (u) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("user_data", u.?);

    const r = try db.get(std.testing.allocator, "rosters", "alice");
    defer if (r) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("roster_data", r.?);
}

test "SqliteBackend: iterator prefix-bounded" {
    const path = "/tmp/xmppd-test-sqlite-iter.db";
    cleanDb(path);
    defer cleanDb(path);
    var db = try SqliteBackend.open(path, .{});
    defer db.close();

    try db.put("rosters", "alice\x00bob", "both");
    try db.put("rosters", "alice\x00carol", "to");
    try db.put("rosters", "bob\x00alice", "both");

    var iter = try db.iterator("rosters", "alice\x00");
    defer iter.deinit();

    var count: usize = 0;
    while (iter.next()) |entry| {
        try std.testing.expect(std.mem.startsWith(u8, entry.key, "alice\x00"));
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "SqliteBackend: iterator returns key and value" {
    const path = "/tmp/xmppd-test-sqlite-iterval.db";
    cleanDb(path);
    defer cleanDb(path);
    var db = try SqliteBackend.open(path, .{});
    defer db.close();

    try db.put("data", "key1", "value1");

    var iter = try db.iterator("data", "key");
    defer iter.deinit();

    const entry = iter.next() orelse return error.ExpectedEntry;
    try std.testing.expectEqualStrings("key1", entry.key);
    try std.testing.expectEqualStrings("value1", entry.value);
}

test "SqliteBackend: writeBatch commit" {
    const path = "/tmp/xmppd-test-sqlite-batch.db";
    cleanDb(path);
    defer cleanDb(path);
    var db = try SqliteBackend.open(path, .{});
    defer db.close();

    var batch = try db.writeBatch();
    try batch.put("users", "alice", "a");
    try batch.put("users", "bob", "b");
    try batch.commit();

    const a = try db.get(std.testing.allocator, "users", "alice");
    defer if (a) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("a", a.?);

    const b_val = try db.get(std.testing.allocator, "users", "bob");
    defer if (b_val) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("b", b_val.?);
}

test "SqliteBackend: writeBatch abort" {
    const path = "/tmp/xmppd-test-sqlite-abort.db";
    cleanDb(path);
    defer cleanDb(path);
    var db = try SqliteBackend.open(path, .{});
    defer db.close();

    var batch = try db.writeBatch();
    try batch.put("users", "alice", "a");
    batch.abort();

    const val = try db.get(std.testing.allocator, "users", "alice");
    try std.testing.expect(val == null);
}

test "SqliteBackend: reopen preserves data" {
    const path = "/tmp/xmppd-test-sqlite-reopen.db";
    cleanDb(path);
    defer cleanDb(path);
    {
        var db = try SqliteBackend.open(path, .{});
        try db.put("users", "alice", "persisted");
        db.close();
    }
    {
        var db = try SqliteBackend.open(path, .{});
        defer db.close();
        const val = try db.get(std.testing.allocator, "users", "alice");
        defer if (val) |v| std.testing.allocator.free(v);
        try std.testing.expectEqualStrings("persisted", val.?);
    }
}
