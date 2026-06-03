//! # LMDB Storage Backend
//!
//! Implements the StorageBackend trait using LMDB (via zig-lmdb).
//! Namespaces map to LMDB named databases (DBI handles), cached on first access.
//! Auto-resizes on MDB_MAP_FULL (Postfix pattern).

const std = @import("std");
const lmdb = @import("lmdb");
const backend = @import("backend.zig");

const log = std.log.scoped(.lmdb_store);

const MAX_DBS = 16;
const MAX_RESIZE_RETRIES = 3;

const DbiCacheEntry = struct {
    name_buf: [64]u8,
    name_len: u8,
    dbi: lmdb.Database.DBI,
};

pub const LmdbBackend = struct {
    env: lmdb.Environment,
    dbi_cache: [MAX_DBS]DbiCacheEntry,
    dbi_count: u32,
    map_size: usize,

    comptime {
        backend.assertBackend(LmdbBackend);
    }

    pub fn open(path: []const u8, opts: backend.OpenOptions) !LmdbBackend {
        if (opts.create) {
            std.fs.cwd().makePath(path) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }

        var path_buf: [4096]u8 = undefined;
        if (path.len >= path_buf.len) return error.NameTooLong;
        @memcpy(path_buf[0..path.len], path);
        path_buf[path.len] = 0;

        const env = try lmdb.Environment.init(
            @ptrCast(path_buf[0..path.len :0]),
            .{
                .map_size = opts.map_size,
                .max_dbs = opts.max_namespaces,
                .read_only = opts.read_only,
            },
        );

        return .{
            .env = env,
            .dbi_cache = undefined,
            .dbi_count = 0,
            .map_size = opts.map_size,
        };
    }

    pub fn close(self: *LmdbBackend) void {
        self.env.deinit();
    }

    pub fn get(self: *LmdbBackend, allocator: std.mem.Allocator, ns: []const u8, key: []const u8) !?[]u8 {
        const dbi = try self.getOrCreateDbi(ns);
        const txn = try lmdb.Transaction.init(self.env, .{ .mode = .ReadOnly });
        defer txn.abort();

        const db = lmdb.Database{ .txn = txn, .dbi = dbi };
        const value = db.get(key) catch |err| {
            if (err == error.MDB_NOTFOUND) return null;
            return err;
        };
        const v = value orelse return null;
        return try allocator.dupe(u8, v);
    }

    pub fn put(self: *LmdbBackend, ns: []const u8, key: []const u8, value: []const u8) !void {
        const dbi = try self.getOrCreateDbi(ns);
        var retries: u8 = 0;
        while (retries < MAX_RESIZE_RETRIES) : (retries += 1) {
            const txn = try lmdb.Transaction.init(self.env, .{ .mode = .ReadWrite });
            const db = lmdb.Database{ .txn = txn, .dbi = dbi };
            db.set(key, value) catch |err| {
                txn.abort();
                if (err == error.MDB_MAP_FULL) {
                    self.map_size *|= 2;
                    log.info("MDB_MAP_FULL, resizing to {d} bytes", .{self.map_size});
                    try self.env.resize(self.map_size);
                    continue;
                }
                return err;
            };
            try txn.commit();
            return;
        }
        return error.MDB_MAP_FULL;
    }

    pub fn delete(self: *LmdbBackend, ns: []const u8, key: []const u8) !void {
        const dbi = try self.getOrCreateDbi(ns);
        const txn = try lmdb.Transaction.init(self.env, .{ .mode = .ReadWrite });
        const db = lmdb.Database{ .txn = txn, .dbi = dbi };
        db.delete(key) catch |err| {
            txn.abort();
            if (err == error.MDB_NOTFOUND) return;
            return err;
        };
        try txn.commit();
    }

    pub fn iterator(self: *LmdbBackend, ns: []const u8, prefix: []const u8) !Iterator {
        const dbi = try self.getOrCreateDbi(ns);
        const txn = try lmdb.Transaction.init(self.env, .{ .mode = .ReadOnly });
        errdefer txn.abort();

        const db = lmdb.Database{ .txn = txn, .dbi = dbi };
        const cur = try db.cursor();

        var iter = Iterator{
            .cursor = cur,
            .txn = txn,
            .prefix = undefined,
            .prefix_len = @min(prefix.len, 256),
            .started = false,
        };
        @memcpy(iter.prefix[0..iter.prefix_len], prefix[0..iter.prefix_len]);
        return iter;
    }

    pub fn writeBatch(self: *LmdbBackend) !WriteBatch {
        const txn = try lmdb.Transaction.init(self.env, .{ .mode = .ReadWrite });
        return .{ .txn = txn, .backend = self, .dbi_count_at_start = self.dbi_count };
    }

    // -- Iterator --

    pub const Iterator = struct {
        cursor: lmdb.Cursor,
        txn: lmdb.Transaction,
        prefix: [256]u8,
        prefix_len: usize,
        started: bool,

        pub fn next(self: *Iterator) ?backend.Entry {
            const key = if (!self.started) blk: {
                self.started = true;
                break :blk self.cursor.seek(self.prefix[0..self.prefix_len]) catch return null;
            } else blk: {
                break :blk self.cursor.goToNext() catch return null;
            };

            const k = key orelse return null;
            if (!std.mem.startsWith(u8, k, self.prefix[0..self.prefix_len])) return null;

            const value = self.cursor.getCurrentValue() catch return null;
            return .{ .key = k, .value = value };
        }

        pub fn deinit(self: *Iterator) void {
            self.cursor.deinit();
            self.txn.abort();
        }
    };

    // -- WriteBatch --

    pub const WriteBatch = struct {
        txn: lmdb.Transaction,
        backend: *LmdbBackend,
        dbi_count_at_start: u32,

        pub fn put(self: *WriteBatch, ns: []const u8, key: []const u8, value: []const u8) !void {
            const dbi = try self.resolveDbi(ns);
            const db = lmdb.Database{ .txn = self.txn, .dbi = dbi };
            try db.set(key, value);
        }

        pub fn delete(self: *WriteBatch, ns: []const u8, key: []const u8) !void {
            const dbi = try self.resolveDbi(ns);
            const db = lmdb.Database{ .txn = self.txn, .dbi = dbi };
            db.delete(key) catch |err| {
                if (err == error.MDB_NOTFOUND) return;
                return err;
            };
        }

        pub fn commit(self: *WriteBatch) !void {
            try self.txn.commit();
        }

        pub fn abort(self: *WriteBatch) void {
            self.txn.abort();
            // Roll back DBI cache entries created during this batch
            self.backend.dbi_count = self.dbi_count_at_start;
        }

        fn resolveDbi(self: *WriteBatch, ns: []const u8) !lmdb.Database.DBI {
            for (self.backend.dbi_cache[0..self.backend.dbi_count]) |entry| {
                if (std.mem.eql(u8, entry.name_buf[0..entry.name_len], ns))
                    return entry.dbi;
            }
            var name_z: [65]u8 = undefined;
            if (ns.len > 64) return error.MDB_BAD_VALSIZE;
            @memcpy(name_z[0..ns.len], ns);
            name_z[ns.len] = 0;
            const db = try lmdb.Database.open(
                self.txn,
                @ptrCast(name_z[0..ns.len :0]),
                .{ .create = true },
            );
            if (self.backend.dbi_count < MAX_DBS) {
                var e = &self.backend.dbi_cache[self.backend.dbi_count];
                @memcpy(e.name_buf[0..ns.len], ns);
                e.name_len = @intCast(ns.len);
                e.dbi = db.dbi;
                self.backend.dbi_count += 1;
            }
            return db.dbi;
        }
    };

    // -- Internal --

    fn getOrCreateDbi(self: *LmdbBackend, ns: []const u8) !lmdb.Database.DBI {
        for (self.dbi_cache[0..self.dbi_count]) |entry| {
            if (std.mem.eql(u8, entry.name_buf[0..entry.name_len], ns))
                return entry.dbi;
        }
        if (self.dbi_count >= MAX_DBS) return error.MDB_DBS_FULL;

        var name_z: [65]u8 = undefined;
        if (ns.len > 64) return error.MDB_BAD_VALSIZE;
        @memcpy(name_z[0..ns.len], ns);
        name_z[ns.len] = 0;

        const txn = try lmdb.Transaction.init(self.env, .{ .mode = .ReadWrite });
        errdefer txn.abort();
        const db = try lmdb.Database.open(
            txn,
            @ptrCast(name_z[0..ns.len :0]),
            .{ .create = true },
        );
        try txn.commit();

        var entry = &self.dbi_cache[self.dbi_count];
        @memcpy(entry.name_buf[0..ns.len], ns);
        entry.name_len = @intCast(ns.len);
        entry.dbi = db.dbi;
        self.dbi_count += 1;

        return db.dbi;
    }
};

// ============================================================================
// Tests
// ============================================================================

fn freshTestDir() []const u8 {
    const path = "/tmp/xmppd-test-lmdb";
    std.fs.cwd().deleteTree(path) catch {};
    return path;
}

test "LmdbBackend: open and close" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    db.close();
}

test "LmdbBackend: put and get" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();

    try db.put("users", "alice", "creds_alice");
    try db.put("users", "bob", "creds_bob");

    const val = try db.get(std.testing.allocator, "users", "alice");
    defer if (val) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("creds_alice", val.?);

    const missing = try db.get(std.testing.allocator, "users", "charlie");
    try std.testing.expect(missing == null);
}

test "LmdbBackend: delete" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();

    try db.put("users", "alice", "creds");
    try db.delete("users", "alice");

    const val = try db.get(std.testing.allocator, "users", "alice");
    try std.testing.expect(val == null);

    try db.delete("users", "nonexistent");
}

test "LmdbBackend: overwrite value" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();

    try db.put("users", "alice", "old");
    try db.put("users", "alice", "new");

    const val = try db.get(std.testing.allocator, "users", "alice");
    defer if (val) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("new", val.?);
}

test "LmdbBackend: separate namespaces" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
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

test "LmdbBackend: iterator prefix-bounded" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
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

test "LmdbBackend: iterator returns key and value" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();

    try db.put("data", "key1", "value1");

    var iter = try db.iterator("data", "key");
    defer iter.deinit();

    const entry = iter.next() orelse return error.ExpectedEntry;
    try std.testing.expectEqualStrings("key1", entry.key);
    try std.testing.expectEqualStrings("value1", entry.value);
}

test "LmdbBackend: writeBatch commit" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();

    var batch = try db.writeBatch();
    try batch.put("users", "alice", "a");
    try batch.put("users", "bob", "b");
    try batch.commit();

    const a = try db.get(std.testing.allocator, "users", "alice");
    defer if (a) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("a", a.?);

    const b = try db.get(std.testing.allocator, "users", "bob");
    defer if (b) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("b", b.?);
}

test "LmdbBackend: writeBatch abort" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{});
    defer db.close();

    var batch = try db.writeBatch();
    try batch.put("users", "alice", "a");
    batch.abort();

    const val = try db.get(std.testing.allocator, "users", "alice");
    try std.testing.expect(val == null);
}
