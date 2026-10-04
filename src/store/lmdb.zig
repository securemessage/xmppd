//! # LMDB Storage Backend
//!
//! Implements the StorageBackend trait using LMDB (via zig-lmdb).
//! Namespaces map to LMDB named databases (DBI handles): the canonical set
//! (backend.canonical_namespaces) is opened at startup under one write
//! transaction; any other namespace is created lazily under dbi_lock (S9 —
//! cache mutation is mutex-guarded, and the env map size is never resized
//! at runtime because LMDB documents that as unsafe with open read txns;
//! MAP_FULL surfaces as an error, tune via [server] lmdb_map_size_mb).

const std = @import("std");
const lmdb = @import("lmdb");
const backend = @import("backend");

const log = std.log.scoped(.lmdb_store);

const MAX_DBS = 16;

const DbiCacheEntry = struct {
    name_buf: [64]u8,
    name_len: u8,
    dbi: lmdb.Database.DBI,
};

pub const Backend = LmdbBackend;

pub const LmdbBackend = struct {
    env: lmdb.Environment,
    dbi_cache: [MAX_DBS]DbiCacheEntry,
    dbi_count: u32,
    map_size: usize,
    /// Guards dbi_cache lookups/appends (S9); also serializes writes of
    /// dbi_count from WriteBatch abort.
    dbi_lock: std.Thread.Mutex = .{},
    /// Set once the 80% warning has fired.
    usage_warned: bool = false,

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

        var self: LmdbBackend = .{
            .env = env,
            .dbi_cache = undefined,
            .dbi_count = 0,
            .map_size = opts.map_size,
        };
        if (!opts.read_only) try self.openCanonicalNamespaces();
        self.warnIfNearlyFull();
        return self;
    }

    /// Open every canonical namespace in one write transaction (S9): no
    /// worker thread creates a DBI mid-operation, so the cache races in
    /// getOrCreateDbi/resolveDbi can only ever fire for a genuinely new
    /// (test-only) namespace.
    fn openCanonicalNamespaces(self: *LmdbBackend) !void {
        const txn = try lmdb.Transaction.init(self.env, .{ .mode = .ReadWrite });
        errdefer txn.abort();
        for (backend.canonical_namespaces) |ns| {
            var name_z: [65]u8 = undefined;
            if (ns.len > 64) return error.MDB_BAD_VALSIZE;
            @memcpy(name_z[0..ns.len], ns);
            name_z[ns.len] = 0;
            const db = try lmdb.Database.open(txn, @ptrCast(name_z[0..ns.len :0]), .{ .create = true });
            const entry = &self.dbi_cache[self.dbi_count];
            @memcpy(entry.name_buf[0..ns.len], ns);
            entry.name_len = @intCast(ns.len);
            entry.dbi = db.dbi;
            self.dbi_count += 1;
        }
        try txn.commit();
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
        const txn = try lmdb.Transaction.init(self.env, .{ .mode = .ReadWrite });
        errdefer txn.abort();
        const db = lmdb.Database{ .txn = txn, .dbi = dbi };
        try db.set(key, value);
        try txn.commit();
        self.warnIfNearlyFull();
    }

    /// Log once when live content crosses 80% of the map. LMDB documents
    /// env resizing with open read transactions as unsafe, so a full map is
    /// an operational error (restart with a bigger configured map) rather
    /// than something we paper over at runtime (S9).
    fn warnIfNearlyFull(self: *LmdbBackend) void {
        if (self.usage_warned) return;
        const st = self.env.stat() catch return;
        const used_bytes = (@as(usize, st.branch_pages + st.leaf_pages + st.overflow_pages)) * @as(usize, st.psize);
        if (used_bytes > self.map_size / 5 * 4) {
            self.usage_warned = true;
            log.warn("LMDB map above 80% used ({d} of {d} bytes) — raise [server] lmdb_map_size_mb and restart before MAP_FULL", .{ used_bytes, self.map_size });
        }
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
        self.dbi_lock.lock();
        const dc = self.dbi_count;
        self.dbi_lock.unlock();
        return .{ .txn = txn, .backend = self, .dbi_count_at_start = dc };
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
                if (self.prefix_len == 0) {
                    break :blk self.cursor.goToFirst() catch return null;
                } else {
                    break :blk self.cursor.seek(self.prefix[0..self.prefix_len]) catch return null;
                }
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
            self.backend.dbi_lock.lock();
            self.backend.dbi_count = self.dbi_count_at_start;
            self.backend.dbi_lock.unlock();
        }

        fn resolveDbi(self: *WriteBatch, ns: []const u8) !lmdb.Database.DBI {
            self.backend.dbi_lock.lock();
            defer self.backend.dbi_lock.unlock();
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
        // S9: lookup and lazy creation share this lock; canonical namespaces
        // are already open so this contends only for test/unknown names.
        self.dbi_lock.lock();
        defer self.dbi_lock.unlock();
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

test "LmdbBackend: MAP_FULL is a hard error — no runtime env resize (T358/S9)" {
    const path = freshTestDir();
    var db = try LmdbBackend.open(path, .{ .map_size = 128 * 1024 });
    defer db.close();

    var big: [16384]u8 = @splat('x');
    var key_buf: [32]u8 = undefined;
    var got_full = false;
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        const key = std.fmt.bufPrint(&key_buf, "k{d}", .{i}) catch unreachable;
        db.put("users", key, &big) catch |err| {
            if (err == error.MDB_MAP_FULL) {
                got_full = true;
                break;
            }
            return err;
        };
    }
    try std.testing.expect(got_full);
    // The map size is untouched: nothing resized underneath readers.
    try std.testing.expectEqual(@as(usize, 128 * 1024), db.map_size);
}
