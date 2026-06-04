//! # RocksDB Storage Backend
//!
//! Implements the StorageBackend trait using RocksDB's C API.
//! Namespaces map to column families, cached on first access.
//! Links against system librocksdb (databases/rocksdb in FreeBSD ports).

const std = @import("std");
const backend = @import("backend");
const c = @cImport(@cInclude("rocksdb/c.h"));

const log = std.log.scoped(.rocksdb_store);

const MAX_COLUMN_FAMILIES = 16;

const CfCacheEntry = struct {
    name_buf: [64]u8,
    name_len: u8,
    handle: *c.rocksdb_column_family_handle_t,
};

pub const RocksDbBackend = struct {
    db: *c.rocksdb_t,
    options: *c.rocksdb_options_t,
    read_opts: *c.rocksdb_readoptions_t,
    write_opts: *c.rocksdb_writeoptions_t,
    cf_cache: [MAX_COLUMN_FAMILIES]CfCacheEntry,
    cf_count: u32,
    path_buf: [4096]u8,
    path_len: usize,

    comptime {
        backend.assertBackend(RocksDbBackend);
    }

    pub fn open(path: []const u8, opts: backend.OpenOptions) !RocksDbBackend {
        _ = opts;

        if (path.len >= 4096) return error.NameTooLong;

        const options = c.rocksdb_options_create() orelse return error.OutOfMemory;
        c.rocksdb_options_set_create_if_missing(options, 1);
        c.rocksdb_options_set_create_missing_column_families(options, 1);
        c.rocksdb_options_set_compression(options, c.rocksdb_lz4_compression);

        var path_z: [4096]u8 = undefined;
        @memcpy(path_z[0..path.len], path);
        path_z[path.len] = 0;

        // Try to list existing column families
        var cf_count: usize = 0;
        var err: [*c]u8 = null;

        const cf_names = c.rocksdb_list_column_families(
            options,
            @ptrCast(path_z[0..path.len :0]),
            &cf_count,
            &err,
        );

        // If DB doesn't exist yet, open with just default CF
        if (err != null or cf_names == null) {
            if (err != null) c.rocksdb_free(@ptrCast(err));
            err = null;

            const db = c.rocksdb_open(
                options,
                @ptrCast(path_z[0..path.len :0]),
                &err,
            ) orelse {
                if (err != null) {
                    log.err("rocksdb_open: {s}", .{std.mem.span(err)});
                    c.rocksdb_free(@ptrCast(err));
                }
                c.rocksdb_options_destroy(options);
                return error.RocksDbOpenFailed;
            };

            var self = RocksDbBackend{
                .db = db,
                .options = options,
                .read_opts = c.rocksdb_readoptions_create() orelse {
                    c.rocksdb_close(db);
                    c.rocksdb_options_destroy(options);
                    return error.OutOfMemory;
                },
                .write_opts = c.rocksdb_writeoptions_create() orelse {
                    c.rocksdb_close(db);
                    c.rocksdb_options_destroy(options);
                    return error.OutOfMemory;
                },
                .cf_cache = undefined,
                .cf_count = 0,
                .path_buf = undefined,
                .path_len = path.len,
            };
            @memcpy(self.path_buf[0..path.len], path);
            return self;
        }

        // Open with all existing column families
        const num_cfs = @min(cf_count, MAX_COLUMN_FAMILIES);
        var cf_opts_arr: [MAX_COLUMN_FAMILIES]*c.rocksdb_options_t = undefined;
        var cf_handles_arr: [MAX_COLUMN_FAMILIES]?*c.rocksdb_column_family_handle_t = undefined;
        var cf_names_z: [MAX_COLUMN_FAMILIES][*c]const u8 = undefined;

        for (0..num_cfs) |i| {
            cf_opts_arr[i] = options;
            cf_names_z[i] = @ptrCast(cf_names[i]);
        }

        const db = c.rocksdb_open_column_families(
            options,
            @ptrCast(path_z[0..path.len :0]),
            @intCast(num_cfs),
            @ptrCast(&cf_names_z),
            @ptrCast(&cf_opts_arr),
            @ptrCast(&cf_handles_arr),
            &err,
        ) orelse {
            if (err != null) {
                log.err("rocksdb_open_column_families: {s}", .{std.mem.span(err)});
                c.rocksdb_free(@ptrCast(err));
            }
            c.rocksdb_options_destroy(options);
            c.rocksdb_list_column_families_destroy(cf_names, cf_count);
            return error.RocksDbOpenFailed;
        };

        var self = RocksDbBackend{
            .db = db,
            .options = options,
            .read_opts = c.rocksdb_readoptions_create() orelse {
                c.rocksdb_close(db);
                c.rocksdb_options_destroy(options);
                c.rocksdb_list_column_families_destroy(cf_names, cf_count);
                return error.OutOfMemory;
            },
            .write_opts = c.rocksdb_writeoptions_create() orelse {
                c.rocksdb_close(db);
                c.rocksdb_options_destroy(options);
                c.rocksdb_list_column_families_destroy(cf_names, cf_count);
                return error.OutOfMemory;
            },
            .cf_cache = undefined,
            .cf_count = 0,
            .path_buf = undefined,
            .path_len = path.len,
        };
        @memcpy(self.path_buf[0..path.len], path);

        // Cache non-default column family handles
        for (0..num_cfs) |i| {
            const name_ptr: [*:0]const u8 = @ptrCast(cf_names[i]);
            const name_len = std.mem.len(name_ptr);
            const name = name_ptr[0..name_len];

            // Skip "default" CF — we don't use it for namespaced data
            if (std.mem.eql(u8, name, "default")) {
                if (cf_handles_arr[i]) |h| {
                    c.rocksdb_column_family_handle_destroy(h);
                }
                continue;
            }

            if (self.cf_count < MAX_COLUMN_FAMILIES) {
                var entry = &self.cf_cache[self.cf_count];
                const copy_len = @min(name_len, 64);
                @memcpy(entry.name_buf[0..copy_len], name[0..copy_len]);
                entry.name_len = @intCast(copy_len);
                entry.handle = cf_handles_arr[i].?;
                self.cf_count += 1;
            } else {
                if (cf_handles_arr[i]) |h| {
                    c.rocksdb_column_family_handle_destroy(h);
                }
            }
        }

        c.rocksdb_list_column_families_destroy(cf_names, cf_count);
        return self;
    }

    pub fn close(self: *RocksDbBackend) void {
        for (self.cf_cache[0..self.cf_count]) |entry| {
            c.rocksdb_column_family_handle_destroy(entry.handle);
        }
        c.rocksdb_readoptions_destroy(self.read_opts);
        c.rocksdb_writeoptions_destroy(self.write_opts);
        c.rocksdb_close(self.db);
        c.rocksdb_options_destroy(self.options);
    }

    pub fn get(self: *RocksDbBackend, allocator: std.mem.Allocator, ns: []const u8, key: []const u8) !?[]u8 {
        const cf = try self.getOrCreateCf(ns);
        var val_len: usize = 0;
        var err: [*c]u8 = null;

        const val_ptr = c.rocksdb_get_cf(
            self.db,
            self.read_opts,
            cf,
            key.ptr,
            key.len,
            &val_len,
            &err,
        );

        if (err != null) {
            log.err("rocksdb_get_cf: {s}", .{std.mem.span(err)});
            c.rocksdb_free(@ptrCast(err));
            return error.RocksDbReadFailed;
        }

        if (val_ptr == null) return null;

        const result = try allocator.alloc(u8, val_len);
        @memcpy(result, @as([*]const u8, @ptrCast(val_ptr))[0..val_len]);
        c.rocksdb_free(@ptrCast(val_ptr));
        return result;
    }

    pub fn put(self: *RocksDbBackend, ns: []const u8, key: []const u8, value: []const u8) !void {
        const cf = try self.getOrCreateCf(ns);
        var err: [*c]u8 = null;

        c.rocksdb_put_cf(
            self.db,
            self.write_opts,
            cf,
            key.ptr,
            key.len,
            value.ptr,
            value.len,
            &err,
        );

        if (err != null) {
            log.err("rocksdb_put_cf: {s}", .{std.mem.span(err)});
            c.rocksdb_free(@ptrCast(err));
            return error.RocksDbWriteFailed;
        }
    }

    pub fn delete(self: *RocksDbBackend, ns: []const u8, key: []const u8) !void {
        const cf = try self.getOrCreateCf(ns);
        var err: [*c]u8 = null;

        c.rocksdb_delete_cf(
            self.db,
            self.write_opts,
            cf,
            key.ptr,
            key.len,
            &err,
        );

        if (err != null) {
            log.err("rocksdb_delete_cf: {s}", .{std.mem.span(err)});
            c.rocksdb_free(@ptrCast(err));
            return error.RocksDbWriteFailed;
        }
    }

    pub fn iterator(self: *RocksDbBackend, ns: []const u8, prefix: []const u8) !Iterator {
        const cf = try self.getOrCreateCf(ns);

        const iter = c.rocksdb_create_iterator_cf(
            self.db,
            self.read_opts,
            cf,
        ) orelse return error.OutOfMemory;

        var it = Iterator{
            .iter = iter,
            .prefix = undefined,
            .prefix_len = @min(prefix.len, 256),
            .started = false,
        };
        @memcpy(it.prefix[0..it.prefix_len], prefix[0..it.prefix_len]);
        return it;
    }

    pub fn writeBatch(self: *RocksDbBackend) !WriteBatch {
        const batch = c.rocksdb_writebatch_create() orelse return error.OutOfMemory;
        return .{
            .batch = batch,
            .backend = self,
        };
    }

    // -- Iterator --

    pub const Iterator = struct {
        iter: *c.rocksdb_iterator_t,
        prefix: [256]u8,
        prefix_len: usize,
        started: bool,

        pub fn next(self: *Iterator) ?backend.Entry {
            if (!self.started) {
                self.started = true;
                if (self.prefix_len == 0) {
                    c.rocksdb_iter_seek_to_first(self.iter);
                } else {
                    c.rocksdb_iter_seek(
                        self.iter,
                        &self.prefix,
                        self.prefix_len,
                    );
                }
            } else {
                c.rocksdb_iter_next(self.iter);
            }

            if (c.rocksdb_iter_valid(self.iter) == 0) return null;

            var key_len: usize = 0;
            const key_ptr = c.rocksdb_iter_key(self.iter, &key_len);
            if (key_ptr == null) return null;

            const key: [*]const u8 = @ptrCast(key_ptr);

            // Prefix-bound check
            if (self.prefix_len > 0) {
                if (key_len < self.prefix_len) return null;
                if (!std.mem.startsWith(u8, key[0..key_len], self.prefix[0..self.prefix_len]))
                    return null;
            }

            var val_len: usize = 0;
            const val_ptr = c.rocksdb_iter_value(self.iter, &val_len);
            const value: [*]const u8 = if (val_ptr) |v| @ptrCast(v) else "";

            return .{
                .key = key[0..key_len],
                .value = value[0..val_len],
            };
        }

        pub fn deinit(self: *Iterator) void {
            c.rocksdb_iter_destroy(self.iter);
        }
    };

    // -- WriteBatch --

    pub const WriteBatch = struct {
        batch: *c.rocksdb_writebatch_t,
        backend: *RocksDbBackend,

        pub fn put(self: *WriteBatch, ns: []const u8, key: []const u8, value: []const u8) !void {
            const cf = try self.backend.getOrCreateCf(ns);
            c.rocksdb_writebatch_put_cf(
                self.batch,
                cf,
                key.ptr,
                key.len,
                value.ptr,
                value.len,
            );
        }

        pub fn delete(self: *WriteBatch, ns: []const u8, key: []const u8) !void {
            const cf = try self.backend.getOrCreateCf(ns);
            c.rocksdb_writebatch_delete_cf(
                self.batch,
                cf,
                key.ptr,
                key.len,
            );
        }

        pub fn commit(self: *WriteBatch) !void {
            var err: [*c]u8 = null;
            c.rocksdb_write(
                self.backend.db,
                self.backend.write_opts,
                self.batch,
                &err,
            );
            c.rocksdb_writebatch_destroy(self.batch);

            if (err != null) {
                log.err("rocksdb_write: {s}", .{std.mem.span(err)});
                c.rocksdb_free(@ptrCast(err));
                return error.RocksDbWriteFailed;
            }
        }

        pub fn abort(self: *WriteBatch) void {
            c.rocksdb_writebatch_destroy(self.batch);
        }
    };

    // -- Internal --

    fn getOrCreateCf(self: *RocksDbBackend, ns: []const u8) !*c.rocksdb_column_family_handle_t {
        // Check cache
        for (self.cf_cache[0..self.cf_count]) |entry| {
            if (std.mem.eql(u8, entry.name_buf[0..entry.name_len], ns))
                return entry.handle;
        }

        if (self.cf_count >= MAX_COLUMN_FAMILIES) return error.TooManyColumnFamilies;
        if (ns.len > 64) return error.NameTooLong;

        // Create new column family
        var name_z: [65]u8 = undefined;
        @memcpy(name_z[0..ns.len], ns);
        name_z[ns.len] = 0;

        var err: [*c]u8 = null;
        const cf_opts = c.rocksdb_options_create() orelse return error.OutOfMemory;
        defer c.rocksdb_options_destroy(cf_opts);

        const handle = c.rocksdb_create_column_family(
            self.db,
            cf_opts,
            @ptrCast(name_z[0..ns.len :0]),
            &err,
        ) orelse {
            if (err != null) {
                log.err("rocksdb_create_column_family: {s}", .{std.mem.span(err)});
                c.rocksdb_free(@ptrCast(err));
            }
            return error.RocksDbCfCreateFailed;
        };

        var entry = &self.cf_cache[self.cf_count];
        @memcpy(entry.name_buf[0..ns.len], ns);
        entry.name_len = @intCast(ns.len);
        entry.handle = handle;
        self.cf_count += 1;

        return handle;
    }
};

// ============================================================================
// Tests
// ============================================================================

fn freshTestDir() []const u8 {
    const path = "/tmp/xmppd-test-rocksdb";
    std.fs.cwd().deleteTree(path) catch {};
    return path;
}

test "RocksDbBackend: open and close" {
    const path = freshTestDir();
    var db = try RocksDbBackend.open(path, .{});
    db.close();
}

test "RocksDbBackend: put and get" {
    const path = freshTestDir();
    var db = try RocksDbBackend.open(path, .{});
    defer db.close();

    try db.put("users", "alice", "creds_alice");
    try db.put("users", "bob", "creds_bob");

    const val = try db.get(std.testing.allocator, "users", "alice");
    defer if (val) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("creds_alice", val.?);

    const missing = try db.get(std.testing.allocator, "users", "charlie");
    try std.testing.expect(missing == null);
}

test "RocksDbBackend: delete" {
    const path = freshTestDir();
    var db = try RocksDbBackend.open(path, .{});
    defer db.close();

    try db.put("users", "alice", "creds");
    try db.delete("users", "alice");

    const val = try db.get(std.testing.allocator, "users", "alice");
    try std.testing.expect(val == null);

    // Deleting non-existent key should not error
    try db.delete("users", "nonexistent");
}

test "RocksDbBackend: overwrite value" {
    const path = freshTestDir();
    var db = try RocksDbBackend.open(path, .{});
    defer db.close();

    try db.put("users", "alice", "old");
    try db.put("users", "alice", "new");

    const val = try db.get(std.testing.allocator, "users", "alice");
    defer if (val) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("new", val.?);
}

test "RocksDbBackend: separate namespaces" {
    const path = freshTestDir();
    var db = try RocksDbBackend.open(path, .{});
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

test "RocksDbBackend: iterator prefix-bounded" {
    const path = freshTestDir();
    var db = try RocksDbBackend.open(path, .{});
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

test "RocksDbBackend: iterator returns key and value" {
    const path = freshTestDir();
    var db = try RocksDbBackend.open(path, .{});
    defer db.close();

    try db.put("data", "key1", "value1");

    var iter = try db.iterator("data", "key");
    defer iter.deinit();

    const entry = iter.next() orelse return error.ExpectedEntry;
    try std.testing.expectEqualStrings("key1", entry.key);
    try std.testing.expectEqualStrings("value1", entry.value);
}

test "RocksDbBackend: writeBatch commit" {
    const path = freshTestDir();
    var db = try RocksDbBackend.open(path, .{});
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

test "RocksDbBackend: writeBatch abort" {
    const path = freshTestDir();
    var db = try RocksDbBackend.open(path, .{});
    defer db.close();

    var batch = try db.writeBatch();
    try batch.put("users", "alice", "a");
    batch.abort();

    const val = try db.get(std.testing.allocator, "users", "alice");
    try std.testing.expect(val == null);
}

test "RocksDbBackend: reopen preserves data" {
    const path = freshTestDir();
    {
        var db = try RocksDbBackend.open(path, .{});
        try db.put("users", "alice", "persisted");
        db.close();
    }
    {
        var db = try RocksDbBackend.open(path, .{});
        defer db.close();
        const val = try db.get(std.testing.allocator, "users", "alice");
        defer if (val) |v| std.testing.allocator.free(v);
        try std.testing.expectEqualStrings("persisted", val.?);
    }
}
