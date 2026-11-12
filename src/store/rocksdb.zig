//! # RocksDB Storage Backend
//!
//! Implements the StorageBackend trait using RocksDB's C API.
//! Namespaces map to column families, cached on first access.
//! Links against system librocksdb (databases/rocksdb in FreeBSD ports).

const std = @import("std");
const backend = @import("backend");
const c = @cImport(@cInclude("rocksdb/c.h"));

const log = std.log.scoped(.rocksdb_store);

const MAX_COLUMN_FAMILIES = 24;

const CfCacheEntry = struct {
    name_buf: [64]u8,
    name_len: u8,
    handle: *c.rocksdb_column_family_handle_t,
};

pub const Backend = RocksDbBackend;

pub const RocksDbBackend = struct {
    db: *c.rocksdb_t,
    options: *c.rocksdb_options_t,
    read_opts: *c.rocksdb_readoptions_t,
    write_opts: *c.rocksdb_writeoptions_t,
    cf_cache: [MAX_COLUMN_FAMILIES]CfCacheEntry,
    cf_count: u32,
    path_buf: [4096]u8,
    path_len: usize,
    compound_mutex: std.Thread.Mutex = .{},
    /// Guards cf_cache lookups/appends (S9): canonical column families are
    /// created at open(); the lock covers only test/unknown names.
    cf_lock: std.Thread.Mutex = .{},
    /// Serializes putIfAbsent claim checks in this process; held by a batch
    /// from its first putIfAbsent until the batch ends.
    claim_mutex: std.Thread.Mutex = .{},
    /// RocksDB reads are MVCC snapshots and cannot observe a half-applied
    /// write, so they do not need the store's compound lock (S9).
    pub const reads_are_snapshot = true;

    /// putIfAbsent claim checks run under claim_mutex, which only orders
    /// batches inside this process. Nothing stops a second daemon on the
    /// same DB from interleaving a claim, so OIDC account binding is not
    /// safe on this backend.
    pub const cross_process_claims = false;

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

        // Write performance tuning: reduce compaction stall impact on the event loop.
        // - 4 write buffers (default 2): more runway before L0 flush is forced
        // - 128MB write buffer (default 64MB): less frequent flushes
        // - L0 slowdown at 20 files (default 20): keep default, avoids premature throttle
        // - L0 stop at 36 files (default 36): keep default
        // - Max background jobs 4 (default 1): parallel compaction + flush
        // - Bytes-per-sync 1MB: spread fsync over time, avoid write stalls from OS page cache flush
        c.rocksdb_options_set_max_write_buffer_number(options, 4);
        c.rocksdb_options_set_write_buffer_size(options, 128 * 1024 * 1024);
        c.rocksdb_options_set_max_background_jobs(options, 4);
        c.rocksdb_options_set_bytes_per_sync(options, 1024 * 1024);

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
            try self.ensureCanonicalCfs();
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
        try self.ensureCanonicalCfs();
        return self;
    }

    /// Canonical namespaces exist as column families from day one (S9), so
    /// workers never race lazy creation on the cf cache.
    fn ensureCanonicalCfs(self: *RocksDbBackend) !void {
        for (backend.canonical_namespaces) |ns| _ = try self.getOrCreateCf(ns);
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
        if (prefix.len > backend.MAX_PREFIX_LEN) return error.PrefixTooLong;
        const cf = try self.getOrCreateCf(ns);

        const iter = c.rocksdb_create_iterator_cf(
            self.db,
            self.read_opts,
            cf,
        ) orelse return error.OutOfMemory;

        var it = Iterator{
            .iter = iter,
            .prefix = undefined,
            .prefix_len = prefix.len,
            .started = false,
        };
        @memcpy(it.prefix[0..it.prefix_len], prefix);
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
        prefix: [backend.MAX_PREFIX_LEN]u8,
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
        batch: ?*c.rocksdb_writebatch_t,
        backend: *RocksDbBackend,
        /// End attempts so far (commit or abort). abort() after a commit
        /// attempt is a no-op (S9); the count keeps a guard violation
        /// observable instead of a silent double destroy.
        ends: u8 = 0,
        /// Set while this batch holds backend.claim_mutex (putIfAbsent).
        claim_held: bool = false,
        /// Keys this batch claimed through putIfAbsent (c_allocator dupes;
        /// freed by releaseClaims). Bounded by max_claims_per_batch.
        claimed: std.ArrayListUnmanaged(Claimed) = .empty,
        /// Test-only fault hook (S9): the commit fails the way a RocksDB
        /// write error does, without driving the C layer.
        fail_commit: bool = false,

        const Claimed = struct { ns: []u8, key: []u8 };
        const max_claims_per_batch = 256;

        /// In-process read under the same serialization putIfAbsent uses:
        /// claim_mutex is held from the first get or putIfAbsent until the
        /// batch ends, so a get-then-putIfAbsent pair is atomic against
        /// other batches in this process (not across processes). Sees
        /// committed state plus this batch's own putIfAbsent claims; a
        /// pending plain put() is not modeled.
        pub fn get(self: *WriteBatch, allocator: std.mem.Allocator, ns: []const u8, key: []const u8) !?[]u8 {
            if (!self.claim_held) {
                self.backend.claim_mutex.lock();
                self.claim_held = true;
            }
            for (self.claimed.items) |cl| {
                if (std.mem.eql(u8, cl.ns, ns) and std.mem.eql(u8, cl.key, key))
                    return try allocator.dupe(u8, "");
            }
            return self.backend.get(allocator, ns, key);
        }

        /// In-process conditional insert: the committed-state check runs
        /// under claim_mutex, held until the batch ends, so two batches in
        /// this process cannot both claim the same key. RocksDB WriteBatch
        /// cannot express a conditional, so this is not atomic against a
        /// second process or against writers that do not use putIfAbsent.
        pub fn putIfAbsent(self: *WriteBatch, ns: []const u8, key: []const u8, value: []const u8) !void {
            if (!self.claim_held) {
                self.backend.claim_mutex.lock();
                self.claim_held = true;
            }
            for (self.claimed.items) |cl| {
                if (std.mem.eql(u8, cl.ns, ns) and std.mem.eql(u8, cl.key, key)) return error.Conflict;
            }
            const existing = try self.backend.get(std.heap.c_allocator, ns, key);
            if (existing) |v| {
                std.heap.c_allocator.free(v);
                return error.Conflict;
            }
            if (self.claimed.items.len >= max_claims_per_batch) return error.ClaimLimit;
            const ns_copy = try std.heap.c_allocator.dupe(u8, ns);
            errdefer std.heap.c_allocator.free(ns_copy);
            const key_copy = try std.heap.c_allocator.dupe(u8, key);
            errdefer std.heap.c_allocator.free(key_copy);
            try self.claimed.append(std.heap.c_allocator, .{ .ns = ns_copy, .key = key_copy });
            try self.put(ns, key, value);
        }

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
            // A write is atomic and the C batch is destroyed once either
            // way: abort() after a commit attempt is a no-op (S9).
            self.ends += 1;
            if (self.fail_commit) {
                self.destroyBatch();
                return error.RocksDbWriteFailed;
            }
            var err: [*c]u8 = null;
            c.rocksdb_write(
                self.backend.db,
                self.backend.write_opts,
                self.batch,
                &err,
            );
            self.destroyBatch();

            if (err != null) {
                log.err("rocksdb_write: {s}", .{std.mem.span(err)});
                c.rocksdb_free(@ptrCast(err));
                return error.RocksDbWriteFailed;
            }
        }

        pub fn abort(self: *WriteBatch) void {
            if (self.ends > 0) return;
            self.ends += 1;
            self.destroyBatch();
        }

        fn destroyBatch(self: *WriteBatch) void {
            self.releaseClaims();
            if (self.batch) |b| {
                c.rocksdb_writebatch_destroy(b);
                self.batch = null;
            }
        }

        fn releaseClaims(self: *WriteBatch) void {
            for (self.claimed.items) |cl| {
                std.heap.c_allocator.free(cl.ns);
                std.heap.c_allocator.free(cl.key);
            }
            self.claimed.deinit(std.heap.c_allocator);
            self.claimed = .empty;
            if (self.claim_held) {
                self.backend.claim_mutex.unlock();
                self.claim_held = false;
            }
        }
    };

    // -- Internal --

    fn getOrCreateCf(self: *RocksDbBackend, ns: []const u8) !*c.rocksdb_column_family_handle_t {
        // S9: cache lookup and lazy creation share this lock.
        self.cf_lock.lock();
        defer self.cf_lock.unlock();
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

/// A path unique to this process and call, so two suites running at once do
/// not open and delete each other's database.
fn freshTestDir(buf: []u8) []const u8 {
    test_dir_seq += 1;
    return std.fmt.bufPrint(buf, "/tmp/xmppd-test-rocksdb-{d}-{d}", .{ std.c.getpid(), test_dir_seq }) catch unreachable;
}

var test_dir_seq: u32 = 0;

test "RocksDbBackend: open and close" {
    var path_buf: [64]u8 = undefined;
    const path = freshTestDir(&path_buf);
    defer std.fs.cwd().deleteTree(path) catch {};
    var db = try RocksDbBackend.open(path, .{});
    db.close();
}

test "RocksDbBackend: putIfAbsent claims once and conflicts on committed keys" {
    var path_buf: [64]u8 = undefined;
    const path = freshTestDir(&path_buf);
    defer std.fs.cwd().deleteTree(path) catch {};
    var db = try RocksDbBackend.open(path, .{});
    defer db.close();

    var b1 = try db.writeBatch();
    try b1.putIfAbsent("users", "alice", "v1");
    try std.testing.expectError(error.Conflict, b1.putIfAbsent("users", "alice", "v2"));
    try b1.commit();

    var b2 = try db.writeBatch();
    try std.testing.expectError(error.Conflict, b2.putIfAbsent("users", "alice", "v3"));
    try b2.commit();

    const got = try db.get(std.testing.allocator, "users", "alice");
    defer if (got) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("v1", got.?);
}

test "RocksDbBackend: put and get" {
    var path_buf: [64]u8 = undefined;
    const path = freshTestDir(&path_buf);
    defer std.fs.cwd().deleteTree(path) catch {};
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
    var path_buf: [64]u8 = undefined;
    const path = freshTestDir(&path_buf);
    defer std.fs.cwd().deleteTree(path) catch {};
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
    var path_buf: [64]u8 = undefined;
    const path = freshTestDir(&path_buf);
    defer std.fs.cwd().deleteTree(path) catch {};
    var db = try RocksDbBackend.open(path, .{});
    defer db.close();

    try db.put("users", "alice", "old");
    try db.put("users", "alice", "new");

    const val = try db.get(std.testing.allocator, "users", "alice");
    defer if (val) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("new", val.?);
}

test "RocksDbBackend: separate namespaces" {
    var path_buf: [64]u8 = undefined;
    const path = freshTestDir(&path_buf);
    defer std.fs.cwd().deleteTree(path) catch {};
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
    var path_buf: [64]u8 = undefined;
    const path = freshTestDir(&path_buf);
    defer std.fs.cwd().deleteTree(path) catch {};
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

test "RocksDbBackend: iterator honors a prefix past 256 bytes and rejects over-cap" {
    var path_buf: [64]u8 = undefined;
    const path = freshTestDir(&path_buf);
    defer std.fs.cwd().deleteTree(path) catch {};
    var db = try RocksDbBackend.open(path, .{});
    defer db.close();

    // Two owners whose scan prefixes share the first 290 bytes: any
    // fixed-size clip shorter than the prefix merges their rows.
    const owner_a = ("a" ** 290) ++ "-first";
    const owner_b = ("a" ** 290) ++ "-other";
    comptime std.debug.assert(std.mem.eql(u8, owner_a[0..290], owner_b[0..290]));

    const ns = comptime backend.registered("rosters");
    const key_a = owner_a ++ "\x00item1";
    const key_b = owner_b ++ "\x00item2";
    try db.put(ns, key_a, "a");
    try db.put(ns, key_b, "b");

    const prefix = owner_a ++ "\x00";

    // Collect-then-delete, the pattern removeAll/destroyRoom callers use.
    var keys: [4][backend.MAX_PREFIX_LEN]u8 = undefined;
    var key_lens: [4]usize = undefined;
    var scanned: usize = 0;
    {
        var iter = try db.iterator(ns, prefix);
        defer iter.deinit();
        while (iter.next()) |entry| {
            if (scanned == keys.len) return error.TooManyEntries;
            @memcpy(keys[scanned][0..entry.key.len], entry.key);
            key_lens[scanned] = entry.key.len;
            scanned += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), scanned);
    try std.testing.expectEqualStrings(key_a, keys[0][0..key_lens[0]]);

    for (key_lens[0..scanned], 0..) |len, i| {
        try db.delete(ns, keys[i][0..len]);
    }
    const b_val = try db.get(std.testing.allocator, ns, key_b);
    defer if (b_val) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("b", b_val.?);

    try std.testing.expectError(error.PrefixTooLong, db.iterator(ns, "x" ** (backend.MAX_PREFIX_LEN + 1)));
}

test "RocksDbBackend: iterator returns key and value" {
    var path_buf: [64]u8 = undefined;
    const path = freshTestDir(&path_buf);
    defer std.fs.cwd().deleteTree(path) catch {};
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
    var path_buf: [64]u8 = undefined;
    const path = freshTestDir(&path_buf);
    defer std.fs.cwd().deleteTree(path) catch {};
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
    var path_buf: [64]u8 = undefined;
    const path = freshTestDir(&path_buf);
    defer std.fs.cwd().deleteTree(path) catch {};
    var db = try RocksDbBackend.open(path, .{});
    defer db.close();

    var batch = try db.writeBatch();
    try batch.put("users", "alice", "a");
    batch.abort();

    const val = try db.get(std.testing.allocator, "users", "alice");
    try std.testing.expect(val == null);
}

test "RocksDbBackend: abort after a commit attempt is a no-op" {
    var path_buf: [64]u8 = undefined;
    const path = freshTestDir(&path_buf);
    defer std.fs.cwd().deleteTree(path) catch {};
    var db = try RocksDbBackend.open(path, .{});
    defer db.close();

    var batch = try db.writeBatch();
    try batch.put("users", "alice", "a");
    try batch.commit();
    try std.testing.expectEqual(@as(u8, 1), batch.ends);
    try std.testing.expect(batch.batch == null);

    batch.abort();
    try std.testing.expectEqual(@as(u8, 1), batch.ends);
    batch.abort();
    try std.testing.expectEqual(@as(u8, 1), batch.ends);
}

test "RocksDbBackend: a failed write ends the batch" {
    var path_buf: [64]u8 = undefined;
    const path = freshTestDir(&path_buf);
    defer std.fs.cwd().deleteTree(path) catch {};
    var db = try RocksDbBackend.open(path, .{});
    defer db.close();

    var batch = try db.writeBatch();
    try batch.put("users", "alice", "a");
    // Fault hook: the commit fails the way a RocksDB write error does.
    batch.fail_commit = true;
    try std.testing.expectError(error.RocksDbWriteFailed, batch.commit());
    try std.testing.expectEqual(@as(u8, 1), batch.ends);
    try std.testing.expect(batch.batch == null);

    // abort() after the commit attempt is a no-op.
    batch.abort();
    try std.testing.expectEqual(@as(u8, 1), batch.ends);

    // Nothing was written.
    const val = try db.get(std.testing.allocator, "users", "alice");
    defer if (val) |v| std.testing.allocator.free(v);
    try std.testing.expect(val == null);
}

test "RocksDbBackend: reopen preserves data" {
    var path_buf: [64]u8 = undefined;
    const path = freshTestDir(&path_buf);
    defer std.fs.cwd().deleteTree(path) catch {};
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

fn expectPrefixScan(db: anytype, ns: []const u8, prefix: []const u8, want: usize) !void {
    var iter = try db.iterator(ns, prefix);
    defer iter.deinit();
    var n: usize = 0;
    while (iter.next()) |e| {
        try std.testing.expect(std.mem.startsWith(u8, e.key, prefix));
        n += 1;
    }
    try std.testing.expectEqual(want, n);
}

test "RocksDbBackend: iterator scan over 0xFF tails, empty prefix, a shared-head owner and the exact cap" {
    var path_buf: [64]u8 = undefined;
    const path = freshTestDir(&path_buf);
    defer std.fs.cwd().deleteTree(path) catch {};
    var db = try RocksDbBackend.open(path, .{});
    defer db.close();
    const ns = comptime backend.registered("rosters");

    // Keys that stress the lexicographic edges of a prefix scan: trailing
    // 0xFF bytes, a key sitting on the computed upper bound, and all-0xFF
    // prefixes. The counts pin the sorted order the scan must honor.
    const ks = [_][]const u8{ "ab\xFE\xFF", "ab\xFF", "ab\xFF\x00x", "ab\xFF\xFF", "ac", "\xFF\xFE", "\xFF\xFF", "\xFF\xFF\x01" };
    for (ks) |k| try db.put(ns, k, "v");
    try expectPrefixScan(&db, ns, "ab\xFF", 3);
    try expectPrefixScan(&db, ns, "ab\xFE", 1);
    try expectPrefixScan(&db, ns, "\xFF\xFF", 2);
    try expectPrefixScan(&db, ns, "\xFF", 3);
    try expectPrefixScan(&db, ns, "", 8);

    // Two owners sharing a 296-byte head: a clipped seek or compare merges
    // their rows.
    const owner_a = ("a" ** 290) ++ "-first\x00";
    const owner_b = ("a" ** 290) ++ "-other\x00";
    try db.put(ns, owner_a ++ "i", "a");
    try db.put(ns, owner_b ++ "i", "b");
    try expectPrefixScan(&db, ns, owner_b, 1);
    try expectPrefixScan(&db, ns, owner_a, 1);

    // An exact-cap prefix must be accepted and matched, not rejected.
    const cap = "c" ** backend.MAX_PREFIX_LEN;
    try db.put(ns, cap, "c");
    try expectPrefixScan(&db, ns, cap, 1);
    try expectPrefixScan(&db, ns, cap[0 .. backend.MAX_PREFIX_LEN - 1], 1);
}
