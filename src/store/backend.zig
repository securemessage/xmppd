//! # Storage Backend Interface
//!
//! Comptime trait that all storage backends must implement. Domain stores
//! (UserStore, RosterStore, ArchiveStore, etc.) are parameterized on a
//! concrete backend type — zero runtime dispatch, full inlining.
//!
//! ## Memory ownership
//!
//! - `get()` returns allocator-owned memory. Caller frees.
//! - `Iterator.next()` returns backend-managed memory valid until the next
//!   `next()` call or `deinit()`. Copy if you need to keep it.
//! - `WriteBatch` accumulates operations and commits atomically.
//!
//! ## Namespace mapping
//!
//! The `ns` parameter maps to backend-specific containers:
//! - LMDB: named database (DBI handle)
//! - RocksDB: column family
//! - SQLite: table name
//!
//! ## Iterator invariant
//!
//! Iterators are prefix-bounded. `next()` returns null when the cursor key
//! no longer starts with the prefix passed to `iterator()`. Each backend
//! enforces this internally — callers never leak data from adjacent
//! namespaces.

const std = @import("std");

/// Options for opening a storage backend.
pub const OpenOptions = struct {
    /// Maximum number of namespaces (LMDB: max_dbs, others: ignored).
    max_namespaces: u32 = 16,

    /// Initial map size in bytes (LMDB-specific, ignored by others).
    /// Auto-resized on MDB_MAP_FULL.
    map_size: usize = 64 * 1024 * 1024,

    /// Create the database/directory if it doesn't exist.
    create: bool = true,

    /// Open in read-only mode.
    read_only: bool = false,
};

/// A key-value entry returned by iterators.
pub const Entry = struct {
    key: []const u8,
    value: []const u8,
};

/// Comptime validation: asserts that type B satisfies the StorageBackend
/// interface. Call at the top of any generic store to get clear compile
/// errors if a backend is incomplete.
///
/// Required interface on B:
///
///   // Lifecycle
///   fn open(path: []const u8, opts: OpenOptions) !B
///   fn close(self: *B) void
///
///   // Key-value (each call is a self-contained transaction)
///   fn get(self: *B, allocator: Allocator, ns: []const u8, key: []const u8) !?[]u8
///   fn put(self: *B, ns: []const u8, key: []const u8, value: []const u8) !void
///   fn delete(self: *B, ns: []const u8, key: []const u8) !void
///
///   // Prefix-bounded iteration
///   fn iterator(self: *B, ns: []const u8, prefix: []const u8) !B.Iterator
///
///   // Atomic batch writes
///   fn writeBatch(self: *B) !B.WriteBatch
///
/// Required on B.Iterator:
///   fn next(self: *Iterator) ?Entry
///   fn deinit(self: *Iterator) void
///
/// Required on B.WriteBatch:
///   fn put(self: *WriteBatch, ns: []const u8, key: []const u8, value: []const u8) !void
///   fn delete(self: *WriteBatch, ns: []const u8, key: []const u8) !void
///   fn commit(self: *WriteBatch) !void
///   fn abort(self: *WriteBatch) void
///
pub fn assertBackend(comptime B: type) void {
    comptime {
        if (!@hasDecl(B, "open"))
            @compileError("StorageBackend missing: open([]const u8, OpenOptions) !B");
        if (!@hasDecl(B, "close"))
            @compileError("StorageBackend missing: close(*B) void");
        if (!@hasDecl(B, "get"))
            @compileError("StorageBackend missing: get(*B, Allocator, []const u8, []const u8) !?[]u8");
        if (!@hasDecl(B, "put"))
            @compileError("StorageBackend missing: put(*B, []const u8, []const u8, []const u8) !void");
        if (!@hasDecl(B, "delete"))
            @compileError("StorageBackend missing: delete(*B, []const u8, []const u8) !void");

        if (!@hasDecl(B, "Iterator"))
            @compileError("StorageBackend missing: const Iterator type");
        if (!@hasDecl(B, "iterator"))
            @compileError("StorageBackend missing: iterator(*B, []const u8, []const u8) !Iterator");
        if (!@hasDecl(B.Iterator, "next"))
            @compileError("StorageBackend.Iterator missing: next(*Iterator) ?Entry");
        if (!@hasDecl(B.Iterator, "deinit"))
            @compileError("StorageBackend.Iterator missing: deinit(*Iterator) void");

        if (!@hasDecl(B, "WriteBatch"))
            @compileError("StorageBackend missing: const WriteBatch type");
        if (!@hasDecl(B, "writeBatch"))
            @compileError("StorageBackend missing: writeBatch(*B) !WriteBatch");
        if (!@hasDecl(B.WriteBatch, "put"))
            @compileError("StorageBackend.WriteBatch missing: put(...)");
        if (!@hasDecl(B.WriteBatch, "delete"))
            @compileError("StorageBackend.WriteBatch missing: delete(...)");
        if (!@hasDecl(B.WriteBatch, "commit"))
            @compileError("StorageBackend.WriteBatch missing: commit(...)");
        if (!@hasDecl(B.WriteBatch, "abort"))
            @compileError("StorageBackend.WriteBatch missing: abort(...)");
    }
}

// ============================================================================
// Tests
// ============================================================================

/// In-memory backend for testing. Stores data in hash maps.
/// Also serves as the reference implementation of the trait contract.
const MemoryBackend = struct {
    const Self = @This();

    namespaces: std.StringHashMapUnmanaged(std.StringHashMapUnmanaged([]const u8)),
    arena: std.heap.ArenaAllocator,
    backing: std.mem.Allocator,

    pub fn open(path: []const u8, opts: OpenOptions) !Self {
        _ = path;
        _ = opts;
        return .{
            .namespaces = .{},
            .arena = std.heap.ArenaAllocator.init(std.testing.allocator),
            .backing = std.testing.allocator,
        };
    }

    pub fn close(self: *Self) void {
        // Free all namespace maps
        var ns_iter = self.namespaces.iterator();
        while (ns_iter.next()) |entry| {
            var map = entry.value_ptr.*;
            map.deinit(self.backing);
        }
        self.namespaces.deinit(self.backing);
        self.arena.deinit();
    }

    pub fn get(self: *Self, allocator: std.mem.Allocator, ns: []const u8, key: []const u8) !?[]u8 {
        const map = self.namespaces.get(ns) orelse return null;
        const value = map.get(key) orelse return null;
        return try allocator.dupe(u8, value);
    }

    pub fn put(self: *Self, ns: []const u8, key: []const u8, value: []const u8) !void {
        const alloc = self.arena.allocator();
        const gop = try self.namespaces.getOrPut(self.backing, ns);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{};
        }
        const k = try alloc.dupe(u8, key);
        const v = try alloc.dupe(u8, value);
        try gop.value_ptr.put(self.backing, k, v);
    }

    pub fn delete(self: *Self, ns: []const u8, key: []const u8) !void {
        var map = self.namespaces.get(ns) orelse return;
        _ = map.fetchRemove(key);
    }

    pub const Iterator = struct {
        entries: []const IterEntry,
        pos: usize,

        const IterEntry = struct { key: []const u8, value: []const u8 };

        pub fn next(self: *Iterator) ?Entry {
            if (self.pos >= self.entries.len) return null;
            const e = self.entries[self.pos];
            self.pos += 1;
            return .{ .key = e.key, .value = e.value };
        }

        pub fn deinit(self: *Iterator) void {
            _ = self;
        }
    };

    pub fn iterator(self: *Self, ns: []const u8, prefix: []const u8) !Iterator {
        const map = self.namespaces.get(ns) orelse return .{ .entries = &.{}, .pos = 0 };
        const alloc = self.arena.allocator();

        // Collect matching entries (prefix-bounded)
        var count: usize = 0;
        var it = map.iterator();
        while (it.next()) |_| count += 1;

        var result = try alloc.alloc(Iterator.IterEntry, count);
        var out: usize = 0;
        var it2 = map.iterator();
        while (it2.next()) |entry| {
            if (std.mem.startsWith(u8, entry.key_ptr.*, prefix)) {
                result[out] = .{ .key = entry.key_ptr.*, .value = entry.value_ptr.* };
                out += 1;
            }
        }

        return .{ .entries = result[0..out], .pos = 0 };
    }

    pub const WriteBatch = struct {
        backend: *Self,
        ops: std.ArrayListUnmanaged(BatchOp),

        const BatchOp = union(enum) {
            put_op: struct { ns: []const u8, key: []const u8, value: []const u8 },
            delete_op: struct { ns: []const u8, key: []const u8 },
        };

        pub fn put(self: *WriteBatch, ns: []const u8, key: []const u8, value: []const u8) !void {
            try self.ops.append(self.backend.backing, .{ .put_op = .{
                .ns = ns,
                .key = key,
                .value = value,
            } });
        }

        pub fn delete(self: *WriteBatch, ns: []const u8, key: []const u8) !void {
            try self.ops.append(self.backend.backing, .{ .delete_op = .{
                .ns = ns,
                .key = key,
            } });
        }

        pub fn commit(self: *WriteBatch) !void {
            for (self.ops.items) |op| {
                switch (op) {
                    .put_op => |p| try self.backend.put(p.ns, p.key, p.value),
                    .delete_op => |d| try self.backend.delete(d.ns, d.key),
                }
            }
            self.ops.deinit(self.backend.backing);
        }

        pub fn abort(self: *WriteBatch) void {
            self.ops.deinit(self.backend.backing);
        }
    };

    pub fn writeBatch(self: *Self) !WriteBatch {
        return .{ .backend = self, .ops = .{} };
    }
};

test "assertBackend accepts conforming type" {
    comptime assertBackend(MemoryBackend);
}

test "MemoryBackend: put and get" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    try db.put("users", "alice", "creds_alice");
    try db.put("users", "bob", "creds_bob");

    const val = try db.get(std.testing.allocator, "users", "alice");
    defer if (val) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("creds_alice", val.?);

    const missing = try db.get(std.testing.allocator, "users", "charlie");
    try std.testing.expect(missing == null);
}

test "MemoryBackend: delete" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    try db.put("users", "alice", "creds");
    try db.delete("users", "alice");

    const val = try db.get(std.testing.allocator, "users", "alice");
    try std.testing.expect(val == null);
}

test "MemoryBackend: iterator prefix-bounded" {
    var db = try MemoryBackend.open("", .{});
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

test "MemoryBackend: iterator on missing namespace" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var iter = try db.iterator("nonexistent", "prefix");
    defer iter.deinit();
    try std.testing.expect(iter.next() == null);
}

test "MemoryBackend: writeBatch atomic" {
    var db = try MemoryBackend.open("", .{});
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

test "MemoryBackend: writeBatch abort" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var batch = try db.writeBatch();
    try batch.put("users", "alice", "a");
    batch.abort();

    const val = try db.get(std.testing.allocator, "users", "alice");
    try std.testing.expect(val == null);
}

test "MemoryBackend: separate namespaces" {
    var db = try MemoryBackend.open("", .{});
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

test "OpenOptions defaults" {
    const opts = OpenOptions{};
    try std.testing.expectEqual(@as(u32, 16), opts.max_namespaces);
    try std.testing.expectEqual(@as(usize, 64 * 1024 * 1024), opts.map_size);
    try std.testing.expect(opts.create);
    try std.testing.expect(!opts.read_only);
}

test "Entry struct" {
    const e = Entry{ .key = "foo", .value = "bar" };
    try std.testing.expectEqualStrings("foo", e.key);
    try std.testing.expectEqualStrings("bar", e.value);
}
