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

    /// LMDB map size in bytes (ignored by other backends). Never resized at
    /// runtime (S9: LMDB forbids env resize with concurrent readers); a
    /// daemon hitting MDB_MAP_FULL must be restarted with a larger value
    /// (config key: [server] lmdb_map_size_mb). Default 8 GiB: address space
    /// is cheap on amd64, growth is preallocated sparse pages, and v0.8.x
    /// production DBs already exceed 64 MiB (S9).
    map_size: usize = 8 * 1024 * 1024 * 1024,

    /// Create the database/directory if it doesn't exist.
    create: bool = true,

    /// Open in read-only mode.
    read_only: bool = false,
};

/// Every store namespace. Backends open/create all of them at open() (S9)
/// so no worker thread ever creates a container mid-operation (LMDB DBI
/// creation races the handle cache otherwise).
pub const canonical_namespaces = [_][]const u8{
    "users",
    "rosters",
    "vcards",
    "pep",
    "locks",
    "lastact",
    "invites",
    "blocklist",
    "offline",
    "rooms",
    "messages",
    "by_contact",
    "pending_sub", // presence_handler subscription tracking
    "room_affiliations", // MUC persistent affiliations
};

/// Bind a namespace constant to the registered set. Every store owner
/// defines its constant through this, so a rename on either side is a
/// compile error instead of a silently orphaned container.
pub fn registered(comptime ns: []const u8) []const u8 {
    for (canonical_namespaces) |candidate| {
        if (std.mem.eql(u8, candidate, ns)) return candidate;
    }
    @compileError("namespace \"" ++ ns ++ "\" is not registered in canonical_namespaces");
}

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
/// commit() leaves the batch ended whether it succeeds or fails (a failed
/// LMDB commit already aborts its txn internally; a failed RocksDB write
/// is atomic and a failed SQLite COMMIT is rolled back). abort() after a
/// commit attempt is therefore a no-op: calling it anyway double-ends the
/// batch (the mdb_txn_abort that frees env->me_txn0, S9).
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
pub const MemoryBackend = struct {
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
        /// End attempts so far (commit or abort). abort() after a commit
        /// attempt is a no-op (S9); the count keeps a guard violation
        /// observable instead of a silent double free.
        ends: u8 = 0,
        /// Fault hook for tests: commit fails at this op index after the
        /// earlier ops were applied (a partial failure), exercising the
        /// failure cleanup.
        fail_op_at: ?usize = null,

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
            // Ended whether the apply succeeds or not: a partial failure
            // must not leave the op list allocated, and abort() after the
            // commit attempt is a no-op (S9).
            defer self.end();
            for (self.ops.items, 0..) |op, i| {
                if (self.fail_op_at) |n| {
                    if (i == n) return error.MapFull;
                }
                switch (op) {
                    .put_op => |p| try self.backend.put(p.ns, p.key, p.value),
                    .delete_op => |d| try self.backend.delete(d.ns, d.key),
                }
            }
        }

        pub fn abort(self: *WriteBatch) void {
            if (self.ends > 0) return;
            self.end();
        }

        fn end(self: *WriteBatch) void {
            self.ends += 1;
            self.ops.deinit(self.backend.backing);
            self.ops = .{};
        }
    };

    pub fn writeBatch(self: *Self) !WriteBatch {
        return .{ .backend = self, .ops = .{} };
    }
};

/// Test-only backend: every WriteBatch operation fails as if the map were
/// full (set `fail_ops = false` to let a batch reach commit) and commit/
/// abort counts are exposed so a caller can prove its errdefer abort ran
/// (S9). With `fail_commit` set, commit fails the same way and
/// `abort_after_commit` counts any abort() arriving after a commit attempt
/// (contract misuse: the batch is already ended). The iterator serves a
/// fixed entry list.
pub const FailBatchBackend = struct {
    aborted: usize = 0,
    committed: usize = 0,
    commit_attempts: usize = 0,
    abort_after_commit: usize = 0,
    fail_ops: bool = true,
    fail_commit: bool = false,
    iter_entries: []const Entry = &.{},

    const Self = @This();

    comptime {
        assertBackend(Self);
    }

    pub fn open(path: []const u8, opts: OpenOptions) !Self {
        _ = path;
        _ = opts;
        return .{};
    }

    pub fn close(self: *Self) void {
        _ = self;
    }

    pub fn get(self: *Self, allocator: std.mem.Allocator, ns: []const u8, key: []const u8) !?[]u8 {
        _ = self;
        _ = allocator;
        _ = ns;
        _ = key;
        return null;
    }

    pub fn put(self: *Self, ns: []const u8, key: []const u8, value: []const u8) !void {
        _ = self;
        _ = ns;
        _ = key;
        _ = value;
    }

    pub fn delete(self: *Self, ns: []const u8, key: []const u8) !void {
        _ = self;
        _ = ns;
        _ = key;
    }

    pub const Iterator = struct {
        entries: []const Entry,
        pos: usize = 0,

        pub fn next(self: *Iterator) ?Entry {
            if (self.pos >= self.entries.len) return null;
            const e = self.entries[self.pos];
            self.pos += 1;
            return e;
        }

        pub fn deinit(_: *Iterator) void {}
    };

    pub fn iterator(self: *Self, ns: []const u8, prefix: []const u8) !Iterator {
        _ = ns;
        _ = prefix;
        return .{ .entries = self.iter_entries };
    }

    pub const WriteBatch = struct {
        owner: *Self,
        commit_attempted: bool = false,
        ended: bool = false,

        pub fn put(self: *WriteBatch, ns: []const u8, key: []const u8, value: []const u8) !void {
            _ = ns;
            _ = key;
            _ = value;
            if (self.owner.fail_ops) return error.MapFull;
        }

        pub fn delete(self: *WriteBatch, ns: []const u8, key: []const u8) !void {
            _ = ns;
            _ = key;
            if (self.owner.fail_ops) return error.MapFull;
        }

        pub fn commit(self: *WriteBatch) !void {
            self.commit_attempted = true;
            self.owner.commit_attempts += 1;
            if (self.owner.fail_commit) return error.MapFull;
            self.ended = true;
            self.owner.committed += 1;
        }

        pub fn abort(self: *WriteBatch) void {
            if (self.commit_attempted) {
                self.owner.abort_after_commit += 1;
                return;
            }
            if (self.ended) return;
            self.ended = true;
            self.owner.aborted += 1;
        }
    };

    pub fn writeBatch(self: *Self) !WriteBatch {
        return .{ .owner = self };
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

test "MemoryBackend: a partial commit failure frees the op list and ends the batch" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var batch = try db.writeBatch();
    try batch.put("users", "alice", "a");
    try batch.put("users", "bob", "b");
    try batch.put("users", "carol", "c");
    // Fail the third op: two are applied before the failure.
    batch.fail_op_at = 2;
    try std.testing.expectError(error.MapFull, batch.commit());

    // The batch is ended and the op list freed: a partial failure must not
    // leak it (S9).
    try std.testing.expectEqual(@as(u8, 1), batch.ends);
    try std.testing.expectEqual(@as(usize, 0), batch.ops.items.len);

    // abort() after the commit attempt is a no-op.
    batch.abort();
    try std.testing.expectEqual(@as(u8, 1), batch.ends);

    // Ops before the failure were applied; the failed one was not.
    const a = try db.get(std.testing.allocator, "users", "alice");
    defer if (a) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("a", a.?);
    const c = try db.get(std.testing.allocator, "users", "carol");
    try std.testing.expect(c == null);
}

test "MemoryBackend: abort after a commit attempt is a no-op" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var batch = try db.writeBatch();
    try batch.put("users", "alice", "a");
    try batch.commit();
    try std.testing.expectEqual(@as(u8, 1), batch.ends);

    batch.abort();
    try std.testing.expectEqual(@as(u8, 1), batch.ends);
    batch.abort();
    try std.testing.expectEqual(@as(u8, 1), batch.ends);

    const a = try db.get(std.testing.allocator, "users", "alice");
    defer if (a) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("a", a.?);
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
    // 8 GiB default (S9): headroom for existing production DBs that
    // already exceed 64 MiB; sparse maps cost address space only.
    try std.testing.expectEqual(@as(usize, 8 * 1024 * 1024 * 1024), opts.map_size);
    try std.testing.expect(opts.create);
    try std.testing.expect(!opts.read_only);
}

test "canonical_namespaces are unique, within the LMDB name bound, and ratcheted" {
    // Real invariants instead of a list re-checking itself: a duplicate
    // name would collide in the DBI cache lookups, and a name over 64
    // bytes fails mdb_dbi_open (name_buf is [64]u8 plus NUL). The count
    // ratchets the set: additions must be deliberate, removals break the
    // stores that own them (pending_sub = presence_handler,
    // room_affiliations = room_store).
    for (canonical_namespaces, 0..) |ns, i| {
        try std.testing.expect(ns.len > 0 and ns.len <= 64);
        for (canonical_namespaces[i + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, ns, other));
        }
    }
    try std.testing.expectEqual(@as(usize, 14), canonical_namespaces.len);
}

const TokenKind = enum { str, chr, comment };
const Token = struct { end: usize, kind: TokenKind };

/// Skip a string, char or line-comment token starting at `i`, or return
/// null when a plain token starts there. Call shapes quoted inside
/// strings and comments are not call sites.
fn skipToken(text: []const u8, i: usize) ?Token {
    if (i + 2 <= text.len and text[i] == '/' and text[i + 1] == '/') {
        var j = i + 2;
        while (j < text.len and text[j] != '\n') : (j += 1) {}
        return .{ .end = j, .kind = .comment };
    }
    if (i + 2 <= text.len and text[i] == '\\' and text[i + 1] == '\\') {
        var j = i + 2;
        while (j < text.len and text[j] != '\n') : (j += 1) {}
        return .{ .end = j, .kind = .str };
    }
    if (text[i] == '"' or text[i] == '\'') {
        const quote = text[i];
        var j = i + 1;
        while (j < text.len) : (j += 1) {
            if (text[j] == '\\') {
                j += 1;
                continue;
            }
            if (text[j] == quote) return .{ .end = j + 1, .kind = if (quote == '"') .str else .chr };
        }
        return .{ .end = text.len, .kind = .str };
    }
    return null;
}

const CallArgs = struct { count: usize, ns_literal: bool };

/// Parse the top-level argument list of a call starting just after its
/// open paren: the argument count and whether the namespace slot is a
/// string literal. Null on an unbalanced call.
fn nsArgIsLiteral(text: []const u8, start: usize, ns_index: usize) ?CallArgs {
    var depth: usize = 0;
    var i: usize = start;
    var count: usize = 0;
    var arg_index: usize = 0;
    var saw = false;
    var first_seen = false;
    var ns_literal = false;
    while (i < text.len) : (i += 1) {
        if (skipToken(text, i)) |tok| {
            if (!first_seen and arg_index == ns_index and tok.kind == .str) ns_literal = true;
            if (tok.kind != .comment) {
                first_seen = true;
                saw = true;
            }
            i = tok.end - 1;
            continue;
        }
        switch (text[i]) {
            '(', '[', '{' => {
                depth += 1;
                first_seen = true;
                saw = true;
            },
            ')', ']', '}' => {
                if (text[i] == ')' and depth == 0) {
                    if (saw) count += 1;
                    return .{ .count = count, .ns_literal = ns_literal };
                }
                if (depth == 0) return null;
                depth -= 1;
                saw = true;
            },
            ',' => {
                if (depth == 0) {
                    if (saw) count += 1;
                    arg_index += 1;
                    saw = false;
                    first_seen = false;
                }
            },
            else => {
                if (!std.ascii.isWhitespace(text[i])) {
                    if (!first_seen) {
                        first_seen = true;
                        if (arg_index == ns_index) ns_literal = text[i] == '"';
                    }
                    saw = true;
                }
            },
        }
    }
    return null;
}

const ScanResult = struct { count: usize, first_line: usize };

/// Count call sites whose namespace argument is a string literal. The
/// backend signatures fix both the arity and the namespace slot
/// (put(ns, key, value), delete(ns, key), iterator(ns, prefix),
/// get(allocator, ns, key)), so map, config and pool calls do not match.
fn countNsLiterals(text: []const u8) ScanResult {
    const calls = [_]struct { name: []const u8, args: usize, ns: usize }{
        .{ .name = "pu" ++ "t", .args = 3, .ns = 0 },
        .{ .name = "del" ++ "ete", .args = 2, .ns = 0 },
        .{ .name = "it" ++ "erator", .args = 2, .ns = 0 },
        .{ .name = "g" ++ "et", .args = 3, .ns = 1 },
    };
    var result = ScanResult{ .count = 0, .first_line = 0 };
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        if (skipToken(text, i)) |tok| {
            i = tok.end - 1;
            continue;
        }
        if (text[i] != '.') continue;
        var j = i + 1;
        while (j < text.len and (std.ascii.isAlphanumeric(text[j]) or text[j] == '_')) : (j += 1) {}
        for (calls) |call| {
            if (!std.mem.eql(u8, text[i + 1 .. j], call.name)) continue;
            if (j >= text.len or text[j] != '(') break;
            if (nsArgIsLiteral(text, j + 1, call.ns)) |parsed| {
                if (parsed.count == call.args and parsed.ns_literal) {
                    result.count += 1;
                    if (result.first_line == 0) {
                        result.first_line = std.mem.count(u8, text[0..i], "\n") + 1;
                    }
                }
            }
            break;
        }
        i = j - 1;
    }
    return result;
}

/// Locate the src tree for the scan. @src().file is a basename under Zig
/// 0.15, so the tree is found relative to the invocation directory.
/// Never skips: a tree that cannot be found fails the test.
fn openSrcDir() !std.fs.Dir {
    const candidates = [_][]const u8{ "src", "../src", "../../src", "../../../src" };
    for (candidates) |candidate| {
        var dir = std.fs.cwd().openDir(candidate, .{ .iterate = true }) catch continue;
        dir.access("store/backend.zig", .{}) catch {
            dir.close();
            continue;
        };
        return dir;
    }
    return error.SourceTreeNotFound;
}

test "D7: source ratchet, no string-literal namespace arguments in src/" {
    // The backend API takes a runtime namespace string, so a call site
    // passing a literal skips the registered() binding to
    // canonical_namespaces: a renamed owner can drift from its call sites
    // while the suite stays green (B7). Every backend call whose
    // namespace argument is a string literal is counted per file and
    // pinned here. Counts may only shrink; a new literal must be
    // justified in this table. The four backend conformance test files
    // seed fixture rows under unregistered names ("scratch",
    // "nonexistent") and carry their fixture counts; every other file in
    // src/ is zero.
    const expected = [_]struct { []const u8, usize }{
        .{ "store/backend.zig", 29 },
        .{ "store/lmdb.zig", 39 },
        .{ "store/rocksdb.zig", 32 },
        .{ "store/sqlite.zig", 35 },
    };
    var seen = [_]bool{false} ** expected.len;

    const allocator = std.testing.allocator;
    var src_dir = try openSrcDir();
    defer src_dir.close();
    var walker = try src_dir.walk(allocator);
    defer walker.deinit();

    var files: usize = 0;
    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;
        const text = try entry.dir.readFileAlloc(allocator, entry.basename, 16 * 1024 * 1024);
        defer allocator.free(text);
        files += 1;

        var want: usize = 0;
        for (expected, 0..) |row, idx| {
            if (std.mem.eql(u8, row[0], entry.path)) {
                want = row[1];
                seen[idx] = true;
            }
        }
        const result = countNsLiterals(text);
        if (result.count != want) {
            std.log.err("D7 ratchet: {s} has {d} string-literal namespace arguments (first at line {d}), table pins {d}", .{ entry.path, result.count, result.first_line, want });
            return error.RatchetMismatch;
        }
    }

    // A pinned file that moved or vanished must not leave the table.
    for (expected, 0..) |row, idx| {
        if (!seen[idx]) {
            std.log.err("D7 ratchet: {s} was not scanned, table pins {d} literal namespace arguments", .{ row[0], row[1] });
            return error.RatchetCoverage;
        }
    }
    // The walk must keep covering the tree; lower this deliberately when
    // source files go away.
    if (files < 60) {
        std.log.err("D7 ratchet: scanned {d} source files under src/, expected at least 60", .{files});
        return error.RatchetCoverage;
    }
}

test "Entry struct" {
    const e = Entry{ .key = "foo", .value = "bar" };
    try std.testing.expectEqualStrings("foo", e.key);
    try std.testing.expectEqualStrings("bar", e.value);
}
