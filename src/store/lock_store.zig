//! # LockStore — Permanent account lock storage
//!
//! Stores permanent account locks in a StorageBackend. Locks persist across
//! daemon restarts and work for both local and future external auth users.
//!
//! ## Binary format (5 bytes)
//!
//! ```
//! | lock_type (1) | locked_epoch (4 BE) |
//! ```
//!
//! Namespace: `locks`, Key: `username`
//!
//! ## Lock types
//!
//! - 0x01: permanent (via xmppctl lock)
//! - 0x02: reserved for future use

const std = @import("std");
const backend_mod = @import("backend");

const log = std.log.scoped(.lock_store);

pub const NAMESPACE = backend_mod.registered("locks");
const LOCK_VALUE_SIZE = 5; // lock_type(1) + epoch(4)

/// Lock keys are canonical ASCII-lowercase localparts: XMPP localparts are
/// case-insensitive, so a lock on "alice" must hold for "Alice" and "ALICE"
/// alike (S3). Empty or overlong names cannot be valid identities;
/// the check path maps the error to fail-closed.
const MAX_KEY_LEN = 256;

fn canonicalKey(username: []const u8, buf: *[MAX_KEY_LEN]u8) error{KeyTooLong}![]const u8 {
    if (username.len == 0 or username.len > MAX_KEY_LEN) return error.KeyTooLong;
    for (username, 0..) |ch, i| buf[i] = std.ascii.toLower(ch);
    return buf[0..username.len];
}

/// Whether a failed backend open means "nothing is stored there yet" (a
/// missing environment or missing namespace). Every other failure
/// (permissions, corruption, map limits) is a real fault, not emptiness.
pub fn isMissingStoreError(err: anyerror) bool {
    return switch (err) {
        error.FileNotFound,
        error.PathNotFound,
        error.NOENT,
        error.MDB_NOTFOUND,
        => true,
        else => false,
    };
}

/// Open the shared op-storage backend read-only for a lock-checking daemon.
/// The open never creates; when it fails because the environment or the
/// namespaces do not exist yet (fresh install), the store is provisioned
/// once read-write and reopened read-only. Any other failure is returned
/// untouched: a fault must never be papered over with a provisioning write.
pub fn openReadOnlyProvisioned(comptime Backend: type, path: []const u8, opts: backend_mod.OpenOptions) !Backend {
    var ro = opts;
    ro.read_only = true;
    ro.create = false;
    return Backend.open(path, ro) catch |first_err| blk: {
        if (!isMissingStoreError(first_err)) return first_err;
        log.warn("lock store at {s} not created yet ({}); provisioning read-write once", .{ path, first_err });
        var rw = opts;
        rw.read_only = false;
        rw.create = true;
        var provision = try Backend.open(path, rw);
        provision.close();
        break :blk Backend.open(path, ro);
    };
}

/// Bring the `locks` namespace to canonical keys on a short-lived
/// read-write handle and report whether the namespace is now canonical.
/// A lock-checking daemon runs this at start: production serves its
/// checks from a read-only handle (xmppd-auth-oidc), and while legacy
/// rows remain every check miss scans the whole namespace on the auth
/// loop thread (S3). The open never creates, so a missing store keeps
/// its fail-open guard and stays with the provisioning path; a
/// deployment that cannot open the store read-write keeps its rows and
/// the read-only path learns `legacy_free` from its scans instead.
pub fn migrateIfWritable(comptime Backend: type, allocator: std.mem.Allocator, path: []const u8, opts: backend_mod.OpenOptions) !bool {
    var rw = opts;
    rw.read_only = false;
    rw.create = false;
    var handle = Backend.open(path, rw) catch |err| {
        log.warn("lock store at {s} not writable for migration ({}); lock checks keep their legacy scan", .{ path, err });
        return false;
    };
    defer handle.close();
    var store = LockStore(Backend).init(&handle);
    try store.migrateLegacyKeys(allocator);
    return true;
}

/// Lock type identifiers.
pub const LockType = enum(u8) {
    permanent = 0x01,
    reserved = 0x02,
};

/// A lock record.
pub const LockRecord = struct {
    lock_type: LockType,
    locked_epoch: u32,
};

pub fn LockStore(comptime Backend: type) type {
    comptime backend_mod.assertBackend(Backend);

    return struct {
        backend: *Backend,

        /// Set once the namespace is known to hold only canonical keys
        /// (after migration or a clean legacy scan): misses then skip the
        /// legacy scan entirely.
        legacy_free: bool = false,

        const Self = @This();

        pub fn init(b: *Backend) Self {
            return .{ .backend = b };
        }

        /// Collect every non-canonical row that folds to `canon` into
        /// `out` (caller frees each key and the list). Records
        /// `legacy_free` when the whole namespace is canonical so later
        /// misses skip this scan.
        fn legacyFindAll(self: *Self, allocator: std.mem.Allocator, canon: []const u8, out: *std.ArrayListUnmanaged([]u8)) !void {
            var legacy_any = false;
            var it = try self.backend.iterator(NAMESPACE, "");
            defer it.deinit();
            while (it.next()) |entry| {
                var canon_buf: [MAX_KEY_LEN]u8 = undefined;
                const fold = canonicalKey(entry.key, &canon_buf) catch continue;
                if (std.mem.eql(u8, fold, entry.key)) continue;
                legacy_any = true;
                if (std.mem.eql(u8, fold, canon)) {
                    try out.append(allocator, try allocator.dupe(u8, entry.key));
                }
            }
            if (!legacy_any) self.legacy_free = true;
        }

        /// Check if a username is locked. Returns the lock record if locked, null otherwise.
        pub fn isLocked(self: *Self, allocator: std.mem.Allocator, username: []const u8) !?LockRecord {
            var key_buf: [MAX_KEY_LEN]u8 = undefined;
            const key = try canonicalKey(username, &key_buf);
            const raw = self.backend.get(allocator, NAMESPACE, key) catch |err| {
                log.err("lock_store lookup failed for '{s}': {}", .{ username, err });
                return err;
            };
            const data = raw orelse {
                // A fold-equal legacy row is the same lock; without this
                // lookup it reads as unlocked (S3).
                if (self.legacy_free) return null;
                var legacy_keys: std.ArrayListUnmanaged([]u8) = .{};
                defer {
                    for (legacy_keys.items) |k| allocator.free(k);
                    legacy_keys.deinit(allocator);
                }
                try self.legacyFindAll(allocator, key, &legacy_keys);
                if (legacy_keys.items.len == 0) return null;
                const legacy_raw = try self.backend.get(allocator, NAMESPACE, legacy_keys.items[0]);
                const legacy_data = legacy_raw orelse return null;
                defer allocator.free(legacy_data);
                if (legacy_data.len < LOCK_VALUE_SIZE) return error.CorruptLockRecord;
                return deserialize(legacy_data[0..LOCK_VALUE_SIZE]);
            };
            defer allocator.free(data);

            // Corrupt entry: treat as locked, never silently unlocked
            // (S3). The caller maps store errors to closed.
            if (data.len < LOCK_VALUE_SIZE) return error.CorruptLockRecord;
            return deserialize(data[0..LOCK_VALUE_SIZE]);
        }

        /// Lock an account. Overwrites any existing lock.
        pub fn lock(self: *Self, username: []const u8, lock_type: LockType) !void {
            var key_buf: [MAX_KEY_LEN]u8 = undefined;
            const key = try canonicalKey(username, &key_buf);
            const now = currentEpoch();
            const value = serialize(lock_type, now);
            try self.backend.put(NAMESPACE, key, &value);
            log.info("locked account: {s} (type={d})", .{ username, @intFromEnum(lock_type) });
        }

        /// Unlock an account. No-op if not locked. A canonical row and a
        /// fold-equal legacy row are one lock under two keys: unlock must
        /// remove both, or the survivor still reads as locked (S3).
        pub fn unlock(self: *Self, allocator: std.mem.Allocator, username: []const u8) !void {
            var key_buf: [MAX_KEY_LEN]u8 = undefined;
            const key = try canonicalKey(username, &key_buf);
            var removed = false;
            if (try self.backend.get(allocator, NAMESPACE, key)) |v| {
                allocator.free(v);
                try self.backend.delete(NAMESPACE, key);
                removed = true;
            }
            // Every fold-equal legacy row is the same lock under a pre-fold
            // key: remove all of them, or a survivor still reads as locked.
            if (!self.legacy_free) {
                var legacy_keys: std.ArrayListUnmanaged([]u8) = .{};
                defer {
                    for (legacy_keys.items) |k| allocator.free(k);
                    legacy_keys.deinit(allocator);
                }
                try self.legacyFindAll(allocator, key, &legacy_keys);
                for (legacy_keys.items) |legacy_key| {
                    try self.backend.delete(NAMESPACE, legacy_key);
                    removed = true;
                }
            }
            if (removed) log.info("unlocked account: {s}", .{username});
        }

        /// Re-key rows whose key is not canonical lowercase (written before
        /// keys were case-folded). The write daemon runs this on open so the
        /// set is canonical before the first check; a reader that cannot
        /// write still enforces such rows through the legacy lookup. When a
        /// canonical and a legacy row collide, the canonical row stays.
        pub fn migrateLegacyKeys(self: *Self, allocator: std.mem.Allocator) !void {
            var legacy: std.ArrayListUnmanaged([]const u8) = .{};
            defer {
                for (legacy.items) |k| allocator.free(k);
                legacy.deinit(allocator);
            }
            {
                var it = try self.backend.iterator(NAMESPACE, "");
                defer it.deinit();
                while (it.next()) |entry| {
                    var canon_buf: [MAX_KEY_LEN]u8 = undefined;
                    const canon = canonicalKey(entry.key, &canon_buf) catch continue;
                    if (std.mem.eql(u8, canon, entry.key)) continue;
                    try legacy.append(allocator, try allocator.dupe(u8, entry.key));
                }
            }
            for (legacy.items) |k| {
                var canon_buf: [MAX_KEY_LEN]u8 = undefined;
                const canon = try canonicalKey(k, &canon_buf);
                const taken = try self.backend.get(allocator, NAMESPACE, canon);
                if (taken) |v| {
                    allocator.free(v);
                    log.warn("lock_store: legacy row '{s}' dropped; canonical '{s}' exists", .{ k, canon });
                } else {
                    const value_raw = try self.backend.get(allocator, NAMESPACE, k);
                    const value = value_raw orelse continue;
                    defer allocator.free(value);
                    try self.backend.put(NAMESPACE, canon, value);
                    log.info("lock_store: legacy row '{s}' re-keyed to '{s}'", .{ k, canon });
                }
                try self.backend.delete(NAMESPACE, k);
            }
            self.legacy_free = true;
        }

        /// Record that the namespace is known canonical (a migration ran
        /// on a read-write handle at daemon start): misses then skip the
        /// legacy scan from the first check on.
        pub fn learnLegacyFree(self: *Self) void {
            self.legacy_free = true;
        }

        /// Remove lock entry (used during account deletion cascade).
        pub fn remove(self: *Self, allocator: std.mem.Allocator, username: []const u8) !void {
            return self.unlock(allocator, username);
        }
    };
}

fn serialize(lock_type: LockType, epoch: u32) [LOCK_VALUE_SIZE]u8 {
    var buf: [LOCK_VALUE_SIZE]u8 = undefined;
    buf[0] = @intFromEnum(lock_type);
    std.mem.writeInt(u32, buf[1..5], epoch, .big);
    return buf;
}

fn deserialize(data: *const [LOCK_VALUE_SIZE]u8) LockRecord {
    return .{
        .lock_type = std.meta.intToEnum(LockType, data[0]) catch .permanent,
        .locked_epoch = std.mem.readInt(u32, data[1..5], .big),
    };
}

fn currentEpoch() u32 {
    const ts = std.time.timestamp();
    return @intCast(@as(u64, @bitCast(ts)) & 0xFFFFFFFF);
}

// ============================================================================
// Tests
// ============================================================================

test "LockStore: lock and check" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = LockStore(MemoryBackend).init(&db);

    // Not locked initially
    const result1 = try store.isLocked(allocator, "alice");
    try std.testing.expect(result1 == null);

    // Lock
    try store.lock("alice", .permanent);

    // Now locked
    const result2 = try store.isLocked(allocator, "alice");
    try std.testing.expect(result2 != null);
    try std.testing.expectEqual(LockType.permanent, result2.?.lock_type);
    try std.testing.expect(result2.?.locked_epoch > 0);
}

test "LockStore: unlock" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = LockStore(MemoryBackend).init(&db);

    try store.lock("bob", .permanent);
    try store.unlock(allocator, "bob");

    const result = try store.isLocked(allocator, "bob");
    try std.testing.expect(result == null);
}

test "LockStore: unlock non-existent is no-op" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = LockStore(MemoryBackend).init(&db);

    // Should not error
    try store.unlock(allocator, "ghost");
}

test "LockStore: multiple users independent" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = LockStore(MemoryBackend).init(&db);

    try store.lock("alice", .permanent);

    // alice is locked, bob is not
    try std.testing.expect((try store.isLocked(allocator, "alice")) != null);
    try std.testing.expect((try store.isLocked(allocator, "bob")) == null);
}

test "LockStore: a corrupt lock record reads as an error, not unlocked" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = LockStore(MemoryBackend).init(&db);

    // Write a truncated record straight into the namespace: it is corrupt,
    // and isLocked fails closed on it.
    try db.put(NAMESPACE, "alice", "x");

    try std.testing.expectError(error.CorruptLockRecord, store.isLocked(allocator, "alice"));
}

test "LockStore: keys are case-folded on write and check" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = LockStore(MemoryBackend).init(&db);

    try store.lock("alice", .permanent);
    // A case variant of a locked name must hit the same lock row: before the
    // fix, "Alice" logged in while "alice" was locked.
    try std.testing.expect((try store.isLocked(allocator, "Alice")) != null);
    try std.testing.expect((try store.isLocked(allocator, "ALICE")) != null);
    try std.testing.expect((try store.isLocked(allocator, "alice")) != null);

    // Writes fold too: locking "BoB" locks "bob", and unlock matches any case.
    try store.lock("BoB", .permanent);
    try std.testing.expect((try store.isLocked(allocator, "bob")) != null);
    try store.unlock(allocator, "BOB");
    try std.testing.expect((try store.isLocked(allocator, "bob")) == null);
}

test "LockStore: empty and overlong names fail closed" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = LockStore(MemoryBackend).init(&db);

    // A name that cannot be canonical is an error, and callers map lock
    // store errors to fail-closed.
    try std.testing.expectError(error.KeyTooLong, store.isLocked(allocator, ""));
    var big: [300]u8 = undefined;
    @memset(&big, 'a');
    try std.testing.expectError(error.KeyTooLong, store.isLocked(allocator, &big));
    try std.testing.expectError(error.KeyTooLong, store.lock("", .permanent));
}

test "LockStore: legacy mixed-case rows are enforced and removable" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = LockStore(MemoryBackend).init(&db);

    // A row written before keys were case-folded: stored as typed.
    try db.put(NAMESPACE, "Alice", &serialize(.permanent, 7));

    // The fold-equal row is the same lock and must hold for every case.
    const hit = (try store.isLocked(allocator, "alice")) orelse return error.NotLocked;
    try std.testing.expectEqual(@as(u32, 7), hit.locked_epoch);
    try std.testing.expect((try store.isLocked(allocator, "ALICE")) != null);

    // unlock reaches the row it could not before.
    try store.unlock(allocator, "alice");
    try std.testing.expect((try db.get(allocator, NAMESPACE, "Alice")) == null);
    try std.testing.expect((try store.isLocked(allocator, "alice")) == null);
}

test "LockStore: unlock clears a canonical and a legacy row for the same name (D3)" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = LockStore(MemoryBackend).init(&db);

    // Both rows describe the same lock: the canonical one and one written
    // before keys were case-folded. Removing either alone leaves the
    // account locked (S3).
    try store.lock("alice", .permanent);
    try db.put(NAMESPACE, "Alice", &serialize(.permanent, 7));

    try store.unlock(allocator, "alice");

    try std.testing.expect((try db.get(allocator, NAMESPACE, "alice")) == null);
    try std.testing.expect((try db.get(allocator, NAMESPACE, "Alice")) == null);
    try std.testing.expect((try store.isLocked(allocator, "alice")) == null);
    try std.testing.expect((try store.isLocked(allocator, "ALICE")) == null);
}

test "LockStore: unlock clears every fold-equal legacy row (D3)" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = LockStore(MemoryBackend).init(&db);

    // Two pre-fold rows for one account. Removing only the first leaves the
    // second enforcing the lock.
    try db.put(NAMESPACE, "Alice", &serialize(.permanent, 7));
    try db.put(NAMESPACE, "ALICE", &serialize(.permanent, 8));

    try store.unlock(allocator, "alice");

    try std.testing.expect((try db.get(allocator, NAMESPACE, "Alice")) == null);
    try std.testing.expect((try db.get(allocator, NAMESPACE, "ALICE")) == null);
    try std.testing.expect((try store.isLocked(allocator, "alice")) == null);
    try std.testing.expect((try store.isLocked(allocator, "ALICE")) == null);
}

test "LockStore: migration re-keys legacy rows to canonical" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = LockStore(MemoryBackend).init(&db);

    try db.put(NAMESPACE, "Alice", &serialize(.permanent, 1));
    try db.put(NAMESPACE, "bOB", &serialize(.permanent, 2));
    try store.migrateLegacyKeys(allocator);

    const a = (try store.isLocked(allocator, "alice")) orelse return error.NotLocked;
    try std.testing.expectEqual(@as(u32, 1), a.locked_epoch);
    const b = (try store.isLocked(allocator, "BOB")) orelse return error.NotLocked;
    try std.testing.expectEqual(@as(u32, 2), b.locked_epoch);
    try std.testing.expect((try db.get(allocator, NAMESPACE, "Alice")) == null);
    try std.testing.expect((try db.get(allocator, NAMESPACE, "bOB")) == null);
    // The set is canonical now: later misses skip the legacy scan.
    try std.testing.expect(store.legacy_free);
}

test "LockStore: migration keeps the canonical row over a legacy duplicate" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = LockStore(MemoryBackend).init(&db);

    try db.put(NAMESPACE, "Alice", &serialize(.permanent, 1));
    try db.put(NAMESPACE, "alice", &serialize(.permanent, 2));
    try store.migrateLegacyKeys(allocator);

    const a = (try store.isLocked(allocator, "alice")) orelse return error.NotLocked;
    try std.testing.expectEqual(@as(u32, 2), a.locked_epoch);
    try std.testing.expect((try db.get(allocator, NAMESPACE, "Alice")) == null);
}

/// Test double for openReadOnlyProvisioned: an open that fails with a
/// scripted error on the first attempt, then succeeds, recording whether
/// the provisioning (create, read-write) pass ran.
const OpenProbe = struct {
    var attempts: usize = 0;
    var provisioned: bool = false;
    var first_error: ?anyerror = null;

    fn reset(err: ?anyerror) void {
        attempts = 0;
        provisioned = false;
        first_error = err;
    }

    pub fn open(_: []const u8, opts: backend_mod.OpenOptions) !OpenProbe {
        attempts += 1;
        if (attempts == 1) {
            if (first_error) |e| return e;
        } else if (opts.create and !opts.read_only) {
            provisioned = true;
        }
        return .{};
    }

    pub fn close(_: *OpenProbe) void {}
};

test "lock store open: only a missing store is provisioned" {
    // Missing environment (fresh install): provision once, reopen read-only.
    OpenProbe.reset(error.NOENT);
    _ = try openReadOnlyProvisioned(OpenProbe, "ignored", .{});
    try std.testing.expectEqual(@as(usize, 3), OpenProbe.attempts); // fail, provision, reopen
    try std.testing.expect(OpenProbe.provisioned);

    // Missing namespace: same fresh-install path.
    OpenProbe.reset(error.MDB_NOTFOUND);
    _ = try openReadOnlyProvisioned(OpenProbe, "ignored", .{});
    try std.testing.expect(OpenProbe.provisioned);

    // A real fault propagates untouched: no provisioning write over it.
    OpenProbe.reset(error.ACCES);
    try std.testing.expectError(error.ACCES, openReadOnlyProvisioned(OpenProbe, "ignored", .{}));
    try std.testing.expect(!OpenProbe.provisioned);
    try std.testing.expectEqual(@as(usize, 1), OpenProbe.attempts);
}

/// Test double for migrateIfWritable: records the open it makes and
/// shares one in-memory store across handles, like an on-disk backend
/// (MemoryBackend.open is fresh per call).
const MigrateProbe = struct {
    var attempts: usize = 0;
    var last_read_only: ?bool = null;
    var last_create: ?bool = null;
    var open_err: ?anyerror = null;
    var shared: ?backend_mod.MemoryBackend = null;

    mem: *backend_mod.MemoryBackend,
    compound_mutex: std.Thread.Mutex = .{},

    fn reset(err: ?anyerror) void {
        done();
        attempts = 0;
        last_read_only = null;
        last_create = null;
        open_err = err;
    }

    /// Close the shared store: the per-test leak check runs while the
    /// probe's statics outlive the test body.
    fn done() void {
        if (shared) |*s| {
            s.close();
            shared = null;
        }
    }

    fn seed(key: []const u8) !void {
        if (shared == null) shared = try backend_mod.MemoryBackend.open("", .{});
        try shared.?.put(NAMESPACE, key, &serialize(.permanent, 3));
    }

    pub fn open(_: []const u8, opts: backend_mod.OpenOptions) !MigrateProbe {
        attempts += 1;
        last_read_only = opts.read_only;
        last_create = opts.create;
        if (open_err) |e| return e;
        if (shared == null) shared = try backend_mod.MemoryBackend.open("", .{});
        return .{ .mem = &shared.? };
    }

    pub fn close(_: *MigrateProbe) void {}

    pub fn get(self: *MigrateProbe, allocator: std.mem.Allocator, ns: []const u8, key: []const u8) !?[]u8 {
        return self.mem.get(allocator, ns, key);
    }

    pub fn put(self: *MigrateProbe, ns: []const u8, key: []const u8, value: []const u8) !void {
        return self.mem.put(ns, key, value);
    }

    pub fn delete(self: *MigrateProbe, ns: []const u8, key: []const u8) !void {
        return self.mem.delete(ns, key);
    }

    pub const Iterator = backend_mod.MemoryBackend.Iterator;
    pub fn iterator(self: *MigrateProbe, ns: []const u8, prefix: []const u8) !Iterator {
        return self.mem.iterator(ns, prefix);
    }

    pub const WriteBatch = backend_mod.MemoryBackend.WriteBatch;
    pub fn writeBatch(self: *MigrateProbe) !WriteBatch {
        return self.mem.writeBatch();
    }
};

test "lock store open: the migration pass opens read-write and never creates" {
    defer MigrateProbe.done();
    MigrateProbe.reset(null);
    try MigrateProbe.seed("Alice");

    const migrated = try migrateIfWritable(MigrateProbe, std.testing.allocator, "ignored", .{});
    try std.testing.expect(migrated);
    try std.testing.expectEqual(@as(?bool, false), MigrateProbe.last_read_only);
    try std.testing.expectEqual(@as(?bool, false), MigrateProbe.last_create);

    // The legacy row was re-keyed on that handle: canonical present,
    // pre-fold key gone.
    const canon = try MigrateProbe.shared.?.get(std.testing.allocator, NAMESPACE, "alice");
    try std.testing.expect(canon != null);
    if (canon) |v| std.testing.allocator.free(v);
    const legacy = try MigrateProbe.shared.?.get(std.testing.allocator, NAMESPACE, "Alice");
    try std.testing.expect(legacy == null);
    if (legacy) |v| std.testing.allocator.free(v);
}

test "lock store open: a missing store is not created by the migration pass" {
    defer MigrateProbe.done();
    // The fail-open guard stays with the provisioning path (S3): the
    // migration open must never create.
    MigrateProbe.reset(error.NOENT);
    const migrated = try migrateIfWritable(MigrateProbe, std.testing.allocator, "ignored", .{});
    try std.testing.expect(!migrated);
    try std.testing.expectEqual(@as(?bool, false), MigrateProbe.last_create);
    try std.testing.expectEqual(@as(usize, 1), MigrateProbe.attempts);
}

test "lock store open: a store that will not open read-write keeps the read-only path" {
    defer MigrateProbe.done();
    // A read-only deployment cannot migrate; the daemon keeps serving
    // checks and their misses learn legacy_free from their scans.
    MigrateProbe.reset(error.EROFS);
    const migrated = try migrateIfWritable(MigrateProbe, std.testing.allocator, "ignored", .{});
    try std.testing.expect(!migrated);
    try std.testing.expectEqual(@as(?bool, false), MigrateProbe.last_read_only);
    try std.testing.expectEqual(@as(?bool, false), MigrateProbe.last_create);
}

test "LockStore: a learned canonical namespace skips the legacy scan (D4)" {
    const allocator = std.testing.allocator;
    const MemoryBackend = backend_mod.MemoryBackend;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = LockStore(MemoryBackend).init(&db);

    // A pre-fold row that the migration pass proved away: the read-only
    // path learned the namespace is canonical, so a miss does not scan.
    try db.put(NAMESPACE, "Alice", &serialize(.permanent, 7));
    store.learnLegacyFree();

    try std.testing.expect((try store.isLocked(allocator, "alice")) == null);
}
