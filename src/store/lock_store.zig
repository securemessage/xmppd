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

        /// Find a non-canonical row that folds to `canon`: rows written
        /// before keys were case-folded carry the name as typed ("Alice")
        /// and miss the canonical lookup. Returns the row's actual key
        /// (caller frees), or null. Records in `legacy_free` when the whole
        /// namespace is canonical so later misses skip this scan.
        fn legacyFind(self: *Self, allocator: std.mem.Allocator, canon: []const u8) !?[]u8 {
            var found: ?[]u8 = null;
            var legacy_any = false;
            var it = try self.backend.iterator(NAMESPACE, "");
            defer it.deinit();
            while (it.next()) |entry| {
                var canon_buf: [MAX_KEY_LEN]u8 = undefined;
                const fold = canonicalKey(entry.key, &canon_buf) catch continue;
                if (std.mem.eql(u8, fold, entry.key)) continue;
                legacy_any = true;
                if (found == null and std.mem.eql(u8, fold, canon)) {
                    found = try allocator.dupe(u8, entry.key);
                }
            }
            if (!legacy_any) self.legacy_free = true;
            return found;
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
                const legacy_key = (try self.legacyFind(allocator, key)) orelse return null;
                defer allocator.free(legacy_key);
                const legacy_raw = try self.backend.get(allocator, NAMESPACE, legacy_key);
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

        /// Unlock an account. No-op if not locked.
        pub fn unlock(self: *Self, allocator: std.mem.Allocator, username: []const u8) !void {
            var key_buf: [MAX_KEY_LEN]u8 = undefined;
            const key = try canonicalKey(username, &key_buf);
            const existing = try self.backend.get(allocator, NAMESPACE, key);
            if (existing) |v| {
                allocator.free(v);
                try self.backend.delete(NAMESPACE, key);
                log.info("unlocked account: {s}", .{username});
                return;
            }
            // A fold-equal legacy row is the same lock and must be removed
            // too, or unlock cannot clear it (S3).
            if (self.legacy_free) return;
            const legacy_key = (try self.legacyFind(allocator, key)) orelse return;
            defer allocator.free(legacy_key);
            try self.backend.delete(NAMESPACE, legacy_key);
            log.info("unlocked account: {s} (legacy key '{s}')", .{ username, legacy_key });
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
