//! # UserStore — generic user credential storage
//!
//! Stores SCRAM-SHA-256 derived credentials in a StorageBackend.
//! Parameterized at comptime — zero runtime dispatch.
//!
//! ## Binary format (100 bytes)
//!
//! ```
//! | salt (32) | stored_key (32) | server_key (32) | iter_count_be (4) |
//! ```
//!
//! Namespace: `users`, Key: `username`

const std = @import("std");
const sasl = @import("sasl");
const backend_mod = @import("backend");
const precis = @import("precis_username");
const oidc_ids = @import("oidc_identity_store");

const log = std.log.scoped(.user_store);

pub const NAMESPACE = backend_mod.registered("users");
const CRED_SIZE = 32 + 32 + 32 + 4; // 100 bytes

/// Startup certification is deliberately bounded. Exceeding the bound means
/// the namespace cannot be certified and fails closed just like a bad key.
pub const max_startup_scan_keys = 100_000;

pub const StartupScanError = error{
    UnpreparedAccountName,
    ScanLimitExceeded,
    ScanFailed,
};

/// Verify once, on the auth daemon's startup path, that every users key is
/// already in RFC 7622 prepared form. No rows are changed and no read fallback
/// is provided: an unprepared key makes startup refuse loudly so the operator
/// runs `xmppctl migrate-precis` instead of users being silently locked out.
/// Startup-only scratch: verifyPreparedUsers runs once before the auth event
/// loop, so this is deliberately not thread-local (avoids 64 KiB of TLS in
/// every auth and crypto-pool thread).
var startup_precis_scratch: precis.Scratch = undefined;

pub fn verifyPreparedUsers(comptime Backend: type, backend: *Backend, max_keys: usize) StartupScanError!void {
    comptime backend_mod.assertBackend(Backend);
    var iterator = backend.iterator(NAMESPACE, "") catch return error.ScanFailed;
    defer iterator.deinit();

    var count: usize = 0;
    while (iterator.next()) |entry| {
        if (count == max_keys) return error.ScanLimitExceeded;
        count += 1;
        const prepared = startup_precis_scratch.localpart(entry.key) catch
            return error.UnpreparedAccountName;
        if (!std.mem.eql(u8, prepared, entry.key)) return error.UnpreparedAccountName;
    }
}

pub fn UserStore(comptime Backend: type) type {
    comptime backend_mod.assertBackend(Backend);

    return struct {
        backend: *Backend,

        const Self = @This();

        pub fn init(b: *Backend) Self {
            return .{ .backend = b };
        }

        pub fn deinit(self: *Self) void {
            _ = self;
        }

        /// Look up a user's stored credentials by username.
        pub fn lookup(self: *Self, allocator: std.mem.Allocator, username: []const u8) !?sasl.StoredCredentials {
            const raw = try self.backend.get(allocator, NAMESPACE, username) orelse return null;
            defer allocator.free(raw);
            return deserializeCredentials(raw);
        }

        /// Add a new user. Derives SCRAM credentials from the password.
        /// Returns error.UserExists if the username is taken and
        /// error.OidcBound when the localpart belongs to an OIDC subject.
        /// The OIDC reverse-index check and the users row claim run inside
        /// one serialized write transaction, so a first OIDC login or a
        /// second registration cannot slip between the checks and the
        /// write (T-52633E2B).
        pub fn addUser(self: *Self, allocator: std.mem.Allocator, username: []const u8, password: []const u8) !void {
            const creds = try sasl.StoredCredentials.generate(password, 4096);
            const value = serializeCredentials(creds);

            if (oidc_ids.claim_window_hook) |hook| hook();

            var kbuf: [512]u8 = undefined;
            const rkey = oidc_ids.reverseKey(&kbuf, username) catch null;

            var batch = try self.backend.writeBatch();
            var ended = false;
            defer if (!ended) batch.abort();

            // A localpart bound to an OIDC (iss, sub) belongs to that
            // subject; a local users row would hand a password credential
            // into the bound account.
            if (rkey) |key| {
                if (try batch.get(allocator, oidc_ids.NAMESPACE, key)) |row| {
                    allocator.free(row);
                    log.info("refusing local registration of OIDC-bound localpart '{s}'", .{username});
                    return error.OidcBound;
                }
            }

            batch.putIfAbsent(NAMESPACE, username, &value) catch |err| switch (err) {
                error.Conflict => return error.UserExists,
                else => return err,
            };
            try batch.commit();
            ended = true;
            log.info("added user: {s}", .{username});
        }

        /// Remove a user. Returns error.UserNotFound if not present.
        pub fn removeUser(self: *Self, allocator: std.mem.Allocator, username: []const u8) !void {
            const existing = try self.backend.get(allocator, NAMESPACE, username);
            if (existing) |v| {
                allocator.free(v);
            } else {
                return error.UserNotFound;
            }
            try self.backend.delete(NAMESPACE, username);
            log.info("removed user: {s}", .{username});
        }

        /// Change a user's password. Derives new SCRAM credentials.
        pub fn changePassword(self: *Self, allocator: std.mem.Allocator, username: []const u8, password: []const u8) !void {
            const existing = try self.backend.get(allocator, NAMESPACE, username);
            if (existing) |v| {
                allocator.free(v);
            } else {
                return error.UserNotFound;
            }
            const creds = try sasl.StoredCredentials.generate(password, 4096);
            const value = serializeCredentials(creds);
            try self.backend.put(NAMESPACE, username, &value);
            log.info("changed password for: {s}", .{username});
        }

        /// Return all usernames. Caller owns the returned slice and its elements.
        pub fn listUsers(self: *Self, allocator: std.mem.Allocator) ![][]const u8 {
            var iter = try self.backend.iterator(NAMESPACE, "");
            defer iter.deinit();

            var list: std.ArrayListUnmanaged([]const u8) = .{};
            errdefer {
                for (list.items) |item| allocator.free(item);
                list.deinit(allocator);
            }

            while (iter.next()) |entry| {
                try list.append(allocator, try allocator.dupe(u8, entry.key));
            }

            return try list.toOwnedSlice(allocator);
        }
    };
}

// ============================================================================
// Serialization
// ============================================================================

fn serializeCredentials(creds: sasl.StoredCredentials) [CRED_SIZE]u8 {
    var buf: [CRED_SIZE]u8 = undefined;
    @memcpy(buf[0..32], &creds.salt);
    @memcpy(buf[32..64], &creds.stored_key);
    @memcpy(buf[64..96], &creds.server_key);
    std.mem.writeInt(u32, buf[96..100], creds.iteration_count, .big);
    return buf;
}

fn deserializeCredentials(data: []const u8) ?sasl.StoredCredentials {
    if (data.len != CRED_SIZE) return null;
    return .{
        .salt = data[0..32].*,
        .stored_key = data[32..64].*,
        .server_key = data[64..96].*,
        .iteration_count = std.mem.readInt(u32, data[96..100], .big),
    };
}

// ============================================================================
// Tests (using MemoryBackend)
// ============================================================================

const MemoryBackend = backend_mod.MemoryBackend;
const lmdb_backend_mod = @import("lmdb_backend");
const TestStore = UserStore(MemoryBackend);

test "UserStore: add and lookup" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.addUser(std.testing.allocator, "alice", "password1");

    const creds = try store.lookup(std.testing.allocator, "alice");
    try std.testing.expect(creds != null);
    try std.testing.expectEqual(@as(u32, 4096), creds.?.iteration_count);

    const missing = try store.lookup(std.testing.allocator, "charlie");
    try std.testing.expect(missing == null);
}

test "UserStore: duplicate user rejected" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.addUser(std.testing.allocator, "alice", "pass");
    try std.testing.expectError(error.UserExists, store.addUser(std.testing.allocator, "alice", "other"));
}

test "UserStore: addUser refuses an OIDC-bound localpart (T-52633E2B)" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    var ids = oidc_ids.Store(MemoryBackend).init(&db);
    _ = try ids.bind(std.testing.allocator, "https://idp.example", "sub-1", "bound-lp", .auto, 1, null);

    try std.testing.expectError(error.OidcBound, store.addUser(std.testing.allocator, "bound-lp", "pw"));
    // No users row was created and an unbound name still registers.
    try std.testing.expect((try store.lookup(std.testing.allocator, "bound-lp")) == null);
    try store.addUser(std.testing.allocator, "free-lp", "pw");
}

test "UserStore: remove user" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.addUser(std.testing.allocator, "alice", "pass");
    try store.removeUser(std.testing.allocator, "alice");

    const creds = try store.lookup(std.testing.allocator, "alice");
    try std.testing.expect(creds == null);

    try std.testing.expectError(error.UserNotFound, store.removeUser(std.testing.allocator, "gone"));
}

test "UserStore: change password" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.addUser(std.testing.allocator, "alice", "oldpass");
    const old = (try store.lookup(std.testing.allocator, "alice")).?;

    try store.changePassword(std.testing.allocator, "alice", "newpass");
    const new = (try store.lookup(std.testing.allocator, "alice")).?;

    try std.testing.expect(!std.mem.eql(u8, &old.stored_key, &new.stored_key));
    try std.testing.expectError(error.UserNotFound, store.changePassword(std.testing.allocator, "ghost", "x"));
}

test "UserStore: list users" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.addUser(std.testing.allocator, "alice", "a");
    try store.addUser(std.testing.allocator, "bob", "b");

    const users = try store.listUsers(std.testing.allocator);
    defer {
        for (users) |u| std.testing.allocator.free(u);
        std.testing.allocator.free(users);
    }
    try std.testing.expectEqual(@as(usize, 2), users.len);
}

test "UserStore: credentials verify with SCRAM" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestStore.init(&db);

    try store.addUser(std.testing.allocator, "testuser", "testpassword");
    const creds = (try store.lookup(std.testing.allocator, "testuser")).?;

    // Re-derive with same salt — keys should match
    const rederived = try sasl.StoredCredentials.derive("testpassword", creds.salt, 4096);
    try std.testing.expectEqualSlices(u8, &creds.stored_key, &rederived.stored_key);
    try std.testing.expectEqualSlices(u8, &creds.server_key, &rederived.server_key);
}

test "UserStore: startup scan accepts only prepared account names" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    try db.put(NAMESPACE, "alice", "x");
    try db.put(NAMESPACE, "naplestb", "x");
    try db.put(NAMESPACE, "\u{03BF}\u{03B4}\u{03BF}\u{03C3}", "x");
    try db.put(NAMESPACE, "a!", "x");
    try verifyPreparedUsers(MemoryBackend, &db, 4);

    try db.put(NAMESPACE, "NaplesTB", "x");
    try std.testing.expectError(error.UnpreparedAccountName, verifyPreparedUsers(MemoryBackend, &db, 5));
    try db.delete(NAMESPACE, "NaplesTB");

    try db.put(NAMESPACE, "bad name", "x");
    try std.testing.expectError(error.UnpreparedAccountName, verifyPreparedUsers(MemoryBackend, &db, 5));
}

test "UserStore: startup scan is bounded and fails closed at the bound" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    try db.put(NAMESPACE, "alice", "x");
    try db.put(NAMESPACE, "bob", "x");
    try db.put(NAMESPACE, "carol", "x");
    try std.testing.expectError(error.ScanLimitExceeded, verifyPreparedUsers(MemoryBackend, &db, 2));
    try verifyPreparedUsers(MemoryBackend, &db, 3);
}

test "serializeCredentials roundtrip" {
    const creds = try sasl.StoredCredentials.generate("test", 4096);
    const buf = serializeCredentials(creds);
    const back = deserializeCredentials(&buf).?;
    try std.testing.expectEqualSlices(u8, &creds.salt, &back.salt);
    try std.testing.expectEqualSlices(u8, &creds.stored_key, &back.stored_key);
    try std.testing.expectEqualSlices(u8, &creds.server_key, &back.server_key);
    try std.testing.expectEqual(creds.iteration_count, back.iteration_count);
}

// ============================================================================
// Claim-window races (local registration vs OIDC first login)
// ============================================================================
//
// claim_window_hook lands the queued competing operation at the point a
// split check-then-write sequence left open between its checks and its
// write: the holder's hook call runs the interloper to completion
// (disarming first, so the interloper's own hook call is a no-op), then
// the holder opens the write transaction that now must see the
// interloper's committed rows.

var window_interloper: ?*const fn () void = null;

fn windowDispatch() void {
    const f = window_interloper orelse return;
    window_interloper = null;
    f();
}

fn armWindow(interloper: *const fn () void) void {
    window_interloper = interloper;
    oidc_ids.claim_window_hook = windowDispatch;
}

test "addUser: an OIDC binding inside the registration window refuses the users row" {
    const S = struct {
        var db: *MemoryBackend = undefined;
        var op: *MemoryBackend = undefined;
        var arch: *MemoryBackend = undefined;
        fn interloper() void {
            var r = oidc_ids.Resolver(MemoryBackend, MemoryBackend){
                .store = oidc_ids.Store(MemoryBackend).init(db),
                .op_backend = op,
                .archive_backend = arch,
                .user_domain = "morante.dev",
            };
            var lp: [oidc_ids.max_localpart_len]u8 = undefined;
            var len: usize = 0;
            _ = r.resolve(std.testing.allocator, "https://idp.example", "sub-1", "alice", &lp, &len) catch unreachable;
        }
    };
    defer oidc_ids.claim_window_hook = null;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var op = try MemoryBackend.open("", .{});
    defer op.close();
    var arch = try MemoryBackend.open("", .{});
    defer arch.close();
    S.db = &db;
    S.op = &op;
    S.arch = &arch;

    var store = TestStore.init(&db);
    armWindow(S.interloper);
    try std.testing.expectError(error.OidcBound, store.addUser(std.testing.allocator, "alice", "pw"));

    // The subject's binding stands and no users row was created.
    var ids = oidc_ids.Store(MemoryBackend).init(&db);
    const bound = try ids.lookupSubject(std.testing.allocator, "https://idp.example", "sub-1");
    defer if (bound) |v| std.testing.allocator.free(v);
    try std.testing.expect(bound != null);
    try std.testing.expect((try store.lookup(std.testing.allocator, "alice")) == null);
}

test "Resolver: IBR inside the bind window refuses the auto-claim" {
    const S = struct {
        var db: *MemoryBackend = undefined;
        fn interloper() void {
            var users = TestStore.init(db);
            users.addUser(std.testing.allocator, "alice", "pw") catch {};
        }
    };
    defer oidc_ids.claim_window_hook = null;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var op = try MemoryBackend.open("", .{});
    defer op.close();
    var arch = try MemoryBackend.open("", .{});
    defer arch.close();
    S.db = &db;

    var r = oidc_ids.Resolver(MemoryBackend, MemoryBackend){
        .store = oidc_ids.Store(MemoryBackend).init(&db),
        .op_backend = &op,
        .archive_backend = &arch,
        .user_domain = "morante.dev",
    };
    armWindow(S.interloper);
    var lp: [oidc_ids.max_localpart_len]u8 = undefined;
    var len: usize = 0;
    const out = try r.resolve(std.testing.allocator, "https://idp.example", "sub-1", "alice", &lp, &len);
    try std.testing.expectEqual(out, oidc_ids.Resolution{ .refused = .local_account });

    // The account row stands and the subject gained no binding rows.
    var store = TestStore.init(&db);
    try std.testing.expect((try store.lookup(std.testing.allocator, "alice")) != null);
    const stray = try r.store.lookupSubject(std.testing.allocator, "https://idp.example", "sub-1");
    defer if (stray) |v| std.testing.allocator.free(v);
    try std.testing.expect(stray == null);
}

test "addUser: a second registration inside the window loses and never overwrites" {
    const S = struct {
        var db: *MemoryBackend = undefined;
        fn interloper() void {
            var users = TestStore.init(db);
            users.addUser(std.testing.allocator, "alice", "first") catch {};
        }
    };
    defer oidc_ids.claim_window_hook = null;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    S.db = &db;

    var store = TestStore.init(&db);
    armWindow(S.interloper);
    try std.testing.expectError(error.UserExists, store.addUser(std.testing.allocator, "alice", "second"));

    // The interloper's credentials survive: a blind put() would have
    // overwritten them.
    const creds = (try store.lookup(std.testing.allocator, "alice")).?;
    const rederived = try sasl.StoredCredentials.derive("first", creds.salt, 4096);
    try std.testing.expectEqualSlices(u8, &creds.stored_key, &rederived.stored_key);
}

test "claim window: real LMDB serializes the OIDC claim against a registration" {
    const Lmdb = lmdb_backend_mod.Backend;
    const S = struct {
        var auth: *Lmdb = undefined;
        fn interloper() void {
            var users = UserStore(Lmdb).init(auth);
            users.addUser(std.heap.c_allocator, "alice", "pw") catch {};
        }
    };
    defer oidc_ids.claim_window_hook = null;

    const path = "/home/admin/tmp/xmppd-test-oidcwin-lmdb1";
    std.fs.cwd().deleteTree(path) catch {};
    defer std.fs.cwd().deleteTree(path) catch {};
    try std.fs.cwd().makePath(path);
    var auth = try Lmdb.open(path, .{ .create = false, .map_size = 16 * 1024 * 1024 });
    defer auth.close();
    S.auth = &auth;

    var r = oidc_ids.Resolver(Lmdb, Lmdb){
        .store = oidc_ids.Store(Lmdb).init(&auth),
        .user_domain = "morante.dev",
    };
    armWindow(S.interloper);
    var lp: [oidc_ids.max_localpart_len]u8 = undefined;
    var len: usize = 0;
    const out = try r.resolve(std.heap.c_allocator, "https://idp.example", "sub-1", "alice", &lp, &len);
    try std.testing.expectEqual(out, oidc_ids.Resolution{ .refused = .local_account });

    const stray = try r.store.lookupSubject(std.heap.c_allocator, "https://idp.example", "sub-1");
    defer if (stray) |v| std.heap.c_allocator.free(v);
    try std.testing.expect(stray == null);
}

test "claim window: real LMDB serializes a registration against the OIDC claim" {
    const Lmdb = lmdb_backend_mod.Backend;
    const S = struct {
        var auth: *Lmdb = undefined;
        fn interloper() void {
            var r = oidc_ids.Resolver(Lmdb, Lmdb){
                .store = oidc_ids.Store(Lmdb).init(auth),
                .user_domain = "morante.dev",
            };
            var lp: [oidc_ids.max_localpart_len]u8 = undefined;
            var len: usize = 0;
            _ = r.resolve(std.heap.c_allocator, "https://idp.example", "sub-1", "alice", &lp, &len) catch unreachable;
        }
    };
    defer oidc_ids.claim_window_hook = null;

    const path = "/home/admin/tmp/xmppd-test-oidcwin-lmdb2";
    std.fs.cwd().deleteTree(path) catch {};
    defer std.fs.cwd().deleteTree(path) catch {};
    try std.fs.cwd().makePath(path);
    var auth = try Lmdb.open(path, .{ .create = false, .map_size = 16 * 1024 * 1024 });
    defer auth.close();
    S.auth = &auth;

    var store = UserStore(Lmdb).init(&auth);
    armWindow(S.interloper);
    try std.testing.expectError(error.OidcBound, store.addUser(std.heap.c_allocator, "alice", "pw"));

    const bound = try store.backend.get(std.heap.c_allocator, oidc_ids.NAMESPACE, "lalice");
    defer if (bound) |v| std.heap.c_allocator.free(v);
    try std.testing.expect(bound != null);
    try std.testing.expect((try store.lookup(std.heap.c_allocator, "alice")) == null);
}
