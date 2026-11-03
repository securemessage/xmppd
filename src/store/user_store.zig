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

const log = std.log.scoped(.user_store);

pub const NAMESPACE = backend_mod.registered("users");
const CRED_SIZE = 32 + 32 + 32 + 4; // 100 bytes

/// Startup certification is deliberately bounded. Exceeding the bound means
/// the namespace cannot be certified and fails closed just like a bad key.
pub const max_startup_scan_keys = 100_000;

pub const StartupScanError = error{
    UnpreparedAccountName,
    ScanLimitExceeded,
};

/// Verify once, on the auth daemon's startup path, that every users key is
/// already in RFC 7622 prepared form. No rows are changed and no read fallback
/// is provided: an unprepared key makes startup refuse loudly so the operator
/// runs `xmppctl migrate-precis` instead of users being silently locked out.
pub fn verifyPreparedUsers(comptime Backend: type, backend: *Backend, max_keys: usize) !void {
    comptime backend_mod.assertBackend(Backend);
    var iterator = try backend.iterator(NAMESPACE, "");
    defer iterator.deinit();

    var prep_buf: [6 * precis.max_input_octets]u8 = undefined;
    var scratch_cps: [3 * precis.max_input_octets]u21 = undefined;
    var scratch_cccs: [3 * precis.max_input_octets]u8 = undefined;
    var count: usize = 0;
    while (iterator.next()) |entry| {
        if (count == max_keys) return error.ScanLimitExceeded;
        count += 1;
        const prepared = precis.xmppLocalpart(entry.key, &prep_buf, &scratch_cps, &scratch_cccs) catch
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
        /// Returns error.UserExists if the username is taken.
        pub fn addUser(self: *Self, allocator: std.mem.Allocator, username: []const u8, password: []const u8) !void {
            // Check for duplicate
            const existing = try self.backend.get(allocator, NAMESPACE, username);
            if (existing) |v| {
                allocator.free(v);
                return error.UserExists;
            }

            const creds = try sasl.StoredCredentials.generate(password, 4096);
            const value = serializeCredentials(creds);
            try self.backend.put(NAMESPACE, username, &value);
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
