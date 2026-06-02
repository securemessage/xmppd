//! # UserStore — flat-file credential storage
//!
//! Stores SCRAM-SHA-256 derived credentials in a simple text format:
//!
//! ```
//! # username:salt_hex:stored_key_hex:server_key_hex:iteration_count
//! alice:a1b2c3...:d4e5f6...:789abc...:4096
//! bob:112233...:445566...:778899...:4096
//! ```
//!
//! Loaded into memory at startup, modified in-memory, and written back
//! atomically (write temp + rename) on mutations.

const std = @import("std");
const sasl = @import("sasl");

const log = std.log.scoped(.user_store);

/// A user entry in the store.
pub const UserEntry = struct {
    username: []const u8,
    credentials: sasl.StoredCredentials,
};

pub const UserStore = struct {
    entries: std.ArrayListUnmanaged(UserEntry),
    /// Allocator for string data.
    arena: std.heap.ArenaAllocator,
    /// Backing allocator (for ArrayListUnmanaged).
    allocator: std.mem.Allocator,
    /// Path to the users.db file.
    path: []const u8,

    pub fn init(allocator: std.mem.Allocator, path: []const u8) UserStore {
        return .{
            .entries = .{},
            .arena = std.heap.ArenaAllocator.init(allocator),
            .allocator = allocator,
            .path = path,
        };
    }

    pub fn deinit(self: *UserStore) void {
        self.entries.deinit(self.allocator);
        self.arena.deinit();
    }

    /// Load users from the file. Creates an empty store if the file doesn't exist.
    pub fn load(self: *UserStore) !void {
        self.entries.clearRetainingCapacity();
        _ = self.arena.reset(.retain_capacity);

        const file = std.fs.cwd().openFile(self.path, .{}) catch |err| {
            if (err == error.FileNotFound) {
                log.info("user store not found at {s}, starting empty", .{self.path});
                return;
            }
            return err;
        };
        defer file.close();

        const alloc = self.arena.allocator();

        // Read entire file (users.db is small — typically <10KB)
        const contents = try file.readToEndAlloc(alloc, 1024 * 1024);

        var lines = std.mem.splitScalar(u8, contents, '\n');
        while (lines.next()) |line| {
            // Skip empty lines and comments
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            const entry = parseLine(alloc, trimmed) catch |err| {
                log.warn("skipping malformed line: {}", .{err});
                continue;
            };
            try self.entries.append(self.allocator, entry);
        }

        log.info("loaded {d} users from {s}", .{ self.entries.items.len, self.path });
    }

    /// Look up a user by username. Returns their stored credentials or null.
    pub fn lookup(self: *const UserStore, username: []const u8) ?sasl.StoredCredentials {
        for (self.entries.items) |entry| {
            if (std.mem.eql(u8, entry.username, username)) {
                return entry.credentials;
            }
        }
        return null;
    }

    /// Add a new user with the given password. Derives SCRAM credentials.
    /// Returns error.UserExists if the username is already taken.
    pub fn addUser(self: *UserStore, username: []const u8, password: []const u8) !void {
        // Check for duplicate
        for (self.entries.items) |entry| {
            if (std.mem.eql(u8, entry.username, username)) {
                return error.UserExists;
            }
        }

        const alloc = self.arena.allocator();
        const creds = sasl.StoredCredentials.generate(password, 4096);

        try self.entries.append(self.allocator, .{
            .username = try alloc.dupe(u8, username),
            .credentials = creds,
        });

        try self.save();
        log.info("added user: {s}", .{username});
    }

    /// Remove a user. Returns error.UserNotFound if not present.
    pub fn removeUser(self: *UserStore, username: []const u8) !void {
        for (self.entries.items, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.username, username)) {
                _ = self.entries.orderedRemove(i);
                try self.save();
                log.info("removed user: {s}", .{username});
                return;
            }
        }
        return error.UserNotFound;
    }

    /// Change a user's password. Derives new SCRAM credentials.
    pub fn changePassword(self: *UserStore, username: []const u8, password: []const u8) !void {
        for (self.entries.items) |*entry| {
            if (std.mem.eql(u8, entry.username, username)) {
                entry.credentials = sasl.StoredCredentials.generate(password, 4096);
                try self.save();
                log.info("changed password for: {s}", .{username});
                return;
            }
        }
        return error.UserNotFound;
    }

    /// Return all usernames.
    pub fn listUsers(self: *const UserStore, allocator: std.mem.Allocator) ![][]const u8 {
        const result = try allocator.alloc([]const u8, self.entries.items.len);
        for (self.entries.items, 0..) |entry, i| {
            result[i] = entry.username;
        }
        return result;
    }

    /// Write the store atomically: write to temp file, then rename.
    fn save(self: *const UserStore) !void {
        // Build temp path
        var tmp_path_buf: [256]u8 = undefined;
        const tmp_path = std.fmt.bufPrint(&tmp_path_buf, "{s}.tmp", .{self.path}) catch return error.PathTooLong;

        // Build file content in memory (users.db is small)
        var content_buf: [65536]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&content_buf);
        const w = fbs.writer();

        w.writeAll("# xmppd user store — do not edit while server is running\n") catch return error.WriteFailed;
        w.writeAll("# format: username:salt_hex:stored_key_hex:server_key_hex:iteration_count\n") catch return error.WriteFailed;

        for (self.entries.items) |entry| {
            w.writeAll(entry.username) catch return error.WriteFailed;
            w.writeByte(':') catch return error.WriteFailed;
            writeHex(w, &entry.credentials.salt) catch return error.WriteFailed;
            w.writeByte(':') catch return error.WriteFailed;
            writeHex(w, &entry.credentials.stored_key) catch return error.WriteFailed;
            w.writeByte(':') catch return error.WriteFailed;
            writeHex(w, &entry.credentials.server_key) catch return error.WriteFailed;
            w.print(":{d}\n", .{entry.credentials.iteration_count}) catch return error.WriteFailed;
        }

        const content = fbs.getWritten();

        // Write to temp file
        const file = try std.fs.cwd().createFile(tmp_path, .{});
        file.writeAll(content) catch {
            file.close();
            std.fs.cwd().deleteFile(tmp_path) catch {};
            return error.WriteFailed;
        };
        file.close();

        // Atomic rename
        std.fs.cwd().rename(tmp_path, self.path) catch |err| {
            std.fs.cwd().deleteFile(tmp_path) catch {};
            return err;
        };
    }

    /// Parse a single line from the users.db file.
    fn parseLine(alloc: std.mem.Allocator, line: []const u8) !UserEntry {
        var iter = std.mem.splitScalar(u8, line, ':');

        const username_raw = iter.next() orelse return error.InvalidFormat;
        const salt_hex = iter.next() orelse return error.InvalidFormat;
        const stored_key_hex = iter.next() orelse return error.InvalidFormat;
        const server_key_hex = iter.next() orelse return error.InvalidFormat;
        const iter_count_str = iter.next() orelse return error.InvalidFormat;

        if (salt_hex.len != 64) return error.InvalidFormat;
        if (stored_key_hex.len != 64) return error.InvalidFormat;
        if (server_key_hex.len != 64) return error.InvalidFormat;

        var salt: [32]u8 = undefined;
        hexDecode(salt_hex, &salt) catch return error.InvalidFormat;

        var stored_key: [32]u8 = undefined;
        hexDecode(stored_key_hex, &stored_key) catch return error.InvalidFormat;

        var server_key: [32]u8 = undefined;
        hexDecode(server_key_hex, &server_key) catch return error.InvalidFormat;

        const iteration_count = std.fmt.parseInt(u32, iter_count_str, 10) catch return error.InvalidFormat;

        return .{
            .username = try alloc.dupe(u8, username_raw),
            .credentials = .{
                .salt = salt,
                .stored_key = stored_key,
                .server_key = server_key,
                .iteration_count = iteration_count,
            },
        };
    }
};

// ============================================================================
// Hex helpers
// ============================================================================

fn writeHex(writer: anytype, data: []const u8) !void {
    for (data) |byte| {
        try writer.print("{x:0>2}", .{byte});
    }
}

fn hexDecode(hex: []const u8, out: []u8) !void {
    if (hex.len != out.len * 2) return error.InvalidHexLength;
    for (out, 0..) |*byte, i| {
        byte.* = std.fmt.parseInt(u8, hex[i * 2 .. i * 2 + 2], 16) catch return error.InvalidHexChar;
    }
}

// ============================================================================
// Tests
// ============================================================================

test "UserStore: add, lookup, list, remove" {
    const allocator = std.testing.allocator;
    const path = "/tmp/xmppd-test-users.db";

    // Clean up
    std.fs.cwd().deleteFile(path) catch {};
    defer std.fs.cwd().deleteFile(path) catch {};

    var store = UserStore.init(allocator, path);
    defer store.deinit();

    try store.load(); // Empty file, should not error

    // Add users
    try store.addUser("alice", "password1");
    try store.addUser("bob", "password2");

    // Duplicate should fail
    try std.testing.expectError(error.UserExists, store.addUser("alice", "other"));

    // Lookup
    const alice_creds = store.lookup("alice") orelse return error.NotFound;
    try std.testing.expectEqual(@as(u32, 4096), alice_creds.iteration_count);
    try std.testing.expect(store.lookup("bob") != null);
    try std.testing.expect(store.lookup("charlie") == null);

    // List
    const users = try store.listUsers(allocator);
    defer allocator.free(users);
    try std.testing.expectEqual(@as(usize, 2), users.len);

    // Remove
    try store.removeUser("alice");
    try std.testing.expect(store.lookup("alice") == null);
    try std.testing.expectError(error.UserNotFound, store.removeUser("nonexistent"));
}

test "UserStore: save and reload" {
    const allocator = std.testing.allocator;
    const path = "/tmp/xmppd-test-users-reload.db";

    std.fs.cwd().deleteFile(path) catch {};
    defer std.fs.cwd().deleteFile(path) catch {};

    // Create and populate
    {
        var store = UserStore.init(allocator, path);
        defer store.deinit();
        try store.load();
        try store.addUser("testuser", "testpassword");
    }

    // Reload into a new store
    {
        var store = UserStore.init(allocator, path);
        defer store.deinit();
        try store.load();

        try std.testing.expectEqual(@as(usize, 1), store.entries.items.len);
        const creds = store.lookup("testuser") orelse return error.NotFound;
        try std.testing.expectEqual(@as(u32, 4096), creds.iteration_count);

        // Verify the credentials actually work with SCRAM
        // The stored credentials should validate against the original password
        // We can't reverse the hash, but we can derive new creds with the same
        // salt and verify they match
        const salt = creds.salt;
        const rederived = sasl.StoredCredentials.derive("testpassword", salt, 4096);
        try std.testing.expectEqualSlices(u8, &creds.stored_key, &rederived.stored_key);
        try std.testing.expectEqualSlices(u8, &creds.server_key, &rederived.server_key);
    }
}

test "UserStore: changePassword" {
    const allocator = std.testing.allocator;
    const path = "/tmp/xmppd-test-users-passwd.db";

    std.fs.cwd().deleteFile(path) catch {};
    defer std.fs.cwd().deleteFile(path) catch {};

    var store = UserStore.init(allocator, path);
    defer store.deinit();
    try store.load();

    try store.addUser("alice", "oldpass");
    const old_creds = store.lookup("alice") orelse return error.NotFound;
    const old_key = old_creds.stored_key;

    try store.changePassword("alice", "newpass");
    const new_creds = store.lookup("alice") orelse return error.NotFound;

    // Keys should differ after password change
    try std.testing.expect(!std.mem.eql(u8, &old_key, &new_creds.stored_key));

    // Nonexistent user
    try std.testing.expectError(error.UserNotFound, store.changePassword("ghost", "x"));
}

test "UserStore: empty file loads cleanly" {
    const allocator = std.testing.allocator;
    const path = "/tmp/xmppd-test-users-empty.db";

    // Create an empty file
    {
        const f = try std.fs.cwd().createFile(path, .{});
        f.close();
    }
    defer std.fs.cwd().deleteFile(path) catch {};

    var store = UserStore.init(allocator, path);
    defer store.deinit();
    try store.load();
    try std.testing.expectEqual(@as(usize, 0), store.entries.items.len);
}

test "UserStore: comments and blank lines are skipped" {
    const allocator = std.testing.allocator;
    const path = "/tmp/xmppd-test-users-comments.db";

    {
        const f = try std.fs.cwd().createFile(path, .{});
        defer f.close();
        try f.writeAll("# This is a comment\n\n  \n");
    }
    defer std.fs.cwd().deleteFile(path) catch {};

    var store = UserStore.init(allocator, path);
    defer store.deinit();
    try store.load();
    try std.testing.expectEqual(@as(usize, 0), store.entries.items.len);
}

test "hexDecode roundtrip" {
    var input = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    var hex_buf: [8]u8 = undefined;
    _ = std.fmt.bufPrint(&hex_buf, "{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{ input[0], input[1], input[2], input[3] }) catch unreachable;

    var output: [4]u8 = undefined;
    try hexDecode(&hex_buf, &output);
    try std.testing.expectEqualSlices(u8, &input, &output);
}
