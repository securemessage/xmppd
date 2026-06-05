//! # RoomStore — Persistent MUC room configuration and affiliations
//!
//! Stores room configuration and per-user affiliations for persistent rooms.
//! Transient rooms exist only in memory (RoomRegistry) and are never written here.
//!
//! ## Key Schema
//!
//! Namespace: `rooms`
//! Room config key: `room_jid`
//! Room config value: binary format (see RoomConfig.serialize/deserialize)
//!
//! Namespace: `room_affiliations`
//! Affiliation key: `room_jid\x00bare_jid`
//! Affiliation value: single byte (Affiliation enum ordinal)
//!
//! ## Lifecycle
//!
//! 1. Room created with persistent=true → RoomStore.createRoom()
//! 2. Affiliation changed → RoomStore.setAffiliation()
//! 3. Server restart → RoomStore.loadAll() reconstructs RoomRegistry
//! 4. Room destroyed → RoomStore.destroyRoom() removes config + all affiliations

const std = @import("std");
const backend = @import("backend");

const NS_ROOMS = "rooms";
const NS_AFFILIATIONS = "room_affiliations";

/// MUC role — runtime only, not persisted.
pub const Role = enum(u8) {
    none = 0,
    visitor = 1,
    participant = 2,
    moderator = 3,

    pub fn toName(self: Role) []const u8 {
        return switch (self) {
            .none => "none",
            .visitor => "visitor",
            .participant => "participant",
            .moderator => "moderator",
        };
    }

    pub fn fromName(name: []const u8) ?Role {
        if (std.mem.eql(u8, name, "none")) return .none;
        if (std.mem.eql(u8, name, "visitor")) return .visitor;
        if (std.mem.eql(u8, name, "participant")) return .participant;
        if (std.mem.eql(u8, name, "moderator")) return .moderator;
        return null;
    }
};

/// MUC affiliation — persistent, stored in RoomStore.
pub const Affiliation = enum(u8) {
    outcast = 0,
    none = 1,
    member = 2,
    admin = 3,
    owner = 4,

    pub fn toName(self: Affiliation) []const u8 {
        return switch (self) {
            .outcast => "outcast",
            .none => "none",
            .member => "member",
            .admin => "admin",
            .owner => "owner",
        };
    }

    pub fn fromName(name: []const u8) ?Affiliation {
        if (std.mem.eql(u8, name, "outcast")) return .outcast;
        if (std.mem.eql(u8, name, "none")) return .none;
        if (std.mem.eql(u8, name, "member")) return .member;
        if (std.mem.eql(u8, name, "admin")) return .admin;
        if (std.mem.eql(u8, name, "owner")) return .owner;
        return null;
    }

    /// Default role for this affiliation in an unmoderated room.
    pub fn defaultRole(self: Affiliation) Role {
        return switch (self) {
            .outcast => .none,
            .none => .participant,
            .member => .participant,
            .admin => .moderator,
            .owner => .moderator,
        };
    }
};

/// Persistent room configuration.
pub const RoomConfig = struct {
    persistent: bool = true,
    members_only: bool = false,
    moderated: bool = false,
    password_protected: bool = false,
    password_buf: [64]u8 = [_]u8{0} ** 64,
    password_len: u8 = 0,
    max_occupants: u16 = 0,
    public_room: bool = true,
    anonymous: bool = true,
    history_length: u16 = 20,
    allow_invites: bool = true,
    created_at: u64 = 0,
    name_buf: [256]u8 = [_]u8{0} ** 256,
    name_len: u16 = 0,
    subject_buf: [512]u8 = [_]u8{0} ** 512,
    subject_len: u16 = 0,

    pub fn getName(self: *const RoomConfig) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    pub fn getSubject(self: *const RoomConfig) []const u8 {
        return self.subject_buf[0..self.subject_len];
    }

    pub fn getPassword(self: *const RoomConfig) []const u8 {
        return self.password_buf[0..self.password_len];
    }

    pub fn setName(self: *RoomConfig, name: []const u8) void {
        const len: u16 = @intCast(@min(name.len, self.name_buf.len));
        @memcpy(self.name_buf[0..len], name[0..len]);
        self.name_len = len;
    }

    pub fn setSubject(self: *RoomConfig, subject: []const u8) void {
        const len: u16 = @intCast(@min(subject.len, self.subject_buf.len));
        @memcpy(self.subject_buf[0..len], subject[0..len]);
        self.subject_len = len;
    }

    pub fn setPassword(self: *RoomConfig, password: []const u8) void {
        const len: u8 = @intCast(@min(password.len, self.password_buf.len));
        @memcpy(self.password_buf[0..len], password[0..len]);
        self.password_len = len;
        self.password_protected = len > 0;
    }

    /// Serialize to binary format for storage.
    /// Format: flags(2) | max_occupants(2 BE) | history_length(2 BE) |
    ///         created_at(8 BE) | password_len(1) | password(64) |
    ///         name_len(2 BE) | name | subject_len(2 BE) | subject
    pub fn serialize(self: *const RoomConfig, buf: []u8) ?usize {
        const needed = 2 + 2 + 2 + 8 + 1 + 64 + 2 + self.name_len + 2 + self.subject_len;
        if (buf.len < needed) return null;

        var pos: usize = 0;

        // Flags (2 bytes — 8 booleans, room for expansion)
        var flags: u16 = 0;
        if (self.persistent) flags |= (1 << 0);
        if (self.members_only) flags |= (1 << 1);
        if (self.moderated) flags |= (1 << 2);
        if (self.password_protected) flags |= (1 << 3);
        if (self.public_room) flags |= (1 << 4);
        if (self.anonymous) flags |= (1 << 5);
        if (self.allow_invites) flags |= (1 << 6);
        std.mem.writeInt(u16, buf[pos..][0..2], flags, .big);
        pos += 2;

        // max_occupants (2 BE)
        std.mem.writeInt(u16, buf[pos..][0..2], self.max_occupants, .big);
        pos += 2;

        // history_length (2 BE)
        std.mem.writeInt(u16, buf[pos..][0..2], self.history_length, .big);
        pos += 2;

        // created_at (8 BE)
        std.mem.writeInt(u64, buf[pos..][0..8], self.created_at, .big);
        pos += 8;

        // password_len (1) + password (64)
        buf[pos] = self.password_len;
        pos += 1;
        @memcpy(buf[pos..][0..64], &self.password_buf);
        pos += 64;

        // name_len (2 BE) + name
        std.mem.writeInt(u16, buf[pos..][0..2], self.name_len, .big);
        pos += 2;
        if (self.name_len > 0) {
            @memcpy(buf[pos..][0..self.name_len], self.name_buf[0..self.name_len]);
            pos += self.name_len;
        }

        // subject_len (2 BE) + subject
        std.mem.writeInt(u16, buf[pos..][0..2], self.subject_len, .big);
        pos += 2;
        if (self.subject_len > 0) {
            @memcpy(buf[pos..][0..self.subject_len], self.subject_buf[0..self.subject_len]);
            pos += self.subject_len;
        }

        return pos;
    }

    /// Deserialize from binary storage format.
    pub fn deserialize(data: []const u8) ?RoomConfig {
        if (data.len < 2 + 2 + 2 + 8 + 1 + 64) return null;

        var config = RoomConfig{};
        var pos: usize = 0;

        // Flags
        const flags = std.mem.readInt(u16, data[pos..][0..2], .big);
        pos += 2;
        config.persistent = (flags & (1 << 0)) != 0;
        config.members_only = (flags & (1 << 1)) != 0;
        config.moderated = (flags & (1 << 2)) != 0;
        config.password_protected = (flags & (1 << 3)) != 0;
        config.public_room = (flags & (1 << 4)) != 0;
        config.anonymous = (flags & (1 << 5)) != 0;
        config.allow_invites = (flags & (1 << 6)) != 0;

        // max_occupants
        config.max_occupants = std.mem.readInt(u16, data[pos..][0..2], .big);
        pos += 2;

        // history_length
        config.history_length = std.mem.readInt(u16, data[pos..][0..2], .big);
        pos += 2;

        // created_at
        config.created_at = std.mem.readInt(u64, data[pos..][0..8], .big);
        pos += 8;

        // password
        config.password_len = data[pos];
        pos += 1;
        @memcpy(&config.password_buf, data[pos..][0..64]);
        pos += 64;

        // name
        if (pos + 2 > data.len) return null;
        config.name_len = std.mem.readInt(u16, data[pos..][0..2], .big);
        pos += 2;
        if (config.name_len > 0) {
            if (pos + config.name_len > data.len) return null;
            @memcpy(config.name_buf[0..config.name_len], data[pos..][0..config.name_len]);
            pos += config.name_len;
        }

        // subject
        if (pos + 2 > data.len) return null;
        config.subject_len = std.mem.readInt(u16, data[pos..][0..2], .big);
        pos += 2;
        if (config.subject_len > 0) {
            if (pos + config.subject_len > data.len) return null;
            @memcpy(config.subject_buf[0..config.subject_len], data[pos..][0..config.subject_len]);
            pos += config.subject_len;
        }

        return config;
    }
};

/// Generic RoomStore parameterized on a StorageBackend.
pub fn RoomStore(comptime Backend: type) type {
    comptime {
        backend.assertBackend(Backend);
    }

    return struct {
        const Self = @This();
        db: *Backend,
        allocator: std.mem.Allocator,

        pub fn init(db: *Backend, allocator: std.mem.Allocator) Self {
            return .{ .db = db, .allocator = allocator };
        }

        /// Store a room configuration (create or update).
        pub fn saveRoom(self: *Self, room_jid: []const u8, config: *const RoomConfig) !void {
            var buf: [1024]u8 = undefined;
            const len = config.serialize(&buf) orelse return error.SerializationFailed;
            try self.db.put(NS_ROOMS, room_jid, buf[0..len]);
        }

        /// Load a room configuration by JID.
        pub fn loadRoom(self: *Self, room_jid: []const u8) !?RoomConfig {
            const data = try self.db.get(self.allocator, NS_ROOMS, room_jid) orelse return null;
            defer self.allocator.free(data);
            return RoomConfig.deserialize(data);
        }

        /// Delete a room and all its affiliations.
        pub fn destroyRoom(self: *Self, room_jid: []const u8) !void {
            // Delete config
            try self.db.delete(NS_ROOMS, room_jid);

            // Delete all affiliations for this room (prefix scan)
            var key_buf: [512]u8 = undefined;
            const prefix_len = room_jid.len + 1; // room_jid + \x00
            if (prefix_len > key_buf.len) return;
            @memcpy(key_buf[0..room_jid.len], room_jid);
            key_buf[room_jid.len] = 0;
            const prefix = key_buf[0..prefix_len];

            var iter = try self.db.iterator(NS_AFFILIATIONS, prefix);
            defer iter.deinit();

            // Collect keys to delete (can't delete during iteration)
            var del_keys: [256][256]u8 = undefined;
            var del_lens: [256]usize = undefined;
            var del_count: usize = 0;

            while (iter.next()) |entry| {
                if (del_count >= 256) break;
                const klen = @min(entry.key.len, 256);
                @memcpy(del_keys[del_count][0..klen], entry.key[0..klen]);
                del_lens[del_count] = klen;
                del_count += 1;
            }

            for (0..del_count) |i| {
                self.db.delete(NS_AFFILIATIONS, del_keys[i][0..del_lens[i]]) catch {};
            }
        }

        /// Set a user's affiliation in a room.
        pub fn setAffiliation(self: *Self, room_jid: []const u8, bare_jid: []const u8, affiliation: Affiliation) !void {
            var key_buf: [512]u8 = undefined;
            const key_len = room_jid.len + 1 + bare_jid.len;
            if (key_len > key_buf.len) return error.KeyTooLong;
            @memcpy(key_buf[0..room_jid.len], room_jid);
            key_buf[room_jid.len] = 0;
            @memcpy(key_buf[room_jid.len + 1 ..][0..bare_jid.len], bare_jid);
            const key = key_buf[0..key_len];

            if (affiliation == .none) {
                // Remove affiliation entry (default is "none")
                self.db.delete(NS_AFFILIATIONS, key) catch {};
            } else {
                const val = [_]u8{@intFromEnum(affiliation)};
                try self.db.put(NS_AFFILIATIONS, key, &val);
            }
        }

        /// Get a user's affiliation in a room.
        pub fn getAffiliation(self: *Self, room_jid: []const u8, bare_jid: []const u8) !Affiliation {
            var key_buf: [512]u8 = undefined;
            const key_len = room_jid.len + 1 + bare_jid.len;
            if (key_len > key_buf.len) return .none;
            @memcpy(key_buf[0..room_jid.len], room_jid);
            key_buf[room_jid.len] = 0;
            @memcpy(key_buf[room_jid.len + 1 ..][0..bare_jid.len], bare_jid);
            const key = key_buf[0..key_len];

            const data = try self.db.get(self.allocator, NS_AFFILIATIONS, key) orelse return .none;
            defer self.allocator.free(data);
            if (data.len < 1) return .none;
            return @enumFromInt(data[0]);
        }

        /// Load all persistent room JIDs (for startup).
        /// Writes room JIDs into the provided slice, returns count.
        pub fn listRooms(self: *Self, buf: [][]const u8) !usize {
            var iter = try self.db.iterator(NS_ROOMS, "");
            defer iter.deinit();

            var count: usize = 0;
            while (iter.next()) |entry| {
                if (count >= buf.len) break;
                // Duplicate the key so it survives iterator advancement
                const dupe = try self.allocator.dupe(u8, entry.key);
                buf[count] = dupe;
                count += 1;
            }
            return count;
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

test "RoomConfig: serialize and deserialize roundtrip" {
    var config = RoomConfig{};
    config.persistent = true;
    config.members_only = true;
    config.moderated = false;
    config.public_room = true;
    config.anonymous = true;
    config.allow_invites = true;
    config.max_occupants = 50;
    config.history_length = 25;
    config.created_at = 1717632000;
    config.setName("Test Room");
    config.setSubject("Welcome!");
    config.setPassword("secret");

    var buf: [1024]u8 = undefined;
    const len = config.serialize(&buf).?;

    const restored = RoomConfig.deserialize(buf[0..len]).?;
    try std.testing.expect(restored.persistent);
    try std.testing.expect(restored.members_only);
    try std.testing.expect(!restored.moderated);
    try std.testing.expect(restored.public_room);
    try std.testing.expect(restored.password_protected);
    try std.testing.expectEqual(@as(u16, 50), restored.max_occupants);
    try std.testing.expectEqual(@as(u16, 25), restored.history_length);
    try std.testing.expectEqual(@as(u64, 1717632000), restored.created_at);
    try std.testing.expectEqualStrings("Test Room", restored.getName());
    try std.testing.expectEqualStrings("Welcome!", restored.getSubject());
    try std.testing.expectEqualStrings("secret", restored.getPassword());
}

test "RoomConfig: empty config roundtrip" {
    const config = RoomConfig{};
    var buf: [1024]u8 = undefined;
    const len = config.serialize(&buf).?;

    const restored = RoomConfig.deserialize(buf[0..len]).?;
    try std.testing.expect(restored.persistent);
    try std.testing.expect(!restored.members_only);
    try std.testing.expect(!restored.moderated);
    try std.testing.expectEqual(@as(u16, 0), restored.name_len);
    try std.testing.expectEqual(@as(u16, 0), restored.subject_len);
}

test "Affiliation: defaultRole" {
    try std.testing.expectEqual(Role.none, Affiliation.outcast.defaultRole());
    try std.testing.expectEqual(Role.participant, Affiliation.none.defaultRole());
    try std.testing.expectEqual(Role.participant, Affiliation.member.defaultRole());
    try std.testing.expectEqual(Role.moderator, Affiliation.admin.defaultRole());
    try std.testing.expectEqual(Role.moderator, Affiliation.owner.defaultRole());
}

test "Affiliation: name roundtrip" {
    inline for (@typeInfo(Affiliation).@"enum".fields) |field| {
        const aff: Affiliation = @enumFromInt(field.value);
        const name = aff.toName();
        const restored = Affiliation.fromName(name).?;
        try std.testing.expectEqual(aff, restored);
    }
}

test "Role: name roundtrip" {
    inline for (@typeInfo(Role).@"enum".fields) |field| {
        const role: Role = @enumFromInt(field.value);
        const name = role.toName();
        const restored = Role.fromName(name).?;
        try std.testing.expectEqual(role, restored);
    }
}

// ============================================================================
// RoomStore(MemoryBackend) integration tests
// ============================================================================

const MemoryBackend = backend.MemoryBackend;
const TestRoomStore = RoomStore(MemoryBackend);

test "RoomStore: save and load room config" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestRoomStore.init(&db, std.testing.allocator);

    var config = RoomConfig{};
    config.persistent = true;
    config.members_only = true;
    config.max_occupants = 100;
    config.history_length = 30;
    config.created_at = 1717632000;
    config.setName("General");
    config.setSubject("Welcome to General!");

    try store.saveRoom("general@conference.localhost", &config);

    const loaded = try store.loadRoom("general@conference.localhost");
    try std.testing.expect(loaded != null);
    const c = loaded.?;
    try std.testing.expect(c.persistent);
    try std.testing.expect(c.members_only);
    try std.testing.expectEqual(@as(u16, 100), c.max_occupants);
    try std.testing.expectEqual(@as(u16, 30), c.history_length);
    try std.testing.expectEqual(@as(u64, 1717632000), c.created_at);
    try std.testing.expectEqualStrings("General", c.getName());
    try std.testing.expectEqualStrings("Welcome to General!", c.getSubject());
}

test "RoomStore: load nonexistent room returns null" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestRoomStore.init(&db, std.testing.allocator);

    const loaded = try store.loadRoom("nonexistent@conference.localhost");
    try std.testing.expect(loaded == null);
}

test "RoomStore: destroy room removes config" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestRoomStore.init(&db, std.testing.allocator);

    var config = RoomConfig{};
    config.setName("Temp Room");
    try store.saveRoom("temp@conference.localhost", &config);

    try store.destroyRoom("temp@conference.localhost");

    const loaded = try store.loadRoom("temp@conference.localhost");
    try std.testing.expect(loaded == null);
}

test "RoomStore: set and get affiliation" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestRoomStore.init(&db, std.testing.allocator);

    try store.setAffiliation("room@conference.localhost", "alice@localhost", .owner);
    try store.setAffiliation("room@conference.localhost", "bob@localhost", .admin);
    try store.setAffiliation("room@conference.localhost", "eve@localhost", .outcast);

    const alice_aff = try store.getAffiliation("room@conference.localhost", "alice@localhost");
    try std.testing.expectEqual(Affiliation.owner, alice_aff);

    const bob_aff = try store.getAffiliation("room@conference.localhost", "bob@localhost");
    try std.testing.expectEqual(Affiliation.admin, bob_aff);

    const eve_aff = try store.getAffiliation("room@conference.localhost", "eve@localhost");
    try std.testing.expectEqual(Affiliation.outcast, eve_aff);

    // Unknown user defaults to .none
    const unknown = try store.getAffiliation("room@conference.localhost", "unknown@localhost");
    try std.testing.expectEqual(Affiliation.none, unknown);
}

test "RoomStore: set affiliation to none removes entry" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestRoomStore.init(&db, std.testing.allocator);

    try store.setAffiliation("room@conference.localhost", "alice@localhost", .admin);
    const before = try store.getAffiliation("room@conference.localhost", "alice@localhost");
    try std.testing.expectEqual(Affiliation.admin, before);

    try store.setAffiliation("room@conference.localhost", "alice@localhost", .none);
    const after = try store.getAffiliation("room@conference.localhost", "alice@localhost");
    try std.testing.expectEqual(Affiliation.none, after);
}

test "RoomStore: affiliations isolated between rooms" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestRoomStore.init(&db, std.testing.allocator);

    try store.setAffiliation("room1@conference.localhost", "alice@localhost", .owner);
    try store.setAffiliation("room2@conference.localhost", "alice@localhost", .member);

    const room1 = try store.getAffiliation("room1@conference.localhost", "alice@localhost");
    try std.testing.expectEqual(Affiliation.owner, room1);

    const room2 = try store.getAffiliation("room2@conference.localhost", "alice@localhost");
    try std.testing.expectEqual(Affiliation.member, room2);
}

test "RoomStore: destroy room removes affiliations" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestRoomStore.init(&db, std.testing.allocator);

    var config = RoomConfig{};
    try store.saveRoom("room@conference.localhost", &config);
    try store.setAffiliation("room@conference.localhost", "alice@localhost", .owner);
    try store.setAffiliation("room@conference.localhost", "bob@localhost", .admin);

    try store.destroyRoom("room@conference.localhost");

    // Affiliations should be gone
    const alice = try store.getAffiliation("room@conference.localhost", "alice@localhost");
    try std.testing.expectEqual(Affiliation.none, alice);
    const bob = try store.getAffiliation("room@conference.localhost", "bob@localhost");
    try std.testing.expectEqual(Affiliation.none, bob);
}

test "RoomStore: listRooms" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestRoomStore.init(&db, std.testing.allocator);

    var c1 = RoomConfig{};
    c1.setName("Room 1");
    try store.saveRoom("room1@conference.localhost", &c1);

    var c2 = RoomConfig{};
    c2.setName("Room 2");
    try store.saveRoom("room2@conference.localhost", &c2);

    var jid_buf: [16][]const u8 = undefined;
    const count = try store.listRooms(&jid_buf);
    defer for (jid_buf[0..count]) |jid| std.testing.allocator.free(jid);
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "RoomStore: update room config" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestRoomStore.init(&db, std.testing.allocator);

    var config = RoomConfig{};
    config.setName("Original");
    config.moderated = false;
    try store.saveRoom("room@conference.localhost", &config);

    // Update
    config.setName("Updated");
    config.moderated = true;
    try store.saveRoom("room@conference.localhost", &config);

    const loaded = (try store.loadRoom("room@conference.localhost")).?;
    try std.testing.expectEqualStrings("Updated", loaded.getName());
    try std.testing.expect(loaded.moderated);
}
