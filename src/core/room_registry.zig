//! # RoomRegistry — In-memory MUC room and occupant state
//!
//! Tracks all active rooms and their occupants. Persistent rooms are loaded
//! from RoomStore on startup; transient rooms exist only here and are
//! destroyed when the last occupant leaves.
//!
//! This is the MUC equivalent of SessionRegistry — the core routing table
//! for groupchat message fan-out and presence delivery.

const std = @import("std");
const room_store = @import("room_store");
const RoomConfig = room_store.RoomConfig;
const Role = room_store.Role;
const Affiliation = room_store.Affiliation;

const log = std.log.scoped(.muc);

/// Maximum concurrent rooms.
pub const MAX_ROOMS = 256;

/// Maximum occupants per room.
pub const MAX_OCCUPANTS = 128;

/// Sentinel session_id for remote (S2S) occupants.
pub const REMOTE_OCCUPANT: usize = std.math.maxInt(usize);

/// A single occupant in a room.
pub const Occupant = struct {
    /// Room-local nickname.
    nick_buf: [64]u8 = [_]u8{0} ** 64,
    nick_len: u8 = 0,
    /// Full JID of the real user (user@domain/resource).
    real_jid_buf: [256]u8 = [_]u8{0} ** 256,
    real_jid_len: u16 = 0,
    /// Bare JID of the real user (user@domain).
    bare_jid_buf: [256]u8 = [_]u8{0} ** 256,
    bare_jid_len: u16 = 0,
    /// Session ID (index into Server.sessions). REMOTE_OCCUPANT for federated.
    session_id: usize = 0,
    /// Worker thread that owns this session (for cross-thread fan-out routing).
    worker_id: u16 = 0,
    /// Current role (runtime, not persisted).
    role: Role = .participant,
    /// Current affiliation (may differ from stored if changed at runtime).
    affiliation: Affiliation = .none,

    pub fn getNick(self: *const Occupant) []const u8 {
        return self.nick_buf[0..self.nick_len];
    }

    pub fn getRealJid(self: *const Occupant) []const u8 {
        return self.real_jid_buf[0..self.real_jid_len];
    }

    pub fn getBareJid(self: *const Occupant) []const u8 {
        return self.bare_jid_buf[0..self.bare_jid_len];
    }

    pub fn setNick(self: *Occupant, nick: []const u8) void {
        const len: u8 = @intCast(@min(nick.len, self.nick_buf.len));
        @memcpy(self.nick_buf[0..len], nick[0..len]);
        self.nick_len = len;
    }

    pub fn setRealJid(self: *Occupant, jid: []const u8) void {
        const len: u16 = @intCast(@min(jid.len, self.real_jid_buf.len));
        @memcpy(self.real_jid_buf[0..len], jid[0..len]);
        self.real_jid_len = len;
    }

    pub fn setBareJid(self: *Occupant, jid: []const u8) void {
        const len: u16 = @intCast(@min(jid.len, self.bare_jid_buf.len));
        @memcpy(self.bare_jid_buf[0..len], jid[0..len]);
        self.bare_jid_len = len;
    }
};

/// An active MUC room with its occupants.
pub const Room = struct {
    /// Room bare JID (room@conference.example.com).
    jid_buf: [256]u8 = [_]u8{0} ** 256,
    jid_len: u16 = 0,
    /// Room configuration.
    config: RoomConfig = .{},
    /// Occupant slots.
    occupants: [MAX_OCCUPANTS]?Occupant = [_]?Occupant{null} ** MAX_OCCUPANTS,
    occupant_count: usize = 0,
    /// Whether this room is active (slot in use).
    active: bool = false,

    pub fn getJid(self: *const Room) []const u8 {
        return self.jid_buf[0..self.jid_len];
    }

    pub fn setJid(self: *Room, jid: []const u8) void {
        const len: u16 = @intCast(@min(jid.len, self.jid_buf.len));
        @memcpy(self.jid_buf[0..len], jid[0..len]);
        self.jid_len = len;
    }

    /// Find an occupant by nickname.
    pub fn findByNick(self: *const Room, nick: []const u8) ?usize {
        for (&self.occupants, 0..) |*slot, i| {
            if (slot.*) |*occ| {
                if (std.mem.eql(u8, occ.getNick(), nick)) return i;
            }
        }
        return null;
    }

    /// Find an occupant by session ID.
    pub fn findBySessionId(self: *const Room, session_id: usize) ?usize {
        for (&self.occupants, 0..) |*slot, i| {
            if (slot.*) |*occ| {
                if (occ.session_id == session_id) return i;
            }
        }
        return null;
    }

    /// Find an occupant by bare JID.
    pub fn findByBareJid(self: *const Room, bare_jid: []const u8) ?usize {
        for (&self.occupants, 0..) |*slot, i| {
            if (slot.*) |*occ| {
                if (std.mem.eql(u8, occ.getBareJid(), bare_jid)) return i;
            }
        }
        return null;
    }

    /// Add an occupant to the room. Returns slot index or error.
    pub fn addOccupant(self: *Room, nick: []const u8, real_jid: []const u8, bare_jid: []const u8, session_id: usize, worker_id: u16, role: Role, affiliation: Affiliation) !usize {
        // Check capacity
        if (self.config.max_occupants > 0 and self.occupant_count >= self.config.max_occupants) {
            return error.RoomFull;
        }

        // Find free slot
        for (&self.occupants, 0..) |*slot, i| {
            if (slot.* == null) {
                var occ = Occupant{};
                occ.setNick(nick);
                occ.setRealJid(real_jid);
                occ.setBareJid(bare_jid);
                occ.session_id = session_id;
                occ.worker_id = worker_id;
                occ.role = role;
                occ.affiliation = affiliation;
                slot.* = occ;
                self.occupant_count += 1;
                return i;
            }
        }

        return error.RoomFull;
    }

    /// Remove an occupant by slot index.
    pub fn removeOccupant(self: *Room, index: usize) ?Occupant {
        if (index >= MAX_OCCUPANTS) return null;
        const occ = self.occupants[index] orelse return null;
        self.occupants[index] = null;
        self.occupant_count -= 1;
        return occ;
    }

    /// Remove an occupant by session ID. Returns the removed occupant.
    pub fn removeBySessionId(self: *Room, session_id: usize) ?Occupant {
        const idx = self.findBySessionId(session_id) orelse return null;
        return self.removeOccupant(idx);
    }
};

/// Registry of all active MUC rooms.
/// Rooms are heap-allocated (each Room is ~10KB due to occupant slots).
/// Thread-safe: all mutations protected by RwLock. Readers (fan-out) take shared lock.
pub const RoomRegistry = struct {
    rooms: [MAX_ROOMS]?*Room = [_]?*Room{null} ** MAX_ROOMS,
    count: usize = 0,
    allocator: std.mem.Allocator,
    /// Read-write lock for thread safety. Write lock for mutations (join/part/create/destroy),
    /// shared lock for reads (fan-out, disco queries).
    lock: std.Thread.RwLock = .{},

    pub fn init(allocator: std.mem.Allocator) RoomRegistry {
        return .{ .allocator = allocator };
    }

    /// Find a room by its bare JID.
    pub fn findByJid(self: *RoomRegistry, jid: []const u8) ?*Room {
        for (&self.rooms) |*slot| {
            if (slot.*) |room| {
                if (room.active and std.mem.eql(u8, room.getJid(), jid)) {
                    return room;
                }
            }
        }
        return null;
    }

    /// Create a new room. Returns the room or error if full.
    pub fn createRoom(self: *RoomRegistry, jid: []const u8, config: RoomConfig) !*Room {
        // Check for duplicate
        if (self.findByJid(jid) != null) return error.RoomExists;

        // Find free slot
        for (&self.rooms) |*slot| {
            if (slot.* == null) {
                const room = try self.allocator.create(Room);
                room.* = .{};
                room.setJid(jid);
                room.config = config;
                room.active = true;
                slot.* = room;
                self.count += 1;
                log.info("room created: {s}", .{jid});
                return room;
            }
        }

        return error.TooManyRooms;
    }

    /// Destroy a room by JID. Returns true if found and destroyed.
    pub fn destroyRoom(self: *RoomRegistry, jid: []const u8) bool {
        for (&self.rooms) |*slot| {
            if (slot.*) |room| {
                if (room.active and std.mem.eql(u8, room.getJid(), jid)) {
                    self.allocator.destroy(room);
                    slot.* = null;
                    self.count -= 1;
                    log.info("room destroyed: {s}", .{jid});
                    return true;
                }
            }
        }
        return false;
    }

    /// Remove all occupants with the given session_id from ALL rooms.
    /// Returns the number of rooms the session was removed from.
    pub fn removeOccupantBySessionId(self: *RoomRegistry, session_id: usize) usize {
        var removed: usize = 0;
        for (&self.rooms) |*slot| {
            const room = slot.* orelse continue;
            if (!room.active) continue;
            if (room.removeBySessionId(session_id)) |_| {
                removed += 1;
                // If room is now empty and not persistent, destroy it
                if (room.occupant_count == 0 and !room.config.persistent) {
                    log.info("transient room destroyed (empty): {s}", .{room.getJid()});
                    self.allocator.destroy(room);
                    slot.* = null;
                    self.count -= 1;
                }
            }
        }
        return removed;
    }

    /// List all public rooms. Writes room pointers into buf, returns count.
    pub fn listPublicRooms(self: *RoomRegistry, buf: []*const Room) usize {
        var count: usize = 0;
        for (&self.rooms) |*slot| {
            if (count >= buf.len) break;
            if (slot.*) |room| {
                if (room.active and room.config.public_room) {
                    buf[count] = room;
                    count += 1;
                }
            }
        }
        return count;
    }

    /// Deinitialize — free all allocated rooms.
    pub fn deinit(self: *RoomRegistry) void {
        for (&self.rooms) |*slot| {
            if (slot.*) |room| {
                self.allocator.destroy(room);
                slot.* = null;
            }
        }
        self.count = 0;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "RoomRegistry: create and find room" {
    var reg = RoomRegistry.init(std.testing.allocator);
    defer reg.deinit();
    var config = RoomConfig{};
    config.setName("Test Room");
    config.public_room = true;

    const room = try reg.createRoom("test@conference.localhost", config);
    try std.testing.expectEqual(@as(usize, 1), reg.count);
    try std.testing.expectEqualStrings("test@conference.localhost", room.getJid());
    try std.testing.expect(room.active);

    const found = reg.findByJid("test@conference.localhost").?;
    try std.testing.expectEqualStrings("Test Room", found.config.getName());
}

test "RoomRegistry: destroy room" {
    var reg = RoomRegistry.init(std.testing.allocator);
    defer reg.deinit();
    _ = try reg.createRoom("test@conference.localhost", .{});
    try std.testing.expectEqual(@as(usize, 1), reg.count);

    try std.testing.expect(reg.destroyRoom("test@conference.localhost"));
    try std.testing.expectEqual(@as(usize, 0), reg.count);
    try std.testing.expect(reg.findByJid("test@conference.localhost") == null);
}

test "RoomRegistry: duplicate room creation fails" {
    var reg = RoomRegistry.init(std.testing.allocator);
    defer reg.deinit();
    _ = try reg.createRoom("test@conference.localhost", .{});
    try std.testing.expectError(error.RoomExists, reg.createRoom("test@conference.localhost", .{}));
}

test "Room: add and find occupant" {
    var room = Room{};
    room.active = true;
    room.setJid("test@conference.localhost");

    const idx = try room.addOccupant("alice", "alice@localhost/mobile", "alice@localhost", 5, 0, .participant, .none);
    try std.testing.expectEqual(@as(usize, 0), idx);
    try std.testing.expectEqual(@as(usize, 1), room.occupant_count);

    // Find by nick
    try std.testing.expectEqual(@as(?usize, 0), room.findByNick("alice"));
    try std.testing.expect(room.findByNick("bob") == null);

    // Find by session
    try std.testing.expectEqual(@as(?usize, 0), room.findBySessionId(5));
    try std.testing.expect(room.findBySessionId(99) == null);
}

test "Room: remove occupant" {
    var room = Room{};
    room.active = true;
    room.setJid("test@conference.localhost");

    _ = try room.addOccupant("alice", "alice@localhost/mobile", "alice@localhost", 5, 0, .participant, .none);
    _ = try room.addOccupant("bob", "bob@localhost/desktop", "bob@localhost", 7, 0, .participant, .none);
    try std.testing.expectEqual(@as(usize, 2), room.occupant_count);

    const removed = room.removeBySessionId(5).?;
    try std.testing.expectEqualStrings("alice", removed.getNick());
    try std.testing.expectEqual(@as(usize, 1), room.occupant_count);
    try std.testing.expect(room.findByNick("alice") == null);
    try std.testing.expect(room.findByNick("bob") != null);
}

test "RoomRegistry: removeOccupantBySessionId cleans transient rooms" {
    var reg = RoomRegistry.init(std.testing.allocator);
    defer reg.deinit();
    var config = RoomConfig{};
    config.persistent = false; // transient

    const room = try reg.createRoom("temp@conference.localhost", config);
    _ = try room.addOccupant("alice", "alice@localhost/m", "alice@localhost", 3, 0, .participant, .owner);
    try std.testing.expectEqual(@as(usize, 1), reg.count);

    const removed_count = reg.removeOccupantBySessionId(3);
    try std.testing.expectEqual(@as(usize, 1), removed_count);
    // Transient room auto-destroyed
    try std.testing.expectEqual(@as(usize, 0), reg.count);
}

test "RoomRegistry: persistent room survives empty" {
    var reg = RoomRegistry.init(std.testing.allocator);
    defer reg.deinit();
    var config = RoomConfig{};
    config.persistent = true;

    const room = try reg.createRoom("persist@conference.localhost", config);
    _ = try room.addOccupant("alice", "alice@localhost/m", "alice@localhost", 3, 0, .participant, .owner);

    _ = reg.removeOccupantBySessionId(3);
    // Persistent room stays
    try std.testing.expectEqual(@as(usize, 1), reg.count);
    try std.testing.expect(reg.findByJid("persist@conference.localhost") != null);
}

test "Room: nickname conflict" {
    var room = Room{};
    room.active = true;
    room.setJid("test@conference.localhost");

    _ = try room.addOccupant("alice", "alice@localhost/m", "alice@localhost", 5, 0, .participant, .none);
    // Same nick from different user — caller should check findByNick first
    try std.testing.expect(room.findByNick("alice") != null);
}

test "Room: max occupants enforcement" {
    var room = Room{};
    room.active = true;
    room.setJid("test@conference.localhost");
    room.config.max_occupants = 2;

    _ = try room.addOccupant("alice", "alice@localhost/m", "alice@localhost", 1, 0, .participant, .none);
    _ = try room.addOccupant("bob", "bob@localhost/m", "bob@localhost", 2, 0, .participant, .none);
    // Third occupant should be rejected
    try std.testing.expectError(error.RoomFull, room.addOccupant("carol", "carol@localhost/m", "carol@localhost", 3, 0, .participant, .none));
    try std.testing.expectEqual(@as(usize, 2), room.occupant_count);
}

test "Room: findByBareJid" {
    var room = Room{};
    room.active = true;
    room.setJid("test@conference.localhost");

    _ = try room.addOccupant("alice", "alice@localhost/mobile", "alice@localhost", 5, 0, .participant, .none);
    _ = try room.addOccupant("bob", "bob@localhost/desktop", "bob@localhost", 7, 0, .moderator, .admin);

    try std.testing.expectEqual(@as(?usize, 0), room.findByBareJid("alice@localhost"));
    try std.testing.expectEqual(@as(?usize, 1), room.findByBareJid("bob@localhost"));
    try std.testing.expect(room.findByBareJid("unknown@localhost") == null);
}

test "Room: occupant role and affiliation" {
    var room = Room{};
    room.active = true;
    room.setJid("test@conference.localhost");

    _ = try room.addOccupant("owner", "alice@localhost/m", "alice@localhost", 1, 0, .moderator, .owner);
    _ = try room.addOccupant("guest", "bob@localhost/m", "bob@localhost", 2, 0, .visitor, .none);

    const owner = room.occupants[0].?;
    try std.testing.expectEqual(Role.moderator, owner.role);
    try std.testing.expectEqual(Affiliation.owner, owner.affiliation);
    try std.testing.expectEqualStrings("owner", owner.getNick());

    const guest = room.occupants[1].?;
    try std.testing.expectEqual(Role.visitor, guest.role);
    try std.testing.expectEqual(Affiliation.none, guest.affiliation);
}

test "Room: remove and re-add occupant reuses slot" {
    var room = Room{};
    room.active = true;
    room.setJid("test@conference.localhost");

    const idx0 = try room.addOccupant("alice", "alice@localhost/m", "alice@localhost", 1, 0, .participant, .none);
    _ = try room.addOccupant("bob", "bob@localhost/m", "bob@localhost", 2, 0, .participant, .none);
    try std.testing.expectEqual(@as(usize, 0), idx0);
    try std.testing.expectEqual(@as(usize, 2), room.occupant_count);

    // Remove alice (slot 0)
    _ = room.removeOccupant(0);
    try std.testing.expectEqual(@as(usize, 1), room.occupant_count);

    // New occupant should reuse slot 0
    const idx_carol = try room.addOccupant("carol", "carol@localhost/m", "carol@localhost", 3, 0, .participant, .none);
    try std.testing.expectEqual(@as(usize, 0), idx_carol);
    try std.testing.expectEqual(@as(usize, 2), room.occupant_count);
}

test "RoomRegistry: listPublicRooms filters non-public" {
    var reg = RoomRegistry.init(std.testing.allocator);
    defer reg.deinit();

    var pub_config = RoomConfig{};
    pub_config.public_room = true;
    pub_config.setName("Public Room");
    _ = try reg.createRoom("public@conference.localhost", pub_config);

    var priv_config = RoomConfig{};
    priv_config.public_room = false;
    priv_config.setName("Private Room");
    _ = try reg.createRoom("private@conference.localhost", priv_config);

    try std.testing.expectEqual(@as(usize, 2), reg.count);

    var buf: [8]*const Room = undefined;
    const public_count = reg.listPublicRooms(&buf);
    try std.testing.expectEqual(@as(usize, 1), public_count);
    try std.testing.expectEqualStrings("Public Room", buf[0].config.getName());
}

test "RoomRegistry: removeOccupantBySessionId from multiple rooms" {
    var reg = RoomRegistry.init(std.testing.allocator);
    defer reg.deinit();

    const room1 = try reg.createRoom("room1@conference.localhost", .{ .persistent = false });
    const room2 = try reg.createRoom("room2@conference.localhost", .{ .persistent = false });

    // Same user in both rooms
    _ = try room1.addOccupant("alice", "alice@localhost/m", "alice@localhost", 3, 0, .participant, .none);
    _ = try room1.addOccupant("bob", "bob@localhost/m", "bob@localhost", 4, 0, .participant, .none);
    _ = try room2.addOccupant("alice", "alice@localhost/m", "alice@localhost", 3, 0, .participant, .none);

    // Disconnect alice — removed from both rooms
    const removed_count = reg.removeOccupantBySessionId(3);
    try std.testing.expectEqual(@as(usize, 2), removed_count);

    // room2 was transient + empty → auto-destroyed
    // room1 still has bob
    try std.testing.expectEqual(@as(usize, 1), reg.count);
    const remaining = reg.findByJid("room1@conference.localhost").?;
    try std.testing.expectEqual(@as(usize, 1), remaining.occupant_count);
}
