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
const room_mailbox_mod = @import("room_mailbox");
const RoomConfig = room_store.RoomConfig;
const Role = room_store.Role;
const Affiliation = room_store.Affiliation;
pub const RoomMailbox = room_mailbox_mod.RoomMailbox;

const log = std.log.scoped(.muc);

/// Maximum concurrent rooms.
pub const MAX_ROOMS = 256;

/// Determine which worker owns a room by hashing its JID.
/// Pure computation — no shared state, no locks.
/// Returns 0 in single-thread mode (worker_count <= 1).
pub fn roomOwner(room_jid: []const u8, worker_count: u16) u16 {
    if (worker_count <= 1) return 0;
    // FNV-1a hash for deterministic distribution
    var hash: u32 = 2166136261;
    for (room_jid) |byte| {
        hash ^= byte;
        hash *%= 16777619;
    }
    return @intCast(hash % worker_count);
}

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
    /// Session ID (local index into Server.sessions). REMOTE_OCCUPANT for federated.
    session_id: usize = 0,
    /// Worker thread that owns this session (for cross-thread fan-out routing).
    worker_id: u16 = 0,
    /// Session generation (from SessionMap bind) for ABA-safe cross-thread delivery.
    generation: u32 = 0,
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
    /// Occupant slots (indexed storage for iteration + PendingFanout continuation).
    occupants: [MAX_OCCUPANTS]?Occupant = [_]?Occupant{null} ** MAX_OCCUPANTS,
    occupant_count: usize = 0,
    /// Whether this room is active (slot in use).
    active: bool = false,
    /// Bitmask of workers that have ≥1 occupant. Bit N set = worker N has occupants.
    /// Used for O(workers) multicast instead of O(occupants) cross-thread delivery.
    worker_mask: u16 = 0,
    /// Per-room actor message mailbox. Cross-thread messages from MPSC are pushed
    /// here; owning worker round-robins across rooms for fair scheduling.
    mailbox: RoomMailbox = .{},
    /// Allocator for hash map internals.
    allocator: std.mem.Allocator = undefined,
    /// O(1) nick → slot index lookup.
    nick_map: std.StringHashMapUnmanaged(u8) = .{},
    /// O(1) real_jid → slot index lookup.
    jid_map: std.StringHashMapUnmanaged(u8) = .{},

    pub fn init(allocator: std.mem.Allocator) Room {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Room) void {
        self.nick_map.deinit(self.allocator);
        self.jid_map.deinit(self.allocator);
    }

    pub fn getJid(self: *const Room) []const u8 {
        return self.jid_buf[0..self.jid_len];
    }

    pub fn setJid(self: *Room, jid: []const u8) void {
        const len: u16 = @intCast(@min(jid.len, self.jid_buf.len));
        @memcpy(self.jid_buf[0..len], jid[0..len]);
        self.jid_len = len;
    }

    /// Check if any occupant belongs to the given worker.
    pub fn hasOccupantOnWorker(self: *const Room, wid: u16) bool {
        for (&self.occupants) |*slot| {
            if (slot.*) |*occ| {
                if (occ.worker_id == wid) return true;
            }
        }
        return false;
    }

    /// Find an occupant by nickname. O(1) via hash map.
    pub fn findByNick(self: *const Room, nick: []const u8) ?usize {
        return @as(?usize, self.nick_map.get(nick) orelse return null);
    }

    /// Find an occupant by full JID (user@domain/resource). O(1) via hash map.
    pub fn findByRealJid(self: *const Room, real_jid: []const u8) ?usize {
        return @as(?usize, self.jid_map.get(real_jid) orelse return null);
    }

    /// Find an occupant by bare JID (user@domain).
    pub fn findByBareJid(self: *const Room, bare_jid: []const u8) ?usize {
        for (&self.occupants, 0..) |*slot, i| {
            if (slot.*) |*occ| {
                if (std.mem.eql(u8, occ.getBareJid(), bare_jid)) return i;
            }
        }
        return null;
    }

    /// Add an occupant to the room. Returns slot index or error.
    pub fn addOccupant(self: *Room, nick: []const u8, real_jid: []const u8, bare_jid: []const u8, session_id: usize, worker_id: u16, generation: u32, role: Role, affiliation: Affiliation) !usize {
        // Idempotent: if already present by JID, return existing slot
        if (self.findByRealJid(real_jid)) |existing_idx| return existing_idx;

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
                occ.generation = generation;
                occ.role = role;
                occ.affiliation = affiliation;
                slot.* = occ;
                self.occupant_count += 1;
                self.worker_mask |= @as(u16, 1) << @intCast(worker_id);
                // Update hash map indices (keys point into occupant inline buffers)
                const slot_idx: u8 = @intCast(i);
                self.nick_map.put(self.allocator, self.occupants[i].?.getNick(), slot_idx) catch {};
                self.jid_map.put(self.allocator, self.occupants[i].?.getRealJid(), slot_idx) catch {};
                return i;
            }
        }

        return error.RoomFull;
    }

    /// Remove an occupant by slot index.
    pub fn removeOccupant(self: *Room, index: usize) ?Occupant {
        if (index >= MAX_OCCUPANTS) return null;
        const occ = self.occupants[index] orelse return null;
        // Remove from hash map indices before nulling the slot
        _ = self.nick_map.fetchRemove(occ.getNick());
        _ = self.jid_map.fetchRemove(occ.getRealJid());
        self.occupants[index] = null;
        self.occupant_count -= 1;
        if (!self.hasOccupantOnWorker(occ.worker_id)) {
            self.worker_mask &= ~(@as(u16, 1) << @intCast(occ.worker_id));
        }
        return occ;
    }

    /// Remove an occupant by full JID. Returns the removed occupant.
    pub fn removeByRealJid(self: *Room, real_jid: []const u8) ?Occupant {
        const idx = self.findByRealJid(real_jid) orelse return null;
        return self.removeOccupant(idx);
    }
};

/// Maximum entries in the room directory (for disco#items across all workers).
pub const MAX_DIRECTORY_ENTRIES = 256;

/// An entry in the room directory (local projection of all public rooms across all workers).
pub const DirectoryEntry = struct {
    jid_buf: [256]u8 = [_]u8{0} ** 256,
    jid_len: u16 = 0,
    name_buf: [128]u8 = [_]u8{0} ** 128,
    name_len: u8 = 0,
    active: bool = false,

    pub fn getJid(self: *const DirectoryEntry) []const u8 {
        return self.jid_buf[0..self.jid_len];
    }

    pub fn getName(self: *const DirectoryEntry) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

/// Registry of all active MUC rooms.
/// Rooms are heap-allocated (each Room is ~10KB due to occupant slots).
///
/// In the actor model (v0.6.0+), each worker thread owns its own RoomRegistry
/// instance. Room ownership is determined by `roomOwner(room_jid, worker_count)`.
/// No locks needed — single-threaded access by the owning worker only.
pub const RoomRegistry = struct {
    rooms: [MAX_ROOMS]?*Room = [_]?*Room{null} ** MAX_ROOMS,
    count: usize = 0,
    allocator: std.mem.Allocator,
    /// Room directory — local projection of all public rooms across ALL workers.
    /// Updated via room_directory_update broadcasts. Used by disco#items to return
    /// a complete room list without scatter-gather.
    directory: [MAX_DIRECTORY_ENTRIES]DirectoryEntry = [_]DirectoryEntry{.{}} ** MAX_DIRECTORY_ENTRIES,
    directory_count: usize = 0,

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
                room.* = Room.init(self.allocator);
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
                    room.deinit();
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

    /// Remove all occupants with the given full JID from ALL rooms.
    /// Returns the number of rooms the session was removed from.
    /// NOTE: Does NOT destroy empty rooms — cleanup is deferred to
    /// drainRoomMailboxes in the event loop to avoid ordering conflicts.
    pub fn removeOccupantByRealJid(self: *RoomRegistry, real_jid: []const u8) usize {
        var removed: usize = 0;
        for (&self.rooms) |*slot| {
            const room = slot.* orelse continue;
            if (!room.active) continue;
            if (room.removeByRealJid(real_jid)) |_| {
                removed += 1;
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

    /// Update the room directory (local projection of all public rooms).
    /// Called when a room_directory_update broadcast arrives from another worker.
    pub fn updateDirectory(self: *RoomRegistry, jid: []const u8, name: []const u8, active: bool) void {
        // Look for existing entry with this JID
        for (&self.directory) |*entry| {
            if (entry.active and std.mem.eql(u8, entry.getJid(), jid)) {
                if (active) {
                    // Update name
                    const nlen: u8 = @intCast(@min(name.len, entry.name_buf.len));
                    @memcpy(entry.name_buf[0..nlen], name[0..nlen]);
                    entry.name_len = nlen;
                } else {
                    // Remove
                    entry.active = false;
                    self.directory_count -= 1;
                }
                return;
            }
        }

        if (!active) return; // Nothing to remove

        // Add new entry in first empty slot
        for (&self.directory) |*entry| {
            if (!entry.active) {
                const jlen: u16 = @intCast(@min(jid.len, entry.jid_buf.len));
                @memcpy(entry.jid_buf[0..jlen], jid[0..jlen]);
                entry.jid_len = jlen;
                const nlen: u8 = @intCast(@min(name.len, entry.name_buf.len));
                @memcpy(entry.name_buf[0..nlen], name[0..nlen]);
                entry.name_len = nlen;
                entry.active = true;
                self.directory_count += 1;
                return;
            }
        }
    }

    /// List all active directory entries (for disco#items across all workers).
    pub fn listDirectory(self: *RoomRegistry, buf: []DirectoryEntry) usize {
        var count: usize = 0;
        for (&self.directory) |*entry| {
            if (count >= buf.len) break;
            if (entry.active) {
                buf[count] = entry.*;
                count += 1;
            }
        }
        return count;
    }

    /// Deinitialize — free all allocated rooms.
    pub fn deinit(self: *RoomRegistry) void {
        for (&self.rooms) |*slot| {
            if (slot.*) |room| {
                room.deinit();
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
    var room = Room.init(std.testing.allocator);
    defer room.deinit();
    room.active = true;
    room.setJid("test@conference.localhost");

    const idx = try room.addOccupant("alice", "alice@localhost/mobile", "alice@localhost", 5, 0, 0, .participant, .none);
    try std.testing.expectEqual(@as(usize, 0), idx);
    try std.testing.expectEqual(@as(usize, 1), room.occupant_count);

    // Find by nick
    try std.testing.expectEqual(@as(?usize, 0), room.findByNick("alice"));
    try std.testing.expect(room.findByNick("bob") == null);

    // Find by real JID
    try std.testing.expectEqual(@as(?usize, 0), room.findByRealJid("alice@localhost/mobile"));
    try std.testing.expect(room.findByRealJid("nobody@localhost/x") == null);
}

test "Room: remove occupant" {
    var room = Room.init(std.testing.allocator);
    defer room.deinit();
    room.active = true;
    room.setJid("test@conference.localhost");

    _ = try room.addOccupant("alice", "alice@localhost/mobile", "alice@localhost", 5, 0, 0, .participant, .none);
    _ = try room.addOccupant("bob", "bob@localhost/desktop", "bob@localhost", 7, 0, 0, .participant, .none);
    try std.testing.expectEqual(@as(usize, 2), room.occupant_count);

    const removed = room.removeByRealJid("alice@localhost/mobile").?;
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
    _ = try room.addOccupant("alice", "alice@localhost/m", "alice@localhost", 3, 0, 0, .participant, .owner);
    try std.testing.expectEqual(@as(usize, 1), reg.count);

    const removed_count = reg.removeOccupantByRealJid("alice@localhost/m");
    try std.testing.expectEqual(@as(usize, 1), removed_count);
    // Room still exists (empty) — destruction is deferred to event loop cleanup
    try std.testing.expectEqual(@as(usize, 1), reg.count);
    const room2 = reg.findByJid("temp@conference.localhost").?;
    try std.testing.expectEqual(@as(usize, 0), room2.occupant_count);
}

test "RoomRegistry: persistent room survives empty" {
    var reg = RoomRegistry.init(std.testing.allocator);
    defer reg.deinit();
    var config = RoomConfig{};
    config.persistent = true;

    const room = try reg.createRoom("persist@conference.localhost", config);
    _ = try room.addOccupant("alice", "alice@localhost/m", "alice@localhost", 3, 0, 0, .participant, .owner);

    _ = reg.removeOccupantByRealJid("alice@localhost/m");
    // Persistent room stays
    try std.testing.expectEqual(@as(usize, 1), reg.count);
    try std.testing.expect(reg.findByJid("persist@conference.localhost") != null);
}

test "Room: nickname conflict" {
    var room = Room.init(std.testing.allocator);
    defer room.deinit();
    room.active = true;
    room.setJid("test@conference.localhost");

    _ = try room.addOccupant("alice", "alice@localhost/m", "alice@localhost", 5, 0, 0, .participant, .none);
    // Same nick from different user — caller should check findByNick first
    try std.testing.expect(room.findByNick("alice") != null);
}

test "Room: max occupants enforcement" {
    var room = Room.init(std.testing.allocator);
    defer room.deinit();
    room.active = true;
    room.setJid("test@conference.localhost");
    room.config.max_occupants = 2;

    _ = try room.addOccupant("alice", "alice@localhost/m", "alice@localhost", 1, 0, 0, .participant, .none);
    _ = try room.addOccupant("bob", "bob@localhost/m", "bob@localhost", 2, 0, 0, .participant, .none);
    // Third occupant should be rejected
    try std.testing.expectError(error.RoomFull, room.addOccupant("carol", "carol@localhost/m", "carol@localhost", 3, 0, 0, .participant, .none));
    try std.testing.expectEqual(@as(usize, 2), room.occupant_count);
}

test "Room: findByBareJid" {
    var room = Room.init(std.testing.allocator);
    defer room.deinit();
    room.active = true;
    room.setJid("test@conference.localhost");

    _ = try room.addOccupant("alice", "alice@localhost/mobile", "alice@localhost", 5, 0, 0, .participant, .none);
    _ = try room.addOccupant("bob", "bob@localhost/desktop", "bob@localhost", 7, 0, 0, .moderator, .admin);

    try std.testing.expectEqual(@as(?usize, 0), room.findByBareJid("alice@localhost"));
    try std.testing.expectEqual(@as(?usize, 1), room.findByBareJid("bob@localhost"));
    try std.testing.expect(room.findByBareJid("unknown@localhost") == null);
}

test "Room: occupant role and affiliation" {
    var room = Room.init(std.testing.allocator);
    defer room.deinit();
    room.active = true;
    room.setJid("test@conference.localhost");

    _ = try room.addOccupant("owner", "alice@localhost/m", "alice@localhost", 1, 0, 0, .moderator, .owner);
    _ = try room.addOccupant("guest", "bob@localhost/m", "bob@localhost", 2, 0, 0, .visitor, .none);

    const owner = room.occupants[0].?;
    try std.testing.expectEqual(Role.moderator, owner.role);
    try std.testing.expectEqual(Affiliation.owner, owner.affiliation);
    try std.testing.expectEqualStrings("owner", owner.getNick());

    const guest = room.occupants[1].?;
    try std.testing.expectEqual(Role.visitor, guest.role);
    try std.testing.expectEqual(Affiliation.none, guest.affiliation);
}

test "Room: remove and re-add occupant reuses slot" {
    var room = Room.init(std.testing.allocator);
    defer room.deinit();
    room.active = true;
    room.setJid("test@conference.localhost");

    const idx0 = try room.addOccupant("alice", "alice@localhost/m", "alice@localhost", 1, 0, 0, .participant, .none);
    _ = try room.addOccupant("bob", "bob@localhost/m", "bob@localhost", 2, 0, 0, .participant, .none);
    try std.testing.expectEqual(@as(usize, 0), idx0);
    try std.testing.expectEqual(@as(usize, 2), room.occupant_count);

    // Remove alice (slot 0)
    _ = room.removeOccupant(0);
    try std.testing.expectEqual(@as(usize, 1), room.occupant_count);

    // New occupant should reuse slot 0
    const idx_carol = try room.addOccupant("carol", "carol@localhost/m", "carol@localhost", 3, 0, 0, .participant, .none);
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

test "RoomRegistry: removeOccupantByRealJid from multiple rooms" {
    var reg = RoomRegistry.init(std.testing.allocator);
    defer reg.deinit();

    const room1 = try reg.createRoom("room1@conference.localhost", .{ .persistent = false });
    const room2 = try reg.createRoom("room2@conference.localhost", .{ .persistent = false });

    // Same user in both rooms
    _ = try room1.addOccupant("alice", "alice@localhost/m", "alice@localhost", 3, 0, 0, .participant, .none);
    _ = try room1.addOccupant("bob", "bob@localhost/m", "bob@localhost", 4, 0, 0, .participant, .none);
    _ = try room2.addOccupant("alice", "alice@localhost/m", "alice@localhost", 3, 0, 0, .participant, .none);

    // Disconnect alice — removed from both rooms
    const removed_count = reg.removeOccupantByRealJid("alice@localhost/m");
    try std.testing.expectEqual(@as(usize, 2), removed_count);

    // Both rooms still exist — destruction deferred to event loop cleanup
    // room1 still has bob, room2 is empty
    try std.testing.expectEqual(@as(usize, 2), reg.count);
    const remaining = reg.findByJid("room1@conference.localhost").?;
    try std.testing.expectEqual(@as(usize, 1), remaining.occupant_count);
    const empty = reg.findByJid("room2@conference.localhost").?;
    try std.testing.expectEqual(@as(usize, 0), empty.occupant_count);
}

test "Room: worker_mask set on add" {
    var room = Room.init(std.testing.allocator);
    defer room.deinit();
    room.active = true;
    room.setJid("test@conference.localhost");
    try std.testing.expectEqual(@as(u16, 0), room.worker_mask);

    _ = try room.addOccupant("alice", "alice@localhost/m", "alice@localhost", 1, 0, 0, .participant, .none);
    try std.testing.expectEqual(@as(u16, 0b0001), room.worker_mask);

    _ = try room.addOccupant("bob", "bob@localhost/m", "bob@localhost", 2, 1, 0, .participant, .none);
    try std.testing.expectEqual(@as(u16, 0b0011), room.worker_mask);

    // Same worker — bit already set
    _ = try room.addOccupant("carol", "carol@localhost/m", "carol@localhost", 3, 0, 0, .participant, .none);
    try std.testing.expectEqual(@as(u16, 0b0011), room.worker_mask);
}

test "Room: worker_mask cleared on remove when no occupants remain on worker" {
    var room = Room.init(std.testing.allocator);
    defer room.deinit();
    room.active = true;
    room.setJid("test@conference.localhost");

    _ = try room.addOccupant("alice", "alice@localhost/m", "alice@localhost", 1, 0, 0, .participant, .none);
    _ = try room.addOccupant("bob", "bob@localhost/m", "bob@localhost", 2, 1, 0, .participant, .none);
    _ = try room.addOccupant("carol", "carol@localhost/m", "carol@localhost", 3, 0, 0, .participant, .none);
    try std.testing.expectEqual(@as(u16, 0b0011), room.worker_mask);

    // Remove alice (worker 0) — carol still on worker 0
    _ = room.removeByRealJid("alice@localhost/m");
    try std.testing.expectEqual(@as(u16, 0b0011), room.worker_mask);

    // Remove carol (worker 0) — no one left on worker 0
    _ = room.removeByRealJid("carol@localhost/m");
    try std.testing.expectEqual(@as(u16, 0b0010), room.worker_mask);

    // Remove bob (worker 1) — empty
    _ = room.removeByRealJid("bob@localhost/m");
    try std.testing.expectEqual(@as(u16, 0b0000), room.worker_mask);
}

test "Room: hasOccupantOnWorker" {
    var room = Room.init(std.testing.allocator);
    defer room.deinit();
    room.active = true;
    room.setJid("test@conference.localhost");

    try std.testing.expect(!room.hasOccupantOnWorker(0));
    _ = try room.addOccupant("alice", "alice@localhost/m", "alice@localhost", 1, 2, 0, .participant, .none);
    try std.testing.expect(!room.hasOccupantOnWorker(0));
    try std.testing.expect(room.hasOccupantOnWorker(2));
}

test "roomOwner: single worker always returns 0" {
    try std.testing.expectEqual(@as(u16, 0), roomOwner("room@conference.localhost", 0));
    try std.testing.expectEqual(@as(u16, 0), roomOwner("room@conference.localhost", 1));
}

test "roomOwner: deterministic distribution" {
    const owner1 = roomOwner("dev@conference.example.com", 4);
    const owner2 = roomOwner("dev@conference.example.com", 4);
    try std.testing.expectEqual(owner1, owner2); // same input → same output

    // Different rooms may land on different workers
    const a = roomOwner("room-a@conference.example.com", 4);
    const b = roomOwner("room-b@conference.example.com", 4);
    _ = a;
    _ = b;
    // Both must be < worker_count
    try std.testing.expect(roomOwner("room-a@conference.example.com", 4) < 4);
    try std.testing.expect(roomOwner("room-b@conference.example.com", 4) < 4);
}
