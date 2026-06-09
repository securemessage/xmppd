//! # SessionMap — thread-safe JID-keyed session routing table
//!
//! Single source of truth for all session routing, replacing both the per-worker
//! SessionRegistry and the global SharedSessionRegistry. Keyed on JID strings
//! (no integer slot mapping, no partitioning, no sync between two registries).
//!
//! ## Dual Index
//!
//! - `full_map`: full JID ("alice@host/mobile") → SessionEntry — O(1) exact lookup
//! - `bare_map`: bare JID ("alice@host") → BoundedArray of SessionEntry — O(1) multi-resource lookup
//!
//! Both indexes are maintained atomically on bind/unbind.
//!
//! ## Thread Safety
//!
//! All locking is internal. Callers never see the lock. A `multi_worker` flag
//! gates lock acquisition — in single-thread mode, no lock overhead at all.
//!
//! - Read (shared) lock: findByFullJid, findByBareJid, findAvailableByBareJid, getGeneration
//! - Write (exclusive) lock: bind, unbind, setPresenceAvailable

const std = @import("std");

const log = std.log.scoped(.session_map);

/// Maximum resources per bare JID (multi-device).
/// 16 covers any reasonable scenario (phone, tablet, desktop, web × multiple clients).
const MAX_RESOURCES: usize = 16;

/// Maximum resource length stored inline in SessionEntry.
/// Covers all practical resources (RFC allows 1023, but clients use ≤32).
const MAX_RESOURCE_LEN: usize = 64;

/// Result of a session lookup — contains routing information for cross-thread delivery.
pub const SessionEntry = struct {
    worker_id: u16,
    local_session_id: u32,
    generation: u32,
    presence_available: bool = false,
    resource_buf: [MAX_RESOURCE_LEN]u8 = undefined,
    resource_len: u8 = 0,

    /// Get the resource string for this entry.
    pub fn resource(self: *const SessionEntry) []const u8 {
        return self.resource_buf[0..self.resource_len];
    }
};

/// Bounded list of session entries for a bare JID (multi-resource).
pub const EntryList = struct {
    buffer: [MAX_RESOURCES]SessionEntry = undefined,
    len: usize = 0,

    pub fn append(self: *EntryList, entry: SessionEntry) !void {
        if (self.len >= MAX_RESOURCES) return error.TooManyResources;
        self.buffer[self.len] = entry;
        self.len += 1;
    }

    pub fn constSlice(self: *const EntryList) []const SessionEntry {
        return self.buffer[0..self.len];
    }

    pub fn slice(self: *EntryList) []SessionEntry {
        return self.buffer[0..self.len];
    }

    pub fn orderedRemove(self: *EntryList, index: usize) SessionEntry {
        const removed = self.buffer[index];
        if (index < self.len - 1) {
            var i = index;
            while (i < self.len - 1) : (i += 1) {
                self.buffer[i] = self.buffer[i + 1];
            }
        }
        self.len -= 1;
        return removed;
    }
};

/// Thread-safe, JID-keyed session routing table.
pub const SessionMap = struct {
    full_map: std.StringHashMap(SessionEntry),
    bare_map: std.StringHashMap(EntryList),
    lock: std.Thread.RwLock = .{},
    multi_worker: bool,
    allocator: std.mem.Allocator,
    /// Generation counter — incremented globally on every unbind for ABA protection.
    next_generation: u32 = 1,

    pub fn init(allocator: std.mem.Allocator, multi_worker: bool) SessionMap {
        return .{
            .full_map = std.StringHashMap(SessionEntry).init(allocator),
            .bare_map = std.StringHashMap(EntryList).init(allocator),
            .multi_worker = multi_worker,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SessionMap) void {
        // Free all owned key strings in full_map
        var full_iter = self.full_map.iterator();
        while (full_iter.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
        }
        self.full_map.deinit();

        // Free all owned key strings in bare_map
        var bare_iter = self.bare_map.iterator();
        while (bare_iter.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
        }
        self.bare_map.deinit();
    }

    /// Register a session after successful resource binding.
    /// Returns the assigned generation, or error on failure.
    pub fn bind(
        self: *SessionMap,
        worker_id: u16,
        local_session_id: u32,
        local: []const u8,
        domain: []const u8,
        resource: []const u8,
    ) !u32 {
        if (self.multi_worker) self.lock.lock();
        defer if (self.multi_worker) self.lock.unlock();

        const gen = self.next_generation;
        self.next_generation +%= 1;

        if (resource.len > MAX_RESOURCE_LEN) return error.ResourceTooLong;

        var entry = SessionEntry{
            .worker_id = worker_id,
            .local_session_id = local_session_id,
            .generation = gen,
            .resource_len = @intCast(resource.len),
        };
        @memcpy(entry.resource_buf[0..resource.len], resource);

        // Check for duplicate using stack buffer (no allocation)
        var check_buf: [384]u8 = undefined;
        const check_jid = buildJidBuf(&check_buf, local, domain, resource) orelse return error.JidTooLong;
        if (self.full_map.contains(check_jid)) {
            return error.AlreadyBound;
        }

        // Build full JID key: local@domain/resource (heap-allocated, owned by map)
        const full_key = try self.buildFullJid(local, domain, resource);
        errdefer self.allocator.free(full_key);

        try self.full_map.put(full_key, entry);

        // Update bare_map: local@domain → append entry
        const bare_key = try self.buildBareJid(local, domain);
        if (self.bare_map.getPtr(bare_key)) |list| {
            // Bare JID already exists — just append the new resource
            self.allocator.free(bare_key);
            list.append(entry) catch return error.TooManyResources;
        } else {
            // First resource for this bare JID
            var list = EntryList{};
            list.append(entry) catch unreachable;
            try self.bare_map.put(bare_key, list);
        }

        log.info("bind {s}@{s}/{s} worker={d} session={d} gen={d}", .{
            local, domain, resource, worker_id, local_session_id, gen,
        });

        return gen;
    }

    /// Unregister a session. Returns the entry that was removed, or null if not found.
    pub fn unbind(
        self: *SessionMap,
        local: []const u8,
        domain: []const u8,
        resource: []const u8,
    ) ?SessionEntry {
        if (self.multi_worker) self.lock.lock();
        defer if (self.multi_worker) self.lock.unlock();

        // Build full JID for lookup
        var full_buf: [384]u8 = undefined;
        const full_jid = buildJidBuf(&full_buf, local, domain, resource) orelse return null;

        // Remove from full_map
        const removed = self.full_map.fetchRemove(full_jid) orelse return null;
        // Free the owned key
        self.allocator.free(removed.key);
        const entry = removed.value;

        // Remove from bare_map
        var bare_buf: [320]u8 = undefined;
        const bare_jid = buildBareBuf(&bare_buf, local, domain) orelse return entry;

        if (self.bare_map.getPtr(bare_jid)) |list| {
            // Find and remove the matching entry from the list
            var i: usize = 0;
            while (i < list.len) {
                if (list.buffer[i].local_session_id == entry.local_session_id and
                    list.buffer[i].worker_id == entry.worker_id)
                {
                    _ = list.orderedRemove(i);
                    break;
                }
                i += 1;
            }
            // If bare JID has no more resources, remove the bare_map entry entirely
            if (list.len == 0) {
                const bare_removed = self.bare_map.fetchRemove(bare_jid);
                if (bare_removed) |br| self.allocator.free(br.key);
            }
        }

        log.info("unbind {s}@{s}/{s} (was worker={d} session={d} gen={d})", .{
            local, domain, resource, entry.worker_id, entry.local_session_id, entry.generation,
        });

        return entry;
    }

    /// Find a session by full JID (local@domain/resource). O(1).
    pub fn findByFullJid(
        self: *SessionMap,
        local: []const u8,
        domain: []const u8,
        resource: []const u8,
    ) ?SessionEntry {
        if (self.multi_worker) self.lock.lockShared();
        defer if (self.multi_worker) self.lock.unlockShared();

        var buf: [384]u8 = undefined;
        const full_jid = buildJidBuf(&buf, local, domain, resource) orelse return null;
        return self.full_map.get(full_jid);
    }

    /// Find all sessions for a bare JID (local@domain). O(1) + O(resources).
    /// Writes results into the provided buffer. Returns count.
    pub fn findByBareJid(
        self: *SessionMap,
        local: []const u8,
        domain: []const u8,
        buf: []SessionEntry,
    ) usize {
        if (self.multi_worker) self.lock.lockShared();
        defer if (self.multi_worker) self.lock.unlockShared();

        var bare_buf: [320]u8 = undefined;
        const bare_jid = buildBareBuf(&bare_buf, local, domain) orelse return 0;

        const list = self.bare_map.get(bare_jid) orelse return 0;
        const count = @min(list.len, buf.len);
        @memcpy(buf[0..count], list.constSlice()[0..count]);
        return count;
    }

    /// Find all presence-available sessions for a bare JID. O(1) + O(resources).
    pub fn findAvailableByBareJid(
        self: *SessionMap,
        local: []const u8,
        domain: []const u8,
        buf: []SessionEntry,
    ) usize {
        if (self.multi_worker) self.lock.lockShared();
        defer if (self.multi_worker) self.lock.unlockShared();

        var bare_buf: [320]u8 = undefined;
        const bare_jid = buildBareBuf(&bare_buf, local, domain) orelse return 0;

        const list = self.bare_map.get(bare_jid) orelse return 0;
        var count: usize = 0;
        for (list.constSlice()) |entry| {
            if (entry.presence_available) {
                if (count >= buf.len) break;
                buf[count] = entry;
                count += 1;
            }
        }
        return count;
    }

    /// Check if any session for a bare JID is presence-available.
    pub fn isAvailable(self: *SessionMap, local: []const u8, domain: []const u8) bool {
        if (self.multi_worker) self.lock.lockShared();
        defer if (self.multi_worker) self.lock.unlockShared();

        var bare_buf: [320]u8 = undefined;
        const bare_jid = buildBareBuf(&bare_buf, local, domain) orelse return false;

        const list = self.bare_map.get(bare_jid) orelse return false;
        for (list.constSlice()) |entry| {
            if (entry.presence_available) return true;
        }
        return false;
    }

    /// Mark a session as presence-available or unavailable.
    pub fn setPresenceAvailable(
        self: *SessionMap,
        local: []const u8,
        domain: []const u8,
        resource: []const u8,
        available: bool,
    ) void {
        if (self.multi_worker) self.lock.lock();
        defer if (self.multi_worker) self.lock.unlock();

        // Update full_map entry
        var full_buf: [384]u8 = undefined;
        const full_jid = buildJidBuf(&full_buf, local, domain, resource) orelse return;
        if (self.full_map.getPtr(full_jid)) |entry| {
            entry.presence_available = available;
        }

        // Update bare_map entry
        var bare_buf: [320]u8 = undefined;
        const bare_jid = buildBareBuf(&bare_buf, local, domain) orelse return;
        if (self.bare_map.getPtr(bare_jid)) |list| {
            for (list.slice()) |*entry| {
                // Match by full JID identity (worker + local_session_id)
                if (self.full_map.get(full_jid)) |full_entry| {
                    if (entry.worker_id == full_entry.worker_id and
                        entry.local_session_id == full_entry.local_session_id)
                    {
                        entry.presence_available = available;
                    }
                }
            }
        }
    }

    /// Get the generation for a session by full JID. Returns null if not bound.
    pub fn getGeneration(
        self: *SessionMap,
        local: []const u8,
        domain: []const u8,
        resource: []const u8,
    ) ?u32 {
        if (self.multi_worker) self.lock.lockShared();
        defer if (self.multi_worker) self.lock.unlockShared();

        var buf: [384]u8 = undefined;
        const full_jid = buildJidBuf(&buf, local, domain, resource) orelse return null;
        const entry = self.full_map.get(full_jid) orelse return null;
        return entry.generation;
    }

    /// Get the generation for a session by worker_id + local_session_id.
    /// Used by the MPSC drain handler for ABA validation.
    pub fn getGenerationById(
        self: *SessionMap,
        worker_id: u16,
        local_session_id: u32,
        generation: u32,
    ) bool {
        if (self.multi_worker) self.lock.lockShared();
        defer if (self.multi_worker) self.lock.unlockShared();

        // Scan full_map for a matching entry — this is rare (only called during MPSC drain)
        var iter = self.full_map.iterator();
        while (iter.next()) |kv| {
            const e = kv.value_ptr.*;
            if (e.worker_id == worker_id and
                e.local_session_id == local_session_id and
                e.generation == generation)
            {
                return true;
            }
        }
        return false;
    }

    // ========================================================================
    // Internal helpers — build JID strings
    // ========================================================================

    /// Allocate and build "local@domain/resource" key string.
    fn buildFullJid(self: *SessionMap, local: []const u8, domain: []const u8, resource: []const u8) ![]u8 {
        const len = local.len + 1 + domain.len + 1 + resource.len;
        const key = try self.allocator.alloc(u8, len);
        var pos: usize = 0;
        @memcpy(key[pos..][0..local.len], local);
        pos += local.len;
        key[pos] = '@';
        pos += 1;
        @memcpy(key[pos..][0..domain.len], domain);
        pos += domain.len;
        key[pos] = '/';
        pos += 1;
        @memcpy(key[pos..][0..resource.len], resource);
        return key;
    }

    /// Allocate and build "local@domain" key string.
    fn buildBareJid(self: *SessionMap, local: []const u8, domain: []const u8) ![]u8 {
        const len = local.len + 1 + domain.len;
        const key = try self.allocator.alloc(u8, len);
        var pos: usize = 0;
        @memcpy(key[pos..][0..local.len], local);
        pos += local.len;
        key[pos] = '@';
        pos += 1;
        @memcpy(key[pos..][0..domain.len], domain);
        return key;
    }

    /// Build "local@domain/resource" into a stack buffer (no allocation).
    fn buildJidBuf(buf: []u8, local: []const u8, domain: []const u8, resource: []const u8) ?[]const u8 {
        const len = local.len + 1 + domain.len + 1 + resource.len;
        if (len > buf.len) return null;
        var pos: usize = 0;
        @memcpy(buf[pos..][0..local.len], local);
        pos += local.len;
        buf[pos] = '@';
        pos += 1;
        @memcpy(buf[pos..][0..domain.len], domain);
        pos += domain.len;
        buf[pos] = '/';
        pos += 1;
        @memcpy(buf[pos..][0..resource.len], resource);
        return buf[0..len];
    }

    /// Build "local@domain" into a stack buffer (no allocation).
    fn buildBareBuf(buf: []u8, local: []const u8, domain: []const u8) ?[]const u8 {
        const len = local.len + 1 + domain.len;
        if (len > buf.len) return null;
        var pos: usize = 0;
        @memcpy(buf[pos..][0..local.len], local);
        pos += local.len;
        buf[pos] = '@';
        pos += 1;
        @memcpy(buf[pos..][0..domain.len], domain);
        return buf[0..len];
    }
};

// ============================================================================
// Tests
// ============================================================================

test "SessionMap: bind and findByFullJid" {
    var map = SessionMap.init(std.testing.allocator, false);
    defer map.deinit();

    const gen = try map.bind(0, 5, "alice", "localhost", "mobile");
    try std.testing.expect(gen > 0);

    const entry = map.findByFullJid("alice", "localhost", "mobile").?;
    try std.testing.expectEqual(@as(u16, 0), entry.worker_id);
    try std.testing.expectEqual(@as(u32, 5), entry.local_session_id);
    try std.testing.expectEqual(gen, entry.generation);
    try std.testing.expect(!entry.presence_available);
}

test "SessionMap: unbind removes entry" {
    var map = SessionMap.init(std.testing.allocator, false);
    defer map.deinit();

    _ = try map.bind(1, 3, "bob", "localhost", "desktop");

    const removed = map.unbind("bob", "localhost", "desktop").?;
    try std.testing.expectEqual(@as(u16, 1), removed.worker_id);
    try std.testing.expectEqual(@as(u32, 3), removed.local_session_id);

    try std.testing.expect(map.findByFullJid("bob", "localhost", "desktop") == null);
}

test "SessionMap: findByBareJid multi-resource" {
    var map = SessionMap.init(std.testing.allocator, false);
    defer map.deinit();

    _ = try map.bind(0, 1, "alice", "localhost", "mobile");
    _ = try map.bind(1, 2, "alice", "localhost", "desktop");
    _ = try map.bind(0, 3, "bob", "localhost", "laptop");

    var buf: [8]SessionEntry = undefined;
    const count = map.findByBareJid("alice", "localhost", &buf);
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "SessionMap: findAvailableByBareJid" {
    var map = SessionMap.init(std.testing.allocator, false);
    defer map.deinit();

    _ = try map.bind(0, 1, "alice", "localhost", "mobile");
    _ = try map.bind(1, 2, "alice", "localhost", "desktop");

    try std.testing.expect(!map.isAvailable("alice", "localhost"));

    map.setPresenceAvailable("alice", "localhost", "mobile", true);
    try std.testing.expect(map.isAvailable("alice", "localhost"));

    var buf: [8]SessionEntry = undefined;
    const count = map.findAvailableByBareJid("alice", "localhost", &buf);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(@as(u32, 1), buf[0].local_session_id);
}

test "SessionMap: duplicate bind fails" {
    var map = SessionMap.init(std.testing.allocator, false);
    defer map.deinit();

    _ = try map.bind(0, 5, "alice", "localhost", "mobile");
    try std.testing.expectError(error.AlreadyBound, map.bind(1, 6, "alice", "localhost", "mobile"));
}

test "SessionMap: unbind nonexistent returns null" {
    var map = SessionMap.init(std.testing.allocator, false);
    defer map.deinit();

    try std.testing.expect(map.unbind("alice", "localhost", "ghost") == null);
}

test "SessionMap: generation increments" {
    var map = SessionMap.init(std.testing.allocator, false);
    defer map.deinit();

    const gen1 = try map.bind(0, 1, "alice", "localhost", "mobile");
    _ = map.unbind("alice", "localhost", "mobile");
    const gen2 = try map.bind(0, 1, "alice", "localhost", "mobile");
    try std.testing.expect(gen2 > gen1);
}

test "SessionMap: bare_map cleaned on last unbind" {
    var map = SessionMap.init(std.testing.allocator, false);
    defer map.deinit();

    _ = try map.bind(0, 1, "alice", "localhost", "mobile");
    _ = try map.bind(1, 2, "alice", "localhost", "desktop");

    var buf: [8]SessionEntry = undefined;
    try std.testing.expectEqual(@as(usize, 2), map.findByBareJid("alice", "localhost", &buf));

    _ = map.unbind("alice", "localhost", "mobile");
    try std.testing.expectEqual(@as(usize, 1), map.findByBareJid("alice", "localhost", &buf));

    _ = map.unbind("alice", "localhost", "desktop");
    try std.testing.expectEqual(@as(usize, 0), map.findByBareJid("alice", "localhost", &buf));
}

test "SessionMap: workers on different threads" {
    var map = SessionMap.init(std.testing.allocator, false);
    defer map.deinit();

    _ = try map.bind(0, 1, "alice", "host", "mobile");
    _ = try map.bind(1, 1, "bob", "host", "desktop");
    _ = try map.bind(2, 1, "charlie", "host", "tablet");

    const alice = map.findByFullJid("alice", "host", "mobile").?;
    try std.testing.expectEqual(@as(u16, 0), alice.worker_id);

    const bob = map.findByFullJid("bob", "host", "desktop").?;
    try std.testing.expectEqual(@as(u16, 1), bob.worker_id);

    const charlie = map.findByFullJid("charlie", "host", "tablet").?;
    try std.testing.expectEqual(@as(u16, 2), charlie.worker_id);
}

test "SessionMap: getGenerationById for ABA check" {
    var map = SessionMap.init(std.testing.allocator, false);
    defer map.deinit();

    const gen = try map.bind(0, 5, "alice", "host", "mobile");
    try std.testing.expect(map.getGenerationById(0, 5, gen));
    try std.testing.expect(!map.getGenerationById(0, 5, gen + 1)); // wrong gen
    try std.testing.expect(!map.getGenerationById(1, 5, gen)); // wrong worker

    _ = map.unbind("alice", "host", "mobile");
    try std.testing.expect(!map.getGenerationById(0, 5, gen)); // unbound
}

test "SessionMap: resource stored in entry" {
    var map = SessionMap.init(std.testing.allocator, false);
    defer map.deinit();

    _ = try map.bind(0, 1, "alice", "host", "mobile");
    _ = try map.bind(1, 2, "alice", "host", "desktop");
    map.setPresenceAvailable("alice", "host", "mobile", true);
    map.setPresenceAvailable("alice", "host", "desktop", true);

    var buf: [8]SessionEntry = undefined;
    const count = map.findAvailableByBareJid("alice", "host", &buf);
    try std.testing.expectEqual(@as(usize, 2), count);

    // Verify resources are stored and accessible
    var found_mobile = false;
    var found_desktop = false;
    for (buf[0..count]) |*entry| {
        const res = entry.resource();
        if (std.mem.eql(u8, res, "mobile")) found_mobile = true;
        if (std.mem.eql(u8, res, "desktop")) found_desktop = true;
    }
    try std.testing.expect(found_mobile);
    try std.testing.expect(found_desktop);
}
