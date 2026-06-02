//! # SessionRegistry — maps JIDs to active sessions
//!
//! Tracks all bound (active) sessions by their full JID, enabling:
//! - Bare JID → all full JIDs for that user (multi-resource)
//! - Full JID → session ID for direct delivery
//! - Presence tracking per session
//!
//! This is the core routing table for stanza delivery.

const std = @import("std");

const log = std.log.scoped(.session_registry);

/// Maximum concurrent bound sessions.
pub const MAX_BOUND_SESSIONS = 1024;

/// An entry in the session registry representing a bound session.
pub const BoundSession = struct {
    /// Session/connection ID (index into Server.sessions).
    id: usize,
    /// Local part of the JID (e.g., "alice").
    local: []const u8,
    /// Domain part of the JID (e.g., "localhost").
    domain: []const u8,
    /// Resource part of the JID (e.g., "mobile").
    resource: []const u8,
    /// Whether this session has sent initial presence.
    presence_available: bool = false,
};

/// Registry of all active (bound) sessions.
pub const SessionRegistry = struct {
    entries: [MAX_BOUND_SESSIONS]?BoundSession = [_]?BoundSession{null} ** MAX_BOUND_SESSIONS,
    count: usize = 0,

    /// Register a session after successful resource binding.
    pub fn bind(self: *SessionRegistry, id: usize, local: []const u8, domain: []const u8, resource: []const u8) !void {
        if (id >= MAX_BOUND_SESSIONS) return error.InvalidSessionId;
        if (self.entries[id] != null) return error.AlreadyBound;

        self.entries[id] = .{
            .id = id,
            .local = local,
            .domain = domain,
            .resource = resource,
        };
        self.count += 1;
        log.info("bound session {d}: {s}@{s}/{s}", .{ id, local, domain, resource });
    }

    /// Unregister a session (on disconnect or stream close).
    pub fn unbind(self: *SessionRegistry, id: usize) ?BoundSession {
        if (id >= MAX_BOUND_SESSIONS) return null;
        const entry = self.entries[id] orelse return null;
        self.entries[id] = null;
        self.count -= 1;
        return entry;
    }

    /// Get the bound session for a given ID.
    pub fn get(self: *const SessionRegistry, id: usize) ?*const BoundSession {
        if (id >= MAX_BOUND_SESSIONS) return null;
        if (self.entries[id]) |*entry| return entry;
        return null;
    }

    /// Get a mutable reference to the bound session.
    pub fn getMut(self: *SessionRegistry, id: usize) ?*BoundSession {
        if (id >= MAX_BOUND_SESSIONS) return null;
        if (self.entries[id]) |*entry| return entry;
        return null;
    }

    /// Mark a session as presence-available.
    pub fn setPresenceAvailable(self: *SessionRegistry, id: usize, available: bool) void {
        if (self.getMut(id)) |entry| {
            entry.presence_available = available;
        }
    }

    /// Find a session by full JID (local@domain/resource).
    pub fn findByFullJid(self: *const SessionRegistry, local: []const u8, domain: []const u8, resource: []const u8) ?*const BoundSession {
        for (&self.entries) |*slot| {
            if (slot.*) |*entry| {
                if (std.mem.eql(u8, entry.local, local) and
                    std.mem.eql(u8, entry.domain, domain) and
                    std.mem.eql(u8, entry.resource, resource))
                {
                    return entry;
                }
            }
        }
        return null;
    }

    /// Find all sessions for a bare JID (local@domain).
    /// Writes session IDs into the provided buffer.
    /// Returns the number of matching sessions found.
    pub fn findByBareJid(self: *const SessionRegistry, local: []const u8, domain: []const u8, buf: []usize) usize {
        var count: usize = 0;
        for (&self.entries) |*slot| {
            if (count >= buf.len) break;
            if (slot.*) |*entry| {
                if (std.mem.eql(u8, entry.local, local) and
                    std.mem.eql(u8, entry.domain, domain))
                {
                    buf[count] = entry.id;
                    count += 1;
                }
            }
        }
        return count;
    }

    /// Find all available (presence-sent) sessions for a bare JID.
    pub fn findAvailableByBareJid(self: *const SessionRegistry, local: []const u8, domain: []const u8, buf: []usize) usize {
        var count: usize = 0;
        for (&self.entries) |*slot| {
            if (count >= buf.len) break;
            if (slot.*) |*entry| {
                if (entry.presence_available and
                    std.mem.eql(u8, entry.local, local) and
                    std.mem.eql(u8, entry.domain, domain))
                {
                    buf[count] = entry.id;
                    count += 1;
                }
            }
        }
        return count;
    }

    /// Check if any session for a bare JID is available (has sent presence).
    pub fn isAvailable(self: *const SessionRegistry, local: []const u8, domain: []const u8) bool {
        for (&self.entries) |*slot| {
            if (slot.*) |*entry| {
                if (entry.presence_available and
                    std.mem.eql(u8, entry.local, local) and
                    std.mem.eql(u8, entry.domain, domain))
                {
                    return true;
                }
            }
        }
        return false;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "SessionRegistry: bind and get" {
    var reg = SessionRegistry{};

    try reg.bind(5, "alice", "localhost", "mobile");
    try std.testing.expectEqual(@as(usize, 1), reg.count);

    const entry = reg.get(5).?;
    try std.testing.expectEqualStrings("alice", entry.local);
    try std.testing.expectEqualStrings("mobile", entry.resource);
    try std.testing.expect(!entry.presence_available);
}

test "SessionRegistry: unbind" {
    var reg = SessionRegistry{};

    try reg.bind(3, "bob", "localhost", "desktop");
    const unbound = reg.unbind(3).?;
    try std.testing.expectEqualStrings("bob", unbound.local);
    try std.testing.expectEqual(@as(usize, 0), reg.count);
    try std.testing.expect(reg.get(3) == null);
}

test "SessionRegistry: findByBareJid multi-resource" {
    var reg = SessionRegistry{};

    try reg.bind(1, "alice", "localhost", "mobile");
    try reg.bind(2, "alice", "localhost", "desktop");
    try reg.bind(3, "bob", "localhost", "laptop");

    var buf: [8]usize = undefined;
    const count = reg.findByBareJid("alice", "localhost", &buf);
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "SessionRegistry: findByFullJid" {
    var reg = SessionRegistry{};

    try reg.bind(1, "alice", "localhost", "mobile");
    try reg.bind(2, "alice", "localhost", "desktop");

    const found = reg.findByFullJid("alice", "localhost", "desktop").?;
    try std.testing.expectEqual(@as(usize, 2), found.id);
    try std.testing.expect(reg.findByFullJid("alice", "localhost", "tablet") == null);
}

test "SessionRegistry: presence availability" {
    var reg = SessionRegistry{};

    try reg.bind(1, "alice", "localhost", "mobile");
    try reg.bind(2, "alice", "localhost", "desktop");

    try std.testing.expect(!reg.isAvailable("alice", "localhost"));

    reg.setPresenceAvailable(1, true);
    try std.testing.expect(reg.isAvailable("alice", "localhost"));

    var buf: [8]usize = undefined;
    const count = reg.findAvailableByBareJid("alice", "localhost", &buf);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(@as(usize, 1), buf[0]);
}

test "SessionRegistry: duplicate bind errors" {
    var reg = SessionRegistry{};

    try reg.bind(5, "alice", "localhost", "mobile");
    try std.testing.expectError(error.AlreadyBound, reg.bind(5, "alice", "localhost", "desktop"));
}

test "SessionRegistry: unbind nonexistent returns null" {
    var reg = SessionRegistry{};
    try std.testing.expect(reg.unbind(99) == null);
}
