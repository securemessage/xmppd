//! # Last Activity Store (XEP-0012, T164)
//!
//! Per-account "last went offline" timestamps in the operational backend,
//! namespace "lastact", key = bare JID, value = 8-byte big-endian epoch
//! seconds. Written by session teardown when an account's final resource
//! unbinds (session_lifecycle.destroySession); read when a bare-JID
//! jabber:iq:last query targets an offline user (iq_handler).
//!
//! Records live in the shared op DB, so any worker can answer last-activity
//! queries about any local account without cross-worker routing. They are
//! never deleted while the account exists — an online user is answered 0
//! before the record is consulted, and a reconnect simply rewrites the
//! timestamp at the next teardown.

const std = @import("std");

pub const NAMESPACE = "lastact";

/// Record (or refresh) when `bare_jid`'s last resource went offline.
pub fn record(backend: anytype, bare_jid: []const u8, ts: u64) !void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, ts, .big);
    try backend.put(NAMESPACE, bare_jid, &buf);
}

/// Fetch the last-offline timestamp for `bare_jid`, or null when the
/// account has never torn down a session since records were kept.
pub fn get(allocator: std.mem.Allocator, backend: anytype, bare_jid: []const u8) !?u64 {
    const raw = try backend.get(allocator, NAMESPACE, bare_jid) orelse return null;
    defer allocator.free(raw);
    if (raw.len != 8) return null; // corrupt record — treat as absent
    return std.mem.readInt(u64, raw[0..8], .big);
}

/// Remove a record (account deletion).
pub fn remove(backend: anytype, bare_jid: []const u8) !void {
    try backend.delete(NAMESPACE, bare_jid);
}

// --- Tests ---

const backend_mod = @import("backend");
const MemoryBackend = backend_mod.MemoryBackend;

test "last activity: record and get round-trip" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    try record(&db, "alice@localhost", 1700000000);
    const ts = try get(std.testing.allocator, &db, "alice@localhost");
    try std.testing.expectEqual(@as(?u64, 1700000000), ts);
}

test "last activity: missing key returns null" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    const ts = try get(std.testing.allocator, &db, "nobody@localhost");
    try std.testing.expect(ts == null);
}

test "last activity: rewrite keeps newest timestamp" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    try record(&db, "bob@localhost", 100);
    try record(&db, "bob@localhost", 200);
    const ts = try get(std.testing.allocator, &db, "bob@localhost");
    try std.testing.expectEqual(@as(?u64, 200), ts);
}

test "last activity: remove deletes the record" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    try record(&db, "carol@localhost", 300);
    try remove(&db, "carol@localhost");
    const ts = try get(std.testing.allocator, &db, "carol@localhost");
    try std.testing.expect(ts == null);
}

test "last activity: corrupt-length record reads as absent" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    try db.put(NAMESPACE, "dave@localhost", "short");
    const ts = try get(std.testing.allocator, &db, "dave@localhost");
    try std.testing.expect(ts == null);
}
