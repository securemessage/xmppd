//! Bounded store key construction (S4).
//!
//! Store keys join an owner JID, a NUL separator, and one or more
//! client-supplied parts (contact JID, blocked JID, PEP node + item id)
//! into a fixed stack buffer. LMDB limits keys to 511 bytes; the joins
//! this replaces memcpy'd without a length check, so a ~600-byte client
//! JID overflowed the buffer and aborted xmppd-core in ReleaseSafe.

const std = @import("std");

/// LMDB's key size limit (mdb.c `MDB_MAXKEYSIZE` for the default build).
pub const MAX_KEY_LEN: usize = 511;

pub const KeyError = error{KeyTooLong};

/// `a ++ 0 ++ b`, bounded. `buf` must hold the result; the LMDB cap applies
/// even with a larger buffer.
pub fn join2(buf: []u8, a: []const u8, b: []const u8) KeyError![]const u8 {
    const len = a.len + 1 + b.len;
    if (len > buf.len or len > MAX_KEY_LEN) return error.KeyTooLong;
    @memcpy(buf[0..a.len], a);
    buf[a.len] = 0;
    @memcpy(buf[a.len + 1 .. len], b);
    return buf[0..len];
}

/// `a ++ 0 ++ b ++ 0 ++ c`, bounded.
pub fn join3(buf: []u8, a: []const u8, b: []const u8, c: []const u8) KeyError![]const u8 {
    const len = a.len + 1 + b.len + 1 + c.len;
    if (len > buf.len or len > MAX_KEY_LEN) return error.KeyTooLong;
    @memcpy(buf[0..a.len], a);
    buf[a.len] = 0;
    @memcpy(buf[a.len + 1 ..][0..b.len], b);
    buf[a.len + 1 + b.len] = 0;
    @memcpy(buf[a.len + 1 + b.len + 1 .. len], c);
    return buf[0..len];
}

/// `a ++ 0` namespace prefix for per-owner scans, bounded.
pub fn prefix(buf: []u8, a: []const u8) KeyError![]const u8 {
    const len = a.len + 1;
    if (len > buf.len or len > MAX_KEY_LEN) return error.KeyTooLong;
    @memcpy(buf[0..a.len], a);
    buf[a.len] = 0;
    return buf[0..len];
}

/// `a ++ 0 ++ b ++ 0` two-level scan prefix (e.g. PEP user + node), bounded.
/// The trailing separator keeps `b` from matching a longer sibling part.
pub fn prefix2(buf: []u8, a: []const u8, b: []const u8) KeyError![]const u8 {
    const len = a.len + 1 + b.len + 1;
    if (len > buf.len or len > MAX_KEY_LEN) return error.KeyTooLong;
    @memcpy(buf[0..a.len], a);
    buf[a.len] = 0;
    @memcpy(buf[a.len + 1 ..][0..b.len], b);
    buf[a.len + 1 + b.len] = 0;
    return buf[0..len];
}

/// True when `a ++ 0 ++ b` fits the key budget. Ingress validation uses
/// this to reject an oversized client JID before reaching the store.
pub fn fits2(a: []const u8, b: []const u8) bool {
    return a.len + 1 + b.len <= MAX_KEY_LEN;
}

/// True when `a ++ 0 ++ b ++ 0 ++ c` fits the key budget.
pub fn fits3(a: []const u8, b: []const u8, c: []const u8) bool {
    return a.len + 1 + b.len + 1 + c.len <= MAX_KEY_LEN;
}

test "join2 builds a separated key" {
    var buf: [512]u8 = undefined;
    const key = try join2(&buf, "alice@localhost", "bob@localhost");
    try std.testing.expectEqualSlices(u8, "alice@localhost\x00bob@localhost", key);
}

test "join3 builds a doubly separated key" {
    var buf: [512]u8 = undefined;
    const key = try join3(&buf, "u", "node", "id");
    try std.testing.expectEqualSlices(u8, "u\x00node\x00id", key);
}

test "oversized parts return KeyTooLong (S4)" {
    var buf: [512]u8 = undefined;
    const big = "x" ** 300;
    try std.testing.expectError(error.KeyTooLong, join2(&buf, big, big));
    try std.testing.expectError(error.KeyTooLong, join3(&buf, big, big, big));
    try std.testing.expectError(error.KeyTooLong, prefix(&buf, "y" ** 512));
    // Exactly 511 is accepted.
    const key = try join2(&buf, "a" ** 255, "b" ** 255);
    try std.testing.expectEqual(@as(usize, MAX_KEY_LEN), key.len);
}

test "fits2" {
    try std.testing.expect(fits2("a" ** 255, "b" ** 255));
    try std.testing.expect(!fits2("a" ** 256, "b" ** 255));
}
