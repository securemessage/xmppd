//! # XEP-0115: Entity Capabilities — Caps Cache
//!
//! Caches client capability hashes to avoid repeated disco#info queries.
//! The server extracts `ver` from `<c>` elements in presence stanzas, looks
//! up the hash in this cache, and uses the result for PEP +notify filtering.
//!
//! ## Design
//!
//! Fixed-size direct-mapped cache (256 entries). Hash collisions evict the
//! previous entry (acceptable — caps queries are cheap and infrequent).
//! Each entry stores which +notify PEP nodes the client supports as a bitmap.

const std = @import("std");

const log = std.log.scoped(.caps);

/// Maximum length of a caps `ver` hash string (SHA-1 base64 = 28 chars typical, allow more).
pub const MAX_VER_LEN: usize = 48;

/// Number of cache entries (must be power of 2).
const CACHE_SIZE: usize = 256;

/// Bitmap positions for +notify features we care about.
pub const Feature = enum(u6) {
    avatar_metadata = 0,
    bookmarks = 1,
    // Room for future +notify nodes (up to 63)
};

/// A cached capability entry.
const CapsEntry = struct {
    occupied: bool = false,
    ver_buf: [MAX_VER_LEN]u8 = undefined,
    ver_len: u8 = 0,
    /// Bitmap of supported +notify features (indexed by Feature enum).
    features: u64 = 0,

    fn getVer(self: *const CapsEntry) []const u8 {
        return self.ver_buf[0..self.ver_len];
    }
};

/// Fixed-size caps cache with FNV-1a indexing.
pub const CapsCache = struct {
    entries: [CACHE_SIZE]CapsEntry = [_]CapsEntry{.{}} ** CACHE_SIZE,

    /// Look up a ver hash in the cache. Returns the feature bitmap or null if not cached.
    pub fn lookup(self: *const CapsCache, ver: []const u8) ?u64 {
        if (ver.len == 0 or ver.len > MAX_VER_LEN) return null;
        const idx = hashVer(ver);
        const entry = &self.entries[idx];
        if (!entry.occupied) return null;
        if (entry.ver_len != ver.len) return null;
        if (!std.mem.eql(u8, entry.getVer(), ver)) return null;
        return entry.features;
    }

    /// Insert or update a caps entry.
    pub fn insert(self: *CapsCache, ver: []const u8, features: u64) void {
        if (ver.len == 0 or ver.len > MAX_VER_LEN) return;
        const idx = hashVer(ver);
        const entry = &self.entries[idx];
        entry.occupied = true;
        entry.ver_len = @intCast(ver.len);
        @memcpy(entry.ver_buf[0..ver.len], ver);
        entry.features = features;
    }

    /// Check if a specific +notify feature is supported for a given ver hash.
    pub fn hasFeature(self: *const CapsCache, ver: []const u8, feature: Feature) bool {
        const features = self.lookup(ver) orelse return false;
        return (features & (@as(u64, 1) << @intFromEnum(feature))) != 0;
    }
};

/// Parse a feature bitmap from a list of disco#info feature `var` strings.
/// Recognizes +notify namespaces we care about for PEP filtering.
pub fn parseFeaturesFromDisco(feature_vars: []const []const u8) u64 {
    var bitmap: u64 = 0;
    for (feature_vars) |v| {
        if (std.mem.eql(u8, v, "urn:xmpp:avatar:metadata+notify")) {
            bitmap |= (@as(u64, 1) << @intFromEnum(Feature.avatar_metadata));
        } else if (std.mem.eql(u8, v, "urn:xmpp:bookmarks:1#notify")) {
            bitmap |= (@as(u64, 1) << @intFromEnum(Feature.bookmarks));
        }
    }
    return bitmap;
}

/// Parse +notify features from raw disco#info XML response body.
/// Scans for `<feature var='...'/>` patterns and builds a feature bitmap.
pub fn parseFeaturesFromXml(xml_data: []const u8) u64 {
    var bitmap: u64 = 0;
    // Scan for avatar:metadata+notify
    if (std.mem.indexOf(u8, xml_data, "urn:xmpp:avatar:metadata+notify") != null) {
        bitmap |= (@as(u64, 1) << @intFromEnum(Feature.avatar_metadata));
    }
    // Scan for bookmarks:1#notify
    if (std.mem.indexOf(u8, xml_data, "urn:xmpp:bookmarks:1#notify") != null) {
        bitmap |= (@as(u64, 1) << @intFromEnum(Feature.bookmarks));
    }
    return bitmap;
}

/// Extract the `ver` attribute value from a `<c ... ver='...'/>` element in presence XML.
/// Returns the ver string slice within the input, or null if not found.
pub fn extractVerFromPresence(inner_xml: []const u8) ?[]const u8 {
    // Look for <c with caps namespace
    const caps_ns = "http://jabber.org/protocol/caps";
    const c_pos = std.mem.indexOf(u8, inner_xml, caps_ns) orelse return null;

    // Find the ver=' attribute nearby (search backwards for <c and forwards for ver=)
    const search_start = if (c_pos > 200) c_pos - 200 else 0;
    const search_end = @min(inner_xml.len, c_pos + 200);
    const region = inner_xml[search_start..search_end];

    // Find ver=' or ver="
    const ver_prefix = "ver='";
    const ver_prefix_dq = "ver=\"";
    var ver_start: usize = 0;
    var quote_char: u8 = '\'';

    if (std.mem.indexOf(u8, region, ver_prefix)) |pos| {
        ver_start = search_start + pos + ver_prefix.len;
        quote_char = '\'';
    } else if (std.mem.indexOf(u8, region, ver_prefix_dq)) |pos| {
        ver_start = search_start + pos + ver_prefix_dq.len;
        quote_char = '"';
    } else {
        return null;
    }

    // Find the closing quote
    const ver_end = std.mem.indexOfScalarPos(u8, inner_xml, ver_start, quote_char) orelse return null;
    if (ver_end - ver_start > MAX_VER_LEN) return null;
    return inner_xml[ver_start..ver_end];
}

/// FNV-1a hash of ver string, masked to cache index.
fn hashVer(ver: []const u8) usize {
    var h: u32 = 2166136261;
    for (ver) |b| {
        h ^= b;
        h *%= 16777619;
    }
    return @intCast(h & (CACHE_SIZE - 1));
}

// ============================================================================
// Tests
// ============================================================================

test "CapsCache: insert and lookup" {
    var cache = CapsCache{};
    cache.insert("ABC123==", 0x03); // avatar + bookmarks

    const result = cache.lookup("ABC123==");
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u64, 0x03), result.?);

    // Non-existent
    try std.testing.expect(cache.lookup("XYZ999==") == null);
}

test "CapsCache: hasFeature" {
    var cache = CapsCache{};
    cache.insert("TestVer==", @as(u64, 1) << @intFromEnum(Feature.avatar_metadata));

    try std.testing.expect(cache.hasFeature("TestVer==", .avatar_metadata));
    try std.testing.expect(!cache.hasFeature("TestVer==", .bookmarks));
}

test "extractVerFromPresence: standard caps element" {
    const xml = "<priority>0</priority><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://gajim.org' ver='ABC123=='/>";
    const ver = extractVerFromPresence(xml);
    try std.testing.expect(ver != null);
    try std.testing.expectEqualStrings("ABC123==", ver.?);
}

test "extractVerFromPresence: double quotes" {
    const xml = "<c xmlns=\"http://jabber.org/protocol/caps\" hash=\"sha-1\" ver=\"XYZ789==\"/>";
    const ver = extractVerFromPresence(xml);
    try std.testing.expect(ver != null);
    try std.testing.expectEqualStrings("XYZ789==", ver.?);
}

test "extractVerFromPresence: no caps element" {
    const xml = "<priority>5</priority><show>away</show>";
    try std.testing.expect(extractVerFromPresence(xml) == null);
}

test "parseFeaturesFromXml: recognizes +notify features" {
    const xml = "<feature var='urn:xmpp:avatar:metadata+notify'/><feature var='urn:xmpp:bookmarks:1#notify'/>";
    const features = parseFeaturesFromXml(xml);
    try std.testing.expectEqual(@as(u64, 0x03), features);
}

test "parseFeaturesFromXml: no +notify features" {
    const xml = "<feature var='http://jabber.org/protocol/disco#info'/>";
    const features = parseFeaturesFromXml(xml);
    try std.testing.expectEqual(@as(u64, 0), features);
}
