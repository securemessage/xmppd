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
const Sha1 = std.crypto.hash.Sha1;

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

/// Extract the `node` attribute value from a `<c ... node='...'/>` element in presence XML.
/// Returns the node string slice within the input, or null if not found.
pub fn extractNodeFromPresence(inner_xml: []const u8) ?[]const u8 {
    const caps_ns = "http://jabber.org/protocol/caps";
    const c_pos = std.mem.indexOf(u8, inner_xml, caps_ns) orelse return null;

    const search_start = if (c_pos > 200) c_pos - 200 else 0;
    const search_end = @min(inner_xml.len, c_pos + 200);
    const region = inner_xml[search_start..search_end];

    // Find node=' or node="
    const node_prefix = "node='";
    const node_prefix_dq = "node=\"";
    var node_start: usize = 0;
    var quote_char: u8 = '\'';

    if (std.mem.indexOf(u8, region, node_prefix)) |pos| {
        node_start = search_start + pos + node_prefix.len;
        quote_char = '\'';
    } else if (std.mem.indexOf(u8, region, node_prefix_dq)) |pos| {
        node_start = search_start + pos + node_prefix_dq.len;
        quote_char = '"';
    } else {
        return null;
    }

    const node_end = std.mem.indexOfScalarPos(u8, inner_xml, node_start, quote_char) orelse return null;
    if (node_end - node_start > 256) return null;
    return inner_xml[node_start..node_end];
}

/// Build a disco#info query IQ stanza for caps verification (XEP-0115 §5.3).
/// Writes `<iq type='get' from='server' to='jid' id='caps-N'><query xmlns='disco#info' node='node#ver'/></iq>`
/// into the provided buffer. Returns the written slice, or null if buffer too small.
pub fn buildCapsQuery(
    buf: []u8,
    server_host: []const u8,
    to_jid: []const u8,
    node: []const u8,
    ver: []const u8,
    query_id: u32,
) ?[]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    w.writeAll("<iq type='get' from='") catch return null;
    w.writeAll(server_host) catch return null;
    w.writeAll("' to='") catch return null;
    w.writeAll(to_jid) catch return null;
    w.writeAll("' id='caps-") catch return null;
    // Write query_id as decimal
    var id_buf: [10]u8 = undefined;
    const id_str = std.fmt.bufPrint(&id_buf, "{d}", .{query_id}) catch return null;
    w.writeAll(id_str) catch return null;
    w.writeAll("'><query xmlns='http://jabber.org/protocol/disco#info' node='") catch return null;
    w.writeAll(node) catch return null;
    w.writeByte('#') catch return null;
    w.writeAll(ver) catch return null;
    w.writeAll("'/></iq>") catch return null;
    return fbs.getWritten();
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
// XEP-0115 §5: Server Caps Verification String
// ============================================================================

/// The server's caps node URI (used in the `node` attribute of `<c>`).
pub const SERVER_NODE: []const u8 = "https://securemessage.cc/xmppd";

/// Maximum length of a base64-encoded SHA-1 hash (28 chars).
const MAX_CAPS_HASH_LEN: usize = 28;

/// Pre-computed server caps verification string (base64-encoded SHA-1).
/// Computed once at startup from the server's disco#info features.
pub const ServerCaps = struct {
    ver_hash: [MAX_CAPS_HASH_LEN]u8 = undefined,
    ver_len: u8 = 0,
    caps_xml: [256]u8 = undefined,
    caps_xml_len: u8 = 0,

    pub fn getVer(self: *const ServerCaps) []const u8 {
        return self.ver_hash[0..self.ver_len];
    }

    pub fn getCapsXml(self: *const ServerCaps) []const u8 {
        return self.caps_xml[0..self.caps_xml_len];
    }
};

/// Server disco#info features — must match exactly what iq_handler returns.
/// Sorted alphabetically per XEP-0115 §5.1 step 3.
const SERVER_FEATURES = [_][]const u8{
    "http://jabber.org/protocol/caps",
    "http://jabber.org/protocol/chatstates",
    "http://jabber.org/protocol/disco#info",
    "http://jabber.org/protocol/disco#items",
    "http://jabber.org/protocol/pubsub#auto-create",
    "http://jabber.org/protocol/pubsub#auto-subscribe",
    "http://jabber.org/protocol/pubsub#persistent-items",
    "http://jabber.org/protocol/pubsub#publish",
    "http://jabber.org/protocol/pubsub#retrieve-items",
    "http://jabber.org/protocol/pubsub#subscribe",
    "jabber:iq:last",
    "jabber:iq:roster",
    "jabber:iq:version",
    "msgoffline",
    "urn:xmpp:avatar:metadata+notify",
    "urn:xmpp:blocking",
    "urn:xmpp:bookmarks:1#notify",
    "urn:xmpp:carbons:2",
    "urn:xmpp:chat-markers:0",
    "urn:xmpp:csi:0",
    "urn:xmpp:hints",
    "urn:xmpp:mam:2",
    "urn:xmpp:message-correct:0",
    "urn:xmpp:ping",
    "urn:xmpp:receipts",
    "urn:xmpp:sid:0",
    "urn:xmpp:sm:3",
    "vcard-temp",
};

/// Compute the XEP-0115 §5.1 verification string for the server's disco#info.
/// Returns a ServerCaps with the base64-encoded SHA-1 hash and a pre-built
/// `<c>` XML element for injection into presence stanzas.
pub fn computeServerCaps() ServerCaps {
    var caps = ServerCaps{};

    // XEP-0115 §5.1:
    // 1. Sort identities by category/type/lang/name (server has one identity)
    // 2. For each identity: S += "category/type/lang/name<"
    // 3. Sort features alphabetically (SERVER_FEATURES is already sorted)
    // 4. For each feature: S += "feature<"
    // 5. SHA-1 hash → base64

    var hasher = Sha1.init(.{});

    // Step 2: Server identity — category=server, type=im, lang=(empty), name=xmppd
    hasher.update("server/im//xmppd<");

    // Step 4: Features (already sorted)
    for (SERVER_FEATURES) |feature| {
        hasher.update(feature);
        hasher.update("<");
    }

    const digest = hasher.finalResult();
    const encoder = std.base64.standard.Encoder;
    const enc_len = encoder.calcSize(digest.len);
    if (enc_len <= MAX_CAPS_HASH_LEN) {
        const encoded = encoder.encode(caps.ver_hash[0..enc_len], &digest);
        caps.ver_len = @intCast(encoded.len);
    }

    // Pre-build the <c> XML element
    var fbs = std.io.fixedBufferStream(&caps.caps_xml);
    const w = fbs.writer();
    w.writeAll("<c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='") catch {};
    w.writeAll(SERVER_NODE) catch {};
    w.writeAll("' ver='") catch {};
    w.writeAll(caps.getVer()) catch {};
    w.writeAll("'/>") catch {};
    caps.caps_xml_len = @intCast(fbs.pos);

    return caps;
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

test "extractNodeFromPresence: standard caps element" {
    const xml = "<c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://gajim.org' ver='ABC123=='/>";
    const node = extractNodeFromPresence(xml);
    try std.testing.expect(node != null);
    try std.testing.expectEqualStrings("http://gajim.org", node.?);
}

test "extractNodeFromPresence: double quotes" {
    const xml = "<c xmlns=\"http://jabber.org/protocol/caps\" hash=\"sha-1\" node=\"http://conversations.im\" ver=\"XYZ==\"/>";
    const node = extractNodeFromPresence(xml);
    try std.testing.expect(node != null);
    try std.testing.expectEqualStrings("http://conversations.im", node.?);
}

test "extractNodeFromPresence: no caps element" {
    const xml = "<priority>5</priority>";
    try std.testing.expect(extractNodeFromPresence(xml) == null);
}

test "buildCapsQuery: well-formed" {
    var buf: [512]u8 = undefined;
    const result = buildCapsQuery(&buf, "example.com", "alice@example.com/res", "http://gajim.org", "ABC123==", 42);
    try std.testing.expect(result != null);
    const xml = result.?;
    try std.testing.expect(std.mem.indexOf(u8, xml, "type='get'") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "from='example.com'") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "to='alice@example.com/res'") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "id='caps-42'") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "node='http://gajim.org#ABC123=='") != null);
}

test "computeServerCaps: produces valid base64 SHA-1 hash" {
    const caps = computeServerCaps();
    // SHA-1 base64 is always 28 chars
    try std.testing.expectEqual(@as(u8, 28), caps.ver_len);
    // Hash must be non-empty
    try std.testing.expect(caps.ver_len > 0);
    // Verify it's valid base64 (all chars in alphabet + padding)
    for (caps.getVer()) |ch| {
        try std.testing.expect(
            (ch >= 'A' and ch <= 'Z') or
                (ch >= 'a' and ch <= 'z') or
                (ch >= '0' and ch <= '9') or
                ch == '+' or ch == '/' or ch == '=',
        );
    }
}

test "computeServerCaps: deterministic" {
    const caps1 = computeServerCaps();
    const caps2 = computeServerCaps();
    try std.testing.expectEqualStrings(caps1.getVer(), caps2.getVer());
}

test "computeServerCaps: XML element well-formed" {
    const caps = computeServerCaps();
    const xml = caps.getCapsXml();
    try std.testing.expect(xml.len > 0);
    try std.testing.expect(std.mem.startsWith(u8, xml, "<c xmlns='http://jabber.org/protocol/caps'"));
    try std.testing.expect(std.mem.endsWith(u8, xml, "'/>"));
    try std.testing.expect(std.mem.indexOf(u8, xml, "hash='sha-1'") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, SERVER_NODE) != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, caps.getVer()) != null);
}

test "SERVER_FEATURES: sorted alphabetically" {
    var i: usize = 1;
    while (i < SERVER_FEATURES.len) : (i += 1) {
        const order = std.mem.order(u8, SERVER_FEATURES[i - 1], SERVER_FEATURES[i]);
        try std.testing.expect(order == .lt);
    }
}
