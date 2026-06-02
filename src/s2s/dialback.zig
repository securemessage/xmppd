//! # XEP-0220 Server Dialback — Fallback S2S authentication
//!
//! Dialback is a legacy S2S authentication mechanism used when DANE/TLSA
//! records are unavailable. It verifies that the initiating server actually
//! controls the domain it claims by performing a reverse DNS-based callback.
//!
//! ## Protocol Flow (initiating a.example → receiving b.example)
//!
//! ```
//! 1. a→b: <db:result from='a.example' to='b.example'>KEY</db:result>
//! 2. b→a: (opens NEW connection to a.example)
//!          <db:verify from='b.example' to='a.example' id='STREAM_ID'>KEY</db:verify>
//! 3. a→b: (on verify connection)
//!          <db:verify from='a.example' to='b.example' id='STREAM_ID' type='valid'/>
//! 4. b→a: (on original connection)
//!          <db:result from='b.example' to='a.example' type='valid'/>
//! ```
//!
//! ## Key Generation (RFC 3920 §8.3 + XEP-0220 §4)
//!
//! `key = HMAC-SHA256(stream_secret, target || ' ' || origin || ' ' || stream_id)`
//!
//! The stream secret is a per-instance random value generated at daemon startup.
//! It MUST NOT be disclosed and MUST change on restart.

const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// Length of the HMAC-SHA256 output in bytes.
pub const KEY_LEN = HmacSha256.mac_length; // 32

/// Length of the hex-encoded dialback key.
pub const KEY_HEX_LEN = KEY_LEN * 2; // 64

/// Length of the stream secret.
pub const SECRET_LEN: usize = 32;

/// Dialback state for an outbound connection awaiting verification.
pub const DialbackState = enum {
    /// Not using dialback (DANE verified, or not yet decided).
    inactive,
    /// We sent db:result, waiting for db:result type='valid'/'invalid'.
    awaiting_result,
    /// We received db:result from peer, need to verify (open callback).
    awaiting_verification,
    /// Verification callback sent db:verify, awaiting response.
    verifying,
    /// Dialback completed successfully.
    valid,
    /// Dialback failed.
    invalid,
};

/// Generate a random stream secret (call once at daemon startup).
pub fn generateSecret() [SECRET_LEN]u8 {
    var secret: [SECRET_LEN]u8 = undefined;
    std.crypto.random.bytes(&secret);
    return secret;
}

/// Compute a dialback key.
///
/// key = HMAC-SHA256(secret, target || ' ' || origin || ' ' || stream_id)
///
/// Returns the raw 32-byte key.
pub fn computeKey(
    secret: *const [SECRET_LEN]u8,
    target: []const u8,
    origin: []const u8,
    stream_id: []const u8,
) [KEY_LEN]u8 {
    var mac: [KEY_LEN]u8 = undefined;
    var hmac = HmacSha256.init(secret);
    hmac.update(target);
    hmac.update(" ");
    hmac.update(origin);
    hmac.update(" ");
    hmac.update(stream_id);
    hmac.final(&mac);
    return mac;
}

/// Compute a dialback key and return it as a lowercase hex string.
pub fn computeKeyHex(
    secret: *const [SECRET_LEN]u8,
    target: []const u8,
    origin: []const u8,
    stream_id: []const u8,
) [KEY_HEX_LEN]u8 {
    const raw = computeKey(secret, target, origin, stream_id);
    return hexEncode(&raw);
}

/// Verify a received dialback key against the expected value.
///
/// Returns true if the key matches.
pub fn verifyKey(
    secret: *const [SECRET_LEN]u8,
    target: []const u8,
    origin: []const u8,
    stream_id: []const u8,
    received_key_hex: []const u8,
) bool {
    if (received_key_hex.len != KEY_HEX_LEN) return false;
    const expected = computeKeyHex(secret, target, origin, stream_id);
    return std.mem.eql(u8, &expected, received_key_hex);
}

/// Build a `<db:result>` stanza (initiating server sends this).
///
/// `<db:result from='origin' to='target'>KEY_HEX</db:result>`
pub fn buildDbResult(
    buf: []u8,
    origin: []const u8,
    target: []const u8,
    key_hex: []const u8,
) ![]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    try w.writeAll("<db:result xmlns:db='jabber:server:dialback' from='");
    try w.writeAll(origin);
    try w.writeAll("' to='");
    try w.writeAll(target);
    try w.writeAll("'>");
    try w.writeAll(key_hex);
    try w.writeAll("</db:result>");
    return fbs.getWritten();
}

/// Build a `<db:result type='...'>` response (receiving server sends this after verification).
///
/// `<db:result from='target' to='origin' type='valid'/>`
pub fn buildDbResultResponse(
    buf: []u8,
    from: []const u8,
    to: []const u8,
    valid: bool,
) ![]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    try w.writeAll("<db:result xmlns:db='jabber:server:dialback' from='");
    try w.writeAll(from);
    try w.writeAll("' to='");
    try w.writeAll(to);
    try w.writeAll("' type='");
    try w.writeAll(if (valid) "valid" else "invalid");
    try w.writeAll("'/>");
    return fbs.getWritten();
}

/// Build a `<db:verify>` stanza (receiving server sends this to the authoritative server).
///
/// `<db:verify from='verifier' to='origin' id='stream_id'>KEY_HEX</db:verify>`
pub fn buildDbVerify(
    buf: []u8,
    from: []const u8,
    to: []const u8,
    stream_id: []const u8,
    key_hex: []const u8,
) ![]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    try w.writeAll("<db:verify xmlns:db='jabber:server:dialback' from='");
    try w.writeAll(from);
    try w.writeAll("' to='");
    try w.writeAll(to);
    try w.writeAll("' id='");
    try w.writeAll(stream_id);
    try w.writeAll("'>");
    try w.writeAll(key_hex);
    try w.writeAll("</db:verify>");
    return fbs.getWritten();
}

/// Build a `<db:verify type='...'>` response (authoritative server verifies and responds).
///
/// `<db:verify from='origin' to='verifier' id='stream_id' type='valid'/>`
pub fn buildDbVerifyResponse(
    buf: []u8,
    from: []const u8,
    to: []const u8,
    stream_id: []const u8,
    valid: bool,
) ![]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    try w.writeAll("<db:verify xmlns:db='jabber:server:dialback' from='");
    try w.writeAll(from);
    try w.writeAll("' to='");
    try w.writeAll(to);
    try w.writeAll("' id='");
    try w.writeAll(stream_id);
    try w.writeAll("' type='");
    try w.writeAll(if (valid) "valid" else "invalid");
    try w.writeAll("'/>");
    return fbs.getWritten();
}

/// Per-connection dialback tracker for the initiating side.
///
/// Used by OutboundConnection to track the dialback exchange.
pub const OutboundDialback = struct {
    state: DialbackState = .inactive,
    /// The key we sent in db:result.
    sent_key: [KEY_HEX_LEN]u8 = undefined,
    sent_key_valid: bool = false,

    /// Start dialback: compute key and transition to awaiting_result.
    pub fn initiate(
        self: *OutboundDialback,
        secret: *const [SECRET_LEN]u8,
        target: []const u8,
        origin: []const u8,
        stream_id: []const u8,
    ) void {
        self.sent_key = computeKeyHex(secret, target, origin, stream_id);
        self.sent_key_valid = true;
        self.state = .awaiting_result;
    }

    /// Handle db:result type='valid' or type='invalid' from the receiving server.
    pub fn handleResult(self: *OutboundDialback, valid: bool) void {
        if (self.state != .awaiting_result) return;
        self.state = if (valid) .valid else .invalid;
    }

    /// Get the hex key to include in db:result.
    pub fn getKeyHex(self: *const OutboundDialback) ?[]const u8 {
        if (!self.sent_key_valid) return null;
        return &self.sent_key;
    }

    /// Whether dialback completed successfully.
    pub fn isValid(self: *const OutboundDialback) bool {
        return self.state == .valid;
    }

    /// Whether dialback has been attempted and failed.
    pub fn isFailed(self: *const OutboundDialback) bool {
        return self.state == .invalid;
    }
};

/// Per-connection dialback tracker for the receiving side.
///
/// Used by S2sSession to track an inbound dialback exchange.
pub const InboundDialback = struct {
    state: DialbackState = .inactive,
    /// Key received in db:result from the initiating server.
    received_key_buf: [KEY_HEX_LEN]u8 = undefined,
    received_key_len: usize = 0,
    /// The stream ID of the inbound connection (needed for verification).
    stream_id_buf: [64]u8 = undefined,
    stream_id_len: usize = 0,
    /// Origin domain (from attribute of db:result).
    origin_buf: [256]u8 = undefined,
    origin_len: usize = 0,

    /// Record a received db:result from the initiating server.
    pub fn receiveResult(
        self: *InboundDialback,
        origin: []const u8,
        stream_id: []const u8,
        key_hex: []const u8,
    ) void {
        // Store the received key
        const key_copy_len = @min(key_hex.len, self.received_key_buf.len);
        @memcpy(self.received_key_buf[0..key_copy_len], key_hex[0..key_copy_len]);
        self.received_key_len = key_copy_len;

        // Store stream ID
        const sid_copy_len = @min(stream_id.len, self.stream_id_buf.len);
        @memcpy(self.stream_id_buf[0..sid_copy_len], stream_id[0..sid_copy_len]);
        self.stream_id_len = sid_copy_len;

        // Store origin domain
        const origin_copy_len = @min(origin.len, self.origin_buf.len);
        @memcpy(self.origin_buf[0..origin_copy_len], origin[0..origin_copy_len]);
        self.origin_len = origin_copy_len;

        self.state = .awaiting_verification;
    }

    /// Verify the received key locally (authoritative server path).
    ///
    /// If we ARE the authoritative server for the target domain (i.e., we
    /// generated the stream_id), we can verify the key directly.
    pub fn verifyLocally(
        self: *InboundDialback,
        secret: *const [SECRET_LEN]u8,
        local_domain: []const u8,
    ) bool {
        const key = self.getReceivedKey();
        const origin = self.getOrigin();
        const stream_id = self.getStreamId();
        if (key.len == 0 or origin.len == 0 or stream_id.len == 0) return false;
        return verifyKey(secret, local_domain, origin, stream_id, key);
    }

    /// Mark dialback as verified (after receiving db:verify type='valid' response
    /// from the authoritative server callback, or after local verification).
    pub fn setValid(self: *InboundDialback) void {
        self.state = .valid;
    }

    /// Mark dialback as failed.
    pub fn setInvalid(self: *InboundDialback) void {
        self.state = .invalid;
    }

    /// Get the received key hex.
    pub fn getReceivedKey(self: *const InboundDialback) []const u8 {
        return self.received_key_buf[0..self.received_key_len];
    }

    /// Get the stored stream ID.
    pub fn getStreamId(self: *const InboundDialback) []const u8 {
        return self.stream_id_buf[0..self.stream_id_len];
    }

    /// Get the stored origin domain.
    pub fn getOrigin(self: *const InboundDialback) []const u8 {
        return self.origin_buf[0..self.origin_len];
    }

    /// Whether dialback completed successfully.
    pub fn isValid(self: *const InboundDialback) bool {
        return self.state == .valid;
    }

    /// Whether dialback has been attempted and failed.
    pub fn isFailed(self: *const InboundDialback) bool {
        return self.state == .invalid;
    }
};

// ============================================================================
// Helpers
// ============================================================================

/// Encode raw bytes as lowercase hex.
fn hexEncode(bytes: []const u8) [KEY_HEX_LEN]u8 {
    const hex_chars = "0123456789abcdef";
    var out: [KEY_HEX_LEN]u8 = undefined;
    for (bytes, 0..) |byte, i| {
        out[i * 2] = hex_chars[byte >> 4];
        out[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return out;
}

// ============================================================================
// Tests
// ============================================================================

test "generateSecret: produces 32 random bytes" {
    const s1 = generateSecret();
    const s2 = generateSecret();
    // Two random secrets should (almost certainly) differ
    try std.testing.expect(!std.mem.eql(u8, &s1, &s2));
    try std.testing.expectEqual(@as(usize, SECRET_LEN), s1.len);
}

test "computeKey: deterministic for same inputs" {
    const secret = [_]u8{0x42} ** SECRET_LEN;
    const k1 = computeKey(&secret, "b.example", "a.example", "stream-123");
    const k2 = computeKey(&secret, "b.example", "a.example", "stream-123");
    try std.testing.expectEqualSlices(u8, &k1, &k2);
}

test "computeKey: different inputs produce different keys" {
    const secret = [_]u8{0x42} ** SECRET_LEN;
    const k1 = computeKey(&secret, "b.example", "a.example", "stream-123");
    const k2 = computeKey(&secret, "b.example", "a.example", "stream-456");
    try std.testing.expect(!std.mem.eql(u8, &k1, &k2));
}

test "computeKey: different secrets produce different keys" {
    const s1 = [_]u8{0x42} ** SECRET_LEN;
    const s2 = [_]u8{0x99} ** SECRET_LEN;
    const k1 = computeKey(&s1, "b.example", "a.example", "stream-1");
    const k2 = computeKey(&s2, "b.example", "a.example", "stream-1");
    try std.testing.expect(!std.mem.eql(u8, &k1, &k2));
}

test "computeKeyHex: returns 64 hex characters" {
    const secret = [_]u8{0xAB} ** SECRET_LEN;
    const hex = computeKeyHex(&secret, "b.example", "a.example", "sid-1");
    try std.testing.expectEqual(@as(usize, KEY_HEX_LEN), hex.len);
    // All chars should be hex
    for (hex) |ch| {
        try std.testing.expect((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f'));
    }
}

test "verifyKey: valid key passes" {
    const secret = [_]u8{0x55} ** SECRET_LEN;
    const hex = computeKeyHex(&secret, "target.example", "origin.example", "sid-abc");
    try std.testing.expect(verifyKey(&secret, "target.example", "origin.example", "sid-abc", &hex));
}

test "verifyKey: wrong key fails" {
    const secret = [_]u8{0x55} ** SECRET_LEN;
    const wrong_key = [_]u8{'a'} ** KEY_HEX_LEN;
    try std.testing.expect(!verifyKey(&secret, "target.example", "origin.example", "sid-abc", &wrong_key));
}

test "verifyKey: wrong length fails" {
    const secret = [_]u8{0x55} ** SECRET_LEN;
    try std.testing.expect(!verifyKey(&secret, "a", "b", "c", "tooshort"));
}

test "verifyKey: wrong stream_id fails" {
    const secret = [_]u8{0x55} ** SECRET_LEN;
    const hex = computeKeyHex(&secret, "target.example", "origin.example", "sid-abc");
    try std.testing.expect(!verifyKey(&secret, "target.example", "origin.example", "sid-WRONG", &hex));
}

test "buildDbResult: correct XML format" {
    var buf: [512]u8 = undefined;
    const key = [_]u8{'a'} ** KEY_HEX_LEN;
    const xml = try buildDbResult(&buf, "a.example", "b.example", &key);
    try std.testing.expect(std.mem.indexOf(u8, xml, "from='a.example'") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "to='b.example'") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "jabber:server:dialback") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "</db:result>") != null);
}

test "buildDbResultResponse: valid response" {
    var buf: [256]u8 = undefined;
    const xml = try buildDbResultResponse(&buf, "b.example", "a.example", true);
    try std.testing.expect(std.mem.indexOf(u8, xml, "type='valid'") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "from='b.example'") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "to='a.example'") != null);
}

test "buildDbResultResponse: invalid response" {
    var buf: [256]u8 = undefined;
    const xml = try buildDbResultResponse(&buf, "b.example", "a.example", false);
    try std.testing.expect(std.mem.indexOf(u8, xml, "type='invalid'") != null);
}

test "buildDbVerify: correct XML format" {
    var buf: [512]u8 = undefined;
    const key = [_]u8{'b'} ** KEY_HEX_LEN;
    const xml = try buildDbVerify(&buf, "b.example", "a.example", "sid-xyz", &key);
    try std.testing.expect(std.mem.indexOf(u8, xml, "from='b.example'") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "to='a.example'") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "id='sid-xyz'") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "</db:verify>") != null);
}

test "buildDbVerifyResponse: valid response" {
    var buf: [256]u8 = undefined;
    const xml = try buildDbVerifyResponse(&buf, "a.example", "b.example", "sid-xyz", true);
    try std.testing.expect(std.mem.indexOf(u8, xml, "type='valid'") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "id='sid-xyz'") != null);
}

test "buildDbVerifyResponse: invalid response" {
    var buf: [256]u8 = undefined;
    const xml = try buildDbVerifyResponse(&buf, "a.example", "b.example", "sid-xyz", false);
    try std.testing.expect(std.mem.indexOf(u8, xml, "type='invalid'") != null);
}

test "OutboundDialback: initiate and handle valid result" {
    const secret = [_]u8{0x77} ** SECRET_LEN;
    var db = OutboundDialback{};
    try std.testing.expectEqual(DialbackState.inactive, db.state);

    db.initiate(&secret, "b.example", "a.example", "sid-001");
    try std.testing.expectEqual(DialbackState.awaiting_result, db.state);
    try std.testing.expect(db.sent_key_valid);
    try std.testing.expect(db.getKeyHex() != null);

    db.handleResult(true);
    try std.testing.expect(db.isValid());
    try std.testing.expect(!db.isFailed());
}

test "OutboundDialback: initiate and handle invalid result" {
    const secret = [_]u8{0x77} ** SECRET_LEN;
    var db = OutboundDialback{};

    db.initiate(&secret, "b.example", "a.example", "sid-002");
    db.handleResult(false);
    try std.testing.expect(db.isFailed());
    try std.testing.expect(!db.isValid());
}

test "OutboundDialback: handleResult ignored if inactive" {
    var db = OutboundDialback{};
    db.handleResult(true);
    try std.testing.expectEqual(DialbackState.inactive, db.state);
}

test "InboundDialback: receive result and verify locally" {
    const secret = [_]u8{0x88} ** SECRET_LEN;

    // Simulate: a.example connects to us (b.example), sends db:result
    // We (b.example) need to verify the key
    const key_hex = computeKeyHex(&secret, "b.example", "a.example", "our-stream-id");

    var db = InboundDialback{};
    try std.testing.expectEqual(DialbackState.inactive, db.state);

    db.receiveResult("a.example", "our-stream-id", &key_hex);
    try std.testing.expectEqual(DialbackState.awaiting_verification, db.state);
    try std.testing.expectEqualStrings("a.example", db.getOrigin());
    try std.testing.expectEqualStrings("our-stream-id", db.getStreamId());
    try std.testing.expectEqualStrings(&key_hex, db.getReceivedKey());

    // Verify locally (we are the authoritative server for b.example)
    const valid = db.verifyLocally(&secret, "b.example");
    try std.testing.expect(valid);

    db.setValid();
    try std.testing.expect(db.isValid());
}

test "InboundDialback: verify locally with wrong secret fails" {
    const secret = [_]u8{0x88} ** SECRET_LEN;
    const wrong_secret = [_]u8{0x99} ** SECRET_LEN;

    const key_hex = computeKeyHex(&secret, "b.example", "a.example", "sid-x");

    var db = InboundDialback{};
    db.receiveResult("a.example", "sid-x", &key_hex);

    // Use wrong secret to verify — should fail
    const valid = db.verifyLocally(&wrong_secret, "b.example");
    try std.testing.expect(!valid);

    db.setInvalid();
    try std.testing.expect(db.isFailed());
}

test "InboundDialback: verify locally with wrong stream_id fails" {
    const secret = [_]u8{0x88} ** SECRET_LEN;

    const key_hex = computeKeyHex(&secret, "b.example", "a.example", "correct-sid");

    var db = InboundDialback{};
    // Receive with different stream_id than what was used to generate the key
    db.receiveResult("a.example", "wrong-sid", &key_hex);

    const valid = db.verifyLocally(&secret, "b.example");
    try std.testing.expect(!valid);
}

test "full dialback round-trip: initiating + receiving" {
    const secret = [_]u8{0xCC} ** SECRET_LEN;
    const stream_id = "s2s-42-1717344000";

    // Initiating side (a.example → b.example)
    var outbound = OutboundDialback{};
    outbound.initiate(&secret, "b.example", "a.example", stream_id);
    const key_hex = outbound.getKeyHex().?;

    // Receiving side (b.example) receives the db:result
    var inbound = InboundDialback{};
    inbound.receiveResult("a.example", stream_id, key_hex);

    // Receiving side verifies (it knows the secret because it generated the stream_id)
    const valid = inbound.verifyLocally(&secret, "b.example");
    try std.testing.expect(valid);
    inbound.setValid();

    // Receiving side sends db:result type='valid' → initiating side handles it
    outbound.handleResult(true);

    try std.testing.expect(outbound.isValid());
    try std.testing.expect(inbound.isValid());
}

test "hexEncode: known value" {
    const input = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF } ++ [_]u8{0} ** 28;
    const hex = hexEncode(&input);
    try std.testing.expect(std.mem.startsWith(u8, &hex, "deadbeef"));
}
