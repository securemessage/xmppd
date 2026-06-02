//! # IPC Protocol — Length-prefixed binary messages over Unix sockets
//!
//! Reusable framing layer for inter-process communication between xmppd
//! components (Core↔Auth, Core↔Store, Core↔S2S).
//!
//! ## Wire format
//!
//! ```
//! ┌──────────┬──────────────────────────┐
//! │ len (4B) │ payload (len bytes)      │
//! │ LE u32   │ tag (1B) + fields        │
//! └──────────┴──────────────────────────┘
//! ```
//!
//! ## Auth IPC messages
//!
//! | Tag  | Direction  | Message        |
//! |------|------------|----------------|
//! | 0x01 | Core→Auth  | AuthRequest    |
//! | 0x02 | Auth→Core  | AuthChallenge  |
//! | 0x03 | Auth→Core  | AuthSuccess    |
//! | 0x04 | Auth→Core  | AuthFailure    |
//! | 0x05 | Core→Auth  | SaslResponse   |

const std = @import("std");
const posix = std.posix;

/// Maximum IPC message payload size (64KB).
pub const MAX_PAYLOAD_SIZE: u32 = 65536;

/// Frame header size (4-byte LE length).
pub const HEADER_SIZE: usize = 4;

/// Message tags for the auth IPC protocol.
pub const Tag = enum(u8) {
    auth_request = 0x01,
    auth_challenge = 0x02,
    auth_success = 0x03,
    auth_failure = 0x04,
    sasl_response = 0x05,
};

/// SASL mechanism identifier byte.
pub const MechanismId = enum(u8) {
    plain = 0x01,
    scram_sha_256 = 0x02,

    pub fn fromName(name: []const u8) ?MechanismId {
        if (std.mem.eql(u8, name, "PLAIN")) return .plain;
        if (std.mem.eql(u8, name, "SCRAM-SHA-256")) return .scram_sha_256;
        return null;
    }

    pub fn toName(self: MechanismId) []const u8 {
        return switch (self) {
            .plain => "PLAIN",
            .scram_sha_256 => "SCRAM-SHA-256",
        };
    }
};

/// Auth IPC message — tagged union of all message types.
pub const Message = union(enum) {
    /// Core→Auth: start authentication for a connection.
    auth_request: AuthRequest,
    /// Auth→Core: SASL challenge (SCRAM server-first-message).
    auth_challenge: AuthChallenge,
    /// Auth→Core: authentication succeeded.
    auth_success: AuthSuccess,
    /// Auth→Core: authentication failed.
    auth_failure: AuthFailure,
    /// Core→Auth: SASL response (SCRAM client-final-message).
    sasl_response: SaslResponse,
};

pub const AuthRequest = struct {
    /// Connection ID for correlation.
    conn_id: u32,
    /// SASL mechanism.
    mechanism: MechanismId,
    /// Username (from SASL initial response).
    username: []const u8,
    /// SASL payload (base64-decoded initial response).
    payload: []const u8,
};

pub const AuthChallenge = struct {
    conn_id: u32,
    challenge: []const u8,
};

pub const AuthSuccess = struct {
    conn_id: u32,
    username: []const u8,
    server_final: []const u8,
};

pub const AuthFailure = struct {
    conn_id: u32,
    reason: []const u8,
};

pub const SaslResponse = struct {
    conn_id: u32,
    payload: []const u8,
};

// ============================================================================
// Serialization
// ============================================================================

/// Serialize a Message into a length-prefixed wire frame.
/// Returns the total bytes written (header + payload).
pub fn encode(msg: Message, buf: []u8) !usize {
    if (buf.len < HEADER_SIZE + 1) return error.BufferTooSmall;

    // Reserve space for the length header; write payload starting at offset 4
    var pos: usize = HEADER_SIZE;

    switch (msg) {
        .auth_request => |req| {
            buf[pos] = @intFromEnum(Tag.auth_request);
            pos += 1;
            // conn_id (4B LE)
            std.mem.writeInt(u32, buf[pos..][0..4], req.conn_id, .little);
            pos += 4;
            // mechanism (1B)
            buf[pos] = @intFromEnum(req.mechanism);
            pos += 1;
            // username_len (2B LE) + username
            pos = try writeField(buf, pos, req.username);
            // payload_len (2B LE) + payload
            pos = try writeField(buf, pos, req.payload);
        },
        .auth_challenge => |ch| {
            buf[pos] = @intFromEnum(Tag.auth_challenge);
            pos += 1;
            std.mem.writeInt(u32, buf[pos..][0..4], ch.conn_id, .little);
            pos += 4;
            pos = try writeField(buf, pos, ch.challenge);
        },
        .auth_success => |s| {
            buf[pos] = @intFromEnum(Tag.auth_success);
            pos += 1;
            std.mem.writeInt(u32, buf[pos..][0..4], s.conn_id, .little);
            pos += 4;
            pos = try writeField(buf, pos, s.username);
            pos = try writeField(buf, pos, s.server_final);
        },
        .auth_failure => |f| {
            buf[pos] = @intFromEnum(Tag.auth_failure);
            pos += 1;
            std.mem.writeInt(u32, buf[pos..][0..4], f.conn_id, .little);
            pos += 4;
            pos = try writeField(buf, pos, f.reason);
        },
        .sasl_response => |r| {
            buf[pos] = @intFromEnum(Tag.sasl_response);
            pos += 1;
            std.mem.writeInt(u32, buf[pos..][0..4], r.conn_id, .little);
            pos += 4;
            pos = try writeField(buf, pos, r.payload);
        },
    }

    // Write the length header (payload size, excluding the 4-byte header itself)
    const payload_len: u32 = @intCast(pos - HEADER_SIZE);
    std.mem.writeInt(u32, buf[0..4], payload_len, .little);

    return pos;
}

/// Deserialize a payload (after length-prefix header has been stripped) into a Message.
/// The returned message borrows slices from `payload` — do not free payload while using the message.
pub fn decode(payload: []const u8) !Message {
    if (payload.len < 1) return error.MessageTooShort;

    const tag_byte = payload[0];
    const data = payload[1..];

    return switch (tag_byte) {
        @intFromEnum(Tag.auth_request) => blk: {
            if (data.len < 6) break :blk error.MessageTooShort; // conn_id(4) + mechanism(1) + username_len(2) min
            const conn_id = std.mem.readInt(u32, data[0..4], .little);
            const mech_byte = data[4];
            const mechanism = std.meta.intToEnum(MechanismId, mech_byte) catch return error.InvalidMechanism;
            var pos: usize = 5;
            const username = try readField(data, &pos);
            const req_payload = try readField(data, &pos);
            break :blk Message{ .auth_request = .{
                .conn_id = conn_id,
                .mechanism = mechanism,
                .username = username,
                .payload = req_payload,
            } };
        },
        @intFromEnum(Tag.auth_challenge) => blk: {
            if (data.len < 6) break :blk error.MessageTooShort;
            const conn_id = std.mem.readInt(u32, data[0..4], .little);
            var pos: usize = 4;
            const challenge = try readField(data, &pos);
            break :blk Message{ .auth_challenge = .{
                .conn_id = conn_id,
                .challenge = challenge,
            } };
        },
        @intFromEnum(Tag.auth_success) => blk: {
            if (data.len < 6) break :blk error.MessageTooShort;
            const conn_id = std.mem.readInt(u32, data[0..4], .little);
            var pos: usize = 4;
            const username = try readField(data, &pos);
            const server_final = try readField(data, &pos);
            break :blk Message{ .auth_success = .{
                .conn_id = conn_id,
                .username = username,
                .server_final = server_final,
            } };
        },
        @intFromEnum(Tag.auth_failure) => blk: {
            if (data.len < 6) break :blk error.MessageTooShort;
            const conn_id = std.mem.readInt(u32, data[0..4], .little);
            var pos: usize = 4;
            const reason = try readField(data, &pos);
            break :blk Message{ .auth_failure = .{
                .conn_id = conn_id,
                .reason = reason,
            } };
        },
        @intFromEnum(Tag.sasl_response) => blk: {
            if (data.len < 6) break :blk error.MessageTooShort;
            const conn_id = std.mem.readInt(u32, data[0..4], .little);
            var pos: usize = 4;
            const resp_payload = try readField(data, &pos);
            break :blk Message{ .sasl_response = .{
                .conn_id = conn_id,
                .payload = resp_payload,
            } };
        },
        else => error.UnknownTag,
    };
}

// ============================================================================
// Frame I/O helpers
// ============================================================================

/// Read a complete frame from a buffer that may contain partial data.
/// Returns the payload slice and the total frame size consumed, or null if
/// the buffer doesn't contain a complete frame yet.
pub fn readFrame(buf: []const u8) ?struct { payload: []const u8, consumed: usize } {
    if (buf.len < HEADER_SIZE) return null;
    const payload_len = std.mem.readInt(u32, buf[0..4], .little);
    if (payload_len > MAX_PAYLOAD_SIZE) return null; // Invalid/corrupt
    const total = HEADER_SIZE + payload_len;
    if (buf.len < total) return null;
    return .{
        .payload = buf[HEADER_SIZE..total],
        .consumed = total,
    };
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Write a length-prefixed field (2-byte LE length + data).
fn writeField(buf: []u8, start: usize, data: []const u8) !usize {
    const field_len: u16 = std.math.cast(u16, data.len) orelse return error.FieldTooLong;
    var pos = start;
    if (pos + 2 + data.len > buf.len) return error.BufferTooSmall;
    std.mem.writeInt(u16, buf[pos..][0..2], field_len, .little);
    pos += 2;
    @memcpy(buf[pos .. pos + data.len], data);
    pos += data.len;
    return pos;
}

/// Read a length-prefixed field (2-byte LE length + data). Returns a slice into `data`.
fn readField(data: []const u8, pos: *usize) ![]const u8 {
    if (pos.* + 2 > data.len) return error.MessageTooShort;
    const field_len = std.mem.readInt(u16, data[pos.*..][0..2], .little);
    pos.* += 2;
    if (pos.* + field_len > data.len) return error.MessageTooShort;
    const result = data[pos.* .. pos.* + field_len];
    pos.* += field_len;
    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "AuthRequest encode/decode roundtrip" {
    var buf: [1024]u8 = undefined;

    const msg = Message{ .auth_request = .{
        .conn_id = 42,
        .mechanism = .scram_sha_256,
        .username = "alice",
        .payload = "n,,n=alice,r=rOprNGfwEbeRWgbNEkqO",
    } };

    const written = try encode(msg, &buf);
    const frame = readFrame(buf[0..written]) orelse return error.NoFrame;

    const decoded = try decode(frame.payload);
    const req = decoded.auth_request;
    try std.testing.expectEqual(@as(u32, 42), req.conn_id);
    try std.testing.expectEqual(MechanismId.scram_sha_256, req.mechanism);
    try std.testing.expectEqualStrings("alice", req.username);
    try std.testing.expectEqualStrings("n,,n=alice,r=rOprNGfwEbeRWgbNEkqO", req.payload);
}

test "AuthChallenge encode/decode roundtrip" {
    var buf: [1024]u8 = undefined;

    const msg = Message{ .auth_challenge = .{
        .conn_id = 7,
        .challenge = "r=combined,s=salt,i=4096",
    } };

    const written = try encode(msg, &buf);
    const frame = readFrame(buf[0..written]) orelse return error.NoFrame;

    const decoded = try decode(frame.payload);
    const ch = decoded.auth_challenge;
    try std.testing.expectEqual(@as(u32, 7), ch.conn_id);
    try std.testing.expectEqualStrings("r=combined,s=salt,i=4096", ch.challenge);
}

test "AuthSuccess encode/decode roundtrip" {
    var buf: [1024]u8 = undefined;

    const msg = Message{ .auth_success = .{
        .conn_id = 99,
        .username = "bob",
        .server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=",
    } };

    const written = try encode(msg, &buf);
    const frame = readFrame(buf[0..written]) orelse return error.NoFrame;

    const decoded = try decode(frame.payload);
    const s = decoded.auth_success;
    try std.testing.expectEqual(@as(u32, 99), s.conn_id);
    try std.testing.expectEqualStrings("bob", s.username);
    try std.testing.expectEqualStrings("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=", s.server_final);
}

test "AuthFailure encode/decode roundtrip" {
    var buf: [1024]u8 = undefined;

    const msg = Message{ .auth_failure = .{
        .conn_id = 13,
        .reason = "not-authorized",
    } };

    const written = try encode(msg, &buf);
    const frame = readFrame(buf[0..written]) orelse return error.NoFrame;

    const decoded = try decode(frame.payload);
    const f = decoded.auth_failure;
    try std.testing.expectEqual(@as(u32, 13), f.conn_id);
    try std.testing.expectEqualStrings("not-authorized", f.reason);
}

test "SaslResponse encode/decode roundtrip" {
    var buf: [1024]u8 = undefined;

    const msg = Message{ .sasl_response = .{
        .conn_id = 42,
        .payload = "c=biws,r=combined,p=dHzmhGToJJFZ2v8wR0n/TN1Y0g==",
    } };

    const written = try encode(msg, &buf);
    const frame = readFrame(buf[0..written]) orelse return error.NoFrame;

    const decoded = try decode(frame.payload);
    const r = decoded.sasl_response;
    try std.testing.expectEqual(@as(u32, 42), r.conn_id);
    try std.testing.expectEqualStrings("c=biws,r=combined,p=dHzmhGToJJFZ2v8wR0n/TN1Y0g==", r.payload);
}

test "readFrame with partial data returns null" {
    // Only 2 bytes — not enough for a header
    try std.testing.expect(readFrame(&[_]u8{ 0x05, 0x00 }) == null);

    // Header says 10 bytes but only 6 total
    var buf: [6]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], 10, .little);
    buf[4] = 0x01;
    buf[5] = 0x00;
    try std.testing.expect(readFrame(&buf) == null);
}

test "readFrame with exact data succeeds" {
    var buf: [7]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], 3, .little); // 3-byte payload
    buf[4] = 0xAA;
    buf[5] = 0xBB;
    buf[6] = 0xCC;

    const frame = readFrame(&buf) orelse return error.NoFrame;
    try std.testing.expectEqual(@as(usize, 3), frame.payload.len);
    try std.testing.expectEqual(@as(usize, 7), frame.consumed);
    try std.testing.expectEqual(@as(u8, 0xAA), frame.payload[0]);
}

test "decode unknown tag returns error" {
    const result = decode(&[_]u8{0xFF});
    try std.testing.expectError(error.UnknownTag, result);
}

test "decode empty payload returns error" {
    const result = decode(&[_]u8{});
    try std.testing.expectError(error.MessageTooShort, result);
}

test "encode with empty fields" {
    var buf: [1024]u8 = undefined;

    const msg = Message{ .auth_request = .{
        .conn_id = 0,
        .mechanism = .plain,
        .username = "",
        .payload = "",
    } };

    const written = try encode(msg, &buf);
    const frame = readFrame(buf[0..written]) orelse return error.NoFrame;
    const decoded = try decode(frame.payload);
    const req = decoded.auth_request;
    try std.testing.expectEqual(@as(u32, 0), req.conn_id);
    try std.testing.expectEqual(MechanismId.plain, req.mechanism);
    try std.testing.expectEqualStrings("", req.username);
    try std.testing.expectEqualStrings("", req.payload);
}

test "multiple frames in sequence" {
    var buf: [2048]u8 = undefined;
    var offset: usize = 0;

    // Encode two messages back-to-back
    const msg1 = Message{ .auth_failure = .{ .conn_id = 1, .reason = "fail1" } };
    const msg2 = Message{ .auth_failure = .{ .conn_id = 2, .reason = "fail2" } };

    offset += try encode(msg1, buf[offset..]);
    offset += try encode(msg2, buf[offset..]);

    // Decode first
    const frame1 = readFrame(buf[0..offset]) orelse return error.NoFrame;
    const decoded1 = try decode(frame1.payload);
    try std.testing.expectEqual(@as(u32, 1), decoded1.auth_failure.conn_id);

    // Decode second
    const remaining = buf[frame1.consumed..offset];
    const frame2 = readFrame(remaining) orelse return error.NoFrame;
    const decoded2 = try decode(frame2.payload);
    try std.testing.expectEqual(@as(u32, 2), decoded2.auth_failure.conn_id);
}

test "MechanismId fromName/toName roundtrip" {
    try std.testing.expectEqual(MechanismId.plain, MechanismId.fromName("PLAIN").?);
    try std.testing.expectEqual(MechanismId.scram_sha_256, MechanismId.fromName("SCRAM-SHA-256").?);
    try std.testing.expect(MechanismId.fromName("BOGUS") == null);
    try std.testing.expectEqualStrings("PLAIN", MechanismId.plain.toName());
    try std.testing.expectEqualStrings("SCRAM-SHA-256", MechanismId.scram_sha_256.toName());
}
