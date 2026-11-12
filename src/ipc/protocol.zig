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
const net = @import("net_frame");

/// The IPC transport: all peers read and write frames through lib/net
/// (ADR-8). FrameReader drains to EAGAIN with a distinct EOF and reports
/// an oversize header as a protocol error (T328, T329); FrameWriter owns
/// the bounded send backlog (T257).
pub const FrameReader = net.FrameReader;
pub const FrameWriter = net.FrameWriter;
pub const Frame = net.Frame;
pub const RecvResult = net.RecvResult;
pub const WriteResult = net.WriteResult;
pub const parseFrame = net.parseFrame;

/// Legacy boundary check for callers not yet on FrameReader; an
/// oversized header collapses to null here while parseFrame/next()
/// report it as Oversize. Removed when every peer is on FrameReader.
pub fn readFrame(buf: []const u8) ?Frame {
    return parseFrame(buf) catch null;
}

comptime {
    // The codec below and lib/net framing share one wire contract; a
    // drift between the two constants is a compile error, not a bug.
    std.debug.assert(net.HEADER_SIZE == HEADER_SIZE);
    std.debug.assert(net.MAX_PAYLOAD_SIZE == MAX_PAYLOAD_SIZE);
}

/// Maximum IPC message payload size (64KB).
pub const MAX_PAYLOAD_SIZE: u32 = 65536;

/// Frame header size (4-byte LE length).
pub const HEADER_SIZE: usize = 4;

/// Largest possible wire frame (header + max payload).
pub const MAX_FRAME_SIZE: usize = MAX_PAYLOAD_SIZE + HEADER_SIZE;

/// Message tags for the IPC protocol.
pub const Tag = enum(u8) {
    // Auth IPC (0x01–0x05)
    auth_request = 0x01,
    auth_challenge = 0x02,
    auth_success = 0x03,
    auth_failure = 0x04,
    sasl_response = 0x05,

    // Auth management IPC (0x06–0x0B)
    register_request = 0x06,
    register_result = 0x07,
    password_change_request = 0x08,
    password_change_result = 0x09,
    account_delete_request = 0x0A,
    account_delete_result = 0x0B,

    // Mechanism handshake (0x0C)
    mechanism_list = 0x0C,

    // Auth lifecycle (0x0D)
    /// Core→Auth: the connection died mid-exchange; drop any state.
    auth_abort = 0x0D,

    // S2S IPC (0x10–0x12)
    s2s_deliver = 0x10,
    s2s_inbound = 0x11,
    s2s_delivery_failed = 0x12,
};

/// SASL mechanism identifier byte.
pub const MechanismId = enum(u8) {
    plain = 0x01,
    scram_sha_256 = 0x02,
    oauthbearer = 0x03,

    pub fn fromName(name: []const u8) ?MechanismId {
        if (std.mem.eql(u8, name, "PLAIN")) return .plain;
        if (std.mem.eql(u8, name, "SCRAM-SHA-256")) return .scram_sha_256;
        if (std.mem.eql(u8, name, "OAUTHBEARER")) return .oauthbearer;
        return null;
    }

    pub fn toName(self: MechanismId) []const u8 {
        return switch (self) {
            .plain => "PLAIN",
            .scram_sha_256 => "SCRAM-SHA-256",
            .oauthbearer => "OAUTHBEARER",
        };
    }
};

/// IPC message — tagged union of all message types.
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

    /// Core→Auth: in-band registration request (pre-auth).
    register_request: RegisterRequest,
    /// Auth→Core: registration result.
    register_result: RegisterResult,
    /// Core→Auth: request password change for authenticated user.
    password_change_request: PasswordChangeRequest,
    /// Auth→Core: password change result.
    password_change_result: PasswordChangeResult,
    /// Core→Auth: request account deletion.
    account_delete_request: AccountDeleteRequest,
    /// Auth→Core: account deletion result.
    account_delete_result: AccountDeleteResult,

    /// Auth→Core: supported SASL mechanisms (sent once on IPC connect).
    mechanism_list: MechanismList,
    /// Core→Auth: connection died mid-exchange — drop its SCRAM slot now.
    /// Without it, connections that vanish before a final response leaked
    /// daemon state and their conn_id aliases poisoned the NEXT session on
    /// the recycled slot (T32 load-driver finding).
    auth_abort: AuthAbort,

    /// Core→S2S: deliver a stanza to a remote domain.
    s2s_deliver: S2sDeliver,
    /// S2S→Core: inbound stanza from a remote domain for a local user.
    s2s_inbound: S2sInbound,
    /// S2S→Core: stanza delivery to remote domain failed.
    s2s_delivery_failed: S2sDeliveryFailed,
};

pub const AuthRequest = struct {
    /// Connection ID for correlation.
    conn_id: u32,
    /// SASL mechanism.
    mechanism: MechanismId,
    /// Client IP address string (from accept()).
    client_ip: []const u8,
    /// Channel binding type: 0=none, 1=tls-server-end-point, 2=tls-exporter.
    cb_type: u8,
    /// Channel binding data (empty when cb_type=0).
    cb_data: []const u8,
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
    /// OIDC profile photo URL (from `picture` claim). Empty for non-OIDC auth.
    photo_url: []const u8 = "",
};

pub const AuthFailure = struct {
    conn_id: u32,
    reason: []const u8,
};

pub const SaslResponse = struct {
    conn_id: u32,
    payload: []const u8,
};

pub const AuthAbort = struct {
    conn_id: u32,
};

// ============================================================================
// Auth management IPC message types
// ============================================================================

pub const PasswordChangeRequest = struct {
    /// Connection ID for correlation.
    conn_id: u32,
    /// Username whose password is being changed.
    username: []const u8,
    /// New password (plaintext — will be hashed by auth daemon).
    new_password: []const u8,
};

pub const PasswordChangeResult = struct {
    /// Connection ID for correlation.
    conn_id: u32,
    /// Whether the operation succeeded.
    success: bool,
    /// Reason string (empty on success, error description on failure).
    reason: []const u8,
};

pub const AccountDeleteRequest = struct {
    /// Connection ID for correlation.
    conn_id: u32,
    /// Username of the account to delete.
    username: []const u8,
};

pub const AccountDeleteResult = struct {
    /// Connection ID for correlation.
    conn_id: u32,
    /// Whether the operation succeeded.
    success: bool,
    /// Reason string (empty on success, error description on failure).
    reason: []const u8,
};

pub const RegisterRequest = struct {
    /// Connection ID for correlation.
    conn_id: u32,
    /// Requested username.
    username: []const u8,
    /// Password (plaintext — will be hashed by auth daemon).
    password: []const u8,
    /// Invitation code (empty if not required).
    invite_code: []const u8,
    /// Client IP address (for rate limiting).
    client_ip: []const u8,
};

pub const RegisterResult = struct {
    /// Connection ID for correlation.
    conn_id: u32,
    /// Whether the registration succeeded.
    success: bool,
    /// Reason string (empty on success, error description on failure).
    reason: []const u8,
};

// ============================================================================
// Mechanism handshake IPC message type
// ============================================================================

pub const MechanismList = struct {
    /// Number of mechanisms.
    count: u8,
    /// Mechanism IDs (up to 8).
    mechanisms: [8]MechanismId,

    pub fn init(mechs: []const MechanismId) MechanismList {
        var ml = MechanismList{
            .count = @intCast(@min(mechs.len, 8)),
            .mechanisms = undefined,
        };
        for (mechs[0..ml.count], 0..ml.count) |m, i| {
            ml.mechanisms[i] = m;
        }
        return ml;
    }

    pub fn slice(self: *const MechanismList) []const MechanismId {
        return self.mechanisms[0..self.count];
    }

    // Wire shape: count(1B) + count ids; the untyped tail is not sent.
    pub fn ipcEncodedLen(self: *const MechanismList) usize {
        return 1 + self.count;
    }

    pub fn ipcEncode(self: *const MechanismList, buf: []u8, pos: usize) EncodeError!usize {
        var p = pos;
        if (p + 1 + self.count > buf.len) return error.BufferTooSmall;
        buf[p] = self.count;
        p += 1;
        for (self.mechanisms[0..self.count]) |m| {
            buf[p] = @intFromEnum(m);
            p += 1;
        }
        return p;
    }

    pub fn ipcDecode(data: []const u8, pos: *usize) DecodeError!MechanismList {
        if (pos.* + 1 > data.len) return error.MessageTooShort;
        const count = data[pos.*];
        pos.* += 1;
        if (count > 8) return error.InvalidEnum;
        if (pos.* + count > data.len) return error.MessageTooShort;
        var ml = MechanismList{ .count = count, .mechanisms = undefined };
        for (0..count) |i| {
            ml.mechanisms[i] = std.meta.intToEnum(MechanismId, data[pos.* + i]) catch return error.InvalidEnum;
        }
        pos.* += count;
        return ml;
    }
};

// ============================================================================
// S2S IPC message types
// ============================================================================

pub const S2sDeliver = struct {
    /// Sender's full JID (local@domain/resource).
    from_jid: []const u8,
    /// Recipient's JID (local@domain or local@domain/resource).
    to_jid: []const u8,
    /// Full serialized stanza XML (opaque bytes — core serializes, s2s forwards verbatim).
    stanza_xml: []const u8,
};

pub const S2sInbound = struct {
    /// Sender's full JID on the remote server.
    from_jid: []const u8,
    /// Recipient's JID on this server.
    to_jid: []const u8,
    /// Full serialized stanza XML.
    stanza_xml: []const u8,
};

pub const S2sDeliveryFailed = struct {
    /// Original sender's JID.
    from_jid: []const u8,
    /// Intended recipient's JID.
    to_jid: []const u8,
    /// Error type (e.g., "remote-server-not-found", "remote-server-timeout").
    error_type: []const u8,
};

// ============================================================================
// Serialization — codec generated from the Message union
// ============================================================================

// Every variant's payload is a struct encoded field by field in
// declaration order:
//
//   u8, bool, enum(u8)   -> 1 byte (bool: 0/1, enum: tag value)
//   u32                  -> 4 bytes little-endian
//   []const u8           -> u16 little-endian length + bytes
//   custom               -> the type's ipcEncodedLen/ipcEncode/ipcDecode
//
// The wire format is unchanged from the hand-written codec: identical
// tags, field order and encodings, including the optional trailing
// photo_url on auth_success (a struct field with a default decodes as
// absent when the wire runs out; everything else must consume the
// payload exactly or it is TrailingBytes).

pub const EncodeError = error{
    /// The output slice cannot hold the frame/payload.
    BufferTooSmall,
    /// A []const u8 field exceeds the u16 wire length.
    FieldTooLong,
    /// The assembled payload exceeds MAX_PAYLOAD_SIZE.
    PayloadTooLarge,
};

pub const DecodeError = error{
    /// Fewer bytes than a field (or the tag) needs.
    MessageTooShort,
    /// Tag byte does not name a Message variant.
    UnknownTag,
    /// A u8 does not map onto its enum (MechanismId, mechanism count>8).
    InvalidEnum,
    /// Bytes remain after the last field of the message.
    TrailingBytes,
};

/// Payload size in bytes (tag + fields, without the 4-byte header).
pub fn payloadLen(msg: Message) usize {
    return switch (msg) {
        inline else => |p| 1 + payloadEncodedLen(@TypeOf(p), p),
    };
}

/// Total frame size in bytes (header + payload); equal to encode()'s
/// return value for the same message.
pub fn encodedLen(msg: Message) usize {
    return HEADER_SIZE + payloadLen(msg);
}

/// Encode msg's payload (tag + fields) into buf. Returns bytes written.
/// For the FrameWriter path: begin(encodedLen - HEADER_SIZE), encode the
/// payload into scratch[HEADER_SIZE..], commit the return value.
pub fn encodePayload(msg: Message, buf: []u8) EncodeError!usize {
    var pos: usize = 0;
    switch (msg) {
        inline else => |p, tag| {
            const tag_byte: u8 = @intFromEnum(@field(Tag, @tagName(tag)));
            if (pos + 1 > buf.len) return error.BufferTooSmall;
            buf[pos] = tag_byte;
            pos += 1;
            pos = try encodeStruct(@TypeOf(p), p, buf, pos);
        },
    }
    if (pos > MAX_PAYLOAD_SIZE) return error.PayloadTooLarge;
    return pos;
}

/// Serialize a Message into a length-prefixed wire frame.
/// Returns the total bytes written (header + payload).
pub fn encode(msg: Message, buf: []u8) EncodeError!usize {
    if (buf.len < HEADER_SIZE) return error.BufferTooSmall;
    const payload_len = try encodePayload(msg, buf[HEADER_SIZE..]);
    std.mem.writeInt(u32, buf[0..HEADER_SIZE], @intCast(payload_len), .little);
    return HEADER_SIZE + payload_len;
}

/// Deserialize a payload (after the length-prefix header has been
/// stripped) into a Message. The returned message borrows slices from
/// `payload`; do not free payload while using the message.
pub fn decode(payload: []const u8) DecodeError!Message {
    if (payload.len < 1) return error.MessageTooShort;
    const tag_byte = payload[0];
    const data = payload[1..];

    inline for (@typeInfo(Message).@"union".fields) |uf| {
        if (tag_byte == @intFromEnum(@field(Tag, uf.name))) {
            var pos: usize = 0;
            const value = try decodeStruct(uf.type, data, &pos);
            if (pos != data.len) return error.TrailingBytes;
            return @unionInit(Message, uf.name, value);
        }
    }
    return error.UnknownTag;
}

// ============================================================================
// Generated field codecs
// ============================================================================

fn payloadEncodedLen(comptime T: type, p: T) usize {
    if (T == []const u8) return 2 + p.len;
    if (@hasDecl(T, "ipcEncodedLen")) return p.ipcEncodedLen();
    var n: usize = 0;
    inline for (@typeInfo(T).@"struct".fields) |f| {
        n += fieldEncodedLen(f.type, @field(p, f.name));
    }
    return n;
}

fn fieldEncodedLen(comptime T: type, v: T) usize {
    if (T == []const u8) return 2 + v.len;
    return switch (T) {
        u8, bool => 1,
        u32 => 4,
        else => switch (@typeInfo(T)) {
            .@"enum" => |e| if (e.tag_type == u8) 1 else @compileError("unsupported IPC enum " ++ @typeName(T)),
            else => @compileError("unsupported IPC field type " ++ @typeName(T)),
        },
    };
}

fn encodeStruct(comptime T: type, p: T, buf: []u8, pos0: usize) EncodeError!usize {
    if (@hasDecl(T, "ipcEncode")) return p.ipcEncode(buf, pos0);
    var pos = pos0;
    inline for (@typeInfo(T).@"struct".fields) |f| {
        pos = try encodeField(f.type, buf, pos, @field(p, f.name));
    }
    return pos;
}

fn encodeField(comptime T: type, buf: []u8, pos0: usize, v: T) EncodeError!usize {
    var pos = pos0;
    if (T == []const u8) {
        const field_len: u16 = std.math.cast(u16, v.len) orelse return error.FieldTooLong;
        if (pos + 2 + v.len > buf.len) return error.BufferTooSmall;
        std.mem.writeInt(u16, buf[pos..][0..2], field_len, .little);
        pos += 2;
        @memcpy(buf[pos .. pos + v.len], v);
        pos += v.len;
        return pos;
    }
    switch (T) {
        u8 => {
            if (pos + 1 > buf.len) return error.BufferTooSmall;
            buf[pos] = v;
            return pos + 1;
        },
        bool => {
            if (pos + 1 > buf.len) return error.BufferTooSmall;
            buf[pos] = @intFromBool(v);
            return pos + 1;
        },
        u32 => {
            if (pos + 4 > buf.len) return error.BufferTooSmall;
            std.mem.writeInt(u32, buf[pos..][0..4], v, .little);
            return pos + 4;
        },
        else => switch (@typeInfo(T)) {
            .@"enum" => |e| {
                if (e.tag_type != u8) @compileError("unsupported IPC enum " ++ @typeName(T));
                if (pos + 1 > buf.len) return error.BufferTooSmall;
                buf[pos] = @intFromEnum(v);
                return pos + 1;
            },
            else => @compileError("unsupported IPC field type " ++ @typeName(T)),
        },
    }
}

fn decodeStruct(comptime T: type, data: []const u8, pos: *usize) DecodeError!T {
    if (@hasDecl(T, "ipcDecode")) return T.ipcDecode(data, pos);
    var out: T = undefined;
    inline for (@typeInfo(T).@"struct".fields) |f| {
        if (pos.* >= data.len and f.defaultValue() != null) {
            // Trailing defaulted field absent from the wire (the
            // auth_success photo_url a pre-photo_url peer never sends).
            @field(out, f.name) = f.defaultValue().?;
        } else {
            @field(out, f.name) = try decodeField(f.type, data, pos);
        }
    }
    return out;
}

fn decodeField(comptime T: type, data: []const u8, pos: *usize) DecodeError!T {
    if (T == []const u8) {
        if (pos.* + 2 > data.len) return error.MessageTooShort;
        const field_len = std.mem.readInt(u16, data[pos.*..][0..2], .little);
        pos.* += 2;
        if (pos.* + field_len > data.len) return error.MessageTooShort;
        const v = data[pos.* .. pos.* + field_len];
        pos.* += field_len;
        return v;
    }
    switch (T) {
        u8 => {
            if (pos.* + 1 > data.len) return error.MessageTooShort;
            const v = data[pos.*];
            pos.* += 1;
            return v;
        },
        bool => {
            if (pos.* + 1 > data.len) return error.MessageTooShort;
            const v = data[pos.*] != 0;
            pos.* += 1;
            return v;
        },
        u32 => {
            if (pos.* + 4 > data.len) return error.MessageTooShort;
            const v = std.mem.readInt(u32, data[pos.*..][0..4], .little);
            pos.* += 4;
            return v;
        },
        else => switch (@typeInfo(T)) {
            .@"enum" => |e| {
                if (e.tag_type != u8) @compileError("unsupported IPC enum " ++ @typeName(T));
                if (pos.* + 1 > data.len) return error.MessageTooShort;
                const v = std.meta.intToEnum(T, data[pos.*]) catch return error.InvalidEnum;
                pos.* += 1;
                return v;
            },
            else => @compileError("unsupported IPC field type " ++ @typeName(T)),
        },
    }
}

// ============================================================================
// Tests
// ============================================================================

test "AuthRequest encode/decode roundtrip" {
    var buf: [1024]u8 = undefined;

    const msg = Message{ .auth_request = .{
        .conn_id = 42,
        .mechanism = .scram_sha_256,
        .client_ip = "192.168.1.100",
        .cb_type = 0,
        .cb_data = "",
        .username = "alice",
        .payload = "n,,n=alice,r=rOprNGfwEbeRWgbNEkqO",
    } };

    const written = try encode(msg, &buf);
    const frame = readFrame(buf[0..written]) orelse return error.NoFrame;

    const decoded = try decode(frame.payload);
    const req = decoded.auth_request;
    try std.testing.expectEqual(@as(u32, 42), req.conn_id);
    try std.testing.expectEqual(MechanismId.scram_sha_256, req.mechanism);
    try std.testing.expectEqualStrings("192.168.1.100", req.client_ip);
    try std.testing.expectEqual(@as(u8, 0), req.cb_type);
    try std.testing.expectEqualStrings("", req.cb_data);
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

test "AuthAbort encode/decode roundtrip" {
    var buf: [64]u8 = undefined;

    const written = try encode(.{ .auth_abort = .{ .conn_id = 0xABCD1234 } }, &buf);
    const frame = readFrame(buf[0..written]) orelse return error.NoFrame;
    const decoded = try decode(frame.payload);
    try std.testing.expectEqual(@as(u32, 0xABCD1234), decoded.auth_abort.conn_id);
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
        .client_ip = "",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = "",
    } };

    const written = try encode(msg, &buf);
    const frame = readFrame(buf[0..written]) orelse return error.NoFrame;
    const decoded = try decode(frame.payload);
    const req = decoded.auth_request;
    try std.testing.expectEqual(@as(u32, 0), req.conn_id);
    try std.testing.expectEqual(MechanismId.plain, req.mechanism);
    try std.testing.expectEqualStrings("", req.client_ip);
    try std.testing.expectEqual(@as(u8, 0), req.cb_type);
    try std.testing.expectEqualStrings("", req.cb_data);
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

fn sampleField(comptime T: type) T {
    if (T == []const u8) return "sample";
    if (T == bool) return true;
    if (T == u8) return 0x42;
    if (T == u32) return 0xDEADBEEF;
    return switch (@typeInfo(T)) {
        .@"enum" => @enumFromInt(1),
        else => @compileError("no sample for " ++ @typeName(T)),
    };
}

fn samplePayload(comptime T: type) T {
    if (T == MechanismList) return MechanismList.init(&.{ .plain, .scram_sha_256 });
    var p: T = undefined;
    inline for (@typeInfo(T).@"struct".fields) |f| {
        @field(p, f.name) = sampleField(f.type);
    }
    return p;
}

test "codec: every Message variant round-trips by offset" {
    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    var buf2: [MAX_FRAME_SIZE]u8 = undefined;
    inline for (@typeInfo(Message).@"union".fields) |uf| {
        const msg = @unionInit(Message, uf.name, samplePayload(uf.type));
        const n = try encode(msg, &buf);
        try std.testing.expectEqual(encodedLen(msg), n);
        const fr = (try parseFrame(buf[0..n])).?;
        try std.testing.expectEqual(n, fr.consumed);
        const back = try decode(fr.payload);
        // decode then encode must be the identity on the wire bytes.
        const n2 = try encode(back, &buf2);
        try std.testing.expectEqualSlices(u8, buf[0..n], buf2[0..n2]);
    }
}

test "decode rejects trailing bytes" {
    var buf: [64]u8 = undefined;
    const n = try encode(Message{ .auth_abort = .{ .conn_id = 7 } }, &buf);
    buf[n] = 0xAA; // one stray byte past the payload
    try std.testing.expectError(error.TrailingBytes, decode(buf[HEADER_SIZE .. n + 1]));
}

test "parseFrame reports oversize headers" {
    var buf: [HEADER_SIZE]u8 = undefined;
    std.mem.writeInt(u32, &buf, MAX_PAYLOAD_SIZE + 1, .little);
    try std.testing.expectError(error.Oversize, parseFrame(&buf));
    try std.testing.expect(readFrame(&buf) == null);
}

test "auth_success without photo_url decodes with default" {
    // A pre-photo_url peer sends tag + conn_id + username + server_final
    // only; the defaulted field decodes as absent.
    var payload: [256]u8 = undefined;
    var pos: usize = 0;
    payload[pos] = @intFromEnum(Tag.auth_success);
    pos += 1;
    std.mem.writeInt(u32, payload[pos..][0..4], 9, .little);
    pos += 4;
    inline for ([_][]const u8{ "user", "sf" }) |f| {
        std.mem.writeInt(u16, payload[pos..][0..2], @intCast(f.len), .little);
        pos += 2;
        @memcpy(payload[pos .. pos + f.len], f);
        pos += f.len;
    }
    const msg = try decode(payload[0..pos]);
    switch (msg) {
        .auth_success => |p| {
            try std.testing.expectEqual(@as(u32, 9), p.conn_id);
            try std.testing.expectEqualStrings("user", p.username);
            try std.testing.expectEqualStrings("sf", p.server_final);
            try std.testing.expectEqualStrings("", p.photo_url);
        },
        else => return error.WrongVariant,
    }
}

test "encode rejects overlong field and oversized payload" {
    var small: [8]u8 = undefined;
    // BufferTooSmall: frame does not fit.
    try std.testing.expectError(error.BufferTooSmall, encode(
        Message{ .sasl_response = .{ .conn_id = 1, .payload = "x" } },
        &small,
    ));
    const alloc = std.testing.allocator;
    const data = try alloc.alloc(u8, 81000);
    defer alloc.free(data);
    const out = try alloc.alloc(u8, 81000);
    defer alloc.free(out);
    // FieldTooLong: a []const u8 field past the u16 wire length.
    @memset(data[0..66000], 'a');
    try std.testing.expectError(error.FieldTooLong, encode(
        Message{ .sasl_response = .{ .conn_id = 1, .payload = data[0..66000] } },
        out,
    ));
    // PayloadTooLarge: fields individually under u16 but sum over 64 KiB.
    @memset(data, 'b');
    try std.testing.expectError(error.PayloadTooLarge, encode(
        Message{ .auth_request = .{
            .conn_id = 1,
            .mechanism = .plain,
            .client_ip = "ip",
            .cb_type = 0,
            .cb_data = data[0..40000],
            .username = "u",
            .payload = data[40000..80000],
        } },
        out,
    ));
}

test "max-size payload round-trips" {
    const alloc = std.testing.allocator;
    const data = try alloc.alloc(u8, MAX_PAYLOAD_SIZE);
    defer alloc.free(data);
    const buf = try alloc.alloc(u8, MAX_FRAME_SIZE);
    defer alloc.free(buf);
    @memset(data, 'z');
    const msg = Message{ .sasl_response = .{ .conn_id = 1, .payload = data[0 .. MAX_PAYLOAD_SIZE - 1 - 4 - 2] } };
    const n = try encode(msg, buf);
    try std.testing.expectEqual(MAX_FRAME_SIZE, n);
    const fr = (try parseFrame(buf[0..n])).?;
    const back = try decode(fr.payload);
    try std.testing.expectEqualStrings(data[0 .. MAX_PAYLOAD_SIZE - 7], back.sasl_response.payload);
}

test "MechanismId fromName/toName roundtrip" {
    try std.testing.expectEqual(MechanismId.plain, MechanismId.fromName("PLAIN").?);
    try std.testing.expectEqual(MechanismId.scram_sha_256, MechanismId.fromName("SCRAM-SHA-256").?);
    try std.testing.expectEqual(MechanismId.oauthbearer, MechanismId.fromName("OAUTHBEARER").?);
    try std.testing.expect(MechanismId.fromName("BOGUS") == null);
    try std.testing.expectEqualStrings("PLAIN", MechanismId.plain.toName());
    try std.testing.expectEqualStrings("SCRAM-SHA-256", MechanismId.scram_sha_256.toName());
    try std.testing.expectEqualStrings("OAUTHBEARER", MechanismId.oauthbearer.toName());
}

test "S2sDeliver encode/decode roundtrip" {
    var buf: [4096]u8 = undefined;

    const stanza = "<message from='alice@a.example/res' to='bob@b.example' id='msg1'><body>hello</body></message>";
    const msg = Message{ .s2s_deliver = .{
        .from_jid = "alice@a.example/res",
        .to_jid = "bob@b.example",
        .stanza_xml = stanza,
    } };

    const written = try encode(msg, &buf);
    const frame = readFrame(buf[0..written]) orelse return error.NoFrame;
    const decoded = try decode(frame.payload);
    const d = decoded.s2s_deliver;
    try std.testing.expectEqualStrings("alice@a.example/res", d.from_jid);
    try std.testing.expectEqualStrings("bob@b.example", d.to_jid);
    try std.testing.expectEqualStrings(stanza, d.stanza_xml);
}

test "S2sInbound encode/decode roundtrip" {
    var buf: [4096]u8 = undefined;

    const stanza = "<message from='carol@remote.example' to='dave@local.example'><body>hi</body></message>";
    const msg = Message{ .s2s_inbound = .{
        .from_jid = "carol@remote.example",
        .to_jid = "dave@local.example",
        .stanza_xml = stanza,
    } };

    const written = try encode(msg, &buf);
    const frame = readFrame(buf[0..written]) orelse return error.NoFrame;
    const decoded = try decode(frame.payload);
    const d = decoded.s2s_inbound;
    try std.testing.expectEqualStrings("carol@remote.example", d.from_jid);
    try std.testing.expectEqualStrings("dave@local.example", d.to_jid);
    try std.testing.expectEqualStrings(stanza, d.stanza_xml);
}

test "S2sDeliveryFailed encode/decode roundtrip" {
    var buf: [1024]u8 = undefined;

    const msg = Message{ .s2s_delivery_failed = .{
        .from_jid = "alice@a.example/res",
        .to_jid = "bob@b.example",
        .error_type = "remote-server-not-found",
    } };

    const written = try encode(msg, &buf);
    const frame = readFrame(buf[0..written]) orelse return error.NoFrame;
    const decoded = try decode(frame.payload);
    const d = decoded.s2s_delivery_failed;
    try std.testing.expectEqualStrings("alice@a.example/res", d.from_jid);
    try std.testing.expectEqualStrings("bob@b.example", d.to_jid);
    try std.testing.expectEqualStrings("remote-server-not-found", d.error_type);
}

test "MechanismList encode/decode roundtrip" {
    var buf: [1024]u8 = undefined;

    const mechs = [_]MechanismId{ .oauthbearer, .plain };
    const ml = MechanismList.init(&mechs);
    const msg = Message{ .mechanism_list = ml };

    const written = try encode(msg, &buf);
    const frame = readFrame(buf[0..written]) orelse return error.NoFrame;
    const decoded = try decode(frame.payload);
    const decoded_ml = decoded.mechanism_list;
    try std.testing.expectEqual(@as(u8, 2), decoded_ml.count);
    try std.testing.expectEqual(MechanismId.oauthbearer, decoded_ml.mechanisms[0]);
    try std.testing.expectEqual(MechanismId.plain, decoded_ml.mechanisms[1]);
}

test "MechanismList init and slice" {
    const mechs = [_]MechanismId{ .plain, .scram_sha_256 };
    const ml = MechanismList.init(&mechs);
    try std.testing.expectEqual(@as(u8, 2), ml.count);
    const s = ml.slice();
    try std.testing.expectEqual(@as(usize, 2), s.len);
    try std.testing.expectEqual(MechanismId.plain, s[0]);
    try std.testing.expectEqual(MechanismId.scram_sha_256, s[1]);
}

test "lib/net FrameWriter hosts encode() in place" {
    const frame_mod = @import("net_frame");
    var w: frame_mod.FrameWriter = .{};
    defer w.deinit(std.testing.allocator);

    // The whole-frame encoder writes header + payload into the scratch
    // begin() reserved; commitEncoded takes the return value as the
    // frame total. The backlog must equal a plain encode, byte for
    // byte, and parse back as exactly one frame.
    const msg = Message{ .auth_failure = .{ .conn_id = 7, .reason = "denied" } };
    const scratch = try w.begin(std.testing.allocator, MAX_PAYLOAD_SIZE, 1 << 20);
    const total = try encode(msg, scratch);
    w.commitEncoded(total);
    try std.testing.expectEqual(total, w.buf.items.len);

    var ref: [1024]u8 = undefined;
    const n = try encode(msg, &ref);
    try std.testing.expectEqualSlices(u8, ref[0..n], w.buf.items);

    const frame = readFrame(w.buf.items) orelse return error.NoFrame;
    try std.testing.expectEqual(w.buf.items.len, frame.consumed);
    const decoded = try decode(frame.payload);
    try std.testing.expectEqual(@as(u32, 7), decoded.auth_failure.conn_id);
}
