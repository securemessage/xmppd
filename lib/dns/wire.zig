//! # DNS wire format — query construction + response parsing (T-16C82690)
//!
//! The blocking `res_query()` path suits the daemon's infrequent lookups but
//! is unusable on an event loop. This module builds queries and parses
//! responses directly (RFC 1035), including compressed names (0xC0 pointers),
//! so async resolvers can drive their own sockets.
//!
//! All parsing borrows from the packet slice; names are decompressed into the
//! caller-supplied arena.

const std = @import("std");

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_TLSA: u16 = 52;

pub const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_NXDOMAIN: u8 = 3;

pub const FLAG_TC: u16 = 0x0200;

/// A single resource record from the answer/authority/additional sections.
/// `name` is decompressed (arena-allocated); `rdata` borrows the packet.
pub const Rr = struct {
    name: []const u8,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdata: []const u8,
};

pub const Message = struct {
    id: u16,
    rcode: u8,
    truncated: bool,
    /// answers + additional (additional carry inline A/AAAA for SRV targets)
    rrs: []Rr,
};

/// Encode a standard query for `qname`/`qtype` (rd set) into `buf`.
/// Returns bytes written (fixed 12-byte header + question).
pub fn buildQuery(buf: []u8, id: u16, qname: []const u8, qtype: u16) !usize {
    if (buf.len < 12 + qname.len + 16) return error.BufferTooSmall;

    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();

    try w.writeInt(u16, id, .big);
    try w.writeInt(u16, 0x0100, .big); // RD
    try w.writeInt(u16, 1, .big); // QDCOUNT
    try w.writeInt(u16, 0, .big); // ANCOUNT
    try w.writeInt(u16, 0, .big); // NSCOUNT
    try w.writeInt(u16, 0, .big); // ARCOUNT

    var it = std.mem.splitScalar(u8, qname, '.');
    while (it.next()) |label| {
        if (label.len == 0) return error.InvalidName;
        if (label.len > 63) return error.InvalidName;
        try w.writeByte(@intCast(label.len));
        try w.writeAll(label);
    }
    try w.writeByte(0);
    try w.writeInt(u16, qtype, .big);
    try w.writeInt(u16, CLASS_IN, .big);

    return fbs.pos;
}

/// Decompress a possibly pointer-compressed name. Walks labels; pointer
/// (0xC0) jumps are followed WITHOUT advancing the outer cursor.
/// Names exceeding 255 bytes decoded are rejected.
pub fn decompressName(msg: []const u8, offset: usize, alloc: std.mem.Allocator) !struct { name: []const u8, next: usize } {
    var out = std.ArrayList(u8){};
    errdefer out.deinit(alloc);

    var cursor = offset;
    var jumped = false;
    var next = offset;
    var jumps: usize = 0;

    while (true) {
        if (cursor >= msg.len) return error.NameOutOfBounds;
        const len = msg[cursor];
        if (len == 0) {
            if (!jumped) next = cursor + 1;
            if (cursor + 1 <= msg.len) cursor += 1;
            break;
        }
        if (len & 0xC0 == 0xC0) {
            if (cursor + 1 >= msg.len) return error.NameOutOfBounds;
            const ptr = (@as(usize, len & 0x3F) << 8) | msg[cursor + 1];
            if (ptr >= msg.len) return error.NameOutOfBounds;
            if (!jumped) next = cursor + 2;
            cursor = ptr;
            jumped = true;
            jumps += 1;
            if (jumps > 4) return error.PointerLoop;
            continue;
        }
        if (len & 0xC0 != 0) return error.InvalidNameByte;
        cursor += 1;
        if (cursor + len > msg.len) return error.NameOutOfBounds;
        if (out.items.len > 0) try out.append(alloc, '.');
        try out.appendSlice(alloc, msg[cursor .. cursor + len]);
        cursor += len;
        if (out.items.len > 255) return error.InvalidName;
    }

    return .{ .name = try out.toOwnedSlice(alloc), .next = if (jumped) next else cursor };
}

/// Parse a response message. Skips the question section by name-walking.
/// Returns all RRs (answer + authority + additional) decompressed into `alloc`
/// (use an arena and free the whole thing at once).
pub fn parse(alloc: std.mem.Allocator, msg: []const u8) !Message {
    if (msg.len < 12) return error.Truncated;

    const id = std.mem.readInt(u16, msg[0..2], .big);
    const flags = std.mem.readInt(u16, msg[2..4], .big);
    const qdcount = std.mem.readInt(u16, msg[4..6], .big);
    const ancount = std.mem.readInt(u16, msg[6..8], .big);
    const nscount = std.mem.readInt(u16, msg[8..10], .big);
    const arcount = std.mem.readInt(u16, msg[10..12], .big);

    var cursor: usize = 12;

    // Skip questions: name (possibly terminated by pointer), QTYPE, QCLASS.
    var q: usize = 0;
    while (q < qdcount) : (q += 1) {
        cursor = try skipName(msg, cursor);
        cursor += 4;
        if (cursor > msg.len) return error.Truncated;
    }

    const total: usize = @as(usize, ancount) + nscount + arcount;
    var rrs = try std.ArrayList(Rr).initCapacity(alloc, @min(total, 16));

    var i: usize = 0;
    while (i < total) : (i += 1) {
        const nm = try decompressName(msg, cursor, alloc);
        cursor = nm.next;
        if (cursor + 10 > msg.len) return error.Truncated;
        const rtype = std.mem.readInt(u16, msg[cursor..][0..2], .big);
        const class = std.mem.readInt(u16, msg[cursor..][2..4], .big);
        const ttl = std.mem.readInt(u32, msg[cursor..][4..8], .big);
        const rdlen = std.mem.readInt(u16, msg[cursor..][8..10], .big);
        cursor += 10;
        if (cursor + rdlen > msg.len) return error.Truncated;
        rrs.append(alloc, .{
            .name = nm.name,
            .rtype = rtype,
            .class = class,
            .ttl = ttl,
            .rdata = msg[cursor .. cursor + rdlen],
        }) catch return error.OutOfMemory;
        cursor += rdlen;
    }

    return .{
        .id = id,
        .rcode = @intCast(flags & 0xF),
        .truncated = flags & FLAG_TC != 0,
        .rrs = rrs.items,
    };
}

/// Skip one wire-format name starting at `offset` without decompressing.
/// Handles compression pointers (jump target is followed only to find the
/// end of THIS reference).
fn skipName(msg: []const u8, offset: usize) !usize {
    var cursor = offset;
    while (true) {
        if (cursor >= msg.len) return error.Truncated;
        const len = msg[cursor];
        if (len == 0) return cursor + 1;
        if (len & 0xC0 == 0xC0) return cursor + 2;
        cursor += 1 + @as(usize, len);
    }
}

// --- Tests ---

test "buildQuery encodes a question" {
    var buf: [256]u8 = undefined;
    const n = try buildQuery(&buf, 0x1234, "_xmpp-client._tcp.example.com", TYPE_SRV);
    const pkt = buf[0..n];

    try std.testing.expectEqual(@as(u16, 0x1234), std.mem.readInt(u16, pkt[0..2], .big));
    try std.testing.expectEqual(@as(u16, 0x0100), std.mem.readInt(u16, pkt[2..4], .big));
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, pkt[4..6], .big));
    // Question tail: qtype SRV + class IN
    try std.testing.expectEqual(TYPE_SRV, std.mem.readInt(u16, pkt[pkt.len - 4 ..][0..2], .big));
    try std.testing.expectEqual(CLASS_IN, std.mem.readInt(u16, pkt[pkt.len - 2 ..][0..2], .big));
}

test "decompressName handles plain labels and pointer compression" {
    // ...question at 12; "www"+pointer-to-"example.com" pattern.
    // Packet: header(12) + name[3"www" ptr(12+veristandoff)] — craft:
    // [12]: 7 "example" 3 "com" 0   -> example.com ends at 23
    // [23+]: 3 "www" 0xC0,0x0C       -> www.example.com
    var msg: [64]u8 = [_]u8{0} ** 64;
    @memcpy(msg[12 .. 12 + 8], [_]u8{7} ++ "example");
    @memcpy(msg[20..24], [_]u8{3} ++ "com");
    msg[24] = 0;
    const off2 = 25;
    @memcpy(msg[off2..][0..4], [_]u8{3} ++ "www");
    msg[off2 + 4] = 0xC0;
    msg[off2 + 5] = 12;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const d1 = try decompressName(&msg, 12, arena.allocator());
    try std.testing.expectEqualStrings("example.com", d1.name);
    try std.testing.expectEqual(@as(usize, 25), d1.next);

    const d2 = try decompressName(&msg, off2, arena.allocator());
    try std.testing.expectEqualStrings("www.example.com", d2.name);
    try std.testing.expectEqual(@as(usize, off2 + 6), d2.next);
}

test "parse: one A answer round-trips" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Header: id=0xBEEF, QR|RD|RA, qd=1, an=1
    var msg: [128]u8 = [_]u8{0} ** 128;
    std.mem.writeInt(u16, msg[0..2], 0xBEEF, .big);
    std.mem.writeInt(u16, msg[2..4], 0x8180, .big);
    std.mem.writeInt(u16, msg[4..6], 1, .big);
    std.mem.writeInt(u16, msg[6..8], 1, .big);

    // Question: 4"test" 0 + qtype A + qclass IN
    var pos: usize = 12;
    msg[pos] = 4;
    @memcpy(msg[pos + 1 .. pos + 5], "test");
    pos += 5;
    msg[pos] = 0;
    pos += 1;
    std.mem.writeInt(u16, msg[pos..][0..2], TYPE_A, .big);
    std.mem.writeInt(u16, msg[pos..][2..4], CLASS_IN, .big);
    pos += 4;
    const qend = pos;

    // Answer: ptr to qname, A 127.0.0.1, ttl 60
    msg[pos] = 0xC0;
    msg[pos + 1] = 12;
    pos += 2;
    std.mem.writeInt(u16, msg[pos..][0..2], TYPE_A, .big);
    std.mem.writeInt(u16, msg[pos..][2..4], CLASS_IN, .big);
    std.mem.writeInt(u32, msg[pos..][4..8], 60, .big);
    std.mem.writeInt(u16, msg[pos..][8..10], 4, .big);
    pos += 10;
    @memcpy(msg[pos .. pos + 4], &[_]u8{ 127, 0, 0, 1 });
    pos += 4;
    _ = qend;

    const m = try parse(alloc, msg[0..pos]);
    try std.testing.expectEqual(@as(u16, 0xBEEF), m.id);
    try std.testing.expectEqual(@as(u8, RCODE_NOERROR), m.rcode);
    try std.testing.expect(!m.truncated);
    try std.testing.expectEqual(@as(usize, 1), m.rrs.len);
    try std.testing.expectEqualStrings("test", m.rrs[0].name);
    try std.testing.expectEqual(@as(u16, TYPE_A), m.rrs[0].rtype);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, m.rrs[0].rdata);
}
