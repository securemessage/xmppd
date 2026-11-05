//! FrameReader and FrameWriter: IPC length-prefixed frames (ADR-8, F3).
//!
//! Wire-compatible with src/ipc/protocol.zig: a u32 little-endian payload
//! length, then payload_len bytes, payload_len <= MAX_PAYLOAD_SIZE. Both
//! sides are fd-agnostic and expect a non-blocking fd: the reader drains
//! to EAGAIN with a distinct EOF and parses by offset with compaction
//! once per recv; the writer encodes in place into a bounded backlog and
//! drains to EAGAIN.

const std = @import("std");
const posix = std.posix;

pub const HEADER_SIZE: usize = 4;
/// Wire value of src/ipc/protocol.zig's MAX_PAYLOAD_SIZE; A2 keeps them in
/// sync when the codec moves.
pub const MAX_PAYLOAD_SIZE: u32 = 65536;
pub const MAX_FRAME_SIZE: usize = MAX_PAYLOAD_SIZE + HEADER_SIZE;

/// One complete frame carved out of the reader's buffer.
/// `payload` borrows the buffer: process or copy it before the next
/// `next`/`recv`/`consume` call. `consumed` is the byte count to hand to
/// `consume` once the frame is processed.
pub const Frame = struct { payload: []const u8, consumed: usize };

pub const RecvResult = enum {
    /// At least one byte was moved into the buffer.
    data,
    /// EAGAIN before any byte moved: the caller re-arms read interest.
    would_block,
    /// The buffer cannot take more until the caller consumes.
    full,
    /// Orderly peer shutdown (read returned 0); no more data will come.
    eof,
};

pub const NextError = error{
    /// Header's payload_len exceeds MAX_PAYLOAD_SIZE: a protocol error,
    /// never a skip.
    Oversize,
};

pub const WriteResult = enum {
    /// The whole backlog reached the kernel.
    drained,
    /// EAGAIN before the backlog emptied: the caller re-arms write
    /// interest and drains again on the next writable event.
    would_block,
};

pub const BeginError = std.mem.Allocator.Error || error{
    /// The frame plus the existing backlog exceeds the caller's cap.
    BacklogFull,
    /// The requested payload scratch exceeds MAX_PAYLOAD_SIZE.
    Oversize,
};

/// Reads frames from one fd into a caller-owned buffer.
///
/// `consumed` is the deferred-compaction cursor: bytes below it were
/// handed out and finished; `recv` folds them away once per call, never
/// per frame.
pub const FrameReader = struct {
    buf: []u8,
    len: usize = 0,
    consumed: usize = 0,
    eof: bool = false,

    pub fn init(buf: []u8) FrameReader {
        return .{ .buf = buf };
    }

    /// Move unconsumed bytes to the front and clear the cursor.
    pub fn compact(r: *FrameReader) void {
        if (r.consumed == 0) return;
        const remaining = r.len - r.consumed;
        if (remaining > 0) {
            std.mem.copyForwards(u8, r.buf[0..remaining], r.buf[r.consumed..r.len]);
        }
        r.len = remaining;
        r.consumed = 0;
    }

    /// Read until EAGAIN, buffer full, or EOF. Compacts the consumed
    /// prefix once before reading. `r.eof` latches: once set, `recv`
    /// reports `.eof` without another syscall.
    pub fn recv(r: *FrameReader, fd: posix.fd_t) posix.ReadError!RecvResult {
        if (r.eof) return .eof;
        r.compact();
        var moved: bool = false;
        while (true) {
            const space = r.buf.len - r.len;
            if (space == 0) return if (moved) .data else .full;
            const n = posix.read(fd, r.buf[r.len..r.buf.len]) catch |err| {
                return switch (err) {
                    error.WouldBlock => if (moved) .data else .would_block,
                    else => err,
                };
            };
            if (n == 0) {
                r.eof = true;
                return if (moved) .data else .eof;
            }
            r.len += n;
            moved = true;
        }
    }

    /// Carve the next complete frame out of the buffer, or null when the
    /// buffered bytes do not hold one. Parses by offset; the returned
    /// payload borrows `buf`.
    pub fn next(r: *const FrameReader) NextError!?Frame {
        const avail = r.buf[r.consumed..r.len];
        if (avail.len < HEADER_SIZE) return null;
        const payload_len = std.mem.readInt(u32, avail[0..HEADER_SIZE], .little);
        if (payload_len > MAX_PAYLOAD_SIZE) return NextError.Oversize;
        const total = HEADER_SIZE + payload_len;
        if (avail.len < total) return null;
        return .{
            .payload = avail[HEADER_SIZE..total],
            .consumed = total,
        };
    }

    /// Mark `n` buffered bytes processed (pass `frame.consumed`).
    pub fn consume(r: *FrameReader, n: usize) void {
        std.debug.assert(r.consumed + n <= r.len);
        r.consumed += n;
    }
};

/// Buffers frames for one fd as a bounded, growable backlog.
/// `[0..start)` was sent, `[start..buf.items.len)` is unsent.
pub const FrameWriter = struct {
    buf: std.ArrayList(u8) = .empty,
    start: usize = 0,

    pub fn deinit(w: *FrameWriter, alloc: std.mem.Allocator) void {
        w.buf.deinit(alloc);
    }

    /// Fold the sent prefix away before appending, same shape as
    /// IpcConn.queueSend.
    fn reclaim(w: *FrameWriter) void {
        const unsent = w.buf.items.len - w.start;
        if (w.start >= unsent or w.start >= 4096) {
            std.mem.copyForwards(u8, w.buf.items, w.buf.items[w.start..]);
            w.buf.items.len = unsent;
            w.start = 0;
        }
    }

    /// Reserve scratch for one frame and return its payload region:
    /// `scratch[0..max_payload]` starts after the header slot. Encode
    /// into it (protocol.encode), then `commit` the real length.
    /// `backlog_cap` bounds total unsent bytes (e.g. CLIENT_SEND_CAP).
    pub fn begin(w: *FrameWriter, alloc: std.mem.Allocator, max_payload: usize, backlog_cap: usize) BeginError![]u8 {
        if (max_payload > MAX_PAYLOAD_SIZE) return BeginError.Oversize;
        w.reclaim();
        const unsent = w.buf.items.len - w.start;
        if (unsent + HEADER_SIZE + max_payload > backlog_cap) return BeginError.BacklogFull;
        try w.buf.ensureUnusedCapacity(alloc, HEADER_SIZE + max_payload);
        const scratch = w.buf.items.ptr + w.buf.items.len + HEADER_SIZE;
        return scratch[0..max_payload];
    }

    /// Patch the LE length into the reserved header and queue the frame.
    pub fn commit(w: *FrameWriter, payload_len: usize) void {
        std.debug.assert(payload_len <= MAX_PAYLOAD_SIZE);
        const scratch = w.buf.unusedCapacitySlice();
        std.debug.assert(scratch.len >= HEADER_SIZE + payload_len);
        std.mem.writeInt(u32, scratch[0..HEADER_SIZE], @intCast(payload_len), .little);
        w.buf.items.len += HEADER_SIZE + payload_len;
    }

    /// Write the backlog until it empties or the fd says EAGAIN. On a
    /// fully drained backlog the buffer resets so a busy conn returns to
    /// zero live bytes without a copy.
    pub fn drain(w: *FrameWriter, fd: posix.fd_t) posix.WriteError!WriteResult {
        while (w.start < w.buf.items.len) {
            const n = posix.write(fd, w.buf.items[w.start..]) catch |err| {
                return switch (err) {
                    error.WouldBlock => .would_block,
                    else => err,
                };
            };
            if (n == 0) return .would_block;
            w.start += n;
        }
        w.buf.clearRetainingCapacity();
        w.start = 0;
        return .drained;
    }

    /// Unsent bytes currently in the backlog.
    pub fn pending(w: *const FrameWriter) usize {
        return w.buf.items.len - w.start;
    }
};

const o_nonblock: c_int = 0x4; // O_NONBLOCK

fn setNonBlocking(fd: posix.fd_t) !void {
    const fl = std.c.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
    if (fl < 0) return error.Unexpected;
    if (fl & o_nonblock == 0) {
        if (std.c.fcntl(fd, posix.F.SETFL, fl | o_nonblock) != 0) return error.Unexpected;
    }
}

fn socketpair() ![2]posix.fd_t {
    var pair: [2]std.c.fd_t = undefined;
    const flags = posix.SOCK.STREAM | posix.SOCK.CLOEXEC;
    if (std.c.socketpair(posix.AF.UNIX, flags, 0, &pair) != 0) return error.Unexpected;
    try setNonBlocking(pair[0]);
    try setNonBlocking(pair[1]);
    return pair;
}

test "Frame: roundtrip through a socketpair" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var w: FrameWriter = .{};
    defer w.deinit(std.testing.allocator);
    const scratch = try w.begin(std.testing.allocator, 64, 4096);
    const payload = "hello frame";
    @memcpy(scratch[0..payload.len], payload);
    w.commit(payload.len);
    try std.testing.expectEqual(.drained, try w.drain(pair[0]));

    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    var r = FrameReader.init(&buf);
    try std.testing.expectEqual(.data, try r.recv(pair[1]));
    const f = (try r.next()).?;
    try std.testing.expectEqualStrings(payload, f.payload);
    r.consume(f.consumed);
    try std.testing.expectEqual(@as(?Frame, null), try r.next());
}

test "Frame: split header and split payload assemble by offset" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    const payload = "0123456789";
    var frame_bytes: [HEADER_SIZE + 16]u8 = undefined;
    std.mem.writeInt(u32, frame_bytes[0..4], payload.len, .little);
    @memcpy(frame_bytes[4 .. 4 + payload.len], payload);

    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    var r = FrameReader.init(&buf);

    _ = try posix.write(pair[0], frame_bytes[0..2]);
    try std.testing.expectEqual(.data, try r.recv(pair[1]));
    try std.testing.expectEqual(@as(?Frame, null), try r.next());

    _ = try posix.write(pair[0], frame_bytes[2 .. 4 + 4]);
    try std.testing.expectEqual(.data, try r.recv(pair[1]));
    try std.testing.expectEqual(@as(?Frame, null), try r.next());

    _ = try posix.write(pair[0], frame_bytes[8 .. 4 + payload.len]);
    try std.testing.expectEqual(.data, try r.recv(pair[1]));
    const f = (try r.next()).?;
    try std.testing.expectEqualStrings(payload, f.payload);
    r.consume(f.consumed);
}

test "Frame: coalesced frames parse one at a time" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var w: FrameWriter = .{};
    defer w.deinit(std.testing.allocator);
    for ([_][]const u8{ "one", "two", "three" }) |p| {
        const scratch = try w.begin(std.testing.allocator, 64, 4096);
        @memcpy(scratch[0..p.len], p);
        w.commit(p.len);
    }
    try std.testing.expectEqual(.drained, try w.drain(pair[0]));

    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    var r = FrameReader.init(&buf);
    _ = try r.recv(pair[1]);
    for ([_][]const u8{ "one", "two", "three" }) |p| {
        const f = (try r.next()).?;
        try std.testing.expectEqualStrings(p, f.payload);
        r.consume(f.consumed);
    }
    try std.testing.expectEqual(@as(?Frame, null), try r.next());
}

test "Frame: oversize header is a protocol error" {
    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    var r = FrameReader.init(&buf);
    std.mem.writeInt(u32, buf[0..4], MAX_PAYLOAD_SIZE + 1, .little);
    r.len = HEADER_SIZE + 4;
    try std.testing.expectError(NextError.Oversize, r.next());
}

test "Frame: recv distinguishes would_block, eof, and data" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    var r = FrameReader.init(&buf);
    try std.testing.expectEqual(.would_block, try r.recv(pair[1]));

    _ = try posix.write(pair[0], "x");
    try std.testing.expectEqual(.data, try r.recv(pair[1]));

    posix.shutdown(pair[0], .both) catch {};
    // First call may see the buffered byte plus EOF; the next must report eof.
    _ = try r.recv(pair[1]);
    try std.testing.expectEqual(.eof, try r.recv(pair[1]));
}

test "Frame: recv reports full on an unconsumed buffer" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var buf: [8]u8 = undefined;
    var r = FrameReader.init(&buf);
    _ = try posix.write(pair[0], "0123456789abcdef");
    try std.testing.expectEqual(.data, try r.recv(pair[1]));
    try std.testing.expectEqual(8, r.len);
    try std.testing.expectEqual(.full, try r.recv(pair[1]));
}

test "Frame: writer backlog grows past EAGAIN and drains after" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    // Shrink the send side; FreeBSD clamps SO_SNDBUF, so the backlog is
    // sized well past any clamp.
    const one_k: c_int = 1024;
    try posix.setsockopt(pair[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&one_k));

    var w: FrameWriter = .{};
    defer w.deinit(std.testing.allocator);
    const payload_len: usize = 64 << 10;
    const scratch = try w.begin(std.testing.allocator, payload_len, 1 << 20);
    @memset(scratch[0..payload_len], 0x5a);
    w.commit(payload_len);
    try std.testing.expectEqual(.would_block, try w.drain(pair[0]));
    try std.testing.expect(w.pending() > 0);

    const sink = try std.testing.allocator.alloc(u8, HEADER_SIZE + payload_len);
    defer std.testing.allocator.free(sink);
    var got: usize = 0;
    while (got < sink.len) {
        const n = posix.read(pair[1], sink[got..]) catch |err| switch (err) {
            error.WouldBlock => {
                _ = try w.drain(pair[0]);
                continue;
            },
            else => return err,
        };
        if (n == 0) break;
        got += n;
        _ = try w.drain(pair[0]);
    }
    try std.testing.expectEqual(.drained, try w.drain(pair[0]));
    try std.testing.expectEqual(HEADER_SIZE + payload_len, got);
}

test "Frame: begin/commit produce wire-identical bytes" {
    var w: FrameWriter = .{};
    defer w.deinit(std.testing.allocator);
    const payload = "wire bytes";
    const scratch = try w.begin(std.testing.allocator, payload.len, 4096);
    @memcpy(scratch[0..payload.len], payload);
    w.commit(payload.len);

    var expected: [HEADER_SIZE + 16]u8 = undefined;
    std.mem.writeInt(u32, expected[0..4], @intCast(payload.len), .little);
    @memcpy(expected[4 .. 4 + payload.len], payload);
    try std.testing.expectEqualSlices(u8, expected[0 .. HEADER_SIZE + payload.len], w.buf.items);
}

test "Frame: begin refuses past the backlog cap" {
    var w: FrameWriter = .{};
    defer w.deinit(std.testing.allocator);
    _ = try w.begin(std.testing.allocator, 16, 64);
    w.commit(0);
    try std.testing.expectError(BeginError.BacklogFull, w.begin(std.testing.allocator, 64, 64));
}
