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

    /// True when the peer ended the stream with a partial frame
    /// buffered: eof latched and unconsumed bytes that can never
    /// complete. Check after `next` returns null; a complete frame
    /// still buffered is handed out first.
    pub fn truncated(r: *const FrameReader) bool {
        return r.eof and r.consumed < r.len;
    }
};

/// Buffers frames for one fd as a bounded, growable backlog.
/// `[0..start)` was sent, `[start..buf.items.len)` is unsent.
pub const FrameWriter = struct {
    buf: std.ArrayList(u8) = .empty,
    start: usize = 0,
    /// Backlog capacity kept once `drain` empties the writer (default
    /// 64 KiB): one burst must not pin megabytes for the conn's life.
    high_water: usize = 64 << 10,

    pub fn deinit(w: *FrameWriter, alloc: std.mem.Allocator) void {
        w.buf.deinit(alloc);
    }

    /// Fold the sent prefix away before appending, same shape as
    /// IpcConn.queueSend. Folding is O(unsent), so it runs only when it
    /// is free work (the sent prefix outweighs the backlog) or the
    /// frame cannot fit the tail space; folding on every begin after a
    /// small drain is O(backlog) per call.
    fn reclaim(w: *FrameWriter, need: usize) void {
        if (w.start == 0) return;
        const unsent = w.buf.items.len - w.start;
        if (w.start >= unsent or w.buf.capacity - w.buf.items.len < need) {
            std.mem.copyForwards(u8, w.buf.items, w.buf.items[w.start..]);
            w.buf.items.len = unsent;
            w.start = 0;
        }
    }

    /// Reserve scratch for one frame, header slot included:
    /// `scratch[0..HEADER_SIZE]` is the length slot, the payload region
    /// is `scratch[HEADER_SIZE..][0..max_payload]`. Encode the payload
    /// there and `commit` the real length, or run a whole-frame encoder
    /// that writes its own header (protocol.encode) over `scratch[0..]`
    /// and `commitEncoded` its return value.
    /// `backlog_cap` bounds total unsent bytes (e.g. CLIENT_SEND_CAP).
    pub fn begin(
        w: *FrameWriter,
        alloc: std.mem.Allocator,
        max_payload: usize,
        backlog_cap: usize,
    ) BeginError![]u8 {
        if (max_payload > MAX_PAYLOAD_SIZE) return BeginError.Oversize;
        const need = HEADER_SIZE + max_payload;
        const unsent = w.buf.items.len - w.start;
        if (unsent + need > backlog_cap) return BeginError.BacklogFull;
        w.reclaim(need);
        try w.buf.ensureUnusedCapacity(alloc, need);
        const scratch = w.buf.items.ptr + w.buf.items.len;
        return scratch[0..need];
    }

    /// Patch the LE length into the reserved header and queue the frame.
    pub fn commit(w: *FrameWriter, payload_len: usize) void {
        std.debug.assert(payload_len <= MAX_PAYLOAD_SIZE);
        const scratch = w.buf.unusedCapacitySlice();
        std.debug.assert(scratch.len >= HEADER_SIZE + payload_len);
        std.mem.writeInt(u32, scratch[0..HEADER_SIZE], @intCast(payload_len), .little);
        w.buf.items.len += HEADER_SIZE + payload_len;
    }

    /// Queue a frame whose encoder already wrote the length header into
    /// scratch[0..HEADER_SIZE] (protocol.encode returns header + payload
    /// as `total`). The embedded length must match `total - HEADER_SIZE`,
    /// so a caller cannot double-frame or truncate without tripping.
    pub fn commitEncoded(w: *FrameWriter, total: usize) void {
        std.debug.assert(total >= HEADER_SIZE and total <= MAX_FRAME_SIZE);
        const scratch = w.buf.unusedCapacitySlice();
        std.debug.assert(scratch.len >= total);
        const embedded = std.mem.readInt(u32, scratch[0..HEADER_SIZE], .little);
        std.debug.assert(embedded == total - HEADER_SIZE);
        w.buf.items.len += total;
    }

    /// Once the backlog drains empty, release capacity above the
    /// high-water mark (same shape as Outbox.releaseSpill).
    fn releaseCapacity(w: *FrameWriter, alloc: std.mem.Allocator) void {
        if (w.buf.capacity <= w.high_water) return;
        if (alloc.resize(w.buf.allocatedSlice(), w.high_water)) {
            w.buf.capacity = w.high_water;
            return;
        }
        w.buf.shrinkAndFree(alloc, 0);
        // Best-effort retention; an alloc failure re-grows next burst.
        w.buf.ensureTotalCapacityPrecise(alloc, w.high_water) catch {};
    }

    /// Write the backlog until it empties or the fd says EAGAIN. On a
    /// fully drained backlog the buffer resets so a busy conn returns to
    /// zero live bytes without a copy, and capacity above `high_water`
    /// is released.
    pub fn drain(
        w: *FrameWriter,
        alloc: std.mem.Allocator,
        fd: posix.fd_t,
    ) posix.WriteError!WriteResult {
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
        w.releaseCapacity(alloc);
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
    @memcpy(scratch[HEADER_SIZE..][0..payload.len], payload);
    w.commit(payload.len);
    try std.testing.expectEqual(.drained, try w.drain(std.testing.allocator, pair[0]));

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
        @memcpy(scratch[HEADER_SIZE..][0..p.len], p);
        w.commit(p.len);
    }
    try std.testing.expectEqual(.drained, try w.drain(std.testing.allocator, pair[0]));

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
    // The first recv after shutdown must report eof: the latch engages
    // on the EOF read itself, not one call later.
    try std.testing.expectEqual(.eof, try r.recv(pair[1]));
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
    @memset(scratch[HEADER_SIZE..][0..payload_len], 0x5a);
    w.commit(payload_len);
    try std.testing.expectEqual(.would_block, try w.drain(std.testing.allocator, pair[0]));
    try std.testing.expect(w.pending() > 0);

    const sink = try std.testing.allocator.alloc(u8, HEADER_SIZE + payload_len);
    defer std.testing.allocator.free(sink);
    var got: usize = 0;
    while (got < sink.len) {
        const n = posix.read(pair[1], sink[got..]) catch |err| switch (err) {
            error.WouldBlock => {
                _ = try w.drain(std.testing.allocator, pair[0]);
                continue;
            },
            else => return err,
        };
        if (n == 0) break;
        got += n;
        _ = try w.drain(std.testing.allocator, pair[0]);
    }
    try std.testing.expectEqual(.drained, try w.drain(std.testing.allocator, pair[0]));
    try std.testing.expectEqual(HEADER_SIZE + payload_len, got);
}

test "Frame: begin/commit produce wire-identical bytes" {
    var w: FrameWriter = .{};
    defer w.deinit(std.testing.allocator);
    const payload = "wire bytes";
    const scratch = try w.begin(std.testing.allocator, payload.len, 4096);
    @memcpy(scratch[HEADER_SIZE..][0..payload.len], payload);
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

test "Frame: commitEncoded accepts a self-encoded frame" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var w: FrameWriter = .{};
    defer w.deinit(std.testing.allocator);
    const payload = "self encoded";
    const scratch = try w.begin(std.testing.allocator, payload.len, 4096);
    // A whole-frame encoder (protocol.encode) writes its own length
    // header at scratch[0..4]; commitEncoded adopts it as one frame.
    std.mem.writeInt(u32, scratch[0..4], @intCast(payload.len), .little);
    @memcpy(scratch[HEADER_SIZE..][0..payload.len], payload);
    w.commitEncoded(HEADER_SIZE + payload.len);
    try std.testing.expectEqual(HEADER_SIZE + payload.len, w.pending());

    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    var r = FrameReader.init(&buf);
    try std.testing.expectEqual(.drained, try w.drain(std.testing.allocator, pair[0]));
    try std.testing.expectEqual(.data, try r.recv(pair[1]));
    const f = (try r.next()).?;
    try std.testing.expectEqualStrings(payload, f.payload);
}

test "Frame: begin folds the sent prefix only when needed" {
    const alloc = std.testing.allocator;
    var w: FrameWriter = .{};
    defer w.deinit(alloc);
    // 4 MiB backlog (IPC CLIENT_SEND_CAP), kernel drains 8 KiB per
    // pass; a fold on every begin moves the whole backlog each call
    // (P19 measured 753 MiB over 256 calls).
    while (w.pending() < (4 << 20) - 70000) {
        const s = try w.begin(alloc, 1000, 4 << 20);
        @memset(s[HEADER_SIZE..][0..1000], 0x11);
        w.commit(1000);
    }
    var copied: usize = 0;
    for (0..256) |_| {
        w.start += 8192;
        const before = w.pending();
        const s = try w.begin(alloc, 100, 8 << 20);
        _ = s;
        w.commit(100);
        if (w.start == 0) copied += before;
    }
    try std.testing.expect(copied <= 16 << 20);
}

test "Frame: a max-size payload parses" {
    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    var r = FrameReader.init(&buf);
    // Fill the buffer manually: payload_len == MAX_PAYLOAD_SIZE is the
    // accepted boundary, not Oversize.
    std.mem.writeInt(u32, buf[0..HEADER_SIZE], MAX_PAYLOAD_SIZE, .little);
    r.len = MAX_FRAME_SIZE;
    const f = (try r.next()).?;
    try std.testing.expectEqual(@as(usize, MAX_PAYLOAD_SIZE), f.payload.len);
    try std.testing.expectEqual(@as(usize, MAX_FRAME_SIZE), f.consumed);
}

test "Frame: recv compacts the consumed prefix before reading" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var buf: [16]u8 = undefined;
    var r = FrameReader.init(&buf);

    _ = try posix.write(pair[0], "ABCD");
    try std.testing.expectEqual(.data, try r.recv(pair[1]));
    r.consume(2);

    _ = try posix.write(pair[0], "EFGH");
    try std.testing.expectEqual(.data, try r.recv(pair[1]));
    // The consumed prefix folded away once: "CD" moved to the front.
    try std.testing.expectEqual(@as(usize, 0), r.consumed);
    try std.testing.expectEqual(@as(usize, 6), r.len);
    try std.testing.expectEqualStrings("CDEFGH", r.buf[0..r.len]);
}

test "Frame: eof mid-frame is reported by truncated()" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var buf: [MAX_FRAME_SIZE]u8 = undefined;
    var r = FrameReader.init(&buf);

    // Two bytes of a header, then EOF: the leftover can never complete.
    _ = try posix.write(pair[0], &[_]u8{ 0x05, 0x00 });
    posix.shutdown(pair[0], .both) catch {};
    try std.testing.expectEqual(.data, try r.recv(pair[1]));
    try std.testing.expectEqual(@as(?Frame, null), try r.next());
    try std.testing.expect(r.truncated());

    // Consumed leftovers are not truncated, and a clean eof is not.
    r.consume(r.len);
    try std.testing.expect(!r.truncated());
}

test "Frame: drain releases backlog capacity above the high-water mark" {
    const alloc = std.testing.allocator;
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var w: FrameWriter = .{ .high_water = 64 };
    defer w.deinit(alloc);
    const s = try w.begin(alloc, 256, 4096);
    @memset(s[HEADER_SIZE..][0..200], 0x22);
    w.commit(200);
    try std.testing.expect(w.buf.capacity > w.high_water);

    try std.testing.expectEqual(.drained, try w.drain(alloc, pair[0]));
    try std.testing.expect(w.buf.capacity <= w.high_water);
    try std.testing.expectEqual(@as(usize, 0), w.pending());
}
