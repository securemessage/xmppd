//! # IPC Client — connects to a Unix domain socket IPC server
//!
//! Used by xmppd-core to communicate with xmppd-auth. Handles:
//! - Non-blocking connect to a Unix socket path
//! - Buffered reading with partial frame reassembly
//! - Message send/receive using the protocol framing
//!
//! ## Integration with kqueue
//!
//! The client socket fd is registered with the main event loop. When readable,
//! call `recvMessages()` to drain available data and extract complete frames.
//! The caller provides a callback or iterates the returned messages.

const std = @import("std");
const posix = std.posix;
const protocol = @import("ipc_protocol");

const log = std.log.scoped(.ipc_client);

/// IPC receive buffer: one full wire frame (T257: 32 KiB truncated a
/// 32-64 KiB s2s frame; the lane is now sized like a peer frame). Heap,
/// allocated at connect.
const RECV_BUF_SIZE = protocol.MAX_FRAME_SIZE;

/// Hard cap on unsent frames to the daemon. The send queue is heap-grown
/// up to this cap (T32 measured ~50 in-flight auth requests in bursts).
const SEND_CAP: usize = 4 << 20;

/// Error set for flush(): the writer drain plus the owner checks.
pub const FlushError = error{ NotConnected, NoAllocator } || posix.WriteError;
/// Error set for send(): flush plus the codec and the bounded writer.
/// The flush attempt is reported so a caller never sees success for a
/// frame whose write just failed.
pub const SendError = FlushError || protocol.BeginError || protocol.EncodeError;
/// Error set for recv(): the link state checks, the lazy buffer
/// allocation, plus the reader's read errors.
pub const RecvError = error{ NotConnected, NoAllocator } || std.mem.Allocator.Error || posix.ReadError;
/// Error set for nextMessage(): the frame boundary check plus the codec.
pub const NextMessageError = protocol.NextError || protocol.DecodeError;

pub const IpcClient = struct {
    /// The Unix socket file descriptor (-1 if not connected).
    fd: posix.fd_t = -1,

    /// lib/net receive side (ADR-8): the parser plus a heap buffer one
    /// full wire frame fills, allocated on connect() (or lazily by recv
    /// for test-built clients).
    reader: protocol.FrameReader = .{ .buf = &.{} },
    /// lib/net send side: messages encode in place into a bounded
    /// backlog (SEND_CAP) and drain to EAGAIN (T257).
    writer: protocol.FrameWriter = .{},
    /// Backs reader.buf and the writer backlog; set once at construction
    /// by the owner (Server).
    alloc: ?std.mem.Allocator = null,

    /// Whether the connection is established.
    connected: bool = false,

    /// Connect to an IPC server at the given Unix socket path.
    pub fn connect(self: *IpcClient, path: []const u8) !void {
        if (self.connected) return error.AlreadyConnected;

        // The wire sees whole frames; the receive buffer must hold one.
        // Allocate before the socket exists: an allocation error after
        // adopting the fd would fire the errdefer close and leave self.fd
        // naming a closed descriptor (dangling fd, double close later).
        if (self.reader.buf.len == 0) {
            const a = self.alloc orelse return error.NoAllocator;
            self.reader = protocol.FrameReader.init(try a.alloc(u8, RECV_BUF_SIZE));
        }

        const sock = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
        errdefer posix.close(sock);
        // A peer that died between our read events turns the next write
        // into SIGPIPE; suppress it per-socket so flush() can return the
        // error instead of the process dying before it lands.
        try setNoSigpipe(sock);

        // Build sockaddr_un
        var addr: std.c.sockaddr.un = std.mem.zeroes(std.c.sockaddr.un);
        addr.family = posix.AF.UNIX;
        if (path.len >= addr.path.len) return error.PathTooLong;
        @memcpy(addr.path[0..path.len], path);

        posix.connect(sock, @ptrCast(&addr), @sizeOf(std.c.sockaddr.un)) catch |err| {
            switch (err) {
                error.WouldBlock => {}, // Non-blocking connect in progress
                error.ConnectionRefused => return error.ConnectionRefused,
                else => return error.ConnectFailed,
            }
        };

        self.fd = sock;
        self.connected = true;
        self.reader = protocol.FrameReader.init(self.reader.buf);
        self.writer.buf.clearRetainingCapacity();
        self.writer.start = 0;
    }

    /// Close the IPC connection.
    pub fn close(self: *IpcClient) void {
        if (self.fd >= 0) {
            posix.close(self.fd);
            self.fd = -1;
        }
        self.connected = false;
        self.reader = protocol.FrameReader.init(self.reader.buf);
        self.writer.buf.clearRetainingCapacity();
        self.writer.start = 0;
        // Free only on deinit: reconnect reuses the owned buffer.
    }

    /// Free the writer backlog and the receive buffer (owner's lifetime
    /// ends). The connection must be closed first.
    pub fn deinit(self: *IpcClient) void {
        if (self.alloc) |a| {
            self.writer.deinit(a);
            if (self.reader.buf.len > 0) {
                a.free(self.reader.buf);
                self.reader = .{ .buf = &.{} };
            }
            self.alloc = null;
        }
    }

    /// Send a message to the auth daemon.
    /// Encodes the message into the backlog and attempts to flush.
    pub fn send(self: *IpcClient, msg: protocol.Message) SendError!void {
        if (!self.connected) return error.NotConnected;
        const alloc = self.alloc orelse return error.NoAllocator;

        // Encode in place into the backlog: no 64 KiB stack scratch on an
        // event-loop thread (T257). begin() reserves the frame behind the
        // unsent tail and refuses past SEND_CAP; nothing is queued on an
        // encode error.
        const scratch = self.writer.begin(alloc, protocol.payloadLen(msg), SEND_CAP) catch |err| {
            log.err("failed to queue a {s} frame for the wire ({}): dropping it", .{ @tagName(msg), err });
            return err;
        };
        const payload_len = protocol.encodePayload(msg, scratch[protocol.HEADER_SIZE..]) catch |err| {
            log.err("failed to encode a {s} frame for the wire ({}): dropping it", .{ @tagName(msg), err });
            return err;
        };
        self.writer.commit(payload_len);

        // Try to flush immediately; a write failure already dropped
        // `connected` inside flush(). Propagate it: the caller's catch
        // fails the exchange rather than reporting success for a frame
        // that may never reach the wire.
        _ = try self.flush();
    }

    /// Flush the send backlog to the socket until it empties or the fd
    /// says EAGAIN. A write error drops `connected`, same as EOF.
    pub fn flush(self: *IpcClient) FlushError!protocol.WriteResult {
        if (self.writer.pending() == 0) return .drained;
        if (self.fd < 0) return error.NotConnected;

        const alloc = self.alloc orelse return error.NoAllocator;
        return self.writer.drain(alloc, self.fd) catch |err| {
            self.connected = false;
            return err;
        };
    }

    /// Returns true if there is unsent data in the send buffer.
    pub fn hasPendingSend(self: *const IpcClient) bool {
        return self.writer.pending() > 0;
    }

    /// Queued-but-unsent bytes (tests).
    pub fn unsentBytes(self: *const IpcClient) []const u8 {
        return self.writer.unsentBytes();
    }

    /// Read available data from the socket into the frame buffer.
    /// Returns .data/.full/.would_block/.eof: .eof is the peer's orderly
    /// shutdown and drops `connected`; .would_block moved nothing and is
    /// NOT an error: buffered frames may still complete a message.
    pub fn recv(self: *IpcClient) RecvError!protocol.RecvResult {
        if (!self.connected) return error.NotConnected;
        if (self.fd < 0) return error.NotConnected;

        // Tests and late-alloc'd owners reach here without connect().
        if (self.reader.buf.len == 0) {
            const a = self.alloc orelse return error.NoAllocator;
            self.reader = protocol.FrameReader.init(try a.alloc(u8, RECV_BUF_SIZE));
        }

        const rr = self.reader.recv(self.fd) catch |err| {
            self.connected = false;
            return err;
        };
        if (rr == .eof) self.connected = false;
        return rr;
    }

    /// Try to extract one complete message from the receive buffer.
    /// Returns null if no complete frame is available yet.
    /// The returned Message borrows from the recv buffer — process it
    /// before calling nextMessage() or recv() again.
    pub fn nextMessage(self: *IpcClient) NextMessageError!?protocol.Message {
        const frame = try self.reader.next() orelse return null;
        const msg = try protocol.decode(frame.payload);
        // consume() only moves the cursor; the decoded slices stay valid
        // until the next recv() compacts the consumed prefix away.
        self.reader.consume(frame.consumed);
        return msg;
    }
};

// ============================================================================
// Tests
// ============================================================================

const so_nosigpipe: c_int = 0x0800; // SO_NOSIGPIPE (FreeBSD)

fn setNoSigpipe(fd: posix.fd_t) !void {
    const one: c_int = 1;
    try posix.setsockopt(fd, posix.SOL.SOCKET, so_nosigpipe, std.mem.asBytes(&one));
}

/// Create a Unix socketpair for testing. SO_NOSIGPIPE on both ends so a
/// dead-peer write surfaces EPIPE instead of killing the test process.
fn makeUnixSocketPair() ![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    errdefer posix.close(fds[0]);
    errdefer posix.close(fds[1]);
    try setNoSigpipe(fds[0]);
    try setNoSigpipe(fds[1]);
    return fds;
}

test "IpcClient: send and receive over socketpair" {
    const fds = try makeUnixSocketPair();
    defer posix.close(fds[1]);

    var client = IpcClient{};
    client.fd = fds[0];
    client.connected = true;
    client.alloc = std.testing.allocator;
    defer client.deinit();
    defer client.close();

    // Send an auth request
    try client.send(.{ .auth_request = .{
        .conn_id = 5,
        .mechanism = .scram_sha_256,
        .client_ip = "10.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "test",
        .payload = "initial-data",
    } });

    // Read from the peer side
    var peer_buf: [1024]u8 = undefined;
    const n = try posix.read(fds[1], &peer_buf);
    try std.testing.expect(n > 0);

    // Parse the frame
    const frame = (try protocol.parseFrame(peer_buf[0..n])) orelse return error.NoFrame;
    const decoded = try protocol.decode(frame.payload);
    try std.testing.expectEqual(@as(u32, 5), decoded.auth_request.conn_id);
    try std.testing.expectEqualStrings("test", decoded.auth_request.username);
}

test "IpcClient: send reports a dead peer instead of returning success" {
    const fds = try makeUnixSocketPair();
    posix.close(fds[1]); // peer is gone before the first write

    var client = IpcClient{};
    client.fd = fds[0];
    client.connected = true;
    client.alloc = std.testing.allocator;
    defer client.deinit();
    defer client.close();

    const msg = protocol.Message{ .auth_request = .{
        .conn_id = 5,
        .mechanism = .scram_sha_256,
        .client_ip = "10.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "test",
        .payload = "initial-data",
    } };
    // The write has nowhere to go: the FIRST send must surface the flush
    // failure. A swallowed error would report success here and only show
    // up as NotConnected on the next call.
    client.send(msg) catch |err| {
        try std.testing.expect(err != error.NotConnected);
        try std.testing.expect(!client.connected);
        return;
    };
    return error.SendReportedSuccessOnDeadPeer;
}

test "IpcClient: receive message from peer" {
    const fds = try makeUnixSocketPair();
    defer posix.close(fds[1]);

    var client = IpcClient{};
    client.fd = fds[0];
    client.connected = true;
    client.alloc = std.testing.allocator;
    defer client.deinit();
    defer client.close();

    // Peer sends an auth success
    var frame_buf: [1024]u8 = undefined;
    const frame_len = try protocol.encode(.{ .auth_success = .{
        .conn_id = 5,
        .username = "alice",
        .server_final = "v=abc123",
    } }, &frame_buf);
    _ = try posix.write(fds[1], frame_buf[0..frame_len]);

    // Client receives
    _ = try client.recv();
    const msg = try client.nextMessage() orelse return error.NoMessage;
    try std.testing.expectEqual(@as(u32, 5), msg.auth_success.conn_id);
    try std.testing.expectEqualStrings("alice", msg.auth_success.username);
    try std.testing.expectEqualStrings("v=abc123", msg.auth_success.server_final);
}

test "IpcClient: nextMessage returns null with partial frame" {
    const fds = try makeUnixSocketPair();
    defer posix.close(fds[1]);

    var client = IpcClient{};
    client.fd = fds[0];
    client.connected = true;
    client.alloc = std.testing.allocator;
    defer client.deinit();
    defer client.close();

    // Send only a partial frame (just the length header, no payload)
    var header: [4]u8 = undefined;
    std.mem.writeInt(u32, &header, 50, .little); // Says 50 bytes payload
    _ = try posix.write(fds[1], &header);

    _ = try client.recv();
    const msg = try client.nextMessage();
    try std.testing.expect(msg == null); // Not enough data yet
}

test "IpcClient: close resets state" {
    var client = IpcClient{};
    const fds = try makeUnixSocketPair();
    posix.close(fds[1]);

    client.fd = fds[0];
    client.connected = true;
    client.reader.len = 10;

    client.close();
    try std.testing.expect(!client.connected);
    try std.testing.expectEqual(@as(posix.fd_t, -1), client.fd);
    try std.testing.expectEqual(@as(usize, 0), client.reader.len);
}

test "IpcClient: connect failure before adoption leaves no dangling fd" {
    // A live listener lets connect() succeed; the client has no allocator
    // and no preset recv buffer, so the buffer allocation fails. The fd
    // must not be adopted before that allocation: self.fd would name a
    // descriptor the errdefer already closed, and the next close() would
    // double-close whatever reused the number.
    const path = "/tmp/xmppd-test-ipc-noalloc.sock";
    std.fs.cwd().deleteFile(path) catch {};
    defer std.fs.cwd().deleteFile(path) catch {};

    const lfd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(lfd);
    var addr: std.c.sockaddr.un = std.mem.zeroes(std.c.sockaddr.un);
    addr.family = posix.AF.UNIX;
    @memcpy(addr.path[0..path.len], path);
    try posix.bind(lfd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.un));
    try posix.listen(lfd, 4);

    var client = IpcClient{}; // alloc = null, reader.buf empty
    try std.testing.expectError(error.NoAllocator, client.connect(path));
    try std.testing.expectEqual(@as(posix.fd_t, -1), client.fd);
    try std.testing.expect(!client.connected);
}
