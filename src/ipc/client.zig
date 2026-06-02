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

/// IPC receive buffer size — 32KB should handle many concurrent auth exchanges.
const RECV_BUF_SIZE = 32768;

/// IPC send buffer size — 16KB.
const SEND_BUF_SIZE = 16384;

pub const IpcClient = struct {
    /// The Unix socket file descriptor (-1 if not connected).
    fd: posix.fd_t = -1,

    /// Receive buffer for partial frame reassembly.
    recv_buf: [RECV_BUF_SIZE]u8 = undefined,
    recv_len: usize = 0,

    /// Send buffer.
    send_buf: [SEND_BUF_SIZE]u8 = undefined,
    send_start: usize = 0,
    send_end: usize = 0,

    /// Whether the connection is established.
    connected: bool = false,

    /// Connect to an IPC server at the given Unix socket path.
    pub fn connect(self: *IpcClient, path: []const u8) !void {
        if (self.connected) return error.AlreadyConnected;

        const sock = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
        errdefer posix.close(sock);

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
        self.recv_len = 0;
        self.send_start = 0;
        self.send_end = 0;
    }

    /// Close the IPC connection.
    pub fn close(self: *IpcClient) void {
        if (self.fd >= 0) {
            posix.close(self.fd);
            self.fd = -1;
        }
        self.connected = false;
        self.recv_len = 0;
        self.send_start = 0;
        self.send_end = 0;
    }

    /// Send a message to the auth daemon.
    /// Encodes the message into the send buffer and attempts to flush.
    pub fn send(self: *IpcClient, msg: protocol.Message) !void {
        if (!self.connected) return error.NotConnected;

        // Encode into a temporary buffer
        var frame_buf: [4096]u8 = undefined;
        const frame_len = try protocol.encode(msg, &frame_buf);

        // Append to send buffer
        const space = SEND_BUF_SIZE - self.send_end;
        if (frame_len > space) {
            self.compactSendBuf();
            const space2 = SEND_BUF_SIZE - self.send_end;
            if (frame_len > space2) return error.SendBufferFull;
        }
        @memcpy(self.send_buf[self.send_end .. self.send_end + frame_len], frame_buf[0..frame_len]);
        self.send_end += frame_len;

        // Try to flush immediately
        _ = self.flush() catch {};
    }

    /// Flush the send buffer to the socket. Returns bytes written.
    pub fn flush(self: *IpcClient) !usize {
        if (self.send_start >= self.send_end) return 0;
        if (self.fd < 0) return error.NotConnected;

        const data = self.send_buf[self.send_start..self.send_end];
        const n = posix.write(self.fd, data) catch |err| {
            return switch (err) {
                error.WouldBlock => @as(usize, 0),
                error.BrokenPipe => blk: {
                    self.connected = false;
                    break :blk error.ConnectionReset;
                },
                else => blk: {
                    self.connected = false;
                    break :blk error.ConnectionReset;
                },
            };
        };

        self.send_start += n;
        if (self.send_start == self.send_end) {
            self.send_start = 0;
            self.send_end = 0;
        }
        return n;
    }

    /// Returns true if there is unsent data in the send buffer.
    pub fn hasPendingSend(self: *const IpcClient) bool {
        return self.send_start < self.send_end;
    }

    /// Read available data from the socket and extract complete messages.
    /// Returns the number of complete messages available. Call `nextMessage()`
    /// to retrieve them.
    pub fn recv(self: *IpcClient) !usize {
        if (!self.connected) return error.NotConnected;
        if (self.fd < 0) return error.NotConnected;

        // Read into recv_buf
        const space = RECV_BUF_SIZE - self.recv_len;
        if (space == 0) return error.RecvBufferFull;

        const n = posix.read(self.fd, self.recv_buf[self.recv_len .. self.recv_len + space]) catch |err| {
            return switch (err) {
                error.WouldBlock => @as(usize, 0),
                error.ConnectionResetByPeer => blk: {
                    self.connected = false;
                    break :blk error.ConnectionReset;
                },
                else => blk: {
                    self.connected = false;
                    break :blk error.ConnectionReset;
                },
            };
        };

        if (n == 0) {
            // EOF
            self.connected = false;
            return error.ConnectionClosed;
        }

        self.recv_len += n;
        return n;
    }

    /// Try to extract one complete message from the receive buffer.
    /// Returns null if no complete frame is available yet.
    /// The returned Message borrows from the recv buffer — process it
    /// before calling recv() again.
    pub fn nextMessage(self: *IpcClient) !?protocol.Message {
        const data = self.recv_buf[0..self.recv_len];
        const frame = protocol.readFrame(data) orelse return null;

        const msg = try protocol.decode(frame.payload);

        // Compact: shift remaining data to front
        const remaining = self.recv_len - frame.consumed;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.recv_buf[0..remaining], self.recv_buf[frame.consumed..self.recv_len]);
        }
        self.recv_len = remaining;

        return msg;
    }

    fn compactSendBuf(self: *IpcClient) void {
        if (self.send_start == 0) return;
        const remaining = self.send_end - self.send_start;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.send_buf[0..remaining], self.send_buf[self.send_start..self.send_end]);
        }
        self.send_end = remaining;
        self.send_start = 0;
    }
};

// ============================================================================
// Tests
// ============================================================================

/// Create a Unix socketpair for testing.
fn makeUnixSocketPair() ![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    return fds;
}

test "IpcClient: send and receive over socketpair" {
    const fds = try makeUnixSocketPair();
    defer posix.close(fds[1]);

    var client = IpcClient{};
    client.fd = fds[0];
    client.connected = true;
    defer client.close();

    // Send an auth request
    try client.send(.{ .auth_request = .{
        .conn_id = 5,
        .mechanism = .scram_sha_256,
        .username = "test",
        .payload = "initial-data",
    } });

    // Read from the peer side
    var peer_buf: [1024]u8 = undefined;
    const n = try posix.read(fds[1], &peer_buf);
    try std.testing.expect(n > 0);

    // Parse the frame
    const frame = protocol.readFrame(peer_buf[0..n]) orelse return error.NoFrame;
    const decoded = try protocol.decode(frame.payload);
    try std.testing.expectEqual(@as(u32, 5), decoded.auth_request.conn_id);
    try std.testing.expectEqualStrings("test", decoded.auth_request.username);
}

test "IpcClient: receive message from peer" {
    const fds = try makeUnixSocketPair();
    defer posix.close(fds[1]);

    var client = IpcClient{};
    client.fd = fds[0];
    client.connected = true;
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
    client.recv_len = 10;

    client.close();
    try std.testing.expect(!client.connected);
    try std.testing.expectEqual(@as(posix.fd_t, -1), client.fd);
    try std.testing.expectEqual(@as(usize, 0), client.recv_len);
}
