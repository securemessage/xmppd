//! # IPC Server — Unix domain socket server for inter-process communication
//!
//! Used by xmppd-auth to accept connections from xmppd-core. Handles:
//! - Binding and listening on a Unix socket path
//! - Accepting new client connections
//! - Per-client receive buffers for partial frame reassembly
//! - Message dispatch via callback
//!
//! ## Integration with kqueue
//!
//! The listen socket fd is registered for EVFILT_READ. On accept, the
//! new client fd is also registered. When a client fd is readable,
//! call `handleClient()` to receive and decode messages.

const std = @import("std");
const posix = std.posix;
const protocol = @import("ipc_protocol");

const log = std.log.scoped(.ipc_server);

/// Maximum simultaneous IPC client connections.
const MAX_IPC_CLIENTS = 16;

/// Per-IPC-client receive buffer size.
const CLIENT_BUF_SIZE = 8192;

/// Per-IPC-client send buffer size.
const CLIENT_SEND_BUF_SIZE = 16384;

/// A connected IPC client (one xmppd-core process).
pub const IpcConn = struct {
    fd: posix.fd_t = -1,
    recv_buf: [CLIENT_BUF_SIZE]u8 = undefined,
    recv_len: usize = 0,
    /// Bytes consumed by the last nextMessage() — compacted on the next call.
    recv_consumed: usize = 0,
    send_buf: [CLIENT_SEND_BUF_SIZE]u8 = undefined,
    send_start: usize = 0,
    send_end: usize = 0,
    active: bool = false,

    /// Read data from the socket. Returns 0 on EOF.
    pub fn recv(self: *IpcConn) !usize {
        self.compactRecvBuf();
        const space = CLIENT_BUF_SIZE - self.recv_len;
        if (space == 0) return error.BufferFull;

        const n = posix.read(self.fd, self.recv_buf[self.recv_len .. self.recv_len + space]) catch |err| {
            return switch (err) {
                error.WouldBlock => @as(usize, 0),
                else => error.ReadFailed,
            };
        };

        self.recv_len += n;
        return n;
    }

    /// Extract the next complete message from the recv buffer.
    /// Returns null if no complete frame is available.
    /// The returned Message borrows from the recv buffer — process it
    /// before calling nextMessage() or recv() again.
    pub fn nextMessage(self: *IpcConn) !?protocol.Message {
        // Apply deferred compaction from the previous call
        self.compactRecvBuf();

        const data = self.recv_buf[0..self.recv_len];
        const frame = protocol.readFrame(data) orelse return null;

        const msg = try protocol.decode(frame.payload);

        // Defer compaction — the returned msg borrows from recv_buf.
        self.recv_consumed = frame.consumed;

        return msg;
    }

    /// Apply deferred compaction: shift unconsumed data to the front.
    fn compactRecvBuf(self: *IpcConn) void {
        if (self.recv_consumed == 0) return;
        const remaining = self.recv_len - self.recv_consumed;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.recv_buf[0..remaining], self.recv_buf[self.recv_consumed..self.recv_len]);
        }
        self.recv_len = remaining;
        self.recv_consumed = 0;
    }

    /// Queue a response message for sending.
    pub fn queueSend(self: *IpcConn, msg: protocol.Message) !void {
        var frame_buf: [4096]u8 = undefined;
        const frame_len = try protocol.encode(msg, &frame_buf);

        const space = CLIENT_SEND_BUF_SIZE - self.send_end;
        if (frame_len > space) {
            self.compactSendBuf();
            const space2 = CLIENT_SEND_BUF_SIZE - self.send_end;
            if (frame_len > space2) return error.SendBufferFull;
        }
        @memcpy(self.send_buf[self.send_end .. self.send_end + frame_len], frame_buf[0..frame_len]);
        self.send_end += frame_len;
    }

    /// Flush the send buffer. Returns bytes written.
    pub fn flush(self: *IpcConn) !usize {
        if (self.send_start >= self.send_end) return 0;

        const data = self.send_buf[self.send_start..self.send_end];
        const n = posix.write(self.fd, data) catch |err| {
            return switch (err) {
                error.WouldBlock => @as(usize, 0),
                else => error.WriteFailed,
            };
        };

        self.send_start += n;
        if (self.send_start == self.send_end) {
            self.send_start = 0;
            self.send_end = 0;
        }
        return n;
    }

    /// Returns true if there is unsent data.
    pub fn hasPendingSend(self: *const IpcConn) bool {
        return self.send_start < self.send_end;
    }

    pub fn close(self: *IpcConn) void {
        if (self.fd >= 0) {
            posix.close(self.fd);
            self.fd = -1;
        }
        self.active = false;
        self.recv_len = 0;
        self.send_start = 0;
        self.send_end = 0;
    }

    fn compactSendBuf(self: *IpcConn) void {
        if (self.send_start == 0) return;
        const remaining = self.send_end - self.send_start;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.send_buf[0..remaining], self.send_buf[self.send_start..self.send_end]);
        }
        self.send_end = remaining;
        self.send_start = 0;
    }
};

pub const IpcServer = struct {
    /// Listen socket fd.
    listen_fd: posix.fd_t = -1,

    /// Connected IPC clients.
    clients: [MAX_IPC_CLIENTS]IpcConn = [_]IpcConn{IpcConn{}} ** MAX_IPC_CLIENTS,

    /// Path to the socket file (for cleanup).
    socket_path: [108]u8 = std.mem.zeroes([108]u8),
    path_len: usize = 0,

    /// Bind and listen on a Unix domain socket.
    pub fn listen(self: *IpcServer, path: []const u8) !void {
        const sock = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
        errdefer posix.close(sock);

        // Remove stale socket file
        std.fs.cwd().deleteFile(path) catch {};

        var addr: std.c.sockaddr.un = std.mem.zeroes(std.c.sockaddr.un);
        addr.family = posix.AF.UNIX;
        if (path.len >= addr.path.len) return error.PathTooLong;
        @memcpy(addr.path[0..path.len], path);

        try posix.bind(sock, @ptrCast(&addr), @sizeOf(std.c.sockaddr.un));
        try posix.listen(sock, 8);

        self.listen_fd = sock;
        @memcpy(self.socket_path[0..path.len], path);
        self.path_len = path.len;

        log.info("IPC server listening on {s}", .{path});
    }

    /// Accept a new IPC client connection.
    /// Returns the client index, or null if no connection pending or at capacity.
    pub fn accept(self: *IpcServer) !?usize {
        const client_fd = posix.accept(self.listen_fd, null, null, posix.SOCK.NONBLOCK) catch |err| {
            return switch (err) {
                error.WouldBlock => null,
                else => error.AcceptFailed,
            };
        };

        // Find a free slot
        for (&self.clients, 0..) |*slot, i| {
            if (!slot.active) {
                slot.* = IpcConn{};
                slot.fd = client_fd;
                slot.active = true;
                log.info("IPC client connected, slot={d} fd={d}", .{ i, client_fd });
                return i;
            }
        }

        // No free slot
        posix.close(client_fd);
        log.warn("IPC connection rejected: all {d} slots full", .{MAX_IPC_CLIENTS});
        return null;
    }

    /// Get a client connection by index.
    pub fn getClient(self: *IpcServer, index: usize) ?*IpcConn {
        if (index >= MAX_IPC_CLIENTS) return null;
        if (!self.clients[index].active) return null;
        return &self.clients[index];
    }

    /// Close a client connection.
    pub fn closeClient(self: *IpcServer, index: usize) void {
        if (index >= MAX_IPC_CLIENTS) return;
        if (self.clients[index].active) {
            log.info("IPC client disconnected, slot={d}", .{index});
            self.clients[index].close();
        }
    }

    /// Clean up: close all clients, close listen socket, remove socket file.
    pub fn deinit(self: *IpcServer) void {
        for (&self.clients) |*client| {
            if (client.active) client.close();
        }
        if (self.listen_fd >= 0) {
            posix.close(self.listen_fd);
            self.listen_fd = -1;
        }
        // Remove socket file
        if (self.path_len > 0) {
            const path = self.socket_path[0..self.path_len];
            std.fs.cwd().deleteFile(path) catch {};
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "IpcServer: listen, accept, send/receive" {
    const path = "/tmp/xmppd-test-ipc.sock";

    // Clean up in case of previous test failure
    std.fs.cwd().deleteFile(path) catch {};

    var server = IpcServer{};
    defer server.deinit();
    try server.listen(path);

    // Connect a client
    const client_fd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(client_fd);

    var addr: std.c.sockaddr.un = std.mem.zeroes(std.c.sockaddr.un);
    addr.family = posix.AF.UNIX;
    @memcpy(addr.path[0..path.len], path);
    posix.connect(client_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.un)) catch |err| {
        switch (err) {
            error.WouldBlock => {},
            else => return err,
        }
    };

    // Give the connection a moment
    std.Thread.sleep(10 * std.time.ns_per_ms);

    // Accept
    const slot = try server.accept() orelse return error.AcceptFailed;
    const conn = server.getClient(slot) orelse return error.NoClient;
    try std.testing.expect(conn.active);
    try std.testing.expect(conn.fd >= 0);

    // Client sends a message
    var frame_buf: [1024]u8 = undefined;
    const frame_len = try protocol.encode(.{ .auth_request = .{
        .conn_id = 1,
        .mechanism = .plain,
        .client_ip = "192.168.1.50",
        .cb_type = 0,
        .cb_data = "",
        .username = "bob",
        .payload = "secret",
    } }, &frame_buf);
    _ = try posix.write(client_fd, frame_buf[0..frame_len]);

    std.Thread.sleep(10 * std.time.ns_per_ms);

    // Server receives
    const n = try conn.recv();
    try std.testing.expect(n > 0);

    const msg = try conn.nextMessage() orelse return error.NoMessage;
    try std.testing.expectEqual(@as(u32, 1), msg.auth_request.conn_id);
    try std.testing.expectEqualStrings("bob", msg.auth_request.username);
}

test "IpcServer: deinit cleans up socket file" {
    const path = "/tmp/xmppd-test-ipc-cleanup.sock";
    std.fs.cwd().deleteFile(path) catch {};

    var server = IpcServer{};
    try server.listen(path);

    // Verify socket exists
    std.fs.cwd().access(path, .{}) catch {
        return error.SocketNotCreated;
    };

    server.deinit();

    // Verify socket is removed
    const result = std.fs.cwd().access(path, .{});
    try std.testing.expectError(error.FileNotFound, result);
}

test "IpcConn: queueSend and flush" {
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    defer posix.close(fds[1]);

    var conn = IpcConn{};
    conn.fd = fds[0];
    conn.active = true;
    defer conn.close();

    // Queue a response
    try conn.queueSend(.{ .auth_success = .{
        .conn_id = 10,
        .username = "alice",
        .server_final = "v=sig",
    } });

    try std.testing.expect(conn.hasPendingSend());

    // Flush
    _ = try conn.flush();
    try std.testing.expect(!conn.hasPendingSend());

    // Read from peer
    var buf: [1024]u8 = undefined;
    const n = try posix.read(fds[1], &buf);
    try std.testing.expect(n > 0);

    const frame = protocol.readFrame(buf[0..n]) orelse return error.NoFrame;
    const msg = try protocol.decode(frame.payload);
    try std.testing.expectEqual(@as(u32, 10), msg.auth_success.conn_id);
}
