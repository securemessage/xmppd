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
/// 64 worker cap + 16 headroom for xmppctl / s2s / monitoring.
pub const MAX_IPC_CLIENTS = 80;

/// Per-IPC-client receive buffer size.
const CLIENT_BUF_SIZE = 8192;

/// Hard cap on a client's unsent response backlog. Login storms against
/// xmppd-auth queue one SCRAM challenge plus one result per in-flight SASL
/// exchange; the old fixed 16 KiB buffer overflowed after ~118 in-flight
/// requests and the caller closed the core link, wedging auth until restart.
/// The buffer now GROWS on demand (heap), and intake backpressure (EV_READ
/// disable at the auth daemon's high-water mark) keeps reality far below
/// this cap.
const CLIENT_SEND_CAP: usize = 4 << 20;

/// A connected IPC client (one xmppd-core process).
pub const IpcConn = struct {
    fd: posix.fd_t = -1,
    recv_buf: [CLIENT_BUF_SIZE]u8 = undefined,
    recv_len: usize = 0,
    /// Bytes consumed by the last nextMessage() — compacted on the next call.
    recv_consumed: usize = 0,
    /// Growable (heap) response backlog: [0..send_start] consumed,
    /// [send_start..len) unsent. Allocated lazily from `alloc`.
    send_list: std.ArrayListUnmanaged(u8) = .{},
    send_start: usize = 0,
    /// Set when the slot is activated (IpcServer.accept) or by tests.
    alloc: ?std.mem.Allocator = null,
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

    /// Queue a response message for sending. Grows the backlog buffer on
    /// demand; returns SendBufferFull only past CLIENT_SEND_CAP.
    pub fn queueSend(self: *IpcConn, msg: protocol.Message) !void {
        var frame_buf: [4096]u8 = undefined;
        const frame_len = try protocol.encode(msg, &frame_buf);

        const alloc = self.alloc orelse return error.NoAllocator;
        const unsent = self.send_list.items.len - self.send_start;
        if (unsent + frame_len > CLIENT_SEND_CAP) return error.SendBufferFull;
        // Reclaim the consumed prefix before growing.
        if (self.send_start >= unsent or self.send_start >= 4096) {
            std.mem.copyForwards(u8, self.send_list.items, self.send_list.items[self.send_start..]);
            self.send_list.items.len = unsent;
            self.send_start = 0;
        }
        try self.send_list.appendSlice(alloc, frame_buf[0..frame_len]);
    }

    /// Flush the send buffer. Returns bytes written.
    pub fn flush(self: *IpcConn) !usize {
        const items = self.send_list.items;
        if (self.send_start >= items.len) return 0;

        const n = posix.write(self.fd, items[self.send_start..]) catch |err| {
            return switch (err) {
                error.WouldBlock => @as(usize, 0),
                else => error.WriteFailed,
            };
        };

        self.send_start += n;
        if (self.send_start == self.send_list.items.len) {
            self.send_start = 0;
            self.send_list.clearRetainingCapacity();
        }
        return n;
    }

    /// Returns true if there is unsent data.
    pub fn hasPendingSend(self: *const IpcConn) bool {
        return self.send_start < self.send_list.items.len;
    }

    /// Unflushed bytes — the intake throttle keys on this.
    pub fn pendingSendBytes(self: *const IpcConn) usize {
        return self.send_list.items.len - self.send_start;
    }

    pub fn close(self: *IpcConn) void {
        if (self.fd >= 0) {
            posix.close(self.fd);
            self.fd = -1;
        }
        if (self.alloc) |a| {
            self.send_list.deinit(a);
            self.alloc = null;
        }
        self.active = false;
        self.recv_len = 0;
        self.send_start = 0;
    }
};

pub const IpcServer = struct {
    /// Listen socket fd.
    listen_fd: posix.fd_t = -1,

    /// Connected IPC clients.
    clients: [MAX_IPC_CLIENTS]IpcConn = [_]IpcConn{IpcConn{}} ** MAX_IPC_CLIENTS,

    /// Backs per-client growable send backlogs (must outlive the server).
    allocator: std.mem.Allocator,

    /// Path to the socket file (for cleanup).
    socket_path: [108]u8 = std.mem.zeroes([108]u8),
    path_len: usize = 0,

    pub fn init(allocator: std.mem.Allocator) IpcServer {
        return .{ .allocator = allocator };
    }

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
                slot.alloc = self.allocator;
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

    var server = IpcServer.init(std.testing.allocator);
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

test "IpcConn: queueSend buffers past the old 16KiB cap without dropping the client" {
    // Regression: a SCRAM challenge burst overflowed the 16 KiB per-client
    // send buffer and the caller closed the IPC link, wedging auth for the
    // whole server. The buffer must absorb a login storm (thousands of
    // pending frames) — intake backpressure handles the rest upstream.
    var conn = IpcConn{};
    conn.fd = -1; // buffer-only; never flushed
    conn.alloc = std.testing.allocator;
    conn.active = true;
    defer if (conn.alloc) |a| conn.send_list.deinit(a);

    var queued: usize = 0;
    while (queued < 2000) : (queued += 1) {
        try conn.queueSend(.{ .auth_success = .{
            .conn_id = 10,
            .username = "alice",
            .server_final = "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        } });
    }
    try std.testing.expect(conn.pendingSendBytes() > 16384);
    try std.testing.expect(conn.hasPendingSend());
}

test "IpcServer: deinit cleans up socket file" {
    const path = "/tmp/xmppd-test-ipc-cleanup.sock";
    std.fs.cwd().deleteFile(path) catch {};

    var server = IpcServer.init(std.testing.allocator);
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
    conn.alloc = std.testing.allocator;
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
