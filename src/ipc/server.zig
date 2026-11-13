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

// FreeBSD: absent from zig's std.c for this version.
/// FreeBSD 15 maps neither geteuid nor getegid in this zig's std.c; declare
/// both locally. getgroups backs the cr_groups test.
extern "c" fn geteuid() std.c.uid_t;
extern "c" fn getegid() std.c.gid_t;
extern "c" fn getgroups(ngroups: c_int, grouplist: [*]std.c.gid_t) c_int;

/// LOCAL_PEERCRED peer credentials (FreeBSD sys/un.h + sys/ucred.h):
/// getpeereid exposes only the EFFECTIVE gid, so a peer carrying the
/// daemon's group as a supplementary group passes the 0660 socket check
/// yet fails the gate. cr_groups holds the effective gid first, then the
/// supplementary groups (T258).
const SOL_LOCAL: c_int = 0;
const LOCAL_PEERCRED: c_int = 1;
const XU_NGROUPS = 16;
const Xucred = extern struct {
    cr_version: c_uint,
    cr_uid: std.c.uid_t,
    cr_ngroups: c_short,
    cr_groups: [XU_NGROUPS]std.c.gid_t,
    cr_pid: std.c.pid_t,
};

const so_nosigpipe: c_int = 0x0800; // SO_NOSIGPIPE (FreeBSD)

fn setNoSigpipe(fd: posix.fd_t) !void {
    const one: c_int = 1;
    try posix.setsockopt(fd, posix.SOL.SOCKET, so_nosigpipe, std.mem.asBytes(&one));
}

/// Whether an IPC peer may connect: root, the daemon's own uid, or any
/// peer group (effective or supplementary) equal to the daemon's gid.
/// Fails closed when LOCAL_PEERCRED is unavailable.
pub fn peerCredentialsAuthorized(fd: c_int, self_euid: std.c.uid_t, self_egid: std.c.gid_t) bool {
    var cred: Xucred = undefined;
    var len: posix.socklen_t = @sizeOf(Xucred);
    if (std.c.getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, @ptrCast(&cred), &len) != 0) return false;
    if (len < @sizeOf(Xucred)) return false;
    if (cred.cr_uid == 0 or cred.cr_uid == self_euid) return true;
    const n: usize = @intCast(@min(@max(cred.cr_ngroups, 0), XU_NGROUPS));
    for (cred.cr_groups[0..n]) |g| {
        if (g == self_egid) return true;
    }
    return false;
}

/// Maximum simultaneous IPC client connections.
/// 64 worker cap + 16 headroom for xmppctl / s2s / monitoring.
pub const MAX_IPC_CLIENTS = 80;

/// Per-IPC-client receive buffer: one full wire frame (T257: the
/// 8 KiB buf silently closed the core-s2s lane on 9-16 KiB stanzas).
/// Heap-allocated per client at accept time (80 slots * 64 KiB).
const RECV_BUF_SIZE = protocol.MAX_FRAME_SIZE;

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
    /// lib/net receive side (ADR-8): the parser over the heap buffer
    /// IpcServer.accept (or tests) allocates with RECV_BUF_SIZE bytes.
    /// reader.buf is the empty slice while the slot is inactive.
    reader: protocol.FrameReader = .{ .buf = &.{} },
    /// lib/net send side: responses encode in place into a bounded
    /// backlog (CLIENT_SEND_CAP) and drain to EAGAIN.
    writer: protocol.FrameWriter = .{},
    /// Set when the slot is activated (IpcServer.accept) or by tests.
    alloc: ?std.mem.Allocator = null,
    active: bool = false,

    /// Pull bytes into the frame buffer until EAGAIN, full, or EOF.
    /// .eof is the peer's orderly shutdown; .would_block moved nothing:
    /// a stale readable event must not read as a hangup (T329).
    pub fn recv(self: *IpcConn) (error{BufferNotAllocated} || posix.ReadError)!protocol.RecvResult {
        // accept() always allocates; an empty buffer names an
        // uninitialized slot, and .full on it would wedge the lane
        // instead of dying loudly.
        if (self.reader.buf.len == 0) return error.BufferNotAllocated;
        return self.reader.recv(self.fd);
    }

    /// Extract the next complete message from the recv buffer.
    /// Returns null if no complete frame is available.
    /// The returned Message borrows from the recv buffer — process it
    /// before calling nextMessage() or recv() again.
    pub fn nextMessage(self: *IpcConn) (protocol.NextError || protocol.DecodeError)!?protocol.Message {
        const frame = try self.reader.next() orelse return null;
        const msg = try protocol.decode(frame.payload);
        // consume() only moves the cursor; the decoded slices stay valid
        // until the next recv() compacts the consumed prefix away.
        self.reader.consume(frame.consumed);
        return msg;
    }

    /// Queue a response message for sending. Grows the backlog buffer on
    /// demand; begin() refuses with BacklogFull past CLIENT_SEND_CAP.
    pub fn queueSend(self: *IpcConn, msg: protocol.Message) (error{NoAllocator} || protocol.BeginError || protocol.EncodeError)!void {
        const alloc = self.alloc orelse return error.NoAllocator;

        // Encode in place into the backlog: no 64 KiB stack scratch on an
        // event-loop thread (T257). Nothing is queued on error.
        const scratch = self.writer.begin(alloc, protocol.payloadLen(msg), CLIENT_SEND_CAP) catch |err| {
            log.err("failed to queue a {s} frame for the wire ({}): dropping it", .{ @tagName(msg), err });
            return err;
        };
        const payload_len = protocol.encodePayload(msg, scratch[protocol.HEADER_SIZE..]) catch |err| {
            log.err("failed to encode a {s} frame for the wire ({}): dropping it", .{ @tagName(msg), err });
            return err;
        };
        self.writer.commit(payload_len);
    }

    /// Flush the send backlog until it empties or the fd says EAGAIN.
    pub fn flush(self: *IpcConn) (error{NoAllocator} || posix.WriteError)!protocol.WriteResult {
        if (self.writer.pending() == 0) return .drained;
        const alloc = self.alloc orelse return error.NoAllocator;
        return self.writer.drain(alloc, self.fd);
    }

    /// Returns true if there is unsent data.
    pub fn hasPendingSend(self: *const IpcConn) bool {
        return self.writer.pending() > 0;
    }

    /// Unflushed bytes — the intake throttle keys on this.
    pub fn pendingSendBytes(self: *const IpcConn) usize {
        return self.writer.pending();
    }

    /// Queued-but-unsent bytes (tests).
    pub fn unsentBytes(self: *const IpcConn) []const u8 {
        return self.writer.unsentBytes();
    }

    pub fn close(self: *IpcConn) void {
        if (self.fd >= 0) {
            posix.close(self.fd);
            self.fd = -1;
        }
        if (self.alloc) |a| {
            self.writer.deinit(a);
            if (self.reader.buf.len > 0) a.free(self.reader.buf);
            self.alloc = null;
        }
        self.writer = .{};
        self.reader = .{ .buf = &.{} };
        self.active = false;
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

        // The socket must not be world-writable (T258): group mode is the
        // operator escape hatch; the directory perms narrow it further.
        var path_z: [104]u8 = undefined;
        @memcpy(path_z[0..path.len], path);
        path_z[path.len] = 0;
        if (std.c.chmod(@ptrCast(&path_z), 0o660) != 0) {
            log.warn("chmod(0660) on {s} failed", .{path});
        }

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

        // A core that died between our read events turns the next reply
        // write into SIGPIPE; suppress it per-socket so flush() returns
        // the error instead of the process dying before it lands.
        setNoSigpipe(client_fd) catch {
            posix.close(client_fd);
            return error.AcceptFailed;
        };

        // Peer credentials gate (T258): root, the daemon's own uid,
        // OR membership in the daemon's group through ANY of the peer's
        // groups (LOCAL_PEERCRED cr_groups; getpeereid's effective gid made
        // the 0660 socket mode a silent no-op for supplementary members).
        // The `ctl` sentinel for maintenance tooling remains for a
        // follow-up.
        if (!peerCredentialsAuthorized(client_fd, geteuid(), getegid())) {
            log.warn("IPC connection rejected: peer is neither root, the daemon uid, nor a member of the daemon group", .{});
            posix.close(client_fd);
            return null;
        }

        // Find a free slot
        for (&self.clients, 0..) |*slot, i| {
            if (!slot.active) {
                const recv_buf = self.allocator.alloc(u8, RECV_BUF_SIZE) catch {
                    log.err("IPC client rejected: recv buffer allocation failed", .{});
                    posix.close(client_fd);
                    return null;
                };
                slot.* = IpcConn{};
                slot.fd = client_fd;
                slot.alloc = self.allocator;
                slot.reader = protocol.FrameReader.init(recv_buf);
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
    const rr = try conn.recv();
    try std.testing.expectEqual(protocol.RecvResult.data, rr);

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
    defer if (conn.alloc) |a| conn.writer.deinit(a);

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

test "IpcConn: a payload over the old 8 KiB receive buffer arrives through a real socket (T257)" {
    // Regression: the receiver held an 8 KiB buffer, so a 9-16 KiB
    // core-to-s2s stanza frame filled the lane and the caller closed it.
    // This drives a real socketpair end to end.
    const alloc = std.testing.allocator;

    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds) != 0)
        return error.SocketPairFailed;
    defer posix.close(fds[0]);

    var conn = IpcConn{
        .fd = fds[1],
        .alloc = alloc,
        .reader = protocol.FrameReader.init(try alloc.alloc(u8, RECV_BUF_SIZE)),
    };
    defer conn.close();

    const big = try alloc.alloc(u8, 12000);
    defer alloc.free(big);
    @memset(big, 's');

    // Encode into a heap scratch the size of one frame (the production
    // path does this via FrameWriter.begin scratch).
    const scratch = try alloc.alloc(u8, protocol.MAX_FRAME_SIZE);
    defer alloc.free(scratch);
    const frame_len = try protocol.encode(.{ .s2s_inbound = .{
        .from_jid = "eve@them.example",
        .to_jid = "bob@us.example",
        .stanza_xml = big,
    } }, scratch);
    _ = try posix.write(fds[0], scratch[0..frame_len]);

    std.Thread.sleep(5 * std.time.ns_per_ms);

    _ = try conn.recv();
    const msg = try conn.nextMessage() orelse return error.NoMessage;
    try std.testing.expectEqual(@as(usize, 12000), msg.s2s_inbound.stanza_xml.len);
    try std.testing.expectEqualStrings("eve@them.example", msg.s2s_inbound.from_jid);
}

test "IpcConn: recv reports would_block, eof and data distinctly (T329)" {
    // Regression: recv() once folded WouldBlock and EOF into the same 0,
    // so a stale readable event read as a hangup and the caller closed a
    // healthy lane. The result must distinguish them.
    const alloc = std.testing.allocator;
    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds) != 0)
        return error.SocketPairFailed;
    defer posix.close(fds[0]);

    var conn = IpcConn{
        .fd = fds[1],
        .alloc = alloc,
        .reader = protocol.FrameReader.init(try alloc.alloc(u8, RECV_BUF_SIZE)),
    };
    defer conn.close();

    try std.testing.expectEqual(protocol.RecvResult.would_block, try conn.recv());

    var frame_buf: [64]u8 = undefined;
    const frame_len = try protocol.encode(.{ .auth_abort = .{ .conn_id = 3 } }, &frame_buf);
    _ = try posix.write(fds[0], frame_buf[0..frame_len]);
    try std.testing.expectEqual(protocol.RecvResult.data, try conn.recv());
    const msg = try conn.nextMessage() orelse return error.NoMessage;
    try std.testing.expectEqual(@as(u32, 3), msg.auth_abort.conn_id);

    // Orderly peer shutdown: eof, latched on every later call.
    posix.shutdown(fds[0], .both) catch {};
    try std.testing.expectEqual(protocol.RecvResult.eof, try conn.recv());
    try std.testing.expectEqual(protocol.RecvResult.eof, try conn.recv());
}

test "IpcConn: frames larger than the old 4 KiB encode buffer are deliverable (T257)" {
    // Regression: encode used a 4096-byte scratch while the wire protocol
    // allows 64 KiB; an 8 KiB s2s_inbound stanza failed encode and the
    // caller's catch dropped it without a log.
    var conn = IpcConn{};
    conn.fd = -1;
    conn.alloc = std.testing.allocator;
    conn.active = true;
    defer if (conn.alloc) |a| conn.writer.deinit(a);

    const big = try std.testing.allocator.alloc(u8, 8192);
    defer std.testing.allocator.free(big);
    @memset(big, 'x');

    try conn.queueSend(.{ .s2s_inbound = .{
        .from_jid = "a@example.com",
        .to_jid = "b@example.com",
        .stanza_xml = big,
    } });
    try std.testing.expect(conn.hasPendingSend());
}

test "IpcServer: socket file lands with mode 0660 (T258)" {
    const path = "/tmp/xmppd-test-ipc-mode.sock";
    std.fs.cwd().deleteFile(path) catch {};
    defer std.fs.cwd().deleteFile(path) catch {};

    var server = IpcServer.init(std.testing.allocator);
    try server.listen(path);
    defer server.deinit();

    const st = try std.fs.cwd().statFile(path);
    try std.testing.expectEqual(@as(u32, 0o660), @as(u32, @intCast(st.mode & 0o777)));
}

test "IpcServer: peer gate reads cr_groups, not just the effective gid (T258)" {
    // AF_UNIX socketpair: both ends carry this process's credentials, so
    // the gate sees our own uid and full group set.
    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    const euid = geteuid();
    const egid = getegid();

    // Same uid: authorized regardless of the daemon gid.
    try std.testing.expect(peerCredentialsAuthorized(fds[0], euid, egid));

    // The negative and supplementary-group cases need a non-root test
    // process: root's uid short-circuits every check.
    if (euid != 0) {
        // Foreign uid AND foreign gid: rejected.
        try std.testing.expect(!peerCredentialsAuthorized(fds[0], euid + 1, egid + 1));

        // A daemon gid that is one of our SUPPLEMENTARY groups must
        // authorize with a foreign uid: getpeereid's effective-gid view
        // rejected exactly this peer, making the 0660 group bit useless.
        var groups: [XU_NGROUPS]std.c.gid_t = undefined;
        const ng = getgroups(XU_NGROUPS, &groups);
        var supp: ?std.c.gid_t = null;
        if (ng > 0) {
            for (groups[0..@intCast(ng)]) |g| {
                if (g != egid) {
                    supp = g;
                    break;
                }
            }
        }
        if (supp) |g| {
            try std.testing.expect(peerCredentialsAuthorized(fds[0], euid + 1, g));
        }
    }
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

    const frame = (try protocol.parseFrame(buf[0..n])) orelse return error.NoFrame;
    const msg = try protocol.decode(frame.payload);
    try std.testing.expectEqual(@as(u32, 10), msg.auth_success.conn_id);
}
