//! bind: TCP and Unix listeners for the loop (ADR-8, F2).
//!
//! bindTcp honors bind_address for IPv4 and IPv6 literals and returns a
//! non-blocking CLOEXEC listener with SO_REUSEPORT_LB (accept-side load
//! balancing across loops) and TCP_NODELAY (inherited by every accepted
//! connection through the syncache). bindUnix validates the path, probes a
//! stale socket on EADDRINUSE, and applies the requested mode after bind.
//!
//! Listener accepts from a readable event: drain to EAGAIN, stop after
//! batch_limit and requeue so a busy listener cannot starve the loop. On
//! EMFILE/ENFILE/ENOBUFS/ENOMEM it pauses read interest until the next
//! close() on the loop (a freed descriptor), with a fallback resume deadline
//! so a listener also recovers when nothing closes.
//!
//! peerCred returns the LOCAL_PEERCRED credentials of an accepted Unix
//! socket (uid, gid).

const std = @import("std");
const posix = std.posix;
const Token = @import("token.zig").Token;
const loop_mod = @import("loop.zig");
const Loop = loop_mod.Loop;
const Handle = loop_mod.Handle;
const Interest = loop_mod.Interest;

pub const BindTcpError = error{
    InvalidAddress,
    AddressInUse,
    AddressNotAvailable,
    AccessDenied,
    SystemResources,
    Unexpected,
};

pub const BindUnixError = error{
    PathTooLong,
    AddressInUse,
    NotASocket,
    AccessDenied,
    SystemResources,
    Unexpected,
};

pub const TcpOptions = struct {
    address: []const u8, // IPv4 or IPv6 literal; names are rejected (no DNS)
    port: u16,
    backlog: u31 = 4096,
    reuse_port_lb: bool = true, // SO_REUSEPORT_LB: one listener per loop
    v6_only: bool = true,
    nodelay: bool = true, // TCP_NODELAY on the listener only
};

pub const UnixOptions = struct {
    path: [:0]const u8,
    mode: posix.mode_t,
    backlog: u31 = 128,
};

const so_reuseport_lb: c_int = 0x00010000; // SO_REUSEPORT_LB, absent from some std.c.SO blocks
const tcp_nodelay: c_int = 1; // TCP_NODELAY
const ipv6_v6only: c_int = 0x1b; // IPV6_V6ONLY
const sun_path_max = 104; // sizeof(sockaddr_un.sun_path)

fn socketError(err: posix.SocketError) error{ AccessDenied, SystemResources, Unexpected } {
    return switch (err) {
        error.AccessDenied => error.AccessDenied,
        error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded, error.SystemResources => error.SystemResources,
        else => error.Unexpected,
    };
}

/// Non-blocking CLOEXEC TCP listener on an IPv4 or IPv6 literal (including
/// bind_address hosts); names are rejected instead of resolved. The caller
/// attaches the fd to a loop via `Listener.attach`.
pub fn bindTcp(options: *const TcpOptions) BindTcpError!posix.fd_t {
    const addr = std.net.Address.parseIp(options.address, options.port) catch return error.InvalidAddress;
    const fd = posix.socket(addr.any.family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0) catch |err| return socketError(err);
    errdefer posix.close(fd);

    const one: c_int = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch return error.Unexpected;
    if (options.reuse_port_lb) {
        posix.setsockopt(fd, posix.SOL.SOCKET, so_reuseport_lb, std.mem.asBytes(&one)) catch return error.Unexpected;
    }
    if (options.nodelay) {
        posix.setsockopt(fd, std.c.IPPROTO.TCP, tcp_nodelay, std.mem.asBytes(&one)) catch return error.Unexpected;
    }
    if (addr.any.family == posix.AF.INET6 and options.v6_only) {
        posix.setsockopt(fd, posix.IPPROTO.IPV6, ipv6_v6only, std.mem.asBytes(&one)) catch return error.Unexpected;
    }

    posix.bind(fd, &addr.any, addr.getOsSockLen()) catch |err| return switch (err) {
        error.AddressInUse => error.AddressInUse,
        error.AccessDenied => error.AccessDenied,
        error.AddressNotAvailable => error.AddressNotAvailable,
        else => error.Unexpected,
    };
    posix.listen(fd, options.backlog) catch |err| return switch (err) {
        error.AddressInUse => error.AddressInUse,
        else => error.Unexpected,
    };
    return fd;
}

/// Non-blocking CLOEXEC Unix-domain listener. Order: bind, chmod(mode),
/// listen, so the socket never carries the wrong mode. On EADDRINUSE a
/// connect probe decides: ECONNREFUSED means stale (unlink once, retry);
/// ENOTSOCK means a non-socket file owns the path (NotASocket, never
/// unlinked); anything else means a live listener (AddressInUse).
pub fn bindUnix(options: *const UnixOptions) BindUnixError!posix.fd_t {
    const path = options.path;
    if (path.len >= sun_path_max) return error.PathTooLong;

    var un: posix.sockaddr.un = undefined;
    un.family = posix.AF.UNIX;
    @memset(&un.path, 0);
    @memcpy(un.path[0..path.len], path);
    un.len = @intCast(@offsetOf(posix.sockaddr.un, "path") + path.len + 1);
    const salen: posix.socklen_t = @intCast(@sizeOf(posix.sockaddr.un));

    const fd = posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0) catch |err| return socketError(err);
    errdefer posix.close(fd);

    posix.bind(fd, @ptrCast(&un), salen) catch |err| switch (err) {
        error.AddressInUse => try reclaimStale(path, &un, salen, fd),
        error.AccessDenied => return error.AccessDenied,
        else => return error.Unexpected,
    };

    posix.fchmodat(posix.AT.FDCWD, path, options.mode, 0) catch |err| switch (err) {
        error.AccessDenied => return error.AccessDenied,
        else => return error.Unexpected,
    };
    posix.listen(fd, options.backlog) catch return error.Unexpected;
    return fd;
}

/// EADDRINUSE probe with raw connect(2): std.posix.connect maps ENOTSOCK
/// (the regular-file case this probe exists for) to unreachable.
fn reclaimStale(path: [:0]const u8, un: *const posix.sockaddr.un, salen: posix.socklen_t, fd: posix.fd_t) BindUnixError!void {
    const probe = posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch |err| return socketError(err);
    defer posix.close(probe);

    if (std.c.connect(probe, @ptrCast(un), salen) == 0) return error.AddressInUse;
    switch (posix.errno(-1)) {
        .CONNREFUSED => {}, // stale: reclaim below
        .NOTSOCK => return error.NotASocket,
        else => return error.AddressInUse,
    }
    posix.unlink(path) catch return error.AddressInUse;
    posix.bind(fd, @ptrCast(un), salen) catch |err| return switch (err) {
        error.AddressInUse => error.AddressInUse,
        error.AccessDenied => error.AccessDenied,
        else => return error.Unexpected,
    };
}

pub const PeerCred = struct { uid: posix.uid_t, gid: posix.gid_t };

const xucred = extern struct {
    version: c_uint,
    uid: posix.uid_t,
    ngroups: c_short,
    groups: [16]posix.gid_t,
};

/// LOCAL_PEERCRED for an accepted Unix-domain socket. The option lives at
/// local(4) level 0, not SOL_SOCKET.
pub fn peerCred(fd: posix.fd_t) error{ NotUnixSocket, Unexpected }!PeerCred {
    var cred: xucred = undefined;
    var len: posix.socklen_t = @sizeOf(xucred);
    if (std.c.getsockopt(fd, local_level, so_local_peercred, &cred, &len) != 0) {
        return switch (posix.errno(-1)) {
            .INVAL, .OPNOTSUPP, .NOTSOCK => error.NotUnixSocket,
            else => error.Unexpected,
        };
    }
    return .{ .uid = cred.uid, .gid = if (cred.ngroups > 0) cred.groups[0] else 0 };
}

const so_local_peercred: c_int = 0x0001; // LOCAL_PEERCRED on FreeBSD
const local_level: c_int = 0; // local(4) getsockopt level

/// Owns one listening fd on a Loop. `onReadable` is the consumer's handler
/// for the listener's `.readable` event.
pub const Listener = struct {
    loop: *Loop,
    handle: Handle,
    batch_limit: u16,
    fallback_resume_ms: u64,

    pub const Options = struct {
        batch_limit: u16 = 32,
        fallback_resume_ms: u64 = 250,
    };

    /// Attach `fd` (a bindTcp/bindUnix listener; the loop takes ownership) and
    /// watch read interest with consumer token `ctx`.
    pub fn init(loop: *Loop, fd: posix.fd_t, ctx: Token, options: *const Options) loop_mod.AttachError!Listener {
        const handle = try loop.attach(fd, ctx, .{ .read = true });
        return .{
            .loop = loop,
            .handle = handle,
            .batch_limit = options.batch_limit,
            .fallback_resume_ms = options.fallback_resume_ms,
        };
    }

    /// Drain pending accepts into `onConn` (which takes ownership of each
    /// accepted fd). Stops at EAGAIN or after batch_limit; over the limit the
    /// listener requeues itself. On descriptor exhaustion read interest
    /// pauses until a close() or the fallback deadline resumes it.
    pub fn onReadable(
        self: *Listener,
        ctx: *anyopaque,
        onConn: *const fn (ctx: *anyopaque, fd: posix.fd_t) void,
    ) void {
        if (self.loop.isPaused(self.handle)) return;
        const lfd = self.loop.fdOf(self.handle) orelse return;
        var accepted: u16 = 0;
        while (accepted < self.batch_limit) : (accepted += 1) {
            const fd = posix.accept(lfd, null, null, posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC) catch |err| switch (err) {
                error.WouldBlock => return,
                error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded, error.SystemResources => {
                    self.pauseWithFallback();
                    return;
                },
                else => continue, // aborted peer or transient failure; keep draining
            };
            onConn(ctx, fd);
        }
        // Hit the batch bound: come back for the rest after one pass so a
        // busy listener cannot starve other handles.
        self.loop.requeue(self.handle, .read) catch return;
    }

    fn pauseWithFallback(self: *Listener) void {
        self.loop.pauseReadUntilClose(self.handle) catch return;
        const resume_ctx: Token = .{
            .index = self.handle.index,
            .gen = self.handle.gen,
            .kind = loop_mod.resume_kind,
        };
        // TimerTableFull only loses the fallback; close() still resumes.
        _ = self.loop.scheduleIn(self.fallback_resume_ms, resume_ctx) catch |err| switch (err) {
            error.TimerTableFull => return,
        };
    }

    /// Consumer-side resume; the fallback deadline also reaches here through
    /// the loop's resume_kind interception.
    pub fn resumePaused(self: *Listener) void {
        self.loop.resumePaused(self.handle) catch |err| switch (err) {
            error.StaleHandle => {},
        };
    }

    pub fn close(self: *Listener) void {
        self.loop.close(self.handle) catch |err| switch (err) {
            error.StaleHandle => {},
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

const test_ctx: Token = .{ .index = 1, .gen = 1, .kind = 0xEE };

fn testLoop() !Loop {
    var loop: Loop = undefined;
    const options: loop_mod.Options = .{ .handles_max = 32, .timers_max = 16, .events_max = 16 };
    try loop.init(std.testing.allocator, &options);
    return loop;
}

fn boundAddr(fd: posix.fd_t) !posix.sockaddr.storage {
    var sa: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    var len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    try std.testing.expectEqual(0, std.c.getsockname(fd, @ptrCast(&sa), &len));
    return sa;
}

const AcceptProbe = struct {
    fds: [8]posix.fd_t = .{-1} ** 8,
    n: usize = 0,
    fn onConn(ctx_: *anyopaque, fd: posix.fd_t) void {
        const self: *AcceptProbe = @ptrCast(@alignCast(ctx_));
        self.fds[self.n] = fd;
        self.n += 1;
    }
};

test "bindTcp: listener accepts a non-blocking connection" {
    var loop = try testLoop();
    defer loop.deinit(std.testing.allocator);

    const lfd = try bindTcp(&.{ .address = "127.0.0.1", .port = 0 });
    const bound = try boundAddr(lfd);

    var listener = try Listener.init(&loop, lfd, test_ctx, &.{});
    var probe: AcceptProbe = .{};
    defer for (probe.fds) |fd| {
        if (fd >= 0) posix.close(fd);
    };

    const cfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(cfd);
    try posix.connect(cfd, @ptrCast(&bound), @sizeOf(posix.sockaddr.in));

    try loop.wait();
    const ev = loop.next().?;
    try std.testing.expect(ev == .readable);
    try std.testing.expect(ev.readable.handle.eql(listener.handle));
    listener.onReadable(&probe, AcceptProbe.onConn);
    try std.testing.expectEqual(@as(usize, 1), probe.n);

    // The accepted fd is non-blocking: an empty read gives WouldBlock.
    var buf: [4]u8 = undefined;
    try std.testing.expectError(error.WouldBlock, posix.read(probe.fds[0], &buf));
}

test "bindTcp: two listeners share the port with REUSEPORT_LB" {
    const lfd_a = try bindTcp(&.{ .address = "127.0.0.1", .port = 0 });
    defer posix.close(lfd_a);
    const bound = try boundAddr(lfd_a);
    const port = @as(*const posix.sockaddr.in, @ptrCast(@alignCast(&bound))).port;
    const lfd_b = try bindTcp(&.{ .address = "127.0.0.1", .port = std.mem.bigToNative(u16, port) });
    defer posix.close(lfd_b);
}

test "bindTcp: IPv6 literal binds and accepts on ::1" {
    var loop = try testLoop();
    defer loop.deinit(std.testing.allocator);

    const lfd = try bindTcp(&.{ .address = "::1", .port = 0 });
    const bound = try boundAddr(lfd);
    var listener = try Listener.init(&loop, lfd, test_ctx, &.{});
    _ = &listener;

    const cfd = try posix.socket(posix.AF.INET6, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(cfd);
    try posix.connect(cfd, @ptrCast(&bound), @sizeOf(posix.sockaddr.in6));

    try loop.wait();
    const ev = loop.next().?;
    try std.testing.expect(ev == .readable);
    const afd = try posix.accept(lfd, null, null, posix.SOCK.CLOEXEC);
    posix.close(afd);
}

test "bindTcp: a DNS name is rejected, a bad literal is rejected" {
    try std.testing.expectError(error.InvalidAddress, bindTcp(&.{ .address = "localhost", .port = 80 }));
    try std.testing.expectError(error.InvalidAddress, bindTcp(&.{ .address = "999.0.0.1", .port = 80 }));
}

test "bindUnix: accepts and reports LOCAL_PEERCRED" {
    var loop = try testLoop();
    defer loop.deinit(std.testing.allocator);

    const path = "/home/admin/tmp/scratch/devin-net/f2-test.sock";
    posix.unlink(path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    defer posix.unlink(path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => unreachable,
    };
    const lfd = try bindUnix(&.{ .path = path, .mode = 0o600 });
    var listener = try Listener.init(&loop, lfd, test_ctx, &.{});

    const cfd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(cfd);
    var un: posix.sockaddr.un = undefined;
    un.family = posix.AF.UNIX;
    @memset(&un.path, 0);
    @memcpy(un.path[0..path.len], path);
    un.len = @intCast(@offsetOf(posix.sockaddr.un, "path") + path.len + 1);
    try posix.connect(cfd, @ptrCast(&un), @sizeOf(posix.sockaddr.un));

    var probe: AcceptProbe = .{};
    defer for (probe.fds) |fd| {
        if (fd >= 0) posix.close(fd);
    };
    try loop.wait();
    _ = loop.next();
    listener.onReadable(&probe, AcceptProbe.onConn);
    try std.testing.expectEqual(@as(usize, 1), probe.n);

    const cred = try peerCred(probe.fds[0]);
    try std.testing.expectEqual(std.c.getuid(), cred.uid);
}

test "bindUnix: a stale socket path is reclaimed" {
    const path = "/home/admin/tmp/scratch/devin-net/f2-stale.sock";
    // A dead (unlinked-or-closed) socket path: create and close a listener.
    const dead = try bindUnix(&.{ .path = path, .mode = 0o600 });
    posix.close(dead);
    // The path now exists but nothing listens: the probe must reclaim it.
    defer posix.unlink(path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => unreachable,
    };
    const lfd = try bindUnix(&.{ .path = path, .mode = 0o600 });
    defer posix.close(lfd);
}

test "bindUnix: long path refused, live listener and regular file refused, mode applied" {
    var long_buf: [128]u8 = undefined;
    const long_path = try std.fmt.bufPrintZ(&long_buf, "/tmp/{s}", .{"x" ** 110});
    try std.testing.expectError(error.PathTooLong, bindUnix(&.{ .path = long_path, .mode = 0o600 }));

    const path = "/home/admin/tmp/scratch/devin-net/f2-live.sock";
    const live = try bindUnix(&.{ .path = path, .mode = 0o640 });
    defer posix.close(live);
    defer posix.unlink(path) catch unreachable;
    // A listener already owns the path: the probe connects, so AddressInUse.
    try std.testing.expectError(error.AddressInUse, bindUnix(&.{ .path = path, .mode = 0o600 }));

    // The requested mode is on the socket before listen returns it.
    var st: posix.Stat = undefined;
    try std.testing.expectEqual(0, std.c.stat(path, &st));
    try std.testing.expectEqual(@as(u32, 0o640), @as(u32, @intCast(st.mode & 0o777)));

    const reg = "/home/admin/tmp/scratch/devin-net/f2-regular";
    {
        const f = try std.fs.cwd().createFile(reg, .{});
        f.close();
    }
    defer std.fs.cwd().deleteFile(reg) catch unreachable;
    try std.testing.expectError(error.NotASocket, bindUnix(&.{ .path = reg, .mode = 0o600 }));
}

test "Listener: EMFILE pauses, a close resumes (forked child, lowered RLIMIT)" {
    // A forked child with a lowered RLIMIT_NOFILE proves the pause path:
    // accept fails EMFILE, read interest is disabled, a loop.close() frees a
    // descriptor and the listener resumes.
    const pid = try posix.fork();
    if (pid == 0) {
        childEmfile();
        posix.exit(1);
    }
    const res = posix.waitpid(pid, 0);
    try std.testing.expectEqual(@as(u32, 0), @as(u32, @intCast(res.status)));
}

fn childEmfile() void {
    // Open every fd first, then clamp RLIMIT_NOFILE below the open count so
    // the next accept() trips EMFILE.
    const rl = posix.getrlimit(.NOFILE) catch posix.exit(2);

    var loop = testLoop() catch posix.exit(4);

    const lfd = bindTcp(&.{ .address = "127.0.0.1", .port = 0 }) catch posix.exit(6);
    var listener = Listener.init(&loop, lfd, test_ctx, &.{}) catch posix.exit(7);

    // Spare handle the child closes to free a descriptor for the resume.
    var pair: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0, &pair) != 0)
        posix.exit(8);
    const spare = loop.attach(pair[1], test_ctx, .{ .read = true }) catch posix.exit(9);
    posix.close(pair[0]);

    const bound = boundAddr(lfd) catch posix.exit(10);
    const cfd = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch posix.exit(11);
    posix.connect(cfd, @ptrCast(&bound), @sizeOf(posix.sockaddr.in)) catch posix.exit(12);

    const lim2: posix.rlimit = .{ .cur = 4, .max = rl.max };
    posix.setrlimit(.NOFILE, lim2) catch posix.exit(13);

    loop.wait() catch posix.exit(14);
    var probe: AcceptProbe = .{};
    while (loop.next()) |ev| {
        if (ev == .readable) listener.onReadable(&probe, AcceptProbe.onConn);
    }
    if (probe.n != 0) posix.exit(15); // accept must have failed
    if (!loop.isPaused(listener.handle)) posix.exit(16);

    // Back under the quota (a soft limit may be raised to the hard one), the
    // close frees a descriptor and resumes the listener.
    const back: posix.rlimit = .{ .cur = rl.max, .max = rl.max };
    posix.setrlimit(.NOFILE, back) catch posix.exit(21);
    loop.close(spare) catch posix.exit(17);
    if (loop.isPaused(listener.handle)) posix.exit(18);

    // A fresh connection proves read interest fired again after the resume.
    const cfd2 = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch posix.exit(22);
    posix.connect(cfd2, @ptrCast(&bound), @sizeOf(posix.sockaddr.in)) catch posix.exit(23);
    loop.wait() catch posix.exit(19);
    while (loop.next()) |ev| {
        if (ev == .readable) listener.onReadable(&probe, AcceptProbe.onConn);
    }
    // The EMFILE'd connection stayed in the backlog: it and the fresh one
    // are both accepted after the resume.
    if (probe.n != 2) posix.exit(20);
    posix.exit(0);
}
