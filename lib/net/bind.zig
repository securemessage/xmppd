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
//! socket: uid, gid, the group set the kernel reports (XU_NGROUPS=16 cap,
//! flagged possibly-truncated at exactly 16) and pid.

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
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.SystemResources,
        => error.SystemResources,
        else => error.Unexpected,
    };
}

const stream_nb = posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC;

/// Non-blocking CLOEXEC TCP listener on an IPv4 or IPv6 literal (including
/// bind_address hosts); names are rejected instead of resolved. The caller
/// attaches the fd to a loop via `Listener.attach`.
pub fn bindTcp(options: *const TcpOptions) BindTcpError!posix.fd_t {
    const addr = std.net.Address.parseIp(options.address, options.port) catch
        return error.InvalidAddress;
    const fd = posix.socket(addr.any.family, stream_nb, 0) catch |err| return socketError(err);
    errdefer posix.close(fd);

    const one: c_int = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch
        return error.Unexpected;
    if (options.reuse_port_lb) {
        posix.setsockopt(fd, posix.SOL.SOCKET, so_reuseport_lb, std.mem.asBytes(&one)) catch
            return error.Unexpected;
    }
    if (options.nodelay) {
        posix.setsockopt(fd, std.c.IPPROTO.TCP, tcp_nodelay, std.mem.asBytes(&one)) catch
            return error.Unexpected;
    }
    if (addr.any.family == posix.AF.INET6) {
        // FreeBSD defaults V6ONLY on; the option must clear it for a
        // dual-stack listener, not just set it.
        const v6only: c_int = @intFromBool(options.v6_only);
        posix.setsockopt(fd, posix.IPPROTO.IPV6, ipv6_v6only, std.mem.asBytes(&v6only)) catch
            return error.Unexpected;
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

    const fd = posix.socket(posix.AF.UNIX, stream_nb, 0) catch |err| return socketError(err);
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
fn reclaimStale(
    path: [:0]const u8,
    un: *const posix.sockaddr.un,
    salen: posix.socklen_t,
    fd: posix.fd_t,
) BindUnixError!void {
    const stream_cx = posix.SOCK.STREAM | posix.SOCK.CLOEXEC;
    const probe = posix.socket(posix.AF.UNIX, stream_cx, 0) catch |err| return socketError(err);
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

/// Peer credentials from LOCAL_PEERCRED: uid, effective gid, the full
/// group set (effective gid first, then supplementary groups) and pid.
/// Superset of getpeereid, which exposes no supplementary groups; T258
/// moved the IPC gate to LOCAL_PEERCRED for exactly that reason.
pub const PeerCred = struct {
    uid: posix.uid_t,
    gid: posix.gid_t,
    groups: [16]posix.gid_t,
    group_count: u8,
    pid: posix.pid_t,
    /// The peer may have had more supplementary groups than the 16 the
    /// kernel copies (cru2x caps cr_ngroups at XU_NGROUPS, so exactly 16
    /// cannot be told apart from more). Callers must fail closed.
    truncated: bool,
};

/// struct xucred (sys/ucred.h): cr_version, cr_uid, cr_ngroups counting
/// cr_gid, cr_groups[16] with the effective gid first, then a union of
/// an unused pointer and cr_pid.
const xucred = extern struct {
    version: c_uint,
    uid: posix.uid_t,
    ngroups: c_short,
    _pad: u16 = 0,
    groups: [16]posix.gid_t,
    pid_union: extern union { unused: ?*anyopaque, pid: posix.pid_t },
};

comptime {
    std.debug.assert(@offsetOf(xucred, "groups") == 12);
    std.debug.assert(@offsetOf(xucred, "pid_union") == 80);
    std.debug.assert(@sizeOf(xucred) == 88);
}

const xucred_version: c_uint = 0;

/// LOCAL_PEERCRED for an accepted Unix-domain socket. The option lives at
/// local(4) level 0, not SOL_SOCKET. Returns NotUnixSocket on any other
/// fd or socket type, and rejects an unexpected xucred layout version.
/// `errno_out`, when given, carries the raw errno on any failure.
pub fn peerCred(fd: posix.fd_t, errno_out: ?*u32) error{ NotUnixSocket, Unexpected }!PeerCred {
    var cred: xucred = undefined;
    var len: posix.socklen_t = @sizeOf(xucred);
    if (std.c.getsockopt(fd, local_level, so_local_peercred, &cred, &len) != 0) {
        const e = posix.errno(-1);
        if (errno_out) |out| out.* = @intFromEnum(e);
        return switch (e) {
            .INVAL, .OPNOTSUPP, .NOTSOCK => error.NotUnixSocket,
            else => error.Unexpected,
        };
    }
    // cru2x caps cr_ngroups at XU_NGROUPS=16 (kern_prot.c), so the count
    // never exceeds 16 and a count of exactly 16 may be a truncated set.
    return credFromXucred(cred) orelse {
        if (errno_out) |out| out.* = @intFromEnum(posix.E.PROTO);
        return error.Unexpected;
    };
}

fn credFromXucred(cred: xucred) ?PeerCred {
    if (cred.version != xucred_version or cred.ngroups < 0 or cred.ngroups > 1024)
        return null;
    return .{
        .uid = cred.uid,
        .gid = if (cred.ngroups > 0) cred.groups[0] else 0,
        .groups = cred.groups,
        .group_count = @intCast(@min(cred.ngroups, 16)),
        .pid = cred.pid_union.pid,
        .truncated = cred.ngroups >= 16,
    };
}

const so_local_peercred: c_int = 0x0001; // LOCAL_PEERCRED on FreeBSD
const local_level: c_int = 0; // local(4) getsockopt level

/// Owns one listening fd on a Loop. The consumer calls `acceptNext` on each
/// `.readable` event and drains until a terminal outcome (drained,
/// batch_limit, paused, peer_rejected or an error).
pub const Listener = struct {
    loop: *Loop,
    handle: Handle,
    family: Family,
    accepted_this_pass: u16,
    aborted: u64, // ECONNABORTED/EPROTO: peer reset before accept
    pause_reason: PauseReason,
    fallback_timer: ?loop_mod.TimerId, // armed for ENFILE/ENOBUFS/ENOMEM
    /// Pauses whose fallback could not be scheduled (timer table full):
    /// the listener still resumes on a close, but nothing wakes it
    /// otherwise. Visible so a starved table is observable.
    fallback_lost: u32,
    fallback_resume_ms: u64,

    pub const Family = enum { tcp, unix };
    /// Max accepts per readable pass; the listener requeues for the rest.
    pub const accept_batch_max = 256;
    pub const fallback_resume_ms_default: u64 = 250;

    pub const PauseReason = enum { emfile, enfile, enobufs, enomem };

    pub const AttachError = loop_mod.AttachError || error{Unexpected};
    pub const AcceptError = error{ ListenerInvalid, Unexpected };

    pub const AcceptOutcome = union(enum) {
        accepted: Accepted, // fd is O_NONBLOCK | O_CLOEXEC, owned by the caller
        drained, // EAGAIN
        batch_limit, // accept_batch_max reached; listener requeued
        paused: PauseReason, // EMFILE/ENFILE/ENOBUFS/ENOMEM: read disabled
        peer_rejected: u32, // unix: LOCAL_PEERCRED failed (errno); fd closed
    };

    pub const Peer = union(enum) { ip: std.net.Address, unix: PeerCred };
    pub const Accepted = struct {
        fd: posix.fd_t,
        peer: Peer,
    };

    /// Takes ownership of a listening fd (from bindTcp/bindUnix or inherited
    /// from the master); sets O_NONBLOCK and FD_CLOEXEC on it, then registers
    /// read interest with consumer token `ctx`.
    pub fn attach(
        self: *Listener,
        loop: *Loop,
        fd: posix.fd_t,
        ctx: Token,
        family: Family,
    ) AttachError!void {
        // An adopted fd (master-spawned listener) may arrive blocking and
        // inheritable; accept must never block the loop.
        try adoptFlags(fd);
        const handle = try loop.attach(fd, ctx, .{ .read = true });
        self.* = .{
            .loop = loop,
            .handle = handle,
            .family = family,
            .accepted_this_pass = 0,
            .aborted = 0,
            .fallback_lost = 0,
            .pause_reason = .emfile,
            .fallback_timer = null,
            .fallback_resume_ms = fallback_resume_ms_default,
        };
    }

    /// One accept step: an `accepted` outcome per pending connection,
    /// `drained` at EAGAIN, `batch_limit` after accept_batch_max in one pass
    /// (the listener requeues itself), `paused` on descriptor exhaustion
    /// (read interest resumes on a close or the fallback deadline),
    /// `peer_rejected` when LOCAL_PEERCRED fails on a unix accept. EINTR
    /// retries, ECONNABORTED/EPROTO are counted and skipped, and every other
    /// errno is an explicit outcome or error; nothing spins.
    pub fn acceptNext(self: *Listener) AcceptError!AcceptOutcome {
        if (self.loop.isPaused(self.handle)) {
            self.accepted_this_pass = 0;
            return .{ .paused = self.pause_reason };
        }
        // The pause ended through a close or a resume: the fallback deadline
        // is no longer needed; cancel it so it cannot resume a later pause
        // early (cancel returns false once it already fired).
        if (self.fallback_timer) |t| {
            _ = self.loop.cancelTimer(t);
            self.fallback_timer = null;
        }
        if (self.accepted_this_pass >= accept_batch_max) {
            // Come back for the rest after one pass so a busy listener
            // cannot starve other handles.
            self.accepted_this_pass = 0;
            self.loop.requeue(self.handle, .read) catch return error.Unexpected;
            return .batch_limit;
        }
        const lfd = self.loop.fdOf(self.handle) orelse return error.ListenerInvalid;
        while (true) {
            var sa: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
            var salen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
            const rc = std.c.accept4(lfd, @ptrCast(&sa), &salen, accept_flags);
            if (rc < 0) {
                switch (posix.errno(rc)) {
                    .AGAIN => {
                        self.accepted_this_pass = 0;
                        return .drained;
                    },
                    .INTR => continue,
                    .CONNABORTED, .PROTO => {
                        self.aborted += 1;
                        continue;
                    },
                    .MFILE => return self.pause(.emfile),
                    .NFILE => return self.pause(.enfile),
                    .NOBUFS => return self.pause(.enobufs),
                    .NOMEM => return self.pause(.enomem),
                    .BADF, .NOTSOCK, .INVAL, .OPNOTSUPP => return error.ListenerInvalid,
                    else => return error.Unexpected,
                }
            }
            self.accepted_this_pass += 1;
            const fd: posix.fd_t = @intCast(rc);
            if (self.family == .unix) {
                var cred_errno: u32 = 0;
                const cred = peerCred(fd, &cred_errno) catch {
                    posix.close(fd);
                    self.accepted_this_pass = 0;
                    return .{ .peer_rejected = cred_errno };
                };
                return .{ .accepted = .{ .fd = fd, .peer = .{ .unix = cred } } };
            }
            return .{ .accepted = .{ .fd = fd, .peer = .{ .ip = peerAddress(&sa) } } };
        }
    }

    fn pause(self: *Listener, reason: PauseReason) AcceptError!AcceptOutcome {
        self.pause_reason = reason;
        // The accept pass is over: the next pass gets the whole budget.
        self.accepted_this_pass = 0;
        self.loop.pauseReadUntilClose(self.handle) catch |err| return switch (err) {
            error.StaleHandle => error.ListenerInvalid,
            error.PausedListFull => error.Unexpected,
        };
        // Every exhaustion pause gets the fallback deadline: relief may come
        // from a close on another loop's thread (thread-per-core model), so
        // this loop cannot rely on its own close() path. The TimerId, not a
        // ctx sentinel, identifies it in onDeadline.
        const ms = self.fallback_resume_ms;
        self.fallback_timer = self.loop.scheduleIn(ms, .none) catch blk: {
            self.fallback_lost += 1;
            break :blk null;
        };
        return .{ .paused = reason };
    }

    /// Route a `.deadline` event: returns true when it was this listener's
    /// fallback resume (the pause is lifted here). The consumer calls this
    /// on every deadline event; unrelated deadlines return false.
    pub fn onDeadline(self: *Listener, d: loop_mod.Deadline) bool {
        const t = self.fallback_timer orelse return false;
        if (!d.timer.eql(t)) return false;
        self.fallback_timer = null;
        self.loop.resumePaused(self.handle) catch |err| switch (err) {
            error.StaleHandle => {},
        };
        return true;
    }

    pub fn close(self: *Listener) void {
        self.loop.close(self.handle) catch |err| switch (err) {
            error.StaleHandle => {},
        };
    }
};

const accept_flags: c_uint = posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC;
const fd_cloexec: c_int = 1; // FD_CLOEXEC
const o_nonblock: c_int = 0x4; // O_NONBLOCK

fn adoptFlags(fd: posix.fd_t) error{Unexpected}!void {
    if (std.c.fcntl(fd, posix.F.SETFD, fd_cloexec) != 0) return error.Unexpected;
    const fl = std.c.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
    if (fl < 0) return error.Unexpected;
    if (fl & o_nonblock == 0) {
        if (std.c.fcntl(fd, posix.F.SETFL, fl | o_nonblock) != 0) return error.Unexpected;
    }
}

fn peerAddress(sa: *const posix.sockaddr.storage) std.net.Address {
    const base: *const posix.sockaddr = @ptrCast(@alignCast(sa));
    return switch (base.family) {
        posix.AF.INET6 => .{ .in6 = .{
            .sa = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(sa))).*,
        } },
        else => .{ .in = .{ .sa = @as(*const posix.sockaddr.in, @ptrCast(@alignCast(sa))).* } },
    };
}

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

const AcceptDrain = struct {
    n: usize = 0,
    last: Listener.AcceptOutcome = .drained,
    last_peer: ?Listener.Peer = null,

    /// acceptNext() until a terminal outcome; accepted fds land in `fds`.
    fn drain(
        self: *AcceptDrain,
        l: *Listener,
        fds: []posix.fd_t,
    ) Listener.AcceptError!Listener.AcceptOutcome {
        self.n = 0;
        while (true) {
            const out = try l.acceptNext();
            self.last = out;
            switch (out) {
                .accepted => |a| {
                    fds[self.n] = a.fd;
                    self.last_peer = a.peer;
                    self.n += 1;
                },
                else => return out,
            }
        }
    }
};

test "bindTcp: listener accepts a non-blocking connection" {
    var loop = try testLoop();
    defer loop.deinit(std.testing.allocator);

    const lfd = try bindTcp(&.{ .address = "127.0.0.1", .port = 0 });
    // Created with SOCK_CLOEXEC: no exec may ever inherit the listener.
    const fd_flags = try posix.fcntl(lfd, posix.F.GETFD, 0);
    try std.testing.expect(fd_flags & posix.FD_CLOEXEC != 0);
    const bound = try boundAddr(lfd);

    var listener: Listener = undefined;
    try listener.attach(&loop, lfd, test_ctx, .tcp);
    var accepted: [8]posix.fd_t = .{-1} ** 8;
    defer for (accepted) |fd| {
        if (fd >= 0) posix.close(fd);
    };

    const cfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(cfd);
    try posix.connect(cfd, @ptrCast(&bound), @sizeOf(posix.sockaddr.in));

    try loop.wait();
    const ev = loop.next().?;
    try std.testing.expect(ev == .readable);
    try std.testing.expect(ev.readable.handle.eql(listener.handle));

    var d: AcceptDrain = .{};
    try std.testing.expect(try d.drain(&listener, &accepted) == .drained);
    try std.testing.expectEqual(@as(usize, 1), d.n);
    const peer = d.last_peer.?;
    try std.testing.expect(peer == .ip);
    var caddr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    var clen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    try std.testing.expectEqual(0, std.c.getsockname(cfd, @ptrCast(&caddr), &clen));
    const cs: *posix.sockaddr.in = @ptrCast(@alignCast(&caddr));
    try std.testing.expect(peer.ip.in.sa.addr == cs.addr); // peer address is the client's

    // The accepted fd is non-blocking (empty read: WouldBlock) and inherits
    // TCP_NODELAY from the listener through the syncache.
    var buf: [4]u8 = undefined;
    try std.testing.expectError(error.WouldBlock, posix.read(accepted[0], &buf));
    var nd: c_int = 0;
    var ndlen: posix.socklen_t = @sizeOf(c_int);
    const real_nodelay: c_int = 1; // TCP_NODELAY; do not share the setup const
    try std.testing.expectEqual(
        0,
        std.c.getsockopt(accepted[0], std.c.IPPROTO.TCP, real_nodelay, &nd, &ndlen),
    );
    try std.testing.expect(nd != 0);
}

test "bindTcp: two listeners share the port with REUSEPORT_LB" {
    const lfd_a = try bindTcp(&.{ .address = "127.0.0.1", .port = 0 });
    defer posix.close(lfd_a);
    const bound = try boundAddr(lfd_a);
    const port = @as(*const posix.sockaddr.in, @ptrCast(@alignCast(&bound))).port;
    const lfd_b = try bindTcp(&.{ .address = "127.0.0.1", .port = std.mem.bigToNative(u16, port) });
    defer posix.close(lfd_b);
}

test "peerCred: a full XU_NGROUPS set is flagged possibly truncated" {
    // The kernel caps cr_ngroups at 16, so exactly-16 may hide more.
    var xc: xucred = .{
        .version = xucred_version,
        .uid = 1001,
        .ngroups = 16,
        .groups = @splat(55),
        .pid_union = .{ .pid = 42 },
    };
    const pc = credFromXucred(xc).?;
    try std.testing.expectEqual(@as(u8, 16), pc.group_count);
    try std.testing.expect(pc.truncated);

    xc.ngroups = 15;
    const full = credFromXucred(xc).?;
    try std.testing.expectEqual(@as(u8, 15), full.group_count);
    try std.testing.expect(!full.truncated);
}

test "peerCred: a wrong xucred version is rejected" {
    // V06c: a mismatched layout version must not decode at all.
    const xc: xucred = .{
        .version = xucred_version + 1,
        .uid = 1001,
        .ngroups = 3,
        .groups = @splat(55),
        .pid_union = .{ .pid = 42 },
    };
    try std.testing.expect(credFromXucred(xc) == null);
}

test "bindTcp: IPv6 literal binds and accepts on ::1" {
    var loop = try testLoop();
    defer loop.deinit(std.testing.allocator);

    const lfd = try bindTcp(&.{ .address = "::1", .port = 0 });
    // V6ONLY is on by default so the v6 listener never captures v4 traffic.
    var v6only: c_int = 0;
    var v6len: posix.socklen_t = @sizeOf(c_int);
    try std.testing.expectEqual(
        0,
        std.c.getsockopt(lfd, std.c.IPPROTO.IPV6, 27, &v6only, &v6len), // IPV6_V6ONLY
    );
    try std.testing.expect(v6only != 0);
    const bound = try boundAddr(lfd);
    var listener: Listener = undefined;
    try listener.attach(&loop, lfd, test_ctx, .tcp);

    const cfd = try posix.socket(posix.AF.INET6, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(cfd);
    try posix.connect(cfd, @ptrCast(&bound), @sizeOf(posix.sockaddr.in6));

    try loop.wait();
    const ev = loop.next().?;
    try std.testing.expect(ev == .readable);
    var accepted: [4]posix.fd_t = .{-1} ** 4;
    defer for (accepted) |fd| {
        if (fd >= 0) posix.close(fd);
    };
    var d: AcceptDrain = .{};
    const out = try d.drain(&listener, &accepted);
    try std.testing.expectEqual(@as(usize, 1), d.n);
    try std.testing.expect(out == .drained);
}

test "bindTcp: v6_only false leaves the v6 listener dual-stack" {
    // FreeBSD defaults IPV6_V6ONLY on; the option must clear it explicitly.
    const lfd = try bindTcp(&.{ .address = "::1", .port = 0, .v6_only = false });
    defer posix.close(lfd);
    var v6only: c_int = 1;
    var v6len: posix.socklen_t = @sizeOf(c_int);
    try std.testing.expectEqual(
        0,
        std.c.getsockopt(lfd, std.c.IPPROTO.IPV6, 27, &v6only, &v6len), // IPV6_V6ONLY
    );
    try std.testing.expectEqual(@as(c_int, 0), v6only);
}

test "bindTcp: a non-local address reports AddressNotAvailable" {
    try std.testing.expectError(
        error.AddressNotAvailable,
        bindTcp(&.{ .address = "192.0.2.1", .port = 0 }), // TEST-NET-1, never local
    );
}

test "bindTcp: a DNS name is rejected, a bad literal is rejected" {
    try std.testing.expectError(error.InvalidAddress, bindTcp(&.{
        .address = "localhost",
        .port = 80,
    }));
    try std.testing.expectError(error.InvalidAddress, bindTcp(&.{
        .address = "999.0.0.1",
        .port = 80,
    }));
}

test "bindUnix: accepts and reports LOCAL_PEERCRED" {
    var loop = try testLoop();
    defer loop.deinit(std.testing.allocator);

    var pbuf: [64]u8 = undefined;
    const path = testSockPath(&pbuf, "test");
    posix.unlink(path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    defer posix.unlink(path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => unreachable,
    };
    const lfd = try bindUnix(&.{ .path = path, .mode = 0o600 });
    var listener: Listener = undefined;
    try listener.attach(&loop, lfd, test_ctx, .unix);

    const cfd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(cfd);
    var un: posix.sockaddr.un = undefined;
    un.family = posix.AF.UNIX;
    @memset(&un.path, 0);
    @memcpy(un.path[0..path.len], path);
    un.len = @intCast(@offsetOf(posix.sockaddr.un, "path") + path.len + 1);
    try posix.connect(cfd, @ptrCast(&un), @sizeOf(posix.sockaddr.un));

    try loop.wait();
    _ = loop.next();
    const out = try listener.acceptNext();
    const a = out.accepted;
    defer posix.close(a.fd);
    const cred = switch (a.peer) {
        .unix => |c| c,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(std.c.getuid(), cred.uid);
    try std.testing.expectEqual(getegid(), cred.gid);
    try std.testing.expect(cred.group_count >= 1);
    try std.testing.expectEqual(getegid(), cred.groups[0]);
    try std.testing.expectEqual(std.c.getpid(), cred.pid);

    // A TCP listener driven as family .unix fails LOCAL_PEERCRED on the
    // accepted socket and reports peer_rejected with the errno.
    const tlfd = try bindTcp(&.{ .address = "127.0.0.1", .port = 0 });
    const tbound = try boundAddr(tlfd);
    var tlistener: Listener = undefined;
    try tlistener.attach(&loop, tlfd, test_ctx, .unix);
    const tcfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(tcfd);
    try posix.connect(tcfd, @ptrCast(&tbound), @sizeOf(posix.sockaddr.in));
    try loop.wait();
    _ = loop.next();
    const rej = try tlistener.acceptNext();
    try std.testing.expect(rej == .peer_rejected);
    try std.testing.expect(rej.peer_rejected != 0);
}

extern "c" fn getegid() posix.gid_t;

/// Cwd-relative, pid-tagged unix socket path for tests: short enough for
/// sun_path and never tied to a user-specific directory.
fn testSockPath(buf: []u8, tag: []const u8) [:0]const u8 {
    return std.fmt.bufPrintZ(buf, "xn-{d}-{s}.sock", .{ std.c.getpid(), tag }) catch unreachable;
}

test "bindUnix: a stale socket path is reclaimed" {
    var pbuf: [64]u8 = undefined;
    const path = testSockPath(&pbuf, "stale");
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
    try std.testing.expectError(error.PathTooLong, bindUnix(&.{
        .path = long_path,
        .mode = 0o600,
    }));

    var pbuf: [64]u8 = undefined;
    const path = testSockPath(&pbuf, "live");
    const live = try bindUnix(&.{ .path = path, .mode = 0o640 });
    defer posix.close(live);
    defer posix.unlink(path) catch unreachable;
    // A listener already owns the path: the probe connects, so AddressInUse.
    try std.testing.expectError(error.AddressInUse, bindUnix(&.{ .path = path, .mode = 0o600 }));

    // The requested mode is on the socket before listen returns it.
    var st: posix.Stat = undefined;
    try std.testing.expectEqual(0, std.c.stat(path, &st));
    try std.testing.expectEqual(@as(u32, 0o640), @as(u32, @intCast(st.mode & 0o777)));

    var rbuf: [64]u8 = undefined;
    const reg = testSockPath(&rbuf, "regular");
    {
        const f = try std.fs.cwd().createFile(reg, .{});
        f.close();
    }
    defer std.fs.cwd().deleteFile(reg) catch unreachable;
    try std.testing.expectError(error.NotASocket, bindUnix(&.{ .path = reg, .mode = 0o600 }));
}

test "Listener: bad descriptor and non-listener surface as ListenerInvalid" {
    var loop = try testLoop();
    defer loop.deinit(std.testing.allocator);

    const lfd = try bindTcp(&.{ .address = "127.0.0.1", .port = 0 });
    var listener: Listener = undefined;
    try listener.attach(&loop, lfd, test_ctx, .tcp);

    // /dev/null over the listen fd: ENOTSOCK is an error, never a panic.
    const devnull = try posix.open("/dev/null", .{ .ACCMODE = .RDWR }, 0);
    defer posix.close(devnull);
    try posix.dup2(devnull, lfd);
    try std.testing.expectError(error.ListenerInvalid, listener.acceptNext());

    // A valid but non-listening fd: accept4 gives EINVAL, same error.
    var pair: [2]posix.fd_t = undefined;
    const sp_flags = posix.SOCK.STREAM | posix.SOCK.CLOEXEC;
    try std.testing.expectEqual(0, std.c.socketpair(posix.AF.UNIX, sp_flags, 0, &pair));
    defer posix.close(pair[0]);
    var listener2: Listener = undefined;
    try listener2.attach(&loop, pair[1], test_ctx, .tcp);
    try std.testing.expectError(error.ListenerInvalid, listener2.acceptNext());
}

test "Listener: accept_batch_max requeues for the rest of the backlog" {
    // This test needs ~2*total descriptors on top of whatever earlier
    // tests still hold, which can exceed the default soft NOFILE under
    // load. At the cap socket()/accept() returns EMFILE, the listener
    // pauses its read interest, and the queue fills while the loop
    // sleeps forever. Raise the soft cap to the hard one so EMFILE
    // cannot pause the drain.
    const rl = try posix.getrlimit(.NOFILE);
    if (rl.cur < rl.max) try posix.setrlimit(.NOFILE, .{ .cur = rl.max, .max = rl.max });

    var loop = try testLoop();
    defer loop.deinit(std.testing.allocator);

    const lfd = try bindTcp(&.{ .address = "127.0.0.1", .port = 0 });
    const bound = try boundAddr(lfd);
    var listener: Listener = undefined;
    try listener.attach(&loop, lfd, test_ctx, .tcp);

    const total = Listener.accept_batch_max + 8;
    var cfds: [total]posix.fd_t = .{-1} ** total;
    defer for (cfds) |fd| {
        if (fd >= 0) posix.close(fd);
    };
    for (&cfds) |*cfd| {
        cfd.* = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
        try posix.connect(cfd.*, @ptrCast(&bound), @sizeOf(posix.sockaddr.in));
    }

    var accepted: [total]posix.fd_t = .{-1} ** total;
    defer for (accepted) |fd| {
        if (fd >= 0) posix.close(fd);
    };

    // A deadline, not a pass count: under load the tail of the backlog can
    // complete late, and a bare wait() sleeps forever because the loop only
    // wakes on I/O. The deadline fails the test instead of hanging the suite.
    const deadline = try loop.scheduleIn(30_000, test_ctx);
    var got: usize = 0;
    var saw_batch_limit = false;
    while (got < total) {
        try loop.wait();
        while (loop.next()) |ev| {
            switch (ev) {
                .readable => {
                    while (true) {
                        const out = try listener.acceptNext();
                        switch (out) {
                            .accepted => |a| {
                                accepted[got] = a.fd;
                                got += 1;
                            },
                            .batch_limit => saw_batch_limit = true,
                            else => {},
                        }
                        if (out != .accepted) break;
                    }
                },
                .deadline => |d| {
                    if (d.timer.eql(deadline)) {
                        std.debug.print(
                            "accept_batch_max backlog: {d}/{d} connects arrived before the deadline\n",
                            .{ got, total },
                        );
                        return error.ConnectBacklogDeadline;
                    }
                    // The listener's own fallback deadline: let it lift a
                    // transient pause (ENOBUFS and friends) before ours ends.
                    _ = listener.onDeadline(d);
                },
                else => {},
            }
        }
    }
    _ = loop.cancelTimer(deadline);
    try std.testing.expect(saw_batch_limit);
    try std.testing.expectEqual(total, got);
}

test "Listener: an adopted blocking fd gets O_NONBLOCK and FD_CLOEXEC" {
    var loop = try testLoop();
    defer loop.deinit(std.testing.allocator);

    // A bare blocking listener fd, as one inherited from the master.
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    var listener: Listener = undefined;
    try listener.attach(&loop, fd, test_ctx, .tcp);

    const fl = std.c.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
    try std.testing.expect(fl >= 0 and fl & o_nonblock != 0);
    const fdf = std.c.fcntl(fd, posix.F.GETFD, @as(c_int, 0));
    try std.testing.expect(fdf >= 0 and fdf & fd_cloexec != 0);
}

test "Listener: onDeadline drives the fallback resume" {
    var loop = try testLoop();
    defer loop.deinit(std.testing.allocator);

    const lfd = try bindTcp(&.{ .address = "127.0.0.1", .port = 0 });
    var listener: Listener = undefined;
    try listener.attach(&loop, lfd, test_ctx, .tcp);

    // Pause the read interest and arm the fallback the way pause() does.
    try loop.pauseReadUntilClose(listener.handle);
    listener.fallback_timer = try loop.scheduleIn(1, .none);
    try std.testing.expect(loop.isPaused(listener.handle));

    try loop.wait();
    const ev = loop.next().?;
    try std.testing.expect(ev == .deadline);
    try std.testing.expect(listener.onDeadline(ev.deadline));
    try std.testing.expect(!loop.isPaused(listener.handle));
    try std.testing.expect(listener.fallback_timer == null);

    // An unrelated deadline is not claimed.
    const other = try loop.scheduleIn(1, .none);
    try loop.wait();
    const ev2 = loop.next().?;
    try std.testing.expect(ev2 == .deadline);
    try std.testing.expect(ev2.deadline.timer.eql(other));
    try std.testing.expect(!listener.onDeadline(ev2.deadline));
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
    var listener: Listener = undefined;
    listener.attach(&loop, lfd, test_ctx, .tcp) catch posix.exit(7);

    // Spare handle the child closes to free a descriptor for the resume.
    var pair: [2]posix.fd_t = undefined;
    const sp_nb = posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC;
    if (std.c.socketpair(posix.AF.UNIX, sp_nb, 0, &pair) != 0) posix.exit(8);
    const spare = loop.attach(pair[1], test_ctx, .{ .read = true }) catch posix.exit(9);
    posix.close(pair[0]);

    const bound = boundAddr(lfd) catch posix.exit(10);
    const st_cx = posix.SOCK.STREAM | posix.SOCK.CLOEXEC;
    const cfd = posix.socket(posix.AF.INET, st_cx, 0) catch posix.exit(11);
    posix.connect(cfd, @ptrCast(&bound), @sizeOf(posix.sockaddr.in)) catch posix.exit(12);

    const lim2: posix.rlimit = .{ .cur = 4, .max = rl.max };
    posix.setrlimit(.NOFILE, lim2) catch posix.exit(13);

    loop.wait() catch posix.exit(14);
    var n: usize = 0;
    var paused = false;
    while (loop.next()) |ev| {
        if (ev == .readable) {
            while (true) {
                const out = listener.acceptNext() catch posix.exit(24);
                switch (out) {
                    .accepted => |a| {
                        posix.close(a.fd);
                        n += 1;
                    },
                    .paused => {
                        paused = true;
                        break;
                    },
                    else => break,
                }
            }
        }
    }
    if (n != 0) posix.exit(15); // accept must have failed
    if (!paused) posix.exit(25);
    if (!loop.isPaused(listener.handle)) posix.exit(16);
    // The EMFILE pause also arms the fallback deadline: relief may come from
    // a close on another loop's thread.
    if (listener.fallback_timer == null) posix.exit(27);

    // Back under the quota (a soft limit may be raised to the hard one), the
    // close frees a descriptor and resumes the listener.
    const back: posix.rlimit = .{ .cur = rl.max, .max = rl.max };
    posix.setrlimit(.NOFILE, back) catch posix.exit(21);
    loop.close(spare) catch posix.exit(17);
    if (loop.isPaused(listener.handle)) posix.exit(18);

    // A fresh connection proves read interest fired again after the resume.
    const st_cx2 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC;
    const cfd2 = posix.socket(posix.AF.INET, st_cx2, 0) catch posix.exit(22);
    posix.connect(cfd2, @ptrCast(&bound), @sizeOf(posix.sockaddr.in)) catch posix.exit(23);
    loop.wait() catch posix.exit(19);
    while (loop.next()) |ev| {
        if (ev == .readable) {
            while (true) {
                const out = listener.acceptNext() catch posix.exit(26);
                switch (out) {
                    .accepted => |a| {
                        posix.close(a.fd);
                        n += 1;
                    },
                    else => break,
                }
            }
        }
    }
    // The EMFILE'd connection stayed in the backlog: it and the fresh one
    // are both accepted after the resume.
    if (n != 2) posix.exit(20);
    posix.exit(0);
}

test "Listener: paused resets the pass's accept budget" {
    // A pause mid-drain must not shrink the next pass's batch budget.
    var loop = try testLoop();
    defer loop.deinit(std.testing.allocator);

    const lfd = try bindTcp(&.{ .address = "127.0.0.1", .port = 0 });
    const bound = try boundAddr(lfd);
    var listener: Listener = undefined;
    try listener.attach(&loop, lfd, test_ctx, .tcp);

    const cfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(cfd);
    try posix.connect(cfd, @ptrCast(&bound), @sizeOf(posix.sockaddr.in));
    try loop.wait();
    while (loop.next()) |_| {}

    const out = try listener.acceptNext();
    try std.testing.expect(out == .accepted);
    posix.close(out.accepted.fd);
    try std.testing.expectEqual(@as(u16, 1), listener.accepted_this_pass);

    try loop.pauseReadUntilClose(listener.handle);
    try std.testing.expect(try listener.acceptNext() == .paused);
    try std.testing.expectEqual(@as(u16, 0), listener.accepted_this_pass);
}

test "Listener: pause and peer_rejected reset the accept budget" {
    var loop = try testLoop();
    defer loop.deinit(std.testing.allocator);

    const lfd = try bindTcp(&.{ .address = "127.0.0.1", .port = 0 });
    const bound = try boundAddr(lfd);
    var listener: Listener = undefined;
    try listener.attach(&loop, lfd, test_ctx, .tcp);

    const cfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(cfd);
    try posix.connect(cfd, @ptrCast(&bound), @sizeOf(posix.sockaddr.in));
    const c2 = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(c2);
    try posix.connect(c2, @ptrCast(&bound), @sizeOf(posix.sockaddr.in));
    try loop.wait();
    while (loop.next()) |_| {}

    // pause(): an accept-errno pause starts a fresh pass, budget included.
    const out = try listener.acceptNext();
    try std.testing.expect(out == .accepted);
    posix.close(out.accepted.fd);
    _ = try listener.pause(.emfile);
    try std.testing.expectEqual(@as(u16, 0), listener.accepted_this_pass);
    try loop.resumePaused(listener.handle);

    // peer_rejected: a TCP accepted fd cannot carry unix credentials, so
    // a listener declared unix reports rejection and resets the budget.
    listener.family = .unix;
    const out2 = try listener.acceptNext();
    try std.testing.expect(out2 == .peer_rejected);
    try std.testing.expectEqual(@as(u16, 0), listener.accepted_this_pass);
}

test "Listener: a close-resumed pause cancels the armed fallback" {
    // Without the cancel a stale deadline fires later and resumes whatever
    // pause is armed then (V08b).
    var loop = try testLoop();
    defer loop.deinit(std.testing.allocator);

    const lfd = try bindTcp(&.{ .address = "127.0.0.1", .port = 0 });
    var listener: Listener = undefined;
    try listener.attach(&loop, lfd, test_ctx, .tcp);

    var pair: [2]posix.fd_t = undefined;
    const sp_flags = posix.SOCK.STREAM | posix.SOCK.CLOEXEC;
    try std.testing.expectEqual(0, std.c.socketpair(posix.AF.UNIX, sp_flags, 0, &pair));
    const h = try loop.attach(pair[0], test_ctx, .{ .read = true });
    posix.close(pair[1]);

    try loop.pauseReadUntilClose(listener.handle);
    listener.fallback_timer = try loop.scheduleIn(60000, .none);
    try loop.close(h); // a close on this loop resumes the pause

    _ = listener.acceptNext() catch {}; // preamble cancels the fallback
    try std.testing.expect(listener.fallback_timer == null);
    try std.testing.expectEqual(@as(usize, 0), loop.wheel.entries.count());
}

test "Listener: a full timer table is counted, not swallowed" {
    var loop = try testLoop();
    defer loop.deinit(std.testing.allocator);

    const lfd = try bindTcp(&.{ .address = "127.0.0.1", .port = 0 });
    var listener: Listener = undefined;
    try listener.attach(&loop, lfd, test_ctx, .tcp);

    // Fill the wheel so the fallback deadline cannot be scheduled.
    for (0..16) |_| {
        _ = try loop.scheduleIn(60000, .none);
    }
    const out = try listener.pause(.emfile);
    try std.testing.expect(out == .paused);
    try std.testing.expect(listener.fallback_timer == null);
    try std.testing.expectEqual(@as(u32, 1), listener.fallback_lost);
}

test "Listener: onDeadline claims only the fallback timer" {
    // An unrelated deadline while the fallback is armed must not lift the
    // pause or consume the TimerId (V09).
    var loop = try testLoop();
    defer loop.deinit(std.testing.allocator);

    const lfd = try bindTcp(&.{ .address = "127.0.0.1", .port = 0 });
    var listener: Listener = undefined;
    try listener.attach(&loop, lfd, test_ctx, .tcp);
    try loop.pauseReadUntilClose(listener.handle);

    const fallback = try loop.scheduleIn(60000, .none);
    listener.fallback_timer = fallback;
    const other = try loop.scheduleIn(60000, .none);

    try std.testing.expect(!listener.onDeadline(.{ .timer = other, .ctx = .none }));
    try std.testing.expect(listener.fallback_timer != null);
    try std.testing.expect(listener.onDeadline(.{ .timer = fallback, .ctx = .none }));
    try std.testing.expect(listener.fallback_timer == null);
}

test "Listener: EMFILE relieved outside the loop resumes on the fallback" {
    // No close on this loop frees the descriptor; only the 250 ms fallback
    // deadline can lift the pause.
    const pid = try posix.fork();
    if (pid == 0) {
        childEmfileOutsideLoop();
        posix.exit(1);
    }
    const res = posix.waitpid(pid, 0);
    try std.testing.expectEqual(@as(u32, 0), @as(u32, @intCast(res.status)));
}

fn childEmfileOutsideLoop() void {
    const rl = posix.getrlimit(.NOFILE) catch posix.exit(2);

    var loop = testLoop() catch posix.exit(4);
    const lfd = bindTcp(&.{ .address = "127.0.0.1", .port = 0 }) catch posix.exit(6);
    var listener: Listener = undefined;
    listener.attach(&loop, lfd, test_ctx, .tcp) catch posix.exit(7);

    const bound = boundAddr(lfd) catch posix.exit(10);
    const st_cx = posix.SOCK.STREAM | posix.SOCK.CLOEXEC;
    const cfd = posix.socket(posix.AF.INET, st_cx, 0) catch posix.exit(11);
    posix.connect(cfd, @ptrCast(&bound), @sizeOf(posix.sockaddr.in)) catch posix.exit(12);

    const lim2: posix.rlimit = .{ .cur = 4, .max = rl.max };
    posix.setrlimit(.NOFILE, lim2) catch posix.exit(13);

    loop.wait() catch posix.exit(14);
    var paused = false;
    while (loop.next()) |ev| {
        if (ev == .readable) {
            while (true) {
                const out = listener.acceptNext() catch posix.exit(24);
                switch (out) {
                    .accepted => |a| posix.close(a.fd),
                    .paused => {
                        paused = true;
                        break;
                    },
                    else => break,
                }
            }
        }
    }
    if (!paused) posix.exit(25);
    if (!loop.isPaused(listener.handle)) posix.exit(16);
    if (listener.fallback_timer == null) posix.exit(27);

    // Descriptors free up with no close on this loop: raise the quota so the
    // EMFILE condition is gone, but leave the listener paused. Only the
    // fallback deadline can resume it.
    const back: posix.rlimit = .{ .cur = rl.max, .max = rl.max };
    posix.setrlimit(.NOFILE, back) catch posix.exit(21);

    const watchdog = loop.scheduleIn(2000, test_ctx) catch posix.exit(22);
    var resumed = false;
    var accepted = false;
    while (!(resumed and accepted)) {
        loop.wait() catch posix.exit(19);
        while (loop.next()) |ev| {
            switch (ev) {
                .deadline => |d| {
                    if (d.timer.eql(watchdog)) posix.exit(20); // never resumed
                    if (listener.onDeadline(d)) resumed = true;
                },
                .readable => {
                    const out = listener.acceptNext() catch posix.exit(26);
                    if (out == .accepted) {
                        posix.close(out.accepted.fd);
                        accepted = true;
                    }
                },
                else => {},
            }
        }
    }
    posix.exit(0);
}
