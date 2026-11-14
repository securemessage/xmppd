//! # Process identity and pid files — xmppd master
//!
//! Kernel facts for child and orphan processes (kern.proc.pid kinfo_proc),
//! the `{run_dir}/{name}.pid` child pid files, and the identity-checked
//! orphan kill for children a dead master left behind (T259).
//!
//! A child pid file holds one line "PID START_SEC COMMBASE". START_SEC is
//! the process's kernel start time (ki_start.tv_sec): pid numbers recycle,
//! so a stale pid file can only name a victim when start time and comm
//! also match, and the victim must be reparented to init.

const std = @import("std");

const posix = std.posix;

const log = std.log.scoped(.master);

/// Build `{run_dir}/{file}` into `buf` for the child pid-file paths
/// (T259: nothing under /var/run/xmppd is hardcoded anymore).
pub fn pidFilePath(buf: []u8, run_dir: []const u8, file: []const u8) ![]const u8 {
    if (run_dir.len + 1 + file.len > buf.len) return error.PathTooLong;
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ run_dir, file }) catch unreachable;
}

/// The child's kernel-reported start time in seconds, or null when the pid
/// has no kinfo. writeChildPid records 0 for null; a stored 0 never matches
/// a live process's ki_start, so the orphan-kill identity check spares it.
pub fn childStartSec(pid: posix.pid_t) ?i64 {
    var kp: KinfoProc = undefined;
    if (!lookupKinfoProc(pid, &kp)) return null;
    return kp.ki_start.tv_sec;
}

/// Write a child PID file for orphan detection on restart. Contents: a
/// line "PID START_TIME_SEC COMMBASE". Read by cleanupOrphan against live
/// kinfo_proc. (T259: run_dir-scoped, failures are logged.)
pub fn writeChildPid(path: []const u8, pid: posix.pid_t, base: []const u8) void {
    const file = std.fs.cwd().createFile(path, .{}) catch |err| {
        log.err("writeChildPid {s}: {}", .{ path, err });
        return;
    };
    defer file.close();
    const start_opt = childStartSec(pid);
    if (start_opt == null) {
        log.warn("writeChildPid {s}: no kinfo for pid {d}; recording start 0", .{ path, pid });
    }
    const start_sec = start_opt orelse 0;
    var buf: [80]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{d} {d} {s}\n", .{ pid, start_sec, base }) catch return;
    file.writeAll(s) catch |err| log.err("writeChildPid write {s}: {}", .{ path, err });
}

/// Remove a child PID file (called during clean shutdown).
pub fn removeChildPid(path: []const u8) void {
    std.fs.cwd().deleteFile(path) catch {};
}

/// FreeBSD kinfo_proc slice for the orphan sanity check (T259).
/// Layout probed from /usr/include/sys/user.h on 15.1 amd64: ppid at 76,
/// start at 336, comm at 447, sizeof 1088. Returned by the
/// { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid } sysctl.
/// Absent from zig's std.c for this version, so declare it.
extern "c" fn sysctl(mib: [*c]const c_int, miblen: c_uint, oldp: ?*anyopaque, oldlenp: ?*usize, newp: ?*const anyopaque, newlen: usize) c_int;
pub const KinfoProc = extern struct {
    _pad0: [76]u8,
    ki_ppid: c_int,
    _pad1: [256]u8,
    ki_start: extern struct { tv_sec: c_long, tv_usec: c_long },
    _pad2: [95]u8,
    ki_comm: [20]u8,
    _pad3: [621]u8,
};

comptime {
    std.debug.assert(@sizeOf(KinfoProc) == 1088);
    std.debug.assert(@offsetOf(KinfoProc, "ki_ppid") == 76);
    std.debug.assert(@offsetOf(KinfoProc, "ki_start") == 336);
    std.debug.assert(@offsetOf(KinfoProc, "ki_comm") == 447);
}

/// Live-process identity via kern.proc.pid.X (T259). Handles the
/// `/usr/include/sys/user.h` ABI directly rather than kern.proc.pathname:
/// PATHNAME returns ENOENT once a pkg upgrade has replaced the binary,
/// while ki_comm survives. ki_start distinguishes pid recycling.
pub fn lookupKinfoProc(pid: posix.pid_t, out: *KinfoProc) bool {
    // { CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1, pid }
    const mib = [_]c_int{ 1, 14, 1, pid };
    var len: usize = @sizeOf(KinfoProc);
    if (sysctl(&mib, mib.len, @ptrCast(out), &len, null, 0) != 0) return false;
    if (len < @offsetOf(KinfoProc, "ki_comm") + 20) return false;
    return true;
}

/// True when pid currently runs a binary whose comm starts with
/// expected_basename AND was started at expected_start_sec (epoch).
/// An orphan passes a further constraint handled in cleanupOrphan: the
/// process must have been reparented to init (ppid==1).
pub fn procMatchesIdentity(pid: posix.pid_t, expected_basename: []const u8, expected_start_sec: i64) bool {
    var kp: KinfoProc = undefined;
    if (!lookupKinfoProc(pid, &kp)) return false;
    if (kp.ki_start.tv_sec != expected_start_sec) return false;
    const comm = std.mem.sliceTo(&kp.ki_comm, 0);
    return std.mem.startsWith(u8, comm, expected_basename);
}

/// Identity triple-check for the orphan-kill: matches comm+start AND the
/// process is a child of init (ppid==1, orphans get reparented there).
pub fn procIsOrphanMatch(pid: posix.pid_t, expected_basename: []const u8, expected_start_sec: i64) bool {
    if (!procMatchesIdentity(pid, expected_basename, expected_start_sec)) return false;
    var kp: KinfoProc = undefined;
    if (!lookupKinfoProc(pid, &kp)) return false;
    return kp.ki_ppid == 1;
}

/// Bounded wait for a process's NOTE_EXIT on a private kqueue: orphan
/// grace deadlines ride EVFILT_PROC and a one-shot EVFILT_TIMER instead
/// of sleeps (T336). True when the exit arrived before the deadline.
fn waitExit(pid: posix.pid_t, ms: i64) bool {
    if (std.c.kill(pid, 0) != 0) return true;
    const kq = std.c.kqueue();
    if (kq < 0) return false;
    defer _ = std.c.close(kq);
    var changes = [_]std.c.Kevent{
        .{
            .ident = @intCast(pid),
            .filter = std.c.EVFILT.PROC,
            .flags = std.c.EV.ADD,
            .fflags = std.c.NOTE.EXIT,
            .data = 0,
            .udata = 0,
        },
        .{
            .ident = 1,
            .filter = std.c.EVFILT.TIMER,
            .flags = std.c.EV.ADD | std.c.EV.ONESHOT,
            .fflags = 0,
            .data = ms,
            .udata = 0,
        },
    };
    if (std.c.kevent(kq, &changes, changes.len, &changes, 0, null) < 0) return false;
    // Close the arm window: a death between the first check and the
    // registration is caught here instead of costing the deadline.
    if (std.c.kill(pid, 0) != 0) return true;
    var out: [2]std.c.Kevent = undefined;
    const n = std.c.kevent(kq, &[_]std.c.Kevent{}, 0, &out, out.len, null);
    if (n <= 0) return false;
    for (out[0..@intCast(n)]) |ev| {
        if (ev.filter == std.c.EVFILT.PROC) return true;
    }
    return false;
}

/// Check for an orphaned child process from a previous master instance.
/// PID files now live under run_dir and hold "PID START_SEC BASE". Kill
/// only when the live process still matches comm + start time + ppid==1,
/// so a recycled pid or a pkg-upgraded binary can never take a stray
/// SIGKILL (T259). identity is re-verified before SIGKILL too.
pub fn cleanupOrphan(path: []const u8, expected_basename: []const u8) void {
    cleanupOrphanTimed(path, expected_basename, 2_000, 100);
}

fn cleanupOrphanTimed(path: []const u8, expected_basename: []const u8, term_ms: i64, kill_ms: i64) void {
    const file = std.fs.cwd().openFile(path, .{}) catch return;
    defer file.close();

    var buf: [80]u8 = undefined;
    const n = posix.read(file.handle, &buf) catch return;
    if (n == 0) return;

    const trimmed = std.mem.trimRight(u8, buf[0..n], "\n \t\r");
    var parts = std.mem.tokenizeScalar(u8, trimmed, ' ');
    const pid = std.fmt.parseInt(posix.pid_t, parts.next() orelse return, 10) catch return;
    const start_field = parts.next() orelse "0"; // old one-field files: no start time
    const pid_start = std.fmt.parseInt(i64, start_field, 10) catch 0;
    if (pid <= 1) return;

    const alive = std.c.kill(pid, 0) == 0;
    if (!alive) {
        std.fs.cwd().deleteFile(path) catch {};
        return;
    }

    // Old-format one-line pid files have no start time: there is no safe
    // tie-break against a recycled pid, so clean up the file and move on.
    if (pid_start == 0) {
        log.warn("pid file {s} has no start time; cannot verify identity, NOT killing pid={d}", .{ path, pid });
        std.fs.cwd().deleteFile(path) catch {};
        return;
    }
    if (!procIsOrphanMatch(pid, expected_basename, pid_start)) {
        log.warn("pid file {s} references pid={d} that is not our child: NOT killing it", .{ path, pid });
        std.fs.cwd().deleteFile(path) catch {};
        return;
    }

    log.warn("killing orphaned child pid={d} from {s}", .{ pid, path });
    _ = std.c.kill(pid, posix.SIG.TERM);
    if (!waitExit(pid, term_ms)) {
        // Re-verify before the kill escalation: a fresh process on the
        // same pid number between SIGTERM and SIGKILL must not eat it.
        if (std.c.kill(pid, 0) == 0 and procIsOrphanMatch(pid, expected_basename, pid_start)) {
            log.warn("orphan pid={d} did not exit, sending SIGKILL", .{pid});
            _ = std.c.kill(pid, posix.SIG.KILL);
            _ = waitExit(pid, kill_ms);
        }
    }

    std.fs.cwd().deleteFile(path) catch {};
}

test "lookupKinfoProc/procMatchesIdentity: live process facts for self; identity mismatch rejected (T259)" {
    const self_pid = std.c.getpid();
    var kp: KinfoProc = undefined;
    try std.testing.expect(lookupKinfoProc(self_pid, &kp));

    // comm of this test binary is "master-tests".
    const comm = std.mem.sliceTo(&kp.ki_comm, 0);
    try std.testing.expectEqualStrings("master-tests", comm);
    try std.testing.expect(procMatchesIdentity(self_pid, "master-tests", kp.ki_start.tv_sec));
    try std.testing.expect(!procMatchesIdentity(self_pid, "xmppd-core", kp.ki_start.tv_sec));
    try std.testing.expect(!procMatchesIdentity(self_pid, "master-tests", kp.ki_start.tv_sec + 1));
    // A pid surely not ours must not match at all.
    try std.testing.expect(!procMatchesIdentity(1, "xmppd-core", kp.ki_start.tv_sec));
}

fn lookupKinfoProcChecked(pid: posix.pid_t) bool {
    var kp: KinfoProc = undefined;
    return lookupKinfoProc(pid, &kp);
}

test "lookupKinfoProc returns false for a pid that does not exist" {
    try std.testing.expect(!lookupKinfoProcChecked(-1));
}

test "childStartSec: live pid has a start time; a dead pid returns null (T259)" {
    // writeChildPid must not silently store start 0 for a pid it cannot
    // look up; the null return is what makes the warn path reachable.
    try std.testing.expect(childStartSec(std.c.getpid()) != null);
    try std.testing.expect(childStartSec(-1) == null);
}

test "pidFilePath builds run_dir-relative path" {
    var buf: [4096]u8 = undefined;
    const p = try pidFilePath(&buf, "/var/run/xmppd", "auth.pid");
    try std.testing.expectEqualStrings("/var/run/xmppd/auth.pid", p);
}

extern "c" fn sigsuspend(mask: *const posix.sigset_t) c_int;

fn pauseForever() noreturn {
    const mask = posix.sigemptyset();
    while (true) _ = sigsuspend(&mask);
}

/// Fork a grandchild through an intermediate that exits at once: the
/// survivor reparents to init, the ppid==1 shape the orphan check needs.
/// Its pid comes back over the pipe; mid's reap is complete before the
/// grandchild's reparenting becomes visible to kinfo.
fn spawnTestOrphan(ignore_term: bool) !posix.pid_t {
    const pipe_fds = try posix.pipe();
    const mid = try posix.fork();
    if (mid == 0) {
        const g = try posix.fork();
        if (g == 0) {
            if (ignore_term) {
                const ign: posix.Sigaction = .{
                    .handler = .{ .handler = posix.SIG.IGN },
                    .flags = 0,
                    .mask = posix.sigemptyset(),
                };
                posix.sigaction(posix.SIG.TERM, &ign, null);
            }
            pauseForever();
        }
        var b: [4]u8 = undefined;
        std.mem.writeInt(i32, &b, @intCast(g), .little);
        _ = posix.write(pipe_fds[1], &b) catch {};
        std.c._exit(0);
    }
    posix.close(pipe_fds[1]);
    defer posix.close(pipe_fds[0]);
    var b: [4]u8 = undefined;
    const n = try posix.read(pipe_fds[0], &b);
    try std.testing.expectEqual(@as(usize, 4), n);
    var st: c_int = 0;
    _ = std.c.waitpid(mid, &st, 0);
    return std.mem.readInt(i32, &b, .little);
}

/// NOTE_EXIT watch plus a bound on the test's own kqueue: assertions
/// ride the same event the production wait consumes.
const ExitWatch = struct {
    kq: posix.fd_t,

    fn init(pid: posix.pid_t, bound_ms: i64) !ExitWatch {
        const kq = std.c.kqueue();
        try std.testing.expect(kq >= 0);
        var changes = [_]std.c.Kevent{
            .{
                .ident = @intCast(pid),
                .filter = std.c.EVFILT.PROC,
                .flags = std.c.EV.ADD,
                .fflags = std.c.NOTE.EXIT,
                .data = 0,
                .udata = 0,
            },
            .{
                .ident = 1,
                .filter = std.c.EVFILT.TIMER,
                .flags = std.c.EV.ADD | std.c.EV.ONESHOT,
                .fflags = 0,
                .data = bound_ms,
                .udata = 0,
            },
        };
        try std.testing.expect(std.c.kevent(kq, &changes, changes.len, &changes, 0, null) == 0);
        return .{ .kq = kq };
    }

    fn deinit(self: *ExitWatch) void {
        _ = std.c.close(self.kq);
    }

    /// True when the watched pid's NOTE_EXIT arrived before the bound.
    fn sawExit(self: *ExitWatch) bool {
        var out: [2]std.c.Kevent = undefined;
        const n = std.c.kevent(self.kq, &[_]std.c.Kevent{}, 0, &out, out.len, null);
        if (n <= 0) return false;
        for (out[0..@intCast(n)]) |ev| {
            if (ev.filter == std.c.EVFILT.PROC) return true;
        }
        return false;
    }
};

fn fileExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

test "cleanupOrphan: an identity-matching orphan exits on TERM inside the grace" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const run_dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(run_dir);
    var pb: [4096]u8 = undefined;
    const path = try pidFilePath(&pb, run_dir, "stub.pid");

    const g = try spawnTestOrphan(false);
    defer _ = std.c.kill(g, posix.SIG.KILL);
    var kp: KinfoProc = undefined;
    try std.testing.expect(lookupKinfoProc(g, &kp));
    try std.testing.expectEqual(@as(c_int, 1), kp.ki_ppid);
    writeChildPid(path, g, "master-tests");

    var ew = try ExitWatch.init(g, 4_000);
    defer ew.deinit();
    cleanupOrphanTimed(path, "master-tests", 2_000, 200);
    try std.testing.expect(ew.sawExit());
    try std.testing.expect(!fileExists(path));
}

test "cleanupOrphan: a TERM-ignoring orphan is SIGKILLed at the grace deadline" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const run_dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(run_dir);
    var pb: [4096]u8 = undefined;
    const path = try pidFilePath(&pb, run_dir, "stub.pid");

    // Only SIGKILL can take this one down, so its exit proves escalation.
    const g = try spawnTestOrphan(true);
    defer _ = std.c.kill(g, posix.SIG.KILL);
    var kp: KinfoProc = undefined;
    try std.testing.expect(lookupKinfoProc(g, &kp));
    try std.testing.expectEqual(@as(c_int, 1), kp.ki_ppid);
    writeChildPid(path, g, "master-tests");

    var ew = try ExitWatch.init(g, 4_000);
    defer ew.deinit();
    cleanupOrphanTimed(path, "master-tests", 200, 1_000);
    try std.testing.expect(ew.sawExit());
    try std.testing.expect(!fileExists(path));
}

test "cleanupOrphan: a pid file naming a mismatched live process spares it" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const run_dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(run_dir);
    var pb: [4096]u8 = undefined;
    const path = try pidFilePath(&pb, run_dir, "stub.pid");

    const g = try spawnTestOrphan(false);
    defer {
        _ = std.c.kill(g, posix.SIG.KILL);
    }
    var kp: KinfoProc = undefined;
    try std.testing.expect(lookupKinfoProc(g, &kp));
    try std.testing.expectEqual(@as(c_int, 1), kp.ki_ppid);
    writeChildPid(path, g, "master-tests");

    // ppid and start match; only the expected comm differs, so the
    // identity gate is what spares it.
    cleanupOrphanTimed(path, "xmppd-auth", 200, 200);
    try std.testing.expect(std.c.kill(g, 0) == 0);
    try std.testing.expect(!fileExists(path));
}
