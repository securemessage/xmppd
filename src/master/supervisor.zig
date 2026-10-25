//! # Supervisor — child process management for xmppd master
//!
//! Spawns, monitors, and restarts the `xmppd-core` child process.
//! Integrates with the event loop via `EVFILT_PROC` (kqueue) for
//! non-blocking child exit detection.
//!
//! ## Restart Policy
//!
//! On unexpected child exit, the supervisor restarts with exponential
//! backoff: 1s, 2s, 4s, 8s, 16s, 30s (capped). A successful run of
//! 60+ seconds resets the backoff to 1s.
//!
//! ## Signal Forwarding
//!
//! - `SIGTERM` → forward to child, wait, then exit
//! - `SIGHUP` → forward to child (future: config reload)

const std = @import("std");
const posix = std.posix;

const log = std.log.scoped(.supervisor);

// libc entries absent from std.c (FreeBSD): supplementary group reset and
// fd-table truncation used by the child's privilege/hygiene path (T356/S7).
extern "c" fn setgroups(size: c_int, list: *const posix.gid_t) c_int;
extern "c" fn closefrom(lowfd: c_int) void;

/// FD_CLOEXEC for fcntl(F_GETFD/F_SETFD) (FreeBSD <fcntl.h>; not exported
/// by std.c).
const FD_CLOEXEC: c_int = 1;

/// Minimum backoff delay (nanoseconds).
const MIN_BACKOFF_NS: u64 = 1 * std.time.ns_per_s;
/// Maximum backoff delay (nanoseconds).
const MAX_BACKOFF_NS: u64 = 30 * std.time.ns_per_s;
/// If the child runs for this long, reset backoff.
const STABLE_RUN_NS: u64 = 60 * std.time.ns_per_s;

/// Init failures: a root process without a run user.
pub const InitError = error{RunUserRequired};

/// Child process state.
pub const ChildState = enum {
    /// No child has been spawned.
    not_started,
    /// Child is running.
    running,
    /// Child exited, awaiting restart.
    exited,
    /// Supervisor is shutting down — don't restart.
    shutting_down,
};

pub const Supervisor = struct {
    /// Path to the child executable.
    exe_path: []const u8,
    /// Arguments to pass to the child.
    args: []const []const u8,
    /// Unprivileged user/group IDs for the child process (0 = no drop).
    uid: std.posix.uid_t = 0,
    gid: std.posix.gid_t = 0,
    /// Listener sockets the child inherits, remapped to 3..3+len-1; every
    /// other fd above stderr is closed. Empty = the whole table is closed.
    pass_fds: []const posix.fd_t = &.{},
    /// Current child PID, or null if not running.
    child_pid: ?posix.pid_t = null,
    /// Child state.
    state: ChildState = .not_started,
    /// Current backoff delay in nanoseconds.
    backoff_ns: u64 = MIN_BACKOFF_NS,
    /// Timestamp when the child was last started.
    last_start: i128 = 0,
    /// Number of consecutive restarts (resets after stable run).
    restart_count: u32 = 0,

    /// Initialize the supervisor. A process running as root must name a run
    /// user; without one every child would start as root, so init refuses.
    /// The euid is a parameter so the refusal is testable without being root.
    pub fn init(
        exe_path: []const u8,
        args: []const []const u8,
        euid: std.posix.uid_t,
    ) InitError!Supervisor {
        if (euid == 0) return error.RunUserRequired;
        return .{
            .exe_path = exe_path,
            .args = args,
        };
    }

    /// Initialize with privilege drop. A root caller passing uid 0 has not
    /// named a run user and is refused; a non-root caller may inherit.
    pub fn initWithUser(
        exe_path: []const u8,
        args: []const []const u8,
        uid: std.posix.uid_t,
        gid: std.posix.gid_t,
        euid: std.posix.uid_t,
    ) InitError!Supervisor {
        if (euid == 0 and uid == 0) return error.RunUserRequired;
        return .{
            .exe_path = exe_path,
            .args = args,
            .uid = uid,
            .gid = gid,
        };
    }

    /// Child-side fd hygiene (T356/S7): remap pass_fds to 3..3+len-1
    /// and truncate the rest of the table. Failures exit the child (125);
    /// only valid between fork and exec.
    ///
    /// Each source is dup'd once through fcntl(F_DUPFD) so the kernel
    /// allocates free descriptors above the target zone first (no clobber,
    /// no fixed scratch base), then moved into place with dup2 (closes the
    /// target atomically before copying).
    pub fn applyFdPass(self: *Supervisor) void {
        const scratch_max = 64; // Supervisor.pass_fds has no more entries than MAX_WORKERS
        var scratch: [scratch_max]i32 = @splat(-1);
        const n = @min(self.pass_fds.len, scratch_max);
        // Phase 1: park sources ABOVE the target zone (min = 3+n) so nothing
        // inside 3..3+n-1 matters during phase 2, and the scratch base never
        // exceeds the caller's RLIMIT_NOFILE.
        const scratch_min: i32 = 3 + @as(i32, @intCast(n));
        for (self.pass_fds[0..n], 0..) |src, i| {
            if (src <= 2) continue; // stdio stays put
            const target: i32 = 3 + @as(i32, @intCast(i));
            if (src == target) continue; // already in position
            scratch[i] = std.c.fcntl(src, std.c.F.DUPFD, scratch_min);
            if (scratch[i] < 0) std.c._exit(125);
        }

        // Phase 2: duplicate parked copies into their final slots with dup2
        // (target closed atomically by the dup call), then close originals
        // and strays above the band.
        for (self.pass_fds[0..n], 0..) |src, i| {
            if (src <= 2) continue;
            const target: i32 = 3 + @as(i32, @intCast(i));
            if (src == target) {
                // Already in position. dup2 clears FD_CLOEXEC on remapped
                // fds, but a skipped fd keeps its flag and listeners are
                // SOCK_CLOEXEC: clear it or exec closes the socket (S7).
                const flags = std.c.fcntl(src, std.c.F.GETFD);
                if (flags < 0) std.c._exit(125);
                if (std.c.fcntl(src, std.c.F.SETFD, flags & ~FD_CLOEXEC) < 0) std.c._exit(125);
                continue;
            }
            if (std.c.dup2(scratch[i], target) < 0) std.c._exit(125);
            _ = std.c.close(scratch[i]);
        }

        // Everything not in the target band or stdio goes (original sources
        // included).
        closefrom(@intCast(3 + self.pass_fds.len));
    }

    /// A uid-only drop resolves the run user's primary gid parent-side
    /// (getpwuid_r is not async-signal-safe for the forked child). Without
    /// it setgroups([0]) would leave the child in wheel (S7). Fails
    /// closed: no passwd entry, no spawn.
    pub fn resolveRunGid(self: *Supervisor) !void {
        if (self.uid == 0 or self.gid != 0) return;
        var pw: std.c.passwd = undefined;
        var pw_buf: [1024]u8 = undefined;
        var result: ?*std.c.passwd = null;
        const rc = std.c.getpwuid_r(self.uid, &pw, &pw_buf, pw_buf.len, &result);
        if (rc != 0 or result == null) {
            log.err("uid {d} has no passwd entry; refusing to spawn with root's groups", .{self.uid});
            return error.PasswdLookupFailed;
        }
        try self.adoptRunGid(result.?.gid);
    }

    /// Adopt a resolved primary gid for the privilege drop. A run user in
    /// group root would keep the child in group root after setgid; that is
    /// refused rather than dropped into.
    pub fn adoptRunGid(self: *Supervisor, gid: posix.gid_t) !void {
        if (self.uid != 0 and gid == 0) {
            log.err("run user uid {d} has gid 0; refusing to drop into group root", .{self.uid});
            return error.RunGidIsRoot;
        }
        self.gid = gid;
    }

    /// Spawn the child process using fork+execve.
    ///
    /// Returns the child PID on success. The `exe_path` must be a
    /// null-terminated string ([:0]const u8) or will be copied to
    /// a stack buffer with null termination.
    ///
    /// The child receives argv[0] = exe_path, followed by self.args.
    pub fn spawnChild(self: *Supervisor) !posix.pid_t {
        if (self.exe_path.len == 0 or self.exe_path[0] != '/') {
            log.warn("exe_path '{s}' is not absolute — execve may fail if cwd lacks the binary", .{self.exe_path});
        }

        try self.resolveRunGid();

        const pid = try posix.fork();

        if (pid == 0) {
            // --- Child process ---
            // Null-terminate exe_path on stack for execve
            var path_buf: [1024]u8 = undefined;
            if (self.exe_path.len >= path_buf.len) std.c._exit(126);
            @memcpy(path_buf[0..self.exe_path.len], self.exe_path);
            path_buf[self.exe_path.len] = 0;

            // Build argv: [exe_path, args..., null]
            // Max 16 args (more than enough for xmppd daemons)
            var argv_buf: [18:null]?[*:0]const u8 = .{null} ** 18;
            argv_buf[0] = @ptrCast(&path_buf);

            var arg_bufs: [16][1024]u8 = undefined;
            const max_args = @min(self.args.len, 16);
            for (0..max_args) |i| {
                const arg = self.args[i];
                if (arg.len >= arg_bufs[i].len) std.c._exit(126);
                @memcpy(arg_bufs[i][0..arg.len], arg);
                arg_bufs[i][arg.len] = 0;
                argv_buf[1 + i] = @ptrCast(&arg_bufs[i]);
            }
            argv_buf[1 + max_args] = null;

            // Reset signal mask — children must not inherit parent's blocked signals
            var empty_mask = posix.sigemptyset();
            posix.sigprocmask(posix.SIG.SETMASK, &empty_mask, null);

            // Drop privileges before exec if configured. setgroups always
            // runs on ANY drop (uid or gid), never gated on gid alone: a
            // uid-only drop would otherwise keep root's supplementary groups
            // (wheel, operator), S7. Order: setgroups, setgid, setuid.
            if (self.gid != 0 or self.uid != 0) {
                if (setgroups(1, &self.gid) != 0) std.c._exit(125);
            }
            if (self.gid != 0) {
                if (std.c.setgid(self.gid) != 0) std.c._exit(125);
            }
            if (self.uid != 0) {
                const ret_u = std.c.setuid(self.uid);
                if (ret_u != 0) std.c._exit(125);
            }

            // fd hygiene: remap the passed listener sockets to 3..N and
            // close everything else, so a child holds only its own fds
            // (S7).
            self.applyFdPass();

            const envp = [_:null]?[*:0]const u8{null};
            _ = std.c.execve(
                @ptrCast(&path_buf),
                &argv_buf,
                &envp,
            );
            // execve only returns on failure
            std.c._exit(127);
        }

        // --- Parent process ---
        self.child_pid = pid;
        self.state = .running;
        self.last_start = std.time.nanoTimestamp();
        log.info("spawned child pid={d}", .{pid});
        return pid;
    }

    /// Handle child exit notification.
    ///
    /// Call this when kqueue `EVFILT_PROC` fires or after `waitpid()`.
    /// Updates state and backoff. Returns true if the supervisor should
    /// restart the child (i.e., not shutting down).
    pub fn handleChildExit(self: *Supervisor, status: u32) bool {
        const exit_code = (status >> 8) & 0xFF;
        const signal = status & 0x7F;

        if (signal != 0) {
            log.warn("child pid={?d} killed by signal {d}", .{ self.child_pid, signal });
        } else {
            log.info("child pid={?d} exited with code {d}", .{ self.child_pid, exit_code });
        }

        if (self.state == .shutting_down) {
            return false;
        }

        self.state = .exited;

        // Check if the child ran long enough to be considered stable
        const now = std.time.nanoTimestamp();
        const run_duration: u64 = @intCast(@max(0, now - self.last_start));

        if (run_duration >= STABLE_RUN_NS) {
            // Stable run — reset backoff
            self.backoff_ns = MIN_BACKOFF_NS;
            self.restart_count = 0;
        } else {
            // Quick exit — increase backoff
            self.backoff_ns = @min(self.backoff_ns * 2, MAX_BACKOFF_NS);
            self.restart_count += 1;
        }

        return true;
    }

    /// Get the current backoff delay in milliseconds (for timer registration).
    pub fn backoffMs(self: *const Supervisor) u32 {
        return @intCast(self.backoff_ns / std.time.ns_per_ms);
    }

    /// Initiate graceful shutdown. Sends SIGTERM to the child if running.
    pub fn shutdown(self: *Supervisor) void {
        self.state = .shutting_down;
        if (self.child_pid) |pid| {
            log.info("sending SIGTERM to child pid={d}", .{pid});
            // Use kill(2) directly
            _ = std.c.kill(pid, posix.SIG.TERM);
        }
    }

    /// Forward a signal to the child process.
    pub fn forwardSignal(self: *Supervisor, signo: u8) void {
        if (self.child_pid) |pid| {
            _ = std.c.kill(pid, @intCast(signo));
        }
    }

    /// Returns true if the child is currently running.
    pub fn isRunning(self: *const Supervisor) bool {
        return self.state == .running and self.child_pid != null;
    }

    /// Wait for the child to exit (blocking).
    /// Used during shutdown to wait for graceful exit.
    pub fn waitChild(self: *Supervisor) !u32 {
        const pid = self.child_pid orelse return 0;
        var status: u32 = 0;
        const ret = std.c.waitpid(pid, @ptrCast(&status), 0);
        if (ret < 0) return error.WaitFailed;
        self.child_pid = null;
        return status;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Supervisor: init and basic state" {
    const sup = try Supervisor.init("/usr/local/bin/xmppd-core", &.{}, 1);
    try std.testing.expect(sup.child_pid == null);
    try std.testing.expect(sup.state == .not_started);
    try std.testing.expect(!sup.isRunning());
    try std.testing.expectEqual(@as(u32, 1000), sup.backoffMs());
}

test "Supervisor: init refuses root without a run user" {
    try std.testing.expectError(error.RunUserRequired, Supervisor.init("/unused", &.{}, 0));
    try std.testing.expectError(error.RunUserRequired, Supervisor.initWithUser("/unused", &.{}, 0, 0, 0));

    const with_user = try Supervisor.initWithUser("/unused", &.{}, 65534, 65534, 0);
    try std.testing.expectEqual(@as(posix.uid_t, 65534), with_user.uid);
    const nonroot = try Supervisor.init("/unused", &.{}, 1000);
    try std.testing.expectEqual(@as(posix.uid_t, 0), nonroot.uid);
}

test "Supervisor: handleChildExit with quick exit increases backoff" {
    var sup = try Supervisor.init("/usr/local/bin/xmppd-core", &.{}, 1);
    sup.state = .running;
    sup.child_pid = 12345;
    sup.last_start = std.time.nanoTimestamp(); // Just started

    const should_restart = sup.handleChildExit(0); // Exit code 0
    try std.testing.expect(should_restart);
    try std.testing.expect(sup.state == .exited);
    try std.testing.expectEqual(@as(u64, 2 * std.time.ns_per_s), sup.backoff_ns);
    try std.testing.expectEqual(@as(u32, 1), sup.restart_count);
}

test "Supervisor: handleChildExit during shutdown returns false" {
    var sup = try Supervisor.init("/usr/local/bin/xmppd-core", &.{}, 1);
    sup.state = .shutting_down;
    sup.child_pid = 12345;

    const should_restart = sup.handleChildExit(0);
    try std.testing.expect(!should_restart);
}

test "Supervisor: backoff caps at MAX_BACKOFF" {
    var sup = try Supervisor.init("/usr/local/bin/xmppd-core", &.{}, 1);
    sup.backoff_ns = MAX_BACKOFF_NS;
    sup.state = .running;
    sup.child_pid = 12345;
    sup.last_start = std.time.nanoTimestamp();

    _ = sup.handleChildExit(1);
    try std.testing.expectEqual(MAX_BACKOFF_NS, sup.backoff_ns);
}

test "Supervisor: shutdown sets state and clears after wait" {
    var sup = try Supervisor.init("/usr/local/bin/xmppd-core", &.{}, 1);
    sup.state = .running;
    // No real child — just test state transitions
    sup.child_pid = null;

    sup.shutdown();
    try std.testing.expect(sup.state == .shutting_down);
}

test "Supervisor: fork and wait" {
    // Direct fork test — child immediately exits with code 0
    const pid = try posix.fork();
    if (pid == 0) {
        // Child
        std.c._exit(0);
    }

    // Parent — simulate supervisor state
    var sup = try Supervisor.init("/nonexistent", &.{}, 1);
    sup.child_pid = pid;
    sup.state = .running;

    const status = try sup.waitChild();
    const exit_code = (status >> 8) & 0xFF;
    try std.testing.expectEqual(@as(u32, 0), exit_code);
}

test "Supervisor: child fd hygiene remaps pass_fds to 3..N and closes the rest (T356)" {
    // Three socketpairs: the first two are the pass_fds (child must see them
    // remapped to 3 and 4); the third is a stray the child must NOT have
    // after closefrom. The child reports over fd4.
    var p1: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &p1) != 0) return error.Socketpair;
    defer posix.close(p1[0]);
    defer posix.close(p1[1]);
    var p2: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &p2) != 0) return error.Socketpair;
    defer posix.close(p2[0]);
    defer posix.close(p2[1]);
    var stray: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &stray) != 0) return error.Socketpair;
    defer posix.close(stray[0]);
    defer posix.close(stray[1]);

    var sup = try Supervisor.init("/unused", &.{}, 1);
    sup.pass_fds = &.{ p1[1], p2[1] };
    const stray_child_end = stray[1];

    const pid = try posix.fork();
    if (pid == 0) {
        sup.applyFdPass();
        var verdict: [4]u8 = .{ 'N', 'O', 'N', 'E' }; // overwritten below
        if (std.c.write(3, "x", 1) == 1) verdict[0] = 'Y'; // remapped listener works
        if (std.c.write(stray_child_end, "x", 1) < 0) verdict[1] = 'Y'; // stray end is gone
        _ = std.c.write(4, &verdict, verdict.len); // report over remapped fd4
        std.c._exit(0);
    }

    var buf: [4]u8 = undefined;
    const n = try posix.read(p2[0], &buf);
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqualStrings("YY", buf[0..2]);

    var sup2 = try Supervisor.init("/nonexistent", &.{}, 1);
    sup2.child_pid = pid;
    sup2.state = .running;
    _ = try sup2.waitChild();
}

test "Supervisor: a pass_fd already at its target survives exec" {
    // SOCK_CLOEXEC shape: the listener fd is already 3 and carries
    // FD_CLOEXEC. applyFdPass must clear the flag, or execve closes the
    // socket and the child loses the listener.
    var p: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &p) != 0) return error.Socketpair;
    defer posix.close(p[0]);

    var sup = try Supervisor.init("/unused", &.{}, 1);
    sup.pass_fds = &.{3};

    const pid = try posix.fork();
    if (pid == 0) {
        // Park the write end at fd 3 (parent's table untouched) and restore
        // the CLOEXEC flag dup2 cleared, mirroring a SOCK_CLOEXEC listener.
        if (std.c.dup2(p[1], 3) < 0) std.c._exit(125);
        if (std.c.fcntl(3, std.c.F.SETFD, FD_CLOEXEC) < 0) std.c._exit(125);
        sup.applyFdPass();
        const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "printf Y >&3" };
        const envp = [_:null]?[*:0]const u8{null};
        _ = std.c.execve("/bin/sh", &argv, &envp);
        std.c._exit(127);
    }

    // Only the child holds the write end now: if exec closed fd 3 the read
    // sees EOF instead of "Y".
    posix.close(p[1]);
    var buf: [1]u8 = undefined;
    const n = try posix.read(p[0], &buf);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 'Y'), buf[0]);

    var sup2 = try Supervisor.init("/nonexistent", &.{}, 1);
    sup2.child_pid = pid;
    sup2.state = .running;
    _ = try sup2.waitChild();
}

test "Supervisor: fd remap works under a low RLIMIT_NOFILE" {
    // The scratch F_DUPFD band sits right above the targets, so a small
    // descriptor limit (10) does not break the remap.
    var p1: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &p1) != 0) return error.Socketpair;
    var p2: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &p2) != 0) return error.Socketpair;

    var sup = try Supervisor.init("/unused", &.{}, 1);
    sup.pass_fds = &.{ 6, 7 };

    const pid = try posix.fork();
    if (pid == 0) {
        // Deterministic child table: park both sources above the target
        // zone first (raw ends inside 3..7 clobber each other under dup2),
        // move the parked copies onto 6 and 7, then drop every other
        // descriptor and cap the space at 10.
        const parked1 = std.c.fcntl(p1[1], std.c.F.DUPFD, @as(c_int, 16));
        if (parked1 < 0) std.c._exit(125);
        const parked2 = std.c.fcntl(p2[1], std.c.F.DUPFD, @as(c_int, 16));
        if (parked2 < 0) std.c._exit(125);
        if (std.c.dup2(parked1, 6) < 0) std.c._exit(125);
        if (std.c.dup2(parked2, 7) < 0) std.c._exit(125);
        var fd: c_int = 3;
        while (fd < 64) : (fd += 1) {
            if (fd == 6 or fd == 7) continue;
            _ = std.c.close(fd);
        }
        var lim: std.c.rlimit = undefined;
        if (std.c.getrlimit(.NOFILE, &lim) != 0) std.c._exit(125);
        lim.cur = 10;
        if (std.c.setrlimit(.NOFILE, &lim) != 0) std.c._exit(125);
        sup.applyFdPass();
        var verdict: [2]u8 = .{ 'N', 'N' };
        if (std.c.write(3, "x", 1) == 1) verdict[0] = 'Y'; // remapped listener works
        if (std.c.write(4, "", 0) == 0) verdict[1] = 'Y'; // report channel is fd 4
        _ = std.c.write(4, &verdict, 2);
        std.c._exit(0);
    }

    posix.close(p1[1]);
    posix.close(p2[1]);
    defer posix.close(p1[0]);
    defer posix.close(p2[0]);

    var buf: [2]u8 = undefined;
    const n = try posix.read(p2[0], &buf);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqualStrings("YY", buf[0..2]);

    var sup2 = try Supervisor.init("/nonexistent", &.{}, 1);
    sup2.child_pid = pid;
    sup2.state = .running;
    _ = try sup2.waitChild();
}

/// An expected refusal logs at err (D8) and an err log in the test
/// process fails the test: the runner counts err-level logs. A refusal
/// under test runs in a forked child with stderr captured, so the log
/// cannot trip the runner while the captured line proves the level and
/// the message. The child returns 0 when the error and the supervisor
/// state match, and a distinct code naming the mismatch otherwise.
const captured_stderr_cap = 64 * 1024;

const Captured = struct { status: u8, stderr: [captured_stderr_cap]u8, len: usize };

fn runCaptured(child_fn: *const fn () callconv(.c) u8) !Captured {
    const fds = try posix.pipe();
    const pid = posix.fork() catch |err| {
        _ = posix.close(fds[0]);
        _ = posix.close(fds[1]);
        return err;
    };
    if (pid == 0) {
        _ = posix.close(fds[0]);
        _ = posix.dup2(fds[1], 2) catch std.c._exit(125);
        _ = posix.close(fds[1]);
        std.c._exit(child_fn());
    }
    _ = posix.close(fds[1]);
    defer _ = posix.close(fds[0]);

    // Drain to EOF so a child that writes more than the cap never blocks on
    // a full pipe; the excess is discarded.
    var out = Captured{ .status = 0, .stderr = undefined, .len = 0 };
    var scratch: [4096]u8 = undefined;
    while (true) {
        const n = posix.read(fds[0], &scratch) catch break;
        if (n == 0) break;
        const take = @min(out.stderr.len - out.len, n);
        @memcpy(out.stderr[out.len..][0..take], scratch[0..take]);
        out.len += take;
    }

    // waitpid retries EINTR itself, so the child is always reaped.
    const res = posix.waitpid(pid, 0);
    // A child killed by a signal has an empty exit status; reporting it as 0
    // would read as success.
    if (!posix.W.IFEXITED(res.status)) return error.ChildSignaled;
    out.status = posix.W.EXITSTATUS(res.status);
    return out;
}

fn childResolveUnknownUid() callconv(.c) u8 {
    var sup = Supervisor.init("/unused", &.{}, 1) catch return 1;
    sup.uid = 999999;
    if (sup.resolveRunGid()) |_| return 1 else |err| {
        return if (err == error.PasswdLookupFailed) 0 else 2;
    }
}

fn childSpawnNoPasswd() callconv(.c) u8 {
    var sup = Supervisor.init("/unused", &.{}, 1) catch return 1;
    sup.uid = 999999;
    if (sup.spawnChild()) |_| return 1 else |err| {
        if (err != error.PasswdLookupFailed) return 2;
        if (sup.child_pid != null) return 3;
        return if (sup.state == .not_started) 0 else 4;
    }
}

fn childAdoptGidZero() callconv(.c) u8 {
    var sup = Supervisor.init("/unused", &.{}, 1) catch return 1;
    sup.uid = 65534;
    if (sup.adoptRunGid(0)) |_| return 1 else |err| {
        if (err != error.RunGidIsRoot) return 2;
        return if (sup.gid == 0) 0 else 3;
    }
}

test "Supervisor: uid-only drop resolves the run user's gid" {
    // setgroups([0]) on a uid-only drop kept wheel; the gid must come from
    // the passwd entry of the run user.
    var sup = try Supervisor.init("/unused", &.{}, 1);
    sup.uid = 65534; // nobody
    try sup.resolveRunGid();
    try std.testing.expectEqual(@as(posix.gid_t, 65534), sup.gid);

    // No drop configured: untouched.
    var sup2 = try Supervisor.init("/unused", &.{}, 1);
    try sup2.resolveRunGid();
    try std.testing.expectEqual(@as(posix.gid_t, 0), sup2.gid);

    // Explicit gid wins; no lookup.
    var sup3 = try Supervisor.init("/unused", &.{}, 1);
    sup3.uid = 65534;
    sup3.gid = 4242;
    try sup3.resolveRunGid();
    try std.testing.expectEqual(@as(posix.gid_t, 4242), sup3.gid);

    // Unknown uid fails closed instead of spawning with root's groups,
    // and logs the refusal at err (D8).
    const captured = try runCaptured(childResolveUnknownUid);
    try std.testing.expectEqual(@as(u8, 0), captured.status);
    try std.testing.expect(std.mem.indexOf(u8, captured.stderr[0..captured.len], "(err): uid 999999 has no passwd entry; refusing to spawn with root's groups") != null);
}

test "Supervisor: spawnChild refuses to start when the run user has no passwd entry" {
    // spawnChild resolves the run gid before forking: without the lookup a
    // uid-only drop would fork and then run with the parent's groups. The
    // refusal logs at err (D8); the child encodes the error and the
    // untouched state in its exit code.
    const captured = try runCaptured(childSpawnNoPasswd);
    try std.testing.expectEqual(@as(u8, 0), captured.status);
    try std.testing.expect(std.mem.indexOf(u8, captured.stderr[0..captured.len], "(err): uid 999999 has no passwd entry; refusing to spawn with root's groups") != null);
}

fn childKillSelf() callconv(.c) u8 {
    posix.raise(posix.SIG.KILL) catch return 1;
    return 0;
}

fn childWriteLongStderr() callconv(.c) u8 {
    var line: [1024]u8 = undefined;
    @memset(line[0..], 'x');
    var written: usize = 0;
    while (written < 16 * 1024) {
        const n = posix.write(2, &line) catch return 1;
        written += n;
    }
    return 0;
}

test "Supervisor: a captured child killed by a signal is not reported as success" {
    // A signal death leaves an empty exit status; reading it as exit 0 would
    // let a crashed refusal child pass as a matching one.
    try std.testing.expectError(error.ChildSignaled, runCaptured(childKillSelf));
}

test "Supervisor: captured stderr keeps a child's long output" {
    // The parent drains the pipe to EOF, so the child always finishes, and
    // the capture holds more than a single 4 KiB read.
    const captured = try runCaptured(childWriteLongStderr);
    try std.testing.expectEqual(@as(u8, 0), captured.status);
    try std.testing.expectEqual(@as(usize, 16 * 1024), captured.len);
    try std.testing.expect(std.mem.allEqual(u8, captured.stderr[0..captured.len], 'x'));
}

fn childWriteHugeStderr() callconv(.c) u8 {
    var line: [1024]u8 = undefined;
    @memset(line[0..], 'y');
    var written: usize = 0;
    while (written < 192 * 1024) {
        const n = posix.write(2, &line) catch return 1;
        written += n;
    }
    return 0;
}

test "Supervisor: the capture cap drops only the excess while the drain reaches EOF" {
    // 192 KiB is more than the 64 KiB cap plus a 64 KiB pipe buffer: a drain
    // that stops at the cap would block the child and never reap it.
    const captured = try runCaptured(childWriteHugeStderr);
    try std.testing.expectEqual(@as(u8, 0), captured.status);
    try std.testing.expectEqual(captured_stderr_cap, captured.len);
    try std.testing.expect(std.mem.allEqual(u8, captured.stderr[0..captured.len], 'y'));
}

/// The identity drop runs setgroups, which needs privilege: a non-root
/// caller on a host without it gets EPERM and the child dies at 125. The
/// probe runs the call in a forked child so the runner's own group list is
/// never touched. The call is injectable to test the probe itself (D6).
const SetgroupsCall = *const fn (c_int, *const posix.gid_t) callconv(.c) c_int;

fn probeDropPrivilege(gid: posix.gid_t, call: SetgroupsCall) bool {
    const pid = posix.fork() catch return false;
    if (pid == 0) {
        var groups: [1]posix.gid_t = .{gid};
        std.c._exit(if (call(1, &groups[0]) == 0) 0 else 1);
    }
    var status: u32 = 0;
    const ret = std.c.waitpid(pid, @ptrCast(&status), 0);
    if (ret < 0) return false;
    return ((status >> 8) & 0xFF) == 0;
}

/// Run a test only where the drop privilege exists: without it the child
/// cannot enter the run user's primary group and the spawn dies at 125.
fn requireDropPrivilege(gid: posix.gid_t, call: SetgroupsCall) !void {
    if (!probeDropPrivilege(gid, call)) return error.SkipZigTest;
}

fn probeSetgroupsOk(_: c_int, _: *const posix.gid_t) callconv(.c) c_int {
    return 0;
}

fn probeSetgroupsDenied(_: c_int, _: *const posix.gid_t) callconv(.c) c_int {
    return -1;
}

test "Supervisor: the drop-privilege probe reports the setgroups privilege (D6)" {
    // A probe that is stuck reporting "no privilege" must fail the test,
    // not turn it into a skip.
    try std.testing.expect(probeDropPrivilege(0, probeSetgroupsOk));
    try std.testing.expect(!probeDropPrivilege(0, probeSetgroupsDenied));
}

test "Supervisor: spawnChild drops the child into the run user's primary group" {
    // The child reports its kernel group list from inside the dropped
    // identity: exactly the primary gid of the run user's passwd entry,
    // never the parent's supplementary groups (wheel, operator).
    const uid = posix.getuid();
    var pw: std.c.passwd = undefined;
    var pw_buf: [1024]u8 = undefined;
    var result: ?*std.c.passwd = null;
    const rc = std.c.getpwuid_r(uid, &pw, &pw_buf, pw_buf.len, &result);
    if (rc != 0 or result == null) return error.PasswdLookupFailed;
    const expected_gid = result.?.gid;

    // Without the setgroups privilege the drop cannot happen (D6).
    try requireDropPrivilege(expected_gid, setgroups);

    var p: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &p) != 0) return error.Socketpair;
    defer posix.close(p[0]);
    var w_open = true;
    errdefer if (w_open) posix.close(p[1]);

    var sup = try Supervisor.init("/bin/sh", &.{ "-c", "exec /usr/bin/id -G >&3" }, 1);
    sup.uid = uid; // uid-only drop: the gid comes from the passwd lookup
    sup.pass_fds = &.{p[1]};

    const pid = try sup.spawnChild();
    posix.close(p[1]);
    w_open = false;

    var buf: [64]u8 = undefined;
    const n = try posix.read(p[0], &buf);
    const reported = std.mem.trim(u8, buf[0..n], " \t\r\n");
    var expected_buf: [16]u8 = undefined;
    const expected = try std.fmt.bufPrint(&expected_buf, "{d}", .{expected_gid});
    try std.testing.expectEqualStrings(expected, reported);

    try std.testing.expectEqual(pid, sup.child_pid.?);
    const status = try sup.waitChild();
    try std.testing.expectEqual(@as(u32, 0), (status >> 8) & 0xFF);
}

test "Supervisor: a run gid of 0 is refused" {
    // group root after the drop is still group root: refuse it, logging at
    // err (D8). The child encodes the error and the untouched gid in its
    // exit code.
    const captured = try runCaptured(childAdoptGidZero);
    try std.testing.expectEqual(@as(u8, 0), captured.status);
    try std.testing.expect(std.mem.indexOf(u8, captured.stderr[0..captured.len], "(err): run user uid 65534 has gid 0; refusing to drop into group root") != null);

    // A real primary gid is adopted.
    var sup = try Supervisor.init("/unused", &.{}, 1);
    sup.uid = 65534;
    try sup.adoptRunGid(65534);
    try std.testing.expectEqual(@as(posix.gid_t, 65534), sup.gid);

    // uid 0 means no drop; gid 0 stays.
    var sup2 = try Supervisor.init("/unused", &.{}, 1);
    try sup2.adoptRunGid(0);
    try std.testing.expectEqual(@as(posix.gid_t, 0), sup2.gid);
}
