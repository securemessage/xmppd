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

/// Minimum backoff delay (nanoseconds).
const MIN_BACKOFF_NS: u64 = 1 * std.time.ns_per_s;
/// Maximum backoff delay (nanoseconds).
const MAX_BACKOFF_NS: u64 = 30 * std.time.ns_per_s;
/// If the child runs for this long, reset backoff.
const STABLE_RUN_NS: u64 = 60 * std.time.ns_per_s;

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

    /// Initialize the supervisor.
    ///
    /// - `exe_path` — absolute path to the child executable
    /// - `args` — arguments (exe_path is NOT automatically prepended)
    pub fn init(exe_path: []const u8, args: []const []const u8) Supervisor {
        return .{
            .exe_path = exe_path,
            .args = args,
        };
    }

    /// Initialize with privilege drop.
    pub fn initWithUser(exe_path: []const u8, args: []const []const u8, uid: std.posix.uid_t, gid: std.posix.gid_t) Supervisor {
        return .{
            .exe_path = exe_path,
            .args = args,
            .uid = uid,
            .gid = gid,
        };
    }

    /// Child-side fd hygiene (T356/S7): remap pass_fds to 3..3+len-1 and
    /// truncate the rest of the table. Two-phase through a scratch zone so
    /// a dup2 target can never clobber a still-needed source. Failures exit
    /// the child (125); only valid between fork and exec.
    pub fn applyFdPass(self: *Supervisor) void {
        const TMP_BASE: i32 = 8192;
        for (self.pass_fds, 0..) |src, i| {
            if (src <= 2) continue; // stdio stays put
            if (std.c.dup2(src, TMP_BASE + @as(i32, @intCast(i))) < 0) std.c._exit(125);
        }
        var i: usize = 0;
        while (i < self.pass_fds.len) : (i += 1) {
            if (self.pass_fds[i] <= 2) continue;
            if (std.c.dup2(TMP_BASE + @as(i32, @intCast(i)), 3 + @as(i32, @intCast(i))) < 0) std.c._exit(125);
            _ = std.c.close(TMP_BASE + @as(i32, @intCast(i)));
        }
        closefrom(@intCast(3 + self.pass_fds.len));
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

            // Drop privileges before exec if configured. setgroups first:
            // without it the child keeps root's supplementary groups
            // (wheel, operator) even after setuid (T356/S7).
            if (self.gid != 0) {
                if (setgroups(1, &self.gid) != 0) std.c._exit(125);
                if (std.c.setgid(self.gid) != 0) std.c._exit(125);
            }
            if (self.uid != 0) {
                const ret_u = std.c.setuid(self.uid);
                if (ret_u != 0) std.c._exit(125);
            }

            // fd hygiene: remap the passed listener sockets to 3..N, close
            // everything else (S7 — before this, every child inherited
            // every listener and internal master fd).
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
    const sup = Supervisor.init("/usr/local/bin/xmppd-core", &.{});
    try std.testing.expect(sup.child_pid == null);
    try std.testing.expect(sup.state == .not_started);
    try std.testing.expect(!sup.isRunning());
    try std.testing.expectEqual(@as(u32, 1000), sup.backoffMs());
}

test "Supervisor: handleChildExit with quick exit increases backoff" {
    var sup = Supervisor.init("/usr/local/bin/xmppd-core", &.{});
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
    var sup = Supervisor.init("/usr/local/bin/xmppd-core", &.{});
    sup.state = .shutting_down;
    sup.child_pid = 12345;

    const should_restart = sup.handleChildExit(0);
    try std.testing.expect(!should_restart);
}

test "Supervisor: backoff caps at MAX_BACKOFF" {
    var sup = Supervisor.init("/usr/local/bin/xmppd-core", &.{});
    sup.backoff_ns = MAX_BACKOFF_NS;
    sup.state = .running;
    sup.child_pid = 12345;
    sup.last_start = std.time.nanoTimestamp();

    _ = sup.handleChildExit(1);
    try std.testing.expectEqual(MAX_BACKOFF_NS, sup.backoff_ns);
}

test "Supervisor: shutdown sets state and clears after wait" {
    var sup = Supervisor.init("/usr/local/bin/xmppd-core", &.{});
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
    var sup = Supervisor.init("/nonexistent", &.{});
    sup.child_pid = pid;
    sup.state = .running;

    const status = try sup.waitChild();
    const exit_code = (status >> 8) & 0xFF;
    try std.testing.expectEqual(@as(u32, 0), exit_code);
}

test "Supervisor: child fd hygiene remaps pass_fds to 3..N and closes the rest (T356/S7)" {
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

    var sup = Supervisor.init("/unused", &.{});
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

    var sup2 = Supervisor.init("/nonexistent", &.{});
    sup2.child_pid = pid;
    sup2.state = .running;
    _ = try sup2.waitChild();
}
