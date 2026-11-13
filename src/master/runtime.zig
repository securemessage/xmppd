//! # Runtime — the master's supervisor event machine.
//!
//! Owns the lib/net Loop the supervisor runs on (ADR-8): child exits arrive
//! as EVFILT_PROC NOTE_EXIT events the loop reaps itself (lib/net does the
//! waitpid, including the #60 deferred-reap race fix), restarts and
//! shutdown escalations ride one-shot deadline timers, and TERM/INT/HUP
//! arrive as EVFILT_SIGNAL. Nothing in this file sleeps or waitpid-blocks.
//!
//! ## Shutdown
//!
//! TERM/INT signals every live child at once and arms a one-shot deadline.
//! Each NOTE_EXIT is reaped by the loop; when the last child is gone the
//! master exits. A missed deadline escalates to SIGKILL for the stragglers
//! under a second deadline, and a second missed deadline gives up so the
//! master can never hang on an unkillable child.
//!
//! ## Startup readiness
//!
//! A child that declares `ready_socket` gates the spawn sequence: the
//! master waits on a per-child readiness pipe's EVFILT_READ under a
//! one-shot deadline before spawning the next child. One byte means
//! ready; a missed deadline is a failed start and shuts the half-spawned
//! set down.
//!
//! Today's children cannot self-report, so the master owns the pipe's
//! write end and a prober decides readiness the same way the dependents
//! experience it: a Unix connect() against the child's IPC socket. The
//! prober wakes on an EVFILT_VNODE watch of the socket's directory (a
//! nested kqueue fd registered with the loop, the resolver's pattern)
//! and retries refused connects on a short deadline for the bind-to-
//! listen gap. A later --ready-fd child can write the same byte itself
//! and the prober goes away; the pipe contract stays.

const std = @import("std");
const net = @import("net");
const supervisor_mod = @import("supervisor.zig");
const procinfo = @import("procinfo.zig");

const posix = std.posix;
const Supervisor = supervisor_mod.Supervisor;

const log = std.log.scoped(.xmppd);

/// Timer ctx kind for a child's restart backoff deadline.
const restart_kind: u8 = 0x81;
/// Timer ctx kind for the shutdown escalation deadlines.
const shutdown_kind: u8 = 0x82;
/// Handle ctx kind for a child's readiness pipe read end.
const ready_pipe_kind: u8 = 0x83;
/// Handle ctx kind for a readiness prober's nested kqueue fd.
const probe_kq_kind: u8 = 0x84;
/// Timer ctx kind for a refused-connect retry.
const probe_retry_kind: u8 = 0x85;
/// Timer ctx kind for the per-child readiness deadline.
const ready_deadline_kind: u8 = 0x86;

fn restartCtx(idx: usize) net.Token {
    return .{ .index = @intCast(idx), .gen = 1, .kind = restart_kind };
}

fn shutdownCtx() net.Token {
    return .{ .index = 0, .gen = 1, .kind = shutdown_kind };
}

fn readyPipeCtx(idx: usize) net.Token {
    return .{ .index = @intCast(idx), .gen = 1, .kind = ready_pipe_kind };
}

fn probeKqCtx(idx: usize) net.Token {
    return .{ .index = @intCast(idx), .gen = 1, .kind = probe_kq_kind };
}

fn probeRetryCtx(idx: usize) net.Token {
    return .{ .index = @intCast(idx), .gen = 1, .kind = probe_retry_kind };
}

fn readyDeadlineCtx(idx: usize) net.Token {
    return .{ .index = @intCast(idx), .gen = 1, .kind = ready_deadline_kind };
}

/// One supervised child in the runtime table.
pub const ChildCtl = struct {
    /// Short name for log lines ("auth", "s2s", "core").
    name: []const u8,
    /// Child pid-file basename under run_dir ("auth.pid").
    pid_file: []const u8,
    /// Executable comm basename recorded in the pid file (orphan identity).
    exe_base: []const u8,
    /// Unix IPC socket the readiness prober connects to; set for every
    /// child whose dependents must not spawn until it listens. null for
    /// a child nothing gates on (the last in the spawn order).
    ready_socket: ?[]const u8 = null,
    sup: *Supervisor,
};

/// Escalation deadlines; the fields exist so tests can tighten them.
pub const Limits = struct {
    /// Grace between the SIGTERM broadcast and SIGKILL escalation.
    term_grace_ms: u64 = 10_000,
    /// Grace between SIGKILL and giving up on a straggler.
    kill_grace_ms: u64 = 5_000,
    /// Per-child readiness deadline during the gated spawn sequence.
    ready_ms: u64 = 10_000,
    /// Refused-connect retry while a gated child's socket is coming up.
    probe_retry_ms: u64 = 25,
};

const Phase = enum { starting, running, stopping, killing };

/// Per-child readiness gate, live only while a gated spawn is pending.
const Gate = struct {
    /// Loop handle and fd of the readiness pipe's read end.
    pipe_rh: ?net.Token = null,
    pipe_r: posix.fd_t = -1,
    /// Write end the runtime's prober owns; -1 when the byte source is
    /// external or already consumed.
    pipe_w: posix.fd_t = -1,
    /// Prober: a nested kqueue carrying the socket directory's VNODE
    /// watch, registered with the loop as a readable fd.
    kq: posix.fd_t = -1,
    kq_h: ?net.Token = null,
    dir_fd: posix.fd_t = -1,
    active: bool = false,
};

pub const Runtime = struct {
    allocator: std.mem.Allocator,
    loop: net.Loop = undefined,
    /// Spawn order; shutdown signals dependents first (reverse).
    children: []ChildCtl,
    run_dir: []const u8,
    limits: Limits,
    phase: Phase = .running,
    running: bool = true,
    pid_path: [4096]u8 = undefined,
    /// Readiness gates, index-aligned with children.
    gates: []Gate = &.{},
    /// Next child the startup sequence spawns.
    pending: usize = 0,
    /// Child whose readiness byte the sequence waits on, if any.
    waiting_ready: ?usize = null,
    /// Set when the gated sequence could not finish; main exits nonzero.
    start_failed: bool = false,
    /// The first failure reason; tests assert which path tripped.
    fail_why: []const u8 = "",
    /// Readiness bytes consumed; tests assert the gate path ran.
    ready_count: usize = 0,

    pub const InitError = net.loop.InitError || net.Loop.WatchSignalError;

    /// Create the loop and claim TERM/INT/HUP through EVFILT_SIGNAL.
    pub fn init(
        allocator: std.mem.Allocator,
        children: []ChildCtl,
        run_dir: []const u8,
        limits: Limits,
    ) InitError!Runtime {
        var rt: Runtime = .{
            .allocator = allocator,
            .children = children,
            .run_dir = run_dir,
            .limits = limits,
        };
        rt.gates = try allocator.alloc(Gate, children.len);
        errdefer allocator.free(rt.gates);
        for (rt.gates) |*g| g.* = .{};
        try rt.loop.init(allocator, &.{ .handles_max = 32, .timers_max = 16 });
        errdefer rt.loop.deinit(allocator);
        try rt.loop.watchSignal(posix.SIG.TERM);
        try rt.loop.watchSignal(posix.SIG.INT);
        try rt.loop.watchSignal(posix.SIG.HUP);
        return rt;
    }

    pub fn deinit(self: *Runtime) void {
        // Loop-attached fds (pipe reads, prober kqueues) die with the
        // loop; the prober-owned write end and directory fd do not.
        for (self.gates) |*g| {
            if (g.pipe_w >= 0) posix.close(g.pipe_w);
            if (g.dir_fd >= 0) posix.close(g.dir_fd);
        }
        self.allocator.free(self.gates);
        self.loop.deinit(self.allocator);
    }

    /// Spawn one child, arm its EVFILT_PROC exit watch, and write its pid
    /// file (rewritten on every respawn so a later orphan check carries
    /// the live identity, T259).
    pub fn spawnChild(self: *Runtime, idx: usize) !posix.pid_t {
        const ctl = &self.children[idx];
        const pid = try ctl.sup.spawnChild();
        try self.loop.watchProcess(pid);
        self.writePidFile(ctl, pid);
        return pid;
    }

    /// Register an already-running pid as child idx: arm the exit watch and
    /// mark the supervisor running. Tests inject forked children through
    /// here; real spawns go through spawnChild.
    pub fn adoptChild(self: *Runtime, idx: usize, pid: posix.pid_t) !void {
        const ctl = &self.children[idx];
        ctl.sup.child_pid = pid;
        ctl.sup.state = .running;
        ctl.sup.last_start = std.time.nanoTimestamp();
        try self.loop.watchProcess(pid);
    }

    fn writePidFile(self: *Runtime, ctl: *const ChildCtl, pid: posix.pid_t) void {
        const path = procinfo.pidFilePath(&self.pid_path, self.run_dir, ctl.pid_file) catch return;
        procinfo.writeChildPid(path, pid, ctl.exe_base);
    }

    /// Remove a child pid file (graceful shutdown path).
    pub fn removePidFile(self: *Runtime, ctl: *const ChildCtl) void {
        const path = procinfo.pidFilePath(&self.pid_path, self.run_dir, ctl.pid_file) catch return;
        procinfo.removeChildPid(path);
    }

    /// Begin the gated spawn sequence. Children spawn in table order; a
    /// child with ready_socket holds the sequence on its readiness byte
    /// before the next spawn. After start(), run() drives the rest.
    pub fn start(self: *Runtime) !void {
        self.phase = .starting;
        for (self.children) |*ctl| {
            const path = ctl.ready_socket orelse continue;
            if (path.len >= @sizeOf(@FieldType(std.c.sockaddr.un, "path"))) {
                log.err("{s}: ready socket path exceeds sun_path: {s}", .{ ctl.name, path });
                return error.PathTooLong;
            }
        }
        self.advanceStartupInternal();
    }

    /// Spawn until a gate pauses the sequence or the table is done.
    fn advanceStartup(self: *Runtime) !void {
        while (self.pending < self.children.len) {
            const idx = self.pending;
            self.pending += 1;
            _ = try self.spawnChild(idx);
            if (self.children[idx].ready_socket != null) {
                try self.armGate(idx);
                return;
            }
        }
        if (self.phase == .starting) {
            self.phase = .running;
            log.info("all children spawned and ready", .{});
        }
    }

    /// A failed spawn or gate arm still shuts the started children down.
    fn advanceStartupInternal(self: *Runtime) void {
        self.advanceStartup() catch |err| {
            const idx = if (self.pending > 0) self.pending - 1 else 0;
            log.err("cannot spawn {s}: {}", .{ self.children[idx].name, err });
            self.failStart(idx, "spawn failed");
        };
    }

    /// Arm the full production gate for a spawned child: a fresh pipe
    /// (runtime holds the write end) plus the socket prober.
    fn armGate(self: *Runtime, idx: usize) !void {
        const pipe_fds = posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true }) catch return error.PipeFailed;
        var armed = false;
        defer if (!armed) {
            posix.close(pipe_fds[0]);
            posix.close(pipe_fds[1]);
        };
        try self.armGatePipe(idx, pipe_fds[0]);
        armed = true; // pipe_r is the gate's now
        self.gates[idx].pipe_w = pipe_fds[1];
        errdefer self.closeGate(idx);
        if (self.children[idx].ready_socket) |path| try self.armProbe(idx, path);
    }

    /// Attach an existing readiness pipe read end and arm the deadline.
    /// Tests and future --ready-fd children supply the write side.
    pub fn armGatePipe(self: *Runtime, idx: usize, pipe_r: posix.fd_t) !void {
        const gate = &self.gates[idx];
        const h = self.loop.attach(pipe_r, readyPipeCtx(idx), .{ .read = true }) catch return error.HandleTableFull;
        errdefer self.loop.close(h) catch {};
        _ = self.loop.scheduleIn(self.limits.ready_ms, readyDeadlineCtx(idx)) catch return error.TimerTableFull;
        gate.pipe_rh = h;
        gate.pipe_r = pipe_r;
        gate.active = true;
        self.waiting_ready = idx;
    }

    /// The connect prober: an inner kqueue with a VNODE watch on the
    /// socket's directory, registered with the loop as a readable fd,
    /// plus an immediate probe for an already-listening socket.
    fn armProbe(self: *Runtime, idx: usize, sock_path: []const u8) !void {
        const gate = &self.gates[idx];
        const kq = try posix.kqueue();
        errdefer posix.close(kq);
        gate.kq = kq;
        const dir = std.fs.path.dirname(sock_path) orelse ".";
        gate.dir_fd = try posix.open(dir, .{ .ACCMODE = .RDONLY }, 0);
        errdefer {
            posix.close(gate.dir_fd);
            gate.dir_fd = -1;
        }
        var change = [_]std.c.Kevent{.{
            .ident = @intCast(gate.dir_fd),
            .filter = std.c.EVFILT.VNODE,
            .flags = std.c.EV.ADD | std.c.EV.CLEAR,
            .fflags = std.c.NOTE.WRITE | std.c.NOTE.DELETE | std.c.NOTE.RENAME,
            .data = 0,
            .udata = 0,
        }};
        if (std.c.kevent(kq, &change, 1, &change, 0, null) < 0) return error.VnodeWatchFailed;
        gate.kq_h = try self.loop.attach(kq, probeKqCtx(idx), .{ .read = true });
        self.probeConnect(idx);
    }

    fn stopProbe(self: *Runtime, idx: usize) void {
        const gate = &self.gates[idx];
        if (gate.kq_h) |h| {
            self.loop.close(h) catch {};
            gate.kq_h = null;
            gate.kq = -1;
        }
        if (gate.dir_fd >= 0) {
            posix.close(gate.dir_fd);
            gate.dir_fd = -1;
        }
    }

    /// One connect against the child's IPC socket: success writes the
    /// readiness byte; anything else rides a bounded retry deadline.
    fn probeConnect(self: *Runtime, idx: usize) void {
        const gate = &self.gates[idx];
        if (!gate.active or self.waiting_ready != idx) return;
        const sock_path = self.children[idx].ready_socket orelse return;
        const fd = posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0) catch return;
        defer posix.close(fd);
        var addr: std.c.sockaddr.un = std.mem.zeroes(std.c.sockaddr.un);
        addr.family = posix.AF.UNIX;
        if (sock_path.len >= addr.path.len) return;
        @memcpy(addr.path[0..sock_path.len], sock_path);
        posix.connect(fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.un)) catch {
            _ = self.loop.scheduleIn(self.limits.probe_retry_ms, probeRetryCtx(idx)) catch {};
            return;
        };
        self.signalReady(idx);
    }

    /// The prober's verdict, delivered through the same byte any
    /// self-reporting child would write.
    fn signalReady(self: *Runtime, idx: usize) void {
        const gate = &self.gates[idx];
        if (gate.pipe_w >= 0) {
            _ = posix.write(gate.pipe_w, "R") catch {};
            posix.close(gate.pipe_w);
            gate.pipe_w = -1;
        }
        self.stopProbe(idx);
    }

    /// Tear down one gate's resources; callers own waiting_ready.
    fn closeGate(self: *Runtime, idx: usize) void {
        const gate = &self.gates[idx];
        if (gate.pipe_rh) |h| {
            self.loop.close(h) catch {};
            gate.pipe_rh = null;
            gate.pipe_r = -1;
        }
        if (gate.pipe_w >= 0) {
            posix.close(gate.pipe_w);
            gate.pipe_w = -1;
        }
        self.stopProbe(idx);
        gate.active = false;
    }

    /// A gate that can never complete: log the reason once and shut the
    /// half-spawned set down through the normal escalation path. Warn
    /// level, like the escalation diagnostics: the nonzero exit carries
    /// the severity.
    fn failStart(self: *Runtime, idx: usize, why: []const u8) void {
        if (!self.start_failed) {
            self.start_failed = true;
            self.fail_why = why;
            log.warn("startup failed for {s}: {s}", .{ self.children[idx].name, why });
        }
        if (self.waiting_ready == idx) self.waiting_ready = null;
        self.closeGate(idx);
        self.beginShutdown();
    }

    fn onReadable(self: *Runtime, io: net.loop.Io) void {
        switch (io.ctx.kind) {
            ready_pipe_kind => self.onReadyByte(io),
            probe_kq_kind => self.onProbeKq(io),
            else => {},
        }
    }

    /// The readiness byte, or EOF when the source vanished without one.
    fn onReadyByte(self: *Runtime, io: net.loop.Io) void {
        const idx: usize = io.ctx.index;
        if (idx >= self.children.len) return;
        if (self.waiting_ready != idx) {
            _ = self.loop.close(io.handle) catch {};
            return;
        }
        const gate = &self.gates[idx];
        var buf: [8]u8 = undefined;
        const n = posix.read(gate.pipe_r, &buf) catch 0;
        if (n == 0) {
            self.failStart(idx, "readiness pipe closed without a ready byte");
            return;
        }
        gate.active = false;
        if (gate.pipe_rh) |h| {
            _ = self.loop.close(h) catch {};
            gate.pipe_rh = null;
            gate.pipe_r = -1;
        }
        if (gate.pipe_w >= 0) {
            posix.close(gate.pipe_w);
            gate.pipe_w = -1;
        }
        self.stopProbe(idx);
        self.waiting_ready = null;
        self.ready_count += 1;
        log.info("child {s} is ready", .{self.children[idx].name});
        self.advanceStartupInternal();
    }

    /// Directory change under the prober: drain the nested queue and
    /// probe the socket.
    fn onProbeKq(self: *Runtime, io: net.loop.Io) void {
        const idx: usize = io.ctx.index;
        if (idx >= self.gates.len) return;
        const gate = &self.gates[idx];
        if (gate.kq < 0) return;
        var evs: [4]std.c.Kevent = undefined;
        const zero_ts: posix.timespec = .{ .sec = 0, .nsec = 0 };
        _ = std.c.kevent(gate.kq, &[_]std.c.Kevent{}, 0, &evs, evs.len, &zero_ts);
        self.probeConnect(idx);
    }

    /// The supervisor loop: restart dead children per backoff policy,
    /// forward HUP to every child, and drive the shutdown escalation.
    pub fn run(self: *Runtime) void {
        while (self.running) {
            self.loop.wait() catch |err| {
                log.err("event loop wait failed: {}", .{err});
                break;
            };
            while (self.loop.next()) |ev| {
                switch (ev) {
                    .process_exit => |p| self.onChildExit(p),
                    .deadline => |d| self.onDeadline(d),
                    .signal => |s| self.onSignal(s),
                    .readable => |io| self.onReadable(io),
                    else => {},
                }
            }
        }
    }

    /// Any child still tracked as alive (spawned, not yet reaped).
    fn anyAlive(self: *const Runtime) bool {
        for (self.children) |*ctl| {
            if (ctl.sup.child_pid != null) return true;
        }
        return false;
    }

    /// SIGTERM every live child and arm the escalation deadline.
    fn beginShutdown(self: *Runtime) void {
        self.phase = .stopping;
        for (self.children) |*ctl| ctl.sup.shutdown();
        if (!self.anyAlive()) {
            self.running = false;
            return;
        }
        _ = self.loop.scheduleIn(self.limits.term_grace_ms, shutdownCtx()) catch {
            self.running = false;
        };
    }

    /// The TERM grace expired: SIGKILL whatever is left and arm the last
    /// deadline. A second TERM while stopping takes the same path.
    fn escalate(self: *Runtime) void {
        self.phase = .killing;
        var left: usize = 0;
        for (self.children) |*ctl| {
            if (ctl.sup.child_pid) |pid| {
                log.warn("child {s} pid={d} did not exit on SIGTERM; sending SIGKILL", .{ ctl.name, pid });
                ctl.sup.forwardSignal(posix.SIG.KILL);
                left += 1;
            }
        }
        if (left == 0) {
            self.running = false;
            return;
        }
        _ = self.loop.scheduleIn(self.limits.kill_grace_ms, shutdownCtx()) catch {
            self.running = false;
        };
    }

    fn childIndexOf(self: *Runtime, pid: posix.pid_t) ?usize {
        for (self.children, 0..) |*ctl, i| {
            if (ctl.sup.child_pid != null and ctl.sup.child_pid.? == pid) return i;
        }
        return null;
    }

    fn onChildExit(self: *Runtime, p: net.loop.ProcessExit) void {
        const idx = self.childIndexOf(p.pid) orelse return;
        const ctl = &self.children[idx];
        const action = ctl.sup.handleChildExit(p.status);
        // Only a real termination frees the pid slot: a stopped/continued
        // report must not make a live child untracked.
        if (action != .ignore) ctl.sup.child_pid = null;
        // A gated child dying before its byte can never become ready.
        if (self.waiting_ready == idx) {
            self.failStart(idx, "exited before signaling readiness");
            return;
        }
        switch (self.phase) {
            .running, .starting => switch (action) {
                .restart => {
                    log.info("restarting {s} in {d}ms", .{ ctl.name, ctl.sup.backoffMs() });
                    _ = self.loop.scheduleIn(ctl.sup.backoffMs(), restartCtx(idx)) catch |err| {
                        log.err("cannot schedule {s} restart: {}", .{ ctl.name, err });
                        self.running = false;
                    };
                },
                .shutdown => self.running = false,
                .ignore => {},
            },
            .stopping, .killing => {
                if (!self.anyAlive()) self.running = false;
            },
        }
    }

    fn onDeadline(self: *Runtime, d: net.Deadline) void {
        switch (d.ctx.kind) {
            restart_kind => {
                if (self.phase != .running and self.phase != .starting) return;
                const idx: usize = d.ctx.index;
                if (idx >= self.children.len) return;
                const ctl = &self.children[idx];
                _ = self.spawnChild(idx) catch |err| {
                    log.err("failed to respawn {s}: {}", .{ ctl.name, err });
                    self.running = false;
                };
            },
            shutdown_kind => switch (self.phase) {
                .running, .starting => {},
                .stopping => self.escalate(),
                .killing => {
                    log.err("children still alive after SIGKILL grace; giving up", .{});
                    self.running = false;
                },
            },
            ready_deadline_kind => {
                const idx: usize = d.ctx.index;
                if (idx < self.children.len and self.waiting_ready == idx)
                    self.failStart(idx, "readiness deadline expired");
            },
            probe_retry_kind => {
                const idx: usize = d.ctx.index;
                if (idx < self.children.len) self.probeConnect(idx);
            },
            else => {},
        }
    }

    fn onSignal(self: *Runtime, s: net.loop.SignalEvent) void {
        if (s.signo == posix.SIG.TERM or s.signo == posix.SIG.INT) {
            log.info("received signal {d}, shutting down", .{s.signo});
            switch (self.phase) {
                .running, .starting => self.beginShutdown(),
                // A repeat TERM while stopping escalates at once.
                .stopping => self.escalate(),
                .killing => {},
            }
        } else if (s.signo == posix.SIG.HUP) {
            if (self.phase != .running) return;
            log.info("received SIGHUP, forwarding to all children", .{});
            for (self.children) |*ctl| ctl.sup.forwardSignal(@intCast(s.signo));
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

const test_limits: Limits = .{ .term_grace_ms = 300, .kill_grace_ms = 300, .ready_ms = 300, .probe_retry_ms = 20 };

extern "c" fn sigsuspend(mask: *const posix.sigset_t) c_int;

/// Signals a forked child suspends through; the test decides each one's
/// disposition first. Handlers run and return here; ignored signals do
/// not wake it, default dispositions kill it.
fn pauseForever() noreturn {
    const mask = posix.sigemptyset();
    while (true) _ = sigsuspend(&mask);
}

/// The runtime loop and every kqueue registration it owns must live on one
/// thread (Loop.assertOwner). RtThread runs init+adopt+run there; the
/// ready pipe byte tells the test watches are armed before it signals.
const RtThread = struct {
    children: []ChildCtl,
    run_dir: []const u8,
    limits: Limits,
    /// Pids to adopt, one per child in `children` (forked earlier).
    pids: []const posix.pid_t,
    /// Gate arming, index-aligned with pids: a nonnegative value is a
    /// pipe read fd for armGatePipe (the test or a --ready-fd child owns
    /// the write end), -1 arms the production gate (pipe plus prober on
    /// ready_socket), -2 leaves the child ungated.
    gate_fds: []const i32 = &.{},
    /// Test-owned: a byte lands here once watches are armed ('R') or init
    /// failed ('E').
    ready_w: posix.fd_t,
    /// Set once run() has returned, before deinit restores the signal
    /// dispositions: tests may self-signal only while this is false.
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    err: ?anyerror = null,
    /// Runtime outcomes the test asserts on after join.
    rt_phase: Phase = .running,
    start_failed: bool = false,
    fail_why: []const u8 = "",
    ready_count: usize = 0,

    fn main(self: *RtThread) void {
        var rt = Runtime.init(std.testing.allocator, self.children, self.run_dir, self.limits) catch |err| {
            self.err = err;
            _ = posix.write(self.ready_w, "E") catch {};
            return;
        };
        defer rt.deinit();
        var gated = false;
        for (self.pids, 0..) |pid, i| {
            rt.adoptChild(i, pid) catch |err| {
                self.err = err;
                _ = posix.write(self.ready_w, "E") catch {};
                return;
            };
            const mode = if (i < self.gate_fds.len) self.gate_fds[i] else -2;
            if (mode >= 0) {
                rt.armGatePipe(i, @intCast(mode)) catch |err| {
                    self.err = err;
                    _ = posix.write(self.ready_w, "E") catch {};
                    return;
                };
                gated = true;
            } else if (mode == -1) {
                rt.armGate(i) catch |err| {
                    self.err = err;
                    _ = posix.write(self.ready_w, "E") catch {};
                    return;
                };
                gated = true;
            }
        }
        if (gated) {
            // The test pre-adopted every child; the sequence resumes into
            // .running as soon as the outstanding gate completes.
            rt.phase = .starting;
            rt.pending = self.children.len;
        }
        _ = posix.write(self.ready_w, "R") catch {};
        rt.run();
        self.rt_phase = rt.phase;
        self.start_failed = rt.start_failed;
        self.fail_why = rt.fail_why;
        self.ready_count = rt.ready_count;
        self.done.store(true, .release);
    }
};

/// TERM the runtime only while it is still watching; after done the
/// process-wide disposition is restored and a self-signal would kill the
/// test itself.
fn stopRuntime(ctx: *const RtThread) void {
    if (!ctx.done.load(.acquire)) killSelf(posix.SIG.TERM);
}

fn awaitReady(ready_r: posix.fd_t) !void {
    var b: [1]u8 = undefined;
    const n = try posix.read(ready_r, &b);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, 'R'), b[0]);
}

/// A one-shot deadline and optional NOTE_EXIT watches on the test's own
/// kqueue: the orchestration side of every test waits on real events, not
/// sleeps.
const TestWait = struct {
    kq: posix.fd_t,

    fn init() !TestWait {
        const kq = std.c.kqueue();
        try testing.expect(kq >= 0);
        return .{ .kq = kq };
    }

    fn deinit(self: *TestWait) void {
        _ = std.c.close(self.kq);
    }

    fn armDeadline(self: *TestWait, ident: usize, ms: i64) void {
        var ev = [_]std.c.Kevent{.{
            .ident = ident,
            .filter = std.c.EVFILT.TIMER,
            .flags = std.c.EV.ADD | std.c.EV.ONESHOT,
            .fflags = 0,
            .data = ms,
            .udata = 0,
        }};
        const n = std.c.kevent(self.kq, &ev, 1, &ev, 0, null);
        testing.expect(n == 0) catch @panic("deadline arm failed");
    }

    fn armExit(self: *TestWait, pid: posix.pid_t) void {
        var ev = [_]std.c.Kevent{.{
            .ident = @intCast(pid),
            .filter = std.c.EVFILT.PROC,
            .flags = std.c.EV.ADD,
            .fflags = std.c.NOTE.EXIT,
            .data = 0,
            .udata = 0,
        }};
        const n = std.c.kevent(self.kq, &ev, 1, &ev, 0, null);
        testing.expect(n == 0) catch @panic("exit watch arm failed");
    }

    /// One event; null when the deadline (ident wait_deadline_ident) fired
    /// first.
    const wait_deadline_ident: usize = 0xdead;
    fn waitOne(self: *TestWait, out: *std.c.Kevent) ?void {
        var list = [_]std.c.Kevent{undefined};
        const n = std.c.kevent(self.kq, &[_]std.c.Kevent{}, 0, &list, 1, null);
        if (n <= 0) return null;
        out.* = list[0];
        if (out.filter == std.c.EVFILT.TIMER and out.ident == wait_deadline_ident) return null;
        return {};
    }
};

fn killSelf(signo: u8) void {
    _ = std.c.kill(std.c.getpid(), signo);
}

fn reap(pid: posix.pid_t) void {
    var st: c_int = 0;
    _ = std.c.waitpid(pid, &st, 0);
}

test "Runtime: a TERM-ignoring child is SIGKILLed at the grace deadline" {
    const pid = try posix.fork();
    if (pid == 0) {
        const ign: posix.Sigaction = .{
            .handler = .{ .handler = posix.SIG.IGN },
            .flags = 0,
            .mask = posix.sigemptyset(),
        };
        posix.sigaction(posix.SIG.TERM, &ign, null);
        pauseForever();
    }
    var child_gone = false;
    defer {
        if (!child_gone) {
            _ = std.c.kill(pid, posix.SIG.KILL);
            reap(pid);
        }
    }

    var sup = try Supervisor.init("/nonexistent", &.{}, 1);
    var children = [_]ChildCtl{
        .{ .name = "stub", .pid_file = "stub.pid", .exe_base = "stub", .sup = &sup },
    };
    const ready = try posix.pipe();
    defer posix.close(ready[0]);
    defer posix.close(ready[1]);
    var ctx: RtThread = .{
        .children = children[0..],
        .run_dir = "/nonexistent",
        .limits = test_limits,
        .pids = &.{pid},
        .ready_w = ready[1],
    };
    const thr = try std.Thread.spawn(.{}, RtThread.main, .{&ctx});

    try awaitReady(ready[0]);

    // The watch for the test's own wait: the child must die, and the
    // runtime must then return on its own.
    var tw = try TestWait.init();
    defer tw.deinit();
    tw.armExit(pid);
    tw.armDeadline(TestWait.wait_deadline_ident, 5000);

    killSelf(posix.SIG.TERM);

    // The child ignores TERM, so only the escalation can kill it.
    var ev: std.c.Kevent = undefined;
    const got = tw.waitOne(&ev);
    if (got == null) {
        stopRuntime(&ctx);
        thr.join();
        std.debug.print("child still alive: SIGKILL escalation missing\n", .{});
        return error.TestUnexpectedResult;
    }
    try testing.expectEqual(std.c.EVFILT.PROC, ev.filter);
    child_gone = true;
    thr.join();
    try testing.expect(ctx.err == null);
    try testing.expect(std.c.kill(pid, 0) != 0); // reaped and gone
}

var hup_pipe_w: std.c.fd_t = -1;

fn hupByte(_: c_int) callconv(.c) void {
    _ = std.c.write(hup_pipe_w, "H", 1);
}

test "Runtime: SIGHUP is forwarded to every child" {
    var pipes: [2][2]posix.fd_t = undefined;
    var pids: [2]posix.pid_t = undefined;
    var sups: [2]Supervisor = undefined;
    var children: [2]ChildCtl = undefined;
    for (0..2) |i| {
        pipes[i] = try posix.pipe();
        pids[i] = try posix.fork();
        if (pids[i] == 0) {
            hup_pipe_w = pipes[i][1];
            const hup: posix.Sigaction = .{
                .handler = .{ .handler = hupByte },
                .flags = 0,
                .mask = posix.sigemptyset(),
            };
            posix.sigaction(posix.SIG.HUP, &hup, null);
            pauseForever();
        }
        sups[i] = try Supervisor.init("/nonexistent", &.{}, 1);
        children[i] = .{
            .name = "stub",
            .pid_file = "stub.pid",
            .exe_base = "stub",
            .sup = &sups[i],
        };
    }
    defer for (0..2) |i| {
        _ = std.c.kill(pids[i], posix.SIG.KILL);
        reap(pids[i]);
        posix.close(pipes[i][0]);
        posix.close(pipes[i][1]);
    };

    const ready = try posix.pipe();
    defer posix.close(ready[0]);
    defer posix.close(ready[1]);
    var ctx: RtThread = .{
        .children = children[0..],
        .run_dir = "/nonexistent",
        .limits = test_limits,
        .pids = pids[0..],
        .ready_w = ready[1],
    };
    const thr = try std.Thread.spawn(.{}, RtThread.main, .{&ctx});
    try awaitReady(ready[0]);

    // Both children must observe the forwarded HUP; the test waits on the
    // two pipe read ends under one deadline.
    var tw = try TestWait.init();
    defer tw.deinit();
    for (0..2) |i| {
        var ev = [_]std.c.Kevent{.{
            .ident = @intCast(pipes[i][0]),
            .filter = std.c.EVFILT.READ,
            .flags = std.c.EV.ADD,
            .fflags = 0,
            .data = 0,
            .udata = i + 1,
        }};
        try testing.expectEqual(0, std.c.kevent(tw.kq, &ev, 1, &ev, 0, null));
    }
    tw.armDeadline(TestWait.wait_deadline_ident, 5000);

    killSelf(posix.SIG.HUP);

    var seen: usize = 0;
    while (seen < 2) : (seen += 1) {
        var ev: std.c.Kevent = undefined;
        if (tw.waitOne(&ev) == null) break;
        try testing.expectEqual(std.c.EVFILT.READ, ev.filter);
        var b: [1]u8 = undefined;
        try testing.expectEqual(@as(usize, 1), try posix.read(@intCast(ev.ident), &b));
        try testing.expectEqual(@as(u8, 'H'), b[0]);
    }
    if (seen < 2) {
        stopRuntime(&ctx);
        thr.join();
        std.debug.print("only {d}/2 children saw the forwarded SIGHUP\n", .{seen});
        return error.TestUnexpectedResult;
    }

    killSelf(posix.SIG.TERM);
    thr.join();
    try testing.expect(ctx.err == null);
}

test "Runtime: a respawned child gets a fresh pid file" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const run_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(run_dir);

    var sup = try Supervisor.init("/bin/sleep", &.{"60"}, 1);
    const pid1 = try sup.spawnChild();
    defer {
        _ = std.c.kill(pid1, posix.SIG.KILL);
        reap(pid1);
    }
    var children = [_]ChildCtl{
        .{ .name = "stub", .pid_file = "stub.pid", .exe_base = "sleep", .sup = &sup },
    };

    var path_buf: [4096]u8 = undefined;
    const pid_path = try procinfo.pidFilePath(&path_buf, run_dir, "stub.pid");
    procinfo.writeChildPid(pid_path, pid1, "sleep");

    const ready = try posix.pipe();
    defer posix.close(ready[0]);
    defer posix.close(ready[1]);
    var ctx: RtThread = .{
        .children = children[0..],
        .run_dir = run_dir,
        .limits = test_limits,
        .pids = &.{pid1},
        .ready_w = ready[1],
    };
    const thr = try std.Thread.spawn(.{}, RtThread.main, .{&ctx});
    try awaitReady(ready[0]);

    // Watch the pid file itself: the respawn rewrites it with the new
    // child's identity (NOTE_WRITE on the truncate+write).
    var tw = try TestWait.init();
    defer tw.deinit();
    const pid_fd = try posix.open(pid_path, .{ .ACCMODE = .RDONLY }, 0);
    defer posix.close(pid_fd);
    {
        var ev = [_]std.c.Kevent{.{
            .ident = @intCast(pid_fd),
            .filter = std.c.EVFILT.VNODE,
            .flags = std.c.EV.ADD | std.c.EV.CLEAR,
            .fflags = std.c.NOTE.WRITE | std.c.NOTE.DELETE | std.c.NOTE.RENAME,
            .data = 0,
            .udata = 0,
        }};
        try testing.expectEqual(0, std.c.kevent(tw.kq, &ev, 1, &ev, 0, null));
    }
    // Respawn backoff after a quick exit is 2 s; allow room under one
    // deadline.
    tw.armDeadline(TestWait.wait_deadline_ident, 8000);

    _ = std.c.kill(pid1, posix.SIG.TERM);

    var ev: std.c.Kevent = undefined;
    const got = tw.waitOne(&ev);
    if (got == null) {
        stopRuntime(&ctx);
        thr.join();
        std.debug.print("pid file never rewritten: respawn did not run\n", .{});
        return error.TestUnexpectedResult;
    }

    const new_pid = blk: {
        const f = try std.fs.cwd().openFile(pid_path, .{});
        defer f.close();
        var buf: [80]u8 = undefined;
        const n = try posix.read(f.handle, &buf);
        var it = std.mem.tokenizeScalar(u8, buf[0..n], ' ');
        break :blk try std.fmt.parseInt(posix.pid_t, it.next().?, 10);
    };
    try testing.expect(new_pid != pid1);
    try testing.expect(std.c.kill(new_pid, 0) == 0); // the respawn is live
    defer {
        _ = std.c.kill(new_pid, posix.SIG.KILL);
        reap(new_pid);
    }

    killSelf(posix.SIG.TERM);
    thr.join();
    try testing.expect(ctx.err == null);
}

/// Bound a runtime that will not exit on its own: wait one event (or the
/// deadline), TERM it if still watching, and join.
fn stopRuntimeBounded(tw: *TestWait, ctx: *const RtThread, thr: std.Thread, ms: i64) void {
    tw.armDeadline(TestWait.wait_deadline_ident, ms);
    var ev: std.c.Kevent = undefined;
    _ = tw.waitOne(&ev);
    stopRuntime(ctx);
    thr.join();
}

fn listenUnix(sock_path: []const u8) !posix.fd_t {
    const fd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(fd);
    var addr: std.c.sockaddr.un = std.mem.zeroes(std.c.sockaddr.un);
    addr.family = posix.AF.UNIX;
    try testing.expect(sock_path.len < addr.path.len);
    @memcpy(addr.path[0..sock_path.len], sock_path);
    try posix.bind(fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.un));
    try posix.listen(fd, 4);
    return fd;
}

test "Runtime: a readiness byte completes the gated startup" {
    const pipe_fds = try posix.pipe();
    const pid = try posix.fork();
    if (pid == 0) {
        posix.close(pipe_fds[0]);
        _ = posix.write(pipe_fds[1], "R") catch {};
        pauseForever();
    }
    posix.close(pipe_fds[1]);
    defer {
        _ = std.c.kill(pid, posix.SIG.KILL);
        reap(pid);
    }

    var sup = try Supervisor.init("/nonexistent", &.{}, 1);
    var children = [_]ChildCtl{
        .{ .name = "stub", .pid_file = "stub.pid", .exe_base = "stub", .sup = &sup },
    };
    const ready = try posix.pipe();
    defer posix.close(ready[0]);
    defer posix.close(ready[1]);
    var ctx: RtThread = .{
        .children = children[0..],
        .run_dir = "/nonexistent",
        .limits = test_limits,
        .pids = &.{pid},
        // The gate owns pipe_fds[0] from here; the forked child holds
        // the write end, the shape a --ready-fd child will take.
        .gate_fds = &.{pipe_fds[0]},
        .ready_w = ready[1],
    };
    const thr = try std.Thread.spawn(.{}, RtThread.main, .{&ctx});
    try awaitReady(ready[0]);

    var tw = try TestWait.init();
    defer tw.deinit();
    stopRuntimeBounded(&tw, &ctx, thr, 800);
    try testing.expect(ctx.err == null);
    try testing.expect(!ctx.start_failed);
    try testing.expectEqual(@as(usize, 1), ctx.ready_count);
}

test "Runtime: the socket prober completes a gate on a listening socket" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const run_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(run_dir);
    const sock_path = try std.fmt.allocPrint(testing.allocator, "{s}/probe.sock", .{run_dir});
    defer testing.allocator.free(sock_path);

    const listener = try listenUnix(sock_path);
    defer posix.close(listener);

    const pid = try posix.fork();
    if (pid == 0) pauseForever();
    defer {
        _ = std.c.kill(pid, posix.SIG.KILL);
        reap(pid);
    }

    var sup = try Supervisor.init("/nonexistent", &.{}, 1);
    var children = [_]ChildCtl{
        .{ .name = "stub", .pid_file = "stub.pid", .exe_base = "stub", .ready_socket = sock_path, .sup = &sup },
    };
    const ready = try posix.pipe();
    defer posix.close(ready[0]);
    defer posix.close(ready[1]);
    var ctx: RtThread = .{
        .children = children[0..],
        .run_dir = "/nonexistent",
        .limits = test_limits,
        .pids = &.{pid},
        .gate_fds = &.{-1},
        .ready_w = ready[1],
    };
    const thr = try std.Thread.spawn(.{}, RtThread.main, .{&ctx});
    try awaitReady(ready[0]);

    var tw = try TestWait.init();
    defer tw.deinit();
    stopRuntimeBounded(&tw, &ctx, thr, 800);
    try testing.expect(ctx.err == null);
    try testing.expect(!ctx.start_failed);
    try testing.expectEqual(@as(usize, 1), ctx.ready_count);
}

test "Runtime: a missed readiness deadline fails the startup" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const run_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(run_dir);
    // Inside the watched directory but never bound: the prober only
    // ever sees refusals until the deadline fires.
    const sock_path = try std.fmt.allocPrint(testing.allocator, "{s}/never.sock", .{run_dir});
    defer testing.allocator.free(sock_path);

    const pid = try posix.fork();
    if (pid == 0) pauseForever();
    var child_gone = false;
    defer {
        if (!child_gone) {
            _ = std.c.kill(pid, posix.SIG.KILL);
            reap(pid);
        }
    }

    var sup = try Supervisor.init("/nonexistent", &.{}, 1);
    var children = [_]ChildCtl{
        .{ .name = "stub", .pid_file = "stub.pid", .exe_base = "stub", .ready_socket = sock_path, .sup = &sup },
    };
    const ready = try posix.pipe();
    defer posix.close(ready[0]);
    defer posix.close(ready[1]);
    var ctx: RtThread = .{
        .children = children[0..],
        .run_dir = "/nonexistent",
        .limits = test_limits,
        .pids = &.{pid},
        .gate_fds = &.{-1},
        .ready_w = ready[1],
    };
    const thr = try std.Thread.spawn(.{}, RtThread.main, .{&ctx});
    try awaitReady(ready[0]);

    // The deadline fires at 300 ms, the runtime TERM-kills the adopted
    // child and exits; the test's own watch bounds the wait. The fail
    // reason separates this path from a child killed by the test's own
    // TERM, which would also read as a failed start.
    var tw = try TestWait.init();
    defer tw.deinit();
    tw.armExit(pid);
    tw.armDeadline(TestWait.wait_deadline_ident, 2000);
    var ev: std.c.Kevent = undefined;
    _ = tw.waitOne(&ev);
    child_gone = true;
    stopRuntime(&ctx);
    thr.join();
    try testing.expect(ctx.err == null);
    try testing.expect(ctx.start_failed);
    try testing.expectEqualStrings("readiness deadline expired", ctx.fail_why);
    try testing.expectEqual(@as(usize, 0), ctx.ready_count);
}

test "Runtime: a gated child exiting before its byte fails the startup" {
    const pipe_fds = try posix.pipe();
    defer posix.close(pipe_fds[1]);

    const pid = try posix.fork();
    if (pid == 0) pauseForever();
    var child_gone = false;
    defer {
        if (!child_gone) {
            _ = std.c.kill(pid, posix.SIG.KILL);
            reap(pid);
        }
    }

    var sup = try Supervisor.init("/nonexistent", &.{}, 1);
    var children = [_]ChildCtl{
        .{ .name = "stub", .pid_file = "stub.pid", .exe_base = "stub", .sup = &sup },
    };
    const ready = try posix.pipe();
    defer posix.close(ready[0]);
    defer posix.close(ready[1]);
    var ctx: RtThread = .{
        .children = children[0..],
        .run_dir = "/nonexistent",
        .limits = test_limits,
        .pids = &.{pid},
        .gate_fds = &.{pipe_fds[0]},
        .ready_w = ready[1],
    };
    const thr = try std.Thread.spawn(.{}, RtThread.main, .{&ctx});
    try awaitReady(ready[0]);

    var tw = try TestWait.init();
    defer tw.deinit();
    tw.armExit(pid);
    tw.armDeadline(TestWait.wait_deadline_ident, 2000);
    _ = std.c.kill(pid, posix.SIG.TERM);
    var ev: std.c.Kevent = undefined;
    _ = tw.waitOne(&ev);
    child_gone = true;
    stopRuntime(&ctx);
    thr.join();
    try testing.expect(ctx.err == null);
    try testing.expect(ctx.start_failed);
    try testing.expectEqualStrings("exited before signaling readiness", ctx.fail_why);
    try testing.expectEqual(@as(usize, 0), ctx.ready_count);
}
