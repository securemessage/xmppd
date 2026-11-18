//! # Runtime: the master's supervisor event machine.
//!
//! Owns the lib/net Loop the supervisor runs on (ADR-8): child exits arrive
//! as EVFILT_PROC NOTE_EXIT events the loop reaps itself (lib/net does the
//! waitpid, including the #60 deferred-reap race fix), restarts and
//! shutdown escalations ride one-shot deadline timers, and TERM/INT/HUP
//! arrive as EVFILT_SIGNAL. Nothing in this file sleeps or waitpid-blocks.
//! HUP is forwarded only to children that declare `forward_hup`: core and
//! s2s install no HUP handler, and the default action would kill them.
//!
//! ## Shutdown
//!
//! TERM/INT signals every live child at once and arms a one-shot deadline.
//! Each NOTE_EXIT is reaped by the loop; when the last child is gone the
//! master exits. A missed deadline escalates to SIGKILL for the stragglers
//! under a second deadline, and a second missed deadline gives up so the
//! master can never hang on an unkillable child. Every internal failure
//! (a respawn that cannot spawn, a deadline that cannot be armed) enters
//! the same path, so the master never exits with a live child it has not
//! signalled; a child still alive at give-up keeps its pid file for the
//! next master's orphan cleanup. TERM also ends a gated startup: the
//! active readiness gate is torn down, so a late byte, deadline or child
//! exit neither spawns the pending children nor marks the stop a failed
//! start.
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
//! nested kqueue fd registered with the loop, the resolver's pattern).
//! A missing socket waits for the next directory event; only a refused
//! connect (the bind-to-listen gap) arms a short retry deadline, one per
//! gate, at most `probe_refused_max` times per directory event so a
//! stale socket file left by a crashed child is never polled. Each probe
//! is a connect-and-close the child sees as a short-lived IPC peer (s2s
//! logs a "core connected" / "core disconnected" pair). A later
//! --ready-fd child can write the same byte itself and the prober goes
//! away; the pipe contract stays.
//!
//! ## Timers
//!
//! Every deadline the runtime arms is held by its TimerId and cancelled
//! when its purpose ends; a deadline whose id no longer matches the held
//! one is stale and ignored.

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
    /// The child installs a SIGHUP handler. HUP's default action
    /// terminates the process, so the master forwards a reload only to
    /// children that opt in.
    forward_hup: bool = false,
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
    /// Refused-connect retries per directory event before the prober
    /// waits for the next event (a stale socket file refuses forever).
    probe_refused_max: u8 = 4,
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
    /// The readiness deadline and the single pending refused-connect
    /// retry, cancelled when the gate completes or closes.
    deadline_timer: ?net.TimerId = null,
    retry_timer: ?net.TimerId = null,
    /// Refused-connect retries since the last directory event.
    refused_retries: u8 = 0,
    active: bool = false,
};

/// Clear `slot` when `fired` is the deadline it holds. False for a stale
/// deadline (cancelled, superseded, or never armed through this slot).
fn takeTimer(slot: *?net.TimerId, fired: net.TimerId) bool {
    const held = slot.* orelse return false;
    if (!held.eql(fired)) return false;
    slot.* = null;
    return true;
}

pub const Runtime = struct {
    allocator: std.mem.Allocator,
    loop: net.Loop = undefined,
    /// Spawn order (dependencies before dependents). Shutdown signals
    /// every live child at once; no child waits on another.
    children: []ChildCtl,
    run_dir: []const u8,
    limits: Limits,
    phase: Phase = .running,
    running: bool = true,
    pid_path: [4096]u8 = undefined,
    /// Readiness gates, index-aligned with children.
    gates: []Gate = &.{},
    /// Pending restart backoff deadlines, index-aligned with children.
    restart_timers: []?net.TimerId = &.{},
    /// The armed TERM-grace or SIGKILL-grace deadline.
    shutdown_timer: ?net.TimerId = null,
    /// connect() probes issued; tests assert the prober does not poll.
    probe_count: usize = 0,
    /// A SIGHUP arrived while the child in waiting_ready was starting;
    /// it is delivered when that child's readiness byte arrives.
    hup_deferred: bool = false,
    /// Next child the startup sequence spawns.
    pending: usize = 0,
    /// Child whose readiness byte the sequence waits on, if any.
    waiting_ready: ?usize = null,
    /// Set when the gated sequence could not finish; main exits nonzero.
    start_failed: bool = false,
    /// The first failure reason; tests assert which path tripped.
    fail_why: []const u8 = "",
    /// Set when supervision itself failed after startup (a respawn, or a
    /// deadline that could not be armed); main exits nonzero.
    runtime_failed: bool = false,
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
        rt.restart_timers = try allocator.alloc(?net.TimerId, children.len);
        errdefer allocator.free(rt.restart_timers);
        @memset(rt.restart_timers, null);
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
        self.allocator.free(self.restart_timers);
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

    /// After run(): remove the pid file of every reaped child. A child
    /// still alive (the SIGKILL grace gave up on it) keeps its file so
    /// the next master's identity-checked orphan cleanup can find it.
    pub fn removeReapedPidFiles(self: *Runtime) void {
        for (self.children) |*ctl| {
            if (ctl.sup.child_pid) |pid| {
                log.warn("child {s} pid={d} is still alive at master exit; keeping {s}", .{ ctl.name, pid, ctl.pid_file });
                continue;
            }
            self.removePidFile(ctl);
        }
    }

    /// Cancel the deadline `slot` holds, if any.
    fn cancelSlot(self: *Runtime, slot: *?net.TimerId) void {
        if (slot.*) |id| _ = self.loop.cancelTimer(id);
        slot.* = null;
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
    /// Once shutdown begins the sequence is over: a late readiness byte
    /// must never spawn a child the shutdown already passed.
    fn advanceStartup(self: *Runtime) !void {
        if (self.phase != .starting) return;
        while (self.pending < self.children.len) {
            const idx = self.pending;
            self.pending += 1;
            _ = try self.spawnChild(idx);
            if (self.children[idx].ready_socket != null) {
                try self.armGate(idx);
                return;
            }
        }
        self.phase = .running;
        log.info("all children spawned and ready", .{});
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
        gate.deadline_timer = self.loop.scheduleIn(self.limits.ready_ms, readyDeadlineCtx(idx)) catch return error.TimerTableFull;
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
        self.cancelSlot(&gate.retry_timer);
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
    /// readiness byte. A refused connect (socket bound, not yet
    /// listening) arms the gate's retry deadline; any other failure,
    /// a missing socket included, waits for the next directory event.
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
        self.probe_count += 1;
        posix.connect(fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.un)) catch |err| {
            switch (err) {
                error.ConnectionRefused, error.WouldBlock => self.armProbeRetry(idx),
                else => {},
            }
            return;
        };
        self.signalReady(idx);
    }

    /// At most one pending retry per gate, and at most probe_refused_max
    /// per directory event: a stale socket file refuses forever and must
    /// not turn the retry into a poll.
    fn armProbeRetry(self: *Runtime, idx: usize) void {
        const gate = &self.gates[idx];
        if (gate.retry_timer != null) return;
        if (gate.refused_retries >= self.limits.probe_refused_max) return;
        gate.refused_retries += 1;
        gate.retry_timer = self.loop.scheduleIn(self.limits.probe_retry_ms, probeRetryCtx(idx)) catch |err| blk: {
            log.warn("{s}: cannot arm readiness probe retry: {}", .{ self.children[idx].name, err });
            break :blk null;
        };
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
        self.cancelSlot(&gate.deadline_timer);
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
        if (self.waiting_ready == idx) {
            self.waiting_ready = null;
            self.hup_deferred = false;
        }
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
    /// A readable with nothing to read yet (WouldBlock) keeps waiting.
    /// A byte outside startup is stale and spawns nothing.
    fn onReadyByte(self: *Runtime, io: net.loop.Io) void {
        const idx: usize = io.ctx.index;
        if (idx >= self.children.len) return;
        if (self.phase != .starting or self.waiting_ready != idx) {
            _ = self.loop.close(io.handle) catch {};
            return;
        }
        const gate = &self.gates[idx];
        var buf: [8]u8 = undefined;
        const n = posix.read(gate.pipe_r, &buf) catch |err| switch (err) {
            error.WouldBlock => return,
            else => 0,
        };
        if (n == 0) {
            self.failStart(idx, "readiness pipe closed without a ready byte");
            return;
        }
        self.closeGate(idx);
        self.waiting_ready = null;
        if (self.hup_deferred) {
            self.hup_deferred = false;
            self.children[idx].sup.forwardSignal(posix.SIG.HUP);
        }
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
        // New directory activity may be a fresh socket: the refused
        // budget restarts, and a pending retry already covers this probe.
        gate.refused_retries = 0;
        if (gate.retry_timer != null) return;
        self.probeConnect(idx);
    }

    /// The supervisor loop: restart dead children per backoff policy,
    /// forward HUP to every child, and drive the shutdown escalation.
    pub fn run(self: *Runtime) void {
        while (self.running) {
            self.step() catch |err| {
                // No deadline can be armed without the loop: TERM every
                // live child once and exit nonzero; unreaped children keep
                // their pid files for the next master's orphan cleanup.
                log.err("event loop wait failed: {}; sending SIGTERM to every child", .{err});
                self.runtime_failed = true;
                for (self.children) |*ctl| ctl.sup.shutdown();
                break;
            };
        }
    }

    /// One loop wait and dispatch of every event it collected.
    fn step(self: *Runtime) !void {
        try self.loop.wait();
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

    /// Any child still tracked as alive (spawned, not yet reaped).
    fn anyAlive(self: *const Runtime) bool {
        for (self.children) |*ctl| {
            if (ctl.sup.child_pid != null) return true;
        }
        return false;
    }

    /// SIGTERM every live child, drop pending respawns and the active
    /// readiness gate, and arm the escalation deadline. The gate teardown
    /// ends a gated startup: no child spawns after this and nothing is
    /// recorded as a startup failure. Idempotent once shutdown has begun.
    fn beginShutdown(self: *Runtime) void {
        if (self.phase == .stopping or self.phase == .killing) return;
        self.phase = .stopping;
        for (self.restart_timers) |*slot| self.cancelSlot(slot);
        for (self.gates, 0..) |*g, i| {
            if (g.active) self.closeGate(i);
        }
        self.waiting_ready = null;
        self.hup_deferred = false;
        for (self.children) |*ctl| ctl.sup.shutdown();
        if (!self.anyAlive()) {
            self.running = false;
            return;
        }
        self.shutdown_timer = self.loop.scheduleIn(self.limits.term_grace_ms, shutdownCtx()) catch |err| {
            log.warn("cannot arm the SIGTERM grace deadline: {}; escalating now", .{err});
            self.runtime_failed = true;
            self.escalate();
            return;
        };
    }

    /// The TERM grace expired: SIGKILL whatever is left and arm the last
    /// deadline, replacing the TERM-grace one. A second TERM while
    /// stopping takes the same path.
    fn escalate(self: *Runtime) void {
        self.phase = .killing;
        self.cancelSlot(&self.shutdown_timer);
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
        self.shutdown_timer = self.loop.scheduleIn(self.limits.kill_grace_ms, shutdownCtx()) catch |err| {
            log.warn("cannot arm the SIGKILL grace deadline: {}; giving up", .{err});
            self.runtime_failed = true;
            self.running = false;
            return;
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
        // A gated child dying before its byte can never become ready;
        // failStart moves the runtime to .stopping, handled below. That
        // only matters while the start is live: after TERM the exit is
        // the requested stop, not a startup failure.
        if (self.phase == .starting and self.waiting_ready == idx) {
            self.failStart(idx, "exited before signaling readiness");
        }
        switch (self.phase) {
            .running, .starting => switch (action) {
                .restart => {
                    log.info("restarting {s} in {d}ms", .{ ctl.name, ctl.sup.backoffMs() });
                    self.restart_timers[idx] = self.loop.scheduleIn(ctl.sup.backoffMs(), restartCtx(idx)) catch |err| {
                        log.warn("cannot schedule {s} restart: {}; shutting down", .{ ctl.name, err });
                        self.runtime_failed = true;
                        self.beginShutdown();
                        return;
                    };
                },
                .shutdown => self.beginShutdown(),
                .ignore => {},
            },
            .stopping, .killing => {
                if (!self.anyAlive()) self.running = false;
            },
        }
    }

    fn onDeadline(self: *Runtime, d: net.Deadline) void {
        const idx: usize = d.ctx.index;
        switch (d.ctx.kind) {
            restart_kind => {
                if (idx >= self.children.len) return;
                if (!takeTimer(&self.restart_timers[idx], d.timer)) return;
                if (self.phase != .running and self.phase != .starting) return;
                const ctl = &self.children[idx];
                _ = self.spawnChild(idx) catch |err| {
                    log.warn("failed to respawn {s}: {}; shutting down", .{ ctl.name, err });
                    self.runtime_failed = true;
                    self.beginShutdown();
                };
            },
            shutdown_kind => {
                if (!takeTimer(&self.shutdown_timer, d.timer)) return;
                switch (self.phase) {
                    .running, .starting => {},
                    .stopping => self.escalate(),
                    .killing => {
                        log.warn("children still alive after SIGKILL grace; giving up", .{});
                        self.runtime_failed = true;
                        self.running = false;
                    },
                }
            },
            ready_deadline_kind => {
                if (idx >= self.children.len) return;
                if (self.phase != .starting) return;
                if (!takeTimer(&self.gates[idx].deadline_timer, d.timer)) return;
                if (self.waiting_ready == idx) self.failStart(idx, "readiness deadline expired");
            },
            probe_retry_kind => {
                if (idx >= self.children.len) return;
                if (!takeTimer(&self.gates[idx].retry_timer, d.timer)) return;
                self.probeConnect(idx);
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
            switch (self.phase) {
                .running, .starting => self.forwardHup(),
                .stopping, .killing => log.info("received SIGHUP during shutdown; not forwarded", .{}),
            }
        }
    }

    /// Forward HUP to every live child that handles it (forward_hup). A
    /// child still awaiting readiness may not have installed its handler
    /// yet, so its copy is held and delivered when its readiness byte
    /// arrives.
    fn forwardHup(self: *Runtime) void {
        log.info("received SIGHUP, forwarding to children that reload on it", .{});
        for (self.children, 0..) |*ctl, i| {
            if (!ctl.forward_hup) continue;
            if (self.waiting_ready == i) {
                self.hup_deferred = true;
                continue;
            }
            ctl.sup.forwardSignal(posix.SIG.HUP);
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

test "Runtime: SIGHUP is forwarded to every forward_hup child and no other" {
    // Children 0 and 1 opt in; child 2 does not (core and s2s install no
    // HUP handler, and the default action would kill them).
    var pipes: [3][2]posix.fd_t = undefined;
    var pids: [3]posix.pid_t = undefined;
    var sups: [3]Supervisor = undefined;
    var children: [3]ChildCtl = undefined;
    for (0..3) |i| {
        pipes[i] = try posix.pipe();
        pids[i] = try forkStub(pipes[i][1], false);
        sups[i] = try Supervisor.init("/nonexistent", &.{}, 1);
        children[i] = .{
            .name = "stub",
            .pid_file = "stub.pid",
            .exe_base = "stub",
            .forward_hup = i < 2,
            .sup = &sups[i],
        };
    }
    defer for (0..3) |i| {
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

    // Both opted-in children must observe the forwarded HUP and child 2
    // must not; the test waits on all three pipe read ends.
    var tw = try TestWait.init();
    defer tw.deinit();
    for (0..3) |i| {
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
    var stray = false;
    while (seen < 2) {
        var ev: std.c.Kevent = undefined;
        if (tw.waitOne(&ev) == null) break;
        try testing.expectEqual(std.c.EVFILT.READ, ev.filter);
        var b: [1]u8 = undefined;
        try testing.expectEqual(@as(usize, 1), try posix.read(@intCast(ev.ident), &b));
        try testing.expectEqual(@as(u8, 'H'), b[0]);
        if (ev.udata == 3) stray = true else seen += 1;
    }
    // Child 2 was signalled after the others if at all: give its byte a
    // bounded window to land before declaring it absent.
    if (!stray and seen == 2) {
        tw.armDeadline(TestWait.wait_deadline_ident, 300);
        var ev: std.c.Kevent = undefined;
        if (tw.waitOne(&ev) != null) stray = ev.udata == 3;
    }
    if (seen < 2 or stray) {
        stopRuntime(&ctx);
        thr.join();
        std.debug.print("forward_hup children saw {d}/2 HUPs; non-opted child signalled: {}\n", .{ seen, stray });
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

/// A private directory with a short absolute path for unix socket
/// tests. testing.tmpDir lives under the checkout's .zig-cache, and
/// sun_path is 104 bytes on FreeBSD, so socket paths built there break
/// on a deep checkout (T436). mkdtemp creates the dir mode 0700; the
/// path stays well under sun_path for any checkout depth.
extern "c" fn mkdtemp(template: [*:0]u8) ?[*:0]u8;

const SockDir = struct {
    buf: [104]u8 = undefined,
    len: usize = 0,

    fn path(self: *const SockDir) []const u8 {
        return self.buf[0..self.len];
    }

    /// "{dir}/{name}" into `buf`; always shorter than sun_path.
    fn sockPath(self: *const SockDir, buf: []u8, name: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ self.path(), name });
    }

    fn cleanup(self: *const SockDir) void {
        std.fs.cwd().deleteTree(self.path()) catch |err|
            std.debug.print("sockDir cleanup {s}: {s}\n", .{ self.path(), @errorName(err) });
    }
};

fn sockDir() !SockDir {
    var tmpl: [104:0]u8 = @splat(0);
    const base = "/tmp/xmppd-rt-XXXXXX";
    @memcpy(tmpl[0..base.len], base);
    const dir = mkdtemp(&tmpl) orelse return error.SockDirFailed;
    const p = std.mem.sliceTo(dir, 0);
    var sd: SockDir = .{};
    try testing.expect(p.len < sd.buf.len);
    @memcpy(sd.buf[0..p.len], p);
    sd.len = p.len;
    return sd;
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
    var sd = try sockDir();
    defer sd.cleanup();
    var sock_buf: [104]u8 = undefined;
    const sock_path = try sd.sockPath(&sock_buf, "probe.sock");

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
    var sd = try sockDir();
    defer sd.cleanup();
    var sock_buf: [104]u8 = undefined;
    // Inside the watched directory but never bound: the prober only
    // ever sees refusals until the deadline fires.
    const sock_path = try sd.sockPath(&sock_buf, "never.sock");

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

// The tests below drive a Runtime on the test thread itself: step() runs
// one loop wait and its dispatch, so state is asserted between events
// with no thread handoff and no timing guesses.

/// Fork a child that suspends forever. With `hup_w` >= 0 it writes 'H'
/// there on each SIGHUP; with `ignore_term` it survives SIGTERM. Returns
/// once the child's dispositions are installed (it writes one byte on a
/// private pipe), so a signal sent next cannot hit the defaults.
fn forkStub(hup_w: posix.fd_t, ignore_term: bool) !posix.pid_t {
    const armed = try posix.pipe();
    defer posix.close(armed[0]);
    const pid = posix.fork() catch |err| {
        posix.close(armed[1]);
        return err;
    };
    if (pid == 0) {
        posix.close(armed[0]);
        if (hup_w >= 0) {
            hup_pipe_w = hup_w;
            const hup: posix.Sigaction = .{
                .handler = .{ .handler = hupByte },
                .flags = 0,
                .mask = posix.sigemptyset(),
            };
            posix.sigaction(posix.SIG.HUP, &hup, null);
        }
        if (ignore_term) {
            const ign: posix.Sigaction = .{
                .handler = .{ .handler = posix.SIG.IGN },
                .flags = 0,
                .mask = posix.sigemptyset(),
            };
            posix.sigaction(posix.SIG.TERM, &ign, null);
        }
        _ = posix.write(armed[1], "A") catch {};
        posix.close(armed[1]);
        pauseForever();
    }
    posix.close(armed[1]);
    var b: [1]u8 = undefined;
    if (try posix.read(armed[0], &b) != 1) return error.StubNotArmed;
    return pid;
}

/// Kill and reap a stub the runtime has not reaped. A reaped pid may be
/// recycled, so callers pass only pids still tracked as live.
fn killStub(sup: *const Supervisor) void {
    const pid = sup.child_pid orelse return;
    _ = std.c.kill(pid, posix.SIG.KILL);
    reap(pid);
}

fn armedTimers(rt: *Runtime) u32 {
    return rt.loop.wheel.entries.count();
}

/// Wait up to `ms` for `fd` to turn readable on a private kqueue.
fn readableWithin(fd: posix.fd_t, ms: i64) !bool {
    var tw = try TestWait.init();
    defer tw.deinit();
    var ev = [_]std.c.Kevent{.{
        .ident = @intCast(fd),
        .filter = std.c.EVFILT.READ,
        .flags = std.c.EV.ADD,
        .fflags = 0,
        .data = 0,
        .udata = 0,
    }};
    try testing.expectEqual(0, std.c.kevent(tw.kq, &ev, 1, &ev, 0, null));
    tw.armDeadline(TestWait.wait_deadline_ident, ms);
    var out: std.c.Kevent = undefined;
    return tw.waitOne(&out) != null;
}

test "Runtime: a missing ready socket is not polled; its directory event probes it" {
    var sd = try sockDir();
    defer sd.cleanup();
    const run_dir = sd.path();
    var sock_buf: [104]u8 = undefined;
    const sock_path = try sd.sockPath(&sock_buf, "late.sock");

    var sup = try Supervisor.init("/nonexistent", &.{}, 1);
    var children = [_]ChildCtl{
        .{ .name = "stub", .pid_file = "stub.pid", .exe_base = "stub", .ready_socket = sock_path, .sup = &sup },
    };
    var limits = test_limits;
    limits.ready_ms = 5_000;
    var rt = try Runtime.init(testing.allocator, children[0..], run_dir, limits);
    defer rt.deinit();
    try rt.adoptChild(0, try forkStub(-1, false));
    defer killStub(&sup);
    rt.phase = .starting;
    rt.pending = children.len;
    try rt.armGate(0);

    // One probe found no socket. Only the readiness deadline is armed:
    // no retry timer stands in for the directory watch.
    try testing.expectEqual(@as(usize, 1), rt.probe_count);
    try testing.expect(rt.gates[0].retry_timer == null);
    try testing.expectEqual(@as(u32, 1), armedTimers(&rt));

    const listener = try listenUnix(sock_path);
    defer posix.close(listener);
    while (rt.ready_count == 0 and !rt.start_failed) try rt.step();
    try testing.expect(!rt.start_failed);
    try testing.expectEqual(@as(usize, 1), rt.ready_count);
    // Directory events alone drove the probes.
    try testing.expect(rt.probe_count <= 3);
    // The readiness deadline was cancelled with the gate.
    try testing.expectEqual(@as(u32, 0), armedTimers(&rt));
}

test "Runtime: a stale socket file is retried a bounded number of times, not polled" {
    var sd = try sockDir();
    defer sd.cleanup();
    const run_dir = sd.path();
    var sock_buf: [104]u8 = undefined;
    const sock_path = try sd.sockPath(&sock_buf, "stale.sock");
    // A crashed child's socket: the file stays, connects are refused.
    posix.close(try listenUnix(sock_path));

    var sup = try Supervisor.init("/nonexistent", &.{}, 1);
    var children = [_]ChildCtl{
        .{ .name = "stub", .pid_file = "stub.pid", .exe_base = "stub", .ready_socket = sock_path, .sup = &sup },
    };
    var limits = test_limits;
    limits.ready_ms = 5_000;
    var rt = try Runtime.init(testing.allocator, children[0..], run_dir, limits);
    defer rt.deinit();
    try rt.adoptChild(0, try forkStub(-1, false));
    defer killStub(&sup);
    rt.phase = .starting;
    rt.pending = children.len;
    try rt.armGate(0);

    // The refused budget runs out and the prober goes quiet; without the
    // cap the retry would run until the readiness deadline failed start.
    while (rt.gates[0].retry_timer != null and !rt.start_failed) try rt.step();
    try testing.expect(!rt.start_failed);
    try testing.expectEqual(@as(usize, 1) + limits.probe_refused_max, rt.probe_count);
    try testing.expectEqual(@as(u32, 1), armedTimers(&rt));

    // The child replacing its socket wakes the prober through the
    // directory watch.
    try std.fs.cwd().deleteFile(sock_path);
    const listener = try listenUnix(sock_path);
    defer posix.close(listener);
    while (rt.ready_count == 0 and !rt.start_failed) try rt.step();
    try testing.expect(!rt.start_failed);
    try testing.expectEqual(@as(usize, 1), rt.ready_count);
}

test "Runtime: a second TERM replaces the TERM-grace deadline instead of stacking it" {
    var sup = try Supervisor.init("/nonexistent", &.{}, 1);
    var children = [_]ChildCtl{
        .{ .name = "stub", .pid_file = "stub.pid", .exe_base = "stub", .sup = &sup },
    };
    var rt = try Runtime.init(testing.allocator, children[0..], "/nonexistent", test_limits);
    defer rt.deinit();
    try rt.adoptChild(0, try forkStub(-1, true));
    defer killStub(&sup);

    const term: net.loop.SignalEvent = .{ .signo = posix.SIG.TERM, .count = 1 };
    rt.onSignal(term);
    try testing.expectEqual(Phase.stopping, rt.phase);
    try testing.expectEqual(@as(u32, 1), armedTimers(&rt));
    // The repeat TERM escalates. A stale TERM-grace deadline left armed
    // would fire inside the SIGKILL grace and give up early.
    rt.onSignal(term);
    try testing.expectEqual(Phase.killing, rt.phase);
    try testing.expectEqual(@as(u32, 1), armedTimers(&rt));
    try testing.expect(rt.shutdown_timer != null);

    while (rt.running) try rt.step();
    try testing.expect(sup.child_pid == null);
}

/// Child a's respawn is refused parent-side (its run uid has no passwd
/// entry, which the supervisor logs at err); child b must then be
/// terminated, not orphaned. Runs under runCaptured so the err log stays
/// out of the test process. 0 on success, a distinct code per mismatch.
fn childRespawnFailure() callconv(.c) u8 {
    var sup_a = Supervisor.init("/nonexistent", &.{}, 1) catch return 10;
    sup_a.uid = 0x7fff_fff0;
    sup_a.backoff_ns = 10 * std.time.ns_per_ms;
    var sup_b = Supervisor.init("/nonexistent", &.{}, 1) catch return 11;
    var children = [_]ChildCtl{
        .{ .name = "a", .pid_file = "a.pid", .exe_base = "stub", .sup = &sup_a },
        .{ .name = "b", .pid_file = "b.pid", .exe_base = "stub", .sup = &sup_b },
    };
    const pid_a = forkStub(-1, false) catch return 12;
    sup_a.child_pid = pid_a;
    defer killStub(&sup_a);
    const pid_b = forkStub(-1, false) catch return 13;
    sup_b.child_pid = pid_b;
    defer killStub(&sup_b);
    var rt = Runtime.init(std.heap.page_allocator, children[0..], "/nonexistent", test_limits) catch return 14;
    defer rt.deinit();
    rt.adoptChild(0, pid_a) catch return 15;
    rt.adoptChild(1, pid_b) catch return 16;

    _ = std.c.kill(pid_a, posix.SIG.KILL);
    while (rt.running) rt.step() catch return 17;
    if (!rt.runtime_failed) return 2;
    if (sup_b.child_pid != null) return 3;
    return 0;
}

test "Runtime: a failed respawn shuts the remaining children down" {
    const captured = try supervisor_mod.runCaptured(childRespawnFailure);
    const stderr = captured.stderr[0..captured.len];
    if (captured.status != 0) std.debug.print("child status {d}, stderr:\n{s}\n", .{ captured.status, stderr });
    try testing.expectEqual(@as(u8, 0), captured.status);
    try testing.expect(std.mem.indexOf(u8, stderr, "failed to respawn a: error.PasswdLookupFailed; shutting down") != null);
}

test "Runtime: deadlines that cannot be armed still terminate every child" {
    // A full timer table: the restart cannot be scheduled, then neither
    // grace deadline can. Each failure falls through to the next stage,
    // so the sibling is still signalled before run() returns.
    var sup_a = try Supervisor.init("/nonexistent", &.{}, 1);
    var sup_b = try Supervisor.init("/nonexistent", &.{}, 1);
    var children = [_]ChildCtl{
        .{ .name = "a", .pid_file = "a.pid", .exe_base = "stub", .sup = &sup_a },
        .{ .name = "b", .pid_file = "b.pid", .exe_base = "stub", .sup = &sup_b },
    };
    const pid_a = try forkStub(-1, false);
    const pid_b = try forkStub(-1, true);
    var tw = try TestWait.init();
    defer tw.deinit();
    tw.armExit(pid_b);
    var rt = try Runtime.init(testing.allocator, children[0..], "/nonexistent", test_limits);
    defer rt.deinit();
    try rt.adoptChild(0, pid_a);
    try rt.adoptChild(1, pid_b);
    defer killStub(&sup_a);
    defer killStub(&sup_b);

    const filler: net.Token = .{ .index = 0, .gen = 1, .kind = 0x7f };
    while (true) _ = rt.loop.scheduleIn(60_000, filler) catch break;

    _ = std.c.kill(pid_a, posix.SIG.KILL);
    while (rt.running) try rt.step();
    try testing.expect(rt.runtime_failed);
    try testing.expectEqual(Phase.killing, rt.phase);
    // b ignores TERM: only the SIGKILL from the escalation ends it.
    tw.armDeadline(TestWait.wait_deadline_ident, 2_000);
    var ev: std.c.Kevent = undefined;
    try testing.expect(tw.waitOne(&ev) != null);
    try testing.expectEqual(std.c.EVFILT.PROC, ev.filter);
    reap(pid_b);
    sup_b.child_pid = null;
}

test "Runtime: only reaped children lose their pid files" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const run_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(run_dir);

    var sup_a = try Supervisor.init("/nonexistent", &.{}, 1);
    var sup_b = try Supervisor.init("/nonexistent", &.{}, 1);
    // b survived the SIGKILL grace: still tracked as live.
    sup_b.child_pid = std.math.maxInt(posix.pid_t);
    var children = [_]ChildCtl{
        .{ .name = "a", .pid_file = "a.pid", .exe_base = "stub", .sup = &sup_a },
        .{ .name = "b", .pid_file = "b.pid", .exe_base = "stub", .sup = &sup_b },
    };
    try tmp.dir.writeFile(.{ .sub_path = "a.pid", .data = "1 1 stub\n" });
    try tmp.dir.writeFile(.{ .sub_path = "b.pid", .data = "2 1 stub\n" });

    var rt: Runtime = .{
        .allocator = testing.allocator,
        .children = children[0..],
        .run_dir = run_dir,
        .limits = test_limits,
    };
    rt.removeReapedPidFiles();
    try testing.expectError(error.FileNotFound, tmp.dir.access("a.pid", .{}));
    try tmp.dir.access("b.pid", .{});
}

test "Runtime: a readable readiness pipe with no byte yet keeps waiting" {
    var sup = try Supervisor.init("/nonexistent", &.{}, 1);
    var children = [_]ChildCtl{
        .{ .name = "stub", .pid_file = "stub.pid", .exe_base = "stub", .sup = &sup },
    };
    var rt = try Runtime.init(testing.allocator, children[0..], "/nonexistent", test_limits);
    defer rt.deinit();
    try rt.adoptChild(0, try forkStub(-1, false));
    defer killStub(&sup);
    const p = try posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
    defer posix.close(p[1]);
    rt.phase = .starting;
    rt.pending = children.len;
    try rt.armGatePipe(0, p[0]);

    // A spurious readable: the read would block, which is not EOF.
    rt.onReadyByte(.{ .handle = rt.gates[0].pipe_rh.?, .ctx = readyPipeCtx(0), .data = 0, .eof = false, .errno = 0 });
    try testing.expect(!rt.start_failed);
    try testing.expect(rt.gates[0].active);

    _ = try posix.write(p[1], "R");
    while (rt.ready_count == 0 and !rt.start_failed) try rt.step();
    try testing.expect(!rt.start_failed);
    try testing.expectEqual(@as(usize, 1), rt.ready_count);
}

test "Runtime: SIGHUP during startup reaches ready children now and the gated child on readiness" {
    const hup_a = try posix.pipe();
    defer posix.close(hup_a[0]);
    defer posix.close(hup_a[1]);
    const hup_b = try posix.pipe();
    defer posix.close(hup_b[0]);
    defer posix.close(hup_b[1]);

    var sup_a = try Supervisor.init("/nonexistent", &.{}, 1);
    var sup_b = try Supervisor.init("/nonexistent", &.{}, 1);
    var children = [_]ChildCtl{
        .{ .name = "a", .pid_file = "a.pid", .exe_base = "stub", .forward_hup = true, .sup = &sup_a },
        .{ .name = "b", .pid_file = "b.pid", .exe_base = "stub", .forward_hup = true, .sup = &sup_b },
    };
    const pid_a = try forkStub(hup_a[1], false);
    const pid_b = try forkStub(hup_b[1], false);
    var rt = try Runtime.init(testing.allocator, children[0..], "/nonexistent", test_limits);
    defer rt.deinit();
    try rt.adoptChild(0, pid_a);
    try rt.adoptChild(1, pid_b);
    defer killStub(&sup_a);
    defer killStub(&sup_b);

    // a is ready; b holds the gated sequence.
    const gate = try posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
    defer posix.close(gate[1]);
    rt.phase = .starting;
    rt.pending = children.len;
    try rt.armGatePipe(1, gate[0]);

    rt.onSignal(.{ .signo = posix.SIG.HUP, .count = 1 });
    try testing.expect(try readableWithin(hup_a[0], 2_000));
    try testing.expect(rt.hup_deferred);
    try testing.expect(!try readableWithin(hup_b[0], 200));

    _ = try posix.write(gate[1], "R");
    while (rt.ready_count == 0 and !rt.start_failed) try rt.step();
    try testing.expect(!rt.start_failed);
    try testing.expect(!rt.hup_deferred);
    try testing.expect(try readableWithin(hup_b[0], 2_000));
}

test "Runtime: a readiness byte after TERM spawns nothing and drops the gate" {
    var sup_a = try Supervisor.init("/nonexistent", &.{}, 1);
    var sup_b = try Supervisor.init("/nonexistent", &.{}, 1);
    var children = [_]ChildCtl{
        .{ .name = "a", .pid_file = "a.pid", .exe_base = "stub", .sup = &sup_a },
        .{ .name = "b", .pid_file = "b.pid", .exe_base = "stub", .sup = &sup_b },
    };
    // Fork before init: watchSignal turns TERM into SIG_IGN process-wide
    // and the stub must keep the default disposition to die on TERM.
    const pid_a = try forkStub(-1, false);
    var rt = try Runtime.init(testing.allocator, children[0..], "/nonexistent", test_limits);
    defer rt.deinit();
    try rt.adoptChild(0, pid_a);
    defer killStub(&sup_a);
    defer killStub(&sup_b);

    // a is up and gating; b is never spawned. The gate owns gate_r[0];
    // the dup keeps the pipe's read side open so the byte below cannot
    // SIGPIPE once shutdown closes the runtime's end.
    const gate_r = try posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
    defer posix.close(gate_r[1]);
    const gate_hold = try posix.dup(gate_r[0]);
    defer posix.close(gate_hold);
    rt.phase = .starting;
    rt.pending = 1;
    try rt.armGatePipe(0, gate_r[0]);
    rt.hup_deferred = true;

    rt.onSignal(.{ .signo = posix.SIG.TERM, .count = 1 });
    try testing.expectEqual(Phase.stopping, rt.phase);
    try testing.expect(rt.waiting_ready == null);
    try testing.expect(!rt.hup_deferred);
    try testing.expect(!rt.gates[0].active);
    // Only the shutdown grace deadline is armed now.
    try testing.expectEqual(@as(u32, 1), armedTimers(&rt));

    // The late byte lands in a pipe the runtime no longer reads, and the
    // gated child exits on its TERM.
    _ = try posix.write(gate_r[1], "R");
    while (rt.running) try rt.step();
    try testing.expectEqual(@as(usize, 1), rt.pending);
    try testing.expectEqual(@as(i128, 0), sup_b.last_start);
    try testing.expectEqual(@as(usize, 0), rt.ready_count);
    try testing.expect(!rt.start_failed);

    // Last line of defense: the spawn sequence itself refuses outside
    // .starting.
    rt.advanceStartupInternal();
    try testing.expectEqual(@as(usize, 1), rt.pending);
    try testing.expectEqual(@as(i128, 0), sup_b.last_start);
}

test "Runtime: the gated child exiting on TERM is a stop, not a failed start" {
    var sup = try Supervisor.init("/nonexistent", &.{}, 1);
    var children = [_]ChildCtl{
        .{ .name = "stub", .pid_file = "stub.pid", .exe_base = "stub", .sup = &sup },
    };
    const pid = try forkStub(-1, false);
    var rt = try Runtime.init(testing.allocator, children[0..], "/nonexistent", test_limits);
    defer rt.deinit();
    try rt.adoptChild(0, pid);
    defer killStub(&sup);
    const p = try posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
    defer posix.close(p[1]);
    rt.phase = .starting;
    rt.pending = children.len;
    try rt.armGatePipe(0, p[0]);

    rt.onSignal(.{ .signo = posix.SIG.TERM, .count = 1 });
    try testing.expectEqual(@as(u32, 1), armedTimers(&rt));
    // The stub dies on TERM; its exit is the requested stop and ends the
    // run, so main exits like any other shutdown.
    rt.run();
    try testing.expectEqual(Phase.stopping, rt.phase);
    try testing.expect(!rt.start_failed);
    try testing.expectEqualStrings("", rt.fail_why);
    try testing.expect(sup.child_pid == null);
}

test "Runtime: TERM while gated cancels the readiness deadline" {
    var sup = try Supervisor.init("/nonexistent", &.{}, 1);
    var children = [_]ChildCtl{
        .{ .name = "stub", .pid_file = "stub.pid", .exe_base = "stub", .sup = &sup },
    };
    const pid = try forkStub(-1, false);
    var rt = try Runtime.init(testing.allocator, children[0..], "/nonexistent", test_limits);
    defer rt.deinit();
    try rt.adoptChild(0, pid);
    defer killStub(&sup);
    const p = try posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
    defer posix.close(p[1]);
    rt.phase = .starting;
    rt.pending = children.len;
    try rt.armGatePipe(0, p[0]);
    // The readiness deadline is the only timer before the signal.
    try testing.expectEqual(@as(u32, 1), armedTimers(&rt));

    rt.onSignal(.{ .signo = posix.SIG.TERM, .count = 1 });
    // The deadline is gone with the gate: only the shutdown grace
    // deadline remains, and nothing can mark this stop a failed start.
    try testing.expectEqual(@as(u32, 1), armedTimers(&rt));
    try testing.expect(rt.gates[0].deadline_timer == null);
    rt.run();
    try testing.expect(!rt.start_failed);
}

test "Runtime: a gated wait that outlives .starting cannot fail or advance the start" {
    // beginShutdown tears the active gate down; the per-path guards are
    // the last line of defense if gated startup state ever outlives the
    // phase. Force that state directly: gate armed, phase .stopping.
    var sup_a = try Supervisor.init("/nonexistent", &.{}, 1);
    var sup_b = try Supervisor.init("/nonexistent", &.{}, 1);
    var children = [_]ChildCtl{
        .{ .name = "a", .pid_file = "a.pid", .exe_base = "stub", .sup = &sup_a },
        .{ .name = "b", .pid_file = "b.pid", .exe_base = "stub", .sup = &sup_b },
    };
    const pid_a = try forkStub(-1, false);
    var rt = try Runtime.init(testing.allocator, children[0..], "/nonexistent", test_limits);
    defer rt.deinit();
    try rt.adoptChild(0, pid_a);
    defer killStub(&sup_a);
    defer killStub(&sup_b);
    const p = try posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
    defer posix.close(p[1]);
    rt.phase = .starting;
    rt.pending = 1;
    try rt.armGatePipe(0, p[0]);
    rt.phase = .stopping;

    // A readiness byte in .stopping is stale: dropped, never consumed.
    _ = try posix.write(p[1], "R");
    try rt.step();
    try testing.expectEqual(@as(usize, 0), rt.ready_count);
    try testing.expectEqual(@as(usize, 1), rt.pending);

    // The spawn sequence itself refuses outside .starting.
    rt.advanceStartupInternal();
    try testing.expectEqual(@as(usize, 1), rt.pending);
    try testing.expectEqual(@as(i128, 0), sup_b.last_start);

    // The armed readiness deadline fires and is dropped.
    while (armedTimers(&rt) != 0 and !rt.start_failed) try rt.step();
    try testing.expect(!rt.start_failed);

    // The gated child's exit is just an exit, never a failed start.
    _ = std.c.kill(sup_a.child_pid.?, posix.SIG.TERM);
    while (rt.running) try rt.step();
    try testing.expect(!rt.start_failed);
    try testing.expect(sup_a.child_pid == null);
}
