//! # Runtime — the master's supervisor event machine.
//!
//! Owns the lib/net Loop the supervisor runs on (ADR-8): child exits arrive
//! as EVFILT_PROC NOTE_EXIT events the loop reaps itself (lib/net does the
//! waitpid, including the #60 deferred-reap race fix), restarts ride
//! one-shot deadline timers, and TERM/INT/HUP arrive as EVFILT_SIGNAL.
//!
//! The current shutdown path still waits children sequentially; the
//! shutdown item replaces that with the deadline-escalation machine.

const std = @import("std");
const net = @import("net");
const supervisor_mod = @import("supervisor.zig");
const procinfo = @import("procinfo.zig");

const posix = std.posix;
const Supervisor = supervisor_mod.Supervisor;

const log = std.log.scoped(.xmppd);

/// Timer ctx kind for a child's restart backoff deadline.
const restart_kind: u8 = 0x81;

fn restartCtx(idx: usize) net.Token {
    return .{ .index = @intCast(idx), .gen = 1, .kind = restart_kind };
}

/// One supervised child in the runtime table.
pub const ChildCtl = struct {
    /// Short name for log lines ("auth", "s2s", "core").
    name: []const u8,
    /// Child pid-file basename under run_dir ("auth.pid").
    pid_file: []const u8,
    /// Executable comm basename recorded in the pid file (orphan identity).
    exe_base: []const u8,
    sup: *Supervisor,
};

pub const Runtime = struct {
    allocator: std.mem.Allocator,
    loop: net.Loop = undefined,
    /// Spawn order; shutdown signals children in reverse (dependents first).
    children: []ChildCtl,
    run_dir: []const u8,
    running: bool = true,
    pid_path: [4096]u8 = undefined,

    pub const InitError = net.Loop.InitError || net.Loop.WatchSignalError;

    /// Create the loop and claim TERM/INT/HUP through EVFILT_SIGNAL.
    pub fn init(
        allocator: std.mem.Allocator,
        children: []ChildCtl,
        run_dir: []const u8,
    ) InitError!Runtime {
        var rt: Runtime = .{
            .allocator = allocator,
            .children = children,
            .run_dir = run_dir,
        };
        try rt.loop.init(allocator, &.{ .handles_max = 32, .timers_max = 16 });
        errdefer rt.loop.deinit(allocator);
        try rt.loop.watchSignal(posix.SIG.TERM);
        try rt.loop.watchSignal(posix.SIG.INT);
        try rt.loop.watchSignal(posix.SIG.HUP);
        return rt;
    }

    pub fn deinit(self: *Runtime) void {
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

    fn writePidFile(self: *Runtime, ctl: *const ChildCtl, pid: posix.pid_t) void {
        const path = procinfo.pidFilePath(&self.pid_path, self.run_dir, ctl.pid_file) catch return;
        procinfo.writeChildPid(path, pid, ctl.exe_base);
    }

    /// Remove a child pid file (graceful shutdown path).
    pub fn removePidFile(self: *Runtime, ctl: *const ChildCtl) void {
        const path = procinfo.pidFilePath(&self.pid_path, self.run_dir, ctl.pid_file) catch return;
        procinfo.removeChildPid(path);
    }

    /// The supervisor loop: restart dead children per backoff policy,
    /// forward HUP to the auth child, and shut everything down on TERM/INT.
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
                    else => {},
                }
            }
        }
    }

    fn childIndexOf(self: *Runtime, pid: posix.pid_t) ?usize {
        for (self.children, 0..) |*ctl, i| {
            if (ctl.sup.child_pid != null and ctl.sup.child_pid.? == pid) return i;
        }
        return null;
    }

    fn onChildExit(self: *Runtime, p: net.ProcessExit) void {
        const idx = self.childIndexOf(p.pid) orelse return;
        const ctl = &self.children[idx];
        const action = ctl.sup.handleChildExit(p.status);
        ctl.sup.child_pid = null;
        switch (action) {
            .restart => {
                log.info("restarting {s} in {d}ms", .{ ctl.name, ctl.sup.backoffMs() });
                _ = self.loop.scheduleIn(ctl.sup.backoffMs(), restartCtx(idx)) catch |err| {
                    log.err("cannot schedule {s} restart: {}", .{ ctl.name, err });
                    self.running = false;
                };
            },
            .shutdown => self.running = false,
            .ignore => {},
        }
    }

    fn onDeadline(self: *Runtime, d: net.Deadline) void {
        if (d.ctx.kind != restart_kind) return;
        const idx: usize = d.ctx.index;
        if (idx >= self.children.len) return;
        const ctl = &self.children[idx];
        _ = self.spawnChild(idx) catch |err| {
            log.err("failed to respawn {s}: {}", .{ ctl.name, err });
            self.running = false;
        };
    }

    fn onSignal(self: *Runtime, s: net.SignalEvent) void {
        if (s.signo == posix.SIG.TERM or s.signo == posix.SIG.INT) {
            log.info("received signal {d}, shutting down", .{s.signo});
            // Dependents first (spawn order reversed): core, s2s, auth.
            var i = self.children.len;
            while (i > 0) {
                i -= 1;
                const ctl = &self.children[i];
                ctl.sup.shutdown();
                _ = ctl.sup.waitChild() catch {};
            }
            self.running = false;
        } else if (s.signo == posix.SIG.HUP) {
            log.info("received SIGHUP, forwarding to auth daemon", .{});
            self.children[0].sup.forwardSignal(@intCast(s.signo));
        }
    }
};
