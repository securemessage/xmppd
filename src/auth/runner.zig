//! # Auth daemon runner -- shared event loop for xmppd-auth and xmppd-auth-oidc
//!
//! Owns the kqueue event loop, the IPC listener and client lanes (accept,
//! generations, intake backpressure, coalesced flush, close) and signal
//! handling for both auth daemons. The per-daemon Hooks own the store, the
//! worker-pool drain and any message interception; xmppd-auth's loop is the
//! reference for dispatch order, watermarks and close semantics.
//!
//! ## Hooks contract
//!
//! - `pub const log` -- scoped logger used for runner messages
//! - `intercept(self, runner, msg, slot) bool` -- consume a message before
//!   the handler sees it (OIDC parks IdP-bound requests and aborts here);
//!   return false to let the runner deliver it to the handler
//! - `onPoolWake(self, runner)` -- drain the worker pool and queue replies
//!   through runner.replyToLane; never called when no pool fd was given
//! - `onLaneClose(self, slot)` -- extra per-lane teardown after the runner
//!   has dropped the lane's SCRAM sessions
//! - `onSighup(self)` -- the daemon's own SIGHUP handling

const std = @import("std");
const posix = std.posix;
const IpcServer = @import("ipc_server").IpcServer;
const MAX_IPC_CLIENTS = @import("ipc_server").MAX_IPC_CLIENTS;
const protocol = @import("ipc_protocol");
const event_loop_mod = @import("event_loop");
const EventLoop = event_loop_mod.EventLoop;
const ChangeList = event_loop_mod.ChangeList;
const handler_mod = @import("handler");

/// Sentinel value for the listener fd in kqueue udata.
pub const LISTENER_UDATA: usize = std.math.maxInt(usize);

/// Sentinel value for the worker-pool wake pipe in kqueue udata.
pub const POOL_UDATA: usize = std.math.maxInt(usize) - 1;

/// Base udata for IPC client connections.
pub const CLIENT_UDATA_BASE: usize = 0x10000;

/// Backpressure watermarks for IPC client intake. Sized against the SCRAM
/// frame reality: a challenge+result pair is ~300 bytes, so 256 KiB of
/// backlog is ~850 in-flight exchanges -- deep but bounded.
pub const RX_PAUSE_AT: usize = 768 << 10;
pub const RX_RESUME_AT: usize = 256 << 10;

pub fn Runner(comptime Store: type, comptime Hooks: type) type {
    return struct {
        allocator: std.mem.Allocator,
        hooks: *Hooks,
        handler: *handler_mod.AuthHandler(Store),
        mechs: []const protocol.MechanismId,

        /// Heap-allocated: the struct is ~2 MB since MAX_IPC_CLIENTS went
        /// 16 -> 80, too big for the stack (T161).
        ipc: *IpcServer,
        loop: EventLoop,

        /// Scratch for batching changes across iterations. Sized for the
        /// worst iteration: one write arm + one pause-toggle per client
        /// lane plus loop constants (S22).
        scratch: [2 * MAX_IPC_CLIENTS + 8]posix.Kevent = undefined,
        batch: ChangeList = undefined,

        /// ABA guard for deferred replies: bumped on every client accept so
        /// a stale completion can't land on a different core connection
        /// that reused the slot.
        ipc_gens: [MAX_IPC_CLIENTS]u32 = [_]u32{0} ** MAX_IPC_CLIENTS,

        /// Intake throttle: when a lane's response backlog passes the
        /// high-water mark, stop reading NEW requests from that client
        /// (EV_DISABLE its read filter) until the backlog drains. Purely
        /// event-driven -- no timers.
        read_paused: [MAX_IPC_CLIENTS]bool = [_]bool{false} ** MAX_IPC_CLIENTS,

        /// The watermarks as instance fields: tests shrink the window
        /// instead of producing 768 KiB of replies.
        rx_pause_at: usize = RX_PAUSE_AT,
        rx_resume_at: usize = RX_RESUME_AT,

        /// Lanes that gained outbound backlog this iteration; flushed once
        /// per iteration at the end of event dispatch (S22): a write sitting
        /// un-staged strands replies until unrelated activity.
        flush_pending: [MAX_IPC_CLIENTS]bool = [_]bool{false} ** MAX_IPC_CLIENTS,

        running: bool = true,

        const Self = @This();

        /// Everything init() can fail with: the IPC listener socket, the
        /// kqueue and the staged registrations.
        pub const InitError = posix.SocketError || posix.BindError || posix.ListenError ||
            posix.KQueueError || error{
            OutOfMemory,
            PathTooLong,
            EventNotFound,
            ProcessNotFound,
            SystemResources,
        };

        pub fn init(
            self: *Self,
            allocator: std.mem.Allocator,
            hooks: *Hooks,
            handler: *handler_mod.AuthHandler(Store),
            socket_path: []const u8,
            mechs: []const protocol.MechanismId,
            pool_fd: ?posix.fd_t,
        ) InitError!void {
            // The hooks contract, checked at call time so Hooks may be the
            // enclosing daemon type (a self-referential field).
            comptime {
                if (!@hasDecl(Hooks, "log"))
                    @compileError("auth runner hooks must declare 'pub const log' (std.log.scoped)");
                for (.{ "intercept", "onPoolWake", "onLaneClose", "onSighup" }) |name| {
                    if (!std.meta.hasFn(Hooks, name))
                        @compileError("auth runner hooks must provide fn " ++ name);
                }
            }
            self.allocator = allocator;
            self.hooks = hooks;
            self.handler = handler;
            self.mechs = mechs;
            self.ipc_gens = [_]u32{0} ** MAX_IPC_CLIENTS;
            self.read_paused = [_]bool{false} ** MAX_IPC_CLIENTS;
            self.rx_pause_at = RX_PAUSE_AT;
            self.rx_resume_at = RX_RESUME_AT;
            self.flush_pending = [_]bool{false} ** MAX_IPC_CLIENTS;
            self.running = true;
            self.batch = ChangeList.init(&self.scratch);

            const ipc = try allocator.create(IpcServer);
            errdefer allocator.destroy(ipc);
            ipc.* = IpcServer.init(allocator);
            try ipc.listen(socket_path);
            errdefer ipc.deinit();
            self.ipc = ipc;

            self.loop = try EventLoop.init(allocator, 32);
            errdefer self.loop.deinit();

            // Register listener + signals (signal masking is automatic).
            try self.loop.addFd(ipc.listen_fd, .read, LISTENER_UDATA);
            if (pool_fd) |fd| try self.loop.addFd(fd, .read, POOL_UDATA);
            try self.loop.addSignal(posix.SIG.TERM);
            try self.loop.addSignal(posix.SIG.INT);
            try self.loop.addSignal(posix.SIG.HUP);
        }

        pub fn deinit(self: *Self) void {
            self.ipc.deinit();
            self.allocator.destroy(self.ipc);
            self.loop.deinit();
        }

        /// One poll iteration: submit staged changes, dispatch the events,
        /// then flush every lane that gained backlog once.
        pub fn step(self: *Self, timeout_ms: ?u32) !void {
            const events = self.loop.submitAndPoll(self.batch.slice(), timeout_ms) catch |err| {
                Hooks.log.err("event loop poll failed: {}", .{err});
                return err;
            };
            self.batch.reset();

            for (events) |ev| {
                switch (ev) {
                    .signal => |s| {
                        if (s.signo == posix.SIG.TERM or s.signo == posix.SIG.INT) {
                            Hooks.log.info("received signal {d}, shutting down", .{s.signo});
                            self.running = false;
                        } else if (s.signo == posix.SIG.HUP) {
                            self.hooks.onSighup();
                        }
                    },
                    .fd_readable => |e| {
                        if (e.udata == LISTENER_UDATA) {
                            self.acceptClient();
                        } else if (e.udata == POOL_UDATA) {
                            self.hooks.onPoolWake(self);
                        } else if (e.udata >= CLIENT_UDATA_BASE) {
                            const slot = e.udata - CLIENT_UDATA_BASE;
                            // A paused client's read filter is disabled, so
                            // no event should arrive -- but one may already
                            // be queued from before the disable landed.
                            if (!self.read_paused[slot]) self.handleIpcClient(slot);
                        }
                    },
                    .fd_writable => |e| {
                        if (e.udata >= CLIENT_UDATA_BASE) {
                            const slot = e.udata - CLIENT_UDATA_BASE;
                            self.flushIpcClient(slot);
                        }
                    },
                    else => {},
                }
            }

            // Coalesced flush: every lane that gained backlog this iteration
            // writes once here. A lane still holding backlog afterwards gets
            // its one-shot write arm. A swallowed staging failure strands
            // the lane's replies (S22); close such a lane loudly.
            for (&self.flush_pending, 0..) |*dirty, slot| {
                if (!dirty.*) continue;
                dirty.* = false;
                const conn = self.ipc.getClient(slot) orelse continue;
                _ = conn.flush() catch {
                    Hooks.log.err("IPC client {d} flush error: closing", .{slot});
                    self.closeLane(slot);
                    continue;
                };
                if (conn.hasPendingSend()) {
                    self.batch.addWriteOnce(conn.fd, CLIENT_UDATA_BASE + slot) catch {
                        Hooks.log.err("change list full arming write for IPC slot {d}: closing the lane", .{slot});
                        self.closeLane(slot);
                        continue;
                    };
                }
            }
        }

        pub fn run(self: *Self) void {
            while (self.running) {
                self.step(null) catch break;
            }
        }

        fn acceptClient(self: *Self) void {
            const slot = (self.ipc.accept() catch |err| {
                Hooks.log.err("IPC accept failed: {s}", .{@errorName(err)});
                return;
            }) orelse return;
            self.ipc_gens[slot] +%= 1;
            self.read_paused[slot] = false;
            const conn = self.ipc.getClient(slot) orelse return;
            self.batch.addRead(conn.fd, CLIENT_UDATA_BASE + slot) catch {
                Hooks.log.err("change list full accepting IPC slot {d}: closing the lane", .{slot});
                self.closeLane(slot);
                return;
            };

            // Send MechanismList immediately on connect.
            const ml_msg = protocol.Message{ .mechanism_list = protocol.MechanismList.init(self.mechs) };
            conn.queueSend(ml_msg) catch {
                self.closeLane(slot);
                return;
            };
            if (conn.hasPendingSend()) self.flush_pending[slot] = true;
        }

        /// Close an IPC client lane: its sessions die with it (T279) instead
        /// of waiting for the 60 s stale probe, its staged changes are
        /// dropped, and the daemon's own teardown runs before closeClient.
        pub fn closeLane(self: *Self, slot: usize) void {
            if (self.ipc.getClient(slot)) |conn| self.batch.purgeFd(conn.fd);
            self.handler.closeLaneSessions(slot);
            self.hooks.onLaneClose(slot);
            self.ipc.closeClient(slot);
            self.read_paused[slot] = false;
            self.flush_pending[slot] = false;
        }

        /// Queue a reply to a lane: a send failure closes the lane, and the
        /// queued bytes join the end-of-iteration flush and count against
        /// the intake throttle.
        pub fn replyToLane(self: *Self, slot: usize, msg: protocol.Message) void {
            const conn = self.ipc.getClient(slot) orelse return;
            conn.queueSend(msg) catch {
                self.closeLane(slot);
                return;
            };
            if (conn.hasPendingSend()) self.flush_pending[slot] = true;
            self.updateReadBackpressure(slot);
        }

        fn updateReadBackpressure(self: *Self, slot: usize) void {
            const conn = self.ipc.getClient(slot) orelse return;
            if (conn.fd < 0) return;
            const pend = conn.pendingSendBytes();
            if (!self.read_paused[slot] and pend > self.rx_pause_at) {
                self.read_paused[slot] = true;
                self.batch.disableRead(conn.fd) catch {
                    // Can't enforce the throttle: a missed EV_DISABLE would
                    // spin the loop on a drowned lane (S22). Close rather
                    // than lie.
                    Hooks.log.err("change list full pausing IPC slot {d}: closing the lane", .{slot});
                    self.closeLane(slot);
                    return;
                };
                Hooks.log.warn("IPC client {d}: {d}B outbound backlog > {d}B -- pausing intake until drained", .{ slot, pend, self.rx_pause_at });
            } else if (self.read_paused[slot] and pend < self.rx_resume_at) {
                self.read_paused[slot] = false;
                self.batch.enableRead(conn.fd) catch {
                    Hooks.log.err("change list full resuming IPC slot {d}: closing the lane", .{slot});
                    self.closeLane(slot);
                    return;
                };
                Hooks.log.info("IPC client {d}: backlog drained to {d}B -- resuming intake", .{ slot, pend });
            }
        }

        fn handleIpcClient(self: *Self, slot: usize) void {
            defer self.updateReadBackpressure(slot);
            const conn = self.ipc.getClient(slot) orelse return;

            const rr = conn.recv() catch |err| {
                Hooks.log.err("IPC client {d} recv error: {} -- closing", .{ slot, err });
                self.closeLane(slot);
                return;
            };

            // .would_block is a stale event, not a hangup (T329): fall
            // through and still parse whatever the buffer already holds.
            if (rr == .eof) {
                self.closeLane(slot);
                return;
            }

            // Process all complete messages
            while (true) {
                const msg = conn.nextMessage() catch {
                    self.closeLane(slot);
                    return;
                };

                if (msg == null) break;

                if (self.hooks.intercept(self, msg.?, @intCast(slot))) {
                    // intercept may have closed the lane on a send failure.
                    if (self.ipc.getClient(slot) == null) return;
                    continue;
                }

                switch (self.handler.handleMessage(msg.?, @intCast(slot), self.ipc_gens[slot])) {
                    .reply => |response| {
                        conn.queueSend(response) catch {
                            self.closeLane(slot);
                            return;
                        };

                        // Clean up SCRAM session after sending
                        // success/failure (lane, conn_id) keyed: lanes
                        // share conn_id numbers (T279).
                        switch (response) {
                            .auth_success => |s| self.handler.cleanupSession(@intCast(slot), s.conn_id),
                            .auth_failure => |f| self.handler.cleanupSession(@intCast(slot), f.conn_id),
                            else => {},
                        }

                        // Deferred flush: the lane writes once at end of
                        // iteration (S22).
                        if (conn.hasPendingSend()) self.flush_pending[slot] = true;
                    },
                    .deferred, .none => {},
                }
            }
        }

        fn flushIpcClient(self: *Self, slot: usize) void {
            const conn = self.ipc.getClient(slot) orelse return;

            _ = conn.flush() catch {
                self.closeLane(slot);
                return;
            };

            // Re-arm write if more data pending
            if (conn.hasPendingSend()) {
                self.batch.addWriteOnce(conn.fd, CLIENT_UDATA_BASE + slot) catch {
                    Hooks.log.err("change list full arming write in flushIpcClient for slot {d}: closing the lane", .{slot});
                    self.closeLane(slot);
                    return;
                };
            }
            self.updateReadBackpressure(slot);
        }
    };
}
