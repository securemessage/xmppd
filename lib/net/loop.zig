//! Loop: one kqueue, one thread, staged interest reconciliation (ADR-8, F2).
//!
//! A Loop owns its attached fds until `close` or `detach`. Consumers stage
//! interest with `attach`/`setInterest`; one `wait()` per iteration commits
//! every change in a single kevent(2) (the change buffer holds at most two
//! entries per handle, so it cannot overflow) and harvests ready events.
//! `next()` translates one event at a time so the handle generation is
//! checked at delivery: an event for a handle closed earlier in the same
//! batch is dropped as stale and can never reach a connection that reused
//! the slot or the fd.
//!
//! Read interest is EV_CLEAR and persistent (handlers drain to EAGAIN); write
//! interest is EV_DISPATCH, re-armed only while wanted. `close` tombstones the
//! handle's dirty-list entry, so the other handles' changes keep their order.
//! Registration failures arrive as EV_ERROR records on the eventlist (the
//! event buffer always has room for every change) and are delivered as
//! `change_failed` events, never ignored.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const kev = @import("kevent.zig");
const Token = @import("token.zig").Token;
const SlotMap = @import("slotmap.zig").SlotMap;
const wake_mod = @import("wake.zig");
const wheel_mod = @import("timer_wheel.zig");

/// Kind values minted by the loop itself. Consumer kinds live only in `ctx`.
pub const handle_kind: u8 = 0x01;
pub const wake_kind: u8 = 0x02;
pub const timer_kind: u8 = 0x03;
pub const broadcast_kind: u8 = 0x04;
pub const signal_kind: u8 = 0x05;
pub const proc_kind: u8 = 0x06;
// No internal ctx kind is reserved: loop-internal timers (the listener's
// fallback resume) identify themselves by TimerId, so every kind value
// stays available to consumers.

/// Process-global signal ownership: a signal may have exactly one watching
/// loop process-wide. SIGCHLD is excluded and keeps SIG_DFL.
pub const max_signal = 128;
var signal_owners = [_]std.atomic.Value(bool){std.atomic.Value(bool).init(false)} ** max_signal;

/// Ident and udata of the loop's EVFILT_USER knote.
pub const wake_ident: usize = 0;
pub const wake_token: Token = .{ .index = 0, .gen = 1, .kind = wake_kind };
const broadcast_token: Token = .{ .index = 0, .gen = 1, .kind = broadcast_kind };
pub const timer_ident: usize = 0;
const timer_token: Token = .{ .index = 0, .gen = 1, .kind = timer_kind };

pub const TimerId = wheel_mod.TimerId;
pub const Deadline = wheel_mod.Deadline;

pub const Handle = Token;
pub const Interest = packed struct(u8) { read: bool = false, write: bool = false, _pad: u6 = 0 };
pub const Filter = enum(u8) { read, write };
pub const Op = enum(u8) { add, enable, disable };

pub const Io = struct {
    handle: Handle,
    ctx: Token,
    data: i64,
    eof: bool,
    errno: u32,
};

pub const ChangeFailure = struct {
    handle: Handle,
    ctx: Token,
    filter: Filter,
    op: Op,
    errno: u32,
};

pub const SignalEvent = struct { signo: u32, count: i64 };
pub const ProcessExit = struct { pid: posix.pid_t };

pub const Event = union(enum) {
    readable: Io,
    writable: Io,
    change_failed: ChangeFailure,
    wake,
    broadcast_closed,
    deadline: Deadline,
    signal: SignalEvent,
    process_exit: ProcessExit,
};

pub const Stats = struct {
    waits: u64 = 0,
    changes_committed: u64 = 0,
    raw_events: u64 = 0,
    delivered_events: u64 = 0,
    stale_events: u64 = 0,
    change_failures: u64 = 0,
    synthetic_events: u64 = 0,
    paused_resumes: u64 = 0,
    handles_attached: u64 = 0,
    handles_closed: u64 = 0,
    wakes: u64 = 0,
    last_errno: u32 = 0,
};

const RegState = enum(u8) { none, enabled, disabled };

const HandleState = struct {
    fd: posix.fd_t,
    ctx: Token,
    want: Interest,
    reg_read: RegState,
    reg_write: RegState,
    dirty: bool,
    paused: bool, // read disabled until the next close() on this loop
    broken: bool, // a change was rejected; the consumer must close
    req_read: bool, // a readable synthetic event is queued
    req_write: bool, // a writable synthetic event is queued
};

const RequeueEntry = struct { token: Token, filter: Filter };

pub const AttachError = error{HandleTableFull};
pub const HandleError = error{StaleHandle};
pub const PauseError = error{ StaleHandle, PausedListFull };
pub const DetachError = error{StaleHandle} || kev.ApplyError;
pub const WaitError = kev.SubmitWaitError || error{ TimerArmFailed, BroadcastDisarmFailed };
pub const InitError = std.mem.Allocator.Error || error{ SystemResources, Unexpected };

pub const FlushHook = struct {
    ctx: *anyopaque,
    func: *const fn (ctx: *anyopaque) void,
};

pub const Options = struct {
    handles_max: u32,
    timers_max: u32,
    events_max: u32 = 256,
    paused_max: u16 = 16,
    on_flush: ?FlushHook = null,
};

const extras_max = 2; // loop-internal changes beyond the two per handle

pub const Loop = struct {
    kq: posix.fd_t,
    handles: SlotMap(HandleState),
    dirty: std.ArrayList(Token),
    requeue_list: std.ArrayList(RequeueEntry),
    requeue_len: usize, // entries staged before this wait, emitted this pass
    requeue_pos: usize,
    paused: std.ArrayList(Token),
    change_buf: []kev.Kevent,
    event_buf: []kev.Kevent,
    batch_pos: usize,
    batch_len: usize,
    batch_changes: usize,
    immediate: bool,
    options: Options,
    stats_: Stats,
    now_ms_: u64,
    owner_tid: std.Thread.Id,
    wake_state: wake_mod.Wake,
    broadcast_fd: posix.fd_t,
    broadcast_seen: bool,
    broadcast_disarm: bool,
    wheel: wheel_mod.TimerWheel,
    timer_armed: bool,
    armed_deadline: u64,
    timer_ready: bool,
    internal_failure: ?InternalFailure,
    watched_signals: std.StaticBitSet(max_signal),

    const InternalFailure = enum { timer, broadcast };

    /// Creates a CLOEXEC kqueue and allocates every buffer; no allocation
    /// happens after init.
    pub fn init(self: *Loop, gpa: std.mem.Allocator, options: *const Options) InitError!void {
        std.debug.assert(options.handles_max >= 1 and options.handles_max <= (1 << 20));
        std.debug.assert(options.events_max >= 1);

        const kq = kqueuex(kqueue_cloexec);
        if (kq < 0) {
            return switch (posix.errno(kq)) {
                .NOMEM, .MFILE, .NFILE => error.SystemResources,
                else => error.Unexpected,
            };
        }
        errdefer posix.close(kq);

        var handles: SlotMap(HandleState) = undefined;
        try handles.init(gpa, options.handles_max, handle_kind);
        errdefer handles.deinit(gpa);

        const change_cap = 2 * options.handles_max + extras_max;
        const change_buf = try gpa.alloc(kev.Kevent, change_cap);
        errdefer gpa.free(change_buf);
        const event_buf = try gpa.alloc(kev.Kevent, change_cap + options.events_max);
        errdefer gpa.free(event_buf);
        const dirty = try gpa.alloc(Token, options.handles_max);
        errdefer gpa.free(dirty);
        const requeue_list = try gpa.alloc(RequeueEntry, 2 * options.handles_max);
        errdefer gpa.free(requeue_list);
        const paused = try gpa.alloc(Token, options.paused_max);
        errdefer gpa.free(paused);

        var wheel: wheel_mod.TimerWheel = undefined;
        try wheel.init(gpa, options.timers_max, monotonicMs());
        errdefer wheel.deinit(gpa);

        self.* = .{
            .kq = kq,
            .handles = handles,
            .dirty = std.ArrayList(Token).initBuffer(dirty),
            .requeue_list = std.ArrayList(RequeueEntry).initBuffer(requeue_list),
            .requeue_len = 0,
            .requeue_pos = 0,
            .paused = std.ArrayList(Token).initBuffer(paused),
            .change_buf = change_buf,
            .event_buf = event_buf,
            .batch_pos = 0,
            .batch_len = 0,
            .batch_changes = 0,
            .immediate = false,
            .options = options.*,
            .stats_ = .{},
            .now_ms_ = monotonicMs(),
            .owner_tid = std.Thread.getCurrentId(),
            .wake_state = .{ .kq = kq, .pending = std.atomic.Value(bool).init(false) },
            .broadcast_fd = -1,
            .broadcast_seen = false,
            .broadcast_disarm = false,
            .wheel = wheel,
            .timer_armed = false,
            .armed_deadline = 0,
            .timer_ready = false,
            .internal_failure = null,
            .watched_signals = std.StaticBitSet(max_signal).initEmpty(),
        };

        // The EVFILT_USER wake knote lives for the loop's lifetime; EV_CLEAR
        // so a delivered trigger resets state and a fresh notify refires.
        const add_user = kev.Kevent{
            .ident = wake_ident,
            .filter = std.c.EVFILT.USER,
            .flags = std.c.EV.ADD | std.c.EV.CLEAR,
            .fflags = 0,
            .data = 0,
            .udata = wake_token.toUdata(),
        };
        kev.applyNow(kq, &add_user) catch |err| return switch (err) {
            error.SystemResources => error.SystemResources,
            else => error.Unexpected,
        };
    }

    /// Closes every attached fd and the kqueue, releasing owned signals.
    pub fn deinit(self: *Loop, gpa: std.mem.Allocator) void {
        var it = self.watched_signals.iterator(.{});
        while (it.next()) |signo| {
            signal_owners[signo].store(false, .release);
            restoreDefaultHandler(@intCast(signo));
        }
        for (self.handles.values[0..self.handles.pool]) |h| {
            if (h.fd >= 0) rawClose(h.fd);
        }
        posix.close(self.kq);
        self.handles.deinit(gpa);
        self.wheel.deinit(gpa);
        gpa.free(self.dirty.allocatedSlice());
        gpa.free(self.requeue_list.allocatedSlice());
        gpa.free(self.paused.allocatedSlice());
        gpa.free(self.change_buf);
        gpa.free(self.event_buf);
        self.* = undefined;
    }

    // -- Handles -------------------------------------------------------------

    /// Register `fd` (the loop takes ownership until close/detach) with the
    /// consumer token `ctx` and initial `interest`. Changes are staged, not
    /// sent to the kernel until `wait()`.
    pub fn attach(self: *Loop, fd: posix.fd_t, ctx: Token, interest: Interest) AttachError!Handle {
        self.assertOwner();
        std.debug.assert(fd >= 0);
        if (builtin.mode == .Debug) {
            // One knote pair per (fd, filter); a duplicate fd would overwrite
            // the first handle's knotes and deliver its events to the second.
            for (self.handles.values[0..self.handles.pool]) |h| {
                std.debug.assert(h.fd != fd);
            }
        }
        const token = self.handles.insert(.{
            .fd = fd,
            .ctx = ctx,
            .want = interest,
            .reg_read = .none,
            .reg_write = .none,
            .dirty = true,
            .paused = false,
            .broken = false,
            .req_read = false,
            .req_write = false,
        }) catch return error.HandleTableFull;
        self.dirty.appendAssumeCapacity(token);
        self.stats_.handles_attached += 1;
        return token;
    }

    /// Change the wanted interest; staged until the next `wait()`. Calling
    /// with `.read = false` disables the knote (cheap resume), it does not
    /// delete it.
    pub fn setInterest(self: *Loop, handle: Handle, interest: Interest) HandleError!void {
        self.assertOwner();
        const h = self.resolve(handle) orelse return error.StaleHandle;
        h.want = interest;
        self.markDirty(handle, h);
    }

    /// Emit a synthetic `readable`/`writable` event for `handle` on the next
    /// pass, after a zero-timeout wait. Bounds per-event work (accept and read
    /// drains) without starving other handles; idempotent per filter.
    pub fn requeue(self: *Loop, handle: Handle, filter: Filter) HandleError!void {
        self.assertOwner();
        const h = self.resolve(handle) orelse return error.StaleHandle;
        switch (filter) {
            .read => {
                if (h.req_read) return;
                h.req_read = true;
            },
            .write => {
                if (h.req_write) return;
                h.req_write = true;
            },
        }
        // Live entries are bounded by the two req flags per live handle;
        // reclaim the dead emitted prefix before it can push the list past
        // its capacity.
        if (self.requeue_list.items.len == self.requeue_list.capacity) self.collectRequeue();
        self.requeue_list.appendAssumeCapacity(.{ .token = handle, .filter = filter });
        self.immediate = true;
    }

    /// Disable read interest until the next `close()` of any handle on this
    /// loop, then re-enable. For listeners paused on EMFILE/ENFILE.
    pub fn pauseReadUntilClose(self: *Loop, handle: Handle) PauseError!void {
        self.assertOwner();
        const h = self.resolve(handle) orelse return error.StaleHandle;
        if (h.paused) return;
        if (self.paused.items.len >= self.options.paused_max) return error.PausedListFull;
        h.paused = true;
        self.paused.appendAssumeCapacity(handle);
        self.markDirty(handle, h);
    }

    /// True while `handle`'s read interest is paused.
    pub fn isPaused(self: *Loop, handle: Handle) bool {
        const h = self.resolve(handle) orelse return false;
        return h.paused;
    }

    /// Undo a `pauseReadUntilClose` early (Listener's fallback deadline and
    /// any consumer-side resume path). `want.read` was never changed, so this
    /// just clears the mask and re-commits.
    pub fn resumePaused(self: *Loop, handle: Handle) HandleError!void {
        self.assertOwner();
        const h = self.resolve(handle) orelse return error.StaleHandle;
        if (!h.paused) return;
        h.paused = false;
        for (self.paused.items, 0..) |tok, i| {
            if (tok.eql(handle)) {
                _ = self.paused.swapRemove(i);
                break;
            }
        }
        self.markDirty(handle, h);
    }

    /// Purge the handle's staged changes (dirty-list tombstone, order of the
    /// other handles preserved), free the slot and close the fd. Every paused
    /// listener on this loop resumes read interest.
    pub fn close(self: *Loop, handle: Handle) HandleError!void {
        self.assertOwner();
        const h = self.resolve(handle) orelse return error.StaleHandle;
        const fd = h.fd;
        h.fd = -1; // freed slots keep their value; deinit skips -1
        self.purgeDirty(handle, h);
        self.purgeRequeue(handle, h);
        _ = self.handles.remove(handle);
        rawClose(fd);
        self.stats_.handles_closed += 1;

        // Every paused handle resumes: a close frees a descriptor, which is
        // what pauseReadUntilClose waits for. Stale tokens drop out too.
        while (self.paused.items.len > 0) {
            const tok = self.paused.items[0];
            if (self.handles.get(tok)) |p| {
                if (p.paused) {
                    p.paused = false;
                    self.markDirty(tok, p);
                    self.stats_.paused_resumes += 1;
                }
            }
            _ = self.paused.swapRemove(0);
        }
    }

    /// Hand the fd to another loop (ADR-11 handshake pool): each registered
    /// filter gets an immediate EV_DELETE, so no staged delete can apply to a
    /// different fd with the same number on a later kqueue. Returns the fd.
    /// On a delete failure the handle is closed and the error propagated.
    pub fn detach(self: *Loop, handle: Handle) DetachError!posix.fd_t {
        self.assertOwner();
        const h = self.resolve(handle) orelse return error.StaleHandle;
        const fd = h.fd;
        var first_err: ?kev.ApplyError = null;
        if (h.reg_read != .none) {
            self.kdelete(fd, std.c.EVFILT.READ) catch |err| {
                if (first_err == null) first_err = err;
            };
        }
        if (h.reg_write != .none) {
            self.kdelete(fd, std.c.EVFILT.WRITE) catch |err| {
                if (first_err == null) first_err = err;
            };
        }
        h.fd = -1;
        self.purgeDirty(handle, h);
        self.purgeRequeue(handle, h);
        _ = self.handles.remove(handle);
        if (first_err) |err| {
            rawClose(fd);
            return err;
        }
        return fd;
    }

    pub fn fdOf(self: *Loop, handle: Handle) ?posix.fd_t {
        const h = self.resolve(handle) orelse return null;
        return h.fd;
    }

    /// CLOCK_MONOTONIC in milliseconds, read once per `wait()`.
    pub fn nowMs(self: *const Loop) u64 {
        return self.now_ms_;
    }

    /// The cross-thread wake handle. Producers join the pointer before the
    /// loop is torn down; `notify` is the only call made off-thread.
    pub fn waker(self: *Loop) *wake_mod.Wake {
        return &self.wake_state;
    }

    /// Register the shared broadcast pipe's read end (one-time setup,
    /// immediate): `broadcast.close()` reports `.broadcast_closed` once on
    /// every watching loop, then the knote is disabled so the persistent
    /// EV_EOF cannot spin the loop.
    pub fn watchBroadcast(self: *Loop, broadcast: *const wake_mod.Broadcast) kev.ApplyError!void {
        self.assertOwner();
        std.debug.assert(self.broadcast_fd < 0);
        const add = kev.Kevent{
            .ident = @intCast(broadcast.read_fd),
            .filter = std.c.EVFILT.READ,
            .flags = std.c.EV.ADD,
            .fflags = 0,
            .data = 0,
            .udata = broadcast_token.toUdata(),
        };
        try kev.applyNow(self.kq, &add);
        self.broadcast_fd = broadcast.read_fd;
    }

    // -- Timers --------------------------------------------------------------

    /// Deadline `delay_ms` from now; emits `.deadline` once. Lifecycle
    /// deadlines only; timers never drive I/O.
    pub fn scheduleIn(self: *Loop, delay_ms: u64, ctx: Token) error{TimerTableFull}!TimerId {
        self.assertOwner();
        return self.wheel.schedule(monotonicMs() +| delay_ms, ctx);
    }

    pub fn scheduleAt(self: *Loop, deadline_ms: u64, ctx: Token) error{TimerTableFull}!TimerId {
        self.assertOwner();
        return self.wheel.schedule(deadline_ms, ctx);
    }

    /// O(1) cancel. False when the id is stale (already fired or cancelled).
    pub fn cancelTimer(self: *Loop, timer: TimerId) bool {
        self.assertOwner();
        return self.wheel.cancel(timer);
    }

    // -- Signals and processes ------------------------------------------------

    pub const WatchSignalError = error{
        InvalidSignal,
        SignalOwned,
        KqueueInvalid,
        BadDescriptor,
        NotFound,
        ProcessNotFound,
        SystemResources,
        AccessDenied,
        InvalidArgument,
        Unexpected,
    };

    /// Watch `signo` via EVFILT_SIGNAL: claims process-wide ownership (a
    /// second loop, or a second watch, gets SignalOwned), sets SIG_IGN so the
    /// process keeps running, and attaches the knote immediately. SIGCHLD is
    /// rejected: it stays SIG_DFL so wait(2) keeps working.
    pub fn watchSignal(self: *Loop, signo: u8) WatchSignalError!void {
        self.assertOwner();
        if (signo == 0 or signo >= max_signal or signo == posix.SIG.CHLD) return error.InvalidSignal;
        if (signal_owners[signo].swap(true, .acq_rel)) return error.SignalOwned;
        errdefer signal_owners[signo].store(false, .release);

        const ign: posix.Sigaction = .{
            .handler = .{ .handler = posix.SIG.IGN },
            .flags = 0,
            .mask = posix.sigemptyset(),
        };
        posix.sigaction(signo, &ign, null);
        errdefer restoreDefaultHandler(signo);

        const add = kev.Kevent{
            .ident = signo,
            .filter = std.c.EVFILT.SIGNAL,
            .flags = std.c.EV.ADD,
            .fflags = 0,
            .data = 0,
            .udata = (Token{ .index = signo, .gen = 1, .kind = signal_kind }).toUdata(),
        };
        try kev.applyNow(self.kq, &add);
        self.watched_signals.set(signo);
    }

    /// Remove the knote, restore SIG_DFL and release ownership. Stale or
    /// missing knotes are tolerated.
    pub fn unwatchSignal(self: *Loop, signo: u8) void {
        self.assertOwner();
        if (signo == 0 or signo >= max_signal) return;
        if (!self.watched_signals.isSet(signo)) return;
        const del = kev.Kevent{
            .ident = signo,
            .filter = std.c.EVFILT.SIGNAL,
            .flags = std.c.EV.DELETE,
            .fflags = 0,
            .data = 0,
            .udata = (Token{ .index = signo, .gen = 1, .kind = signal_kind }).toUdata(),
        };
        // Best-effort delete: the knote is either gone already (fine, that is
        // the wanted state) or dropped with the kqueue at deinit.
        kev.applyNow(self.kq, &del) catch |err| switch (err) {
            error.NotFound, error.BadDescriptor => {},
            else => {},
        };
        self.watched_signals.unset(signo);
        signal_owners[signo].store(false, .release);
        restoreDefaultHandler(signo);
    }

    /// Process exit notification via EVFILT_PROC + NOTE_EXIT; emits
    /// `.process_exit` with the pid. ESRCH means the pid does not exist.
    pub fn watchProcess(self: *Loop, pid: posix.pid_t) kev.ApplyError!void {
        self.assertOwner();
        const add = kev.Kevent{
            .ident = @intCast(pid),
            .filter = std.c.EVFILT.PROC,
            .flags = std.c.EV.ADD,
            .fflags = std.c.NOTE.EXIT,
            .data = 0,
            .udata = (Token{ .index = @truncate(@as(u64, @bitCast(@as(i64, pid)))), .gen = 1, .kind = proc_kind }).toUdata(),
        };
        try kev.applyNow(self.kq, &add);
    }

    // -- Iteration -----------------------------------------------------------

    /// The next `wait()` uses a zero timeout. Set automatically by
    /// `requeue`.
    pub fn requestImmediate(self: *Loop) void {
        self.immediate = true;
    }

    /// End-of-iteration step: run the flush hook, reconcile dirty handles into
    /// the change buffer, then one kevent(2) applies the whole staged set and
    /// harvests the next batch. Asserts the previous batch was fully consumed.
    pub fn wait(self: *Loop) WaitError!void {
        self.assertOwner();
        if (self.internal_failure) |f| {
            self.internal_failure = null;
            return switch (f) {
                .timer => error.TimerArmFailed,
                .broadcast => error.BroadcastDisarmFailed,
            };
        }
        std.debug.assert(self.batch_pos == self.batch_len);
        std.debug.assert(self.requeue_pos == self.requeue_len);
        self.compactRequeue();

        if (self.options.on_flush) |hook| hook.func(hook.ctx);

        var nchanges: usize = 0;
        for (self.dirty.items) |tok| {
            const h = self.handles.get(tok) orelse continue; // closed: tombstone
            h.dirty = false;
            if (h.broken) continue;
            nchanges = self.commitHandle(tok, h, nchanges);
        }
        self.dirty.clearRetainingCapacity();
        if (self.broadcast_disarm and self.broadcast_fd >= 0) {
            self.change_buf[nchanges] = .{
                .ident = @intCast(self.broadcast_fd),
                .filter = std.c.EVFILT.READ,
                .flags = std.c.EV.DISABLE,
                .fflags = 0,
                .data = 0,
                .udata = broadcast_token.toUdata(),
            };
            nchanges += 1;
            self.broadcast_disarm = false;
        }

        // Arm the single one-shot kernel timer to the wheel's next deadline;
        // EVFILT_TIMER data is milliseconds by default.
        if (self.wheel.nextDeadline()) |d| {
            if (!self.timer_armed or self.armed_deadline != d) {
                self.change_buf[nchanges] = .{
                    .ident = timer_ident,
                    .filter = std.c.EVFILT.TIMER,
                    .flags = std.c.EV.ADD | std.c.EV.ONESHOT,
                    .fflags = 0,
                    .data = @intCast(d -| monotonicMs()),
                    .udata = timer_token.toUdata(),
                };
                nchanges += 1;
                self.timer_armed = true;
                self.armed_deadline = d;
            }
        } else if (self.timer_armed) {
            self.change_buf[nchanges] = .{
                .ident = timer_ident,
                .filter = std.c.EVFILT.TIMER,
                .flags = std.c.EV.DELETE,
                .fflags = 0,
                .data = 0,
                .udata = timer_token.toUdata(),
            };
            nchanges += 1;
            self.timer_armed = false;
        }
        std.debug.assert(nchanges <= self.change_buf.len);

        self.requeue_len = self.requeue_list.items.len;
        self.requeue_pos = 0;

        var zero_ts: posix.timespec = .{ .sec = 0, .nsec = 0 };
        const timeout: ?*const posix.timespec = if (self.immediate) &zero_ts else null;
        self.immediate = false;

        self.batch_len = try kev.submitWait(
            self.kq,
            self.change_buf[0..nchanges],
            self.event_buf,
            timeout,
            &self.stats_.last_errno,
        );
        self.batch_changes = nchanges;
        self.stats_.waits += 1;
        self.stats_.changes_committed += nchanges;
        self.stats_.raw_events += self.batch_len;
        self.batch_pos = 0;
        self.now_ms_ = monotonicMs();
    }

    /// Deliver the next event of the current batch, or null. Kernel events in
    /// kernel order, then synthetic events for requeued handles.
    pub fn next(self: *Loop) ?Event {
        self.assertOwner();
        while (self.batch_pos < self.batch_len) {
            const raw = self.event_buf[self.batch_pos];
            self.batch_pos += 1;
            if (self.translate(raw)) |event| return event;
        }
        if (self.timer_ready) {
            while (self.wheel.popExpired(self.now_ms_)) |dl| {
                self.stats_.delivered_events += 1;
                return .{ .deadline = dl };
            }
            self.timer_ready = false;
        }
        while (self.requeue_pos < self.requeue_len) {
            const entry = self.requeue_list.items[self.requeue_pos];
            self.requeue_pos += 1;
            const h = self.handles.get(entry.token) orelse {
                self.stats_.stale_events += 1;
                continue;
            };
            switch (entry.filter) {
                .read => h.req_read = false,
                .write => h.req_write = false,
            }
            self.stats_.synthetic_events += 1;
            self.stats_.delivered_events += 1;
            const io: Io = .{ .handle = entry.token, .ctx = h.ctx, .data = 0, .eof = false, .errno = 0 };
            return switch (entry.filter) {
                .read => .{ .readable = io },
                .write => .{ .writable = io },
            };
        }
        return null;
    }

    pub fn stats(self: *const Loop) *const Stats {
        return &self.stats_;
    }

    // -- Internals -----------------------------------------------------------

    /// Drop the emitted prefix of the requeue list: entries below
    /// `requeue_pos` were already delivered and can never fire again.
    fn collectRequeue(self: *Loop) void {
        const pos = self.requeue_pos;
        if (pos == 0) return;
        const live = self.requeue_list.items.len - pos;
        std.mem.copyForwards(
            RequeueEntry,
            self.requeue_list.items[0..live],
            self.requeue_list.items[pos..],
        );
        self.requeue_list.shrinkRetainingCapacity(live);
        self.requeue_len -= pos;
        self.requeue_pos = 0;
    }

    /// Order-preserving removal of the handle's undelivered requeue
    /// entries; the other handles' entries keep their order.
    fn purgeRequeue(self: *Loop, handle: Handle, h: *HandleState) void {
        if (!h.req_read and !h.req_write) return;
        h.req_read = false;
        h.req_write = false;
        var out = self.requeue_pos;
        var kept_pending: usize = 0;
        var i = self.requeue_pos;
        while (i < self.requeue_list.items.len) : (i += 1) {
            const entry = self.requeue_list.items[i];
            if (entry.token.eql(handle)) continue;
            self.requeue_list.items[out] = entry;
            out += 1;
            if (i < self.requeue_len) kept_pending += 1;
        }
        self.requeue_list.shrinkRetainingCapacity(out);
        self.requeue_len = self.requeue_pos + kept_pending;
    }

    /// Keep requeue entries appended after `requeue_len` (this pass already
    /// delivered its share) for the next pass.
    fn compactRequeue(self: *Loop) void {
        const tail = self.requeue_list.items.len - self.requeue_len;
        if (tail > 0) {
            std.mem.copyForwards(
                RequeueEntry,
                self.requeue_list.items[0..tail],
                self.requeue_list.items[self.requeue_len..],
            );
        }
        self.requeue_list.shrinkRetainingCapacity(tail);
        self.requeue_len = 0;
        self.requeue_pos = 0;
    }

    fn resolve(self: *Loop, token: Token) ?*HandleState {
        return self.handles.get(token);
    }

    fn markDirty(self: *Loop, token: Token, h: *HandleState) void {
        if (h.dirty) return;
        h.dirty = true;
        self.dirty.appendAssumeCapacity(token);
    }

    /// Order-preserving removal of `handle`'s staged dirty entry (S20): the
    /// other handles' entries keep their relative order. Skipped outright
    /// when the handle is not dirty, keeping close() O(1) in the common
    /// case instead of O(dirty list).
    fn purgeDirty(self: *Loop, handle: Handle, h: *HandleState) void {
        if (!h.dirty) return;
        h.dirty = false;
        for (self.dirty.items, 0..) |tok, i| {
            if (tok.eql(handle)) {
                const tail = self.dirty.items.len - i - 1;
                std.mem.copyForwards(
                    Token,
                    self.dirty.items[i .. i + tail],
                    self.dirty.items[i + 1 ..],
                );
                self.dirty.shrinkRetainingCapacity(self.dirty.items.len - 1);
                return;
            }
        }
    }

    /// Immediate EV_DELETE for one filter; ENOENT counts as success.
    fn kdelete(self: *Loop, fd: posix.fd_t, filter: i16) kev.ApplyError!void {
        const del = kev.Kevent{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = std.c.EV.DELETE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        };
        kev.applyNow(self.kq, &del) catch |err| switch (err) {
            error.NotFound => return,
            else => return err,
        };
    }

    /// Emit at most one change per filter for one dirty handle.
    fn commitHandle(self: *Loop, token: Token, h: *HandleState, nchanges: usize) usize {
        var n = nchanges;
        n = self.commitFilter(token, h, .read, n);
        n = self.commitFilter(token, h, .write, n);
        return n;
    }

    fn commitFilter(self: *Loop, token: Token, h: *HandleState, filter: Filter, n: usize) usize {
        const wanted = switch (filter) {
            .read => h.want.read and !h.paused,
            .write => h.want.write,
        };
        const reg = switch (filter) {
            .read => h.reg_read,
            .write => h.reg_write,
        };
        var flags: u16 = 0;
        var new_reg: RegState = reg;
        switch (reg) {
            .none => {
                if (!wanted) return n;
                flags = std.c.EV.ADD | std.c.EV.ENABLE;
                flags |= switch (filter) {
                    .read => std.c.EV.CLEAR,
                    .write => std.c.EV.DISPATCH,
                };
                new_reg = .enabled;
            },
            .enabled => {
                if (wanted) return n;
                flags = std.c.EV.DISABLE;
                new_reg = .disabled;
            },
            .disabled => {
                if (!wanted) return n;
                flags = std.c.EV.ENABLE;
                new_reg = .enabled;
            },
        }
        self.change_buf[n] = .{
            .ident = @intCast(h.fd),
            .filter = switch (filter) {
                .read => std.c.EVFILT.READ,
                .write => std.c.EVFILT.WRITE,
            },
            .flags = flags,
            .fflags = 0,
            .data = 0,
            .udata = token.toUdata(),
        };
        switch (filter) {
            .read => h.reg_read = new_reg,
            .write => h.reg_write = new_reg,
        }
        return n + 1;
    }

    fn translate(self: *Loop, raw: kev.Kevent) ?Event {
        const token = Token.fromUdata(raw.udata);
        if (raw.flags & std.c.EV.ERROR != 0 and token.kind != handle_kind) {
            // A loop-internal change (timer arm/disarm, broadcast disarm)
            // failed; the next wait() reports the named error. The kernel
            // did not apply it: mark the timer disarmed so the next commit
            // re-arms rather than trusting the stale optimistic flag (a
            // still-armed knote left by a failed delete only costs one
            // spurious wakeup).
            self.stats_.change_failures += 1;
            self.internal_failure = switch (token.kind) {
                timer_kind => .timer,
                else => .broadcast,
            };
            if (token.kind == timer_kind) self.timer_armed = false;
            return null;
        }
        switch (token.kind) {
            handle_kind => {},
            timer_kind => {
                // One-shot timer consumed; expired entries emit as .deadline
                // events after the raw batch.
                self.timer_armed = false;
                self.timer_ready = true;
                return null;
            },
            signal_kind => {
                self.stats_.delivered_events += 1;
                return .{ .signal = .{ .signo = token.index, .count = raw.data } };
            },
            proc_kind => {
                self.stats_.delivered_events += 1;
                return .{ .process_exit = .{ .pid = @intCast(raw.ident) } };
            },
            wake_kind => {
                self.wake_state.consume();
                self.stats_.wakes += 1;
                self.stats_.delivered_events += 1;
                return .wake;
            },
            broadcast_kind => {
                if (raw.flags & ev_eof == 0 or self.broadcast_seen) return null;
                self.broadcast_seen = true;
                self.broadcast_disarm = true;
                self.stats_.delivered_events += 1;
                return .broadcast_closed;
            },
            else => {
                self.stats_.stale_events += 1;
                return null;
            },
        }
        const h = self.resolve(token) orelse {
            self.stats_.stale_events += 1;
            return null;
        };

        const filter: Filter = switch (raw.filter) {
            std.c.EVFILT.READ => .read,
            std.c.EVFILT.WRITE => .write,
            else => {
                self.stats_.stale_events += 1;
                return null;
            },
        };

        if (raw.flags & std.c.EV.ERROR != 0) {
            // A change for this handle was rejected: mark it broken so no
            // further changes are generated, and surface the failure. The op
            // is recovered from the staged change it echoes (ident + filter).
            h.broken = true;
            self.stats_.change_failures += 1;
            self.stats_.delivered_events += 1;
            return .{ .change_failed = .{
                .handle = token,
                .ctx = h.ctx,
                .filter = filter,
                .op = self.opOf(raw),
                .errno = @intCast(@max(0, raw.data)),
            } };
        }

        if (filter == .write and raw.flags & std.c.EV.DISPATCH != 0) {
            // The kernel disarmed the write knote on delivery; if the
            // consumer still wants write, the next commit re-arms it with
            // EV_ENABLE (DESIGN 6.3).
            h.reg_write = .disabled;
            if (h.want.write) self.markDirty(token, h);
        }
        self.stats_.delivered_events += 1;
        const io: Io = .{
            .handle = token,
            .ctx = h.ctx,
            .data = raw.data,
            .eof = raw.flags & ev_eof != 0,
            .errno = raw.fflags,
        };
        return switch (filter) {
            .read => .{ .readable = io },
            .write => .{ .writable = io },
        };
    }

    /// The EV_ERROR record echoes the rejected change minus its flags; find
    /// the matching staged change (ident + filter) to recover the operation.
    fn opOf(self: *Loop, raw: kev.Kevent) Op {
        for (self.change_buf[0..self.batch_changes]) |ch| {
            if (ch.ident == raw.ident and ch.filter == raw.filter) {
                if (ch.flags & std.c.EV.ADD != 0) return .add;
                if (ch.flags & std.c.EV.ENABLE != 0) return .enable;
                if (ch.flags & std.c.EV.DISABLE != 0) return .disable;
                return .add;
            }
        }
        return .add;
    }

    fn assertOwner(self: *Loop) void {
        if (builtin.mode == .Debug) {
            std.debug.assert(self.owner_tid == std.Thread.getCurrentId());
        }
    }
};

const kqueue_cloexec: c_int = 0x00000001;
const ev_eof: u16 = 0x8000; // EV_EOF, absent from std.c.EV on FreeBSD
extern "c" fn kqueuex(flags: c_int) c_int;

/// close(2) that tolerates EBADF: the fd may have been closed out-of-band
/// (the change_failed path leads consumers here) or already reaped.
fn rawClose(fd: posix.fd_t) void {
    _ = std.c.close(fd);
}

fn restoreDefaultHandler(signo: u8) void {
    const dfl: posix.Sigaction = .{
        .handler = .{ .handler = posix.SIG.DFL },
        .flags = 0,
        .mask = posix.sigemptyset(),
    };
    posix.sigaction(signo, &dfl, null);
}

pub fn monotonicMs() u64 {
    const ts = posix.clock_gettime(.MONOTONIC) catch unreachable;
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(@divFloor(ts.nsec, 1_000_000)));
}

// ============================================================================
// Tests
// ============================================================================

fn testOptions(on_flush: ?FlushHook) Options {
    return .{ .handles_max = 64, .timers_max = 16, .events_max = 16, .on_flush = on_flush };
}

fn testLoop(on_flush: ?FlushHook) !Loop {
    var loop: Loop = undefined;
    try loop.init(std.testing.allocator, &testOptions(on_flush));
    return loop;
}

fn socketpairNb() ![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0, &fds) != 0)
        return error.SocketPairFailed;
    return fds;
}

fn tctx(i: u32) Token {
    return .{ .index = i, .gen = 1, .kind = 0xEE };
}

/// Drain the current batch into `out`.
fn drain(loop: *Loop, out: *std.ArrayList(Event)) !void {
    while (loop.next()) |ev| try out.append(std.testing.allocator, ev);
}

fn readableCount(events: []const Event) usize {
    var n: usize = 0;
    for (events) |ev| {
        if (ev == .readable) n += 1;
    }
    return n;
}

test "Loop: readable event carries ctx, byte count and no eof" {
    // One byte in the pipe produces one readable event with data >= 1.
    var loop = try testLoop(null);
    defer loop.deinit(std.testing.allocator);

    const pair = try socketpairNb();
    defer posix.close(pair[0]);
    const h = try loop.attach(pair[1], tctx(7), .{ .read = true });
    _ = try posix.write(pair[0], "x");

    try loop.wait();
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(std.testing.allocator);
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    const ev = events.items[0].readable;
    try std.testing.expect(ev.handle.eql(h));
    try std.testing.expect(ev.ctx.eql(tctx(7)));
    try std.testing.expect(ev.data >= 1);
    try std.testing.expect(!ev.eof);
    try std.testing.expectEqual(@as(u32, 0), ev.errno);
}

test "Loop: peer close delivers eof" {
    var loop = try testLoop(null);
    defer loop.deinit(std.testing.allocator);

    const pair = try socketpairNb();
    const h = try loop.attach(pair[1], tctx(1), .{ .read = true });
    posix.close(pair[0]);

    try loop.wait();
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(std.testing.allocator);
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    const ev = events.items[0].readable;
    try std.testing.expect(ev.handle.eql(h));
    try std.testing.expect(ev.eof);
}

const linger_t = extern struct { l_onoff: c_int, l_linger: c_int };

/// TCP pair over loopback: returns {accepted_side, client_side}; the client
/// side is non-blocking and ready to attach.
fn tcpPair() !struct { server: posix.fd_t, client: posix.fd_t } {
    const lfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(lfd);
    const one: c_int = 1;
    try posix.setsockopt(lfd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));
    const any = try std.net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(lfd, &any.any, any.getOsSockLen());
    try posix.listen(lfd, 8);
    var bound: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    var blen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    try std.testing.expectEqual(0, std.c.getsockname(lfd, @ptrCast(&bound), &blen));

    const cfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(cfd);
    posix.connect(cfd, @ptrCast(&bound), blen) catch |err| switch (err) {
        error.WouldBlock => {},
        else => return err,
    };
    const afd = try posix.accept(lfd, null, null, 0);
    posix.close(lfd);
    return .{ .server = afd, .client = cfd };
}

test "Loop: socket error arrives as eof plus errno" {
    // A refused connect delivers a writable event with EV_EOF and the socket
    // error (ECONNREFUSED) in errno, taken from fflags.
    var loop = try testLoop(null);
    defer loop.deinit(std.testing.allocator);

    // Grab a port nobody listens on: bind, record, close.
    const lfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    const any = try std.net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(lfd, &any.any, any.getOsSockLen());
    var bound: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    var blen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    try std.testing.expectEqual(0, std.c.getsockname(lfd, @ptrCast(&bound), &blen));
    posix.close(lfd);

    const cfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
    posix.connect(cfd, @ptrCast(&bound), blen) catch |err| switch (err) {
        // A refused loopback connect usually pends (EINPROGRESS) but can
        // report ECONNREFUSED synchronously under load; either way the
        // socket error is pending and the write knote reports it below.
        error.WouldBlock, error.ConnectionRefused => {},
        else => return err,
    };
    const h = try loop.attach(cfd, tctx(1), .{ .write = true });

    try loop.wait();
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(std.testing.allocator);
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    const ev = events.items[0].writable;
    try std.testing.expect(ev.handle.eql(h));
    try std.testing.expect(ev.eof);
    try std.testing.expect(ev.errno == @intFromEnum(posix.E.CONNREFUSED));
}

test "Loop: write interest is delivered once and re-armed only when wanted" {
    var loop = try testLoop(null);
    defer loop.deinit(std.testing.allocator);

    const pair = try socketpairNb();
    defer posix.close(pair[0]);
    const h = try loop.attach(pair[1], tctx(1), .{ .write = true });

    try loop.wait();
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(std.testing.allocator);
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    _ = events.items[0].writable;
    events.clearRetainingCapacity();

    // EV_DISPATCH disarmed the knote on delivery, but write is still
    // wanted: the next commit re-arms it and the still-writable socket
    // fires again without another setInterest call.
    loop.requestImmediate();
    try loop.wait();
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    _ = events.items[0].writable;
    events.clearRetainingCapacity();

    // Not wanting write leaves the knote disarmed and produces no change.
    try loop.setInterest(h, .{});
    const committed = loop.stats().changes_committed;
    loop.requestImmediate();
    try loop.wait();
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 0), events.items.len);
    try std.testing.expectEqual(committed, loop.stats().changes_committed);
}

test "Loop: change buffer bound under churn is two entries per dirty handle" {
    // Every handle toggles interest every iteration; changes per commit can
    // never exceed 2 x dirty handles.
    var loop = try testLoop(null);
    defer loop.deinit(std.testing.allocator);

    const n = 8;
    var peers: [n]posix.fd_t = undefined;
    var handles: [n]Handle = undefined;
    for (0..n) |i| {
        const pair = try socketpairNb();
        peers[i] = pair[0];
        handles[i] = try loop.attach(pair[1], tctx(@intCast(i)), .{ .read = true });
    }
    defer for (peers) |fd| posix.close(fd);

    loop.requestImmediate();
    try loop.wait();
    try std.testing.expectEqual(@as(u64, n), loop.stats().changes_committed);
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(std.testing.allocator);
    try drain(&loop, &events);

    const before = loop.stats().changes_committed;
    for (handles) |h| {
        try loop.setInterest(h, .{ .read = true, .write = true });
        try loop.setInterest(h, .{ .read = true });
        try loop.setInterest(h, .{ .read = true, .write = true });
    }
    loop.requestImmediate();
    try loop.wait();
    try drain(&loop, &events);
    try std.testing.expectEqual(before + n, loop.stats().changes_committed);
}

test "Loop: close purges staged changes and preserves the order of the rest" {
    // Dirty A, B, C; close B before the commit: A and C register cleanly and
    // no failure record appears for B.
    var loop = try testLoop(null);
    defer loop.deinit(std.testing.allocator);

    var peers: [3]posix.fd_t = undefined;
    var handles: [3]Handle = undefined;
    for (0..3) |i| {
        const pair = try socketpairNb();
        peers[i] = pair[0];
        handles[i] = try loop.attach(pair[1], tctx(@intCast(i)), .{ .read = true });
    }
    defer posix.close(peers[0]);
    defer posix.close(peers[2]);

    try loop.close(handles[1]);
    posix.close(peers[1]);
    _ = try posix.write(peers[0], "a");
    _ = try posix.write(peers[2], "c");

    try loop.wait();
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(std.testing.allocator);
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 2), events.items.len);
    try std.testing.expect(events.items[0].readable.handle.eql(handles[0]));
    try std.testing.expect(events.items[1].readable.handle.eql(handles[2]));
    try std.testing.expectEqual(@as(u64, 0), loop.stats().change_failures);
}

test "Loop: a failed internal timer change disarms the flag and names the error" {
    var loop = try testLoop(null);
    defer loop.deinit(std.testing.allocator);

    // The kernel echoes a rejected EVFILT_TIMER change as an EV_ERROR
    // record: the knote was not applied, so the optimistic armed flag must
    // reset and the next wait() must name TimerArmFailed.
    loop.timer_armed = true;
    const raw: kev.Kevent = .{
        .ident = timer_ident,
        .filter = std.c.EVFILT.TIMER,
        .flags = std.c.EV.ERROR,
        .fflags = 0,
        .data = @intFromEnum(posix.E.NOMEM),
        .udata = timer_token.toUdata(),
    };
    try std.testing.expect(loop.translate(raw) == null);
    try std.testing.expect(!loop.timer_armed);
    try std.testing.expectError(error.TimerArmFailed, loop.wait());
    try std.testing.expectEqual(@as(u64, 1), loop.stats().change_failures);

    const raw_bcast: kev.Kevent = .{
        .ident = 0,
        .filter = std.c.EVFILT.READ,
        .flags = std.c.EV.ERROR,
        .fflags = 0,
        .data = @intFromEnum(posix.E.BADF),
        .udata = broadcast_token.toUdata(),
    };
    try std.testing.expect(loop.translate(raw_bcast) == null);
    try std.testing.expectError(error.BroadcastDisarmFailed, loop.wait());
}

test "Loop: close leaves other dirty entries and the flag consistent" {
    var loop = try testLoop(null);
    defer loop.deinit(std.testing.allocator);

    const a = try socketpairNb();
    defer posix.close(a[0]);
    const b = try socketpairNb();
    defer posix.close(b[0]);
    const ha = try loop.attach(a[1], tctx(1), .{ .read = true });
    const hb = try loop.attach(b[1], tctx(2), .{ .read = true });
    loop.requestImmediate();
    try loop.wait(); // commits both; neither handle stays dirty

    // hb is clean: its close must leave ha's dirty entry alone.
    try loop.setInterest(ha, .{ .read = true, .write = true });
    try std.testing.expectEqual(@as(usize, 1), loop.dirty.items.len);
    try loop.close(hb);
    try std.testing.expectEqual(@as(usize, 1), loop.dirty.items.len);
    try std.testing.expect(loop.dirty.items[0].eql(ha));

    // ha is dirty: its close removes exactly its entry.
    try loop.close(ha);
    try std.testing.expectEqual(@as(usize, 0), loop.dirty.items.len);
}

test "Loop: a stale token after slot reuse never resolves" {
    // Close a handle, reissue the slot for a new fd, then prove the old token
    // is rejected everywhere and receives nothing. Capacity 1 forces the
    // second attach to reuse the freed slot.
    var options = testOptions(null);
    options.handles_max = 1;
    var loop: Loop = undefined;
    try loop.init(std.testing.allocator, &options);
    defer loop.deinit(std.testing.allocator);

    const pair = try socketpairNb();
    defer posix.close(pair[0]);
    const first = try loop.attach(pair[1], tctx(1), .{ .read = true });
    try loop.close(first);

    const pair2 = try socketpairNb();
    defer posix.close(pair2[0]);
    const second = try loop.attach(pair2[1], tctx(2), .{ .read = true });
    try std.testing.expectEqual(first.index, second.index);

    try std.testing.expectError(error.StaleHandle, loop.setInterest(first, .{ .read = true }));
    try std.testing.expectError(error.StaleHandle, loop.close(first));
    try std.testing.expect(loop.fdOf(first) == null);

    _ = try posix.write(pair2[0], "z");
    try loop.wait();
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(std.testing.allocator);
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    try std.testing.expect(events.items[0].readable.handle.eql(second));
    try std.testing.expect(events.items[0].readable.ctx.eql(tctx(2)));
}

test "Loop: a rejected change surfaces as change_failed with the errno" {
    // Close the fd behind the loop's back, then force a change on it: the
    // kernel rejects it with EBADF, delivered as change_failed.
    var loop = try testLoop(null);
    defer loop.deinit(std.testing.allocator);

    const pair = try socketpairNb();
    defer posix.close(pair[0]);
    const h = try loop.attach(pair[1], tctx(9), .{ .read = true });
    loop.requestImmediate();
    try loop.wait();
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(std.testing.allocator);
    try drain(&loop, &events);

    const fd = loop.fdOf(h).?;
    posix.close(fd); // out-of-band close; the knote is gone
    try loop.setInterest(h, .{});
    try loop.wait();
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    const cf = events.items[0].change_failed;
    try std.testing.expect(cf.handle.eql(h));
    try std.testing.expect(cf.ctx.eql(tctx(9)));
    try std.testing.expectEqual(.read, cf.filter);
    try std.testing.expectEqual(.disable, cf.op);
    try std.testing.expect(cf.errno == @intFromEnum(posix.E.BADF));

    // The handle is broken but still closes cleanly (fd already closed).
    try loop.close(h);
}

test "Loop: paused read resumes on the next close and reports queued data" {
    var loop = try testLoop(null);
    defer loop.deinit(std.testing.allocator);

    const pair = try socketpairNb();
    defer posix.close(pair[0]);
    const paused_h = try loop.attach(pair[1], tctx(1), .{ .read = true });
    const other = try socketpairNb();
    defer posix.close(other[0]);
    const other_h = try loop.attach(other[1], tctx(2), .{ .read = true });

    loop.requestImmediate();
    try loop.wait();
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(std.testing.allocator);
    try drain(&loop, &events);

    try loop.pauseReadUntilClose(paused_h);
    _ = try posix.write(pair[0], "d");
    loop.requestImmediate();
    try loop.wait(); // commits EV_DISABLE
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 0), readableCount(events.items));

    loop.requestImmediate(); // paused knote stays silent even with data pending
    try loop.wait();
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 0), events.items.len);

    try loop.close(other_h); // frees a descriptor: paused listener resumes
    try loop.wait(); // commits EV_ENABLE; the queued byte fires
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    try std.testing.expect(events.items[0].readable.handle.eql(paused_h));
    try std.testing.expectEqual(@as(u64, 1), loop.stats().paused_resumes);
}

test "Loop: detach removes knotes and the fd works on a second loop" {
    var loop_a = try testLoop(null);
    defer loop_a.deinit(std.testing.allocator);
    var loop_b = try testLoop(null);
    defer loop_b.deinit(std.testing.allocator);

    const pair = try socketpairNb();
    defer posix.close(pair[0]);
    const h = try loop_a.attach(pair[1], tctx(1), .{ .read = true });
    loop_a.requestImmediate();
    try loop_a.wait();
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(std.testing.allocator);
    try drain(&loop_a, &events);

    const fd = try loop_a.detach(h);
    const h2 = try loop_b.attach(fd, tctx(2), .{ .read = true });
    _ = try posix.write(pair[0], "m");
    try loop_b.wait();
    try drain(&loop_b, &events);
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    try std.testing.expect(events.items[0].readable.handle.eql(h2));
}

test "Loop: requeue emits a synthetic event after a zero-timeout wait" {
    var loop = try testLoop(null);
    defer loop.deinit(std.testing.allocator);

    const pair = try socketpairNb();
    defer posix.close(pair[0]);
    const h = try loop.attach(pair[1], tctx(1), .{ .read = true });
    loop.requestImmediate();
    try loop.wait();
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(std.testing.allocator);
    try drain(&loop, &events);

    try loop.requeue(h, .read);
    try loop.wait(); // zero timeout: no kernel events, one synthetic
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    const ev = events.items[0].readable;
    try std.testing.expect(ev.handle.eql(h));
    try std.testing.expectEqual(@as(i64, 0), ev.data);
    try std.testing.expect(!ev.eof);
    try std.testing.expectEqual(@as(u64, 1), loop.stats().synthetic_events);

    // Requeueing again produces exactly one more, not duplicates.
    events.clearRetainingCapacity();
    try loop.requeue(h, .read);
    try loop.requeue(h, .read);
    try loop.wait();
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
}

test "Loop: close and detach remove requeue entries so the list stays bounded" {
    // attach + requeue + close churned before one wait must not let the
    // requeue list grow past its 2-per-handle bound.
    var options = testOptions(null);
    options.handles_max = 1;
    var loop: Loop = undefined;
    try loop.init(std.testing.allocator, &options);
    defer loop.deinit(std.testing.allocator);

    for (0..4) |_| {
        const pair = try socketpairNb();
        posix.close(pair[0]);
        const h = try loop.attach(pair[1], tctx(1), .{ .read = true });
        try loop.requeue(h, .read);
        try loop.requeue(h, .write);
        try loop.close(h);
        try std.testing.expectEqual(@as(usize, 0), loop.requeue_list.items.len);
    }

    const pair = try socketpairNb();
    posix.close(pair[0]);
    const h = try loop.attach(pair[1], tctx(1), .{ .read = true });
    try loop.requeue(h, .read);
    _ = try loop.detach(h);
    try std.testing.expectEqual(@as(usize, 0), loop.requeue_list.items.len);
}

test "Loop: emitted requeue entries are reclaimed on append" {
    // After both filters emit, the dead entries still occupy the list;
    // requeueing the same handle must reclaim them instead of overflowing.
    var options = testOptions(null);
    options.handles_max = 1;
    var loop: Loop = undefined;
    try loop.init(std.testing.allocator, &options);
    defer loop.deinit(std.testing.allocator);

    const pair = try socketpairNb();
    defer posix.close(pair[0]);
    const h = try loop.attach(pair[1], tctx(1), .{ .read = true });
    try loop.requeue(h, .read);
    try loop.requeue(h, .write);
    try loop.wait();
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(std.testing.allocator);
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 2), events.items.len);
    try std.testing.expectEqual(@as(usize, 2), loop.requeue_list.items.len);

    events.clearRetainingCapacity();
    try loop.requeue(h, .read);
    try loop.wait();
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    try std.testing.expect(events.items[0] == .readable);
}

const FlushProbe = struct {
    calls: usize = 0,
    loop: *Loop = undefined,
    fd: posix.fd_t = -1,
    attached: ?Handle = null,

    fn run(self_: *anyopaque) void {
        const self: *FlushProbe = @ptrCast(@alignCast(self_));
        self.calls += 1;
        if (self.fd >= 0 and self.attached == null) {
            self.attached = self.loop.attach(self.fd, tctx(5), .{ .read = true }) catch null;
        }
    }
};

test "Loop: flush hook runs once per wait and its changes join the commit" {
    var probe: FlushProbe = .{};
    var loop = try testLoop(.{ .ctx = &probe, .func = FlushProbe.run });
    defer loop.deinit(std.testing.allocator);
    probe.loop = &loop;

    const pair = try socketpairNb();
    defer posix.close(pair[0]);
    probe.fd = pair[1];

    loop.requestImmediate();
    try loop.wait(); // hook attached the fd in this very commit
    try std.testing.expectEqual(@as(usize, 1), probe.calls);
    try std.testing.expect(probe.attached != null);
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(std.testing.allocator);
    try drain(&loop, &events);

    _ = try posix.write(pair[0], "f");
    try loop.wait();
    try std.testing.expectEqual(@as(usize, 2), probe.calls);
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    try std.testing.expect(events.items[0].readable.handle.eql(probe.attached.?));
}

test "Loop: scheduleIn fires a deadline event and cancel silences it" {
    var loop = try testLoop(null);
    defer loop.deinit(std.testing.allocator);

    const t = try loop.scheduleIn(30, tctx(3));
    // The kernel timer may fire a tick early while the wheel's deadline is
    // still 1 ms out; the loop re-arms for the remainder, so retry bounded.
    var ev: ?Event = null;
    for (0..5) |_| {
        try loop.wait();
        if (loop.next()) |e| {
            ev = e;
            break;
        }
    }
    try std.testing.expect(ev.? == .deadline);
    try std.testing.expect(ev.?.deadline.timer.eql(t));
    try std.testing.expect(ev.?.deadline.ctx.eql(tctx(3)));

    // A cancelled timer emits nothing and the knote is disarmed.
    const t2 = try loop.scheduleIn(50, tctx(4));
    try std.testing.expect(loop.cancelTimer(t2));
    try std.testing.expect(!loop.cancelTimer(t2));
    loop.requestImmediate();
    try loop.wait();
    try std.testing.expect(loop.next() == null);
}

test "Loop: a deadline with any consumer ctx kind is delivered, none reserved" {
    // ctx kind 0x07 was once reserved for the listener's internal resume
    // timer: a consumer timer using it was silently swallowed. All kinds
    // now surface as deadline events.
    var loop = try testLoop(null);
    defer loop.deinit(std.testing.allocator);

    var reserved: Token = tctx(7);
    reserved.kind = 0x07;
    _ = try loop.scheduleIn(1, reserved);
    try loop.wait();
    const ev = loop.next().?;
    try std.testing.expect(ev == .deadline);
    try std.testing.expect(ev.deadline.ctx.eql(reserved));
    try std.testing.expect(loop.next() == null);
}

test "Loop: cancelling a collected-but-unemitted deadline loses no other deadline" {
    // The handler cancels a sibling whose timer was already collected onto
    // the due list, then fills every level-0 slot. All 64 must fire: the
    // cancelled entry's stale links must not corrupt the wheel.
    var options = testOptions(null);
    options.timers_max = 128;
    var loop: Loop = undefined;
    try loop.init(std.testing.allocator, &options);
    defer loop.deinit(std.testing.allocator);

    const base = loop.nowMs();
    _ = try loop.scheduleAt(base + 2, tctx(1));
    const sibling = try loop.scheduleAt(base + 2, tctx(2));
    var scheduled = false;
    var fired: usize = 0;
    var watchdog = false;
    var iters: usize = 0;
    while (!watchdog and iters < 500) : (iters += 1) {
        try loop.wait();
        while (loop.next()) |e| switch (e) {
            .deadline => |d| {
                if (d.ctx.index == 1 and !scheduled) {
                    _ = loop.cancelTimer(sibling);
                    const now = loop.nowMs();
                    for (0..64) |i| _ = try loop.scheduleAt(now + i, tctx(100));
                    _ = try loop.scheduleIn(500, tctx(999));
                    scheduled = true;
                } else if (d.ctx.index == 100) {
                    fired += 1;
                } else if (d.ctx.index == 999) {
                    watchdog = true;
                }
            },
            else => {},
        };
    }
    try std.testing.expect(watchdog);
    try std.testing.expectEqual(@as(usize, 64), fired);
}

test "Loop: watchSignal delivers count and ownership excludes a second watch" {
    var loop = try testLoop(null);
    defer loop.deinit(std.testing.allocator);
    var loop2 = try testLoop(null);
    defer loop2.deinit(std.testing.allocator);

    try loop.watchSignal(posix.SIG.USR1);
    try std.testing.expectError(error.SignalOwned, loop2.watchSignal(posix.SIG.USR1));
    try std.testing.expectError(error.SignalOwned, loop.watchSignal(posix.SIG.USR1));

    try posix.raise(posix.SIG.USR1);
    try loop.wait();
    const ev = loop.next().?;
    try std.testing.expect(ev == .signal);
    try std.testing.expectEqual(posix.SIG.USR1, ev.signal.signo);
    try std.testing.expect(ev.signal.count >= 1);

    loop.unwatchSignal(posix.SIG.USR1);
    try loop2.watchSignal(posix.SIG.USR1); // ownership was released

    try std.testing.expectError(error.InvalidSignal, loop.watchSignal(posix.SIG.CHLD));
}

test "Loop: watchProcess reports the child's exit" {
    var loop = try testLoop(null);
    defer loop.deinit(std.testing.allocator);

    const pid = try posix.fork();
    if (pid == 0) {
        posix.exit(0);
    }
    defer _ = posix.waitpid(pid, 0);
    try loop.watchProcess(pid);

    try loop.wait();
    const ev = loop.next().?;
    try std.testing.expect(ev == .process_exit);
    try std.testing.expectEqual(pid, ev.process_exit.pid);

    try std.testing.expectError(error.ProcessNotFound, loop.watchProcess(1 << 22));
}

test "Loop: attach at capacity fails with HandleTableFull" {
    var options = testOptions(null);
    options.handles_max = 2;
    var loop: Loop = undefined;
    try loop.init(std.testing.allocator, &options);
    defer loop.deinit(std.testing.allocator);

    const p1 = try socketpairNb();
    const p2 = try socketpairNb();
    const p3 = try socketpairNb();
    defer posix.close(p1[0]);
    defer posix.close(p2[0]);
    defer posix.close(p3[0]);
    defer posix.close(p3[1]);
    _ = try loop.attach(p1[1], tctx(1), .{ .read = true });
    _ = try loop.attach(p2[1], tctx(2), .{ .read = true });
    try std.testing.expectError(error.HandleTableFull, loop.attach(p3[1], tctx(3), .{ .read = true }));
}
