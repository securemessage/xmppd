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

/// Kind values minted by the loop itself. Consumer kinds live only in `ctx`.
pub const handle_kind: u8 = 0x01;
pub const wake_kind: u8 = 0x02;
pub const timer_kind: u8 = 0x03;
pub const broadcast_kind: u8 = 0x04;

/// Ident and udata of the loop's EVFILT_USER knote.
pub const wake_ident: usize = 0;
pub const wake_token: Token = .{ .index = 0, .gen = 1, .kind = wake_kind };
const broadcast_token: Token = .{ .index = 0, .gen = 1, .kind = broadcast_kind };

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

pub const Event = union(enum) {
    readable: Io,
    writable: Io,
    change_failed: ChangeFailure,
    wake,
    broadcast_closed,
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
pub const WaitError = kev.SubmitWaitError;
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
    requeue: std.ArrayList(RequeueEntry),
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
        const requeue = try gpa.alloc(RequeueEntry, 2 * options.handles_max);
        errdefer gpa.free(requeue);
        const paused = try gpa.alloc(Token, options.paused_max);
        errdefer gpa.free(paused);

        self.* = .{
            .kq = kq,
            .handles = handles,
            .dirty = std.ArrayList(Token).initBuffer(dirty),
            .requeue = std.ArrayList(RequeueEntry).initBuffer(requeue),
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
            .now_ms_ = 0,
            .owner_tid = std.Thread.getCurrentId(),
            .wake_state = .{ .kq = kq, .pending = std.atomic.Value(bool).init(false) },
            .broadcast_fd = -1,
            .broadcast_seen = false,
            .broadcast_disarm = false,
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

    /// Closes every attached fd and the kqueue.
    pub fn deinit(self: *Loop, gpa: std.mem.Allocator) void {
        for (self.handles.values[0..self.handles.pool]) |h| {
            if (h.fd >= 0) rawClose(h.fd);
        }
        posix.close(self.kq);
        self.handles.deinit(gpa);
        gpa.free(self.dirty.allocatedSlice());
        gpa.free(self.requeue.allocatedSlice());
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
    pub fn requeueHandle(self: *Loop, handle: Handle, filter: Filter) HandleError!void {
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
        self.requeue.appendAssumeCapacity(.{ .token = handle, .filter = filter });
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

    /// Purge the handle's staged changes (dirty-list tombstone, order of the
    /// other handles preserved), free the slot and close the fd. Every paused
    /// listener on this loop resumes read interest.
    pub fn close(self: *Loop, handle: Handle) HandleError!void {
        self.assertOwner();
        const h = self.resolve(handle) orelse return error.StaleHandle;
        const fd = h.fd;
        h.fd = -1; // freed slots keep their value; deinit skips -1
        self.purgeDirty(handle);
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
        self.purgeDirty(handle);
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

    // -- Iteration -----------------------------------------------------------

    /// The next `wait()` uses a zero timeout. Set automatically by
    /// `requeueHandle`.
    pub fn requestImmediate(self: *Loop) void {
        self.immediate = true;
    }

    /// End-of-iteration step: run the flush hook, reconcile dirty handles into
    /// the change buffer, then one kevent(2) applies the whole staged set and
    /// harvests the next batch. Asserts the previous batch was fully consumed.
    pub fn wait(self: *Loop) WaitError!void {
        self.assertOwner();
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
        std.debug.assert(nchanges <= self.change_buf.len);

        self.requeue_len = self.requeue.items.len;
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
        while (self.requeue_pos < self.requeue_len) {
            const entry = self.requeue.items[self.requeue_pos];
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

    /// Keep requeue entries appended after `requeue_len` (this pass already
    /// delivered its share) for the next pass.
    fn compactRequeue(self: *Loop) void {
        const tail = self.requeue.items.len - self.requeue_len;
        if (tail > 0) {
            std.mem.copyForwards(
                RequeueEntry,
                self.requeue.items[0..tail],
                self.requeue.items[self.requeue_len..],
            );
        }
        self.requeue.shrinkRetainingCapacity(tail);
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
    /// other handles' entries keep their relative order.
    fn purgeDirty(self: *Loop, handle: Handle) void {
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
        switch (token.kind) {
            handle_kind => {},
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
            // The kernel disarmed the write knote on delivery.
            h.reg_write = .disabled;
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
        error.WouldBlock => {},
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

    // EV_DISPATCH disarmed the knote: an idle pass produces nothing.
    loop.requestImmediate();
    try loop.wait();
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 0), events.items.len);

    // Wanting write again re-arms it.
    try loop.setInterest(h, .{ .write = true });
    try loop.wait();
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
    _ = events.items[0].writable;
    events.clearRetainingCapacity();

    // After delivery, not wanting write keeps it silent with no changes.
    try loop.setInterest(h, .{});
    loop.requestImmediate();
    try loop.wait();
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 0), events.items.len);
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

    try loop.requeueHandle(h, .read);
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
    try loop.requeueHandle(h, .read);
    try loop.requeueHandle(h, .read);
    try loop.wait();
    try drain(&loop, &events);
    try std.testing.expectEqual(@as(usize, 1), events.items.len);
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
