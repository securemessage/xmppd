//! Wake and Broadcast: cross-thread loop wakeup and N-loop shutdown.
//!
//! Wake is an EVFILT_USER knote registered by the owning Loop. A producer
//! pushes work into its queue, then notify()s: an atomic pending flag means
//! only the idle -> busy transition costs a syscall, and a notification can
//! never be lost (the consumer clears the flag before draining, so a push
//! racing the drain triggers the next wake). The trigger repeats the knote's
//! udata: an EVFILT_USER change with flags=0 rewrites kn_kevent.udata, and
//! EV_KEEPUDATA sits inside EV_SYSFLAGS so the kernel strips it.
//!
//! Broadcast is one shared pipe per process: every watching loop registers
//! the read end, and close()ing the write end gives every kqueue a persistent
//! EV_EOF (one byte would wake only one reader), which is how the master
//! drains N workers at once.

const std = @import("std");
const posix = std.posix;
const kev = @import("kevent.zig");
const Token = @import("token.zig").Token;
const loop_mod = @import("loop.zig");

pub const Wake = struct {
    kq: posix.fd_t,
    pending: std.atomic.Value(bool),

    pub const NotifyError = error{
        LoopClosed, // the knote or kqueue is gone
        SystemResources,
        Unexpected,
    };

    /// Any thread. Writes to the kernel only on the false -> true transition.
    pub fn notify(self: *Wake) NotifyError!void {
        if (self.pending.swap(true, .acq_rel)) return;
        const trigger = kev.Kevent{
            .ident = loop_mod.wake_ident,
            .filter = std.c.EVFILT.USER,
            .flags = 0,
            .fflags = std.c.NOTE.TRIGGER,
            .data = 0,
            .udata = loop_mod.wake_token.toUdata(),
        };
        kev.applyNow(self.kq, &trigger) catch |err| {
            // Clear so a retry can trigger again; a dead loop surfaces once.
            _ = self.pending.swap(false, .acq_rel);
            return switch (err) {
                error.NotFound, error.BadDescriptor, error.KqueueInvalid => error.LoopClosed,
                error.SystemResources => error.SystemResources,
                else => error.Unexpected,
            };
        };
    }

    /// The owning loop clears the flag before it reports `.wake`; a producer
    /// that runs between the clear and the drain triggers a fresh wake.
    pub fn consume(self: *Wake) void {
        _ = self.pending.swap(false, .acq_rel);
    }
};

pub const Broadcast = struct {
    read_fd: posix.fd_t,
    write_fd: std.atomic.Value(posix.fd_t),

    /// Non-blocking CLOEXEC pipe; read_fd is shared with every watching loop.
    pub fn init(self: *Broadcast) error{ SystemResources, Unexpected }!void {
        const flags: posix.O = .{ .NONBLOCK = true, .CLOEXEC = true };
        const fds = posix.pipe2(flags) catch |err| switch (err) {
            error.SystemFdQuotaExceeded, error.ProcessFdQuotaExceeded => return error.SystemResources,
            else => return error.Unexpected,
        };
        self.* = .{
            .read_fd = fds[0],
            .write_fd = std.atomic.Value(posix.fd_t).init(fds[1]),
        };
    }

    /// Any thread, idempotent: the first call closes the write end and every
    /// watching kqueue sees EV_EOF on the read end.
    pub fn close(self: *Broadcast) void {
        const fd = self.write_fd.swap(-1, .acq_rel);
        if (fd >= 0) _ = std.c.close(fd);
    }

    /// After every loop stopped watching (shutdown complete).
    pub fn deinit(self: *Broadcast) void {
        self.close();
        _ = std.c.close(self.read_fd);
        self.read_fd = -1;
    }
};

// ============================================================================
// Tests
// ============================================================================

fn testLoop() !loop_mod.Loop {
    var loop: loop_mod.Loop = undefined;
    const options: loop_mod.Options = .{ .handles_max = 8, .timers_max = 4, .events_max = 8 };
    try loop.init(std.testing.allocator, &options);
    return loop;
}

test "Wake: notify delivers one wake event, coalesced" {
    // Two notifies before the wait cost one delivery; the flag is cleared at
    // delivery so a later notify wakes again.
    var loop = try testLoop();
    defer loop.deinit(std.testing.allocator);

    try loop.waker().notify();
    try loop.waker().notify();
    try loop.wait();
    try std.testing.expectEqual(.wake, loop.next().?);
    try std.testing.expectEqual(@as(u64, 1), loop.stats().wakes);
    try std.testing.expect(loop.next() == null);

    loop.requestImmediate();
    try loop.wait();
    try std.testing.expect(loop.next() == null); // consumed, no replay

    try loop.waker().notify();
    try loop.wait();
    try std.testing.expectEqual(.wake, loop.next().?);
}

const NotifyCtx = struct {
    wake: *Wake,
    count: usize,
    fn run(self: *NotifyCtx) void {
        for (0..self.count) |_| self.wake.notify() catch return;
    }
};

test "Wake: N producer threads coalesce to one pending flag flip" {
    var loop = try testLoop();
    defer loop.deinit(std.testing.allocator);

    var ctxs: [4]NotifyCtx = undefined;
    var threads: [4]std.Thread = undefined;
    for (&ctxs, &threads) |*ctx_, *t| {
        ctx_.* = .{ .wake = loop.waker(), .count = 50 };
        t.* = try std.Thread.spawn(.{}, NotifyCtx.run, .{ctx_});
    }
    for (threads) |t| t.join();

    try loop.wait();
    try std.testing.expectEqual(.wake, loop.next().?);
    try std.testing.expectEqual(@as(u64, 1), loop.stats().wakes);

    // The pending flag was consumed; nothing lingers.
    loop.requestImmediate();
    try loop.wait();
    try std.testing.expect(loop.next() == null);
}

test "Broadcast: close reaches every watching loop exactly once" {
    var broadcast: Broadcast = undefined;
    try broadcast.init();
    defer broadcast.deinit();

    var loop_a = try testLoop();
    defer loop_a.deinit(std.testing.allocator);
    var loop_b = try testLoop();
    defer loop_b.deinit(std.testing.allocator);
    try loop_a.watchBroadcast(&broadcast);
    try loop_b.watchBroadcast(&broadcast);

    broadcast.close();

    try loop_a.wait();
    try std.testing.expectEqual(.broadcast_closed, loop_a.next().?);
    try loop_b.wait();
    try std.testing.expectEqual(.broadcast_closed, loop_b.next().?);

    // The knote is disarmed after delivery: the persistent EOF cannot spin.
    loop_a.requestImmediate();
    try loop_a.wait();
    try std.testing.expect(loop_a.next() == null);
}
