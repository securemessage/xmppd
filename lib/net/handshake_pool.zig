//! HandshakePool: bounded TLS handshake lanes (ADR-11, F7).
//!
//! Each lane is one thread with one lib/net Loop. A handoff moves the fd and
//! its Tls object into a fixed-capacity job; completion moves both back to
//! the owning worker through that worker's bounded completion ring. Neither
//! object is shared concurrently: ownership transfers with the job.

const std = @import("std");
const posix = std.posix;
const net = @import("net");

const log = std.log.scoped(.handshake_pool);

pub const Error = error{
    PoolBusy,
    PoolStopped,
    SystemResources,
    Unexpected,
    OutOfMemory,
};

pub const Options = struct {
    workers: usize,
    threads: usize,
    active_per_thread: usize = 32,
    queue_per_thread: usize = 128,
    timeout_ms: u64 = 10_000,
};

pub const Job = struct {
    worker_id: u16,
    token_udata: usize,
    fd: posix.fd_t,
    tls: net.Tls,
};

pub const Completion = struct {
    worker_id: u16,
    token_udata: usize,
    fd: posix.fd_t,
    tls: net.Tls,
    ok: bool,
    timed_out: bool,
};

pub const Counters = struct {
    submitted: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    refused: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    completed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    failed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    timed_out: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    completion_ring_full: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    completion_wake_failed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

const lane_kind: u8 = 90;

const Active = struct {
    used: bool = false,
    gen: u24 = 1,
    job: Job = undefined,
    handle: net.Handle = net.Token.none,
    timer: ?net.TimerId = null,
    timed_out: bool = false,
};

const Lane = struct {
    gpa: std.mem.Allocator,
    timeout_ms: u64,
    queue: []Job,
    qhead: usize = 0,
    qlen: usize = 0,
    mutex: std.Thread.Mutex = .{},
    active: []Active,
    active_count: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    loop: net.Loop = undefined,
    ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    init_failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    stopping: *std.atomic.Value(bool),
    pool: *Pool,
    thread: ?std.Thread = null,

    fn wakePtr(self: *Lane) *net.Wake {
        return &self.loop.wake_state;
    }
};

const Endpoint = struct {
    mutex: std.Thread.Mutex = .{},
    ring: []Completion,
    head: usize = 0,
    len: usize = 0,
    read_fd: posix.fd_t = -1,
    write_fd: posix.fd_t = -1,
};

pub const Pool = struct {
    gpa: std.mem.Allocator,
    options: Options,
    lanes: []Lane,
    endpoints: []Endpoint,
    stopping: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    started: bool = false,
    next_lane: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    counters: Counters = .{},

    pub fn init(self: *Pool, gpa: std.mem.Allocator, options: Options) Error!void {
        if (options.workers == 0 or options.threads == 0 or options.active_per_thread == 0) return error.Unexpected;
        const lanes = try gpa.alloc(Lane, options.threads);
        errdefer gpa.free(lanes);
        const endpoints = try gpa.alloc(Endpoint, options.workers);
        errdefer gpa.free(endpoints);

        self.* = .{
            .gpa = gpa,
            .options = options,
            .lanes = lanes,
            .endpoints = endpoints,
        };

        const completion_cap = options.threads * (options.active_per_thread + options.queue_per_thread);
        var endpoints_init: usize = 0;
        errdefer for (endpoints[0..endpoints_init]) |*ep| {
            closePipe(ep);
            gpa.free(ep.ring);
        };
        for (endpoints, 0..) |*ep, i| {
            _ = i;
            ep.* = .{ .ring = try gpa.alloc(Completion, completion_cap) };
            errdefer gpa.free(ep.ring);
            try makePipe(ep);
            endpoints_init += 1;
        }

        var lanes_init: usize = 0;
        errdefer for (lanes[0..lanes_init]) |*lane| {
            gpa.free(lane.queue);
            gpa.free(lane.active);
        };
        for (lanes) |*lane| {
            lane.* = .{
                .gpa = gpa,
                .timeout_ms = options.timeout_ms,
                .queue = try gpa.alloc(Job, options.queue_per_thread),
                .active = try gpa.alloc(Active, options.active_per_thread),
                .stopping = &self.stopping,
                .pool = self,
            };
            for (lane.active) |*a| a.* = .{};
            lanes_init += 1;
        }
    }

    pub fn start(self: *Pool) Error!void {
        if (self.started) return;
        var spawned: usize = 0;
        errdefer {
            self.stopping.store(true, .release);
            for (self.lanes[0..spawned]) |*lane| lane.wakePtr().notify() catch {};
            for (self.lanes[0..spawned]) |*lane| if (lane.thread) |t| t.join();
        }
        for (self.lanes, 0..) |*lane, i| {
            lane.thread = std.Thread.spawn(.{}, laneMain, .{lane}) catch |err| switch (err) {
                else => return error.SystemResources,
            };
            spawned = i + 1;
        }
        var spins: usize = 0;
        while (true) {
            var ready_count: usize = 0;
            var failed = false;
            for (self.lanes) |*lane| {
                if (lane.ready.load(.acquire)) ready_count += 1;
                if (lane.init_failed.load(.acquire)) failed = true;
            }
            if (failed) return error.SystemResources;
            if (ready_count == self.lanes.len) break;
            spins += 1;
            if (spins > 100_000) return error.SystemResources;
            std.Thread.yield() catch {};
        }
        self.started = true;
    }

    pub fn deinit(self: *Pool) void {
        if (self.started) {
            self.stopping.store(true, .release);
            for (self.lanes) |*lane| lane.wakePtr().notify() catch {};
            for (self.lanes) |*lane| if (lane.thread) |t| t.join();
        }
        for (0..self.options.workers) |worker_id| {
            while (self.popCompletion(@intCast(worker_id))) |comp| {
                var owned = comp;
                destroyOwned(owned.fd, &owned.tls);
            }
        }
        for (self.lanes) |*lane| {
            self.gpa.free(lane.queue);
            self.gpa.free(lane.active);
        }
        for (self.endpoints) |*ep| {
            closePipe(ep);
            self.gpa.free(ep.ring);
        }
        self.gpa.free(self.lanes);
        self.gpa.free(self.endpoints);
        self.* = undefined;
    }

    pub fn completionFd(self: *const Pool, worker_id: u16) posix.fd_t {
        return self.endpoints[worker_id].read_fd;
    }

    /// Move one fd/Tls pair into the pool. On success the caller no longer
    /// owns either object. On PoolBusy or any error the caller keeps both.
    pub fn submit(self: *Pool, job: Job) Error!void {
        if (!self.started or self.stopping.load(.acquire)) {
            _ = self.counters.refused.fetchAdd(1, .monotonic);
            return error.PoolStopped;
        }
        const cap = self.options.active_per_thread + self.options.queue_per_thread;
        const base = self.next_lane.fetchAdd(1, .monotonic) % self.lanes.len;
        for (0..self.lanes.len) |off| {
            const lane = &self.lanes[(base + off) % self.lanes.len];
            lane.mutex.lock();
            const occupied = lane.active_count.load(.acquire) + lane.qlen;
            if (occupied < cap and lane.qlen < lane.queue.len) {
                const at = (lane.qhead + lane.qlen) % lane.queue.len;
                lane.queue[at] = job;
                lane.qlen += 1;
                const notify_result = lane.wakePtr().notify();
                if (notify_result) |_| {
                    lane.mutex.unlock();
                    _ = self.counters.submitted.fetchAdd(1, .monotonic);
                    return;
                } else |_| {
                    lane.qlen -= 1;
                    lane.mutex.unlock();
                    _ = self.counters.refused.fetchAdd(1, .monotonic);
                    return error.PoolStopped;
                }
            }
            lane.mutex.unlock();
        }
        _ = self.counters.refused.fetchAdd(1, .monotonic);
        return error.PoolBusy;
    }

    /// Pop one completion for a worker. The caller owns fd and tls in the
    /// returned record exactly once.
    pub fn popCompletion(self: *Pool, worker_id: u16) ?Completion {
        const ep = &self.endpoints[worker_id];
        ep.mutex.lock();
        defer ep.mutex.unlock();
        if (ep.len == 0) return null;
        const out = ep.ring[ep.head];
        ep.head = (ep.head + 1) % ep.ring.len;
        ep.len -= 1;
        return out;
    }

    fn pushCompletion(self: *Pool, completion: Completion) bool {
        const ep = &self.endpoints[completion.worker_id];
        ep.mutex.lock();
        if (ep.len == ep.ring.len) {
            ep.mutex.unlock();
            _ = self.counters.completion_ring_full.fetchAdd(1, .monotonic);
            return false;
        }
        const at = (ep.head + ep.len) % ep.ring.len;
        ep.ring[at] = completion;
        ep.len += 1;
        ep.mutex.unlock();
        const byte = [_]u8{1};
        _ = posix.write(ep.write_fd, &byte) catch |err| blk: {
            switch (err) {
                error.WouldBlock => {},
                else => _ = self.counters.completion_wake_failed.fetchAdd(1, .monotonic),
            }
            break :blk 0;
        };
        return true;
    }
};

fn makePipe(ep: *Endpoint) Error!void {
    const flags: posix.O = .{ .NONBLOCK = true, .CLOEXEC = true };
    const fds = posix.pipe2(flags) catch |err| switch (err) {
        error.SystemFdQuotaExceeded,
        error.ProcessFdQuotaExceeded,
        => return error.SystemResources,
        else => return error.Unexpected,
    };
    ep.read_fd = fds[0];
    ep.write_fd = fds[1];
}

fn closePipe(ep: *Endpoint) void {
    if (ep.read_fd >= 0) posix.close(ep.read_fd);
    if (ep.write_fd >= 0) posix.close(ep.write_fd);
    ep.read_fd = -1;
    ep.write_fd = -1;
}

fn destroyOwned(fd: posix.fd_t, tls: *net.Tls) void {
    tls.conn.deinit();
    if (fd >= 0) posix.close(fd);
}

fn laneMain(lane: *Lane) void {
    const options: net.LoopOptions = .{
        .handles_max = @intCast(lane.active.len),
        .timers_max = @intCast(lane.active.len),
        .events_max = @intCast(@min(lane.active.len * 2 + 2, 256)),
    };
    lane.loop.init(lane.gpa, &options) catch {
        lane.init_failed.store(true, .release);
        lane.ready.store(true, .release);
        return;
    };
    lane.ready.store(true, .release);

    while (!lane.stopping.load(.acquire) or lane.active_count.load(.acquire) != 0 or queuedLen(lane) != 0) {
        lane.loop.wait() catch |err| {
            log.err("handshake lane wait failed: {s}", .{@errorName(err)});
            break;
        };
        while (lane.loop.next()) |ev| {
            switch (ev) {
                .wake => promoteQueued(lane),
                .readable, .writable => |io| stepToken(lane, io.ctx),
                .deadline => |d| timeoutToken(lane, d.ctx),
                .change_failed => |cf| failToken(lane, cf.ctx),
                else => {},
            }
        }
        promoteQueued(lane);
    }

    // Shutdown owns every remaining job directly. Workers are already stopping
    // or stopped, so no completion is posted across a dying loop boundary.
    for (lane.active, 0..) |*a, idx| {
        if (!a.used) continue;
        finishActive(lane, idx, null);
    }
    while (popQueued(lane)) |job| {
        var tls = job.tls;
        destroyOwned(job.fd, &tls);
    }
    lane.loop.deinit(lane.gpa);
}

fn laneToken(idx: usize, gen: u24) net.Token {
    return .{ .index = @intCast(idx), .gen = gen, .kind = lane_kind };
}

fn validActive(lane: *Lane, token: net.Token) ?usize {
    if (token.kind != lane_kind or token.index >= lane.active.len) return null;
    const a = &lane.active[token.index];
    if (!a.used or a.gen != token.gen) return null;
    return token.index;
}

fn stepToken(lane: *Lane, token: net.Token) void {
    const idx = validActive(lane, token) orelse return;
    stepActive(lane, idx);
}

fn failToken(lane: *Lane, token: net.Token) void {
    const idx = validActive(lane, token) orelse return;
    finishActive(lane, idx, false);
}

fn timeoutToken(lane: *Lane, token: net.Token) void {
    const idx = validActive(lane, token) orelse return;
    lane.active[idx].timed_out = true;
    _ = lane.pool.counters.timed_out.fetchAdd(1, .monotonic);
    finishActive(lane, idx, false);
}

fn queuedLen(lane: *Lane) usize {
    lane.mutex.lock();
    defer lane.mutex.unlock();
    return lane.qlen;
}

fn popQueued(lane: *Lane) ?Job {
    lane.mutex.lock();
    defer lane.mutex.unlock();
    if (lane.qlen == 0) return null;
    const job = lane.queue[lane.qhead];
    lane.qhead = (lane.qhead + 1) % lane.queue.len;
    lane.qlen -= 1;
    return job;
}

/// Move one queued job into a reserved active slot. The queue decrement and
/// active-count increment are one mutex-held transfer so submitters cannot
/// observe the job in neither class and admit work past active plus queue.
fn popQueuedForActivation(lane: *Lane) ?Job {
    lane.mutex.lock();
    defer lane.mutex.unlock();
    if (lane.qlen == 0 or lane.active_count.load(.acquire) >= lane.active.len) return null;
    const job = lane.queue[lane.qhead];
    lane.qhead = (lane.qhead + 1) % lane.queue.len;
    lane.qlen -= 1;
    lane.active_count.store(lane.active_count.load(.acquire) + 1, .release);
    return job;
}

fn promoteQueued(lane: *Lane) void {
    while (lane.active_count.load(.acquire) < lane.active.len) {
        const job = popQueuedForActivation(lane) orelse break;
        var idx: ?usize = null;
        for (lane.active, 0..) |*a, i| {
            if (!a.used) {
                idx = i;
                break;
            }
        }
        const i = idx orelse {
            lane.active_count.store(lane.active_count.load(.acquire) - 1, .release);
            var tls = job.tls;
            destroyOwned(job.fd, &tls);
            continue;
        };
        var a = &lane.active[i];
        a.job = job;
        a.used = true;
        a.timer = null;
        a.timed_out = false;
        const ctx = laneToken(i, a.gen);
        a.handle = lane.loop.attach(job.fd, ctx, .{ .read = true, .write = true }) catch {
            finishActive(lane, i, false);
            continue;
        };
        a.timer = lane.loop.scheduleIn(lane.timeout_ms, ctx) catch null;
        stepActive(lane, i);
    }
}

fn stepActive(lane: *Lane, idx: usize) void {
    const a = &lane.active[idx];
    if (!a.used) return;
    const result = a.job.tls.conn.doHandshake() catch {
        finishActive(lane, idx, false);
        return;
    };
    switch (result) {
        .complete => finishActive(lane, idx, true),
        .want_read => lane.loop.setInterest(a.handle, .{ .read = true }) catch finishActive(lane, idx, false),
        .want_write => lane.loop.setInterest(a.handle, .{ .read = true, .write = true }) catch finishActive(lane, idx, false),
    }
}

/// Finish one active job. `ok == null` means shutdown destruction: the fd and
/// TLS object are destroyed locally and no completion is posted.
fn finishActive(lane: *Lane, idx: usize, ok: ?bool) void {
    const a = &lane.active[idx];
    if (!a.used) return;
    var job = a.job;
    const was_timed_out = a.timed_out;
    if (a.timer) |timer| _ = lane.loop.cancelTimer(timer);

    var fd: posix.fd_t = -1;
    var detached = false;
    if (ok != null) {
        fd = lane.loop.detach(a.handle) catch -1;
        detached = fd >= 0;
    } else {
        lane.loop.close(a.handle) catch {};
    }

    a.used = false;
    a.gen +%= 1;
    if (a.gen == 0) a.gen = 1;
    lane.active_count.store(lane.active_count.load(.acquire) - 1, .release);

    if (ok) |initial_success| {
        var success = initial_success;
        if (!detached) success = false;
        if (success) {
            job.tls.ktls_tx = job.tls.conn.ktlsSend();
            job.tls.ktls_rx = job.tls.conn.ktlsRecv();
        }
        const completion: Completion = .{
            .worker_id = job.worker_id,
            .token_udata = job.token_udata,
            .fd = fd,
            .tls = job.tls,
            .ok = success,
            .timed_out = was_timed_out,
        };
        if (success) {
            _ = lane.pool.counters.completed.fetchAdd(1, .monotonic);
        } else {
            _ = lane.pool.counters.failed.fetchAdd(1, .monotonic);
        }
        if (!lane.pool.pushCompletion(completion)) {
            var tls = completion.tls;
            destroyOwned(completion.fd, &tls);
        }
    } else {
        var tls = job.tls;
        tls.conn.deinit();
    }
}
