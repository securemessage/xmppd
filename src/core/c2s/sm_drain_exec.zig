//! Off-loop executor for the section-5 unacked drain's offline stores.
//!
//! The worker loop hands bounded `storeHeldPointer` jobs to a ring; a
//! dedicated writer thread wakes on its own kqueue (a one-byte wake pipe
//! written on the empty-to-non-empty edge), takes the store's compound
//! lock and commits, then pushes each job onto the owning worker's
//! completion stack and triggers that loop's self-wake knote. LMDB write
//! latency therefore never reaches an event batch: submission either
//! queues within MAX_JOBS or fails, and a refused submission is counted
//! and bounced by the caller - the loop never falls back to an inline
//! commit on allocation failure or queue pressure.
//!
//! Threads: `submit`, `pending`, `start`, `stop` and `deinit` run on the
//! owning loop thread; `writerMain` and `pumpStore` run on the executor
//! thread (tests drive `pumpStore` on the test thread when no thread was
//! started). Completions are popped and settled back on the loop by the
//! drain tick, which also releases each job's retained blob.

const std = @import("std");
const posix = std.posix;
const log = std.log.scoped(.sm_drain_exec);

const Blob = @import("delivery_queue").Blob;
const router = @import("../routing/router.zig");
const EventLoop = @import("../worker/loop.zig").EventLoop;

/// Signature the executor uses to commit one job; the adapter folds the
/// store's `!bool` (quota full, backend error) into a plain `stored`.
pub const StoreFn = *const fn (
    ctx: *anyopaque,
    recipient: []const u8,
    from_jid: []const u8,
    stanza_id: []const u8,
    timestamp: u64,
    stanza_xml: []const u8,
) bool;

/// One store job. `from` and `stanza_id` point into `blob` bytes, which
/// the job keeps retained until the loop settles the completion.
pub const Job = struct {
    /// Intrusive link on the completion stack.
    next: ?*Job = null,
    /// Completion stack of the owning worker.
    completed: *std.atomic.Value(?*Job),
    /// Loop the executor wakes after pushing the completion.
    wake: *EventLoop,
    store_ctx: *anyopaque,
    store_fn: StoreFn,
    blob: *Blob,
    recipient_len: u16 = 0,
    recipient: [router.BARE_JID_MAX]u8 = undefined,
    from: []const u8 = &.{},
    stanza_id: []const u8 = &.{},
    timestamp: u64 = 0,
    /// Filled by the executor thread before the completion push.
    stored: bool = false,

    /// Release the retained blob and the job allocation. Callable from
    /// any thread once the job is unlinked from every queue.
    pub fn destroy(job: *Job) void {
        job.blob.releaseRetention();
        std.heap.c_allocator.destroy(job);
    }
};

/// Arguments to `Executor.submit` (the store call, the retained stanza
/// and where its completion lands).
pub const Submit = struct {
    completed: *std.atomic.Value(?*Job),
    wake: *EventLoop,
    store_ctx: *anyopaque,
    store_fn: StoreFn,
    blob: *Blob,
    recipient: []const u8,
    from_jid: []const u8,
    stanza_id: []const u8,
    timestamp: u64,
};

pub const Executor = struct {
    /// Jobs outstanding across the ring and in-flight completions. Also
    /// bounds retained blob bytes at MAX_JOBS x MAX_BLOB_SIZE.
    pub const MAX_JOBS: usize = 256;

    ring: [MAX_JOBS]?*Job = .{null} ** MAX_JOBS,
    /// Index of the oldest queued job, the append point, and live count;
    /// all three move under `mutex`.
    head: usize = 0,
    tail: usize = 0,
    count: usize = 0,
    mutex: std.Thread.Mutex = .{},

    pipe_rd: posix.fd_t = -1,
    pipe_wr: posix.fd_t = -1,

    /// Set by stop(); the writer drains and exits.
    stopping: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Wake coalescing: true while a wake byte is queued or in flight
    /// (same discipline as the archive write queue).
    wake_pending: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    started: bool = false,
    thread: ?std.Thread = null,

    /// Ops visibility: submissions, refused submissions, commits handed
    /// to completions, and wake-pipe write failures.
    submitted: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    queue_full: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    completed_jobs: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    wake_failed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Queue a store job. Non-blocking: fails with error.Full when the
    /// ring is at MAX_JOBS or the job allocation fails, so the caller
    /// settles the stanza as refused-and-bounced instead of committing
    /// inline. Retains `req.blob` only on success.
    pub fn submit(self: *Executor, req: Submit) error{Full}!void {
        std.debug.assert(req.recipient.len <= router.BARE_JID_MAX);
        const job = std.heap.c_allocator.create(Job) catch {
            _ = self.queue_full.fetchAdd(1, .monotonic);
            return error.Full;
        };
        req.blob.retain();
        job.* = .{
            .completed = req.completed,
            .wake = req.wake,
            .store_ctx = req.store_ctx,
            .store_fn = req.store_fn,
            .blob = req.blob,
            .recipient_len = @intCast(req.recipient.len),
            .from = req.from_jid,
            .stanza_id = req.stanza_id,
            .timestamp = req.timestamp,
        };
        @memcpy(job.recipient[0..req.recipient.len], req.recipient);

        self.mutex.lock();
        if (self.count >= MAX_JOBS) {
            self.mutex.unlock();
            job.destroy();
            _ = self.queue_full.fetchAdd(1, .monotonic);
            return error.Full;
        }
        self.ring[self.tail] = job;
        self.tail = (self.tail + 1) % MAX_JOBS;
        self.count += 1;
        _ = self.submitted.fetchAdd(1, .monotonic);
        self.mutex.unlock();

        // Coalesced wake: only the wake_pending false->true edge writes
        // the pipe. With no writer thread running (tests) there is no
        // edge to coalesce against and nothing to wake.
        if (self.pipe_wr >= 0 and !self.wake_pending.swap(true, .seq_cst)) {
            _ = posix.write(self.pipe_wr, "\x00") catch |err| switch (err) {
                error.WouldBlock => {},
                else => {
                    self.wake_pending.store(false, .seq_cst);
                    _ = self.wake_failed.fetchAdd(1, .monotonic);
                },
            };
        }
    }

    /// Queued jobs waiting for the executor thread (test assertion and
    /// the writer's empty check share it).
    pub fn pending(self: *Executor) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.count;
    }

    /// Executor-side work: commit up to `limit` queued jobs and post
    /// each completion to its worker's stack plus self-wake. The writer
    /// thread drives this; tests drive it directly when no thread runs.
    /// Returns the number of jobs completed.
    pub fn pumpStore(self: *Executor, limit: usize) usize {
        var n: usize = 0;
        while (n < limit) {
            const job = self.pop() orelse break;
            job.stored = job.store_fn(
                job.store_ctx,
                job.recipient[0..job.recipient_len],
                job.from,
                job.stanza_id,
                job.timestamp,
                job.blob.bytes(),
            );
            self.pushCompleted(job);
            n += 1;
        }
        return n;
    }

    /// Create the wake pipe and spawn the writer thread. The loop calls
    /// it once at run start; without a thread, `submit` still queues and
    /// `pumpStore` steps the queue synchronously.
    pub fn start(self: *Executor) !void {
        std.debug.assert(!self.started);
        const fds = try posix.pipe();
        _ = std.c.fcntl(fds[0], std.c.F.SETFL, @as(c_int, @bitCast(std.c.O{ .NONBLOCK = true })));
        _ = std.c.fcntl(fds[1], std.c.F.SETFL, @as(c_int, @bitCast(std.c.O{ .NONBLOCK = true })));

        self.stopping.store(false, .release);
        self.pipe_rd = fds[0];
        self.pipe_wr = fds[1];
        self.thread = std.Thread.spawn(.{}, writerMain, .{self}) catch |err| {
            posix.close(fds[0]);
            posix.close(fds[1]);
            self.pipe_rd = -1;
            self.pipe_wr = -1;
            return err;
        };
        self.started = true;
    }

    /// Signal the writer to drain and exit, then join it. Completions
    /// for the final jobs sit on the workers' stacks for the drain tick
    /// or the deinit sweep to settle.
    pub fn stop(self: *Executor) void {
        if (!self.started) return;
        self.stopping.store(true, .seq_cst);
        _ = posix.write(self.pipe_wr, "\x00") catch {
            _ = self.wake_failed.fetchAdd(1, .monotonic);
        };
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        self.started = false;
    }

    /// Destroy every job still queued (unstarted executor or jobs
    /// submitted after the writer stopped) and close the pipe. Completions
    /// already posted belong to the owning worker's sweep, not here.
    pub fn deinit(self: *Executor) void {
        std.debug.assert(!self.started);
        while (self.pop()) |job| job.destroy();
        if (self.pipe_rd >= 0) posix.close(self.pipe_rd);
        if (self.pipe_wr >= 0) posix.close(self.pipe_wr);
    }

    fn pop(self: *Executor) ?*Job {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.count == 0) return null;
        const job = self.ring[self.head];
        self.ring[self.head] = null;
        self.head = (self.head + 1) % MAX_JOBS;
        self.count -= 1;
        return job;
    }

    /// Push the job onto its worker's completion stack and wake that
    /// loop. Treiber push: release so the stack top the loop pops
    /// carries the committed `stored` value.
    fn pushCompleted(self: *Executor, job: *Job) void {
        var top = job.completed.load(.monotonic);
        while (true) {
            job.next = top;
            if (job.completed.cmpxchgWeak(top, job, .release, .monotonic)) |t| {
                top = t;
                continue;
            }
            break;
        }
        _ = self.completed_jobs.fetchAdd(1, .monotonic);
        job.wake.selfWake() catch {
            _ = self.wake_failed.fetchAdd(1, .monotonic);
            log.err("SM drain executor: completion self-wake failed", .{});
        };
    }

    /// Drain the wake pipe (after EVFILT_READ on pipe_rd). Clears
    /// wake_pending after the byte drain and before the writer's empty
    /// check so no wake is lost to the flag race (same ordering the
    /// archive queue documents).
    fn drainPipe(self: *Executor) void {
        var buf: [64]u8 = undefined;
        while (true) {
            const n = posix.read(self.pipe_rd, &buf) catch break;
            if (n <= 0) break;
            if (n < buf.len) break;
        }
        _ = self.wake_pending.swap(false, .seq_cst);
    }

    /// Writer-thread main loop: kqueue-wait on the pipe, commit all
    /// queued jobs per wake, exit once stopping and empty.
    fn writerMain(self: *Executor) void {
        const kq = posix.kqueue() catch {
            // No wait primitive left: settle what is queued so no
            // submission is stranded, then exit.
            _ = self.pumpStore(MAX_JOBS);
            return;
        };
        defer posix.close(kq);

        const change = [1]posix.Kevent{.{
            .ident = @intCast(self.pipe_rd),
            .filter = std.c.EVFILT.READ,
            .flags = std.c.EV.ADD | std.c.EV.ENABLE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        }};
        var events: [1]posix.Kevent = undefined;
        _ = posix.kevent(kq, &change, &events, null) catch |err| {
            // Without the pipe knote a plain kevent wait never returns
            // and stop() would hang in join: settle the queue and exit.
            log.err("SM drain executor: pipe registration failed: {s} - exiting writer thread", .{@errorName(err)});
            _ = self.pumpStore(MAX_JOBS);
            return;
        };

        while (true) {
            _ = self.pumpStore(MAX_JOBS);

            self.drainPipe();
            // Check flags after drainPipe: a stop or wake byte consumed
            // there is not re-deliverable, so its effect must be observed
            // before kevent arms. Sleep only on an empty ring: a job
            // pushed after this check is an empty-to-non-empty edge, so
            // its wake byte lands before the wait.
            if (self.stopping.load(.acquire) and self.pending() == 0) return;
            if (self.pending() != 0) continue;
            _ = posix.kevent(kq, &.{}, &events, null) catch |err| {
                log.err("SM drain executor kevent failed: {s} - exiting writer thread", .{@errorName(err)});
                return;
            };
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

const MockStore = struct {
    calls: u32 = 0,
    quota_full: bool = false,
    last_stanza: []u8 = &.{},

    fn store(ctx: *anyopaque, _: []const u8, _: []const u8, _: []const u8, _: u64, stanza_xml: []const u8) bool {
        const self: *MockStore = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        if (self.last_stanza.len > 0) std.heap.c_allocator.free(self.last_stanza);
        self.last_stanza = std.heap.c_allocator.dupe(u8, stanza_xml) catch &.{};
        return !self.quota_full;
    }
};

fn testLoop(allocator: std.mem.Allocator) !EventLoop {
    return EventLoop.init(allocator, 8);
}

test "Executor: submit queues, pump commits, completion carries the outcome" {
    const allocator = std.testing.allocator;
    var exec: Executor = .{};
    defer exec.deinit();

    var loop = try testLoop(allocator);
    defer loop.deinit();
    var completed: std.atomic.Value(?*Job) = std.atomic.Value(?*Job).init(null);
    var store: MockStore = .{};
    const blob = try Blob.createUncharged(allocator, "<message id='m1'/>");

    try exec.submit(.{
        .completed = &completed,
        .wake = &loop,
        .store_ctx = &store,
        .store_fn = MockStore.store,
        .blob = blob,
        .recipient = "alice@localhost",
        .from_jid = "bob@localhost/res",
        .stanza_id = "m1",
        .timestamp = 1,
    });
    blob.releaseRetention();

    // The commit did not run on the submitting thread.
    try std.testing.expectEqual(@as(u32, 0), store.calls);
    try std.testing.expectEqual(@as(usize, 1), exec.pending());

    try std.testing.expectEqual(@as(usize, 1), exec.pumpStore(Executor.MAX_JOBS));
    try std.testing.expectEqual(@as(u32, 1), store.calls);
    try std.testing.expectEqualStrings("<message id='m1'/>", store.last_stanza);

    const job = completed.load(.monotonic).?;
    try std.testing.expect(job.stored);
    job.destroy();
    std.heap.c_allocator.free(store.last_stanza);
}

test "Executor: a full ring refuses instead of growing" {
    const allocator = std.testing.allocator;
    var exec: Executor = .{};
    defer exec.deinit();

    var loop = try testLoop(allocator);
    defer loop.deinit();
    var completed: std.atomic.Value(?*Job) = std.atomic.Value(?*Job).init(null);
    var store: MockStore = .{};

    var blobs: [Executor.MAX_JOBS + 1]*Blob = undefined;
    for (&blobs, 0..) |*b, i| {
        b.* = try Blob.createUncharged(allocator, "<m/>");
        defer b.*.releaseRetention();
        const req = Submit{
            .completed = &completed,
            .wake = &loop,
            .store_ctx = &store,
            .store_fn = MockStore.store,
            .blob = b.*,
            .recipient = "alice@localhost",
            .from_jid = "",
            .stanza_id = "",
            .timestamp = @intCast(i),
        };
        if (i < Executor.MAX_JOBS) {
            try exec.submit(req);
        } else {
            try std.testing.expectError(error.Full, exec.submit(req));
        }
    }
    try std.testing.expectEqual(@as(usize, Executor.MAX_JOBS), exec.pending());
    try std.testing.expectEqual(@as(u64, 1), exec.queue_full.load(.monotonic));

    _ = exec.pumpStore(Executor.MAX_JOBS);
    try std.testing.expectEqual(@as(u32, Executor.MAX_JOBS), store.calls);
    while (completed.load(.monotonic)) |job| {
        completed.store(job.next, .monotonic);
        job.destroy();
    }
}

test "Executor: the writer thread commits and stop drains the queue" {
    const allocator = std.testing.allocator;
    var exec: Executor = .{};
    defer exec.deinit();

    var loop = try testLoop(allocator);
    defer loop.deinit();
    var completed: std.atomic.Value(?*Job) = std.atomic.Value(?*Job).init(null);
    var store: MockStore = .{};

    try exec.start();
    const blob = try Blob.createUncharged(allocator, "<message id='m9'/>");
    try exec.submit(.{
        .completed = &completed,
        .wake = &loop,
        .store_ctx = &store,
        .store_fn = MockStore.store,
        .blob = blob,
        .recipient = "alice@localhost",
        .from_jid = "bob@localhost/res",
        .stanza_id = "m9",
        .timestamp = 9,
    });
    blob.releaseRetention();

    // Bounded wait for the writer thread's completion push.
    var tries: usize = 0;
    while (completed.load(.acquire) == null and tries < 1_000_000) : (tries += 1) {
        std.Thread.yield() catch {};
    }
    const job = completed.load(.acquire).?;
    try std.testing.expect(job.stored);
    try std.testing.expectEqual(@as(u32, 1), store.calls);
    job.destroy();
    std.heap.c_allocator.free(store.last_stanza);

    // stop() joins the writer after it drains whatever is queued.
    const blob2 = try Blob.createUncharged(allocator, "<message id='m10'/>");
    try exec.submit(.{
        .completed = &completed,
        .wake = &loop,
        .store_ctx = &store,
        .store_fn = MockStore.store,
        .blob = blob2,
        .recipient = "alice@localhost",
        .from_jid = "",
        .stanza_id = "m10",
        .timestamp = 10,
    });
    blob2.releaseRetention();
    exec.stop();
    try std.testing.expectEqual(@as(u32, 2), store.calls);
    const job2 = completed.load(.acquire).?;
    job2.destroy();
    std.heap.c_allocator.free(store.last_stanza);
}
