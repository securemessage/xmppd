//! # Archive Write Queue — decouple storage I/O from the event loops (T87)
//!
//! Every core worker used to call archive.store() inline; a backend
//! compaction stall (50-500ms) froze every session on that worker. Now
//! producers enqueue deep-copied jobs into a bounded ring guarded by a
//! mutex, and ONE writer thread drains it, calling store() on the shared
//! archive backend. Stalls cost the writer thread only; the event loops
//! never touch the write path. A side benefit: archive writes are now
//! single-threaded (they were N-writer concurrent before).
//!
//! ## Discipline
//!
//! - Job payloads are deep-copied with the C allocator: producers and the
//!   writer share no allocator state (same rule as sm_handoff.zig).
//! - Bounded ring (MAX_JOBS). At 75% a warning logs once; full jobs are
//!   dropped with an error — message delivery is never delayed by archival.
//! - The writer wakes via the classic 1-byte pipe: its read end sits in the
//!   writer thread's own kqueue; producers write a byte after enqueueing.
//! - The writer calls store() per job (a single WriteBatch was considered
//!   and deferred: duplicate-key behavior within one batch differs per
//!   backend; per-job keeps semantics identical to the old inline path).
//! - MAM/history reads stay inline on the workers (eventually consistent by
//!   design: a MAM query may miss a message archived milliseconds ago).

const std = @import("std");
const posix = std.posix;

const log = std.log.scoped(.archive_writer);

/// One archive write: owner bare JID, conversation partner, stanza-id,
/// timestamp, full stanza XML. All slices owned by the queue.
pub const Job = struct {
    owner: []u8,
    with: []u8,
    stanza_id: []u8,
    timestamp: u64,
    stanza_xml: []u8,

    pub fn deinit(self: *Job) void {
        std.heap.c_allocator.free(self.owner);
        std.heap.c_allocator.free(self.with);
        std.heap.c_allocator.free(self.stanza_id);
        std.heap.c_allocator.free(self.stanza_xml);
    }
};

/// Deep-copy a job; the job owns its slices on success.
fn copyJob(owner: []const u8, with: []const u8, stanza_id: []const u8, timestamp: u64, stanza_xml: []const u8) !Job {
    var job = Job{
        .owner = try std.heap.c_allocator.dupe(u8, owner),
        .with = undefined,
        .stanza_id = undefined,
        .timestamp = timestamp,
        .stanza_xml = undefined,
    };
    errdefer std.heap.c_allocator.free(job.owner);
    job.with = try std.heap.c_allocator.dupe(u8, with);
    errdefer std.heap.c_allocator.free(job.with);
    job.stanza_id = try std.heap.c_allocator.dupe(u8, stanza_id);
    errdefer std.heap.c_allocator.free(job.stanza_id);
    job.stanza_xml = try std.heap.c_allocator.dupe(u8, stanza_xml);
    return job;
}

/// Bounded producer/consumer ring with a wake pipe.
pub const ArchiveWriteQueue = struct {
    /// Survives ~12s of stall at 170 archive writes/sec (task analysis).
    pub const MAX_JOBS: usize = 2048;

    slots: [MAX_JOBS]Job = undefined,
    head: usize = 0, // next pop
    tail: usize = 0, // next push
    mutex: std.Thread.Mutex = .{},

    pipe_rd: posix.fd_t = -1,
    pipe_wr: posix.fd_t = -1,

    /// Set by shutdown; the writer drains and exits.
    stopping: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// latch for the 75% warning so it logs once per surge, not per job
    high_water_warned: bool = false,

    /// Total dropped jobs (queue full) since start — for ops visibility.
    dropped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn init() !ArchiveWriteQueue {
        const fds = try posix.pipe();
        errdefer posix.close(fds[0]);
        errdefer posix.close(fds[1]);
        _ = std.c.fcntl(fds[0], std.c.F.SETFL, @as(c_int, @bitCast(std.c.O{ .NONBLOCK = true })));
        _ = std.c.fcntl(fds[1], std.c.F.SETFL, @as(c_int, @bitCast(std.c.O{ .NONBLOCK = true })));
        return .{ .pipe_rd = fds[0], .pipe_wr = fds[1] };
    }

    /// Free any undrained jobs, then close the pipe. Call after the writer
    /// thread has been joined.
    pub fn deinit(self: *ArchiveWriteQueue) void {
        while (self.pop()) |job_value| {
            var job = job_value;
            job.deinit();
        }
        if (self.pipe_rd >= 0) posix.close(self.pipe_rd);
        if (self.pipe_wr >= 0) posix.close(self.pipe_wr);
    }

    fn countLocked(self: *const ArchiveWriteQueue) usize {
        // head/tail move in lockstep under the mutex; count = tail - head.
        return self.tail - self.head;
    }

    /// Deep-copy and enqueue. Full: drop, log, count — delivery unaffected.
    pub fn enqueue(
        self: *ArchiveWriteQueue,
        owner: []const u8,
        with: []const u8,
        stanza_id: []const u8,
        timestamp: u64,
        stanza_xml: []const u8,
    ) void {
        var job = copyJob(owner, with, stanza_id, timestamp, stanza_xml) catch {
            log.err("archive write queue: job copy alloc failed — dropping", .{});
            return;
        };

        self.mutex.lock();
        defer self.mutex.unlock();

        const n = self.countLocked();
        if (n >= MAX_JOBS) {
            _ = self.dropped.fetchAdd(1, .monotonic);
            job.deinit();
            log.warn("archive write queue full ({d}) — dropping job ({d} dropped total)", .{ n, self.dropped.load(.monotonic) });
            return;
        }
        const warn_mark = MAX_JOBS * 3 / 4;
        if (n >= warn_mark and !self.high_water_warned) {
            self.high_water_warned = true;
            log.warn("archive write queue at {d}/{d} (backend stalled?)", .{ n, MAX_JOBS });
        } else if (n < warn_mark and self.high_water_warned) {
            self.high_water_warned = false;
        }

        self.slots[self.tail % MAX_JOBS] = job;
        self.tail += 1;

        _ = posix.write(self.pipe_wr, "\x00") catch {};
    }

    /// Pop a job (caller owns its memory). Null when empty.
    pub fn pop(self: *ArchiveWriteQueue) ?Job {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.head == self.tail) return null;
        defer self.head += 1;
        return self.slots[self.head % MAX_JOBS];
    }

    /// Drain the wake pipe (after EVFILT_READ on pipe_rd).
    pub fn drainPipe(self: *ArchiveWriteQueue) void {
        var buf: [64]u8 = undefined;
        while (true) {
            const n = posix.read(self.pipe_rd, &buf) catch break;
            if (n <= 0) break;
            if (n < buf.len) break;
        }
    }

    /// Writer-thread main loop: kqueue-wait on the pipe, drain up to
    /// `batch` jobs per iteration into the store, exit when stopping and
    /// empty. The store type only needs
    /// `store(owner, with, stanza_id, timestamp, stanza_xml) !void`.
    pub fn writerLoop(self: *ArchiveWriteQueue, store: anytype, batch: usize) void {
        const kq = posix.kqueue() catch {
            // No kqueue means no event-driven wait; drain what's queued and
            // give up — the process is mid-shutdown if this ever fires.
            log.err("writer kqueue failed — draining queue and exiting writer thread", .{});
            self.drainInto(store, std.math.maxInt(usize));
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
        _ = posix.kevent(kq, &change, &events, null) catch {};

        while (true) {
            self.drainInto(store, batch);

            if (self.stopping.load(.acquire) and self.countIsEmpty()) {
                return;
            }

            self.drainPipe();
            _ = posix.kevent(kq, &.{}, &events, null) catch |err| {
                log.err("writer kevent failed: {} — exiting writer thread", .{err});
                return;
            };
        }
    }

    /// Store up to `batch` queued jobs. Bounded so a flood can't starve the
    /// stopping check; the wake pipe keeps the loop hot between batches.
    fn drainInto(self: *ArchiveWriteQueue, store: anytype, batch: usize) void {
        var processed: usize = 0;
        while (processed < batch) : (processed += 1) {
            var job = self.pop() orelse break;
            store.store(job.owner, job.with, job.stanza_id, job.timestamp, job.stanza_xml) catch |err| {
                log.err("archive store failed: {}", .{err});
            };
            job.deinit();
        }
    }

    fn countIsEmpty(self: *ArchiveWriteQueue) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.head == self.tail;
    }
};

// ============================================================================
// Tests
// ============================================================================

const MockStore = struct {
    stored: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    fail_next: bool = false,

    pub fn store(self: *MockStore, owner: []const u8, with: []const u8, stanza_id: []const u8, ts: u64, xml: []const u8) !void {
        _ = owner;
        _ = with;
        _ = stanza_id;
        _ = ts;
        _ = xml;
        if (self.fail_next) {
            self.fail_next = false;
            return error.Fail;
        }
        _ = self.stored.fetchAdd(1, .monotonic);
    }
};

test "ArchiveWriteQueue: enqueue/pop roundtrip with C-owned deep copy" {
    var q = try ArchiveWriteQueue.init();
    defer q.deinit();

    var src_owner = [_]u8{ 'a', 'l', 'i', 'c', 'e' };
    q.enqueue(&src_owner, "bob@localhost", "sid1", 1200, "<message/>");
    // mutate the source after enqueue to prove the deep copy
    src_owner = [_]u8{ 'x' } ** 5;

    var job = q.pop().?;
    defer job.deinit();
    try std.testing.expectEqualStrings("alice", job.owner);
    try std.testing.expectEqualStrings("bob@localhost", job.with);
    try std.testing.expect(q.pop() == null);
}

test "ArchiveWriteQueue: full ring drops and counts" {
    var q = try ArchiveWriteQueue.init();
    defer q.deinit(); // frees undrained jobs

    for (0..ArchiveWriteQueue.MAX_JOBS + 8) |_| {
        q.enqueue("a@localhost", "b@localhost", "s", 1, "<m/>");
    }
    try std.testing.expectEqual(@as(u64, 8), q.dropped.load(.monotonic));
}

test "ArchiveWriteQueue: writerLoop drains into store and exits on stop" {
    var q = try ArchiveWriteQueue.init();
    defer q.deinit();

    var store = MockStore{};
    const t = try std.Thread.spawn(.{}, struct {
        fn run(queue: *ArchiveWriteQueue, st: *MockStore) void {
            queue.writerLoop(st, 64);
        }
    }.run, .{ &q, &store });

    q.enqueue("a@localhost", "b@localhost", "s1", 1, "<m1/>");
    q.enqueue("a@localhost", "b@localhost", "s2", 2, "<m2/>");

    const deadline = std.time.milliTimestamp() + 5000;
    while (store.stored.load(.monotonic) < 2 and std.time.milliTimestamp() < deadline) {
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    try std.testing.expectEqual(@as(u32, 2), store.stored.load(.monotonic));

    q.stopping.store(true, .release);
    // Wake the writer so it notices the flag
    _ = posix.write(q.pipe_wr, "\x00") catch {};
    t.join();
}
