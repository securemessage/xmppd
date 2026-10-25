//! # Archive Write Queue - decouple storage I/O from the event loops (T87)
//!
//! Producers enqueue deep-copied jobs into a bounded ring guarded by a
//! mutex; one writer thread drains it and calls the shared archive
//! backend. Backend stalls (compaction, fsync) cost the writer thread
//! only; the event loops never touch the write path. Archive writes are
//! single-threaded, so the backend sees one writer.
//!
//! ## Discipline
//!
//! - Job payloads are deep-copied with the C allocator: producers and the
//!   writer share no allocator state (same rule as sm_handoff.zig).
//! - Bounded ring (MAX_JOBS). At 75% a warning logs once; when full, jobs
//!   are dropped with an error - message delivery is never delayed by
//!   archival.
//! - The writer wakes via a 1-byte pipe whose read end sits in the
//!   writer thread's own kqueue. Producers write a byte only when an
//!   enqueue takes the ring from empty to non-empty, and the writer
//!   re-checks the count before sleeping so no wakeup can be lost.
//! - Job payloads live in one allocation per job; the writer commits a
//!   storeAll batch per DRAIN_CAP chunk instead of one commit per job.
//!   A failed chunk is retried job by job so one bad job drops only
//!   itself.
//! - MAM/history reads stay inline on the workers (eventually consistent
//!   by design: a MAM query may miss a message archived milliseconds
//!   ago).

const std = @import("std");
const posix = std.posix;

const log = std.log.scoped(.archive_writer);

/// Counter-based log throttle: fires on the first event and on every
/// power-of-two-th after it, so a flood logs a handful of lines instead
/// of one per event. Call with the post-increment total (>= 1).
pub fn logEveryPowerOfTwo(total: u64) bool {
    return total != 0 and std.math.isPowerOfTwo(total);
}

/// One archive write: owner bare JID, conversation partner, stanza-id,
/// timestamp, full stanza XML. All slices point into `block`, the single
/// allocation the queue owns.
pub const Job = struct {
    owner: []u8,
    with: []u8,
    stanza_id: []u8,
    timestamp: u64,
    stanza_xml: []u8,
    /// Backing allocation for the four slices above.
    block: []u8,

    pub fn deinit(self: *Job) void {
        std.heap.c_allocator.free(self.block);
    }
};

/// Deep-copy a job in one allocation; the job owns `block` on success.
fn copyJob(owner: []const u8, with: []const u8, stanza_id: []const u8, timestamp: u64, stanza_xml: []const u8) !Job {
    const block = try std.heap.c_allocator.alloc(u8, owner.len + with.len + stanza_id.len + stanza_xml.len);
    const o_end = owner.len;
    const w_end = o_end + with.len;
    const s_end = w_end + stanza_id.len;
    @memcpy(block[0..o_end], owner);
    @memcpy(block[o_end..w_end], with);
    @memcpy(block[w_end..s_end], stanza_id);
    @memcpy(block[s_end..], stanza_xml);
    return .{
        .block = block,
        .owner = block[0..o_end],
        .with = block[o_end..w_end],
        .stanza_id = block[w_end..s_end],
        .timestamp = timestamp,
        .stanza_xml = block[s_end..],
    };
}

/// Bounded producer/consumer ring with a wake pipe.
pub const ArchiveWriteQueue = struct {
    /// Survives ~12s of stall at 170 archive writes/sec (task analysis).
    pub const MAX_JOBS: usize = 2048;

    /// Jobs per storeAll call inside a drain; bounds the live job set the
    /// writer holds between pops.
    const DRAIN_CAP: usize = 64;

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

    /// Job payload copies that failed on allocation - dropped before enqueue.
    copy_failed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Jobs the store call rejected inside the writer - logged per job.
    store_failed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Wake-pipe writes that failed after an empty-to-non-empty enqueue;
    /// the writer may sleep while work is pending.
    wake_failed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// storeAll chunks that failed as a batch but landed on the per-job
    /// retry. Only the writer thread increments it.
    retry_recovered: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Chunk of jobs popped per storeAll call inside a drain.
    drain_jobs: [DRAIN_CAP]Job = undefined,

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

    /// Deep-copy and enqueue. Full: drop, log, count - delivery unaffected.
    pub fn enqueue(
        self: *ArchiveWriteQueue,
        owner: []const u8,
        with: []const u8,
        stanza_id: []const u8,
        timestamp: u64,
        stanza_xml: []const u8,
    ) void {
        var job = copyJob(owner, with, stanza_id, timestamp, stanza_xml) catch {
            _ = self.copy_failed.fetchAdd(1, .monotonic);
            log.err("archive write queue: job copy alloc failed - dropping", .{});
            return;
        };

        self.mutex.lock();

        const n = self.countLocked();
        if (n >= MAX_JOBS) {
            self.mutex.unlock();
            const total = self.dropped.fetchAdd(1, .monotonic) + 1;
            job.deinit();
            // Log the first drop and every power of two after it: a full
            // queue would otherwise log per job on the event loop.
            if (logEveryPowerOfTwo(total)) {
                log.warn("archive write queue full ({d}) - dropping job ({d} dropped total)", .{ n, total });
            }
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
        const wake = n == 0;
        self.mutex.unlock();

        // Wake the writer only on the empty-to-non-empty transition; it
        // re-checks the count before sleeping, so further bytes buy
        // nothing. The write runs after the mutex is released so the
        // lock is never held across a syscall.
        if (wake) {
            _ = posix.write(self.pipe_wr, "\x00") catch {
                _ = self.wake_failed.fetchAdd(1, .monotonic);
                log.err("archive write queue: wake write failed - writer may stall until next enqueue", .{});
            };
        }
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

            self.drainPipe();
            // The flags are checked after drainPipe on purpose: a stop or
            // wake byte consumed there is not re-deliverable, so its
            // effect must be observed before kevent arms.
            if (self.stopping.load(.acquire) and self.countIsEmpty()) {
                return;
            }
            // Sleep only when the ring is empty: jobs pushed between the
            // drain and this point must not wait for a later wakeup (V15).
            // A job pushed after this check is an empty-to-non-empty
            // transition, so its wake byte lands in the pipe before kevent.
            if (!self.countIsEmpty()) continue;
            _ = posix.kevent(kq, &.{}, &events, null) catch |err| {
                log.err("writer kevent failed: {} - exiting writer thread", .{err});
                return;
            };
        }
    }

    /// Store up to `batch` queued jobs in chunks of DRAIN_CAP, one storeAll
    /// commit per chunk. Bounded so a flood can't starve the stopping check.
    fn drainInto(self: *ArchiveWriteQueue, store: anytype, batch: usize) void {
        var processed: usize = 0;
        while (processed < batch) {
            var n: usize = 0;
            const room = @min(batch - processed, DRAIN_CAP);
            while (n < room) : (n += 1) {
                self.drain_jobs[n] = self.pop() orelse break;
            }
            if (n == 0) break;
            const items = self.drain_jobs[0..n];
            store.storeAll(items) catch |batch_err| {
                // One bad job must not discard the chunk it rode in
                // with: retry each job alone and count only the jobs
                // that still fail.
                var failed: usize = 0;
                var last_err: anyerror = batch_err;
                for (items) |*job| {
                    store.store(job.owner, job.with, job.stanza_id, job.timestamp, job.stanza_xml) catch |err| {
                        failed += 1;
                        last_err = err;
                    };
                }
                if (failed > 0) {
                    const total = self.store_failed.fetchAdd(@intCast(failed), .monotonic) + failed;
                    if (total == failed or logEveryPowerOfTwo(total)) {
                        log.warn("archive store: {d} of {d} jobs failed after retry ({d} failed total): {}", .{ failed, n, total, last_err });
                    }
                } else {
                    const total = self.retry_recovered.fetchAdd(1, .monotonic) + 1;
                    if (logEveryPowerOfTwo(total)) {
                        log.warn("archive store batch failed; all {d} jobs landed on retry: {}", .{ n, batch_err });
                    }
                }
            };
            for (items) |*job| job.deinit();
            processed += n;
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
    batches: u32 = 0,
    fail_next: bool = false,
    /// Per-job store() rejects jobs whose stanza_id equals this marker.
    poisoned_id: []const u8 = "poison",

    pub fn storeAll(self: *MockStore, items: anytype) !void {
        if (self.fail_next) {
            self.fail_next = false;
            return error.Fail;
        }
        self.batches += 1;
        _ = self.stored.fetchAdd(@intCast(items.len), .monotonic);
    }

    pub fn store(self: *MockStore, _: []const u8, _: []const u8, stanza_id: []const u8, _: u64, _: []const u8) !void {
        if (std.mem.eql(u8, stanza_id, self.poisoned_id)) return error.JobRejected;
        _ = self.stored.fetchAdd(1, .monotonic);
    }
};

test "logEveryPowerOfTwo fires on the first event and powers of two only" {
    var fired: u64 = 0;
    var last: u64 = 0;
    for (1..1025) |n| {
        if (logEveryPowerOfTwo(n)) {
            fired += 1;
            last = n;
        }
    }
    // 1, 2, 4, ..., 1024: eleven hits in the first 1024 events.
    try std.testing.expectEqual(@as(u64, 11), fired);
    try std.testing.expectEqual(@as(u64, 1024), last);
    try std.testing.expect(logEveryPowerOfTwo(1));
    try std.testing.expect(!logEveryPowerOfTwo(0));
    try std.testing.expect(!logEveryPowerOfTwo(3));
}

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

test "ArchiveWriteQueue: a failed batch retries each job alone (S31)" {
    var q = try ArchiveWriteQueue.init();
    defer q.deinit();

    var store = MockStore{ .fail_next = true };
    q.enqueue("a@localhost", "b@localhost", "s1", 1, "<m/>");
    q.enqueue("a@localhost", "b@localhost", "s2", 2, "<m/>");
    q.drainInto(&store, 64);

    // The batch error drops nothing: both jobs land on the retry.
    try std.testing.expectEqual(@as(u64, 0), q.store_failed.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 2), store.stored.load(.monotonic));
}

test "ArchiveWriteQueue: one bad job in a chunk loses only itself" {
    var q = try ArchiveWriteQueue.init();
    defer q.deinit();

    var store = MockStore{ .fail_next = true };
    q.enqueue("a@localhost", "b@localhost", "s1", 1, "<m/>");
    q.enqueue("a@localhost", "b@localhost", "poison", 2, "<m/>");
    q.enqueue("a@localhost", "b@localhost", "s3", 3, "<m/>");
    q.drainInto(&store, 64);

    // The poisoned job fails both in the batch and on its own retry;
    // its two neighbors land.
    try std.testing.expectEqual(@as(u64, 1), q.store_failed.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 2), store.stored.load(.monotonic));
}

test "ArchiveWriteQueue: drainInto writes one storeAll batch per chunk (Q8)" {
    var q = try ArchiveWriteQueue.init();
    defer q.deinit();

    var store = MockStore{};
    for (0..ArchiveWriteQueue.DRAIN_CAP + 1) |_| {
        q.enqueue("a@localhost", "b@localhost", "s", 1, "<m/>");
    }
    q.drainInto(&store, 128);

    try std.testing.expectEqual(@as(u32, 2), store.batches);
    try std.testing.expectEqual(@as(u32, ArchiveWriteQueue.DRAIN_CAP + 1), store.stored.load(.monotonic));
}

test "ArchiveWriteQueue: wake byte only on the empty-to-non-empty transition (Q8)" {
    var q = try ArchiveWriteQueue.init();
    defer q.deinit();

    var buf: [8]u8 = undefined;
    q.enqueue("a@localhost", "b@localhost", "s", 1, "<m/>");
    try std.testing.expectEqual(@as(usize, 1), try posix.read(q.pipe_rd, &buf));

    q.enqueue("a@localhost", "b@localhost", "s", 1, "<m/>");
    try std.testing.expectError(error.WouldBlock, posix.read(q.pipe_rd, &buf));
}

test "ArchiveWriteQueue: a burst larger than one drain all lands (V15)" {
    var q = try ArchiveWriteQueue.init();
    defer q.deinit();

    var store = MockStore{};
    const t = try std.Thread.spawn(.{}, struct {
        fn run(queue: *ArchiveWriteQueue, st: *MockStore) void {
            queue.writerLoop(st, 64);
        }
    }.run, .{ &q, &store });

    for (0..200) |_| {
        q.enqueue("a@localhost", "b@localhost", "s", 1, "<m/>");
    }

    // No stop flag and no spare wake byte: every job must arrive through
    // the queue's own wakeup path inside the deadline.
    const deadline = std.time.milliTimestamp() + 10000;
    while (store.stored.load(.monotonic) < 200 and std.time.milliTimestamp() < deadline) {
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    const stored_before_stop = store.stored.load(.monotonic);
    q.stopping.store(true, .release);
    _ = posix.write(q.pipe_wr, "\x00") catch {};
    t.join();
    try std.testing.expectEqual(@as(u32, 200), stored_before_stop);
}

/// Store mock whose first storeAll call blocks until released. Holding
/// the writer inside a drain leaves the ring empty so the next enqueue
/// is an empty-to-non-empty transition whose byte the writer's own
/// drainPipe consumes: only the non-empty recheck before kevent keeps
/// that job from stranding.
const GatedStore = struct {
    stored: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    entered: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    release: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn storeAll(self: *GatedStore, items: anytype) !void {
        if (self.entered.fetchAdd(1, .monotonic) == 0) {
            while (!self.release.load(.acquire)) {
                std.Thread.sleep(1 * std.time.ns_per_ms);
            }
        }
        _ = self.stored.fetchAdd(@intCast(items.len), .monotonic);
    }

    pub fn store(self: *GatedStore, _: []const u8, _: []const u8, _: []const u8, _: u64, _: []const u8) !void {
        _ = self.stored.fetchAdd(1, .monotonic);
    }
};

test "ArchiveWriteQueue: a job enqueued during a blocked drain is not stranded (V15)" {
    var q = try ArchiveWriteQueue.init();
    defer q.deinit();

    var store = GatedStore{};
    const t = try std.Thread.spawn(.{}, struct {
        fn run(queue: *ArchiveWriteQueue, st: *GatedStore) void {
            queue.writerLoop(st, 64);
        }
    }.run, .{ &q, &store });

    q.enqueue("a@localhost", "b@localhost", "s1", 1, "<m/>");
    // Wait until the writer holds s1 inside storeAll and the ring reads
    // empty, then land s2 in the drain-to-drainPipe window.
    while (store.entered.load(.monotonic) == 0) {
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    q.enqueue("a@localhost", "b@localhost", "s2", 2, "<m/>");
    store.release.store(true, .release);

    // s2 must be stored without any further producer activity.
    const deadline = std.time.milliTimestamp() + 5000;
    while (store.stored.load(.monotonic) < 2 and std.time.milliTimestamp() < deadline) {
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    const stored_before_stop = store.stored.load(.monotonic);
    q.stopping.store(true, .release);
    _ = posix.write(q.pipe_wr, "\x00") catch {};
    t.join();
    try std.testing.expectEqual(@as(u32, 2), stored_before_stop);
}

// S31 regression: jobs pushed through the queue must land in the backend
// and still be there after the backend is closed and reopened.
test "ArchiveWriteQueue: 1:1 and groupchat jobs reach the store and survive a reopen (S31)" {
    try reopenSurvival(@import("rocksdb_backend"));
    try reopenSurvival(@import("lmdb_backend"));
}

fn reopenSurvival(comptime BackendMod: type) !void {
    const archive_store_mod = @import("archive_store");
    const Backend = BackendMod.Backend;
    const Store = archive_store_mod.ArchiveStore(Backend);
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("archive");
    const path = try tmp.dir.realpathAlloc(alloc, "archive");
    defer alloc.free(path);

    var be = try Backend.open(path, .{});
    var store = Store.init(&be, alloc);
    var q = try ArchiveWriteQueue.init();

    const t = try std.Thread.spawn(.{}, struct {
        fn run(queue: *ArchiveWriteQueue, st: *Store) void {
            queue.writerLoop(st, 128);
        }
    }.run, .{ &q, &store });

    q.enqueue("alice@test.dev", "bob@test.dev", "m-1", 1700000000, "<message from='alice@test.dev/r' to='bob@test.dev' type='chat' id='m-1'><body>1:1</body></message>");
    q.enqueue("room@conf.test.dev", "room@conf.test.dev/alice", "g-1", 1700000001, "<message from='room@conf.test.dev/alice' type='groupchat' id='g-1'><body>gc</body></message>");

    // Stopping drains the queue fully before the writer exits.
    q.stopping.store(true, .release);
    _ = posix.write(q.pipe_wr, "\x00") catch {};
    t.join();
    q.deinit();

    const m1 = try store.getMessage("alice@test.dev", 1700000000, "m-1");
    try std.testing.expect(m1 != null);
    try std.testing.expect(std.mem.indexOf(u8, m1.?, "type='chat'") != null);
    alloc.free(m1.?);
    const g1 = try store.getMessage("room@conf.test.dev", 1700000001, "g-1");
    try std.testing.expect(g1 != null);
    try std.testing.expect(std.mem.indexOf(u8, g1.?, "type='groupchat'") != null);
    alloc.free(g1.?);

    be.close();

    var be2 = try Backend.open(path, .{});
    defer be2.close();
    var store2 = Store.init(&be2, alloc);
    const m1b = try store2.getMessage("alice@test.dev", 1700000000, "m-1");
    try std.testing.expect(m1b != null);
    alloc.free(m1b.?);
    const g1b = try store2.getMessage("room@conf.test.dev", 1700000001, "g-1");
    try std.testing.expect(g1b != null);
    alloc.free(g1b.?);
}

// N1 regression on real LMDB: a put that fails inside a write txn must
// end that txn. A leaked txn makes every later write fail with
// MDB_UNKNOWN_ERROR, so the job after the bad one and every job in the
// next drain would be lost until restart.
test "ArchiveWriteQueue: a rejected LMDB put does not break later writes (N1)" {
    const archive_store_mod = @import("archive_store");
    const Backend = @import("lmdb_backend").Backend;
    const Store = archive_store_mod.ArchiveStore(Backend);
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("archive");
    const path = try tmp.dir.realpathAlloc(alloc, "archive");
    defer alloc.free(path);

    var be = try Backend.open(path, .{});
    defer be.close();
    var store = Store.init(&be, alloc);
    var q = try ArchiveWriteQueue.init();
    defer q.deinit();

    // A 600-byte partner JID pushes the by_contact key past LMDB's
    // 511-byte key limit: the second put fails inside the write txn.
    const big_with = [_]u8{'b'} ** 600;
    q.enqueue("a@localhost", "b@localhost", "m-1", 1, "<m1/>");
    q.enqueue("a@localhost", &big_with, "m-2", 2, "<m2/>");
    q.enqueue("a@localhost", "b@localhost", "m-3", 3, "<m3/>");
    q.drainInto(&store, 64);

    // A fourth job in a second drain: only reachable if the rejected
    // put's txn was aborted instead of leaked.
    q.enqueue("a@localhost", "b@localhost", "m-4", 4, "<m4/>");
    q.drainInto(&store, 64);

    try std.testing.expectEqual(@as(u64, 1), q.store_failed.load(.monotonic));
    const landed = [_]struct { id: []const u8, ts: u64 }{
        .{ .id = "m-1", .ts = 1 },
        .{ .id = "m-3", .ts = 3 },
        .{ .id = "m-4", .ts = 4 },
    };
    for (landed) |m| {
        const got = try store.getMessage("a@localhost", m.ts, m.id);
        try std.testing.expect(got != null);
        alloc.free(got.?);
    }
}
