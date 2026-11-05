//! # Crypto Pool: offload PBKDF2/Argon2id from the auth event loop (T121)
//!
//! The auth daemon's event loop is single-threaded; PBKDF2 (and eventually
//! Argon2id) blocks every other IPC request while deriving. This pool moves
//! derivation onto a fixed set of worker threads.
//!
//! ## Discipline
//!
//! Workers do crypto ONLY: no sockets, no store access, no loop-thread
//! memory. Jobs and completions live in preallocated bounded rings, so no
//! heap allocation happens per job. Password bytes sit in a fixed inline
//! buffer per job slot and are wiped with `secureZero` on every exit path:
//! after a worker pops the slot, after the derived copy is consumed, and
//! for jobs still queued when the pool stops. put() refuses when MAX_JOBS
//! jobs are outstanding (accepted but their completion not yet popped),
//! which is what keeps both rings within capacity. The workers wait on a
//! condition variable over the job ring; completions are drained by the
//! event loop. The worker-to-loop wake is a one-byte pipe write that
//! fires only on the `wake_pending` false->true transition (the loop
//! clears the flag in `drainPipe` before popping completions), so a burst
//! of completions costs one byte per drain cycle and none is ever lost.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sasl = @import("sasl");

const log = std.log.scoped(.crypto_pool);

/// Maximum jobs outstanding at once: queued, in flight, or completed but
/// not yet popped. Full = the event loop answers temporary-auth-failure
/// immediately instead of queueing unboundedly. The completion ring has
/// the same capacity, so every accepted job is guaranteed a completion
/// slot (the reservation is structural).
pub const MAX_JOBS: usize = 256;

/// Maximum password bytes a job slot can hold. Over-bound passwords are
/// still accepted: the job completes with ok = false and no derive, so the
/// caller answers and charges the attempt exactly like a wrong password.
/// Refusing them instead would let a client probe account existence (the
/// handler only reaches put() for known users). Must equal the derive prep
/// bound in lib/sasl/scram.zig (prep_buf.len / 2): a password that fits a
/// slot is always derivable.
pub const PASSWORD_LEN_MAX: usize = 1024;

comptime {
    std.debug.assert(PASSWORD_LEN_MAX == 1024);
}

/// One derivation task. `password` is a fixed inline buffer holding
/// `password_len` bytes; it is `secureZero`'d when the job leaves the
/// pool, so no plaintext survives in pool memory.
pub const Job = struct {
    id: u64,
    password_len: u16,
    /// True when the submitted password exceeded PASSWORD_LEN_MAX: nothing
    /// was copied into `password` and the worker completes ok = false
    /// without deriving.
    over_bound: bool,
    salt: [32]u8,
    iteration_count: u32,
    expected_stored_key: [32]u8,
    password: [PASSWORD_LEN_MAX]u8,
};

/// Result of a derivation: did the derived key match the stored one.
pub const Completion = struct {
    id: u64,
    ok: bool,
};

/// Fixed-size pool. put() is called from the event loop; completions are
/// collected with popCompletion() after the wake pipe fires.
pub const CryptoPool = struct {
    /// Allocates the job and completion rings once, on first use. The
    /// job path itself never allocates; the rings are what let the pool
    /// stay small enough to live in a frame local.
    allocator: std.mem.Allocator,

    /// Bounded FIFO of queued jobs, allocated once by ensureRingsLocked.
    /// `job_head` is the next slot a worker pops, `job_tail` the next a
    /// producer fills; the count is `job_tail - job_head` and both move
    /// only under `job_mutex`.
    job_slots: []Job = &.{},
    job_head: usize = 0,
    job_tail: usize = 0,

    /// Bounded FIFO of published completions, same capacity as the job
    /// ring: at most `MAX_JOBS` jobs are outstanding, so a worker can
    /// always publish without allocating. `completion_head` is the next
    /// pop, `completion_tail` the next publish, under `completion_mutex`.
    completions: []Completion = &.{},
    completion_head: usize = 0,
    completion_tail: usize = 0,

    /// Accepted jobs whose completion has not been popped yet, under
    /// `completion_mutex`. This counter is both the bound on put() and
    /// the proof that every accepted job owns a completion slot.
    reserved_completions: usize = 0,

    job_mutex: std.Thread.Mutex = .{},
    job_cond: std.Thread.Condition = .{},
    completion_mutex: std.Thread.Mutex = .{},

    /// Wake coalescing flag (Q2): true while a wake byte may still be
    /// pending delivery. Workers write the pipe byte only on the
    /// false->true transition; drainPipe clears it before the caller
    /// drains completions.
    wake_pending: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    stopping: bool = false,
    running_threads: usize = 0,
    next_job_id: u64 = 1,

    /// Wake pipe: workers write one byte per drain cycle; the loop reads.
    /// Both ends are non-blocking; a write EAGAIN means the pipe is still
    /// readable, i.e. a wake is already signaled.
    pipe_rd: posix.fd_t = -1,
    pipe_wr: posix.fd_t = -1,

    threads_buf: [MAX_THREADS]std.Thread = undefined,
    thread_count: usize = 0,

    pub const MAX_THREADS = 8;

    /// Copy the password into a job slot and queue it. Outstanding jobs
    /// are capped at MAX_JOBS, which is also the completion ring
    /// capacity, so a worker can always publish its result. A full ring
    /// is an explicit error.QueueFull. An over-bound password is queued
    /// with password_len = 0 and nothing copied; the worker finishes it
    /// ok = false without deriving.
    pub fn put(self: *CryptoPool, password: []const u8, salt: [32]u8, iteration_count: u32, expected_stored_key: [32]u8) !u64 {
        self.job_mutex.lock();
        defer self.job_mutex.unlock();
        try self.ensureRingsLocked();
        {
            self.completion_mutex.lock();
            defer self.completion_mutex.unlock();
            if (self.reserved_completions >= MAX_JOBS) return error.QueueFull;
            self.reserved_completions += 1;
        }

        std.debug.assert(self.job_tail - self.job_head < MAX_JOBS);
        const id = self.next_job_id;
        self.next_job_id +%= 1;
        const slot = &self.job_slots[self.job_tail % MAX_JOBS];
        const over = password.len > PASSWORD_LEN_MAX;
        slot.* = .{
            .id = id,
            .password_len = if (over) 0 else @intCast(password.len),
            .over_bound = over,
            .salt = salt,
            .iteration_count = iteration_count,
            .expected_stored_key = expected_stored_key,
            .password = undefined,
        };
        if (!over) @memcpy(slot.password[0..password.len], password);
        self.job_tail += 1;
        self.job_cond.signal();
        return id;
    }

    /// Drain the wake pipe (EVFILT_READ then this). Clears the wake flag
    /// after the byte drain and before the caller's completion drain: a
    /// worker publishing after the clear sees the false->true edge and
    /// writes a byte for the next wait, so no completion is missed.
    pub fn drainPipe(self: *CryptoPool) void {
        var buf: [64]u8 = undefined;
        while (true) {
            const n = posix.read(self.pipe_rd, &buf) catch break;
            if (n <= 0) break;
            if (n < buf.len) break;
        }
        self.wake_pending.store(false, .seq_cst);
    }

    /// Pop a completed derivation, or null when the drain is done. Popping
    /// releases the job's outstanding slot.
    pub fn popCompletion(self: *CryptoPool) ?Completion {
        self.completion_mutex.lock();
        defer self.completion_mutex.unlock();
        if (self.completion_head == self.completion_tail) return null;
        defer {
            self.completion_head += 1;
            self.reserved_completions -= 1;
        }
        return self.completions[self.completion_head % MAX_JOBS];
    }

    /// Allocate the job and completion rings once. put() and start()
    /// call this under job_mutex, which serializes the first use.
    fn ensureRingsLocked(self: *CryptoPool) !void {
        if (self.job_slots.len != 0) return;
        const jobs = try self.allocator.alloc(Job, MAX_JOBS);
        errdefer self.allocator.free(jobs);
        const completions = try self.allocator.alloc(Completion, MAX_JOBS);
        self.job_slots = jobs;
        self.completions = completions;
    }

    /// Wipe and drop every queued-but-unstarted job: the slots hold
    /// plaintext until zeroed. Called by stop() after the workers join.
    fn dropQueued(self: *CryptoPool) void {
        self.job_mutex.lock();
        defer self.job_mutex.unlock();
        while (self.job_head < self.job_tail) {
            std.crypto.secureZero(u8, &self.job_slots[self.job_head % MAX_JOBS].password);
            self.job_head += 1;
        }
    }

    /// Spawn the worker threads and open the wake pipe (both ends
    /// non-blocking: the loop drains the read end, workers write the
    /// write end and treat EAGAIN as already-signaled).
    pub fn start(self: *CryptoPool, thread_count: usize) !void {
        const fds = try posix.pipe();
        errdefer posix.close(fds[0]);
        errdefer posix.close(fds[1]);
        const nonblock: usize = @intCast(@as(c_int, @bitCast(std.c.O{ .NONBLOCK = true })));
        _ = try posix.fcntl(fds[0], std.c.F.SETFL, nonblock);
        _ = try posix.fcntl(fds[1], std.c.F.SETFL, nonblock);
        self.pipe_rd = fds[0];
        self.pipe_wr = fds[1];
        errdefer {
            self.pipe_rd = -1;
            self.pipe_wr = -1;
        }

        {
            self.job_mutex.lock();
            defer self.job_mutex.unlock();
            try self.ensureRingsLocked();
        }
        errdefer self.freeRings();

        const n = @min(thread_count, MAX_THREADS);
        for (0..n) |i| {
            self.threads_buf[i] = self.spawnWorker() catch |err| {
                // Pool with zero threads is useless; errdefer closes the pipe.
                if (i == 0) return err;
                break;
            };
            self.thread_count += 1;
        }
    }

    /// Spawn one worker. The is_test branch lets a test fail the first
    /// spawn to pin the errdefer cleanup in start().
    fn spawnWorker(self: *CryptoPool) std.Thread.SpawnError!std.Thread {
        if (builtin.is_test and test_spawn_fail) return error.SystemResources;
        return std.Thread.spawn(.{}, workerMain, .{self});
    }

    /// Free the job and completion rings. Safe when they were never
    /// allocated (a never-started pool, or a start that failed before
    /// its errdefer ran).
    fn freeRings(self: *CryptoPool) void {
        if (self.job_slots.len != 0) self.allocator.free(self.job_slots);
        if (self.completions.len != 0) self.allocator.free(self.completions);
        self.job_slots = &.{};
        self.completions = &.{};
    }

    /// Stop workers and close the pipe. Queued-but-unstarted jobs are
    /// dropped: their passwords are wiped and shutdown abandons their
    /// pending auths (the core side times out; nothing here outlives the
    /// daemon).
    pub fn stop(self: *CryptoPool) void {
        {
            self.job_mutex.lock();
            defer self.job_mutex.unlock();
            self.stopping = true;
            self.job_cond.broadcast();
        }
        for (self.threads_buf[0..self.thread_count]) |t| t.join();
        self.thread_count = 0;

        if (self.pipe_rd >= 0) posix.close(self.pipe_rd);
        if (self.pipe_wr >= 0) posix.close(self.pipe_wr);
        self.pipe_rd = -1;
        self.pipe_wr = -1;

        // Wipe the queued jobs that never ran: their slots hold
        // plaintext until zeroed, and their outstanding reservations
        // die with the pool.
        self.dropQueued();

        // In-flight completions published before the join are dropped
        // with the pool: drain the ring so a pop after stop() returns
        // null instead of underflowing the reservation counter.
        self.completion_mutex.lock();
        self.completion_head = self.completion_tail;
        self.reserved_completions = 0;
        self.completion_mutex.unlock();

        self.freeRings();
    }

    /// Publish one completion and wake the loop. put() bounds outstanding
    /// jobs by the ring capacity, so the publish cannot fail. The wake
    /// byte goes out only on the wake_pending false->true edge; the flag
    /// is the source of truth and the byte a hint.
    fn finish(self: *CryptoPool, id: u64, ok: bool) void {
        {
            self.completion_mutex.lock();
            defer self.completion_mutex.unlock();
            std.debug.assert(self.completion_tail - self.completion_head < MAX_JOBS);
            self.completions[self.completion_tail % MAX_JOBS] = .{ .id = id, .ok = ok };
            self.completion_tail += 1;
        }

        if (!self.wake_pending.swap(true, .seq_cst)) {
            _ = posix.write(self.pipe_wr, "\x00") catch |err| switch (err) {
                error.WouldBlock => {},
                else => {
                    // Delivery failed: clear the flag so a later
                    // completion retries the wake instead of every
                    // publish being coalesced away forever.
                    self.wake_pending.store(false, .seq_cst);
                    log.err("completion wake write failed for job {d}: {s}", .{ id, @errorName(err) });
                },
            };
        }
    }

    fn workerMain(self: *CryptoPool) void {
        while (true) {
            // Field-wise copy into a single local: a whole-struct copy
            // would leave a second plaintext image in the frame that the
            // job.password wipe below cannot reach.
            var job: Job = undefined;
            {
                self.job_mutex.lock();
                defer self.job_mutex.unlock();
                while (self.job_tail == self.job_head and !self.stopping) {
                    self.job_cond.wait(&self.job_mutex);
                }
                if (self.stopping) return; // in-flight job finishes; queue dropped by stop()
                const slot = &self.job_slots[self.job_head % MAX_JOBS];
                job.id = slot.id;
                job.password_len = slot.password_len;
                job.over_bound = slot.over_bound;
                job.salt = slot.salt;
                job.iteration_count = slot.iteration_count;
                job.expected_stored_key = slot.expected_stored_key;
                @memcpy(job.password[0..slot.password_len], slot.password[0..slot.password_len]);
                std.crypto.secureZero(u8, &slot.password);
                self.job_head += 1;
            }
            if (builtin.is_test) test_worker_job_addr.store(@intFromPtr(&job), .release);

            // The residue check is registered before the wipe so it runs
            // second (defers run LIFO): it samples job.password after the
            // secureZero, on every exit path, before the next iteration
            // reuses the frame.
            defer if (builtin.is_test) {
                test_worker_pw_zeroed.store(std.mem.allEqual(u8, job.password[0..], 0), .release);
            };
            defer std.crypto.secureZero(u8, &job.password);
            // An over-bound job holds no password bytes; it fails like a
            // wrong password without paying for a derive.
            if (job.over_bound) {
                self.finish(job.id, false);
                continue;
            }
            // Prep failure means the presented password can never match a
            // prepped stored credential: report as a mismatch.
            const test_creds = sasl.StoredCredentials.derive(job.password[0..job.password_len], job.salt, job.iteration_count) catch {
                self.finish(job.id, false);
                continue;
            };
            // T211 follow-up: constant-time compare for StoredKey (the
            // reference in scram.zig uses the same pattern).
            const ok = std.crypto.timing_safe.eql([32]u8, test_creds.stored_key, job.expected_stored_key);
            self.finish(job.id, ok);
        }
    }
};

/// Test-only residue anchors, written by workerMain under builtin.is_test:
/// the job copy's address, and whether the password buffer read back all
/// zeros after the wipe defer ran. Never written in non-test builds.
var test_worker_job_addr: std.atomic.Value(usize) = std.atomic.Value(usize).init(0);
var test_worker_pw_zeroed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

/// Test-only: fail the first spawn in start() to pin its error cleanup.
var test_spawn_fail: bool = false;

// ============================================================================
// Tests
// ============================================================================

fn completionCount(pool: *CryptoPool) usize {
    pool.completion_mutex.lock();
    defer pool.completion_mutex.unlock();
    return pool.completion_tail - pool.completion_head;
}

fn reservedCount(pool: *CryptoPool) usize {
    pool.completion_mutex.lock();
    defer pool.completion_mutex.unlock();
    return pool.reserved_completions;
}

/// Keep the password out of a literal first argument; the D7 source ratchet
/// cannot distinguish this pool's put from a backend put at the call site.
fn putTestJob(pool: *CryptoPool, password: []const u8, salt: [32]u8, iteration_count: u32, expected_stored_key: [32]u8) !u64 {
    return pool.put(password, salt, iteration_count, expected_stored_key);
}

test "CryptoPool: more than eight completions wait without a drain" {
    var pool = CryptoPool{ .allocator = std.testing.allocator };
    try pool.start(4);
    defer pool.stop();

    const creds = try sasl.StoredCredentials.derive("burst", @splat(3), 4096);
    var ids: [16]u64 = undefined;
    for (&ids) |*id| id.* = try putTestJob(&pool, "burst", @splat(3), 4096, creds.stored_key);

    const deadline = std.time.milliTimestamp() + 5000;
    while (completionCount(&pool) < ids.len and std.time.milliTimestamp() < deadline) {
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    try std.testing.expectEqual(@as(usize, 16), completionCount(&pool));

    var seen = [_]bool{false} ** 16;
    for (0..ids.len) |_| {
        const c = pool.popCompletion() orelse return error.NoCompletion;
        var found = false;
        for (ids, 0..) |id, i| {
            if (id == c.id) {
                seen[i] = true;
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }
    for (seen) |s| try std.testing.expect(s);
}

test "CryptoPool: the wake follows a visible completion" {
    var pool = CryptoPool{ .allocator = std.testing.allocator };
    try pool.start(1);
    defer pool.stop();

    const creds = try sasl.StoredCredentials.derive("visible", @splat(4), 1);
    const id = try putTestJob(&pool, "visible", @splat(4), 1, creds.stored_key);

    // Hold the completion lock and poll for a wake. A worker that writes
    // the wake before publishing leaves the ring empty at that moment.
    pool.completion_mutex.lock();
    var saw_wake = false;
    var bad = false;
    var buf: [1]u8 = undefined;
    const until = std.time.milliTimestamp() + 200;
    while (std.time.milliTimestamp() < until) {
        const n = std.posix.read(pool.pipe_rd, &buf) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => {
                pool.completion_mutex.unlock();
                return err;
            },
        };
        if (n > 0) {
            saw_wake = true;
            bad = pool.completion_tail == pool.completion_head;
            break;
        }
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    pool.completion_mutex.unlock();
    try std.testing.expect(!bad);

    if (!saw_wake) {
        const deadline = std.time.milliTimestamp() + 3000;
        while (std.time.milliTimestamp() < deadline) {
            const n = std.posix.read(pool.pipe_rd, &buf) catch |err| switch (err) {
                error.WouldBlock => 0,
                else => return err,
            };
            if (n > 0) {
                saw_wake = true;
                break;
            }
            std.Thread.sleep(1 * std.time.ns_per_ms);
        }
    }
    try std.testing.expect(saw_wake);

    const c = pool.popCompletion() orelse return error.NoCompletion;
    try std.testing.expectEqual(id, c.id);
}

test "CryptoPool: derive matches inline computation" {
    var pool = CryptoPool{ .allocator = std.testing.allocator };
    try pool.start(2);
    defer pool.stop();

    const creds = try sasl.StoredCredentials.derive("hunter2", @splat(1), 4096);

    const id1 = try pool.put("hunter2", @splat(1), 4096, creds.stored_key);
    const id2 = try pool.put("wrong", @splat(1), 4096, creds.stored_key);

    var got: [2]Completion = undefined;
    var n: usize = 0;
    const deadline = std.time.milliTimestamp() + 5000;
    while (n < 2 and std.time.milliTimestamp() < deadline) {
        if (pool.popCompletion()) |c| {
            got[n] = c;
            n += 1;
        } else {
            std.Thread.sleep(1 * std.time.ns_per_ms);
        }
    }
    try std.testing.expectEqual(@as(usize, 2), n);
    for (got[0..n]) |c| {
        if (c.id == id1) {
            try std.testing.expect(c.ok);
        } else if (c.id == id2) {
            try std.testing.expect(!c.ok);
        } else {
            return error.UnexpectedJobId;
        }
    }
}

test "CryptoPool: queue is bounded" {
    var pool = CryptoPool{ .allocator = std.testing.allocator };
    // No start(): nothing drains, so the cap is hit deterministically.
    defer pool.stop();

    const creds = try sasl.StoredCredentials.derive("x", @splat(2), 4096);
    var accepted: usize = 0;
    for (0..MAX_JOBS + 8) |_| {
        _ = pool.put("x", @splat(2), 4096, creds.stored_key) catch |err| switch (err) {
            error.QueueFull => break,
            else => return err,
        };
        accepted += 1;
    }
    try std.testing.expectEqual(MAX_JOBS, accepted);
}

test "CryptoPool: a full queue releases the failed reservation" {
    var pool = CryptoPool{ .allocator = std.testing.allocator };
    // No start(): nothing drains, so the cap is hit deterministically.
    defer pool.stop();

    const creds = try sasl.StoredCredentials.derive("x", @splat(2), 4096);
    for (0..MAX_JOBS) |_| {
        _ = try putTestJob(&pool, "x", @splat(2), 4096, creds.stored_key);
    }
    try std.testing.expectEqual(@as(usize, MAX_JOBS), reservedCount(&pool));

    // The rejected put checked the bound before reserving and must leave
    // the counter untouched, or every refusal leaks one reservation.
    err: {
        _ = putTestJob(&pool, "x", @splat(2), 4096, creds.stored_key) catch |e| switch (e) {
            error.QueueFull => break :err,
            else => return e,
        };
        return error.ExpectedQueueFull;
    }
    try std.testing.expectEqual(@as(usize, MAX_JOBS), reservedCount(&pool));
}

test "CryptoPool: completed but unpopped jobs still count against the bound" {
    // The bound is on outstanding jobs, not queued ones: a full ring of
    // completions waiting for popCompletion() must still reject put(),
    // or the completion publish would overrun the ring.
    var pool = CryptoPool{ .allocator = std.testing.allocator };
    try pool.start(2);
    defer pool.stop();

    const creds = try sasl.StoredCredentials.derive("x", @splat(2), 1);
    for (0..MAX_JOBS) |_| {
        _ = try putTestJob(&pool, "x", @splat(2), 1, creds.stored_key);
    }
    const deadline = std.time.milliTimestamp() + 10000;
    while (completionCount(&pool) < MAX_JOBS and std.time.milliTimestamp() < deadline) {
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    try std.testing.expectEqual(MAX_JOBS, completionCount(&pool));
    try std.testing.expectError(error.QueueFull, putTestJob(&pool, "x", @splat(2), 1, creds.stored_key));
    _ = pool.popCompletion() orelse return error.NoCompletion;
    _ = try putTestJob(&pool, "x", @splat(2), 1, creds.stored_key);
}

test "CryptoPool: finished jobs release their reservation" {
    var pool = CryptoPool{ .allocator = std.testing.allocator };
    try pool.start(4);
    defer pool.stop();

    const creds = try sasl.StoredCredentials.derive("burst", @splat(3), 4096);
    const n: usize = 8;
    for (0..n) |_| {
        _ = try putTestJob(&pool, "burst", @splat(3), 4096, creds.stored_key);
    }

    // Every accepted job publishes exactly one completion; popping it
    // releases the outstanding slot, so the counter must be back to zero
    // once the burst drains.
    const deadline = std.time.milliTimestamp() + 5000;
    while (completionCount(&pool) < n and std.time.milliTimestamp() < deadline) {
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    for (0..n) |_| {
        _ = pool.popCompletion() orelse return error.NoCompletion;
    }
    try std.testing.expectEqual(@as(usize, 0), reservedCount(&pool));
}

test "CryptoPool: stop releases the dropped jobs' reservations" {
    var pool = CryptoPool{ .allocator = std.testing.allocator };
    // No start(): the queued jobs are dropped by stop() without completing.
    const creds = try sasl.StoredCredentials.derive("x", @splat(2), 4096);
    _ = try putTestJob(&pool, "x", @splat(2), 4096, creds.stored_key);
    _ = try putTestJob(&pool, "x", @splat(2), 4096, creds.stored_key);
    try std.testing.expectEqual(@as(usize, 2), reservedCount(&pool));

    pool.stop();
    try std.testing.expectEqual(@as(usize, 0), reservedCount(&pool));
}

test "CryptoPool: the pool struct stays off the hot path's stack" {
    // main.zig keeps the pool in a frame local; the rings are the only
    // bulk and they are allocated on the heap once, on first use.
    try std.testing.expect(@sizeOf(CryptoPool) < 4096);
}

test "CryptoPool: the job path allocates once, then never per job" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var pool = CryptoPool{ .allocator = failing.allocator() };
    try pool.start(1);
    defer pool.stop();

    // Rings exist after start(); fail the allocator on any further
    // request so a put-time allocation breaks the test.
    failing.fail_index = failing.alloc_index;

    const creds = try sasl.StoredCredentials.derive("pw", @splat(5), 1);
    const n: usize = 8;
    for (0..n) |_| {
        _ = try putTestJob(&pool, "pw", @splat(5), 1, creds.stored_key);
    }
    for (0..n) |_| {
        _ = try awaitCompletion(&pool);
    }
}

test "CryptoPool: a failed first spawn frees the rings" {
    // main.zig never calls stop() when start() fails, so the error path
    // must release the rings itself. The DebugAllocator reports any
    // surviving ring as a leak at deinit.
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    test_spawn_fail = true;
    defer test_spawn_fail = false;

    var pool = CryptoPool{ .allocator = gpa.allocator() };
    defer pool.stop(); // safe after a failed start: no threads, fds reset
    try std.testing.expectError(error.SystemResources, pool.start(1));
    try std.testing.expect(gpa.deinit() == .ok);
}

test "CryptoPool: a completion left over stop() cannot be popped" {
    // stop() drains the completion ring along with the reservation
    // count, so a straggler pop returns null instead of underflowing
    // reserved_completions.
    var pool = CryptoPool{ .allocator = std.testing.allocator };
    try pool.start(1);
    defer pool.stop();

    const creds = try sasl.StoredCredentials.derive("x", @splat(2), 1);
    _ = try putTestJob(&pool, "x", @splat(2), 1, creds.stored_key);

    const deadline = std.time.milliTimestamp() + 5000;
    while (completionCount(&pool) == 0 and std.time.milliTimestamp() < deadline) {
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    try std.testing.expectEqual(@as(usize, 1), completionCount(&pool));

    pool.stop();
    try std.testing.expect(pool.popCompletion() == null);
    try std.testing.expectEqual(@as(usize, 0), reservedCount(&pool));
}

/// Poll popCompletion until a result arrives or the deadline passes.
fn awaitCompletion(pool: *CryptoPool) !Completion {
    const deadline = std.time.milliTimestamp() + 5000;
    while (std.time.milliTimestamp() < deadline) {
        if (pool.popCompletion()) |c| return c;
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    return error.NoCompletion;
}

test "CryptoPool: an over-bound password completes as a failed auth" {
    var pool = CryptoPool{ .allocator = std.testing.allocator };
    try pool.start(1);
    defer pool.stop();

    var too_long: [PASSWORD_LEN_MAX + 64]u8 = @splat('x');
    std.crypto.random.bytes(too_long[PASSWORD_LEN_MAX..]);
    const creds = try sasl.StoredCredentials.derive("x", @splat(2), 1);

    // Accepted like any other job: it counts as outstanding, and its
    // completion is the same ok=false a wrong password gets.
    const id = try pool.put(&too_long, @splat(2), 1, creds.stored_key);
    try std.testing.expectEqual(@as(usize, 1), reservedCount(&pool));

    const c = try awaitCompletion(&pool);
    try std.testing.expectEqual(id, c.id);
    try std.testing.expect(!c.ok);
}

test "CryptoPool: an over-bound password is not truncated to a match" {
    // The first PASSWORD_LEN_MAX bytes are a real credential. If the pool
    // truncated instead of flagging the job over-bound, the derive would
    // return ok=true.
    var pool = CryptoPool{ .allocator = std.testing.allocator };
    try pool.start(1);
    defer pool.stop();

    var pw: [PASSWORD_LEN_MAX + 1]u8 = @splat('k');
    const creds = try sasl.StoredCredentials.derive(pw[0..PASSWORD_LEN_MAX], @splat(7), 1);
    const over_id = try pool.put(&pw, @splat(7), 1, creds.stored_key);
    const ok_id = try pool.put(pw[0..PASSWORD_LEN_MAX], @splat(7), 1, creds.stored_key);

    var saw_over = false;
    var saw_ok = false;
    while (!saw_over or !saw_ok) {
        const c = try awaitCompletion(&pool);
        if (c.id == over_id) {
            try std.testing.expect(!c.ok);
            saw_over = true;
        } else if (c.id == ok_id) {
            try std.testing.expect(c.ok);
            saw_ok = true;
        } else {
            return error.UnexpectedJobId;
        }
    }
}

test "CryptoPool: completed and dropped jobs leave no password bytes" {
    // A worker wipes the slot's inline password when it pops the job.
    // Scan the ring for the submitted marker after the job completes.
    var pool = CryptoPool{ .allocator = std.testing.allocator };
    try pool.start(1);
    defer pool.stop();

    const creds = try sasl.StoredCredentials.derive("wipe-marker-a1", @splat(6), 1);
    _ = try putTestJob(&pool, "wipe-marker-a1", @splat(6), 1, creds.stored_key);

    const deadline = std.time.milliTimestamp() + 3000;
    while (std.time.milliTimestamp() < deadline) {
        if (pool.popCompletion()) |_| break;
        std.Thread.sleep(1 * std.time.ns_per_ms);
    } else {
        return error.NoCompletion;
    }
    for (pool.job_slots) |*slot| {
        try std.testing.expect(std.mem.indexOf(u8, slot.password[0..], "wipe-marker-a1") == null);
    }
}

test "CryptoPool: stop wipes queued slots before freeing them" {
    // Scan job_slots while they are still mapped: Allocator.free poisons
    // the ring in safe modes, so a scan after stop() cannot tell the
    // wipe from the poison. dropQueued() is what stop() calls.
    var pool = CryptoPool{ .allocator = std.testing.allocator };
    defer pool.stop();
    _ = try putTestJob(&pool, "wipe-marker-q3", @splat(7), 1, @splat(8));
    pool.dropQueued();
    for (pool.job_slots) |*slot| {
        try std.testing.expect(std.mem.indexOf(u8, slot.password[0..], "wipe-marker-q3") == null);
    }
}

/// Count occurrences of `needle` inside the mapped region containing
/// `anchor`. procstat -v reports the grown extents, so the scan never
/// reads outside a live mapping (the worker's stack extent is only a
/// few KiB above its frames; a fixed window could run off the top).
fn scanRegionContaining(anchor: usize, needle: []const u8) !usize {
    var pidbuf: [16]u8 = undefined;
    const pids = try std.fmt.bufPrint(&pidbuf, "{d}", .{std.c.getpid()});
    const res = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &.{ "procstat", "-v", pids },
        .max_output_bytes = 1 << 22,
    });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    var lines = std.mem.splitScalar(u8, res.stdout, '\n');
    _ = lines.next();
    while (lines.next()) |line| {
        var it = std.mem.tokenizeAny(u8, line, " \t");
        var cols: [3][]const u8 = undefined;
        var n: usize = 0;
        while (it.next()) |c| : (n += 1) {
            if (n < cols.len) cols[n] = c;
        }
        if (n < 3) continue;
        const start = std.fmt.parseInt(usize, cols[1], 0) catch continue;
        const end = std.fmt.parseInt(usize, cols[2], 0) catch continue;
        if (anchor < start or anchor >= end) continue;
        const region = @as([*]const u8, @ptrFromInt(start))[0 .. end - start];
        var hits: usize = 0;
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, region, pos, needle)) |i| : (pos = i + 1) {
            hits += 1;
        }
        return hits;
    }
    return error.AnchorNotMapped;
}

test "CryptoPool: no plaintext left on the worker stack" {
    var pool = CryptoPool{ .allocator = std.testing.allocator };
    try pool.start(1);
    defer pool.stop();

    // Random marker: the submitted buffer itself lives on this thread's
    // stack, outside the scanned region.
    var marker: [96]u8 = undefined;
    std.crypto.random.bytes(&marker);
    const creds = try sasl.StoredCredentials.derive("wipe", @splat(6), 1);
    _ = try putTestJob(&pool, &marker, @splat(6), 1, creds.stored_key);
    _ = try awaitCompletion(&pool);

    const job_addr = test_worker_job_addr.load(.acquire);
    try std.testing.expect(job_addr != 0);
    std.Thread.sleep(20 * std.time.ns_per_ms);

    // The worker samples its own copy at scope exit, before the next
    // iteration re-poisons the frame: a missed wipe leaves the marker
    // readable then.
    try std.testing.expect(test_worker_pw_zeroed.load(.acquire));

    // Any second plaintext image the pickup left elsewhere in the frame
    // outlives the job copy: scan the whole mapped stack region for it.
    try std.testing.expectEqual(@as(usize, 0), try scanRegionContaining(job_addr, &marker));
}

test "CryptoPool: one wake byte per drain cycle" {
    // The consumer never drains during this test, so wake_pending stays
    // set after the first completion: a burst of 16 completions must
    // leave exactly one byte in the pipe.
    var pool = CryptoPool{ .allocator = std.testing.allocator };
    try pool.start(4);
    defer pool.stop();

    const creds = try sasl.StoredCredentials.derive("burst", @splat(3), 1);
    const n: usize = 16;
    for (0..n) |_| {
        _ = try putTestJob(&pool, "burst", @splat(3), 1, creds.stored_key);
    }

    const deadline = std.time.milliTimestamp() + 5000;
    while (completionCount(&pool) < n and std.time.milliTimestamp() < deadline) {
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    try std.testing.expectEqual(n, completionCount(&pool));

    var buf: [64]u8 = undefined;
    var total: usize = 0;
    while (std.time.milliTimestamp() < deadline) {
        const got = std.posix.read(pool.pipe_rd, &buf) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => return err,
        };
        total += got;
        if (total > 0) break;
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    try std.testing.expectEqual(@as(usize, 1), total);
}

test "CryptoPool: no completion is lost under a kqueue-driven drain" {
    // Producers fire random bursts per round and idle between rounds,
    // like real login traffic; the consumer waits on the wake pipe in
    // kqueue, drains the byte, then pops to empty. A completion that
    // misses its wake edge is left stranded in the ring past the kevent
    // timeout, so lost wakeups show up as a count, not a hang.
    const rounds = 400;
    const producers = 4;
    const per_max = 16;
    var pool = CryptoPool{ .allocator = std.testing.allocator };
    try pool.start(CryptoPool.MAX_THREADS);
    defer pool.stop();

    const kq = try std.posix.kqueue();
    defer std.posix.close(kq);
    var ch = [1]std.posix.Kevent{.{
        .ident = @intCast(pool.pipe_rd),
        .filter = std.c.EVFILT.READ,
        .flags = std.c.EV.ADD | std.c.EV.ENABLE,
        .fflags = 0,
        .data = 0,
        .udata = 0,
    }};
    _ = try std.posix.kevent(kq, &ch, &.{}, null);

    const creds = try sasl.StoredCredentials.derive("s", @splat(9), 1);

    const Shared = struct {
        round: std.atomic.Value(usize) = .init(0),
        quit: std.atomic.Value(bool) = .init(false),
        sizes: [producers]usize = undefined,
    };
    var sh = Shared{};
    const Prod = struct {
        fn run(p: *CryptoPool, s: *Shared, idx: usize, stored: [32]u8) void {
            var seen: usize = 0;
            while (true) {
                var r = s.round.load(.acquire);
                while (r == seen) {
                    if (s.quit.load(.acquire)) return;
                    std.Thread.yield() catch {};
                    r = s.round.load(.acquire);
                }
                seen = r;
                for (0..s.sizes[idx]) |_| {
                    _ = putTestJob(p, "s", @splat(9), 1, stored) catch |err|
                        std.debug.panic("put: {s}", .{@errorName(err)});
                }
            }
        }
    };

    var threads: [producers]std.Thread = undefined;
    for (&threads, 0..) |*t, i| {
        t.* = try std.Thread.spawn(.{}, Prod.run, .{ &pool, &sh, i, creds.stored_key });
    }

    var lost: usize = 0;
    var late: usize = 0;
    var received: usize = 0;
    var expected_total: usize = 0;
    var evs: [4]std.posix.Kevent = undefined;
    const ts = std.posix.timespec{ .sec = 0, .nsec = 500 * std.time.ns_per_ms };
    const ts_grace = std.posix.timespec{ .sec = 10, .nsec = 0 };
    for (1..rounds + 1) |r| {
        var expect: usize = 0;
        for (sh.sizes[0..producers]) |*s| {
            s.* = 1 + std.crypto.random.uintLessThan(usize, per_max);
            expect += s.*;
        }
        expected_total += expect;
        sh.round.store(r, .release);
        var got: usize = 0;
        while (got < expect) {
            const n = try std.posix.kevent(kq, &.{}, &evs, &ts);
            if (n == 0 and completionCount(&pool) == 0) continue;
            if (n == 0) {
                // A worker preempted between its wake_pending swap and
                // the write delivers the byte late; only a wake still
                // missing after a long grace counts as lost.
                if (try std.posix.kevent(kq, &.{}, &evs, &ts_grace) == 0) {
                    lost += 1;
                } else {
                    late += 1;
                }
            }
            pool.drainPipe();
            while (pool.popCompletion()) |c| {
                try std.testing.expect(c.ok);
                got += 1;
            }
        }
        received += got;
    }
    sh.quit.store(true, .release);
    for (threads) |t| t.join();

    std.debug.print("kqueue drain: {d} late wakes\n", .{late});
    try std.testing.expectEqual(@as(usize, 0), lost);
    try std.testing.expectEqual(expected_total, received);
    try std.testing.expectEqual(@as(usize, 0), reservedCount(&pool));
}
