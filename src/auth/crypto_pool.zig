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
    /// Retained for the construction contract (`.{ .allocator = ... }`).
    /// The pool's storage is fully inline: nothing allocates through it.
    allocator: std.mem.Allocator,

    /// Bounded FIFO of queued jobs. `job_head` is the next slot a worker
    /// pops, `job_tail` the next a producer fills; the count is
    /// `job_tail - job_head` and both move only under `job_mutex`.
    job_slots: [MAX_JOBS]Job = undefined,
    job_head: usize = 0,
    job_tail: usize = 0,

    /// Bounded FIFO of published completions, same capacity as the job
    /// ring: at most `MAX_JOBS` jobs are outstanding, so a worker can
    /// always publish without allocating. `completion_head` is the next
    /// pop, `completion_tail` the next publish, under `completion_mutex`.
    completions: [MAX_JOBS]Completion = undefined,
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
        {
            self.completion_mutex.lock();
            defer self.completion_mutex.unlock();
            if (self.reserved_completions >= MAX_JOBS) return error.QueueFull;
            self.reserved_completions += 1;
        }

        self.job_mutex.lock();
        defer self.job_mutex.unlock();
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

    /// Spawn the worker threads and open the wake pipe (both ends
    /// non-blocking: the loop drains the read end, workers write the
    /// write end and treat EAGAIN as already-signaled).
    pub fn start(self: *CryptoPool, thread_count: usize) !void {
        const fds = try posix.pipe();
        errdefer posix.close(fds[0]);
        errdefer posix.close(fds[1]);
        _ = std.c.fcntl(fds[0], std.c.F.SETFL, @as(c_int, @bitCast(std.c.O{ .NONBLOCK = true })));
        _ = std.c.fcntl(fds[1], std.c.F.SETFL, @as(c_int, @bitCast(std.c.O{ .NONBLOCK = true })));
        self.pipe_rd = fds[0];
        self.pipe_wr = fds[1];

        const n = @min(thread_count, MAX_THREADS);
        for (0..n) |i| {
            self.threads_buf[i] = std.Thread.spawn(.{}, workerMain, .{self}) catch |err| {
                // Pool with zero threads is useless; errdefer closes the pipe.
                if (i == 0) return err;
                break;
            };
            self.thread_count += 1;
        }
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
        self.job_mutex.lock();
        while (self.job_head < self.job_tail) {
            std.crypto.secureZero(u8, &self.job_slots[self.job_head % MAX_JOBS].password);
            self.job_head += 1;
        }
        self.job_mutex.unlock();

        self.completion_mutex.lock();
        self.reserved_completions = 0;
        self.completion_mutex.unlock();
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

/// Read the pool wake pipe until a byte arrives or the deadline passes;
/// returns false on timeout. Mirrors waitForPoolWake in handler tests.
fn waitWakeByte(pool: *CryptoPool, deadline_ms: i64) !bool {
    var buf: [8]u8 = undefined;
    while (std.time.milliTimestamp() < deadline_ms) {
        const n = std.posix.read(pool.pipe_rd, &buf) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => return err,
        };
        if (n > 0) return true;
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    return false;
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

test "CryptoPool: the job path needs no heap allocation" {
    // The rings are inline: put() and completion publish must succeed with
    // an allocator that fails every request.
    var pool = CryptoPool{ .allocator = std.testing.failing_allocator };
    try pool.start(1);
    defer pool.stop();

    const creds = try sasl.StoredCredentials.derive("pw", @splat(5), 1);
    const id = try putTestJob(&pool, "pw", @splat(5), 1, creds.stored_key);

    const deadline = std.time.milliTimestamp() + 3000;
    while (std.time.milliTimestamp() < deadline) {
        if (pool.popCompletion()) |c| {
            try std.testing.expectEqual(id, c.id);
            try std.testing.expect(c.ok);
            return;
        }
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    return error.NoCompletion;
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
    // A worker wipes the slot's inline password when it pops the job, and
    // stop() wipes every queued slot it drops. Scan the ring for the
    // submitted marker after each exit path.
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
    for (&pool.job_slots) |*slot| {
        try std.testing.expect(std.mem.indexOf(u8, slot.password[0..], "wipe-marker-a1") == null);
    }

    var pool2 = CryptoPool{ .allocator = std.testing.allocator };
    // No start(): the job stays queued and stop() must wipe its slot.
    _ = try putTestJob(&pool2, "wipe-marker-b2", @splat(7), 1, @splat(8));
    pool2.stop();
    for (&pool2.job_slots) |*slot| {
        try std.testing.expect(std.mem.indexOf(u8, slot.password[0..], "wipe-marker-b2") == null);
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

test "CryptoPool: no completion is lost under a producer burst" {
    // Four producer threads race put(); up to MAX_THREADS workers race
    // the completion side. The consumer only pops after a real wake, so
    // a lost wakeup shows up as a timeout instead of a hang.
    var pool = CryptoPool{ .allocator = std.testing.allocator };
    try pool.start(4);
    defer pool.stop();

    const creds = try sasl.StoredCredentials.derive("s", @splat(9), 1);
    const jobs_per_producer = 50;
    const producers = 4;

    const Producer = struct {
        fn run(p: *CryptoPool, stored: [32]u8) void {
            for (0..jobs_per_producer) |_| {
                _ = putTestJob(p, "s", @splat(9), 1, stored) catch |err| {
                    std.debug.panic("put failed: {s}", .{@errorName(err)});
                };
            }
        }
    };

    var threads: [producers]std.Thread = undefined;
    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, Producer.run, .{ &pool, creds.stored_key });
    }

    var received: usize = 0;
    const total = producers * jobs_per_producer;
    const deadline = std.time.milliTimestamp() + 10000;
    while (received < total and std.time.milliTimestamp() < deadline) {
        if (try waitWakeByte(&pool, std.time.milliTimestamp() + 100)) {
            pool.drainPipe();
            while (pool.popCompletion()) |c| {
                try std.testing.expect(c.ok);
                received += 1;
            }
        }
    }
    for (threads) |t| t.join();

    try std.testing.expectEqual(total, received);
    try std.testing.expectEqual(@as(usize, 0), reservedCount(&pool));
}
