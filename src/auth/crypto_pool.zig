//! # Crypto Pool — offload PBKDF2/Argon2id from the auth event loop (T121)
//!
//! The auth daemon's event loop is single-threaded; PBKDF2 (and eventually
//! Argon2id) blocks every other IPC request while deriving. This pool moves
//! derivation onto a fixed set of worker threads.
//!
//! ## Discipline
//!
//! Workers do crypto ONLY: no sockets, no store access, no loop-thread
//! memory. Job passwords are deep-copied with the C allocator (loop and
//! worker share no allocator state). The workers wait on a condition
//! variable over the bounded job ring; completions are drained by the event
//! loop, which is woken with the classic one-byte pipe write (the pipe's
//! read end is registered in kqueue).

const std = @import("std");
const posix = std.posix;
const sasl = @import("sasl");

const log = std.log.scoped(.crypto_pool);

/// Maximum jobs queued at once. Full = the event loop answers
/// temporary-auth-failure immediately instead of queueing unboundedly.
pub const MAX_JOBS: usize = 256;

/// One derivation task. `password` is pool-owned (freed on completion).
pub const Job = struct {
    id: u64,
    password: []u8,
    salt: [32]u8,
    iteration_count: u32,
    expected_stored_key: [32]u8,
};

/// Result of a derivation: did the derived key match the stored one.
pub const Completion = struct {
    id: u64,
    ok: bool,
};

/// Fixed-size pool. put() is called from the event loop; completions are
/// collected with popCompletion() after the wake pipe fires.
pub const CryptoPool = struct {
    allocator: std.mem.Allocator,

    jobs: std.ArrayListUnmanaged(Job) = .{},
    completions: std.ArrayListUnmanaged(Completion) = .{},

    job_mutex: std.Thread.Mutex = .{},
    job_cond: std.Thread.Condition = .{},
    completion_mutex: std.Thread.Mutex = .{},

    stopping: bool = false,
    running_threads: usize = 0,
    next_job_id: u64 = 1,

    /// Wake pipe: worker writes one byte per completion; the loop reads.
    pipe_rd: posix.fd_t = -1,
    pipe_wr: posix.fd_t = -1,

    threads_buf: [MAX_THREADS]std.Thread = undefined,
    thread_count: usize = 0,

    pub const MAX_THREADS = 8;

    /// Pool owns job.password after a successful put.
    pub fn put(self: *CryptoPool, password: []const u8, salt: [32]u8, iteration_count: u32, expected_stored_key: [32]u8) !u64 {
        const copy = std.heap.c_allocator.dupe(u8, password) catch return error.OutOfMemory;
        errdefer std.heap.c_allocator.free(copy);

        self.job_mutex.lock();
        defer self.job_mutex.unlock();
        if (self.jobs.items.len >= MAX_JOBS) return error.QueueFull;
        const id = self.next_job_id;
        self.next_job_id +%= 1;
        try self.jobs.append(self.allocator, .{
            .id = id,
            .password = copy,
            .salt = salt,
            .iteration_count = iteration_count,
            .expected_stored_key = expected_stored_key,
        });
        self.job_cond.signal();
        return id;
    }

    /// Drain the wake pipe (EVFILT_READ then this).
    pub fn drainPipe(self: *CryptoPool) void {
        var buf: [64]u8 = undefined;
        while (true) {
            const n = posix.read(self.pipe_rd, &buf) catch break;
            if (n <= 0) break;
            if (n < buf.len) break;
        }
    }

    /// Pop a completed derivation, or null when the drain is done.
    pub fn popCompletion(self: *CryptoPool) ?Completion {
        self.completion_mutex.lock();
        defer self.completion_mutex.unlock();
        if (self.completions.items.len == 0) return null;
        return self.completions.orderedRemove(0);
    }

    /// Spawn the worker threads and open the wake pipe (read end
    /// non-blocking for the loop's drain; same pattern as WakePipe).
    pub fn start(self: *CryptoPool, thread_count: usize) !void {
        const fds = try posix.pipe();
        errdefer posix.close(fds[0]);
        errdefer posix.close(fds[1]);
        _ = std.c.fcntl(fds[0], std.c.F.SETFL, @as(c_int, @bitCast(std.c.O{ .NONBLOCK = true })));
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
    /// dropped and freed — shutdown abandons their pending auths (the core
    /// side times out; nothing here outlives the daemon).
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

        for (self.jobs.items) |j| std.heap.c_allocator.free(j.password);
        self.jobs.deinit(self.allocator);
        self.completions.deinit(self.allocator);
    }

    fn workerMain(self: *CryptoPool) void {
        while (true) {
            const job = blk: {
                self.job_mutex.lock();
                defer self.job_mutex.unlock();
                while (self.jobs.items.len == 0 and !self.stopping) {
                    self.job_cond.wait(&self.job_mutex);
                }
                if (self.stopping) break :blk null; // in-flight job finishes; queue dropped by stop()
                break :blk self.jobs.orderedRemove(0);
            } orelse return;

            defer std.heap.c_allocator.free(job.password);
            // Prep failure means the presented password can never match a
            // prepped stored credential: report as a mismatch.
            const test_creds = sasl.StoredCredentials.derive(job.password, job.salt, job.iteration_count) catch {
                self.completion_mutex.lock();
                defer self.completion_mutex.unlock();
                self.completions.append(self.allocator, .{ .id = job.id, .ok = false }) catch {};
                continue;
            };
            // T211 follow-up: constant-time compare for StoredKey (the
            // reference in scram.zig uses the same pattern).
            const ok = std.crypto.timing_safe.eql([32]u8, test_creds.stored_key, job.expected_stored_key);

            {
                self.completion_mutex.lock();
                defer self.completion_mutex.unlock();
                self.completions.append(self.allocator, .{ .id = job.id, .ok = ok }) catch {
                    // Dropping a completion strands the client's auth attempt on
                    // the core side until it times out — loud, not silent.
                    log.err("completion queue append failed for job {d}", .{job.id});
                    continue;
                };
            }
            _ = posix.write(self.pipe_wr, "\x00") catch {};
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

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
    defer {
        for (pool.jobs.items) |j| std.heap.c_allocator.free(j.password);
        pool.jobs.deinit(std.testing.allocator);
        pool.completions.deinit(std.testing.allocator);
    }

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
