//! # xmppc Engine — ONE kqueue loop driving N client sessions
//!
//! Owns the kqueue, the session slot map, the cross-thread wake pipe, and the
//! connect/registration helpers. Session lifecycle and protocol handling
//! live in session.zig; protocol parsing in parser.zig; the stream FSM in
//! stream.zig; I/O in transport.zig.
//!
//! ## Slot map (T-80EFEC29)
//! Sessions live in stable slots behind generational `Handle`s — the public
//! session id and the kqueue `udata`. A freed slot bumps its generation, so
//! a stale event or a stale handle is dropped by a cheap check; removal
//! never moves a live session, never invalidates a `*Session` handed to a
//! callback, and never touches kqueue.
//!
//! ## Thread ownership
//! The kqueue loop owns every Session: callbacks (setEventHandler) run on
//! the engine thread and may touch session state directly (e.g. sendStanza
//! via sessionAt). Foreign threads interact ONLY through the command
//! mailbox — postStanza and stopSession — never through *Session itself.
//!
//! ## Changelist (T-65F61479)
//! kqueue registrations are STAGED into a buffer and applied by the ONE
//! `kevent()` wait per loop iteration (project kqueue rule: never a kevent
//! call without an eventlist). The wake pipe's one-time registration is the
//! single deliberate exception (created lazily on first use).

const std = @import("std");
const ssl = @import("ssl");
const sasl = @import("sasl");
const tls = @import("tls");

const Session = @import("session.zig").Session;
const SessionConfig = @import("session.zig").SessionConfig;
const Event = @import("session.zig").Event;
const Transport = @import("transport.zig").Transport;
const Resolver = @import("resolver.zig").Resolver;
const Resolution = @import("resolver.zig").Resolution;
const DnsStatus = @import("resolver.zig").Status;

const log = std.log.scoped(.xmppc);

const Kevent = std.posix.Kevent;
const posix = std.posix;

fn kev(ident: usize, filter: i16, flags: u16, udata: usize) Kevent {
    return .{ .ident = ident, .filter = filter, .flags = flags, .fflags = 0, .data = 0, .udata = udata };
}

/// A generationally-tagged session slot. Stale handles fail `Engine.get`
/// and late kqueue events fail the same check — the slot was reused.
pub const Handle = packed struct {
    index: u32,
    generation: u32,

    pub fn encode(h: Handle) usize {
        return @intCast(@as(u64, @bitCast(h)));
    }
    pub fn decode(v: usize) Handle {
        return @bitCast(@as(u64, v));
    }
};

/// One kqueue registration change, staged until the waiting kevent() call.
const Change = Kevent;

/// Synchronous hostname resolution (the one blocking call in the client).
fn resolveHost(host: []const u8) !std.c.sockaddr.in {
    var name_buf: [256]u8 = undefined;
    if (host.len >= name_buf.len) return error.NameTooLong;
    @memcpy(name_buf[0..host.len], host);
    name_buf[host.len] = 0;

    var hints: std.c.addrinfo = std.mem.zeroes(std.c.addrinfo);
    hints.family = posix.AF.INET;
    hints.socktype = posix.SOCK.STREAM;

    var result: ?*std.c.addrinfo = null;
    const rc = std.c.getaddrinfo(@ptrCast(&name_buf), null, &hints, &result);
    if (@intFromEnum(rc) != 0 or result == null) return error.ResolutionFailed;
    defer std.c.freeaddrinfo(result.?);

    const addr_in: *const std.c.sockaddr.in = @ptrCast(@alignCast(result.?.addr.?));
    return .{ .port = 0, .addr = addr_in.addr };
}

// ============================================================================
// Engine
// ============================================================================

pub const Engine = struct {
    const WAKE_UDATA: usize = std.math.maxInt(usize);
    const DNS_UDATA: usize = std.math.maxInt(usize) - 1;
    const TICK_UDATA: usize = std.math.maxInt(usize) - 2;

    /// One queued command for a session. `stanza` is application payload
    /// bytes; `stop` carries the failure reason.
    pub const Command = union(enum) {
        stanza: []u8,
        stop: []u8,
    };

    const QueuedCmd = struct { handle: Handle, cmd: Command };

    /// Drop bound for the command mailbox; a flooded consumer gets drops,
    /// not unbounded memory.
    const CMD_QUEUE_MAX = 4096;

    const Slot = struct {
        session: Session,
        generation: u32,
        live: bool,
    };

    const SCRAM_CACHE_MAX = 128;

    /// Driver-facing cumulative counters (T32 load-driver). Written ONLY on
    /// the engine thread; atomic so a consumer thread may statsSnapshot()
    /// mid-run without a lock.
    pub const Stats = struct {
        /// TCP connect()s that completed with SO_ERROR == 0.
        connects_completed: std.atomic.Value(u64) = .init(0),
        /// Sessions that reached .established (bind + SM done, or resumed).
        sessions_established: std.atomic.Value(u64) = .init(0),
        /// Transport bytes read/written (application path; the TLS
        /// handshake's own wire bytes are not included).
        bytes_rx: std.atomic.Value(u64) = .init(0),
        bytes_tx: std.atomic.Value(u64) = .init(0),
        /// Longest single loopOnce processing time in µs — everything the
        /// iteration does (drains + event dispatch) excluding the kevent
        /// wait itself. The event-loop stall metric.
        max_iter_us: std.atomic.Value(u64) = .init(0),
        /// ns epoch of the first/last completed connect / establishment
        /// (0 = none yet) for driver-side rate computation.
        first_connect_ns: std.atomic.Value(u64) = .init(0),
        last_connect_ns: std.atomic.Value(u64) = .init(0),
        first_established_ns: std.atomic.Value(u64) = .init(0),
        last_established_ns: std.atomic.Value(u64) = .init(0),
    };

    /// Plain (non-atomic) copy returned by statsSnapshot().
    pub const StatsFlat = struct {
        connects_completed: u64 = 0,
        sessions_established: u64 = 0,
        bytes_rx: u64 = 0,
        bytes_tx: u64 = 0,
        max_iter_us: u64 = 0,
        first_connect_ns: u64 = 0,
        last_connect_ns: u64 = 0,
        first_established_ns: u64 = 0,
        last_established_ns: u64 = 0,
    };

    pub fn statsSnapshot(self: *Engine) StatsFlat {
        return .{
            .connects_completed = self.stats.connects_completed.load(.monotonic),
            .sessions_established = self.stats.sessions_established.load(.monotonic),
            .bytes_rx = self.stats.bytes_rx.load(.monotonic),
            .bytes_tx = self.stats.bytes_tx.load(.monotonic),
            .max_iter_us = self.stats.max_iter_us.load(.monotonic),
            .first_connect_ns = self.stats.first_connect_ns.load(.monotonic),
            .last_connect_ns = self.stats.last_connect_ns.load(.monotonic),
            .first_established_ns = self.stats.first_established_ns.load(.monotonic),
            .last_established_ns = self.stats.last_established_ns.load(.monotonic),
        };
    }

    pub fn statsReset(self: *Engine) void {
        self.stats.connects_completed.store(0, .monotonic);
        self.stats.sessions_established.store(0, .monotonic);
        self.stats.bytes_rx.store(0, .monotonic);
        self.stats.bytes_tx.store(0, .monotonic);
        self.stats.max_iter_us.store(0, .monotonic);
        self.stats.first_connect_ns.store(0, .monotonic);
        self.stats.last_connect_ns.store(0, .monotonic);
        self.stats.first_established_ns.store(0, .monotonic);
        self.stats.last_established_ns.store(0, .monotonic);
    }

    fn nowNs() u64 {
        return @intCast(@max(0, std.time.nanoTimestamp()));
    }

    // --- engine-thread hooks (Sessions call these) ---

    pub fn noteConnect(self: *Engine) void {
        const now = nowNs();
        _ = self.stats.connects_completed.fetchAdd(1, .monotonic);
        if (self.stats.first_connect_ns.load(.monotonic) == 0)
            self.stats.first_connect_ns.store(now, .monotonic);
        self.stats.last_connect_ns.store(now, .monotonic);
    }

    pub fn noteEstablished(self: *Engine) void {
        const now = nowNs();
        _ = self.stats.sessions_established.fetchAdd(1, .monotonic);
        if (self.stats.first_established_ns.load(.monotonic) == 0)
            self.stats.first_established_ns.store(now, .monotonic);
        self.stats.last_established_ns.store(now, .monotonic);
    }

    pub fn noteRx(self: *Engine, n: usize) void {
        _ = self.stats.bytes_rx.fetchAdd(@intCast(n), .monotonic);
    }

    pub fn noteTx(self: *Engine, n: usize) void {
        _ = self.stats.bytes_tx.fetchAdd(@intCast(n), .monotonic);
    }

    fn noteIterUs(self: *Engine, us: u64) void {
        // Single writer (engine thread): read-modify-write is race-free here.
        if (us > self.stats.max_iter_us.load(.monotonic))
            self.stats.max_iter_us.store(us, .monotonic);
    }

    const DeriveJob = struct {
        handle: Handle,
        /// Owned copies: the session (and its caller-owned strings) may die
        /// while the worker runs. Allocated AND freed on the engine thread —
        /// the worker never touches the allocator.
        password: []u8,
        salt: []u8,
        iterations: u32,
        /// SCRAM hash family (SHA-256 or SHA-1); the worker derives with it
        /// and the completion carries it back so the session can verify.
        hash: sasl.scram.Hash,
    };
    const DeriveDone = struct { job: DeriveJob, salted: sasl.scram.SaltedPassword };
    /// Fixed-capacity completion ring: the worker never allocates, so the
    /// engine allocator is not required to be thread-safe.
    const DONE_CAP = 64;

    kq: posix.fd_t,
    allocator: std.mem.Allocator,
    /// XMPPC_EVTRACE snapshot taken at init — getenv() walks the whole
    /// environment, far too expensive per event/flush on the engine thread.
    trace: bool,
    slots: std.ArrayListUnmanaged(Slot),
    free_slots: std.ArrayListUnmanaged(u32),
    live_count: usize = 0,
    /// Async DNS engine (lazy-open on first resolve).
    resolver: ?Resolver = null,
    /// One-second housekeeping tick (resolver retransmits/timeouts). The
    /// single allowed periodic timer on this loop.
    resolver_tick_armed: bool = false,

    tls_ctx: ?ssl.SslContext = null,
    /// PKIX-verifying client context (lazy): system CA store, per-connection
    /// hostname check. Fallback when DANE brought no TLSA records (T202).
    tls_ctx_ca: ?ssl.SslContext = null,
    /// Server-authentication policy seeded into each new session
    /// (dane_first default; lab rigs set .none — see xmppc.zig).
    default_tls_policy: tls.VerifyMode = .dane_first,
    thread: ?std.Thread = null,

    /// The single event sink for all sessions (T-25A16875 c): established,
    /// closed, stanza. Always delivered on the engine thread.
    on_event: ?@import("session.zig").EventHandler = null,
    on_event_ctx: ?*anyopaque = null,

    /// Cross-thread command mailbox (postStanza / stopSession): the ONLY
    /// way foreign threads touch a session. Copied here under the lock,
    /// drained on the engine thread by drainCommands. Two lists swapped
    /// each drain so capacity is retained.
    cmd_active: std.ArrayListUnmanaged(QueuedCmd) = .{},
    cmd_spare: std.ArrayListUnmanaged(QueuedCmd) = .{},
    cmd_lock: std.Thread.Mutex = .{},
    // Self-pipe for cross-thread wake-up (N-worker shutdown / stopSession
    // from a foreign thread). EVFILT_SIGNAL is unreliable across threads;
    // a real kqueue event on the pipe read-end is not.
    wake_pipe: [2]posix.fd_t = .{ -1, -1 },

    /// Staged kqueue registration changes, folded into the next waiting
    /// kevent() call. Mutex-guarded: attachFromThreadFd callers may stage
    /// from foreign threads.
    changes: std.ArrayListUnmanaged(Change) = .{},
    changes_lock: std.Thread.Mutex = .{},

    // --- SCRAM SaltedPassword cache + off-loop derivation (T-7AD30E73) ---
    // Hi() (4096..1M PBKDF2 iterations) must not run on the kqueue thread:
    // it stalls every session of the Engine during each login. Cache lookups
    // and inserts happen ONLY on the engine thread (no lock); the worker
    // touches just the two queues. SaltedPassword is password-equivalent
    // material: kept in memory only, zeroed on eviction/deinit.

    /// Worker derivations run (cache misses). Tests and the load driver
    /// assert N sessions of one account derive once.
    scram_derives: usize = 0,
    /// Cache hits served without touching the worker.
    scram_cache_hits: usize = 0,

    scram_cache: std.StringHashMapUnmanaged(sasl.scram.SaltedPassword) = .{},

    crypto_mutex: std.Thread.Mutex = .{},
    /// Signaled on: job queued, done-ring room freed, stop requested.
    crypto_cond: std.Thread.Condition = .{},
    crypto_jobs: std.ArrayListUnmanaged(DeriveJob) = .{},
    crypto_done: [DONE_CAP]?DeriveDone = @splat(null),
    crypto_done_head: usize = 0, // worker writes
    crypto_done_tail: usize = 0, // engine reads
    crypto_done_len: usize = 0,
    crypto_thread: ?std.Thread = null,
    crypto_stop: bool = false,

    sm_queues: std.StringHashMapUnmanaged(SmQueue) = .{},

    /// Driver-facing cumulative counters (T32). Written only on the engine
    /// thread through the note*() helpers; read via statsSnapshot().
    stats: Stats = .{},

    /// Set by Session.fail() (engine thread). Sessions failed during the
    /// drain phase must be reaped BEFORE this iteration's kevent(): once
    /// every session is dead nothing remains armed on the kqueue, so the
    /// wait would never return to reach the runLoop's reap.
    reap_pending: bool = false,

    /// Bumped on every run(): a previous loop that is still unwinding (its
    /// last session died while a foreign thread already attached the next
    /// one, reviving live_count) sees its generation go stale and exits
    /// before the replacement thread spawns.
    run_gen: u32 = 0,

    // --- XEP-0198 outbound unacked queues (T-9BC4D065) ---
    // Keyed by SM id; a queue outlives the Session that produced it because
    // resume spins up a NEW Session (SessionConfig.sm_resume_id) that must
    // find the old queue to drop acked entries and replay the rest.
    // Engine-thread only: every entry point is the read loop, sendStanza,
    // or the established action.

    pub const SmEntry = struct {
        /// Owned copy of the raw stanza bytes.
        bytes: []u8,
        /// Wire sequence of the most recent send (1-based to match 'h').
        seq: u32,
    };
    pub const SmQueue = struct {
        entries: std.ArrayListUnmanaged(SmEntry) = .{},
        next_seq: u32 = 1,
    };
    /// Backpressure bound: a server that never acks stops the send path
    // with error.SmBacklog instead of growing memory without limit.
    pub const SM_UNACKED_MAX = 512;

    /// Wrap-aware a <= b in XEP-0198 sequence space (u32, wraps at 2^32).
    fn smSeqLte(a: u32, b: u32) bool {
        return (b -% a) < (@as(u32, 1) << 31);
    }

    /// Fresh `<enabled id=...>`: start (or reset) the queue for `sm_id`.
    pub fn smRegisterFresh(self: *Engine, sm_id: []const u8) !void {
        if (self.sm_queues.getPtr(sm_id)) |q| {
            self.smQueueClear(q);
            q.next_seq = 1;
            return;
        }
        _ = try self.smQueueCreate(sm_id);
    }

    fn smQueueCreate(self: *Engine, sm_id: []const u8) !*SmQueue {
        const key = try self.allocator.dupe(u8, sm_id);
        errdefer self.allocator.free(key);
        try self.sm_queues.put(self.allocator, key, .{});
        return self.sm_queues.getPtr(key).?;
    }

    fn smQueueClear(self: *Engine, q: *SmQueue) void {
        for (q.entries.items) |e| self.allocator.free(e.bytes);
        q.entries.clearRetainingCapacity();
    }

    /// Track one outbound stanza while SM is active. Returns the unacked
    /// depth (the Session uses it to pace `<r/>` ack requests).
    pub fn smTrackSend(self: *Engine, sm_id: []const u8, stanza: []const u8) !usize {
        const q = self.sm_queues.getPtr(sm_id) orelse try self.smQueueCreate(sm_id);
        if (q.entries.items.len >= SM_UNACKED_MAX) return error.SmBacklog;
        const bytes = try self.allocator.dupe(u8, stanza);
        errdefer self.allocator.free(bytes);
        try q.entries.append(self.allocator, .{ .bytes = bytes, .seq = q.next_seq });
        q.next_seq +%= 1;
        return q.entries.items.len;
    }

    /// Server `<a h=.../>`: drop everything up to and including seq h.
    pub fn smAck(self: *Engine, sm_id: []const u8, h: u32) void {
        const q = self.sm_queues.getPtr(sm_id) orelse return;
        var n: usize = 0;
        while (n < q.entries.items.len and smSeqLte(q.entries.items[n].seq, h)) : (n += 1)
            self.allocator.free(q.entries.items[n].bytes);
        if (n > 0) std.mem.copyForwards(SmEntry, q.entries.items[0 .. q.entries.items.len - n], q.entries.items[n..]);
        q.entries.shrinkRetainingCapacity(q.entries.items.len - n);
    }

    /// Drop the queue for `sm_id` (resume `<failed/>`, consumer giving up on
    /// resume). Returns how many unacked stanzas were discarded.
    pub fn smDrop(self: *Engine, sm_id: []const u8) u32 {
        const kv = self.sm_queues.fetchRemove(sm_id) orelse return 0;
        const count: u32 = @intCast(kv.value.entries.items.len);
        var q = kv.value;
        self.smQueueClear(&q);
        q.entries.deinit(self.allocator);
        self.allocator.free(kv.key);
        return count;
    }

    /// Replay on `<resumed h=.../>`: drop acked entries, hand the queue back
    /// for the Session to re-queue remaining bytes in order (each gets a
    /// fresh wire sequence). Null when there is nothing to replay.
    pub fn smReplayQueue(self: *Engine, sm_id: []const u8, h: u32) ?*SmQueue {
        self.smAck(sm_id, h);
        const q = self.sm_queues.getPtr(sm_id) orelse return null;
        if (q.entries.items.len == 0) return null;
        return q;
    }

    pub fn init(allocator: std.mem.Allocator) !Engine {
        const kq = posix.kqueue() catch return error.KqueueInit;
        return .{
            .kq = kq,
            .allocator = allocator,
            .slots = .{},
            .free_slots = .{},
            .trace = std.posix.getenv("XMPPC_EVTRACE") != null,
        };
    }

    pub fn deinit(self: *Engine) void {
        if (self.thread) |*t| {
            t.join();
            self.thread = null;
        }
        self.stopAll();
        if (self.resolver) |*r| r.deinit();
        // Stop the crypto worker, then reclaim its buffers (all on this
        // thread: the worker is joined before any free happens).
        self.crypto_mutex.lock();
        self.crypto_stop = true;
        self.crypto_cond.signal();
        self.crypto_mutex.unlock();
        if (self.crypto_thread) |t| {
            t.join();
            self.crypto_thread = null;
        }
        for (self.crypto_jobs.items) |job| {
            self.allocator.free(job.password);
            self.allocator.free(job.salt);
        }
        self.crypto_jobs.deinit(self.allocator);
        for (&self.crypto_done) |*slot| {
            if (slot.*) |d| {
                self.allocator.free(d.job.password);
                self.allocator.free(d.job.salt);
                slot.* = null;
            }
        }
        self.scramCacheClear();
        self.scram_cache.deinit(self.allocator);
        var sm_it = self.sm_queues.iterator();
        while (sm_it.next()) |kv| {
            self.smQueueClear(kv.value_ptr);
            kv.value_ptr.entries.deinit(self.allocator);
            self.allocator.free(kv.key_ptr.*);
        }
        self.sm_queues.deinit(self.allocator);
        self.slots.deinit(self.allocator);
        self.free_slots.deinit(self.allocator);
        self.changes.deinit(self.allocator);
        if (self.tls_ctx) |*c| c.deinit();
        if (self.tls_ctx_ca) |*c| c.deinit();
        // Leftover posted-but-never-applied commands.
        for (self.cmd_active.items) |*c| self.allocator.free(cmdPayload(c));
        for (self.cmd_spare.items) |*c| self.allocator.free(cmdPayload(c));
        self.cmd_active.deinit(self.allocator);
        self.cmd_spare.deinit(self.allocator);
        if (self.wake_pipe[0] >= 0) posix.close(self.wake_pipe[0]);
        if (self.wake_pipe[1] >= 0) posix.close(self.wake_pipe[1]);
        posix.close(self.kq);
    }

    /// Look up a cached SaltedPassword for (password, salt, iterations).
    /// Engine thread only (cache is unsynchronized by design).
    pub fn scramCached(self: *Engine, password: []const u8, salt: []const u8, iterations: u32, hash: sasl.scram.Hash) ?sasl.scram.SaltedPassword {
        var kbuf: [1024]u8 = undefined;
        const key = std.fmt.bufPrint(&kbuf, "{d}\x00{s}\x00{s}\x00{d}", .{ @intFromEnum(hash), password, salt, iterations }) catch return null;
        return self.scram_cache.get(key);
    }

    /// Queue a SaltedPassword derivation for the crypto worker; the session
    /// parks until onSaslDerived fires from the loopOnce drain. Engine
    /// thread only.
    pub fn queueDerive(self: *Engine, h: Handle, password: []const u8, salt: []const u8, iterations: u32, hash: sasl.scram.Hash) !void {
        const pw_copy = try self.allocator.dupe(u8, password);
        errdefer self.allocator.free(pw_copy);
        const salt_copy = try self.allocator.dupe(u8, salt);
        errdefer self.allocator.free(salt_copy);

        self.crypto_mutex.lock();
        defer self.crypto_mutex.unlock();
        if (self.crypto_thread == null) {
            self.crypto_thread = std.Thread.spawn(.{}, Engine.cryptoWorkerMain, .{self}) catch null;
            if (self.crypto_thread == null) return error.WorkerSpawn;
        }
        try self.crypto_jobs.append(self.allocator, .{
            .handle = h,
            .password = pw_copy,
            .salt = salt_copy,
            .iterations = iterations,
            .hash = hash,
        });
        self.crypto_cond.signal();
    }

    fn scramCacheClear(self: *Engine) void {
        var it = self.scram_cache.iterator();
        while (it.next()) |e| {
            std.crypto.secureZero(u8, std.mem.asBytes(e.value_ptr));
            self.allocator.free(e.key_ptr.*);
        }
        self.scram_cache.clearRetainingCapacity();
    }

    fn cryptoWorkerMain(self: *Engine) void {
        while (true) {
            self.crypto_mutex.lock();
            // Pop only when completion is guaranteed: ring room was checked,
            // and the worker is the ring's sole producer.
            while ((self.crypto_jobs.items.len == 0 or self.crypto_done_len == DONE_CAP) and !self.crypto_stop)
                self.crypto_cond.wait(&self.crypto_mutex);
            if (self.crypto_stop) {
                self.crypto_mutex.unlock();
                return; // queued jobs are reclaimed by deinit
            }
            const job = self.crypto_jobs.orderedRemove(0);
            self.crypto_mutex.unlock();

            const salted = sasl.scram.deriveSalted(job.hash, job.password, job.salt, job.iterations);

            self.crypto_mutex.lock();
            self.crypto_done[self.crypto_done_head] = .{ .job = job, .salted = salted };
            self.crypto_done_head = (self.crypto_done_head + 1) % DONE_CAP;
            self.crypto_done_len += 1;
            self.crypto_mutex.unlock();
            self.requestWake();
        }
    }

    /// Engine-thread drain of completed derivations (top of loopOnce):
    /// adopt each result into the cache, free the job's copies, resume the
    /// parked session (generation-checked; dead sessions are skipped).
    fn drainCryptoDone(self: *Engine) void {
        while (true) {
            self.crypto_mutex.lock();
            if (self.crypto_done_len == 0) {
                self.crypto_mutex.unlock();
                return;
            }
            const done = self.crypto_done[self.crypto_done_tail].?;
            self.crypto_done[self.crypto_done_tail] = null;
            self.crypto_done_tail = (self.crypto_done_tail + 1) % DONE_CAP;
            self.crypto_done_len -= 1;
            self.crypto_mutex.unlock();
            // Ring room freed: wake a worker blocked on DONE_CAP.
            self.crypto_cond.signal();

            defer self.allocator.free(done.job.password);
            defer self.allocator.free(done.job.salt);
            self.scram_derives += 1;

            const key = std.fmt.allocPrint(self.allocator, "{d}\x00{s}\x00{s}\x00{d}", .{ @intFromEnum(done.job.hash), done.job.password, done.job.salt, done.job.iterations }) catch null;
            if (key) |k| {
                if (self.scram_cache.contains(k)) {
                    self.allocator.free(k);
                } else {
                    if (self.scram_cache.count() >= SCRAM_CACHE_MAX) self.scramCacheClear();
                    self.scram_cache.put(self.allocator, k, done.salted) catch self.allocator.free(k);
                }
            }
            if (self.sessionAt(done.job.handle)) |s| s.onSaslDerived(self, done.salted);
        }
    }

    /// Wake the kqueue loop from any thread (no-op if the loop is not
    /// blocked, e.g. between run() iterations).
    pub fn requestWake(self: *Engine) void {
        if (self.wake_pipe[1] < 0) {
            self.wake_pipe = posix.pipe() catch return;
            // Non-blocking read end so the drain loop in loopOnce() never stalls.
            _ = std.c.fcntl(self.wake_pipe[0], std.c.F.SETFL, @as(c_int, @bitCast(std.c.O{ .NONBLOCK = true })));
            const ev = kev(@intCast(self.wake_pipe[0]), std.c.EVFILT.READ, std.c.EV.ADD, WAKE_UDATA);
            _ = posix.kevent(self.kq, &.{ev}, &.{}, null) catch return;
        }
        _ = posix.write(self.wake_pipe[1], &.{1}) catch {};
    }

    pub fn stopAll(self: *Engine) void {
        for (self.slots.items) |*slot| {
            if (slot.live) slot.session.destroy(self.allocator);
            slot.live = false;
        }
        self.live_count = 0;
    }

    /// Install a client TLS context (DANE-first: PKIX verify disabled, so
    /// self-signed / DANE-validated certs both work).
    ///
    /// The shared initializers arm KTLS unconditionally (battle-tested server
    /// behavior), but a client must not offload when its peer might: two
    /// KTLS-armed endpoints desync across lo0/epair/bridge (FreeBSD PR
    /// 296498). Offload is therefore disabled here unless `ktls` is true —
    /// opt in only against non-KTLS peers or real-NIC paths (IFCAP_MEXTPG).
    pub fn useTls(self: *Engine, ktls: ?bool) !void {
        if (self.tls_ctx) |_| return;
        self.tls_ctx = ssl.SslContext.initClient() catch return error.TlsInit;
        if (!(ktls orelse false)) self.tls_ctx.?.disableKtls();
    }

    /// PKIX-verifying client context (lazy init): system CA trust store.
    /// Sessions use it when their policy requires verification but the
    /// resolution brought no TLSA records (T202 fallback order).
    pub fn clientCaTlsContext(self: *Engine) !ssl.SslContext {
        if (self.tls_ctx_ca == null) {
            self.tls_ctx_ca = ssl.SslContext.initClientVerified() catch return error.TlsInit;
        }
        return self.tls_ctx_ca.?;
    }

    pub fn sessionCount(self: *const Engine) usize {
        return self.live_count;
    }

    /// Access a live session by its handle (from startSession/attachFd).
    /// Returns null for dead/reaped sessions and for stale handles.
    pub fn sessionAt(self: *Engine, h: Handle) ?*Session {
        if (h.index >= self.slots.items.len) return null;
        const slot = &self.slots.items[@intCast(h.index)];
        if (!slot.live or slot.generation != h.generation) return null;
        if (!slot.session.alive) return null;
        return &slot.session;
    }

    /// Stop a session. Safe from ANY thread: the stop is posted to the
    /// command mailbox and executed on the engine thread. Stops are exempt
    /// from the mailbox bound (a dropped stop would leak the teardown
    /// signal); they are bounded by the number of live sessions.
    pub fn stopSession(self: *Engine, h: Handle, reason: []const u8) void {
        const copy = self.allocator.dupe(u8, reason) catch return;
        const ok = blk: {
            self.cmd_lock.lock();
            defer self.cmd_lock.unlock();
            self.cmd_active.append(self.allocator, .{ .handle = h, .cmd = .{ .stop = copy } }) catch break :blk false;
            break :blk true;
        };
        if (!ok) {
            self.allocator.free(copy);
            log.err("out of memory posting stop command for a session", .{});
            return;
        }
        self.requestWake();
    }

    /// Send one application stanza from ANY thread: the bytes are copied
    /// and queued on the engine thread (foreign threads must not touch
    /// Session state directly).
    pub fn postStanza(self: *Engine, h: Handle, stanza: []const u8) !void {
        const copy = try self.allocator.dupe(u8, stanza);
        self.postCommand(h, .{ .stanza = copy }) catch |err| {
            self.allocator.free(copy);
            return err;
        };
    }

    fn postCommand(self: *Engine, h: Handle, cmd: Command) !void {
        {
            self.cmd_lock.lock();
            defer self.cmd_lock.unlock();
            if (self.cmd_active.items.len >= CMD_QUEUE_MAX) return error.CommandQueueFull;
            self.cmd_active.append(self.allocator, .{ .handle = h, .cmd = cmd }) catch return error.OutOfMemory;
        }
        self.requestWake();
    }

    /// Engine-thread: apply every posted command. Stanzas route through
    /// Session.sendStanza (established guard lives there); stops fail
    /// the session. Drops are logged, never silent.
    fn drainCommands(self: *Engine) void {
        self.cmd_lock.lock();
        std.mem.swap(@TypeOf(self.cmd_active), &self.cmd_active, &self.cmd_spare);
        self.cmd_lock.unlock();
        var pending = &self.cmd_spare;
        defer {
            for (pending.items) |*c| self.allocator.free(cmdPayload(c));
            pending.clearRetainingCapacity();
        }
        for (pending.items) |cmd| {
            switch (cmd.cmd) {
                .stanza => |bytes| {
                    const s = self.sessionAt(cmd.handle) orelse {
                        log.debug("posted stanza dropped: dead session", .{});
                        continue;
                    };
                    _ = s.sendStanza(bytes) catch |err| {
                        log.debug("posted stanza dropped: {}", .{err});
                        continue;
                    };
                },
                .stop => |reason| {
                    if (self.sessionAt(cmd.handle)) |s| s.fail(self.allocator, reason);
                },
            }
        }
    }

    fn cmdPayload(c: anytype) []u8 {
        return switch (c.cmd) {
            .stanza => |b| b,
            .stop => |r| r,
        };
    }

    /// Install the single event handler receiving every session Event
    /// (established / closed / stanza). Null clears it.
    pub fn setEventHandler(self: *Engine, cb: ?@import("session.zig").EventHandler, ctx: ?*anyopaque) void {
        self.on_event = cb;
        self.on_event_ctx = ctx;
    }

    /// Fire an Event at the consumer. Called by Session internals on the
    /// engine thread; safe to call with no handler (event drops silently).
    pub fn dispatchEvent(self: *Engine, handle: Handle, ev: Event) void {
        if (self.on_event) |cb| cb(self.on_event_ctx, self, handle, ev);
    }

    /// Begin a client session. All config fields are arena-copied into the
    /// Session, so the caller's storage may be reused or freed immediately.
    /// Returns the session handle.
    ///
    /// `host` as a literal IP connects immediately; otherwise DNS resolution
    /// runs asynchronously (SRV chain -> A/AAAA -> TLSA) on this loop and the
    /// session continues when the answer lands. Connect failure walks the
    /// target list.
    pub fn startSession(self: *Engine, config: SessionConfig) !Handle {
        var s = try Session.init(self.allocator);
        s.engine = self;
        s.setConfig(config) catch {
            s.destroy(self.allocator);
            return error.OutOfMemory;
        };
        s.port = config.port;
        s.tls_policy = self.default_tls_policy;

        // Literal IP: skip DNS entirely (lab rigs, explicit endpoints).
        if (std.net.Address.parseIp(config.host, 0)) |_| {
            return self.connectDirect(&s, config.host, config.port);
        } else |_| {}

        // Hostname: park the session in .resolving and hand the lookup to
        // the async resolver on THIS engine. Nothing blocks.
        if (self.resolver == null) {
            self.resolver = Resolver.init(self.allocator);
            self.resolver.?.setCallback(.{ .ctx = self, .fun = onDnsResult });
        }
        // Register the session slot first so the resolution completes to a
        // live handle.
        const h = try self.allocSlot();
        const slot = &self.slots.items[@intCast(h.index)];
        slot.session = s;
        slot.session.handle = h;
        slot.live = true;
        slot.session.phase = .resolving;
        self.live_count += 1;
        self.resolver.?.resolve(config.host, config.port, h.encode()) catch |err| {
            slot.session.destroy(self.allocator);
            self.freeSlot(h);
            return err;
        };
        self.armResolverTick();
        return h;
    }

    /// Direct connect without DNS (literal IP or the socketpair test seam's
    /// pre-connected fd).
    pub fn connectDirect(self: *Engine, s: *Session, host: []const u8, port: u16) !Handle {
        const addr_v4 = resolveHost(host) catch {
            return error.NameResolutionFailed;
        };
        var addr = addr_v4;
        addr.port = std.mem.nativeToBig(u16, port);
        const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0) catch |serr| {
            log.warn("socket() failed: {}", .{serr});
            s.destroy(self.allocator);
            return error.SocketCreate;
        };
        posix.connect(fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch |err| {
            if (err != error.WouldBlock) {
                log.warn("connect() to {s}:{d} failed immediately: {}", .{ host, port, err });
                posix.close(fd);
                s.destroy(self.allocator);
                return error.ConnectFailed;
            }
        };
        return self.attachPrepared(s, fd);
    }

    // ---- DNS completion ---------------------------------------------------

    fn armResolverTick(self: *Engine) void {
        if (self.resolver == null or self.resolver_tick_armed) return;
        self.resolver_tick_armed = true;
        // Register the resolver socket + a 1 s housekeeping tick.
        const dns_fd = self.resolver.?.sockFd();
        if (dns_fd >= 0) {
            const dev = kev(@intCast(dns_fd), std.c.EVFILT.READ, std.c.EV.ADD | std.c.EV.ENABLE, DNS_UDATA);
            self.stage(dev);
        }
        const tick = kev(1, std.c.EVFILT.TIMER, std.c.EV.ADD | std.c.EV.ENABLE, TICK_UDATA);
        // NOTE: kev() here carries data=0; EVFILT_TIMER's interval must go in
        // `data` (ms). kev() doesn't expose it — write the record directly.
        var tev = tick;
        tev.data = 1000;
        self.stage(tev);
    }

    /// Completion callback for the resolver (engine thread). static per Cb.
    fn onDnsResult(ctx: ?*anyopaque, session_key: usize, status: DnsStatus, res: ?Resolution) void {
        const self: *Engine = @ptrCast(@alignCast(ctx orelse return));
        const h = Handle.decode(session_key);
        const s = self.sessionAt(h) orelse return;
        s.onResolution(res, status);
    }

    /// Attach a pre-connected fd — the test seam for driving a Session over
    /// socketpair(2) with a scripted fake server (no network, no certs for
    /// the plaintext cases). The fd must be non-blocking and connected (or a
    /// socketpair/stream fd); the session then runs the same post-connect
    /// path as startSession (stream open on first writability). config.host
    /// and config.port are unused here.
    pub fn attachFd(self: *Engine, fd: posix.fd_t, config: SessionConfig) !Handle {
        var s = try Session.init(self.allocator);
        s.engine = self;
        s.setConfig(config) catch {
            s.destroy(self.allocator);
            return error.OutOfMemory;
        };
        s.tls_policy = self.default_tls_policy;
        return self.attachPrepared(&s, fd);
    }

    fn attachPrepared(self: *Engine, s: *Session, fd: posix.fd_t) !Handle {
        s.fd = fd;
        s.tport = Transport.initPlain(fd);
        s.phase = .connecting;

        const h = try self.allocSlot();
        const slot = &self.slots.items[@intCast(h.index)];
        slot.session = s.*;
        slot.session.handle = h;
        slot.live = true;
        // Both filters are registered below — keep the session's bookkeeping
        // in step (disarm/arm are idempotent guards).
        slot.session.write_registered = true;
        slot.session.read_registered = true;
        self.live_count += 1;
        self.addRead(fd, h);
        self.addWrite(fd, h);
        return h;
    }

    fn allocSlot(self: *Engine) !Handle {
        if (self.free_slots.items.len > 0) {
            const idx = self.free_slots.items[self.free_slots.items.len - 1];
            self.free_slots.items.len -= 1;
            const slot = &self.slots.items[@intCast(idx)];
            return .{ .index = idx, .generation = slot.generation };
        }
        // Placeholder session is overwritten by the caller before use.
        try self.slots.append(self.allocator, .{ .session = undefined, .generation = 0, .live = false });
        return .{ .index = @intCast(self.slots.items.len - 1), .generation = 0 };
    }

    fn freeSlot(self: *Engine, h: Handle) void {
        const slot = &self.slots.items[@intCast(h.index)];
        slot.live = false;
        slot.generation +%= 1;
        self.free_slots.append(self.allocator, h.index) catch {};
        self.live_count -= 1;
    }

    /// Join the loop thread without respawning it: the deterministic "loop
    /// fully stopped" point a consumer needs before re-attaching a session
    /// from its control thread (attachFd only stages; a still-running old
    /// loop would otherwise drive the fresh session concurrently).
    pub fn waitLoopExit(self: *Engine) void {
        if (self.thread) |*t| {
            self.requestWake();
            t.join();
            self.thread = null;
        }
    }

    /// Run the kqueue loop on a dedicated thread.
    pub fn run(self: *Engine) !void {
        self.run_gen +%= 1;
        self.waitLoopExit();
        const t = std.Thread.spawn(.{}, Engine.runLoop, .{self}) catch return error.ThreadSpawn;
        self.thread = t;
    }

    /// Run the kqueue loop inline on the caller thread until all sessions die.
    pub fn runSync(self: *Engine) !void {
        while (self.live_count > 0) {
            self.loopOnce() catch {
                // kevent error — fail every session and stop rather than spin.
                for (self.slots.items) |*slot| {
                    if (slot.live) slot.session.fail(self.allocator, "kqueue-error");
                }
                self.reapDead();
                break;
            };
            self.reapDead();
        }
    }

    fn runLoop(self: *Engine) void {
        const gen = self.run_gen;
        while (self.live_count > 0 and self.run_gen == gen) {
            self.loopOnce() catch break;
            self.reapDead();
        }
    }

    fn loopOnce(self: *Engine) !void {
        const t_iter_start = std.time.nanoTimestamp();
        // Drain the self-pipe first: a wake is a "re-examine" request, not
        // data. The read end is non-blocking, so this terminates on EAGAIN.
        if (self.wake_pipe[0] >= 0) {
            var wbuf: [128]u8 = undefined;
            while (true) {
                _ = posix.read(self.wake_pipe[0], &wbuf) catch break;
            }
        }
        self.drainCommands();

        // Resume sessions whose off-loop SaltedPassword derivation finished.
        self.drainCryptoDone();

        // Sessions killed by the drains above (stopSession commands, dead
        // resumes) are reaped now, not after the wait: with no live session
        // left armed, kevent() would block forever and runLoop's own reap
        // never runs. No-op when nothing died.
        if (self.reap_pending) self.reapDead();
        if (self.live_count == 0) return; // nothing armed: never wait        // Fold everything staged since the last iteration into THIS kevent:
        // snapshot the buffer, then release the lock — event handlers stage
        // new changes during dispatch (they'd otherwise self-deadlock).
        var evbuf: [64]Kevent = undefined;
        var staged: [64]Change = undefined;
        self.changes_lock.lock();
        const staged_count = @min(self.changes.items.len, staged.len);
        @memcpy(staged[0..staged_count], self.changes.items[0..staged_count]);
        // Compact the tail: `len -= n` alone discards everything past slot
        // 64 (the leftover entries sit at HIGHER indices; the shortened
        // array then exposes the already-consumed head as valid and the
        // tail is dropped — observed under burst load as lost EV_DELETEs
        // and a level-triggered WRITE livelock at ~32 sessions).
        std.mem.copyForwards(Change, self.changes.items, self.changes.items[staged_count..]);
        self.changes.items.len -= staged_count;
        self.changes_lock.unlock();

        const t_wait_start = std.time.nanoTimestamp();
        const n = posix.kevent(self.kq, staged[0..staged_count], &evbuf, null) catch {
            return error.SystemResources;
        };
        const t_wait_end = std.time.nanoTimestamp();
        if (self.trace) {
            std.debug.print("[engine] staged={d} returned={d}\n", .{ staged_count, n });
            for (evbuf[0..n]) |ev| std.debug.print("  ev fd={d} filter={d} flags=0x{x} reg={} wan=\n", .{ ev.ident, ev.filter, ev.flags, ev.udata });
        }

        for (evbuf[0..n]) |ev| {
            if (ev.udata == WAKE_UDATA) continue;
            if (ev.udata == DNS_UDATA) {
                if (self.resolver) |*r| r.onReadable();
                continue;
            }
            if (ev.udata == TICK_UDATA) {
                if (self.resolver) |*r| r.tick();
                continue;
            }
            const h = Handle.decode(ev.udata);
            const s = self.sessionAt(h) orelse continue;
            switch (ev.filter) {
                std.c.EVFILT.READ => s.onRead(self) catch s.fail(self.allocator, "read-error"),
                std.c.EVFILT.WRITE => s.onWritable(self) catch s.fail(self.allocator, "write-error"),
                else => {},
            }
            // EV_EOF lives in ev.flags (not fflags): the peer shut down the
            // read direction. Checked after dispatch so any last buffered
            // data is drained before the session is failed. sys/event.h
            // EV_EOF — not exposed as std.c.EV.EOF for FreeBSD in this zig
            // std; the value is stable ABI.
            if (ev.flags & 0x8000 != 0) s.fail(self.allocator, "peer-closed");
            if (ev.flags & std.c.EV.ERROR != 0) {
                std.debug.print("[engine] EV_ERROR fd={d} filter={d} data={d}\n", .{ ev.ident, ev.filter, ev.data });
                s.fail(self.allocator, "socket-error");
            }
        }
        // Stall bookkeeping: everything EXCEPT the kevent wait counts —
        // drains at the top plus event dispatch below it.
        const t_done = std.time.nanoTimestamp();
        const work_ns = (t_wait_start - t_iter_start) + (t_done - t_wait_end);
        self.noteIterUs(@intCast(@max(0, @divTrunc(work_ns, 1000))));
    }

    /// Destroy + release dead sessions. Slots stay; generations advance.
    fn reapDead(self: *Engine) void {
        self.reap_pending = false;
        for (self.slots.items, 0..) |*slot, i| {
            if (!slot.live) continue;
            if (slot.session.alive) continue;
            slot.session.destroy(self.allocator);
            self.freeSlot(.{ .index = @intCast(i), .generation = slot.generation });
        }
    }

    // --- kqueue helpers: stage registration changes (applied at the wait) ---

    pub fn addRead(self: *Engine, fd: posix.fd_t, h: Handle) void {
        self.stage(kev(@intCast(fd), std.c.EVFILT.READ, std.c.EV.ADD | std.c.EV.ENABLE, h.encode()));
    }
    pub fn addWrite(self: *Engine, fd: posix.fd_t, h: Handle) void {
        self.stage(kev(@intCast(fd), std.c.EVFILT.WRITE, std.c.EV.ADD | std.c.EV.ENABLE, h.encode()));
    }
    pub fn removeRead(self: *Engine, fd: posix.fd_t) void {
        self.stage(kev(@intCast(fd), std.c.EVFILT.READ, std.c.EV.DELETE, 0));
    }
    pub fn removeWrite(self: *Engine, fd: posix.fd_t) void {
        self.stage(kev(@intCast(fd), std.c.EVFILT.WRITE, std.c.EV.DELETE, 0));
    }

    /// Stage a registration change for the next loop iteration's kevent(),
    /// then wake the loop: a kevent() blocked on a drained changelist would
    /// otherwise not apply the registration until an unrelated fd event.
    /// Never calls kevent for registration alone (project kqueue rule).
    fn stage(self: *Engine, ev: Change) void {
        self.changes_lock.lock();
        defer self.changes_lock.unlock();
        self.changes.append(self.allocator, ev) catch {};
        self.requestWake();
    }
};

test "engine: SM unacked queue track/ack/drop incl. sequence wrap (T-9BC4D065)" {
    const alloc = std.testing.allocator;
    var engine = try Engine.init(alloc);
    defer engine.deinit();

    try engine.smRegisterFresh("s1");
    _ = try engine.smTrackSend("s1", "<m1/>");
    _ = try engine.smTrackSend("s1", "<m2/>");
    _ = try engine.smTrackSend("s1", "<m3/>");
    engine.smAck("s1", 2);
    const q = engine.sm_queues.getPtr("s1").?;
    try std.testing.expectEqual(@as(usize, 1), q.entries.items.len);
    try std.testing.expectEqualStrings("<m3/>", q.entries.items[0].bytes);

    // Wrap: with only near-wrap entries in flight (the realistic case —
    // h advances as the peer handles our stanzas), acks across the 2^32
    // boundary must drop the right prefix.
    engine.smAck("s1", 3);
    try std.testing.expectEqual(@as(usize, 0), q.entries.items.len);
    q.next_seq = 0xFFFF_FFFE;
    _ = try engine.smTrackSend("s1", "<m4/>"); // seq FFFE
    _ = try engine.smTrackSend("s1", "<m5/>"); // seq FFFF
    _ = try engine.smTrackSend("s1", "<m6/>"); // seq 0 (wrapped)
    engine.smAck("s1", 0xFFFF_FFFF);
    try std.testing.expectEqual(@as(usize, 1), q.entries.items.len);
    try std.testing.expectEqualStrings("<m6/>", q.entries.items[0].bytes);
    engine.smAck("s1", 0); // wrapped h acks the m6 entry too
    try std.testing.expectEqual(@as(usize, 0), q.entries.items.len);

    try std.testing.expectEqual(@as(u32, 0), engine.smDrop("s1"));
    try std.testing.expect(engine.sm_queues.getPtr("s1") == null);
}
