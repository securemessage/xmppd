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
//! via sessionAt). Foreign threads interact ONLY through the engine's
//! thread-safe entry points — startSession (slots the session, the loop
//! launches it), postStanza and stopSession — never through *Session
//! itself.
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
    /// Consumer-timer udata range base: token N rides as TIMER_UDATA - N.
    /// The range sits below the reserved sentinels and far above any Handle
    /// encode, so loopOnce routes it to onTimerEvent before Handle decode.
    const TIMER_UDATA: usize = std.math.maxInt(usize) - 3;
    const TIMER_MAX = 65536;

    /// One queued command for a session. `start` launches a session slotted
    /// by a foreign-thread startSession; `stanza` is application payload
    /// bytes; `stop` carries the failure reason.
    pub const Command = union(enum) {
        start,
        stanza: []u8,
        stop: []u8,
    };

    /// One-shot timer callback; runs on the engine thread like session
    /// events (it may startSession/postStanza/stopSession inline).
    pub const TimerFn = *const fn (ctx: ?*anyopaque, engine: *Engine) void;
    const Timer = struct { cb: TimerFn, ctx: ?*anyopaque };

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
        /// Session.fail() calls and reapDead() destroys (teardown forensics,
        /// T237/T244). A stop command for a session the slot map no longer
        /// owns is counted separately — that is a lost teardown signal.
        sessions_failed: std.atomic.Value(u64) = .init(0),
        sessions_reaped: std.atomic.Value(u64) = .init(0),
        stops_dropped: std.atomic.Value(u64) = .init(0),
        /// Mailbox/wake-pipe forensics: commands appended by ANY thread,
        /// commands actually dispatched, wake bytes written, and pipe bytes
        /// drained (teardown-hang instrumentation, T237).
        cmds_posted: std.atomic.Value(u64) = .init(0),
        cmds_drained: std.atomic.Value(u64) = .init(0),
        wakes_written: std.atomic.Value(u64) = .init(0),
        wakes_read: std.atomic.Value(u64) = .init(0),
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
        sessions_failed: u64 = 0,
        sessions_reaped: u64 = 0,
        stops_dropped: u64 = 0,
        cmds_posted: u64 = 0,
        cmds_drained: u64 = 0,
        wakes_written: u64 = 0,
        wakes_read: u64 = 0,
        wake_pending: bool = false,
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
            .sessions_failed = self.stats.sessions_failed.load(.monotonic),
            .sessions_reaped = self.stats.sessions_reaped.load(.monotonic),
            .stops_dropped = self.stats.stops_dropped.load(.monotonic),
            .cmds_posted = self.stats.cmds_posted.load(.monotonic),
            .cmds_drained = self.stats.cmds_drained.load(.monotonic),
            .wakes_written = self.stats.wakes_written.load(.monotonic),
            .wakes_read = self.stats.wakes_read.load(.monotonic),
            .wake_pending = self.wake_pending.load(.acquire),
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
        self.stats.sessions_failed.store(0, .monotonic);
        self.stats.sessions_reaped.store(0, .monotonic);
        self.stats.stops_dropped.store(0, .monotonic);
        self.stats.cmds_posted.store(0, .monotonic);
        self.stats.cmds_drained.store(0, .monotonic);
        self.stats.wakes_written.store(0, .monotonic);
        self.stats.wakes_read.store(0, .monotonic);
    }

    pub fn noteFail(self: *Engine) void {
        _ = self.stats.sessions_failed.fetchAdd(1, .monotonic);
    }
    pub fn noteReap(self: *Engine) void {
        _ = self.stats.sessions_reaped.fetchAdd(1, .monotonic);
    }
    fn noteStopDropped(self: *Engine) void {
        _ = self.stats.stops_dropped.fetchAdd(1, .monotonic);
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

    // --- generational session slots (T-80EFEC29), foreign-thread safe (T237) ---
    // Slots live in fixed CHUNK-entry chunks: a published chunk pointer never
    // changes until deinit, so an engine-thread reader (sessionAt, event
    // dispatch) never chases a realloc while a foreign-thread startSession
    // reserves a slot. Only allocSlot/freeSlot mutate the free list and the
    // watermark, under slots_lock.
    pub const CHUNK = 1024;
    /// 64 chunks = 65536 sessions — at/above the process fd limit anyway.
    pub const MAX_CHUNKS = 64;
    const Chunk = [CHUNK]Slot;

    chunks: [MAX_CHUNKS]std.atomic.Value(?*Chunk) = @splat(.init(null)),
    /// Next never-issued slot index. Read lock-free for the early-out in
    /// sessionAt; written only under slots_lock.
    hi: std.atomic.Value(usize) = .init(0),
    slots_lock: std.Thread.Mutex = .{},
    free_slots: std.ArrayListUnmanaged(u32) = .{},
    live_count: std.atomic.Value(usize) = .init(0),

    kq: posix.fd_t,
    allocator: std.mem.Allocator,
    /// XMPPC_EVTRACE snapshot taken at init — getenv() walks the whole
    /// environment, far too expensive per event/flush on the engine thread.
    trace: bool,
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

    /// One-shot consumer timers: reconnect backoff and other delayed
    /// actions. The kqueue timer (EV_ONESHOT) is the single source of a
    /// firing; the map entry is consumed when it dispatches. The loop keeps
    /// running while timers are pending even with no live sessions.
    /// `timers` and `next_timer` are guarded by `timers_lock` (schedule and
    /// cancelTimer may run on any thread); callbacks run outside the lock.
    timers: std.AutoHashMapUnmanaged(usize, Timer) = .{},
    next_timer: usize = 0,
    timers_lock: std.Thread.Mutex = .{},

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
    //
    // Wake discipline (T236/T237): BOTH ends are O_NONBLOCK and writers post
    // one byte UNCONDITIONALLY (the canonical self-pipe pattern). A full
    // pipe turns a write into EAGAIN — which is safe by construction: full
    // implies nonempty, which arms the level-triggered READ and wakes the
    // loop, whose drain empties it. The T236 coalescing FLAG was removed:
    // clearing it before the drain let a swap(true) win and write a byte
    // that was then drained while the flag stayed set, suppressing every
    // later wake (live-locked teardown, observed 2026-10-03).
    wake_pipe: [2]posix.fd_t = .{ -1, -1 },
    /// Serializes only the one-time lazy pipe creation (two foreign callers
    /// racing the create would leak/clobber an fd pair); the steady-state
    /// wake path takes no lock.
    wake_create_lock: std.Thread.Mutex = .{},
    /// Kept only as observability (read by statsSnapshot().wake_pending):
    /// true while the loop has not yet drained the pipe this iteration.
    wake_pending: std.atomic.Value(bool) = .init(false),
    /// Kernel tid of the thread executing the loop (0 = not running). The
    /// engine thread must never write to the wake pipe: its staged changes
    /// fold into the kevent() it is about to call, and a blocking pipe
    /// write would self-deadlock. FreeBSD tids start at 100000, so 0 never
    /// aliases a live thread.
    loop_tid: std.atomic.Value(std.Thread.Id) = .init(0),

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
        for (&self.chunks) |*c| {
            if (c.load(.acquire)) |chunk| self.allocator.destroy(chunk);
        }
        self.free_slots.deinit(self.allocator);
        self.changes.deinit(self.allocator);
        self.timers.deinit(self.allocator);
        if (self.tls_ctx) |*c| c.deinit();
        if (self.tls_ctx_ca) |*c| c.deinit();
        // Leftover posted-but-never-applied commands.
        for (self.cmd_active.items) |*c| self.cmdFree(c);
        for (self.cmd_spare.items) |*c| self.cmdFree(c);
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

    /// Wake the kqueue loop from any foreign thread (no-op if the loop is
    /// not blocked, e.g. between run() iterations). The engine thread never
    /// needs a wake: everything it staged folds into the kevent() it is
    /// about to call.
    pub fn requestWake(self: *Engine) void {
        if (self.loop_tid.load(.acquire) == std.Thread.getCurrentId()) return;
        self.wake_pending.store(true, .release);
        if (self.wake_pipe[1] < 0) {
            // One-time lazy create. Creation races between two foreign
            // callers finalize through wake_create_lock; AFTER creation the
            // fds never change, so the steady-state write path is lock-free.
            self.wake_create_lock.lock();
            defer self.wake_create_lock.unlock();
            if (self.wake_pipe[1] < 0) {
                self.wake_pipe = posix.pipe() catch return;
                // Both ends non-blocking: the read drain never stalls, and
                // a full pipe turns into EAGAIN ("a wake is already
                // pending") instead of blocking the caller (T236 deadlock).
                const nb: c_int = @bitCast(std.c.O{ .NONBLOCK = true });
                _ = std.c.fcntl(self.wake_pipe[0], std.c.F.SETFL, nb);
                _ = std.c.fcntl(self.wake_pipe[1], std.c.F.SETFL, nb);
                const ev = kev(@intCast(self.wake_pipe[0]), std.c.EVFILT.READ, std.c.EV.ADD, WAKE_UDATA);
                _ = posix.kevent(self.kq, &.{ev}, &.{}, null) catch {
                    posix.close(self.wake_pipe[0]);
                    posix.close(self.wake_pipe[1]);
                    self.wake_pipe = .{ -1, -1 };
                    return;
                };
            }
        }
        // Unconditional nonblocking byte: full? then a wake is pending by
        // definition (the level-triggered READ on a nonempty pipe always
        // re-fires the wait). The drain side empties the pipe fully.
        const n = posix.write(self.wake_pipe[1], &.{1}) catch 0;
        if (n == 1) _ = self.stats.wakes_written.fetchAdd(1, .monotonic);
    }

    pub fn stopAll(self: *Engine) void {
        var i: usize = 0;
        while (i < self.hi.load(.monotonic)) : (i += 1) {
            const slot = self.slotAt(@intCast(i)) orelse continue;
            if (slot.live) slot.session.destroy(self.allocator);
            slot.live = false;
        }
        self.live_count.store(0, .monotonic);
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
        return self.live_count.load(.monotonic);
    }

    /// Slot storage for a handle index, or null when the index is past the
    /// watermark (guard against fabricated handles aliasing the undefined
    /// tail of the newest chunk). Lock-free: chunk pointers are append-only
    /// until deinit.
    fn slotAt(self: *Engine, index: u32) ?*Slot {
        const i: usize = @intCast(index);
        if (i >= self.hi.load(.acquire)) return null;
        const chunk = self.chunks[i / CHUNK].load(.acquire) orelse return null;
        return &chunk[i % CHUNK];
    }

    /// Access a live session by its handle (from startSession/attachFd).
    /// Returns null for dead/reaped sessions and for stale handles.
    pub fn sessionAt(self: *Engine, h: Handle) ?*Session {
        const slot = self.slotAt(h.index) orelse return null;
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
        _ = self.stats.cmds_posted.fetchAdd(1, .monotonic);
        self.requestWake();
    }

    // ---- consumer timers ------------------------------------------------

    /// Run `cb(ctx, engine)` once on the engine thread after `delay_ms`
    /// (>= 0; 0 fires on the next loop pass). Returns a cancel token.
    /// Callable from any thread. As with foreign-thread startSession, a
    /// foreign caller must ensure the loop is running with work pending (or
    /// schedule before run()): a loop that already exited is not restarted.
    /// The callback may touch engine state directly; it runs on the loop.
    pub fn schedule(self: *Engine, delay_ms: i64, cb: TimerFn, ctx: ?*anyopaque) !usize {
        if (delay_ms < 0) return error.InvalidDelay;
        self.timers_lock.lock();
        defer self.timers_lock.unlock();
        // Tokens wrap through the TIMER window; a pending-timer collision scans
        // forward to the next free token (TIMER_MAX bounds concurrency, not
        // lifetime count).
        var tries: usize = 0;
        while (tries < TIMER_MAX) : (tries += 1) {
            const token = TIMER_UDATA - self.next_timer;
            self.next_timer = @mod(self.next_timer + 1, TIMER_MAX);
            if (self.timers.contains(token)) continue;
            try self.timers.put(self.allocator, token, .{ .cb = cb, .ctx = ctx });
            var tev = kev(token, std.c.EVFILT.TIMER, std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT, token);
            tev.data = delay_ms; // EVFILT_TIMER expiry sits in data (ms)
            // A map entry without a staged registration would keep the loop
            // alive forever with nothing to fire it.
            self.stageOrFail(tev) catch |err| {
                _ = self.timers.remove(token);
                return err;
            };
            return token;
        }
        return error.TimerLimit;
    }

    /// Cancel a pending timer from any thread. No-op for a fired or unknown
    /// token. A cancel racing a callback that is already running is lost,
    /// matching EV_ONESHOT semantics.
    pub fn cancelTimer(self: *Engine, token: usize) void {
        self.timers_lock.lock();
        defer self.timers_lock.unlock();
        if (self.timers.remove(token)) {
            self.stage(kev(token, std.c.EVFILT.TIMER, std.c.EV.DELETE, token));
        }
    }

    /// Pending consumer timers (keep-alive for the loop when every session
    /// is dead; e.g. reconnect backoff).
    pub fn timersPending(self: *Engine) usize {
        self.timers_lock.lock();
        defer self.timers_lock.unlock();
        return self.timers.count();
    }

    /// Dispatch one kevent from the consumer-timer udata window. An EV_ERROR
    /// receipt means the kernel rejected the change (errno in `data`): a
    /// failed EV_ADD drops the timer without running it and is logged; a
    /// failed EV_DELETE (entry already gone) is ignored.
    fn onTimerEvent(self: *Engine, ev: Kevent) void {
        if (ev.filter != std.c.EVFILT.TIMER) return;
        self.timers_lock.lock();
        const entry = self.timers.fetchRemove(ev.udata);
        self.timers_lock.unlock();
        const kv = entry orelse return;
        if (ev.flags & std.c.EV.ERROR != 0) {
            log.warn("consumer timer {d} rejected by kqueue (errno {d}); dropped without firing", .{ TIMER_UDATA - ev.udata, ev.data });
            return;
        }
        kv.value.cb(kv.value.ctx, self);
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
            // .start/.stop are exempt from the mailbox bound: both are
            // bounded by the session count itself, and dropping one would
            // leak the reservation / the teardown signal respectively.
            if (cmd == .stanza and self.cmd_active.items.len >= CMD_QUEUE_MAX)
                return error.CommandQueueFull;
            self.cmd_active.append(self.allocator, .{ .handle = h, .cmd = cmd }) catch return error.OutOfMemory;
        }
        _ = self.stats.cmds_posted.fetchAdd(1, .monotonic);
        self.requestWake();
    }

    /// Engine-thread: apply every posted command. Starts launch a slotted
    /// session's connect/DNS phase; stanzas route through Session.sendStanza
    /// (established guard lives there); stops fail the session. Drops are
    /// logged, never silent.
    fn drainCommands(self: *Engine) void {
        self.cmd_lock.lock();
        std.mem.swap(@TypeOf(self.cmd_active), &self.cmd_active, &self.cmd_spare);
        self.cmd_lock.unlock();
        var pending = &self.cmd_spare;
        defer {
            for (pending.items) |*c| self.cmdFree(c);
            pending.clearRetainingCapacity();
        }
        for (pending.items) |cmd| {
            _ = self.stats.cmds_drained.fetchAdd(1, .monotonic);
            switch (cmd.cmd) {
                .start => self.launchSession(cmd.handle),
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
                    if (self.sessionAt(cmd.handle)) |s|
                        s.fail(self.allocator, reason)
                    else
                        self.noteStopDropped();
                },
            }
        }
    }

    fn cmdFree(self: *Engine, c: *QueuedCmd) void {
        switch (c.cmd) {
            .stanza => |b| self.allocator.free(b),
            .stop => |r| self.allocator.free(r),
            .start => {},
        }
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

    /// Begin a client session — callable from ANY thread (T237). All config
    /// fields are arena-copied into the Session, so the caller's storage may
    /// be reused or freed immediately. Returns the session handle.
    ///
    /// The session is slotted (prepareSession) on the CALLER's thread. On
    /// the engine thread the launch runs inline (startSession before
    /// engine.run() keeps its old behavior); from any other thread the
    /// launch is posted to the command mailbox and executed by the loop —
    /// this is what lets consumers add sessions to a running engine, and
    /// what lets the load driver pace a ramp instead of herding.
    ///
    /// Connect/DNS failures surface as `.closed` events for the returned
    /// handle (a foreign-thread caller has no synchronous failure path).
    /// Hard errors (OOM, mailbox full, session-cap reached) are returned.
    pub fn startSession(self: *Engine, config: SessionConfig) !Handle {
        const h = try self.prepareSession(config);
        if (self.loop_tid.load(.acquire) == std.Thread.getCurrentId()) {
            self.launchSession(h);
            return h;
        }
        self.postCommand(h, .start) catch |err| {
            // Never reached the loop: nothing else knows the slot, reclaim it.
            if (self.sessionAt(h)) |s| s.destroy(self.allocator);
            self.freeSlot(h);
            return err;
        };
        return h;
    }

    /// Caller-thread prologue of startSession: build the Session, arena-copy
    /// the config, slot it live. The returned handle becomes observable to
    /// the engine through the command mailbox's lock ordering.
    fn prepareSession(self: *Engine, config: SessionConfig) !Handle {
        var s = try Session.init(self.allocator);
        s.engine = self;
        s.setConfig(config) catch {
            s.destroy(self.allocator);
            return error.OutOfMemory;
        };
        s.port = config.port;
        s.tls_policy = self.default_tls_policy;

        const h = try self.allocSlot();
        const slot = self.slotAt(h.index).?;
        slot.session = s;
        slot.session.handle = h;
        slot.live = true;
        _ = self.live_count.fetchAdd(1, .monotonic);
        return h;
    }

    /// Engine-thread continuation of startSession (inline, or the `.start`
    /// mailbox command). `host` as a literal IP connects immediately;
    /// otherwise DNS resolution runs asynchronously (SRV chain -> A/AAAA ->
    /// TLSA) on this loop and the session continues when the answer lands.
    fn launchSession(self: *Engine, h: Handle) void {
        const s = self.sessionAt(h) orelse return; // stopped before launch

        // Literal IP: skip DNS entirely (lab rigs, explicit endpoints).
        if (std.net.Address.parseIp(s.host, 0)) |_| {
            self.connectPrepared(s) catch {
                s.fail(self.allocator, "connect-failed");
            };
            return;
        } else |_| {}

        // Hostname: park the session in .resolving and hand the lookup to
        // the async resolver on THIS engine. Nothing blocks.
        if (self.resolver == null) {
            self.resolver = Resolver.init(self.allocator);
            self.resolver.?.setCallback(.{ .ctx = self, .fun = onDnsResult });
        }
        s.phase = .resolving;
        self.resolver.?.resolve(s.host, s.port, h.encode()) catch {
            s.fail(self.allocator, "resolve-error");
            return;
        };
        self.armResolverTick();
    }

    /// Wire a connected fd into an already-slotted session (engine thread):
    /// plain transport, both filters staged, bookkeeping in step
    /// (disarm/arm are idempotent guards).
    fn wireFd(self: *Engine, h: Handle, fd: posix.fd_t) void {
        const s = self.sessionAt(h).?;
        s.fd = fd;
        s.tport = Transport.initPlain(fd);
        s.phase = .connecting;
        s.write_registered = true;
        s.read_registered = true;
        self.addRead(fd, h);
        self.addWrite(fd, h);
    }

    /// Direct connect without DNS for a slotted session (literal IP).
    /// Engine thread only.
    fn connectPrepared(self: *Engine, s: *Session) !void {
        const addr_v4 = resolveHost(s.host) catch {
            return error.NameResolutionFailed;
        };
        var addr = addr_v4;
        addr.port = std.mem.nativeToBig(u16, s.port);
        const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0) catch |serr| {
            log.warn("socket() failed: {}", .{serr});
            return error.SocketCreate;
        };
        posix.connect(fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch |err| {
            if (err != error.WouldBlock) {
                log.warn("connect() to {s}:{d} failed immediately: {}", .{ s.host, s.port, err });
                posix.close(fd);
                return error.ConnectFailed;
            }
        };
        self.wireFd(s.handle, fd);
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
        const h = try self.prepareSession(config);
        self.wireFd(h, fd);
        return h;
    }

    fn allocSlot(self: *Engine) !Handle {
        self.slots_lock.lock();
        defer self.slots_lock.unlock();
        if (self.free_slots.items.len > 0) {
            const idx = self.free_slots.items[self.free_slots.items.len - 1];
            self.free_slots.items.len -= 1;
            const slot = &self.chunks[@intCast(idx / CHUNK)].load(.acquire).?[@intCast(idx % CHUNK)];
            return .{ .index = idx, .generation = slot.generation };
        }
        const hi = self.hi.load(.monotonic);
        if (hi >= CHUNK * MAX_CHUNKS) return error.TooManySessions;
        const c = hi / CHUNK;
        if (self.chunks[c].load(.acquire) == null) {
            const chunk = try self.allocator.create(Chunk);
            // Slots beyond the watermark stay live=false; publish the chunk
            // before the watermark moves.
            chunk.* = @splat(.{ .session = undefined, .generation = 0, .live = false });
            self.chunks[c].store(chunk, .release);
        }
        self.hi.store(hi + 1, .release);
        return .{ .index = @intCast(hi), .generation = 0 };
    }

    fn freeSlot(self: *Engine, h: Handle) void {
        self.slots_lock.lock();
        defer self.slots_lock.unlock();
        const slot = self.slotAt(h.index) orelse return;
        slot.live = false;
        slot.generation +%= 1;
        self.free_slots.append(self.allocator, h.index) catch {};
        _ = self.live_count.fetchSub(1, .monotonic);
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

    /// Run the kqueue loop on a dedicated thread. The loop lives while any
    /// session is live or any consumer timer is pending, so backoff timers
    /// keep the engine up after its last session dies. Consumers adding
    /// sessions from other threads (thread-safe startSession) must have a
    /// session or timer pending before calling run().
    pub fn run(self: *Engine) !void {
        self.run_gen +%= 1;
        self.waitLoopExit();
        const t = std.Thread.spawn(.{}, Engine.runLoop, .{self}) catch return error.ThreadSpawn;
        self.thread = t;
    }

    /// Run the kqueue loop inline on the caller thread until all sessions die.
    pub fn runSync(self: *Engine) !void {
        self.loop_tid.store(std.Thread.getCurrentId(), .release);
        defer self.loop_tid.store(0, .release);
        while (self.live_count.load(.monotonic) > 0 or self.timersPending() > 0) {
            self.loopOnce() catch {
                // kevent error — fail every session and stop rather than spin.
                var i: usize = 0;
                while (i < self.hi.load(.monotonic)) : (i += 1) {
                    const slot = self.slotAt(@intCast(i)) orelse continue;
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
        self.loop_tid.store(std.Thread.getCurrentId(), .release);
        defer self.loop_tid.store(0, .release);
        while ((self.live_count.load(.monotonic) > 0 or self.timersPending() > 0) and self.run_gen == gen) {
            self.loopOnce() catch break;
            self.reapDead();
        }
    }

    fn loopOnce(self: *Engine) !void {
        const t_iter_start = std.time.nanoTimestamp();
        // Drain the self-pipe first: a wake is a "re-examine" request, not
        // data. Clear the coalescing flag BEFORE reading so a concurrent
        // writer's false->true transition always lands its byte
        // (post-write the level-triggered READ re-fires the wait anyway).
        // The read end is non-blocking, so the drain terminates on EAGAIN.
        if (self.wake_pipe[0] >= 0) {
            self.wake_pending.store(false, .release);
            var wbuf: [128]u8 = undefined;
            while (true) {
                const r = posix.read(self.wake_pipe[0], &wbuf) catch break;
                _ = self.stats.wakes_read.fetchAdd(@intCast(r), .monotonic);
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
        // Nothing armed: never wait.
        if (self.live_count.load(.monotonic) == 0 and self.timersPending() == 0) return;
        // Fold everything staged since the last iteration into THIS kevent:
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
        // Wakes are coalesced, so changes left past this batch have no wake
        // of their own and would wait for an unrelated event. While a
        // backlog remains, this kevent() still applies its batch and returns
        // ready events, but does not block.
        const backlog = self.changes.items.len > 0;
        self.changes_lock.unlock();
        const no_block = posix.timespec{ .sec = 0, .nsec = 0 };

        const t_wait_start = std.time.nanoTimestamp();
        const n = posix.kevent(self.kq, staged[0..staged_count], &evbuf, if (backlog) &no_block else null) catch {
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
            // Consumer timer window: dispatch the callback and consume the
            // map entry (EV_ONESHOT already dropped the registration). A
            // cancelled timer whose event raced the DELETE finds no entry.
            if (ev.udata <= TIMER_UDATA and ev.udata > TIMER_UDATA - TIMER_MAX) {
                self.onTimerEvent(ev);
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
        var i: usize = 0;
        while (i < self.hi.load(.monotonic)) : (i += 1) {
            const slot = self.slotAt(@intCast(i)) orelse continue;
            if (!slot.live) continue;
            if (slot.session.alive) continue;
            slot.session.destroy(self.allocator);
            self.noteReap();
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
        self.stageOrFail(ev) catch {};
    }

    /// `stage` for callers that must not lose the change (consumer timers).
    fn stageOrFail(self: *Engine, ev: Change) !void {
        self.changes_lock.lock();
        defer self.changes_lock.unlock();
        try self.changes.append(self.allocator, ev);
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

test "engine: startSession from a foreign thread launches via the mailbox (T237)" {
    const alloc = std.testing.allocator;
    var eng = try Engine.init(alloc);
    defer eng.deinit();

    const Probe = struct {
        closes: std.atomic.Value(u32) = .init(0),
        fn onEvent(ctx: ?*anyopaque, _: *Engine, _: Handle, ev: Event) void {
            const p: *@This() = @ptrCast(@alignCast(ctx.?));
            if (ev == .closed) _ = p.closes.fetchAdd(1, .monotonic);
        }
    };
    var probe = Probe{};
    eng.setEventHandler(Probe.onEvent, &probe);

    // Started from the main thread while the loop is not ours: the session
    // must be slotted synchronously but launched by the loop thread.
    const h = try eng.startSession(.{
        .host = "127.0.0.1", // nothing listens here: the launch fails fast
        .port = 1,
        .domain = "localhost",
        .user = "u",
        .password = "p",
        .resource = "r",
    });
    try std.testing.expect(eng.slotAt(h.index) != null);

    try eng.run();
    eng.waitLoopExit(); // joins once the refused session has been reaped
    try std.testing.expectEqual(@as(u32, 1), probe.closes.load(.monotonic));
}

test "engine: wake pipe never blocks on un-read staged changes (T236)" {
    const alloc = std.testing.allocator;
    var eng = try Engine.init(alloc);
    defer eng.deinit();

    // No loop is running: with a blocking write end the 16 KiB pipe fills
    // after ~8192 of these and the caller hangs forever (pre-fix behavior).
    // Nonblocking unconditional writes may fill the pipe — that is safe by
    // construction (a nonempty pipe keeps READ armed; EAGAIN is a no-op).
    const h = Handle{ .index = 0, .generation = 0 };
    var i: usize = 0;
    while (i < 20000) : (i += 1) eng.addRead(999_999, h);

    var wbuf: [128]u8 = undefined;
    try std.testing.expect((try posix.read(eng.wake_pipe[0], &wbuf)) > 0);
    eng.requestWake();
    // Drain to empty; a post-drain wake must leave exactly one byte.
    var drained: usize = 0;
    while (posix.read(eng.wake_pipe[0], &wbuf)) |r| {
        drained += r;
        if (drained >= 1 << 20) break;
    } else |_| {}
    const before = eng.stats.wakes_written.load(.monotonic);
    eng.requestWake();
    try std.testing.expect(eng.stats.wakes_written.load(.monotonic) > before);
    try std.testing.expectEqual(@as(usize, 1), try posix.read(eng.wake_pipe[0], &wbuf));

    // requestWake from the thread the loop runs on must not write.
    eng.loop_tid.store(std.Thread.getCurrentId(), .release);
    defer eng.loop_tid.store(0, .release);
    eng.requestWake();
    try std.testing.expectError(error.WouldBlock, posix.read(eng.wake_pipe[0], &wbuf));
}

fn countingTimerCb(ctx: ?*anyopaque, engine: *Engine) void {
    _ = engine;
    const n: *usize = @ptrCast(@alignCast(ctx.?));
    n.* += 1;
}

test "engine: schedule rejects a negative delay without arming anything" {
    const alloc = std.testing.allocator;
    var eng = try Engine.init(alloc);
    defer eng.deinit();
    var fired: usize = 0;
    try std.testing.expectError(error.InvalidDelay, eng.schedule(-1, countingTimerCb, &fired));
    try std.testing.expectEqual(@as(usize, 0), eng.timersPending());
    eng.changes_lock.lock();
    defer eng.changes_lock.unlock();
    try std.testing.expectEqual(@as(usize, 0), eng.changes.items.len);
}

test "engine: timer EV_ERROR receipt drops the timer without firing it" {
    const alloc = std.testing.allocator;
    var eng = try Engine.init(alloc);
    defer eng.deinit();
    var fired: usize = 0;
    const rejected = try eng.schedule(10, countingTimerCb, &fired);
    const ok = try eng.schedule(10, countingTimerCb, &fired);

    // Kernel rejection of the EV_ADD: flags EV_ERROR, errno in data.
    var receipt = kev(rejected, std.c.EVFILT.TIMER, std.c.EV.ERROR, rejected);
    receipt.data = @intFromEnum(posix.E.NOMEM);
    eng.onTimerEvent(receipt);
    try std.testing.expectEqual(@as(usize, 0), fired);
    try std.testing.expectEqual(@as(usize, 1), eng.timersPending());

    // Receipt for a token with no entry (e.g. EV_DELETE after dispatch): inert.
    eng.onTimerEvent(receipt);
    try std.testing.expectEqual(@as(usize, 0), fired);

    // A real expiry still fires the other timer exactly once.
    const expiry = kev(ok, std.c.EVFILT.TIMER, 0, ok);
    eng.onTimerEvent(expiry);
    eng.onTimerEvent(expiry);
    try std.testing.expectEqual(@as(usize, 1), fired);
    try std.testing.expectEqual(@as(usize, 0), eng.timersPending());
}
