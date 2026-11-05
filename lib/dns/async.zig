//! # lib/dns/async.zig - shared async resolver (X2, Phorge T276)
//!
//! A reusable asynchronous DNS resolver:
//!
//! - Responses are demuxed on (id, qname, qtype) together (T296), never
//!   on the id alone.
//! - `Service` selects the SRV prefix pair: client = _xmpps-client then
//!   _xmpp-client; server = _xmpps-server then _xmpp-server (XEP-0368).
//! - Raw record queries (A/AAAA/SRV/TLSA) via `query()`; `resolve()` is
//!   the SRV->addr->TLSA chain on top of them.
//! - Multiple SRV targets are ordered per RFC 2782 (priority, then
//!   weighted-random by weight).
//! - A truncated (TC) UDP answer retries the same query over TCP.
//! - Each pending query carries a one-shot EVFILT_TIMER deadline on the
//!   resolver's own kqueue; there is no polling and no sleeping.
//! - A bounded per-(qname,qtype) cache honors record TTLs.
//!
//! The resolver owns a kqueue; `step(0)` pumps socket I/O and fired
//! timers without blocking so any event loop can drive it.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const dns = @import("dns");
const wire = @import("wire");
const net = std.net;

const log = std.log.scoped(.dns_async);

const KIND_SRV = wire.TYPE_SRV;
const KIND_A = wire.TYPE_A;
const KIND_AAAA = wire.TYPE_AAAA;
const KIND_TLSA = wire.TYPE_TLSA;
const KIND_SOA: u16 = 6;

const TIMEOUT_MS: i64 = 2000;
const MAX_TRIES: u8 = 2;
const TCP_TIMEOUT_MS: i64 = 4000;
/// Bound on a whole resolve() chain across every SRV target; the
/// per-query deadline still applies inside it.
const CHAIN_DEADLINE_MS: i64 = 10_000;
const MAX_JOBS: usize = 64;
/// Flattened connect targets per resolution; a hostile SRV answer
/// cannot grow a job's target list past this.
const TARGET_CAP: usize = 16;
/// Parsed SRV entries kept per job, bounded at absorb time: twice the
/// emitted cap so per-target failures still leave targets to try.
const SRV_CAP: usize = 32;
/// Cache TTL ceiling: positive and negative entries alike are
/// expired after five minutes regardless of the advertised TTL.
const CACHE_TTL_CEIL_S: u32 = 300;
/// Per-worker cache bounds (ADR-13: "sized for federation"): at most
/// CACHE_ENTRIES_MAX owner names and CACHE_BYTES_MAX accounted bytes
/// (owner name + rdata + per-entry overhead). Eviction on insert
/// prefers stale rows over fresh and falls back to the LRU tail.
const CACHE_ENTRIES_MAX: usize = 4096;
const CACHE_BYTES_MAX: usize = 4 * 1024 * 1024;
/// RFC 8767: a stale answer is servable for at most one day past
/// expiry, and a failed refresh is not retried inside 30 s.
const STALE_MAX_MS: i64 = 86_400_000;
const STALE_RECHECK_MS: i64 = 30_000;
/// The stale-serve log line is emitted at most once per window and
/// owner name.
const STALE_LOG_MS: i64 = 60_000;
/// How many LRU nodes evictOne may walk looking for a stale owner
/// before it settles for the window's tail-most unpinned fresh one;
/// the bound lifts while every node seen is pinned.
const EVICT_SCAN_MAX: usize = 32;

pub const Service = enum(u8) { client = 0, server = 1 };

const SRV_TLS = [2][]const u8{ "_xmpps-client._tcp", "_xmpps-server._tcp" };
const SRV_PLAIN = [2][]const u8{ "_xmpp-client._tcp", "_xmpp-server._tcp" };

pub const RType = enum(u16) { a = KIND_A, aaaa = KIND_AAAA, srv = KIND_SRV, tlsa = KIND_TLSA };

/// Per-target DANE outcome (ADR-13). `tlsa` is empty for both .absent
/// and .lookup_failed, so this word is authoritative: only .absent
/// (NXDOMAIN/NODATA) permits PKIX fallback, while .lookup_failed is a
/// temporary failure of the target - never PKIX.
pub const TlsaStatus = enum { absent, present, lookup_failed };

pub const Target = struct {
    addr: net.Address,
    host: []const u8, // owned
    tlsa: []dns.TlsaRecord, // owned; empty when none
    tlsa_status: TlsaStatus,
    is_direct_tls: bool,
};

pub const Resolution = struct {
    targets: []Target = &.{},

    pub fn deinitOn(self: *Resolution, alloc: std.mem.Allocator) void {
        for (self.targets) |t| {
            alloc.free(t.host);
            for (t.tlsa) |r| alloc.free(r.association_data);
            if (t.tlsa.len > 0) alloc.free(t.tlsa);
        }
        if (self.targets.len > 0) alloc.free(self.targets);
        self.* = .{};
    }
};

/// Raw record result for query(). The rrs array and every rr's name and
/// rdata are owned; free with deinitOn.
pub const RecordResult = struct {
    rrs: []wire.Rr = &.{},
    ttl: u32 = 0,

    pub fn deinitOn(self: *RecordResult, alloc: std.mem.Allocator) void {
        for (self.rrs) |rr| {
            alloc.free(rr.name);
            alloc.free(rr.rdata);
        }
        if (self.rrs.len > 0) alloc.free(self.rrs);
        self.* = .{};
    }
};

/// service_unavailable: every SRV target was ".", RFC 2782's way of
/// publishing "no such service on this domain" - distinct from the
/// domain itself being missing (nxdomain).
pub const Status = enum { resolved, nxdomain, service_unavailable, failed };

pub const Cb = struct {
    ctx: ?*anyopaque,
    fun: *const fn (ctx: ?*anyopaque, session_key: usize, status: Status, res: ?Resolution) void,
};

/// Completion for raw record queries.
pub const QueryCb = struct {
    ctx: ?*anyopaque,
    fun: *const fn (ctx: ?*anyopaque, session_key: usize, status: Status, res: ?RecordResult) void,
};

const Phase = enum { srv_tls, srv_plain, addr, addr6, tlsa, fallback_addr, fallback_addr4, fallback_tlsa, raw, done };

/// Phases that serve the SRV target at srv_pos; a failure inside one
/// dooms only that target, never the whole job.
fn isTargetPhase(phase: Phase) bool {
    return switch (phase) {
        .addr, .addr6, .tlsa => true,
        else => false,
    };
}

/// Session keys sharing one in-flight job. Bounded inline: a full
/// job takes no more waiters and the lookup starts a fresh job.
const MAX_WAITERS: usize = 16;

const Job = struct {
    /// Session keys waiting on this job; identical in-flight lookups
    /// share one job and every waiter still gets its own callback.
    waiters: [MAX_WAITERS]usize = undefined,
    waiter_count: usize = 0,
    /// Bit per waiter slot, set by cancel() while this job's callbacks
    /// are already firing: the completion loop skips marked waiters.
    /// Only meaningful on the job under in_callback; never survives.
    waiter_cancelled: u16 = 0,
    name: []const u8, // owned
    phase: Phase,
    service_idx: u8 = 0,
    is_raw: bool = false,
    /// Index into the resolver's slot table; paired with `gen` so a
    /// queued timer event can be told apart from a live job.
    slot: u8 = 0,
    gen: u16 = 0,
    /// Port used when the SRV chain yields nothing and the fallback
    /// address path runs.
    default_port: u16 = 0,
    /// TLSA lookups cost one round trip per target; callers that
    /// cannot use DANE (plain transports) skip them entirely.
    want_tlsa: bool = false,

    srv_list: std.ArrayListUnmanaged(SrvEnt) = .{},
    srv_pos: usize = 0,
    /// A fallback address query that hard-failed (timeout, SERVFAIL):
    /// when neither family yields an address this decides between
    /// .failed and .nxdomain.
    fallback_err: bool = false,
    /// A per-target address query that hard-failed (timeout, SERVFAIL,
    /// a dead TCP leg): when every SRV target is consumed without an
    /// address this decides between .failed and .nxdomain the way
    /// fallback_err does for the fallback path. NXDOMAIN is reserved
    /// for authoritative absences; the s2s retry treats it as
    /// permanent while a wire failure is temporary.
    target_err: bool = false,
    /// Addresses collected for the current SRV target across the A
    /// and AAAA phases.
    cur_addr4: ?net.Address = null,
    cur_addr6: ?net.Address = null,

    // Wire state for the outstanding query.
    dns_id: u16 = 0,
    pending_qname: []const u8 = "", // owned
    pending_qtype: u16 = 0,
    request: []u8 = &.{},
    /// Sends of the outstanding query on its current transport. UDP:
    /// the first send plus retransmits, one per deadline at
    /// TIMEOUT_MS. The TC upgrade to TCP resets it to 0 and arms
    /// TCP_TIMEOUT_MS; a later chain query on the TCP leg starts at 1
    /// under TIMEOUT_MS, so it retries once, not the full UDP budget.
    tries: u8 = 0,
    use_tcp: bool = false,
    tcp_fd: posix.fd_t = -1,
    tcp_buf: std.ArrayListUnmanaged(u8) = .{},
    /// Outbound TCP frame staged once and flushed incrementally;
    /// tcp_connected marks whether connect() has completed.
    tcp_out: std.ArrayListUnmanaged(u8) = .{},
    tcp_out_pos: usize = 0,
    tcp_connected: bool = false,
    /// Per-socket nonce stamped into TCP knote udata: close() then
    /// socket() reuses fd numbers, so an event queued for an earlier
    /// connection is told apart from the new one by this count.
    tcp_seq: u8 = 0,
    /// Whether the outstanding query was already re-sent once after
    /// the peer closed the connection (RFC 7766 close-after-answer);
    /// a second close on the same query fails the phase instead.
    tcp_eof_resent: bool = false,

    /// The stale cache row the outstanding wire query refreshes; the
    /// row stays pinned (refreshing) for the job's life so eviction
    /// cannot free the borrow, and a wire failure serves it to the
    /// waiters (RFC 8767).
    stale: ?CacheHit = null,
    /// A refresh job past its waiters: they were answered from stale
    /// at the per-query deadline, so the job takes no new waiters and
    /// its wire query only updates the cache row.
    refresh_only: bool = false,

    targets: std.ArrayListUnmanaged(Target) = .{},
};

const SrvEnt = struct {
    host: []const u8 = "", // owned
    port: u16 = 0,
    priority: u16 = 0,
    weight: u16 = 0,
    is_direct_tls: bool = false,
    addr: ?net.Address = null,
    /// RFC 2782: a "." target means the service is unavailable here.
    unavailable: bool = false,
};

/// Negative cache flavor: the name is absent (nxdomain) or the name
/// exists without records of the asked type (nodata).
const NegKind = enum { none, nxdomain, nodata };

/// One cached RRset (or negative answer) per owner and qtype.
/// expires_ms ends the fresh window; stale_ms ends the serve-stale
/// window at expires_ms + STALE_MAX_MS (RFC 8767 one-day cap).
/// last_fail_ms stamps the most recent failed refresh for the
/// STALE_RECHECK_MS suppression rule; refreshing marks a wire refresh
/// in flight: the row is pinned (a job may hold a borrowed pointer to
/// it) and a second refresh is never started alongside it.
const TypeEnt = struct {
    rtype: u16,
    neg: NegKind = .none,
    rrs: []wire.Rr = &.{}, // names and rdata owned per record
    expires_ms: i64 = 0,
    stale_ms: i64 = 0,
    /// minInt so a never-attempted row reads as "failed long ago"
    /// under the saturating recheck compare: uptime below
    /// STALE_RECHECK_MS would otherwise read as a recent failure.
    last_fail_ms: i64 = std.math.minInt(i64),
    refreshing: bool = false,
};

/// Cache owner: every type row for one folded qname, its LRU node and
/// its accounted bytes. Type rows are heap objects so a pointer stays
/// valid across row inserts and removals while a refresh pins it.
const OwnerEnt = struct {
    name: []u8, // folded qname, owned; also the map key
    node: std.DoublyLinkedList.Node = .{},
    types: std.ArrayListUnmanaged(*TypeEnt) = .{},
    bytes: usize = 0,
    /// Rate limiter for the stale-serve log line, per owner name;
    /// minInt so the first serve always logs, even at low uptime.
    stale_log_ms: i64 = std.math.minInt(i64),
};

/// A located cache row plus its owner, so stale serving can account
/// and log per owner name.
const CacheHit = struct { owner: *OwnerEnt, ent: *TypeEnt };

/// cacheGetClass verdicts: a fresh row serves at once; a stale row
/// serves only through the RFC 8767 refresh rules.
const CacheClass = union(enum) { fresh: CacheHit, stale: CacheHit };

/// A request waiting for an in-flight job slot.
const WaitEnt = struct {
    session_key: usize = 0,
    name: []u8 = &.{}, // owned
    kind: enum { resolve, query },
    service_idx: u8 = 0,
    default_port: u16 = 0,
    want_tlsa: bool = false,
    rtype: u16 = 0,
};

const WAIT_CAP: usize = 256;

pub const Resolver = struct {
    alloc: std.mem.Allocator,
    fd: posix.fd_t = -1,
    kq: posix.fd_t = -1,
    server: net.Address = undefined,
    server_configured: bool = false,
    /// Path read once at init; a field so tests can point at a fixture
    /// instead of the host resolver configuration.
    resolv_conf_path: []const u8 = "/etc/resolv.conf",
    jobs: std.ArrayListUnmanaged(*Job) = .{},
    /// Slot table for event udata: a queued deadline or TCP socket
    /// event carries (gen, slot) so a job freed by an earlier event in
    /// the same kevent batch is recognized as stale and never touched.
    slots: [MAX_JOBS]?*Job = .{null} ** MAX_JOBS,
    slot_gen: [MAX_JOBS]u16 = .{0} ** MAX_JOBS,
    /// Seeded from the CSPRNG; drives only the RFC 2782 weighted picks
    /// so tests can reseed for deterministic draws. Query ids come from
    /// the CSPRNG per send, never from a seeded PRNG sequence.
    prng: std.Random.DefaultPrng = std.Random.DefaultPrng.init(0),
    cb: Cb = .{ .ctx = null, .fun = noopCallback },
    qcb: QueryCb = .{ .ctx = null, .fun = noopQueryCallback },
    /// The RR and negative cache: folded owner name -> OwnerEnt, an
    /// intrusive owner LRU (MRU head) and the accounted byte total.
    /// Bounded by CACHE_ENTRIES_MAX and CACHE_BYTES_MAX; a hit hashes
    /// a stack-folded name and never allocates (ADR-13, RFC 8767).
    owners: std.StringHashMapUnmanaged(*OwnerEnt) = .{},
    lru: std.DoublyLinkedList = .{},
    cache_bytes: usize = 0,
    /// Stale answers served (RFC 8767); counted for observability.
    stale_serves: usize = 0,
    /// Requests queued behind a full in-flight set; promoted FIFO as
    /// jobs complete.
    wait_queue: std.ArrayListUnmanaged(WaitEnt) = .{},
    /// Whole-chain deadline for resolve() jobs; a field so tests can
    /// shrink it instead of sleeping ten seconds.
    chain_deadline_ms: i64 = CHAIN_DEADLINE_MS,
    /// Monotonic clock for cache expiry; a field so tests can pin
    /// time instead of sleeping on real TTLs.
    now_ms: *const fn () i64 = nowMs,
    /// Requests rejected because the wait queue was full; observability
    /// for a queue that silently dropping would otherwise hide.
    too_many_jobs: usize = 0,
    /// Wire observability: replies too short to demux, replies that
    /// match no in-flight job (late or mismatched), stale ICMP refusals
    /// charged to a later send, and unexpected socket errors.
    malformed_replies: usize = 0,
    unmatched_replies: usize = 0,
    stale_icmp: usize = 0,
    /// Test seam: report every UDP send as failed (see sendUdp).
    fail_sends: if (builtin.is_test) bool else void = if (builtin.is_test) false else {},
    /// Test seam: refuse the next N TCP connects synchronously (see
    /// tcpSend); FreeBSD does this on real wire paths.
    fail_connects: if (builtin.is_test) usize else void = if (builtin.is_test) 0 else {},
    /// Test seam: leave every TCP connect pending (see tcpSend); an
    /// unconnected stream socket is never writable, so the armed
    /// WRITE knote stays quiet and the connect never races a refusal.
    pend_connects: if (builtin.is_test) bool else void = if (builtin.is_test) false else {},
    /// Test seam: report every knote registration as failed (see
    /// keventApplyChecked); covers the ensureOpen failure ordering.
    fail_kevents: if (builtin.is_test) bool else void = if (builtin.is_test) false else {},
    /// kevent() errors seen inside step(); the first is logged so a
    /// dead kqueue cannot fail silently while the caller's loop spins.
    kevent_errors: usize = 0,
    udp_errors: usize = 0,
    /// The job currently firing completion callbacks, or null. Set
    /// inside a dropJob/complete/completeRaw waiter loop, after the
    /// job is already off `jobs`, so a cancel() issued from inside a
    /// callback can still mark the job's remaining waiters. Loops
    /// restore the previous value on exit: a callback that completes
    /// another job synchronously (a cached resolve) must not lose the
    /// outer job's cancel marks. One slot, not a stack: a cancel of
    /// the doubly-outer job issued from inside a doubly-nested
    /// callback cannot be tracked this way.
    in_callback: ?*Job = null,

    fn noopCallback(_: ?*anyopaque, _: usize, _: Status, _: ?Resolution) void {}
    fn noopQueryCallback(_: ?*anyopaque, _: usize, _: Status, _: ?RecordResult) void {}

    pub fn init(alloc: std.mem.Allocator) Resolver {
        var r = Resolver{ .alloc = alloc, .prng = std.Random.DefaultPrng.init(std.crypto.random.int(u64)) };
        // Nameserver configuration is loaded here, off the event loop;
        // after init, ensureOpen only ever fails fast.
        r.loadResolvConf();
        return r;
    }

    /// Read the configured resolv.conf into `server`; a missing or
    /// unparseable file leaves the resolver unconfigured, which
    /// ensureOpen reports as error.NoResolver.
    pub fn loadResolvConf(self: *Resolver) void {
        if (readResolvConf(self.alloc, self.resolv_conf_path)) |addr| {
            self.server = addr;
            self.server_configured = true;
        } else |_| {}
    }

    pub fn deinit(self: *Resolver) void {
        for (self.jobs.items) |j| self.freeJob(j);
        self.jobs.deinit(self.alloc);
        for (self.wait_queue.items) |e| self.alloc.free(e.name);
        self.wait_queue.deinit(self.alloc);
        var owner_it = self.owners.iterator();
        while (owner_it.next()) |e| self.freeOwner(e.value_ptr.*);
        self.owners.deinit(self.alloc);
        if (self.fd >= 0) posix.close(self.fd);
        if (self.kq >= 0) posix.close(self.kq);
    }

    pub fn setServer(self: *Resolver, addr: net.Address) void {
        self.server = addr;
        self.server_configured = true;
    }

    pub fn setCallback(self: *Resolver, cb: Cb) void {
        self.cb = cb;
    }

    pub fn setQueryCallback(self: *Resolver, cb: QueryCb) void {
        self.qcb = cb;
    }

    /// UDP socket fd - callers may register it on their own loop and call
    /// step(0) when it reads; deadlines still fire via step().
    pub fn sockFd(self: *const Resolver) posix.fd_t {
        return self.fd;
    }

    /// The resolver's own kqueue. A kqueue fd is itself EVFILT_READ-
    /// able on a parent kqueue (it reports when events are pending),
    /// so an embedding loop can watch this single fd and call step(0)
    /// instead of shadow-registering the UDP socket and a tick.
    pub fn kqFd(self: *const Resolver) posix.fd_t {
        return self.kq;
    }

    /// Raw record query: A, AAAA, SRV or TLSA answered via the query
    /// callback with owned RRs. A cache hit or an unencodable name
    /// fires that callback inside query() before it returns.
    pub fn query(self: *Resolver, name: []const u8, rtype: RType, session_key: usize) !void {
        // RFC 7622 3.2, same as resolve(): a trailing dot on a
        // domainpart is absent, so an FQDN queries like the bare name.
        const fqdn = if (name.len > 0 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
        const qt: u16 = @intFromEnum(rtype);
        if (self.cacheGetClass(fqdn, qt)) |class| switch (class) {
            .fresh => |hit| {
                const ent = hit.ent;
                switch (ent.neg) {
                    .nxdomain => self.qcb.fun(self.qcb.ctx, session_key, .nxdomain, null),
                    .nodata => self.qcb.fun(self.qcb.ctx, session_key, .resolved, .{ .rrs = &.{}, .ttl = 0 }),
                    .none => {
                        const rrs = try self.dupRrs(ent.rrs);
                        const ttl_ms = @max(0, ent.expires_ms - self.now_ms());
                        self.qcb.fun(self.qcb.ctx, session_key, .resolved, .{ .rrs = rrs, .ttl = @intCast(ttl_ms / 1000) });
                    },
                }
                return;
            },
            .stale => |hit| {
                // A refresh already running or attempted inside the
                // recheck window serves the stale row at once; no
                // job slot is needed to answer from the cache.
                const now = self.now_ms();
                if (hit.ent.refreshing or now -| hit.ent.last_fail_ms < STALE_RECHECK_MS) {
                    try self.answerStaleNow(hit, session_key);
                    return;
                }
                // Otherwise this lookup starts the wire refresh.
            },
        };
        try self.ensureOpen();
        if (self.slotsFull()) {
            // ADR-13: a refresh never starves a client lookup the
            // cache could answer, so a waiterless refresh-only job
            // yields its slot first.
            _ = self.reclaimRefreshOnly();
        }
        if (self.slotsFull()) {
            try self.enqueueWait(session_key, fqdn, .{ .kind = .query, .rtype = qt });
            return;
        }
        const job = try self.allocJob(session_key, fqdn);
        job.phase = .raw;
        job.is_raw = true;
        {
            errdefer self.freeJob(job);
            try self.jobs.append(self.alloc, job);
        }
        // A cache hit inside sendQuery can complete and free the job
        // synchronously; after this call `job` may not be touched.
        self.sendQuery(job, fqdn, qt) catch |err| {
            self.abortJob(job);
            return err;
        };
    }

    /// Queue a request behind the in-flight cap; promoted FIFO by
    /// promoteWait as jobs complete.
    fn enqueueWait(self: *Resolver, session_key: usize, name: []const u8, opts: WaitEnt) !void {
        if (self.wait_queue.items.len >= WAIT_CAP) {
            self.too_many_jobs += 1;
            return error.TooManyJobs;
        }
        var e = opts;
        e.session_key = session_key;
        e.name = try self.alloc.dupe(u8, name);
        try self.wait_queue.append(self.alloc, e);
    }

    /// In-flight capacity is the slot table, not `jobs`: a job
    /// firing its completion callbacks already left `jobs` but
    /// still holds its slot until freeJob runs after the last
    /// callback, so a lookup issued from inside a callback must
    /// see the table as full.
    fn slotsFull(self: *const Resolver) bool {
        for (self.slots) |s| {
            if (s == null) return false;
        }
        return true;
    }

    /// Launch the head of the wait queue now that a job slot opened.
    /// A launch that fails answers the waiter's callback with .failed;
    /// there is no error return this deep in the pump. A queued
    /// lookup still outranks a waiterless refresh-only job, so a
    /// full table sheds one before the head is launched.
    fn promoteWait(self: *Resolver) void {
        while (self.wait_queue.items.len > 0) {
            if (self.slotsFull() and !self.dropRefreshOnly()) break;
            const e = self.wait_queue.orderedRemove(0);
            defer self.alloc.free(e.name);
            switch (e.kind) {
                .query => self.launchQuery(e),
                .resolve => self.launchResolve(e),
            }
        }
    }

    fn launchQuery(self: *Resolver, e: WaitEnt) void {
        const job = self.allocJob(e.session_key, e.name) catch {
            self.qcb.fun(self.qcb.ctx, e.session_key, .failed, null);
            return;
        };
        job.phase = .raw;
        job.is_raw = true;
        self.jobs.append(self.alloc, job) catch {
            self.freeJob(job);
            self.qcb.fun(self.qcb.ctx, e.session_key, .failed, null);
            return;
        };
        self.sendQuery(job, e.name, e.rtype) catch self.dropJob(job, .failed);
    }

    fn launchResolve(self: *Resolver, e: WaitEnt) void {
        const job = self.allocJob(e.session_key, e.name) catch {
            self.cb.fun(self.cb.ctx, e.session_key, .failed, null);
            return;
        };
        job.phase = .srv_tls;
        job.service_idx = e.service_idx;
        job.default_port = e.default_port;
        job.want_tlsa = e.want_tlsa;
        self.jobs.append(self.alloc, job) catch {
            self.freeJob(job);
            self.cb.fun(self.cb.ctx, e.session_key, .failed, null);
            return;
        };
        self.armChainDeadline(job) catch return self.dropJob(job, .failed);
        self.sendSrv(job, SRV_TLS[job.service_idx]) catch self.dropJob(job, .failed);
    }

    /// Release a session's interest: detach the waiter from every job
    /// (freeing a job when it was the last waiter, which disarms its
    /// deadlines and purges its slot so a queued timer event is
    /// stale) and drop any not-yet-launched queue entries. No
    /// callback fires for the key afterwards.
    pub fn cancel(self: *Resolver, session_key: usize) void {
        // A callback already in flight may cancel a sibling waiter of
        // the job being completed; that job is off `jobs` already, so
        // mark its waiter bits and let the completion loop skip them.
        if (self.in_callback) |job| {
            for (job.waiters[0..job.waiter_count], 0..) |k, w| {
                if (k == session_key) job.waiter_cancelled |= @as(u16, 1) << @intCast(w);
            }
        }

        // Purge the wait queue first: freeing a job below promotes its
        // head, and a queued entry of the cancelled key must never be
        // launched (its callback could otherwise fire from the cache).
        var qi: usize = 0;
        while (qi < self.wait_queue.items.len) {
            if (self.wait_queue.items[qi].session_key == session_key) {
                const removed = self.wait_queue.orderedRemove(qi);
                self.alloc.free(removed.name);
                continue;
            }
            qi += 1;
        }
        var i: usize = 0;
        while (i < self.jobs.items.len) {
            const job = self.jobs.items[i];
            var w: usize = 0;
            while (w < job.waiter_count) : (w += 1) {
                if (job.waiters[w] == session_key) {
                    job.waiters[w] = job.waiters[job.waiter_count - 1];
                    job.waiter_count -= 1;
                    break;
                }
            }
            // A refresh-only job has no waiters by definition; it
            // dies with its wire query or the chain deadline.
            if (job.waiter_count == 0 and !job.refresh_only) {
                // A cancelled refresh is not a failed one: unpin the
                // borrowed row without stamping last_fail_ms, so the
                // next lookup refreshes at once instead of serving
                // stale inside the recheck window.
                if (job.stale) |hit| {
                    hit.ent.refreshing = false;
                    job.stale = null;
                }
                _ = self.jobs.orderedRemove(i);
                self.freeJob(job);
                self.promoteWait();
                continue; // the list shifted; re-examine slot i
            }
            i += 1;
        }
    }

    /// SRV chain resolve. Literal IPs complete synchronously with one
    /// target (no UDP traffic).
    /// The callback may fire before resolve() returns: literal IPs,
    /// cache hits, and names that cannot be encoded or staged (the
    /// "async nxdomain" paths) all complete inside the call.
    /// want_tlsa: fetch TLSA records per target (_port._tcp.<target>)
    /// when the caller can authenticate with them; false callers get
    /// the same addresses without the extra round trips.
    pub fn resolve(self: *Resolver, name: []const u8, service: Service, default_port: u16, session_key: usize, want_tlsa: bool) !void {
        // RFC 7622 3.2: a trailing dot on a domainpart is absent, so an
        // FQDN resolves like the bare name.
        const fqdn = if (name.len > 0 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
        if (net.Address.parseIp(fqdn, default_port)) |addr| {
            const t = Target{ .addr = addr, .host = try self.alloc.dupe(u8, fqdn), .tlsa = &.{}, .tlsa_status = .absent, .is_direct_tls = false };
            const list = try self.alloc.alloc(Target, 1);
            list[0] = t;
            self.cb.fun(self.cb.ctx, session_key, .resolved, .{ .targets = list });
            return;
        } else |_| {}

        try self.ensureOpen();
        // An identical in-flight lookup takes another waiter instead of
        // a second job on the wire. want_tlsa joins the merge key: a
        // TLSA-less job would starve a DANE caller of its records.
        for (self.jobs.items) |job| {
            if (job.is_raw) continue;
            if (job.service_idx != @intFromEnum(service)) continue;
            if (job.default_port != default_port) continue;
            if (job.want_tlsa != want_tlsa) continue;
            if (!std.ascii.eqlIgnoreCase(job.name, fqdn)) continue;
            // A full job takes no more waiters; the lookup starts a
            // fresh job on the wire instead of failing.
            if (job.waiter_count >= MAX_WAITERS) continue;
            job.waiters[job.waiter_count] = session_key;
            job.waiter_count += 1;
            return;
        }
        if (self.slotsFull()) {
            // Same rule as query(): refresh-only jobs yield to client
            // lookups, so a fully cached resolve() can always answer.
            _ = self.reclaimRefreshOnly();
        }
        if (self.slotsFull()) {
            try self.enqueueWait(session_key, fqdn, .{ .kind = .resolve, .service_idx = @intFromEnum(service), .default_port = default_port, .want_tlsa = want_tlsa });
            return;
        }
        const job = try self.allocJob(session_key, fqdn);
        job.phase = .srv_tls;
        job.service_idx = @intFromEnum(service);
        job.default_port = default_port;
        job.want_tlsa = want_tlsa;
        {
            errdefer self.freeJob(job);
            try self.jobs.append(self.alloc, job);
        }
        self.armChainDeadline(job) catch |err| {
            self.abortJob(job);
            return err;
        };
        self.sendSrv(job, SRV_TLS[job.service_idx]) catch |err| {
            self.abortJob(job);
            return err;
        };
    }

    // -- kqueue pump -----------------------------------------------------

    fn ensureOpen(self: *Resolver) !void {
        if (self.kq < 0) self.kq = try posix.kqueue();
        if (self.fd >= 0) return;
        if (!self.server_configured) {
            log.warn("dns: no nameserver configured", .{});
            return error.NoResolver;
        }
        const fd = try posix.socket(self.server.any.family, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
        errdefer posix.close(fd);
        try rawConnect(fd, &self.server.any, self.server.getOsSockLen());
        var ch = [1]posix.Kevent{.{ .ident = @intCast(fd), .filter = std.c.EVFILT.READ, .flags = std.c.EV.ADD | std.c.EV.ENABLE, .fflags = 0, .data = 0, .udata = 0 }};
        try self.keventApply(&ch);
        // Publish only once the knote is armed: an early failure
        // leaves self.fd holding the socket errdefer just closed, and
        // a later send or deinit would touch whatever reused it.
        self.fd = fd;
    }

    /// One kevent turn on the resolver's kqueue. `timeout_ms` may be 0
    /// (pump only) - callers pass their next-loop deadline, not a sleep.
    pub fn step(self: *Resolver, timeout_ms: i32) void {
        if (self.kq < 0) return;
        var events: [16]posix.Kevent = undefined;
        const ts: std.c.timespec = .{ .sec = @intCast(@divTrunc(timeout_ms, 1000)), .nsec = @intCast(@rem(timeout_ms, 1000) * 1_000_000) };
        const n = rawKevent(self.kq, &.{}, &events, &ts) catch |err| {
            self.kevent_errors += 1;
            if (self.kevent_errors == 1) log.warn("dns: kevent failed in step: {}", .{err});
            return;
        };
        self.dispatchEvents(events[0..n]);
    }

    /// Dispatch one event batch: socket progress first, deadlines
    /// second, so a reply that frees a job makes the same batch's
    /// deadline event for it correctly stale under (gen, slot).
    fn dispatchEvents(self: *Resolver, events: []const posix.Kevent) void {
        for (events) |ev| {
            if (ev.filter == std.c.EVFILT.READ) {
                const fd: posix.fd_t = @intCast(ev.ident);
                if (fd == self.fd) {
                    self.onReadable();
                } else if (self.tcpJobFromEvent(ev)) |job| {
                    self.onTcpReadable(job);
                }
            } else if (ev.filter == std.c.EVFILT.WRITE) {
                // A refused connect also reports writable, so check
                // SO_ERROR once before the socket is used; a connected
                // socket arriving here resumes a WouldBlock flush.
                if (self.tcpJobFromEvent(ev)) |job| {
                    if (!job.tcp_connected) {
                        if (rawSoError(job.tcp_fd)) |_| {
                            job.tcp_connected = true;
                        } else |_| {
                            // The connect died; the outstanding query
                            // is unanswered, so it runs the ordinary
                            // phase-scoped failure path. The dead
                            // socket is dropped first or the next
                            // query would stage on it.
                            self.tcpClose(job);
                            self.failQuery(job);
                            continue;
                        }
                    }
                    self.tcpWrite(job) catch |err| {
                        if (err == error.PeerClosed) {
                            _ = self.tcpPeerClosed(job);
                        } else {
                            self.dropJob(job, .failed);
                        }
                    };
                }
            }
        }
        for (events) |ev| {
            if (ev.filter != std.c.EVFILT.TIMER) continue;
            // The event may have been queued before the job was freed
            // by an earlier event in this same batch. udata bit 6 marks
            // the whole-chain deadline vs a retry.
            if (self.jobFromUdata(ev.udata)) |job| {
                if (ev.udata & 0x40 != 0) self.onChainDeadline(job) else self.onDeadline(job);
            }
        }
    }

    // -- wire I/O --------------------------------------------------------

    fn sendSrv(self: *Resolver, job: *Job, prefix: []const u8) !void {
        var buf: [280]u8 = undefined;
        // A prefixed name that cannot even be staged cannot exist on
        // the wire: same NXDOMAIN answer as an over-long buildQuery.
        const qname = std.fmt.bufPrint(&buf, "{s}.{s}", .{ prefix, job.name }) catch return self.onNxdomain(job);
        try self.sendQuery(job, qname, KIND_SRV);
    }

    /// A fresh random id per query: sequential ids from one fixed
    /// source port make blind spoofing easy. Retries a colliding id a
    /// bounded number of times; with at most MAX_JOBS in flight the
    /// space of 65536 ids is never crowded.
    fn nextId(self: *Resolver) !u16 {
        for (0..16) |_| {
            const id = std.crypto.random.int(u16);
            var in_flight = false;
            for (self.jobs.items) |j| {
                if (j.dns_id == id) {
                    in_flight = true;
                    break;
                }
            }
            if (!in_flight) return id;
        }
        return error.NoFreeId;
    }

    /// Allocate a job in a free slot and stamp it with that slot's
    /// generation; timer udata carries both so a queued event naming a
    /// freed job is ignored instead of dereferenced.
    fn allocJob(self: *Resolver, session_key: usize, name: []const u8) !*Job {
        const job = try self.alloc.create(Job);
        errdefer self.alloc.destroy(job);
        job.* = .{
            .name = try self.alloc.dupe(u8, name),
            .phase = .srv_tls,
        };
        errdefer self.alloc.free(job.name);
        job.waiters[0] = session_key;
        job.waiter_count = 1;
        for (&self.slots, 0..) |*s, i| {
            if (s.* == null) {
                self.slot_gen[i] +%= 1;
                s.* = job;
                job.slot = @intCast(i);
                job.gen = self.slot_gen[i];
                return job;
            }
        }
        return error.TooManyJobs;
    }

    /// Arm the job's one-shot deadline; udata carries (gen, slot) so an
    /// event queued before the job's free is recognized as stale.
    fn armDeadline(self: *Resolver, job: *Job, ms: i64) !void {
        var ch = [1]posix.Kevent{.{
            .ident = @intFromPtr(job),
            .filter = std.c.EVFILT.TIMER,
            .flags = std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT,
            .fflags = 0, // default unit is ms
            .data = @intCast(ms),
            .udata = (@as(usize, job.gen) << 8) | job.slot,
        }};
        try self.keventApply(&ch);
    }

    /// Whole-chain bound, armed once per resolve() job beside the
    /// per-query deadline: a long or hostile SRV list must not hold a
    /// session past chain_deadline_ms of total resolution time. The
    /// knote ident is the job pointer ORed low (Job is aligned, so a
    /// set low bit never aliases the retry timer's ident), and udata
    /// carries the kind bit next to (gen, slot).
    fn armChainDeadline(self: *Resolver, job: *Job) !void {
        var ch = [1]posix.Kevent{.{
            .ident = @intFromPtr(job) | 1,
            .filter = std.c.EVFILT.TIMER,
            .flags = std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT,
            .fflags = 0,
            .data = @intCast(self.chain_deadline_ms),
            .udata = (@as(usize, job.gen) << 8) | 0x40 | job.slot,
        }};
        try self.keventApply(&ch);
    }

    /// Disarm both timer knotes. The retry knote may already be gone
    /// (a fired ONESHOT deletes itself on delivery), so deletes run
    /// through the receipt path with ENOENT accepted: a raw changelist
    /// would abort at the first failure and leave the chain timer
    /// armed past freeJob.
    fn disarmDeadline(self: *Resolver, job: *Job) void {
        if (self.kq < 0) return;
        var ch = [2]posix.Kevent{
            .{ .ident = @intFromPtr(job), .filter = std.c.EVFILT.TIMER, .flags = std.c.EV.DELETE, .fflags = 0, .data = 0, .udata = 0 },
            .{ .ident = @intFromPtr(job) | 1, .filter = std.c.EVFILT.TIMER, .flags = std.c.EV.DELETE, .fflags = 0, .data = 0, .udata = 0 },
        };
        self.keventDelete(&ch) catch {};
    }

    /// Resolve a timer event's (gen, slot) udata back to a live job;
    /// null when the job was freed or its slot was re-used.
    fn jobFromUdata(self: *Resolver, udata: usize) ?*Job {
        const slot: usize = udata & 0x3F;
        const gen: u16 = @intCast(udata >> 8);
        if (slot >= MAX_JOBS) return null;
        const job = self.slots[slot] orelse return null;
        if (self.slot_gen[slot] != gen) return null;
        return job;
    }

    /// TCP knote udata names the connection as well as the job:
    /// (seq, gen, slot). Bit 0x40 stays clear; that bit marks the
    /// chain timer in timer udata.
    fn tcpUdata(job: *const Job) usize {
        return (@as(usize, job.tcp_seq) << 32) | (@as(usize, job.gen) << 8) | job.slot;
    }

    /// Resolve a TCP socket event's (seq, gen, slot) udata back to the
    /// job that armed it; null when the slot is dead or re-used, or
    /// when the event names a connection already closed (close() then
    /// socket() reuses fd numbers, so ident alone cannot tell the old
    /// knote's event from the new connection's). The u16 cast in
    /// jobFromUdata cannot carry the seq bits, so TCP events must
    /// never go through it.
    fn tcpJobFromEvent(self: *Resolver, ev: posix.Kevent) ?*Job {
        const slot: usize = ev.udata & 0x3F;
        const gen: u16 = @truncate(ev.udata >> 8);
        const seq: u8 = @truncate(ev.udata >> 32);
        if (slot >= MAX_JOBS) return null;
        const job = self.slots[slot] orelse return null;
        if (self.slot_gen[slot] != gen) return null;
        if (job.tcp_fd != @as(posix.fd_t, @intCast(ev.ident))) return null;
        if (job.tcp_seq != seq) return null;
        return job;
    }

    /// Connected-UDP send. An ICMP port-unreachable queued from an
    /// earlier datagram surfaces as ECONNREFUSED on a later send; that
    /// error belongs to the earlier packet, so it is consumed and the
    /// send retried once instead of failing the wrong job.
    fn sendUdp(self: *Resolver, pkt: []const u8) !void {
        // Test seam: report a wire send failure without touching the
        // socket (a closed fd is UB territory, not a failure path).
        if (builtin.is_test) {
            if (self.fail_sends) return error.SendFailed;
        }
        _ = rawSend(self.fd, pkt, 0) catch |err| switch (err) {
            error.Refused => {
                self.stale_icmp += 1;
                _ = rawSend(self.fd, pkt, 0) catch return error.SendFailed;
                return;
            },
            else => return error.SendFailed,
        };
    }

    /// Apply changelist entries and surface per-entry failures. Every
    /// change carries EV_RECEIPT: the kernel returns one EV_ERROR event
    /// per entry (data = 0 on success, the errno on failure) and never
    /// drains real pending events into this harvest, so socket progress
    /// reaches step() through the kqueue alone and a failed entry cannot
    /// eat an event harvested after it.
    fn keventApply(self: *Resolver, ch: []const posix.Kevent) !void {
        try self.keventApplyChecked(ch, false);
    }

    /// Changelist of deletes: a receipt reporting ENOENT means the
    /// knote was already gone, which is exactly the state the delete
    /// asked for. Any other receipt errno still fails the call.
    fn keventDelete(self: *Resolver, ch: []const posix.Kevent) !void {
        try self.keventApplyChecked(ch, true);
    }

    fn keventApplyChecked(self: *Resolver, ch: []const posix.Kevent, enoent_ok: bool) !void {
        if (builtin.is_test) {
            if (self.fail_kevents) return error.KeventChange;
        }
        const nonblock = std.c.timespec{ .sec = 0, .nsec = 0 };
        var evbuf: [8]posix.Kevent = undefined;
        var off: usize = 0;
        while (off < ch.len) {
            // A full eventlist stops later changes, so the batch never
            // exceeds the buffer that reports it.
            const n = @min(ch.len - off, evbuf.len);
            var batch: [8]posix.Kevent = undefined;
            for (ch[off .. off + n], 0..) |ev, i| {
                batch[i] = ev;
                batch[i].flags |= std.c.EV.RECEIPT;
            }
            const got = try rawKevent(self.kq, batch[0..n], &evbuf, &nonblock);
            for (evbuf[0..got]) |ev| {
                if (ev.data == 0) continue;
                if (enoent_ok and ev.data == @intFromEnum(std.c.E.NOENT)) continue;
                return error.KeventChange;
            }
            off += n;
        }
    }

    fn sendQuery(self: *Resolver, job: *Job, qname: []const u8, qtype: u16) !void {
        // The chain consults the RR cache the same way a raw query
        // does; a hit feeds the phase machine a synthetic message,
        // and a negative hit drives the matching failure path. A
        // stale row feeds the same path after a failed refresh or
        // while a refresh already runs.
        if (self.cacheGetClass(qname, qtype)) |class| {
            switch (class) {
                .fresh => |hit| return self.feedEnt(job, hit.ent, true),
                .stale => |hit| {
                    const now = self.now_ms();
                    if (hit.ent.refreshing or now -| hit.ent.last_fail_ms < STALE_RECHECK_MS) {
                        return self.serveStale(job, hit);
                    }
                    // A wire refresh starts here: pin the row on the
                    // job so eviction cannot free the borrow.
                    hit.ent.refreshing = true;
                    job.stale = hit;
                },
            }
        }
        var buf: [512]u8 = undefined;
        const id = try self.nextId();
        const q = wire.buildQuery(&buf, id, qname, qtype) catch |err| switch (err) {
            // A name that cannot be encoded cannot exist on the wire,
            // so the answer is the negative one the cache would have
            // given: run the NXDOMAIN path (raw jobs report .nxdomain,
            // a TLSA phase reads it as absent).
            error.InvalidName => return self.onNxdomain(job),
            else => return err,
        };
        const pkt = try self.alloc.dupe(u8, buf[0..q]);
        if (job.request.len > 0) self.alloc.free(job.request);
        job.request = pkt;
        job.dns_id = std.mem.readInt(u16, pkt[0..2], .big);
        if (job.pending_qname.len > 0) self.alloc.free(job.pending_qname);
        job.pending_qname = try self.alloc.dupe(u8, qname);
        job.pending_qtype = qtype;
        job.tries = 1;
        if (job.use_tcp) {
            // A new query re-arms the close-after-answer resend
            // budget whichever send arm it takes.
            job.tcp_eof_resent = false;
            if (job.tcp_out_pos < job.tcp_out.items.len) {
                // A frame still mid-write cannot share the stream with
                // a new one: re-open the connection so the new query
                // stages on an empty tcp_out.
                self.tcpRestart(job) catch |err| {
                    if (err == error.PeerClosed) {
                        if (!self.tcpPeerClosed(job)) return;
                    } else if (self.tcpConnectFailed(job, err)) return else return err;
                };
            } else {
                // A connection surviving from an earlier query is
                // reused; its fully flushed frame is cleared so the
                // new query stages and is written.
                job.tcp_out.clearRetainingCapacity();
                job.tcp_out_pos = 0;
                self.tcpSend(job) catch |err| {
                    if (err == error.PeerClosed) {
                        if (!self.tcpPeerClosed(job)) return;
                    } else if (self.tcpConnectFailed(job, err)) return else return err;
                };
            }
        } else {
            try self.sendUdp(pkt);
        }
        self.armDeadline(job, TIMEOUT_MS) catch return error.SendFailed;
    }

    /// Feed a cached row's answer to the job: a negative row drives
    /// the matching failure path, a positive row arrives as a
    /// synthetic NOERROR message. recache=false on a stale serve so
    /// the row's refresh bookkeeping and windows are never rewritten.
    fn feedEnt(self: *Resolver, job: *Job, ent: *TypeEnt, recache: bool) void {
        if (job.is_raw) {
            switch (ent.neg) {
                .nxdomain => return self.dropJob(job, .nxdomain),
                .nodata => return self.completeRaw(job, .{ .id = 0, .rcode = wire.RCODE_NOERROR, .truncated = false, .rrs = &.{}, .raw = &.{} }, recache),
                .none => {},
            }
        } else switch (ent.neg) {
            .nxdomain => return self.onNxdomain(job),
            .nodata, .none => {},
        }
        const hit = wire.Message{ .id = 0, .rcode = wire.RCODE_NOERROR, .truncated = false, .rrs = ent.rrs, .raw = &.{} };
        if (job.is_raw) return self.completeRaw(job, hit, recache);
        return self.advance(job, hit);
    }

    /// Count a stale serve and emit the per-owner log line at most
    /// once per STALE_LOG_MS.
    fn noteStaleServe(self: *Resolver, owner: *OwnerEnt) void {
        self.stale_serves += 1;
        const now = self.now_ms();
        if (now -| owner.stale_log_ms >= STALE_LOG_MS) {
            owner.stale_log_ms = now;
            log.warn("dns: serving stale {s}", .{owner.name});
        }
    }

    /// Serve a stale row's answer to the job (RFC 8767): the row is
    /// pinned while the feed runs so a callback reaching the cache
    /// cannot free the borrowed records, and the feed never
    /// recaches. The caller owns refresh bookkeeping; the pinned
    /// flag is restored on exit.
    fn serveStale(self: *Resolver, job: *Job, hit: CacheHit) void {
        const ent = hit.ent;
        const pinned = ent.refreshing;
        ent.refreshing = true;
        self.noteStaleServe(hit.owner);
        self.feedEnt(job, ent, false);
        ent.refreshing = pinned;
    }

    /// The per-query deadline fired on a job refreshing a stale row
    /// (RFC 8767): waiters get the stale answer now. A chain job
    /// feeds it to the phase machine and moves on while a detached
    /// refresh-only job carries the renewal. A raw job answers its
    /// waiters and keeps the wire query as a refresh-only job bounded
    /// by the chain deadline, so the row still gets its renewal.
    fn serveStaleDeadline(self: *Resolver, job: *Job) void {
        const hit = job.stale.?;
        if (job.is_raw) {
            job.refresh_only = true;
            self.answerStaleRaw(job, hit);
            job.waiter_count = 0;
            self.armChainDeadline(job) catch {
                self.dropJob(job, .failed);
                return;
            };
            self.armDeadline(job, TIMEOUT_MS) catch {
                self.dropJob(job, .failed);
                return;
            };
            // Queued client lookups outrank this renewal; may free job.
            self.promoteWait();
            return;
        }
        const ent = hit.ent;
        // The chain moves on with the stale answer while a detached
        // refresh-only job renews the row on the wire: the dead query
        // is not a failed refresh (no last_fail_ms stamp) and the
        // row keeps refreshing instead of expiring behind it.
        var name_buf: [280]u8 = undefined;
        const qname = name_buf[0..job.pending_qname.len];
        @memcpy(qname, job.pending_qname);
        const qtype = job.pending_qtype;
        job.stale = null;
        ent.refreshing = false;
        // The feed may complete and free this job; only the copied
        // query name and type are safe to use afterwards.
        self.serveStale(job, hit);
        self.spawnRefresh(qname, qtype);
    }

    /// Detached renewal for a stale row a chain already answered
    /// from (RFC 8767): a waiterless raw job re-asks the wire query
    /// so the row still gets its refresh after the borrowing chain
    /// moved on. Bounded by its own chain deadline; skipped while
    /// the job table is full (the next stale hit starts one instead).
    fn spawnRefresh(self: *Resolver, qname: []const u8, qtype: u16) void {
        if (self.slotsFull()) return;
        const job = self.allocJob(0, qname) catch return;
        job.phase = .raw;
        job.is_raw = true;
        job.refresh_only = true;
        job.waiter_count = 0;
        self.jobs.append(self.alloc, job) catch {
            self.freeJob(job);
            return;
        };
        self.armChainDeadline(job) catch return self.abortJob(job);
        // The stale consult inside sendQuery re-pins the row on the
        // job; last_fail_ms was never stamped for the leg that died
        // (the renewal is still in flight), so the recheck window
        // lets the query go out instead of serving stale again.
        self.sendQuery(job, qname, qtype) catch self.abortJob(job);
    }

    /// Answer a raw job's waiters from a stale row: the same
    /// RecordResult shapes completeRaw produces, without removing
    /// the job or recaching.
    fn answerStaleRaw(self: *Resolver, job: *Job, hit: CacheHit) void {
        const ent = hit.ent;
        self.noteStaleServe(hit.owner);
        const prev_cb = self.in_callback;
        self.in_callback = job;
        for (job.waiters[0..job.waiter_count], 0..) |key, w| {
            if (job.waiter_cancelled & (@as(u16, 1) << @intCast(w)) != 0) continue;
            switch (ent.neg) {
                .nxdomain => self.qcb.fun(self.qcb.ctx, key, .nxdomain, null),
                else => {
                    const rrs = self.dupRrs(ent.rrs) catch {
                        self.qcb.fun(self.qcb.ctx, key, .failed, null);
                        continue;
                    };
                    self.qcb.fun(self.qcb.ctx, key, .resolved, .{ .rrs = rrs, .ttl = 0 });
                },
            }
        }
        self.in_callback = prev_cb;
    }

    /// Direct stale serve for query(): a refresh in flight or a
    /// recheck-suppressed attempt answers the caller from the stale
    /// row without taking a job slot.
    fn answerStaleNow(self: *Resolver, hit: CacheHit, session_key: usize) !void {
        const ent = hit.ent;
        self.noteStaleServe(hit.owner);
        switch (ent.neg) {
            .nxdomain => self.qcb.fun(self.qcb.ctx, session_key, .nxdomain, null),
            .nodata => self.qcb.fun(self.qcb.ctx, session_key, .resolved, .{ .rrs = &.{}, .ttl = 0 }),
            .none => {
                const rrs = try self.dupRrs(ent.rrs);
                self.qcb.fun(self.qcb.ctx, session_key, .resolved, .{ .rrs = rrs, .ttl = 0 });
            },
        }
    }

    /// A wire answer ends the refresh attempt: drop the job's pin on
    /// the stale row before the insert below replaces it.
    fn markStaleOk(self: *Resolver, job: *Job) void {
        _ = self;
        if (job.stale) |hit| {
            hit.ent.refreshing = false;
            job.stale = null;
        }
    }

    fn onDeadline(self: *Resolver, job: *Job) void {
        if (job.stale != null and !job.refresh_only) {
            // A refresh still running at the per-query deadline
            // serves the stale row now and keeps resolving (RFC 8767).
            return self.serveStaleDeadline(job);
        }
        if (job.tries >= MAX_TRIES) {
            // tries counts sends of the outstanding query on its
            // current transport: on UDP a retry retransmits the
            // datagram, on TCP a retry re-opens the connection and
            // resends the frame.
            log.warn("dns: timeout after {d} tries for {s}", .{ job.tries, job.name });
            self.failQuery(job);
            return;
        }
        job.tries += 1;
        if (job.use_tcp) {
            self.tcpRestart(job) catch |err| {
                if (err == error.PeerClosed) {
                    if (!self.tcpPeerClosed(job)) return;
                } else if (err == error.ConnectFailed) {
                    self.tcpClose(job);
                    self.failQuery(job);
                    return;
                } else {
                    self.dropJob(job, .failed);
                    return;
                }
            };
        } else {
            self.sendUdp(job.request) catch {
                self.dropJob(job, .failed);
                return;
            };
        }
        self.armDeadline(job, TIMEOUT_MS) catch {
            self.dropJob(job, .failed);
        };
    }

    /// The outstanding query is dead (retries exhausted or a refusal
    /// rcode). Inside a per-target phase only that SRV target is
    /// skipped; inside the fallback the other family still gets its
    /// try; every other phase fails the job.
    fn failQuery(self: *Resolver, job: *Job) void {
        if (job.stale) |hit| {
            // A failed refresh serves the stale row it tried to
            // renew; last_fail_ms suppresses another attempt inside
            // the recheck window. The pin survives the feed so the
            // borrowed records stay live through the callbacks.
            const ent = hit.ent;
            job.stale = null;
            ent.last_fail_ms = self.now_ms();
            self.serveStale(job, hit);
            ent.refreshing = false;
            return;
        }
        switch (job.phase) {
            .srv_tls => {
                // A refusal on the direct-TLS name falls through to
                // the STARTTLS name the way "." or an empty answer does.
                self.clearSrvList(job);
                job.phase = .srv_plain;
                self.sendSrv(job, SRV_PLAIN[job.service_idx]) catch return self.dropJob(job, .failed);
            },
            // A per-target failure costs only the phase that failed:
            // one dead address family still lets the other answer,
            // and a failed TLSA lookup marks the target lookup_failed
            // (a temporary failure, never PKIX).
            .addr => {
                job.target_err = true;
                job.phase = .addr6;
                self.sendAddr(job, KIND_AAAA) catch return self.finishTarget(job);
            },
            .addr6 => {
                job.target_err = true;
                self.finishTarget(job);
            },
            .tlsa => self.failTargetTlsa(job),
            .fallback_addr => {
                job.fallback_err = true;
                job.phase = .fallback_addr4;
                self.sendFallback(job, KIND_A) catch return self.dropJob(job, .failed);
            },
            .fallback_addr4 => {
                job.fallback_err = true;
                self.finishFallback(job);
            },
            .fallback_tlsa => {
                self.emitFallbackTargets(job, &.{}, .lookup_failed) catch return self.dropJob(job, .failed);
                self.complete(job);
            },
            else => self.dropJob(job, .failed),
        }
    }

    /// End the current SRV target after an address-family failure:
    /// emit whichever families resolved, then move to the next target
    /// in RFC 2782 order. A caller wanting DANE still gets the TLSA
    /// round trip for the target's surviving addresses; only a target
    /// with nothing resolved is skipped outright.
    fn finishTarget(self: *Resolver, job: *Job) void {
        if (job.cur_addr4 == null and job.cur_addr6 == null) {
            job.cur_addr4 = null;
            job.cur_addr6 = null;
            self.nextTarget(job) catch return self.dropJob(job, .failed);
            return;
        }
        if (job.want_tlsa) {
            job.phase = .tlsa;
            self.sendTlsa(job) catch return self.failTargetTlsa(job);
            return;
        }
        self.emitAndAdvance(job, &.{}, .absent);
    }

    /// The whole-chain bound fired: hand the waiters whatever targets
    /// were collected so far instead of failing an almost-done chain.
    /// A target whose TLSA query is still pending at the bound is a
    /// lookup_failed target (ADR-13), never a bare "no DANE" one.
    fn onChainDeadline(self: *Resolver, job: *Job) void {
        log.warn("dns: chain deadline exceeded for {s}", .{job.name});
        switch (job.phase) {
            .tlsa => self.emitTargets(job, &.{}, .lookup_failed) catch return self.dropJob(job, .failed),
            .fallback_tlsa => self.emitFallbackTargets(job, &.{}, .lookup_failed) catch return self.dropJob(job, .failed),
            else => {},
        }
        if (job.targets.items.len > 0) {
            self.complete(job);
        } else {
            self.dropJob(job, .failed);
        }
    }

    // -- TCP fallback ----------------------------------------------------

    /// Drop the job's TCP connection and staged frame. close() retires
    /// the socket's knotes at once; the resolver stages no deletes.
    /// Events already harvested for the old fd are caught by the seq
    /// check in tcpJobFromEvent.
    fn tcpClose(self: *Resolver, job: *Job) void {
        _ = self;
        if (job.tcp_fd >= 0) posix.close(job.tcp_fd);
        job.tcp_fd = -1;
        job.tcp_connected = false;
        job.tcp_buf.clearRetainingCapacity();
        job.tcp_out.clearRetainingCapacity();
        job.tcp_out_pos = 0;
    }

    /// Re-open the TCP leg from scratch: a retry is a fresh connection
    /// carrying the frame again, which covers a dead connection and a
    /// frame stuck mid-write alike.
    fn tcpRestart(self: *Resolver, job: *Job) !void {
        self.tcpClose(job);
        try self.tcpSend(job);
    }

    /// A synchronous connect refusal is the same wire failure the
    /// pending-connect SO_ERROR arm reports: the dead socket is
    /// dropped and the per-phase failure runs, so a refusal costs
    /// only the failing phase. Returns true when `err` was the
    /// refusal (and handled); the job may be freed, so callers must
    /// not touch it afterwards.
    fn tcpConnectFailed(self: *Resolver, job: *Job, err: anyerror) bool {
        if (err != error.ConnectFailed) return false;
        self.tcpClose(job);
        self.failQuery(job);
        return true;
    }

    /// The peer closed or reset the connection while the outstanding
    /// query was unanswered: RFC 7766 permits a close after any
    /// answer, so the query is re-sent once on a fresh connection
    /// instead of failing. A second close on the same query, or a
    /// failed reconnect whether it arrives as a send error here or as
    /// SO_ERROR on the connect's knote, runs the ordinary failQuery
    /// path which costs only the failing phase. Returns false once
    /// failQuery ran: the job may already be freed and must not be
    /// touched again.
    fn tcpPeerClosed(self: *Resolver, job: *Job) bool {
        self.tcpClose(job);
        if (job.tcp_eof_resent) {
            self.failQuery(job);
            return false;
        }
        job.tcp_eof_resent = true;
        self.tcpSend(job) catch {
            self.failQuery(job);
            return false;
        };
        return true;
    }

    /// Open the TCP socket and start connect; the WRITE knote drives the
    /// actual send once connect completes.
    fn tcpSend(self: *Resolver, job: *Job) !void {
        if (job.tcp_fd >= 0) {
            // A pending connect owns the armed one-shot WRITE knote:
            // it stages and flushes the frame once SO_ERROR clears.
            // Writing now would send on an unconnected socket, whose
            // ENOTCONN is a panic under std.posix, not an error.
            if (!job.tcp_connected) return;
            return self.tcpWrite(job);
        }
        const fd = try posix.socket(self.server.any.family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
        errdefer posix.close(fd);
        job.tcp_seq +%= 1;
        var ch: [2]posix.Kevent = undefined;
        var connected = true;
        if (builtin.is_test) {
            // FreeBSD refuses connects synchronously on real paths
            // (loopback ~1%, pf EACCES on a source-port collision), so
            // the refusal arm is exercised here, not only probed.
            if (self.fail_connects > 0) {
                self.fail_connects -= 1;
                return error.ConnectFailed;
            }
            // Skip connect(2): the socket stays unconnected, so the
            // armed WRITE knote never fires and the connect stays
            // pending for as long as the test needs it.
            if (self.pend_connects) connected = false;
        }
        if (connected) {
            rawConnect(fd, &self.server.any, self.server.getOsSockLen()) catch |e| switch (e) {
                error.WouldBlock => connected = false,
                error.Failed => return error.ConnectFailed,
            };
        }
        ch[0] = .{ .ident = @intCast(fd), .filter = std.c.EVFILT.READ, .flags = std.c.EV.ADD | std.c.EV.ENABLE, .fflags = 0, .data = 0, .udata = tcpUdata(job) };
        var n: usize = 1;
        if (!connected) {
            // Only a pending connect wants the writable event; arming
            // it after an immediate connect would fire a second write
            // of the same frame later.
            ch[1] = .{ .ident = @intCast(fd), .filter = std.c.EVFILT.WRITE, .flags = std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT, .fflags = 0, .data = 0, .udata = tcpUdata(job) };
            n = 2;
        }
        try self.keventApply(ch[0..n]);
        job.tcp_fd = fd;
        job.tcp_connected = connected;
        if (connected) self.tcpWrite(job) catch |err| {
            // The errdefer above closes fd on this error path; detach
            // it from the job so a later tcpClose cannot close a
            // recycled fd number.
            job.tcp_fd = -1;
            job.tcp_connected = false;
            return err;
        };
    }

    /// Re-arm the one-shot writable event so a flush that hit
    /// WouldBlock resumes when the socket drains.
    fn armTcpWrite(self: *Resolver, job: *Job) !void {
        var ch = [1]posix.Kevent{.{
            .ident = @intCast(job.tcp_fd),
            .filter = std.c.EVFILT.WRITE,
            .flags = std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT,
            .fflags = 0,
            .data = 0,
            .udata = tcpUdata(job),
        }};
        try self.keventApply(&ch);
    }

    /// TCP DNS frames are length-prefixed; the frame is staged once in
    /// tcp_out and flushed across partial writes and WouldBlock.
    /// MSG.NOSIGNAL keeps a write to a dead peer an EPIPE error rather
    /// than a process-killing SIGPIPE; that error and a reset report
    /// the same close-after-answer condition as a read-side EOF, so
    /// they surface as error.PeerClosed.
    fn tcpWrite(self: *Resolver, job: *Job) !void {
        if (job.tcp_out.items.len == 0) {
            var hdr: [2]u8 = undefined;
            std.mem.writeInt(u16, &hdr, @intCast(job.request.len), .big);
            try job.tcp_out.appendSlice(self.alloc, &hdr);
            try job.tcp_out.appendSlice(self.alloc, job.request);
        }
        while (job.tcp_out_pos < job.tcp_out.items.len) {
            const n = rawSend(job.tcp_fd, job.tcp_out.items[job.tcp_out_pos..], posix.MSG.NOSIGNAL) catch |err| switch (err) {
                error.WouldBlock => return self.armTcpWrite(job),
                error.Closed => return error.PeerClosed,
                else => return error.SendFailed,
            };
            job.tcp_out_pos += n;
        }
    }

    /// Drop the first frame_len bytes off the job's TCP frame buffer.
    fn consumeTcpFrame(job: *Job, frame_len: usize) void {
        const items = job.tcp_buf.items;
        std.mem.copyForwards(u8, items[0 .. items.len - frame_len], items[frame_len..]);
        job.tcp_buf.items.len -= frame_len;
    }

    /// Consume every complete frame in tcp_buf. A frame is a two-octet
    /// length plus at most 65535 octets, so the length check applies
    /// per frame, not to the whole buffer: a maximal frame followed by
    /// more data is legal. The unconsumed tail is always a partial
    /// frame smaller than 2 + 65535 octets, so the buffer is bounded.
    fn pumpTcpFrames(self: *Resolver, job: *Job) void {
        while (job.tcp_buf.items.len >= 2) {
            const want = std.mem.readInt(u16, job.tcp_buf.items[0..2], .big);
            const frame_len = @as(usize, want) + 2;
            if (job.tcp_buf.items.len < frame_len) return;
            const ours = if (self.matchJob(job.tcp_buf.items[2..frame_len])) |m| m == job else false;
            if (ours) {
                // Consume before handling: the job can live on for the
                // next phase on this connection and a handled frame
                // must never be re-parsed. handleResponse parses a
                // stable copy because consuming slides the buffer.
                const pkt = self.alloc.dupe(u8, job.tcp_buf.items[2..frame_len]) catch {
                    self.dropJob(job, .failed);
                    return;
                };
                defer self.alloc.free(pkt);
                consumeTcpFrame(job, frame_len);
                self.handleResponse(job, pkt);
                return;
            }
            // A frame that answers no outstanding query on this
            // connection is foreign: count it like an unmatched UDP
            // reply, then drop it.
            self.unmatched_replies += 1;
            consumeTcpFrame(job, frame_len);
        }
    }

    fn onTcpReadable(self: *Resolver, job: *Job) void {
        var buf: [8192]u8 = undefined;
        const n = rawRecv(job.tcp_fd, &buf, 0) catch |err| switch (err) {
            error.WouldBlock => return,
            // A reset after the frame was written reports the same
            // close-after-answer condition as the FIN below.
            error.Closed => {
                _ = self.tcpPeerClosed(job);
                return;
            },
            else => {
                // An error on a socket whose connect never completed
                // is the refused-connect condition: the outstanding
                // query runs the ordinary phase failure.
                if (!job.tcp_connected) {
                    self.tcpClose(job);
                    self.failQuery(job);
                } else {
                    self.dropJob(job, .failed);
                }
                return;
            },
        };
        if (n == 0) {
            // RFC 7766 lets a server close after any answer; the
            // outstanding query is re-sent once on a fresh
            // connection before the phase is given up.
            _ = self.tcpPeerClosed(job);
            return;
        }
        job.tcp_buf.appendSlice(self.alloc, buf[0..n]) catch {
            self.dropJob(job, .failed);
            return;
        };
        self.pumpTcpFrames(job);
    }

    // -- responses --------------------------------------------------------

    /// T296: a response belongs to a query only when id AND qname AND
    /// qtype all match - a colliding id does not steer a different query.
    /// Dropping the qtype check alone is masked by the qname check;
    /// the wrong-qtype decoy test still pins the combination.
    fn matchJob(self: *Resolver, pkt: []const u8) ?*Job {
        if (pkt.len < 12) return null;
        const id = std.mem.readInt(u16, pkt[0..2], .big);
        var arena_state = std.heap.ArenaAllocator.init(self.alloc);
        defer arena_state.deinit();
        const q = parseQuestion(arena_state.allocator(), pkt) catch return null;
        for (self.jobs.items) |j| {
            if (j.dns_id != id) continue;
            if (j.pending_qtype != q.qtype) continue;
            if (!std.ascii.eqlIgnoreCase(j.pending_qname, q.qname)) continue;
            return j;
        }
        return null;
    }

    pub fn onReadable(self: *Resolver) void {
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = rawRecv(self.fd, &buf, 0) catch |err| switch (err) {
                error.WouldBlock => return,
                // A refusal queued by an earlier datagram is consumed,
                // not charged to whichever job receives next.
                error.Refused => {
                    self.stale_icmp += 1;
                    continue;
                },
                else => {
                    self.udp_errors += 1;
                    log.warn("dns: udp recv error: {}", .{err});
                    return;
                },
            };
            if (n < 12) {
                self.malformed_replies += 1;
                continue;
            }
            if (self.matchJob(buf[0..n])) |job| {
                self.handleResponse(job, buf[0..n]);
            } else {
                self.unmatched_replies += 1;
            }
        }
    }

    fn handleResponse(self: *Resolver, job: *Job, pkt: []const u8) void {
        var arena_state = std.heap.ArenaAllocator.init(self.alloc);
        defer arena_state.deinit();

        const msg = wire.parse(arena_state.allocator(), pkt) catch {
            // A malformed refresh answer is a failed refresh: the
            // stale row it tried to renew still serves the waiters.
            if (job.stale != null) return self.failQuery(job);
            return self.dropJob(job, .failed);
        };
        if (msg.truncated) {
            // A TC message is never an answer. On a job already on
            // TCP it is a late duplicate of the reply that caused
            // the upgrade; parsing it as NODATA would forge an empty
            // answer and, on a TLSA leg, downgrade a failed lookup
            // to absent (ADR-13).
            if (job.use_tcp) return;
            job.use_tcp = true;
            job.tries = 0;
            self.tcpSend(job) catch |err| {
                if (err == error.PeerClosed) {
                    if (!self.tcpPeerClosed(job)) return;
                } else if (self.tcpConnectFailed(job, err)) return else return self.dropJob(job, .failed);
            };
            self.armDeadline(job, TCP_TIMEOUT_MS) catch return self.dropJob(job, .failed);
            return;
        }

        switch (msg.rcode) {
            wire.RCODE_NOERROR => {},
            wire.RCODE_NXDOMAIN => {
                self.markStaleOk(job);
                self.cachePutNeg(job.pending_qname, job.pending_qtype, .nxdomain, msg);
                return self.onNxdomain(job);
            },
            else => return self.failQuery(job),
        }

        // Only answer-section records that actually answer the
        // outstanding query may reach a phase or the cache.
        const valid = self.filterAnswers(arena_state.allocator(), msg, job) catch
            return self.dropJob(job, .failed);
        var filtered = msg;
        filtered.rrs = valid;
        self.markStaleOk(job);

        if (valid.len == 0) {
            self.cachePutNeg(job.pending_qname, job.pending_qtype, .nodata, msg);
        } else if (!job.is_raw) {
            // Chain responses fill the same RR cache raw queries use;
            // completeRaw covers the raw path on its own.
            self.cachePut(job.pending_qname, job.pending_qtype, valid);
        }

        if (job.is_raw) return self.completeRaw(job, filtered, true);
        switch (job.phase) {
            .srv_tls, .srv_plain, .addr, .addr6, .tlsa, .fallback_addr, .fallback_addr4, .fallback_tlsa => self.advance(job, filtered),
            .raw, .done => {},
        }
    }

    /// Answer-section records answering the outstanding query: the
    /// owner must equal the asked name or a CNAME target it resolved
    /// to, the type must be the asked type (or the CNAME record
    /// itself), and the class must be IN. Authority and additional
    /// records are dropped before they can reach a caller or the
    /// cache.
    fn filterAnswers(self: *Resolver, alloc: std.mem.Allocator, msg: wire.Message, job: *Job) ![]wire.Rr {
        _ = self;
        var out = try std.ArrayList(wire.Rr).initCapacity(alloc, msg.rrs.len);
        var expected = job.pending_qname;
        for (msg.rrs) |rr| {
            // The section check alone is masked by the owner/type
            // checks below for most injections; the poisoned-section
            // test pins the combination.
            if (rr.section != .answer) continue;
            if (rr.class != wire.CLASS_IN) continue;
            if (!std.ascii.eqlIgnoreCase(rr.name, expected)) continue;
            if (rr.rtype == wire.TYPE_CNAME and rr.rtype != job.pending_qtype) {
                // The chain retargets the expected owner for the
                // records that follow.
                const target = wire.decompressName(msg.raw, rr.rdata_off, alloc) catch continue;
                out.append(alloc, rr) catch return error.OutOfMemory;
                expected = target.name;
                continue;
            }
            if (rr.rtype != job.pending_qtype) continue;
            out.append(alloc, rr) catch return error.OutOfMemory;
        }
        return out.items;
    }

    /// Free one slot held by a waiterless refresh-only job so a
    /// client lookup can take it (ADR-13: a refresh never starves a
    /// lookup the cache could answer). The dropped refresh counts as
    /// a failed one: freeJob stamps last_fail_ms, suppressing an
    /// immediate respawn for the recheck window. The promoted wait
    /// queue keeps FIFO order. Returns true when a job was reclaimed.
    fn reclaimRefreshOnly(self: *Resolver) bool {
        if (!self.dropRefreshOnly()) return false;
        self.promoteWait();
        return true;
    }

    /// Drop one refresh-only job; no promote so callers inside a
    /// callback cannot reenter the queue pump. Returns true when a
    /// job was freed.
    fn dropRefreshOnly(self: *Resolver) bool {
        for (self.jobs.items, 0..) |job, i| {
            if (job.refresh_only) {
                _ = self.jobs.orderedRemove(i);
                self.freeJob(job);
                return true;
            }
        }
        return false;
    }

    /// Remove a job without answering its waiters: for callers that
    /// already get the failure as an error return, where firing the
    /// callback too would answer the request twice.
    fn abortJob(self: *Resolver, job: *Job) void {
        for (self.jobs.items, 0..) |j, i| {
            if (j == job) {
                _ = self.jobs.orderedRemove(i);
                break;
            }
        }
        self.freeJob(job);
        self.promoteWait();
    }

    fn dropJob(self: *Resolver, job: *Job, status: Status) void {
        for (self.jobs.items, 0..) |j, i| {
            if (j == job) {
                _ = self.jobs.orderedRemove(i);
                break;
            }
        }
        const prev_cb = self.in_callback;
        if (job.is_raw) {
            self.in_callback = job;
            for (job.waiters[0..job.waiter_count], 0..) |key, w| {
                if (job.waiter_cancelled & (@as(u16, 1) << @intCast(w)) != 0) continue;
                self.qcb.fun(self.qcb.ctx, key, status, null);
            }
            self.in_callback = prev_cb;
        } else {
            self.in_callback = job;
            for (job.waiters[0..job.waiter_count], 0..) |key, w| {
                if (job.waiter_cancelled & (@as(u16, 1) << @intCast(w)) != 0) continue;
                self.cb.fun(self.cb.ctx, key, status, null);
            }
            self.in_callback = prev_cb;
        }
        self.freeJob(job);
        self.promoteWait();
    }

    fn complete(self: *Resolver, job: *Job) void {
        for (self.jobs.items, 0..) |j, i| {
            if (j == job) {
                _ = self.jobs.orderedRemove(i);
                break;
            }
        }
        // Every waiter gets its own deep copy of the target set; the
        // callback owns what it receives.
        const prev_cb = self.in_callback;
        self.in_callback = job;
        for (job.waiters[0..job.waiter_count], 0..) |key, w| {
            if (job.waiter_cancelled & (@as(u16, 1) << @intCast(w)) != 0) continue;
            const targets = self.dupTargets(job.targets.items) catch {
                self.cb.fun(self.cb.ctx, key, .failed, null);
                continue;
            };
            self.cb.fun(self.cb.ctx, key, .resolved, .{ .targets = targets });
        }
        self.in_callback = prev_cb;
        self.freeJob(job);
        self.promoteWait();
    }

    /// Deep-copy a target list for one waiter's Resolution.
    fn dupTargets(self: *Resolver, items: []const Target) ![]Target {
        const out = try self.alloc.alloc(Target, items.len);
        var built: usize = 0;
        errdefer {
            for (out[0..built]) |t| {
                self.alloc.free(t.host);
                for (t.tlsa) |r| self.alloc.free(r.association_data);
                if (t.tlsa.len > 0) self.alloc.free(t.tlsa);
            }
            self.alloc.free(out);
        }
        for (items, 0..) |t, i| {
            const host = try self.alloc.dupe(u8, t.host);
            errdefer self.alloc.free(host);
            var tlsa: []dns.TlsaRecord = &.{};
            if (t.tlsa.len > 0) {
                tlsa = try self.alloc.alloc(dns.TlsaRecord, t.tlsa.len);
                var tn: usize = 0;
                errdefer {
                    for (tlsa[0..tn]) |r| self.alloc.free(r.association_data);
                    self.alloc.free(tlsa);
                }
                for (t.tlsa, 0..) |r, j| {
                    tlsa[j] = r;
                    tlsa[j].association_data = try self.alloc.dupe(u8, r.association_data);
                    tn += 1;
                }
            }
            out[i] = .{ .addr = t.addr, .host = host, .tlsa = tlsa, .tlsa_status = t.tlsa_status, .is_direct_tls = t.is_direct_tls };
            built += 1;
        }
        return out;
    }

    /// Detach the answer RRs from the parse arena (deep copy of every
    /// name and rdata), cache them, and hand them to the query callback.
    /// A stale serve passes recache=false: rewriting the row would
    /// reset its refresh bookkeeping and windows.
    fn completeRaw(self: *Resolver, job: *Job, msg: wire.Message, recache: bool) void {
        for (self.jobs.items, 0..) |j, i| {
            if (j == job) {
                _ = self.jobs.orderedRemove(i);
                break;
            }
        }
        if (recache) self.cachePut(job.pending_qname, job.pending_qtype, msg.rrs);
        const ttl = minTtl(msg.rrs);
        const prev_cb = self.in_callback;
        self.in_callback = job;
        for (job.waiters[0..job.waiter_count], 0..) |key, w| {
            if (job.waiter_cancelled & (@as(u16, 1) << @intCast(w)) != 0) continue;
            const detached = self.dupRrs(msg.rrs) catch {
                self.qcb.fun(self.qcb.ctx, key, .failed, null);
                continue;
            };
            self.qcb.fun(self.qcb.ctx, key, .resolved, .{ .rrs = detached, .ttl = ttl });
        }
        self.in_callback = prev_cb;
        self.freeJob(job);
        self.promoteWait();
    }

    fn minTtl(rrs: []const wire.Rr) u32 {
        var m: u32 = std.math.maxInt(u32);
        for (rrs) |rr| {
            // RFC 2181: the TTL field is 31 bits; a set top bit means 0.
            const t = if (rr.ttl & 0x8000_0000 != 0) 0 else rr.ttl;
            m = @min(m, t);
        }
        return if (m == std.math.maxInt(u32)) 0 else m;
    }

    fn dupRrs(self: *Resolver, rrs: []const wire.Rr) ![]wire.Rr {
        const out = try self.alloc.alloc(wire.Rr, rrs.len);
        var built: usize = 0;
        errdefer {
            for (out[0..built]) |rr| {
                self.alloc.free(rr.name);
                self.alloc.free(rr.rdata);
            }
            self.alloc.free(out);
        }
        for (rrs, 0..) |rr, i| {
            const nb = try self.alloc.dupe(u8, rr.name);
            errdefer self.alloc.free(nb);
            const rb = try self.alloc.dupe(u8, rr.rdata);
            out[i] = .{ .name = nb, .rtype = rr.rtype, .class = rr.class, .ttl = rr.ttl, .rdata = rb };
            built += 1;
        }
        return out;
    }

    fn freeRrs(self: *Resolver, rrs: []wire.Rr) void {
        for (rrs) |rr| {
            self.alloc.free(rr.name);
            self.alloc.free(rr.rdata);
        }
        self.alloc.free(rrs);
    }

    // -- bounded TTL cache -------------------------------------------------

    /// Folded owner key: the qname lowercased on the stack. DNS names
    /// compare case-insensitively, so lookups keyed on the wire form
    /// must fold or a cased duplicate misses.
    fn foldName(buf: []u8, qname: []const u8) ?[]u8 {
        if (qname.len > buf.len) return null;
        for (qname, 0..) |c, i| buf[i] = std.ascii.toLower(c);
        return buf[0..qname.len];
    }

    fn findTypeRow(owner: *OwnerEnt, rtype: u16) ?usize {
        for (owner.types.items, 0..) |ent, i| {
            if (ent.rtype == rtype) return i;
        }
        return null;
    }

    /// Classify the cached row for (qname, rtype): fresh below
    /// expires_ms, stale until stale_ms, and a miss past that (the
    /// dead row is pruned on the spot). A hit moves the owner to the
    /// LRU head. No allocation on this path.
    fn cacheGetClass(self: *Resolver, qname: []const u8, rtype: u16) ?CacheClass {
        var name_buf: [280]u8 = undefined;
        const folded = foldName(&name_buf, qname) orelse return null;
        const owner = self.owners.get(folded) orelse return null;
        const idx = findTypeRow(owner, rtype) orelse return null;
        const now = self.now_ms();
        const ent = owner.types.items[idx];
        if (now < ent.expires_ms) {
            self.lru.remove(&owner.node);
            self.lru.prepend(&owner.node);
            return .{ .fresh = .{ .owner = owner, .ent = ent } };
        }
        if (now < ent.stale_ms) {
            self.lru.remove(&owner.node);
            self.lru.prepend(&owner.node);
            return .{ .stale = .{ .owner = owner, .ent = ent } };
        }
        // Past even the serve-stale window: prune the dead row now
        // rather than waiting for memory pressure to collect it; a
        // row pinned by an in-flight refresh dies with its job.
        if (!ent.refreshing) {
            self.removeTypeRow(owner, idx);
            if (owner.types.items.len == 0) self.removeOwner(owner);
        }
        return null;
    }

    /// Fresh-hit lookup for callers that only want live data.
    fn cacheGet(self: *Resolver, qname: []const u8, rtype: u16) ?*TypeEnt {
        const class = self.cacheGetClass(qname, rtype) orelse return null;
        return switch (class) {
            .fresh => |h| h.ent,
            .stale => null,
        };
    }

    /// Insert or replace the (qname, rtype) row with a deep copy of
    /// `rrs`. An answer carrying a CNAME record proves the owner is
    /// an alias: RFC 8767 section 7 then invalidates the owner's
    /// other cached types, so they are evicted here (a row pinned by
    /// an in-flight refresh survives - it is replaced or failed out
    /// when its refresh concludes). Bounds are enforced after the
    /// insert, stale rows evicting before fresh ones.
    fn cacheInsert(self: *Resolver, qname: []const u8, rtype: u16, rrs: []const wire.Rr, neg: NegKind, ttl_s: u32) void {
        var name_buf: [280]u8 = undefined;
        const folded = foldName(&name_buf, qname) orelse return;
        const now = self.now_ms();
        const dup = self.dupRrs(rrs) catch return;

        const owner = self.owners.get(folded) orelse owner: {
            const name = self.alloc.dupe(u8, folded) catch {
                self.freeRrs(dup);
                return;
            };
            const o = self.alloc.create(OwnerEnt) catch {
                self.alloc.free(name);
                self.freeRrs(dup);
                return;
            };
            o.* = .{ .name = name };
            self.owners.put(self.alloc, o.name, o) catch {
                self.alloc.destroy(o);
                self.alloc.free(name);
                self.freeRrs(dup);
                return;
            };
            self.lru.prepend(&o.node);
            o.bytes = @sizeOf(OwnerEnt) + name.len;
            self.cache_bytes += o.bytes;
            break :owner o;
        };

        const expires_ms = now + @as(i64, ttl_s) * 1000;
        if (findTypeRow(owner, rtype)) |idx| {
            const ent = owner.types.items[idx];
            const old_bytes = typeEntBytes(ent);
            self.freeRrs(ent.rrs);
            ent.* = .{
                .rtype = rtype,
                .neg = neg,
                .rrs = dup,
                .expires_ms = expires_ms,
                .stale_ms = expires_ms + STALE_MAX_MS,
                // A replace must keep the refresh pin: another job may
                // still borrow this row, and dropping the flag lets
                // a CNAME answer or eviction free it under it.
                .refreshing = ent.refreshing,
            };
            const new_bytes = typeEntBytes(ent);
            owner.bytes = owner.bytes - old_bytes + new_bytes;
            self.cache_bytes = self.cache_bytes - old_bytes + new_bytes;
        } else {
            const ent = self.alloc.create(TypeEnt) catch {
                if (owner.types.items.len == 0) self.removeOwner(owner);
                self.freeRrs(dup);
                return;
            };
            ent.* = .{
                .rtype = rtype,
                .neg = neg,
                .rrs = dup,
                .expires_ms = expires_ms,
                .stale_ms = expires_ms + STALE_MAX_MS,
            };
            owner.types.append(self.alloc, ent) catch {
                self.alloc.destroy(ent);
                if (owner.types.items.len == 0) self.removeOwner(owner);
                self.freeRrs(dup);
                return;
            };
            const new_bytes = typeEntBytes(ent);
            owner.bytes += new_bytes;
            self.cache_bytes += new_bytes;
        }
        self.lru.remove(&owner.node);
        self.lru.prepend(&owner.node);

        for (dup) |rr| {
            if (rr.rtype != wire.TYPE_CNAME) continue;
            var i: usize = 0;
            while (i < owner.types.items.len) {
                const ent = owner.types.items[i];
                if (ent.rtype != rtype and !ent.refreshing) {
                    self.removeTypeRow(owner, i);
                    continue;
                }
                i += 1;
            }
            break;
        }
        self.cacheEnforceBounds(now);
    }

    /// Store a second deep copy of the answer under (qname, qtype) with a
    /// TTL-derived expiry, capped at CACHE_TTL_CEIL_S; TTL 0 is not
    /// cached but still replaces the row it refreshed (ADR-13).
    fn cachePut(self: *Resolver, qname: []const u8, qtype: u16, rrs: []const wire.Rr) void {
        const ttl = @min(minTtl(rrs), CACHE_TTL_CEIL_S);
        if (ttl == 0) {
            // completeRaw also calls here with the empty slice right
            // after cachePutNeg handled the negative answer, so only
            // a non-empty answer drops the row.
            if (rrs.len > 0) self.cacheDrop(qname, qtype);
            return;
        }
        self.cacheInsert(qname, qtype, rrs, .none, ttl);
    }

    /// Negative caching per RFC 2308: NXDOMAIN and NODATA answers live
    /// as long as the zone's SOA minimum (the last u32 of the SOA
    /// rdata), capped at the same ceiling. An answer with no SOA or a
    /// zero minimum is not cached but still replaces the row.
    fn cachePutNeg(self: *Resolver, qname: []const u8, qtype: u16, neg: NegKind, msg: wire.Message) void {
        const ttl = @min(soaMinimum(msg) orelse return self.cacheDrop(qname, qtype), CACHE_TTL_CEIL_S);
        if (ttl == 0) return self.cacheDrop(qname, qtype);
        self.cacheInsert(qname, qtype, &.{}, neg, ttl);
    }

    /// A NOERROR or NXDOMAIN answer that cannot be cached still
    /// replaces the row it answered (ADR-13: NOERROR and NXDOMAIN
    /// always replace): drop it unless a refresh pins it, so a later
    /// SERVFAIL fails the lookup instead of serving the stale row.
    fn cacheDrop(self: *Resolver, qname: []const u8, qtype: u16) void {
        var name_buf: [280]u8 = undefined;
        const folded = foldName(&name_buf, qname) orelse return;
        const owner = self.owners.get(folded) orelse return;
        const idx = findTypeRow(owner, qtype) orelse return;
        if (owner.types.items[idx].refreshing) return;
        self.removeTypeRow(owner, idx);
        if (owner.types.items.len == 0) self.removeOwner(owner);
    }

    /// The SOA "minimum" field is the last u32 of the record's rdata;
    /// the owner names that precede it stay unparsed.
    fn soaMinimum(msg: wire.Message) ?u32 {
        for (msg.rrs) |rr| {
            if (rr.section != .authority) continue;
            if (rr.rtype != KIND_SOA) continue;
            if (rr.rdata.len < 20) continue;
            return std.mem.readInt(u32, rr.rdata[rr.rdata.len - 4 ..][0..4], .big);
        }
        return null;
    }

    /// Accounted size of one type row: the row object, its slot in the
    /// owner's row table, and every record's struct, name and rdata.
    fn typeEntBytes(ent: *const TypeEnt) usize {
        var n: usize = @sizeOf(TypeEnt) + @sizeOf(*TypeEnt);
        for (ent.rrs) |rr| n += @sizeOf(wire.Rr) + rr.name.len + rr.rdata.len;
        return n;
    }

    /// An owner with any row still inside its fresh window.
    fn ownerHasFresh(owner: *const OwnerEnt, now: i64) bool {
        for (owner.types.items) |ent| {
            if (now < ent.expires_ms) return true;
        }
        return false;
    }

    /// An owner pinned against eviction: a refreshing row may be
    /// borrowed by the job refreshing it.
    fn ownerPinned(owner: *const OwnerEnt) bool {
        for (owner.types.items) |ent| {
            if (ent.refreshing) return true;
        }
        return false;
    }

    /// Enforce the entry and byte bounds after an insert, evicting
    /// until both hold (or only pinned owners remain).
    fn cacheEnforceBounds(self: *Resolver, now: i64) void {
        while (self.owners.count() > CACHE_ENTRIES_MAX or self.cache_bytes > CACHE_BYTES_MAX) {
            if (!self.evictOne(now)) return;
        }
    }

    /// Evict one owner, stale rows before fresh ones (ADR-13 /
    /// RFC 8767 section 6): the LRU tail is walked for the first
    /// owner holding no fresh row; an all-fresh window sheds its
    /// tail-most unpinned owner instead. The walk is bounded to
    /// EVICT_SCAN_MAX nodes so an insert over budget never costs an
    /// O(owners) scan; a stale owner deeper than the window keeps
    /// its slot. The bound lifts only while every node seen is
    /// pinned, so an all-pinned window still reaches an evictable
    /// owner further up. Returns false when nothing can be evicted.
    fn evictOne(self: *Resolver, now: i64) bool {
        var tail_fresh: ?*OwnerEnt = null;
        var saw_unpinned = false;
        var scanned: usize = 0;
        var node = self.lru.last;
        while (node) |n| : (node = n.prev) {
            const owner: *OwnerEnt = @fieldParentPtr("node", n);
            scanned += 1;
            if (!ownerPinned(owner)) {
                saw_unpinned = true;
                if (!ownerHasFresh(owner, now)) {
                    self.removeOwner(owner);
                    return true;
                }
                if (tail_fresh == null) tail_fresh = owner;
            }
            if (scanned >= EVICT_SCAN_MAX and saw_unpinned) break;
        }
        if (tail_fresh) |owner| {
            self.removeOwner(owner);
            return true;
        }
        return false;
    }

    /// Drop one type row and its accounting. The caller must not hold
    /// a pointer to the row (a refreshing row is never dropped here).
    fn removeTypeRow(self: *Resolver, owner: *OwnerEnt, idx: usize) void {
        const ent = owner.types.items[idx];
        const b = typeEntBytes(ent);
        self.freeTypeEnt(ent);
        _ = owner.types.swapRemove(idx);
        owner.bytes -= b;
        self.cache_bytes -= b;
    }

    /// Unlink and free an owner with all its rows and accounting.
    fn removeOwner(self: *Resolver, owner: *OwnerEnt) void {
        _ = self.owners.remove(owner.name);
        self.lru.remove(&owner.node);
        self.freeOwner(owner);
    }

    fn freeTypeEnt(self: *Resolver, ent: *TypeEnt) void {
        if (ent.rrs.len > 0) self.freeRrs(ent.rrs);
        self.alloc.destroy(ent);
    }

    fn freeOwner(self: *Resolver, owner: *OwnerEnt) void {
        for (owner.types.items) |ent| self.freeTypeEnt(ent);
        owner.types.deinit(self.alloc);
        self.cache_bytes -= owner.bytes;
        self.alloc.free(owner.name);
        self.alloc.destroy(owner);
    }

    fn onNxdomain(self: *Resolver, job: *Job) void {
        if (job.is_raw) return self.dropJob(job, .nxdomain);
        switch (job.phase) {
            .srv_tls => {
                job.phase = .srv_plain;
                self.sendSrv(job, SRV_PLAIN[job.service_idx]) catch return self.dropJob(job, .failed);
            },
            .srv_plain => self.startFallback(job),
            // Per fallback family: NXDOMAIN on one family still lets
            // the other family answer.
            .fallback_addr => {
                job.phase = .fallback_addr4;
                self.sendFallback(job, KIND_A) catch return self.dropJob(job, .failed);
            },
            .fallback_addr4 => self.finishFallback(job),
            // Per target: an NXDOMAIN on either address family means
            // that family is gone; the family that resolved still
            // emits the target.
            .addr => {
                job.phase = .addr6;
                self.sendAddr(job, KIND_AAAA) catch return self.finishTarget(job);
            },
            .addr6 => self.finishTarget(job),
            .tlsa => {
                // TLSA NXDOMAIN keeps the target, just without DANE.
                self.emitAndAdvance(job, &.{}, .absent);
            },
            .fallback_tlsa => {
                self.emitFallbackTargets(job, &.{}, .absent) catch return self.dropJob(job, .failed);
                self.complete(job);
            },
            .raw, .done => {},
        }
    }

    // -- chain advance ------------------------------------------------------

    fn advance(self: *Resolver, job: *Job, msg: wire.Message) void {
        switch (job.phase) {
            .srv_tls, .srv_plain => {
                const direct_tls = job.phase == .srv_tls;
                self.absorbSrv(job, msg, direct_tls);
                var live: usize = 0;
                var dots: usize = 0;
                for (job.srv_list.items) |e| {
                    if (e.unavailable) dots += 1 else live += 1;
                }
                if (live == 0) {
                    if (direct_tls) {
                        // RFC 2782 "." on the _xmpps name says "no
                        // direct TLS", not "no service" (XEP-0368): an
                        // empty answer means the same here. Either way
                        // the STARTTLS name still gets its try.
                        self.clearSrvList(job);
                        job.phase = .srv_plain;
                        self.sendSrv(job, SRV_PLAIN[job.service_idx]) catch return self.dropJob(job, .failed);
                        return;
                    }
                    // "." on the STARTTLS name too is the domain saying
                    // "no XMPP service here"; an empty answer is the
                    // ordinary no-SRV fallback.
                    if (dots > 0) return self.dropJob(job, .service_unavailable);
                    return self.startFallback(job);
                }
                orderSrvRfc2782(job.srv_list.items, self.prng.random());
                job.srv_pos = 0;
                job.phase = .addr;
                self.stepTargetAddr(job) catch return self.dropJob(job, .failed);
            },
            .addr => {
                const target = &job.srv_list.items[job.srv_pos];
                for (msg.rrs) |rr| {
                    if (rr.rtype == KIND_A and job.cur_addr4 == null) {
                        job.cur_addr4 = addrFromRdata(rr, target.port) catch null;
                    }
                }
                job.phase = .addr6;
                self.sendAddr(job, KIND_AAAA) catch {
                    job.target_err = true;
                    return self.finishTarget(job);
                };
            },
            .addr6 => {
                const target = &job.srv_list.items[job.srv_pos];
                for (msg.rrs) |rr| {
                    if (rr.rtype == KIND_AAAA and job.cur_addr6 == null) {
                        job.cur_addr6 = addrFromRdata(rr, target.port) catch null;
                    }
                }
                if (job.cur_addr4 == null and job.cur_addr6 == null) {
                    // This target has no usable address; the next one
                    // in RFC 2782 order is still tried.
                    self.nextTarget(job) catch return self.dropJob(job, .failed);
                    return;
                }
                if (job.want_tlsa) {
                    job.phase = .tlsa;
                    self.sendTlsa(job) catch return self.failTargetTlsa(job);
                    return;
                }
                self.emitAndAdvance(job, &.{}, .absent);
            },
            .tlsa => {
                var tlsa_recs: std.ArrayList(dns.TlsaRecord) = .{};
                defer {
                    for (tlsa_recs.items) |r| self.alloc.free(r.association_data);
                    tlsa_recs.deinit(self.alloc);
                }
                var saw = false;
                for (msg.rrs) |rr| {
                    if (rr.rtype != KIND_TLSA) continue;
                    saw = true;
                    const rec = dns.parseTlsaRdata(rr.rdata, self.alloc) catch continue;
                    tlsa_recs.append(self.alloc, rec) catch continue;
                }
                // Parsed records are .present; an answer whose TLSA
                // records all failed to parse is lookup_failed (the
                // lookup produced nothing usable), and a NOERROR
                // answer with no TLSA records at all is .absent.
                const status: TlsaStatus = if (tlsa_recs.items.len > 0) .present else if (saw) .lookup_failed else .absent;
                self.emitAndAdvance(job, tlsa_recs.items, status);
            },
            .fallback_tlsa => {
                var tlsa_recs: std.ArrayList(dns.TlsaRecord) = .{};
                defer {
                    for (tlsa_recs.items) |r| self.alloc.free(r.association_data);
                    tlsa_recs.deinit(self.alloc);
                }
                var saw = false;
                for (msg.rrs) |rr| {
                    if (rr.rtype != KIND_TLSA) continue;
                    saw = true;
                    const rec = dns.parseTlsaRdata(rr.rdata, self.alloc) catch continue;
                    tlsa_recs.append(self.alloc, rec) catch continue;
                }
                // The fallback targets share one host: the same TLSA
                // owner name covers every emitted address. As above:
                // parsed records .present, all-unparsable
                // lookup_failed, no records .absent.
                const status: TlsaStatus = if (tlsa_recs.items.len > 0) .present else if (saw) .lookup_failed else .absent;
                self.emitFallbackTargets(job, tlsa_recs.items, status) catch return self.dropJob(job, .failed);
                self.complete(job);
            },
            .fallback_addr => {
                for (msg.rrs) |rr| {
                    if (rr.rtype == KIND_AAAA and job.cur_addr6 == null) {
                        job.cur_addr6 = addrFromRdata(rr, job.default_port) catch null;
                    }
                }
                job.phase = .fallback_addr4;
                self.sendFallback(job, KIND_A) catch return self.dropJob(job, .failed);
            },
            .fallback_addr4 => {
                for (msg.rrs) |rr| {
                    if (rr.rtype == KIND_A and job.cur_addr4 == null) {
                        job.cur_addr4 = addrFromRdata(rr, job.default_port) catch null;
                    }
                }
                self.finishFallback(job);
            },
            .raw, .done => {},
        }
    }

    fn absorbSrv(self: *Resolver, job: *Job, msg: wire.Message, direct_tls: bool) void {
        for (msg.rrs) |rr| {
            if (rr.rtype != KIND_SRV) continue;
            const parsed = dns.parseSrvRdata(rr.rdata, self.alloc) catch continue;
            if (job.srv_list.items.len >= SRV_CAP) {
                self.alloc.free(parsed.target);
                continue;
            }
            job.srv_list.append(self.alloc, .{
                .host = parsed.target,
                .port = parsed.port,
                .priority = parsed.priority,
                .weight = parsed.weight,
                .is_direct_tls = direct_tls,
                .unavailable = std.mem.eql(u8, parsed.target, "."),
            }) catch continue;
        }
    }

    /// Free every parsed SRV entry; used when a prefix falls through
    /// to the next name so stale "." markers cannot leak in.
    fn clearSrvList(self: *Resolver, job: *Job) void {
        for (job.srv_list.items) |s| self.alloc.free(s.host);
        job.srv_list.clearRetainingCapacity();
        job.srv_pos = 0;
    }

    /// Begin (or continue) the per-target chain: a target marked "." is
    /// skipped; the first live target gets an A query.
    fn stepTargetAddr(self: *Resolver, job: *Job) !void {
        if (job.targets.items.len >= TARGET_CAP) return self.complete(job);
        while (job.srv_pos < job.srv_list.items.len and
            job.srv_list.items[job.srv_pos].unavailable)
        {
            job.srv_pos += 1;
        }
        if (job.srv_pos >= job.srv_list.items.len) {
            if (job.targets.items.len == 0) {
                // Every entry was consumed without yielding an address;
                // an all-"." list reports the domain's explicit "no
                // service" instead of a missing name.
                var all_dot = job.srv_list.items.len > 0;
                for (job.srv_list.items) |e| {
                    if (!e.unavailable) all_dot = false;
                }
                return self.dropJob(job, if (all_dot) .service_unavailable else if (job.target_err) .failed else .nxdomain);
            }
            return self.complete(job);
        }
        job.cur_addr4 = null;
        job.cur_addr6 = null;
        job.phase = .addr;
        try self.sendAddr(job, KIND_A);
    }

    /// Move to the next SRV target in order, or complete the job.
    fn nextTarget(self: *Resolver, job: *Job) !void {
        job.srv_pos += 1;
        try self.stepTargetAddr(job);
    }

    /// Emit the current target's collected addresses: AAAA first, then
    /// A, each carrying the per-target TLSA set and the direct-TLS flag.
    fn emitTargets(self: *Resolver, job: *Job, tlsa_recs: []dns.TlsaRecord, status: TlsaStatus) !void {
        const ent = &job.srv_list.items[job.srv_pos];
        const addrs = [2]?net.Address{ job.cur_addr6, job.cur_addr4 };
        for (addrs) |a| {
            const addr = a orelse continue;
            try self.emitTarget(job, ent, addr, tlsa_recs, status);
        }
    }

    /// Emit the current target's addresses with `status` and move on
    /// to the next SRV target in RFC 2782 order.
    fn emitAndAdvance(self: *Resolver, job: *Job, tlsa_recs: []dns.TlsaRecord, status: TlsaStatus) void {
        self.emitTargets(job, tlsa_recs, status) catch return self.dropJob(job, .failed);
        job.cur_addr4 = null;
        job.cur_addr6 = null;
        self.nextTarget(job) catch return self.dropJob(job, .failed);
    }

    /// The current target's TLSA query failed or could not be sent:
    /// ADR-13 marks the target lookup_failed (a temporary failure,
    /// never PKIX) and the chain moves on to the next SRV target.
    fn failTargetTlsa(self: *Resolver, job: *Job) void {
        self.emitAndAdvance(job, &.{}, .lookup_failed);
    }

    /// Deep-copy a parsed TLSA set; every emitted target owns its own
    /// copy because Resolution teardown frees each.
    fn dupeTlsa(self: *Resolver, recs: []dns.TlsaRecord) ![]dns.TlsaRecord {
        if (recs.len == 0) return &.{};
        const tlsa = try self.alloc.alloc(dns.TlsaRecord, recs.len);
        var n: usize = 0;
        errdefer {
            for (tlsa[0..n]) |r| self.alloc.free(r.association_data);
            self.alloc.free(tlsa);
        }
        for (recs, 0..) |rec, i| {
            tlsa[i] = rec;
            tlsa[i].association_data = try self.alloc.dupe(u8, rec.association_data);
            n += 1;
        }
        return tlsa;
    }

    fn emitTarget(self: *Resolver, job: *Job, ent: *const SrvEnt, addr: net.Address, tlsa_recs: []dns.TlsaRecord, status: TlsaStatus) !void {
        if (job.targets.items.len >= TARGET_CAP) return;
        const host = try self.alloc.dupe(u8, ent.host);
        errdefer self.alloc.free(host);
        const tlsa = try self.dupeTlsa(tlsa_recs);
        try job.targets.append(self.alloc, .{ .addr = addr, .host = host, .tlsa = tlsa, .tlsa_status = status, .is_direct_tls = ent.is_direct_tls });
    }

    fn sendAddr(self: *Resolver, job: *Job, qtype: u16) !void {
        const ent = &job.srv_list.items[job.srv_pos];
        var buf: [280]u8 = undefined;
        const qname = std.fmt.bufPrint(&buf, "{s}", .{ent.host}) catch return self.onNxdomain(job);
        try self.sendQuery(job, qname, qtype);
    }

    fn sendTlsa(self: *Resolver, job: *Job) !void {
        const ent = &job.srv_list.items[job.srv_pos];
        var buf: [280]u8 = undefined;
        const qname = dns.tlsaQueryName(&buf, ent.port, ent.host) catch return self.onNxdomain(job);
        try self.sendQuery(job, qname, KIND_TLSA);
    }

    /// The no-SRV fallback asks the bare name for an address; called
    /// once per family so a dual-stack host yields both targets.
    fn sendFallback(self: *Resolver, job: *Job, qtype: u16) !void {
        var buf: [280]u8 = undefined;
        const qname = std.fmt.bufPrint(&buf, "{s}", .{job.name}) catch return self.onNxdomain(job);
        try self.sendQuery(job, qname, qtype);
    }

    /// Both fallback families have answered or failed: emit what
    /// arrived (AAAA first), answer nxdomain when nothing did, and
    /// report .failed only when a family query actually errored.
    /// With want_tlsa the targets are held until the TLSA query
    /// concludes: emitting them bare first would let a chain deadline
    /// hand out "no DANE" targets whose lookup is still in flight.
    fn finishFallback(self: *Resolver, job: *Job) void {
        if (job.cur_addr4 == null and job.cur_addr6 == null) {
            return self.dropJob(job, if (job.fallback_err) .failed else .nxdomain);
        }
        if (!job.want_tlsa) {
            self.emitFallbackTargets(job, &.{}, .absent) catch return self.dropJob(job, .failed);
            return self.complete(job);
        }
        job.phase = .fallback_tlsa;
        var buf: [280]u8 = undefined;
        const qname = dns.tlsaQueryName(&buf, job.default_port, job.name) catch return self.dropJob(job, .failed);
        self.sendQuery(job, qname, KIND_TLSA) catch {
            self.emitFallbackTargets(job, &.{}, .lookup_failed) catch return self.dropJob(job, .failed);
            return self.complete(job);
        };
    }

    /// Emit the collected fallback addresses as targets under
    /// `job.name`, each carrying the shared TLSA answer and status.
    /// Idempotent: the collected addresses are cleared on emit.
    fn emitFallbackTargets(self: *Resolver, job: *Job, tlsa_recs: []dns.TlsaRecord, status: TlsaStatus) !void {
        const addrs = [2]?net.Address{ job.cur_addr6, job.cur_addr4 };
        job.cur_addr4 = null;
        job.cur_addr6 = null;
        for (addrs) |a| {
            const addr = a orelse continue;
            if (job.targets.items.len >= TARGET_CAP) return;
            const host = try self.alloc.dupe(u8, job.name);
            errdefer self.alloc.free(host);
            const tlsa = try self.dupeTlsa(tlsa_recs);
            try job.targets.append(self.alloc, .{
                .addr = addr,
                .host = host,
                .tlsa = tlsa,
                .tlsa_status = status,
                .is_direct_tls = false,
            });
        }
    }

    fn freeJob(self: *Resolver, job: *Job) void {
        // A refresh that dies without an answer is a failed refresh:
        // stamp last_fail_ms so the next lookup serves stale inside
        // the recheck window instead of refreshing again at once.
        if (job.stale) |hit| {
            hit.ent.refreshing = false;
            hit.ent.last_fail_ms = self.now_ms();
        }
        if (self.slots[job.slot] == job) self.slots[job.slot] = null;
        self.disarmDeadline(job);
        self.tcpClose(job);
        job.tcp_buf.deinit(self.alloc);
        job.tcp_out.deinit(self.alloc);
        self.alloc.free(job.name);
        if (job.request.len > 0) self.alloc.free(job.request);
        if (job.pending_qname.len > 0) self.alloc.free(job.pending_qname);
        for (job.srv_list.items) |s| {
            self.alloc.free(s.host);
        }
        job.srv_list.deinit(self.alloc);
        for (job.targets.items) |t| {
            self.alloc.free(t.host);
            for (t.tlsa) |r| self.alloc.free(r.association_data);
            if (t.tlsa.len > 0) self.alloc.free(t.tlsa);
        }
        job.targets.deinit(self.alloc);
        self.alloc.destroy(job);
    }

    fn startFallback(self: *Resolver, job: *Job) void {
        job.phase = .fallback_addr;
        job.cur_addr4 = null;
        job.cur_addr6 = null;
        job.fallback_err = false;
        self.sendFallback(job, KIND_AAAA) catch return self.dropJob(job, .failed);
    }
};

// -- raw socket calls -------------------------------------------------------
//
// std.posix maps several socket errnos to unreachable (ENOTCONN on
// send, EBADF/EINVAL on recv and kevent, EISCONN/ECONNABORTED on
// connect). A wire-level event must never panic the process, so the
// send/recv/connect paths below use std.c directly and their errno
// tables have no unreachable arm: anything unmapped is a plain
// failure the caller already handles.

const SockErr = error{ WouldBlock, Refused, Closed, Failed };

fn rawSend(fd: posix.fd_t, buf: []const u8, flags: u32) SockErr!usize {
    while (true) {
        const rc = std.c.sendto(fd, buf.ptr, buf.len, flags, null, 0);
        if (rc >= 0) return @intCast(rc);
        switch (posix.errno(rc)) {
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNREFUSED => return error.Refused,
            .PIPE, .CONNRESET => return error.Closed,
            else => return error.Failed,
        }
    }
}

fn rawRecv(fd: posix.fd_t, buf: []u8, flags: u32) SockErr!usize {
    while (true) {
        const rc = std.c.recvfrom(fd, buf.ptr, buf.len, flags, null, null);
        if (rc >= 0) return @intCast(rc);
        switch (posix.errno(rc)) {
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNREFUSED => return error.Refused,
            .CONNRESET => return error.Closed,
            else => return error.Failed,
        }
    }
}

fn rawConnect(fd: posix.fd_t, addr: *const posix.sockaddr, len: posix.socklen_t) error{ WouldBlock, Failed }!void {
    while (true) {
        const rc = std.c.connect(fd, addr, len);
        if (rc == 0) return;
        switch (posix.errno(rc)) {
            .INTR => continue,
            .AGAIN, .INPROGRESS, .ALREADY => return error.WouldBlock,
            else => return error.Failed,
        }
    }
}

/// SO_ERROR on a pending connect: a nonzero value means the connect
/// failed (refused, unreachable, dead socket); the getsockopt call
/// itself failing is the same dead-socket report.
fn rawSoError(fd: posix.fd_t) error{Failed}!void {
    var code: c_int = 0;
    var len: posix.socklen_t = @sizeOf(c_int);
    if (std.c.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, &code, &len) != 0)
        return error.Failed;
    if (code != 0) return error.Failed;
}

fn rawKevent(kq: posix.fd_t, ch: []const posix.Kevent, events: []posix.Kevent, ts: ?*const std.c.timespec) error{KeventFailed}!usize {
    while (true) {
        const rc = std.c.kevent(kq, ch.ptr, @intCast(ch.len), events.ptr, @intCast(events.len), ts);
        if (rc >= 0) return @intCast(rc);
        switch (posix.errno(rc)) {
            .INTR => continue,
            else => return error.KeventFailed,
        }
    }
}

fn addrFromRdata(rr: wire.Rr, port: u16) !net.Address {
    switch (rr.rtype) {
        KIND_A => {
            if (rr.rdata.len < 4) return error.InvalidRdata;
            var octets: [4]u8 = undefined;
            @memcpy(&octets, rr.rdata[0..4]);
            return net.Address.initIp4(octets, port);
        },
        KIND_AAAA => {
            if (rr.rdata.len < 16) return error.InvalidRdata;
            var octets: [16]u8 = undefined;
            @memcpy(&octets, rr.rdata[0..16]);
            return net.Address.initIp6(octets, port, 0, 0);
        },
        else => return error.InvalidRdata,
    }
}

/// Decode the first question's (qname, qtype) for response demux. The
/// wire parser skips the question section, so this walks it directly.
const Question = struct { qname: []const u8, qtype: u16 };

fn parseQuestion(alloc: std.mem.Allocator, pkt: []const u8) !Question {
    if (pkt.len < 12) return error.Truncated;
    const qdcount = std.mem.readInt(u16, pkt[4..6], .big);
    if (qdcount == 0) return error.NoQuestion;
    const nm = try wire.decompressName(pkt, 12, alloc);
    const off = nm.next;
    if (off + 4 > pkt.len) return error.Truncated;
    return .{ .qname = nm.name, .qtype = std.mem.readInt(u16, pkt[off..][0..2], .big) };
}

/// RFC 2782 ordering: sort by priority, then within a priority pick
/// targets with probability proportional to weight. Weight-0 records
/// are placed at the beginning of each round so an inclusive random
/// draw still gives them a small chance.
fn orderSrvRfc2782(items: []SrvEnt, rand: std.Random) void {
    std.mem.sort(SrvEnt, items, {}, struct {
        fn lt(_: void, a: SrvEnt, b: SrvEnt) bool {
            return a.priority < b.priority;
        }
    }.lt);
    var i: usize = 0;
    while (i < items.len) {
        var j = i;
        while (j < items.len and items[j].priority == items[i].priority) : (j += 1) {}
        const group = items[i..j];
        // Stable partition: weight-0 records lead each pick round.
        std.mem.sort(SrvEnt, group, {}, struct {
            fn lt(_: void, a: SrvEnt, b: SrvEnt) bool {
                return (a.weight == 0) != (b.weight == 0) and a.weight == 0;
            }
        }.lt);
        var k: usize = 0;
        while (k < group.len) : (k += 1) {
            var total: u64 = 0;
            for (group[k..]) |it| total += it.weight;
            const r = rand.intRangeAtMost(u64, 0, total);
            var acc: u64 = 0;
            var pick: usize = k;
            for (group[k..], k..) |it, m| {
                acc += it.weight;
                if (r <= acc) {
                    pick = m;
                    break;
                }
            }
            std.mem.swap(SrvEnt, &group[k], &group[pick]);
        }
        i = j;
    }
}

fn nowMs() i64 {
    // Monotonic: a wall-clock step must not prematurely expire or
    // extend cache entries. The clock id is comptime-fixed, so the
    // call cannot fail on a conforming kernel.
    const ts = std.posix.clock_gettime(.MONOTONIC) catch unreachable;
    return ts.sec * 1000 + @divTrunc(ts.nsec, 1_000_000);
}

/// Parse resolv.conf the way FreeBSD libc's res_init does: a ';' or
/// '#' comments out the line only in column 0, the "nameserver"
/// keyword must start the line, and the address token ends at the
/// first blank, ';', or '#'. The whole file is read so a long
/// preamble cannot hide a nameserver past the first read.
fn readResolvConf(alloc: std.mem.Allocator, path: []const u8) !net.Address {
    const f = try std.fs.cwd().openFile(path, .{});
    defer f.close();
    const data = try f.readToEndAlloc(alloc, 1 << 20);
    defer alloc.free(data);
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == ';' or line[0] == '#') continue;
        if (!std.mem.startsWith(u8, line, "nameserver")) continue;
        const rest = line["nameserver".len..];
        // libc MATCH(): a blank or tab must follow the keyword, so
        // "nameserver9.9.9.9" is not a nameserver line.
        if (rest.len == 0 or (rest[0] != ' ' and rest[0] != '\t')) continue;
        const start = std.mem.indexOfNone(u8, rest, " \t") orelse continue;
        const tail = rest[start..];
        const tok = tail[0 .. std.mem.indexOfAny(u8, tail, ";# \t") orelse tail.len];
        if (tok.len == 0) continue;
        if (net.Address.parseIp(tok, 53)) |addr| {
            // std accepts a lone zone marker ("fe80::1%") and numeric
            // zones; libc rejects the empty zone and any zone on a
            // non-v6 address.
            if (std.mem.indexOfScalar(u8, tok, '%')) |pct| {
                if (pct + 1 == tok.len) continue;
                if (addr.any.family != posix.AF.INET6) continue;
            }
            return addr;
        } else |_| {
            // libc ip6_str2scopeid: a numeric zone applies to any IPv6
            // address; a named zone applies to link-local (fe80::/10)
            // and ffx1/ffx2 multicast, resolved via if_nametoindex.
            const pct = std.mem.indexOfScalar(u8, tok, '%') orelse continue;
            var addr = net.Address.parseIp(tok[0..pct], 53) catch continue;
            if (addr.any.family != posix.AF.INET6) continue;
            const zname = tok[pct + 1 ..];
            var zbuf: [16]u8 = undefined;
            if (zname.len == 0 or zname.len >= zbuf.len) continue;
            var numeric = true;
            for (zname) |c| {
                if (!std.ascii.isDigit(c)) {
                    numeric = false;
                    break;
                }
            }
            if (numeric) {
                addr.in6.sa.scope_id = std.fmt.parseInt(u32, zname, 10) catch continue;
                return addr;
            }
            const ab = &addr.in6.sa.addr;
            const linklocal = ab[0] == 0xfe and (ab[1] & 0xc0) == 0x80;
            const mc_scope = ab[1] & 0x0f;
            const mc_named = ab[0] == 0xff and (mc_scope == 0x01 or mc_scope == 0x02);
            if (!linklocal and !mc_named) continue;
            @memcpy(zbuf[0..zname.len], zname);
            zbuf[zname.len] = 0;
            const idx = std.c.if_nametoindex(zbuf[0..zname.len :0]);
            if (idx == 0) continue;
            addr.in6.sa.scope_id = @intCast(idx);
            return addr;
        }
    }
    return error.NoNameserver;
}

// ---------------------------------------------------------------------
// Tests: a local fake nameserver answers over UDP and TCP, driven only by
// the resolver's own kqueue (step() is the loop's wait, never a sleep).
// ---------------------------------------------------------------------

const TestCtx = struct {
    status: ?Status = null,
    res: ?Resolution = null,
    raw: ?RecordResult = null,
    calls: usize = 0,

    fn onResolve(ctx_ptr: ?*anyopaque, _: usize, status: Status, res: ?Resolution) void {
        const self: *TestCtx = @ptrCast(@alignCast(ctx_ptr.?));
        self.status = status;
        self.res = res;
        self.calls += 1;
    }
    fn onQuery(ctx_ptr: ?*anyopaque, _: usize, status: Status, res: ?RecordResult) void {
        const self: *TestCtx = @ptrCast(@alignCast(ctx_ptr.?));
        self.status = status;
        self.raw = res;
        self.calls += 1;
    }
};

/// Fake nameserver: one UDP socket + one TCP listener on 127.0.0.1,
/// a thread answering canned responses per qname/qtype.
const FakeDns = struct {
    udp_fd: posix.fd_t,
    tcp_fd: posix.fd_t,
    port: u16,
    alive: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
    truncate_udp: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    decoy_qname: []const u8 = "",
    /// When set, A answers also carry an authority SOA and an
    /// additional-section A for an unrelated owner.
    poison_sections: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, every SRV answer is NODATA, pushing resolve() onto
    /// the fallback address path.
    empty_srv: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, SRV answers carry a single "." target: RFC 2782's
    /// "service unavailable on this domain".
    srv_dot: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, only the _xmpps* SRV answer carries the "." target:
    /// "no direct TLS", which must still fall through to _xmpp*.
    srv_tls_dot: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, _xmpps* SRV queries are answered SERVFAIL: a refusal
    /// must fall through to _xmpp* the way "." does.
    srv_tls_fail: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, address queries are received but never answered,
    /// exercising per-query retries and the whole-chain deadline.
    a_silent: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When non-zero, SRV answers carry this many targets (t0.test,
    /// t1.test, ...) to exercise the flattened-target cap.
    srv_many: u8 = 0,
    /// When < 255, address queries for "t{idx}.test" are answered
    /// SERVFAIL, exercising the per-target skip.
    a_servfail_idx: std.atomic.Value(u8) = std.atomic.Value(u8).init(255),
    /// When set, every A (or AAAA) query is answered SERVFAIL: one
    /// failed family must not doom the family that resolved.
    a_fail: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    aaaa_fail: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, A (or AAAA) queries are answered NXDOMAIN with the
    /// shared authority SOA: the family is absent, not failed.
    a_nxdomain: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    aaaa_nxdomain: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, TLSA queries are answered SERVFAIL: the lookup
    /// failed, it did not prove the RRset absent.
    tlsa_fail: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, TLSA queries get an empty NOERROR answer (NODATA).
    tlsa_nodata: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, TLSA queries are received but never answered.
    tlsa_silent: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, TLSA queries are answered NXDOMAIN with the shared SOA.
    tlsa_nxdomain: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, the TLSA answer carries a record too short to parse.
    tlsa_garbage: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, AAAA queries are answered with ::1 so dual-stack
    /// paths have real data.
    a_aaaa: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, SRV answers carry three targets with wire-order
    /// priorities 30, 10, 20; RFC 2782 must emit t_lo first.
    srv_prio_mix: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, SRV answers exist only for the _xmpps-client and
    /// _xmpp-client prefixes; anything else is NODATA.
    client_srv_only: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, A answers carry a TTL with the top bit set (RFC 2181
    /// treats that as zero, not as a large number).
    a_ttl_highbit: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, every answer is NXDOMAIN with an authority SOA whose
    /// minimum is 120 s - feeds the negative cache.
    nxdomain_all: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, NODATA answers carry the same authority SOA record.
    soa_nodata: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When set, SRV queries are received but never answered.
    srv_silent: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// When non-zero, the decoy's question carries this qtype instead
    /// of echoing the asked type (T296 qtype decoy).
    decoy_qtype: u16 = 0,
    udp_recvd: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    tcp_recvd: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    tlsa_recvd: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    thread: std.Thread = undefined,

    fn run(self: *FakeDns) void {
        var buf: [4096]u8 = undefined;
        while (self.alive.load(.acquire)) {
            var pfd = [2]posix.pollfd{
                .{ .fd = self.udp_fd, .events = std.c.POLL.IN, .revents = 0 },
                .{ .fd = self.tcp_fd, .events = std.c.POLL.IN, .revents = 0 },
            };
            _ = posix.poll(&pfd, 100) catch return;
            if (pfd[0].revents != 0) {
                var peer: posix.sockaddr = undefined;
                var plen: posix.socklen_t = @sizeOf(posix.sockaddr);
                const n = posix.recvfrom(self.udp_fd, &buf, 0, &peer, &plen) catch continue;
                _ = self.udp_recvd.fetchAdd(1, .monotonic);
                var qbuf: [4096]u8 = undefined;
                @memcpy(qbuf[0..n], buf[0..n]);
                const resp_len = self.buildResponse(&buf, qbuf[0..n]);
                // Optional decoy: same id, wrong qname - must be ignored (T296).
                if (self.decoy_qname.len > 0) {
                    var decoy: [1024]u8 = undefined;
                    const dn = self.buildDecoy(&decoy, qbuf[0..n]);
                    _ = posix.sendto(self.udp_fd, decoy[0..dn], 0, &peer, plen) catch {};
                }
                if (resp_len > 0) _ = posix.sendto(self.udp_fd, buf[0..resp_len], 0, &peer, plen) catch {};
            }
            if (pfd[1].revents != 0) {
                const cfd = posix.accept(self.tcp_fd, null, null, 0) catch continue;
                defer posix.close(cfd);
                var hdr: [2]u8 = undefined;
                if (readFull(cfd, &hdr) != 2) continue;
                const want = std.mem.readInt(u16, &hdr, .big);
                const n = readFull(cfd, buf[0..want]);
                if (n != want) continue;
                _ = self.tcp_recvd.fetchAdd(1, .monotonic);
                var qbuf: [4096]u8 = undefined;
                @memcpy(qbuf[0..n], buf[0..n]);
                const resp_len = self.buildResponse(&buf, qbuf[0..n]);
                var out: [2]u8 = undefined;
                std.mem.writeInt(u16, &out, @intCast(resp_len), .big);
                _ = posix.send(cfd, &out, 0) catch {};
                if (resp_len > 0) _ = posix.send(cfd, buf[0..resp_len], 0) catch {};
            }
        }
    }

    /// Question-based canned answers: _xmpps SRV -> NODATA, _xmpp SRV ->
    /// SRV record for srv.test:15222, A -> 127.0.0.1, TLSA -> one record.
    /// When truncate_udp is armed the UDP path answers with TC set and no
    /// answers, forcing the TCP fallback.
    fn buildResponse(self: *FakeDns, out: []u8, pkt: []const u8) usize {
        var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena_state.deinit();
        const alloc = arena_state.allocator();
        const q = parseQuestion(alloc, pkt) catch return 0;
        const id = std.mem.readInt(u16, pkt[0..2], .big);

        if (self.truncate_udp.load(.monotonic) and self.tcp_recvd.load(.monotonic) == 0) {
            // Header-only truncated response.
            const flags: u16 = 0x8180 | wire.FLAG_TC;
            std.mem.writeInt(u16, out[0..2], id, .big);
            std.mem.writeInt(u16, out[2..4], flags, .big);
            std.mem.writeInt(u16, out[4..6], 1, .big);
            @memset(out[6..12], 0);
            const qlen = pkt.len - 12;
            @memcpy(out[12 .. 12 + qlen], pkt[12..]);
            return 12 + qlen;
        }

        var answers: std.ArrayListUnmanaged(u8) = .{};
        var ancount: u16 = 0;
        if ((q.qtype == wire.TYPE_A or q.qtype == wire.TYPE_AAAA) and self.a_silent.load(.monotonic)) return 0;
        if (q.qtype == wire.TYPE_SRV and self.srv_silent.load(.monotonic)) return 0;
        if (q.qtype == wire.TYPE_TLSA and self.tlsa_silent.load(.monotonic)) return 0;
        const is_addr_q = q.qtype == wire.TYPE_A or q.qtype == wire.TYPE_AAAA;
        const family_fail = (q.qtype == wire.TYPE_A and self.a_fail.load(.monotonic)) or
            (q.qtype == wire.TYPE_AAAA and self.aaaa_fail.load(.monotonic));
        const family_nx = (q.qtype == wire.TYPE_A and self.a_nxdomain.load(.monotonic)) or
            (q.qtype == wire.TYPE_AAAA and self.aaaa_nxdomain.load(.monotonic)) or
            (q.qtype == wire.TYPE_TLSA and self.tlsa_nxdomain.load(.monotonic));
        const nx = self.nxdomain_all.load(.monotonic) or family_nx;
        var named_fail = false;
        if (self.a_servfail_idx.load(.monotonic) != 255 and is_addr_q) {
            var fbuf: [32]u8 = undefined;
            const fname = std.fmt.bufPrint(&fbuf, "t{d}.test", .{self.a_servfail_idx.load(.monotonic)}) catch "";
            named_fail = std.mem.eql(u8, q.qname, fname);
        }
        if (is_addr_q and (family_fail or named_fail)) {
            std.mem.writeInt(u16, out[0..2], id, .big);
            std.mem.writeInt(u16, out[2..4], 0x8182, .big);
            std.mem.writeInt(u16, out[4..6], 1, .big);
            @memset(out[6..12], 0);
            const qlen = pkt.len - 12;
            @memcpy(out[12 .. 12 + qlen], pkt[12..]);
            return 12 + qlen;
        }
        if (q.qtype == wire.TYPE_SRV and self.srv_tls_fail.load(.monotonic) and
            std.mem.startsWith(u8, q.qname, "_xmpps"))
        {
            std.mem.writeInt(u16, out[0..2], id, .big);
            std.mem.writeInt(u16, out[2..4], 0x8182, .big);
            std.mem.writeInt(u16, out[4..6], 1, .big);
            @memset(out[6..12], 0);
            const qlen = pkt.len - 12;
            @memcpy(out[12 .. 12 + qlen], pkt[12..]);
            return 12 + qlen;
        }
        if (q.qtype == wire.TYPE_SRV) {
            const client_prefix = std.mem.startsWith(u8, q.qname, "_xmpps-client") or std.mem.startsWith(u8, q.qname, "_xmpp-client");
            if (self.client_srv_only.load(.monotonic) and !client_prefix) {
                // NODATA for anything but the client prefixes.
            } else if (self.srv_tls_dot.load(.monotonic) and std.mem.startsWith(u8, q.qname, "_xmpps")) {
                ancount = 1;
                appendAnswerHdr(alloc, &answers, wire.TYPE_SRV, 60, 7);
                var v: u16 = 0;
                v = 10;
                answers.appendSlice(alloc, std.mem.asBytes(&std.mem.nativeToBig(u16, v))) catch {};
                v = 100;
                answers.appendSlice(alloc, std.mem.asBytes(&std.mem.nativeToBig(u16, v))) catch {};
                v = 0;
                answers.appendSlice(alloc, std.mem.asBytes(&std.mem.nativeToBig(u16, v))) catch {};
                answers.append(alloc, 0) catch {}; // "." root target
            } else if (std.mem.startsWith(u8, q.qname, "_xmpps") or self.empty_srv.load(.monotonic)) {
                // NODATA for the direct-TLS prefix, or everywhere when
                // the test wants the fallback path.
            } else if (self.srv_many > 0) {
                var i: u8 = 0;
                while (i < self.srv_many) : (i += 1) {
                    ancount += 1;
                    var tbuf: [32]u8 = undefined;
                    const tname = std.fmt.bufPrint(&tbuf, "t{d}.test", .{i}) catch unreachable;
                    appendAnswerHdr(alloc, &answers, wire.TYPE_SRV, 60, 6 + encLen(tname));
                    var v: u16 = 0;
                    v = 10;
                    answers.appendSlice(alloc, std.mem.asBytes(&std.mem.nativeToBig(u16, v))) catch {};
                    v = 1;
                    answers.appendSlice(alloc, std.mem.asBytes(&std.mem.nativeToBig(u16, v))) catch {};
                    v = 15222;
                    answers.appendSlice(alloc, std.mem.asBytes(&std.mem.nativeToBig(u16, v))) catch {};
                    appendEncodedName(alloc, &answers, tname);
                }
            } else if (self.srv_prio_mix.load(.monotonic)) {
                const entries = [3]struct { n: []const u8, p: u16 }{
                    .{ .n = "t_hi.test", .p = 30 },
                    .{ .n = "t_lo.test", .p = 10 },
                    .{ .n = "t_mid.test", .p = 20 },
                };
                for (entries) |ent| {
                    ancount += 1;
                    appendAnswerHdr(alloc, &answers, wire.TYPE_SRV, 60, 6 + encLen(ent.n));
                    var v: u16 = ent.p;
                    answers.appendSlice(alloc, std.mem.asBytes(&std.mem.nativeToBig(u16, v))) catch {};
                    v = 100;
                    answers.appendSlice(alloc, std.mem.asBytes(&std.mem.nativeToBig(u16, v))) catch {};
                    v = 15222;
                    answers.appendSlice(alloc, std.mem.asBytes(&std.mem.nativeToBig(u16, v))) catch {};
                    appendEncodedName(alloc, &answers, ent.n);
                }
            } else if (self.srv_dot.load(.monotonic)) {
                ancount = 1;
                appendAnswerHdr(alloc, &answers, wire.TYPE_SRV, 60, 7);
                var v: u16 = 0;
                v = 10;
                answers.appendSlice(alloc, std.mem.asBytes(&std.mem.nativeToBig(u16, v))) catch {};
                v = 100;
                answers.appendSlice(alloc, std.mem.asBytes(&std.mem.nativeToBig(u16, v))) catch {};
                v = 0;
                answers.appendSlice(alloc, std.mem.asBytes(&std.mem.nativeToBig(u16, v))) catch {};
                answers.append(alloc, 0) catch {}; // "." root target
            } else {
                ancount = 1;
                appendAnswerHdr(alloc, &answers, wire.TYPE_SRV, 60, 6 + encLen("srv.test"));
                var v: u16 = 0;
                v = 10;
                answers.appendSlice(alloc, std.mem.asBytes(&std.mem.nativeToBig(u16, v))) catch {};
                v = 100;
                answers.appendSlice(alloc, std.mem.asBytes(&std.mem.nativeToBig(u16, v))) catch {};
                v = 15222;
                answers.appendSlice(alloc, std.mem.asBytes(&std.mem.nativeToBig(u16, v))) catch {};
                appendEncodedName(alloc, &answers, "srv.test");
            }
        } else if (q.qtype == wire.TYPE_AAAA and self.a_aaaa.load(.monotonic) and !family_nx) {
            ancount = 1;
            appendAnswerHdr(alloc, &answers, wire.TYPE_AAAA, 60, 16);
            var v6: [16]u8 = .{0} ** 16;
            v6[15] = 1;
            answers.appendSlice(alloc, &v6) catch {};
        } else if (q.qtype == wire.TYPE_A and !family_nx) {
            ancount = 1;
            const ttl: u32 = if (self.a_ttl_highbit.load(.monotonic)) 0x8000_0000 else 60;
            appendAnswerHdr(alloc, &answers, wire.TYPE_A, ttl, 4);
            answers.appendSlice(alloc, &.{ 127, 0, 0, 1 }) catch {};
        } else if (q.qtype == wire.TYPE_TLSA) {
            _ = self.tlsa_recvd.fetchAdd(1, .monotonic);
            if (self.tlsa_fail.load(.monotonic)) {
                std.mem.writeInt(u16, out[0..2], id, .big);
                std.mem.writeInt(u16, out[2..4], 0x8182, .big);
                std.mem.writeInt(u16, out[4..6], 1, .big);
                @memset(out[6..12], 0);
                const qlen = pkt.len - 12;
                @memcpy(out[12 .. 12 + qlen], pkt[12..]);
                return 12 + qlen;
            }
            if (!self.tlsa_nodata.load(.monotonic)) {
                ancount = 1;
                if (self.tlsa_garbage.load(.monotonic)) {
                    appendAnswerHdr(alloc, &answers, wire.TYPE_TLSA, 60, 2);
                    answers.appendSlice(alloc, &.{ 3, 0 }) catch {};
                } else {
                    appendAnswerHdr(alloc, &answers, wire.TYPE_TLSA, 60, 7);
                    answers.appendSlice(alloc, &.{ 3, 0, 1, 0xDE, 0xAD, 0xBE, 0xEF }) catch {};
                }
            }
        }

        var nscount: u16 = 0;
        var arcount: u16 = 0;
        var extra: std.ArrayListUnmanaged(u8) = .{};
        if (q.qtype == wire.TYPE_A and self.poison_sections.load(.monotonic)) {
            // Authority SOA whose rdata is opaque to the filter, plus an
            // additional A record for an owner the query never asked
            // about.
            nscount = 1;
            extra.appendSlice(alloc, &.{ 0xC0, 0x0C }) catch {};
            appendAnswerTail(alloc, &extra, 6, 60, 20);
            extra.appendSlice(alloc, &[_]u8{0} ** 20) catch {};
            arcount = 1;
            appendEncodedName(alloc, &extra, "evil.test");
            appendAnswerTail(alloc, &extra, wire.TYPE_A, 60, 4);
            extra.appendSlice(alloc, &.{ 10, 9, 9, 9 }) catch {};
        }

        if (nx or (ancount == 0 and self.soa_nodata.load(.monotonic))) {
            // Authority SOA: owner ".", mname "." rname ".", five u32
            // fields whose last (minimum) is 120 seconds.
            nscount += 1;
            extra.append(alloc, 0) catch {};
            appendAnswerTail(alloc, &extra, 6, 60, 22);
            extra.appendSlice(alloc, &.{ 0, 0 }) catch {};
            for ([_]u32{ 1, 7200, 3600, 604800, 120 }) |w| {
                extra.appendSlice(alloc, std.mem.asBytes(&std.mem.nativeToBig(u32, w))) catch {};
            }
        }
        const flags: u16 = if (nx) 0x8183 else 0x8180;
        std.mem.writeInt(u16, out[0..2], id, .big);
        std.mem.writeInt(u16, out[2..4], flags, .big);
        std.mem.writeInt(u16, out[4..6], 1, .big);
        std.mem.writeInt(u16, out[6..8], ancount, .big);
        std.mem.writeInt(u16, out[8..10], nscount, .big);
        std.mem.writeInt(u16, out[10..12], arcount, .big);
        const qlen = pkt.len - 12;
        @memcpy(out[12 .. 12 + qlen], pkt[12..]);
        var off = 12 + qlen;
        @memcpy(out[off .. off + answers.items.len], answers.items);
        off += answers.items.len;
        @memcpy(out[off .. off + extra.items.len], extra.items);
        off += extra.items.len;
        return off;
    }

    /// Same id and a real answer, but the question section names a
    /// different owner - a T296 decoy.
    fn buildDecoy(self: *FakeDns, out: []u8, pkt: []const u8) usize {
        var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena_state.deinit();
        const alloc = arena_state.allocator();
        const q = parseQuestion(alloc, pkt) catch return 0;
        const id = std.mem.readInt(u16, pkt[0..2], .big);
        std.mem.writeInt(u16, out[0..2], id, .big);
        std.mem.writeInt(u16, out[2..4], 0x8180, .big);
        std.mem.writeInt(u16, out[4..6], 1, .big);
        std.mem.writeInt(u16, out[6..8], 1, .big);
        @memset(out[8..12], 0);
        var off: usize = 12;
        appendEncodedNameTo(out, &off, self.decoy_qname);
        const decoy_qt = if (self.decoy_qtype != 0) self.decoy_qtype else q.qtype;
        std.mem.writeInt(u16, out[off..][0..2], decoy_qt, .big);
        std.mem.writeInt(u16, out[off + 2 ..][0..2], 1, .big);
        off += 4;
        // Bogus answer: A record pointing at 10.9.9.9.
        out[off] = 0xC0;
        out[off + 1] = 0x0C;
        std.mem.writeInt(u16, out[off + 2 ..][0..2], wire.TYPE_A, .big);
        std.mem.writeInt(u16, out[off + 4 ..][0..2], 1, .big);
        std.mem.writeInt(u32, out[off + 6 ..][0..4], 60, .big);
        std.mem.writeInt(u16, out[off + 10 ..][0..2], 4, .big);
        out[off + 12] = 10;
        out[off + 13] = 9;
        out[off + 14] = 9;
        out[off + 15] = 9;
        return off + 16;
    }
};

fn readFull(fd: posix.fd_t, buf: []u8) usize {
    var got: usize = 0;
    while (got < buf.len) {
        const n = posix.recv(fd, buf[got..], 0) catch return got;
        if (n == 0) return got;
        got += n;
    }
    return got;
}

fn encLen(name: []const u8) usize {
    var len: usize = 1;
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |lbl| len += lbl.len + 1;
    return len;
}

fn appendEncodedName(alloc: std.mem.Allocator, list: *std.ArrayListUnmanaged(u8), name: []const u8) void {
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |lbl| {
        list.append(alloc, @intCast(lbl.len)) catch return;
        list.appendSlice(alloc, lbl) catch return;
    }
    list.append(alloc, 0) catch return;
}

fn appendEncodedNameTo(out: []u8, off: *usize, name: []const u8) void {
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |lbl| {
        out[off.*] = @intCast(lbl.len);
        off.* += 1;
        @memcpy(out[off.* .. off.* + lbl.len], lbl);
        off.* += lbl.len;
    }
    out[off.*] = 0;
    off.* += 1;
}

fn appendAnswerHdr(a: std.mem.Allocator, list: *std.ArrayListUnmanaged(u8), rtype: u16, ttl: u32, rdlen: usize) void {
    list.appendSlice(a, &.{ 0xC0, 0x0C }) catch return;
    appendAnswerTail(a, list, rtype, ttl, rdlen);
}

/// The type/class/ttl/rdlen tail of a resource record, when the owner
/// name was already emitted (a pointer or an encoded name).
fn appendAnswerTail(a: std.mem.Allocator, list: *std.ArrayListUnmanaged(u8), rtype: u16, ttl: u32, rdlen: usize) void {
    list.appendSlice(a, std.mem.asBytes(&std.mem.nativeToBig(u16, rtype))) catch return;
    list.appendSlice(a, std.mem.asBytes(&std.mem.nativeToBig(u16, 1))) catch return;
    list.appendSlice(a, std.mem.asBytes(&std.mem.nativeToBig(u32, ttl))) catch return;
    list.appendSlice(a, std.mem.asBytes(&std.mem.nativeToBig(u16, @intCast(rdlen)))) catch return;
}

fn startFakeDns(truncate: bool, decoy: []const u8) !*FakeDns {
    const srv = try std.testing.allocator.create(FakeDns);
    srv.* = .{
        .udp_fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0),
        .tcp_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0),
        .port = 0,
    };
    // TCP answers must arrive on the same port the query addressed:
    // take a TCP port, then hold the UDP half of the same number,
    // retrying the pair on collision instead of racing the OS.
    var attempts: usize = 0;
    while (true) : (attempts += 1) {
        if (attempts == 256) return error.AddressInUse;
        const bind_addr = try net.Address.parseIp("127.0.0.1", 0);
        try posix.bind(srv.tcp_fd, &bind_addr.any, bind_addr.getOsSockLen());
        var actual: posix.sockaddr = undefined;
        var slen: posix.socklen_t = @sizeOf(posix.sockaddr);
        try posix.getsockname(srv.tcp_fd, &actual, &slen);
        srv.port = net.Address.initPosix(@alignCast(&actual)).getPort();
        const udp_addr = try net.Address.parseIp("127.0.0.1", srv.port);
        posix.bind(srv.udp_fd, &udp_addr.any, udp_addr.getOsSockLen()) catch |err| switch (err) {
            error.AddressInUse => {
                posix.close(srv.tcp_fd);
                srv.tcp_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
                continue;
            },
            else => return err,
        };
        break;
    }
    try posix.listen(srv.tcp_fd, 8);
    srv.truncate_udp.store(truncate, .monotonic);
    srv.decoy_qname = decoy;
    srv.thread = try std.Thread.spawn(.{}, FakeDns.run, .{srv});
    return srv;
}

fn stopFakeDns(srv: *FakeDns) void {
    srv.alive.store(false, .release);
    srv.thread.join();
    posix.close(srv.udp_fd);
    posix.close(srv.tcp_fd);
    std.testing.allocator.destroy(srv);
}

test "dns-async: UDP A query resolves and the response is demuxed on id+qname+qtype (T296)" {
    const srv = try startFakeDns(false, "decoy.test");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });

    try r.query("host.test", .a, 7);
    var spins: usize = 0;
    while (ctx.status == null and spins < 100) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expect(res.rrs.len == 1);
    try std.testing.expectEqual(wire.TYPE_A, res.rrs[0].rtype);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, res.rrs[0].rdata);
}

test "dns-async: UDP TC bit falls back to TCP for the same query" {
    const srv = try startFakeDns(true, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });

    try r.query("host.test", .a, 9);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    try std.testing.expect(srv.tcp_recvd.load(.monotonic) > 0);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expect(res.rrs.len == 1);
}

test "dns-async: resolve() runs the SRV chain and the TTL cache serves repeats" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expect(res.targets.len >= 1);
    try std.testing.expectEqual(@as(u16, 15222), res.targets[0].addr.getPort());

    // Second identical raw query is served from the TTL cache without
    // touching the wire.
    var qctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &qctx, .fun = TestCtx.onQuery });
    try r.query("host.test", .a, 11);
    spins = 0;
    while (qctx.status == null and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.resolved, qctx.status.?);
    var qres = qctx.raw.?;
    defer qres.deinitOn(std.testing.allocator);
    const first_udp = srv.udp_recvd.load(.monotonic);
    var qctx2 = TestCtx{};
    r.setQueryCallback(.{ .ctx = &qctx2, .fun = TestCtx.onQuery });
    try r.query("host.test", .a, 12);
    try std.testing.expectEqual(Status.resolved, qctx2.status.?);
    var qres2 = qctx2.raw.?;
    defer qres2.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(first_udp, srv.udp_recvd.load(.monotonic));
}

test "dns-async: a failed query build leaves no freed job in the list" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });

    // An unencodable name cannot exist on the wire: the chain reports
    // nxdomain through the callback instead of erroring, and neither
    // path leaves a freed job on the list (J1).
    try r.resolve("bad..name", .client, 5222, 1, true);
    try std.testing.expectEqual(Status.nxdomain, ctx.status.?);
    ctx.status = null;
    try r.query("bad..name", .a, 2);
    try std.testing.expectEqual(Status.nxdomain, ctx.status.?);
    try std.testing.expectEqual(@as(usize, 0), r.jobs.items.len);
}

/// Build a minimal A answer to the query in `query_pkt` at `out`:
/// echo the question, then one A record for 127.0.0.1.
fn buildAResponse(out: []u8, query_pkt: []const u8) usize {
    const id = std.mem.readInt(u16, query_pkt[0..2], .big);
    std.mem.writeInt(u16, out[0..2], id, .big);
    std.mem.writeInt(u16, out[2..4], 0x8180, .big);
    std.mem.writeInt(u16, out[4..6], 1, .big);
    std.mem.writeInt(u16, out[6..8], 1, .big);
    @memset(out[8..12], 0);
    const qlen = query_pkt.len - 12;
    @memcpy(out[12 .. 12 + qlen], query_pkt[12..]);
    const off = 12 + qlen;
    out[off] = 0xC0;
    out[off + 1] = 0x0C;
    std.mem.writeInt(u16, out[off + 2 ..][0..2], wire.TYPE_A, .big);
    std.mem.writeInt(u16, out[off + 4 ..][0..2], 1, .big);
    std.mem.writeInt(u32, out[off + 6 ..][0..4], 60, .big);
    std.mem.writeInt(u16, out[off + 10 ..][0..2], 4, .big);
    @memcpy(out[off + 12 .. off + 16], &[_]u8{ 127, 0, 0, 1 });
    return off + 16;
}

test "dns-async: TCP frame length math and consumption" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 53));

    try r.query("host.test", .a, 7);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    const job = r.jobs.items[0];

    // A maximal legal frame header: the u16 length must be widened
    // before adding the two-octet prefix or the math overflows.
    var hdr: [2]u8 = undefined;
    std.mem.writeInt(u16, &hdr, 65535, .big);
    try job.tcp_buf.appendSlice(std.testing.allocator, &hdr);
    try job.tcp_buf.appendSlice(std.testing.allocator, &[_]u8{0} ** 64);
    r.pumpTcpFrames(job);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);

    // A complete frame that answers no outstanding query is consumed
    // and counted foreign, like an unmatched UDP reply.
    job.tcp_buf.clearRetainingCapacity();
    std.mem.writeInt(u16, &hdr, 12, .big);
    try job.tcp_buf.appendSlice(std.testing.allocator, &hdr);
    try job.tcp_buf.appendSlice(std.testing.allocator, &[_]u8{0} ** 12);
    r.pumpTcpFrames(job);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    try std.testing.expectEqual(@as(usize, 0), job.tcp_buf.items.len);
    try std.testing.expectEqual(@as(usize, 1), r.unmatched_replies);
}

test "dns-async: a maximal frame ahead of the answer is consumed, not fatal" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 53));

    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("host.test", .a, 7);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    const job = r.jobs.items[0];

    // A complete 65535-octet frame of junk, then the real answer frame:
    // the buffer holding more than one max frame is legal per frame.
    var stream: [2 + 65535 + 2 + 512]u8 = undefined;
    std.mem.writeInt(u16, stream[0..2], 65535, .big);
    @memset(stream[2 .. 2 + 65535], 0xAA);
    var off: usize = 2 + 65535;
    const alen = buildAResponse(stream[off + 2 ..], job.request);
    std.mem.writeInt(u16, stream[off..][0..2], @intCast(alen), .big);
    off += 2 + alen;
    try job.tcp_buf.appendSlice(std.testing.allocator, stream[0..off]);
    r.pumpTcpFrames(job);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), r.jobs.items.len);
}

const UdpSink = struct { fd: posix.fd_t, port: u16 };

/// A nameserver that is only a bound UDP socket: the test receives
/// queries and sends answers itself, so nothing ever waits.
fn startUdpSink() !UdpSink {
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    errdefer posix.close(fd);
    const bind_addr = try net.Address.parseIp("127.0.0.1", 0);
    try posix.bind(fd, &bind_addr.any, bind_addr.getOsSockLen());
    var actual: posix.sockaddr = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr);
    try posix.getsockname(fd, &actual, &slen);
    return .{ .fd = fd, .port = net.Address.initPosix(@alignCast(&actual)).getPort() };
}

/// Arm an already-expired one-shot deadline carrying `udata`: pending
/// at the next step() with no sleeping on real time.
fn armStaleTimer(r: *Resolver, udata: usize) void {
    var ch = [1]posix.Kevent{.{
        .ident = 0xDEAD,
        .filter = std.c.EVFILT.TIMER,
        .flags = std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT,
        .fflags = std.c.NOTE.ABSTIME,
        .data = 1,
        .udata = udata,
    }};
    _ = posix.kevent(r.kq, &ch, &.{}, null) catch {};
}

test "dns-async: a deadline event batched with the reply does not touch a freed job" {
    const sink = try startUdpSink();
    defer posix.close(sink.fd);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", sink.port));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });

    try r.query("host.test", .a, 7);
    const job = r.jobs.items[0];

    // Drain the query; loopback delivery is synchronous, so a bounded
    // recv spin is enough with no sleeping.
    var qbuf: [512]u8 = undefined;
    var qn: usize = 0;
    var spins: usize = 0;
    while (qn == 0 and spins < 100_000) : (spins += 1) {
        qn = posix.recv(sink.fd, &qbuf, 0) catch 0;
    }
    try std.testing.expect(qn > 0);

    // Answer it, then queue the expired deadline: both events sit
    // pending for one kevent batch. The read frees the job first, so
    // the timer event must be recognized as stale.
    var resp: [512]u8 = undefined;
    const rlen = buildAResponse(&resp, qbuf[0..qn]);
    var local: posix.sockaddr = undefined;
    var llen: posix.socklen_t = @sizeOf(posix.sockaddr);
    try posix.getsockname(r.fd, &local, &llen);
    _ = try posix.sendto(sink.fd, resp[0..rlen], 0, &local, llen);
    armStaleTimer(&r, (@as(usize, job.gen) << 8) | job.slot);

    // The events may land in one batch or a few; keep pumping until
    // the reply frees the job - whichever order the kernel picks, the
    // stale timer must never touch the freed job.
    var spins2: usize = 0;
    while (ctx.status == null and spins2 < 1000) : (spins2 += 1) r.step(0);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), r.jobs.items.len);
}

test "dns-async: query ids are drawn fresh per query, not sequential" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 53));
    r.prng = std.Random.DefaultPrng.init(0xC0FFEE);

    // Six in-flight jobs: a sequential allocator would emit id, id+1,
    // id+2... while a per-query draw lands anywhere in the space.
    const names: [6][]const u8 = .{ "a.test", "b.test", "c.test", "d.test", "e.test", "f.test" };
    for (names, 0..) |n, i| try r.query(n, .a, i + 1);
    try std.testing.expectEqual(@as(usize, 6), r.jobs.items.len);
    var sequential = true;
    for (1..r.jobs.items.len) |i| {
        if (r.jobs.items[i].dns_id != r.jobs.items[i - 1].dns_id +% 1) sequential = false;
    }
    try std.testing.expect(!sequential);
}

test "dns-async: identically seeded resolvers still draw different ids" {
    var r1 = Resolver.init(std.testing.allocator);
    defer r1.deinit();
    r1.setServer(try net.Address.parseIp("127.0.0.1", 53));
    var r2 = Resolver.init(std.testing.allocator);
    defer r2.deinit();
    r2.setServer(try net.Address.parseIp("127.0.0.1", 53));
    r1.prng = std.Random.DefaultPrng.init(0xBEEF);
    r2.prng = std.Random.DefaultPrng.init(0xBEEF);

    // A seeded-PRNG id source would emit the same sequence in both
    // resolvers; the CSPRNG source makes the draws independent.
    const names: [4][]const u8 = .{ "a.test", "b.test", "c.test", "d.test" };
    var same: usize = 0;
    for (names, 0..) |n, i| {
        try r1.query(n, .a, i + 1);
        try r2.query(n, .a, i + 1);
        if (r1.jobs.items[i].dns_id == r2.jobs.items[i].dns_id) same += 1;
    }
    try std.testing.expect(same < 4);
}

test "dns-async: authority and additional records are dropped, not cached" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.poison_sections.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });

    try r.query("host.test", .a, 7);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.rrs.len);
    try std.testing.expectEqual(wire.TYPE_A, res.rrs[0].rtype);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, res.rrs[0].rdata);

    // The poisoned sections never reached the cache either: a query for
    // the planted owner must go to the wire.
    var ctx2 = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx2, .fun = TestCtx.onQuery });
    try r.query("evil.test", .a, 8);
    spins = 0;
    while (ctx2.status == null and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expect(ctx2.status.? == .resolved or ctx2.status.? == .failed);
    if (ctx2.raw) |*res2| res2.deinitOn(std.testing.allocator);
}

test "dns-async: the fallback address path honors the requested port" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.empty_srv.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("host.test", .server, 5269, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expect(res.targets.len >= 1);
    try std.testing.expectEqual(@as(u16, 5269), res.targets[0].addr.getPort());
}

const FreeingCtx = struct {
    calls: usize = 0,
    keys: [8]usize = .{0} ** 8,
    status: ?Status = null,

    fn onResolve(ctx_ptr: ?*anyopaque, key: usize, status: Status, res: ?Resolution) void {
        const self: *FreeingCtx = @ptrCast(@alignCast(ctx_ptr.?));
        if (self.calls < self.keys.len) self.keys[self.calls] = key;
        self.calls += 1;
        self.status = status;
        if (res) |r| {
            var v = r;
            v.deinitOn(std.testing.allocator);
        }
    }
};

test "dns-async: an all-'.' SRV answer reports service_unavailable, not nxdomain" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_dot.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.service_unavailable, ctx.status.?);
}

test "dns-async: a '.' _xmpps answer falls through to _xmpp" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_tls_dot.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    // "No direct TLS" is not "no service": the STARTTLS SRV answers.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expect(res.targets.len >= 1);
    try std.testing.expectEqualStrings("srv.test", res.targets[0].host);
    try std.testing.expect(!res.targets[0].is_direct_tls);
}

test "dns-async: a SERVFAIL on _xmpps falls through to _xmpp" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_tls_fail.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, false);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    // A refused direct-TLS lookup is not a failure: the STARTTLS SRV
    // still gets its try and resolves the chain.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqualStrings("srv.test", res.targets[0].host);
}

test "dns-async: the whole-chain deadline bounds a silent target list" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.a_silent.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    r.chain_deadline_ms = 200;
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    const start = std.time.milliTimestamp();
    try r.resolve("svc.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 400) : (spins += 1) r.step(50);
    const elapsed = std.time.milliTimestamp() - start;

    try std.testing.expectEqual(Status.failed, ctx.status.?);
    // The chain bound fired long before two 2 s per-query retries
    // plus a 10 s fallback tail could.
    try std.testing.expect(elapsed < 1500);
}

test "dns-async: the chain deadline completes with collected targets" {
    // One SRV target resolved before the chain bound fired: the
    // waiters get that partial answer, not a failure.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("x.test", .client, 5222, 1, false);
    const job = r.jobs.items[0];
    const host = try std.testing.allocator.dupe(u8, "t1.test");
    job.targets.append(std.testing.allocator, .{
        .addr = try net.Address.parseIp("127.0.0.1", 5222),
        .host = host,
        .tlsa = &.{},
        .tlsa_status = .absent,
        .is_direct_tls = false,
    }) catch unreachable;
    r.onChainDeadline(job);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqualStrings("t1.test", res.targets[0].host);
    try std.testing.expectEqual(@as(usize, 0), r.jobs.items.len);
}

test "dns-async: the chain deadline marks pending fallback TLSA lookup_failed" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.empty_srv.store(true, .monotonic);
    srv.a_aaaa.store(true, .monotonic);
    srv.tlsa_silent.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    r.chain_deadline_ms = 300;
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("dual.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    // The bound fired while the shared fallback TLSA query was still
    // pending: the waiting targets are temporary failures, not
    // PKIX-eligible "no TLSA" ones.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), res.targets.len);
    for (res.targets) |t| {
        try std.testing.expectEqual(TlsaStatus.lookup_failed, t.tlsa_status);
        try std.testing.expectEqual(@as(usize, 0), t.tlsa.len);
    }
}

test "dns-async: the chain deadline marks a pending target TLSA lookup_failed" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_many = 1;
    srv.tlsa_silent.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    r.chain_deadline_ms = 300;
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.lookup_failed, res.targets[0].tlsa_status);
}

test "dns-async: a hostile SRV answer is capped at 16 emitted targets" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_many = 20;

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 400) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 16), res.targets.len);
    // The walk stopped at the cap instead of querying all 20 targets.
    try std.testing.expect(srv.udp_recvd.load(.monotonic) < 20 * 3);
}

/// Pre-seed the RR cache for every step of the "svc.test" chain so a
/// resolve completes synchronously without a single datagram.
fn seedSvcChain(r: *Resolver, with_tlsa: bool) void {
    r.cacheInsert("_xmpps-client._tcp.svc.test", KIND_SRV, &.{}, .nodata, 60);
    var srv_rdata = [_]u8{ 0, 10, 0, 100, 0x3B, 0x76, 3, 's', 'r', 'v', 4, 't', 'e', 's', 't', 0 };
    var srv_rrs = [1]wire.Rr{.{ .name = "_xmpp-client._tcp.svc.test", .rtype = KIND_SRV, .class = wire.CLASS_IN, .ttl = 60, .rdata = &srv_rdata }};
    r.cacheInsert("_xmpp-client._tcp.svc.test", KIND_SRV, &srv_rrs, .none, 60);
    var a_rrs = [1]wire.Rr{.{ .name = "srv.test", .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = &.{ 127, 0, 0, 1 } }};
    r.cacheInsert("srv.test", KIND_A, &a_rrs, .none, 60);
    r.cacheInsert("srv.test", KIND_AAAA, &.{}, .nodata, 60);
    if (with_tlsa) {
        var t_rrs = [1]wire.Rr{.{ .name = "_15222._tcp.srv.test", .rtype = KIND_TLSA, .class = wire.CLASS_IN, .ttl = 60, .rdata = &.{ 3, 0, 1, 0xDE, 0xAD, 0xBE, 0xEF } }};
        r.cacheInsert("_15222._tcp.srv.test", KIND_TLSA, &t_rrs, .none, 60);
    }
}

test "dns-async: want_tlsa=false skips the TLSA round trip entirely" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 53));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    seedSvcChain(&r, false);
    try r.resolve("svc.test", .client, 5222, 3, false);
    // The whole chain is served from the RR cache: the callback fires
    // inside resolve() and a stray TLSA query would have hit the wire.
    try std.testing.expect(ctx.status != null);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expect(res.targets.len >= 1);
    for (res.targets) |t| try std.testing.expectEqual(@as(usize, 0), t.tlsa.len);
}

test "dns-async: want_tlsa=true attaches the fetched records per target" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 53));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    seedSvcChain(&r, true);
    try r.resolve("svc.test", .client, 5222, 3, true);
    try std.testing.expect(ctx.status != null);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expect(res.targets.len >= 1);
    try std.testing.expect(res.targets[0].tlsa.len >= 1);
    try std.testing.expectEqual(TlsaStatus.present, res.targets[0].tlsa_status);
}

test "dns-async: a TLSA NODATA marks the target tlsa_status absent" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_many = 1;
    srv.tlsa_nodata.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.absent, res.targets[0].tlsa_status);
    try std.testing.expectEqual(@as(usize, 0), res.targets[0].tlsa.len);
}

test "dns-async: a TLSA SERVFAIL marks the target lookup_failed" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_many = 1;
    srv.tlsa_fail.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    // The target is still emitted with its addresses; the status word
    // marks the TLSA lookup as a temporary failure, never PKIX-eligible.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.lookup_failed, res.targets[0].tlsa_status);
    try std.testing.expectEqual(@as(usize, 0), res.targets[0].tlsa.len);
}

test "dns-async: a TLSA timeout marks the target lookup_failed" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_many = 1;
    srv.tlsa_silent.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.lookup_failed, res.targets[0].tlsa_status);
}

test "dns-async: identical resolves merge into one job" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = FreeingCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = FreeingCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 1, true);
    try r.resolve("svc.test", .client, 5222, 2, true);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    try std.testing.expectEqual(@as(usize, 2), r.jobs.items[0].waiter_count);

    var spins: usize = 0;
    while (ctx.calls < 2 and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(@as(usize, 2), ctx.calls);
    // Both session keys were notified exactly once.
    try std.testing.expect((ctx.keys[0] == 1 and ctx.keys[1] == 2) or (ctx.keys[0] == 2 and ctx.keys[1] == 1));
}

test "dns-async: a trailing dot resolves like the bare name" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    // The FQDN must run the same SRV chain as "svc.test" over the wire.
    try r.resolve("svc.test.", .client, 5222, 3, false);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expect(res.targets.len >= 1);
    try std.testing.expectEqualSlices(u8, "srv.test", res.targets[0].host);
    try std.testing.expectEqual(@as(u16, 15222), res.targets[0].addr.getPort());
}

test "dns-async: an FQDN and the bare name merge into one job" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = FreeingCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = FreeingCtx.onResolve });

    // The stripped name is the merge key, so both lookups share one
    // wire exchange and each waiter still gets its own callback.
    try r.resolve("svc.test.", .client, 5222, 1, false);
    try r.resolve("svc.test", .client, 5222, 2, false);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    try std.testing.expectEqual(@as(usize, 2), r.jobs.items[0].waiter_count);

    var spins: usize = 0;
    while (ctx.calls < 2 and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(@as(usize, 2), ctx.calls);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
}

test "dns-async: over-cap requests queue and cancel detaches" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 53));

    var name_buf: [32]u8 = undefined;
    for (0..65) |i| {
        const n = std.fmt.bufPrint(&name_buf, "h{d}.test", .{i}) catch unreachable;
        try r.resolve(n, .client, 5222, i + 1, true);
    }
    try std.testing.expectEqual(@as(usize, 64), r.jobs.items.len);
    try std.testing.expectEqual(@as(usize, 1), r.wait_queue.items.len);

    // cancel removes the queued entry and an in-flight waiter.
    r.cancel(65);
    try std.testing.expectEqual(@as(usize, 0), r.wait_queue.items.len);
    r.cancel(1);
    try std.testing.expectEqual(@as(usize, 63), r.jobs.items.len);
    // cancel of a missing key is a no-op.
    r.cancel(999);
}

test "dns-async: cache keys fold case; TTL 0 stays off the wire" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));

    // First query goes to the wire; the differently-cased repeat is a
    // folded-key cache hit and never retransmits.
    var ctx1 = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx1, .fun = TestCtx.onQuery });
    try r.query("HOST.test", .a, 7);
    var spins: usize = 0;
    while (ctx1.status == null and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.resolved, ctx1.status.?);
    var res1 = ctx1.raw.?;
    defer res1.deinitOn(std.testing.allocator);
    const wired = srv.udp_recvd.load(.monotonic);

    var ctx2 = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx2, .fun = TestCtx.onQuery });
    try r.query("host.TEST", .a, 8);
    try std.testing.expectEqual(Status.resolved, ctx2.status.?);
    var res2 = ctx2.raw.?;
    defer res2.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(wired, srv.udp_recvd.load(.monotonic));

    // TTL is capped at the 300 s ceiling regardless of the wire value.
    const owned_name = try std.testing.allocator.dupe(u8, "ttl.test");
    defer std.testing.allocator.free(owned_name);
    const owned_rdata = try std.testing.allocator.dupe(u8, &.{ 1, 2, 3, 4 });
    defer std.testing.allocator.free(owned_rdata);
    var rrs = [1]wire.Rr{.{ .name = owned_name, .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 600, .rdata = owned_rdata }};
    r.cachePut("ttl.test", KIND_A, &rrs);
    const ent = r.cacheGet("ttl.test", KIND_A).?;
    const remaining_ms = ent.expires_ms - nowMs();
    try std.testing.expect(remaining_ms <= 300_000 and remaining_ms > 290_000);

    // TTL 0 is never cached.
    rrs[0].ttl = 0;
    r.cachePut("ttl0.test", KIND_A, &rrs);
    try std.testing.expect(r.cacheGet("ttl0.test", KIND_A) == null);
}

test "dns-async: NXDOMAIN and NODATA are negative-cached from the SOA minimum" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.nxdomain_all.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));

    var ctx1 = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx1, .fun = TestCtx.onQuery });
    try r.query("gone.test", .a, 7);
    var spins: usize = 0;
    while (ctx1.status == null and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.nxdomain, ctx1.status.?);
    const wired = srv.udp_recvd.load(.monotonic);

    // The repeat is answered from the negative entry, not the wire.
    var ctx2 = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx2, .fun = TestCtx.onQuery });
    try r.query("gone.test", .a, 8);
    try std.testing.expectEqual(Status.nxdomain, ctx2.status.?);
    try std.testing.expectEqual(wired, srv.udp_recvd.load(.monotonic));

    // NODATA (answer empty, SOA present) caches the same way.
    srv.nxdomain_all.store(false, .monotonic);
    srv.soa_nodata.store(true, .monotonic);
    var ctx3 = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx3, .fun = TestCtx.onQuery });
    try r.query("empty.test", .aaaa, 9);
    spins = 0;
    while (ctx3.status == null and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.resolved, ctx3.status.?);
    try std.testing.expectEqual(@as(usize, 0), ctx3.raw.?.rrs.len);
    const wired2 = srv.udp_recvd.load(.monotonic);

    var ctx4 = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx4, .fun = TestCtx.onQuery });
    try r.query("empty.test", .aaaa, 10);
    try std.testing.expectEqual(Status.resolved, ctx4.status.?);
    try std.testing.expectEqual(wired2, srv.udp_recvd.load(.monotonic));
}

test "dns-async: a full waiter array starts a second job, not a failure" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = FreeingCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = FreeingCtx.onResolve });

    // MAX_WAITERS+1 identical resolves: the 17th must not error and
    // must not grow the first job's bounded waiter array.
    for (0..17) |i| try r.resolve("svc.test", .client, 5222, i + 1, true);
    try std.testing.expectEqual(@as(usize, 2), r.jobs.items.len);
    try std.testing.expectEqual(@as(usize, 16), r.jobs.items[0].waiter_count);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items[1].waiter_count);
}

test "dns-async: a full wait queue counts the rejection (TooManyJobs)" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 53));

    var name_buf: [32]u8 = undefined;
    // 64 in-flight jobs plus 256 queued requests fills both bounds.
    for (0..320) |i| {
        const n = std.fmt.bufPrint(&name_buf, "h{d}.test", .{i}) catch unreachable;
        try r.resolve(n, .client, 5222, i + 1, true);
    }
    try std.testing.expectEqual(@as(usize, 64), r.jobs.items.len);
    try std.testing.expectEqual(@as(usize, 256), r.wait_queue.items.len);

    const n = std.fmt.bufPrint(&name_buf, "overflow.test", .{}) catch unreachable;
    try std.testing.expectError(error.TooManyJobs, r.resolve(n, .client, 5222, 999, true));
    try std.testing.expectEqual(@as(usize, 1), r.too_many_jobs);
}

test "dns-async: cancel fires no callback and frees a last-waiter job" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = FreeingCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = FreeingCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 1, true);
    try r.resolve("svc.test", .client, 5222, 2, true);
    r.cancel(1);
    r.cancel(2);
    // Both waiters gone: the job is freed and its slot purged, so a
    // queued deadline event would be recognized as stale.
    try std.testing.expectEqual(@as(usize, 0), r.jobs.items.len);
    for (r.slots) |s| try std.testing.expect(s == null);

    var spins: usize = 0;
    while (spins < 50) : (spins += 1) r.step(50);
    try std.testing.expectEqual(@as(usize, 0), ctx.calls);
}

test "dns-async: a shared job notifies only its remaining waiters" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = FreeingCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = FreeingCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 1, true);
    try r.resolve("svc.test", .client, 5222, 2, true);
    r.cancel(1);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);

    var spins: usize = 0;
    while (ctx.calls < 1 and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(@as(usize, 1), ctx.calls);
    try std.testing.expectEqual(@as(usize, 2), ctx.keys[0]);
}

const CancelSiblingCtx = struct {
    r: *Resolver,
    calls: [8]usize = .{0} ** 8,

    fn onResolve(ctx_ptr: ?*anyopaque, key: usize, _: Status, res: ?Resolution) void {
        const self: *CancelSiblingCtx = @ptrCast(@alignCast(ctx_ptr.?));
        self.calls[key] += 1;
        if (res) |*v| {
            var x = v.*;
            x.deinitOn(std.testing.allocator);
        }
        if (key == 1) self.r.cancel(2);
    }
};

test "dns-async: cancel inside a sibling callback suppresses its callback" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = CancelSiblingCtx{ .r = &r };
    r.setCallback(.{ .ctx = &ctx, .fun = CancelSiblingCtx.onResolve });

    // Keys 1 and 2 share one job; key 1's callback cancels key 2, whose
    // callback must never fire even though the job completes.
    try r.resolve("svc.test", .client, 5222, 1, true);
    try r.resolve("svc.test", .client, 5222, 2, true);
    var spins: usize = 0;
    while (ctx.calls[1] == 0 and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(@as(usize, 1), ctx.calls[1]);
    try std.testing.expectEqual(@as(usize, 0), ctx.calls[2]);
}

const NestCtx = struct {
    r: *Resolver,
    calls: [16]usize = .{0} ** 16,

    fn onResolve(ctx_ptr: ?*anyopaque, key: usize, _: Status, res: ?Resolution) void {
        const self: *NestCtx = @ptrCast(@alignCast(ctx_ptr.?));
        self.calls[key] += 1;
        if (res) |*v| {
            var x = v.*;
            x.deinitOn(std.testing.allocator);
        }
        // Key 1 finishes a second resolve synchronously from cache and
        // then cancels its sibling: the nested completion must not
        // hide the outer job from cancel().
        if (key == 1) {
            self.r.resolve("svc.test", .client, 5222, 9, false) catch {};
            self.r.cancel(2);
        }
    }
};

test "dns-async: a nested completion inside a callback keeps sibling cancel" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = NestCtx{ .r = &r };
    r.setCallback(.{ .ctx = &ctx, .fun = NestCtx.onResolve });

    // Keys 1 and 2 share one in-flight job; the svc.test chain is
    // cache-seeded so key 1's nested resolve completes inline.
    try r.resolve("x.test", .client, 5222, 1, false);
    try r.resolve("x.test", .client, 5222, 2, false);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    try std.testing.expectEqual(@as(usize, 2), r.jobs.items[0].waiter_count);
    seedSvcChain(&r, false);

    const job = r.jobs.items[0];
    const host = try std.testing.allocator.dupe(u8, "x.test");
    job.targets.append(std.testing.allocator, .{
        .addr = try net.Address.parseIp("127.0.0.1", 5222),
        .host = host,
        .tlsa = &.{},
        .tlsa_status = .absent,
        .is_direct_tls = false,
    }) catch unreachable;
    r.onChainDeadline(job);

    try std.testing.expectEqual(@as(usize, 1), ctx.calls[1]);
    try std.testing.expectEqual(@as(usize, 1), ctx.calls[9]);
    try std.testing.expectEqual(@as(usize, 0), ctx.calls[2]);
}

const NestCancelCtx = struct {
    r: *Resolver,
    calls: [16]usize = .{0} ** 16,
    nested: enum { none, promote_query, resolve_nx } = .none,

    fn onResolve(ctx_ptr: ?*anyopaque, key: usize, _: Status, res: ?Resolution) void {
        const self: *NestCancelCtx = @ptrCast(@alignCast(ctx_ptr.?));
        self.calls[key] += 1;
        if (res) |*v| {
            var x = v.*;
            x.deinitOn(std.testing.allocator);
        }
        if (key != 1) return;
        // Whatever the nested completion did to in_callback, it must
        // be restored so this sibling cancel still marks the outer job.
        switch (self.nested) {
            .none => {},
            .promote_query => self.r.cancel(3),
            .resolve_nx => self.r.resolve("neg.test", .client, 5222, 9, false) catch {},
        }
        self.r.cancel(2);
    }

    fn onQuery(_: ?*anyopaque, _: usize, _: Status, res: ?RecordResult) void {
        if (res) |*v| {
            var x = v.*;
            x.deinitOn(std.testing.allocator);
        }
    }
};

/// Outer job: resolve("x.test") shared by waiters 1 and 2, completed
/// by hand through onChainDeadline so waiter 1's callback drives the
/// nested completion under test and then cancels waiter 2.
fn driveNestedCancel(r: *Resolver, ctx: *NestCancelCtx) !void {
    try r.resolve("x.test", .client, 5222, 1, false);
    try r.resolve("x.test", .client, 5222, 2, false);
    var outer: ?*Job = null;
    for (r.jobs.items) |j| {
        if (std.mem.eql(u8, j.name, "x.test")) outer = j;
    }
    try std.testing.expectEqual(@as(usize, 2), outer.?.waiter_count);
    const host = try std.testing.allocator.dupe(u8, "x.test");
    try outer.?.targets.append(std.testing.allocator, .{
        .addr = try net.Address.parseIp("127.0.0.1", 5222),
        .host = host,
        .tlsa = &.{},
        .tlsa_status = .absent,
        .is_direct_tls = false,
    });
    r.onChainDeadline(outer.?);
    try std.testing.expectEqual(@as(usize, 1), ctx.calls[1]);
    try std.testing.expectEqual(@as(usize, 0), ctx.calls[2]);
}

test "dns-async: a nested completeRaw restores the outer in_callback" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = NestCancelCtx{ .r = &r, .nested = .promote_query };
    r.setCallback(.{ .ctx = &ctx, .fun = NestCancelCtx.onResolve });
    r.setQueryCallback(.{ .ctx = &ctx, .fun = NestCancelCtx.onQuery });

    // Key 3 holds a second in-flight job; a queued raw query sits
    // behind it. cancel(3) frees the job, promoteWait launches the
    // query, and the cache hit completes it through completeRaw.
    try r.resolve("j.test", .client, 5222, 3, false);
    const wname = try std.testing.allocator.dupe(u8, "cached.test");
    try r.wait_queue.append(std.testing.allocator, .{
        .session_key = 5,
        .name = wname,
        .kind = .query,
        .rtype = KIND_A,
    });
    var rrs = [1]wire.Rr{.{ .name = "cached.test", .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = &.{ 127, 0, 0, 1 } }};
    r.cachePut("cached.test", KIND_A, &rrs);

    try driveNestedCancel(&r, &ctx);
}

test "dns-async: a nested dropJob (raw) restores the outer in_callback" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = NestCancelCtx{ .r = &r, .nested = .promote_query };
    r.setCallback(.{ .ctx = &ctx, .fun = NestCancelCtx.onResolve });
    r.setQueryCallback(.{ .ctx = &ctx, .fun = NestCancelCtx.onQuery });

    // Same promote as above, but the queued query hits a cached
    // NXDOMAIN: launchQuery -> sendQuery -> dropJob on the raw branch.
    try r.resolve("j.test", .client, 5222, 3, false);
    const wname = try std.testing.allocator.dupe(u8, "negq.test");
    try r.wait_queue.append(std.testing.allocator, .{
        .session_key = 5,
        .name = wname,
        .kind = .query,
        .rtype = KIND_A,
    });
    r.cacheInsert("negq.test", KIND_A, &.{}, .nxdomain, 60);

    try driveNestedCancel(&r, &ctx);
}

test "dns-async: a nested dropJob (resolve) restores the outer in_callback" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = NestCancelCtx{ .r = &r, .nested = .resolve_nx };
    r.setCallback(.{ .ctx = &ctx, .fun = NestCancelCtx.onResolve });
    r.setQueryCallback(.{ .ctx = &ctx, .fun = NestCancelCtx.onQuery });

    // Every step of the neg.test chain is a cached NXDOMAIN: the
    // nested resolve drops through dropJob on the resolve branch.
    r.cacheInsert("_xmpps-client._tcp.neg.test", KIND_SRV, &.{}, .nxdomain, 60);
    r.cacheInsert("_xmpp-client._tcp.neg.test", KIND_SRV, &.{}, .nxdomain, 60);
    r.cacheInsert("neg.test", KIND_AAAA, &.{}, .nxdomain, 60);
    r.cacheInsert("neg.test", KIND_A, &.{}, .nxdomain, 60);

    try driveNestedCancel(&r, &ctx);
    try std.testing.expectEqual(@as(usize, 1), ctx.calls[9]);
}

test "dns-async: cancel purges the key's queued entry before promoting" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 53));

    // Key 1 waits on an in-flight job and also owns a queued request.
    try r.resolve("held.test", .client, 5222, 1, true);
    var name_buf: [32]u8 = undefined;
    for (2..65) |i| {
        const n = std.fmt.bufPrint(&name_buf, "h{d}.test", .{i}) catch unreachable;
        try r.resolve(n, .client, 5222, i, true);
    }
    try std.testing.expectEqual(@as(usize, 64), r.jobs.items.len);
    try r.query("queued.test", .a, 1);
    try std.testing.expectEqual(@as(usize, 1), r.wait_queue.items.len);

    // Seed the RR cache so a launch of the queued query would complete
    // synchronously; cancelled, it must never run at all.
    const owned_name = try std.testing.allocator.dupe(u8, "queued.test");
    defer std.testing.allocator.free(owned_name);
    const owned_rdata = try std.testing.allocator.dupe(u8, &.{ 10, 1, 1, 1 });
    defer std.testing.allocator.free(owned_rdata);
    var rrs = [1]wire.Rr{.{ .name = owned_name, .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = owned_rdata }};
    r.cachePut("queued.test", KIND_A, &rrs);

    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    r.cancel(1);

    try std.testing.expect(ctx.status == null);
    try std.testing.expectEqual(@as(usize, 0), r.wait_queue.items.len);
    for (r.jobs.items) |j| try std.testing.expect(!std.ascii.eqlIgnoreCase(j.name, "queued.test"));
}

test "dns-async: a failed launch inside promoteWait answers .failed" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 53));

    // A queued query whose job allocation fails still owes its waiter
    // an answer; swallowed, the waiter would hang forever.
    const name = try std.testing.allocator.dupe(u8, "queued.test");
    try r.wait_queue.append(std.testing.allocator, .{
        .session_key = 7,
        .name = name,
        .kind = .query,
        .rtype = KIND_A,
    });
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    r.alloc = failing.allocator();

    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    r.promoteWait();

    try std.testing.expectEqual(Status.failed, ctx.status.?);
    try std.testing.expectEqual(@as(usize, 0), r.jobs.items.len);
    try std.testing.expectEqual(@as(usize, 0), r.wait_queue.items.len);
}

test "dns-async: a silent server exhausts per-query retries into failed" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_silent.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, true);
    // 2 s per try x MAX_TRIES; give the deadline room to fire twice.
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.failed, ctx.status.?);
    // The retry timer retransmitted at least once before dropping.
    try std.testing.expect(srv.udp_recvd.load(.monotonic) >= 2);
}

test "dns-async: the cache evicts the LRU tail past the owner bound" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));

    // Fill the cache directly: eviction order is what matters, not
    // how the entries arrived, and the wire stays out of it.
    const owned_name = try std.testing.allocator.dupe(u8, "x.test");
    defer std.testing.allocator.free(owned_name);
    const owned_rdata = try std.testing.allocator.dupe(u8, &.{ 10, 1, 1, 1 });
    defer std.testing.allocator.free(owned_rdata);
    var rrs = [1]wire.Rr{.{ .name = owned_name, .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = owned_rdata }};
    var name_buf: [40]u8 = undefined;
    for (0..CACHE_ENTRIES_MAX) |i| {
        const n = std.fmt.bufPrint(&name_buf, "c{d}.test", .{i}) catch unreachable;
        r.cachePut(n, KIND_A, &rrs);
    }
    try std.testing.expectEqual(@as(usize, CACHE_ENTRIES_MAX), r.owners.count());

    // A fresh hit marks c0 most-recently-used, so the one-past-full
    // insert sheds the untouched tail (c1), not c0.
    try std.testing.expect(r.cacheGet("c0.test", KIND_A) != null);
    r.cachePut("c_last.test", KIND_A, &rrs);
    try std.testing.expectEqual(@as(usize, CACHE_ENTRIES_MAX), r.owners.count());
    try std.testing.expect(r.cacheGet("c0.test", KIND_A) != null);
    try std.testing.expect(r.cacheGet("c1.test", KIND_A) == null);
    try std.testing.expect(r.cacheGet("c_last.test", KIND_A) != null);

    // c1 was evicted: asking for it again costs a wire round trip.
    const wired = srv.udp_recvd.load(.monotonic);
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("c1.test", .a, 999);
    var spins: usize = 0;
    while (ctx.status == null and spins < 100) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    if (ctx.raw) |*res| {
        var v = res.*;
        v.deinitOn(std.testing.allocator);
    }
    try std.testing.expect(srv.udp_recvd.load(.monotonic) > wired);
}

test "dns-async: the byte budget evicts until it fits" {
    // Goal: inserts past CACHE_BYTES_MAX shed owners until the
    // accounted total fits again. Method: seed 4 KiB rdata records
    // so each owner counts several KiB, then insert past the budget.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 5_000_000;

    const owned_name = try std.testing.allocator.dupe(u8, "x.test");
    defer std.testing.allocator.free(owned_name);
    const owned_rdata = try std.testing.allocator.dupe(u8, &([1]u8{0xAB} ** 4096));
    defer std.testing.allocator.free(owned_rdata);
    var rrs = [1]wire.Rr{.{ .name = owned_name, .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = owned_rdata }};

    var name_buf: [40]u8 = undefined;
    const n_owners = CACHE_BYTES_MAX / 4096 + 64;
    for (0..n_owners) |i| {
        const n = std.fmt.bufPrint(&name_buf, "b{d}.test", .{i}) catch unreachable;
        r.cachePut(n, KIND_A, &rrs);
    }
    try std.testing.expect(r.cache_bytes <= CACHE_BYTES_MAX);
    try std.testing.expect(r.owners.count() < n_owners);
    // Eviction walked the LRU tail: the earliest inserts are gone.
    try std.testing.expect(r.cacheGet("b0.test", KIND_A) == null);
    const last = std.fmt.bufPrint(&name_buf, "b{d}.test", .{n_owners - 1}) catch unreachable;
    try std.testing.expect(r.cacheGet(last, KIND_A) != null);
}

test "dns-async: stale owners evict before fresh ones under pressure" {
    // Goal: RFC 8767 section 6 - an insert over budget evicts a stale
    // owner even when a fresh owner sits at the LRU tail. Method:
    // evictOne is walked by hand on a three-owner cache whose tail
    // is the only fresh entry.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 7_000_000;

    const owned_name = try std.testing.allocator.dupe(u8, "x.test");
    defer std.testing.allocator.free(owned_name);
    const owned_rdata = try std.testing.allocator.dupe(u8, &.{ 10, 1, 1, 1 });
    defer std.testing.allocator.free(owned_rdata);
    var rrs = [1]wire.Rr{.{ .name = owned_name, .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = owned_rdata }};

    // LRU order tail->head: fresh.test, old2.test, old1.test.
    r.cachePut("fresh.test", KIND_A, &rrs);
    rrs[0].ttl = 30;
    r.cachePut("old1.test", KIND_A, &rrs);
    r.cachePut("old2.test", KIND_A, &rrs);
    rrs[0].ttl = 60;
    // Expire only the two older rows.
    fake_now += 31_000;
    try std.testing.expectEqual(@as(usize, 3), r.owners.count());

    try std.testing.expect(r.evictOne(r.now_ms()));
    // old1 was tail-most stale: gone, while the fresh tail survives.
    try std.testing.expectEqual(@as(usize, 2), r.owners.count());
    try std.testing.expect(r.owners.get("old1.test") == null);
    try std.testing.expect(r.cacheGet("fresh.test", KIND_A) != null);
    try std.testing.expect(r.evictOne(r.now_ms()));
    try std.testing.expectEqual(@as(usize, 1), r.owners.count());
    try std.testing.expect(r.cacheGet("fresh.test", KIND_A) != null);
    // All-fresh cache sheds the tail.
    try std.testing.expect(r.evictOne(r.now_ms()));
    try std.testing.expectEqual(@as(usize, 0), r.owners.count());
    try std.testing.expect(!r.evictOne(r.now_ms()));
}

test "dns-async: eviction past the scan window sheds the fresh tail" {
    // Goal: the stale-first walk is bounded to EVICT_SCAN_MAX nodes;
    // a stale owner parked deeper than the window survives while the
    // fresh tail sheds. Method: 94 KiB answers so 43 owners sit just
    // under the byte budget and the 44th overflows, one eviction per
    // insert; the stale row sits EVICT_SCAN_MAX + 1 nodes above the
    // tail.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 11_000_000;

    const owned_name = try std.testing.allocator.dupe(u8, "x.test");
    defer std.testing.allocator.free(owned_name);
    const owned_rdata = try std.testing.allocator.alloc(u8, 94 * 1024);
    defer std.testing.allocator.free(owned_rdata);
    @memset(owned_rdata, 0xAB);
    var rrs = [1]wire.Rr{.{ .name = owned_name, .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = owned_rdata }};

    // LRU tail->head: e0..e32 fresh, stale.test parked past the scan
    // window behind h0..h8.
    var name_buf: [40]u8 = undefined;
    for (0..EVICT_SCAN_MAX + 1) |i| {
        const n = std.fmt.bufPrint(&name_buf, "e{d}.test", .{i}) catch unreachable;
        r.cachePut(n, KIND_A, &rrs);
    }
    rrs[0].ttl = 30;
    r.cachePut("stale.test", KIND_A, &rrs);
    rrs[0].ttl = 60;
    for (0..9) |i| {
        const n = std.fmt.bufPrint(&name_buf, "h{d}.test", .{i}) catch unreachable;
        r.cachePut(n, KIND_A, &rrs);
    }
    // Only the 30 s row is stale; every other owner is still fresh.
    fake_now += 31_000;
    try std.testing.expectEqual(@as(usize, EVICT_SCAN_MAX + 11), r.owners.count());

    // One insert over budget evicts one owner: the window holds only
    // fresh owners, so the tail-most fresh one sheds while the stale
    // owner deeper than the window survives. An unbounded stale-first
    // walk would have evicted stale.test instead.
    r.cachePut("over.test", KIND_A, &rrs);
    try std.testing.expect(r.cache_bytes <= CACHE_BYTES_MAX);
    try std.testing.expect(r.owners.get("e0.test") == null);
    try std.testing.expect(r.owners.get("e32.test") != null);
    try std.testing.expect(r.owners.get("stale.test") != null);
    try std.testing.expect(r.owners.get("over.test") != null);
}

test "dns-async: a CNAME answer evicts sibling types at the owner" {
    // Goal: RFC 8767 section 7 - caching an answer that carries a
    // CNAME record proves the owner an alias and drops its other
    // cached types. Method: seed A and SRV rows, then re-put the A
    // row with a CNAME record in the answer.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 9_000_000;

    const owned_name = try std.testing.allocator.dupe(u8, "x.test");
    defer std.testing.allocator.free(owned_name);
    const owned_rdata = try std.testing.allocator.dupe(u8, &.{ 10, 1, 1, 1 });
    defer std.testing.allocator.free(owned_rdata);
    const a_rr = [1]wire.Rr{.{ .name = owned_name, .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = owned_rdata }};
    const srv_rr = [1]wire.Rr{.{ .name = owned_name, .rtype = KIND_SRV, .class = wire.CLASS_IN, .ttl = 60, .rdata = owned_rdata }};
    r.cachePut("x.test", KIND_A, &a_rr);
    r.cachePut("x.test", KIND_SRV, &srv_rr);
    try std.testing.expect(r.cacheGet("x.test", KIND_SRV) != null);

    const cname_rdata = try std.testing.allocator.dupe(u8, &.{ 3, 'w', 'w', 'w', 0 });
    defer std.testing.allocator.free(cname_rdata);
    const alias = [2]wire.Rr{
        .{ .name = owned_name, .rtype = wire.TYPE_CNAME, .class = wire.CLASS_IN, .ttl = 60, .rdata = cname_rdata },
        .{ .name = owned_name, .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = owned_rdata },
    };
    r.cachePut("x.test", KIND_A, &alias);

    // The SRV row is gone; the refreshed (alias) A row remains.
    try std.testing.expect(r.cacheGet("x.test", KIND_SRV) == null);
    try std.testing.expect(r.cacheGet("x.test", KIND_A) != null);
}

test "dns-async: the default cache clock is monotonic" {
    // A monotonic source sits near uptime (small) while the wall
    // clock sits near the epoch (large); confusing them would break
    // every TTL comparison.
    try std.testing.expect(nowMs() < std.time.milliTimestamp());
}

test "dns-async: RFC 2782 draws follow weight; weight-0 still gets picked" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.prng = std.Random.DefaultPrng.init(0x5EED);

    // Three same-priority targets weighted 3:1:0. Over 400 draws the
    // heavyweight must lead far more often than the 1-weight, and the
    // weightless record must win at least once (inclusive draw).
    var heavy_first: usize = 0;
    var light_first: usize = 0;
    var zero_first: usize = 0;
    for (0..400) |_| {
        var list = [_]SrvEnt{
            .{ .host = "heavy", .weight = 3, .priority = 10 },
            .{ .host = "light", .weight = 1, .priority = 10 },
            .{ .host = "zero", .weight = 0, .priority = 10 },
            .{ .host = "prio5", .weight = 100, .priority = 5 },
        };
        orderSrvRfc2782(&list, r.prng.random());
        // Priority dominates weight: the lone priority-5 record leads.
        try std.testing.expectEqualStrings("prio5", list[0].host);
        if (std.mem.eql(u8, list[1].host, "heavy")) heavy_first += 1;
        if (std.mem.eql(u8, list[1].host, "light")) light_first += 1;
        if (std.mem.eql(u8, list[1].host, "zero")) zero_first += 1;
    }
    try std.testing.expect(heavy_first > light_first * 2);
    try std.testing.expect(zero_first > 0);
}

test "dns-async: a wrong-qtype decoy cannot steer the chain" {
    const srv = try startFakeDns(false, "_xmpp-decoy._tcp.svc.test");
    defer stopFakeDns(srv);
    srv.decoy_qtype = wire.TYPE_AAAA;

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    // The decoy named a service prefix we never asked about AND a
    // qtype we never asked for; the real chain still completes.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expect(res.targets.len >= 1);
}

test "dns-async: a refused TCP connect fails the job via SO_ERROR" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });

    try r.query("host.test", .a, 7);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    const job = r.jobs.items[0];

    // A non-blocking connect to a closed port reports writable with
    // SO_ERROR set; the engine's EVFILT.WRITE path must drop the job.
    // The knote carries the (seq, gen, slot) udata the resolver stamps
    // on its own TCP registrations.
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
    var ch = [1]posix.Kevent{.{
        .ident = @intCast(fd),
        .filter = std.c.EVFILT.WRITE,
        .flags = std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT,
        .fflags = 0,
        .data = 0,
        .udata = Resolver.tcpUdata(job),
    }};
    _ = posix.kevent(r.kq, &ch, &.{}, null) catch {};
    posix.connect(fd, &r.server.any, r.server.getOsSockLen()) catch {};
    job.tcp_fd = fd;

    var spins: usize = 0;
    while (ctx.status == null and spins < 100) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.failed, ctx.status.?);
    try std.testing.expectEqual(@as(usize, 0), r.jobs.items.len);
}

test "dns-async: a chain query staged while the TCP connect is pending cannot panic" {
    // Goal: a TC upgrade whose TCP connect stays pending must not
    // crash when the next phase's query reuses the socket: send(2)
    // on a pending connect is ENOTCONN, which std maps to
    // unreachable. The pending WRITE knote owns the send instead.
    // Method: the pend_connects seam holds every connect pending
    // without calling connect(2), so the test cannot race a
    // synchronous refusal; feed the chain a TC answer and run the
    // retry deadlines so failQuery sends the _xmpp SRV query while
    // the connect is still pending.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.pend_connects = true;
    r.setServer(try net.Address.parseIp("192.0.2.1", 53));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 1, true);
    const job = r.jobs.items[0];

    var tbuf: [512]u8 = undefined;
    r.handleResponse(job, tbuf[0..buildTruncated(&tbuf, job.request)]);
    try std.testing.expect(job.tcp_fd >= 0);
    try std.testing.expect(!job.tcp_connected);

    // Retry deadlines re-open the connection each time; the seam
    // keeps every connect pending.
    r.onDeadline(job);
    try std.testing.expect(!job.tcp_connected);
    r.onDeadline(job);
    // tries exhausted: failQuery advances to the _xmpp SRV query,
    // which stages on the still-pending socket instead of writing.
    r.onDeadline(job);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    try std.testing.expectEqual(Phase.srv_plain, r.jobs.items[0].phase);

    // The whole-chain bound then ends the lookup as a failure.
    r.onChainDeadline(job);
    try std.testing.expectEqual(Status.failed, ctx.status.?);
    try std.testing.expectEqual(@as(usize, 1), ctx.calls);
}

test "dns-async: a duplicate TC reply during a pending connect cannot panic" {
    // Same pending-connect hazard, reached by a second truncated
    // answer matching the retransmitted UDP query: the phase machine
    // must never let a send hit the unconnected socket. The
    // pend_connects seam keeps the connect pending deterministically.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.pend_connects = true;
    r.setServer(try net.Address.parseIp("192.0.2.1", 53));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 1, true);
    const job = r.jobs.items[0];

    var tbuf: [512]u8 = undefined;
    const tl = buildTruncated(&tbuf, job.request);
    r.handleResponse(job, tbuf[0..tl]);
    try std.testing.expect(!job.tcp_connected);
    r.handleResponse(job, tbuf[0..tl]);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    try std.testing.expectEqual(@as(usize, 0), ctx.calls);

    // The next phase's sendQuery reuses the still-pending socket: the
    // guard in tcpSend leaves the frame to the armed WRITE knote
    // rather than writing to the unconnected socket.
    r.handleResponse(job, tbuf[0..answerTcpQuery(&tbuf, job.request)]);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    try std.testing.expectEqual(Phase.srv_plain, r.jobs.items[0].phase);
    try std.testing.expect(!r.jobs.items[0].tcp_connected);

    r.onChainDeadline(r.jobs.items[0]);
    try std.testing.expectEqual(Status.failed, ctx.status.?);
}

test "dns-async: a late TC reply on the TCP leg is not an answer (per-target TLSA)" {
    // Goal: a truncated UDP reply arriving after the job upgraded to
    // TCP must be ignored, never parsed as NODATA: on a TLSA leg
    // that forged absence would permit PKIX under dane_first
    // (ADR-13). The leg must stay lookup_failed.
    // Method: the pend_connects seam holds the TCP connect pending;
    // feed the chain into the .tlsa phase, upgrade with a TC reply,
    // feed the same TC again, then run the retry deadlines.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.pend_connects = true;
    r.setServer(try net.Address.parseIp("192.0.2.1", 53));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 1, true);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;

    // _xmpps SRV NODATA, _xmpp SRV, A record, AAAA NODATA: the job
    // is now in the .tlsa phase with the TLSA query outstanding.
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    try std.testing.expectEqual(Phase.tlsa, job.phase);

    // The TC reply upgrades the query to TCP; the connect stays
    // pending.
    const tl = buildTruncated(&buf, job.request);
    r.handleResponse(job, buf[0..tl]);
    try std.testing.expect(job.use_tcp);
    try std.testing.expect(!job.tcp_connected);

    // The retransmit's late TC reply must be ignored: the job keeps
    // its TLSA phase instead of taking the forged empty answer.
    r.handleResponse(job, buf[0..tl]);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    try std.testing.expectEqual(Phase.tlsa, r.jobs.items[0].phase);
    try std.testing.expectEqual(@as(usize, 0), ctx.calls);

    // The TCP leg can never answer; retry deadlines exhaust into the
    // ordinary phase failure, which marks the target lookup_failed.
    // Each deadline may free the job, so it is re-fetched from the
    // list instead of trusting the stale pointer.
    for (0..MAX_TRIES + 2) |_| {
        if (r.jobs.items.len == 0 or ctx.status != null) break;
        r.onDeadline(r.jobs.items[0]);
    }
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    try std.testing.expectEqual(@as(usize, 1), ctx.calls);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.lookup_failed, res.targets[0].tlsa_status);
}

test "dns-async: a late TC reply on the TCP leg is not an answer (fallback TLSA)" {
    // Same forged-NODATA guard as above, on the no-SRV fallback TLSA
    // leg: the shared TLSA status of the fallback targets must stay
    // lookup_failed. The pend_connects seam holds the connect pending.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.pend_connects = true;
    r.setServer(try net.Address.parseIp("192.0.2.1", 53));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 1, true);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;

    // Both SRV names NODATA, AAAA NODATA, A record: the job is now
    // in the .fallback_tlsa phase with the TLSA query outstanding.
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    try std.testing.expectEqual(Phase.fallback_tlsa, job.phase);

    const tl = buildTruncated(&buf, job.request);
    r.handleResponse(job, buf[0..tl]);
    try std.testing.expect(!job.tcp_connected);

    r.handleResponse(job, buf[0..tl]);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    try std.testing.expectEqual(Phase.fallback_tlsa, r.jobs.items[0].phase);
    try std.testing.expectEqual(@as(usize, 0), ctx.calls);

    // Each deadline may free the job; re-fetch it from the list.
    for (0..MAX_TRIES + 2) |_| {
        if (r.jobs.items.len == 0 or ctx.status != null) break;
        r.onDeadline(r.jobs.items[0]);
    }
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.lookup_failed, res.targets[0].tlsa_status);
}

test "dns-async: a second close on the same TCP query fails the phase (TLSA lookup_failed)" {
    // Goal: RFC 7766 close-after-answer permits one resend. A second
    // close while the resent query is unanswered runs failQuery, so
    // a TLSA leg keeps lookup_failed - never nxdomain, never a
    // whole-job drop, and never a third connection.
    // Method: the chain is fed to .tlsa over injected answers, the
    // TLSA query upgrades to TCP on a test listener, and both
    // accepted connections read the frame then close unanswered.
    const lfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
    defer posix.close(lfd);
    const bind_addr = try net.Address.parseIp("127.0.0.1", 0);
    try posix.bind(lfd, &bind_addr.any, bind_addr.getOsSockLen());
    try posix.listen(lfd, 4);
    var actual: posix.sockaddr = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr);
    try posix.getsockname(lfd, &actual, &slen);
    const port = net.Address.initPosix(@alignCast(&actual)).getPort();

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 1, true);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    try std.testing.expectEqual(Phase.tlsa, job.phase);
    r.handleResponse(job, buf[0..buildTruncated(&buf, job.request)]);

    const tv = posix.timeval{ .sec = 0, .usec = 50_000 };
    var fbuf: [1024]u8 = undefined;
    var hdr: [2]u8 = undefined;
    var accepts: usize = 0;
    while (accepts < 2 and ctx.status == null) : (accepts += 1) {
        const cfd = try acceptTcpBounded(&r, lfd);
        try posix.setsockopt(cfd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
        var got: usize = 0;
        var spins: usize = 0;
        while (got == 0 and spins < 100 and ctx.status == null) : (spins += 1) {
            r.step(10);
            if (readFull(cfd, &hdr) == 2) {
                const want = std.mem.readInt(u16, &hdr, .big);
                if (readFull(cfd, fbuf[0..want]) == want) got = want;
            }
        }
        try std.testing.expect(got > 0);
        // FIN without answering: exercises the recv-0 (FIN) arm of
        // tcpPeerClosed, not the reset arm.
        posix.close(cfd);
    }

    var spins: usize = 0;
    while (ctx.status == null and spins < 100) : (spins += 1) r.step(10);
    try std.testing.expectEqual(@as(usize, 2), accepts);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.lookup_failed, res.targets[0].tlsa_status);

    // The resend bound held: no third connection was opened.
    try std.testing.expectError(error.WouldBlock, posix.accept(lfd, null, null, 0));
}

test "dns-async: a partial frame from a closed connection is dropped, not replayed" {
    // Goal: tcpClose must clear tcp_buf; a fragment received before
    // the peer closed must not sit in front of the next connection's
    // stream, where it would corrupt the frame framing.
    // Method: the first accepted connection is sent half a frame and
    // closed; the resent query's connection gets a clean answer.
    const lfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
    defer posix.close(lfd);
    const bind_addr = try net.Address.parseIp("127.0.0.1", 0);
    try posix.bind(lfd, &bind_addr.any, bind_addr.getOsSockLen());
    try posix.listen(lfd, 4);
    var actual: posix.sockaddr = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr);
    try posix.getsockname(lfd, &actual, &slen);
    const port = net.Address.initPosix(@alignCast(&actual)).getPort();

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", port));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });

    try r.query("host.test", .a, 7);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..buildTruncated(&buf, job.request)]);

    const tv = posix.timeval{ .sec = 0, .usec = 50_000 };
    var fbuf: [1024]u8 = undefined;
    var hdr: [2]u8 = undefined;
    const cfd1 = try acceptTcpBounded(&r, lfd);
    try posix.setsockopt(cfd1, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
    var got: usize = 0;
    var spins: usize = 0;
    while (got == 0 and spins < 100) : (spins += 1) {
        r.step(10);
        if (readFull(cfd1, &hdr) == 2) {
            const want = std.mem.readInt(u16, &hdr, .big);
            if (readFull(cfd1, fbuf[0..want]) == want) got = want;
        }
    }
    try std.testing.expect(got > 0);
    // Half a foreign frame, then FIN.
    const frag = [7]u8{ 0, 20, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
    _ = try posix.send(cfd1, &frag, posix.MSG.NOSIGNAL);
    posix.close(cfd1);

    // The resent query arrives on a second connection; the fragment
    // must not precede its answer in tcp_buf.
    const cfd2 = try acceptTcpBounded(&r, lfd);
    try posix.setsockopt(cfd2, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
    got = 0;
    spins = 0;
    while (got == 0 and spins < 100) : (spins += 1) {
        r.step(10);
        if (readFull(cfd2, &hdr) == 2) {
            const want = std.mem.readInt(u16, &hdr, .big);
            if (readFull(cfd2, fbuf[0..want]) == want) got = want;
        }
    }
    try std.testing.expectEqual(job.request.len, got);
    var abuf: [1024]u8 = undefined;
    const rlen = answerTcpQuery(&abuf, fbuf[0..got]);
    var out_hdr: [2]u8 = undefined;
    std.mem.writeInt(u16, &out_hdr, @intCast(rlen), .big);
    _ = try posix.send(cfd2, &out_hdr, posix.MSG.NOSIGNAL);
    _ = try posix.send(cfd2, abuf[0..rlen], posix.MSG.NOSIGNAL);
    spins = 0;
    while (ctx.status == null and spins < 100) : (spins += 1) r.step(10);
    posix.close(cfd2);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.rrs.len);
}

test "dns-async: a stale TCP event on a recycled fd is ignored" {
    // Goal: TCP knote udata names the connection by (seq, gen, slot);
    // an event armed for a dead connection on the same fd number must
    // not reach the job that owns the fd now.
    // Method: a pending connect held by the pend_connects seam, then
    // dispatch fabricated READ and WRITE events carrying the previous
    // seq.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.pend_connects = true;
    r.setServer(try net.Address.parseIp("192.0.2.1", 53));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 1, true);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..buildTruncated(&buf, job.request)]);
    try std.testing.expect(job.tcp_fd >= 0);
    try std.testing.expect(!job.tcp_connected);

    const stale_udata = (@as(usize, job.tcp_seq -% 1) << 32) |
        (@as(usize, job.gen) << 8) | job.slot;
    var ev = [1]posix.Kevent{.{
        .ident = @intCast(job.tcp_fd),
        .filter = std.c.EVFILT.WRITE,
        .flags = 0,
        .fflags = 0,
        .data = 0,
        .udata = stale_udata,
    }};
    r.dispatchEvents(&ev);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    try std.testing.expect(!job.tcp_connected);

    ev[0].filter = std.c.EVFILT.READ;
    r.dispatchEvents(&ev);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    try std.testing.expectEqual(@as(usize, 0), ctx.calls);
}

test "dns-async: the bare name and its FQDN merge in either order" {
    // Goal: the merge key is the stripped name, so a bare lookup
    // started first still shares the FQDN's wire exchange.
    // Method: bare first, dotted second; one job, two waiters.
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = FreeingCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = FreeingCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 1, false);
    try r.resolve("svc.test.", .client, 5222, 2, false);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    try std.testing.expectEqual(@as(usize, 2), r.jobs.items[0].waiter_count);

    var spins: usize = 0;
    while (ctx.calls < 2 and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(@as(usize, 2), ctx.calls);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
}

test "dns-async: a raw query strips one trailing dot like resolve" {
    // Goal: query() takes the same FQDN normalization as resolve();
    // "host.test." must reach the wire as host.test, not fail on the
    // empty label an unstripped name would encode.
    // Method: one dotted A query against FakeDns; resolved not nxdomain.
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });

    try r.query("host.test.", .a, 7);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.rrs.len);
}

test "dns-async: only one trailing dot is stripped" {
    // Goal: "svc.test.." keeps a trailing dot after one strip, so the
    // empty label cannot be encoded and the resolve is a synchronous
    // nxdomain with no wire traffic.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 53));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test..", .client, 5222, 1, false);
    try std.testing.expectEqual(Status.nxdomain, ctx.status.?);
    try std.testing.expectEqual(@as(usize, 1), ctx.calls);
    try std.testing.expectEqual(@as(usize, 0), r.jobs.items.len);
}

test "dns-async: a refused TCP connect fails the phase, not the job" {
    // Goal: a refused connect reports writable with SO_ERROR set; the
    // outstanding query runs the ordinary phase-scoped failQuery
    // path (the same condition tcpPeerClosed documents for a failed
    // reconnect), so a TLSA leg ends lookup_failed and the resolve
    // completes instead of dropping the whole job.
    // Method: the chain is fed to .tlsa over injected answers, then
    // the TC upgrade connects to a port nobody listens on. The UDP
    // target is a bound socket that absorbs the queries: an
    // unbound port's ICMP refusals could latch onto the resolver's
    // own sends and fail the leg before TCP is reached.
    const ufd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(ufd);
    const uaddr = try net.Address.parseIp("127.0.0.1", 0);
    try posix.bind(ufd, &uaddr.any, uaddr.getOsSockLen());
    var uactual: posix.sockaddr = undefined;
    var uslen: posix.socklen_t = @sizeOf(posix.sockaddr);
    try posix.getsockname(ufd, &uactual, &uslen);
    const port = net.Address.initPosix(@alignCast(&uactual)).getPort();

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 1, true);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    try std.testing.expectEqual(Phase.tlsa, job.phase);
    r.handleResponse(job, buf[0..buildTruncated(&buf, job.request)]);

    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.lookup_failed, res.targets[0].tlsa_status);
}

test "dns-async: a synchronous connect refusal fails the phase, not the job" {
    // Goal: a connect refused inside connect(2) - FreeBSD does this on
    // real paths (loopback ~1%, pf EACCES on a source-port collision) -
    // runs the same per-phase failQuery the asynchronous SO_ERROR arm
    // runs, so a TLSA leg ends lookup_failed and the resolve completes.
    // Method: the chain is fed to .tlsa over injected answers, then the
    // TC upgrade hits the fail_connects seam inside tcpSend.
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 1, true);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    try std.testing.expectEqual(Phase.tlsa, job.phase);
    r.fail_connects = 4;
    r.handleResponse(job, buf[0..buildTruncated(&buf, job.request)]);

    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.lookup_failed, res.targets[0].tlsa_status);
}

test "dns-async: a synchronous refusal at the deadline restart fails the phase" {
    // Goal: onDeadline re-opens a dead TCP leg through tcpRestart; a
    // connect refused inside connect(2) there must run the same
    // per-phase failQuery as the asynchronous SO_ERROR arm, so the
    // TLSA leg ends lookup_failed instead of dropping the job.
    // Method: the chain is fed to .tlsa over injected answers, the
    // TLSA query upgrades to TCP on a held-pending connect, and the
    // retry deadline hits the fail_connects seam for one refusal.
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.pend_connects = true;
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 1, true);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    try std.testing.expectEqual(Phase.tlsa, r.jobs.items[0].phase);
    r.handleResponse(job, buf[0..buildTruncated(&buf, job.request)]);
    try std.testing.expect(r.jobs.items[0].use_tcp);

    r.fail_connects = 1;
    r.onDeadline(job);
    // The refusal was consumed by the restart's connect; the TLSA
    // leg failed the phase and the resolve completed.
    try std.testing.expectEqual(@as(usize, 0), r.fail_connects);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.lookup_failed, res.targets[0].tlsa_status);
}

test "dns-async: a synchronous refusal on the TCP reuse arm fails the phase" {
    // Goal: sendQuery on a TCP job with an empty write buffer takes
    // the reuse arm; a synchronous refusal there runs failQuery, not
    // a job drop.
    // Method: the fallback chain reaches .fallback_addr, upgrades to
    // TCP on a held connect, then the socket is closed and the AAAA
    // leg answered: the A sendQuery re-opens TCP through the reuse
    // arm into the seam's one refusal, and the collected address
    // still resolves the job.
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.pend_connects = true;
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 1, false);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    try std.testing.expectEqual(Phase.fallback_addr, r.jobs.items[0].phase);
    r.handleResponse(job, buf[0..buildTruncated(&buf, job.request)]);
    try std.testing.expect(r.jobs.items[0].use_tcp);

    r.tcpClose(job);
    r.fail_connects = 1;
    r.handleResponse(job, buf[0..buildAaaaAnswer(&buf, job.request)]);
    // The refusal was consumed by the reuse arm's connect; the A leg
    // failed but the AAAA answer still emitted the fallback target.
    try std.testing.expectEqual(@as(usize, 0), r.fail_connects);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
}

test "dns-async: a synchronous refusal on the TCP restart arm fails the phase" {
    // Goal: sendQuery on a TCP job with a mid-write frame takes the
    // restart arm (tcpClose + tcpSend); a synchronous refusal there
    // runs failQuery, not a job drop.
    // Method: same fallback staging; tcp_out is staged mid-write so
    // the A sendQuery takes the restart arm into the refusal.
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.pend_connects = true;
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 1, false);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    try std.testing.expectEqual(Phase.fallback_addr, r.jobs.items[0].phase);
    r.handleResponse(job, buf[0..buildTruncated(&buf, job.request)]);
    try std.testing.expect(r.jobs.items[0].use_tcp);

    try job.tcp_out.append(std.testing.allocator, 0);
    job.tcp_out_pos = 0;
    r.fail_connects = 1;
    r.handleResponse(job, buf[0..buildAaaaAnswer(&buf, job.request)]);
    try std.testing.expectEqual(@as(usize, 0), r.fail_connects);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
}

test "dns-async: an A SERVFAIL plus AAAA NODATA is a temporary failure, not nxdomain" {
    // Goal: a per-target leg that fails marks target_err, so one dead
    // family plus one empty family is a temporary failure, never an
    // nxdomain that would end the chain as 'no service'.
    // Method: an SRV answer, a SERVFAIL on the A leg, NODATA on the
    // AAAA leg; the resolve must report .failed.
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 1, false);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    try std.testing.expectEqual(Phase.addr, r.jobs.items[0].phase);
    r.handleResponse(job, buf[0..buildRcode(&buf, job.request, 2)]);
    try std.testing.expectEqual(Phase.addr6, r.jobs.items[0].phase);
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    try std.testing.expectEqual(Status.failed, ctx.status.?);
}

test "dns-async: an A NODATA plus AAAA SERVFAIL is a temporary failure, not nxdomain" {
    // Same pin for the .addr6 setter: the failure marker set by the
    // second address leg must also produce .failed.
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 1, false);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    try std.testing.expectEqual(Phase.addr, r.jobs.items[0].phase);
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    try std.testing.expectEqual(Phase.addr6, r.jobs.items[0].phase);
    r.handleResponse(job, buf[0..buildRcode(&buf, job.request, 2)]);
    try std.testing.expectEqual(Status.failed, ctx.status.?);
}

test "dns-async: an AAAA send failure after an empty A leg is a temporary failure, not nxdomain" {
    // Same pin for the sendAddr(AAAA) catch in .addr: a wire send
    // failure marks target_err, so the dead family plus the empty A
    // leg is .failed; without the setter the result is .nxdomain.
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 1, false);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    try std.testing.expectEqual(Phase.addr, r.jobs.items[0].phase);
    r.fail_sends = true;
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    r.fail_sends = false;
    try std.testing.expectEqual(Status.failed, ctx.status.?);
}

test "dns-async: an AAAA SERVFAIL plus A NODATA fallback is a temporary failure, not nxdomain" {
    // The fallback_err setter on the first fallback leg: a failed
    // AAAA leg plus an empty A leg is a temporary failure.
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 1, false);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    try std.testing.expectEqual(Phase.fallback_addr, r.jobs.items[0].phase);
    r.handleResponse(job, buf[0..buildRcode(&buf, job.request, 2)]);
    try std.testing.expectEqual(Phase.fallback_addr4, r.jobs.items[0].phase);
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    try std.testing.expectEqual(Status.failed, ctx.status.?);
}

test "dns-async: an AAAA NODATA plus A SERVFAIL fallback is a temporary failure, not nxdomain" {
    // The fallback_err setter on the second fallback leg: an empty
    // AAAA leg plus a failed A leg is a temporary failure.
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 1, false);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    try std.testing.expectEqual(Phase.fallback_addr, r.jobs.items[0].phase);
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    try std.testing.expectEqual(Phase.fallback_addr4, r.jobs.items[0].phase);
    r.handleResponse(job, buf[0..buildRcode(&buf, job.request, 2)]);
    try std.testing.expectEqual(Status.failed, ctx.status.?);
}

test "dns-async: tcp_seq advances on every connection attempt" {
    // TCP knote udata names a connection by (seq, gen, slot); a seq
    // that did not advance would let an old connection's events reach
    // the new one. Every tcpSend must bump it.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.pend_connects = true;
    r.setServer(try net.Address.parseIp("192.0.2.1", 53));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 1, true);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..buildTruncated(&buf, job.request)]);
    const s0 = r.jobs.items[0].tcp_seq;
    r.onDeadline(job);
    try std.testing.expectEqual(s0 +% 1, r.jobs.items[0].tcp_seq);
    r.onDeadline(r.jobs.items[0]);
    try std.testing.expectEqual(s0 +% 2, r.jobs.items[0].tcp_seq);
}

test "dns-async: a kevent error in step is counted" {
    // A dead kqueue must not fail silently: step() counts each
    // kevent error so the caller has a signal in the spin.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    const ufd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    const saved = r.kq;
    // A non-kqueue fd makes kevent(2) fail every time.
    r.kq = ufd;
    r.step(0);
    try std.testing.expectEqual(@as(usize, 1), r.kevent_errors);
    r.step(0);
    try std.testing.expectEqual(@as(usize, 2), r.kevent_errors);
    r.kq = saved;
    posix.close(ufd);
}

test "dns-async: a write on a send-shutdown socket reports peer close, not a drop" {
    // shutdown(.send) sets SBS_CANTSENDMORE locally and at once, so
    // the next send fails EPIPE with no peer timing; a peer close
    // would race FIN-vs-RST on loopback. tcpWrite must map EPIPE to
    // PeerClosed so tcpPeerClosed resends on a fresh connection
    // instead of dropping the job.
    const lfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(lfd);
    const la = try net.Address.parseIp("127.0.0.1", 0);
    try posix.bind(lfd, &la.any, la.getOsSockLen());
    try posix.listen(lfd, 4);
    var actual: posix.sockaddr = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr);
    try posix.getsockname(lfd, &actual, &slen);
    const sa = net.Address.initPosix(@alignCast(&actual));

    const cfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    try posix.connect(cfd, &sa.any, sa.getOsSockLen());
    const afd = try posix.accept(lfd, null, null, 0);
    defer posix.close(afd);
    try posix.shutdown(cfd, .send);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(sa);
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("host.test", .a, 7);
    const job = r.jobs.items[0];
    job.tcp_fd = cfd;
    job.tcp_connected = true;
    try std.testing.expectError(error.PeerClosed, r.tcpWrite(job));
    job.tcp_fd = -1;
    posix.close(cfd);
}

test "dns-async: a repeat resolve is served by the RR cache without wire" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.soa_nodata.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));

    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);

    // Every chain step of the identical resolve now consults the RR
    // cache: no SRV, A or TLSA query may touch the wire again.
    const wired = srv.udp_recvd.load(.monotonic);
    var ctx2 = TestCtx{};
    r.setCallback(.{ .ctx = &ctx2, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 4, true);
    spins = 0;
    while (ctx2.status == null and spins < 50) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.resolved, ctx2.status.?);
    var res2 = ctx2.res.?;
    defer res2.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(wired, srv.udp_recvd.load(.monotonic));
}

test "dns-async: a SERVFAIL on one SRV target skips only that target" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_many = 3;
    srv.a_servfail_idx.store(0, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, false);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    // Wherever the weighted draw placed t0, its refusal dooms only
    // itself: the two healthy targets still resolve.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), res.targets.len);
    var saw_t1 = false;
    var saw_t2 = false;
    for (res.targets) |t| {
        if (std.mem.eql(u8, t.host, "t1.test")) saw_t1 = true;
        if (std.mem.eql(u8, t.host, "t2.test")) saw_t2 = true;
        try std.testing.expect(!std.mem.eql(u8, t.host, "t0.test"));
    }
    try std.testing.expect(saw_t1 and saw_t2);
}

test "dns-async: every address family failing is a temporary failure, not nxdomain" {
    // Goal: when every address query for every SRV target hard-fails
    // the resolve reports .failed (a temporary failure the s2s retry
    // may re-attempt), never .nxdomain, which is reserved for
    // authoritative absences and treated as permanent.
    // Method: FakeDns answers SERVFAIL for both address families.
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.a_fail.store(true, .monotonic);
    srv.aaaa_fail.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 1, false);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.failed, ctx.status.?);
    try std.testing.expectEqual(@as(usize, 1), ctx.calls);
}

test "dns-async: an AAAA SERVFAIL keeps the resolved A address" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_many = 1;
    srv.aaaa_fail.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, false);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    // The A half resolved before the AAAA refusal: the target survives
    // with its IPv4 address instead of being skipped wholesale.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(@as(u16, posix.AF.INET), res.targets[0].addr.any.family);
    try std.testing.expectEqual(@as(u16, 15222), res.targets[0].addr.getPort());
}

test "dns-async: an A SERVFAIL still yields the AAAA address" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_many = 1;
    srv.a_fail.store(true, .monotonic);
    srv.a_aaaa.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, false);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    // The failing family goes first here: the A refusal must still
    // let the AAAA query run and produce the only target.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(@as(u16, posix.AF.INET6), res.targets[0].addr.any.family);
}

test "dns-async: an AAAA NXDOMAIN keeps the resolved A address" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_many = 1;
    srv.aaaa_nxdomain.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, false);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    // The A half resolved before the AAAA NXDOMAIN: the target
    // survives with its IPv4 address instead of being skipped.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(@as(u16, posix.AF.INET), res.targets[0].addr.any.family);
    try std.testing.expectEqual(@as(u16, 15222), res.targets[0].addr.getPort());
}

test "dns-async: an A NXDOMAIN still yields the AAAA address" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_many = 1;
    srv.a_nxdomain.store(true, .monotonic);
    srv.a_aaaa.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, false);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    // The absent family goes first here: the A NXDOMAIN must still
    // let the AAAA query run and produce the only target.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(@as(u16, posix.AF.INET6), res.targets[0].addr.any.family);
}

test "dns-async: a failed AAAA still runs the TLSA query when wanted" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_many = 1;
    srv.aaaa_fail.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    // The AAAA refusal is a failure of that family, not of the target:
    // the resolved A address still gets its TLSA lookup.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(@as(u16, posix.AF.INET), res.targets[0].addr.any.family);
    try std.testing.expect(res.targets[0].tlsa.len >= 1);
}

test "dns-async: parsed SRV entries are capped at 32" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_many = 40;
    srv.a_silent.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    r.chain_deadline_ms = 30_000;
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, false);
    defer r.cancel(3);
    var spins: usize = 0;
    while (r.jobs.items.len > 0 and r.jobs.items[0].srv_list.items.len == 0 and spins < 400) : (spins += 1) r.step(50);

    try std.testing.expect(r.jobs.items.len > 0);
    try std.testing.expectEqual(@as(usize, SRV_CAP), r.jobs.items[0].srv_list.items.len);
}

test "dns-async: the fallback path asks AAAA too and emits v6 first" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.empty_srv.store(true, .monotonic);
    srv.a_aaaa.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("dual.test", .client, 5222, 3, false);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), res.targets.len);
    try std.testing.expectEqual(@as(u16, posix.AF.INET6), res.targets[0].addr.any.family);
    try std.testing.expectEqual(@as(u16, posix.AF.INET), res.targets[1].addr.any.family);
    try std.testing.expectEqual(@as(u16, 5222), res.targets[0].addr.getPort());
}

test "dns-async: a stale deadline cannot hit a re-used slot" {
    const sink = try startUdpSink();
    defer posix.close(sink.fd);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", sink.port));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });

    // Queue an expired deadline for job A, free A, and let job B take
    // the same slot at a new generation.
    try r.query("a.test", .a, 7);
    const job_a = r.jobs.items[0];
    const slot_a = job_a.slot;
    armStaleTimer(&r, (@as(usize, job_a.gen) << 8) | slot_a);
    r.cancel(7);
    try r.query("b.test", .a, 8);
    const job_b = r.jobs.items[0];
    try std.testing.expectEqual(slot_a, job_b.slot);

    // Drain every queued event; the generation check must drop the
    // stale deadline instead of charging job B a retry (tries would
    // become 2).
    for (0..16) |_| r.step(0);
    try std.testing.expectEqual(@as(u8, 1), job_b.tries);
    try std.testing.expect(ctx.status == null);
}

test "dns-async: disarming a fired retry timer still removes the chain timer" {
    const sink = try startUdpSink();
    defer posix.close(sink.fd);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", sink.port));
    r.chain_deadline_ms = 50;

    try r.resolve("svc.test", .client, 5222, 7, false);
    const job = r.jobs.items[0];

    // Simulate the retry knote already delivered and gone: the first
    // delete of disarmDeadline reports ENOENT, and a raw changelist
    // would stop there, leaving the chain timer armed past freeJob.
    var del = [1]posix.Kevent{.{
        .ident = @intFromPtr(job),
        .filter = std.c.EVFILT.TIMER,
        .flags = std.c.EV.DELETE,
        .fflags = 0,
        .data = 0,
        .udata = 0,
    }};
    _ = try posix.kevent(r.kq, &del, &.{}, null);
    r.cancel(7);

    // Harvest the resolver kqueue directly: a surviving chain knote
    // fires ~50 ms out and shows up here even though the slot is dead.
    var evs: [8]posix.Kevent = undefined;
    const ts = std.c.timespec{ .sec = 0, .nsec = 300 * std.time.ns_per_ms };
    const n = try posix.kevent(r.kq, &.{}, &evs, &ts);
    for (evs[0..n]) |ev| {
        try std.testing.expect(ev.filter != std.c.EVFILT.TIMER);
    }
}

test "dns-async: a delete of a missing knote is fine, other receipts still error" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    try r.ensureOpen();

    // ENOENT on a delete receipt is success (the knote is already in
    // the state the delete asked for); keventApply still reports it.
    var del = [1]posix.Kevent{.{
        .ident = 0xDEAD,
        .filter = std.c.EVFILT.TIMER,
        .flags = std.c.EV.DELETE,
        .fflags = 0,
        .data = 0,
        .udata = 0,
    }};
    try r.keventDelete(&del);
    try std.testing.expectError(error.KeventChange, r.keventApply(&del));
}

test "dns-async: a failed registration change reports per entry" {
    const sink = try startUdpSink();
    defer posix.close(sink.fd);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", sink.port));

    try r.query("a.test", .a, 7);
    // Registration on a descriptor the kqueue cannot watch reports its
    // errno through the change's EV_ERROR receipt.
    var bad = [1]posix.Kevent{.{
        .ident = @intCast(std.math.maxInt(u31)),
        .filter = std.c.EVFILT.READ,
        .flags = std.c.EV.ADD | std.c.EV.ENABLE,
        .fflags = 0,
        .data = 0,
        .udata = 0,
    }};
    try std.testing.expectError(error.KeventChange, r.keventApply(&bad));

    // A failing entry must not stop later changes in the same batch:
    // the delete below still applies, so this already-fired timer is
    // disarmed instead of surfacing in a later harvest.
    var armed = [1]posix.Kevent{.{
        .ident = 0xBEEF,
        .filter = std.c.EVFILT.TIMER,
        .flags = std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT,
        .fflags = std.c.NOTE.ABSTIME,
        .data = 1,
        .udata = 0,
    }};
    _ = try posix.kevent(r.kq, &armed, &.{}, null);
    var mixed = [2]posix.Kevent{
        bad[0],
        .{ .ident = 0xBEEF, .filter = std.c.EVFILT.TIMER, .flags = std.c.EV.DELETE, .fflags = 0, .data = 0, .udata = 0 },
    };
    try std.testing.expectError(error.KeventChange, r.keventApply(&mixed));
    var evs: [8]posix.Kevent = undefined;
    const ts = std.c.timespec{ .sec = 0, .nsec = 300 * std.time.ns_per_ms };
    const n = try posix.kevent(r.kq, &.{}, &evs, &ts);
    for (evs[0..n]) |ev| {
        try std.testing.expect(ev.ident != 0xBEEF);
    }
}

test "dns-async: applying changes never drains the events a parent watches" {
    const sink = try startUdpSink();
    defer posix.close(sink.fd);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", sink.port));

    try r.query("a.test", .a, 7);

    // A one-shot WRITE on the resolver's socket is queued at once.
    var wr = [1]posix.Kevent{.{
        .ident = @intCast(r.fd),
        .filter = std.c.EVFILT.WRITE,
        .flags = std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT,
        .fflags = 0,
        .data = 0,
        .udata = 0,
    }};
    _ = try posix.kevent(r.kq, &wr, &.{}, null);

    // A parent kqueue watches the child the way the engine does.
    const pkq = try posix.kqueue();
    defer posix.close(pkq);
    var watch = [1]posix.Kevent{.{
        .ident = @intCast(r.kq),
        .filter = std.c.EVFILT.READ,
        .flags = std.c.EV.ADD | std.c.EV.ENABLE,
        .fflags = 0,
        .data = 0,
        .udata = 0,
    }};
    _ = try posix.kevent(pkq, &watch, &.{}, null);
    const zero = std.c.timespec{ .sec = 0, .nsec = 0 };
    var evs: [4]posix.Kevent = undefined;
    try std.testing.expect(try posix.kevent(pkq, &.{}, &evs, &zero) >= 1);

    // A registration round must not harvest the queued event: drained
    // into userspace here, it would leave the parent blind to it until
    // something else woke step(). One-shot events never re-post.
    var ch = [1]posix.Kevent{.{
        .ident = 0xBEEF,
        .filter = std.c.EVFILT.TIMER,
        .flags = std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT,
        .fflags = std.c.NOTE.ABSTIME,
        .data = 60_000_000,
        .udata = 0,
    }};
    try r.keventApply(&ch);

    const got = try posix.kevent(pkq, &.{}, &evs, &zero);
    try std.testing.expect(got >= 1);
}

test "dns-async: a failed socket registration leaves no dangling fd" {
    // Goal: when the UDP socket's knote registration fails, self.fd
    // must not keep the closed descriptor: a stale number would send
    // on whatever reuses it and deinit would close that stranger's
    // socket (or panic on EBADF).
    // Method: fail the registration through the seam, then check the
    // resolver stays closed and deinit leaves a reused fd alive.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 53));
    r.fail_kevents = true;

    try std.testing.expectError(error.KeventChange, r.ensureOpen());
    try std.testing.expectEqual(@as(posix.fd_t, -1), r.fd);

    // An unrelated socket may now hold the abandoned number; deinit
    // must not close it.
    const ufd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    var actual: posix.sockaddr = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr);
    r.deinit();
    // deinit frees but does not reset the struct; a fresh resolver
    // keeps the deferred deinit off dangling lists.
    r = Resolver.init(std.testing.allocator);
    try posix.getsockname(ufd, &actual, &slen);
    posix.close(ufd);

    // A retry with the seam cleared opens cleanly.
    r.setServer(try net.Address.parseIp("127.0.0.1", 53));
    try r.ensureOpen();
    try std.testing.expect(r.fd >= 0);
}

var fake_now: i64 = 0;
fn fakeNow() i64 {
    return fake_now;
}

test "dns-async: a cache entry past its TTL is stale, then gone" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;

    const owned_name = try std.testing.allocator.dupe(u8, "ttl.test");
    defer std.testing.allocator.free(owned_name);
    const owned_rdata = try std.testing.allocator.dupe(u8, &.{ 10, 1, 1, 1 });
    defer std.testing.allocator.free(owned_rdata);
    var rrs = [1]wire.Rr{.{ .name = owned_name, .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = owned_rdata }};
    r.cachePut("ttl.test", KIND_A, &rrs);
    try std.testing.expect(r.cacheGet("ttl.test", KIND_A) != null);
    fake_now += 59_000;
    try std.testing.expect(r.cacheGet("ttl.test", KIND_A) != null);
    fake_now += 2_000;
    // Past expiry the row is no longer fresh but stays servable
    // through the RFC 8767 stale window.
    try std.testing.expect(r.cacheGet("ttl.test", KIND_A) == null);
    switch (r.cacheGetClass("ttl.test", KIND_A).?) {
        .stale => {},
        .fresh => return error.TestUnexpectedResult,
    }
    // The stale window closes at expiry + 1 day: past it the dead
    // row is pruned with its owner.
    fake_now += STALE_MAX_MS;
    try std.testing.expect(r.cacheGetClass("ttl.test", KIND_A) == null);
    try std.testing.expectEqual(@as(usize, 0), r.owners.count());
}

/// Seed a positive A row already inside the serve-stale window:
/// ttl seconds fresh, then the clock is advanced past expiry.
fn seedStaleA(r: *Resolver, name: []const u8, rdata: []const u8) void {
    var rrs = [1]wire.Rr{.{ .name = name, .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = rdata }};
    r.cacheInsert(name, KIND_A, &rrs, .none, 60);
    fake_now += 61_000;
}

test "dns-async: a stale answer serves when its refresh hits SERVFAIL" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleA(&r, "stale.test", &.{ 10, 1, 1, 1 });
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 7);
    // The stale hit starts a wire refresh instead of answering.
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..buildRcode(&buf, job.request, 2)]);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.rrs.len);
    try std.testing.expectEqualSlices(u8, &.{ 10, 1, 1, 1 }, res.rrs[0].rdata);
    try std.testing.expectEqual(@as(usize, 1), r.stale_serves);
    // The served row keeps its stale bookkeeping: a recached serve
    // would read fresh again and never refresh.
    switch (r.cacheGetClass("stale.test", KIND_A).?) {
        .stale => {},
        .fresh => return error.TestUnexpectedResult,
    }
}

test "dns-async: a wire answer replaces the stale row it refreshed" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleA(&r, "stale.test", &.{ 10, 1, 1, 1 });
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 7);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..answerTcpQuery(&buf, job.request)]);
    // The waiter gets the fresh wire answer, not the stale row.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, res.rrs[0].rdata);
    try std.testing.expectEqual(@as(usize, 0), r.stale_serves);
    try std.testing.expect(r.cacheGet("stale.test", KIND_A) != null);
}

test "dns-async: a NXDOMAIN refresh answer answers nxdomain and unpins the row" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleA(&r, "stale.test", &.{ 10, 1, 1, 1 });
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 7);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..buildRcode(&buf, job.request, 3)]);
    try std.testing.expectEqual(Status.nxdomain, ctx.status.?);
    // The answer carried no SOA, so the stale row was dropped instead
    // of replaced; either way the next lookup goes back to the wire.
    var ctx2 = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx2, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 8);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
}

test "dns-async: a failed refresh is suppressed for the recheck window" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleA(&r, "stale.test", &.{ 10, 1, 1, 1 });
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 7);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..buildRcode(&buf, job.request, 2)]);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    // Inside 30 s of the failed refresh the same lookup serves the
    // stale row at once and never reaches for a job slot.
    fake_now += 5_000;
    var ctx2 = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx2, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 8);
    try std.testing.expectEqual(Status.resolved, ctx2.status.?);
    try std.testing.expectEqual(@as(usize, 0), r.jobs.items.len);
    var res2 = ctx2.raw.?;
    defer res2.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), r.stale_serves);
}

test "dns-async: a refresh past the deadline serves stale and keeps resolving" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleA(&r, "stale.test", &.{ 10, 1, 1, 1 });
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 7);
    const job = r.jobs.items[0];
    // The per-query deadline fires mid-refresh: waiters get the
    // stale answer while the wire query keeps running.
    r.onDeadline(job);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &.{ 10, 1, 1, 1 }, res.rrs[0].rdata);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    try std.testing.expect(r.jobs.items[0].refresh_only);
    // The late wire answer still refreshes the row and frees the job.
    var buf: [512]u8 = undefined;
    r.handleResponse(r.jobs.items[0], buf[0..answerTcpQuery(&buf, job.request)]);
    try std.testing.expectEqual(@as(usize, 0), r.jobs.items.len);
    try std.testing.expect(r.cacheGet("stale.test", KIND_A) != null);
}

test "dns-async: a stale negative answer serves on refresh failure" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    r.cacheInsert("neg.test", KIND_A, &.{}, .nxdomain, 60);
    fake_now += 61_000;
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("neg.test", .a, 7);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..buildRcode(&buf, job.request, 2)]);
    try std.testing.expectEqual(Status.nxdomain, ctx.status.?);
    try std.testing.expectEqual(@as(usize, 1), r.stale_serves);
}

test "dns-async: a stale TLSA answer serves like an address row" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    var rrs = [1]wire.Rr{.{ .name = "_5222._tcp.svc.test", .rtype = KIND_TLSA, .class = wire.CLASS_IN, .ttl = 60, .rdata = &.{ 3, 0, 1, 0xaa } }};
    r.cacheInsert("_5222._tcp.svc.test", KIND_TLSA, &rrs, .none, 60);
    fake_now += 61_000;
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("_5222._tcp.svc.test", .tlsa, 7);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..buildRcode(&buf, job.request, 2)]);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &.{ 3, 0, 1, 0xaa }, res.rrs[0].rdata);
}

test "dns-async: a lookup during a refresh serves stale without a second job" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleA(&r, "stale.test", &.{ 10, 1, 1, 1 });
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 7);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    // The first refresh is in flight: the same lookup serves the
    // stale row at once rather than starting a second wire query.
    var ctx2 = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx2, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 8);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    try std.testing.expectEqual(Status.resolved, ctx2.status.?);
    var res2 = ctx2.raw.?;
    defer res2.deinitOn(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &.{ 10, 1, 1, 1 }, res2.rrs[0].rdata);
    try std.testing.expectEqual(@as(usize, 1), r.stale_serves);
}

test "dns-async: cancel does not free a refresh-only job" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleA(&r, "stale.test", &.{ 10, 1, 1, 1 });
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 7);
    const job = r.jobs.items[0];
    r.onDeadline(job);
    try std.testing.expect(r.jobs.items[0].refresh_only);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    // The answered waiter and unrelated keys alike leave the
    // waiterless refresh job alone.
    r.cancel(7);
    r.cancel(99);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
}

test "dns-async: a NODATA refresh answer clears the row's refresh pin" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleA(&r, "stale.test", &.{ 10, 1, 1, 1 });
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 7);
    const job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    // NODATA without an SOA leaves the stale row in place, but the
    // refresh is over: the pin must drop or every later lookup is
    // served stale forever.
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var ctx2 = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx2, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 8);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
}

test "dns-async: an in-place replace keeps the borrowed row's refresh pin" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    // Job A misses on the name and is still on the wire when another
    // answer lands: a short-TTL row that goes stale, then job B's
    // lookup starts a refresh and borrows the row.
    try r.query("dup.test", .a, 1);
    const ja = r.jobs.items[0];
    var rrs = [1]wire.Rr{.{ .name = "dup.test", .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 1, .rdata = &.{ 10, 1, 1, 1 } }};
    r.cacheInsert("dup.test", KIND_A, &rrs, .none, 1);
    fake_now += 2_000;
    try r.query("dup.test", .a, 2);
    const jb = r.jobs.items[1];
    try std.testing.expect(jb.stale != null);
    // A's late answer replaces the row in place; the pin must
    // survive, or a CNAME answer or eviction frees the row while
    // B still borrows it.
    var buf: [512]u8 = undefined;
    r.handleResponse(ja, buf[0..answerTcpQuery(&buf, ja.request)]);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expect(jb.stale.?.ent.refreshing);
    const cn = [1]wire.Rr{.{ .name = "dup.test", .rtype = wire.TYPE_CNAME, .class = wire.CLASS_IN, .ttl = 60, .rdata = &.{ 3, 'w', 'w', 'w', 0 } }};
    r.cacheInsert("dup.test", KIND_SRV, &cn, .none, 60);
    const o = r.owners.get("dup.test").?;
    try std.testing.expect(Resolver.findTypeRow(o, KIND_A) != null);
    // B's refresh fails: the borrowed row still serves it.
    r.handleResponse(jb, buf[0..buildRcode(&buf, jb.request, 2)]);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res2 = ctx.raw.?;
    defer res2.deinitOn(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, res2.rrs[0].rdata);
}

/// Seed the svc.test chain's per-target TLSA row inside the
/// serve-stale window: .none seeds the record set, the negative
/// flavors seed NODATA/NXDOMAIN rows.
fn seedStaleTlsa(r: *Resolver, neg: NegKind) void {
    var t_rrs = [1]wire.Rr{.{ .name = "_15222._tcp.srv.test", .rtype = KIND_TLSA, .class = wire.CLASS_IN, .ttl = 60, .rdata = &.{ 3, 0, 1, 0xDE, 0xAD } }};
    if (neg == .none) {
        r.cacheInsert("_15222._tcp.srv.test", KIND_TLSA, &t_rrs, .none, 60);
    } else {
        r.cacheInsert("_15222._tcp.srv.test", KIND_TLSA, &.{}, neg, 60);
    }
    fake_now += 61_000;
}

test "dns-async: a TTL-0 answer drops the stale row it refreshed" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleA(&r, "stale.test", &.{ 10, 1, 1, 1 });
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 7);
    var job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    // The live answer carries TTL 0: served to the waiter but never
    // cached, and it still replaces the stale row (ADR-13).
    r.handleResponse(job, buf[0..buildTypedAnswer(&buf, job.request, KIND_A, 0, &.{ 127, 0, 0, 2 })]);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 2 }, res.rrs[0].rdata);
    try std.testing.expect(r.cacheGetClass("stale.test", KIND_A) == null);
    // A later SERVFAIL now fails the lookup; the dropped row is not
    // there to be served stale.
    fake_now += 1_000;
    var ctx2 = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx2, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 8);
    job = r.jobs.items[0];
    r.handleResponse(job, buf[0..buildRcode(&buf, job.request, 2)]);
    try std.testing.expectEqual(Status.failed, ctx2.status.?);
}

test "dns-async: a NODATA refresh without SOA drops the stale row" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleA(&r, "stale.test", &.{ 10, 1, 1, 1 });
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 7);
    var job = r.jobs.items[0];
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..buildNodata(&buf, job.request)]);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expect(r.cacheGetClass("stale.test", KIND_A) == null);
    fake_now += 1_000;
    var ctx2 = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx2, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 8);
    job = r.jobs.items[0];
    r.handleResponse(job, buf[0..buildRcode(&buf, job.request, 2)]);
    try std.testing.expectEqual(Status.failed, ctx2.status.?);
}

const StaleLegAnswer = enum { tlsa_ttl0, nodata };

/// Drive the seeded svc.test chain through one stale-TLSA refresh:
/// feed `first` to the first resolve's TLSA leg and SERVFAIL to the
/// second resolve's. Returns the two targets' tlsa_status values.
fn runStaleTlsaLegs(r: *Resolver, neg: NegKind, first: StaleLegAnswer) ![2]TlsaStatus {
    seedStaleTlsa(r, neg);
    seedSvcChain(r, false);
    var out: [2]TlsaStatus = undefined;
    var buf: [512]u8 = undefined;
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 3, true);
    var job = r.jobs.items[0];
    if (job.pending_qtype != KIND_TLSA) return error.TestUnexpectedResult;
    const n = switch (first) {
        .tlsa_ttl0 => buildTypedAnswer(&buf, job.request, KIND_TLSA, 0, &.{ 3, 1, 1, 0xBE, 0xEF }),
        .nodata => buildNodata(&buf, job.request),
    };
    r.handleResponse(job, buf[0..n]);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    {
        var res = ctx.res.?;
        defer res.deinitOn(std.testing.allocator);
        out[0] = res.targets[0].tlsa_status;
    }
    fake_now += 1_000;
    var ctx2 = TestCtx{};
    r.setCallback(.{ .ctx = &ctx2, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 4, true);
    job = r.jobs.items[0];
    if (job.pending_qtype != KIND_TLSA) return error.TestUnexpectedResult;
    r.handleResponse(job, buf[0..buildRcode(&buf, job.request, 2)]);
    try std.testing.expectEqual(Status.resolved, ctx2.status.?);
    var res2 = ctx2.res.?;
    defer res2.deinitOn(std.testing.allocator);
    out[1] = res2.targets[0].tlsa_status;
    return out;
}

test "dns-async: uncacheable TLSA refresh answers drop the stale row (D3, D4, D5)" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));

    // D3: stale NODATA, live TLSA with TTL 0 -> present, then SERVFAIL
    // -> lookup_failed (the dropped row cannot serve "absent").
    var got = try runStaleTlsaLegs(&r, .nodata, .tlsa_ttl0);
    try std.testing.expectEqual(TlsaStatus.present, got[0]);
    try std.testing.expectEqual(TlsaStatus.lookup_failed, got[1]);

    // D5: stale NXDOMAIN behind the same TTL-0 live answer.
    got = try runStaleTlsaLegs(&r, .nxdomain, .tlsa_ttl0);
    try std.testing.expectEqual(TlsaStatus.present, got[0]);
    try std.testing.expectEqual(TlsaStatus.lookup_failed, got[1]);

    // D4: stale records, a NODATA answer with no SOA -> absent, then
    // SERVFAIL -> lookup_failed instead of the stale records.
    got = try runStaleTlsaLegs(&r, .none, .nodata);
    try std.testing.expectEqual(TlsaStatus.absent, got[0]);
    try std.testing.expectEqual(TlsaStatus.lookup_failed, got[1]);
}

test "dns-async: refresh-only jobs yield a slot to a client lookup" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var name_buf: [32]u8 = undefined;
    var rrs = [1]wire.Rr{.{ .name = "x", .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = &.{ 10, 1, 1, 1 } }};
    for (0..MAX_JOBS + 1) |i| {
        const n = std.fmt.bufPrint(&name_buf, "s{d}.test", .{i}) catch unreachable;
        r.cacheInsert(n, KIND_A, &rrs, .none, 60);
    }
    fake_now += 61_000;
    seedSvcChain(&r, false);
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    // Every lookup on a stale row starts a refresh; each per-query
    // deadline leaves a waiterless refresh-only job until all slots
    // are refreshes.
    for (0..MAX_JOBS) |i| {
        const n = std.fmt.bufPrint(&name_buf, "s{d}.test", .{i}) catch unreachable;
        try r.query(n, .a, 100 + i);
    }
    for (r.jobs.items) |j| {
        r.onDeadline(j);
        var res = ctx.raw.?;
        res.deinitOn(std.testing.allocator);
        ctx.raw = null;
        ctx.status = null;
    }
    try std.testing.expectEqual(@as(usize, MAX_JOBS), r.jobs.items.len);
    // A fully cached resolve answers synchronously: a refresh job
    // yields its slot, the cache answers, and the slot frees again.
    var rctx = TestCtx{};
    r.setCallback(.{ .ctx = &rctx, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 900, false);
    try std.testing.expect(rctx.status != null);
    var res = rctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), r.wait_queue.items.len);
    // A lookup on a stale, not-yet-refreshed row takes a reclaimed
    // slot on the wire instead of queueing behind refreshes.
    const n65 = std.fmt.bufPrint(&name_buf, "s{d}.test", .{MAX_JOBS}) catch unreachable;
    try r.query(n65, .a, 901);
    try std.testing.expectEqual(@as(usize, 0), r.wait_queue.items.len);
    try std.testing.expectEqual(@as(usize, MAX_JOBS), r.jobs.items.len);
}

test "dns-async: a queued lookup is answered as refresh jobs convert" {
    // Goal: a lookup queued behind a full table does not wait for the
    // refresh-only jobs ahead of it to die: the deadline conversion
    // hands a slot to the queue. Method: fill the table with raw
    // stale refreshes, queue a fully cached resolve, fire every
    // per-query deadline.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    var nb: [32]u8 = undefined;
    var rrs = [1]wire.Rr{.{ .name = "x", .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = &.{ 10, 1, 1, 1 } }};
    for (0..MAX_JOBS) |i| {
        const n = std.fmt.bufPrint(&nb, "s{d}.test", .{i}) catch unreachable;
        r.cacheInsert(n, KIND_A, &rrs, .none, 60);
    }
    fake_now += 61_000;
    seedSvcChain(&r, false);
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });
    var qctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &qctx, .fun = TestCtx.onQuery });
    for (0..MAX_JOBS) |i| {
        const n = std.fmt.bufPrint(&nb, "s{d}.test", .{i}) catch unreachable;
        try r.query(n, .a, 100 + i);
    }
    try r.resolve("svc.test", .client, 5222, 900, false);
    try std.testing.expectEqual(@as(usize, 1), r.wait_queue.items.len);
    while (true) {
        var target: ?*Job = null;
        for (r.jobs.items) |j| {
            if (!j.refresh_only) {
                target = j;
                break;
            }
        }
        const t = target orelse break;
        r.onDeadline(t);
        if (qctx.raw) |res| {
            var x = res;
            x.deinitOn(std.testing.allocator);
            qctx.raw = null;
        }
    }
    // The first converted job gave the queued resolve its slot; the
    // chain completed on the cache synchronously.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), r.wait_queue.items.len);
}

const CbLookupCtx = struct {
    r: *Resolver,
    armed: bool = false,
    err1: ?anyerror = null,
    err2: ?anyerror = null,
    status: ?Status = null,
    res: ?Resolution = null,

    fn onResolve(ctx_ptr: ?*anyopaque, _: usize, status: Status, res: ?Resolution) void {
        const self: *CbLookupCtx = @ptrCast(@alignCast(ctx_ptr.?));
        self.status = status;
        self.res = res;
        if (self.armed) {
            self.r.query("cbx1.test", .a, 7001) catch |e| {
                self.err1 = e;
            };
            self.r.query("cbx2.test", .a, 7002) catch |e| {
                self.err2 = e;
            };
        }
    }
};

test "dns-async: a lookup inside a completion callback reclaims a refresh-only slot" {
    // Goal: a completing job still holds its slot while its
    // callbacks run, so capacity is measured on the slot table, not
    // `jobs`; a refresh-only job then yields as usual. Method: one
    // spawned refresh job plus cache misses fill the slots; the
    // completing resolve's callback issues two raw queries.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleTlsa(&r, .none);
    seedSvcChain(&r, false);
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = CbLookupCtx{ .r = &r };
    r.setCallback(.{ .ctx = &ctx, .fun = CbLookupCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 3, true);
    r.onDeadline(r.jobs.items[0]); // chain serves stale; spawns a refresh-only job
    {
        var res0 = ctx.res.?;
        res0.deinitOn(std.testing.allocator);
        ctx.res = null;
        ctx.status = null;
    }
    var spawned: usize = 0;
    for (r.jobs.items) |j| {
        if (j.refresh_only) spawned += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), spawned);
    var nb: [32]u8 = undefined;
    for (0..MAX_JOBS - 2) |i| {
        const n = std.fmt.bufPrint(&nb, "miss{d}.test", .{i}) catch unreachable;
        try r.query(n, .a, 5000 + i);
    }
    // The completing resolve takes the last slot; inside its
    // callback the table reads 63 jobs but all 64 slots are held.
    ctx.armed = true;
    try r.resolve("svc.test", .client, 5222, 4, true);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    // Neither query failed: the first reclaimed the refresh-only
    // slot, the second queued and launched once the resolve's slot
    // freed.
    try std.testing.expect(ctx.err1 == null);
    try std.testing.expect(ctx.err2 == null);
    try std.testing.expectEqual(@as(usize, 0), r.wait_queue.items.len);
    try std.testing.expectEqual(@as(usize, MAX_JOBS), r.jobs.items.len);
}

test "dns-async: a chain deadline serves the stale row it refreshed" {
    // Goal: a per-query deadline on a chain leg refreshing a stale
    // row feeds the row's answer to the phase machine (RFC 8767);
    // the chain resolves from it. Method: stale TLSA behind the
    // svc.test chain; fire onDeadline on the TLSA leg.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleTlsa(&r, .none);
    seedSvcChain(&r, false);
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 3, true);
    const job = r.jobs.items[0];
    if (job.pending_qtype != KIND_TLSA or job.stale == null) return error.TestUnexpectedResult;
    r.onDeadline(job);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(TlsaStatus.present, res.targets[0].tlsa_status);
    try std.testing.expectEqual(@as(usize, 1), r.stale_serves);
}

test "dns-async: a chain deadline serve keeps the refresh running off the chain" {
    // Goal: the deadline stale serve detaches the renewal into a
    // waiterless refresh-only job instead of abandoning it (finding
    // 8, ADR-13). Method: as above, then answer the spawned job's
    // wire query and check the row went fresh.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleTlsa(&r, .none);
    seedSvcChain(&r, false);
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 3, true);
    const job = r.jobs.items[0];
    if (job.pending_qtype != KIND_TLSA or job.stale == null) return error.TestUnexpectedResult;
    r.onDeadline(job);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(TlsaStatus.present, res.targets[0].tlsa_status);
    // The chain completed; the detached refresh job re-asks the same
    // question on the wire.
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    const refresh = r.jobs.items[0];
    try std.testing.expect(refresh.is_raw);
    try std.testing.expect(refresh.refresh_only);
    try std.testing.expectEqual(@as(usize, 0), refresh.waiter_count);
    try std.testing.expectEqualStrings("_15222._tcp.srv.test", refresh.pending_qname);
    var buf: [512]u8 = undefined;
    r.handleResponse(refresh, buf[0..buildTypedAnswer(&buf, refresh.request, KIND_TLSA, 60, &.{ 3, 1, 1, 0xBE, 0xEF })]);
    try std.testing.expectEqual(@as(usize, 0), r.jobs.items.len);
    try std.testing.expect(r.cacheGet("_15222._tcp.srv.test", KIND_TLSA) != null);
}

test "dns-async: a chain failure serves the stale row it refreshed" {
    // Goal: failQuery on a chain leg refreshing a stale row feeds
    // the row's answer to the phase machine instead of the per-phase
    // failure. Method: SERVFAIL the TLSA leg; the target's TLSA
    // records come back from the stale row.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleTlsa(&r, .none);
    seedSvcChain(&r, false);
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 3, true);
    const job = r.jobs.items[0];
    if (job.pending_qtype != KIND_TLSA or job.stale == null) return error.TestUnexpectedResult;
    var buf: [512]u8 = undefined;
    r.handleResponse(job, buf[0..buildRcode(&buf, job.request, 2)]);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(TlsaStatus.present, res.targets[0].tlsa_status);
    try std.testing.expectEqual(@as(usize, 1), r.stale_serves);
}

test "dns-async: a suppressed chain refresh serves the stale row" {
    // Goal: the sendQuery stale consult serves the row at once when
    // a refresh already ran or was attempted inside the recheck
    // window, chain leg or not; no wire query goes out. Method:
    // stamp last_fail_ms on the stale TLSA row, resolve, expect a
    // synchronous answer.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleTlsa(&r, .none);
    const owner = r.owners.get("_15222._tcp.srv.test").?;
    owner.types.items[0].last_fail_ms = fake_now;
    seedSvcChain(&r, false);
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });
    try r.resolve("svc.test", .client, 5222, 3, true);
    // The consult served stale inside resolve(): no job survives.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(TlsaStatus.present, res.targets[0].tlsa_status);
    try std.testing.expectEqual(@as(usize, 0), r.jobs.items.len);
    try std.testing.expectEqual(@as(usize, 1), r.stale_serves);
}

test "dns-async: a stale row refreshes and logs inside the boot window" {
    // Goal: uptime below STALE_RECHECK_MS/STALE_LOG_MS must not read
    // as "recently failed / recently logged": the stamps start at
    // minInt and the compares saturate. Method: pin the clock at
    // 2 s of uptime, hit a stale row, expect a refresh job and a
    // stamped owner log.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000;
    var rrs = [1]wire.Rr{.{ .name = "stale.test", .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 1, .rdata = &.{ 10, 1, 1, 1 } }};
    r.cacheInsert("stale.test", KIND_A, &rrs, .none, 1);
    fake_now = 2_000;
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 7);
    // A zero last_fail_ms would read as a failure 2 s ago and
    // suppress the refresh: the row must go to the wire.
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    // The in-flight refresh suppresses the second lookup: it serves
    // stale and still stamps the owner log below STALE_LOG_MS.
    var ctx2 = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx2, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 8);
    try std.testing.expectEqual(Status.resolved, ctx2.status.?);
    var res = ctx2.raw.?;
    defer res.deinitOn(std.testing.allocator);
    const owner = r.owners.get("stale.test").?;
    try std.testing.expectEqual(fake_now, owner.stale_log_ms);
}

test "dns-async: a cancelled refresh does not suppress the next one" {
    // Goal: cancel is not a wire failure; it must not stamp
    // last_fail_ms, or the next lookup serves stale inside the
    // recheck window instead of refreshing. Method: cancel the
    // refresh, query again, expect a new job on the wire.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleA(&r, "stale.test", &.{ 10, 1, 1, 1 });
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 7);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    r.cancel(7);
    try std.testing.expectEqual(@as(usize, 0), r.jobs.items.len);
    var ctx2 = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx2, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 8);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    try std.testing.expect(ctx2.status == null);
}

test "dns-async: a malformed refresh answer serves the stale row" {
    // Goal: an unparsable wire answer on a refresh fails the
    // refresh, so the stale row it tried to renew answers the
    // waiters (RFC 8767). Method: feed a short garbage packet to the
    // refresh job.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleA(&r, "stale.test", &.{ 10, 1, 1, 1 });
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("stale.test", .a, 7);
    const job = r.jobs.items[0];
    var junk = [4]u8{ 0xde, 0xad, 0xbe, 0xef };
    r.handleResponse(job, &junk);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &.{ 10, 1, 1, 1 }, res.rrs[0].rdata);
    try std.testing.expectEqual(@as(usize, 1), r.stale_serves);
}

test "dns-async: eviction skips a pinned owner at the tail" {
    // Goal: a refreshing row pins its owner against eviction; the
    // walk passes it and sheds the next unpinned owner. Method: pin
    // the LRU tail, evictOne by hand.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 5_000_000;

    const owned_name = try std.testing.allocator.dupe(u8, "x.test");
    defer std.testing.allocator.free(owned_name);
    const owned_rdata = try std.testing.allocator.dupe(u8, &.{ 10, 1, 1, 1 });
    defer std.testing.allocator.free(owned_rdata);
    var rrs = [1]wire.Rr{.{ .name = owned_name, .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = owned_rdata }};

    // LRU head->tail: a.test, b.test, pin.test.
    r.cachePut("pin.test", KIND_A, &rrs);
    r.cachePut("b.test", KIND_A, &rrs);
    r.cachePut("a.test", KIND_A, &rrs);
    const owner = r.owners.get("pin.test").?;
    owner.types.items[0].refreshing = true;

    // The pinned tail is skipped: b.test sheds first, then a.test,
    // and a cache holding only pinned owners has nothing to evict.
    try std.testing.expect(r.evictOne(r.now_ms()));
    try std.testing.expect(r.owners.get("pin.test") != null);
    try std.testing.expect(r.owners.get("b.test") == null);
    try std.testing.expect(r.owners.get("a.test") != null);
    try std.testing.expect(r.evictOne(r.now_ms()));
    try std.testing.expect(r.owners.get("pin.test") != null);
    try std.testing.expect(r.owners.get("a.test") == null);
    try std.testing.expect(!r.evictOne(r.now_ms()));
}

test "dns-async: a dead row past the stale window stays while a refresh pins it" {
    // Goal: the on-hit prune past stale_ms skips a pinned row; the
    // job refreshing it still borrows the records. Method: seed a
    // stale row, age it past the serve-stale window, pin it, consult.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleA(&r, "stale.test", &.{ 10, 1, 1, 1 });
    fake_now += STALE_MAX_MS;
    const owner = r.owners.get("stale.test").?;
    owner.types.items[0].refreshing = true;
    // Past even the serve-stale window the consult misses, but the
    // pinned row and its owner are left for the refreshing job.
    try std.testing.expect(r.cacheGetClass("stale.test", KIND_A) == null);
    try std.testing.expect(r.owners.get("stale.test") != null);
}

test "dns-async: an aborted refresh drops the row's pin" {
    // Goal: a job that dies mid-refresh clears ent.refreshing so the
    // row is not pinned forever. Method: fail the send of a refresh
    // query on a stale row; the abort path frees the job.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 1_000_000;
    seedStaleA(&r, "stale.test", &.{ 10, 1, 1, 1 });
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    r.fail_sends = true;
    try std.testing.expectError(error.SendFailed, r.query("stale.test", .a, 7));
    try std.testing.expectEqual(@as(usize, 0), r.jobs.items.len);
    const owner = r.owners.get("stale.test").?;
    try std.testing.expect(!owner.types.items[0].refreshing);
}

test "dns-async: a CNAME answer keeps the pinned sibling row" {
    // Goal: the CNAME sibling eviction skips a pinned row; a refresh
    // may still borrow it. Method: pin x.test's SRV row, then cache
    // an answer carrying a CNAME record under a third type.
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.now_ms = fakeNow;
    fake_now = 9_000_000;

    const owned_name = try std.testing.allocator.dupe(u8, "x.test");
    defer std.testing.allocator.free(owned_name);
    const owned_rdata = try std.testing.allocator.dupe(u8, &.{ 10, 1, 1, 1 });
    defer std.testing.allocator.free(owned_rdata);
    const a_rr = [1]wire.Rr{.{ .name = owned_name, .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = owned_rdata }};
    const srv_rr = [1]wire.Rr{.{ .name = owned_name, .rtype = KIND_SRV, .class = wire.CLASS_IN, .ttl = 60, .rdata = owned_rdata }};
    r.cachePut("x.test", KIND_A, &a_rr);
    r.cachePut("x.test", KIND_SRV, &srv_rr);
    const owner = r.owners.get("x.test").?;
    owner.types.items[Resolver.findTypeRow(owner, KIND_SRV).?].refreshing = true;

    const cn = [1]wire.Rr{.{ .name = "x.test", .rtype = wire.TYPE_CNAME, .class = wire.CLASS_IN, .ttl = 60, .rdata = &.{ 3, 'w', 'w', 'w', 0 } }};
    r.cacheInsert("x.test", KIND_TLSA, &cn, .none, 60);
    // The unpinned A row is evicted as a sibling of the CNAME; the
    // pinned SRV row survives.
    try std.testing.expect(Resolver.findTypeRow(owner, KIND_A) == null);
    try std.testing.expect(Resolver.findTypeRow(owner, KIND_SRV) != null);
    try std.testing.expect(Resolver.findTypeRow(owner, KIND_TLSA) != null);
}

test "dns-async: SRV targets come back in RFC 2782 priority order" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_prio_mix.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, false);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    // Wire order is hi(30), lo(10), mid(20); the resolver must emit
    // lowest priority first regardless of the wire draw.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), res.targets.len);
    try std.testing.expectEqualStrings("t_lo.test", res.targets[0].host);
    try std.testing.expectEqualStrings("t_mid.test", res.targets[1].host);
    try std.testing.expectEqualStrings("t_hi.test", res.targets[2].host);
}

test "dns-async: a client resolve asks only the client SRV prefixes" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.client_srv_only.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, false);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    // Had the resolver asked the server prefixes, every SRV answer
    // would be NODATA and only the A fallback target would come back.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqualStrings("srv.test", res.targets[0].host);
}

test "dns-async: TCP sends the frame exactly once across connect" {
    // Test-owned listener; the query takes the TCP path directly so
    // nothing sleeps: connect completes on loopback without waiting.
    const lfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(lfd);
    const bind_addr = try net.Address.parseIp("127.0.0.1", 0);
    try posix.bind(lfd, &bind_addr.any, bind_addr.getOsSockLen());
    try posix.listen(lfd, 4);
    var actual: posix.sockaddr = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr);
    try posix.getsockname(lfd, &actual, &slen);
    const port = net.Address.initPosix(@alignCast(&actual)).getPort();

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", port));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });

    try r.query("host.test", .a, 7);
    const job = r.jobs.items[0];
    job.use_tcp = true;
    try r.tcpSend(job);

    var peer: posix.sockaddr = undefined;
    var plen: posix.socklen_t = @sizeOf(posix.sockaddr);
    const cfd = try posix.accept(lfd, &peer, &plen, 0);
    defer posix.close(cfd);

    // Drive the resolver so a pending connect finishes and the write
    // fires; then read exactly one frame.
    var spins: usize = 0;
    while (!job.tcp_connected and spins < 100) : (spins += 1) r.step(10);
    try std.testing.expect(job.tcp_connected);
    r.step(10);
    var fbuf: [300]u8 = undefined;
    const want = job.request.len + 2;
    var got: usize = 0;
    spins = 0;
    while (got < want and spins < 100_000) : (spins += 1) {
        got += posix.recv(cfd, fbuf[got..], posix.MSG.DONTWAIT) catch 0;
    }
    try std.testing.expectEqual(want, got);
    try std.testing.expectEqual(job.request.len, std.mem.readInt(u16, fbuf[0..2], .big));
    try std.testing.expectEqualSlices(u8, job.request, fbuf[2..got]);

    // A stale writable event must not produce a second copy.
    r.step(10);
    const extra = posix.recv(cfd, fbuf[0..1], posix.MSG.DONTWAIT) catch 0;
    try std.testing.expectEqual(@as(usize, 0), extra);
}

/// A TC-flagged echo of `qpkt` with no answers: forces the chain's
/// UDP->TCP upgrade in tests that drive the resolver directly.
fn buildTruncated(out: []u8, qpkt: []const u8) usize {
    const id = std.mem.readInt(u16, qpkt[0..2], .big);
    std.mem.writeInt(u16, out[0..2], id, .big);
    std.mem.writeInt(u16, out[2..4], 0x8180 | wire.FLAG_TC, .big);
    std.mem.writeInt(u16, out[4..6], 1, .big);
    @memset(out[6..12], 0);
    const qlen = qpkt.len - 12;
    @memcpy(out[12 .. 12 + qlen], qpkt[12..]);
    return 12 + qlen;
}

/// A NODATA echo of `qpkt`: NOERROR with no answers, used to feed
/// the chain one phase at a time in tests.
fn buildNodata(out: []u8, qpkt: []const u8) usize {
    const id = std.mem.readInt(u16, qpkt[0..2], .big);
    std.mem.writeInt(u16, out[0..2], id, .big);
    std.mem.writeInt(u16, out[2..4], 0x8180, .big);
    std.mem.writeInt(u16, out[4..6], 1, .big);
    @memset(out[6..12], 0);
    const qlen = qpkt.len - 12;
    @memcpy(out[12 .. 12 + qlen], qpkt[12..]);
    return 12 + qlen;
}

/// An error echo of `qpkt` carrying `rcode` (SERVFAIL is 2): runs the
/// per-phase failure path for the outstanding query.
fn buildRcode(out: []u8, qpkt: []const u8, rcode: u16) usize {
    const id = std.mem.readInt(u16, qpkt[0..2], .big);
    std.mem.writeInt(u16, out[0..2], id, .big);
    std.mem.writeInt(u16, out[2..4], 0x8180 | rcode, .big);
    std.mem.writeInt(u16, out[4..6], 1, .big);
    @memset(out[6..12], 0);
    const qlen = qpkt.len - 12;
    @memcpy(out[12 .. 12 + qlen], qpkt[12..]);
    return 12 + qlen;
}

/// A NOERROR echo of `qpkt` with one answer record of `rtype`, `ttl`
/// and `rdata` (owner = the question via a 0xC00C pointer): feeds a
/// refresh answer with arbitrary cache semantics.
fn buildTypedAnswer(out: []u8, qpkt: []const u8, rtype: u16, ttl: u32, rdata: []const u8) usize {
    const id = std.mem.readInt(u16, qpkt[0..2], .big);
    std.mem.writeInt(u16, out[0..2], id, .big);
    std.mem.writeInt(u16, out[2..4], 0x8180, .big);
    std.mem.writeInt(u16, out[4..6], 1, .big);
    std.mem.writeInt(u16, out[6..8], 1, .big);
    @memset(out[8..12], 0);
    const qlen = qpkt.len - 12;
    @memcpy(out[12 .. 12 + qlen], qpkt[12..]);
    var off = 12 + qlen;
    out[off] = 0xC0;
    out[off + 1] = 0x0C;
    off += 2;
    std.mem.writeInt(u16, out[off..][0..2], rtype, .big);
    std.mem.writeInt(u16, out[off + 2 ..][0..2], 1, .big);
    std.mem.writeInt(u32, out[off + 4 ..][0..4], ttl, .big);
    std.mem.writeInt(u16, out[off + 8 ..][0..2], @intCast(rdata.len), .big);
    off += 10;
    @memcpy(out[off .. off + rdata.len], rdata);
    return off + rdata.len;
}

/// One AAAA answer record for ::1 (owner = the question).
fn encodeAaaaRr(out: []u8) usize {
    var off: usize = 0;
    out[off] = 0xC0;
    out[off + 1] = 0x0C;
    off += 2;
    std.mem.writeInt(u16, out[off..][0..2], wire.TYPE_AAAA, .big);
    std.mem.writeInt(u16, out[off + 2 ..][0..2], 1, .big);
    std.mem.writeInt(u32, out[off + 4 ..][0..4], 60, .big);
    std.mem.writeInt(u16, out[off + 8 ..][0..2], 16, .big);
    off += 10;
    @memcpy(out[off .. off + 16], &([1]u8{0} ** 15 ++ [1]u8{1}));
    return off + 16;
}

/// An AAAA answer for any question: feeds the fallback chain a real
/// address where a same-type answer is needed.
fn buildAaaaAnswer(out: []u8, qpkt: []const u8) usize {
    const id = std.mem.readInt(u16, qpkt[0..2], .big);
    std.mem.writeInt(u16, out[0..2], id, .big);
    std.mem.writeInt(u16, out[2..4], 0x8180, .big);
    std.mem.writeInt(u16, out[4..6], 1, .big);
    std.mem.writeInt(u16, out[6..8], 1, .big);
    @memset(out[8..12], 0);
    const qlen = qpkt.len - 12;
    @memcpy(out[12 .. 12 + qlen], qpkt[12..]);
    var off = 12 + qlen;
    off += encodeAaaaRr(out[off..]);
    return off;
}

/// One SRV answer record (owner = the question via a 0xC00C pointer).
fn encodeSrvRr(out: []u8, port: u16, target: []const u8) usize {
    var off: usize = 0;
    out[off] = 0xC0;
    out[off + 1] = 0x0C;
    off += 2;
    std.mem.writeInt(u16, out[off..][0..2], wire.TYPE_SRV, .big);
    std.mem.writeInt(u16, out[off + 2 ..][0..2], 1, .big);
    std.mem.writeInt(u32, out[off + 4 ..][0..4], 60, .big);
    std.mem.writeInt(u16, out[off + 8 ..][0..2], @intCast(6 + encLen(target)), .big);
    off += 10;
    std.mem.writeInt(u16, out[off..][0..2], 10, .big);
    std.mem.writeInt(u16, out[off + 2 ..][0..2], 100, .big);
    std.mem.writeInt(u16, out[off + 4 ..][0..2], port, .big);
    off += 6;
    appendEncodedNameTo(out, &off, target);
    return off;
}

/// One A answer record for 127.0.0.1 (owner = the question).
fn encodeARr(out: []u8) usize {
    var off: usize = 0;
    out[off] = 0xC0;
    out[off + 1] = 0x0C;
    off += 2;
    std.mem.writeInt(u16, out[off..][0..2], wire.TYPE_A, .big);
    std.mem.writeInt(u16, out[off + 2 ..][0..2], 1, .big);
    std.mem.writeInt(u32, out[off + 4 ..][0..4], 60, .big);
    std.mem.writeInt(u16, out[off + 8 ..][0..2], 4, .big);
    off += 10;
    @memcpy(out[off .. off + 4], &[_]u8{ 127, 0, 0, 1 });
    return off + 4;
}

/// Canned answer for one query frame `qpkt`: NODATA for the direct-TLS
/// SRV name, an SRV record for the STARTTLS name, an A record for the
/// target host, NODATA for anything else (AAAA included).
fn answerTcpQuery(out: []u8, qpkt: []const u8) usize {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const q = parseQuestion(arena_state.allocator(), qpkt) catch return 0;
    var rr_buf: [128]u8 = undefined;
    var rrs: []const u8 = &.{};
    var ancount: u16 = 0;
    if (q.qtype == KIND_SRV and !std.mem.startsWith(u8, q.qname, "_xmpps")) {
        ancount = 1;
        rrs = rr_buf[0..encodeSrvRr(&rr_buf, 15222, "srv.test")];
    } else if (q.qtype == KIND_A) {
        ancount = 1;
        rrs = rr_buf[0..encodeARr(&rr_buf)];
    }
    const id = std.mem.readInt(u16, qpkt[0..2], .big);
    std.mem.writeInt(u16, out[0..2], id, .big);
    std.mem.writeInt(u16, out[2..4], 0x8180, .big);
    std.mem.writeInt(u16, out[4..6], 1, .big);
    std.mem.writeInt(u16, out[6..8], ancount, .big);
    @memset(out[8..12], 0);
    const qlen = qpkt.len - 12;
    @memcpy(out[12 .. 12 + qlen], qpkt[12..]);
    const off = 12 + qlen;
    @memcpy(out[off .. off + rrs.len], rrs);
    return off + rrs.len;
}

test "dns-async: a kept-open TCP connection carries every chain query" {
    // The test owns the nameserver: a TCP listener whose accepted
    // connection stays open while the chain sends it several
    // length-prefixed queries. A staged frame that is never reset
    // would send only the first query and stall the resolve.
    const lfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(lfd);
    const bind_addr = try net.Address.parseIp("127.0.0.1", 0);
    try posix.bind(lfd, &bind_addr.any, bind_addr.getOsSockLen());
    try posix.listen(lfd, 4);
    var actual: posix.sockaddr = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr);
    try posix.getsockname(lfd, &actual, &slen);
    const port = net.Address.initPosix(@alignCast(&actual)).getPort();

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 1, false);
    const job = r.jobs.items[0];

    // The UDP answer's TC bit upgrades the chain to TCP; the _xmpps
    // SRV query is re-sent as the connection's first frame.
    var tbuf: [512]u8 = undefined;
    r.handleResponse(job, tbuf[0..buildTruncated(&tbuf, job.request)]);

    var peer: posix.sockaddr = undefined;
    var plen: posix.socklen_t = @sizeOf(posix.sockaddr);
    const cfd = try posix.accept(lfd, &peer, &plen, 0);
    defer posix.close(cfd);
    const tv = posix.timeval{ .sec = 0, .usec = 200_000 };
    try posix.setsockopt(cfd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv));

    var frames: usize = 0;
    var spins: usize = 0;
    while (ctx.status == null and spins < 100) : (spins += 1) {
        r.step(10);
        var fbuf: [1024]u8 = undefined;
        var hdr: [2]u8 = undefined;
        if (readFull(cfd, &hdr) != 2) continue;
        const want = std.mem.readInt(u16, &hdr, .big);
        if (readFull(cfd, fbuf[0..want]) != want) continue;
        frames += 1;
        var abuf: [1024]u8 = undefined;
        const rlen = answerTcpQuery(&abuf, fbuf[0..want]);
        var out_hdr: [2]u8 = undefined;
        std.mem.writeInt(u16, &out_hdr, @intCast(rlen), .big);
        _ = try posix.send(cfd, &out_hdr, 0);
        _ = try posix.send(cfd, abuf[0..rlen], 0);
    }

    // _xmpps SRV, _xmpp SRV, A, AAAA: four queries share the one
    // connection the TC upgrade opened.
    try std.testing.expectEqual(@as(usize, 4), frames);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqualStrings("srv.test", res.targets[0].host);
}

/// Accept one connection on a nonblocking listener, pumping the
/// resolver between retries so a pending connect can complete; gives
/// up after a bounded number of spins.
fn acceptTcpBounded(r: *Resolver, lfd: posix.fd_t) !posix.fd_t {
    var spins: usize = 0;
    while (spins < 100) : (spins += 1) {
        r.step(10);
        return posix.accept(lfd, null, null, 0) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
    }
    return error.AcceptTimeout;
}

test "dns-async: a TCP retry resends the query on a fresh connection" {
    // Goal: a deadline on the TCP leg re-opens the connection and
    // resends the query frame; a retry that only re-flushes tcp_out
    // would send nothing once the first frame is fully written.
    // Method: test-owned listener takes the real TC upgrade, holds
    // the first connection unanswered, fires the retry deadline via
    // onDeadline, and answers on the second connection.
    const lfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
    defer posix.close(lfd);
    const bind_addr = try net.Address.parseIp("127.0.0.1", 0);
    try posix.bind(lfd, &bind_addr.any, bind_addr.getOsSockLen());
    try posix.listen(lfd, 4);
    var actual: posix.sockaddr = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr);
    try posix.getsockname(lfd, &actual, &slen);
    const port = net.Address.initPosix(@alignCast(&actual)).getPort();

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", port));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });

    try r.query("host.test", .a, 7);
    const job = r.jobs.items[0];

    // The truncated UDP answer upgrades the query to TCP; the first
    // connection carries the request as its one frame.
    var tbuf: [512]u8 = undefined;
    r.handleResponse(job, tbuf[0..buildTruncated(&tbuf, job.request)]);

    const cfd1 = try acceptTcpBounded(&r, lfd);
    defer posix.close(cfd1);
    const tv = posix.timeval{ .sec = 0, .usec = 200_000 };
    try posix.setsockopt(cfd1, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv));

    var fbuf: [1024]u8 = undefined;
    var hdr: [2]u8 = undefined;
    var got: usize = 0;
    var spins: usize = 0;
    while (got == 0 and spins < 100) : (spins += 1) {
        r.step(10);
        if (readFull(cfd1, &hdr) == 2) {
            const want = std.mem.readInt(u16, &hdr, .big);
            if (readFull(cfd1, fbuf[0..want]) == want) got = want;
        }
    }
    try std.testing.expectEqual(job.request.len, got);
    try std.testing.expectEqualSlices(u8, job.request, fbuf[0..got]);

    // The first frame goes unanswered; the retry deadline re-opens
    // the connection instead of waiting on the dead one.
    r.onDeadline(job);

    const cfd2 = try acceptTcpBounded(&r, lfd);
    defer posix.close(cfd2);
    try posix.setsockopt(cfd2, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv));

    // The abandoned first connection reads EOF.
    var eof = false;
    spins = 0;
    while (!eof and spins < 100) : (spins += 1) {
        const n = posix.recv(cfd1, &hdr, 0) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        eof = n == 0;
    }
    try std.testing.expect(eof);

    // The second connection carries exactly one frame: the same
    // request again, length-prefixed.
    got = 0;
    spins = 0;
    while (got == 0 and spins < 100) : (spins += 1) {
        r.step(10);
        if (readFull(cfd2, &hdr) == 2) {
            const want = std.mem.readInt(u16, &hdr, .big);
            if (readFull(cfd2, fbuf[0..want]) == want) got = want;
        }
    }
    try std.testing.expectEqual(job.request.len, got);
    try std.testing.expectEqualSlices(u8, job.request, fbuf[0..got]);
    const extra = posix.recv(cfd2, fbuf[0..1], posix.MSG.DONTWAIT) catch 0;
    try std.testing.expectEqual(@as(usize, 0), extra);

    // Answering on the second connection resolves the query.
    var abuf: [1024]u8 = undefined;
    const rlen = answerTcpQuery(&abuf, fbuf[0..got]);
    var out_hdr: [2]u8 = undefined;
    std.mem.writeInt(u16, &out_hdr, @intCast(rlen), .big);
    _ = try posix.send(cfd2, &out_hdr, 0);
    _ = try posix.send(cfd2, abuf[0..rlen], 0);
    spins = 0;
    while (ctx.status == null and spins < 100) : (spins += 1) r.step(10);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var raw = ctx.raw.?;
    defer raw.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), raw.rrs.len);
    try std.testing.expectEqual(KIND_A, raw.rrs[0].rtype);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 127, 0, 0, 1 }, raw.rrs[0].rdata);
}

test "dns-async: a server closing after an answer costs one reconnect, not the job" {
    // Goal: RFC 7766 lets a server close the connection after any
    // answer; a chain query written into the dead connection must be
    // re-sent once on a fresh one instead of failing the resolve.
    // Method: a test-owned listener answers each chain query on its
    // own accepted connection and closes it at once, so the resolve
    // takes one connection per query.
    const lfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
    defer posix.close(lfd);
    const bind_addr = try net.Address.parseIp("127.0.0.1", 0);
    try posix.bind(lfd, &bind_addr.any, bind_addr.getOsSockLen());
    try posix.listen(lfd, 4);
    var actual: posix.sockaddr = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr);
    try posix.getsockname(lfd, &actual, &slen);
    const port = net.Address.initPosix(@alignCast(&actual)).getPort();

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 1, false);
    const job = r.jobs.items[0];

    // The truncated UDP answer upgrades the chain to TCP; the first
    // connection carries the _xmpps SRV query.
    var tbuf: [512]u8 = undefined;
    r.handleResponse(job, tbuf[0..buildTruncated(&tbuf, job.request)]);

    const tv = posix.timeval{ .sec = 0, .usec = 50_000 };
    var accepts: usize = 0;
    var fbuf: [1024]u8 = undefined;
    var hdr: [2]u8 = undefined;
    while (ctx.status == null and accepts < 8) {
        // Each accepted connection gets exactly one query frame:
        // answer it, then close before the next query is written, so
        // the resolver must notice the EOF and re-connect.
        const cfd = acceptTcpBounded(&r, lfd) catch break;
        accepts += 1;
        try posix.setsockopt(cfd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
        var got: usize = 0;
        var spins: usize = 0;
        while (got == 0 and spins < 100 and ctx.status == null) : (spins += 1) {
            r.step(10);
            if (readFull(cfd, &hdr) == 2) {
                const want = std.mem.readInt(u16, &hdr, .big);
                if (readFull(cfd, fbuf[0..want]) == want) got = want;
            }
        }
        if (got > 0) {
            var abuf: [1024]u8 = undefined;
            const rlen = answerTcpQuery(&abuf, fbuf[0..got]);
            var out_hdr: [2]u8 = undefined;
            std.mem.writeInt(u16, &out_hdr, @intCast(rlen), .big);
            _ = try posix.send(cfd, &out_hdr, posix.MSG.NOSIGNAL);
            _ = try posix.send(cfd, abuf[0..rlen], posix.MSG.NOSIGNAL);
        }
        posix.close(cfd);
    }

    // _xmpps SRV, _xmpp SRV, A, AAAA: one connection per query; the
    // resolver opens no connection a live chain does not need.
    try std.testing.expectEqual(@as(usize, 4), accepts);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqualStrings("srv.test", res.targets[0].host);
}

test "dns-async: resolv.conf is read into the resolver, not on the loop" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "resolv.conf", .data = "nameserver 127.0.0.99\n" });
    var pbuf: [512]u8 = undefined;
    const path = try tmp.dir.realpath("resolv.conf", &pbuf);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.resolv_conf_path = path;
    r.loadResolvConf();
    try std.testing.expect(r.server_configured);
    try std.testing.expectEqual(@as(u16, 53), r.server.getPort());
}

test "dns-async: a commented nameserver line stays a comment" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "resolv.conf", .data = "# nameserver 9.9.9.9\nnameserver 127.0.0.53 # local\n" });
    var pbuf: [512]u8 = undefined;
    const path = try tmp.dir.realpath("resolv.conf", &pbuf);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.resolv_conf_path = path;
    r.loadResolvConf();
    try std.testing.expect(r.server_configured);
    try std.testing.expect(r.server.eql(try net.Address.parseIp("127.0.0.53", 53)));
}

test "dns-async: resolv.conf keywords only count at line start" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // libc res_init: ';' opens a comment in column 0, the keyword
    // must start the line, and "search nameserver" is a search line.
    try tmp.dir.writeFile(.{ .sub_path = "resolv.conf", .data = "; nameserver 9.9.9.1\n  nameserver 9.9.9.2\nsearch nameserver 9.9.9.3\nnameserver 127.0.0.53 ; inline comment\n" });
    var pbuf: [512]u8 = undefined;
    const path = try tmp.dir.realpath("resolv.conf", &pbuf);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.resolv_conf_path = path;
    r.loadResolvConf();
    try std.testing.expect(r.server_configured);
    try std.testing.expect(r.server.eql(try net.Address.parseIp("127.0.0.53", 53)));
}

test "dns-async: a nameserver past the first kilobyte is still found" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var conf: std.ArrayListUnmanaged(u8) = .{};
    defer conf.deinit(std.testing.allocator);
    for (0..40) |_| {
        conf.appendSlice(std.testing.allocator, "# padding comment line padding padding padding\n") catch unreachable;
    }
    try std.testing.expect(conf.items.len > 1024);
    conf.appendSlice(std.testing.allocator, "nameserver 127.0.0.54\n") catch unreachable;
    try tmp.dir.writeFile(.{ .sub_path = "resolv.conf", .data = conf.items });
    var pbuf: [512]u8 = undefined;
    const path = try tmp.dir.realpath("resolv.conf", &pbuf);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.resolv_conf_path = path;
    r.loadResolvConf();
    try std.testing.expect(r.server_configured);
    try std.testing.expect(r.server.eql(try net.Address.parseIp("127.0.0.54", 53)));
}

test "dns-async: resolv.conf needs a blank after the keyword and ends tokens at ; or #" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // libc MATCH() requires blank/tab after "nameserver"; the address
    // token ends at the first blank, ';', or '#'.
    try tmp.dir.writeFile(.{ .sub_path = "resolv.conf", .data = "nameserver9.9.9.9\nnameserver 127.0.0.61;inline\n" });
    var pbuf: [512]u8 = undefined;
    const path = try tmp.dir.realpath("resolv.conf", &pbuf);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.resolv_conf_path = path;
    r.loadResolvConf();
    try std.testing.expect(r.server_configured);
    try std.testing.expect(r.server.eql(try net.Address.parseIp("127.0.0.61", 53)));

    var tmp2 = std.testing.tmpDir(.{});
    defer tmp2.cleanup();
    try tmp2.dir.writeFile(.{ .sub_path = "resolv.conf", .data = "nameserver 127.0.0.62#tag\n" });
    const path2 = try tmp2.dir.realpath("resolv.conf", &pbuf);
    r.resolv_conf_path = path2;
    r.loadResolvConf();
    try std.testing.expect(r.server.eql(try net.Address.parseIp("127.0.0.62", 53)));
}

test "dns-async: a scoped v6 nameserver (fe80::1%lo0) is accepted" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "resolv.conf", .data = "nameserver fe80::1%lo0\n" });
    var pbuf: [512]u8 = undefined;
    const path = try tmp.dir.realpath("resolv.conf", &pbuf);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.resolv_conf_path = path;
    r.loadResolvConf();
    try std.testing.expect(r.server_configured);
    try std.testing.expectEqual(@as(u16, posix.AF.INET6), r.server.any.family);
    // if_nametoindex("lo0") is 2 on this host.
    try std.testing.expectEqual(@as(u32, 2), r.server.in6.sa.scope_id);
}

test "dns-async: resolv.conf scopes follow libc (link-local v6 only, tab separator)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // libc takes a zone only on a link-local v6 nameserver: a scope on
    // a global v6 address, on an IPv4 address, and an empty zone are
    // each skipped; a tab after the keyword is a valid separator.
    try tmp.dir.writeFile(.{ .sub_path = "resolv.conf", .data = "nameserver 2001:db8::1%lo0\nnameserver 127.0.0.1%lo0\nnameserver fe80::1%\nnameserver\t127.0.0.65\n" });
    var pbuf: [512]u8 = undefined;
    const path = try tmp.dir.realpath("resolv.conf", &pbuf);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.resolv_conf_path = path;
    r.loadResolvConf();
    try std.testing.expect(r.server_configured);
    try std.testing.expect(r.server.eql(try net.Address.parseIp("127.0.0.65", 53)));
}

test "dns-async: resolv.conf zones follow libc ip6_str2scopeid" {
    // libc: a numeric zone applies to any IPv6 address; a named zone
    // applies to link-local (fe80::/10) and ffx1/ffx2 multicast only.
    const cases = [_]struct { conf: []const u8, scope: ?u32 }{
        .{ .conf = "nameserver fe80::1%1\n", .scope = 1 },
        .{ .conf = "nameserver 2001:db8::1%2\n", .scope = 2 },
        .{ .conf = "nameserver ::ffff:127.0.0.1%1\n", .scope = 1 },
        .{ .conf = "nameserver ff02::1%lo0\n", .scope = 2 },
        .{ .conf = "nameserver ff01::1%lo0\n", .scope = 2 },
        .{ .conf = "nameserver ff12::1%lo0\n", .scope = 2 },
        .{ .conf = "nameserver ff32::1%lo0\n", .scope = 2 },
        .{ .conf = "nameserver fec0::1%3\n", .scope = 3 },
        .{ .conf = "nameserver febf::1%lo0\n", .scope = 2 },
        .{ .conf = "nameserver 2001:db8::1%lo0\n", .scope = null },
        .{ .conf = "nameserver 127.0.0.1%lo0\n", .scope = null },
        .{ .conf = "nameserver fe80::1%\n", .scope = null },
        // Named zones on non-node/link-local multicast scopes are
        // rejected: ff09/ff0a also pin the scope mask (& 0x07 would
        // alias them to scopes 1/2), ff05/ff0e pin scope != 0.
        .{ .conf = "nameserver ff05::1%lo0\n", .scope = null },
        .{ .conf = "nameserver ff0e::1%lo0\n", .scope = null },
        .{ .conf = "nameserver ff09::1%lo0\n", .scope = null },
        .{ .conf = "nameserver ff0a::1%lo0\n", .scope = null },
    };
    for (cases) |c| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.writeFile(.{ .sub_path = "resolv.conf", .data = c.conf });
        var pbuf: [512]u8 = undefined;
        const path = try tmp.dir.realpath("resolv.conf", &pbuf);
        const got = readResolvConf(std.testing.allocator, path) catch null;
        if (c.scope) |want| {
            try std.testing.expect(got != null);
            try std.testing.expectEqual(want, got.?.in6.sa.scope_id);
        } else try std.testing.expect(got == null);
    }
}

test "dns-async: a TLSA NXDOMAIN marks the target absent (per-target path)" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_many = 1;
    srv.tlsa_nxdomain.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    // NXDOMAIN is authenticated absence, not a lookup failure.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.absent, res.targets[0].tlsa_status);
}

test "dns-async: a fallback TLSA NXDOMAIN marks the targets absent" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.empty_srv.store(true, .monotonic);
    srv.tlsa_nxdomain.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("dual.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.absent, res.targets[0].tlsa_status);
}

test "dns-async: a fallback TLSA SERVFAIL marks the targets lookup_failed" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.empty_srv.store(true, .monotonic);
    srv.tlsa_fail.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("dual.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.lookup_failed, res.targets[0].tlsa_status);
}

test "dns-async: a fallback TLSA answer marks the targets present" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.empty_srv.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("dual.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.present, res.targets[0].tlsa_status);
    try std.testing.expect(res.targets[0].tlsa.len >= 1);
}

test "dns-async: a fallback unparsable TLSA answer is lookup_failed" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.empty_srv.store(true, .monotonic);
    srv.tlsa_garbage.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("dual.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.lookup_failed, res.targets[0].tlsa_status);
}

test "dns-async: an unparsable TLSA answer is lookup_failed, not absent" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.srv_many = 1;
    srv.tlsa_garbage.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    // A TLSA RRset that cannot be parsed gave the lookup nothing
    // usable: temporary failure, never PKIX.
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.lookup_failed, res.targets[0].tlsa_status);
}

test "dns-async: a real TLSA send failure in finishTarget is lookup_failed" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    // Every stage before TLSA is answered from cache, so the only
    // wire send is the TLSA query, and it fails for real.
    r.cacheInsert("_xmpps-client._tcp.svc.test", KIND_SRV, &.{}, .nodata, 60);
    var rdata: std.ArrayListUnmanaged(u8) = .{};
    defer rdata.deinit(std.testing.allocator);
    try rdata.appendSlice(std.testing.allocator, &.{ 0, 10, 0, 100, 0x14, 0x76 });
    appendEncodedName(std.testing.allocator, &rdata, "t.test");
    var srv_rrs = [1]wire.Rr{.{ .name = "_xmpp-client._tcp.svc.test", .rtype = KIND_SRV, .class = wire.CLASS_IN, .ttl = 60, .rdata = rdata.items }};
    r.cacheInsert("_xmpp-client._tcp.svc.test", KIND_SRV, &srv_rrs, .none, 60);
    var a_rrs = [1]wire.Rr{.{ .name = "t.test", .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = &.{ 127, 0, 0, 1 } }};
    r.cacheInsert("t.test", KIND_A, &a_rrs, .none, 60);
    r.cacheInsert("t.test", KIND_AAAA, &.{}, .nxdomain, 60);

    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    r.fail_sends = true;

    try r.resolve("svc.test", .client, 5222, 3, true);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.lookup_failed, res.targets[0].tlsa_status);
}

test "dns-async: an over-long per-target TLSA owner is absent" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    // The SRV target resolves, but its TLSA owner
    // "_5238._tcp.<long_host>" cannot be encoded: the name cannot
    // exist, so the per-target status is absent, never lookup_failed.
    const long_host = "a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63 ++ "." ++ "d" ** 50 ++ ".test";
    r.cacheInsert("_xmpps-client._tcp.svc.test", KIND_SRV, &.{}, .nodata, 60);
    var rdata: std.ArrayListUnmanaged(u8) = .{};
    defer rdata.deinit(std.testing.allocator);
    try rdata.appendSlice(std.testing.allocator, &.{ 0, 10, 0, 100, 0x14, 0x76 });
    appendEncodedName(std.testing.allocator, &rdata, long_host);
    var srv_rrs = [1]wire.Rr{.{ .name = "_xmpp-client._tcp.svc.test", .rtype = KIND_SRV, .class = wire.CLASS_IN, .ttl = 60, .rdata = rdata.items }};
    r.cacheInsert("_xmpp-client._tcp.svc.test", KIND_SRV, &srv_rrs, .none, 60);
    var a_rrs = [1]wire.Rr{.{ .name = long_host, .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = &.{ 127, 0, 0, 1 } }};
    r.cacheInsert(long_host, KIND_A, &a_rrs, .none, 60);
    r.cacheInsert(long_host, KIND_AAAA, &.{}, .nxdomain, 60);

    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    try r.resolve("svc.test", .client, 5222, 3, true);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.absent, res.targets[0].tlsa_status);
}

test "dns-async: an over-long SRV target is skipped for the good one" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    // 282 octets cannot be staged into sendAddr's 280-byte qname
    // buffer: both family sends take the NXDOMAIN arm, the dead
    // target yields no address, and the chain moves on to the next
    // SRV target, which resolves normally.
    const long_host = "x" ** 63 ++ "." ++ "y" ** 63 ++ "." ++ "z" ** 63 ++ "." ++ "w" ** 63 ++ "." ++ "v" ** 30;
    try std.testing.expect(long_host.len > 280);
    r.cacheInsert("_xmpps-client._tcp.svc.test", KIND_SRV, &.{}, .nodata, 60);
    var bad_rdata: std.ArrayListUnmanaged(u8) = .{};
    defer bad_rdata.deinit(std.testing.allocator);
    var good_rdata: std.ArrayListUnmanaged(u8) = .{};
    defer good_rdata.deinit(std.testing.allocator);
    // RFC 2782 sorts the lower priority first, so the dead target is
    // the one tried before srv.test.
    try bad_rdata.appendSlice(std.testing.allocator, &.{ 0, 5, 0, 100, 0x14, 0x76 });
    appendEncodedName(std.testing.allocator, &bad_rdata, long_host);
    try good_rdata.appendSlice(std.testing.allocator, &.{ 0, 10, 0, 100, 0x3B, 0x76 });
    appendEncodedName(std.testing.allocator, &good_rdata, "srv.test");
    var srv_rrs = [2]wire.Rr{
        .{ .name = "_xmpp-client._tcp.svc.test", .rtype = KIND_SRV, .class = wire.CLASS_IN, .ttl = 60, .rdata = bad_rdata.items },
        .{ .name = "_xmpp-client._tcp.svc.test", .rtype = KIND_SRV, .class = wire.CLASS_IN, .ttl = 60, .rdata = good_rdata.items },
    };
    r.cacheInsert("_xmpp-client._tcp.svc.test", KIND_SRV, &srv_rrs, .none, 60);
    var a_rrs = [1]wire.Rr{.{ .name = "srv.test", .rtype = KIND_A, .class = wire.CLASS_IN, .ttl = 60, .rdata = &.{ 127, 0, 0, 1 } }};
    r.cacheInsert("srv.test", KIND_A, &a_rrs, .none, 60);
    r.cacheInsert("srv.test", KIND_AAAA, &.{}, .nxdomain, 60);

    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    try r.resolve("svc.test", .client, 5222, 3, false);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqualStrings("srv.test", res.targets[0].host);
    try std.testing.expectEqual(@as(u16, posix.AF.INET), res.targets[0].addr.any.family);
    try std.testing.expectEqual(@as(u16, 15222), res.targets[0].addr.getPort());
}

test "dns-async: names over 255 wire octets behave as NXDOMAIN" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    // 235 octets: _xmpps overflows but _xmpp (253) is a legal name.
    const d235 = "a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63 ++ "." ++ "d" ** 43;
    try std.testing.expectEqual(@as(usize, 235), d235.len);
    try r.resolve(d235, .client, 5222, 3, true);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    try std.testing.expect(res.targets.len >= 1);
    res.deinitOn(std.testing.allocator);

    // 240 octets: both SRV prefixes overflow; the bare-name fallback
    // A still resolves, and its TLSA owner (251) is legal.
    ctx.status = null;
    ctx.res = null;
    const d240 = "a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63 ++ "." ++ "d" ** 48;
    try std.testing.expectEqual(@as(usize, 240), d240.len);
    try r.resolve(d240, .client, 5222, 4, true);
    spins = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    res = ctx.res.?;
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.present, res.targets[0].tlsa_status);
    res.deinitOn(std.testing.allocator);

    // 253 octets: the bare A is at the wire limit; the TLSA owner
    // overflows, which reads as absent, not a lookup failure.
    ctx.status = null;
    ctx.res = null;
    const d253 = "a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63 ++ "." ++ "d" ** 61;
    try std.testing.expectEqual(@as(usize, 253), d253.len);
    try r.resolve(d253, .client, 5222, 5, true);
    spins = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    res = ctx.res.?;
    try std.testing.expectEqual(@as(usize, 1), res.targets.len);
    try std.testing.expectEqual(TlsaStatus.absent, res.targets[0].tlsa_status);
    res.deinitOn(std.testing.allocator);
}

test "dns-async: a 262+ character name reports async nxdomain" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    // Too long to stage with an SRV prefix and too long for the wire:
    // the callback reports nxdomain inside resolve() itself rather
    // than a synchronous NameTooLong error return.
    const d262 = "a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63 ++ "." ++ "d" ** 70;
    try std.testing.expectEqual(@as(usize, 262), d262.len);
    try r.resolve(d262, .client, 5222, 3, true);
    try std.testing.expectEqual(Status.nxdomain, ctx.status.?);
    try std.testing.expectEqual(@as(usize, 0), r.jobs.items.len);
}

test "dns-async: a name over the staging buffer reports async nxdomain" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    // 300 octets overruns the 280-byte staging buffer in sendFallback
    // itself, so every arm fails staging and the nxdomain completes
    // inside resolve() with no step needed.
    const d300 = "a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63 ++ "." ++ "d" ** 63 ++ "." ++ "e" ** 44;
    try std.testing.expectEqual(@as(usize, 300), d300.len);
    try r.resolve(d300, .client, 5222, 3, true);
    try std.testing.expectEqual(Status.nxdomain, ctx.status.?);
    try std.testing.expectEqual(@as(usize, 0), r.jobs.items.len);
}

test "dns-async: an over-long raw query reports nxdomain" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 9));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });

    // 254 octets exceeds the 255-octet wire limit (RFC 1035 2.3.4).
    try r.query("a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63 ++ "." ++ "d" ** 62, .a, 7);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.nxdomain, ctx.status.?);
}

test "dns-async: a SERVFAIL is never cached and hits the wire again" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.a_fail.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });

    try r.query("fail.test", .a, 1);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.failed, ctx.status.?);
    const n1 = srv.udp_recvd.load(.monotonic);

    ctx.status = null;
    try r.query("fail.test", .a, 2);
    spins = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.failed, ctx.status.?);
    // A cached SERVFAIL would have answered the repeat from memory;
    // a temporary failure must go back to the wire instead.
    try std.testing.expect(srv.udp_recvd.load(.monotonic) > n1);
}

test "dns-async: a timed-out query is never cached and hits the wire again" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.a_silent.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });

    try r.query("fail.test", .a, 1);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.failed, ctx.status.?);
    const n1 = srv.udp_recvd.load(.monotonic);

    ctx.status = null;
    try r.query("fail.test", .a, 2);
    spins = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.failed, ctx.status.?);
    try std.testing.expect(srv.udp_recvd.load(.monotonic) > n1);
}

test "dns-async: a TTL with the top bit set reports zero (RFC 2181)" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);
    srv.a_ttl_highbit.store(true, .monotonic);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });

    try r.query("host.test", .a, 7);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.raw.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 0), res.ttl);
}
