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
const CACHE_CAP: usize = 64;
/// Flattened connect targets per resolution; a hostile SRV answer
/// cannot grow a job's target list past this.
const TARGET_CAP: usize = 16;
/// Parsed SRV entries kept per job, bounded at absorb time: twice the
/// emitted cap so per-target failures still leave targets to try.
const SRV_CAP: usize = 32;
/// Cache TTL ceiling: positive and negative entries alike are
/// expired after five minutes regardless of the advertised TTL.
const CACHE_TTL_CEIL_S: u32 = 300;

pub const Service = enum(u8) { client = 0, server = 1 };

const SRV_TLS = [2][]const u8{ "_xmpps-client._tcp", "_xmpps-server._tcp" };
const SRV_PLAIN = [2][]const u8{ "_xmpp-client._tcp", "_xmpp-server._tcp" };

pub const RType = enum(u16) { a = KIND_A, aaaa = KIND_AAAA, srv = KIND_SRV, tlsa = KIND_TLSA };

pub const Target = struct {
    addr: net.Address,
    host: []const u8, // owned
    tlsa: []dns.TlsaRecord, // owned; empty when none
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
    /// Addresses collected for the current SRV target across the A
    /// and AAAA phases.
    cur_addr4: ?net.Address = null,
    cur_addr6: ?net.Address = null,

    // Wire state for the outstanding query.
    dns_id: u16 = 0,
    pending_qname: []const u8 = "", // owned
    pending_qtype: u16 = 0,
    request: []u8 = &.{},
    tries: u8 = 0,
    use_tcp: bool = false,
    tcp_fd: posix.fd_t = -1,
    tcp_buf: std.ArrayListUnmanaged(u8) = .{},
    /// Outbound TCP frame staged once and flushed incrementally;
    /// tcp_connected marks whether connect() has completed.
    tcp_out: std.ArrayListUnmanaged(u8) = .{},
    tcp_out_pos: usize = 0,
    tcp_connected: bool = false,

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

const CacheEnt = struct {
    key: []u8, // "folded_qname\0qtype_be2"
    rrs: []wire.Rr, // names and rdata owned per record; empty when neg
    neg: NegKind = .none,
    expires_ms: i64,
};

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
    /// Slot table for timer udata: a queued deadline event carries
    /// (gen, slot) so a job freed by an earlier event in the same
    /// kevent batch is never touched (C3 pattern).
    slots: [MAX_JOBS]?*Job = .{null} ** MAX_JOBS,
    slot_gen: [MAX_JOBS]u16 = .{0} ** MAX_JOBS,
    /// Seeded from the CSPRNG; drives only the RFC 2782 weighted picks
    /// so tests can reseed for deterministic draws. Query ids come from
    /// the CSPRNG per send, never from a seeded PRNG sequence.
    prng: std.Random.DefaultPrng = std.Random.DefaultPrng.init(0),
    cb: Cb = .{ .ctx = null, .fun = noopCallback },
    qcb: QueryCb = .{ .ctx = null, .fun = noopQueryCallback },
    cache: std.ArrayListUnmanaged(CacheEnt) = .{},
    /// Requests queued behind a full in-flight set; promoted FIFO as
    /// jobs complete.
    wait_queue: std.ArrayListUnmanaged(WaitEnt) = .{},
    /// Whole-chain deadline for resolve() jobs; a field so tests can
    /// shrink it instead of sleeping ten seconds.
    chain_deadline_ms: i64 = CHAIN_DEADLINE_MS,
    /// Wall clock for cache expiry; a field so tests can pin time
    /// instead of sleeping on real TTLs.
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
    udp_errors: usize = 0,
    /// The job currently firing completion callbacks, or null. Set
    /// inside a dropJob/complete/completeRaw waiter loop, after the
    /// job is already off `jobs`, so a cancel() issued from inside a
    /// callback can still mark the job's remaining waiters. Loops
    /// restore the previous value on exit: a callback that completes
    /// another job synchronously (a cached resolve) must not lose the
    /// outer job's cancel marks.
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
        if (readResolvConf(self.resolv_conf_path)) |addr| {
            self.server = addr;
            self.server_configured = true;
        } else |_| {}
    }

    pub fn deinit(self: *Resolver) void {
        for (self.jobs.items) |j| self.freeJob(j);
        self.jobs.deinit(self.alloc);
        for (self.wait_queue.items) |e| self.alloc.free(e.name);
        self.wait_queue.deinit(self.alloc);
        for (self.cache.items) |e| self.freeCacheEnt(e);
        self.cache.deinit(self.alloc);
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
    /// callback with owned RRs.
    pub fn query(self: *Resolver, name: []const u8, rtype: RType, session_key: usize) !void {
        const qt: u16 = @intFromEnum(rtype);
        if (self.cacheGet(name, qt)) |ent| {
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
        }
        try self.ensureOpen();
        if (self.jobs.items.len >= MAX_JOBS) {
            try self.enqueueWait(session_key, name, .{ .kind = .query, .rtype = qt });
            return;
        }
        const job = try self.allocJob(session_key, name);
        job.phase = .raw;
        job.is_raw = true;
        {
            errdefer self.freeJob(job);
            try self.jobs.append(self.alloc, job);
        }
        // A cache hit inside sendQuery can complete and free the job
        // synchronously; after this call `job` may not be touched.
        self.sendQuery(job, name, qt) catch |err| {
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

    /// Launch the head of the wait queue now that a job slot opened.
    /// A launch that fails answers the waiter's callback with .failed;
    /// there is no error return this deep in the pump.
    fn promoteWait(self: *Resolver) void {
        while (self.jobs.items.len < MAX_JOBS and self.wait_queue.items.len > 0) {
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
            if (job.waiter_count == 0) {
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
    /// want_tlsa: fetch TLSA records per target (_port._tcp.<target>)
    /// when the caller can authenticate with them; false callers get
    /// the same addresses without the extra round trips.
    pub fn resolve(self: *Resolver, name: []const u8, service: Service, default_port: u16, session_key: usize, want_tlsa: bool) !void {
        if (net.Address.parseIp(name, default_port)) |addr| {
            const t = Target{ .addr = addr, .host = try self.alloc.dupe(u8, name), .tlsa = &.{}, .is_direct_tls = false };
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
            if (!std.ascii.eqlIgnoreCase(job.name, name)) continue;
            // A full job takes no more waiters; the lookup starts a
            // fresh job on the wire instead of failing.
            if (job.waiter_count >= MAX_WAITERS) continue;
            job.waiters[job.waiter_count] = session_key;
            job.waiter_count += 1;
            return;
        }
        if (self.jobs.items.len >= MAX_JOBS) {
            try self.enqueueWait(session_key, name, .{ .kind = .resolve, .service_idx = @intFromEnum(service), .default_port = default_port, .want_tlsa = want_tlsa });
            return;
        }
        const job = try self.allocJob(session_key, name);
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
        try posix.connect(fd, &self.server.any, self.server.getOsSockLen());
        self.fd = fd;
        var ch = [1]posix.Kevent{.{ .ident = @intCast(fd), .filter = std.c.EVFILT.READ, .flags = std.c.EV.ADD | std.c.EV.ENABLE, .fflags = 0, .data = 0, .udata = 0 }};
        try self.keventApply(&ch);
    }

    /// One kevent turn on the resolver's kqueue. `timeout_ms` may be 0
    /// (pump only) - callers pass their next-loop deadline, not a sleep.
    pub fn step(self: *Resolver, timeout_ms: i32) void {
        if (self.kq < 0) return;
        var events: [16]posix.Kevent = undefined;
        const ts: std.c.timespec = .{ .sec = @intCast(@divTrunc(timeout_ms, 1000)), .nsec = @intCast(@rem(timeout_ms, 1000) * 1_000_000) };
        const n = posix.kevent(self.kq, &.{}, &events, &ts) catch return;
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
                } else {
                    self.onTcpReadable(fd);
                }
            } else if (ev.filter == std.c.EVFILT.WRITE) {
                // A refused connect also reports writable, so check
                // SO_ERROR once before the socket is used; a connected
                // socket arriving here resumes a WouldBlock flush.
                const fd: posix.fd_t = @intCast(ev.ident);
                for (self.jobs.items) |job| {
                    if (job.tcp_fd == fd) {
                        if (!job.tcp_connected) {
                            posix.getsockoptError(fd) catch {
                                self.dropJob(job, .failed);
                                break;
                            };
                            job.tcp_connected = true;
                        }
                        self.tcpWrite(job) catch self.dropJob(job, .failed);
                        break;
                    }
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
        const qname = std.fmt.bufPrint(&buf, "{s}.{s}", .{ prefix, job.name }) catch return error.NameTooLong;
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

    fn disarmDeadline(self: *Resolver, job: *Job) void {
        var ch = [2]posix.Kevent{
            .{ .ident = @intFromPtr(job), .filter = std.c.EVFILT.TIMER, .flags = std.c.EV.DELETE, .fflags = 0, .data = 0, .udata = 0 },
            .{ .ident = @intFromPtr(job) | 1, .filter = std.c.EVFILT.TIMER, .flags = std.c.EV.DELETE, .fflags = 0, .data = 0, .udata = 0 },
        };
        _ = posix.kevent(self.kq, &ch, &.{}, null) catch {};
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

    /// Connected-UDP send. An ICMP port-unreachable queued from an
    /// earlier datagram surfaces as ECONNREFUSED on a later send; that
    /// error belongs to the earlier packet, so it is consumed and the
    /// send retried once instead of failing the wrong job.
    fn sendUdp(self: *Resolver, pkt: []const u8) !void {
        _ = posix.send(self.fd, pkt, 0) catch |err| switch (err) {
            error.ConnectionRefused => {
                self.stale_icmp += 1;
                _ = posix.send(self.fd, pkt, 0) catch return error.SendFailed;
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
            const got = try posix.kevent(self.kq, batch[0..n], &evbuf, &nonblock);
            for (evbuf[0..got]) |ev| {
                if (ev.data != 0) return error.KeventChange;
            }
            off += n;
        }
    }

    fn sendQuery(self: *Resolver, job: *Job, qname: []const u8, qtype: u16) !void {
        // The chain consults the RR cache the same way a raw query
        // does; a hit feeds the phase machine a synthetic message,
        // and a negative hit drives the matching failure path.
        if (self.cacheGet(qname, qtype)) |ent| {
            if (job.is_raw) {
                switch (ent.neg) {
                    .nxdomain => return self.dropJob(job, .nxdomain),
                    .nodata => return self.completeRaw(job, .{ .id = 0, .rcode = wire.RCODE_NOERROR, .truncated = false, .rrs = &.{}, .raw = &.{} }),
                    .none => {},
                }
            } else switch (ent.neg) {
                .nxdomain => return self.onNxdomain(job),
                .nodata, .none => {},
            }
            const hit = wire.Message{ .id = 0, .rcode = wire.RCODE_NOERROR, .truncated = false, .rrs = ent.rrs, .raw = &.{} };
            if (job.is_raw) return self.completeRaw(job, hit);
            return self.advance(job, hit);
        }
        var buf: [512]u8 = undefined;
        const id = try self.nextId();
        const q = try wire.buildQuery(&buf, id, qname, qtype);
        const pkt = try self.alloc.dupe(u8, buf[0..q]);
        if (job.request.len > 0) self.alloc.free(job.request);
        job.request = pkt;
        job.dns_id = std.mem.readInt(u16, pkt[0..2], .big);
        if (job.pending_qname.len > 0) self.alloc.free(job.pending_qname);
        job.pending_qname = try self.alloc.dupe(u8, qname);
        job.pending_qtype = qtype;
        job.tries = 1;
        if (job.use_tcp) {
            // A connection surviving from an earlier query still holds
            // that query's staged frame; reset it or the new query is
            // never written and the chain stalls on this socket.
            job.tcp_out.clearRetainingCapacity();
            job.tcp_out_pos = 0;
            try self.tcpSend(job);
        } else {
            try self.sendUdp(pkt);
        }
        self.armDeadline(job, TIMEOUT_MS) catch return error.SendFailed;
    }

    fn onDeadline(self: *Resolver, job: *Job) void {
        job.tries += 1;
        if (job.tries <= MAX_TRIES) {
            if (job.use_tcp) {
                self.tcpSend(job) catch {
                    self.dropJob(job, .failed);
                    return;
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
            return;
        }
        log.warn("dns: timeout after {d} tries for {s}", .{ job.tries, job.name });
        self.failQuery(job);
    }

    /// The outstanding query is dead (retries exhausted or a refusal
    /// rcode). Inside a per-target phase only that SRV target is
    /// skipped; inside the fallback the other family still gets its
    /// try; every other phase fails the job.
    fn failQuery(self: *Resolver, job: *Job) void {
        switch (job.phase) {
            // A per-target failure costs only the phase that failed:
            // one dead address family still lets the other answer,
            // and a failed TLSA lookup degrades the target to no-DANE.
            .addr => {
                job.phase = .addr6;
                self.sendAddr(job, KIND_AAAA) catch return self.finishTarget(job);
            },
            .addr6, .tlsa => self.finishTarget(job),
            .fallback_addr => {
                job.fallback_err = true;
                job.phase = .fallback_addr4;
                self.sendFallback(job, KIND_A) catch return self.dropJob(job, .failed);
            },
            .fallback_addr4 => {
                job.fallback_err = true;
                self.finishFallback(job);
            },
            .fallback_tlsa => self.complete(job),
            else => self.dropJob(job, .failed),
        }
    }

    /// End the current SRV target after a failure: emit whichever
    /// address families did resolve, then move to the next target in
    /// RFC 2782 order. Only a target with nothing resolved is skipped.
    fn finishTarget(self: *Resolver, job: *Job) void {
        if (job.cur_addr4 != null or job.cur_addr6 != null) {
            self.emitTargets(job, &.{}) catch return self.dropJob(job, .failed);
        }
        job.cur_addr4 = null;
        job.cur_addr6 = null;
        self.nextTarget(job) catch return self.dropJob(job, .failed);
    }

    /// The whole-chain bound fired: hand the waiters whatever targets
    /// were collected so far instead of failing an almost-done chain.
    fn onChainDeadline(self: *Resolver, job: *Job) void {
        log.warn("dns: chain deadline exceeded for {s}", .{job.name});
        if (job.targets.items.len > 0) {
            self.complete(job);
        } else {
            self.dropJob(job, .failed);
        }
    }

    // -- TCP fallback ----------------------------------------------------

    /// Open the TCP socket and start connect; the WRITE knote drives the
    /// actual send once connect completes.
    fn tcpSend(self: *Resolver, job: *Job) !void {
        if (job.tcp_fd >= 0) return self.tcpWrite(job);
        const fd = try posix.socket(self.server.any.family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
        errdefer posix.close(fd);
        var ch: [2]posix.Kevent = undefined;
        var connected = true;
        posix.connect(fd, &self.server.any, self.server.getOsSockLen()) catch |e| switch (e) {
            error.WouldBlock => connected = false,
            else => return e,
        };
        ch[0] = .{ .ident = @intCast(fd), .filter = std.c.EVFILT.READ, .flags = std.c.EV.ADD | std.c.EV.ENABLE, .fflags = 0, .data = 0, .udata = 0 };
        var n: usize = 1;
        if (!connected) {
            // Only a pending connect wants the writable event; arming
            // it after an immediate connect would fire a second write
            // of the same frame later.
            ch[1] = .{ .ident = @intCast(fd), .filter = std.c.EVFILT.WRITE, .flags = std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT, .fflags = 0, .data = 0, .udata = 0 };
            n = 2;
        }
        try self.keventApply(ch[0..n]);
        job.tcp_fd = fd;
        job.tcp_connected = connected;
        if (connected) return self.tcpWrite(job);
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
            .udata = 0,
        }};
        try self.keventApply(&ch);
    }

    /// TCP DNS frames are length-prefixed; the frame is staged once in
    /// tcp_out and flushed across partial writes and WouldBlock.
    fn tcpWrite(self: *Resolver, job: *Job) !void {
        if (job.tcp_out.items.len == 0) {
            var hdr: [2]u8 = undefined;
            std.mem.writeInt(u16, &hdr, @intCast(job.request.len), .big);
            try job.tcp_out.appendSlice(self.alloc, &hdr);
            try job.tcp_out.appendSlice(self.alloc, job.request);
        }
        while (job.tcp_out_pos < job.tcp_out.items.len) {
            const n = posix.send(job.tcp_fd, job.tcp_out.items[job.tcp_out_pos..], 0) catch |err| switch (err) {
                error.WouldBlock => return self.armTcpWrite(job),
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

    fn onTcpReadable(self: *Resolver, fd: posix.fd_t) void {
        for (self.jobs.items) |job| {
            if (job.tcp_fd != fd) continue;
            var buf: [8192]u8 = undefined;
            const n = posix.recv(fd, &buf, 0) catch |err| switch (err) {
                error.WouldBlock => return,
                else => {
                    self.dropJob(job, .failed);
                    return;
                },
            };
            if (n == 0) {
                self.dropJob(job, .failed);
                return;
            }
            job.tcp_buf.appendSlice(self.alloc, buf[0..n]) catch {
                self.dropJob(job, .failed);
                return;
            };
            self.pumpTcpFrames(job);
            return;
        }
    }

    // -- responses --------------------------------------------------------

    /// T296: a response belongs to a query only when id AND qname AND
    /// qtype all match - a colliding id does not steer a different query.
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
            const n = posix.recv(self.fd, &buf, 0) catch |err| switch (err) {
                error.WouldBlock => return,
                // A refusal queued by an earlier datagram is consumed,
                // not charged to whichever job receives next.
                error.ConnectionRefused => {
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

        const msg = wire.parse(arena_state.allocator(), pkt) catch return self.dropJob(job, .failed);
        if (msg.truncated and !job.use_tcp) {
            job.use_tcp = true;
            job.tries = 0;
            self.tcpSend(job) catch return self.dropJob(job, .failed);
            self.armDeadline(job, TCP_TIMEOUT_MS) catch return self.dropJob(job, .failed);
            return;
        }

        switch (msg.rcode) {
            wire.RCODE_NOERROR => {},
            wire.RCODE_NXDOMAIN => {
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

        if (valid.len == 0) {
            self.cachePutNeg(job.pending_qname, job.pending_qtype, .nodata, msg);
        } else if (!job.is_raw) {
            // Chain responses fill the same RR cache raw queries use;
            // completeRaw covers the raw path on its own.
            self.cachePut(job.pending_qname, job.pending_qtype, valid);
        }

        if (job.is_raw) return self.completeRaw(job, filtered);
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
            out[i] = .{ .addr = t.addr, .host = host, .tlsa = tlsa, .is_direct_tls = t.is_direct_tls };
            built += 1;
        }
        return out;
    }

    /// Detach the answer RRs from the parse arena (deep copy of every
    /// name and rdata), cache them, and hand them to the query callback.
    fn completeRaw(self: *Resolver, job: *Job, msg: wire.Message) void {
        for (self.jobs.items, 0..) |j, i| {
            if (j == job) {
                _ = self.jobs.orderedRemove(i);
                break;
            }
        }
        self.cachePut(job.pending_qname, job.pending_qtype, msg.rrs);
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

    /// Cache key: the case-folded qname, a NUL, then the big-endian
    /// qtype. DNS names compare case-insensitively, so lookups keyed
    /// on the wire form must fold or a cased duplicate misses.
    fn cacheKey(buf: []u8, qname: []const u8, qtype: u16) ?[]u8 {
        if (qname.len + 3 > buf.len) return null;
        for (qname, 0..) |c, i| buf[i] = std.ascii.toLower(c);
        buf[qname.len] = 0;
        std.mem.writeInt(u16, buf[qname.len + 1 ..][0..2], qtype, .big);
        return buf[0 .. qname.len + 3];
    }

    fn cacheGet(self: *Resolver, qname: []const u8, qtype: u16) ?*CacheEnt {
        var key_buf: [280]u8 = undefined;
        const key = cacheKey(&key_buf, qname, qtype) orelse return null;
        const now = self.now_ms();
        for (self.cache.items) |*e| {
            if (std.mem.eql(u8, e.key, key) and e.expires_ms > now) return e;
        }
        return null;
    }

    /// Shared insert: folded key, CACHE_CAP bound with FIFO eviction.
    fn cacheInsert(self: *Resolver, qname: []const u8, qtype: u16, rrs: []wire.Rr, neg: NegKind, ttl_s: u32) void {
        var key_buf: [280]u8 = undefined;
        const kb = cacheKey(&key_buf, qname, qtype) orelse return;
        const key = self.alloc.dupe(u8, kb) catch return;
        const dup = self.dupRrs(rrs) catch {
            self.alloc.free(key);
            return;
        };
        if (self.cache.items.len >= CACHE_CAP) {
            const e = self.cache.orderedRemove(0);
            self.freeCacheEnt(e);
        }
        self.cache.append(self.alloc, .{ .key = key, .rrs = dup, .neg = neg, .expires_ms = self.now_ms() + @as(i64, ttl_s) * 1000 }) catch {
            self.alloc.free(key);
            self.freeRrs(dup);
        };
    }

    /// Store a second deep copy of the answer under (qname, qtype) with a
    /// TTL-derived expiry, capped at CACHE_TTL_CEIL_S; TTL 0 is not
    /// cached.
    fn cachePut(self: *Resolver, qname: []const u8, qtype: u16, rrs: []wire.Rr) void {
        const ttl = @min(minTtl(rrs), CACHE_TTL_CEIL_S);
        if (ttl == 0) return;
        self.cacheInsert(qname, qtype, rrs, .none, ttl);
    }

    /// Negative caching per RFC 2308: NXDOMAIN and NODATA answers live
    /// as long as the zone's SOA minimum (the last u32 of the SOA
    /// rdata), capped at the same ceiling. No SOA, no cache.
    fn cachePutNeg(self: *Resolver, qname: []const u8, qtype: u16, neg: NegKind, msg: wire.Message) void {
        const ttl = @min(soaMinimum(msg) orelse return, CACHE_TTL_CEIL_S);
        if (ttl == 0) return;
        self.cacheInsert(qname, qtype, &.{}, neg, ttl);
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

    fn freeCacheEnt(self: *Resolver, e: CacheEnt) void {
        self.alloc.free(e.key);
        if (e.rrs.len > 0) self.freeRrs(e.rrs);
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
            // that target is gone, not the whole resolution.
            .addr => {
                job.phase = .addr6;
                self.sendAddr(job, KIND_AAAA) catch return self.finishTarget(job);
            },
            .addr6 => self.nextTarget(job) catch return self.dropJob(job, .failed),
            .tlsa => {
                // TLSA NXDOMAIN keeps the target, just without DANE.
                self.emitTargets(job, &.{}) catch return self.dropJob(job, .failed);
                self.nextTarget(job) catch return self.dropJob(job, .failed);
            },
            .fallback_tlsa => self.complete(job),
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
                self.sendAddr(job, KIND_AAAA) catch return self.finishTarget(job);
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
                    self.sendTlsa(job) catch return self.finishTarget(job);
                    return;
                }
                self.emitTargets(job, &.{}) catch return self.dropJob(job, .failed);
                self.nextTarget(job) catch return self.dropJob(job, .failed);
            },
            .tlsa => {
                var tlsa_recs: std.ArrayList(dns.TlsaRecord) = .{};
                defer {
                    for (tlsa_recs.items) |r| self.alloc.free(r.association_data);
                    tlsa_recs.deinit(self.alloc);
                }
                for (msg.rrs) |rr| {
                    if (rr.rtype != KIND_TLSA) continue;
                    const rec = dns.parseTlsaRdata(rr.rdata, self.alloc) catch continue;
                    tlsa_recs.append(self.alloc, rec) catch continue;
                }
                self.emitTargets(job, tlsa_recs.items) catch return self.dropJob(job, .failed);
                self.nextTarget(job) catch return self.dropJob(job, .failed);
            },
            .fallback_tlsa => {
                var tlsa_recs: std.ArrayList(dns.TlsaRecord) = .{};
                defer {
                    for (tlsa_recs.items) |r| self.alloc.free(r.association_data);
                    tlsa_recs.deinit(self.alloc);
                }
                for (msg.rrs) |rr| {
                    if (rr.rtype != KIND_TLSA) continue;
                    const rec = dns.parseTlsaRdata(rr.rdata, self.alloc) catch continue;
                    tlsa_recs.append(self.alloc, rec) catch continue;
                }
                // The fallback targets share one host: the same TLSA
                // owner name covers every emitted address.
                for (job.targets.items) |*t| {
                    t.tlsa = self.dupeTlsa(tlsa_recs.items) catch &.{};
                }
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
                return self.dropJob(job, if (all_dot) .service_unavailable else .nxdomain);
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
    fn emitTargets(self: *Resolver, job: *Job, tlsa_recs: []dns.TlsaRecord) !void {
        const ent = &job.srv_list.items[job.srv_pos];
        const addrs = [2]?net.Address{ job.cur_addr6, job.cur_addr4 };
        for (addrs) |a| {
            const addr = a orelse continue;
            try self.emitTarget(job, ent, addr, tlsa_recs);
        }
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

    fn emitTarget(self: *Resolver, job: *Job, ent: *const SrvEnt, addr: net.Address, tlsa_recs: []dns.TlsaRecord) !void {
        if (job.targets.items.len >= TARGET_CAP) return;
        const host = try self.alloc.dupe(u8, ent.host);
        errdefer self.alloc.free(host);
        const tlsa = try self.dupeTlsa(tlsa_recs);
        try job.targets.append(self.alloc, .{ .addr = addr, .host = host, .tlsa = tlsa, .is_direct_tls = ent.is_direct_tls });
    }

    fn sendAddr(self: *Resolver, job: *Job, qtype: u16) !void {
        const ent = &job.srv_list.items[job.srv_pos];
        var buf: [280]u8 = undefined;
        const qname = std.fmt.bufPrint(&buf, "{s}", .{ent.host}) catch return error.NameTooLong;
        try self.sendQuery(job, qname, qtype);
    }

    fn sendTlsa(self: *Resolver, job: *Job) !void {
        const ent = &job.srv_list.items[job.srv_pos];
        var buf: [280]u8 = undefined;
        const qname = dns.tlsaQueryName(&buf, ent.port, ent.host) catch return error.NameTooLong;
        try self.sendQuery(job, qname, KIND_TLSA);
    }

    /// The no-SRV fallback asks the bare name for an address; called
    /// once per family so a dual-stack host yields both targets.
    fn sendFallback(self: *Resolver, job: *Job, qtype: u16) !void {
        var buf: [280]u8 = undefined;
        const qname = std.fmt.bufPrint(&buf, "{s}", .{job.name}) catch return error.NameTooLong;
        try self.sendQuery(job, qname, qtype);
    }

    /// Both fallback families have answered or failed: emit what
    /// arrived (AAAA first), answer nxdomain when nothing did, and
    /// report .failed only when a family query actually errored.
    fn finishFallback(self: *Resolver, job: *Job) void {
        if (job.cur_addr4 == null and job.cur_addr6 == null) {
            return self.dropJob(job, if (job.fallback_err) .failed else .nxdomain);
        }
        const addrs = [2]?net.Address{ job.cur_addr6, job.cur_addr4 };
        for (addrs) |a| {
            const addr = a orelse continue;
            const host = self.alloc.dupe(u8, job.name) catch return self.dropJob(job, .failed);
            job.targets.append(self.alloc, .{
                .addr = addr,
                .host = host,
                .tlsa = &.{},
                .is_direct_tls = false,
            }) catch {
                self.alloc.free(host);
                return self.dropJob(job, .failed);
            };
        }
        if (!job.want_tlsa) return self.complete(job);
        job.phase = .fallback_tlsa;
        var buf: [280]u8 = undefined;
        const qname = dns.tlsaQueryName(&buf, job.default_port, job.name) catch return self.dropJob(job, .failed);
        self.sendQuery(job, qname, KIND_TLSA) catch return self.dropJob(job, .failed);
    }

    fn freeJob(self: *Resolver, job: *Job) void {
        if (self.slots[job.slot] == job) self.slots[job.slot] = null;
        self.disarmDeadline(job);
        if (job.tcp_fd >= 0) posix.close(job.tcp_fd);
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
    return std.time.milliTimestamp();
}

fn readResolvConf(path: []const u8) !net.Address {
    var buf: [1024]u8 = undefined;
    const f = try std.fs.cwd().openFile(path, .{});
    defer f.close();
    const n = try f.read(&buf);
    var it = std.mem.tokenizeAny(u8, buf[0..n], " \t\n");
    while (it.next()) |tok| {
        if (!std.mem.eql(u8, tok, "nameserver")) continue;
        const addr = it.next() orelse break;
        return net.Address.parseIp(addr, 53) catch continue;
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
    /// additional-section A for an unrelated owner (J5 probe).
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
        const is_addr_q = q.qtype == wire.TYPE_A or q.qtype == wire.TYPE_AAAA;
        const family_fail = (q.qtype == wire.TYPE_A and self.a_fail.load(.monotonic)) or
            (q.qtype == wire.TYPE_AAAA and self.aaaa_fail.load(.monotonic));
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
        } else if (q.qtype == wire.TYPE_AAAA and self.a_aaaa.load(.monotonic)) {
            ancount = 1;
            appendAnswerHdr(alloc, &answers, wire.TYPE_AAAA, 60, 16);
            var v6: [16]u8 = .{0} ** 16;
            v6[15] = 1;
            answers.appendSlice(alloc, &v6) catch {};
        } else if (q.qtype == wire.TYPE_A) {
            ancount = 1;
            const ttl: u32 = if (self.a_ttl_highbit.load(.monotonic)) 0x8000_0000 else 60;
            appendAnswerHdr(alloc, &answers, wire.TYPE_A, ttl, 4);
            answers.appendSlice(alloc, &.{ 127, 0, 0, 1 }) catch {};
        } else if (q.qtype == wire.TYPE_TLSA) {
            _ = self.tlsa_recvd.fetchAdd(1, .monotonic);
            ancount = 1;
            appendAnswerHdr(alloc, &answers, wire.TYPE_TLSA, 60, 7);
            answers.appendSlice(alloc, &.{ 3, 0, 1, 0xDE, 0xAD, 0xBE, 0xEF }) catch {};
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

        if (self.nxdomain_all.load(.monotonic) or (ancount == 0 and self.soa_nodata.load(.monotonic))) {
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
        const flags: u16 = if (self.nxdomain_all.load(.monotonic)) 0x8183 else 0x8180;
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

test "dns-async: a failed query build leaves no freed job in the list (J1)" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));

    try std.testing.expectError(error.InvalidName, r.resolve("bad..name", .client, 5222, 1, true));
    try std.testing.expectError(error.InvalidName, r.query("bad..name", .a, 2));
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

test "dns-async: TCP frame length math and consumption (J2)" {
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

test "dns-async: a maximal frame ahead of the answer is consumed, not fatal (Q1)" {
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

test "dns-async: a deadline event batched with the reply does not touch a freed job (J3)" {
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

test "dns-async: query ids are drawn fresh per query, not sequential (J4)" {
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

test "dns-async: identically seeded resolvers still draw different ids (J4)" {
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

test "dns-async: authority and additional records are dropped, not cached (J5)" {
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

test "dns-async: the fallback address path honors the requested port (J7)" {
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

    fn onResolve(ctx_ptr: ?*anyopaque, key: usize, _: Status, res: ?Resolution) void {
        const self: *FreeingCtx = @ptrCast(@alignCast(ctx_ptr.?));
        if (self.calls < self.keys.len) self.keys[self.calls] = key;
        self.calls += 1;
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

test "dns-async: a '.' _xmpps answer falls through to _xmpp (Q3)" {
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
}

test "dns-async: identical resolves merge into one job (J6)" {
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

test "dns-async: over-cap requests queue and cancel detaches (J6)" {
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

test "dns-async: cache keys fold case; TTL 0 stays off the wire (J8)" {
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

test "dns-async: NXDOMAIN and NODATA are negative-cached from the SOA minimum (J8)" {
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

test "dns-async: a shared job notifies only its remaining waiters (J6)" {
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

test "dns-async: cancel inside a sibling callback suppresses its callback (Q2)" {
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

test "dns-async: a nested completion inside a callback keeps sibling cancel (R3)" {
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
        .is_direct_tls = false,
    }) catch unreachable;
    r.onChainDeadline(job);

    try std.testing.expectEqual(@as(usize, 1), ctx.calls[1]);
    try std.testing.expectEqual(@as(usize, 1), ctx.calls[9]);
    try std.testing.expectEqual(@as(usize, 0), ctx.calls[2]);
}

test "dns-async: cancel purges the key's queued entry before promoting (Q2)" {
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

test "dns-async: a failed launch inside promoteWait answers .failed (Q2)" {
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

test "dns-async: the 65th cache entry evicts the oldest, forcing wire" {
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
    var name_buf: [32]u8 = undefined;
    for (0..CACHE_CAP + 1) |i| {
        const n = std.fmt.bufPrint(&name_buf, "c{d}.test", .{i}) catch unreachable;
        r.cachePut(n, KIND_A, &rrs);
    }
    try std.testing.expectEqual(@as(usize, CACHE_CAP), r.cache.items.len);
    try std.testing.expect(r.cacheGet("c0.test", KIND_A) == null);
    try std.testing.expect(r.cacheGet("c64.test", KIND_A) != null);

    // c0 was evicted FIFO: asking for it again costs a wire round trip.
    const wired = srv.udp_recvd.load(.monotonic);
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });
    try r.query("c0.test", .a, 999);
    var spins: usize = 0;
    while (ctx.status == null and spins < 100) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    if (ctx.raw) |*res| {
        var v = res.*;
        v.deinitOn(std.testing.allocator);
    }
    try std.testing.expect(srv.udp_recvd.load(.monotonic) > wired);
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
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
    var ch = [1]posix.Kevent{.{
        .ident = @intCast(fd),
        .filter = std.c.EVFILT.WRITE,
        .flags = std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT,
        .fflags = 0,
        .data = 0,
        .udata = 0,
    }};
    _ = posix.kevent(r.kq, &ch, &.{}, null) catch {};
    posix.connect(fd, &r.server.any, r.server.getOsSockLen()) catch {};
    job.tcp_fd = fd;

    var spins: usize = 0;
    while (ctx.status == null and spins < 100) : (spins += 1) r.step(50);
    try std.testing.expectEqual(Status.failed, ctx.status.?);
    try std.testing.expectEqual(@as(usize, 0), r.jobs.items.len);
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

test "dns-async: a SERVFAIL on one SRV target skips only that target (Q4)" {
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

test "dns-async: an AAAA SERVFAIL keeps the resolved A address (R2)" {
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

test "dns-async: an A SERVFAIL still yields the AAAA address (R2)" {
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

test "dns-async: parsed SRV entries are capped at 32 (Q4)" {
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

test "dns-async: the fallback path asks AAAA too and emits v6 first (Q4)" {
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

test "dns-async: a stale deadline cannot hit a re-used slot (Q6)" {
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

var fake_now: i64 = 0;
fn fakeNow() i64 {
    return fake_now;
}

test "dns-async: a cache entry past its TTL is a miss (Q6)" {
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
    try std.testing.expect(r.cacheGet("ttl.test", KIND_A) == null);
}

test "dns-async: SRV targets come back in RFC 2782 priority order (Q6)" {
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

test "dns-async: a client resolve asks only the client SRV prefixes (Q6)" {
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
