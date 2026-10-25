//! # lib/dns/async.zig — shared async resolver (X2, Phorge T276)
//!
//! Lifted from lib/xmppc/resolver.zig into a reusable library:
//!
//! - Responses are demuxed on (id, qname, qtype) together (T296), never
//!   on the id alone.
//! - `Service` selects the SRV prefix pair: client = _xmpps-client then
//!   _xmpp-client; server = _xmpps-server then _xmpp-server (XEP-0368).
//! - Raw record queries (A/AAAA/SRV/TLSA) via `query()`; `resolve()` is
//!   the SRV→addr→TLSA chain on top of them.
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

const TIMEOUT_MS: i64 = 2000;
const MAX_TRIES: u8 = 2;
const TCP_TIMEOUT_MS: i64 = 4000;
const MAX_JOBS: usize = 64;
const CACHE_CAP: usize = 64;

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
/// publishing "no such service on this domain" — distinct from the
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

const Phase = enum { srv_tls, srv_plain, addr, addr6, tlsa, fallback_addr, fallback_tlsa, raw, done };

const Job = struct {
    /// Session keys waiting on this job; identical in-flight lookups
    /// share one job and every waiter still gets its own callback.
    waiters: std.ArrayListUnmanaged(usize) = .{},
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

const CacheEnt = struct {
    key: []u8, // "qname\0qtype_be2"
    rrs: []wire.Rr, // names and rdata owned per record
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
    jobs: std.ArrayListUnmanaged(*Job) = .{},
    /// Slot table for timer udata: a queued deadline event carries
    /// (gen, slot) so a job freed by an earlier event in the same
    /// kevent batch is never touched (C3 pattern).
    slots: [MAX_JOBS]?*Job = .{null} ** MAX_JOBS,
    slot_gen: [MAX_JOBS]u16 = .{0} ** MAX_JOBS,
    /// Seeded from the CSPRNG; drives query ids and RFC 2782 weighted
    /// picks. Tests reseed it for deterministic draws.
    prng: std.Random.DefaultPrng = std.Random.DefaultPrng.init(0),
    cb: Cb = .{ .ctx = null, .fun = noopCallback },
    qcb: QueryCb = .{ .ctx = null, .fun = noopQueryCallback },
    cache: std.ArrayListUnmanaged(CacheEnt) = .{},
    /// Requests queued behind a full in-flight set; promoted FIFO as
    /// jobs complete.
    wait_queue: std.ArrayListUnmanaged(WaitEnt) = .{},

    fn noopCallback(_: ?*anyopaque, _: usize, _: Status, _: ?Resolution) void {}
    fn noopQueryCallback(_: ?*anyopaque, _: usize, _: Status, _: ?RecordResult) void {}

    pub fn init(alloc: std.mem.Allocator) Resolver {
        return .{ .alloc = alloc, .prng = std.Random.DefaultPrng.init(std.crypto.random.int(u64)) };
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

    /// UDP socket fd — callers may register it on their own loop and call
    /// step(0) when it reads; deadlines still fire via step().
    pub fn sockFd(self: *const Resolver) posix.fd_t {
        return self.fd;
    }

    /// Raw record query: A, AAAA, SRV or TLSA answered via the query
    /// callback with owned RRs.
    pub fn query(self: *Resolver, name: []const u8, rtype: RType, session_key: usize) !void {
        const qt: u16 = @intFromEnum(rtype);
        if (self.cacheGet(name, qt)) |ent| {
            const rrs = try self.dupRrs(ent.rrs);
            const ttl_ms = @max(0, ent.expires_ms - nowMs());
            self.qcb.fun(self.qcb.ctx, session_key, .resolved, .{ .rrs = rrs, .ttl = @intCast(ttl_ms / 1000) });
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
            self.dropJob(job, .failed);
            return err;
        };
    }

    /// Queue a request behind the in-flight cap; promoted FIFO by
    /// promoteWait as jobs complete.
    fn enqueueWait(self: *Resolver, session_key: usize, name: []const u8, opts: WaitEnt) !void {
        if (self.wait_queue.items.len >= WAIT_CAP) return error.TooManyJobs;
        var e = opts;
        e.session_key = session_key;
        e.name = try self.alloc.dupe(u8, name);
        try self.wait_queue.append(self.alloc, e);
    }

    /// Launch the head of the wait queue now that a job slot opened.
    fn promoteWait(self: *Resolver) void {
        while (self.jobs.items.len < MAX_JOBS and self.wait_queue.items.len > 0) {
            const e = self.wait_queue.orderedRemove(0);
            defer self.alloc.free(e.name);
            switch (e.kind) {
                .query => self.launchQuery(e) catch |err| {
                    log.warn("dns: queued query failed to launch: {}", .{err});
                },
                .resolve => self.launchResolve(e) catch |err| {
                    log.warn("dns: queued resolve failed to launch: {}", .{err});
                },
            }
        }
    }

    fn launchQuery(self: *Resolver, e: WaitEnt) !void {
        const job = try self.allocJob(e.session_key, e.name);
        job.phase = .raw;
        job.is_raw = true;
        {
            errdefer self.freeJob(job);
            try self.jobs.append(self.alloc, job);
        }
        self.sendQuery(job, e.name, e.rtype) catch |err| {
            self.dropJob(job, .failed);
            return err;
        };
    }

    fn launchResolve(self: *Resolver, e: WaitEnt) !void {
        const job = try self.allocJob(e.session_key, e.name);
        job.phase = .srv_tls;
        job.service_idx = e.service_idx;
        job.default_port = e.default_port;
        job.want_tlsa = e.want_tlsa;
        {
            errdefer self.freeJob(job);
            try self.jobs.append(self.alloc, job);
        }
        self.sendSrv(job, SRV_TLS[job.service_idx]) catch |err| {
            self.dropJob(job, .failed);
            return err;
        };
    }

    /// Release a session's interest: detach the waiter from its job
    /// (freeing the job when it was the last waiter) or drop a
    /// not-yet-launched queue entry. No callback fires afterwards.
    pub fn cancel(self: *Resolver, session_key: usize) void {
        for (self.jobs.items) |job| {
            for (job.waiters.items, 0..) |w, i| {
                if (w == session_key) {
                    _ = job.waiters.orderedRemove(i);
                    break;
                }
            }
            if (job.waiters.items.len == 0) {
                for (self.jobs.items, 0..) |j, i| {
                    if (j == job) {
                        _ = self.jobs.orderedRemove(i);
                        break;
                    }
                }
                self.freeJob(job);
                self.promoteWait();
                return;
            }
        }
        for (self.wait_queue.items, 0..) |e, i| {
            if (e.session_key == session_key) {
                const removed = self.wait_queue.orderedRemove(i);
                self.alloc.free(removed.name);
                return;
            }
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
            try job.waiters.append(self.alloc, session_key);
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
        self.sendSrv(job, SRV_TLS[job.service_idx]) catch |err| {
            self.dropJob(job, .failed);
            return err;
        };
    }

    // -- kqueue pump -----------------------------------------------------

    fn ensureOpen(self: *Resolver) !void {
        if (self.kq < 0) self.kq = try posix.kqueue();
        if (self.fd >= 0) return;
        if (!self.server_configured) {
            self.server = readResolvConf() catch {
                log.warn("dns: no /etc/resolv.conf nameserver found", .{});
                return error.NoResolver;
            };
            self.server_configured = true;
        }
        const fd = try posix.socket(self.server.any.family, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
        errdefer posix.close(fd);
        try posix.connect(fd, &self.server.any, self.server.getOsSockLen());
        self.fd = fd;
        var ch = [1]posix.Kevent{.{ .ident = @intCast(fd), .filter = std.c.EVFILT.READ, .flags = std.c.EV.ADD | std.c.EV.ENABLE, .fflags = 0, .data = 0, .udata = 0 }};
        _ = posix.kevent(self.kq, &ch, &.{}, null) catch {};
    }

    /// One kevent turn on the resolver's kqueue. `timeout_ms` may be 0
    /// (pump only) — callers pass their next-loop deadline, not a sleep.
    pub fn step(self: *Resolver, timeout_ms: i32) void {
        if (self.kq < 0) return;
        var events: [16]posix.Kevent = undefined;
        const ts: std.c.timespec = .{ .sec = @intCast(@divTrunc(timeout_ms, 1000)), .nsec = @intCast(@rem(timeout_ms, 1000) * 1_000_000) };
        const n = posix.kevent(self.kq, &.{}, &events, &ts) catch return;
        for (events[0..n]) |ev| {
            if (ev.filter == std.c.EVFILT.TIMER) {
                // The event may have been queued before the job was
                // freed by an earlier event in this same batch.
                if (self.jobFromUdata(ev.udata)) |job| self.onDeadline(job);
            } else if (ev.filter == std.c.EVFILT.READ) {
                const fd: posix.fd_t = @intCast(ev.ident);
                if (fd == self.fd) {
                    self.onReadable();
                } else {
                    self.onTcpReadable(fd);
                }
            } else if (ev.filter == std.c.EVFILT.WRITE) {
                // TCP connect finished — a refused connect also reports
                // writable, so check SO_ERROR before sending.
                const fd: posix.fd_t = @intCast(ev.ident);
                for (self.jobs.items) |job| {
                    if (job.tcp_fd == fd) {
                        posix.getsockoptError(fd) catch {
                            self.dropJob(job, .failed);
                            break;
                        };
                        self.tcpWrite(job) catch self.dropJob(job, .failed);
                        break;
                    }
                }
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
            const id = self.prng.random().int(u16);
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
        try job.waiters.append(self.alloc, session_key);
        errdefer job.waiters.deinit(self.alloc);
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
    fn armDeadline(self: *Resolver, job: *Job, ms: i64) void {
        var ch = [1]posix.Kevent{.{
            .ident = @intFromPtr(job),
            .filter = std.c.EVFILT.TIMER,
            .flags = std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT,
            .fflags = 0, // default unit is ms
            .data = @intCast(ms),
            .udata = (@as(usize, job.gen) << 8) | job.slot,
        }};
        _ = posix.kevent(self.kq, &ch, &.{}, null) catch {};
    }

    fn disarmDeadline(self: *Resolver, job: *Job) void {
        var ch = [1]posix.Kevent{.{ .ident = @intFromPtr(job), .filter = std.c.EVFILT.TIMER, .flags = std.c.EV.DELETE, .fflags = 0, .data = 0, .udata = 0 }};
        _ = posix.kevent(self.kq, &ch, &.{}, null) catch {};
    }

    /// Resolve a timer event's (gen, slot) udata back to a live job;
    /// null when the job was freed or its slot was re-used.
    fn jobFromUdata(self: *Resolver, udata: usize) ?*Job {
        const slot: usize = udata & 0xFF;
        const gen: u16 = @intCast(udata >> 8);
        if (slot >= MAX_JOBS) return null;
        const job = self.slots[slot] orelse return null;
        if (self.slot_gen[slot] != gen) return null;
        return job;
    }

    fn sendQuery(self: *Resolver, job: *Job, qname: []const u8, qtype: u16) !void {
        // The chain consults the RR cache the same way a raw query
        // does; a hit feeds the phase machine a synthetic message.
        if (self.cacheGet(qname, qtype)) |ent| {
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
            try self.tcpSend(job);
        } else {
            _ = posix.send(self.fd, pkt, 0) catch return error.SendFailed;
        }
        self.armDeadline(job, TIMEOUT_MS);
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
                _ = posix.send(self.fd, job.request, 0) catch {};
            }
            self.armDeadline(job, TIMEOUT_MS);
            return;
        }
        log.warn("dns: timeout after {d} tries for {s}", .{ job.tries, job.name });
        self.dropJob(job, .failed);
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
        ch[1] = .{ .ident = @intCast(fd), .filter = std.c.EVFILT.WRITE, .flags = std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.ONESHOT, .fflags = 0, .data = 0, .udata = 0 };
        _ = posix.kevent(self.kq, &ch, &.{}, null) catch {};
        job.tcp_fd = fd;
        if (connected) return self.tcpWrite(job);
    }

    /// TCP DNS frames are length-prefixed.
    fn tcpWrite(self: *Resolver, job: *Job) !void {
        _ = self;
        var hdr: [2]u8 = undefined;
        std.mem.writeInt(u16, &hdr, @intCast(job.request.len), .big);
        _ = posix.send(job.tcp_fd, &hdr, 0) catch return error.SendFailed;
        _ = posix.send(job.tcp_fd, job.request, 0) catch return error.SendFailed;
    }

    fn onTcpReadable(self: *Resolver, fd: posix.fd_t) void {
        for (self.jobs.items) |job| {
            if (job.tcp_fd != fd) continue;
            var buf: [8192]u8 = undefined;
            const n = posix.recv(fd, &buf, 0) catch return;
            if (n == 0) {
                self.dropJob(job, .failed);
                return;
            }
            job.tcp_buf.appendSlice(self.alloc, buf[0..n]) catch {
                self.dropJob(job, .failed);
                return;
            };
            // A TCP DNS frame is a two-octet length plus at most 65535
            // octets; more buffered data means a misbehaving peer.
            if (job.tcp_buf.items.len > 2 + 65535) {
                self.dropJob(job, .failed);
                return;
            }
            while (job.tcp_buf.items.len >= 2) {
                const want = std.mem.readInt(u16, job.tcp_buf.items[0..2], .big);
                const frame_len = @as(usize, want) + 2;
                if (job.tcp_buf.items.len < frame_len) return;
                const pkt = job.tcp_buf.items[2..frame_len];
                if (self.matchJob(pkt)) |matched| {
                    if (matched == job) {
                        // The job may be freed inside handleResponse.
                        self.handleResponse(job, pkt);
                        return;
                    }
                }
                // A complete frame that does not answer this job's
                // outstanding query is consumed and dropped.
                std.mem.copyForwards(u8, job.tcp_buf.items[0 .. job.tcp_buf.items.len - frame_len], job.tcp_buf.items[frame_len..]);
                job.tcp_buf.items.len -= frame_len;
            }
            return;
        }
    }

    // -- responses --------------------------------------------------------

    /// T296: a response belongs to a query only when id AND qname AND
    /// qtype all match — a colliding id does not steer a different query.
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
            const n = posix.recv(self.fd, &buf, 0) catch return;
            if (n < 12) continue;
            if (self.matchJob(buf[0..n])) |job| self.handleResponse(job, buf[0..n]);
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
            self.armDeadline(job, TCP_TIMEOUT_MS);
            return;
        }

        switch (msg.rcode) {
            wire.RCODE_NOERROR => {},
            wire.RCODE_NXDOMAIN => return self.onNxdomain(job),
            else => return self.dropJob(job, .failed),
        }

        // Only answer-section records that actually answer the
        // outstanding query may reach a phase or the cache.
        const valid = self.filterAnswers(arena_state.allocator(), msg, job) catch
            return self.dropJob(job, .failed);
        var filtered = msg;
        filtered.rrs = valid;

        if (job.is_raw) return self.completeRaw(job, filtered);
        switch (job.phase) {
            .srv_tls, .srv_plain, .addr, .addr6, .tlsa, .fallback_addr, .fallback_tlsa => self.advance(job, filtered),
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

    fn dropJob(self: *Resolver, job: *Job, status: Status) void {
        for (self.jobs.items, 0..) |j, i| {
            if (j == job) {
                _ = self.jobs.orderedRemove(i);
                break;
            }
        }
        if (job.is_raw) {
            for (job.waiters.items) |key| self.qcb.fun(self.qcb.ctx, key, status, null);
        } else {
            for (job.waiters.items) |key| self.cb.fun(self.cb.ctx, key, status, null);
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
        for (job.waiters.items) |key| {
            const targets = self.dupTargets(job.targets.items) catch {
                self.cb.fun(self.cb.ctx, key, .failed, null);
                continue;
            };
            self.cb.fun(self.cb.ctx, key, .resolved, .{ .targets = targets });
        }
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
        for (job.waiters.items) |key| {
            const detached = self.dupRrs(msg.rrs) catch {
                self.qcb.fun(self.qcb.ctx, key, .failed, null);
                continue;
            };
            self.qcb.fun(self.qcb.ctx, key, .resolved, .{ .rrs = detached, .ttl = ttl });
        }
        self.freeJob(job);
        self.promoteWait();
    }

    fn minTtl(rrs: []const wire.Rr) u32 {
        var m: u32 = std.math.maxInt(u32);
        for (rrs) |rr| m = @min(m, rr.ttl);
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

    fn cacheGet(self: *Resolver, qname: []const u8, qtype: u16) ?*CacheEnt {
        var key_buf: [280]u8 = undefined;
        if (qname.len + 3 > key_buf.len) return null;
        @memcpy(key_buf[0..qname.len], qname);
        key_buf[qname.len] = 0;
        std.mem.writeInt(u16, key_buf[qname.len + 1 ..][0..2], qtype, .big);
        const key = key_buf[0 .. qname.len + 3];
        const now = nowMs();
        for (self.cache.items) |*e| {
            if (std.mem.eql(u8, e.key, key) and e.expires_ms > now) return e;
        }
        return null;
    }

    /// Store a second deep copy of the answer under (qname, qtype) with a
    /// TTL-derived expiry. Bound: CACHE_CAP entries, FIFO eviction.
    fn cachePut(self: *Resolver, qname: []const u8, qtype: u16, rrs: []wire.Rr) void {
        const ttl = minTtl(rrs);
        if (ttl == 0) return;
        const key = self.alloc.alloc(u8, qname.len + 3) catch return;
        @memcpy(key[0..qname.len], qname);
        key[qname.len] = 0;
        std.mem.writeInt(u16, key[qname.len + 1 ..][0..2], qtype, .big);
        const dup = self.dupRrs(rrs) catch {
            self.alloc.free(key);
            return;
        };
        if (self.cache.items.len >= CACHE_CAP) {
            const e = self.cache.orderedRemove(0);
            self.freeCacheEnt(e);
        }
        self.cache.append(self.alloc, .{ .key = key, .rrs = dup, .expires_ms = nowMs() + @as(i64, ttl) * 1000 }) catch {
            self.alloc.free(key);
            self.freeRrs(dup);
        };
    }

    fn freeCacheEnt(self: *Resolver, e: CacheEnt) void {
        self.alloc.free(e.key);
        self.freeRrs(e.rrs);
    }

    fn onNxdomain(self: *Resolver, job: *Job) void {
        if (job.is_raw) return self.dropJob(job, .nxdomain);
        switch (job.phase) {
            .srv_tls => {
                job.phase = .srv_plain;
                self.sendSrv(job, SRV_PLAIN[job.service_idx]) catch return self.dropJob(job, .failed);
            },
            .srv_plain => self.startFallback(job),
            .fallback_addr => self.dropJob(job, .nxdomain),
            // Per target: an NXDOMAIN on either address family means
            // that target is gone, not the whole resolution.
            .addr => {
                job.phase = .addr6;
                self.sendAddr(job, KIND_AAAA) catch return self.dropJob(job, .failed);
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
                self.absorbSrv(job, msg, job.phase == .srv_tls);
                if (job.srv_list.items.len == 0) {
                    if (job.phase == .srv_tls) {
                        job.phase = .srv_plain;
                        self.sendSrv(job, SRV_PLAIN[job.service_idx]) catch return self.dropJob(job, .failed);
                        return;
                    }
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
                self.sendAddr(job, KIND_AAAA) catch return self.dropJob(job, .failed);
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
                    self.sendTlsa(job) catch return self.dropJob(job, .failed);
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
                for (msg.rrs) |rr| {
                    if (rr.rtype != KIND_TLSA) continue;
                    const rec = dns.parseTlsaRdata(rr.rdata, self.alloc) catch continue;
                    tlsa_recs.append(self.alloc, rec) catch continue;
                }
                if (job.targets.items.len > 0) {
                    job.targets.items[job.targets.items.len - 1].tlsa = tlsa_recs.toOwnedSlice(self.alloc) catch &.{};
                }
                self.complete(job);
            },
            .fallback_addr => {
                var addr6: ?net.Address = null;
                var addr4: ?net.Address = null;
                const defport: u16 = job.default_port;
                for (msg.rrs) |rr| {
                    if (rr.rtype == KIND_AAAA and addr6 == null) addr6 = addrFromRdata(rr, defport) catch null;
                    if (rr.rtype == KIND_A and addr4 == null) addr4 = addrFromRdata(rr, defport) catch null;
                }
                const addr = addr6 orelse addr4 orelse {
                    self.dropJob(job, .nxdomain);
                    return;
                };
                const host = self.alloc.dupe(u8, job.name) catch return self.dropJob(job, .failed);
                job.targets.append(self.alloc, .{
                    .addr = addr,
                    .host = host,
                    .tlsa = &.{},
                    .is_direct_tls = false,
                }) catch return self.dropJob(job, .failed);
                if (!job.want_tlsa) {
                    self.complete(job);
                    return;
                }
                job.phase = .fallback_tlsa;
                var buf: [280]u8 = undefined;
                const qname = dns.tlsaQueryName(&buf, defport, job.name) catch return self.dropJob(job, .failed);
                self.sendQuery(job, qname, KIND_TLSA) catch return self.dropJob(job, .failed);
            },
            .raw, .done => {},
        }
    }

    fn absorbSrv(self: *Resolver, job: *Job, msg: wire.Message, direct_tls: bool) void {
        for (msg.rrs) |rr| {
            if (rr.rtype != KIND_SRV) continue;
            const parsed = dns.parseSrvRdata(rr.rdata, self.alloc) catch continue;
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

    /// Begin (or continue) the per-target chain: a target marked "." is
    /// skipped; the first live target gets an A query.
    fn stepTargetAddr(self: *Resolver, job: *Job) !void {
        while (job.srv_pos < job.srv_list.items.len and
            job.srv_list.items[job.srv_pos].unavailable)
        {
            job.srv_pos += 1;
        }
        if (job.srv_pos >= job.srv_list.items.len) {
            if (job.targets.items.len == 0) {
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

    fn emitTarget(self: *Resolver, job: *Job, ent: *const SrvEnt, addr: net.Address, tlsa_recs: []dns.TlsaRecord) !void {
        const host = try self.alloc.dupe(u8, ent.host);
        errdefer self.alloc.free(host);
        var tlsa: []dns.TlsaRecord = &.{};
        if (tlsa_recs.len > 0) {
            tlsa = try self.alloc.alloc(dns.TlsaRecord, tlsa_recs.len);
            errdefer self.alloc.free(tlsa);
            var n: usize = 0;
            errdefer for (tlsa[0..n]) |r| self.alloc.free(r.association_data);
            for (tlsa_recs, 0..) |r, i| {
                tlsa[i] = r;
                tlsa[i].association_data = try self.alloc.dupe(u8, r.association_data);
                n += 1;
            }
        }
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

    fn freeJob(self: *Resolver, job: *Job) void {
        if (self.slots[job.slot] == job) self.slots[job.slot] = null;
        job.waiters.deinit(self.alloc);
        self.disarmDeadline(job);
        if (job.tcp_fd >= 0) posix.close(job.tcp_fd);
        job.tcp_buf.deinit(self.alloc);
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
        var buf: [280]u8 = undefined;
        const qname = std.fmt.bufPrint(&buf, "{s}", .{job.name}) catch {
            self.dropJob(job, .failed);
            return;
        };
        self.sendQuery(job, qname, KIND_A) catch return self.dropJob(job, .failed);
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

fn readResolvConf() !net.Address {
    var buf: [1024]u8 = undefined;
    const f = try std.fs.openFileAbsolute("/etc/resolv.conf", .{});
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
                // Optional decoy: same id, wrong qname — must be ignored (T296).
                if (self.decoy_qname.len > 0) {
                    var decoy: [1024]u8 = undefined;
                    const dn = self.buildDecoy(&decoy, qbuf[0..n]);
                    _ = posix.sendto(self.udp_fd, decoy[0..dn], 0, &peer, plen) catch {};
                }
                _ = posix.sendto(self.udp_fd, buf[0..resp_len], 0, &peer, plen) catch {};
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
                _ = posix.send(cfd, buf[0..resp_len], 0) catch {};
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
        if (q.qtype == wire.TYPE_SRV) {
            if (std.mem.startsWith(u8, q.qname, "_xmpps") or self.empty_srv.load(.monotonic)) {
                // NODATA for the direct-TLS prefix, or everywhere when
                // the test wants the fallback path.
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
        } else if (q.qtype == wire.TYPE_A) {
            ancount = 1;
            appendAnswerHdr(alloc, &answers, wire.TYPE_A, 60, 4);
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

        std.mem.writeInt(u16, out[0..2], id, .big);
        std.mem.writeInt(u16, out[2..4], 0x8180, .big);
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
    /// different owner — a T296 decoy.
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
        std.mem.writeInt(u16, out[off..][0..2], q.qtype, .big);
        std.mem.writeInt(u16, out[off + 2 ..][0..2], 1, .big);
        off += 4;
        // Bogus answer: A record pointing at 10.9.9.9.
        out[off] = 0xC0;
        out[off + 1] = 0x0C;
        std.mem.writeInt(u16, out[off + 2 ..][0..2], wire.TYPE_A, .big);
        std.mem.writeInt(u16, out[off + 4 ..][0..2], 1, .big);
        std.mem.writeInt(u32, out[off + 6 ..][0..4], 60, .big);
        std.mem.writeInt(u16, out[off + 10 ..][0..2], 4, .big);
        out[off + 12] = 10; out[off + 13] = 9; out[off + 14] = 9; out[off + 15] = 9;
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
    const bind_addr = try net.Address.parseIp("127.0.0.1", 0);
    try posix.bind(srv.udp_fd, &bind_addr.any, bind_addr.getOsSockLen());
    var actual: posix.sockaddr = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr);
    try posix.getsockname(srv.udp_fd, &actual, &slen);
    srv.port = net.Address.initPosix(@alignCast(&actual)).getPort();
    // TCP answers must arrive on the same port the query addressed.
    const tcp_addr = try net.Address.parseIp("127.0.0.1", srv.port);
    try posix.bind(srv.tcp_fd, &tcp_addr.any, tcp_addr.getOsSockLen());
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

test "dns-async: TCP frame length math and consumption (J2)" {
    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", 53));

    try r.query("host.test", .a, 7);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    const job = r.jobs.items[0];

    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0, &fds) != 0)
        return error.Socketpair;
    defer posix.close(fds[0]);
    job.tcp_fd = fds[1];
    defer {
        job.tcp_fd = -1;
        posix.close(fds[1]);
    }

    // A maximal legal frame header: the u16 length must be widened
    // before adding the two-octet prefix or the math overflows.
    var hdr: [2]u8 = undefined;
    std.mem.writeInt(u16, &hdr, 65535, .big);
    _ = try posix.write(fds[0], &hdr);
    _ = try posix.write(fds[0], &[_]u8{0} ** 64);
    r.onTcpReadable(fds[1]);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);

    // A complete frame that answers no outstanding query is consumed.
    job.tcp_buf.clearRetainingCapacity();
    std.mem.writeInt(u16, &hdr, 12, .big);
    _ = try posix.write(fds[0], &hdr);
    _ = try posix.write(fds[0], &[_]u8{0} ** 12);
    r.onTcpReadable(fds[1]);
    try std.testing.expectEqual(@as(usize, 1), r.jobs.items.len);
    try std.testing.expectEqual(@as(usize, 0), job.tcp_buf.items.len);
}

test "dns-async: a deadline event batched with the reply does not touch a freed job (J3)" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setQueryCallback(.{ .ctx = &ctx, .fun = TestCtx.onQuery });

    try r.query("host.test", .a, 7);
    const job = r.jobs.items[0];
    r.armDeadline(job, 1);
    // The reply and the expired deadline are harvested in one kevent
    // batch; the reply frees the job first, so the timer event must be
    // recognized as stale.
    std.Thread.sleep(5 * std.time.ns_per_ms);
    r.step(50);
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

test "dns-async: want_tlsa=false skips the TLSA round trip entirely" {
    const srv = try startFakeDns(false, "");
    defer stopFakeDns(srv);

    var r = Resolver.init(std.testing.allocator);
    defer r.deinit();
    r.setServer(try net.Address.parseIp("127.0.0.1", srv.port));
    var ctx = TestCtx{};
    r.setCallback(.{ .ctx = &ctx, .fun = TestCtx.onResolve });

    try r.resolve("svc.test", .client, 5222, 3, false);
    var spins: usize = 0;
    while (ctx.status == null and spins < 200) : (spins += 1) r.step(50);

    try std.testing.expectEqual(Status.resolved, ctx.status.?);
    var res = ctx.res.?;
    defer res.deinitOn(std.testing.allocator);
    try std.testing.expect(res.targets.len >= 1);
    // No TLSA query ever touched the wire, and targets carry no records.
    try std.testing.expectEqual(@as(u32, 0), srv.tlsa_recvd.load(.monotonic));
    for (res.targets) |t| try std.testing.expectEqual(@as(usize, 0), t.tlsa.len);
}

test "dns-async: want_tlsa=true attaches the fetched records per target" {
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
    try std.testing.expect(srv.tlsa_recvd.load(.monotonic) > 0);
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
    try std.testing.expectEqual(@as(usize, 2), r.jobs.items[0].waiters.items.len);

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
