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

pub const Status = enum { resolved, nxdomain, failed };

pub const Cb = struct {
    ctx: ?*anyopaque,
    fun: *const fn (ctx: ?*anyopaque, session_key: usize, status: Status, res: ?Resolution) void,
};

/// Completion for raw record queries.
pub const QueryCb = struct {
    ctx: ?*anyopaque,
    fun: *const fn (ctx: ?*anyopaque, session_key: usize, status: Status, res: ?RecordResult) void,
};

const Phase = enum { srv_tls, srv_plain, addr, tlsa, fallback_addr, fallback_tlsa, raw, done };

const Job = struct {
    session_key: usize,
    name: []const u8, // owned
    phase: Phase,
    service_idx: u8 = 0,
    is_raw: bool = false,
    /// Index into the resolver's slot table; paired with `gen` so a
    /// queued timer event can be told apart from a live job.
    slot: u8 = 0,
    gen: u16 = 0,

    srv_list: std.ArrayListUnmanaged(SrvEnt) = .{},
    srv_pos: usize = 0,

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
};

const CacheEnt = struct {
    key: []u8, // "qname\0qtype_be2"
    rrs: []wire.Rr, // names and rdata owned per record
    expires_ms: i64,
};

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
    next_id: u16 = 0,
    cb: Cb = .{ .ctx = null, .fun = noopCallback },
    qcb: QueryCb = .{ .ctx = null, .fun = noopQueryCallback },
    cache: std.ArrayListUnmanaged(CacheEnt) = .{},

    fn noopCallback(_: ?*anyopaque, _: usize, _: Status, _: ?Resolution) void {}
    fn noopQueryCallback(_: ?*anyopaque, _: usize, _: Status, _: ?RecordResult) void {}

    pub fn init(alloc: std.mem.Allocator) Resolver {
        return .{ .alloc = alloc, .next_id = std.crypto.random.int(u16) };
    }

    pub fn deinit(self: *Resolver) void {
        for (self.jobs.items) |j| self.freeJob(j);
        self.jobs.deinit(self.alloc);
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
        if (self.jobs.items.len >= MAX_JOBS) return error.TooManyJobs;
        const job = try self.allocJob(session_key, name);
        job.phase = .raw;
        job.is_raw = true;
        errdefer self.freeJob(job);
        try self.sendQuery(job, name, qt);
        try self.jobs.append(self.alloc, job);
    }

    /// SRV chain resolve. Literal IPs complete synchronously with one
    /// target (no UDP traffic).
    pub fn resolve(self: *Resolver, name: []const u8, service: Service, default_port: u16, session_key: usize) !void {
        if (net.Address.parseIp(name, default_port)) |addr| {
            const t = Target{ .addr = addr, .host = try self.alloc.dupe(u8, name), .tlsa = &.{}, .is_direct_tls = false };
            const list = try self.alloc.alloc(Target, 1);
            list[0] = t;
            self.cb.fun(self.cb.ctx, session_key, .resolved, .{ .targets = list });
            return;
        } else |_| {}

        try self.ensureOpen();
        if (self.jobs.items.len >= MAX_JOBS) return error.TooManyJobs;
        const job = try self.allocJob(session_key, name);
        job.phase = .srv_tls;
        job.service_idx = @intFromEnum(service);
        errdefer self.freeJob(job);
        try self.sendSrv(job, SRV_TLS[job.service_idx]);
        try self.jobs.append(self.alloc, job);
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

    fn nextId(self: *Resolver) u16 {
        self.next_id +%= 1;
        return self.next_id;
    }

    /// Allocate a job in a free slot and stamp it with that slot's
    /// generation; timer udata carries both so a queued event naming a
    /// freed job is ignored instead of dereferenced.
    fn allocJob(self: *Resolver, session_key: usize, name: []const u8) !*Job {
        const job = try self.alloc.create(Job);
        errdefer self.alloc.destroy(job);
        job.* = .{
            .session_key = session_key,
            .name = try self.alloc.dupe(u8, name),
            .phase = .srv_tls,
        };
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
        var buf: [512]u8 = undefined;
        const q = try wire.buildQuery(&buf, self.nextId(), qname, qtype);
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

        if (job.is_raw) return self.completeRaw(job, msg);
        switch (job.phase) {
            .srv_tls, .srv_plain, .addr, .tlsa, .fallback_addr, .fallback_tlsa => self.advance(job, msg),
            .raw, .done => {},
        }
    }

    fn dropJob(self: *Resolver, job: *Job, status: Status) void {
        for (self.jobs.items, 0..) |j, i| {
            if (j == job) {
                _ = self.jobs.orderedRemove(i);
                break;
            }
        }
        const key = job.session_key;
        if (job.is_raw) {
            self.qcb.fun(self.qcb.ctx, key, status, null);
        } else {
            self.cb.fun(self.cb.ctx, key, status, null);
        }
        self.freeJob(job);
    }

    fn complete(self: *Resolver, job: *Job) void {
        for (self.jobs.items, 0..) |j, i| {
            if (j == job) {
                _ = self.jobs.orderedRemove(i);
                break;
            }
        }
        const key = job.session_key;
        const targets = self.alloc.alloc(Target, job.targets.items.len) catch {
            self.freeJob(job);
            self.cb.fun(self.cb.ctx, key, .failed, null);
            return;
        };
        @memcpy(targets, job.targets.items);
        job.targets.deinit(self.alloc);
        job.targets = .{};
        self.cb.fun(self.cb.ctx, key, .resolved, .{ .targets = targets });
        self.freeJob(job);
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
        const key = job.session_key;
        const detached = self.dupRrs(msg.rrs) catch {
            self.freeJob(job);
            self.qcb.fun(self.qcb.ctx, key, .failed, null);
            return;
        };
        self.cachePut(job.pending_qname, job.pending_qtype, detached);
        const ttl = minTtl(detached);
        self.qcb.fun(self.qcb.ctx, key, .resolved, .{ .rrs = detached, .ttl = ttl });
        self.freeJob(job);
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
            .tlsa, .fallback_tlsa, .addr => self.complete(job),
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
                orderSrvRfc2782(job.srv_list.items);
                job.srv_pos = 0;
                job.phase = .addr;
                self.sendAddr(job) catch return self.dropJob(job, .failed);
            },
            .addr => {
                const target = &job.srv_list.items[job.srv_pos];
                for (msg.rrs) |rr| {
                    if (rr.rtype == KIND_A or rr.rtype == KIND_AAAA) {
                        if (std.ascii.eqlIgnoreCase(rr.name, target.host)) {
                            target.addr = addrFromRdata(rr, target.port) catch null;
                        }
                    }
                }
                if (target.addr == null) {
                    job.srv_pos += 1;
                    if (job.srv_pos < job.srv_list.items.len) {
                        self.sendAddr(job) catch return self.dropJob(job, .failed);
                        return;
                    }
                    self.startFallback(job);
                    return;
                }
                job.phase = .tlsa;
                self.sendTlsa(job) catch return self.dropJob(job, .failed);
            },
            .tlsa, .fallback_tlsa => {
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
                const defport: u16 = 5222;
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
            }) catch continue;
        }
    }

    fn sendAddr(self: *Resolver, job: *Job) !void {
        const ent = &job.srv_list.items[job.srv_pos];
        var buf: [280]u8 = undefined;
        const qname = std.fmt.bufPrint(&buf, "{s}", .{ent.host}) catch return error.NameTooLong;
        try self.sendQuery(job, qname, KIND_A);
    }

    fn sendTlsa(self: *Resolver, job: *Job) !void {
        const ent = &job.srv_list.items[job.srv_pos];
        const addr = ent.addr.?;
        var buf: [280]u8 = undefined;
        const qname = dns.tlsaQueryName(&buf, ent.port, ent.host) catch return error.NameTooLong;
        try self.sendQuery(job, qname, KIND_TLSA);
        const ta = try self.alloc.alloc(Target, 1);
        ta[0] = .{ .addr = addr, .host = self.alloc.dupe(u8, ent.host) catch return error.OutOfMemory, .tlsa = &.{}, .is_direct_tls = ent.is_direct_tls };
        errdefer self.alloc.free(ta);
        job.targets.append(self.alloc, ta[0]) catch return error.OutOfMemory;
        self.alloc.free(ta);
    }

    fn freeJob(self: *Resolver, job: *Job) void {
        if (self.slots[job.slot] == job) self.slots[job.slot] = null;
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
/// targets with probability proportional to weight.
fn orderSrvRfc2782(items: []SrvEnt) void {
    std.mem.sort(SrvEnt, items, {}, struct {
        fn lt(_: void, a: SrvEnt, b: SrvEnt) bool {
            return a.priority < b.priority;
        }
    }.lt);
    var i: usize = 0;
    var rng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
    const rand = rng.random();
    while (i < items.len) {
        var j = i;
        var total: u64 = 0;
        while (j < items.len and items[j].priority == items[i].priority) : (j += 1) total += items[j].weight;
        var k = i;
        while (k < j) : (k += 1) {
            var pick: usize = k;
            if (total > 0) {
                const r = rand.uintLessThan(u64, total);
                var acc: u64 = 0;
                var m = k;
                while (m < j) : (m += 1) {
                    acc += items[m].weight;
                    if (r < acc) {
                        pick = m;
                        break;
                    }
                }
            }
            std.mem.swap(SrvEnt, &items[k], &items[pick]);
            total -= items[k].weight;
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
    udp_recvd: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    tcp_recvd: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
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
            if (std.mem.startsWith(u8, q.qname, "_xmpps")) {
                // NODATA for the direct-TLS prefix.
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
            ancount = 1;
            appendAnswerHdr(alloc, &answers, wire.TYPE_TLSA, 60, 7);
            answers.appendSlice(alloc, &.{ 3, 0, 1, 0xDE, 0xAD, 0xBE, 0xEF }) catch {};
        }

        std.mem.writeInt(u16, out[0..2], id, .big);
        std.mem.writeInt(u16, out[2..4], 0x8180, .big);
        std.mem.writeInt(u16, out[4..6], 1, .big);
        std.mem.writeInt(u16, out[6..8], ancount, .big);
        @memset(out[8..12], 0);
        const qlen = pkt.len - 12;
        @memcpy(out[12 .. 12 + qlen], pkt[12..]);
        var off = 12 + qlen;
        @memcpy(out[off .. off + answers.items.len], answers.items);
        off += answers.items.len;
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

    try r.resolve("svc.test", .client, 5222, 3);
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

    try std.testing.expectError(error.InvalidName, r.resolve("bad..name", .client, 5222, 1));
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
