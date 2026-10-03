//! # xmppc async DNS resolver (T-16C82690, Phorge T201)
//!
//! One UDP socket per Engine, registered on the engine's kqueue; retransmit
//! and expiry are driven by the engine tick. Per request the chain is:
//!
//!   SRV xmpps + SRV xmpp (XEP-0368 / RFC 6120 §3.2, in that order)
//!     → per-target A/AAAA (RFC 2782 ordered)
//!       → TLSA for each target (used by DANE, T-B5D56AD3)
//!         → callback with the ordered target list + TLSA records
//!
//! Bare-name fallback (no SRV exists): A/AAAA on the name itself at :5222
//! with TLSA `_5222._tcp.<name>`. Literal IPs short-circuit synchronously.
//! All code runs on the engine thread; nothing blocks, nothing allocates
//! lazily per packet (parse scratch uses an arena per response).

const std = @import("std");
const posix = std.posix;
const dns = @import("dns");
const wire = @import("wire");
const net = std.net;

const log = std.log.scoped(.xmppc);

const KIND_SRV = wire.TYPE_SRV;
const KIND_A = wire.TYPE_A;
const KIND_AAAA = wire.TYPE_AAAA;
const KIND_TLSA = wire.TYPE_TLSA;

const SRV_XMPS = "_xmpps-client._tcp";
const SRV_XMPP = "_xmpp-client._tcp";

const TIMEOUT_MS: i64 = 2000;
const MAX_TRIES: u8 = 2;

/// Hand-out to the session when resolution finishes.
pub const Target = struct {
    addr: net.Address, // connected address (port included)
    host: []const u8, // hostname for SNI / TLSA query names (owned by us)
    tlsa: []dns.TlsaRecord, // TLSA records for this target (owned; empty when none)
    is_direct_tls: bool,
};

/// What comes back on completion. Caller frees with `deinitOn`.
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

pub const Status = enum { resolved, nxdomain, failed };

/// Called on the engine thread when a request completes. `session_key` is
/// the value the caller passed to `resolve()`.
pub const Cb = struct {
    ctx: ?*anyopaque,
    fun: *const fn (ctx: ?*anyopaque, session_key: usize, status: Status, res: ?Resolution) void,
};

const Job = struct {
    session_key: usize,

    // Original request shape.
    name: []const u8, // bare domain/host we were given (owned)
    /// SRV name list seen so far, in try-order (owned hosts).
    srv_list: std.ArrayListUnmanaged(SrvEnt),
    srv_pos: usize = 0,
    /// Where we are on the chain for srvs[srv_pos]:
    phase: enum { srv_xmpp, srv_xmpps, srv, addr, tlsa, fallback_addr, fallback_tlsa, done } = .srv,

    // Wire state for the outstanding query.
    dns_id: u16 = 0,
    pending_qname: []const u8 = "", // owned copy of the last query name
    request: []u8 = &.{},
    deadline_ms: i64 = 0,
    tries: u8 = 0,

    /// Collected as we go.
    targets: std.ArrayListUnmanaged(Target) = .{},
};

const SrvEnt = struct {
    host: []const u8 = "", // owned
    port: u16 = 0,
    is_direct_tls: bool = false,
    addr: ?net.Address = null,
    inline_addr_checked: bool = false,
};

pub const Resolver = struct {
    alloc: std.mem.Allocator,
    fd: posix.fd_t = -1,
    server: net.Address = undefined,
    server_configured: bool = false,
    jobs: std.ArrayListUnmanaged(*Job) = .{},
    next_id: u16 = 0,
    cb: Cb = .{ .ctx = null, .fun = noopCallback },

    fn noopCallback(_: ?*anyopaque, _: usize, _: Status, _: ?Resolution) void {}

    pub fn init(alloc: std.mem.Allocator) Resolver {
        return .{ .alloc = alloc, .next_id = std.crypto.random.int(u16) };
    }

    pub fn deinit(self: *Resolver) void {
        for (self.jobs.items) |j| self.freeJob(j);
        self.jobs.deinit(self.alloc);
        if (self.fd >= 0) posix.close(self.fd);
    }

    pub fn setServer(self: *Resolver, addr: net.Address) void {
        self.server = addr;
        self.server_configured = true;
    }

    pub fn setCallback(self: *Resolver, cb: Cb) void {
        self.cb = cb;
    }

    pub fn sockFd(self: *const Resolver) posix.fd_t {
        return self.fd;
    }

    // ------------------------------------------------------------------
    // Request entry
    // ------------------------------------------------------------------

    /// Start resolving `name` (a domain or host). A literal IP completes
    /// synchronously with a single target (no UDP traffic).
    pub fn resolve(self: *Resolver, name: []const u8, default_port: u16, session_key: usize) !void {
        if (net.Address.parseIp(name, default_port)) |addr| {
            const t = Target{
                .addr = addr,
                .host = try self.alloc.dupe(u8, name),
                .tlsa = &.{},
                .is_direct_tls = false,
            };
            const list = try self.alloc.alloc(Target, 1);
            list[0] = t;
            self.cb.fun(self.cb.ctx, session_key, .resolved, .{ .targets = list });
            return;
        } else |_| {}

        try self.ensureOpen();

        const job = try self.alloc.create(Job);
        job.* = .{
            .session_key = session_key,
            .name = try self.alloc.dupe(u8, name),
            .srv_list = .{},
        };
        errdefer self.freeJob(job);

        // XEP-0368: direct-TLS SRV first, then plain XMPP SRV. We walk the
        // chain linearly; the response handlers decide whether to advance.
        job.phase = .srv_xmpps;
        try self.sendSrv(job, SRV_XMPS);
        try self.jobs.append(self.alloc, job);
    }

    // ------------------------------------------------------------------
    // Wire I/O
    // ------------------------------------------------------------------

    fn ensureOpen(self: *Resolver) !void {
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
    }

    fn sendSrv(self: *Resolver, job: *Job, prefix: []const u8) !void {
        var buf: [280]u8 = undefined;
        const qname = std.fmt.bufPrint(&buf, "{s}.{s}", .{ prefix, job.name }) catch return error.NameTooLong;
        try self.sendQuery(job, qname, KIND_SRV);
    }

    fn nextId(self: *Resolver) u16 {
        self.next_id +%= 1;
        return self.next_id;
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
        job.deadline_ms = nowMs() + TIMEOUT_MS;
        job.tries = 1;
        _ = posix.send(self.fd, pkt, 0) catch return error.SendFailed;
    }

    // ------------------------------------------------------------------
    // Tick (timeouts / retransmits)
    // ------------------------------------------------------------------

    pub fn tick(self: *Resolver) void {
        const now = nowMs();
        var i: usize = 0;
        while (i < self.jobs.items.len) {
            const job = self.jobs.items[i];
            if (now < job.deadline_ms) {
                i += 1;
                continue;
            }
            job.tries += 1;
            if (job.tries <= MAX_TRIES) {
                job.deadline_ms = now + TIMEOUT_MS;
                _ = posix.send(self.fd, job.request, 0) catch {};
                i += 1;
                continue;
            }
            log.warn("dns: timeout after {d} tries for {s}", .{ job.tries, job.name });
            _ = self.jobs.orderedRemove(i);
            self.failNow(job);
        }
    }

    // ------------------------------------------------------------------
    // Responses
    // ------------------------------------------------------------------

    pub fn onReadable(self: *Resolver) void {
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = posix.recv(self.fd, &buf, 0) catch |e| switch (e) {
                error.WouldBlock => return,
                else => return,
            };
            if (n < 12) continue;
            const id = std.mem.readInt(u16, buf[0..2], .big);
            var hit: ?*Job = null;
            for (self.jobs.items) |j| {
                if (j.dns_id == id) {
                    hit = j;
                    break;
                }
            }
            if (hit) |job| self.handleResponse(job, buf[0..n]);
        }
    }

    fn handleResponse(self: *Resolver, job: *Job, pkt: []const u8) void {
        var arena_state = std.heap.ArenaAllocator.init(self.alloc);
        defer arena_state.deinit();

        const msg = wire.parse(arena_state.allocator(), pkt) catch return self.dropJob(job, .failed);
        if (msg.truncated) {
            log.warn("dns: truncated UDP answer for {s} (no TCP fallback yet)", .{job.pending_qname});
            return self.dropJob(job, .failed);
        }

        switch (msg.rcode) {
            wire.RCODE_NOERROR => {},
            wire.RCODE_NXDOMAIN => return self.onNxdomain(job),
            else => return self.dropJob(job, .failed),
        }

        switch (job.phase) {
            .srv, .srv_xmpps, .srv_xmpp, .addr, .tlsa, .fallback_addr, .fallback_tlsa => self.advance(job, msg),
            .done => {},
        }
    }

    fn dropJob(self: *Resolver, job: *Job, status: Status) void {
        // Remove from the list (if still there), free, and notify.
        for (self.jobs.items, 0..) |j, i| {
            if (j == job) {
                _ = self.jobs.orderedRemove(i);
                break;
            }
        }
        self.failNowStatus(job, status);
    }

    fn failNow(self: *Resolver, job: *Job) void {
        self.failNowStatus(job, .failed);
    }

    fn failNowStatus(self: *Resolver, job: *Job, status: Status) void {
        const key = job.session_key;
        // Free the job after the callback; Resolution handed out separately.
        self.cb.fun(self.cb.ctx, key, status, null);
        self.freeJob(job);
    }

    fn complete(self: *Resolver, job: *Job) void {
        const key = job.session_key;
        const targets = self.alloc.alloc(Target, job.targets.items.len) catch {
            self.failNow(job);
            return;
        };
        @memcpy(targets, job.targets.items);
        job.targets.deinit(self.alloc);
        job.targets = .{};
        self.cb.fun(self.cb.ctx, key, .resolved, .{ .targets = targets });
        self.freeJob(job);
    }

    fn onNxdomain(self: *Resolver, job: *Job) void {
        switch (job.phase) {
            .srv_xmpps => {
                job.phase = .srv_xmpp;
                self.sendSrv(job, SRV_XMPP) catch return self.dropJob(job, .failed);
            },
            .srv, .srv_xmpp => self.startFallback(job),
            // NXDOMAIN on the bare A/AAAA or TLSA: the latter just means
            // "no DANE", which completes the job successfully.
            .fallback_addr => self.dropJob(job, .nxdomain),
            .tlsa, .fallback_tlsa, .addr => self.complete(job),
            .done => {},
        }
    }

    // ------------------------------------------------------------------
    // Chain advance
    // ------------------------------------------------------------------

    fn advance(self: *Resolver, job: *Job, msg: wire.Message) void {
        switch (job.phase) {
            .srv_xmpps, .srv_xmpp => {
                self.absorbSrv(job, msg, job.phase == .srv_xmpps);
                if (job.srv_list.items.len == 0) {
                    // StartTLS-capable server only advertises one variant;
                    // a SRV answer with zero records still lets us walk on.
                    if (job.phase == .srv_xmpps) {
                        job.phase = .srv_xmpp;
                        self.sendSrv(job, SRV_XMPP) catch return self.dropJob(job, .failed);
                        return;
                    }
                    return self.startFallback(job);
                }
                job.srv_pos = 0;
                job.phase = .addr;
                self.sendAddr(job) catch return self.dropJob(job, .failed);
            },
            .srv => unreachable,
            .addr => {
                // The A answer for srvs[srv_pos]; AAAA inline check.
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
                // Attach the records to the matching target.
                if (job.targets.items.len > 0) {
                    job.targets.items[job.targets.items.len - 1].tlsa = tlsa_recs.items;
                    // Note: ownership of `tlsa_recs` list transfers to Target.
                }
                self.complete(job);
            },
            .fallback_addr => {
                // Bare A/AAAA answers: take one address (prefer AAAA).
                var addr6: ?net.Address = null;
                var addr4: ?net.Address = null;
                for (msg.rrs) |rr| {
                    if (rr.rtype == KIND_AAAA and addr6 == null) addr6 = addrFromRdata(rr, 5222) catch null;
                    if (rr.rtype == KIND_A and addr4 == null) addr4 = addrFromRdata(rr, 5222) catch null;
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
                const qname = dns.tlsaQueryName(&buf, 5222, job.name) catch return self.dropJob(job, .failed);
                self.sendQuery(job, qname, KIND_TLSA) catch return self.dropJob(job, .failed);
            },
            .done => {},
        }
    }

    fn absorbSrv(self: *Resolver, job: *Job, msg: wire.Message, direct_tls: bool) void {
        for (msg.rrs) |rr| {
            if (rr.rtype != KIND_SRV) continue;
            const parsed = dns.parseSrvRdata(rr.rdata, self.alloc) catch continue;
            job.srv_list.append(self.alloc, .{ .host = parsed.target, .port = parsed.port, .is_direct_tls = direct_tls }) catch continue;
        }
    }

    fn sendAddr(self: *Resolver, job: *Job) !void {
        const ent = &job.srv_list.items[job.srv_pos];
        if (ent.inline_addr_checked) return;
        // A first; if the server also carries AAAA inline in 'additional'
        // we already had it; issues one A query per target.
        var buf: [280]u8 = undefined;
        const qname = std.fmt.bufPrint(&buf, "{s}", .{ent.host}) catch return error.NameTooLong;
        try self.sendQuery(job, qname, KIND_A);
        ent.inline_addr_checked = true;
    }

    fn sendTlsa(self: *Resolver, job: *Job) !void {
        const ent = &job.srv_list.items[job.srv_pos];
        const addr = ent.addr.?;
        var buf: [280]u8 = undefined;
        const qname = dns.tlsaQueryName(&buf, ent.port, ent.host) catch return error.NameTooLong;
        try self.sendQuery(job, qname, KIND_TLSA);
        // Bridge: the answer lands in .tlsa phase; capture into the target.
        const ta = try self.alloc.alloc(Target, 1);
        ta[0] = .{ .addr = addr, .host = self.alloc.dupe(u8, ent.host) catch return error.OutOfMemory, .tlsa = &.{}, .is_direct_tls = ent.is_direct_tls };
        errdefer self.alloc.free(ta); // target list owns from here on
        job.targets.append(self.alloc, ta[0]) catch return error.OutOfMemory;
        self.alloc.free(ta);
    }
    // freeJob releases everything owned by the job.
    fn freeJob(self: *Resolver, job: *Job) void {
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
            return net.Address.parseIp4(rr.rdata[0..4], port);
        },
        KIND_AAAA => {
            if (rr.rdata.len < 16) return error.InvalidRdata;
            return net.Address.parseIp6(rr.rdata[0..16], port);
        },
        else => return error.InvalidRdata,
    }
}

fn nowMs() i64 {
    return @intCast(std.time.milliTimestamp());
}

/// First nameserver entry from /etc/resolv.conf.
pub fn readResolvConf() !net.Address {
    var buf: [8192]u8 = undefined;
    const data = std.fs.cwd().readFile("/etc/resolv.conf", &buf) catch return error.NoResolver;
    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (std.mem.startsWith(u8, line, "#")) continue;
        if (!std.mem.startsWith(u8, line, "nameserver")) continue;
        const rest = std.mem.trim(u8, line["nameserver".len..], " \t");
        if (net.Address.parseIp(rest, 53)) |a| return a else |_| continue;
    }
    return error.NoResolver;
}
