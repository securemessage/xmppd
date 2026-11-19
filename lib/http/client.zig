//! # HTTP Client -- HTTPS/1.1 over TLS (OpenSSL) with deadlines and cancellation
//!
//! Designed for OIDC backend use: JWKS fetch, token introspection, ROPC grant.
//! Requests run on the auth daemon's IdP worker threads, never on its event
//! loop.
//!
//! ## Threading
//!
//! A `Client` is safe to share across threads: after `init` its `SSL_CTX`s
//! are only read, never mutated; the verification-path log table is the
//! only shared mutable state and sits behind its own mutex. Each request
//! owns its socket, `SSL`, resolver and kqueue for its whole lifetime;
//! nothing else is shared between in-flight requests. The idle pool is
//! threadlocal: each worker thread parks its own connections, so the
//! request path takes no lock for reuse.
//!
//! ## Features
//!
//! - HTTP/1.1 GET and POST (application/x-www-form-urlencoded)
//! - TLS via OpenSSL on a non-blocking socket driven by a per-request kqueue
//! - Absolute deadline and separate connect budget per request, plus a
//!   cancellation pipe whose EOF aborts the exchange
//! - Non-blocking A/AAAA resolution through the shared async resolver
//!   (lib/dns/async.zig), driven on the request's own kqueue inside the
//!   connect budget; every resolved address is tried in order
//! - DANE-first peer verification: a published TLSA RRset authenticates
//!   the peer (DANE-TA and DANE-EE; a mismatch fails closed). Only an
//!   absent RRset (NXDOMAIN/NODATA) falls back to PKIX with the
//!   configured CA bundle and the URL-host pin. A failed TLSA lookup
//!   (timeout, SERVFAIL) skips the target and never falls back.
//! - Keep-alive per endpoint: one idle connection per (host, port) parked
//!   per worker thread. Reuse skips DNS, TCP and the TLS handshake; the
//!   parked conn must be under 5 s idle, hold no unread bytes inside its
//!   SSL object and pass a zero-timeout EVFILT_READ probe (no pending
//!   bytes, no EOF) or it is closed and a fresh connect runs.
//!   HTTP/1.0 responses, `Connection: close` replies
//!   and EOF-framed bodies are never parked. A GET that dies on a reused
//!   conn before the first response byte retries once on a fresh conn;
//!   POST never retries. Peer verification stays at connect time only.
//! - Response limited to 256KB (JWKS/token responses are small)
//!
//! ## Known limits
//!
//! - kTLS is deliberately not enabled on this client.
//!
//! ## Usage
//!
//! ```zig
//! var client = try http.Client.init(null); // or a CA bundle path
//! defer client.deinit();
//! const options = http.RequestOptions{
//!     .deadline_ns = http.monotonicNs() + 10 * std.time.ns_per_s,
//!     .connect_timeout_ms = 3000,
//! };
//! var response = try client.get(allocator, "https://auth.example.com/jwks", options);
//! defer response.deinit();
//! ```

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Allocator = std.mem.Allocator;

const dns_async = @import("dns_async");
const ssl = @import("ssl");
const wire = @import("wire");

const log = std.log.scoped(.http_client);

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/x509_vfy.h");
    @cInclude("sys/socket.h");
    @cInclude("netinet/in.h");
});

pub const HttpError = error{
    InvalidUrl,
    DnsResolutionFailed,
    ConnectionFailed,
    Timeout,
    Cancelled,
    TlsInitFailed,
    TlsHandshakeFailed,
    TlsWriteFailed,
    TlsReadFailed,
    ResponseTooLarge,
    InvalidResponse,
    OutOfMemory,
};

/// Per-request timing and cancellation. Every wait inside the exchange
/// honors `deadline_ns`; the connect+handshake phase additionally ends at
/// `start + connect_timeout_ms` (freebsd-ktls D5: the handshake is part of
/// connect).
pub const RequestOptions = struct {
    /// Absolute CLOCK_MONOTONIC deadline for the whole exchange, nanoseconds.
    deadline_ns: u64,
    /// TCP connect plus TLS handshake budget; the connect phase ends at
    /// min(start + connect_timeout_ms, deadline_ns).
    connect_timeout_ms: u32,
    /// Read end of a pipe whose EOF cancels the request; -1 when not cancellable.
    cancel_fd: posix.fd_t = -1,
};

/// CLOCK_MONOTONIC in nanoseconds. std.time.Instant reads
/// CLOCK_MONOTONIC_FAST on FreeBSD, which advances once per kernel tick and
/// is too coarse for request deadlines.
pub fn monotonicNs() u64 {
    const ts = posix.clock_gettime(.MONOTONIC) catch return 0;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub const Response = struct {
    status: u16,
    body: []const u8,
    allocator: Allocator,

    pub fn deinit(self: *Response) void {
        // Bodies can carry tokens; never leave them in freed memory.
        std.crypto.secureZero(u8, @constCast(self.body));
        self.allocator.free(self.body);
    }
};

/// What a finished exchange tells the request loop: whether any response
/// byte arrived (the GET retry rule needs zero) and whether the response
/// leaves the connection reusable for the idle pool.
const ReadOutcome = struct {
    saw_byte: bool = false,
    reusable: bool = false,
};

/// Maximum response size (256KB, headers + body).
const MAX_RESPONSE_SIZE: usize = 256 * 1024;

/// Maximum request head size (request line + headers).
const MAX_HEAD_SIZE: usize = 4096;

/// Signature of Client.test_info_hook.
const InfoHook = fn (host: []const u8, port: u16, path: []const u8) void;

/// Bounded table of the last verification path logged at info per
/// (host, port): the Client is shared across IdP worker threads, so
/// entries sit behind a mutex. An endpoint repeats its info line only
/// when its path changes (or its slot was evicted).
const PathLog = struct {
    mutex: std.Thread.Mutex = .{},
    entries: [max_entries]Entry = @splat(.{}),
    /// Oldest-slot cursor for eviction once the table is full.
    next: usize = 0,

    const max_entries = 16;

    const Entry = struct {
        used: bool = false,
        host: [256]u8 = undefined,
        host_len: u8 = 0,
        port: u16 = 0,
        /// One of the string literals from danePathName or "pkix".
        path: []const u8 = "",
    };

    /// Record `path` for (host, port); returns true when the caller
    /// should emit the info line (first sighting or a changed path).
    fn note(self: *PathLog, host: []const u8, port: u16, path: []const u8) bool {
        std.debug.assert(host.len <= 255);
        self.mutex.lock();
        defer self.mutex.unlock();
        var free: ?*Entry = null;
        for (&self.entries) |*e| {
            if (!e.used) {
                free = free orelse e;
                continue;
            }
            if (e.port == port and e.host_len == host.len and
                std.mem.eql(u8, e.host[0..e.host_len], host))
            {
                if (std.mem.eql(u8, e.path, path)) return false;
                e.path = path;
                return true;
            }
        }
        const e = free orelse blk: {
            const victim = &self.entries[self.next];
            self.next = (self.next + 1) % max_entries;
            break :blk victim;
        };
        e.used = true;
        @memcpy(e.host[0..host.len], host);
        e.host_len = @intCast(host.len);
        e.port = port;
        e.path = path;
        return true;
    }
};

/// Persistent HTTPS client: one PKIX SSL_CTX and one DANE SSL_CTX per
/// daemon, parsing the CA bundle once instead of per request (T357/S8).
pub const Client = struct {
    ssl_ctx: *c.SSL_CTX,
    /// Empty-store verification context armed per request with the
    /// target's TLSA records; kept separate from ssl_ctx so a present
    /// RRset can never be satisfied by a PKIX anchor (fail closed).
    dane_ctx: ssl.SslContext,
    /// Which (host, port) last logged which verification path at info;
    /// the only Client state mutated after init, under its own mutex.
    path_log: PathLog,
    /// Test seam: requests resolve through this nameserver instead of
    /// the host's resolver configuration, the same seam
    /// lib/dns/async.zig's own fixtures use.
    test_nameserver: if (builtin.is_test) ?std.net.Address else void = if (builtin.is_test) null else {},
    /// Test seam: invoked exactly where the per-endpoint info line is
    /// emitted, so tests count emissions instead of scraping stderr.
    test_info_hook: if (builtin.is_test) ?*const InfoHook else void = if (builtin.is_test) null else {},

    pub fn init(ca_file: ?[]const u8) HttpError!Client {
        const ctx = initTlsClient(ca_file) orelse return HttpError.TlsInitFailed;
        errdefer c.SSL_CTX_free(ctx);
        var dane_ctx = ssl.SslContext.initClientDane() catch return HttpError.TlsInitFailed;
        // initClientDane arms kernel TLS like every shared initializer;
        // this client stays userland (module header).
        dane_ctx.disableKtls();
        return .{ .ssl_ctx = ctx, .dane_ctx = dane_ctx, .path_log = .{} };
    }

    pub fn deinit(self: *Client) void {
        c.SSL_CTX_free(self.ssl_ctx);
        self.dane_ctx.deinit();
    }

    /// Perform an HTTPS GET request. Caller owns the returned Response.
    /// Runs entirely on the calling thread; safe to call from any worker.
    pub fn get(
        self: *Client,
        allocator: Allocator,
        url: []const u8,
        options: RequestOptions,
    ) HttpError!Response {
        return request(self, allocator, "GET", url, null, null, options);
    }

    /// Perform an HTTPS POST with form-urlencoded body. Caller owns the
    /// returned Response.
    pub fn post(
        self: *Client,
        allocator: Allocator,
        url: []const u8,
        body: []const u8,
        options: RequestOptions,
    ) HttpError!Response {
        return request(
            self,
            allocator,
            "POST",
            url,
            body,
            "application/x-www-form-urlencoded",
            options,
        );
    }
};

// ============================================================================
// Per-request kqueue waits
// ============================================================================

const WaitError = error{ Timeout, Cancelled, WaitFailed };

fn makeKev(ident: usize, filter: i16, flags: u16) posix.Kevent {
    return .{
        .ident = ident,
        .filter = filter,
        .flags = flags,
        .fflags = 0,
        .data = 0,
        .udata = 0,
    };
}

/// Wait until `fd` reports `filter` readiness, the cancel pipe signals EOF,
/// or `deadline_ns` passes. The fd filter is staged EV_ADD|EV_ONESHOT in the
/// same kevent() call that waits; the cancel fd is staged as a persistent
/// EV_ADD (re-adding an existing knote is an idempotent modify).
fn waitIo(
    kq: posix.fd_t,
    fd: posix.fd_t,
    filter: i16,
    deadline_ns: u64,
    cancel_fd: posix.fd_t,
) WaitError!void {
    const now = monotonicNs();
    if (now >= deadline_ns) return error.Timeout;
    const remaining = deadline_ns - now;

    var changes: [2]posix.Kevent = undefined;
    var n_changes: usize = 0;
    changes[n_changes] = makeKev(@intCast(fd), filter, std.c.EV.ADD | std.c.EV.ONESHOT);
    n_changes += 1;
    if (cancel_fd >= 0) {
        changes[n_changes] = makeKev(@intCast(cancel_fd), std.c.EVFILT.READ, std.c.EV.ADD);
        n_changes += 1;
    }

    var events: [2]posix.Kevent = undefined;
    const timeout: posix.timespec = .{
        .sec = @intCast(remaining / std.time.ns_per_s),
        .nsec = @intCast(remaining % std.time.ns_per_s),
    };
    const n = posix.kevent(
        kq,
        changes[0..n_changes],
        &events,
        &timeout,
    ) catch return error.WaitFailed;
    if (n == 0) return error.Timeout;

    var saw_fd = false;
    for (events[0..n]) |ev| {
        if (cancel_fd >= 0 and ev.ident == @as(usize, @intCast(cancel_fd))) {
            return error.Cancelled;
        }
        if (ev.flags & std.c.EV.ERROR != 0) return error.WaitFailed;
        saw_fd = true;
    }
    if (saw_fd) return;
    return error.WaitFailed;
}

/// One established connection: the socket plus its SSL.
const Conn = struct {
    fd: posix.fd_t,
    ssl_ptr: *c.SSL,
};

/// One non-blocking shutdown, never waited on (freebsd-ktls D6), then
/// the SSL and the socket.
fn closeConn(conn: Conn) void {
    _ = c.SSL_shutdown(conn.ssl_ptr);
    c.SSL_free(conn.ssl_ptr);
    posix.close(conn.fd);
}

/// Bounded idle-connection table owned by one thread: at most one parked
/// connection per (host, port). The pool is threadlocal, so reuse adds
/// no lock to the request path; hosts are fixed 256-byte cells like
/// PathLog's. A conn that ages out or reads dead at take time is closed
/// on the spot.
const IdlePool = struct {
    entries: [max_entries]Entry = @splat(.{}),

    const max_entries = 8;
    const max_idle_ns = 5 * std.time.ns_per_s;

    const Entry = struct {
        used: bool = false,
        host: [256]u8 = undefined,
        host_len: u8 = 0,
        port: u16 = 0,
        fd: posix.fd_t = -1,
        ssl_ptr: ?*c.SSL = null,
        idle_since_ns: u64 = 0,
    };

    /// Park `conn` under (host, port). A parked conn for the endpoint is
    /// displaced by the one that just completed; a full table drops the
    /// newcomer. Both keep the table bounded. A conn still holding unread
    /// bytes in its SSL object is never parked: they would parse as the
    /// next response.
    fn put(self: *IdlePool, host: []const u8, port: u16, conn: Conn) void {
        std.debug.assert(host.len <= 255);
        if (!sslDrained(conn)) {
            if (builtin.is_test) pending_drops += 1;
            closeConn(conn);
            return;
        }
        var free: ?*Entry = null;
        for (&self.entries) |*e| {
            if (!e.used) {
                free = free orelse e;
                continue;
            }
            if (e.port == port and e.host_len == host.len and
                std.mem.eql(u8, e.host[0..e.host_len], host))
            {
                closeConn(connOf(e));
                e.fd = conn.fd;
                e.ssl_ptr = conn.ssl_ptr;
                e.idle_since_ns = monotonicNs();
                return;
            }
        }
        const e = free orelse {
            closeConn(conn);
            return;
        };
        e.used = true;
        @memcpy(e.host[0..host.len], host);
        e.host_len = @intCast(host.len);
        e.port = port;
        e.fd = conn.fd;
        e.ssl_ptr = conn.ssl_ptr;
        e.idle_since_ns = monotonicNs();
    }

    /// Hand back the parked conn for (host, port) when it is under the
    /// idle ceiling and still live, else close it and return null.
    fn take(self: *IdlePool, kq: posix.fd_t, host: []const u8, port: u16) ?Conn {
        for (&self.entries) |*e| {
            if (!e.used) continue;
            if (e.port != port or e.host_len != host.len or
                !std.mem.eql(u8, e.host[0..e.host_len], host)) continue;
            const conn = connOf(e);
            e.used = false;
            if (monotonicNs() - e.idle_since_ns >= max_idle_ns or
                !connLive(kq, conn))
            {
                if (builtin.is_test) stale_detects += 1;
                closeConn(conn);
                return null;
            }
            return conn;
        }
        return null;
    }

    fn connOf(e: *const Entry) Conn {
        return .{ .fd = e.fd, .ssl_ptr = e.ssl_ptr.? };
    }
};

/// Per-thread idle pool: IdP workers reuse their own connections only.
threadlocal var idle_pool: IdlePool = .{};

/// Test seam: counts parked connections the take-time probe discarded.
var stale_detects: usize = 0;

/// Test seam: counts conns refused at park time for holding unread SSL
/// bytes.
var pending_drops: usize = 0;

/// Bytes OpenSSL already read from the socket but the parser has not
/// consumed sit in the SSL object, invisible to kevent: plaintext left
/// by a record larger than the read buffer (SSL_pending) or a buffered
/// record not yet processed (SSL_has_pending). Either means the peer
/// wrote past the response end, so the conn is not safe to park or
/// reuse.
fn sslDrained(conn: Conn) bool {
    return c.SSL_pending(conn.ssl_ptr) == 0 and
        c.SSL_has_pending(conn.ssl_ptr) == 0;
}

/// Zero-timeout liveness probe for a parked connection: unread bytes
/// inside the SSL object, any pending byte, an EOF or an error event
/// means the peer already closed or is speaking out of turn, and the
/// conn is not safe to reuse.
fn connLive(kq: posix.fd_t, conn: Conn) bool {
    if (!sslDrained(conn)) return false;
    const changes = [_]posix.Kevent{
        makeKev(@intCast(conn.fd), std.c.EVFILT.READ, std.c.EV.ADD | std.c.EV.ONESHOT),
    };
    var events: [1]posix.Kevent = undefined;
    const zero: posix.timespec = .{ .sec = 0, .nsec = 0 };
    const n = posix.kevent(kq, &changes, &events, &zero) catch return false;
    // A live conn's ONESHOT knote stays on kq; kq closes with the request.
    return n == 0;
}

/// Close every parked connection owned by the calling thread. Worker
/// threads call this at shutdown; tests call it to release their
/// fixture server.
pub fn drainIdlePool() void {
    for (&idle_pool.entries) |*e| {
        if (!e.used) continue;
        closeConn(IdlePool.connOf(e));
        e.used = false;
    }
}

/// Core HTTP request implementation. Owns one socket, one SSL, one
/// resolver and one kqueue for the exchange's duration; a reused conn
/// brings only its socket and SSL from the per-thread idle pool.
fn request(
    client: *Client,
    allocator: Allocator,
    method: []const u8,
    url: []const u8,
    body: ?[]const u8,
    content_type: ?[]const u8,
    options: RequestOptions,
) HttpError!Response {
    const start_ns = monotonicNs();
    const connect_deadline = @min(
        start_ns + @as(u64, options.connect_timeout_ms) * std.time.ns_per_ms,
        options.deadline_ns,
    );

    // Parse URL: https://host[:port]/path
    const parsed = parseUrl(url) orelse return HttpError.InvalidUrl;

    // Zero-terminated host for SNI and the certificate identity check.
    var host_buf: [256]u8 = undefined;
    if (parsed.host.len >= host_buf.len) return HttpError.InvalidUrl;
    @memcpy(host_buf[0..parsed.host.len], parsed.host);
    host_buf[parsed.host.len] = 0;
    const host_z: [*:0]const u8 = @ptrCast(&host_buf);

    const kq = posix.kqueue() catch return HttpError.ConnectionFailed;
    defer posix.close(kq);

    // Reuse comes first: a live pooled conn skips DNS, TCP and the TLS
    // handshake. A parked conn that aged out or reads dead at the probe
    // is closed inside take and the request falls through to a fresh
    // connect; verification stays at connect time only.
    var conn: Conn = undefined;
    var reused = false;
    if (idle_pool.take(kq, parsed.host, parsed.port)) |c0| {
        conn = c0;
        reused = true;
    } else {
        conn = try connectAndHandshake(client, allocator, kq, host_z, parsed, connect_deadline, options);
    }

    // A GET that dies on a reused conn before the first response byte
    // retries once on a fresh conn (the conn may have died between the
    // probe and the exchange). POST is never retried: the caller's
    // exchange policy owns that decision.
    const retryable = std.mem.eql(u8, method, "GET");
    while (true) {
        var outcome: ReadOutcome = .{};
        const resp = exchange(conn, kq, allocator, method, parsed, body, content_type, options, &outcome) catch |err| {
            closeConn(conn);
            if (reused and retryable and !outcome.saw_byte and
                err != HttpError.Timeout and err != HttpError.Cancelled)
            {
                conn = try connectAndHandshake(client, allocator, kq, host_z, parsed, connect_deadline, options);
                reused = false;
                continue;
            }
            return err;
        };
        if (outcome.reusable) {
            idle_pool.put(parsed.host, parsed.port, conn);
        } else {
            closeConn(conn);
        }
        return resp;
    }
}

/// The request's resolver completion slot: the callback may fire inside
/// resolve() itself (literal IPs, names that cannot be encoded).
const ResolveOutcome = struct {
    done: bool = false,
    status: dns_async.Status = .failed,
    res: ?dns_async.Resolution = null,

    fn complete(ctx: ?*anyopaque, _: usize, status: dns_async.Status, res: ?dns_async.Resolution) void {
        const self: *ResolveOutcome = @ptrCast(@alignCast(ctx.?));
        self.done = true;
        self.status = status;
        self.res = res;
    }
};

/// Resolve the URL host on a per-request resolver: A and AAAA for the
/// bare name plus TLSA at _<port>._tcp.<host> when want_tlsa is set.
/// The resolver keeps its own kqueue; the request drives it by waiting
/// on `resolver.kqFd()` through waitIo under the connect deadline, then
/// pumping `step(0)` -- never a sleep, never a blocking call.
fn resolveTargets(
    client: *const Client,
    allocator: Allocator,
    kq: posix.fd_t,
    parsed: ParsedUrl,
    connect_deadline: u64,
    options: RequestOptions,
) HttpError!dns_async.Resolution {
    var resolver = dns_async.Resolver.init(allocator);
    defer resolver.deinit();
    if (builtin.is_test) {
        if (client.test_nameserver) |ns| resolver.setServer(ns);
    }
    var outcome: ResolveOutcome = .{};
    resolver.setCallback(.{ .ctx = &outcome, .fun = ResolveOutcome.complete });
    const session_key = @intFromPtr(&outcome);
    resolver.resolve(parsed.host, .client, parsed.port, session_key, true) catch
        return HttpError.DnsResolutionFailed;
    while (!outcome.done) {
        waitIo(
            kq,
            resolver.kqFd(),
            std.c.EVFILT.READ,
            connect_deadline,
            options.cancel_fd,
        ) catch |werr| {
            resolver.cancel(session_key);
            return switch (werr) {
                error.Timeout => HttpError.Timeout,
                error.Cancelled => HttpError.Cancelled,
                error.WaitFailed => HttpError.DnsResolutionFailed,
            };
        };
        resolver.step(0);
    }
    var res = outcome.res orelse return HttpError.DnsResolutionFailed;
    errdefer res.deinitOn(allocator);
    if (outcome.status != .resolved or res.targets.len == 0) return HttpError.DnsResolutionFailed;
    return res;
}

/// Non-blocking connect to one resolved address under the connect-phase
/// deadline. Returns false when the peer refused or errored (the caller
/// tries the next target); Timeout and Cancelled end the request.
fn tcpConnect(
    kq: posix.fd_t,
    fd: posix.fd_t,
    addr: *const std.net.Address,
    connect_deadline: u64,
    options: RequestOptions,
) WaitError!bool {
    posix.connect(fd, &addr.any, addr.getOsSockLen()) catch |err| switch (err) {
        error.WouldBlock, error.ConnectionPending => {
            waitIo(
                kq,
                fd,
                std.c.EVFILT.WRITE,
                connect_deadline,
                options.cancel_fd,
            ) catch |werr| return switch (werr) {
                error.WaitFailed => false,
                else => |e| e,
            };
            // SO_ERROR is read-and-clear; the socket latched the connect
            // outcome while it was pending.
            posix.getsockoptError(fd) catch return false;
        },
        else => return false,
    };
    return true;
}

/// DNS, TCP connect and TLS handshake under the connect-phase deadline
/// (freebsd-ktls D5: the handshake is part of connect). Every resolved
/// address is tried in order; Caller owns the returned fd and SSL.
fn connectAndHandshake(
    client: *Client,
    allocator: Allocator,
    kq: posix.fd_t,
    host_z: [*:0]const u8,
    parsed: ParsedUrl,
    connect_deadline: u64,
    options: RequestOptions,
) HttpError!Conn {
    var res = try resolveTargets(client, allocator, kq, parsed, connect_deadline, options);
    defer res.deinitOn(allocator);

    // Mirror lib/xmppc/session.zig connectNextTarget: a failed TLSA
    // lookup is a temporary failure of the target, never a reason to
    // fall back to PKIX, so the target is skipped rather than dialed.
    var tlsa_failed = false;
    for (res.targets) |*t| {
        if (t.tlsa_status == .lookup_failed) {
            tlsa_failed = true;
            continue;
        }
        const fd = posix.socket(
            t.addr.any.family,
            posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC,
            0,
        ) catch continue;
        const connected = tcpConnect(kq, fd, &t.addr, connect_deadline, options) catch |cerr| {
            posix.close(fd);
            return switch (cerr) {
                error.Timeout => HttpError.Timeout,
                error.Cancelled => HttpError.Cancelled,
                error.WaitFailed => HttpError.ConnectionFailed,
            };
        };
        if (!connected) {
            posix.close(fd);
            continue;
        }
        // A verification or handshake failure is a hard failure of the
        // request (session.zig fails the session the same way); it is
        // never a reason to try the next target.
        return handshakeTarget(client, allocator, kq, fd, t, host_z, parsed, connect_deadline, options) catch |herr| {
            posix.close(fd);
            return herr;
        };
    }
    // session.zig keeps the informative reason: a TLSA lookup that
    // failed is a DNS failure, not a dead peer.
    if (tlsa_failed) {
        log.warn("https: tlsa-lookup-failed for {s}:{d}", .{ parsed.host, parsed.port });
        return HttpError.DnsResolutionFailed;
    }
    return HttpError.ConnectionFailed;
}

/// Short log tag for the TLSA usage a DANE match anchored on.
fn danePathName(usage: ssl.Usage) []const u8 {
    return switch (usage) {
        .dane_ta => "dane-ta",
        .dane_ee => "dane-ee",
        .pkix_ta => "dane-pkix-ta",
        .pkix_ee => "dane-pkix-ee",
        else => "dane",
    };
}

/// TLS handshake on one connected target under the connect deadline.
/// The verification path mirrors lib/xmppc's dane_first policy: the
/// module's mode() over the usable TLSA set selects an empty-store DANE
/// context that fails closed on mismatch, or the PKIX context with the
/// URL-host pin.
fn handshakeTarget(
    client: *Client,
    allocator: Allocator,
    kq: posix.fd_t,
    fd: posix.fd_t,
    t: *const dns_async.Target,
    host_z: [*:0]const u8,
    parsed: ParsedUrl,
    connect_deadline: u64,
    options: RequestOptions,
) HttpError!Conn {
    // Arm DANE when the target published records; an RRset whose records
    // are all unusable reports .pkix from mode(), exactly the fallback
    // session.zig takes in armDane.
    var dane_state: ?ssl.DaneState = null;
    defer if (dane_state) |*s| s.deinit();
    var dane_armed = false;
    if (t.tlsa.len > 0) {
        const records = allocator.alloc(ssl.DaneRecord, t.tlsa.len) catch return HttpError.OutOfMemory;
        defer allocator.free(records);
        for (t.tlsa, 0..) |r, i| {
            records[i] = .{
                .usage = r.usage,
                .selector = r.selector,
                .matching_type = r.matching_type,
                .data = r.association_data,
            };
        }
        // Reference identifiers: the URL host first (it is also SNI),
        // then the resolved target host when it differs (RFC 7673
        // section 4, mirrored from session.zig armDane).
        var name_bufs: [2][256]u8 = undefined;
        var names: [2][]const u8 = undefined;
        var n_names: usize = 0;
        @memcpy(name_bufs[0][0..parsed.host.len], parsed.host);
        names[0] = name_bufs[0][0..parsed.host.len];
        n_names = 1;
        if (t.host.len > 0 and t.host.len < name_bufs[1].len and
            !std.mem.eql(u8, t.host, names[0]))
        {
            @memcpy(name_bufs[1][0..t.host.len], t.host);
            names[n_names] = name_bufs[1][0..t.host.len];
            n_names += 1;
        }
        dane_state = ssl.initDane(allocator, .{ .names = names[0..n_names] }, records) catch |err| {
            log.warn("https: cannot arm DANE for {s}:{d}: {}", .{ parsed.host, parsed.port, err });
            return HttpError.TlsHandshakeFailed;
        };
        dane_armed = dane_state.?.mode() == .dane;
    }

    var ssl_ptr: *c.SSL = undefined;
    var conn_wrap: ?ssl.SslConn = null;
    if (dane_armed) {
        // The DANE context is SSL_CTX-typed in lib/tls's own cImport; the
        // pointer casts mirror the ones ssl.zig itself applies at the
        // dane-openssl boundary (prepareDane/daneVerdict).
        conn_wrap = ssl.SslConn.initClient(client.dane_ctx, fd, host_z) catch
            return HttpError.TlsInitFailed;
        ssl_ptr = @ptrCast(conn_wrap.?.ssl);
    } else {
        ssl_ptr = c.SSL_new(client.ssl_ctx) orelse return HttpError.TlsInitFailed;
        _ = c.SSL_set_fd(ssl_ptr, @intCast(fd));
        _ = c.SSL_set_tlsext_host_name(ssl_ptr, host_z);
    }
    errdefer c.SSL_free(ssl_ptr);

    var dane_prepared: ssl.DanePrepared = .dane;
    if (conn_wrap) |*cw| {
        // Arm the TLSA set before the handshake runs; a present set can
        // then only authenticate the peer, never fall through to PKIX.
        dane_prepared = cw.prepareDane(&dane_state.?) catch return HttpError.TlsInitFailed;
    } else {
        // Pin the certificate identity to the URL host (T357/S8): VERIFY_PEER
        // alone (chain to a CA) accepts any publicly trusted certificate for
        // any name, so the IdP token/introspection/JWKS endpoints could be
        // answered by the wrong server without this.
        const verify_param = c.SSL_get0_param(ssl_ptr) orelse return HttpError.TlsInitFailed;
        if (c.X509_VERIFY_PARAM_set1_host(verify_param, host_z, 0) != 1)
            return HttpError.TlsInitFailed;
    }

    // TLS handshake on the non-blocking socket.
    while (true) {
        c.ERR_clear_error();
        const ret = c.SSL_connect(ssl_ptr);
        if (ret == 1) break;
        const ssl_err = c.SSL_get_error(ssl_ptr, ret);
        switch (ssl_err) {
            c.SSL_ERROR_WANT_READ => waitIo(
                kq,
                fd,
                std.c.EVFILT.READ,
                connect_deadline,
                options.cancel_fd,
            ) catch |werr| return switch (werr) {
                error.Timeout => HttpError.Timeout,
                error.Cancelled => HttpError.Cancelled,
                error.WaitFailed => HttpError.TlsHandshakeFailed,
            },
            c.SSL_ERROR_WANT_WRITE => waitIo(
                kq,
                fd,
                std.c.EVFILT.WRITE,
                connect_deadline,
                options.cancel_fd,
            ) catch |werr| return switch (werr) {
                error.Timeout => HttpError.Timeout,
                error.Cancelled => HttpError.Cancelled,
                error.WaitFailed => HttpError.TlsHandshakeFailed,
            },
            else => {
                if (conn_wrap) |*cw| {
                    // The verdict is still readable off the failed SSL:
                    // OpenSSL keeps the verification result in place
                    // (session.zig logDaneHandshakeFailure does the same).
                    const v = cw.daneVerdict(dane_prepared, &dane_state.?);
                    log.warn("https: {s}:{d} rejected by DANE: {s}", .{
                        parsed.host,
                        parsed.port,
                        @tagName(v.failure orelse .backend_error),
                    });
                }
                return HttpError.TlsHandshakeFailed;
            },
        }
    }

    const path_name: []const u8 = if (conn_wrap) |*cw| blk: {
        const v = cw.daneVerdict(dane_prepared, &dane_state.?);
        switch (v.outcome) {
            .verified => break :blk danePathName(v.matched.?.usage),
            // session.zig finishDane fails closed on both: a mismatch and
            // an armed handshake that proved nothing.
            .no_usable_records => {
                log.warn("https: {s}:{d} TLSA set held no usable record, refusing", .{ parsed.host, parsed.port });
                return HttpError.TlsHandshakeFailed;
            },
            .failed => {
                log.warn("https: {s}:{d} failed DANE verification: {s}", .{
                    parsed.host,
                    parsed.port,
                    @tagName(v.failure orelse .backend_error),
                });
                return HttpError.TlsHandshakeFailed;
            },
        }
    } else "pkix";
    // The verification path at debug per request, and at info only when
    // the endpoint's path is first seen or changes (path_log dedupes it
    // across the worker threads that share this Client).
    if (client.path_log.note(parsed.host, parsed.port, path_name)) {
        if (builtin.is_test) {
            if (client.test_info_hook) |hook| hook(parsed.host, parsed.port, path_name);
        }
        log.info("https: {s}:{d} peer verified via {s}", .{ parsed.host, parsed.port, path_name });
    }
    log.debug("https: {s}:{d} request verification path {s}", .{ parsed.host, parsed.port, path_name });
    return .{ .fd = fd, .ssl_ptr = ssl_ptr };
}

/// Build the request head plus body into one heap buffer (secrets in the
/// body are wiped before free) and write it out. On WANT_* the retry
/// passes the identical pointer and length (freebsd-ktls D3).
fn sendRequest(
    conn: Conn,
    kq: posix.fd_t,
    allocator: Allocator,
    method: []const u8,
    parsed: ParsedUrl,
    body: ?[]const u8,
    content_type: ?[]const u8,
    options: RequestOptions,
) HttpError!void {
    const body_len = if (body) |b| b.len else 0;
    const req_buf = allocator.alloc(
        u8,
        MAX_HEAD_SIZE + body_len,
    ) catch return HttpError.OutOfMemory;
    defer {
        std.crypto.secureZero(u8, req_buf);
        allocator.free(req_buf);
    }

    var head_len: usize = 0;
    {
        var w: std.Io.Writer = .fixed(req_buf[0..MAX_HEAD_SIZE]);
        w.print("{s} {s} HTTP/1.1\r\n", .{ method, parsed.path }) catch return HttpError.InvalidUrl;
        w.print("Host: {s}\r\n", .{parsed.host_header}) catch return HttpError.InvalidUrl;
        w.writeAll("User-Agent: xmppd/0.1\r\n") catch return HttpError.InvalidUrl;
        // No Connection header: HTTP/1.1 defaults to keep-alive, which
        // the per-thread idle pool relies on.
        if (body) |b| {
            if (content_type) |ct| {
                w.print("Content-Type: {s}\r\n", .{ct}) catch return HttpError.InvalidUrl;
            }
            w.print("Content-Length: {d}\r\n", .{b.len}) catch return HttpError.InvalidUrl;
        }
        w.writeAll("\r\n") catch return HttpError.InvalidUrl;
        head_len = w.buffered().len;
    }
    if (body) |b| @memcpy(req_buf[head_len..][0..b.len], b);
    const req_data = req_buf[0 .. head_len + body_len];

    var sent: usize = 0;
    while (sent < req_data.len) {
        c.ERR_clear_error();
        const ret = c.SSL_write(
            conn.ssl_ptr,
            @ptrCast(req_data.ptr + sent),
            @intCast(req_data.len - sent),
        );
        if (ret > 0) {
            sent += @intCast(ret);
            continue;
        }
        const ssl_err = c.SSL_get_error(conn.ssl_ptr, ret);
        switch (ssl_err) {
            c.SSL_ERROR_WANT_READ => waitIo(
                kq,
                conn.fd,
                std.c.EVFILT.READ,
                options.deadline_ns,
                options.cancel_fd,
            ) catch |werr| return switch (werr) {
                error.Timeout => HttpError.Timeout,
                error.Cancelled => HttpError.Cancelled,
                error.WaitFailed => HttpError.TlsWriteFailed,
            },
            c.SSL_ERROR_WANT_WRITE => waitIo(
                kq,
                conn.fd,
                std.c.EVFILT.WRITE,
                options.deadline_ns,
                options.cancel_fd,
            ) catch |werr| return switch (werr) {
                error.Timeout => HttpError.Timeout,
                error.Cancelled => HttpError.Cancelled,
                error.WaitFailed => HttpError.TlsWriteFailed,
            },
            else => return HttpError.TlsWriteFailed,
        }
    }
}

/// One request/response exchange on `conn`: write the head plus body,
/// then read the response. `outcome` reports how far the exchange got
/// for the caller's reuse and retry decisions.
fn exchange(
    conn: Conn,
    kq: posix.fd_t,
    allocator: Allocator,
    method: []const u8,
    parsed: ParsedUrl,
    body: ?[]const u8,
    content_type: ?[]const u8,
    options: RequestOptions,
    outcome: *ReadOutcome,
) HttpError!Response {
    try sendRequest(conn, kq, allocator, method, parsed, body, content_type, options);
    return readResponse(conn, kq, allocator, options, outcome);
}

/// Read the response against the total deadline, parse it and copy the
/// body into a right-sized allocation the caller owns.
fn readResponse(
    conn: Conn,
    kq: posix.fd_t,
    allocator: Allocator,
    options: RequestOptions,
    outcome: *ReadOutcome,
) HttpError!Response {
    const resp_buf = allocator.alloc(u8, MAX_RESPONSE_SIZE) catch return HttpError.OutOfMemory;
    defer {
        std.crypto.secureZero(u8, resp_buf);
        allocator.free(resp_buf);
    }

    var total: usize = 0;
    var saw_eof = false;
    var framed = false;
    while (!saw_eof) {
        if (total >= MAX_RESPONSE_SIZE) return HttpError.ResponseTooLarge;
        if (total > 0) switch (responseComplete(resp_buf[0..total])) {
            .done => |need| {
                // Bytes beyond the declared frame are a protocol
                // violation; the conn is not trustworthy to park.
                framed = need == total;
                total = need;
                break;
            },
            .incomplete => {},
            .err => |herr| return herr,
        };
        c.ERR_clear_error();
        const ret = c.SSL_read(
            conn.ssl_ptr,
            @ptrCast(resp_buf.ptr + total),
            @intCast(MAX_RESPONSE_SIZE - total),
        );
        if (ret > 0) {
            outcome.saw_byte = true;
            total += @intCast(ret);
            continue;
        }
        const ssl_err = c.SSL_get_error(conn.ssl_ptr, ret);
        switch (ssl_err) {
            c.SSL_ERROR_ZERO_RETURN => saw_eof = true,
            c.SSL_ERROR_SYSCALL => {
                if (total > 0) {
                    saw_eof = true;
                } else {
                    return HttpError.TlsReadFailed;
                }
            },
            c.SSL_ERROR_WANT_READ => waitIo(
                kq,
                conn.fd,
                std.c.EVFILT.READ,
                options.deadline_ns,
                options.cancel_fd,
            ) catch |werr| return switch (werr) {
                error.Timeout => HttpError.Timeout,
                error.Cancelled => HttpError.Cancelled,
                error.WaitFailed => HttpError.TlsReadFailed,
            },
            c.SSL_ERROR_WANT_WRITE => waitIo(
                kq,
                conn.fd,
                std.c.EVFILT.WRITE,
                options.deadline_ns,
                options.cancel_fd,
            ) catch |werr| return switch (werr) {
                error.Timeout => HttpError.Timeout,
                error.Cancelled => HttpError.Cancelled,
                error.WaitFailed => HttpError.TlsReadFailed,
            },
            else => return HttpError.TlsReadFailed,
        }
    }

    if (total == 0) return HttpError.InvalidResponse;

    const resp_data = resp_buf[0..total];
    const status = parseStatusLine(resp_data) orelse return HttpError.InvalidResponse;

    // Find body (after \r\n\r\n)
    const header_end = std.mem.indexOf(
        u8,
        resp_data,
        "\r\n\r\n",
    ) orelse return HttpError.InvalidResponse;
    const body_start = header_end + 4;

    // A declared Content-Length bounds the body; a short body at EOF is a
    // truncated response. A chunked body is validated and decoded in
    // place; its decoded bytes never outgrow their framing.
    var body_slice = resp_data[body_start..];
    switch (parseResponseHead(resp_data[0..header_end])) {
        .invalid => return HttpError.InvalidResponse,
        .too_large => return HttpError.ResponseTooLarge,
        .eof_body => {},
        .length => |cl| {
            if (body_slice.len < cl) return HttpError.InvalidResponse;
            body_slice = body_slice[0..cl];
        },
        .chunked => switch (chunkedScan(body_slice, body_slice)) {
            .incomplete, .invalid => return HttpError.InvalidResponse,
            .too_large => return HttpError.ResponseTooLarge,
            .done => |cs| body_slice = body_slice[0..cs.decoded],
        },
    }

    // Reuse requires a response that finished on its declared framing
    // (never an EOF-delimited body), HTTP/1.1 persistence, and no
    // Connection: close from the peer.
    outcome.reusable = framed and
        std.mem.eql(u8, resp_data[0..8], "HTTP/1.1") and
        !responseWantsClose(resp_data[0..header_end]);

    // Copy body to a right-sized allocation
    const body_copy = allocator.alloc(u8, body_slice.len) catch return HttpError.OutOfMemory;
    @memcpy(body_copy, body_slice);

    return Response{
        .status = status,
        .body = body_copy,
        .allocator = allocator,
    };
}

/// What a response head declares, once the header terminator is present.
const HeadParse = union(enum) {
    /// No Content-Length header: the body runs to EOF.
    eof_body,
    /// Declared body length within MAX_RESPONSE_SIZE.
    length: usize,
    /// A sole "chunked" Transfer-Encoding (RFC 9112 6.1).
    chunked,
    /// A malformed Content-Length, disagreeing duplicates, a
    /// Transfer-Encoding that is not a sole "chunked", or a
    /// Transfer-Encoding alongside a Content-Length.
    invalid,
    /// A declared length above MAX_RESPONSE_SIZE.
    too_large,
};

/// RFC 9110 5.6.2 tchar: the field-name alphabet.
fn isTchar(ch: u8) bool {
    return switch (ch) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        '0'...'9', 'A'...'Z', 'a'...'z' => true,
        else => false,
    };
}

/// RFC 9110 5.1 field-line grammar: field-name is 1*tchar, then ":",
/// then field-value bytes (VCHAR / SP / HTAB / obs-text). A bare CR
/// (RFC 9112 2.2), NUL or any other CTL is never a field-value byte.
fn validFieldLine(line: []const u8) bool {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return false;
    if (colon == 0) return false;
    for (line[0..colon]) |ch| {
        if (!isTchar(ch)) return false;
    }
    for (line[colon + 1 ..]) |ch| {
        if (ch != '\t' and (ch < ' ' or ch == 0x7f)) return false;
    }
    return true;
}

/// Parse the response head: strict Content-Length (decimal digits only,
/// duplicates must agree) and Transfer-Encoding only as a sole "chunked".
fn parseResponseHead(head: []const u8) HeadParse {
    var content_length: ?usize = null;
    var transfer_chunked = false;
    var it = std.mem.splitScalar(u8, head, '\n');
    _ = it.next(); // status line
    while (it.next()) |line_raw| {
        const line = std.mem.trimRight(u8, line_raw, "\r");
        // One grammar check for every field line: name 1*tchar, value
        // bytes VCHAR / SP / HTAB / obs-text. It subsumes the obs-fold
        // (RFC 9112 5.2), empty-name, no-colon and
        // whitespace-before-colon rejections, and keeps a bare CR, NUL
        // or other CTL from hiding a field (RFC 9112 2.2). An empty
        // line is a tolerated bare-LF artifact of the line split.
        if (line.len > 0 and !validFieldLine(line)) return .invalid;
        const te_prefix = "transfer-encoding:";
        // ">=" counts a bare "Transfer-Encoding:" (empty value) as a
        // declared TE. The one implemented coding is a sole "chunked"
        // (RFC 9112 6.1); a stacked coding or "identity" is not, and
        // the coding is applied only once.
        if (line.len >= te_prefix.len and
            std.ascii.eqlIgnoreCase(line[0..te_prefix.len], te_prefix))
        {
            const value = std.mem.trim(u8, line[te_prefix.len..], " \t");
            if (!std.ascii.eqlIgnoreCase(value, "chunked")) return .invalid;
            if (transfer_chunked) return .invalid;
            transfer_chunked = true;
        }
        const cl_prefix = "content-length:";
        // A bare "Content-Length:" reaches the value parse and dies on
        // the empty value (RFC 9112 6.3 rule 5), like every other bad CL.
        if (line.len < cl_prefix.len) continue;
        if (!std.ascii.eqlIgnoreCase(line[0..cl_prefix.len], cl_prefix)) continue;
        const value = std.mem.trim(u8, line[cl_prefix.len..], " \t");
        const cl = parseContentLengthValue(value) catch |err| switch (err) {
            error.Invalid => return .invalid,
            error.Overflow => return .too_large,
        };
        if (cl > MAX_RESPONSE_SIZE) return .too_large;
        if (content_length) |prev| {
            if (prev != cl) return .invalid;
        } else {
            content_length = cl;
        }
    }
    if (transfer_chunked) {
        // RFC 9112 6.3 rules 3 and 5: a message carrying both a
        // Transfer-Encoding and a Content-Length is ambiguous framing;
        // reject it rather than guess.
        if (content_length != null) return .invalid;
        return .chunked;
    }
    return if (content_length) |cl| .{ .length = cl } else .eof_body;
}

/// Does the response head's Connection field ask for close? RFC 9110
/// 7.6.1: Connection is a comma-separated option list; any "close"
/// token ends the conn after this response.
fn responseWantsClose(head: []const u8) bool {
    var it = std.mem.splitScalar(u8, head, '\n');
    _ = it.next(); // status line
    const prefix = "connection:";
    while (it.next()) |line_raw| {
        const line = std.mem.trimRight(u8, line_raw, "\r");
        if (line.len < prefix.len or
            !std.ascii.eqlIgnoreCase(line[0..prefix.len], prefix)) continue;
        var tok = std.mem.splitScalar(u8, line[prefix.len..], ',');
        while (tok.next()) |t| {
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, t, " \t"), "close")) return true;
        }
    }
    return false;
}

/// A Content-Length field value: ASCII digits only. No sign, no
/// underscores, nothing after the trim. Overflow of usize is reported
/// apart so the caller can answer ResponseTooLarge.
fn parseContentLengthValue(value: []const u8) error{ Invalid, Overflow }!usize {
    if (value.len == 0) return error.Invalid;
    for (value) |ch| {
        if (ch < '0' or ch > '9') return error.Invalid;
    }
    return std.fmt.parseInt(usize, value, 10) catch return error.Overflow;
}

/// Longest accepted chunk-size line (size digits plus extensions).
const MAX_CHUNK_SIZE_LINE: usize = 256;

/// One hex digit of a chunk size.
fn hexDigit(ch: u8) ?u8 {
    return switch (ch) {
        '0'...'9' => ch - '0',
        'a'...'f' => ch - 'a' + 10,
        'A'...'F' => ch - 'A' + 10,
        else => null,
    };
}

/// RFC 9112 6.1.1 chunk-ext grammar, strict:
/// *( ";" token [ "=" ( token / quoted-string ) ] ) with no BWS.
/// Semantics are ignored; the shape is bounded so an extension cannot
/// hide framing or grow without limit.
fn validChunkExtensions(exts: []const u8) bool {
    var i: usize = 0;
    while (i < exts.len) {
        if (exts[i] != ';') return false;
        i += 1;
        const name_start = i;
        while (i < exts.len and isTchar(exts[i])) : (i += 1) {}
        if (i == name_start) return false;
        if (i < exts.len and exts[i] == '=') {
            i += 1;
            if (i < exts.len and exts[i] == '"') {
                i += 1;
                var closed = false;
                while (i < exts.len) {
                    const ch = exts[i];
                    if (ch == '"') {
                        closed = true;
                        i += 1;
                        break;
                    }
                    if (ch == '\\' and i + 1 < exts.len) {
                        const esc = exts[i + 1];
                        if (esc != '\t' and (esc < ' ' or esc == 0x7f)) return false;
                        i += 2;
                        continue;
                    }
                    if (ch != '\t' and (ch < ' ' or ch == 0x7f)) return false;
                    i += 1;
                }
                if (!closed) return false;
            } else {
                const val_start = i;
                while (i < exts.len and isTchar(exts[i])) : (i += 1) {}
                if (i == val_start) return false;
            }
        }
    }
    return true;
}

/// Completeness of a partially read chunked body.
const ChunkScan = union(enum) {
    incomplete,
    invalid,
    too_large,
    /// Complete stream: `framed` bytes of chunk coding produced
    /// `decoded` body bytes.
    done: struct { framed: usize, decoded: usize },
};

/// Strict RFC 9112 6.1 chunked-body scan: bounded chunk-size lines and
/// sizes, strictly shaped extensions (ignored), and no trailers (the
/// last chunk is followed by one empty line). With `out` non-null the
/// decoded body is copied into it while scanning; `out.len >= data.len`
/// is the caller's contract, and the decoded body never outgrows its
/// framing, so `out` may alias `data`.
fn chunkedScan(data: []const u8, out: ?[]u8) ChunkScan {
    var pos: usize = 0;
    var decoded: usize = 0;
    while (true) {
        // Chunk-size line: 1*HEXDIT [ chunk-ext ] CRLF, bounded.
        const line_start = pos;
        var line_end: usize = pos;
        while (line_end < data.len and data[line_end] != '\n') : (line_end += 1) {
            if (line_end - line_start >= MAX_CHUNK_SIZE_LINE) return .invalid;
        }
        if (line_end >= data.len) return .incomplete;
        if (line_end == line_start or data[line_end - 1] != '\r') return .invalid;
        const content = data[line_start .. line_end - 1];

        var size: usize = 0;
        var i: usize = 0;
        while (i < content.len and content[i] != ';') : (i += 1) {
            const digit = hexDigit(content[i]) orelse return .invalid;
            // size stays <= MAX_RESPONSE_SIZE, so the multiply cannot
            // approach usize overflow.
            size = size * 16 + digit;
            if (size > MAX_RESPONSE_SIZE) return .too_large;
        }
        if (i == 0) return .invalid;
        if (!validChunkExtensions(content[i..])) return .invalid;
        pos = line_end + 1;

        if (size == 0) {
            // Last chunk: trailers are rejected, so the stream ends
            // with one empty line (RFC 9112 6.1.2).
            if (pos + 2 > data.len) return .incomplete;
            if (!std.mem.eql(u8, data[pos..][0..2], "\r\n")) return .invalid;
            pos += 2;
            return .{ .done = .{ .framed = pos, .decoded = decoded } };
        }

        const data_end = std.math.add(usize, pos, size) catch return .too_large;
        if (data_end + 2 > data.len) return .incomplete;
        if (!std.mem.eql(u8, data[data_end..][0..2], "\r\n")) return .invalid;
        if (out) |dst| {
            const dst_slice = dst[decoded..][0..size];
            const src_slice = data[pos..data_end];
            // dst_slice starts at or before src_slice (decoded bytes
            // never outgrow the framing consumed), so a forward byte
            // copy is safe even with `out` aliasing `data`.
            for (dst_slice, src_slice) |*d, s| d.* = s;
        }
        decoded += size;
        if (decoded > MAX_RESPONSE_SIZE) return .too_large;
        pos = data_end + 2;
    }
}

/// Completeness of a partially read response.
const Complete = union(enum) {
    /// Still in flight (or no Content-Length was declared, in which case
    /// EOF terminates the body).
    incomplete,
    /// Total bytes a complete response occupies.
    done: usize,
    /// The head is already unusable; stop reading.
    err: HttpError,
};

/// Decide whether `data` holds a complete response.
fn responseComplete(data: []const u8) Complete {
    const header_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse return .incomplete;
    const body_start = header_end + 4;
    switch (parseResponseHead(data[0..header_end])) {
        .invalid => return .{ .err = HttpError.InvalidResponse },
        .too_large => return .{ .err = HttpError.ResponseTooLarge },
        .eof_body => return .incomplete,
        .length => |cl| {
            const need = std.math.add(usize, body_start, cl) catch
                return .{ .err = HttpError.ResponseTooLarge };
            if (data.len >= need) return .{ .done = need };
            return .incomplete;
        },
        .chunked => switch (chunkedScan(data[body_start..], null)) {
            .incomplete => return .incomplete,
            .invalid => return .{ .err = HttpError.InvalidResponse },
            .too_large => return .{ .err = HttpError.ResponseTooLarge },
            .done => |cs| {
                const need = std.math.add(usize, body_start, cs.framed) catch
                    return .{ .err = HttpError.ResponseTooLarge };
                return .{ .done = need };
            },
        },
    }
}

// ============================================================================
// URL Parsing
// ============================================================================

const ParsedUrl = struct {
    host: []const u8,
    host_header: []const u8,
    port: u16,
    path: []const u8,
};

fn parseUrl(url: []const u8) ?ParsedUrl {
    // Must start with https://
    const prefix = "https://";
    if (!std.mem.startsWith(u8, url, prefix)) return null;

    const after_scheme = url[prefix.len..];

    // Split host:port from path
    const path_start = std.mem.indexOfScalar(u8, after_scheme, '/') orelse after_scheme.len;
    const authority = after_scheme[0..path_start];
    const path = if (path_start < after_scheme.len) after_scheme[path_start..] else "/";

    // Split host from port
    var host: []const u8 = authority;
    var port: u16 = 443;

    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        host = authority[0..colon];
        port = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch 443;
    }

    if (host.len == 0) return null;

    return ParsedUrl{
        .host = host,
        .host_header = authority,
        .port = port,
        .path = path,
    };
}

// ============================================================================
// TLS
// ============================================================================

fn initTlsClient(ca_file: ?[]const u8) ?*c.SSL_CTX {
    const method = c.TLS_client_method() orelse return null;
    const ctx = c.SSL_CTX_new(method) orelse return null;

    // Set verification mode
    c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);

    // Load CA bundle
    if (ca_file) |path| {
        var path_buf: [1024]u8 = undefined;
        if (path.len < path_buf.len) {
            @memcpy(path_buf[0..path.len], path);
            path_buf[path.len] = 0;
            _ = c.SSL_CTX_load_verify_locations(ctx, &path_buf, null);
        }
    } else {
        // Try common paths
        const ca_paths = [_][*:0]const u8{
            "/usr/local/share/certs/ca-root-nss.crt",
            "/etc/ssl/cert.pem",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/certs/ca-certificates.crt",
        };
        for (ca_paths) |p| {
            if (c.SSL_CTX_load_verify_locations(ctx, p, null) == 1) break;
        }
    }

    return ctx;
}

// ============================================================================
// Response Parsing
// ============================================================================

/// RFC 9112 4: status-line = HTTP-version SP status-code SP [ reason-phrase ]
/// Only HTTP/1.1 and HTTP/1.0 are spoken here. The code is exactly three
/// DIGIT (never signed, never longer) and is followed by the second SP,
/// even for an empty reason phrase. Reason-phrase bytes are HTAB / SP /
/// VCHAR / obs-text, never a CTL.
fn parseStatusLine(data: []const u8) ?u16 {
    const line_end = std.mem.indexOf(u8, data, "\r\n") orelse return null;
    const line = data[0..line_end];
    // "HTTP/1.X " + 3 DIGIT + " " is the shortest accepted shape.
    if (line.len < 13) return null;
    const version = line[0..8];
    if (!std.mem.eql(u8, version, "HTTP/1.1") and
        !std.mem.eql(u8, version, "HTTP/1.0"))
    {
        return null;
    }
    if (line[8] != ' ') return null;
    var code: u16 = 0;
    for (line[9..12]) |ch| {
        if (ch < '0' or ch > '9') return null;
        code = code * 10 + @as(u16, ch - '0');
    }
    if (line[12] != ' ') return null;
    for (line[13..]) |ch| {
        if (ch != '\t' and (ch < ' ' or ch == 0x7f)) return null;
    }
    return code;
}

// ============================================================================
// Tests
// ============================================================================

fn testOptions(deadline_ms: u64, connect_timeout_ms: u32) RequestOptions {
    return .{
        .deadline_ns = monotonicNs() + deadline_ms * std.time.ns_per_ms,
        .connect_timeout_ms = connect_timeout_ms,
    };
}

test "parseUrl: basic https" {
    const p = parseUrl("https://auth.example.com/auth/v1/.well-known/openid-configuration").?;
    try std.testing.expectEqualStrings("auth.example.com", p.host);
    try std.testing.expectEqualStrings("auth.example.com", p.host_header);
    try std.testing.expectEqual(@as(u16, 443), p.port);
    try std.testing.expectEqualStrings("/auth/v1/.well-known/openid-configuration", p.path);
}

test "parseUrl: custom port" {
    const p = parseUrl("https://auth.morante.dev:8443/auth/v1/oidc/token").?;
    try std.testing.expectEqualStrings("auth.morante.dev", p.host);
    try std.testing.expectEqualStrings("auth.morante.dev:8443", p.host_header);
    try std.testing.expectEqual(@as(u16, 8443), p.port);
    try std.testing.expectEqualStrings("/auth/v1/oidc/token", p.path);
}

test "parseUrl: no path" {
    const p = parseUrl("https://example.com").?;
    try std.testing.expectEqualStrings("example.com", p.host);
    try std.testing.expectEqual(@as(u16, 443), p.port);
    try std.testing.expectEqualStrings("/", p.path);
}

test "parseUrl: invalid" {
    try std.testing.expect(parseUrl("http://example.com") == null);
    try std.testing.expect(parseUrl("ftp://example.com") == null);
    try std.testing.expect(parseUrl("") == null);
}

test "parseStatusLine: valid" {
    try std.testing.expectEqual(@as(u16, 200), parseStatusLine("HTTP/1.1 200 OK\r\n").?);
    try std.testing.expectEqual(@as(u16, 401), parseStatusLine("HTTP/1.1 401 Unauthorized\r\n").?);
    try std.testing.expectEqual(@as(u16, 404), parseStatusLine("HTTP/1.0 404 Not Found\r\n").?);
}

test "parseStatusLine: invalid" {
    try std.testing.expect(parseStatusLine("") == null);
    try std.testing.expect(parseStatusLine("GARBAGE") == null);
    try std.testing.expect(parseStatusLine("HTTP/1.1") == null);
}

test "parseStatusLine: strict RFC 9112 4 shape" {
    // The code is exactly three DIGIT followed by the second SP; the
    // reason phrase may be empty but is never a CTL. The old
    // fixed-offset parse accepted most shapes below silently.
    try std.testing.expect(parseStatusLine("HTTP/1.1 2000 OK\r\n") == null);
    try std.testing.expect(parseStatusLine("HTTP/1.1 200OK\r\n") == null);
    try std.testing.expect(parseStatusLine("HTTP/1.1 +12 OK\r\n") == null);
    try std.testing.expect(parseStatusLine("HTTP/1.1 -00 OK\r\n") == null);
    try std.testing.expect(parseStatusLine("HTTP/1.1 20a OK\r\n") == null);
    try std.testing.expect(parseStatusLine("HTTP/1.9 200 OK\r\n") == null);
    try std.testing.expect(parseStatusLine("HTTP/2.0 200 OK\r\n") == null);
    // The second SP is required even for an empty reason phrase.
    try std.testing.expect(parseStatusLine("HTTP/1.1 204\r\n") == null);
    try std.testing.expectEqual(@as(u16, 204), parseStatusLine("HTTP/1.1 204 \r\n").?);
    // Reason phrases may carry VCHAR, SP, HTAB and obs-text.
    try std.testing.expectEqual(
        @as(u16, 200),
        parseStatusLine("HTTP/1.1 200 fine : yes\ttab\r\n").?,
    );
    // A bare CR inside the reason phrase is a CTL, not a phrase byte.
    try std.testing.expect(parseStatusLine("HTTP/1.1 200 bad\rph\r\n") == null);
}

/// Loopback TCP listener that accepts connections into a hold array and
/// never answers, then closes everything after `hold_ms`. Publishes the
/// bound port once listening.
fn serveHanging(hold_ms: u64, port_out: *std.atomic.Value(u16)) void {
    const listen_fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(listen_fd);
    var addr: std.c.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch return;
    posix.listen(listen_fd, 4) catch return;
    var alen: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    posix.getsockname(listen_fd, @ptrCast(&addr), &alen) catch return;
    port_out.store(std.mem.bigToNative(u16, addr.port), .release);

    const deadline = std.time.milliTimestamp() + @as(i64, @intCast(hold_ms));
    var held: [8]posix.fd_t = undefined;
    var held_len: usize = 0;
    defer for (held[0..held_len]) |conn_fd| posix.close(conn_fd);
    while (std.time.milliTimestamp() < deadline) {
        var fds = [_]posix.pollfd{.{ .fd = listen_fd, .events = posix.POLL.IN, .revents = 0 }};
        const pn = posix.poll(&fds, 100) catch 0;
        if (pn <= 0) continue;
        if (held_len >= held.len) continue;
        const conn_fd = posix.accept(listen_fd, null, null, 0) catch continue;
        held[held_len] = conn_fd;
        held_len += 1;
    }
}

test "a server that accepts and never answers hits the connect deadline" {
    var port = std.atomic.Value(u16).init(0);
    // The stub lets go after ~3 s so a build whose handshake wait lost its
    // deadline fails this test on elapsed time instead of hanging forever.
    const th = try std.Thread.spawn(.{}, serveHanging, .{ @as(u64, 3000), &port });
    defer th.join();
    const dl = std.time.milliTimestamp() + 3000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = port.load(.acquire);
    try std.testing.expect(p != 0);

    var client = try Client.init(null);
    defer client.deinit();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/", .{p});

    const t0 = monotonicNs();
    try std.testing.expectError(
        HttpError.Timeout,
        client.get(std.testing.allocator, url, testOptions(2000, 200)),
    );
    const elapsed_ms = (monotonicNs() - t0) / std.time.ns_per_ms;
    try std.testing.expect(elapsed_ms >= 150 and elapsed_ms <= 1000);
}

test "a refused connection is ConnectionFailed" {
    // Bind an ephemeral port, then drop it: the port now refuses.
    const listen_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    var addr: std.c.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    try posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in));
    var alen: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    try posix.getsockname(listen_fd, @ptrCast(&addr), &alen);
    const port = std.mem.bigToNative(u16, addr.port);
    posix.close(listen_fd);

    var client = try Client.init(null);
    defer client.deinit();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/", .{port});
    try std.testing.expectError(
        HttpError.ConnectionFailed,
        client.get(std.testing.allocator, url, testOptions(2000, 2000)),
    );
}

fn closeAfter(fds: []const posix.fd_t, delay_ms: u64) void {
    std.Thread.sleep(delay_ms * std.time.ns_per_ms);
    for (fds) |fd| posix.close(fd);
}

test "closing the cancel pipe aborts an in-flight request" {
    var port = std.atomic.Value(u16).init(0);
    const th = try std.Thread.spawn(.{}, serveHanging, .{ @as(u64, 10000), &port });
    defer th.join();
    const dl = std.time.milliTimestamp() + 3000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = port.load(.acquire);
    try std.testing.expect(p != 0);

    const pipe_fds = try posix.pipe();
    defer posix.close(pipe_fds[0]);

    const closer = try std.Thread.spawn(
        .{},
        closeAfter,
        .{ @as([]const posix.fd_t, pipe_fds[1..2]), @as(u64, 100) },
    );
    defer closer.join();

    var client = try Client.init(null);
    defer client.deinit();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/", .{p});

    const t0 = monotonicNs();
    try std.testing.expectError(
        HttpError.Cancelled,
        client.get(std.testing.allocator, url, .{
            .deadline_ns = monotonicNs() + 10 * std.time.ns_per_s,
            .connect_timeout_ms = 10000,
            .cancel_fd = pipe_fds[0],
        }),
    );
    const elapsed_ms = (monotonicNs() - t0) / std.time.ns_per_ms;
    try std.testing.expect(elapsed_ms < 1000);
}

// --- Hostname verification (T357/S8): in-process TLS server with a     ---
// --- self-signed cert generated at test time (no key material in-tree). ---

/// Write a fresh self-signed cert+key for "localhost" into `dir` via the
/// system OpenSSL CLI. Returns error.SkipZigTest when the tool is missing.
/// openssl writes key-generation progress to stderr, which can exceed a
/// small output cap under load, so allow generous room for it.
fn genTestCert(dir: std.fs.Dir) !void {
    const r = std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &.{
            "openssl",                      "req",           "-x509",
            "-newkey",                      "rsa:2048",      "-nodes",
            "-subj",                        "/CN=localhost", "-addext",
            "subjectAltName=DNS:localhost", "-days",         "1",
            "-keyout",                      "key.pem",       "-out",
            "cert.pem",
        },
        .cwd_dir = dir,
        .max_output_bytes = 64 * 1024,
    }) catch return error.SkipZigTest;
    defer std.testing.allocator.free(r.stdout);
    defer std.testing.allocator.free(r.stderr);
    switch (r.term) {
        .Exited => |code| {
            // Older OpenSSL lacks -addext; retry through the config-less
            // openssl x509 path only if the first form failed.
            if (code != 0) return error.SkipZigTest;
        },
        else => return error.SkipZigTest,
    }
}

/// Serve exactly `n` tiny HTTP replies on a loopback TLS listener, then
/// close. Runs on its own thread; a deadline keeps the test from hanging
/// when the client never connects (or aborts mid-handshake, the point of
/// the mismatch case).
fn serveTlsResponses(
    cert_path: [*:0]const u8,
    key_path: [*:0]const u8,
    n: *std.atomic.Value(usize),
) void {
    const method = c.TLS_server_method() orelse return;
    const ctx = c.SSL_CTX_new(method) orelse return;
    defer c.SSL_CTX_free(ctx);
    if (c.SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1) return;
    if (c.SSL_CTX_use_PrivateKey_file(ctx, key_path, c.SSL_FILETYPE_PEM) != 1) return;

    const listen_fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(listen_fd);
    var addr: std.c.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch return;
    posix.listen(listen_fd, 4) catch return;
    var alen: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    posix.getsockname(listen_fd, @ptrCast(&addr), &alen) catch return;
    n.store(std.mem.nativeToBig(u16, addr.port), .release);

    // Serve the two expected clients. Only an accepted connection counts
    // against that budget: poll timeouts and transient accept errors retry
    // within the deadline, so a pause between client requests is harmless.
    const deadline = std.time.milliTimestamp() + 10000;
    var served: usize = 0;
    while (served < 2 and std.time.milliTimestamp() < deadline) {
        var fds = [_]posix.pollfd{.{ .fd = listen_fd, .events = posix.POLL.IN, .revents = 0 }};
        const pn = posix.poll(&fds, 500) catch 0;
        if (pn <= 0) continue;
        const conn = posix.accept(listen_fd, null, null, 0) catch continue;
        defer posix.close(conn);
        const ssl_ptr = c.SSL_new(ctx) orelse continue;
        defer c.SSL_free(ssl_ptr);
        _ = c.SSL_set_fd(ssl_ptr, conn);
        served += 1;
        if (c.SSL_accept(ssl_ptr) != 1) continue; // mismatch case dies here
        var buf: [4096]u8 = undefined;
        var total: usize = 0;
        while (total < buf.len and std.time.milliTimestamp() < deadline) {
            const r = c.SSL_read(ssl_ptr, @ptrCast(buf[total..].ptr), @intCast(buf.len - total));
            if (r <= 0) break;
            total += @intCast(r);
            if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n") != null) break;
        }
        const resp = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nok\r\n";
        _ = c.SSL_write(ssl_ptr, resp.ptr, resp.len);
    }
}

test "TLS: hostname check pins the certificate identity to the URL host (T357)" {
    // Throwaway cert/key generated at test time so no key material ever
    // sits in the tree.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/cert.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/key.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(key_path);

    var port = std.atomic.Value(usize).init(0);
    const th = try std.Thread.spawn(
        .{},
        serveTlsResponses,
        .{ cert_path.ptr, key_path.ptr, &port },
    );
    defer th.join();
    const dl = std.time.milliTimestamp() + 3000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = port.load(.acquire);
    try std.testing.expect(p != 0);

    var url_buf: [128]u8 = undefined;
    const good_url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/", .{p});
    const dns_srv = try startFakeDns(.{});
    defer stopFakeDns(dns_srv);
    var client = try Client.init(cert_path);
    defer client.deinit();
    useFakeDns(&client, dns_srv);
    var resp = try client.get(std.testing.allocator, good_url, testOptions(5000, 2000));
    defer resp.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp.status);

    // Same endpoint by IP literal: certificate is for 'localhost', so the
    // handshake must fail before S8 would have silently accepted it.
    const bad_url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/", .{p});
    try std.testing.expectError(
        HttpError.TlsHandshakeFailed,
        client.get(std.testing.allocator, bad_url, testOptions(5000, 2000)),
    );
}

test "TLS: the in-process server keeps serving across a pause between requests" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/cert.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/key.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(key_path);

    var port = std.atomic.Value(usize).init(0);
    const th = try std.Thread.spawn(
        .{},
        serveTlsResponses,
        .{ cert_path.ptr, key_path.ptr, &port },
    );
    defer th.join();
    const dl = std.time.milliTimestamp() + 3000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = port.load(.acquire);
    try std.testing.expect(p != 0);

    const dns_srv = try startFakeDns(.{});
    defer stopFakeDns(dns_srv);
    var client = try Client.init(cert_path);
    defer client.deinit();
    useFakeDns(&client, dns_srv);
    var first_buf: [128]u8 = undefined;
    const first_url = try std.fmt.bufPrint(&first_buf, "https://localhost:{d}/", .{p});
    var resp1 = try client.get(std.testing.allocator, first_url, testOptions(5000, 2000));
    defer resp1.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp1.status);

    // The pause outlasts one poll timeout in the server thread.
    std.Thread.sleep(700 * std.time.ns_per_ms);

    var second_buf: [128]u8 = undefined;
    const second_url = try std.fmt.bufPrint(&second_buf, "https://localhost:{d}/", .{p});
    var resp2 = try client.get(std.testing.allocator, second_url, testOptions(5000, 2000));
    defer resp2.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp2.status);
}

// --- verification-path info log dedup -------------------------------

var info_hook_count: usize = 0;

fn countInfoHook(_: []const u8, _: u16, _: []const u8) void {
    info_hook_count += 1;
}

test "TLS: the verification path logs at info once per endpoint" {
    // Two requests to one endpoint emit one info line; the per-request
    // copy rides debug only. The server thread serves two replies.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/cert.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/key.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(key_path);

    var port = std.atomic.Value(usize).init(0);
    const th = try std.Thread.spawn(
        .{},
        serveTlsResponses,
        .{ cert_path.ptr, key_path.ptr, &port },
    );
    defer th.join();
    const dl = std.time.milliTimestamp() + 3000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = port.load(.acquire);
    try std.testing.expect(p != 0);

    const dns_srv = try startFakeDns(.{});
    defer stopFakeDns(dns_srv);
    var client = try Client.init(cert_path);
    defer client.deinit();
    useFakeDns(&client, dns_srv);
    info_hook_count = 0;
    client.test_info_hook = &countInfoHook;

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/", .{p});
    var resp1 = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp1.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp1.status);
    var resp2 = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp2.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp2.status);

    try std.testing.expectEqual(@as(usize, 1), info_hook_count);
}

// --- keep-alive: per-thread idle pool --------------------------------

/// Shared state for the keep-alive fixture server: a small accept loop
/// that spawns one handler thread per connection so an idle pooled conn
/// never blocks a fresh accept.
const KaState = struct {
    port: std.atomic.Value(usize) = .init(0),
    /// Accepted connections; the tests' reuse oracle.
    accepts: std.atomic.Value(usize) = .init(0),
    /// Request heads read, 1-based numbering for the script fields.
    requests: std.atomic.Value(usize) = .init(0),
    /// This request's conn closes without a reply (0 = never).
    close_on: std.atomic.Value(usize) = .init(0),
    /// After replying to this request the conn closes (0 = never).
    close_after: std.atomic.Value(usize) = .init(0),
    /// Set to the request number once close_after's conn was closed:
    /// the FIN is queued before the flag, so a client probing afterwards
    /// sees the EOF deterministically.
    closed_after: std.atomic.Value(usize) = .init(0),
    /// After replying to this request also write a junk record (0 =
    /// never): a peer speaking past the response end.
    extra_after: std.atomic.Value(usize) = .init(0),
    /// On this accept (1-based) write a junk record right after the
    /// handshake, before any request (0 = never).
    junk_on_accept: std.atomic.Value(usize) = .init(0),
    stop: std.atomic.Value(bool) = .init(false),
};

const KaConn = struct {
    ctx: *c.SSL_CTX,
    fd: posix.fd_t,
    st: *KaState,
    /// 1-based accept number, for the accept-scripted fields.
    accept_no: usize,
};

/// One accepted connection: TLS, then a read-head/reply loop honoring
/// the script fields in `st`. Poll keeps the handler responsive to
/// `stop` while the client holds the conn idle in its pool.
fn kaConn(a: KaConn) void {
    var fd = a.fd;
    defer if (fd >= 0) posix.close(fd);
    const ssl_ptr = c.SSL_new(a.ctx) orelse return;
    defer c.SSL_free(ssl_ptr);
    _ = c.SSL_set_fd(ssl_ptr, a.fd);
    if (c.SSL_accept(ssl_ptr) != 1) return;
    if (a.accept_no == a.st.junk_on_accept.load(.acquire)) {
        const junk = "JUNK-NOT-A-RESPONSE";
        _ = c.SSL_write(ssl_ptr, junk.ptr, junk.len);
    }
    const deadline = std.time.milliTimestamp() + 10000;
    var buf: [8192]u8 = undefined;
    var total: usize = 0;
    while (!a.st.stop.load(.acquire) and std.time.milliTimestamp() < deadline) {
        var fds = [_]posix.pollfd{.{ .fd = a.fd, .events = posix.POLL.IN, .revents = 0 }};
        const pn = posix.poll(&fds, 250) catch break;
        if (pn <= 0) continue;
        const r = c.SSL_read(ssl_ptr, @ptrCast(buf[total..].ptr), @intCast(buf.len - total));
        if (r <= 0) return; // peer closed or TLS error
        total += @intCast(r);
        if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n") == null) continue;
        const n = a.st.requests.fetchAdd(1, .acq_rel) + 1;
        if (n == a.st.close_on.load(.acquire)) return; // silent close
        const resp = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nok\r\n";
        _ = c.SSL_write(ssl_ptr, resp.ptr, resp.len);
        if (n == a.st.extra_after.load(.acquire)) {
            const junk = "JUNK-NOT-A-RESPONSE";
            _ = c.SSL_write(ssl_ptr, junk.ptr, junk.len);
        }
        total = 0;
        if (n == a.st.close_after.load(.acquire)) {
            // close_notify, then the socket: the flag is set only after
            // close() queues the FIN.
            _ = c.SSL_shutdown(ssl_ptr);
            posix.close(fd);
            fd = -1;
            a.st.closed_after.store(n, .release);
            return;
        }
    }
}

/// Keep-alive fixture listener: each accepted conn gets a handler
/// thread, so a parked idle conn never stalls a later accept.
fn serveKeepAlive(cert_path: [*:0]const u8, key_path: [*:0]const u8, st: *KaState) void {
    const method = c.TLS_server_method() orelse return;
    const ctx = c.SSL_CTX_new(method) orelse return;
    defer c.SSL_CTX_free(ctx);
    if (c.SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1) return;
    if (c.SSL_CTX_use_PrivateKey_file(ctx, key_path, c.SSL_FILETYPE_PEM) != 1) return;

    const listen_fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(listen_fd);
    var addr: std.c.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch return;
    posix.listen(listen_fd, 4) catch return;
    var alen: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    posix.getsockname(listen_fd, @ptrCast(&addr), &alen) catch return;
    st.port.store(std.mem.nativeToBig(u16, addr.port), .release);

    const deadline = std.time.milliTimestamp() + 15000;
    var handlers: [8]std.Thread = undefined;
    var n_handlers: usize = 0;
    while (!st.stop.load(.acquire) and std.time.milliTimestamp() < deadline) {
        var fds = [_]posix.pollfd{.{ .fd = listen_fd, .events = posix.POLL.IN, .revents = 0 }};
        const pn = posix.poll(&fds, 250) catch break;
        if (pn <= 0) continue;
        const conn = posix.accept(listen_fd, null, null, 0) catch continue;
        const accept_no = st.accepts.fetchAdd(1, .acq_rel) + 1;
        if (n_handlers >= handlers.len) {
            posix.close(conn);
            continue;
        }
        const h = std.Thread.spawn(.{}, kaConn, .{KaConn{
            .ctx = ctx,
            .fd = conn,
            .st = st,
            .accept_no = accept_no,
        }}) catch {
            posix.close(conn);
            continue;
        };
        handlers[n_handlers] = h;
        n_handlers += 1;
    }
    for (handlers[0..n_handlers]) |h| h.join();
}

test "TLS: keep-alive reuses one connection for two GETs to an endpoint" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/cert.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/key.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(key_path);

    var st = KaState{};
    const th = try std.Thread.spawn(.{}, serveKeepAlive, .{ cert_path.ptr, key_path.ptr, &st });
    defer {
        st.stop.store(true, .release);
        th.join();
    }
    const dl = std.time.milliTimestamp() + 3000;
    while (st.port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = st.port.load(.acquire);
    try std.testing.expect(p != 0);

    const dns_srv = try startFakeDns(.{});
    defer stopFakeDns(dns_srv);
    var client = try Client.init(cert_path);
    defer client.deinit();
    defer drainIdlePool();
    useFakeDns(&client, dns_srv);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/jwks", .{p});
    var resp1 = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp1.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp1.status);
    var resp2 = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp2.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp2.status);

    // Both exchanges ran over the first (and only) accept.
    try std.testing.expectEqual(@as(usize, 1), st.accepts.load(.acquire));
    try std.testing.expectEqual(@as(usize, 2), st.requests.load(.acquire));
}

test "TLS: keep-alive retries a GET once when a reused conn dies mid-exchange" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/cert.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/key.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(key_path);

    var st = KaState{};
    // Request 2 closes without a reply: it reaches the reused conn
    // after the liveness probe, so the probe passes and the read fails.
    st.close_on.store(2, .release);
    const th = try std.Thread.spawn(.{}, serveKeepAlive, .{ cert_path.ptr, key_path.ptr, &st });
    defer {
        st.stop.store(true, .release);
        th.join();
    }
    const dl = std.time.milliTimestamp() + 3000;
    while (st.port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = st.port.load(.acquire);
    try std.testing.expect(p != 0);

    const dns_srv = try startFakeDns(.{});
    defer stopFakeDns(dns_srv);
    var client = try Client.init(cert_path);
    defer client.deinit();
    defer drainIdlePool();
    useFakeDns(&client, dns_srv);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/token", .{p});
    var resp1 = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp1.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp1.status);

    // Request 2 dies on the pooled conn before any response byte; the
    // retry lands on a second accept and succeeds.
    var resp2 = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp2.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp2.status);

    try std.testing.expectEqual(@as(usize, 2), st.accepts.load(.acquire));
    try std.testing.expectEqual(@as(usize, 3), st.requests.load(.acquire));
}

test "TLS: keep-alive discards a parked conn the server already closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/cert.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/key.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(key_path);

    var st = KaState{};
    // After replying to request 2 the server closes the conn while the
    // client has it parked.
    st.close_after.store(2, .release);
    const th = try std.Thread.spawn(.{}, serveKeepAlive, .{ cert_path.ptr, key_path.ptr, &st });
    defer {
        st.stop.store(true, .release);
        th.join();
    }
    const dl = std.time.milliTimestamp() + 3000;
    while (st.port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = st.port.load(.acquire);
    try std.testing.expect(p != 0);

    const dns_srv = try startFakeDns(.{});
    defer stopFakeDns(dns_srv);
    var client = try Client.init(cert_path);
    defer client.deinit();
    defer drainIdlePool();
    useFakeDns(&client, dns_srv);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/keys", .{p});
    stale_detects = 0;
    var resp1 = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp1.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp1.status);
    var resp2 = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp2.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp2.status);
    // Both ran over the same accept; without pooling this is 2 already.
    try std.testing.expectEqual(@as(usize, 1), st.accepts.load(.acquire));

    // The server has now closed the parked conn; closed_after is set
    // only after close() queued the FIN.
    while (st.closed_after.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    try std.testing.expectEqual(@as(usize, 2), st.closed_after.load(.acquire));

    var resp3 = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp3.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp3.status);

    // The probe discarded the dead conn; a blind reuse would have been
    // retried on a third accept.
    try std.testing.expectEqual(@as(usize, 1), stale_detects);
    try std.testing.expectEqual(@as(usize, 2), st.accepts.load(.acquire));
}

/// The parked entry for (host, port), or null when none is parked.
fn parkedEntry(host: []const u8, port: u16) ?*IdlePool.Entry {
    for (&idle_pool.entries) |*e| {
        if (e.used and e.port == port and e.host_len == host.len and
            std.mem.eql(u8, e.host[0..e.host_len], host)) return e;
    }
    return null;
}

/// SSL_peek on `ssl_ptr` until one byte arrives or the deadline passes.
/// Pulls the peer's next record into the SSL object, so the kernel
/// socket reports quiet and only the SSL checks can see it.
fn peekUntil(ssl_ptr: *c.SSL, deadline_ms: i64) c_int {
    var buf: [8]u8 = undefined;
    while (std.time.milliTimestamp() < deadline_ms) {
        const r = c.SSL_peek(ssl_ptr, @ptrCast(&buf), @intCast(buf.len));
        if (r > 0) return r;
        std.Thread.sleep(std.time.ns_per_ms);
    }
    return 0;
}

test "TLS: keep-alive discards a parked conn holding unread bytes in OpenSSL" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/cert.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/key.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(key_path);

    var st = KaState{};
    // The server writes a junk record right after response 1: bytes the
    // next request must never parse as its own response.
    st.extra_after.store(1, .release);
    const th = try std.Thread.spawn(.{}, serveKeepAlive, .{ cert_path.ptr, key_path.ptr, &st });
    defer {
        st.stop.store(true, .release);
        th.join();
    }
    const dl = std.time.milliTimestamp() + 3000;
    while (st.port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = st.port.load(.acquire);
    try std.testing.expect(p != 0);

    const dns_srv = try startFakeDns(.{});
    defer stopFakeDns(dns_srv);
    var client = try Client.init(cert_path);
    defer client.deinit();
    defer drainIdlePool();
    useFakeDns(&client, dns_srv);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/jwks", .{p});
    stale_detects = 0;
    var resp1 = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp1.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp1.status);

    // Response 1 parked the conn. Pull the junk record into the parked
    // conn's SSL object: the kernel socket then reports quiet, so a
    // kevent-only probe would call it live.
    const entry = parkedEntry("localhost", @intCast(p)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(peekUntil(entry.ssl_ptr.?, dl) > 0);
    try std.testing.expect(c.SSL_pending(entry.ssl_ptr.?) > 0);

    const kq = try posix.kqueue();
    defer posix.close(kq);
    try std.testing.expect(idle_pool.take(kq, "localhost", @intCast(p)) == null);
    try std.testing.expectEqual(@as(usize, 1), stale_detects);

    // The next GET runs on a fresh conn and gets its own response.
    var resp2 = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp2.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp2.status);
    try std.testing.expectEqual(@as(usize, 2), st.accepts.load(.acquire));
    try std.testing.expectEqual(@as(usize, 2), st.requests.load(.acquire));
}

test "TLS: keep-alive never parks a conn with unread bytes in OpenSSL" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/cert.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/key.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(key_path);

    var st = KaState{};
    // Accept 1 gets a junk record right after the handshake, before any
    // request.
    st.junk_on_accept.store(1, .release);
    const th = try std.Thread.spawn(.{}, serveKeepAlive, .{ cert_path.ptr, key_path.ptr, &st });
    defer {
        st.stop.store(true, .release);
        th.join();
    }
    const dl = std.time.milliTimestamp() + 3000;
    while (st.port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = st.port.load(.acquire);
    try std.testing.expect(p != 0);

    const dns_srv = try startFakeDns(.{});
    defer stopFakeDns(dns_srv);
    var client = try Client.init(cert_path);
    defer client.deinit();
    defer drainIdlePool();
    useFakeDns(&client, dns_srv);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/jwks", .{p});
    const parsed = parseUrl(url).?;
    var host_buf: [256]u8 = undefined;
    @memcpy(host_buf[0..parsed.host.len], parsed.host);
    host_buf[parsed.host.len] = 0;
    const host_z: [*:0]const u8 = @ptrCast(&host_buf);

    const kq = try posix.kqueue();
    defer posix.close(kq);
    const options = testOptions(5000, 2000);
    const conn = try connectAndHandshake(
        &client,
        std.testing.allocator,
        kq,
        host_z,
        parsed,
        monotonicNs() + @as(u64, options.connect_timeout_ms) * std.time.ns_per_ms,
        options,
    );
    var owned = true;
    defer if (owned) closeConn(conn);

    // Pull the junk record into the conn's SSL object so the kernel
    // socket reports quiet.
    try std.testing.expect(peekUntil(conn.ssl_ptr, dl) > 0);
    try std.testing.expect(c.SSL_pending(conn.ssl_ptr) > 0);

    pending_drops = 0;
    idle_pool.put("localhost", @intCast(p), conn);
    owned = false;
    try std.testing.expectEqual(@as(usize, 1), pending_drops);
    try std.testing.expect(idle_pool.take(kq, "localhost", @intCast(p)) == null);
}

test "TLS: keep-alive never retries a POST" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/cert.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/key.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(key_path);

    var st = KaState{};
    // The POST is request 2: it dies on the reused conn without a reply.
    st.close_on.store(2, .release);
    const th = try std.Thread.spawn(.{}, serveKeepAlive, .{ cert_path.ptr, key_path.ptr, &st });
    defer {
        st.stop.store(true, .release);
        th.join();
    }
    const dl = std.time.milliTimestamp() + 3000;
    while (st.port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = st.port.load(.acquire);
    try std.testing.expect(p != 0);

    const dns_srv = try startFakeDns(.{});
    defer stopFakeDns(dns_srv);
    var client = try Client.init(cert_path);
    defer client.deinit();
    defer drainIdlePool();
    useFakeDns(&client, dns_srv);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/token", .{p});
    var resp1 = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp1.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp1.status);
    try std.testing.expectEqual(@as(usize, 1), st.accepts.load(.acquire));

    if (client.post(std.testing.allocator, url, "grant_type=x", testOptions(5000, 2000))) |*resp| {
        var r = resp.*;
        defer r.deinit();
        return error.TestExpectedError;
    } else |_| {}

    // No retry happened: still one accept, and the error surfaced.
    try std.testing.expectEqual(@as(usize, 1), st.accepts.load(.acquire));
}

test "responseComplete: a huge declared length is rejected, not panicked on" {
    const huge = "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\nx";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.ResponseTooLarge },
        responseComplete(huge),
    );
    // Above usize entirely.
    const beyond = "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\nx";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.ResponseTooLarge },
        responseComplete(beyond),
    );
    // Above the response cap but parseable.
    var capped_buf: [160]u8 = undefined;
    const capped = try std.fmt.bufPrint(
        &capped_buf,
        "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\n",
        .{MAX_RESPONSE_SIZE + 1},
    );
    try std.testing.expectEqual(
        Complete{ .err = HttpError.ResponseTooLarge },
        responseComplete(capped),
    );
}

test "responseComplete: Content-Length accepts digits only" {
    const cases = [_][]const u8{ "+5", "1_0", "-1", "abc", "", "0x10" };
    for (cases) |value| {
        var buf: [160]u8 = undefined;
        const head = try std.fmt.bufPrint(
            &buf,
            "HTTP/1.1 200 OK\r\nContent-Length: {s}\r\n\r\n",
            .{value},
        );
        try std.testing.expectEqual(
            Complete{ .err = HttpError.InvalidResponse },
            responseComplete(head),
        );
    }
}

test "responseComplete: duplicate Content-Length headers must agree" {
    const agree = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expectEqual(Complete{ .done = agree.len }, responseComplete(agree));

    const disagree = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 7\r\n\r\nhellow!";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(disagree),
    );
}

test "responseComplete: an empty Content-Length value is rejected" {
    // RFC 9112 6.3 rule 5: an invalid Content-Length in a response is an
    // unrecoverable error, never EOF framing.
    const bare = "HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(bare),
    );
    // The invalid first value is not dropped as a duplicate either.
    const then_valid = "HTTP/1.1 200 OK\r\nContent-Length:\r\nContent-Length: 3\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(then_valid),
    );
}

test "responseComplete: chunked framing completes at the last chunk" {
    // RFC 9112 6.1: a sole "chunked" Transfer-Encoding frames the body
    // by the chunk stream, not by Content-Length or EOF.
    const resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nhelo\r\n0\r\n\r\n";
    try std.testing.expectEqual(Complete{ .done = resp.len }, responseComplete(resp));
    // Declared bytes that have not arrived keep the response in flight.
    const partial = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nhel";
    try std.testing.expectEqual(Complete.incomplete, responseComplete(partial));
    // A stream without its last chunk never completes.
    const no_last = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nhelo\r\n";
    try std.testing.expectEqual(Complete.incomplete, responseComplete(no_last));
    // Bytes past the last chunk are not part of the message.
    const junk = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nNEXT";
    try std.testing.expectEqual(
        Complete{ .done = junk.len - 4 },
        responseComplete(junk),
    );
}

test "responseComplete: Transfer-Encoding accepts only a sole chunked" {
    const identity = "HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(identity),
    );
    const empty = "HTTP/1.1 200 OK\r\nTransfer-Encoding:\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(empty),
    );
    const stacked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(stacked),
    );
    const twice = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(twice),
    );
    // RFC 9112 6.3 rules 3 and 5: TE alongside Content-Length is
    // ambiguous framing; reject rather than guess.
    const both = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(both),
    );
}

test "responseComplete: chunked streams are strict and bounded" {
    const head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    // Chunk data must sit exactly between its CRLFs.
    const short_data = head ++ "4\r\nhel\r\n0\r\n\r\n";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(short_data),
    );
    // A malformed chunk-size digit is invalid.
    const bad_size = head ++ "z\r\n0\r\n\r\n";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(bad_size),
    );
    // Trailers are rejected: the last chunk is followed by one empty
    // line, not by trailer fields.
    const trailer = head ++ "0\r\nX-T: 1\r\n\r\n";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(trailer),
    );
    // A huge declared chunk size is too large, like a huge CL.
    var huge_buf: [160]u8 = undefined;
    const huge = try std.fmt.bufPrint(
        &huge_buf,
        head ++ "{x}\r\n",
        .{MAX_RESPONSE_SIZE + 1},
    );
    try std.testing.expectEqual(
        Complete{ .err = HttpError.ResponseTooLarge },
        responseComplete(huge),
    );
    // Overflowing the size parse is too large, not a wrap.
    const overflow = head ++ "ffffffffffffffffff\r\n";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.ResponseTooLarge },
        responseComplete(overflow),
    );
}

test "responseComplete: chunk extensions are bounded and ignored" {
    const head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    // Strictly shaped extensions decode as if absent.
    const ext = head ++ "5;a=b;c=\"x y\"\r\nhello\r\n0;end\r\n\r\n";
    try std.testing.expectEqual(Complete{ .done = ext.len }, responseComplete(ext));
    // An unterminated quoted string is not a shape to trust.
    const bad_ext = head ++ "5;a=\"unterminated\r\nhello\r\n0\r\n\r\n";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(bad_ext),
    );
    // The chunk-size line bound keeps an extension from growing past
    // MAX_CHUNK_SIZE_LINE.
    var long_val: [300]u8 = undefined;
    @memset(&long_val, 'x');
    var big_buf: [512]u8 = undefined;
    const big_line = try std.fmt.bufPrint(
        &big_buf,
        head ++ "1;a={s}\r\nx\r\n0\r\n\r\n",
        .{long_val[0..]},
    );
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(big_line),
    );
}

test "responseComplete: whitespace before the colon is rejected" {
    // RFC 9112 5.1: a field name followed by whitespace before the colon
    // is a malformed header, not a renamed one. The spaced TE must not
    // smuggle chunk text in as the body and the spaced CL must not
    // silently degrade to EOF framing.
    const te = "HTTP/1.1 200 OK\r\nTransfer-Encoding : chunked\r\n\r\n4\r\nhelo\r\n0\r\n\r\n";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(te),
    );
    const cl = "HTTP/1.1 200 OK\r\nContent-Length : 5\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(cl),
    );
    const tab = "HTTP/1.1 200 OK\r\nContent-Length\t: 5\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(tab),
    );
    // An unrelated header with a spaced name is malformed the same way.
    const other = "HTTP/1.1 200 OK\r\nX-Trace : 1\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(other),
    );
    // RFC 9112 5.2 obs-fold: a folded field must not fall back to EOF
    // framing. The folded line carries no colon, so only the leading-SP
    // rule catches it.
    const folded_te = "HTTP/1.1 200 OK\r\nTransfer-Encoding:\r\n chunked\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(folded_te),
    );
    const folded_cl = "HTTP/1.1 200 OK\r\nContent-Length:\r\n 5\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(folded_cl),
    );
    // A fold after an unrelated header is rejected the same way.
    const folded_bare = "HTTP/1.1 200 OK\r\nX-A: 1\r\n\tchunked\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(folded_bare),
    );
    // An empty Transfer-Encoding value still declares the field.
    const empty_te = "HTTP/1.1 200 OK\r\nTransfer-Encoding:\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(empty_te),
    );
}

test "responseComplete: a reason phrase may contain ' : '" {
    // The status line is skipped before the field rules run, so a
    // reason phrase with whitespace before a colon stays accepted.
    const resp = "HTTP/1.1 200 OK : yes\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expectEqual(Complete{ .done = resp.len }, responseComplete(resp));
}

test "responseComplete: an empty field name is rejected" {
    // RFC 9110 5.1: field-name is one or more tchar; ": v" has none.
    const resp = "HTTP/1.1 200 OK\r\n: v\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(resp),
    );
}

test "responseComplete: an empty line inside the head does not panic" {
    // A bare-LF blank line sits before the CRLFCRLF terminator. The
    // line.len > 0 guard keeps the field-line grammar check from
    // treating it as a malformed field.
    const resp = "HTTP/1.1 200 OK\r\nContent-Length: 5\n\nX: 1\r\n\r\nhello";
    try std.testing.expectEqual(Complete{ .done = resp.len }, responseComplete(resp));
}

test "responseComplete: a one-character field name is accepted" {
    // tchar allows a single-character name; only the truly empty name
    // is invalid.
    const resp = "HTTP/1.1 200 OK\r\nX: 1\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expectEqual(Complete{ .done = resp.len }, responseComplete(resp));
}

test "responseComplete: a field line without a colon is rejected" {
    // RFC 9112 5: a field line is field-name ":". A colonless TE must
    // not slip past the TE reject as an unknown line either.
    const garbage = "HTTP/1.1 200 OK\r\ngarbage\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(garbage),
    );
    const te = "HTTP/1.1 200 OK\r\nTransfer-Encoding chunked\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(te),
    );
}

test "responseComplete: field lines follow the grammar, not a blocklist" {
    // RFC 9110 5.6.2 and RFC 9112 2.2: a bare CR, NUL or other CTL in a
    // field line must not hide a field or reframe the body. Both shapes
    // below used to degrade to EOF framing with the field gone.
    const nul_te = "HTTP/1.1 200 OK\r\n\x00Transfer-Encoding: chunked\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(nul_te),
    );
    const cr_cl = "HTTP/1.1 200 OK\r\nX-A: a\rContent-Length: 5\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(cr_cl),
    );
    // A CTL in the name is not tchar and DEL is a CTL byte in the value.
    const vt_cl = "HTTP/1.1 200 OK\r\n\x0bContent-Length: 5\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(vt_cl),
    );
    const del = "HTTP/1.1 200 OK\r\nX-A: a\x7fb\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(del),
    );
    // HTAB in a value is a field-value byte (RFC 9110 5.5).
    const htab = "HTTP/1.1 200 OK\r\nX-A: a\tb\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expectEqual(Complete{ .done = htab.len }, responseComplete(htab));
}

test "responseComplete: framing ends the body at Content-Length" {
    const resp = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloTAIL";
    try std.testing.expectEqual(
        Complete{ .done = resp.len - 4 },
        responseComplete(resp),
    );
    // Declared but not yet arrived: still in flight.
    const partial = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhello";
    try std.testing.expectEqual(Complete.incomplete, responseComplete(partial));
    // No Content-Length at all: EOF terminates, so never "done".
    const no_cl = "HTTP/1.1 200 OK\r\n\r\nhello";
    try std.testing.expectEqual(Complete.incomplete, responseComplete(no_cl));
}

/// Serve one raw HTTP response over TLS (whatever bytes the test asks),
/// then close. Unlike serveTlsResponses this does not build a correct
/// header: malformed framing is the point.
fn serveTlsRawResponse(
    cert_path: [*:0]const u8,
    key_path: [*:0]const u8,
    response: []const u8,
    port_out: *std.atomic.Value(u16),
) void {
    const method = c.TLS_server_method() orelse return;
    const ctx = c.SSL_CTX_new(method) orelse return;
    defer c.SSL_CTX_free(ctx);
    if (c.SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1) return;
    if (c.SSL_CTX_use_PrivateKey_file(ctx, key_path, c.SSL_FILETYPE_PEM) != 1) return;

    const listen_fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(listen_fd);
    var addr: std.c.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch return;
    posix.listen(listen_fd, 4) catch return;
    var alen: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    posix.getsockname(listen_fd, @ptrCast(&addr), &alen) catch return;
    port_out.store(std.mem.bigToNative(u16, addr.port), .release);

    const deadline = std.time.milliTimestamp() + 10000;
    while (std.time.milliTimestamp() < deadline) {
        var fds = [_]posix.pollfd{.{ .fd = listen_fd, .events = posix.POLL.IN, .revents = 0 }};
        const pn = posix.poll(&fds, 500) catch 0;
        if (pn <= 0) continue;
        const conn_fd = posix.accept(listen_fd, null, null, 0) catch continue;
        defer posix.close(conn_fd);
        const ssl_ptr = c.SSL_new(ctx) orelse continue;
        defer c.SSL_free(ssl_ptr);
        _ = c.SSL_set_fd(ssl_ptr, conn_fd);
        if (c.SSL_accept(ssl_ptr) != 1) continue;
        var buf: [4096]u8 = undefined;
        var total: usize = 0;
        while (total < buf.len and std.time.milliTimestamp() < deadline) {
            const r = c.SSL_read(ssl_ptr, @ptrCast(buf[total..].ptr), @intCast(buf.len - total));
            if (r <= 0) break;
            total += @intCast(r);
            if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n") != null) break;
        }
        _ = c.SSL_write(ssl_ptr, response.ptr, @intCast(response.len));
        // Close_notify: the client reads a clean EOF, not a transport error.
        _ = c.SSL_shutdown(ssl_ptr);
        return;
    }
}

const RawStub = struct {
    thread: std.Thread,
    port: u16,
};

/// Spin up a raw-response TLS stub and return it with its bound port.
fn startRawStub(cert_path: [*:0]const u8, key_path: [*:0]const u8, response: []const u8) !RawStub {
    var port = std.atomic.Value(u16).init(0);
    const stub = try std.Thread.spawn(
        .{},
        serveTlsRawResponse,
        .{ cert_path, key_path, response, &port },
    );
    errdefer stub.join();
    const dl = std.time.milliTimestamp() + 3000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    try std.testing.expect(port.load(.acquire) != 0);
    return .{ .thread = stub, .port = port.load(.acquire) };
}

test "TLS: a huge Content-Length errors instead of panicking the worker" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/cert.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/key.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(key_path);

    var url_buf: [128]u8 = undefined;
    const stub = try startRawStub(
        cert_path,
        key_path,
        "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\nx",
    );
    defer stub.thread.join();
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/", .{stub.port});

    const dns_srv = try startFakeDns(.{});
    defer stopFakeDns(dns_srv);
    var client = try Client.init(cert_path);
    defer client.deinit();
    useFakeDns(&client, dns_srv);
    try std.testing.expectError(
        HttpError.ResponseTooLarge,
        client.get(std.testing.allocator, url, testOptions(5000, 2000)),
    );
}

test "TLS: a body shorter than Content-Length is InvalidResponse" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/cert.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/key.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(key_path);

    // Declares 100 bytes, delivers 4, then closes.
    var url_buf: [128]u8 = undefined;
    const stub = try startRawStub(
        cert_path,
        key_path,
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nok\r\n",
    );
    defer stub.thread.join();
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/", .{stub.port});

    const dns_srv = try startFakeDns(.{});
    defer stopFakeDns(dns_srv);
    var client = try Client.init(cert_path);
    defer client.deinit();
    useFakeDns(&client, dns_srv);
    try std.testing.expectError(
        HttpError.InvalidResponse,
        client.get(std.testing.allocator, url, testOptions(5000, 2000)),
    );
}

test "TLS: bytes past Content-Length are not part of the body" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/cert.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/key.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(key_path);

    var url_buf: [128]u8 = undefined;
    const stub = try startRawStub(
        cert_path,
        key_path,
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloTAIL",
    );
    defer stub.thread.join();
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/", .{stub.port});

    const dns_srv = try startFakeDns(.{});
    defer stopFakeDns(dns_srv);
    var client = try Client.init(cert_path);
    defer client.deinit();
    useFakeDns(&client, dns_srv);
    var resp = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("hello", resp.body);
}

test "TLS: a Content-Length body comes back exactly" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/cert.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/key.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(key_path);

    var port = std.atomic.Value(usize).init(0);
    const th = try std.Thread.spawn(
        .{},
        serveTlsResponses,
        .{ cert_path.ptr, key_path.ptr, &port },
    );
    defer th.join();
    const dl = std.time.milliTimestamp() + 3000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = port.load(.acquire);
    try std.testing.expect(p != 0);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/", .{p});
    const dns_srv = try startFakeDns(.{});
    defer stopFakeDns(dns_srv);
    var client = try Client.init(cert_path);
    defer client.deinit();
    useFakeDns(&client, dns_srv);
    var resp = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("ok\r\n", resp.body);
}

test "TLS: a chunked body is decoded exactly" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/cert.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "{s}/key.pem",
        .{base},
        0,
    );
    defer std.testing.allocator.free(key_path);

    var url_buf: [128]u8 = undefined;
    const stub = try startRawStub(
        cert_path,
        key_path,
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" ++
            "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    );
    defer stub.thread.join();
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/", .{stub.port});

    const dns_srv = try startFakeDns(.{});
    defer stopFakeDns(dns_srv);
    var client = try Client.init(cert_path);
    defer client.deinit();
    useFakeDns(&client, dns_srv);
    var resp = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("hello world", resp.body);
}

// --- Fake nameserver: scripted answers over loopback UDP, the same ---
// --- seam lib/dns/async.zig's own tests use. Requests set          ---
// --- Client.test_nameserver so the suite never touches the host    ---
// --- resolver configuration.                                       ---

const FakeDns = struct {
    udp_fd: posix.fd_t,
    port: u16,
    alive: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
    /// Owner name the scripted address answers belong to.
    a_name: []const u8,
    /// A answer for a_name; null issues NODATA.
    a_addr: ?[4]u8 = .{ 127, 0, 0, 1 },
    /// AAAA answer for a_name; null issues NODATA.
    aaaa_addr: ?[16]u8 = null,
    /// How every TLSA query is answered.
    tlsa_mode: TlsaMode = .nodata,
    /// TLSA rdata when tlsa_mode == .record.
    tlsa_rdata: []const u8 = &.{},
    thread: std.Thread,

    const TlsaMode = enum { record, nodata, nxdomain, servfail };

    fn run(self: *FakeDns) void {
        var buf: [2048]u8 = undefined;
        while (self.alive.load(.acquire)) {
            var fds = [1]posix.pollfd{.{ .fd = self.udp_fd, .events = posix.POLL.IN, .revents = 0 }};
            _ = posix.poll(&fds, 100) catch return;
            if (fds[0].revents == 0) continue;
            var peer: posix.sockaddr = undefined;
            var plen: posix.socklen_t = @sizeOf(posix.sockaddr);
            const n = posix.recvfrom(self.udp_fd, &buf, 0, &peer, &plen) catch continue;
            var out: [2048]u8 = undefined;
            const resp_len = self.buildResponse(&out, buf[0..n]);
            if (resp_len > 0) _ = posix.sendto(self.udp_fd, out[0..resp_len], 0, &peer, plen) catch 0;
        }
    }

    /// Build a response echoing the question, with one scripted answer.
    /// SRV is never published (the resolver falls back to the bare
    /// name); NODATA, NXDOMAIN and SERVFAIL are the negative scripts.
    fn buildResponse(self: *FakeDns, out: []u8, q: []const u8) usize {
        if (q.len < 12) return 0;
        var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        if (std.mem.readInt(u16, q[4..6], .big) == 0) return 0;
        const nm = wire.decompressName(q, 12, arena) catch return 0;
        if (nm.next + 4 > q.len) return 0;
        const qtype = std.mem.readInt(u16, q[nm.next..][0..2], .big);
        const qend = nm.next + 4;

        var rcode: u16 = 0;
        var answer_type: u16 = 0;
        var rdata: []const u8 = &.{};
        var v4: [4]u8 = undefined;
        var v6: [16]u8 = undefined;
        const name_matches = std.ascii.eqlIgnoreCase(nm.name, self.a_name);
        switch (qtype) {
            wire.TYPE_SRV => {},
            wire.TYPE_A => if (name_matches) {
                if (self.a_addr) |a| {
                    answer_type = wire.TYPE_A;
                    v4 = a;
                    rdata = &v4;
                }
            },
            wire.TYPE_AAAA => if (name_matches) {
                if (self.aaaa_addr) |a| {
                    answer_type = wire.TYPE_AAAA;
                    v6 = a;
                    rdata = &v6;
                }
            },
            wire.TYPE_TLSA => switch (self.tlsa_mode) {
                .nodata => {},
                .nxdomain => rcode = 3,
                .servfail => rcode = 2,
                .record => {
                    answer_type = wire.TYPE_TLSA;
                    rdata = self.tlsa_rdata;
                },
            },
            else => {},
        }

        var pos: usize = 0;
        const ancount: u16 = if (answer_type != 0) 1 else 0;
        // The response tail needs the question echo plus one RR.
        if (12 + (qend - 12) + 10 + 2 + rdata.len > out.len) return 0;
        std.mem.writeInt(u16, out[pos..][0..2], std.mem.readInt(u16, q[0..2], .big), .big);
        pos += 2;
        // QR + AA + RD + RA set; rcode from the script.
        std.mem.writeInt(u16, out[pos..][0..2], @as(u16, 0x8580) | rcode, .big);
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], 1, .big);
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], ancount, .big);
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], 0, .big);
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], 0, .big);
        pos += 2;
        @memcpy(out[pos..][0 .. qend - 12], q[12..qend]);
        pos += qend - 12;
        if (answer_type != 0) {
            out[pos] = 0xC0;
            out[pos + 1] = 0x0C;
            pos += 2;
            std.mem.writeInt(u16, out[pos..][0..2], answer_type, .big);
            pos += 2;
            std.mem.writeInt(u16, out[pos..][0..2], wire.CLASS_IN, .big);
            pos += 2;
            std.mem.writeInt(u32, out[pos..][0..4], 60, .big);
            pos += 4;
            std.mem.writeInt(u16, out[pos..][0..2], @intCast(rdata.len), .big);
            pos += 2;
            @memcpy(out[pos..][0..rdata.len], rdata);
            pos += rdata.len;
        }
        return pos;
    }
};

const FakeDnsOpts = struct {
    a_name: []const u8 = "localhost",
    a_addr: ?[4]u8 = .{ 127, 0, 0, 1 },
    aaaa_addr: ?[16]u8 = null,
    tlsa_mode: FakeDns.TlsaMode = .nodata,
    tlsa_rdata: []const u8 = &.{},
};

/// Bind a loopback UDP socket and serve the script on it. Caller stops
/// with stopFakeDns (join bounded by the 100 ms poll tick).
fn startFakeDns(opts: FakeDnsOpts) !*FakeDns {
    const srv = try std.testing.allocator.create(FakeDns);
    errdefer std.testing.allocator.destroy(srv);
    const ufd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(ufd);
    const laddr = try std.net.Address.parseIp("127.0.0.1", 0);
    try posix.bind(ufd, &laddr.any, laddr.getOsSockLen());
    var actual: posix.sockaddr = undefined;
    var alen: posix.socklen_t = @sizeOf(posix.sockaddr);
    try posix.getsockname(ufd, &actual, &alen);
    srv.* = .{
        .udp_fd = ufd,
        .port = std.net.Address.initPosix(@alignCast(&actual)).getPort(),
        .a_name = opts.a_name,
        .a_addr = opts.a_addr,
        .aaaa_addr = opts.aaaa_addr,
        .tlsa_mode = opts.tlsa_mode,
        .tlsa_rdata = opts.tlsa_rdata,
        .thread = undefined,
    };
    srv.thread = try std.Thread.spawn(.{}, FakeDns.run, .{srv});
    return srv;
}

fn stopFakeDns(srv: *FakeDns) void {
    srv.alive.store(false, .release);
    srv.thread.join();
    posix.close(srv.udp_fd);
    std.testing.allocator.destroy(srv);
}

/// Point a client at a fixture nameserver.
fn useFakeDns(client: *Client, srv: *const FakeDns) void {
    client.test_nameserver = std.net.Address.parseIp("127.0.0.1", srv.port) catch unreachable;
}

/// Serve `n` tiny HTTP replies on an IPv6 loopback TLS listener; the
/// AAAA-only test's endpoint. Same shape as serveTlsResponses.
fn serveTlsResponses6(
    cert_path: [*:0]const u8,
    key_path: [*:0]const u8,
    n: *std.atomic.Value(usize),
) void {
    const method = c.TLS_server_method() orelse return;
    const ctx = c.SSL_CTX_new(method) orelse return;
    defer c.SSL_CTX_free(ctx);
    if (c.SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1) return;
    if (c.SSL_CTX_use_PrivateKey_file(ctx, key_path, c.SSL_FILETYPE_PEM) != 1) return;

    const listen_fd = posix.socket(posix.AF.INET6, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(listen_fd);
    var addr: std.c.sockaddr.in6 = std.mem.zeroes(std.c.sockaddr.in6);
    addr.family = posix.AF.INET6;
    addr.addr[15] = 1;
    posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in6)) catch return;
    posix.listen(listen_fd, 4) catch return;
    var alen: posix.socklen_t = @sizeOf(std.c.sockaddr.in6);
    posix.getsockname(listen_fd, @ptrCast(&addr), &alen) catch return;
    n.store(std.mem.nativeToBig(u16, addr.port), .release);

    const deadline = std.time.milliTimestamp() + 10000;
    var served: usize = 0;
    while (served < 2 and std.time.milliTimestamp() < deadline) {
        var fds = [_]posix.pollfd{.{ .fd = listen_fd, .events = posix.POLL.IN, .revents = 0 }};
        const pn = posix.poll(&fds, 500) catch 0;
        if (pn <= 0) continue;
        const conn = posix.accept(listen_fd, null, null, 0) catch continue;
        defer posix.close(conn);
        const ssl_ptr = c.SSL_new(ctx) orelse continue;
        defer c.SSL_free(ssl_ptr);
        _ = c.SSL_set_fd(ssl_ptr, conn);
        served += 1;
        if (c.SSL_accept(ssl_ptr) != 1) continue;
        var buf: [4096]u8 = undefined;
        var total: usize = 0;
        while (total < buf.len and std.time.milliTimestamp() < deadline) {
            const r = c.SSL_read(ssl_ptr, @ptrCast(buf[total..].ptr), @intCast(buf.len - total));
            if (r <= 0) break;
            total += @intCast(r);
            if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n") != null) break;
        }
        const resp = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nok\r\n";
        _ = c.SSL_write(ssl_ptr, resp.ptr, resp.len);
    }
}

/// DER bytes of the PEM certificate in `dir` (for building TLSA rdata).
fn certDerFromPem(allocator: Allocator, pem: []const u8) ![]u8 {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    const s0 = std.mem.indexOf(u8, pem, begin) orelse return error.InvalidPem;
    const s1 = std.mem.indexOf(u8, pem, end) orelse return error.InvalidPem;
    var b64: std.ArrayList(u8) = .{};
    defer b64.deinit(allocator);
    for (pem[s0 + begin.len .. s1]) |ch| {
        if (ch == '\n' or ch == '\r' or ch == ' ' or ch == '\t') continue;
        try b64.append(allocator, ch);
    }
    const der = try allocator.alloc(u8, try std.base64.standard.Decoder.calcSizeForSlice(b64.items));
    errdefer allocator.free(der);
    try std.base64.standard.Decoder.decode(der, b64.items);
    return der;
}

/// TLSA rdata: usage 3 (DANE-EE), selector 0 (cert), matching 1 (SHA-256)
/// over `data` -- or a deliberately wrong digest when `corrupt`.
fn tlsaEeSha256(allocator: Allocator, data: []const u8, corrupt: bool) ![]u8 {
    const rdata = try allocator.alloc(u8, 3 + 32);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    if (corrupt) digest[0] ^= 0xff;
    rdata[0] = 3;
    rdata[1] = 0;
    rdata[2] = 1;
    @memcpy(rdata[3..], &digest);
    return rdata;
}

test "TLS: a published TLSA record authenticates the peer with an empty CA bundle" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/cert.pem", .{base}, 0);
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/key.pem", .{base}, 0);
    defer std.testing.allocator.free(key_path);
    const empty_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/empty.pem", .{base}, 0);
    defer std.testing.allocator.free(empty_path);
    // An empty CA bundle: no traditional anchor can satisfy this
    // self-signed cert, so only DANE can verify the peer.
    try tmp.dir.writeFile(.{ .sub_path = "empty.pem", .data = "" });

    const pem = try tmp.dir.openFile("cert.pem", .{});
    defer pem.close();
    const pem_bytes = try pem.readToEndAlloc(std.testing.allocator, 64 * 1024);
    defer std.testing.allocator.free(pem_bytes);
    const der = try certDerFromPem(std.testing.allocator, pem_bytes);
    defer std.testing.allocator.free(der);
    const tlsa_rdata = try tlsaEeSha256(std.testing.allocator, der, false);
    defer std.testing.allocator.free(tlsa_rdata);

    var port = std.atomic.Value(usize).init(0);
    const th = try std.Thread.spawn(.{}, serveTlsResponses, .{ cert_path.ptr, key_path.ptr, &port });
    defer th.join();
    const dl = std.time.milliTimestamp() + 3000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = port.load(.acquire);
    try std.testing.expect(p != 0);

    const dns_srv = try startFakeDns(.{ .tlsa_mode = .record, .tlsa_rdata = tlsa_rdata });
    defer stopFakeDns(dns_srv);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/", .{p});
    var client = try Client.init(empty_path);
    defer client.deinit();
    useFakeDns(&client, dns_srv);
    var resp = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp.status);
}

test "TLS: a TLSA set that does not match is refused even when PKIX would accept" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/cert.pem", .{base}, 0);
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/key.pem", .{base}, 0);
    defer std.testing.allocator.free(key_path);

    const pem = try tmp.dir.openFile("cert.pem", .{});
    defer pem.close();
    const pem_bytes = try pem.readToEndAlloc(std.testing.allocator, 64 * 1024);
    defer std.testing.allocator.free(pem_bytes);
    const der = try certDerFromPem(std.testing.allocator, pem_bytes);
    defer std.testing.allocator.free(der);
    const tlsa_rdata = try tlsaEeSha256(std.testing.allocator, der, true);
    defer std.testing.allocator.free(tlsa_rdata);

    var port = std.atomic.Value(usize).init(0);
    const th = try std.Thread.spawn(.{}, serveTlsResponses, .{ cert_path.ptr, key_path.ptr, &port });
    defer th.join();
    const dl = std.time.milliTimestamp() + 3000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = port.load(.acquire);
    try std.testing.expect(p != 0);

    const dns_srv = try startFakeDns(.{ .tlsa_mode = .record, .tlsa_rdata = tlsa_rdata });
    defer stopFakeDns(dns_srv);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/", .{p});
    // The CA bundle WOULD verify this cert: the refusal must come from
    // DANE failing closed, never from PKIX.
    var client = try Client.init(cert_path);
    defer client.deinit();
    useFakeDns(&client, dns_srv);
    try std.testing.expectError(
        HttpError.TlsHandshakeFailed,
        client.get(std.testing.allocator, url, testOptions(5000, 2000)),
    );
}

test "TLS: no TLSA published falls back to PKIX with the CA bundle" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/cert.pem", .{base}, 0);
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/key.pem", .{base}, 0);
    defer std.testing.allocator.free(key_path);

    var port = std.atomic.Value(usize).init(0);
    const th = try std.Thread.spawn(.{}, serveTlsResponses, .{ cert_path.ptr, key_path.ptr, &port });
    defer th.join();
    const dl = std.time.milliTimestamp() + 3000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = port.load(.acquire);
    try std.testing.expect(p != 0);

    const dns_srv = try startFakeDns(.{ .tlsa_mode = .nodata });
    defer stopFakeDns(dns_srv);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/", .{p});
    var client = try Client.init(cert_path);
    defer client.deinit();
    useFakeDns(&client, dns_srv);
    var resp = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp.status);
}

test "TLS: a host that only publishes AAAA connects over IPv6" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/cert.pem", .{base}, 0);
    defer std.testing.allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/key.pem", .{base}, 0);
    defer std.testing.allocator.free(key_path);

    var port = std.atomic.Value(usize).init(0);
    const th = try std.Thread.spawn(.{}, serveTlsResponses6, .{ cert_path.ptr, key_path.ptr, &port });
    defer th.join();
    const dl = std.time.milliTimestamp() + 3000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = port.load(.acquire);
    try std.testing.expect(p != 0);

    var v6: [16]u8 = std.mem.zeroes([16]u8);
    v6[15] = 1;
    const dns_srv = try startFakeDns(.{ .a_addr = null, .aaaa_addr = v6 });
    defer stopFakeDns(dns_srv);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/", .{p});
    var client = try Client.init(cert_path);
    defer client.deinit();
    useFakeDns(&client, dns_srv);
    var resp = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp.status);
}

test "DNS: a dead nameserver fails inside the absolute deadline" {
    // Nobody answers on this UDP port: the resolver's waits are all
    // bounded by the request's connect deadline, so the request fails
    // with Timeout rather than hanging on the nameserver.
    var client = try Client.init(null);
    defer client.deinit();
    const dead = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    const laddr = try std.net.Address.parseIp("127.0.0.1", 0);
    try posix.bind(dead, &laddr.any, laddr.getOsSockLen());
    var actual: posix.sockaddr = undefined;
    var alen: posix.socklen_t = @sizeOf(posix.sockaddr);
    try posix.getsockname(dead, &actual, &alen);
    const dead_port = std.net.Address.initPosix(@alignCast(&actual)).getPort();
    posix.close(dead);
    client.test_nameserver = try std.net.Address.parseIp("127.0.0.1", dead_port);

    const t0 = monotonicNs();
    try std.testing.expectError(
        HttpError.Timeout,
        client.get(std.testing.allocator, "https://dead-ns.test/", testOptions(5000, 300)),
    );
    const elapsed_ms = (monotonicNs() - t0) / std.time.ns_per_ms;
    try std.testing.expect(elapsed_ms >= 200 and elapsed_ms <= 2000);
}
