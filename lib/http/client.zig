//! # HTTP Client -- HTTPS/1.1 over TLS (OpenSSL) with deadlines and cancellation
//!
//! Designed for OIDC backend use: JWKS fetch, token introspection, ROPC grant.
//! Requests run on the auth daemon's IdP worker threads, never on its event
//! loop.
//!
//! ## Threading
//!
//! A `Client` is safe to share across threads: after `init` its `SSL_CTX` is
//! only read, never mutated. Each request owns its socket, `SSL` and kqueue
//! for its whole lifetime; nothing is shared between in-flight requests.
//!
//! ## Features
//!
//! - HTTP/1.1 GET and POST (application/x-www-form-urlencoded)
//! - TLS via OpenSSL on a non-blocking socket driven by a per-request kqueue
//! - Absolute deadline and separate connect budget per request, plus a
//!   cancellation pipe whose EOF aborts the exchange
//! - PKIX verification with configurable CA bundle, hostname pinned to the URL
//! - Connection-per-request (no keepalive -- simplicity for 3 fixed endpoints)
//! - Response limited to 256KB (JWKS/token responses are small)
//!
//! ## Known limits
//!
//! - `getaddrinfo` runs blocking with no deadline and requests IPv4 only.
//!   Replaced later by the async resolver work item (A8/X2).
//! - Only the first resolved address is tried.
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
const posix = std.posix;
const Allocator = std.mem.Allocator;

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/x509_vfy.h");
    @cInclude("netdb.h");
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

/// Maximum response size (256KB, headers + body).
const MAX_RESPONSE_SIZE: usize = 256 * 1024;

/// Maximum request head size (request line + headers).
const MAX_HEAD_SIZE: usize = 4096;

/// Persistent HTTPS client: one SSL_CTX per daemon, parsing the CA bundle
/// once instead of per request (T357/S8).
pub const Client = struct {
    ssl_ctx: *c.SSL_CTX,

    pub fn init(ca_file: ?[]const u8) HttpError!Client {
        const ctx = initTlsClient(ca_file) orelse return HttpError.TlsInitFailed;
        return .{ .ssl_ctx = ctx };
    }

    pub fn deinit(self: *Client) void {
        c.SSL_CTX_free(self.ssl_ctx);
    }

    /// Perform an HTTPS GET request. Caller owns the returned Response.
    /// Runs entirely on the calling thread; safe to call from any worker.
    pub fn get(
        self: *const Client,
        allocator: Allocator,
        url: []const u8,
        options: RequestOptions,
    ) HttpError!Response {
        return request(self.ssl_ctx, allocator, "GET", url, null, null, options);
    }

    /// Perform an HTTPS POST with form-urlencoded body. Caller owns the
    /// returned Response.
    pub fn post(
        self: *const Client,
        allocator: Allocator,
        url: []const u8,
        body: []const u8,
        options: RequestOptions,
    ) HttpError!Response {
        return request(
            self.ssl_ctx,
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

/// Core HTTP request implementation. Owns one socket, one SSL and one
/// kqueue for the exchange's duration.
fn request(
    ssl_ctx: *c.SSL_CTX,
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

    const conn = try connectAndHandshake(ssl_ctx, kq, host_z, parsed, connect_deadline, options);
    defer posix.close(conn.fd);
    defer {
        // One non-blocking shutdown, never waited on (freebsd-ktls D6).
        _ = c.SSL_shutdown(conn.ssl_ptr);
        c.SSL_free(conn.ssl_ptr);
    }

    try sendRequest(conn, kq, allocator, method, parsed, body, content_type, options);
    return readResponse(conn, kq, allocator, options);
}

/// DNS, TCP connect and TLS handshake under the connect-phase deadline
/// (freebsd-ktls D5: the handshake is part of connect). Caller owns the
/// returned fd and SSL.
fn connectAndHandshake(
    ssl_ctx: *c.SSL_CTX,
    kq: posix.fd_t,
    host_z: [*:0]const u8,
    parsed: ParsedUrl,
    connect_deadline: u64,
    options: RequestOptions,
) HttpError!Conn {
    // DNS resolution (blocking, IPv4, no deadline -- see module header).
    const peer = resolvePeer(parsed.host, parsed.port) orelse return HttpError.DnsResolutionFailed;
    const fd = peer.fd;
    errdefer posix.close(fd);

    // Non-blocking connect against the connect-phase deadline.
    posix.connect(fd, @ptrCast(&peer.addr), @sizeOf(std.c.sockaddr.in)) catch |err| switch (err) {
        error.WouldBlock, error.ConnectionPending => {
            waitIo(
                kq,
                fd,
                std.c.EVFILT.WRITE,
                connect_deadline,
                options.cancel_fd,
            ) catch |werr| return switch (werr) {
                error.Timeout => HttpError.Timeout,
                error.Cancelled => HttpError.Cancelled,
                error.WaitFailed => HttpError.ConnectionFailed,
            };
            // SO_ERROR is read-and-clear; the socket latched the connect
            // outcome while it was pending.
            posix.getsockoptError(fd) catch return HttpError.ConnectionFailed;
        },
        error.AccessDenied,
        error.PermissionDenied,
        error.AddressInUse,
        error.AddressNotAvailable,
        error.AddressFamilyNotSupported,
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.NetworkUnreachable,
        error.ConnectionTimedOut,
        error.FileNotFound,
        error.SystemResources,
        error.Unexpected,
        => return HttpError.ConnectionFailed,
    };

    const ssl_ptr = c.SSL_new(ssl_ctx) orelse return HttpError.TlsInitFailed;
    errdefer c.SSL_free(ssl_ptr);

    _ = c.SSL_set_fd(ssl_ptr, @intCast(fd));
    _ = c.SSL_set_tlsext_host_name(ssl_ptr, host_z);

    // Pin the certificate identity to the URL host (T357/S8): VERIFY_PEER
    // alone (chain to a CA) accepts any publicly trusted certificate for
    // any name, so the IdP token/introspection/JWKS endpoints could be
    // answered by the wrong server without this.
    const verify_param = c.SSL_get0_param(ssl_ptr) orelse return HttpError.TlsInitFailed;
    if (c.X509_VERIFY_PARAM_set1_host(verify_param, host_z, 0) != 1)
        return HttpError.TlsInitFailed;

    // TLS handshake on the non-blocking socket.
    while (true) {
        c.ERR_clear_error();
        const ret = c.SSL_connect(ssl_ptr);
        if (ret == 1) return .{ .fd = fd, .ssl_ptr = ssl_ptr };
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
            else => return HttpError.TlsHandshakeFailed,
        }
    }
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
        w.writeAll("Connection: close\r\n") catch return HttpError.InvalidUrl;
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

/// Read the response against the total deadline, parse it and copy the
/// body into a right-sized allocation the caller owns.
fn readResponse(
    conn: Conn,
    kq: posix.fd_t,
    allocator: Allocator,
    options: RequestOptions,
) HttpError!Response {
    const resp_buf = allocator.alloc(u8, MAX_RESPONSE_SIZE) catch return HttpError.OutOfMemory;
    defer {
        std.crypto.secureZero(u8, resp_buf);
        allocator.free(resp_buf);
    }

    var total: usize = 0;
    var saw_eof = false;
    while (!saw_eof) {
        if (total >= MAX_RESPONSE_SIZE) return HttpError.ResponseTooLarge;
        if (total > 0) switch (responseComplete(resp_buf[0..total])) {
            .done => |need| {
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
    // truncated response.
    var body_slice = resp_data[body_start..];
    switch (parseResponseHead(resp_data[0..header_end])) {
        .invalid => return HttpError.InvalidResponse,
        .too_large => return HttpError.ResponseTooLarge,
        .eof_body => {},
        .length => |cl| {
            if (body_slice.len < cl) return HttpError.InvalidResponse;
            body_slice = body_slice[0..cl];
        },
    }

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
    /// A malformed Content-Length, disagreeing duplicates, or a
    /// Transfer-Encoding this client does not implement.
    invalid,
    /// A declared length above MAX_RESPONSE_SIZE.
    too_large,
};

/// Parse the response head: strict Content-Length (decimal digits only,
/// duplicates must agree) and no Transfer-Encoding at all.
fn parseResponseHead(head: []const u8) HeadParse {
    var content_length: ?usize = null;
    var it = std.mem.splitScalar(u8, head, '\n');
    _ = it.next(); // status line
    while (it.next()) |line_raw| {
        const line = std.mem.trimRight(u8, line_raw, "\r");
        // RFC 9112 5.2: a line starting with SP or HTAB is an obs-fold
        // continuation of the previous field. This client does not
        // unfold; rejecting keeps a folded Transfer-Encoding or
        // Content-Length from degrading the head to EOF framing.
        if (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) return .invalid;
        // RFC 9112 5.1: no whitespace is allowed between the field name
        // and the colon. "Content-Length : 5" must not fall through to a
        // looser parse of some other header shape.
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            if (std.mem.indexOfAny(u8, line[0..colon], " \t") != null) return .invalid;
        }
        const te_prefix = "transfer-encoding:";
        // ">=" counts a bare "Transfer-Encoding:" (empty value) as a
        // declared TE; it rejects like any other TE.
        if (line.len >= te_prefix.len and
            std.ascii.eqlIgnoreCase(line[0..te_prefix.len], te_prefix))
        {
            return .invalid;
        }
        const cl_prefix = "content-length:";
        if (line.len <= cl_prefix.len) continue;
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
    return if (content_length) |cl| .{ .length = cl } else .eof_body;
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
    const cl = switch (parseResponseHead(data[0..header_end])) {
        .invalid => return .{ .err = HttpError.InvalidResponse },
        .too_large => return .{ .err = HttpError.ResponseTooLarge },
        .eof_body => return .incomplete,
        .length => |cl| cl,
    };
    const need = std.math.add(usize, header_end + 4, cl) catch
        return .{ .err = HttpError.ResponseTooLarge };
    if (data.len >= need) return .{ .done = need };
    return .incomplete;
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
// TCP Connection
// ============================================================================

/// A resolved peer: a fresh non-blocking socket plus the first resolved
/// IPv4 address to connect it to.
const ResolvedPeer = struct {
    fd: posix.fd_t,
    addr: std.c.sockaddr.in,
};

/// Resolve `host` (blocking getaddrinfo, IPv4 only -- a documented limit to
/// be replaced by the async resolver work item A8/X2) and return a
/// non-blocking socket plus the first resolved address, or null.
fn resolvePeer(host: []const u8, port: u16) ?ResolvedPeer {
    // Null-terminate hostname for getaddrinfo
    var host_buf: [256]u8 = undefined;
    if (host.len >= host_buf.len) return null;
    @memcpy(host_buf[0..host.len], host);
    host_buf[host.len] = 0;

    var port_buf: [8]u8 = undefined;
    const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch return null;
    port_buf[port_str.len] = 0;

    var hints: c.struct_addrinfo = std.mem.zeroes(c.struct_addrinfo);
    hints.ai_family = c.AF_INET;
    hints.ai_socktype = c.SOCK_STREAM;

    var result: ?*c.struct_addrinfo = null;
    const gai_ret = c.getaddrinfo(&host_buf, &port_buf, &hints, &result);
    if (gai_ret != 0 or result == null) return null;
    defer c.freeaddrinfo(result.?);

    const ai = result.?;
    if (ai.ai_addrlen > @sizeOf(std.c.sockaddr.in)) return null;
    const fd = std.c.socket(
        @intCast(ai.ai_family),
        @as(u32, @intCast(ai.ai_socktype)) | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC,
        @intCast(ai.ai_protocol),
    );
    if (fd < 0) return null;

    var addr: std.c.sockaddr.in = std.mem.zeroes(std.c.sockaddr.in);
    @memcpy(
        std.mem.asBytes(&addr)[0..ai.ai_addrlen],
        @as([*]const u8, @ptrCast(ai.ai_addr))[0..ai.ai_addrlen],
    );

    return .{ .fd = fd, .addr = addr };
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

fn parseStatusLine(data: []const u8) ?u16 {
    // "HTTP/1.1 200 OK\r\n" or "HTTP/1.0 200 OK\r\n"
    if (data.len < 12) return null;
    if (!std.mem.startsWith(u8, data, "HTTP/1.")) return null;

    // Find the status code (starts at offset 9 after "HTTP/1.X ")
    if (data[8] != ' ') return null;
    return std.fmt.parseInt(u16, data[9..12], 10) catch null;
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
    var client = try Client.init(cert_path);
    defer client.deinit();
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

    var client = try Client.init(cert_path);
    defer client.deinit();
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

test "responseComplete: Transfer-Encoding is rejected outright" {
    const chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nhelo\r\n0\r\n\r\n";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(chunked),
    );
    // Even alongside a Content-Length, the TE wins by rejecting.
    const both = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello";
    try std.testing.expectEqual(
        Complete{ .err = HttpError.InvalidResponse },
        responseComplete(both),
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

    var client = try Client.init(cert_path);
    defer client.deinit();
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

    var client = try Client.init(cert_path);
    defer client.deinit();
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

    var client = try Client.init(cert_path);
    defer client.deinit();
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
    var client = try Client.init(cert_path);
    defer client.deinit();
    var resp = try client.get(std.testing.allocator, url, testOptions(5000, 2000));
    defer resp.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("ok\r\n", resp.body);
}
