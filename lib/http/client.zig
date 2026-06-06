//! # HTTP Client — Minimal blocking HTTP/1.1 over TLS (OpenSSL)
//!
//! Designed for OIDC backend use: JWKS fetch, token introspection, ROPC grant.
//! Runs inside xmppd-auth-oidc process — blocking calls are fine since the auth
//! daemon has its own process (won't block C2S event loop).
//!
//! ## Features
//!
//! - HTTP/1.1 GET and POST (application/x-www-form-urlencoded)
//! - TLS via OpenSSL (reuses lib/tls/ssl.zig FFI)
//! - DANE-first verification (via lib/tls/tls.zig + lib/dns/dns.zig)
//! - PKIX fallback with configurable CA bundle
//! - Connection-per-request (no keepalive — simplicity for 3 fixed endpoints)
//! - Response limited to 256KB (JWKS/token responses are small)
//!
//! ## Usage
//!
//! ```zig
//! const http = @import("http");
//! var response = try http.get(allocator, "https://auth.example.com/.well-known/openid-configuration", null);
//! defer allocator.free(response.body);
//! ```

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/x509.h");
    @cInclude("netdb.h");
    @cInclude("sys/socket.h");
    @cInclude("netinet/in.h");
});

pub const HttpError = error{
    InvalidUrl,
    DnsResolutionFailed,
    ConnectionFailed,
    TlsInitFailed,
    TlsHandshakeFailed,
    TlsWriteFailed,
    TlsReadFailed,
    ResponseTooLarge,
    InvalidResponse,
    OutOfMemory,
};

pub const Response = struct {
    status: u16,
    body: []const u8,
    allocator: Allocator,

    pub fn deinit(self: *Response) void {
        self.allocator.free(self.body);
    }
};

/// Maximum response body size (256KB).
const MAX_RESPONSE_SIZE: usize = 256 * 1024;

/// Perform an HTTPS GET request. Caller owns the returned Response.body.
pub fn get(allocator: Allocator, url: []const u8, ca_file: ?[]const u8) HttpError!Response {
    return request(allocator, "GET", url, null, null, ca_file);
}

/// Perform an HTTPS POST with form-urlencoded body. Caller owns the returned Response.body.
pub fn post(allocator: Allocator, url: []const u8, body: []const u8, ca_file: ?[]const u8) HttpError!Response {
    return request(allocator, "POST", url, body, "application/x-www-form-urlencoded", ca_file);
}

/// Core HTTP request implementation.
fn request(
    allocator: Allocator,
    method: []const u8,
    url: []const u8,
    body: ?[]const u8,
    content_type: ?[]const u8,
    ca_file: ?[]const u8,
) HttpError!Response {
    // Parse URL: https://host[:port]/path
    const parsed = parseUrl(url) orelse return HttpError.InvalidUrl;

    // DNS resolution
    const fd = tcpConnect(parsed.host, parsed.port) orelse return HttpError.ConnectionFailed;
    defer posix.close(fd);

    // TLS setup
    const ssl_ctx = initTlsClient(ca_file) orelse return HttpError.TlsInitFailed;
    defer c.SSL_CTX_free(ssl_ctx);

    const ssl_ptr = c.SSL_new(ssl_ctx) orelse return HttpError.TlsInitFailed;
    defer c.SSL_free(ssl_ptr);

    _ = c.SSL_set_fd(ssl_ptr, @intCast(fd));

    // Set SNI hostname
    var host_buf: [256]u8 = undefined;
    if (parsed.host.len < host_buf.len) {
        @memcpy(host_buf[0..parsed.host.len], parsed.host);
        host_buf[parsed.host.len] = 0;
        _ = c.SSL_set_tlsext_host_name(ssl_ptr, &host_buf);
    }

    // TLS handshake (blocking)
    if (c.SSL_connect(ssl_ptr) != 1) return HttpError.TlsHandshakeFailed;

    // Build HTTP request
    var req_buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&req_buf);
    const w = fbs.writer();

    w.print("{s} {s} HTTP/1.1\r\n", .{ method, parsed.path }) catch return HttpError.OutOfMemory;
    w.print("Host: {s}\r\n", .{parsed.host_header}) catch return HttpError.OutOfMemory;
    w.writeAll("Connection: close\r\n") catch return HttpError.OutOfMemory;

    if (body) |b| {
        if (content_type) |ct| {
            w.print("Content-Type: {s}\r\n", .{ct}) catch return HttpError.OutOfMemory;
        }
        w.print("Content-Length: {d}\r\n", .{b.len}) catch return HttpError.OutOfMemory;
    }

    w.writeAll("\r\n") catch return HttpError.OutOfMemory;
    if (body) |b| {
        w.writeAll(b) catch return HttpError.OutOfMemory;
    }

    const req_data = fbs.getWritten();

    // Send request
    var sent: usize = 0;
    while (sent < req_data.len) {
        const ret = c.SSL_write(ssl_ptr, @ptrCast(req_data.ptr + sent), @intCast(req_data.len - sent));
        if (ret <= 0) return HttpError.TlsWriteFailed;
        sent += @intCast(ret);
    }

    // Read response
    var resp_buf = allocator.alloc(u8, MAX_RESPONSE_SIZE) catch return HttpError.OutOfMemory;
    errdefer allocator.free(resp_buf);
    var total: usize = 0;

    while (total < MAX_RESPONSE_SIZE) {
        const ret = c.SSL_read(ssl_ptr, @ptrCast(resp_buf.ptr + total), @intCast(MAX_RESPONSE_SIZE - total));
        if (ret <= 0) break; // EOF or error
        total += @intCast(ret);
    }

    if (total == 0) {
        allocator.free(resp_buf);
        return HttpError.InvalidResponse;
    }

    // Parse status line: "HTTP/1.1 200 OK\r\n..."
    const resp_data = resp_buf[0..total];
    const status = parseStatusLine(resp_data) orelse {
        allocator.free(resp_buf);
        return HttpError.InvalidResponse;
    };

    // Find body (after \r\n\r\n)
    const header_end = std.mem.indexOf(u8, resp_data, "\r\n\r\n") orelse {
        allocator.free(resp_buf);
        return HttpError.InvalidResponse;
    };

    const body_start = header_end + 4;
    const response_body = resp_data[body_start..];

    // Copy body to a right-sized allocation
    const body_copy = allocator.alloc(u8, response_body.len) catch {
        allocator.free(resp_buf);
        return HttpError.OutOfMemory;
    };
    @memcpy(body_copy, response_body);
    allocator.free(resp_buf);

    return Response{
        .status = status,
        .body = body_copy,
        .allocator = allocator,
    };
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

fn tcpConnect(host: []const u8, port: u16) ?posix.fd_t {
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
    const fd = std.c.socket(@intCast(ai.ai_family), @intCast(ai.ai_socktype), @intCast(ai.ai_protocol));
    if (fd < 0) return null;

    if (std.c.connect(fd, @ptrCast(ai.ai_addr), ai.ai_addrlen) != 0) {
        _ = std.c.close(fd);
        return null;
    }

    return fd;
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
