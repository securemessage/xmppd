//! # SSL — OpenSSL C FFI for socket-level TLS
//!
//! Provides Zig-idiomatic wrappers around OpenSSL 3.x for server-side TLS.
//! Designed for non-blocking integration with kqueue — handshake, read, and
//! write operations return `want_read` / `want_write` when the socket isn't
//! ready, allowing the caller to re-arm the appropriate kqueue filter.
//!
//! ## Lifecycle
//!
//! 1. `SslContext.initServer(cert, key)` — once at startup, shared across connections
//! 2. `SslConn.init(ctx, fd)` — per accepted connection
//! 3. `SslConn.doHandshake()` — called repeatedly until `.complete`
//! 4. `SslConn.read()` / `SslConn.write()` — data transfer
//! 5. `SslConn.deinit()` — cleanup
//!
//! ## DANE Integration
//!
//! After handshake completes, extract the peer certificate chain with
//! `getPeerCertDer()` / `getPeerChainDer()` and pass to `tls.validateDane()`.
//!
//! ## Build Requirements
//!
//! Link against base system OpenSSL:
//! ```zig
//! mod.linkSystemLibrary("ssl");
//! mod.linkSystemLibrary("crypto");
//! ```

const std = @import("std");

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/x509.h");
});

/// Result of a non-blocking TLS handshake attempt.
pub const HandshakeResult = enum {
    /// Handshake completed successfully.
    complete,
    /// Handshake needs to read from the socket. Register EVFILT_READ and retry.
    want_read,
    /// Handshake needs to write to the socket. Register EVFILT_WRITE and retry.
    want_write,
};

/// Result of a non-blocking TLS read or write operation.
pub const IoResult = union(enum) {
    /// Operation completed, `n` bytes transferred.
    ok: usize,
    /// Socket not ready for reading. Register EVFILT_READ and retry.
    want_read,
    /// Socket not ready for writing. Register EVFILT_WRITE and retry.
    want_write,
};

pub const SslError = error{
    /// SSL_CTX or SSL initialization failed.
    SslInitFailed,
    /// Failed to load certificate file.
    CertLoadFailed,
    /// Failed to load private key file.
    KeyLoadFailed,
    /// Private key does not match the certificate.
    KeyMismatch,
    /// TLS handshake failed (peer sent alert, protocol error, etc.).
    HandshakeFailed,
    /// TLS read failed (connection reset, protocol error).
    ReadFailed,
    /// TLS write failed (connection reset, protocol error).
    WriteFailed,
    /// The peer closed the TLS connection cleanly (SSL_ERROR_ZERO_RETURN).
    ConnectionClosed,
    /// Out of memory.
    OutOfMemory,
};

// ============================================================================
// SslContext — shared across all connections
// ============================================================================

/// An OpenSSL `SSL_CTX` wrapper. Create once at server startup, share across
/// all connections. Thread-safe after initialization (OpenSSL 3.x guarantee).
pub const SslContext = struct {
    ctx: *c.SSL_CTX,

    /// Initialize a server-side TLS context with certificate and private key.
    ///
    /// - `cert_path` — path to PEM-encoded certificate file (may include chain)
    /// - `key_path` — path to PEM-encoded private key file
    ///
    /// Uses `TLS_server_method()` which negotiates the highest TLS version
    /// supported by both sides (TLS 1.2 or 1.3).
    pub fn initServer(cert_path: [*:0]const u8, key_path: [*:0]const u8) SslError!SslContext {
        const method = c.TLS_server_method() orelse return SslError.SslInitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return SslError.SslInitFailed;
        errdefer c.SSL_CTX_free(ctx);

        // Load certificate
        if (c.SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1) {
            return SslError.CertLoadFailed;
        }

        // Load private key
        if (c.SSL_CTX_use_PrivateKey_file(ctx, key_path, c.SSL_FILETYPE_PEM) != 1) {
            return SslError.KeyLoadFailed;
        }

        // Verify key matches cert
        if (c.SSL_CTX_check_private_key(ctx) != 1) {
            return SslError.KeyMismatch;
        }

        return SslContext{ .ctx = ctx };
    }

    /// Initialize a client-side TLS context for outbound connections.
    ///
    /// No certificate or key is needed — the connecting party doesn't present
    /// a client cert (unless mutual TLS is required, which is handled separately).
    /// PKIX verification is disabled because we use DANE verification ourselves.
    pub fn initClient() SslError!SslContext {
        const method = c.TLS_client_method() orelse return SslError.SslInitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return SslError.SslInitFailed;
        errdefer c.SSL_CTX_free(ctx);

        // Disable OpenSSL's built-in certificate verification — we do DANE ourselves
        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);

        return SslContext{ .ctx = ctx };
    }

    /// Release the SSL_CTX. All SslConns created from this context must be
    /// freed first.
    pub fn deinit(self: *SslContext) void {
        c.SSL_CTX_free(self.ctx);
        self.ctx = undefined;
    }
};

// ============================================================================
// SslConn — per-connection TLS state
// ============================================================================

/// A per-connection TLS wrapper around OpenSSL's `SSL` object.
/// Provides non-blocking handshake, read, and write operations.
pub const SslConn = struct {
    ssl: *c.SSL,

    /// Create a new server-side TLS connection from an SSL_CTX and a socket fd.
    ///
    /// The fd must already be connected and set to non-blocking mode.
    /// After init, call `doHandshake()` to perform the TLS handshake.
    pub fn init(ctx: SslContext, fd: std.posix.fd_t) SslError!SslConn {
        const ssl = c.SSL_new(ctx.ctx) orelse return SslError.SslInitFailed;
        errdefer c.SSL_free(ssl);

        // Attach the socket fd
        if (c.SSL_set_fd(ssl, @intCast(fd)) != 1) {
            return SslError.SslInitFailed;
        }

        // Server mode — we accept connections
        c.SSL_set_accept_state(ssl);

        return SslConn{ .ssl = ssl };
    }

    /// Create a new client-side TLS connection for outbound use.
    ///
    /// Sets `SSL_set_connect_state` (client role) and optionally sets the
    /// SNI hostname via `SSL_set_tlsext_host_name` for virtual hosting.
    /// After init, call `doHandshake()` to perform the TLS handshake.
    pub fn initClient(ctx: SslContext, fd: std.posix.fd_t, hostname: ?[*:0]const u8) SslError!SslConn {
        const ssl = c.SSL_new(ctx.ctx) orelse return SslError.SslInitFailed;
        errdefer c.SSL_free(ssl);

        if (c.SSL_set_fd(ssl, @intCast(fd)) != 1) {
            return SslError.SslInitFailed;
        }

        // Client mode — we initiate connections
        c.SSL_set_connect_state(ssl);

        // Set SNI hostname if provided
        if (hostname) |h| {
            // SSL_set_tlsext_host_name is a macro in C; use the underlying ctrl call
            _ = c.SSL_ctrl(ssl, c.SSL_CTRL_SET_TLSEXT_HOSTNAME, c.TLSEXT_NAMETYPE_host_name, @ptrCast(@constCast(h)));
        }

        return SslConn{ .ssl = ssl };
    }

    /// Perform (or continue) the TLS handshake.
    ///
    /// For non-blocking sockets, this may return `want_read` or `want_write`.
    /// The caller should register the appropriate kqueue filter and call
    /// `doHandshake()` again when the socket is ready.
    ///
    /// Returns `.complete` when the handshake finishes successfully.
    pub fn doHandshake(self: *SslConn) SslError!HandshakeResult {
        const ret = c.SSL_do_handshake(self.ssl);
        if (ret == 1) return .complete;

        const err = c.SSL_get_error(self.ssl, ret);
        return switch (err) {
            c.SSL_ERROR_WANT_READ => .want_read,
            c.SSL_ERROR_WANT_WRITE => .want_write,
            else => SslError.HandshakeFailed,
        };
    }

    /// Read decrypted data from the TLS connection.
    ///
    /// Returns the number of bytes read, or `want_read`/`want_write` if
    /// the underlying socket isn't ready.
    ///
    /// A return of `ConnectionClosed` means the peer sent a TLS close_notify.
    pub fn read(self: *SslConn, buf: []u8) SslError!IoResult {
        const ret = c.SSL_read(self.ssl, buf.ptr, @intCast(buf.len));
        if (ret > 0) return .{ .ok = @intCast(ret) };

        const err = c.SSL_get_error(self.ssl, ret);
        return switch (err) {
            c.SSL_ERROR_WANT_READ => .want_read,
            c.SSL_ERROR_WANT_WRITE => .want_write,
            c.SSL_ERROR_ZERO_RETURN => SslError.ConnectionClosed,
            else => SslError.ReadFailed,
        };
    }

    /// Write data through the TLS connection.
    ///
    /// Returns the number of bytes written, or `want_read`/`want_write` if
    /// the underlying socket isn't ready.
    pub fn write(self: *SslConn, data: []const u8) SslError!IoResult {
        const ret = c.SSL_write(self.ssl, data.ptr, @intCast(data.len));
        if (ret > 0) return .{ .ok = @intCast(ret) };

        const err = c.SSL_get_error(self.ssl, ret);
        return switch (err) {
            c.SSL_ERROR_WANT_READ => .want_read,
            c.SSL_ERROR_WANT_WRITE => .want_write,
            else => SslError.WriteFailed,
        };
    }

    /// Extract the peer's leaf certificate as DER-encoded bytes.
    ///
    /// Returns `null` if no peer certificate is available (server-side,
    /// peer certs are only available if client certificate auth is enabled).
    ///
    /// Caller owns the returned memory.
    pub fn getPeerCertDer(self: *SslConn, alloc: std.mem.Allocator) SslError!?[]u8 {
        const x509 = c.SSL_get0_peer_certificate(self.ssl) orelse return null;

        // Get DER-encoded length
        const der_len = c.i2d_X509(x509, null);
        if (der_len <= 0) return null;

        const buf = alloc.alloc(u8, @intCast(der_len)) catch return SslError.OutOfMemory;
        errdefer alloc.free(buf);

        var ptr: [*c]u8 = buf.ptr;
        const written = c.i2d_X509(x509, &ptr);
        if (written != der_len) {
            alloc.free(buf);
            return null;
        }

        return buf;
    }

    /// Extract the peer's certificate chain as DER-encoded bytes.
    ///
    /// Returns the intermediate/CA certificates (NOT including the leaf).
    /// The leaf certificate is obtained separately via `getPeerCertDer()`.
    ///
    /// Caller owns the returned slices.
    pub fn getPeerChainDer(self: *SslConn, alloc: std.mem.Allocator) SslError![][]u8 {
        const chain = c.SSL_get_peer_cert_chain(self.ssl) orelse return &.{};

        const num: usize = @intCast(c.OPENSSL_sk_num(@ptrCast(chain)));
        if (num == 0) return &.{};

        const result = alloc.alloc([]u8, num) catch return SslError.OutOfMemory;
        var count: usize = 0;
        errdefer {
            for (result[0..count]) |item| alloc.free(item);
            alloc.free(result);
        }

        for (0..num) |i| {
            // Use OPENSSL_sk_value instead of sk_X509_value to avoid
            // Zig C translator issue with [*c] pointer to opaque X509 type.
            const x509_raw = c.OPENSSL_sk_value(@ptrCast(chain), @intCast(i)) orelse continue;
            const x509: *c.X509 = @ptrCast(@alignCast(x509_raw));

            const der_len = c.i2d_X509(x509, null);
            if (der_len <= 0) continue;

            const buf = alloc.alloc(u8, @intCast(der_len)) catch return SslError.OutOfMemory;

            var ptr: [*c]u8 = buf.ptr;
            const written = c.i2d_X509(x509, &ptr);
            if (written != der_len) {
                alloc.free(buf);
                continue;
            }

            result[count] = buf;
            count += 1;
        }

        // Return only the populated portion
        if (count < num) {
            const trimmed = alloc.alloc([]u8, count) catch return SslError.OutOfMemory;
            @memcpy(trimmed, result[0..count]);
            alloc.free(result);
            return trimmed;
        }

        return result;
    }

    /// Initiate a clean TLS shutdown (sends close_notify alert).
    /// Non-blocking — may need to be called again after kqueue signals readiness.
    pub fn shutdown(self: *SslConn) void {
        _ = c.SSL_shutdown(self.ssl);
    }

    /// Release the SSL object.
    pub fn deinit(self: *SslConn) void {
        c.SSL_free(self.ssl);
        self.ssl = undefined;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "SslContext: initServer fails with bad cert path" {
    const result = SslContext.initServer("/nonexistent/cert.pem", "/nonexistent/key.pem");
    try std.testing.expectError(SslError.CertLoadFailed, result);
}

test "SslContext: initClient succeeds without cert/key" {
    var ctx = try SslContext.initClient();
    defer ctx.deinit();
    // Client context created successfully — no cert/key needed
}

test "HandshakeResult: enum values" {
    // Verify the enum variants exist and are distinct
    const complete: HandshakeResult = .complete;
    const want_read: HandshakeResult = .want_read;
    const want_write: HandshakeResult = .want_write;
    try std.testing.expect(complete != want_read);
    try std.testing.expect(want_read != want_write);
}

test "IoResult: ok variant carries byte count" {
    const result: IoResult = .{ .ok = 42 };
    switch (result) {
        .ok => |n| try std.testing.expectEqual(@as(usize, 42), n),
        else => return error.TestUnexpectedResult,
    }
}

test "IoResult: want_read and want_write are distinct" {
    const wr: IoResult = .want_read;
    const ww: IoResult = .want_write;
    try std.testing.expect(std.meta.activeTag(wr) != std.meta.activeTag(ww));
}
