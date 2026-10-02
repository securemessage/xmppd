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

// OpenSSL 3.0.22 defines SSL_OP_ENABLE_KTLS as the variadic macro
// SSL_OP_BIT(3) ((uint64_t)1 << 3). Zig's cimport lowers that macro to a
// generic function that fails to instantiate, so define the bit by hand.
const SSL_OP_ENABLE_KTLS: u64 = 1 << 3;

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

/// Custom OpenSSL verify callback that always accepts the peer certificate.
/// DANE verification is performed separately after the handshake completes.
/// This allows us to request a peer cert without OpenSSL rejecting it for
/// PKIX reasons (self-signed, unknown CA, etc).
fn alwaysAcceptVerify(_: c_int, _: ?*c.X509_STORE_CTX) callconv(.c) c_int {
    return 1; // Always OK
}

/// An OpenSSL `SSL_CTX` wrapper. Create once at server startup, share across
/// all connections. Thread-safe after initialization (OpenSSL 3.x guarantee).
pub const SslContext = struct {
    ctx: *c.SSL_CTX,
    /// Whether `SSL_OP_ENABLE_KTLS` was armed on this context (kernel-TLS
    /// offload). Recorded here for `ktlsEngaged()` reporting and config.
    ktls: bool,

    /// Initialize a server-side TLS context with certificate and private key.
    ///
    /// - `cert_path` — path to PEM-encoded certificate file (may include chain)
    /// - `key_path` — path to PEM-encoded private key file
    /// - `ktls` — enable kernel-TLS offload (SSL_OP_ENABLE_KTLS). DEFAULT ON.
    ///
    /// Uses `TLS_server_method()` which negotiates the highest TLS version
    /// supported by both sides (TLS 1.2 or 1.3).
    ///
    /// KTLS is a first-class FreeBSD feature and is the default offload for the
    /// server side, where it is both valuable (symmetric crypto in-kernel) and
    /// safe: C2S clients are ordinary non-KTLS peers, so the both-ends kernel
    /// limitation (see initClientWithCert) is never triggered. Pass `false` to
    /// disable (e.g. the local same-host smoke rig, whose client is also
    /// KTLS-armed by default in some builds).
    pub fn initServer(cert_path: [*:0]const u8, key_path: [*:0]const u8, ktls: ?bool) SslError!SslContext {
        const enable_ktls = ktls orelse true;
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

        // Request (but don't require) a client certificate for DANE verification.
        // SSL_VERIFY_PEER without SSL_VERIFY_FAIL_IF_NO_PEER_CERT means:
        // - Ask the client for a cert (CertificateRequest message)
        // - If they provide one, we can inspect it (for DANE)
        // - If they don't provide one, the handshake still succeeds (dialback fallback)
        // Custom callback always returns OK — we do DANE ourselves after handshake.
        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, &alwaysAcceptVerify);

        // Set session ID context — required when SSL_VERIFY_PEER is active,
        // otherwise OpenSSL rejects the second concurrent handshake with
        // SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED (error 0x0A000115).
        const sid_ctx = "xmppd";
        _ = c.SSL_CTX_set_session_id_context(ctx, sid_ctx, sid_ctx.len);

        // Kernel-TLS offload: first-class on FreeBSD and the default here.
        // OpenSSL arms the in-kernel ULP lazily after the handshake (verify
        // with ktlsEngaged()). One-ended kTLS is safe; the only failure mode
        // is BOTH ends arming across an interface without IFCAP_MEXTPG (lo0,
        // epair, bridge) — FreeBSD PR 296498, `EBADMSG`/bad record mac. That
        // is never triggered on C2S because our clients default to offload OFF
        // (initClientWithCert), so the both-ends case cannot occur.
        if (enable_ktls) {
            _ = c.SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
        }

        return SslContext{ .ctx = ctx, .ktls = enable_ktls };
    }

    /// Initialize a client-side TLS context for outbound connections.
    ///
    /// Loads our certificate for presentation to the remote server (needed for
    /// SASL EXTERNAL authentication with DANE). PKIX verification of the remote
    /// peer is disabled because we use DANE verification ourselves.
    pub fn initClient() SslError!SslContext {
        return initClientWithCert(null, null, null);
    }

    /// Initialize a client-side TLS context with a certificate for mutual TLS.
    ///
    /// - `cert_path` / `key_path` — our certificate/key, presented to the remote
    ///   server (required for XMPP S2S SASL EXTERNAL after DANE verification).
    /// - `ktls` — enable kernel-TLS offload. DEFAULT OFF.
    ///
    /// KTLS is first-class on FreeBSD, but a client that arms KTLS fails
    /// (EBADMSG / "bad record mac") when its PEER also arms KTLS and the
    /// packets cross an interface without IFCAP_MEXTPG (lo0, epair, bridge) —
    /// FreeBSD PR 296498. A peer that is another xmppd has server-side KTLS
    /// on by default, so a client talking to it must NOT arm KTLS. One-ended
    /// offload is safe, which is why the server stays on by default. Opt in
    /// only against peers known not to arm it themselves (e.g. a `--no-ktls`
    /// or `ktls=false` server).
    pub fn initClientWithCert(cert_path: ?[*:0]const u8, key_path: ?[*:0]const u8, ktls: ?bool) SslError!SslContext {
        const enable_ktls = ktls orelse false;
        const method = c.TLS_client_method() orelse return SslError.SslInitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return SslError.SslInitFailed;
        errdefer c.SSL_CTX_free(ctx);

        // Disable OpenSSL's built-in certificate verification — we do DANE ourselves
        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);

        // Load our certificate for presentation to remote peer
        if (cert_path) |cp| {
            if (c.SSL_CTX_use_certificate_chain_file(ctx, cp) != 1) {
                return SslError.CertLoadFailed;
            }
        }
        if (key_path) |kp| {
            if (c.SSL_CTX_use_PrivateKey_file(ctx, kp, c.SSL_FILETYPE_PEM) != 1) {
                return SslError.KeyLoadFailed;
            }
            if (c.SSL_CTX_check_private_key(ctx) != 1) {
                return SslError.KeyMismatch;
            }
        }

        // Kernel-TLS offload is opt-in on the client side (default off): see
        // the doc above for the both-ends limitation.
        if (enable_ktls) {
            _ = c.SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
        }

        return SslContext{ .ctx = ctx, .ktls = enable_ktls };
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
            else => {
                // Log the OpenSSL error queue for diagnostics
                var err_buf: [256]u8 = undefined;
                while (true) {
                    const e = c.ERR_get_error();
                    if (e == 0) break;
                    c.ERR_error_string_n(e, &err_buf, err_buf.len);
                    const log = std.log.scoped(.ssl);
                    log.err("TLS handshake error: SSL_get_error={d} detail={s}", .{ err, @as([*:0]const u8, @ptrCast(&err_buf)) });
                }
                return SslError.HandshakeFailed;
            },
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
            else => {
                // Log the OpenSSL error queue for diagnostics.
                var err_buf: [256]u8 = undefined;
                while (true) {
                    const e = c.ERR_get_error();
                    if (e == 0) break;
                    c.ERR_error_string_n(e, &err_buf, err_buf.len);
                    std.log.scoped(.ssl).err("TLS read error: SSL_get_error={d} detail={s}", .{ err, @as([*:0]const u8, @ptrCast(&err_buf)) });
                }
                return SslError.ReadFailed;
            },
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

    /// Returns the number of bytes available for immediate read from the
    /// SSL internal buffer (already decrypted, not yet returned to the app).
    /// A non-zero value means `read()` can return data without a syscall.
    pub fn pending(self: *SslConn) usize {
        const ret = c.SSL_pending(self.ssl);
        return if (ret > 0) @intCast(ret) else 0;
    }

    /// Whether kernel-TLS offload actually engaged on this connection. OpenSSL
    /// arms the in-kernel ULP lazily after the handshake, so this is false
    /// until a record has flowed. Useful for logging/verification that a
    /// KTLS-armed context really offloaded (fallback to userland is silent,
    /// so this is the only way to tell).
    ///
    /// Mirrors the BIO_get_ktls_send/recv macros: send is queried on the
    /// write BIO, recv on the read BIO. True if either direction is offloaded.
    pub fn ktlsEngaged(self: *SslConn) bool {
        // BIO_CTRL_GET_KTLS_SEND = 73, BIO_CTRL_GET_KTLS_RECV = 76.
        if (c.SSL_get_wbio(self.ssl)) |wbio| {
            if (c.BIO_ctrl(wbio, 73, 0, null) > 0) return true;
        }
        if (c.SSL_get_rbio(self.ssl)) |rbio| {
            if (c.BIO_ctrl(rbio, 76, 0, null) > 0) return true;
        }
        return false;
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

    /// Channel binding type identifiers (matches IPC cb_type field).
    pub const CbType = enum(u8) {
        none = 0,
        tls_server_end_point = 1,
        tls_exporter = 2,
    };

    /// Channel binding result — type + 32-byte binding data.
    pub const ChannelBinding = struct {
        cb_type: CbType,
        data: [32]u8,
    };

    /// Extract channel binding data from the TLS session.
    ///
    /// - TLS 1.3: uses `tls-exporter` (RFC 9266) via `SSL_export_keying_material`
    /// - TLS 1.2: uses `tls-server-end-point` (RFC 5929) — SHA-256 of server cert DER
    ///
    /// Returns null if the handshake hasn't completed or binding data
    /// cannot be extracted.
    pub fn getChannelBinding(self: *SslConn) ?ChannelBinding {
        // Check TLS version to determine binding type
        const version = c.SSL_version(self.ssl);
        if (version >= c.TLS1_3_VERSION) {
            // tls-exporter (RFC 9266): export keying material
            var data: [32]u8 = undefined;
            const label = "EXPORTER-Channel-Binding";
            const ret = c.SSL_export_keying_material(
                self.ssl,
                &data,
                32,
                label.ptr,
                label.len,
                "",
                0,
                0, // no context
            );
            if (ret == 1) {
                return .{ .cb_type = .tls_exporter, .data = data };
            }
            return null;
        } else if (version >= c.TLS1_2_VERSION) {
            // tls-server-end-point (RFC 5929): SHA-256 hash of server certificate
            const x509 = c.SSL_get_certificate(self.ssl) orelse return null;
            const der_len = c.i2d_X509(x509, null);
            if (der_len <= 0 or der_len > 65535) return null;

            // Stack-allocate a buffer for the DER (typical cert is 1-4KB)
            var der_buf: [8192]u8 = undefined;
            if (@as(usize, @intCast(der_len)) > der_buf.len) return null;

            var ptr: [*c]u8 = &der_buf;
            const written = c.i2d_X509(x509, &ptr);
            if (written != der_len) return null;

            // SHA-256 hash of the DER-encoded certificate
            var data: [32]u8 = undefined;
            const Sha256 = std.crypto.hash.sha2.Sha256;
            Sha256.hash(der_buf[0..@intCast(der_len)], &data, .{});

            return .{ .cb_type = .tls_server_end_point, .data = data };
        }
        return null;
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

// Self-signed test cert/key (CN=localhost) embedded so tests are self-contained.
const TestCert =
    \\-----BEGIN CERTIFICATE-----
    \\MIIDCTCCAfGgAwIBAgIUC4bDrk8Y0fI5AoKrFkDHpu/Z/UgwDQYJKoZIhvcNAQEL
    \\BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgzMTAyNDEzMloXDTI2MDkw
    \\MjAyNDEzMlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
    \\AAOCAQ8AMIIBCgKCAQEA7G3DDoU55u8Ty5T1knHdEojzVKQxjW9fvWLchkffrS3S
    \\KEyoDCn+3IILv14hKxsILDWf0vYdhiCiFZGJ2iOj3XCgjTsJZbE6d4RETmtHNYvX
    \\OMVdH0XAFpS2Y1mf9xUwBLXfHgaTKp6t0WEW32njMjsJW1uix1UnstRlCnf0FUNC
    \\1+13TSAWn4/j4WeAozPsKDLr64VYFEZfkoB/jOz5AnTb3RzAInW1vmzt9Kk3ITdD
    \\JymJ2AWJ8vz4wOe1yd5TvAtYtnbMg5tuFThKnejsEUnvVCi0Ht+Jcaw4cCLykH+Q
    \\GwtWFRuh/lqiXZY6XbdrNHxFb2neYRyhR5ua9GUzAwIDAQABo1MwUTAdBgNVHQ4E
    \\FgQUGL02ZFJ47GBarVFkmh+i6gsJwggwHwYDVR0jBBgwFoAUGL02ZFJ47GBarVFk
    \\mh+i6gsJwggwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAdC2v
    \\UXaoH/MtZjtJc6UAedgqDgon8dc9h4kBFAE2LXLm0A+hk9aATXp+tGuQgJm+Zk7v
    \\lNZRwrI3vTXVWPpowZ/8225QiEtfoPvJrOHU2I1HIMuqTd8KK5W1XH9tF0w/7/Xe
    \\mPwB/7dNfeV1g2LgLYuP+xg4gZb6bE2cToMcsFcu/8ZsTUrOyW72hkRmMITSPCDD
    \\uIvLB47FBQn+Tv6P7y+fpf0Md3Ac2p/bCogdX76iaZVTjn7OeOmox7OHu9bNXssF
    \\NeA/ahqgHF6HIBLs/kirttsQMJT1WCSqT+UE8D4cJse1vDrXIgFK5ud7hTGJHh1e
    \\yQPImlOe+43+ZCYZfg==
    \\-----END CERTIFICATE-----
    \\
;

const TestKey =
    \\-----BEGIN PRIVATE KEY-----
    \\MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDsbcMOhTnm7xPL
    \\lPWScd0SiPNUpDGNb1+9YtyGR9+tLdIoTKgMKf7cggu/XiErGwgsNZ/S9h2GIKIV
    \\kYnaI6PdcKCNOwllsTp3hEROa0c1i9c4xV0fRcAWlLZjWZ/3FTAEtd8eBpMqnq3R
    \\YRbfaeMyOwlbW6LHVSey1GUKd/QVQ0LX7XdNIBafj+PhZ4CjM+woMuvrhVgURl+S
    \\gH+M7PkCdNvdHMAidbW+bO30qTchN0MnKYnYBYny/PjA57XJ3lO8C1i2dsyDm24V
    \\OEqd6OwRSe9UKLQe34lxrDhwIvKQf5AbC1YVG6H+WqJdljpdt2s0fEVvad5hHKFH
    \\m5r0ZTMDAgMBAAECggEADzt/a8IAVV5hKJ1r5l62petqvfoVTluJPcUzc5wtIYza
    \\juUfut4KpZtR4yc8vNQDhm0TdaNoHR7Fi7if8bFz/zJFEl/BbJh9LZ/v24lElEw7
    \\rTAJefPRjVUsd+qZY972Foi/LeZEHXcNk68NKtgm+g5Kqxumy6bFXFuJyrPNC6U+
    \\YLfkNExhmANADPS56JxajBWk5rjIZEZHNKPgwLoznykNoWld4sDyvgGZ0m73Y0nP
    \\4nCEyiieZUzP/QnNVBwXsJzv5goiJbRlUUTZ2mi+z9cYN2G5pZTue23uFuzgRBIp
    \\iwofyElr8Re/4EsPY/8NMEtTRUZbUGpkfkD8jMutAQKBgQD8DwZtWGVGxtmJp434
    \\g9yRtFCS837eJQLPCSIyHqj+K60KyhIPyMpAxSoVnJ0/+vKR5Lk2UwqpQpu3KJP1
    \\v2gu1yeWI33AFdLkAzCDFbsJIlq4vmLqnnGCK3t+/zOXXWruSUjOvS96A3PE9cXx
    \\PKlFc5ZxB0A4KXHMhDNiLwUDAQKBgQDwICvT8fLV/VMjCUKL0DrIaaBL9pf7Bk9q
    \\INrpWc0tMikTMo1Qkd29pTh6q0cwlKQhXIl7eOhBu01h7aeH9IOXDlBNwVS3yEiS
    \\CrowDxrDAJeMSVbpPXE5lEhE6T1A9XI930ZEGzK8o4XdGG+a2aH6MRnKKtqkun90
    \\xOBfDNgqAwKBgQC0j4LYI6FxIRNGc7vU0YjY62Voz3sLYVHww6c2ZhZC9UChYP2t
    \\RvXzjgnGr4lKAtdvQXyX+MbDV0661xueyD22iDP4bnYverK22b4PuSphsbVxcBjl
    \\3xiK2eE+qUvo22e1SNQaHRX8fqqY5kKkvAK6GMIlN79+O9okWnOAmxQpAQKBgHsg
    \\s/iQ9uj9ZdTwWZwhoRLE/roU7yd7u9r6j+XZ81h6gQ9j+4xVz3MANm7IRs/FWEf3
    \\EFQs0kNqTKqrVx1iptsdLtZADTXT0Ep6j7A2/o0BT7RSouskY1uYClqzkoItmW/a
    \\fkhL/f82hlyxvACWGfWVmdjNkqGnM9XnYfm7N1iLAoGBAOSHVVaA+RpkZnF5qWs8
    \\AW/DtZu00mkSpUT/jAZKNj8MOm5VCNeT6CoROhvgn+f/C6kc6PvzAdJtrDImE9lM
    \\2iPPJ6RMzVun0MZQExGrc6QNJ4jBnvdLLKSl0rq/Can3mf5OIx3ALaVFXnQtrqW6
    \\3m6PRJeGKuEzJztmizyMZfNS
    \\-----END PRIVATE KEY-----
    \\
;

test "SslContext: initServer fails with bad cert path" {
    const result = SslContext.initServer("/nonexistent/cert.pem", "/nonexistent/key.pem", null);
    try std.testing.expectError(SslError.CertLoadFailed, result);
}

test "SslContext: initClient succeeds without cert/key" {
    var ctx = try SslContext.initClient();
    defer ctx.deinit();
    // Client context created successfully — no cert/key needed
    // KTLS is off by default on the client side (both-ends limitation).
    try std.testing.expect(!ctx.ktls);
}

test "SslContext: KTLS default is on for server, off for client" {
    // initServer's happy path needs a cert+key on disk; use a private /tmp
    // dir (unique per run) so the test is self-contained.
    const alloc = std.testing.allocator;
    const tmp = std.fmt.allocPrint(alloc, "/tmp/xmppd-ssl-test-{d}", .{std.time.milliTimestamp()}) catch @panic("alloc");
    try std.fs.cwd().makePath(tmp);
    // allocPrintSentinel yields a NUL-terminated [:0]u8 whose .len EXCLUDES the
    // NUL: .ptr is the [*:0]const u8 the OpenSSL C API wants, and the full slice
    // (len = content) is a clean []const u8 for Zig's file ops.
    const cert_c = std.fmt.allocPrintSentinel(alloc, "{s}/cert.pem", .{tmp}, 0) catch @panic("alloc");
    const key_c = std.fmt.allocPrintSentinel(alloc, "{s}/key.pem", .{tmp}, 0) catch @panic("alloc");
    const cert_path = cert_c[0..cert_c.len];
    const key_path = key_c[0..key_c.len];

    const cert_file = try std.fs.cwd().createFile(cert_path, .{});
    try cert_file.writeAll(TestCert);
    cert_file.close();
    const key_file = try std.fs.cwd().createFile(key_path, .{});
    try key_file.writeAll(TestKey);
    key_file.close();

    // Server: KTLS default ON (first-class FreeBSD feature).
    var srv = try SslContext.initServer(cert_c.ptr, key_c.ptr, null);
    defer srv.deinit();
    try std.testing.expect(srv.ktls);

    // Server: explicit opt-out is honored.
    var srv_off = try SslContext.initServer(cert_c.ptr, key_c.ptr, false);
    defer srv_off.deinit();
    try std.testing.expect(!srv_off.ktls);

    // Client: KTLS default OFF (avoids the both-ends kernel limitation).
    var cli = try SslContext.initClientWithCert(null, null, null);
    defer cli.deinit();
    try std.testing.expect(!cli.ktls);

    // Client: explicit opt-in is honored.
    var cli_on = try SslContext.initClientWithCert(null, null, true);
    defer cli_on.deinit();
    try std.testing.expect(cli_on.ktls);

    std.fs.cwd().deleteFile(cert_path) catch {};
    std.fs.cwd().deleteFile(key_path) catch {};
    std.fs.cwd().deleteDir(tmp) catch {};
    alloc.free(tmp);
    alloc.free(cert_c);
    alloc.free(key_c);
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
