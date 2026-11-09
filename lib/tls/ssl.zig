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
//! Verification runs inside the handshake. Build the state with `initDane()`,
//! arm it on the connection with `prepareDane()` before `doHandshake()`, and
//! read the outcome with `daneVerdict()` afterwards. The records, the
//! usability filter, digest agility and the verdict all come from the shared
//! `pacyworld/dane-zig` module; this file only bridges it to `SSL_CTX`/`SSL`.
//!
//! Inbound S2S learns the peer domain only after TLS, so it cannot arm the
//! handshake. `verifyPeerDane()` verifies the presented chain afterwards on a
//! dedicated context from `initDaneVerifier()`.
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

// The DANE backend keeps its own extern declarations and opaque types, so
// every crossing between the two type worlds happens in this file.
const dane = @import("dane");
const dane_openssl = @import("dane-openssl");

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

/// One TLSA record as the caller sees it: the fields of the DNSSEC RR that
/// participate in verification (RFC 6698 section 2.1).
pub const DaneRecord = struct {
    usage: u8,
    selector: u8,
    matching_type: u8,
    data: []const u8,
};

/// DANE policy for a single handshake. XMPP disables the DANE-EE name check
/// (RFC 7671 section 5.1) and supplies the service domain plus the SRV target
/// as reference identifiers (RFC 7673 section 4).
pub const DanePolicy = struct {
    /// First entry is the SNI value and the base domain for OpenSSL.
    names: []const []const u8,
};

/// A prepared DANE handshake: the record set plus the identifier copies the
/// handshake needs. Owns one allocation, released by `deinit`.
pub const DaneState = struct {
    arena: std.heap.ArenaAllocator,
    set: dane.RecordSet,
    names: []const []const u8,
    policy: dane.Policy,

    pub fn deinit(self: *DaneState) void {
        self.arena.deinit();
    }

    /// Reference identifiers in the form the backend wants them.
    fn refs(self: *const DaneState) dane.ReferenceIds {
        return .{ .names = self.names };
    }

    /// Whether the usable records demand DANE or, with none surviving
    /// filtering, PKIX against the reference identifiers (module plan
    /// section 7). An empty set never means "skip verification".
    pub fn mode(self: *const DaneState) dane.Mode {
        return dane.set.mode(&self.set);
    }
};

/// Verification mode an RRset implies: `.pkix` when no record survives
/// filtering, so a caller can fall back to the system store instead of
/// treating an unusable-only RRset as a match or as a hard failure.
pub const DaneMode = dane.Mode;

/// Upper bound on records and identifiers per handshake, matching the
/// module's own limits so an oversized RRset is rejected, never truncated.
pub const dane_max_records = dane.max_records;

/// Build the DANE state for a handshake from raw TLSA records.
///
/// `records` may contain unusable entries: the module filters them and
/// applies digest agility. An RRset whose usable survivors exceed the
/// module's cap is `error.TooManyRecords`, never truncated. The caller
/// decides what an empty surviving set means; it reads `.pkix` from `mode`.
pub fn initDane(alloc: std.mem.Allocator, policy: DanePolicy, records: []const DaneRecord) DaneError!DaneState {
    if (policy.names.len == 0) return error.NoReferenceIds;
    if (policy.names.len > dane.max_names) return error.TooManyReferenceIds;

    var arena = std.heap.ArenaAllocator.init(alloc);
    errdefer arena.deinit();
    const a = arena.allocator();

    const names = a.alloc([]const u8, policy.names.len) catch return error.OutOfMemory;
    for (policy.names, 0..) |n, i| names[i] = a.dupe(u8, n) catch return error.OutOfMemory;

    const recs = a.alloc(dane.Record, records.len) catch return error.OutOfMemory;
    for (records, 0..) |r, i| {
        recs[i] = .{
            .usage = @enumFromInt(r.usage),
            .selector = @enumFromInt(r.selector),
            .matching_type = @enumFromInt(r.matching_type),
            .data = a.dupe(u8, r.data) catch return error.OutOfMemory,
        };
    }
    const set = dane.RecordSet.init(recs) catch return error.TooManyRecords;

    return .{
        .arena = arena,
        .set = set,
        .names = names,
        .policy = .{ .dane_ee_name_check = false },
    };
}

pub const DaneError = error{
    OutOfMemory,
    TooManyRecords,
    NoReferenceIds,
    TooManyReferenceIds,
};

/// Outcome of `SslConn.daneVerdict`: verified, or failed with a named
/// failure. Re-exported so callers need not import the module directly.
pub const DaneVerdict = dane.Verdict;
pub const Outcome = dane.Outcome;
pub const Failure = dane.Failure;
pub const Usage = dane.Usage;
pub const DanePrepared = dane_openssl.Prepared;

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

        // Enable FreeBSD KTLS — offloads symmetric crypto to kernel.
        // Silently ignored if kernel or OpenSSL lacks KTLS support.
        // SSL_OP_ENABLE_KTLS = SSL_OP_BIT(3) = 1 << 3 = 0x8
        _ = c.SSL_CTX_set_options(ctx, 0x8);

        return SslContext{ .ctx = ctx };
    }

    /// Initialize a client-side TLS context for outbound connections.
    ///
    /// Loads our certificate for presentation to the remote server (needed for
    /// SASL EXTERNAL authentication with DANE). PKIX verification of the remote
    /// peer is disabled because we use DANE verification ourselves.
    pub fn initClient() SslError!SslContext {
        return initClientWithCert(null, null);
    }

    /// Initialize a client-side TLS context with standard PKIX verification:
    /// the system CA trust store, chain validation, and per-connection
    /// hostname checking (SslConn.setHostname). This is the fallback path
    /// when no DANE TLSA records exist for the target.
    pub fn initClientVerified() SslError!SslContext {
        const method = c.TLS_client_method() orelse return SslError.SslInitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return SslError.SslInitFailed;
        errdefer c.SSL_CTX_free(ctx);

        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
        if (c.SSL_CTX_set_default_verify_paths(ctx) != 1) {
            return SslError.SslInitFailed;
        }
        return .{ .ctx = ctx };
    }

    /// Initialize a client-side TLS context that verifies through DANE.
    ///
    /// SSL_VERIFY_PEER makes the handshake fail unless a TLSA record matches,
    /// and the store is left empty so no traditional anchor can satisfy it
    /// (the TLSA match is the only possible anchor). No verify callback is
    /// installed: nothing may override the result. Kernel TLS is armed as in
    /// `initClient`; callers disable it when the peer may also offload.
    pub fn initClientDane() SslError!SslContext {
        return initClientDaneWithCert(null, null);
    }

    /// Initialize a client-side TLS context that verifies through DANE and
    /// presents our certificate (SASL EXTERNAL needs it).
    ///
    /// `SSL_VERIFY_PEER` makes the handshake fail unless a TLSA record
    /// matches, and the store is left empty so no traditional anchor can
    /// satisfy it. No verify callback is installed: nothing may override the
    /// result. Kernel TLS is armed as in `initClient`; callers disable it when
    /// the peer may also offload.
    pub fn initClientDaneWithCert(cert_path: ?[*:0]const u8, key_path: ?[*:0]const u8) SslError!SslContext {
        const method = c.TLS_client_method() orelse return SslError.SslInitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return SslError.SslInitFailed;
        errdefer c.SSL_CTX_free(ctx);

        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
        dane_openssl.enableContext(@ptrCast(ctx)) catch return SslError.SslInitFailed;

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

        _ = c.SSL_CTX_set_options(ctx, 0x8);
        return .{ .ctx = ctx };
    }

    /// Initialize a context used only to verify a peer chain after the
    /// handshake (`SslConn.verifyPeerDane`). It carries the DANE settings and
    /// an empty store; it is never used for a connection.
    pub fn initDaneVerifier() SslError!SslContext {
        const method = c.TLS_client_method() orelse return SslError.SslInitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return SslError.SslInitFailed;
        errdefer c.SSL_CTX_free(ctx);

        dane_openssl.enableContext(@ptrCast(ctx)) catch return SslError.SslInitFailed;
        return .{ .ctx = ctx };
    }

    /// Initialize a client-side TLS context with a certificate for mutual TLS.
    ///
    /// The cert/key are presented to the remote server so it can authenticate us
    /// (required for XMPP S2S SASL EXTERNAL after DANE verification).
    pub fn initClientWithCert(cert_path: ?[*:0]const u8, key_path: ?[*:0]const u8) SslError!SslContext {
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

        // Enable FreeBSD KTLS — offloads symmetric crypto to kernel.
        // Silently ignored if kernel or OpenSSL lacks KTLS support.
        // SSL_OP_ENABLE_KTLS = SSL_OP_BIT(3) = 1 << 3 = 0x8
        _ = c.SSL_CTX_set_options(ctx, 0x8);

        return SslContext{ .ctx = ctx };
    }

    /// Disarm kernel-TLS offload on this context (clears the
    /// SSL_OP_ENABLE_KTLS option the initializers above set).
    ///
    /// Client-side escape hatch for paths where the peer may also arm KTLS:
    /// two KTLS-armed endpoints desync across an interface without
    /// IFCAP_MEXTPG (lo0, epair, bridge) — FreeBSD PR 296498, EBADMSG /
    /// "bad record mac". Local rigs and same-host tooling cross exactly
    /// such interfaces, so they must run one end in userland TLS. Safe to
    /// call before any connection is created from this context.
    pub fn disableKtls(self: *SslContext) void {
        _ = c.SSL_CTX_clear_options(self.ctx, 0x8); // SSL_OP_ENABLE_KTLS
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
    /// The socket this connection is bound to (kept for callers that swap
    /// transports — e.g. lib/xmppc's Transport union — and need the fd back).
    sock_fd: std.posix.fd_t = -1,
    /// Client role (initClient): channel binding picks the PEER certificate
    /// for tls-server-end-point, not our own (T263).
    is_client: bool = false,

    pub fn sockFd(self: *const SslConn) std.posix.fd_t {
        return self.sock_fd;
    }

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

        return SslConn{ .ssl = ssl, .sock_fd = fd };
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

        return SslConn{ .ssl = ssl, .sock_fd = fd, .is_client = true };
    }

    /// Require the peer certificate to match `hostname` (PKIX path only;
    /// DANE mode authenticates via TLSA instead). Uses the connection's
    /// X509_VERIFY_PARAM — call after initClient, before the handshake.
    pub fn setHostname(self: *SslConn, hostname: [*:0]const u8) SslError!void {
        const param = c.SSL_get0_param(self.ssl) orelse return SslError.SslInitFailed;
        if (c.X509_VERIFY_PARAM_set1_host(param, hostname, 0) != 1) {
            return SslError.SslInitFailed;
        }
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
                // Log the OpenSSL error queue for diagnostics. warn, not
                // err: handshake failures are client-caused routine noise
                // (bad certs, port scans, aborted probes), not daemon
                // errors, and the caller reports the failure itself.
                var err_buf: [256]u8 = undefined;
                while (true) {
                    const e = c.ERR_get_error();
                    if (e == 0) break;
                    c.ERR_error_string_n(e, &err_buf, err_buf.len);
                    const log = std.log.scoped(.ssl);
                    log.warn("TLS handshake error: SSL_get_error={d} detail={s}", .{ err, @as([*:0]const u8, @ptrCast(&err_buf)) });
                }
                return SslError.HandshakeFailed;
            },
        };
    }

    /// Arm DANE on this connection before the handshake runs. Must be called
    /// after `initClient` and before the first `doHandshake`.
    ///
    /// Returns `.no_usable_records` when the module kept no record; OpenSSL
    /// then verifies against traditional trust anchors, so the caller applies
    /// its own fallback instead of reading a DANE result.
    pub fn prepareDane(self: *SslConn, state: *const DaneState) SslError!dane_openssl.Prepared {
        return dane_openssl.prepare(@ptrCast(self.ssl), &state.set, state.refs(), state.policy) catch
            return SslError.SslInitFailed;
    }

    /// Map the completed handshake's verification state to a verdict.
    /// `prepared` is what `prepareDane` returned.
    pub fn daneVerdict(self: *SslConn, prepared: dane_openssl.Prepared, state: *const DaneState) dane.Verdict {
        return dane_openssl.verdict(@ptrCast(self.ssl), prepared, &state.set, state.policy);
    }

    /// Verify this connection's peer chain against DANE records after the
    /// handshake (inbound S2S: the peer domain arrives after TLS, so the
    /// handshake could not be armed). `verify_ctx` must be a dedicated
    /// context from `initDaneVerifier`; it carries the DANE settings and an
    /// empty store, so nothing but a TLSA record can anchor the chain.
    pub fn verifyPeerDane(self: *SslConn, verify_ctx: *const SslContext, state: *const DaneState) dane.Verdict {
        return dane_openssl.verifyPeer(@ptrCast(self.ssl), @ptrCast(verify_ctx.ctx), &state.set, state.refs(), state.policy);
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

    /// Returns the number of bytes available for immediate read from the
    /// SSL internal buffer (already decrypted, not yet returned to the app).
    /// A non-zero value means `read()` can return data without a syscall.
    pub fn pending(self: *SslConn) usize {
        const ret = c.SSL_pending(self.ssl);
        return if (ret > 0) @intCast(ret) else 0;
    }

    /// Whether kernel-TLS offload engaged for the send direction. Mirrors
    /// BIO_get_ktls_send: queried on the write BIO. Fallback to userland
    /// crypto is silent, so this is the only way to confirm offload.
    pub fn ktlsSend(self: *SslConn) bool {
        // BIO_CTRL_GET_KTLS_SEND = 73.
        const wbio = c.SSL_get_wbio(self.ssl) orelse return false;
        return c.BIO_ctrl(wbio, 73, 0, null) > 0;
    }

    /// Whether kernel-TLS offload engaged for the receive direction. Mirrors
    /// BIO_get_ktls_recv: queried on the read BIO.
    pub fn ktlsRecv(self: *SslConn) bool {
        // BIO_CTRL_GET_KTLS_RECV = 76.
        const rbio = c.SSL_get_rbio(self.ssl) orelse return false;
        return c.BIO_ctrl(rbio, 76, 0, null) > 0;
    }

    /// Negotiated protocol version and cipher names (e.g. "TLSv1.3",
    /// "TLS_AES_256_GCM_SHA384"). Empty when unset (pre-handshake).
    pub fn versionName(self: *SslConn) []const u8 {
        const v = c.SSL_get_version(self.ssl) orelse return "";
        return std.mem.span(v);
    }

    pub fn cipherName(self: *SslConn) []const u8 {
        const cipher = c.SSL_get_current_cipher(self.ssl) orelse return "";
        const name = c.SSL_CIPHER_get_name(cipher) orelse return "";
        return std.mem.span(name);
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
            // tls-server-end-point (RFC 5929): SHA-256 hash of the SERVER
            // certificate: our local cert when we are the server (TLS
            // accept), the PEER's cert when we are the client (T263).
            const x509 = (if (self.is_client) c.SSL_get0_peer_certificate(self.ssl) else c.SSL_get_certificate(self.ssl)) orelse return null;
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

test "SslContext: initServer fails with bad cert path" {
    const result = SslContext.initServer("/nonexistent/cert.pem", "/nonexistent/key.pem");
    try std.testing.expectError(SslError.CertLoadFailed, result);
}

test "SslContext: initClient succeeds without cert/key" {
    var ctx = try SslContext.initClient();
    defer ctx.deinit();
    // Client context created successfully — no cert/key needed
}

test "SslContext: disableKtls is accepted on a fresh context" {
    var ctx = try SslContext.initClient();
    defer ctx.deinit();
    // Clearing the option the initializer set must not disturb the context.
    ctx.disableKtls();
    ctx.disableKtls(); // idempotent
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
