//! Conn: per-connection I/O on the F2 loop substrate (ADR-8, F3).
//!
//! `Transport` is the byte mover: plain fd or TLS over a socket BIO. All
//! TLS traffic goes through `SSL_read`/`SSL_write` (kTLS D2); the retry
//! after `want_*` presents the identical (ptr, len) the Outbox pin keeps
//! stable (kTLS D3); there is no `SSL_key_update` path (kTLS D9); and
//! kTLS engagement is proven once per handshake through
//! `BIO_get_ktls_send`/`BIO_get_ktls_recv` and recorded as a token.
//! See F3-DESIGN.md for the full contract.

const std = @import("std");
const posix = std.posix;
const ssl = @import("ssl");
const loop_mod = @import("loop.zig");
const Token = @import("token.zig").Token;

pub const Loop = loop_mod.Loop;
pub const Handle = loop_mod.Handle;
pub const Interest = loop_mod.Interest;
pub const Event = loop_mod.Event;
pub const SslError = ssl.SslError;

/// Every error a transport read or write can surface: TLS-layer failures
/// plus the errno-mapped socket errors.
pub const IoError = ssl.SslError || posix.ReadError || posix.WriteError;

pub const KtlsPolicy = enum {
    /// Never refuse a conn for missing offload; record the `sw` token.
    prefer,
    /// Opt-in per listener: fail the conn when either direction did not
    /// offload.
    require,
};

/// The one token recorded per TLS conn (plus a debug log line):
/// which directions kernel-TLS engaged.
pub const KtlsToken = enum { ktls, ktls_tx, ktls_rx, sw };

/// Per-worker counter block the consumer owns (M1 pattern): the record
/// for silent kTLS fallback and fail-closed drops. One pointer in
/// `Options`; nothing here allocates or locks.
pub const Counters = struct {
    ktls: u64 = 0,
    ktls_tx: u64 = 0,
    ktls_rx: u64 = 0,
    sw: u64 = 0,
    outbox_failed_closed: u64 = 0,

    pub fn countKtls(c: *Counters, token: KtlsToken) void {
        switch (token) {
            .ktls => c.ktls += 1,
            .ktls_tx => c.ktls_tx += 1,
            .ktls_rx => c.ktls_rx += 1,
            .sw => c.sw += 1,
        }
    }
};

/// Result of a non-blocking transport read or write.
pub const IoResult = union(enum) {
    /// Bytes moved.
    n: usize,
    /// Drive me on EVFILT_READ.
    want_read,
    /// Drive me on EVFILT_WRITE (SSL_read can want this).
    want_write,
    /// Orderly peer shutdown (read returned 0, or TLS close_notify).
    eof,
    /// Socket or TLS failure; the conn is finished.
    err: IoError,
};

pub const Tls = struct {
    /// `SSL_set_fd` at init; the fd is already non-blocking.
    conn: ssl.SslConn,
    /// Read once after the handshake completes.
    ktls_tx: bool = false,
    ktls_rx: bool = false,
    policy: KtlsPolicy = .prefer,

    /// The token this conn counts once at `finishHandshake`.
    pub fn ktlsToken(t: *const Tls) KtlsToken {
        if (t.ktls_tx and t.ktls_rx) return .ktls;
        if (t.ktls_tx) return .ktls_tx;
        if (t.ktls_rx) return .ktls_rx;
        return .sw;
    }
};

/// Plain fd or TLS, one write path each so the pin story stays single.
/// `tls` points into the owning `Conn`.
pub const Transport = union(enum) {
    plain: posix.fd_t,
    tls: *Tls,

    /// TLS RX is always `SSL_read`; there is no `read()` path on a TLS
    /// conn, so post-handshake records cannot leak as payload (kTLS D2).
    pub fn read(t: *Transport, buf: []u8) IoResult {
        switch (t.*) {
            .plain => |fd| {
                const n = posix.read(fd, buf) catch |err| return switch (err) {
                    error.WouldBlock => .want_read,
                    else => .{ .err = err },
                };
                if (n == 0) return .eof;
                return .{ .n = n };
            },
            .tls => |tls| {
                const r = tls.conn.read(buf) catch |err| return switch (err) {
                    error.ConnectionClosed => .eof,
                    else => .{ .err = err },
                };
                return switch (r) {
                    .ok => |n| .{ .n = n },
                    .want_read => .want_read,
                    .want_write => .want_write,
                };
            },
        }
    }

    /// TLS TX is always `SSL_write` (`SSL_MODE_ENABLE_PARTIAL_WRITE` is
    /// set at ctx setup by the caller; moving-buffer mode is never relied
    /// on). After `want_*` the retry presents the identical (ptr, len);
    /// the Outbox pin is what keeps the slice stable (kTLS D3).
    pub fn write(t: *Transport, buf: []const u8) IoResult {
        switch (t.*) {
            .plain => |fd| {
                const n = posix.write(fd, buf) catch |err| return switch (err) {
                    error.WouldBlock => .want_write,
                    else => .{ .err = err },
                };
                return .{ .n = n };
            },
            .tls => |tls| {
                const r = tls.conn.write(buf) catch |err| return .{ .err = err };
                return switch (r) {
                    .ok => |n| .{ .n = n },
                    .want_read => .want_read,
                    .want_write => .want_write,
                };
            },
        }
    }

    /// Decrypted bytes held inside OpenSSL (`SSL_pending`); always 0 on
    /// the plain transport.
    pub fn pending(t: *const Transport) usize {
        return switch (t.*) {
            .plain => 0,
            .tls => |tls| tls.conn.pending(),
        };
    }

    /// `SSL_shutdown` once, non-blocking, never waited on (kTLS D6).
    /// No-op on the plain transport.
    pub fn shutdown(t: *Transport) void {
        switch (t.*) {
            .plain => {},
            .tls => |tls| tls.conn.shutdown(),
        }
    }
};

const o_nonblock: c_int = 0x4; // O_NONBLOCK
const so_nosigpipe: c_int = 0x0800; // SO_NOSIGPIPE (FreeBSD)

fn setNonBlocking(fd: posix.fd_t) !void {
    const fl = std.c.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
    if (fl < 0) return error.Unexpected;
    if (fl & o_nonblock == 0) {
        if (std.c.fcntl(fd, posix.F.SETFL, fl | o_nonblock) != 0) return error.Unexpected;
    }
}

fn setNoSigpipe(fd: posix.fd_t) !void {
    const one: c_int = 1;
    try posix.setsockopt(fd, posix.SOL.SOCKET, so_nosigpipe, std.mem.asBytes(&one));
}

fn socketpair() ![2]posix.fd_t {
    var pair: [2]std.c.fd_t = undefined;
    const flags = posix.SOCK.STREAM | posix.SOCK.CLOEXEC;
    if (std.c.socketpair(posix.AF.UNIX, flags, 0, &pair) != 0) return error.Unexpected;
    try setNonBlocking(pair[0]);
    try setNonBlocking(pair[1]);
    try setNoSigpipe(pair[0]);
    try setNoSigpipe(pair[1]);
    return pair;
}

// ---------------------------------------------------------------------------
// Test PKI: a throwaway self-signed cert (CN=localhost) generated in memory
// per test through libcrypto and written to a tmp dir. Nothing key-shaped
// lives in the source tree.
// ---------------------------------------------------------------------------

const tc = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/objects.h");
});

fn bioDrain(bio: *tc.BIO, buf: []u8) ![]u8 {
    const n = tc.BIO_read(bio, buf.ptr, @intCast(buf.len));
    if (n <= 0) return error.SslInitFailed;
    return buf[0..@intCast(n)];
}

const TestPki = struct {
    tmp: std.testing.TmpDir,
    ctx: ssl.SslContext,

    fn deinit(pki: *TestPki) void {
        pki.ctx.deinit();
        pki.tmp.cleanup();
    }
};

fn makeTestPki(alloc: std.mem.Allocator) !TestPki {
    const kctx = tc.EVP_PKEY_CTX_new_id(tc.EVP_PKEY_RSA, null) orelse return error.SslInitFailed;
    defer tc.EVP_PKEY_CTX_free(kctx);
    if (tc.EVP_PKEY_keygen_init(kctx) != 1) return error.SslInitFailed;
    var pkey: ?*tc.EVP_PKEY = null;
    if (tc.EVP_PKEY_keygen(kctx, &pkey) != 1) return error.SslInitFailed;
    defer tc.EVP_PKEY_free(pkey);

    const x509 = tc.X509_new() orelse return error.SslInitFailed;
    defer tc.X509_free(x509);
    _ = tc.X509_set_version(x509, 2);
    _ = tc.ASN1_INTEGER_set(tc.X509_get_serialNumber(x509), 1);
    _ = tc.X509_gmtime_adj(tc.X509_getm_notBefore(x509), -60);
    _ = tc.X509_gmtime_adj(tc.X509_getm_notAfter(x509), 60 * 60 * 24 * 365);
    _ = tc.X509_set_pubkey(x509, pkey);
    const name = tc.X509_get_subject_name(x509) orelse return error.SslInitFailed;
    _ = tc.X509_NAME_add_entry_by_txt(name, "CN", tc.MBSTRING_ASC, "localhost", -1, -1, 0);
    _ = tc.X509_set_issuer_name(x509, name);
    if (tc.X509_sign(x509, pkey, tc.EVP_sha256()) == 0) return error.SslInitFailed;

    var pem_buf: [16384]u8 = undefined;
    var tmp = std.testing.tmpDir(.{});
    errdefer tmp.cleanup();
    {
        const bio = tc.BIO_new(tc.BIO_s_mem()) orelse return error.SslInitFailed;
        defer _ = tc.BIO_free(bio);
        if (tc.PEM_write_bio_X509(bio, x509) != 1) return error.SslInitFailed;
        const f = try tmp.dir.createFile("cert.pem", .{});
        defer f.close();
        try f.writeAll(try bioDrain(bio, &pem_buf));
    }
    {
        const bio = tc.BIO_new(tc.BIO_s_mem()) orelse return error.SslInitFailed;
        defer _ = tc.BIO_free(bio);
        if (tc.PEM_write_bio_PrivateKey(bio, pkey, null, null, 0, null, null) != 1) return error.SslInitFailed;
        const f = try tmp.dir.createFile("key.pem", .{});
        defer f.close();
        try f.writeAll(try bioDrain(bio, &pem_buf));
    }
    const cert_pre = try tmp.dir.realpathAlloc(alloc, "cert.pem");
    defer alloc.free(cert_pre);
    const key_pre = try tmp.dir.realpathAlloc(alloc, "key.pem");
    defer alloc.free(key_pre);
    const cert_path = try alloc.dupeZ(u8, cert_pre);
    defer alloc.free(cert_path);
    const key_path = try alloc.dupeZ(u8, key_pre);
    defer alloc.free(key_path);
    return .{ .tmp = tmp, .ctx = try ssl.SslContext.initServer(cert_path, key_path) };
}

/// Drive two non-blocking SslConns' handshakes alternately until both
/// complete. Bounded so a stuck peer cannot hang the suite.
fn driveHandshake(a: *ssl.SslConn, b: *ssl.SslConn) !void {
    var ra: ssl.HandshakeResult = .want_read;
    var rb: ssl.HandshakeResult = .want_read;
    for (0..10_000) |_| {
        if (ra == .complete and rb == .complete) return;
        if (ra != .complete) ra = try a.doHandshake();
        if (rb != .complete) rb = try b.doHandshake();
    }
    return error.HandshakeStuck;
}

test "Transport plain: read, write, eof, and error after close" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var t: Transport = .{ .plain = pair[0] };
    var buf: [64]u8 = undefined;

    // Nothing pending: want_read, not eof or err.
    try std.testing.expectEqual(IoResult.want_read, t.read(&buf));

    const msg = "transport bytes";
    _ = try posix.write(pair[1], msg);
    switch (t.read(&buf)) {
        .n => |n| try std.testing.expectEqualStrings(msg, buf[0..n]),
        else => return error.TestUnexpectedResult,
    }

    switch (t.write("reply")) {
        .n => |n| try std.testing.expectEqual(@as(usize, 5), n),
        else => return error.TestUnexpectedResult,
    }

    posix.shutdown(pair[1], .both) catch {};
    try std.testing.expectEqual(IoResult.eof, t.read(&buf));
}

test "Transport plain: a full send buffer reports want_write" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    // FreeBSD clamps SO_SNDBUF; write enough to outrun any clamp.
    const one_k: c_int = 1024;
    try posix.setsockopt(pair[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&one_k));

    var t: Transport = .{ .plain = pair[0] };
    const bulk = [_]u8{0xab} ** (1 << 20);
    var saw_want = false;
    for (0..1000) |_| {
        switch (t.write(&bulk)) {
            .n => {},
            .want_write => {
                saw_want = true;
                break;
            },
            else => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(saw_want);
}

test "Transport plain: write to a dead peer is an error, not a panic" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    posix.close(pair[1]);

    var t: Transport = .{ .plain = pair[0] };
    switch (t.write("dead")) {
        .err => {},
        else => return error.TestUnexpectedResult,
    }
}

test "Transport tls: handshake, echo, pending, eof" {
    const alloc = std.testing.allocator;
    var pki = try makeTestPki(alloc);
    defer pki.deinit();

    // One userland end (PR 296498): the client context disarms kTLS.
    var client_ctx = try ssl.SslContext.initClient();
    defer client_ctx.deinit();
    client_ctx.disableKtls();

    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var tls: Tls = .{ .conn = try ssl.SslConn.init(pki.ctx, pair[0]), .policy = .prefer };
    defer tls.conn.deinit();
    var client = try ssl.SslConn.initClient(client_ctx, pair[1], null);
    defer client.deinit();
    try driveHandshake(&tls.conn, &client);

    var t: Transport = .{ .tls = &tls };

    var buf: [64]u8 = undefined;
    _ = try client.write("ping");
    switch (t.read(&buf)) {
        .n => |n| try std.testing.expectEqualStrings("ping", buf[0..n]),
        else => return error.TestUnexpectedResult,
    }
    // Read a slice smaller than the record: the rest stays in SSL_pending.
    _ = try client.write("buffered");
    switch (t.read(buf[0..3])) {
        .n => |n| try std.testing.expectEqual(@as(usize, 3), n),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 5), t.pending());
    _ = t.read(&buf);

    switch (t.write("pong")) {
        .n => |n| try std.testing.expectEqual(@as(usize, 4), n),
        else => return error.TestUnexpectedResult,
    }

    // Unix sockets cannot offload: the token is sw under prefer.
    try std.testing.expectEqual(KtlsToken.sw, tls.ktlsToken());

    client.shutdown();
    try std.testing.expectEqual(IoResult.eof, t.read(&buf));
}
