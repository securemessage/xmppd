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

/// Per-pass inbound fairness budget (Options.read_budget_*): bytes or
/// read calls, whichever is spent first, so one fast sender cannot hold
/// a pass that serves thousands of connections.
pub const ReadBudget = struct {
    bytes: usize = 64 << 10,
    reads: u32 = 16,
};

/// What a drain pass ended on.
pub const DrainResult = union(enum) {
    /// EAGAIN: the socket is dry and EV_CLEAR will report new data.
    drained,
    /// Budget spent, inbox full, or TLS wanted a write: re-drive the
    /// conn before the loop sleeps (ConnList + Loop.requeue).
    budget_left,
    /// The TLS read needed a write event first.
    want_write,
    /// Orderly peer shutdown; `eof` latches on the inbox.
    eof,
    /// Socket or TLS failure; the conn is finished.
    err: IoError,
};

/// Reads plaintext or decrypted bytes into a caller-owned slice.
///
/// `consumed` is the deferred-compaction cursor: bytes below it were
/// parsed already; `drain` folds them away once per call, never per
/// message, so parsed spans stay valid until the next drain.
pub const Inbox = struct {
    /// Owned slice, allocated once at Conn.init (Options.inbox_bytes).
    buf: []u8,
    len: usize = 0,
    consumed: usize = 0,
    eof: bool = false,

    pub fn init(buf: []u8) Inbox {
        return .{ .buf = buf };
    }

    /// Bytes available to parse. Borrows `buf` and stays valid until the
    /// next `drain`/`compact`.
    pub fn unread(in: *const Inbox) []const u8 {
        return in.buf[in.consumed..in.len];
    }

    /// Mark `n` parsed bytes consumed; compaction is deferred to drain.
    pub fn consume(in: *Inbox, n: usize) void {
        std.debug.assert(in.consumed + n <= in.len);
        in.consumed += n;
    }

    /// Move unconsumed bytes to the front and clear the cursor.
    pub fn compact(in: *Inbox) void {
        if (in.consumed == 0) return;
        const remaining = in.len - in.consumed;
        if (remaining > 0) {
            std.mem.copyForwards(u8, in.buf[0..remaining], in.buf[in.consumed..in.len]);
        }
        in.len = remaining;
        in.consumed = 0;
    }

    /// Read until EAGAIN, the budget is spent, the inbox fills, or EOF.
    /// A `budget_left` result means more data may be pending, or the
    /// inbox holds bytes the consumer has not consumed yet, and the conn
    /// must be re-driven before the loop sleeps: EV_CLEAR is
    /// transition-armed, so leftover data raises no new event.
    pub fn drain(in: *Inbox, t: *Transport, budget: *ReadBudget) DrainResult {
        if (in.eof) return .eof;
        in.compact();
        while (true) {
            if (budget.reads == 0 or budget.bytes == 0) return .budget_left;
            const space = in.buf.len - in.len;
            if (space == 0) return .budget_left;
            budget.reads -= 1;
            const want = @min(space, budget.bytes);
            switch (t.read(in.buf[in.len .. in.len + want])) {
                .n => |n| {
                    in.len += n;
                    budget.bytes -= n;
                },
                .want_read => return .drained,
                .want_write => return .want_write,
                .eof => {
                    in.eof = true;
                    return .eof;
                },
                .err => |e| return .{ .err = e },
            }
        }
    }
};

/// What an append did with the bytes.
pub const AppendResult = enum {
    /// All parts fit in the ring.
    queued,
    /// Ring was full; parts went to the bounded spill.
    spilled,
    /// Past max_outbound_bytes: fail closed, nothing dropped silently.
    failed_closed,
};

/// What a flush pass ended on.
pub const FlushResult = union(enum) {
    /// Ring and spill are both empty.
    drained,
    /// TLS write needs a read event (post-handshake traffic); arm read.
    want_read,
    /// Kernel send buffer full or TLS wants a write; arm write.
    want_write,
    /// The per-pass flush budget was spent; re-drive via ConnList.
    budget_left,
    /// Socket or TLS failure; the conn is finished.
    err: IoError,
};

/// The retained (ptr, len) of an in-flight write that returned want_*.
/// Formed only from `ring`, never from `spill`: the ring is one heap
/// slice allocated at Conn.init and its addresses cannot move, so a
/// spill realloc can never invalidate the pin (kTLS D3).
const Pin = struct { ptr: [*]const u8, len: usize };

/// Queues outbound bytes: a fixed ring first, a bounded spill behind
/// it. The pin holds the head run across a want_* retry so the TLS
/// retry presents an identical (ptr, len); new bytes sit behind it
/// and are never part of the retry (S23's rule).
pub const Outbox = struct {
    /// Owned slice, allocated once at Conn.init (Options.outbox_ring_bytes).
    ring: []u8,
    /// Index of the first unsent byte.
    head: usize = 0,
    /// Unsent bytes in the ring.
    used: usize = 0,
    /// Backlog behind the ring: [spill_head, items.len) unsent.
    /// `.empty` until first use, so idle conns pay nothing.
    spill: std.ArrayList(u8) = .empty,
    spill_head: usize = 0,
    /// Options.max_outbound_bytes: the spill bound (fail closed past it).
    spill_limit: usize,
    /// Spill capacity kept once the outbox drains empty (default 64 KiB).
    spill_high_water: usize = 64 << 10,
    pin: ?Pin = null,
    counters: *Counters,
    alloc: std.mem.Allocator,

    pub fn init(ring: []u8, alloc: std.mem.Allocator, spill_limit: usize, counters: *Counters) Outbox {
        return .{ .ring = ring, .spill_limit = spill_limit, .counters = counters, .alloc = alloc };
    }

    pub fn deinit(o: *Outbox) void {
        o.spill.deinit(o.alloc);
    }

    /// Total unsent bytes (ring plus pending spill).
    pub fn bytes(o: *const Outbox) usize {
        return o.used + o.spill.items.len - o.spill_head;
    }

    pub fn empty(o: *const Outbox) bool {
        return o.bytes() == 0;
    }

    fn ringFree(o: *const Outbox) usize {
        return o.ring.len - o.used;
    }

    fn ringTail(o: *const Outbox) usize {
        return (o.head + o.used) % o.ring.len;
    }

    /// Gather append: parts are copied once, whole-append into the ring
    /// when it all fits (keeps frames contiguous), otherwise all of it
    /// into the bounded spill. Over `spill_limit` the result is
    /// `failed_closed` and the counter moves; nothing is dropped
    /// silently.
    pub fn append(o: *Outbox, parts: []const []const u8) AppendResult {
        var total: usize = 0;
        for (parts) |p| total += p.len;
        if (total == 0) return .queued;

        if (total <= o.ringFree()) {
            for (parts) |p| o.ringWrite(p);
            return .queued;
        }

        const pending = o.spill.items.len - o.spill_head;
        if (pending + total > o.spill_limit) {
            o.counters.outbox_failed_closed += 1;
            return .failed_closed;
        }
        for (parts) |p| {
            o.spill.appendSlice(o.alloc, p) catch {
                o.counters.outbox_failed_closed += 1;
                return .failed_closed;
            };
        }
        return .spilled;
    }

    /// Copy `data` into the ring's free space (wrapping); caller checked
    /// it fits.
    fn ringWrite(o: *Outbox, data: []const u8) void {
        const cap = o.ring.len;
        var pos = o.ringTail();
        var rest = data;
        while (rest.len > 0) {
            const run = @min(rest.len, cap - pos);
            @memcpy(o.ring[pos .. pos + run], rest[0..run]);
            pos = (pos + run) % cap;
            rest = rest[run..];
        }
        o.used += data.len;
    }

    /// Move spill into the empty ring (bounded copy); the pin is only
    /// ever formed from ring memory, so spill bytes must pass through
    /// the ring before they can be written.
    fn reloadRing(o: *Outbox) void {
        std.debug.assert(o.used == 0);
        const pending = o.spill.items.len - o.spill_head;
        if (pending == 0) return;
        const n = @min(pending, o.ring.len);
        @memcpy(o.ring[0..n], o.spill.items[o.spill_head .. o.spill_head + n]);
        o.head = 0;
        o.used = n;
        o.spill_head += n;
        if (o.spill_head == o.spill.items.len) {
            o.spill.clearRetainingCapacity();
            o.spill_head = 0;
        }
    }

    /// Once the outbox drains empty, release spill capacity above the
    /// high-water mark: one burst must not pin memory for the session.
    fn releaseSpill(o: *Outbox) void {
        if (o.spill.capacity <= o.spill_high_water) return;
        if (o.alloc.resize(o.spill.allocatedSlice(), o.spill_high_water)) {
            o.spill.capacity = o.spill_high_water;
            return;
        }
        o.spill.shrinkAndFree(o.alloc, 0);
        // Best-effort retention of the high-water arena; an alloc
        // failure is not fatal, the spill just re-grows next burst.
        o.spill.ensureTotalCapacityPrecise(o.alloc, o.spill_high_water) catch {};
    }

    /// Write out until empty, want_*, or the per-call byte budget is
    /// spent. A pending pin is retried verbatim before any new slice is
    /// formed; the retry never grows (S23).
    pub fn flush(o: *Outbox, t: *Transport, budget: usize) FlushResult {
        var left = budget;
        while (true) {
            if (o.pin == null) {
                if (o.used == 0) {
                    o.reloadRing();
                    if (o.used == 0) {
                        o.releaseSpill();
                        return .drained;
                    }
                }
                const run = @min(o.used, o.ring.len - o.head);
                const want = @min(run, left);
                if (want == 0) return .budget_left;
                o.pin = .{ .ptr = @ptrCast(o.ring.ptr + o.head), .len = want };
            }
            if (left == 0) return .budget_left;
            const p = o.pin.?;
            switch (t.write(p.ptr[0..p.len])) {
                .n => |n| {
                    if (n == 0) return .want_write;
                    o.head = (o.head + n) % o.ring.len;
                    o.used -= n;
                    o.pin = null;
                    left -= n;
                },
                .want_write => return .want_write,
                .want_read => return .want_read,
                .eof => return .{ .err = error.WriteFailed },
                .err => |e| return .{ .err = e },
            }
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

test "Inbox: drain to EAGAIN, unread stability, consume, compact" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var t: Transport = .{ .plain = pair[0] };
    var buf: [64]u8 = undefined;
    var in = Inbox.init(&buf);
    var budget: ReadBudget = .{};

    _ = try posix.write(pair[1], "first");
    try std.testing.expectEqual(DrainResult.drained, in.drain(&t, &budget));
    try std.testing.expectEqualStrings("first", in.unread());

    // Parsed spans stay valid until the next drain: consume defers.
    in.consume(3);
    try std.testing.expectEqualStrings("st", in.unread());

    _ = try posix.write(pair[1], "second");
    try std.testing.expectEqual(DrainResult.drained, in.drain(&t, &budget));
    // Compaction ran once per drain: "st" moved to the front.
    try std.testing.expectEqualStrings("stsecond", in.unread());

    // A chunk larger than the pre-compaction free space only fits
    // because drain folded the consumed prefix away first.
    in.consume(8);
    const tail = [_]u8{0x30} ** 56;
    _ = try posix.write(pair[1], &tail);
    try std.testing.expectEqual(DrainResult.drained, in.drain(&t, &budget));
    try std.testing.expectEqualStrings(&tail, in.unread());
}

test "Inbox: a spent read budget stops the drain" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var t: Transport = .{ .plain = pair[0] };
    var buf: [32]u8 = undefined;
    var in = Inbox.init(&buf);

    // One read allowed: even with more data pending the drain stops.
    var budget: ReadBudget = .{ .bytes = 64 << 10, .reads = 1 };
    _ = try posix.write(pair[1], "0123456789abcdef");
    try std.testing.expectEqual(DrainResult.budget_left, in.drain(&t, &budget));
    try std.testing.expectEqual(@as(u32, 0), budget.reads);

    in.consume(in.len);
    budget.reads = 8;
    try std.testing.expectEqual(DrainResult.drained, in.drain(&t, &budget));
}

test "Inbox: a full inbox stops the drain until consume" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var t: Transport = .{ .plain = pair[0] };
    var buf: [16]u8 = undefined;
    var in = Inbox.init(&buf);
    var budget: ReadBudget = .{};

    // Consumer left the inbox full: the drain cannot make progress.
    in.len = in.buf.len;
    try std.testing.expectEqual(DrainResult.budget_left, in.drain(&t, &budget));
    in.consume(in.len);
    try std.testing.expectEqualStrings("", in.unread());
    try std.testing.expectEqual(DrainResult.drained, in.drain(&t, &budget));
}

test "Inbox: byte budget is spent by bytes moved, not calls" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var t: Transport = .{ .plain = pair[0] };
    var buf: [64]u8 = undefined;
    var in = Inbox.init(&buf);
    var budget: ReadBudget = .{ .bytes = 5, .reads = 16 };

    _ = try posix.write(pair[1], "0123456789");
    try std.testing.expectEqual(DrainResult.budget_left, in.drain(&t, &budget));
    try std.testing.expectEqual(@as(usize, 5), in.len);
}

test "Inbox: eof is distinct and latches" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var t: Transport = .{ .plain = pair[0] };
    var buf: [16]u8 = undefined;
    var in = Inbox.init(&buf);
    var budget: ReadBudget = .{};

    posix.shutdown(pair[1], .both) catch {};
    try std.testing.expectEqual(DrainResult.eof, in.drain(&t, &budget));
    try std.testing.expectEqual(DrainResult.eof, in.drain(&t, &budget));
}

/// Read until `buf` is full, the peer stops sending, or a bounded spin
/// runs out (a hung producer must fail the suite, not stall it).
fn readAll(fd: posix.fd_t, buf: []u8) !usize {
    var got: usize = 0;
    var spins: usize = 0;
    while (got < buf.len and spins < 100_000) {
        const n = posix.read(fd, buf[got..]) catch |err| switch (err) {
            error.WouldBlock => {
                spins += 1;
                continue;
            },
            else => return err,
        };
        if (n == 0) break;
        got += n;
    }
    return got;
}

test "Outbox: gather order, bytes accounting, drain" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var ring: [64]u8 = undefined;
    var o = Outbox.init(&ring, std.testing.allocator, 1 << 20, &counters);
    defer o.deinit();

    const parts = [_][]const u8{ "he", "llo", " ", "world" };
    try std.testing.expectEqual(AppendResult.queued, o.append(&parts));
    try std.testing.expectEqual(@as(usize, 11), o.bytes());
    try std.testing.expect(!o.empty());

    var t: Transport = .{ .plain = pair[0] };
    try std.testing.expectEqual(FlushResult.drained, o.flush(&t, 1 << 20));
    try std.testing.expect(o.empty());

    var buf: [64]u8 = undefined;
    const n = try readAll(pair[1], buf[0..11]);
    try std.testing.expectEqualStrings("hello world", buf[0..n]);
}

test "Outbox: ring wrap keeps order" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var ring: [16]u8 = undefined;
    var o = Outbox.init(&ring, std.testing.allocator, 1 << 20, &counters);
    defer o.deinit();
    var t: Transport = .{ .plain = pair[0] };

    const first = [_][]const u8{"0123456789"};
    try std.testing.expectEqual(AppendResult.queued, o.append(&first));
    _ = o.flush(&t, 1 << 20);
    _ = try readAll(pair[1], &ring); // peer drains (reuse ring as scratch)

    // Head now sits mid-ring; a 10-byte append wraps around the end.
    const second = [_][]const u8{"abcdefghij"};
    try std.testing.expectEqual(AppendResult.queued, o.append(&second));
    _ = o.flush(&t, 1 << 20);
    var buf: [16]u8 = undefined;
    const n = try readAll(pair[1], buf[0..10]);
    try std.testing.expectEqualStrings("abcdefghij", buf[0..n]);
}

test "Outbox: spill bound fails closed and counts" {
    var counters: Counters = .{};
    var ring: [8]u8 = undefined;
    var o = Outbox.init(&ring, std.testing.allocator, 64, &counters);
    defer o.deinit();

    const big_data = [_]u8{0x41} ** 100;
    const big = [_][]const u8{&big_data};
    try std.testing.expectEqual(AppendResult.failed_closed, o.append(&big));
    try std.testing.expectEqual(@as(u64, 1), counters.outbox_failed_closed);
    try std.testing.expectEqual(@as(usize, 0), o.bytes());
}

test "Outbox: spill reloads through the ring, high-water frees capacity" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var ring: [16]u8 = undefined;
    var o = Outbox.init(&ring, std.testing.allocator, 1 << 20, &counters);
    defer o.deinit();
    o.spill_high_water = 32;
    var t: Transport = .{ .plain = pair[0] };

    // 48 bytes with a 16-byte ring: all of it spills (whole-append
    // rule), then reloads through the ring in order.
    var data: [48]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i);
    const parts = [_][]const u8{&data};
    try std.testing.expectEqual(AppendResult.spilled, o.append(&parts));
    try std.testing.expectEqual(@as(usize, 48), o.bytes());
    const cap_after_spill = o.spill.capacity;
    try std.testing.expect(cap_after_spill > o.spill_high_water);

    try std.testing.expectEqual(FlushResult.drained, o.flush(&t, 1 << 20));
    // Drained: the reload passed spill bytes through the ring in order,
    // and capacity above the high-water mark was released.
    try std.testing.expectEqual(@as(usize, 0), o.bytes());
    try std.testing.expect(o.spill.capacity <= o.spill_high_water);
    var buf: [48]u8 = undefined;
    const n = try readAll(pair[1], &buf);
    try std.testing.expectEqual(@as(usize, 48), n);
    try std.testing.expectEqualSlices(u8, &data, buf[0..n]);
}

test "Outbox: pin retries the identical slice across want_write" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);
    const one_k: c_int = 1024;
    try posix.setsockopt(pair[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&one_k));

    var counters: Counters = .{};
    var ring: [128]u8 = undefined;
    var o = Outbox.init(&ring, std.testing.allocator, 1 << 20, &counters);
    defer o.deinit();
    var t: Transport = .{ .plain = pair[0] };

    // Fill the kernel buffer directly so flushes stall: FreeBSD clamps
    // SO_SNDBUF, so keep writing until the fd itself says EAGAIN.
    const big = [_]u8{0x77} ** (1 << 20);
    var sent: usize = 0;
    while (sent < big.len) {
        sent += posix.write(pair[0], big[sent..]) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
    }

    // An append that stalls mid-way leaves a pin; a second stalled
    // flush must present the identical (ptr, len).
    const a = [_][]const u8{"0123456789abcdef"};
    _ = o.append(&a);
    try std.testing.expectEqual(FlushResult.want_write, o.flush(&t, 1 << 20));
    const pin_ptr = o.pin.?.ptr;
    const pin_len = o.pin.?.len;
    try std.testing.expectEqual(FlushResult.want_write, o.flush(&t, 1 << 20));
    try std.testing.expectEqual(pin_ptr, o.pin.?.ptr);
    try std.testing.expectEqual(pin_len, o.pin.?.len);

    // Bytes appended behind a pending pin are never part of its retry.
    const b = [_][]const u8{"APPENDED-BEHIND"};
    _ = o.append(&b);

    // Interleave flush and peer-read until the outbox drains; the peer
    // must receive byte-identical data, ordered, pin bytes first.
    var scratch: [4096]u8 = undefined;
    var tail: [31]u8 = undefined;
    var idle: usize = 0;
    while (idle < 1000) {
        _ = o.flush(&t, 1 << 20);
        const n = posix.read(pair[1], &scratch) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => return err,
        };
        if (n == 0) {
            idle += 1;
            continue;
        }
        idle = 0;
        if (n >= tail.len) {
            @memcpy(&tail, scratch[n - tail.len .. n]);
        } else {
            const keep = tail.len - n;
            std.mem.copyForwards(u8, tail[0..keep], tail[n..]);
            @memcpy(tail[keep..], scratch[0..n]);
        }
    }
    // The last bytes out are the two appends (16 + 15 = 31).
    try std.testing.expectEqualStrings("0123456789abcdefAPPENDED-BEHIND", &tail);
}
