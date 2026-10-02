//! # xmppc socketpair test seam (T-6871B4C7)
//!
//! Drives Engine/Session over socketpair(2) against a scripted fake server —
//! no network and no PKI for the plaintext cases; the TLS case uses an
//! in-test self-signed cert written into a tmp dir. Coverage beyond what the
//! live smoke run can exercise deterministically:
//!
//!   * happy path (plain and TLS upgrade)
//!   * reads split across element boundaries
//!   * peer close mid-stream (EV_EOF path)
//!   * protocol stream error
//!   * SASL failure condition propagation
//!   * partial writes under backpressure (tiny SO_SNDBUF, oversized payload)
//!   * wrong-password teardown
//!
//! Tests run sequentially; `cur` points at the active harness for the
//! engine-thread callbacks.

const std = @import("std");
const xmppc = @import("xmppc");
const ssl_mod = @import("ssl");

const posix = std.posix;
const Engine = xmppc.Engine;
const Session = xmppc.Session;

// ---------------------------------------------------------------------------
// In-test self-signed cert (CN=localhost, generated for this suite only; the
// plaintext cases don't need it — it exists solely so the TLS-upgraded fake
// server has something to present).
// ---------------------------------------------------------------------------

const TEST_PEM_CERT =
    \\-----BEGIN CERTIFICATE-----
    \\MIIDCTCCAfGgAwIBAgIUCkNVUEosKcKZi53NaWPaSvnUTP4wDQYJKoZIhvcNAQEL
    \\BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTAwMjE4MjcyMVoXDTM2MDky
    \\OTE4MjcyMVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
    \\AAOCAQ8AMIIBCgKCAQEA5Ngkn6hsJ4GQBFIkyyCOzZi2CkMv/E12kYPjOwLw0V4J
    \\KeVLd+X4e4NHjcwxlc2Cv+doW+ZGrSXtpKvEnzdxohcstPO+baLTxA8vzI27XCYd
    \\9GAKgf6MkLrvgJz2zjVIsklZnqlqPM2jkqkatYmubda4FTlBxhH9BNe010lkMrPP
    \\q0U2evOaiRNe0QnvTDhevcus63TVcl1id1LfNlJ1RPB2S9BoOLd90K9VMc+tgJiL
    \\0ulNBHIgLk75OrNMjq1iqHMvRitHmM2kRfJHYFdbkGEM9O1SBZdDTqc170lc9mfh
    \\8545cgAaBtcUi4f3RC8QjTXYJR7DiPkTC5zekmajnQIDAQABo1MwUTAdBgNVHQ4E
    \\FgQU+x5/t1SzsCC1I+L2L61ZrDQ16mEwHwYDVR0jBBgwFoAU+x5/t1SzsCC1I+L2
    \\L61ZrDQ16mEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEASUME
    \\Xji3hJg+7k1cSUxeFm6/FRYM8TnF4qh4UWKCILWMYGo6hYyFBerHSWfBFoI7aD9a
    \\O0C+gadfVP94cHOI2ww0xWz3YEcgT89hIlzOFnMwxikJTXlOpU/MJMmRk6jkHFGf
    \\pq0ZrTT4lRsxZgZSCp/jKIut67J89gY4aImZ1FlXrc5EqdVjp+7qfMcDrUups5GG
    \\huu3sUHF4lgXUERtkxCxMTZSNTq8wY8TObnGOV9hyVX/IoPCq6mLtsKuLh174dVc
    \\ClxRr9/nK16uPc1s0Nf+Z1V2IZS1RjlsrwuPlnz6rK6Wvv6y22roSQzKMBTyQlU1
    \\JnoNdgFffifiJ/yvTg==
    \\-----END CERTIFICATE-----
    \\
;

const TEST_PEM_KEY =
    \\-----BEGIN PRIVATE KEY-----
    \\MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDk2CSfqGwngZAE
    \\UiTLII7NmLYKQy/8TXaRg+M7AvDRXgkp5Ut35fh7g0eNzDGVzYK/52hb5katJe2k
    \\q8SfN3GiFyy0875totPEDy/MjbtcJh30YAqB/oyQuu+AnPbONUiySVmeqWo8zaOS
    \\qRq1ia5t1rgVOUHGEf0E17TXSWQys8+rRTZ685qJE17RCe9MOF69y6zrdNVyXWJ3
    \\Ut82UnVE8HZL0Gg4t33Qr1Uxz62AmIvS6U0EciAuTvk6s0yOrWKocy9GK0eYzaRF
    \\8kdgV1uQYQz07VIFl0NOpzXvSVz2Z+HznjlyABoG1xSLh/dELxCNNdglHsOI+RML
    \\nN6SZqOdAgMBAAECggEAB9kPvHfyqZIsZbGJeHvX2d4kVArE0QK5D7l1p/bsWkm+
    \\x7SI14ZH9LhmUksP4kLHepxNfGVTxClaUnzfg9RLbdMcoeIABFOCrqUUrw+nPrxB
    \\57kJczbPDEGU6BS59A1ovlB8pc/KiGZG90ccVuBvXm3wJy4s/sVsJ2fcWEu4h3KJ
    \\i8jJ5EYOKEbkBnFwCqNKcVcvT7liKcIZj8zQg4K1G4xzhK0arq9+fGgm1/scQ/m2
    \\J532qVnY8RvLVoue0/j4D8uBQf6g4EVTWVy3D0qW5zAlHbhLutx2QfWZJXZBn4gS
    \\MSCwpp++9K89ej5RY0lREkjwxqOunNtO1y5hyASLkwKBgQD+nvIFdSCFNk9gOy2k
    \\iW75s5R16kYJt6+KBPJ7CQerpMoFPmAbax7+gLCb67s1gPO0lhQHdw9sRxf8SacN
    \\IDUL5McOTjhD7CUl9d2OeJfRiL73hCoHlp5YPFSwkXJ7d0zPna83A+RQihgqJMXm
    \\tf0ilInIGuyzv1xZ2TQR5D6ltwKBgQDmFXTF8hF0KvNYIhS7vtGzVYyDC8+HFfGG
    \\cnKUjJrZULH3gIZp32bQw+8XHaYuaBjH0re9HbOKnizbTRZXvVCjrTnDSEPJiaqk
    \\2Rm+M3pDYKTW+rYG0DmLoPJuPLRNGnL69nAzxZlM8NlSrsTXIsKMHbCOEN0eBWvH
    \\b6ogwMyhSwKBgQCWPRc1XS05LRidAY4m/ej7cZjyErAM39O2LsEdE/DwuKVzfqCa
    \\zRRWu3x6JBgss9AZCEz9MqVpEHH4rUTim9RxFibWLBVLDrXEtlRq0oFSY8u6pMNg
    \\AuGf0slt/gR9EaHDB5nxblxzoWgsxdH4Ff4tP1QlPK3aSdmmMmFlBTZp9QKBgHvN
    \\j8fzOPEJK2eA7ycWxj95COJ6uHA3nn55lq3X+np0sU48Ghdd3jT3OO93RLQzzyG2
    \\gKeCE9nCwuA92ofblkh8LVimydLoAKozJ2bwzBj1J72FqeyAnnZDZC9s+peCY9wm
    \\Prmc2aBM+KNE5yXbzlMWpqnK6S/+OsBVlXWKSJGBAoGBAMz2mNg1Q7ZcbUKIx+6i
    \\R2NOLtX9rZhaZTL1y2b8NulrpJiHuaEZwNS/6jDnztdyAVykRYckWhzhq2MjRO0l
    \\hhz4OfTHnQ+UuifdTsXugcr7ZyKN87WTBUbOTZ6tH7uVYI/Su3J5Gv46vCHK/GrF
    \\EHBBKb7pmLiS89UMzOKB4z2E
    \\-----END PRIVATE KEY-----
    \\
;

// ---------------------------------------------------------------------------
// Harness: engine on its own thread, scripted fake server on our end.
// ---------------------------------------------------------------------------

const Outcome = struct {
    established: bool = false,
    failed: bool = false,
    reason: []const u8 = "",
    bound_jid: []const u8 = "",
    sm_id: []const u8 = "",
    ktls_send: bool = false,
    ktls_recv: bool = false,
};

var cur_mutex: std.Thread.Mutex = .{};
var cur_cond: std.Thread.Condition = .{};
var cur_outcome: Outcome = .{};

fn onEstablished(engine: *Engine, index: usize, session: *Session) void {
    _ = engine;
    _ = index;
    const jid_str: []const u8 = if (session.boundJid()) |j|
        std.fmt.allocPrint(std.heap.page_allocator, "{s}@{s}/{s}", .{ j.local, j.domain, j.resource }) catch ""
    else
        "";
    const sm_id: []const u8 = std.heap.page_allocator.dupe(u8, session.smId()) catch "";
    cur_mutex.lock();
    defer cur_mutex.unlock();
    cur_outcome.established = true;
    cur_outcome.bound_jid = jid_str;
    cur_outcome.sm_id = sm_id;
    if (session.tls) |*t| {
        cur_outcome.ktls_send = t.ktlsSend();
        cur_outcome.ktls_recv = t.ktlsRecv();
    }
    cur_cond.signal();
}

fn onClosed(engine: *Engine, index: usize, session: *Session, reason: []const u8) void {
    _ = engine;
    _ = index;
    _ = session;
    const dup = std.heap.page_allocator.dupe(u8, reason) catch "";
    cur_mutex.lock();
    defer cur_mutex.unlock();
    if (!cur_outcome.established) {
        cur_outcome.failed = true;
        cur_outcome.reason = dup;
    }
    cur_cond.signal();
}

fn waitTerminal(timeout_ms: u64) Outcome {
    const deadline = std.time.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    cur_mutex.lock();
    defer cur_mutex.unlock();
    while (!cur_outcome.established and !cur_outcome.failed) {
        const now = std.time.milliTimestamp();
        if (now >= deadline) break;
        // timedWait takes NANOSECONDS.
        cur_cond.timedWait(&cur_mutex, @intCast((deadline - now) * std.time.ns_per_ms)) catch break;
    }
    return cur_outcome;
}

const Rig = struct {
    fake_fd: posix.fd_t,
    read_buf: [16384]u8 = undefined,
    read_len: usize = 0,
    /// Armed after the STARTTLS handshake completes on the fake side.
    tls_conn: ?ssl_mod.SslConn = null,

    fn take(self: *Rig, out: []u8) usize {
        const n = @min(out.len, self.read_len);
        @memcpy(out[0..n], self.read_buf[0..n]);
        std.mem.copyForwards(u8, self.read_buf[0..], self.read_buf[n..self.read_len]);
        self.read_len -= n;
        return n;
    }

    fn readMore(self: *Rig) !void {
        if (self.tls_conn) |*t| {
            const r = t.read(self.read_buf[self.read_len..]) catch |e| switch (e) {
                ssl_mod.SslError.ConnectionClosed => return error.PeerClosed,
                else => return, // transient (e.g. handshake renegotiation WANT): expect() retries
            };
            switch (r) {
                .ok => |n| self.read_len += n,
                else => {},
            }
            return;
        }
        const n = posix.read(self.fake_fd, self.read_buf[self.read_len..]) catch 0;
        self.read_len += n;
    }

    /// Read until `needle` appears in the accumulated buffer (or timeout).
    fn expect(self: *Rig, needle: []const u8, timeout_ms: u64) !void {
        const deadline = std.time.milliTimestamp() + @as(i64, @intCast(timeout_ms));
        while (std.mem.indexOf(u8, self.read_buf[0..self.read_len], needle) == null) {
            if (std.time.milliTimestamp() >= deadline) {
                cur_mutex.lock();
                const failed = cur_outcome.failed;
                const reason = cur_outcome.reason;
                cur_mutex.unlock();
                std.debug.print("rig timeout waiting for '{s}'; got: {s} [client failed={} reason={s}]\n", .{ needle, self.read_buf[0..@min(self.read_len, 400)], failed, reason });
                return error.RigTimeout;
            }
            var fds = [_]posix.pollfd{.{ .fd = self.fake_fd, .events = posix.POLL.IN, .revents = 0 }};
            _ = posix.poll(&fds, 20) catch {};
            self.readMore() catch |e| {
                if (e == error.PeerClosed) return error.PeerClosed;
            };
        }
    }

    fn send(self: *Rig, bytes: []const u8) !void {
        if (self.tls_conn) |*t| {
            var off: usize = 0;
            while (off < bytes.len) {
                const r = t.write(bytes[off..]) catch return error.TlsWrite;
                switch (r) {
                    .ok => |n| off += n,
                    else => std.Thread.sleep(500_000), // WANT_* — client drives concurrently
                }
            }
            return;
        }
        _ = try posix.write(self.fake_fd, bytes);
    }

    /// Dribble bytes in chunks (partial reads for the session's parse loop).
    fn sendChunked(self: *Rig, bytes: []const u8, chunk: usize) !void {
        var off: usize = 0;
        while (off < bytes.len) {
            const n = @min(chunk, bytes.len - off);
            try self.send(bytes[off .. off + n]);
            off += n;
            std.Thread.sleep(2 * std.time.ns_per_ms);
        }
    }
};

fn setup(alloc: std.mem.Allocator, use_tls: bool) !struct { rig: Rig, engine: *Engine } {
    cur_mutex.lock();
    cur_outcome = .{};
    cur_mutex.unlock();

    const engine = try alloc.create(Engine);
    engine.* = try Engine.init(alloc);
    if (use_tls) try engine.useTls(null);

    var fds: [2]posix.fd_t = undefined;
    // std.posix lacks socketpair on FreeBSD in this zig version; std.c has it.
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0, &fds) != 0)
        return error.Socketpair;

    const idx = try engine.attachFd(fds[0], "localhost", "alice", "pass1", "smoke", "");
    if (engine.sessionAt(idx)) |s| {
        s.setCallbacks(onEstablished, onClosed);
        // Lab rig controls (xmppc.zig documents them): the fake server either
        // has no TLS at all (plaintext scripts) or only answers PLAIN (this
        // harness does not run a fake SCRAM verifier; the real-thing SCRAM is
        // covered live by the smoke client).
        s.fsm.tls_required = false;
        s.fsm.allow_plain = true;
    }

    try engine.run();
    return .{ .rig = .{ .fake_fd = fds[1] }, .engine = engine };
}

fn teardown(alloc: std.mem.Allocator, rig: *Rig, engine: *Engine) void {
    if (rig.fake_fd >= 0) posix.close(rig.fake_fd);
    engine.deinit();
    alloc.destroy(engine);
}

// ---------------------------------------------------------------------------
// Scripted server conversations
// ---------------------------------------------------------------------------

/// Pre-TLS features advertising PLAIN only. (The client prefers SCRAM when
/// offered; this harness answers PLAIN — the SCRAM wire dance is exercised
/// for real by xmppc-smoke against a live xmppd rig.)
const pre_tls_features =
    "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='localhost' id='srv-1' version='1.0'>" ++
    "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" ++
    "<mechanism>PLAIN</mechanism></mechanisms></stream:features>";

fn sendPostAuthFeatures(rig: *Rig) !void {
    try rig.send("<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='localhost' id='srv-2' version='1.0'>" ++
        "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>" ++
        "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'><optional/></session>" ++
        "<sm xmlns='urn:xmpp:sm:3'/></stream:features>");
}

/// Plain happy path: features -> PLAIN auth -> success -> features -> bind ->
/// SM enable. Returns after the session reports established.
fn scriptPlainHappy(rig: *Rig) !void {
    try rig.send(pre_tls_features);
    try rig.expect("<auth", 2000);
    try rig.send("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>"); // PLAIN: empty success
    try rig.expect("<stream:stream", 2000); // post-auth re-open
    try sendPostAuthFeatures(rig);
    try rig.expect("<bind", 2000);
    try rig.send("<iq type='result' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>alice@localhost/smoke</jid></bind></iq>");
    try rig.expect("<enable", 2000);
    try rig.send("<enabled xmlns='urn:xmpp:sm:3' id='sm-test-42' resume='true'/>");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "socketpair: plain happy path establishes with bound JID and SM id" {
    const alloc = std.testing.allocator;
    var ctx = try setup(alloc, false);
    defer teardown(alloc, &ctx.rig, ctx.engine);

    try scriptPlainHappy(&ctx.rig);
    const out = waitTerminal(5000);
    if (!out.established) std.debug.print("happy-path not established: failed={} reason='{s}'\n", .{ out.failed, out.reason });
    try std.testing.expect(out.established);
    try std.testing.expectEqualStrings("alice@localhost/smoke", out.bound_jid);
    try std.testing.expectEqualStrings("sm-test-42", out.sm_id);
}

test "socketpair: reads split across element boundaries parse identically" {
    const alloc = std.testing.allocator;
    var ctx = try setup(alloc, false);
    defer teardown(alloc, &ctx.rig, ctx.engine);

    // Same happy path but every server emission arrives in 7-byte dribbles.
    try ctx.rig.sendChunked(pre_tls_features, 7);
    try ctx.rig.expect("<auth", 3000);
    try ctx.rig.sendChunked("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>", 5);
    try ctx.rig.expect("<stream:stream", 3000);
}

test "socketpair: diced stream still reaches bind and established" {
    const alloc = std.testing.allocator;
    var ctx = try setup(alloc, false);
    defer teardown(alloc, &ctx.rig, ctx.engine);

    try ctx.rig.sendChunked(pre_tls_features, 7);
    try ctx.rig.expect("<auth", 3000);
    try ctx.rig.sendChunked("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>", 5);
    try ctx.rig.expect("<stream:stream", 3000);
    try ctx.rig.sendChunked("<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='localhost' id='srv-2' version='1.0'>" ++
        "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>" ++
        "<sm xmlns='urn:xmpp:sm:3'/></stream:features>", 9);
    try ctx.rig.expect("<bind", 3000);
    try ctx.rig.send("<iq type='result' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>alice@localhost/smoke</jid></bind></iq>");
    try ctx.rig.expect("<enable", 3000);
    try ctx.rig.send("<enabled xmlns='urn:xmpp:sm:3' id='sm-split' resume='true'/>");
    const out = waitTerminal(5000);
    try std.testing.expect(out.established);
    try std.testing.expectEqualStrings("sm-split", out.sm_id);
}

test "socketpair: peer close mid-stream fails the session as peer-closed" {
    const alloc = std.testing.allocator;
    var ctx = try setup(alloc, false);
    defer teardown(alloc, &ctx.rig, ctx.engine);

    // Wait for the client's stream open, THEN hang up — with no write in
    // flight the only observation is EV_EOF (closing earlier races the open
    // write against EPIPE and the reason becomes write-error instead).
    try rig_expect_open(&ctx.rig);
    posix.close(ctx.rig.fake_fd);
    ctx.rig.fake_fd = -1;
    const out = waitTerminal(3000);
    try std.testing.expect(out.failed);
    try std.testing.expectEqualStrings("peer-closed", out.reason);
    ctx.rig.fake_fd = -1; // teardown: already closed
}

test "socketpair: protocol stream error propagates the condition" {
    const alloc = std.testing.allocator;
    var ctx = try setup(alloc, false);
    defer teardown(alloc, &ctx.rig, ctx.engine);

    try rig_expect_open(&ctx.rig);
    try ctx.rig.send("<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='localhost' id='srv-9' version='1.0'>" ++
        "<stream:error><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>");
    const out = waitTerminal(3000);
    try std.testing.expect(out.failed);
    try std.testing.expectEqualStrings("policy-violation", out.reason);
}

fn rig_expect_open(rig: *Rig) !void {
    try rig.expect("<stream:stream", 2000);
}

test "socketpair: SASL failure carries the condition" {
    const alloc = std.testing.allocator;
    var ctx = try setup(alloc, false);
    defer teardown(alloc, &ctx.rig, ctx.engine);

    try rig_expect_open(&ctx.rig);
    try ctx.rig.send(pre_tls_features);
    try ctx.rig.expect("<auth", 2000);
    // Wrong-credential answer, both levels.
    try ctx.rig.send("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>");
    const out = waitTerminal(3000);
    try std.testing.expect(out.failed);
    try std.testing.expectEqualStrings("not-authorized", out.reason);
}

test "socketpair: partial writes under a tiny send buffer all arrive" {
    const alloc = std.testing.allocator;
    var ctx = try setup(alloc, false);
    defer teardown(alloc, &ctx.rig, ctx.engine);

    // Shrink the client send buffer to force WANT_WRITE loops on a 100 KiB blob.
    const big = try alloc.alloc(u8, 100 * 1024);
    defer alloc.free(big);
    @memset(big, 'x');

    try scriptPlainHappy(&ctx.rig);
    const out = waitTerminal(5000);
    try std.testing.expect(out.established);

    const engine = ctx.engine;
    if (engine.sessionAt(0)) |s| {
        // Tiny sndbuf on the paired fd.
        const small: c_int = 1024;
        try posix.setsockopt(s.fd, posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&small));
        try s.testQueue(big);
    } else return error.NoSession;

    // Read the whole thing on the fake side, slowly.
    var got: usize = 0;
    var rbuf: [4096]u8 = undefined;
    const deadline = std.time.milliTimestamp() + 5000;
    while (got < big.len and std.time.milliTimestamp() < deadline) {
        const n = posix.read(ctx.rig.fake_fd, &rbuf) catch 0;
        if (n > 0) {
            for (rbuf[0..n]) |byte| try std.testing.expectEqual(@as(u8, 'x'), byte);
            got += n;
        } else {
            std.Thread.sleep(1 * std.time.ns_per_ms);
        }
    }
    try std.testing.expectEqual(big.len, got);
}

test "socketpair: TLS upgrade, full happy path, kTLS flags verified false" {
    const alloc = std.testing.allocator;

    // In-test PKI: write the embedded throwaway cert where SslContext can read it.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const cf = try tmp.dir.createFile("cert.pem", .{});
        defer cf.close();
        try cf.writeAll(TEST_PEM_CERT);
    }
    {
        const kf = try tmp.dir.createFile("key.pem", .{});
        defer kf.close();
        try kf.writeAll(TEST_PEM_KEY);
    }

    const ctx_use_tls = true;
    var ctx = try setup(alloc, ctx_use_tls);
    defer teardown(alloc, &ctx.rig, ctx.engine);

    const cert_pre = try tmp.dir.realpathAlloc(alloc, "cert.pem");
    defer alloc.free(cert_pre);
    const key_pre = try tmp.dir.realpathAlloc(alloc, "key.pem");
    defer alloc.free(key_pre);
    const cert_path = try alloc.dupeZ(u8, cert_pre);
    defer alloc.free(cert_path);
    const key_path = try alloc.dupeZ(u8, key_pre);
    defer alloc.free(key_path);
    var server_ctx = try ssl_mod.SslContext.initServer(cert_path, key_path);
    defer server_ctx.deinit();

    // Pre-TLS features advertise STARTTLS as required (mirrors xmppd).
    try ctx.rig.send("<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='localhost' id='srv-t1' version='1.0'>" ++
        "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>");
    try ctx.rig.expect("<starttls", 2000);
    try ctx.rig.send("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");

    // Arm the server side and drive the handshake until complete (the client
    // side is driven by the engine's kqueue loop concurrently).
    ctx.rig.tls_conn = try ssl_mod.SslConn.init(server_ctx, ctx.rig.fake_fd);
    defer if (ctx.rig.tls_conn) |*t| t.deinit();
    var done = false;
    const hs_deadline = std.time.milliTimestamp() + 5000;
    while (!done and std.time.milliTimestamp() < hs_deadline) {
        const res = try ctx.rig.tls_conn.?.doHandshake();
        done = res == .complete;
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    if (!done) return error.TlsHandshakeTimeout;

    // Post-TLS script: same happy path over the secure channel.
    try ctx.rig.send(pre_tls_features); // mechanisms over TLS now
    try ctx.rig.expect("<auth", 3000);
    try ctx.rig.send("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");
    try ctx.rig.expect("<stream:stream", 3000);
    try sendPostAuthFeatures(&ctx.rig);
    try ctx.rig.expect("<bind", 3000);
    try ctx.rig.send("<iq type='result' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>alice@localhost/smoke</jid></bind></iq>");
    try ctx.rig.expect("<enable", 3000);
    try ctx.rig.send("<enabled xmlns='urn:xmpp:sm:3' id='sm-tls' resume='true'/>");

    const out = waitTerminal(5000);
    try std.testing.expect(out.established);
    try std.testing.expectEqualStrings("alice@localhost/smoke", out.bound_jid);
    try std.testing.expectEqualStrings("sm-tls", out.sm_id);
    // Default rig path is userland TLS on the client; assert the offload
    // flags were actually observed (guardrails rule 3), both directions.
    try std.testing.expect(!out.ktls_send);
    try std.testing.expect(!out.ktls_recv);
}
