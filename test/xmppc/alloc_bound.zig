//! M4 counting-allocator check for the established 1:1 message path.
//!
//! Drives one xmppc session over socketpair(2) against a scripted fake
//! server with an allocator that counts every alloc call, then exchanges
//! stanzas in steady state and asserts the per-run allocation count stays
//! at or below the ratchet ceiling measured at v0.9.1 baseline. Lower the
//! constant only; CI fails on any increase (quality lane).
//!
//! The server-side 1:1 path gets its own counting test when the core
//! Outbox (C2) lands; this one bounds the lib/xmppc side of M4.
//!
//! Only one test lives in this file; keep it self-contained (the
//! session_socketpair harness helpers are file-private).

const std = @import("std");
const xmppc = @import("xmppc");

const posix = std.posix;
const Engine = xmppc.Engine;
const Handle = xmppc.Handle;

/// Ratchet ceiling for alloc calls measured during the steady-state window
/// below (64 stanzas each way). Measured at the v0.9.1 baseline as 147-149
/// (the SM outbound queue dupes every stanza, the reader arena re-inits);
/// lower only. CI fails on any increase (quality lane).
const ALLOC_CEILING: usize = 160;

/// Counts every alloc call of an underlying allocator; free/resize pass
/// through uncounted (the metric is allocation churn, not bytes).
const CountingAllocator = struct {
    inner: std.mem.Allocator,
    allocs: std.atomic.Value(usize) = .init(0),

    fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = allocFn,
            .resize = resizeFn,
            .remap = remapFn,
            .free = freeFn,
        } };
    }
    fn allocFn(ctx: *anyopaque, len: usize, align_: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        _ = self.allocs.fetchAdd(1, .monotonic);
        return self.inner.rawAlloc(len, align_, ret_addr);
    }
    fn resizeFn(ctx: *anyopaque, memory: []u8, align_: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        return self.inner.rawResize(memory, align_, new_len, ret_addr);
    }
    fn remapFn(ctx: *anyopaque, memory: []u8, align_: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        return self.inner.rawRemap(memory, align_, new_len, ret_addr);
    }
    fn freeFn(ctx: *anyopaque, memory: []u8, align_: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.inner.rawFree(memory, align_, ret_addr);
    }
};

var cur_mutex: std.Thread.Mutex = .{};
var cur_cond: std.Thread.Condition = .{};
var cur_established: bool = false;
var cur_stanzas: usize = 0;

fn onEvent(_: ?*anyopaque, _: *Engine, _: Handle, ev: xmppc.Event) void {
    cur_mutex.lock();
    defer cur_mutex.unlock();
    switch (ev) {
        .established => {
            cur_established = true;
            cur_cond.signal();
        },
        .stanza => cur_stanzas += 1,
        .closed, .sm_failed => {},
    }
}

test "alloc-bound: steady-state 1:1 stanza path stays under the ratchet ceiling (M4)" {
    var counting = CountingAllocator{ .inner = std.testing.allocator };
    const alloc = counting.allocator();

    cur_mutex.lock();
    cur_established = false;
    cur_stanzas = 0;
    cur_mutex.unlock();

    const engine = try std.testing.allocator.create(Engine);
    defer std.testing.allocator.destroy(engine);
    engine.* = try Engine.init(alloc);
    defer engine.deinit();
    engine.setEventHandler(onEvent, null);

    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0, &fds) != 0)
        return error.Socketpair;
    defer posix.close(fds[1]);

    const handle = try engine.attachFd(fds[0], .{
        .domain = "localhost",
        .user = "alice",
        .password = "pass1",
        .resource = "smoke",
    });
    if (engine.sessionAt(handle)) |s| {
        // Plaintext fake-server rig, PLAIN mechanism only.
        s.fsm.tls_required = false;
        s.fsm.allow_plain = true;
    }
    try engine.run();

    // Fake server: stream features with PLAIN, then success, bind,
    // SM enable.
    var buf: [16384]u8 = undefined;
    var read_len: usize = 0;
    try sendFd(fds[1], "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='localhost' id='srv-1' version='1.0'><stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features>");
    read_len = try expectFd(fds[1], &buf, read_len, "<auth");
    try sendFd(fds[1], "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");
    read_len = try expectFd(fds[1], &buf, read_len, "<stream:stream");
    try sendFd(fds[1], "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='localhost' id='srv-2' version='1.0'><stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/><session xmlns='urn:ietf:params:xml:ns:xmpp-session'><optional/></session><sm xmlns='urn:xmpp:sm:3'/></stream:features>");
    read_len = try expectFd(fds[1], &buf, read_len, "<bind");
    try sendFd(fds[1], "<iq type='result' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>alice@localhost/smoke</jid></bind></iq>");
    read_len = try expectFd(fds[1], &buf, read_len, "<enable");
    try sendFd(fds[1], "<enabled xmlns='urn:xmpp:sm:3' id='sm-test-42' resume='true'/>");

    // Wait for established.
    {
        const deadline = std.time.milliTimestamp() + 5000;
        cur_mutex.lock();
        defer cur_mutex.unlock();
        while (!cur_established) {
            if (std.time.milliTimestamp() >= deadline) return error.NotEstablished;
            cur_cond.timedWait(&cur_mutex, @intCast((deadline - std.time.milliTimestamp()) * std.time.ns_per_ms)) catch return error.NotEstablished;
        }
    }

    // Steady-state window: 64 stanzas out and 64 back, allocator counted.
    counting.allocs.store(0, .monotonic);
    const stanza_count: usize = 64;
    for (0..stanza_count) |i| {
        var id_buf: [256]u8 = undefined;
        const out = try std.fmt.bufPrint(&id_buf, "<message from='bob@localhost/x' to='alice@localhost' type='chat' id='m{d}'><body>ratchet</body></message>", .{i});
        try engine.postStanza(handle, "<message to='bob@localhost' id='x'><body>ratchet</body></message>");
        try sendFd(fds[1], out);
    }
    // Let the engine drain both directions.
    {
        const deadline = std.time.milliTimestamp() + 5000;
        while (std.time.milliTimestamp() < deadline) {
            cur_mutex.lock();
            const n = cur_stanzas;
            cur_mutex.unlock();
            if (n >= stanza_count) break;
            std.Thread.sleep(5 * std.time.ns_per_ms);
        }
        cur_mutex.lock();
        const n = cur_stanzas;
        cur_mutex.unlock();
        if (n < stanza_count) return error.StanzaDrainTimeout;
    }
    const measured = counting.allocs.load(.monotonic);
    std.debug.print("alloc-bound: {d} alloc calls over {d} exchanged stanzas (ceiling {d})\n", .{ measured, 2 * stanza_count, ALLOC_CEILING });
    if (measured > ALLOC_CEILING) return error.AllocRatchetExceeded;
}

fn sendFd(fd: posix.fd_t, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        written += posix.write(fd, bytes[written..]) catch |err| {
            if (err == error.WouldBlock) return error.WriteStalled else return err;
        };
    }
}

/// Read until `needle` appears in the accumulated buffer; returns the
/// length still kept (may contain bytes after the needle).
fn expectFd(fd: posix.fd_t, buf: []u8, start_len: usize, needle: []const u8) !usize {
    var len = start_len;
    const deadline = std.time.milliTimestamp() + 3000;
    while (std.mem.indexOf(u8, buf[0..len], needle) == null) {
        if (std.time.milliTimestamp() >= deadline) return error.RigTimeout;
        var pfds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
        _ = posix.poll(&pfds, 20) catch {};
        const n = posix.read(fd, buf[len..]) catch 0;
        len += n;
    }
    return len;
}
