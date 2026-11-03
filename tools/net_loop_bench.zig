//! Microbenchmark: lib/net Loop iteration cost (ADR-8, F2).
//! Built via `zig build bench-net-loop` (module pinned to ReleaseFast).
//!
//! Rows:
//!   idle N      - N attached socketpairs, no events: cost of one commit +
//!                 kevent(2) pass (change buffer empty, zero-timeout scan).
//!   active N    - N socketpairs each with 1 byte pending: per-iteration
//!                 harvest cost and per-event delivery cost.
//!   wake        - waker().notify() -> wait() -> .wake round trip.
//!
//! Three runs per row, median reported. CLOCK_MONOTONIC for timestamps.

const std = @import("std");
const posix = std.posix;
const net = @import("net");

const runs = 3;
const iters = 200;

fn nowNs() i128 {
    const ts = posix.clock_gettime(.MONOTONIC) catch unreachable;
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

const ctx_tok: net.Token = .{ .index = 1, .gen = 1, .kind = 0xEE };

fn makeLoop(handles_max: u32) !net.Loop {
    var loop: net.Loop = undefined;
    const options: net.loop.Options = .{
        .handles_max = handles_max,
        .timers_max = 16,
        .events_max = 256,
    };
    try loop.init(std.heap.page_allocator, &options);
    return loop;
}

fn pairFd() !posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0, &fds) != 0)
        return error.SocketPairFailed;
    _ = std.c.close(fds[1]);
    return fds[0];
}

fn median(samples: *[runs]i128) i128 {
    const s = samples[0..];
    std.mem.sort(i128, s, {}, std.sort.asc(i128));
    return s[runs / 2];
}

fn benchIdle(n: u32) !i128 {
    var loop = try makeLoop(n);
    defer loop.deinit(std.heap.page_allocator);
    var fds = try std.heap.page_allocator.alloc(posix.fd_t, n);
    defer std.heap.page_allocator.free(fds);
    for (0..n) |i| {
        fds[i] = try pairFd();
        _ = try loop.attach(fds[i], ctx_tok, .{ .read = true });
    }
    try loop.wait();
    while (loop.next() != null) {}

    var samples: [runs]i128 = undefined;
    for (&samples) |*s| {
        const t0 = nowNs();
        for (0..iters) |_| {
            loop.requestImmediate();
            try loop.wait();
            while (loop.next() != null) {}
        }
        s.* = @divTrunc(nowNs() - t0, iters);
    }
    return median(&samples);
}

fn benchActive(n: u32) !i128 {
    var loop = try makeLoop(n);
    defer loop.deinit(std.heap.page_allocator);
    var fds = try std.heap.page_allocator.alloc(posix.fd_t, n);
    defer std.heap.page_allocator.free(fds);
    var peers = try std.heap.page_allocator.alloc(posix.fd_t, n);
    defer std.heap.page_allocator.free(peers);
    for (0..n) |i| {
        var p: [2]posix.fd_t = undefined;
        if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0, &p) != 0)
            return error.SocketPairFailed;
        peers[i] = p[0];
        fds[i] = p[1];
        _ = try loop.attach(fds[i], ctx_tok, .{ .read = true });
    }
    loop.requestImmediate();
    try loop.wait();
    while (loop.next() != null) {}

    var samples: [runs]i128 = undefined;
    var buf: [64]u8 = undefined;
    for (&samples) |*s| {
        // Every handle gets one pending byte.
        for (peers) |pfd| _ = try posix.write(pfd, "x");
        const t0 = nowNs();
        var delivered: usize = 0;
        try loop.wait();
        while (loop.next()) |ev| {
            if (ev == .readable) {
                delivered += 1;
                _ = posix.read(loop.fdOf(ev.readable.handle).?, &buf) catch 0;
            }
        }
        std.debug.assert(delivered == n);
        s.* = nowNs() - t0;
    }
    return median(&samples);
}

fn benchWake() !i128 {
    var loop = try makeLoop(8);
    defer loop.deinit(std.heap.page_allocator);
    var samples: [runs]i128 = undefined;
    for (&samples) |*s| {
        const t0 = nowNs();
        for (0..iters) |_| {
            try loop.waker().notify();
            try loop.wait();
            const ev = loop.next();
            std.debug.assert(ev.? == .wake);
        }
        s.* = @divTrunc(nowNs() - t0, iters);
    }
    return median(&samples);
}

pub fn main() !void {
    const w = std.debug.lockStderrWriter(&.{});
    defer std.debug.unlockStderrWriter();

    try w.print("net-loop bench (ReleaseFast, median of {d} runs)\n", .{runs});
    for ([_]u32{ 64, 1024, 8192 }) |n| {
        const ns = try benchIdle(n);
        try w.print("idle {d: >5} handles: {d: >8} ns/iter\n", .{ n, ns });
    }
    for ([_]u32{ 64, 1024 }) |n| {
        const ns = try benchActive(n);
        try w.print("active {d: >4} events:  {d: >8} ns/iter ({d: >6} ns/event)\n", .{ n, ns, @divTrunc(ns, @as(i128, n)) });
    }
    const wake_ns = try benchWake();
    try w.print("wake round trip:    {d: >8} ns\n", .{wake_ns});
}
