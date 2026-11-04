//! Microbenchmark: lib/net Loop iteration cost (ADR-8, F2).
//! Built via `zig build bench-net-loop` (module pinned to ReleaseFast).
//! Run pinned for the second column: `cpuset -l 4 zig-out/bin/bench-net-loop`.
//!
//! Matrix (DESIGN 13.10):
//!   idle N       N in {0, 1k, 10k, 50k} idle handles plus one active
//!                socketpair: commit + scan + one delivery per pass.
//!   event A      A in {1, 64, 1k} handles with a byte pending that is never
//!                read(2): harvest + delivery cost per iteration, no I/O.
//!   active A     same, but one read(2) per event (real handler cost).
//!   wake 1|8     cross-thread notify() -> .wake delivery latency: each
//!                producer stamps the time before notify() and the consumer
//!                reports event time minus the earliest stamp.
//!
//! Five samples per row; min/median/max reported (spread). CLOCK_MONOTONIC.

const std = @import("std");
const posix = std.posix;
const net = @import("net");

const runs = 5;
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

/// One end of a socketpair; the peer is closed so no event is pending.
fn pairFd() !posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    const fl = posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC;
    if (std.c.socketpair(posix.AF.UNIX, fl, 0, &fds) != 0) return error.SocketPairFailed;
    _ = std.c.close(fds[1]);
    return fds[0];
}

/// Socketpair whose peer stays open and holds one byte, so the read knote
/// fires on every scan until something reads it.
fn pendingPair(peer: *posix.fd_t) !posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    const fl = posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC;
    if (std.c.socketpair(posix.AF.UNIX, fl, 0, &fds) != 0) return error.SocketPairFailed;
    _ = try posix.write(fds[1], "x");
    peer.* = fds[1];
    return fds[0];
}

fn sortAsc(s: []i128) void {
    std.mem.sort(i128, s, {}, std.sort.asc(i128));
}

fn report(name: []const u8, unit: []const u8, samples: *const [runs]i128) void {
    var s = samples.*;
    sortAsc(&s);
    std.debug.print("{s:<14}{d:>9} ns {s:<4} min {d} med {d} max {d}\n", .{
        name, @divTrunc(s[runs / 2], 1), unit, s[0], s[runs / 2], s[runs - 1],
    });
}

fn benchIdle(n: u32) ![runs]i128 {
    var loop = try makeLoop(@max(n + 1, 1));
    defer loop.deinit(std.heap.page_allocator);
    const alloc = std.heap.page_allocator;
    var fds = try alloc.alloc(posix.fd_t, n);
    defer alloc.free(fds);
    for (0..n) |i| {
        fds[i] = try pairFd();
        _ = try loop.attach(fds[i], ctx_tok, .{ .read = true });
    }
    // One active socketpair among the idle registrations: each timed pass
    // commits, scans and delivers a real read event (I/O cost is constant
    // across N, so the row still isolates the idle-handle overhead).
    var peer: posix.fd_t = undefined;
    const active = try pendingPair(&peer);
    _ = try loop.attach(active, ctx_tok, .{ .read = true });
    var byte: [1]u8 = undefined;
    try loop.wait();
    while (loop.next()) |ev| {
        if (ev == .readable) _ = posix.read(active, &byte) catch 0;
    }

    var samples: [runs]i128 = undefined;
    for (&samples) |*s| {
        const t0 = nowNs();
        for (0..iters) |_| {
            _ = try posix.write(peer, "x");
            try loop.wait();
            while (loop.next()) |ev| {
                if (ev == .readable) _ = posix.read(active, &byte) catch 0;
            }
        }
        s.* = @divTrunc(nowNs() - t0, iters);
    }
    return samples;
}

/// `a` handles each get one fresh byte per sample; the events are delivered
/// but never read(2). The re-pend writes sit outside the timed region, so
/// the row measures harvest + delivery only. EVFILT_READ|EV_CLEAR refires
/// only on new data, which is why the write is required.
fn benchEvent(a: u32) ![runs]i128 {
    var loop = try makeLoop(a);
    defer loop.deinit(std.heap.page_allocator);
    const alloc = std.heap.page_allocator;
    var peers = try alloc.alloc(posix.fd_t, a);
    var mine = try alloc.alloc(posix.fd_t, a);
    defer alloc.free(peers);
    defer alloc.free(mine);
    for (0..a) |i| {
        mine[i] = try pendingPair(&peers[i]);
        _ = try loop.attach(mine[i], ctx_tok, .{ .read = true });
    }
    var scratch: [1]u8 = undefined;
    var samples: [runs]i128 = undefined;
    for (&samples) |*s| {
        const t0 = nowNs();
        var events: u64 = 0;
        while (events < a) {
            try loop.wait();
            while (loop.next()) |ev| {
                if (ev == .readable) events += 1;
            }
        }
        s.* = @divTrunc(nowNs() - t0, @as(i128, @intCast(events)));
        // Untimed: drain, then re-pend for the next sample.
        for (mine) |fd| _ = posix.read(fd, &scratch) catch 0;
        for (peers) |p| _ = posix.write(p, "x") catch 0;
    }
    return samples;
}

/// `a` handles each read(2) and re-pended per event: the row measures the
/// full per-event handler cost including one read.
fn benchActive(a: u32) ![runs]i128 {
    var loop = try makeLoop(a);
    defer loop.deinit(std.heap.page_allocator);
    const alloc = std.heap.page_allocator;
    var peers = try alloc.alloc(posix.fd_t, a);
    var mine = try alloc.alloc(posix.fd_t, a);
    defer alloc.free(peers);
    defer alloc.free(mine);
    for (0..a) |i| {
        mine[i] = try pendingPair(&peers[i]);
        _ = try loop.attach(mine[i], ctx_tok, .{ .read = true });
    }
    var scratch: [1]u8 = undefined;
    var samples: [runs]i128 = undefined;
    for (&samples) |*s| {
        const t0 = nowNs();
        var events: u64 = 0;
        for (0..iters) |_| {
            try loop.wait();
            while (loop.next()) |ev| {
                if (ev != .readable) continue;
                events += 1;
                const fd = loop.fdOf(ev.readable.handle).?;
                _ = posix.read(fd, &scratch) catch 0;
                _ = posix.write(peers[ev.readable.handle.index], "x") catch 0;
            }
        }
        const dt = nowNs() - t0;
        s.* = if (events == 0) 0 else @divTrunc(dt, @as(i128, @intCast(events)));
    }
    return samples;
}

const WakeShared = struct {
    earliest: std.atomic.Value(i128) = .init(std.math.maxInt(i128)),
    done: std.atomic.Value(bool) = .init(false),
};

const Producer = struct {
    wake: *net.Wake,
    shared: *WakeShared,
    fn run(self: *const Producer) void {
        while (!self.shared.done.load(.acquire)) {
            _ = self.shared.earliest.fetchMin(nowNs(), .acq_rel);
            self.wake.notify() catch return;
            std.Thread.yield() catch {};
        }
    }
};

fn benchWake(producers: usize) ![runs]i128 {
    var loop = try makeLoop(1);
    defer loop.deinit(std.heap.page_allocator);
    var shared: WakeShared = .{};
    var threads: [8]std.Thread = undefined;
    const ctx: Producer = .{ .wake = loop.waker(), .shared = &shared };
    for (threads[0..producers]) |*t| t.* = try std.Thread.spawn(.{}, Producer.run, .{&ctx});
    defer {
        shared.done.store(true, .release);
        for (threads[0..producers]) |t| t.join();
    }

    // Latency per .wake: event delivery time minus the earliest notify
    // stamp since the previous delivery. A stamp consumed by an earlier
    // wake clamps the sample to zero; the median stays meaningful.
    var samples: [runs]i128 = undefined;
    for (&samples) |*s| {
        var total: i128 = 0;
        var wakes: u64 = 0;
        while (wakes < iters) {
            try loop.wait();
            while (loop.next()) |ev| {
                if (ev != .wake) continue;
                const t1 = nowNs();
                const t0 = shared.earliest.swap(std.math.maxInt(i128), .acq_rel);
                if (t0 == std.math.maxInt(i128)) continue;
                total += @max(0, t1 - t0);
                wakes += 1;
            }
        }
        s.* = @divTrunc(total, @as(i128, @intCast(wakes)));
    }
    return samples;
}

fn raiseNofile() void {
    var rl = posix.getrlimit(.NOFILE) catch return;
    rl.cur = rl.max;
    posix.setrlimit(.NOFILE, rl) catch {};
}

pub fn main() !void {
    raiseNofile();

    const idle_ns = [_]u32{ 0, 1000, 10000, 50000 };
    for (idle_ns) |n| {
        var buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&buf, "idle {d}", .{n});
        const s = try benchIdle(n);
        report(name, "/iter", &s);
    }

    const active_as = [_]u32{ 1, 64, 1000 };
    for (active_as) |a| {
        var buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&buf, "event {d}", .{a});
        const s = try benchEvent(a);
        report(name, "/event", &s);
    }
    for (active_as) |a| {
        var buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&buf, "active {d}", .{a});
        const s = try benchActive(a);
        report(name, "/event", &s);
    }

    for ([_]usize{ 1, 8 }) |p| {
        var buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&buf, "wake {d}", .{p});
        const s = try benchWake(p);
        report(name, "/wake", &s);
    }
}
