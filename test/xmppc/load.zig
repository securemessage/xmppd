//! xmppc load driver (T32) — drives N client sessions on ONE Engine/kqueue
//! loop against a live xmppd rig and reports the T222/T-BC27B154 gate
//! metrics: connections/sec, logins/sec (wall + pipeline), transport
//! bytes/session, max engine-loop iteration time, and process RSS/session.
//!
//! Uses only the public `xmppc` module API (same consumer contract as
//! xmppc-smoke). Build with `zig build xmppc-load` → zig-out/bin/xmppc-load.
//!
//! Phases:
//!   1. ramp   — register all N sessions, run the engine, wait until every
//!               session settled (established or login-phase close) or the
//!               deadline. Connects are issued in one burst; the server and
//!               kernel pace the actual ramp.
//!   2. hold   — keep everything up for -hold seconds while the driver
//!               thread posts -msg-rate aggregate stanzas/sec, each session
//!               messaging its own bound JID (server routes it right back,
//!               keeping rx and tx symmetric without cross-account fanout).
//!   3. report — one machine-readable `LOAD …` summary line.
//!
//! Usage:
//!   xmppc-load -host H -port P -user U -password W [-domain D]
//!              [-resource PREFIX] [-n N] [-hold S] [-msg-rate R]
//!              [-msg-size B] [-deadline S] [-quiet]
//!
//! Exit 0 when every session established and none died during the hold;
//! 1 otherwise. Login-phase failure reasons are aggregated in the summary.

const std = @import("std");
const xmppc = @import("xmppc");
const Engine = xmppc.Engine;
const Event = xmppc.Event;
const Handle = xmppc.Handle;

// ---------------------------------------------------------------------------
// CLI options
// ---------------------------------------------------------------------------

const Options = struct {
    host: []const u8 = "127.0.0.1",
    domain: []const u8 = "localhost",
    port: u16 = 15222,
    user: []const u8 = "alice@localhost",
    password: []const u8 = "pass1",
    resource: []const u8 = "load",
    count: usize = 1000,
    /// 0 = burst (all connects issued back to back). Otherwise sessions/sec:
    /// paces the startSession loop so a 1000+ SYN storm doesn't overflow the
    /// server's listen backlog before its accept loop drains it.
    connect_rate: u64 = 0,
    hold: u64 = 5,
    msg_rate: u64 = 0, // aggregate client-tx stanzas/sec during the hold
    msg_size: usize = 128, // <body> payload bytes
    deadline: u64 = 120,
    quiet: bool = false,

    fn parse(o: *Options, args: []const [:0]u8) !void {
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            const a = args[i];
            if (a.len < 2 or a[0] != '-') {
                std.debug.print("load: unexpected positional arg {s}\n", .{a});
                return error.BadOption;
            }
            var key: []const u8 = a[1..];
            if (std.mem.indexOfScalar(u8, key, '=')) |p| key = key[0..p];
            if (std.mem.eql(u8, key, "quiet")) {
                o.quiet = true;
                continue;
            }
            if (std.mem.eql(u8, key, "help") or std.mem.eql(u8, key, "h")) {
                std.debug.print(
                    "load: xmppc load driver — N sessions on one engine loop\n" ++
                        "  -host H / -port P    (default 127.0.0.1:15222)\n" ++
                        "  -domain D            (stream to=; default localhost)\n" ++
                        "  -user U -password W  (default alice@localhost/pass1; ALL\n" ++
                        "                        sessions share the account, resources\n" ++
                        "                        differentiate: <PREFIX>-0..N-1)\n" ++
                        "  -resource PREFIX     (default load)\n" ++
                        "  -n N                 (sessions; default 1000)\n" ++
                        "  -connect-rate R      (sessions/sec ramp pace; 0=burst default)\n" ++
                        "  -hold S              (seconds after all settled; default 5)\n" ++
                        "  -msg-rate R          (aggregate stanzas/sec during hold; 0=off)\n" ++
                        "  -msg-size B          (body payload bytes; default 128)\n" ++
                        "  -deadline S          (max seconds to reach all-settled)\n" ++
                        "  -quiet               (suppress per-second hold lines)\n",
                    .{},
                );
                return error.Help;
            }
            var val: []const u8 = "";
            if (std.mem.indexOfScalar(u8, a, '=')) |p| {
                val = a[p + 1 ..];
            } else {
                if (i + 1 >= args.len) {
                    std.debug.print("load: -{s} needs a value\n", .{key});
                    return error.BadOption;
                }
                i += 1;
                val = args[i];
            }
            if (std.mem.eql(u8, key, "host")) {
                o.host = val;
            } else if (std.mem.eql(u8, key, "domain")) {
                o.domain = val;
            } else if (std.mem.eql(u8, key, "port")) {
                o.port = try std.fmt.parseUnsigned(u16, val, 10);
            } else if (std.mem.eql(u8, key, "user")) {
                o.user = val;
            } else if (std.mem.eql(u8, key, "password")) {
                o.password = val;
            } else if (std.mem.eql(u8, key, "resource")) {
                o.resource = val;
            } else if (std.mem.eql(u8, key, "n")) {
                o.count = try std.fmt.parseUnsigned(usize, val, 10);
            } else if (std.mem.eql(u8, key, "connect-rate")) {
                o.connect_rate = try std.fmt.parseUnsigned(u64, val, 10);
            } else if (std.mem.eql(u8, key, "hold")) {
                o.hold = try std.fmt.parseUnsigned(u64, val, 10);
            } else if (std.mem.eql(u8, key, "msg-rate")) {
                o.msg_rate = try std.fmt.parseUnsigned(u64, val, 10);
            } else if (std.mem.eql(u8, key, "msg-size")) {
                o.msg_size = try std.fmt.parseUnsigned(usize, val, 10);
            } else if (std.mem.eql(u8, key, "deadline")) {
                o.deadline = try std.fmt.parseUnsigned(u64, val, 10);
            } else {
                std.debug.print("load: unknown option -{s}\n", .{key});
                return error.BadOption;
            }
        }
        if (o.count == 0) return error.BadOption;
    }
};

// ---------------------------------------------------------------------------
// RSS sampling (std.c has no getrusage for FreeBSD — extern it directly).
// ---------------------------------------------------------------------------

const Timeval = extern struct { sec: c_long, usec: c_long };
const Rusage = extern struct {
    utime: Timeval,
    stime: Timeval,
    maxrss: c_long, // KiB on FreeBSD; process high-water mark
    ixrss: c_long,
    idrss: c_long,
    isrss: c_long,
    minflt: c_long,
    majflt: c_long,
    nswap: c_long,
    inblock: c_long,
    oublock: c_long,
    msgsnd: c_long,
    msgrcv: c_long,
    nsignals: c_long,
    nvcsw: c_long,
    nivcsw: c_long,
};
extern "c" fn getrusage(who: c_int, usage: *Rusage) c_int;

fn maxRssKiB() i64 {
    var ru: Rusage = undefined;
    if (getrusage(0, &ru) != 0) return -1;
    return @intCast(ru.maxrss);
}

// ---------------------------------------------------------------------------
// Shared driver state. Written by engine-thread callbacks, read by the main
// thread — everything under g.lock.
// ---------------------------------------------------------------------------

var g = struct {
    lock: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    total: usize = 0,
    /// Sessions that reached their FIRST terminal state (established or a
    /// login-phase close). The ramp wait targets this.
    settled: usize = 0,
    established: usize = 0,
    failed: usize = 0, // login-phase closes
    post_closes: usize = 0, // established sessions that died later
    /// Per-slot-index flags / bound JID copies (driver-allocated).
    was_established: std.ArrayListUnmanaged(bool) = .{},
    jids: std.ArrayListUnmanaged(?[]u8) = .{},
    fail_reasons: std.StringHashMapUnmanaged(u64) = .{},
    first_fail: []const u8 = "",
    stanzas_rx: u64 = 0,
    stanzas_posted: u64 = 0,
    post_drops: u64 = 0,
    quiet: bool = false,
    /// Set by main right before the stopSession teardown: closes after this
    /// are our own, not load-phase failures.
    draining: bool = false,
}{};

fn slotEnsure(comptime T: type, list: *std.ArrayListUnmanaged(T), idx: usize, fill: T) !*T {
    while (list.items.len <= idx) try list.append(std.heap.c_allocator, fill);
    return &list.items[idx];
}

fn bumpReason(reason: []const u8) void {
    const copy = std.heap.c_allocator.dupe(u8, reason) catch return;
    const gop = g.fail_reasons.getOrPut(std.heap.c_allocator, copy) catch {
        std.heap.c_allocator.free(copy);
        return;
    };
    if (gop.found_existing) {
        std.heap.c_allocator.free(copy); // getOrPut retained the old key
        gop.value_ptr.* += 1;
    } else {
        // getOrPut leaves the value UNINITIALIZED on insertion.
        gop.value_ptr.* = 1;
        if (g.first_fail.len == 0) g.first_fail = copy;
    }
}

fn onEvent(ctx: ?*anyopaque, engine: *Engine, handle: Handle, ev: Event) void {
    _ = ctx;
    const idx: usize = @intCast(handle.index);
    switch (ev) {
        .established => {
            const session = engine.sessionAt(handle) orelse return;
            const jid_str: ?[]u8 = if (session.boundJid()) |j|
                std.fmt.allocPrint(std.heap.c_allocator, "{s}@{s}/{s}", .{ j.local, j.domain, j.resource }) catch null
            else
                null;
            g.lock.lock();
            defer g.lock.unlock();
            if (slotEnsure(bool, &g.was_established, idx, false)) |w| w.* = true else |_| {}
            if (slotEnsure(?[]u8, &g.jids, idx, null)) |jp| jp.* = jid_str else |_| {}
            g.established += 1;
            g.settled += 1;
            g.cond.signal();
        },
        .closed => |reason| {
            g.lock.lock();
            defer g.lock.unlock();
            const was = idx < g.was_established.items.len and g.was_established.items[idx];
            if (was) {
                if (!g.draining) g.post_closes += 1;
            } else {
                g.failed += 1;
                g.settled += 1;
                bumpReason(reason);
            }
            g.cond.signal();
        },
        .stanza => {
            g.lock.lock();
            g.stanzas_rx += 1;
            g.lock.unlock();
        },
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main() !void {
    var o = Options{};
    const args = try std.process.argsAlloc(std.heap.c_allocator);
    defer std.process.argsFree(std.heap.c_allocator, args);
    o.parse(args) catch |err| switch (err) {
        error.Help => std.c._exit(0),
        else => std.c._exit(2),
    };

    const rss_base = maxRssKiB();

    var engine = try Engine.init(std.heap.c_allocator);
    try engine.useTls(null); // lab rig on lo0: userland TLS (PR 296498)
    engine.default_tls_policy = .none;

    g.total = o.count;
    g.quiet = o.quiet;

    engine.setEventHandler(onEvent, null);

    // Register all N sessions BEFORE engine.run(): startSession mutates the
    // slot map, and the loop thread must not iterate it concurrently.
    var handles = try std.ArrayList(Handle).initCapacity(std.heap.c_allocator, o.count);
    defer handles.deinit(std.heap.c_allocator);
    const pace_start = std.time.nanoTimestamp();
    for (0..o.count) |i| {
        if (o.connect_rate > 0) {
            // Fixed-quantum pacing: sleep until the schedule slot for i+1.
            const due_ns = @divTrunc(@as(i128, @intCast(i + 1)) * std.time.ns_per_s, @as(i128, o.connect_rate));
            const target = pace_start + due_ns;
            const now = std.time.nanoTimestamp();
            if (target > now) std.Thread.sleep(@intCast(target - now));
        }
        const res = try std.fmt.allocPrint(std.heap.c_allocator, "{s}-{d}", .{ o.resource, i });
        defer std.heap.c_allocator.free(res);
        const h = engine.startSession(.{
            .host = o.host,
            .port = o.port,
            .domain = o.domain,
            .user = o.user,
            .password = o.password,
            .resource = res,
        }) catch |err| {
            std.debug.print("load: startSession {d}: {}\n", .{ i, err });
            std.c._exit(1);
        };
        handles.appendAssumeCapacity(h);
    }

    // End-to-end ramp clock starts when the FIRST connect is issued — paced
    // ramps include their issuance time in logins/sec-wall by design.
    const t_start = pace_start;
    try engine.run();

    // Ramp wait: every session settled, or the deadline expired.
    const deadline = t_start + @as(i128, o.deadline) * std.time.ns_per_s;
    g.lock.lock();
    while (g.settled < g.total) {
        const now = std.time.nanoTimestamp();
        if (now >= deadline) break;
        g.cond.timedWait(&g.lock, @intCast(deadline - now)) catch break;
    }
    const settled_established = g.established;
    const settled_failed = g.failed;
    g.lock.unlock();
    const t_settled = std.time.nanoTimestamp();

    const snap_ramp = engine.statsSnapshot();
    const ramp_wall_s = @as(f64, @floatFromInt(@max(1, t_settled - t_start))) / std.time.ns_per_s;
    const conn_s = rate(snap_ramp.connects_completed, snap_ramp.first_connect_ns, snap_ramp.last_connect_ns);
    const login_s_pipe = rate(snap_ramp.sessions_established, snap_ramp.first_established_ns, snap_ramp.last_established_ns);
    const login_s_wall = @as(f64, @floatFromInt(snap_ramp.sessions_established)) / ramp_wall_s;

    std.debug.print(
        "load: ramp t={d:.2}s established={d}/{d} failed={d} conn_per_s={d:.0} login_per_s_pipe={d:.0} login_per_s_wall={d:.0} bytes_rx={d} bytes_tx={d} stall_max_us={d} scram_derives={d} cache_hits={d}\n",
        .{ ramp_wall_s, settled_established, g.total, settled_failed, conn_s, login_s_pipe, login_s_wall, snap_ramp.bytes_rx, snap_ramp.bytes_tx, snap_ramp.max_iter_us, engine.scram_derives, engine.scram_cache_hits },
    );

    // Hold phase.
    const hold_start = std.time.nanoTimestamp();
    const hold_end = hold_start + @as(i128, o.hold) * std.time.ns_per_s;
    const body_pad = try std.heap.c_allocator.alloc(u8, o.msg_size);
    defer std.heap.c_allocator.free(body_pad);
    @memset(body_pad, 'x');
    var stanza_seq: u64 = 0;
    var posted_total: u64 = 0;
    var rr: usize = 0;
    var next_report = hold_start + std.time.ns_per_s;
    while (std.time.nanoTimestamp() < hold_end) {
        const now = std.time.nanoTimestamp();
        const due: u64 = @intFromFloat(@floor(@as(f64, @floatFromInt(now - hold_start)) / std.time.ns_per_s * @as(f64, @floatFromInt(o.msg_rate))));
        while (posted_total < due) : (posted_total += 1) {
            stanza_seq += 1;
            // Round-robin to the next established session.
            var tried: usize = 0;
            while (tried < handles.items.len) : (tried += 1) {
                const h = handles.items[rr % handles.items.len];
                rr +%= 1;
                const target: ?[]const u8 = blk: {
                    g.lock.lock();
                    defer g.lock.unlock();
                    break :blk if (h.index < g.jids.items.len) g.jids.items[@intCast(h.index)] else null;
                };
                const jid = target orelse continue;
                const stanza = std.fmt.allocPrint(std.heap.c_allocator, "<message id='l{d}' to='{s}'><body>{s}</body></message>", .{ stanza_seq, jid, body_pad }) catch continue;
                defer std.heap.c_allocator.free(stanza);
                engine.postStanza(h, stanza) catch {
                    g.lock.lock();
                    g.post_drops += 1;
                    g.lock.unlock();
                    break;
                };
                g.lock.lock();
                g.stanzas_posted += 1;
                g.lock.unlock();
                break;
            }
        }
        if (!g.quiet and now >= next_report) {
            next_report += std.time.ns_per_s;
            const snap = engine.statsSnapshot();
            g.lock.lock();
            std.debug.print("load: hold t={d:.1}s posted={d} rx={d} drops={d} stall_max_us={d}\n", .{ @as(f64, @floatFromInt(now - hold_start)) / std.time.ns_per_s, g.stanzas_posted, g.stanzas_rx, g.post_drops, snap.max_iter_us });
            g.lock.unlock();
        }
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }
    const hold_wall_s = @as(f64, @floatFromInt(std.time.nanoTimestamp() - hold_start)) / std.time.ns_per_s;

    const snap_end = engine.statsSnapshot();
    const rss_end = maxRssKiB();

    // Teardown: stop everything, wait for the engine to reap, join threads.
    g.lock.lock();
    g.draining = true;
    g.lock.unlock();
    for (handles.items) |h| engine.stopSession(h, "load-done");
    var tries: u32 = 0;
    while (engine.sessionCount() > 0 and tries < 1000) : (tries += 1)
        std.Thread.sleep(10 * std.time.ns_per_ms);
    engine.deinit();

    g.lock.lock();
    const est = g.established;
    const failed = g.failed;
    const post_closes = g.post_closes;
    const post_drops = g.post_drops;
    const stanzas_posted = g.stanzas_posted;
    const stanzas_rx = g.stanzas_rx;
    const first_fail = g.first_fail;
    g.lock.unlock();

    const n_est: u64 = @max(1, est);
    const ramp_bytes = snap_ramp.bytes_rx + snap_ramp.bytes_tx;
    const hold_bytes = (snap_end.bytes_rx + snap_end.bytes_tx) - ramp_bytes;
    const mem_est_bytes: i64 = if (rss_base >= 0 and rss_end >= rss_base)
        @divTrunc((rss_end - rss_base) * 1024, @as(i64, @intCast(n_est)))
    else
        -1;

    std.debug.print(
        "load: LOAD n={d} established={d} failed={d} post_closes={d} ramp_s={d:.2} conn_per_s={d:.0} login_per_s_pipe={d:.0} login_per_s_wall={d:.0} ramp_bytes_per_session={d} hold_s={d:.1} hold_posted={d} hold_rx={d} hold_drops={d} hold_bytes_per_session={d} stall_max_us={d} scram_derives={d} cache_hits={d} mem_bytes_per_session_est={d} first_fail={s}\n",
        .{ o.count, est, failed, post_closes, ramp_wall_s, conn_s, login_s_pipe, login_s_wall, @divTrunc(ramp_bytes, n_est), hold_wall_s, stanzas_posted, stanzas_rx, post_drops, @divTrunc(hold_bytes, n_est), snap_end.max_iter_us, engine.scram_derives, engine.scram_cache_hits, mem_est_bytes, first_fail },
    );

    var it = g.fail_reasons.iterator();
    while (it.next()) |e| std.debug.print("load: fail-reason {s} x{d}\n", .{ e.key_ptr.*, e.value_ptr.* });
    for (g.jids.items) |j| if (j) |s| std.heap.c_allocator.free(s);
    var rit = g.fail_reasons.keyIterator();
    while (rit.next()) |k| std.heap.c_allocator.free(k.*);
    std.c._exit(if (failed == 0 and post_closes == 0 and est == o.count) 0 else 1);
}

fn rate(count: u64, first_ns: u64, last_ns: u64) f64 {
    if (count == 0 or first_ns == 0 or last_ns <= first_ns) return @floatFromInt(count);
    return @as(f64, @floatFromInt(count)) / (@as(f64, @floatFromInt(last_ns - first_ns)) / std.time.ns_per_s);
}
