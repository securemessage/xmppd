//! xmppc load driver (T32/M2) — drives N client sessions on ONE Engine/kqueue
//! loop (or -engines shards) against a live xmppd rig and reports the
//! T222/T-BC27B154 gate metrics: connections/sec, logins/sec (wall +
//! pipeline), transport bytes/session, max engine-loop iteration time,
//! process RSS/session, plus per-scenario throughput, p50/p99/max latency
//! and true loss.
//!
//! Uses only the public `xmppc` module API (same consumer contract as
//! xmppc-smoke). Build with `zig build xmppc-load` → zig-out/bin/xmppc-load.
//!
//! Phases:
//!   1. ramp   — run the engine FIRST, then startSession at -connect-rate
//!               pacing (startSession is thread-safe; T237), waiting until
//!               every session settled (established or login-phase close) or
//!               the deadline. Pacing therefore spaces real protocol
//!               progress, not just connect issuance.
//!   2. join   — (muc only) every session joins the room; wait for all
//!               self-presences before traffic starts.
//!   3. hold   — keep everything up for -hold seconds while the scenario
//!               posts its traffic shape at -msg-rate aggregate stanzas/sec.
//!   4. drain  — -drain seconds for late delivery (slow readers re-arm their
//!               read interest here so their backlog lands before the
//!               report).
//!   5. report — one machine-readable `LOAD …` summary line plus scenario
//!               lines.
//!
//! Scenarios (-scenario chat|presence|muc|smstorm|slowread):
//!   chat      — <message> at msg-rate; -to self|peer|split picks the target
//!               (peer: i<->i+1, split: i -> i+count/2). Large stanzas are
//!               chat with -msg-size 8192..65536. Distinct-account logins
//!               are any scenario with -accounts N and -msg-rate 0.
//!   presence  — directed <presence> with cycling <show> at msg-rate.
//!   muc       — all N sessions join -room, then groupchat at msg-rate;
//!               fan-out completeness is counted per posted seq.
//!   smstorm   — chat traffic plus SM reconnects at -reconnect-rate
//!               sessions/sec (stop + start with sm_resume_id/h), reporting
//!               resumed vs fresh outcomes and resume latency.
//!   slowread  — the first -slow-readers sessions drop their read interest
//!               after establishment; everyone else messages them at
//!               msg-rate; at -drain the reads re-arm and rx is compared
//!               against posted (the silent-drop check).
//!
//! Usage:
//!   xmppc-load -host H -port P -user U -password W [-domain D]
//!              [-resource PREFIX] [-n N] [-scenario chat] [-accounts A]
//!              [-user-prefix P] [-hold S] [-msg-rate R] [-msg-size B]
//!              [-to self|peer|split] [-room J] [-reconnect-rate R]
//!              [-slow-readers S] [-drain S] [-deadline S] [-quiet]
//!
//! Exit 0 when every session established and none died outside expected
//! churn (smstorm stops, teardown); 1 otherwise. Login-phase failure
//! reasons are aggregated in the summary.

const std = @import("std");
const xmppc = @import("xmppc");
const Engine = xmppc.Engine;
const Event = xmppc.Event;
const Handle = xmppc.Handle;

// ---------------------------------------------------------------------------
// CLI options
// ---------------------------------------------------------------------------

const Scenario = enum { chat, presence, muc, smstorm, slowread };
const ToMode = enum { self, peer, split };

const Options = struct {
    host: []const u8 = "127.0.0.1",
    domain: []const u8 = "localhost",
    port: u16 = 15222,
    user: []const u8 = "alice@localhost",
    password: []const u8 = "pass1",
    resource: []const u8 = "load",
    count: usize = 1000,
    scenario: Scenario = .chat,
    /// Login distinct accounts: session i uses "<user_prefix>{i}@{domain}"
    /// (i mod accounts). 1 = all sessions share -user (old behavior).
    accounts: usize = 1,
    user_prefix: []const u8 = "m2u-",
    to_mode: ToMode = .self,
    room: []const u8 = "m2load@conference.localhost",
    /// 0 = burst (all connects issued back to back). Otherwise sessions/sec:
    /// paces the startSession loop so a 1000+ SYN storm doesn't overflow the
    /// server's listen backlog before its accept loop drains it.
    connect_rate: u64 = 0,
    hold: u64 = 5,
    msg_rate: u64 = 0, // aggregate client-tx stanzas/sec during the hold
    msg_size: usize = 128, // <body> payload bytes
    reconnect_rate: u64 = 0, // smstorm: resumed reconnects/sec during hold
    slow_readers: usize = 0, // slowread: sessions that stop reading after establishment
    deadline: u64 = 120,
    drain: u64 = 3, // post-hold drain window in seconds
    /// Shard sessions across this many Engine instances, each on its own
    /// thread (T-E232E8AE): proves the driver is never the bottleneck and
    /// its loop stalls are read per engine size, not amortised.
    engines: usize = 1,
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
                    "load: xmppc load driver, M2 scenario suite\n" ++
                        "  -host H / -port P    (default 127.0.0.1:15222)\n" ++
                        "  -domain D            (stream to=; default localhost)\n" ++
                        "  -user U -password W  (default alice@localhost/pass1)\n" ++
                        "  -accounts A          (distinct m2u-<i>@domain accounts; 1=one shared)\n" ++
                        "  -user-prefix P       (default m2u-)\n" ++
                        "  -resource PREFIX     (default load)\n" ++
                        "  -n N                 (sessions; default 1000; muc: occupants)\n" ++
                        "  -scenario S          (chat|presence|muc|smstorm|slowread)\n" ++
                        "  -connect-rate R      (sessions/sec ramp pace; 0=burst)\n" ++
                        "  -hold S              (seconds after all settled; default 5)\n" ++
                        "  -msg-rate R          (aggregate stanzas/sec during hold; 0=off)\n" ++
                        "  -msg-size B          (body payload bytes; default 128)\n" ++
                        "  -to M                (self|peer|split; chat+presence target rule)\n" ++
                        "  -room J              (muc room JID; default m2load@conference.localhost)\n" ++
                        "  -reconnect-rate R    (smstorm: SM resumes/sec; requires -scenario smstorm)\n" ++
                        "  -slow-readers S      (slowread: sessions that stop reading)\n" ++
                        "  -drain S             (post-hold drain window; default 3)\n" ++
                        "  -deadline S          (max seconds to reach all-settled)\n" ++
                        "  -engines E           (engine threads; sessions shard round-robin)\n" ++
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
            } else if (std.mem.eql(u8, key, "accounts")) {
                o.accounts = try std.fmt.parseUnsigned(usize, val, 10);
            } else if (std.mem.eql(u8, key, "user-prefix")) {
                o.user_prefix = val;
            } else if (std.mem.eql(u8, key, "scenario")) {
                if (std.meta.stringToEnum(Scenario, val)) |s| {
                    o.scenario = s;
                } else {
                    std.debug.print("load: unknown scenario {s}\n", .{val});
                    return error.BadOption;
                }
            } else if (std.mem.eql(u8, key, "to")) {
                if (std.meta.stringToEnum(ToMode, val)) |m| {
                    o.to_mode = m;
                } else {
                    std.debug.print("load: unknown -to mode {s}\n", .{val});
                    return error.BadOption;
                }
            } else if (std.mem.eql(u8, key, "room")) {
                o.room = val;
            } else if (std.mem.eql(u8, key, "connect-rate")) {
                o.connect_rate = try std.fmt.parseUnsigned(u64, val, 10);
            } else if (std.mem.eql(u8, key, "hold")) {
                o.hold = try std.fmt.parseUnsigned(u64, val, 10);
            } else if (std.mem.eql(u8, key, "msg-rate")) {
                o.msg_rate = try std.fmt.parseUnsigned(u64, val, 10);
            } else if (std.mem.eql(u8, key, "msg-size")) {
                o.msg_size = try std.fmt.parseUnsigned(usize, val, 10);
            } else if (std.mem.eql(u8, key, "reconnect-rate")) {
                o.reconnect_rate = try std.fmt.parseUnsigned(u64, val, 10);
            } else if (std.mem.eql(u8, key, "slow-readers")) {
                o.slow_readers = try std.fmt.parseUnsigned(usize, val, 10);
            } else if (std.mem.eql(u8, key, "drain")) {
                o.drain = try std.fmt.parseUnsigned(u64, val, 10);
            } else if (std.mem.eql(u8, key, "deadline")) {
                o.deadline = try std.fmt.parseUnsigned(u64, val, 10);
            } else if (std.mem.eql(u8, key, "engines")) {
                o.engines = try std.fmt.parseUnsigned(usize, val, 10);
                if (o.engines == 0) return error.BadOption;
            } else {
                std.debug.print("load: unknown option -{s}\n", .{key});
                return error.BadOption;
            }
        }
        if (o.count == 0 or o.engines == 0) return error.BadOption;
        if (o.accounts == 0) return error.BadOption;
        if (o.to_mode == .split and o.count < 2) return error.BadOption;
        if (o.scenario == .smstorm and o.reconnect_rate == 0) {
            std.debug.print("load: smstorm needs -reconnect-rate > 0\n", .{});
            return error.BadOption;
        }
        if (o.scenario == .slowread) {
            if (o.slow_readers == 0 or o.slow_readers >= o.count) {
                std.debug.print("load: slowread needs 0 < -slow-readers < -n\n", .{});
                return error.BadOption;
            }
        }
        if (o.scenario == .presence and o.to_mode == .self) {
            std.debug.print("load: presence needs -to peer or -to split\n", .{});
            return error.BadOption;
        }
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
// Shared driver state. Written by engine-thread callbacks and the main
// thread; everything under g.lock.
// ---------------------------------------------------------------------------

const SessRef = struct { eng: usize, h: Handle };

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
    /// Session handles by ramp position (storm reconnects replace in place).
    handles: std.ArrayListUnmanaged(SessRef) = .{},
    /// ramp keyOf -> position in handles (inserted at ramp time only).
    pos_of: std.AutoHashMapUnmanaged(usize, usize) = .{},
    jids: std.ArrayListUnmanaged(?[]u8) = .{}, // by keyOf(engine, index)
    was_established: std.ArrayListUnmanaged(bool) = .{},
    fail_reasons: std.StringHashMapUnmanaged(u64) = .{},
    first_fail: []const u8 = "",
    stanzas_rx: u64 = 0,
    stanzas_posted: u64 = 0,
    post_drops: u64 = 0,
    quiet: bool = false,
    /// Hold-phase accounting (T239): every posted stanza carries
    /// id="<pfx><seq>-<send_ns>". Received seqs mark a bitset (true loss is
    /// posted-minus-seen after the drain window); latencies are sampled for
    /// p50/p99/max. Sized up-front from -msg-rate x -hold; overflow seqs
    /// count received-but-untracked.
    seen: std.DynamicBitSetUnmanaged = .{},
    seen_bits: usize = 0,
    rx_distinct: u64 = 0, // seqs seen exactly once, by bitset
    rx_untracked: u64 = 0, // seqs past the bitset
    rx_dupes: u64 = 0,
    lat_ns: std.ArrayListUnmanaged(u64) = .{},
    /// Set by main right before the stopSession teardown: closes after this
    /// are our own, not load-phase failures.
    draining: bool = false,
    /// Per-phase establishment latency samples in ns (T-E232E8AE): tcp
    /// connect, stream-open to STARTTLS schedule, TLS handshake, SASL,
    /// bind+SM. Sampled at .established from Session milestones.
    ph_connect_ns: std.ArrayListUnmanaged(u64) = .{},
    ph_starttls_ns: std.ArrayListUnmanaged(u64) = .{},
    ph_tls_ns: std.ArrayListUnmanaged(u64) = .{},
    ph_sasl_ns: std.ArrayListUnmanaged(u64) = .{},
    ph_bind_ns: std.ArrayListUnmanaged(u64) = .{},
    // --- muc --------------------------------------------------------------
    muc_joined: usize = 0, // occupants with their self-presence observed
    muc_joined_bits: std.DynamicBitSetUnmanaged = .{}, // by handles position
    /// Per posted seq: how many copies arrived. Complete fan-out == the
    /// joined occupant count (or the server's observed reflection count).
    muc_fan: std.ArrayListUnmanaged(u32) = .{},
    // --- smstorm ----------------------------------------------------------
    /// new handle keyOf -> (handles pos, reconnect start ns), engine thread.
    storm_pending: std.AutoHashMapUnmanaged(usize, StormEntry) = .{},
    storm_attempts: u64 = 0,
    storm_resumed: u64 = 0,
    storm_fresh: u64 = 0, // re-established WITHOUT SM resume (server lost it)
    storm_sm_failed: u64 = 0, // explicit SM <failed/> on resume attempt
    storm_churn: u64 = 0, // closes caused by our own storm stops
    storm_lat_ns: std.ArrayListUnmanaged(u64) = .{},
    // --- slowread ---------------------------------------------------------
    /// fd of each slow reader at removeRead time, by handles position.
    sr_fd: std.ArrayListUnmanaged(std.posix.fd_t) = .{},
    sr_posted: u64 = 0, // stanzas addressed to slow readers
    sr_closed: u64 = 0, // slow readers the server closed
    /// smstorm stop gate: hold end as ns epoch; 0 until the hold starts.
    hold_end_ns: std.atomic.Value(i64) = .init(0),
}{};

const StormEntry = struct { pos: usize, t0_ns: u64 };

/// Parsed options, set once in main before any engine thread starts.
var opts: Options = .{};

/// Composite key for per-session driver state: handle.index spaces repeat
/// across engines (T-E232E8AE -engines), so key on (engine, index).
fn keyOf(engine_idx: usize, handle_index: u32) usize {
    return engine_idx * 65536 + @as(usize, handle_index);
}

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

/// Sample one session's establishment phase split from its milestones
/// (caller holds nothing; arrays append under g.lock).
fn samplePhases(session: anytype) void {
    const t0 = session.milestoneNs(.start);
    const t1 = session.milestoneNs(.tcp_up);
    const t2 = session.milestoneNs(.tls_start);
    const t3 = session.milestoneNs(.tls_done);
    const t4 = session.milestoneNs(.sasl_done);
    const t5 = session.milestoneNs(.established);
    if (t0 == 0) return;
    if (t1 > t0) g.ph_connect_ns.append(std.heap.c_allocator, t1 - t0) catch {};
    if (t2 > t1 and t1 > 0) g.ph_starttls_ns.append(std.heap.c_allocator, t2 - t1) catch {};
    if (t3 > t2 and t2 > 0) g.ph_tls_ns.append(std.heap.c_allocator, t3 - t2) catch {};
    if (t4 > t3 and t3 > 0) g.ph_sasl_ns.append(std.heap.c_allocator, t4 - t3) catch {};
    if (t5 > t4 and t4 > 0) g.ph_bind_ns.append(std.heap.c_allocator, t5 - t4) catch {};
}

fn pctUs(samples: []u64, num: usize, den: usize) u64 {
    if (samples.len == 0) return 0;
    std.mem.sort(u64, samples, {}, std.sort.asc(u64));
    return samples[@min(samples.len - 1, (samples.len * num) / den)] / 1000;
}

/// Track one received driver stanza by its id "<pfx><seq>-<send_ns>".
/// Returns true when the id parsed as a driver stanza.
fn trackRecv(prefix: u8, id: []const u8) bool {
    if (id.len < 3 or id[0] != prefix) return false;
    const dash = std.mem.indexOfScalar(u8, id, '-') orelse return false;
    const seq = std.fmt.parseUnsigned(u64, id[1..dash], 10) catch return false;
    const sent_ns = std.fmt.parseUnsigned(u64, id[dash + 1 ..], 10) catch return false;
    const now: u64 = @intCast(@max(0, std.time.nanoTimestamp()));
    if (prefix == 'm') {
        // muc: count every copy; latency sampled on the first one.
        if (seq < g.muc_fan.items.len) {
            const c = &g.muc_fan.items[seq - 1];
            if (c.* == 0 and now > sent_ns) g.lat_ns.append(std.heap.c_allocator, now - sent_ns) catch {};
            c.* +|= 1;
        } else {
            g.rx_untracked += 1;
        }
        return true;
    }
    if (seq < g.seen_bits) {
        if (g.seen.isSet(@intCast(seq))) {
            g.rx_dupes += 1;
        } else {
            g.seen.set(@intCast(seq));
            g.rx_distinct += 1;
            if (now > sent_ns) g.lat_ns.append(std.heap.c_allocator, now - sent_ns) catch {};
        }
    } else {
        g.rx_untracked += 1;
    }
    return true;
}

fn onEvent(ctx: ?*anyopaque, engine: *Engine, handle: Handle, ev: Event) void {
    const engine_idx: usize = if (ctx) |c| @intFromPtr(c) else 0;
    const k = keyOf(engine_idx, handle.index);
    switch (ev) {
        .established => {
            const session = engine.sessionAt(handle) orelse return;
            const jid_str: ?[]u8 = if (session.boundJid()) |j|
                std.fmt.allocPrint(std.heap.c_allocator, "{s}@{s}/{s}", .{ j.local, j.domain, j.resource }) catch null
            else
                null;
            g.lock.lock();
            samplePhases(session);
            if (slotEnsure(bool, &g.was_established, k, false)) |w| w.* = true else |_| {}
            if (slotEnsure(?[]u8, &g.jids, k, null)) |jp| jp.* = jid_str else |_| {}
            g.established += 1;
            g.settled += 1;
            g.cond.signal();
            const pos_opt = g.pos_of.get(k);
            var storm_entry: ?StormEntry = null;
            if (opts.scenario == .smstorm) {
                if (g.storm_pending.fetchRemove(k)) |kv| storm_entry = kv.value;
            }
            if (storm_entry) |se| {
                const now: u64 = @intCast(@max(0, std.time.nanoTimestamp()));
                if (now > se.t0_ns) g.storm_lat_ns.append(std.heap.c_allocator, now - se.t0_ns) catch {};
                if (session.smResumed()) g.storm_resumed += 1 else g.storm_fresh += 1;
            }
            const slow_pos: ?usize = if (opts.scenario == .slowread) pos_opt else null;
            g.lock.unlock();

            if (opts.scenario == .muc) {
                // Join right away; the join wait happens after the ramp.
                if (pos_opt) |pos| {
                    const stanza = std.fmt.allocPrint(std.heap.c_allocator, "<presence to='{s}/n{d}'/>", .{ opts.room, pos }) catch return;
                    defer std.heap.c_allocator.free(stanza);
                    engine.postStanza(handle, stanza) catch {};
                }
            }
            if (slow_pos) |pos| {
                if (pos < opts.slow_readers) {
                    // Slow reader: drop read interest so its receive queue
                    // fills; re-armed during the drain phase.
                    if (session.tport) |tp| {
                        const fd = tp.fd();
                        engine.removeRead(fd);
                        g.lock.lock();
                        if (slotEnsure(std.posix.fd_t, &g.sr_fd, pos, -1)) |fp| fp.* = fd else |_| {}
                        g.lock.unlock();
                    }
                }
            }
        },
        .closed => |reason| {
            g.lock.lock();
            defer g.lock.unlock();
            const was = k < g.was_established.items.len and g.was_established.items[k];
            if (was) {
                if (std.mem.eql(u8, reason, "smstorm")) {
                    g.storm_churn += 1;
                } else if (!g.draining) {
                    g.post_closes += 1;
                    if (opts.scenario == .slowread) {
                        if (g.pos_of.get(k)) |pos| {
                            if (pos < opts.slow_readers) g.sr_closed += 1;
                        }
                    }
                }
            } else {
                g.failed += 1;
                g.settled += 1;
                bumpReason(reason);
            }
            g.cond.signal();
        },
        .stanza => |st| {
            g.lock.lock();
            defer g.lock.unlock();
            g.stanzas_rx += 1;
            // Driver stanzas carry id="<pfx><seq>-<send_ns>" (T239).
            const id = st.id;
            if (st.kind == .message and id.len > 0 and (id[0] == 'l' or id[0] == 's')) {
                _ = trackRecv(id[0], id);
            } else if (st.kind == .presence and id.len > 0 and id[0] == 'p') {
                _ = trackRecv('p', id);
            } else if (st.kind == .message and id.len > 0 and id[0] == 'm') {
                // groupchat reflections only (to= sender may see errors
                // from the bare room JID; those carry our id but are not
                // fan-out, filter by from == room/<nick>).
                if (st.from.len > opts.room.len + 1 and std.mem.startsWith(u8, st.from, opts.room) and st.from[opts.room.len] == '/') {
                    _ = trackRecv('m', id);
                }
            }
            // muc join: self-presence is the room's echo of our join.
            // Count once per occupant (later presence updates re-match).
            if (opts.scenario == .muc and st.kind == .presence) {
                if (g.pos_of.get(k)) |pos| {
                    var nick_buf: [32]u8 = undefined;
                    const want_suffix = std.fmt.bufPrint(&nick_buf, "/n{d}", .{pos}) catch "";
                    if (want_suffix.len > 0 and std.mem.endsWith(u8, st.from, want_suffix) and
                        std.mem.startsWith(u8, st.from, opts.room) and
                        pos < g.muc_joined_bits.capacity() and !g.muc_joined_bits.isSet(pos))
                    {
                        g.muc_joined_bits.set(pos);
                        g.muc_joined += 1;
                        g.cond.signal();
                    }
                }
            }
        },
        .sm_failed => |dropped| {
            g.lock.lock();
            defer g.lock.unlock();
            g.storm_sm_failed += 1;
            _ = dropped;
        },
    }
}

// ---------------------------------------------------------------------------
// smstorm: paced SM reconnects, executed on each engine's own thread via a
// recurring consumer timer (100 ms quantum).
// ---------------------------------------------------------------------------

const StormCtx = struct {
    engine_idx: usize,
    eng: *Engine,
    rr: usize = 0,
    due_accum: f64 = 0,
};

fn stormTick(ctx: ?*anyopaque, eng: *Engine) void {
    const sc: *StormCtx = @ptrCast(@alignCast(ctx.?));
    // The storm runs during the hold only; hold_end_ns == 0 until set.
    const hold_end = g.hold_end_ns.load(.acquire);
    if (hold_end != 0 and std.time.nanoTimestamp() >= hold_end) return;
    const per_tick = @as(f64, @floatFromInt(opts.reconnect_rate)) * 0.1 / @as(f64, @floatFromInt(opts.engines));
    sc.due_accum += per_tick;
    while (sc.due_accum >= 1.0) {
        sc.due_accum -= 1.0;
        stormOne(sc, eng);
    }
    // Re-arm the next tick. Errors here just end the storm for this engine.
    _ = eng.schedule(100, stormTick, ctx) catch {};
}

fn stormOne(sc: *StormCtx, eng: *Engine) void {
    g.lock.lock();
    const total = g.handles.items.len;
    if (total == 0) {
        g.lock.unlock();
        return;
    }
    // Next session on this engine without an in-flight reconnect.
    var tries: usize = 0;
    var pos: usize = 0;
    var found = false;
    while (tries < total) : (tries += 1) {
        sc.rr = (sc.rr + 1) % total;
        const ref = g.handles.items[sc.rr];
        if (ref.eng != sc.engine_idx) continue;
        const k = keyOf(ref.eng, ref.h.index);
        if (g.storm_pending.contains(k)) continue;
        pos = sc.rr;
        found = true;
        break;
    }
    if (!found) {
        g.lock.unlock();
        return;
    }
    const ref = g.handles.items[pos];
    const user = accountUser(std.heap.c_allocator, pos) catch {
        g.lock.unlock();
        return;
    };
    const res = std.fmt.allocPrint(std.heap.c_allocator, "{s}-{d}", .{ opts.resource, pos }) catch {
        std.heap.c_allocator.free(user);
        g.lock.unlock();
        return;
    };
    g.lock.unlock();
    defer std.heap.c_allocator.free(user);
    defer std.heap.c_allocator.free(res);

    // Snapshot the SM resume coordinate from the live session.
    const session = eng.sessionAt(ref.h) orelse return;
    if (!session.smEnabled()) return;
    var id_buf: [64]u8 = undefined;
    const sm_id = session.smId();
    if (sm_id.len == 0 or sm_id.len > id_buf.len) return;
    @memcpy(id_buf[0..sm_id.len], sm_id);
    const sm_h = session.smH();

    eng.stopSession(ref.h, "smstorm");
    const new_h = eng.startSession(.{
        .host = opts.host,
        .port = opts.port,
        .domain = opts.domain,
        .user = user,
        .password = opts.password,
        .resource = res,
        .sm_resume_id = id_buf[0..sm_id.len],
        .sm_resume_h = sm_h,
    }) catch return;
    g.lock.lock();
    g.handles.items[pos] = .{ .eng = sc.engine_idx, .h = new_h };
    g.storm_pending.put(std.heap.c_allocator, keyOf(sc.engine_idx, new_h.index), .{
        .pos = pos,
        .t0_ns = @intCast(@max(0, std.time.nanoTimestamp())),
    }) catch {};
    g.storm_attempts += 1;
    g.lock.unlock();
}

/// Account login for handles position pos (distinct-account mode).
fn accountUser(alloc: std.mem.Allocator, pos: usize) ![]u8 {
    if (opts.accounts <= 1) return alloc.dupe(u8, opts.user);
    return std.fmt.allocPrint(alloc, "{s}{d}@{s}", .{ opts.user_prefix, pos % opts.accounts, opts.domain });
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
    opts = o;

    const rss_base = maxRssKiB();

    const engines = try std.heap.c_allocator.alloc(Engine, o.engines);
    for (engines, 0..) |*e, ei| {
        e.* = try Engine.init(std.heap.c_allocator);
        try e.useTls(null); // lab rig on lo0: userland TLS (PR 296498)
        e.default_tls_policy = .none;
        // ctx = engine ordinal for the composite key (small int in a ptr).
        e.setEventHandler(onEvent, @ptrFromInt(ei));
    }

    g.total = o.count;
    g.quiet = o.quiet;
    if (o.scenario == .muc) {
        g.muc_joined_bits = try std.DynamicBitSetUnmanaged.initEmpty(std.heap.c_allocator, o.count);
    }
    defer g.muc_joined_bits.deinit(std.heap.c_allocator);

    // Sessions are started at the paced rate WHILE the engines run
    // (startSession is thread-safe, T237), sharded round-robin across the
    // -engines loops so the driver's own thread is provably not the
    // bottleneck (T-E232E8AE): stall_max_us is read per engine size below.
    try g.handles.ensureTotalCapacity(std.heap.c_allocator, o.count);
    const pace_start = std.time.nanoTimestamp();
    for (0..o.count) |i| {
        if (o.connect_rate > 0) {
            // Fixed-quantum pacing: sleep until the schedule slot for i+1.
            const due_ns = @divTrunc(@as(i128, @intCast(i + 1)) * std.time.ns_per_s, @as(i128, o.connect_rate));
            const target = pace_start + due_ns;
            const now = std.time.nanoTimestamp();
            if (target > now) std.Thread.sleep(@intCast(target - now));
        }
        const ei = i % o.engines;
        const eng = &engines[ei];
        const res = try std.fmt.allocPrint(std.heap.c_allocator, "{s}-{d}", .{ o.resource, i });
        defer std.heap.c_allocator.free(res);
        const user = try accountUser(std.heap.c_allocator, i);
        defer std.heap.c_allocator.free(user);
        const h = eng.startSession(.{
            .host = o.host,
            .port = o.port,
            .domain = o.domain,
            .user = user,
            .password = o.password,
            .resource = res,
        }) catch |err| {
            std.debug.print("load: startSession {d}: {}\n", .{ i, err });
            std.c._exit(1);
        };
        g.lock.lock();
        g.handles.appendAssumeCapacity(.{ .eng = ei, .h = h });
        g.pos_of.put(std.heap.c_allocator, keyOf(ei, h.index), i) catch {};
        g.lock.unlock();
        // run() exits when the live-session count reaches zero: spin each
        // engine up once its first session exists.
        if (i < o.engines) try eng.run();
    }

    // End-to-end ramp clock starts when the FIRST connect is issued — paced
    // ramps include their issuance time in logins/sec-wall by design.
    const t_start = pace_start;

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

    const snap_ramp = aggStats(engines);
    const ramp_wall_s = @as(f64, @floatFromInt(@max(1, t_settled - t_start))) / std.time.ns_per_s;
    const conn_s = rate(snap_ramp.connects_completed, snap_ramp.first_connect_ns, snap_ramp.last_connect_ns);
    const login_s_pipe = rate(snap_ramp.sessions_established, snap_ramp.first_established_ns, snap_ramp.last_established_ns);
    const login_s_wall = @as(f64, @floatFromInt(snap_ramp.sessions_established)) / ramp_wall_s;

    std.debug.print(
        "load: ramp t={d:.2}s established={d}/{d} failed={d} conn_per_s={d:.0} login_per_s_pipe={d:.0} login_per_s_wall={d:.0} bytes_rx={d} bytes_tx={d} stall_max_us={d} scram_derives={d} cache_hits={d}\n",
        .{ ramp_wall_s, settled_established, g.total, settled_failed, conn_s, login_s_pipe, login_s_wall, snap_ramp.bytes_rx, snap_ramp.bytes_tx, snap_ramp.max_iter_us, scramTotal(engines), hitsTotal(engines) },
    );

    // MUC join phase: hold traffic must start only after every occupant is
    // joined, or early groupchat draws error replies and pollutes fan-out.
    if (o.scenario == .muc) {
        const join_deadline = std.time.nanoTimestamp() + 10 * std.time.ns_per_s;
        g.lock.lock();
        while (g.muc_joined < settled_established) {
            const now = std.time.nanoTimestamp();
            if (now >= join_deadline) break;
            g.cond.timedWait(&g.lock, @intCast(join_deadline - now)) catch break;
        }
        const joined = g.muc_joined;
        g.lock.unlock();
        std.debug.print("load: muc join joined={d}/{d}\n", .{ joined, settled_established });
    }

    // Hold phase.
    const hold_start = std.time.nanoTimestamp();
    const hold_end = hold_start + @as(i128, o.hold) * std.time.ns_per_s;
    g.hold_end_ns.store(@intCast(hold_end), .release);
    const body_pad = try std.heap.c_allocator.alloc(u8, o.msg_size);
    defer std.heap.c_allocator.free(body_pad);
    @memset(body_pad, 'x');
    // T239: message ids carry their send sequence and timestamp so true
    // loss (posted minus seen) separates from mere late delivery.
    {
        const bits: usize = @intCast(o.msg_rate * o.hold * 2 + 4096);
        g.seen = try std.DynamicBitSetUnmanaged.initEmpty(std.heap.c_allocator, bits);
        g.seen_bits = bits;
    }
    defer g.seen.deinit(std.heap.c_allocator);
    defer g.lat_ns.deinit(std.heap.c_allocator);
    if (o.scenario == .muc) {
        const bits: usize = @intCast(o.msg_rate * o.hold * 2 + 4096);
        try g.muc_fan.ensureTotalCapacity(std.heap.c_allocator, bits);
        for (0..bits) |_| g.muc_fan.appendAssumeCapacity(0);
    }
    defer g.muc_fan.deinit(std.heap.c_allocator);

    // smstorm: one recurring timer per engine runs reconnects on its thread.
    var storm_ctxs: ?[]StormCtx = null;
    if (o.scenario == .smstorm) {
        storm_ctxs = try std.heap.c_allocator.alloc(StormCtx, o.engines);
        for (storm_ctxs.?, 0..) |*sc, ei| {
            sc.* = .{ .engine_idx = ei, .eng = &engines[ei] };
            _ = engines[ei].schedule(100, stormTick, sc) catch {};
        }
    }
    defer if (storm_ctxs) |sc| std.heap.c_allocator.free(sc);

    var stanza_seq: u64 = 0;
    var posted_total: u64 = 0;
    var rr: usize = 0;
    var next_report = hold_start + std.time.ns_per_s;
    while (std.time.nanoTimestamp() < hold_end) {
        const now = std.time.nanoTimestamp();
        const due: u64 = @intFromFloat(@floor(@as(f64, @floatFromInt(now - hold_start)) / std.time.ns_per_s * @as(f64, @floatFromInt(o.msg_rate))));
        while (posted_total < due) : (posted_total += 1) {
            stanza_seq += 1;
            // Round-robin to the next eligible sender session.
            var tried: usize = 0;
            var sent = false;
            while (tried < o.count) : (tried += 1) {
                rr +%= 1;
                const sender_pos = rr % o.count;
                if (o.scenario == .slowread and sender_pos < o.slow_readers) continue;
                g.lock.lock();
                const ref = g.handles.items[sender_pos];
                g.lock.unlock();
                const stanza = buildTraffic(&o, body_pad, stanza_seq, sender_pos) orelse continue;
                defer std.heap.c_allocator.free(stanza);
                engines[ref.eng].postStanza(ref.h, stanza) catch {
                    g.lock.lock();
                    g.post_drops += 1;
                    g.lock.unlock();
                    sent = true;
                    break;
                };
                g.lock.lock();
                g.stanzas_posted += 1;
                if (o.scenario == .slowread) g.sr_posted += 1;
                g.lock.unlock();
                sent = true;
                break;
            }
            if (!sent) stanza_seq -= 1; // budget slot unused: no established sender
        }
        if (!g.quiet and now >= next_report) {
            next_report += std.time.ns_per_s;
            const snap = aggStats(engines);
            g.lock.lock();
            std.debug.print("load: hold t={d:.1}s posted={d} rx={d} drops={d} stall_max_us={d}\n", .{ @as(f64, @floatFromInt(now - hold_start)) / std.time.ns_per_s, g.stanzas_posted, g.stanzas_rx, g.post_drops, snap.max_iter_us });
            g.lock.unlock();
        }
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }
    const hold_wall_s = @as(f64, @floatFromInt(std.time.nanoTimestamp() - hold_start)) / std.time.ns_per_s;

    // Drain window (T239): late deliveries land here. slowread re-arms the
    // stalled readers at its start so their backlog arrives in time.
    if (o.scenario == .slowread) {
        g.lock.lock();
        for (0..o.slow_readers) |pos| {
            const fd: std.posix.fd_t = if (pos < g.sr_fd.items.len) g.sr_fd.items[pos] else -1;
            const ref = g.handles.items[pos];
            g.lock.unlock();
            if (fd >= 0) engines[ref.eng].addRead(fd, ref.h);
            g.lock.lock();
        }
        g.lock.unlock();
    }
    const drain_end = std.time.nanoTimestamp() + @as(i128, o.drain) * std.time.ns_per_s;
    while (std.time.nanoTimestamp() < drain_end) std.Thread.sleep(10 * std.time.ns_per_ms);

    const snap_end = aggStats(engines);
    const rss_end = maxRssKiB();

    // Teardown: stop everything, wait for the engines to reap, join threads.
    g.lock.lock();
    g.draining = true;
    g.lock.unlock();
    for (g.handles.items) |ref| engines[ref.eng].stopSession(ref.h, "load-done");
    var tries: u32 = 0;
    while (liveTotal(engines) > 0 and tries < 1000) : (tries += 1) {
        std.Thread.sleep(10 * std.time.ns_per_ms);
        // Teardown forensics: once per second while sessions linger, show
        // the fail/reap/drop counters (T237/T244 hang diagnostics).
        if (tries % 100 == 99) {
            const st = aggStats(engines);
            std.debug.print("load: teardown live={d} fails={d} reaped={d} stop_drops={d} posted={d} drained={d} wk_wr={d} wk_rd={d}\n", .{ liveTotal(engines), st.sessions_failed, st.sessions_reaped, st.stops_dropped, st.cmds_posted, st.cmds_drained, st.wakes_written, st.wakes_read });
        }
    }
    for (engines) |*e| e.deinit();

    g.lock.lock();
    const est = g.established;
    const failed = g.failed;
    const post_closes = g.post_closes;
    const post_drops = g.post_drops;
    const stanzas_posted = g.stanzas_posted;
    const first_fail = g.first_fail;
    const rx_distinct = g.rx_distinct + g.rx_untracked;
    const rx_dupes = g.rx_dupes;
    // Scenario-aware loss: muc traffic lands in muc_fan, not the seen bitset.
    var hold_lost: u64 = 0;
    if (o.scenario == .muc) {
        const np: usize = @intCast(@min(stanzas_posted, g.muc_fan.items.len));
        for (g.muc_fan.items[0..np]) |c| {
            if (c == 0) hold_lost += 1;
        }
    } else {
        hold_lost = if (stanzas_posted > rx_distinct) stanzas_posted - rx_distinct else 0;
    }
    const stanzas_rx = g.stanzas_rx;
    g.lock.unlock();

    var lat_p50_us: u64 = 0;
    var lat_p99_us: u64 = 0;
    var lat_max_us: u64 = 0;
    {
        g.lock.lock();
        defer g.lock.unlock();
        const n = g.lat_ns.items.len;
        if (n > 0) {
            std.mem.sort(u64, g.lat_ns.items, {}, std.sort.asc(u64));
            lat_p50_us = g.lat_ns.items[n / 2] / 1000;
            lat_p99_us = g.lat_ns.items[@min(n - 1, (n * 99) / 100)] / 1000;
            lat_max_us = g.lat_ns.items[n - 1] / 1000;
        }
    }

    const n_est: u64 = @max(1, est);
    const ramp_bytes = snap_ramp.bytes_rx + snap_ramp.bytes_tx;
    const hold_bytes = (snap_end.bytes_rx + snap_end.bytes_tx) - ramp_bytes;
    const mem_est_bytes: i64 = if (rss_base >= 0 and rss_end >= rss_base)
        @divTrunc((rss_end - rss_base) * 1024, @as(i64, @intCast(n_est)))
    else
        -1;

    std.debug.print(
        "load: LOAD scenario={s} n={d} accounts={d} established={d} failed={d} post_closes={d} ramp_s={d:.2} conn_per_s={d:.0} login_per_s_pipe={d:.0} login_per_s_wall={d:.0} ramp_bytes_per_session={d} hold_s={d:.1} hold_posted={d} hold_rx={d} hold_rx_distinct={d} hold_dupes={d} hold_lost={d} hold_drops={d} lat_p50_us={d} lat_p99_us={d} lat_max_us={d} hold_bytes_per_session={d} stall_max_us={d} scram_derives={d} cache_hits={d} mem_bytes_per_session_est={d} first_fail={s}\n",
        .{ @tagName(o.scenario), o.count, o.accounts, est, failed, post_closes, ramp_wall_s, conn_s, login_s_pipe, login_s_wall, @divTrunc(ramp_bytes, n_est), hold_wall_s, stanzas_posted, stanzas_rx, rx_distinct, rx_dupes, hold_lost, post_drops, lat_p50_us, lat_p99_us, lat_max_us, @divTrunc(hold_bytes, n_est), snap_end.max_iter_us, scramTotal(engines), hitsTotal(engines), mem_est_bytes, first_fail },
    );

    // Scenario lines.
    reportScenario(&o);

    // Per-phase establishment split (T-E232E8AE), one line per phase:
    // where ramp seconds actually go (connect / STARTTLS / TLS / SASL /
    // bind+SM).
    g.lock.lock();
    const ph: [5]struct { n: []const u8, s: []u64 } = .{
        .{ .n = "connect", .s = g.ph_connect_ns.items },
        .{ .n = "starttls", .s = g.ph_starttls_ns.items },
        .{ .n = "tls", .s = g.ph_tls_ns.items },
        .{ .n = "sasl", .s = g.ph_sasl_ns.items },
        .{ .n = "bind+sm", .s = g.ph_bind_ns.items },
    };
    for (ph) |p| {
        std.debug.print("load: phase {s} n={d} p50_us={d} p99_us={d} max_us={d}\n", .{ p.n, p.s.len, pctUs(p.s, 1, 2), pctUs(p.s, 99, 100), blk: {
            if (p.s.len == 0) break :blk 0;
            std.mem.sort(u64, p.s, {}, std.sort.asc(u64));
            break :blk p.s[p.s.len - 1] / 1000;
        } });
    }
    g.lock.unlock();

    var it = g.fail_reasons.iterator();
    while (it.next()) |e| std.debug.print("load: fail-reason {s} x{d}\n", .{ e.key_ptr.*, e.value_ptr.* });
    for (g.jids.items) |j| if (j) |s| std.heap.c_allocator.free(s);
    var rit = g.fail_reasons.keyIterator();
    while (rit.next()) |k| std.heap.c_allocator.free(k.*);
    // smstorm re-establishments count above o.count; every session must
    // establish at least once, and no session may die outside churn.
    std.c._exit(if (failed == 0 and post_closes == 0 and est >= o.count) 0 else 1);
}

/// Build the hold-phase stanza for this scenario/sender. Returns null when
/// the message has no valid target right now (session not established).
/// seq/ns go into the id so receivers can track loss and latency (T239).
fn buildTraffic(o: *const Options, body_pad: []u8, seq: u64, sender_pos: usize) ?[]u8 {
    const send_ns: u64 = @intCast(@max(0, std.time.nanoTimestamp()));
    // id prefix marks the traffic shape for rx accounting.
    const prefix: u8 = switch (o.scenario) {
        .chat, .smstorm => 'l',
        .presence => 'p',
        .muc => 'm',
        .slowread => 's',
    };
    // Target JID (or room). Lookups under the lock; the stanza build itself
    // happens after unlock to keep the critical section short.
    g.lock.lock();
    const target: ?[]const u8 = switch (o.scenario) {
        .muc => o.room,
        .slowread => blk: {
            // Round-robin over the slow readers; the sender position selects.
            const p = sender_pos % o.slow_readers;
            const tref = g.handles.items[p];
            const jk = keyOf(tref.eng, tref.h.index);
            break :blk if (jk < g.jids.items.len) g.jids.items[jk] else null;
        },
        else => blk: {
            var tpos = sender_pos;
            switch (o.to_mode) {
                .self => {},
                .peer => tpos = if (sender_pos % 2 == 0) sender_pos + 1 else sender_pos - 1,
                .split => tpos = (sender_pos + o.count / 2) % o.count,
            }
            if (tpos >= o.count) break :blk null;
            const tref = g.handles.items[tpos];
            const jk = keyOf(tref.eng, tref.h.index);
            break :blk if (jk < g.jids.items.len) g.jids.items[jk] else null;
        },
    };
    g.lock.unlock();
    const jid = target orelse return null;

    return switch (o.scenario) {
        .presence => blk: {
            const shows = [_][]const u8{ "chat", "away", "xa", "dnd" };
            const stanza = std.fmt.allocPrint(std.heap.c_allocator, "<presence to='{s}' id='{c}{d}-{d}'><show>{s}</show></presence>", .{ jid, prefix, seq, send_ns, shows[@as(usize, @intCast(seq % shows.len))] }) catch return null;
            break :blk stanza;
        },
        .muc => std.fmt.allocPrint(std.heap.c_allocator, "<message type='groupchat' to='{s}' id='m{d}-{d}'><body>{s}</body></message>", .{ jid, seq, send_ns, body_pad }) catch null,
        else => std.fmt.allocPrint(std.heap.c_allocator, "<message id='{c}{d}-{d}' to='{s}'><body>{s}</body></message>", .{ prefix, seq, send_ns, jid, body_pad }) catch null,
    };
}

fn reportScenario(o: *const Options) void {
    switch (o.scenario) {
        .muc => {
            g.lock.lock();
            defer g.lock.unlock();
            var zero: u64 = 0;
            var observed_max: u32 = 0;
            var rx_copies: u64 = 0;
            const posted: usize = @intCast(@min(g.stanzas_posted, g.muc_fan.items.len));
            const fan = g.muc_fan.items[0..posted];
            for (fan) |c| {
                rx_copies += c;
                observed_max = @max(observed_max, c);
                if (c == 0) zero += 1;
            }
            // Completeness counts against the server's observed fan-out
            // (reflection may or may not include the original sender).
            var complete: u64 = 0;
            var partial: u64 = 0;
            for (fan) |c| {
                if (c == 0) continue;
                if (observed_max > 0 and c >= observed_max) complete += 1 else partial += 1;
            }
            std.debug.print("load: muc occupants={d} joined={d} posted={d} copies_rx={d} fanout_observed_max={d} complete={d} partial={d} zero={d}\n", .{ o.count, g.muc_joined, posted, rx_copies, observed_max, complete, partial, zero });
        },
        .smstorm => {
            g.lock.lock();
            defer g.lock.unlock();
            const n = g.storm_lat_ns.items.len;
            var p50: u64 = 0;
            var p99: u64 = 0;
            var mx: u64 = 0;
            if (n > 0) {
                std.mem.sort(u64, g.storm_lat_ns.items, {}, std.sort.asc(u64));
                p50 = g.storm_lat_ns.items[n / 2] / 1000;
                p99 = g.storm_lat_ns.items[@min(n - 1, (n * 99) / 100)] / 1000;
                mx = g.storm_lat_ns.items[n - 1] / 1000;
            }
            std.debug.print("load: smstorm attempts={d} resumed={d} fresh_no_resume={d} sm_failed={d} churn_closes={d} resume_lat_p50_us={d} p99_us={d} max_us={d}\n", .{ g.storm_attempts, g.storm_resumed, g.storm_fresh, g.storm_sm_failed, g.storm_churn, p50, p99, mx });
        },
        .slowread => {
            g.lock.lock();
            defer g.lock.unlock();
            const lost = if (g.sr_posted > g.rx_distinct) g.sr_posted - g.rx_distinct else 0;
            std.debug.print("load: slowread slow_readers={d} posted_to_slow={d} rx_distinct={d} lost={d} slow_closed={d}\n", .{ o.slow_readers, g.sr_posted, g.rx_distinct, lost, g.sr_closed });
        },
        else => {},
    }
}

fn rate(count: u64, first_ns: u64, last_ns: u64) f64 {
    if (count == 0 or first_ns == 0 or last_ns <= first_ns) return @floatFromInt(count);
    return @as(f64, @floatFromInt(count)) / (@as(f64, @floatFromInt(last_ns - first_ns)) / std.time.ns_per_s);
}

/// Cross-engine aggregation (T-E232E8AE): sums for counters, max for stall,
/// min/max endpoints for the rate windows.
fn aggStats(engines: []Engine) Engine.StatsFlat {
    var a = Engine.StatsFlat{};
    for (engines) |*e| {
        const s = e.statsSnapshot();
        a.connects_completed += s.connects_completed;
        a.sessions_established += s.sessions_established;
        a.bytes_rx += s.bytes_rx;
        a.bytes_tx += s.bytes_tx;
        a.max_iter_us = @max(a.max_iter_us, s.max_iter_us);
        a.first_connect_ns = minNonzero(a.first_connect_ns, s.first_connect_ns);
        a.last_connect_ns = @max(a.last_connect_ns, s.last_connect_ns);
        a.first_established_ns = minNonzero(a.first_established_ns, s.first_established_ns);
        a.last_established_ns = @max(a.last_established_ns, s.last_established_ns);
        a.sessions_failed += s.sessions_failed;
        a.sessions_reaped += s.sessions_reaped;
        a.stops_dropped += s.stops_dropped;
        a.cmds_posted += s.cmds_posted;
        a.cmds_drained += s.cmds_drained;
        a.wakes_written += s.wakes_written;
        a.wakes_read += s.wakes_read;
    }
    return a;
}

fn minNonzero(a: u64, b: u64) u64 {
    if (a == 0) return b;
    if (b == 0) return a;
    return @min(a, b);
}

fn liveTotal(engines: []Engine) usize {
    var n: usize = 0;
    for (engines) |*e| n += e.sessionCount();
    return n;
}
fn scramTotal(engines: []Engine) usize {
    var n: usize = 0;
    for (engines) |*e| n += e.scram_derives;
    return n;
}
fn hitsTotal(engines: []Engine) usize {
    var n: usize = 0;
    for (engines) |*e| n += e.scram_cache_hits;
    return n;
}
