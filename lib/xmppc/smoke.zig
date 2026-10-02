//! Smoke client — end-to-end validation of the xmppc client-core against a
//! live xmppd rig (T-91E96A28). Drives the full stack —
//! TCP → STARTTLS → SASL SCRAM-SHA-256 → resource bind → session/SM — on ONE kqueue
//! loop (N client sessions in one process; the load-driver shape).
//!
//! Usage:
//!   xmppc-smoke -host H [-domain D] -port P -user U -password W -resource R
//!               [-n N] [-resume PREV_SMID] [-max-wait S] [-quiet]
//!
//! Exit 0 once every session is established (SM enabled or resumed); 1 on
//! failure. Emits one machine-readable `ESTABLISHED …` / `FAILED …` line.
//!
//! Credential/resource strings are stored by reference inside the Session and
//! must outlive it; this client passes static literals (or heap allocations
//! that live until process exit).

const std = @import("std");
const Engine = @import("session.zig").Engine;
const Session = @import("session.zig").Session;
const Mutex = std.Thread.Mutex;
const Condition = std.Thread.Condition;

// ---------------------------------------------------------------------------
// CLI options
// ---------------------------------------------------------------------------

fn eqKey(key: []const u8, k: []const u8) bool {
    return std.mem.eql(u8, key, k);
}

const Options = struct {
    host: []const u8 = "127.0.0.1",
    domain: []const u8 = "localhost",
    port: u16 = 15222,
    user: []const u8 = "alice@localhost",
    password: []const u8 = "pass1",
    resource: []const u8 = "smoke",
    count: usize = 1,
    resume_id: []const u8 = "",
    max_wait: u64 = 15,
    quiet: bool = false,
    // Keep KTLS armed on the smoke client (default off: the server arms KTLS,
    // and two KTLS-armed endpoints desync across lo0 — FreeBSD PR 296498).
    // Only useful against non-KTLS peers or over a real NIC (IFCAP_MEXTPG).
    ktls: bool = false,

    fn parse(o: *Options, args: []const [:0]u8) !void {
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            const a = args[i];
            if (a.len < 2 or a[0] != '-') {
                std.debug.print("smoke: unexpected positional arg {s}\n", .{a});
                return error.BadOption;
            }
            // `-key value`, `--key value`, or `--key=value`.
            var key: []const u8 = a[1..];
            if (std.mem.indexOfScalar(u8, key, '=')) |p| {
                key = key[0..p];
            }
            // Flag-only options (no following value).
            if (std.mem.eql(u8, key, "quiet")) {
                o.quiet = true;
                continue;
            }
            if (std.mem.eql(u8, key, "ktls")) {
                o.ktls = true;
                continue;
            }
            if (std.mem.eql(u8, key, "help") or std.mem.eql(u8, key, "h")) {
                std.debug.print(
                    "smoke: xmppc client-core end-to-end smoke\n" ++
                        "  -host H          (TCP target; default 127.0.0.1)\n" ++
                        "  -domain D        (stream to= domain; default localhost)\n" ++
                        "  -port P          (default 15222)\n" ++
                        "  -user JID        (default alice@localhost)\n" ++
                        "  -password W      (default pass1)\n" ++
                        "  -resource R      (default smoke; -n N uses smoke-0..N-1)\n" ++
                        "  -resume SMID     (session 0 attempts SM resume of a prior session)\n" ++
                        "  -max-wait S      (seconds; default 15)\n" ++
                        "  -quiet           (suppress the per-event log lines)\n" ++
                        "  -ktls            (keep KTLS armed on the client; only safe vs\n" ++
                        "                    non-KTLS peers or over a real NIC)\n",
                    .{},
                );
                return error.Help;
            }
            var val: []const u8 = "";
            if (std.mem.indexOfScalar(u8, a, '=')) |p| {
                val = a[p + 1 ..];
            } else {
                if (i + 1 >= args.len) {
                    std.debug.print("smoke: -{s} needs a value\n", .{key});
                    return error.BadOption;
                }
                i += 1;
                val = args[i];
            }
            if (eqKey(key, "host")) {
                o.host = val;
            } else if (eqKey(key, "domain")) {
                o.domain = val;
            } else if (eqKey(key, "port")) {
                o.port = parseOpt(u16, val);
            } else if (eqKey(key, "user")) {
                o.user = val;
            } else if (eqKey(key, "password")) {
                o.password = val;
            } else if (eqKey(key, "resource")) {
                o.resource = val;
            } else if (eqKey(key, "n")) {
                o.count = parseOpt(usize, val);
            } else if (eqKey(key, "resume")) {
                o.resume_id = val;
            } else if (eqKey(key, "max-wait")) {
                o.max_wait = parseOpt(u64, val);
            } else {
                std.debug.print("smoke: unknown option -{s}\n", .{key});
                return error.BadOption;
            }
        }
    }
};

fn parseOpt(comptime T: type, val: []const u8) T {
    return std.fmt.parseUnsigned(T, val, 10) catch {
        std.debug.print("smoke: bad value {s} for {s}\n", .{ val, @typeName(T) });
        @panic("smoke: bad option value");
    };
}

// ---------------------------------------------------------------------------
// Shared outcome (engine-thread callbacks write, main reads; guarded by lock).
// Strings are heap-duped because the source (session state / stack buffers)
// does not outlive the callback.
// ---------------------------------------------------------------------------

const Outcome = struct {
    established: bool = false,
    reason: []const u8 = "",
    bound_jid: []const u8 = "",
    sm_id: []const u8 = "",
    sm_enabled: bool = false,
    sm_resumed: bool = false,
};

var g = struct {
    lock: Mutex = .{},
    cond: Condition = .{},
    outcome: Outcome = .{},
    done: usize = 0,
    established: usize = 0,
    total: usize = 0,
    quiet: bool = false,
}{};

// --- engine-thread callbacks ---
fn onEstablished(engine: *Engine, index: usize, session: *Session) void {
    _ = engine;
    _ = index;
    const jid_str: []const u8 = if (session.boundJid()) |j| blk: {
        break :blk std.fmt.allocPrint(std.heap.page_allocator, "{s}@{s}/{s}", .{ j.local, j.domain, j.resource }) catch "";
    } else "";
    const sm_id: []const u8 = std.heap.page_allocator.dupe(u8, session.smId()) catch "";
    g.lock.lock();
    defer g.lock.unlock();
    g.outcome.established = true;
    g.outcome.bound_jid = jid_str;
    g.outcome.sm_id = sm_id;
    g.outcome.sm_enabled = session.smEnabled();
    g.outcome.sm_resumed = session.smResumed();
    g.established += 1;
    g.done += 1;
    if (!g.quiet) {
        std.debug.print(
            "smoke: established {d}/{d} bound={s} sm_enabled={d} sm_resumed={d} sm_id={s}\n",
            .{ g.established, g.total, jid_str, @intFromBool(g.outcome.sm_enabled), @intFromBool(g.outcome.sm_resumed), sm_id },
        );
    }
    g.cond.signal();
}

fn onClosed(engine: *Engine, index: usize, session: *Session, reason: []const u8) void {
    _ = index;
    _ = session;
    g.lock.lock();
    const already = g.outcome.established;
    if (!already) {
        g.outcome.reason = reason;
        g.done += 1;
        if (!g.quiet) {
            std.debug.print("smoke: failed: {s}\n", .{reason});
        }
    }
    g.lock.unlock();
    if (!already) engine.requestWake();
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main() !void {
    var o = Options{};
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);
    o.parse(args) catch |err| switch (err) {
        error.Help => std.c._exit(0),
        else => std.c._exit(2),
    };
    if (o.count == 0) o.count = 1;

    var engine = try Engine.init(std.heap.page_allocator);
    defer engine.deinit();
    try engine.useTls(if (o.ktls) true else null);

    g.total = o.count;
    g.quiet = o.quiet;

    // Register N sessions (one per client). N>1 gets per-session resources so
    // the rig sees N distinct bind results on one loop.
    var idxs = std.ArrayList(usize){};
    defer idxs.deinit(std.heap.page_allocator);
    for (0..o.count) |i| {
        const res: []const u8 = if (o.count == 1) o.resource else blk: {
            break :blk try std.fmt.allocPrint(
                std.heap.page_allocator,
                "{s}-{d}",
                .{ o.resource, i },
            );
        };
        const resume_id: []const u8 = if (o.resume_id.len > 0 and i == 0) o.resume_id else "";
        const id = engine.startSession(o.host, o.port, o.domain, o.user, o.password, res, resume_id) catch |err| {
            std.debug.print("smoke: startSession: {any}\n", .{err});
            std.c._exit(1);
        };
        try idxs.append(std.heap.page_allocator, id);
    }
    for (idxs.items) |id| {
        if (engine.sessionAt(id)) |s| s.setCallbacks(onEstablished, onClosed);
    }

    engine.run() catch {
        std.debug.print("smoke: engine.run failed\n", .{});
        std.c._exit(1);
    };

    // Wait until every session reaches a terminal state (established or
    // failed) or the deadline.
    const deadline = std.time.nanoTimestamp() + @as(i128, o.max_wait) * @as(i128, std.time.ns_per_s);
    g.lock.lock();
    while (g.done < g.total) {
        const now = std.time.nanoTimestamp();
        if (now >= deadline) break;
        g.cond.timedWait(&g.lock, @intCast(deadline - now)) catch break;
    }
    const ok = g.outcome.established and g.established == g.total;
    const reason = g.outcome.reason;
    const bound = g.outcome.bound_jid;
    const sm_id = g.outcome.sm_id;
    const sm_enabled = g.outcome.sm_enabled;
    const sm_resumed = g.outcome.sm_resumed;
    g.lock.unlock();

    // Stop any still-alive sessions and let the engine thread drain before
    // engine.deinit() joins it.
    for (idxs.items) |id| engine.stopSession(id, "smoke-done");
    var tries: u32 = 0;
    while (engine.sessionCount() > 0 and tries < 500) : (tries += 1) {
        std.Thread.sleep(10 * 1000 * 1000); // 10 ms
    }

    std.debug.print(
        "smoke: {s} established={d}/{d} bound={s} sm_enabled={d} sm_resumed={d} sm_id={s}\n",
        .{ if (ok) "ESTABLISHED" else "FAILED", g.established, g.total, bound, @intFromBool(sm_enabled), @intFromBool(sm_resumed), if (ok) sm_id else reason },
    );
    std.c._exit(if (ok) 0 else 1);
}
