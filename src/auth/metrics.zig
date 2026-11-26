//! Per-daemon instrumentation for the auth event loop, in the style of
//! src/core/worker/metrics.zig.
//!
//! One global Counters block per process. The auth daemon's event loop is
//! the only writer and, because SIGUSR1 arrives as EVFILT_SIGNAL on that
//! same loop, also the only reader: bumps are plain monotonic load+store
//! (no lock prefix). Crypto-pool workers never touch this block; a job's
//! latency rides its Completion back to the loop and is counted there.
//!
//! This module is a leaf on purpose: handler.zig is compiled into the
//! xmppd-auth and xmppd-auth-oidc module graphs separately, and the shared
//! block must keep one identity inside each graph. Anything protocol- or
//! policy-shaped in the API would force this module to import a concrete
//! ipc_protocol/policy instance, so the API takes u8 mechanism/reason ids
//! and bools only; callers pass @intFromEnum.

const std = @import("std");
const atomic = std.atomic;
const posix = std.posix;

const log = std.log.scoped(.auth_metrics);

/// log2 microsecond buckets: bucket k holds jobs in [2^k, 2^(k+1)) us.
pub const HIST_BUCKETS = 32;

/// Mechanism indexes are @intFromEnum(MechanismId) - 1 (plain, scram,
/// oauthbearer); asserted against the enum in handler.zig.
pub const MECH_COUNT = 3;

/// Failure outcome indexes are @intFromEnum(FailureReason); asserted
/// against the enum in handler.zig.
pub const REASON_COUNT = 6;

const Counter = atomic.Value(u64);

pub const Counters = struct {
    /// Exchanges opened (auth_request) and terminated (auth_success /
    /// auth_failure), indexed by mechanism id minus one. SCRAM completes
    /// on its second message; started minus completed is the
    /// abandoned-exchange count.
    exchanges_started: [MECH_COUNT]Counter = @splat(.init(0)),
    exchanges_completed: [MECH_COUNT]Counter = @splat(.init(0)),
    /// Successful authentications across all mechanisms.
    auth_success: Counter = .init(0),
    /// Terminal failures indexed by @intFromEnum(FailureReason).
    outcomes: [REASON_COUNT]Counter = @splat(.init(0)),
    /// Rate-limiter decisions at the IP and account keys. lockout_refusals
    /// counts refusals made against a locked key (vs a window or an
    /// unavailable table), including lock denials found by policy.check(),
    /// which has no admit/refuse pair of its own.
    ip_admits: Counter = .init(0),
    ip_refusals: Counter = .init(0),
    account_admits: Counter = .init(0),
    account_refusals: Counter = .init(0),
    lockout_refusals: Counter = .init(0),
    /// Crypto pool: queue-depth high-water, completed jobs, and a log2
    /// microsecond histogram of queue-to-done latency.
    pool_queue_high_water: Counter = .init(0),
    pool_jobs: Counter = .init(0),
    pool_latency_us: [HIST_BUCKETS]Counter = @splat(.init(0)),
    /// SCRAM replay-cache occupancy and its high-water mark, plus the
    /// count of verifies refused because the probe window was all live
    /// (temporary-auth-failure; a live tag is never evicted).
    replay_occupied: Counter = .init(0),
    replay_high_water: Counter = .init(0),
    replay_refusals: Counter = .init(0),
    /// Verifies whose server-first params no longer matched the stored
    /// credentials (password changed mid-cache); answered as scram_stale.
    scram_stale: Counter = .init(0),
    /// Times a lane's intake paused on the outbound backlog watermark.
    ipc_intake_pauses: Counter = .init(0),
};

pub var counters: Counters = .{};

/// Single-writer bump: a monotonic load plus store compiles to
/// mov/add/mov with no lock prefix, and the loop thread is the only
/// writer so nothing can tear (M1 pattern).
inline fn bump(c: *Counter, n: u64) void {
    c.store(c.load(.monotonic) + n, .monotonic);
}

/// One auth_request arrived; mech is @intFromEnum(MechanismId).
pub inline fn exchangeStarted(mech: u8) void {
    std.debug.assert(mech >= 1 and mech <= MECH_COUNT);
    bump(&counters.exchanges_started[mech - 1], 1);
}

/// The exchange produced a terminal reply (not a challenge); mech is
/// @intFromEnum(MechanismId).
pub inline fn exchangeCompleted(mech: u8, success: bool) void {
    std.debug.assert(mech >= 1 and mech <= MECH_COUNT);
    bump(&counters.exchanges_completed[mech - 1], 1);
    if (success) bump(&counters.auth_success, 1);
}

/// One terminal failure reply; reason_idx is @intFromEnum(FailureReason).
pub inline fn failure(reason_idx: u8) void {
    std.debug.assert(reason_idx < REASON_COUNT);
    bump(&counters.outcomes[reason_idx], 1);
}

pub inline fn ipAdmitted() void {
    bump(&counters.ip_admits, 1);
}

pub inline fn ipRefused(lockout: bool) void {
    bump(&counters.ip_refusals, 1);
    if (lockout) bump(&counters.lockout_refusals, 1);
}

pub inline fn accountAdmitted() void {
    bump(&counters.account_admits, 1);
}

pub inline fn accountRefused(lockout: bool) void {
    bump(&counters.account_refusals, 1);
    if (lockout) bump(&counters.lockout_refusals, 1);
}

/// A lock refusal found by policy.check(): a re-check has no admit/refuse
/// pair, so only the lockout split moves.
pub inline fn checkLockout() void {
    bump(&counters.lockout_refusals, 1);
}

/// Queue depth seen by put() after the job lands; raises the high-water
/// mark on an increase. Called on the loop thread under job_mutex.
pub inline fn poolQueued(depth: usize) void {
    const d: u64 = @intCast(depth);
    const hw = counters.pool_queue_high_water.load(.monotonic);
    if (d > hw) counters.pool_queue_high_water.store(d, .monotonic);
}

/// One finished pool job and its queue-to-done latency in microseconds.
/// Called on the loop thread from takeCryptoReply.
pub inline fn poolJobDone(latency_us: u64) void {
    bump(&counters.pool_jobs, 1);
    const bucket: usize = if (latency_us == 0) 0 else @min(63 - @clz(latency_us), HIST_BUCKETS - 1);
    bump(&counters.pool_latency_us[bucket], 1);
}

/// A SCRAM session slot went active.
pub inline fn replayInserted() void {
    const n = counters.replay_occupied.load(.monotonic) + 1;
    counters.replay_occupied.store(n, .monotonic);
    const hw = counters.replay_high_water.load(.monotonic);
    if (n > hw) counters.replay_high_water.store(n, .monotonic);
}

/// An insert hit a probe window of all-live tags; the verify is refused
/// with temporary-auth-failure rather than evicting a live tag.
pub inline fn replayRefused() void {
    bump(&counters.replay_refusals, 1);
}

/// A verify's (salt, iterations) no longer matched the stored credentials;
/// answered scram_stale so the core evicts its params-cache entry.
pub inline fn scramStale() void {
    bump(&counters.scram_stale, 1);
}

/// A replay slot went inactive; a remove without a matching insert is a
/// programmer error.
pub inline fn replayRemoved() void {
    const n = counters.replay_occupied.load(.monotonic);
    std.debug.assert(n > 0);
    counters.replay_occupied.store(n - 1, .monotonic);
}

/// A lane's intake paused on the outbound backlog watermark.
pub inline fn ipcPaused() void {
    bump(&counters.ipc_intake_pauses, 1);
}

/// Block SIGUSR1 on the calling thread. main() calls this before any
/// thread exists so spawned threads inherit the mask: a process-directed
/// USR1 can never take its default terminate, and the loop's
/// EVFILT_SIGNAL knote still records it for the dump.
pub fn blockUsr1() void {
    var mask = posix.sigemptyset();
    posix.sigaddset(&mask, posix.SIG.USR1);
    posix.sigprocmask(posix.SIG.BLOCK, &mask, null);
}

/// Reset every counter; tests use it to start from a clean slate.
pub fn reset() void {
    counters = .{};
}

fn read(c: *const Counter) u64 {
    return c.load(.monotonic);
}

/// Names in mechanism-index order (MechanismId enum order minus one).
const mech_names = [MECH_COUNT][]const u8{ "PLAIN", "SCRAM-SHA-256", "OAUTHBEARER" };

/// Wire reason strings in @intFromEnum(FailureReason) order.
const reason_names = [REASON_COUNT][]const u8{
    "invalid-encoding",       "not-authorized",   "mechanism-not-supported",
    "temporary-auth-failure", "account-disabled", "policy-violation",
};

/// Log the daemon's counters and the crypto-pool latency histogram.
/// Called from the loop's EVFILT_SIGNAL handler on the only thread that
/// writes the block, so relaxed loads suffice.
pub fn dump() void {
    const c = &counters;
    log.info("auth counters: success={d} ip admit={d} refuse={d} account admit={d} refuse={d} lockout_refusals={d}", .{
        read(&c.auth_success),   read(&c.ip_admits),        read(&c.ip_refusals),
        read(&c.account_admits), read(&c.account_refusals), read(&c.lockout_refusals),
    });
    for (&c.exchanges_started, &c.exchanges_completed, mech_names) |*st, *co, name| {
        log.info("auth exchanges {s}: started={d} completed={d} abandoned={d}", .{
            name, read(st), read(co), read(st) -| read(co),
        });
    }
    var rbuf: [REASON_COUNT * 40]u8 = undefined;
    var rw: std.Io.Writer = .fixed(&rbuf);
    var first = true;
    for (&c.outcomes, reason_names) |*o, name| {
        const n = read(o);
        if (n == 0) continue;
        if (!first) rw.writeAll(" ") catch break;
        first = false;
        rw.print("{s}:{d}", .{ name, n }) catch break;
    }
    log.info("auth outcomes: {s}", .{rw.buffered()});
    log.info("auth scram replay: occupied={d} high_water={d} refusals={d} stale={d}; ipc_intake_pauses={d}", .{
        read(&c.replay_occupied), read(&c.replay_high_water), read(&c.replay_refusals), read(&c.scram_stale), read(&c.ipc_intake_pauses),
    });
    var hbuf: [HIST_BUCKETS * 24]u8 = undefined;
    var hw: std.Io.Writer = .fixed(&hbuf);
    first = true;
    for (&c.pool_latency_us, 0..) |*b, k| {
        const n = read(b);
        if (n == 0) continue;
        if (!first) hw.writeAll(" ") catch break;
        first = false;
        if (k == 0)
            hw.print("<2us:{d}", .{n}) catch break
        else
            hw.print("{d}us:{d}", .{ @as(u64, 1) << @intCast(k), n }) catch break;
    }
    log.info("auth pool: jobs={d} queue_high_water={d} latency us (log2): {s}", .{
        read(&c.pool_jobs), read(&c.pool_queue_high_water), hw.buffered(),
    });
}

// ============================================================================
// Tests
// ============================================================================

test "exchange counters move per mechanism" {
    reset();
    defer reset();

    exchangeStarted(1); // PLAIN
    exchangeStarted(1);
    exchangeStarted(2); // SCRAM-SHA-256
    exchangeCompleted(1, true);
    exchangeCompleted(2, false);

    const c = &counters;
    try std.testing.expectEqual(@as(u64, 2), read(&c.exchanges_started[0]));
    try std.testing.expectEqual(@as(u64, 1), read(&c.exchanges_started[1]));
    try std.testing.expectEqual(@as(u64, 0), read(&c.exchanges_started[2]));
    try std.testing.expectEqual(@as(u64, 1), read(&c.exchanges_completed[0]));
    try std.testing.expectEqual(@as(u64, 1), read(&c.exchanges_completed[1]));
    try std.testing.expectEqual(@as(u64, 1), read(&c.auth_success));
}

test "failure outcomes move per reason" {
    reset();
    defer reset();

    failure(0); // invalid-encoding
    failure(3); // temporary-auth-failure
    failure(3);

    const c = &counters;
    try std.testing.expectEqual(@as(u64, 1), read(&c.outcomes[0]));
    try std.testing.expectEqual(@as(u64, 2), read(&c.outcomes[3]));
    try std.testing.expectEqual(@as(u64, 3), blk: {
        var total: u64 = 0;
        for (&c.outcomes) |*o| total += read(o);
        break :blk total;
    });
}

test "admit and refusal counters split lockouts from window denials" {
    reset();
    defer reset();

    ipAdmitted();
    ipAdmitted();
    ipRefused(false); // window
    ipRefused(true); // locked key
    accountAdmitted();
    accountRefused(false);
    accountRefused(true);
    checkLockout(); // policy.check() lock denial

    const c = &counters;
    try std.testing.expectEqual(@as(u64, 2), read(&c.ip_admits));
    try std.testing.expectEqual(@as(u64, 2), read(&c.ip_refusals));
    try std.testing.expectEqual(@as(u64, 1), read(&c.account_admits));
    try std.testing.expectEqual(@as(u64, 2), read(&c.account_refusals));
    try std.testing.expectEqual(@as(u64, 3), read(&c.lockout_refusals));
}

test "poolQueued keeps the high-water mark and poolJobDone assigns log2 buckets" {
    reset();
    defer reset();

    poolQueued(3);
    poolQueued(2); // below the mark: no move
    poolQueued(7);
    try std.testing.expectEqual(@as(u64, 7), read(&counters.pool_queue_high_water));

    poolJobDone(0); // <1us -> bucket 0
    poolJobDone(1500); // 1500us -> bucket 10 (1024)
    poolJobDone(2500); // 2500us -> bucket 11 (2048)
    poolJobDone(std.math.maxInt(u64)); // saturates at the last bucket

    const c = &counters;
    try std.testing.expectEqual(@as(u64, 4), read(&c.pool_jobs));
    try std.testing.expectEqual(@as(u64, 1), read(&c.pool_latency_us[0]));
    try std.testing.expectEqual(@as(u64, 1), read(&c.pool_latency_us[10]));
    try std.testing.expectEqual(@as(u64, 1), read(&c.pool_latency_us[11]));
    try std.testing.expectEqual(@as(u64, 1), read(&c.pool_latency_us[HIST_BUCKETS - 1]));
}

test "replay occupancy tracks a high-water mark" {
    reset();
    defer reset();

    replayInserted();
    replayInserted();
    replayRemoved();
    try std.testing.expectEqual(@as(u64, 1), read(&counters.replay_occupied));
    try std.testing.expectEqual(@as(u64, 2), read(&counters.replay_high_water));

    replayRemoved();
    try std.testing.expectEqual(@as(u64, 0), read(&counters.replay_occupied));
    try std.testing.expectEqual(@as(u64, 2), read(&counters.replay_high_water));
}

test "ipcPaused counts intake pauses" {
    reset();
    defer reset();
    ipcPaused();
    ipcPaused();
    try std.testing.expectEqual(@as(u64, 2), read(&counters.ipc_intake_pauses));
}

test "blockUsr1 masks SIGUSR1 and spawned threads inherit the mask" {
    // Without the block a process-directed USR1 terminates the daemon on
    // whichever thread did not mask it.
    blockUsr1();

    var empty = posix.sigemptyset();
    var probe: posix.sigset_t = undefined;
    posix.sigprocmask(posix.SIG.BLOCK, &empty, &probe);
    try std.testing.expect(posix.sigismember(&probe, posix.SIG.USR1));

    var inherited = false;
    const t = try std.Thread.spawn(.{}, struct {
        fn run(ok: *bool) void {
            var e = posix.sigemptyset();
            var m: posix.sigset_t = undefined;
            posix.sigprocmask(posix.SIG.BLOCK, &e, &m);
            ok.* = posix.sigismember(&m, posix.SIG.USR1);
        }
    }.run, .{&inherited});
    t.join();
    try std.testing.expect(inherited);
}

test "dump runs on a populated block" {
    reset();
    defer reset();
    exchangeStarted(2);
    exchangeCompleted(2, true);
    failure(1);
    poolQueued(4);
    poolJobDone(900_000);
    replayInserted();
    ipcPaused();
    dump();
}
