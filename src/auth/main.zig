//! # xmppd-auth — Authentication daemon
//!
//! Separate process that handles SASL authentication exchanges over a Unix
//! domain socket IPC channel. Reads user credentials from the storage backend
//! (LMDB by default) and processes SCRAM-SHA-256 and PLAIN authentication.
//!
//! ## Usage
//!
//! ```
//! xmppd-auth --db /var/db/xmppd/ --socket /var/run/xmppd/auth.sock
//! ```
//!
//! ## Signals
//!
//! - SIGHUP: logged (LMDB always sees latest committed data)
//! - SIGTERM: graceful shutdown

const std = @import("std");
const xmppd_log = @import("xmppd_log");
const root_allocator = @import("root_allocator");
pub const std_options = xmppd_log.std_options;

const OpBackendType = @import("op_backend").Backend;
const config_mod = @import("config");
const backend_mod = @import("backend");
const user_store_mod = @import("user_store");
const UserStore = user_store_mod.UserStore(OpBackendType);
const handler_mod = @import("handler");
const AuthHandler = handler_mod.AuthHandler(UserStore);
const protocol = @import("ipc_protocol");
const runner_mod = @import("runner");
const RateLimiter = @import("rate_limiter").RateLimiter;
const RatePolicy = @import("rate_limiter").RatePolicy;
const crypto_pool_mod = @import("crypto_pool");
const lock_store_mod = @import("lock_store");
const LockStore = lock_store_mod.LockStore(OpBackendType);
const LockChecker = handler_mod.LockChecker;
const invite_store_mod = @import("invite_store");
const InviteStore = invite_store_mod.InviteStore(OpBackendType);
const InviteValidator = handler_mod.InviteValidator;
const RegistrationConfig = handler_mod.RegistrationConfig;

/// Mechanisms this daemon advertises on connect; each must have a store
/// capability behind it (checked at compile time).
const AUTH_MECHS = [_]protocol.MechanismId{ .scram_sha_256, .plain };

comptime {
    handler_mod.assertMechanisms(UserStore, &AUTH_MECHS);
}

const log = std.log.scoped(.xmppd_auth);

/// Certify the users namespace before any request is served. There is
/// deliberately no raw-name read fallback.
fn parseUsersScanLimit(text: []const u8) !usize {
    return std.fmt.parseInt(usize, text, 10) catch error.InvalidArgs;
}

/// CLI wins over config, which wins over the built-in default.
fn resolveUsersScanLimit(default: usize, cli_value: ?[]const u8, config_value: ?[]const u8) !usize {
    if (cli_value) |v| return parseUsersScanLimit(v);
    if (config_value) |v| return parseUsersScanLimit(v);
    return default;
}

fn verifyUsersAtStartup(comptime Backend: type, backend: *Backend, max_keys: usize) !void {
    return user_store_mod.verifyPreparedUsers(Backend, backend, max_keys);
}

pub fn main() !void {
    var root = root_allocator.Root.init();
    defer root.deinit();
    const allocator = root.allocator();

    // Parse arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var db_path: []const u8 = "/var/db/xmppd";
    var socket_path: []const u8 = "/var/run/xmppd/auth.sock";
    var map_size_mb: usize = 8192; // OpenOptions.map_size default (S9)
    var rate_policy = RatePolicy{};
    var rate_limit_enabled = true;
    var reg_config = RegistrationConfig{};
    var users_scan_limit_arg: ?[]const u8 = null;
    var config_users_scan_limit: ?[]const u8 = null;
    // T121: crypto pool size. 0 disables (inline derive in the event loop).
    var crypto_threads: u32 = 4;

    var config_path: ?[]const u8 = null;

    _ = args.next(); // Skip argv[0]

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--config") or std.mem.eql(u8, arg, "-c")) {
            config_path = args.next() orelse {
                log.err("--config requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--db")) {
            db_path = args.next() orelse {
                log.err("--db requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--socket")) {
            socket_path = args.next() orelse {
                log.err("--socket requires a value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--max-auth-per-account")) {
            rate_policy.max_per_account = parseU32Arg(args.next()) orelse {
                log.err("--max-auth-per-account requires a numeric value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--max-auth-per-ip")) {
            rate_policy.max_per_ip = parseU32Arg(args.next()) orelse {
                log.err("--max-auth-per-ip requires a numeric value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--auth-window")) {
            rate_policy.window_seconds = parseU32Arg(args.next()) orelse {
                log.err("--auth-window requires a numeric value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--lockout-duration")) {
            rate_policy.lockout_duration = parseU32Arg(args.next()) orelse {
                log.err("--lockout-duration requires a numeric value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--lockout-threshold")) {
            rate_policy.lockout_threshold = @intCast(parseU32Arg(args.next()) orelse {
                log.err("--lockout-threshold requires a numeric value", .{});
                return error.InvalidArgs;
            });
        } else if (std.mem.eql(u8, arg, "--ip-lockout-threshold")) {
            rate_policy.ip_lockout_threshold = @intCast(parseU32Arg(args.next()) orelse {
                log.err("--ip-lockout-threshold requires a numeric value", .{});
                return error.InvalidArgs;
            });
        } else if (std.mem.eql(u8, arg, "--no-rate-limit")) {
            rate_limit_enabled = false;
        } else if (std.mem.eql(u8, arg, "--enable-registration")) {
            reg_config.enabled = true;
        } else if (std.mem.eql(u8, arg, "--no-require-invite")) {
            reg_config.require_invite = false;
        } else if (std.mem.eql(u8, arg, "--users-scan-limit")) {
            users_scan_limit_arg = args.next() orelse {
                log.err("--users-scan-limit requires a numeric value", .{});
                return error.InvalidArgs;
            };
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        } else {
            log.warn("unknown argument: {s}", .{arg});
        }
    }

    // Apply config file defaults (CLI flags take precedence)
    var cfg: ?config_mod.Config = null;
    if (config_path) |cp| {
        cfg = config_mod.parse(allocator, cp) catch |err| {
            log.err("failed to read config file '{s}': {}", .{ cp, err });
            return error.InvalidArgs;
        };
        const c = &cfg.?;

        // [server] section
        if (std.mem.eql(u8, db_path, "/var/db/xmppd")) {
            if (c.get("server", "db_path")) |v| db_path = v;
        }
        // LMDB map size: fixed at open, never resized at runtime (S9).
        if (c.get("server", "lmdb_map_size_mb")) |v| {
            map_size_mb = std.fmt.parseInt(usize, v, 10) catch map_size_mb;
        }

        // [auth] section
        if (std.mem.eql(u8, socket_path, "/var/run/xmppd/auth.sock")) {
            if (c.get("auth", "socket")) |v| socket_path = v;
        }
        // CLI args outrank config; config applies only at the untouched
        // default. Compare against the struct default, not a copy-pasted
        // literal (T196: literals bit-rotted when defaults moved).
        const rate_defaults = RatePolicy{};
        if (rate_policy.max_per_account == rate_defaults.max_per_account) {
            if (c.get("auth", "max_per_account")) |v| {
                rate_policy.max_per_account = std.fmt.parseInt(u32, v, 10) catch rate_defaults.max_per_account;
            }
        }
        if (rate_policy.max_per_ip == rate_defaults.max_per_ip) {
            if (c.get("auth", "max_per_ip")) |v| {
                rate_policy.max_per_ip = std.fmt.parseInt(u32, v, 10) catch rate_defaults.max_per_ip;
            }
        }
        if (rate_policy.window_seconds == rate_defaults.window_seconds) {
            if (c.get("auth", "window_seconds")) |v| {
                rate_policy.window_seconds = std.fmt.parseInt(u32, v, 10) catch rate_defaults.window_seconds;
            }
        }
        if (rate_policy.lockout_duration == rate_defaults.lockout_duration) {
            if (c.get("auth", "lockout_duration")) |v| {
                rate_policy.lockout_duration = std.fmt.parseInt(u32, v, 10) catch rate_defaults.lockout_duration;
            }
        }
        if (rate_policy.lockout_threshold == rate_defaults.lockout_threshold) {
            if (c.get("auth", "lockout_threshold")) |v| {
                rate_policy.lockout_threshold = @intCast(std.fmt.parseInt(u32, v, 10) catch rate_defaults.lockout_threshold);
            }
        }
        if (rate_policy.ip_lockout_threshold == rate_defaults.ip_lockout_threshold) {
            if (c.get("auth", "ip_lockout_threshold")) |v| {
                rate_policy.ip_lockout_threshold = @intCast(std.fmt.parseInt(u32, v, 10) catch rate_defaults.ip_lockout_threshold);
            }
        }
        if (c.get("auth", "rate_limit")) |v| {
            if (std.mem.eql(u8, v, "false")) rate_limit_enabled = false;
        }
        if (c.get("auth", "crypto_threads")) |v| {
            crypto_threads = std.fmt.parseInt(u32, v, 10) catch 4;
        }
        if (c.get("auth", "registration")) |v| {
            if (std.mem.eql(u8, v, "true")) reg_config.enabled = true;
        }
        if (c.get("auth", "require_invite")) |v| {
            if (std.mem.eql(u8, v, "false")) reg_config.require_invite = false;
        }
        if (c.get("auth", "users_scan_limit")) |v| {
            config_users_scan_limit = v;
        }

        log.info("config file: {s}", .{cp});
    }
    defer if (cfg) |*c| c.deinit();

    const users_scan_limit = resolveUsersScanLimit(
        user_store_mod.max_startup_scan_keys,
        users_scan_limit_arg,
        config_users_scan_limit,
    ) catch |err| {
        log.err("invalid users_scan_limit value", .{});
        return err;
    };

    // Build auth-specific sub-path: {db_path}/auth
    var auth_path_buf: [1024]u8 = undefined;
    const auth_path = std.fmt.bufPrint(&auth_path_buf, "{s}/auth", .{db_path}) catch {
        log.err("db path too long", .{});
        return error.InvalidArgs;
    };
    log.info("xmppd-auth starting, db={s} socket={s}", .{ auth_path, socket_path });

    if (try backend_mod.migrationPending(db_path)) {
        log.err("an interrupted migrate-precis recovery is pending; rerun 'xmppctl migrate-precis --apply' before starting xmppd-auth", .{});
        return error.MigrationPending;
    }

    // Open storage backend
    var backend = try OpBackendType.open(auth_path, .{ .map_size = map_size_mb * 1024 * 1024 });
    defer backend.close();
    var store = UserStore.init(&backend);
    verifyUsersAtStartup(OpBackendType, &backend, users_scan_limit) catch |err| {
        if (err == error.ScanLimitExceeded) {
            log.err("users namespace exceeds the {d}-key startup scan bound; raise --users-scan-limit or review the account DB", .{users_scan_limit});
        } else if (err == error.ScanFailed) {
            log.err("users namespace scan failed; check the account database", .{});
        } else {
            log.err("users namespace is not in RFC 7622 prepared form ({}); run 'xmppctl migrate-precis --apply' offline before starting xmppd-auth", .{err});
        }
        return err;
    };
    var lock_store = LockStore.init(&backend);
    // Rows written before keys were case-folded carry the name as typed and
    // must not survive into service (S3).
    try lock_store.migrateLegacyKeys(allocator);
    var invite_store = InviteStore.init(&backend);

    // Initialize rate limiter
    var rate_limiter = try RateLimiter.init(allocator, rate_policy);
    defer rate_limiter.deinit();

    // Initialize auth handler
    var handler = AuthHandler.init(allocator, &store);
    if (rate_limit_enabled) {
        handler.setRateLimiter(&rate_limiter);
        log.info("rate policy: {d}/account, {d}/ip, window={d}s, lockout={d}s after {d} account / {d} ip failures", .{
            rate_policy.max_per_account,
            rate_policy.max_per_ip,
            rate_policy.window_seconds,
            rate_policy.lockout_duration,
            rate_policy.lockout_threshold,
            rate_policy.ip_lockout_threshold,
        });
    } else {
        log.warn("auth rate limiting DISABLED — no brute-force protection (benchmark/testing only)", .{});
    }
    var lock_checker: handler_mod.LockStoreChecker(OpBackendType) = undefined;
    lock_checker.init(&lock_store, allocator);
    handler.setLockChecker(lock_checker.checker);
    handler.reg_config = reg_config;
    var invite_ctx = InviteValidatorCtx{ .invite_store = &invite_store, .allocator = allocator };
    if (reg_config.enabled and reg_config.require_invite) {
        handler.invite_validator = makeInviteValidator(&invite_ctx);
    }
    defer handler.deinit();

    if (reg_config.enabled) {
        log.info("registration enabled (require_invite={s})", .{if (reg_config.require_invite) "true" else "false"});
    }

    // T121: crypto offload pool — PBKDF2 derives run off the event loop.
    // Started before the listener accepts anything; on failure the daemon
    // continues with inline derivation (the pre-T121 behavior).
    var crypto_pool = crypto_pool_mod.CryptoPool{ .allocator = allocator };
    var pool_started = false;
    if (crypto_threads > 0) {
        crypto_pool.start(crypto_threads) catch |err| {
            log.err("crypto pool failed to start ({}): falling back to inline derivation", .{err});
        };
        pool_started = crypto_pool.thread_count > 0;
    }
    if (pool_started) {
        handler.enableCryptoPool(&crypto_pool);
        log.info("crypto pool: {d} worker threads", .{crypto_pool.thread_count});
    }
    defer if (pool_started) crypto_pool.stop();

    // Run the shared auth daemon loop (src/auth/runner.zig): it owns the
    // IPC listener, the kqueue, lane generations, intake backpressure,
    // flush coalescing, the crypto-pool drain and signals.
    var hooks = AuthHooks{ .crypto_pool = if (pool_started) &crypto_pool else null };
    var auth_runner: runner_mod.Runner(UserStore, AuthHooks) = undefined;
    try auth_runner.init(
        allocator,
        &hooks,
        &handler,
        socket_path,
        &AUTH_MECHS,
        if (pool_started) crypto_pool.pipe_rd else null,
    );
    defer auth_runner.deinit();
    auth_runner.run();

    log.info("xmppd-auth shutdown complete", .{});
}

/// Per-daemon hooks for the shared runner (src/auth/runner.zig): the
/// crypto-pool drain and the daemon's SIGHUP text. Message dispatch and
/// lane bookkeeping stay with the runner, which is the xmppd-auth
/// reference behavior.
const AuthHooks = struct {
    crypto_pool: ?*crypto_pool_mod.CryptoPool,

    pub const log = std.log.scoped(.xmppd_auth);

    /// xmppd-auth hands every message to the handler; nothing is consumed
    /// before it.
    pub fn intercept(self: *AuthHooks, runner: anytype, msg: protocol.Message, slot: u16) bool {
        _ = self;
        _ = runner;
        _ = msg;
        _ = slot;
        return false;
    }

    /// T121: crypto completions -- render and send replies.
    pub fn onPoolWake(self: *AuthHooks, runner: anytype) void {
        const pool = self.crypto_pool orelse return;
        pool.drainPipe();
        while (pool.popCompletion()) |completion| {
            self.pumpCryptoReply(runner, completion);
        }
    }

    pub fn onLaneClose(self: *AuthHooks, slot: usize) void {
        _ = self;
        _ = slot;
    }

    pub fn onSighup(self: *AuthHooks) void {
        _ = self;
        AuthHooks.log.info("received SIGHUP (LMDB -- no reload needed)", .{});
    }

    /// T121: send a finished crypto job's reply to its IPC client. The
    /// slot generation both validates the client is still the connection
    /// that asked and prevents a stale reply reaching an unrelated
    /// (reused) slot.
    fn pumpCryptoReply(self: *AuthHooks, runner: anytype, c: crypto_pool_mod.Completion) void {
        _ = self;
        var reply = runner.handler.takeCryptoReply(c) orelse return;
        defer reply.deinit(runner.handler.allocator);

        const slot: usize = reply.slot;
        if (slot >= runner.ipc_gens.len or runner.ipc_gens[slot] != reply.slot_gen) return;

        runner.replyToLane(slot, reply.msg);
    }
};

/// Context for the invite validator callback.
const InviteValidatorCtx = struct {
    invite_store: *InviteStore,
    allocator: std.mem.Allocator,
};

/// Create an InviteValidator interface backed by an InviteStore.
/// The context is owned by the caller and must outlive the validator.
fn makeInviteValidator(ctx: *InviteValidatorCtx) InviteValidator {
    const S = struct {
        fn check(raw_ctx: *anyopaque, code: []const u8) bool {
            const c: *InviteValidatorCtx = @ptrCast(@alignCast(raw_ctx));
            return c.invite_store.validate(c.allocator, code) catch false;
        }
    };
    return .{
        .ctx = @ptrCast(ctx),
        .validateFn = &S.check,
    };
}

fn parseU32Arg(arg: ?[]const u8) ?u32 {
    const s = arg orelse return null;
    return std.fmt.parseInt(u32, s, 10) catch null;
}

test "auth startup: users_scan_limit config is parsed and validated" {
    try std.testing.expectEqual(@as(usize, 500), try parseUsersScanLimit("500"));
    try std.testing.expectError(error.InvalidArgs, parseUsersScanLimit("not-a-number"));
    try std.testing.expectEqual(@as(usize, 100), try resolveUsersScanLimit(100000, "100", "200"));
    try std.testing.expectEqual(@as(usize, 200), try resolveUsersScanLimit(100000, null, "200"));
    try std.testing.expectEqual(@as(usize, 100000), try resolveUsersScanLimit(100000, null, null));
    try std.testing.expectError(error.InvalidArgs, resolveUsersScanLimit(100000, null, "typo"));
}

test "auth startup: main applies --users-scan-limit" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const auth_path = try std.fs.path.join(allocator, &.{ base, "auth" });
    defer allocator.free(auth_path);

    var db = try OpBackendType.open(auth_path, .{});
    try db.put(user_store_mod.NAMESPACE, "alice", "x");
    try db.put(user_store_mod.NAMESPACE, "bob", "x");
    db.close();

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{
            "zig-out/bin/xmppd-auth",
            "--db",
            base,
            "--socket",
            "/nonexistent-precis-test/auth.sock",
            "--users-scan-limit",
            "1",
        },
        .max_output_bytes = 64 * 1024,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| try std.testing.expect(code != 0),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "startup scan bound") != null);
}

test "auth startup: a pending migrate-precis marker refuses startup" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const marker_path = try std.fs.path.join(allocator, &.{ base, "migrate-precis.pending" });
    defer allocator.free(marker_path);
    var marker = try std.fs.cwd().createFile(marker_path, .{});
    defer marker.close();
    try marker.writeAll("deadbeef\n");

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{
            "zig-out/bin/xmppd-auth",
            "--db",
            base,
            "--socket",
            "/nonexistent-precis-test/auth.sock",
        },
        .max_output_bytes = 64 * 1024,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| try std.testing.expect(code != 0),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "migrate-precis recovery is pending") != null);
}

test "auth startup: an unprepared users key refuses startup" {
    var db = try backend_mod.MemoryBackend.open("", .{});
    defer db.close();
    try db.put(user_store_mod.NAMESPACE, "NaplesTB", "x");
    try std.testing.expectError(error.UnpreparedAccountName, verifyUsersAtStartup(backend_mod.MemoryBackend, &db, user_store_mod.max_startup_scan_keys));

    try db.delete(user_store_mod.NAMESPACE, "NaplesTB");
    try db.put(user_store_mod.NAMESPACE, "naplestb", "x");
    try verifyUsersAtStartup(backend_mod.MemoryBackend, &db, user_store_mod.max_startup_scan_keys);
    try std.testing.expectError(error.ScanLimitExceeded, verifyUsersAtStartup(backend_mod.MemoryBackend, &db, 0));
    try verifyUsersAtStartup(backend_mod.MemoryBackend, &db, 1);
}

fn printUsage() void {
    const usage =
        \\Usage: xmppd-auth [OPTIONS]
        \\
        \\Options:
        \\  --db PATH                  Storage directory (default: /var/db/xmppd)
        \\  --socket PATH              IPC socket path (default: /var/run/xmppd/auth.sock)
        \\  --max-auth-per-account N   Max attempts per account per window (default: 60)
        \\  --max-auth-per-ip N        Max attempts per IP per window (default: 200)
        \\  --auth-window N            Rate window in seconds (default: 120)
        \\  --lockout-duration N       Temp lockout duration in seconds (default: 300)
        \\  --lockout-threshold N      Consecutive account failures before lockout (default: 10)
        \\  --ip-lockout-threshold N   Consecutive IP failures before lockout (default: 20)
        \\  --no-rate-limit            Disable auth rate limiting entirely (testing/benchmarks only)
        \\  --enable-registration      Enable in-band registration (XEP-0077)
        \\  --no-require-invite        Allow registration without invitation code
        \\  --users-scan-limit N       Max users keys certified at startup (default: 100000)
        \\  --help, -h                 Show this help
        \\
    ;
    var buf: [0]u8 = .{};
    var stdout = std.fs.File.stdout().writer(&buf);
    stdout.interface.writeAll(usage) catch {};
}
