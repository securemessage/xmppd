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
const conf = @import("conf");
const schema = @import("schema");
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
const metrics = @import("auth_metrics");
const scram_mech = handler_mod.scram_mech;
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

/// Loads into caller-owned storage so the parser does not remain in main's
/// long-lived stack frame. Values borrow the loader arena until deinit.
noinline fn loadAuthConfig(loaded: *schema.AuthLoader, gpa: std.mem.Allocator, argv: []const []const u8, diag: *conf.Diag) conf.Error!void {
    loaded.* = schema.AuthLoader.init(gpa);
    errdefer loaded.deinit();
    try loaded.loadInto(.{
        .conf_fd = schema.confFdArg(argv),
        .path = schema.configPathArg(argv),
        .args = argv,
    }, diag);
}

/// Certify the users namespace before any request is served. There is
/// deliberately no raw-name read fallback.
fn verifyUsersAtStartup(comptime Backend: type, backend: *Backend, max_keys: usize) !void {
    return user_store_mod.verifyPreparedUsers(Backend, backend, max_keys);
}

pub fn main() !void {
    // A1: block SIGUSR1 before any thread exists so every spawned thread
    // inherits the mask. A process-directed USR1 can then never take its
    // default terminate on an unblocked thread; the loop's EVFILT_SIGNAL
    // knote still records it and dumps the counters.
    metrics.blockUsr1();

    var root = root_allocator.Root.init();
    defer root.deinit();
    const allocator = root.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next();
    var argv = std.ArrayList([]const u8).empty;
    defer argv.deinit(allocator);
    while (args.next()) |arg| try argv.append(allocator, arg);

    const Cfg = struct {
        diag: conf.Diag,
        loader: schema.AuthLoader,
    };
    const cfg = try allocator.create(Cfg);
    cfg.diag = .{};
    loadAuthConfig(&cfg.loader, allocator, argv.items, &cfg.diag) catch |err| {
        log.err("{f}", .{&cfg.diag});
        allocator.destroy(cfg);
        return err;
    };
    defer {
        cfg.loader.deinit();
        allocator.destroy(cfg);
    }
    const v = &cfg.loader.values;
    if (v.meta.help) {
        try printUsage(allocator);
        return;
    }

    const config_path = schema.configPathArg(argv.items);
    const lockout_duration = schema.validateAuthRate(&cfg.loader, config_path, &cfg.diag) catch |err| {
        log.err("{f}", .{&cfg.diag});
        return err;
    };
    const map_size_bytes = schema.mapSizeBytes(&cfg.loader, config_path, &cfg.diag) catch |err| {
        log.err("{f}", .{&cfg.diag});
        return err;
    };
    const db_path = v.server.db_path;
    const socket_path = v.auth.socket;
    const users_scan_limit = v.auth.users_scan_limit;
    const crypto_threads = v.auth.crypto_threads;
    const rate_limit_enabled = v.auth.rate_limit;
    const rate_policy = RatePolicy{
        .max_per_account = v.auth.max_per_account,
        .max_per_ip = v.auth.max_per_ip,
        .window_seconds = v.auth.window_seconds,
        .lockout_duration = lockout_duration,
        .lockout_threshold = v.auth.lockout_threshold,
        .ip_lockout_threshold = v.auth.ip_lockout_threshold,
    };
    const reg_config = RegistrationConfig{
        .enabled = v.auth.registration,
        .require_invite = v.auth.require_invite,
    };
    if (config_path) |cp| log.info("config file: {s}", .{cp});

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
    var backend = try OpBackendType.open(auth_path, .{ .map_size = map_size_bytes });
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

    // Initialize auth handler. The replay cache is sized from the
    // configured login-rate ceiling times the nonce freshness window
    // (ADR-6): a window sized for the declared ceiling can hold every live
    // nonce a compliant load produces, so inserts refuse before they evict.
    // The fake-derivation key persists in {db}/auth (created once, 0600):
    // a fake salt then survives restarts exactly like a real one.
    var scram_secret: ?[32]u8 = null;
    if (std.fs.cwd().openDir(auth_path, .{})) |d| {
        var dir = d;
        defer dir.close();
        scram_secret = scram_mech.loadOrCreateSecret(dir) catch |err| blk: {
            if (err == error.InvalidSecretFile) {
                log.err("corrupt published SCRAM secret {s}/{s}; refusing to start; repair or replace it offline", .{ auth_path, scram_mech.SECRET_FILE });
                return err;
            }
            log.err("cannot load or create {s}/{s} ({}); fakes use a per-boot key", .{ auth_path, scram_mech.SECRET_FILE, err });
            break :blk null;
        };
    } else |err| {
        log.err("cannot open {s} for the scram secret ({}); fakes use a per-boot key", .{ auth_path, err });
    }
    defer if (scram_secret) |*s| std.crypto.secureZero(u8, s[0..]);
    const replay_capacity = @as(usize, v.auth.login_rate_ceiling) * @as(usize, v.auth.scram_nonce_window_seconds);
    var handler = AuthHandler.init(allocator, &store, .{
        .replay_capacity = replay_capacity,
        .nonce_window_seconds = v.auth.scram_nonce_window_seconds,
        .nonce_skew_seconds = v.auth.scram_nonce_skew_seconds,
        .scram_secret = scram_secret,
    }) catch |err| {
        log.err("replay cache alloc of {d} entries failed ({s}); refusing to start", .{ replay_capacity, @errorName(err) });
        return err;
    };
    if (handler.replay_entries.len == 0) {
        log.warn("replay cache configured with 0 entries; every SCRAM verify refuses", .{});
    } else {
        log.info("replay cache: {d} entries ({d} logins/s ceiling x {d}s window), nonce skew {d}s", .{
            handler.replay_entries.len, v.auth.login_rate_ceiling, v.auth.scram_nonce_window_seconds, v.auth.scram_nonce_skew_seconds,
        });
    }
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

    pub fn onSigusr1(self: *AuthHooks) void {
        _ = self;
        metrics.dump();
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

test "auth startup: a corrupt published SCRAM secret refuses startup" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const auth_path = try std.fs.path.join(allocator, &.{ base, "auth" });
    defer allocator.free(auth_path);

    var db = try OpBackendType.open(auth_path, .{});
    db.close();
    const secret_path = try std.fs.path.join(allocator, &.{ auth_path, scram_mech.SECRET_FILE });
    defer allocator.free(secret_path);
    var secret = try std.fs.cwd().createFile(secret_path, .{});
    defer secret.close();
    try secret.writeAll("short");

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{
            "zig-out/bin/xmppd-auth",
            "--db",
            base,
            "--socket",
            "/nonexistent-secret-test/auth.sock",
        },
        .max_output_bytes = 64 * 1024,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| try std.testing.expect(code != 0),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "corrupt published SCRAM secret") != null);
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

test "auth startup: --lockout-threshold over u16 max is a bad value, not a panic" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);

    // The threshold fields are u16: 70000 must be rejected as a bad value
    // (InvalidArgs) rather than trip the cast check.
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{
            "zig-out/bin/xmppd-auth",
            "--db",
            base,
            "--socket",
            "/nonexistent-threshold-test/auth.sock",
            "--lockout-threshold",
            "70000",
        },
        .max_output_bytes = 64 * 1024,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| try std.testing.expect(code != 0),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "--lockout-threshold") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "invalid value") != null);
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

fn printUsage(allocator: std.mem.Allocator) std.Io.Writer.Error!void {
    var gen = schema.AuthLoader.init(allocator);
    defer gen.deinit();
    var buf: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&buf);
    try stdout.interface.writeAll("Usage: xmppd-auth [OPTIONS]\n\n");
    try gen.writeHelp(&stdout.interface);
    try stdout.interface.flush();
}

test "auth startup: bad file rate values fail with file and line" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][]const u8{
        "max_per_account = nope",
        "lockout_threshold = 70000",
        "max_per_ip = 65536",
    }) |setting| {
        const file = try tmp.dir.createFile("bad.ini", .{ .truncate = true });
        try file.writeAll("[auth]\n");
        try file.writeAll(setting);
        try file.writeAll("\n");
        file.close();
        const path = try tmp.dir.realpathAlloc(allocator, "bad.ini");
        defer allocator.free(path);

        const result = try std.process.Child.run(.{
            .allocator = allocator,
            .argv = &.{ "zig-out/bin/xmppd-auth", "--config", path },
            .max_output_bytes = 64 * 1024,
        });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        switch (result.term) {
            .Exited => |code| try std.testing.expect(code != 0),
            else => return error.TestUnexpectedResult,
        }
        const location = try std.fmt.allocPrint(allocator, "{s}:2:", .{path});
        defer allocator.free(location);
        try std.testing.expect(std.mem.indexOf(u8, result.stderr, location) != null);
        try std.testing.expect(std.mem.indexOf(u8, result.stderr, "invalid value") != null or
            std.mem.indexOf(u8, result.stderr, "exceeds 65535") != null);
    }
}

test "auth startup: generated help lists every schema CLI spelling" {
    const allocator = std.testing.allocator;
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "zig-out/bin/xmppd-auth", "--help" },
        .max_output_bytes = 64 * 1024,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        else => return error.TestUnexpectedResult,
    }
    inline for (schema.auth_cli) |spec| {
        var buf: [128]u8 = undefined;
        const option = try std.fmt.bufPrint(&buf, "--{s}", .{spec.name});
        try std.testing.expect(std.mem.indexOf(u8, result.stdout, option) != null);
        for (spec.aliases) |alias| {
            const short = try std.fmt.bufPrint(&buf, "-{s}", .{alias});
            try std.testing.expect(std.mem.indexOf(u8, result.stdout, short) != null);
        }
    }
}
