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
pub const std_options = xmppd_log.std_options;

const posix = std.posix;
const IpcServer = @import("ipc_server").IpcServer;
const IpcConn = @import("ipc_server").IpcConn;
const OpBackendType = @import("op_backend").Backend;
const config_mod = @import("config");
const user_store_mod = @import("user_store");
const UserStore = user_store_mod.UserStore(OpBackendType);
const handler_mod = @import("handler");
const AuthHandler = handler_mod.AuthHandler(UserStore);
const protocol = @import("ipc_protocol");
const event_loop_mod = @import("event_loop");
const EventLoop = event_loop_mod.EventLoop;
const ChangeList = event_loop_mod.ChangeList;
const Event = event_loop_mod.Event;
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

const log = std.log.scoped(.xmppd_auth);

/// Sentinel value for the listener fd in kqueue udata.
const LISTENER_UDATA: usize = std.math.maxInt(usize);

/// Sentinel value for the crypto pool wake pipe in kqueue udata (T121).
const POOL_UDATA: usize = std.math.maxInt(usize) - 1;

/// Base udata for IPC client connections.
const CLIENT_UDATA_BASE: usize = 0x10000;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var db_path: []const u8 = "/var/db/xmppd";
    var socket_path: []const u8 = "/var/run/xmppd/auth.sock";
    var rate_policy = RatePolicy{};
    var rate_limit_enabled = true;
    var reg_config = RegistrationConfig{};
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
        } else if (std.mem.eql(u8, arg, "--no-rate-limit")) {
            rate_limit_enabled = false;
        } else if (std.mem.eql(u8, arg, "--enable-registration")) {
            reg_config.enabled = true;
        } else if (std.mem.eql(u8, arg, "--no-require-invite")) {
            reg_config.require_invite = false;
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

        log.info("config file: {s}", .{cp});
    }
    defer if (cfg) |*c| c.deinit();

    // Build auth-specific sub-path: {db_path}/auth
    var auth_path_buf: [1024]u8 = undefined;
    const auth_path = std.fmt.bufPrint(&auth_path_buf, "{s}/auth", .{db_path}) catch {
        log.err("db path too long", .{});
        return error.InvalidArgs;
    };
    log.info("xmppd-auth starting, db={s} socket={s}", .{ auth_path, socket_path });

    // Open storage backend
    var backend = try OpBackendType.open(auth_path, .{});
    defer backend.close();
    var store = UserStore.init(&backend);
    var lock_store = LockStore.init(&backend);
    var invite_store = InviteStore.init(&backend);

    // Initialize rate limiter
    var rate_limiter = try RateLimiter.init(allocator, rate_policy);
    defer rate_limiter.deinit();

    // Initialize auth handler
    var handler = AuthHandler.init(allocator, &store);
    if (rate_limit_enabled) {
        handler.setRateLimiter(&rate_limiter);
        log.info("rate policy: {d}/account, {d}/ip, window={d}s, lockout={d}s after {d} failures", .{
            rate_policy.max_per_account,
            rate_policy.max_per_ip,
            rate_policy.window_seconds,
            rate_policy.lockout_duration,
            rate_policy.lockout_threshold,
        });
    } else {
        log.warn("auth rate limiting DISABLED — no brute-force protection (benchmark/testing only)", .{});
    }
    handler.setLockChecker(handler_mod.makeLockChecker(OpBackendType, &lock_store, allocator));
    handler.reg_config = reg_config;
    if (reg_config.enabled and reg_config.require_invite) {
        handler.invite_validator = makeInviteValidator(&invite_store, allocator);
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

    // Start IPC server (heap-allocated: the struct is ~2 MB since
    // MAX_IPC_CLIENTS went 16 -> 80, too big for the stack — T161)
    const ipc = try allocator.create(IpcServer);
    ipc.* = IpcServer.init(allocator);
    defer {
        ipc.deinit();
        allocator.destroy(ipc);
    }
    try ipc.listen(socket_path);

    // Initialize event loop
    var loop = try EventLoop.init(allocator, 32);
    defer loop.deinit();

    // Register listener + signals (signal masking is automatic)
    try loop.addFd(ipc.listen_fd, .read, LISTENER_UDATA);
    if (pool_started) try loop.addFd(crypto_pool.pipe_rd, .read, POOL_UDATA);
    try loop.addSignal(posix.SIG.TERM);
    try loop.addSignal(posix.SIG.INT);
    try loop.addSignal(posix.SIG.HUP);

    // ABA guard for deferred crypto replies: bumped on every client accept so
    // a stale completion can't land on a different core connection that
    // reused the slot.
    var ipc_gens = [_]u32{0} ** @import("ipc_server").MAX_IPC_CLIENTS;

    // Intake throttle: when a core's response backlog passes the high-water
    // mark, stop reading NEW requests from that client (EV_DISABLE its read
    // filter) until the backlog drains. Purely event-driven — no timers.
    var read_paused = [_]bool{false} ** @import("ipc_server").MAX_IPC_CLIENTS;

    // Scratch buffer for batching changes across iterations.
    var scratch: [16]posix.Kevent = undefined;
    var batch = ChangeList.init(&scratch);

    // Main event loop
    var running = true;
    while (running) {
        const events = loop.submitAndPoll(batch.slice(), null) catch |err| {
            log.err("event loop poll failed: {}", .{err});
            break;
        };
        batch.reset();

        for (events) |ev| {
            switch (ev) {
                .signal => |s| {
                    if (s.signo == posix.SIG.TERM or s.signo == posix.SIG.INT) {
                        log.info("received signal {d}, shutting down", .{s.signo});
                        running = false;
                    } else if (s.signo == posix.SIG.HUP) {
                        log.info("received SIGHUP (LMDB — no reload needed)", .{});
                    }
                },
                .fd_readable => |e| {
                    if (e.udata == LISTENER_UDATA) {
                        // New IPC client connection
                        if (ipc.accept() catch null) |slot| {
                            ipc_gens[slot] +%= 1;
                            read_paused[slot] = false;
                            const conn = ipc.getClient(slot) orelse continue;
                            batch.addRead(conn.fd, CLIENT_UDATA_BASE + slot) catch break;

                            // Send MechanismList immediately on connect
                            const mechs = [_]protocol.MechanismId{ .scram_sha_256, .plain };
                            const ml_msg = protocol.Message{ .mechanism_list = protocol.MechanismList.init(&mechs) };
                            conn.queueSend(ml_msg) catch {
                                ipc.closeClient(slot);
                                continue;
                            };
                            if (conn.hasPendingSend()) {
                                batch.addWriteOnce(conn.fd, CLIENT_UDATA_BASE + slot) catch {};
                            }
                        }
                    } else if (e.udata == POOL_UDATA) {
                        // T121: crypto completions — render and send replies
                        crypto_pool.drainPipe();
                        while (crypto_pool.popCompletion()) |c| {
                            pumpCryptoReply(ipc, &handler, c, &ipc_gens, &batch, &read_paused);
                        }
                    } else if (e.udata >= CLIENT_UDATA_BASE) {
                        const slot = e.udata - CLIENT_UDATA_BASE;
                        // Belts-and-braces: a paused client's read filter is
                        // disabled, so no event should arrive — but one may
                        // already be queued from before the disable landed.
                        if (!read_paused[slot])
                            handleIpcClient(ipc, &handler, &batch, slot, &ipc_gens, &read_paused);
                    }
                },
                .fd_writable => |e| {
                    if (e.udata >= CLIENT_UDATA_BASE) {
                        const slot = e.udata - CLIENT_UDATA_BASE;
                        flushIpcClient(ipc, &batch, slot, &read_paused);
                    }
                },
                else => {},
            }
        }
    }

    log.info("xmppd-auth shutdown complete", .{});
}

/// Backpressure watermarks for IPC client intake. Sized against the SCRAM
/// frame reality: a challenge+result pair is ~300 bytes, so 256 KiB of
/// backlog is ~850 in-flight exchanges — deep but bounded.
const RX_PAUSE_AT: usize = 768 << 10;
const RX_RESUME_AT: usize = 256 << 10;

fn updateReadBackpressure(ipc: *IpcServer, batch: *ChangeList, slot: usize, read_paused: []bool) void {
    const conn = ipc.getClient(slot) orelse return;
    if (conn.fd < 0) return;
    const pend = conn.pendingSendBytes();
    if (!read_paused[slot] and pend > RX_PAUSE_AT) {
        read_paused[slot] = true;
        batch.disableRead(conn.fd) catch {};
        log.warn("IPC client {d}: {d}B outbound backlog > {d}B — pausing intake until drained", .{ slot, pend, RX_PAUSE_AT });
    } else if (read_paused[slot] and pend < RX_RESUME_AT) {
        read_paused[slot] = false;
        batch.enableRead(conn.fd) catch {};
        log.info("IPC client {d}: backlog drained to {d}B — resuming intake", .{ slot, pend });
    }
}

fn handleIpcClient(ipc: *IpcServer, handler: *AuthHandler, batch: *ChangeList, slot: usize, ipc_gens: []const u32, read_paused: []bool) void {
    defer updateReadBackpressure(ipc, batch, slot, read_paused);
    const conn = ipc.getClient(slot) orelse return;

    const n = conn.recv() catch |err| {
        log.err("IPC client {d} recv error: {} — closing", .{ slot, err });
        ipc.closeClient(slot);
        read_paused[slot] = false;
        return;
    };

    if (n == 0) {
        ipc.closeClient(slot);
        return;
    }

    // Process all complete messages
    while (true) {
        const msg = conn.nextMessage() catch {
            ipc.closeClient(slot);
            return;
        };

        if (msg == null) break;

        switch (handler.handleMessage(msg.?, @intCast(slot), ipc_gens[slot])) {
            .reply => |response| {
                conn.queueSend(response) catch {
                    ipc.closeClient(slot);
                    return;
                };

                // Clean up SCRAM session after sending success/failure
                switch (response) {
                    .auth_success => |s| handler.cleanupSession(s.conn_id),
                    .auth_failure => |f| handler.cleanupSession(f.conn_id),
                    else => {},
                }

                // One-shot write notification for pending data
                if (conn.hasPendingSend()) {
                    batch.addWriteOnce(conn.fd, CLIENT_UDATA_BASE + slot) catch {};
                }
            },
            // Crypto pool answers via the completion pipe (T121).
            .deferred, .none => {},
        }
    }
}

/// T121: send a finished crypto job's reply to its IPC client. The slot
/// generation both validates the client is still the connection that asked
/// and prevents a stale reply reaching an unrelated (reused) slot.
fn pumpCryptoReply(ipc: *IpcServer, handler: *AuthHandler, c: crypto_pool_mod.Completion, ipc_gens: []const u32, batch: *ChangeList, read_paused: []bool) void {
    var reply = handler.takeCryptoReply(c) orelse return;
    defer reply.deinit(handler.allocator);

    const slot: usize = reply.slot;
    if (slot >= ipc_gens.len or ipc_gens[slot] != reply.slot_gen) return;

    const conn = ipc.getClient(slot) orelse return;
    conn.queueSend(reply.msg) catch {
        ipc.closeClient(slot);
        read_paused[slot] = false;
        return;
    };
    if (conn.hasPendingSend()) {
        batch.addWriteOnce(conn.fd, CLIENT_UDATA_BASE + slot) catch {};
    }
    updateReadBackpressure(ipc, batch, slot, read_paused);
}

fn flushIpcClient(ipc: *IpcServer, batch: *ChangeList, slot: usize, read_paused: []bool) void {
    const conn = ipc.getClient(slot) orelse return;

    _ = conn.flush() catch {
        ipc.closeClient(slot);
        read_paused[slot] = false;
        return;
    };

    // Re-arm write if more data pending
    if (conn.hasPendingSend()) {
        batch.addWriteOnce(conn.fd, CLIENT_UDATA_BASE + slot) catch {};
    }
    updateReadBackpressure(ipc, batch, slot, read_paused);
}

/// Context for the invite validator callback.
const InviteValidatorCtx = struct {
    invite_store: *InviteStore,
    allocator: std.mem.Allocator,
};

/// Create an InviteValidator interface backed by an InviteStore.
fn makeInviteValidator(is: *InviteStore, alloc: std.mem.Allocator) InviteValidator {
    const S = struct {
        var ctx: InviteValidatorCtx = undefined;

        fn check(raw_ctx: *anyopaque, code: []const u8) bool {
            _ = raw_ctx;
            return ctx.invite_store.validate(ctx.allocator, code) catch false;
        }
    };
    S.ctx = .{ .invite_store = is, .allocator = alloc };
    return .{
        .ctx = @ptrCast(&S.ctx),
        .validateFn = &S.check,
    };
}

fn parseU32Arg(arg: ?[]const u8) ?u32 {
    const s = arg orelse return null;
    return std.fmt.parseInt(u32, s, 10) catch null;
}

fn printUsage() void {
    const usage =
        \\Usage: xmppd-auth [OPTIONS]
        \\
        \\Options:
        \\  --db PATH                  Storage directory (default: /var/db/xmppd)
        \\  --socket PATH              IPC socket path (default: /var/run/xmppd/auth.sock)
        \\  --max-auth-per-account N   Max attempts per account per window (default: 5)
        \\  --max-auth-per-ip N        Max attempts per IP per window (default: 20)
        \\  --auth-window N            Rate window in seconds (default: 120)
        \\  --lockout-duration N       Temp lockout duration in seconds (default: 300)
        \\  --lockout-threshold N      Consecutive failures before lockout (default: 10)
        \\  --no-rate-limit            Disable auth rate limiting entirely (testing/benchmarks only)
        \\  --enable-registration      Enable in-band registration (XEP-0077)
        \\  --no-require-invite        Allow registration without invitation code
        \\  --help, -h                 Show this help
        \\
    ;
    var buf: [0]u8 = .{};
    var stdout = std.fs.File.stdout().writer(&buf);
    stdout.interface.writeAll(usage) catch {};
}
