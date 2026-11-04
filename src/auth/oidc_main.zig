//! # xmppd-auth-oidc -- OIDC authentication daemon
//!
//! Separate process that handles OAUTHBEARER and PLAIN (via ROPC) authentication
//! against an external Identity Provider. Reads [oidc] config from xmppd.conf.
//!
//! ## Usage
//!
//! ```
//! xmppd-auth-oidc --config /usr/local/etc/xmppd/xmppd.conf --socket /var/run/xmppd/auth.sock
//! ```
//!
//! ## Mechanisms Offered
//!
//! Sends [OAUTHBEARER, PLAIN] as its MechanismList on IPC connect.
//! SCRAM-SHA-256 is not supported (IdP doesn't expose stored_key/server_key).
//!
//! ## Dispatch model
//!
//! The event loop never touches the IdP. A PLAIN or OAUTHBEARER auth_request
//! is copied and queued on a bounded worker pool (IdpPool) that runs the
//! blocking HTTP exchange with deadlines; a completion wakes the loop, which
//! parks the verdict in store.answer and replays the request through the
//! AuthHandler so admission, lock checks and outcome recording stay in one
//! place.

const std = @import("std");
const xmppd_log = @import("xmppd_log");
pub const std_options = xmppd_log.std_options;

const posix = std.posix;
const Allocator = std.mem.Allocator;
const IpcServer = @import("ipc_server").IpcServer;
const IpcConn = @import("ipc_server").IpcConn;
const MAX_IPC_CLIENTS = @import("ipc_server").MAX_IPC_CLIENTS;
const handler_mod = @import("handler");
const oidc = @import("oidc");
const OidcStore = oidc.OidcStore;
const OidcConfig = oidc.OidcConfig;
const IdpPool = oidc.IdpPool;
const AuthHandler = handler_mod.AuthHandler(OidcStore);
const protocol = @import("ipc_protocol");
const event_loop_mod = @import("event_loop");
const EventLoop = event_loop_mod.EventLoop;
const ChangeList = event_loop_mod.ChangeList;
const config_mod = @import("config");
const RateLimiter = @import("rate_limiter").RateLimiter;
const RatePolicy = @import("rate_limiter").RatePolicy;
const policy_mod = @import("policy");
const OpBackendType = @import("op_backend").Backend;
const lock_store_mod = @import("lock_store");
const LockStore = lock_store_mod.LockStore(OpBackendType);

const log = std.log.scoped(.xmppd_auth_oidc);

/// Sentinel value for the listener fd in kqueue udata.
const LISTENER_UDATA: usize = std.math.maxInt(usize);

/// Sentinel value for the IdP pool wake pipe in kqueue udata.
const POOL_UDATA: usize = std.math.maxInt(usize) - 1;

/// Base udata for IPC client connections.
const CLIENT_UDATA_BASE: usize = 0x10000;

/// In-flight IdP exchange caps: a queued or running exchange spends pool
/// capacity, so one account or one client IP may only park so many before
/// the newest request is answered temporary-auth-failure, uncounted.
const max_inflight_per_account: usize = 4;
const max_inflight_per_ip: usize = 16;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var socket_path: []const u8 = "/var/run/xmppd/auth.sock";
    var config_path: []const u8 = "/usr/local/etc/xmppd/xmppd.conf";
    var db_path: []const u8 = "/var/db/xmppd";
    var map_size_mb: usize = 8192; // OpenOptions.map_size default (S9)

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
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        } else {
            log.warn("unknown argument: {s}", .{arg});
        }
    }

    // Parse config file
    var cfg = config_mod.parse(allocator, config_path) catch |err| {
        log.err("failed to read config file '{s}': {}", .{ config_path, err });
        return error.InvalidArgs;
    };
    defer cfg.deinit();

    // Read [oidc] section
    const issuer = cfg.get("oidc", "issuer") orelse {
        log.err("missing required config: [oidc] issuer", .{});
        return error.InvalidArgs;
    };
    const client_id = cfg.get("oidc", "client_id") orelse {
        log.err("missing required config: [oidc] client_id", .{});
        return error.InvalidArgs;
    };
    const client_secret = cfg.get("oidc", "client_secret") orelse {
        log.err("missing required config: [oidc] client_secret", .{});
        return error.InvalidArgs;
    };
    const token_endpoint = cfg.get("oidc", "token_endpoint") orelse {
        log.err("missing required config: [oidc] token_endpoint", .{});
        return error.InvalidArgs;
    };
    const jwks_uri = cfg.get("oidc", "jwks_uri") orelse {
        log.err("missing required config: [oidc] jwks_uri", .{});
        return error.InvalidArgs;
    };
    const ca_file = cfg.get("oidc", "ca_file");
    const introspection_endpoint = cfg.get("oidc", "introspection_endpoint");
    const user_domain = cfg.get("oidc", "user_domain");

    // Override socket path from config if present
    if (cfg.get("oidc", "socket")) |s| {
        socket_path = s;
    }
    // Same db resolution as xmppd-auth: [server] db_path when not overridden.
    if (std.mem.eql(u8, db_path, "/var/db/xmppd")) {
        if (cfg.get("server", "db_path")) |v| db_path = v;
    }
    if (cfg.get("server", "lmdb_map_size_mb")) |v| {
        map_size_mb = std.fmt.parseInt(usize, v, 10) catch map_size_mb;
    }

    // IdP worker pool configuration: parsed strictly, an invalid value
    // refuses to start rather than silently falling back.
    var pool_options = IdpPool.Options{
        .threads = 8,
        .max_outstanding = 256,
        .connect_timeout_ms = 3000,
        .timeout_ms = 10000,
    };
    if (cfg.get("oidc", "idp_threads")) |v| {
        pool_options.threads = parseBounded(u8, v, 1, IdpPool.max_threads) orelse {
            log.err("invalid [oidc] idp_threads '{s}' (want 1..{d})", .{ v, IdpPool.max_threads });
            return error.InvalidArgs;
        };
    }
    if (cfg.get("oidc", "idp_max_outstanding")) |v| {
        pool_options.max_outstanding = parseBounded(u16, v, 1, 4096) orelse {
            log.err("invalid [oidc] idp_max_outstanding '{s}' (want 1..4096)", .{v});
            return error.InvalidArgs;
        };
    }
    if (cfg.get("oidc", "idp_connect_timeout_ms")) |v| {
        pool_options.connect_timeout_ms = parseBounded(u32, v, 100, 60000) orelse {
            log.err("invalid [oidc] idp_connect_timeout_ms '{s}' (want 100..60000)", .{v});
            return error.InvalidArgs;
        };
    }
    if (cfg.get("oidc", "idp_timeout_ms")) |v| {
        pool_options.timeout_ms = parseBounded(u32, v, pool_options.connect_timeout_ms, 120000) orelse {
            log.err("invalid [oidc] idp_timeout_ms '{s}' (want {d}..120000)", .{ v, pool_options.connect_timeout_ms });
            return error.InvalidArgs;
        };
    }

    log.info("xmppd-auth-oidc starting", .{});
    log.info("  issuer: {s}", .{issuer});
    log.info("  client_id: {s}", .{client_id});
    log.info("  token_endpoint: {s}", .{token_endpoint});
    log.info("  jwks_uri: {s}", .{jwks_uri});
    if (user_domain) |d| log.info("  user_domain: {s}", .{d});
    log.info("  socket: {s}", .{socket_path});
    log.info("  idp pool: {d} threads, {d} max outstanding, connect {d} ms, timeout {d} ms", .{
        pool_options.threads,
        pool_options.max_outstanding,
        pool_options.connect_timeout_ms,
        pool_options.timeout_ms,
    });

    // Initialize OIDC store
    var oidc_store = OidcStore.init(allocator, OidcConfig{
        .issuer = issuer,
        .client_id = client_id,
        .client_secret = client_secret,
        .token_endpoint = token_endpoint,
        .jwks_uri = jwks_uri,
        .introspection_endpoint = introspection_endpoint,
        .ca_file = ca_file,
        .user_domain = user_domain,
    });
    defer oidc_store.deinit();
    oidc_store.start() catch {
        log.err("OIDC HTTPS client init failed, refusing to start", .{});
        return error.TlsInitFailed;
    };

    // Initialize rate limiter
    var rate_policy = RatePolicy{};
    if (cfg.get("oidc", "rate_max_per_account")) |v| {
        rate_policy.max_per_account = std.fmt.parseInt(u32, v, 10) catch rate_policy.max_per_account;
    }
    if (cfg.get("oidc", "rate_max_per_ip")) |v| {
        rate_policy.max_per_ip = std.fmt.parseInt(u32, v, 10) catch rate_policy.max_per_ip;
    }
    var rate_limiter = try RateLimiter.init(allocator, rate_policy);
    defer rate_limiter.deinit();

    // Initialize auth handler (generic over OidcStore)
    var handler = AuthHandler.init(allocator, &oidc_store);
    const rate_limit_disabled = if (cfg.get("oidc", "rate_limit")) |v| std.mem.eql(u8, v, "false") else false;
    if (!rate_limit_disabled) {
        handler.setRateLimiter(&rate_limiter);
    } else {
        log.warn("auth rate limiting DISABLED -- no brute-force protection (benchmark/testing only)", .{});
    }
    defer handler.deinit();

    // Permanent account locks come from the shared store, read-only, no
    // creation: an OIDC daemon seeing an empty/missing store must not boot
    // into fail-open (S3). A startup error kills the daemon outright. A
    // fresh install (missing environment or namespaces) is provisioned once
    // read-write and reopened read-only; every other open fault kills the
    // daemon instead of being provisioned over.
    var auth_path_buf: [1024]u8 = undefined;
    const auth_path = std.fmt.bufPrint(&auth_path_buf, "{s}/auth", .{db_path}) catch return error.InvalidArgs;
    var lock_backend: OpBackendType = undefined;
    var lock_store = openLockStore(OpBackendType, allocator, auth_path, map_size_mb * 1024 * 1024, &lock_backend) catch |err| {
        log.err("lock store open failed for {s}, refusing to start: {}", .{ auth_path, err });
        return err;
    };
    defer lock_backend.close();
    handler.setLockChecker(handler_mod.makeLockChecker(OpBackendType, &lock_store, allocator));

    var daemon: Daemon = undefined;
    try daemon.init(allocator, &oidc_store, &handler, socket_path, pool_options);
    defer daemon.deinit();
    daemon.run();

    log.info("xmppd-auth-oidc shutdown complete", .{});
}

/// Parse a config integer and reject values outside [min, max].
fn parseBounded(comptime T: type, value: []const u8, min: T, max: T) ?T {
    const n = std.fmt.parseInt(T, value, 10) catch return null;
    if (n < min or n > max) return null;
    return n;
}

/// An auth_request parked while its IdP exchange runs on a pool worker.
/// `owned` is one allocation holding client_ip ++ username ++ payload ++
/// cb_data; it is wiped before free (the payload carries the password).
const Pending = struct {
    slot: u16,
    /// ipc_gens at dispatch: a completion replaying onto a recycled lane
    /// slot is dropped instead of answering the wrong connection.
    slot_gen: u32,
    conn_id: u32,
    mechanism: protocol.MechanismId,
    cb_type: u8,
    owned: []u8,
    client_ip_len: u16,
    username_len: u16,
    payload_len: u16,
    cb_data_len: u16,
    /// Canonical account key for the in-flight cap; empty for OAUTHBEARER.
    account_key: [lock_store_mod.MAX_KEY_LEN]u8 = undefined,
    account_key_len: u16 = 0,
    /// Set by auth_abort or lane close: the pool job still runs and still
    /// spends the in-flight caps until its completion is consumed; the
    /// verdict is then discarded without a replay.
    orphaned: bool = false,

    fn clientIp(self: *const Pending) []const u8 {
        return self.owned[0..self.client_ip_len];
    }

    fn accountKey(self: *const Pending) []const u8 {
        return self.account_key[0..self.account_key_len];
    }
};

/// The OIDC auth daemon: one event loop on kqueue, one bounded worker pool
/// for blocking IdP exchanges, and a pending table correlating jobs back to
/// the request that queued them. Built in place (batch borrows scratch).
pub const Daemon = struct {
    allocator: Allocator,
    store: *OidcStore,
    handler: *AuthHandler,

    ipc: *IpcServer,
    loop: EventLoop,
    pool: IdpPool,

    /// Scratch for batching kqueue changes across one iteration; sized for
    /// the worst iteration like xmppd-auth (S22).
    scratch: [2 * MAX_IPC_CLIENTS + 8]posix.Kevent = undefined,
    batch: ChangeList = undefined,

    /// ABA guard bumped on every accept so a stale completion cannot land
    /// on a connection that reused the slot.
    ipc_gens: [MAX_IPC_CLIENTS]u32 = [_]u32{0} ** MAX_IPC_CLIENTS,
    /// Lanes that gained outbound backlog this iteration; flushed once at
    /// the end of step().
    flush_pending: [MAX_IPC_CLIENTS]bool = [_]bool{false} ** MAX_IPC_CLIENTS,

    /// Dispatched exchanges awaiting a completion, keyed by job id.
    /// Capacity is ensured at init for the pool bound; it never grows on
    /// the hot path.
    pending: std.AutoHashMapUnmanaged(u64, Pending) = .empty,

    running: bool = true,

    pub fn init(self: *Daemon, allocator: Allocator, store: *OidcStore, handler: *AuthHandler, socket_path: []const u8, pool_options: IdpPool.Options) !void {
        self.allocator = allocator;
        self.store = store;
        self.handler = handler;
        self.pending = .empty;
        self.ipc_gens = [_]u32{0} ** MAX_IPC_CLIENTS;
        self.flush_pending = [_]bool{false} ** MAX_IPC_CLIENTS;
        self.running = true;
        self.batch = ChangeList.init(&self.scratch);

        const ipc = try allocator.create(IpcServer);
        errdefer allocator.destroy(ipc);
        ipc.* = IpcServer.init(allocator);
        try ipc.listen(socket_path);
        errdefer ipc.deinit();
        self.ipc = ipc;

        self.loop = try EventLoop.init(allocator, 32);
        errdefer self.loop.deinit();

        self.pool = .{};
        try self.pool.start(allocator, store, pool_options);
        errdefer self.pool.stop();

        try self.pending.ensureTotalCapacity(allocator, pool_options.max_outstanding);
        errdefer self.pending.deinit(allocator);

        try self.loop.addFd(ipc.listen_fd, .read, LISTENER_UDATA);
        try self.loop.addFd(self.pool.wake_rd, .read, POOL_UDATA);
        try self.loop.addSignal(posix.SIG.TERM);
        try self.loop.addSignal(posix.SIG.INT);
        try self.loop.addSignal(posix.SIG.HUP);
    }

    /// One poll iteration: submit staged changes, dispatch the events, then
    /// flush every lane that gained backlog once.
    pub fn step(self: *Daemon, timeout_ms: ?u32) !void {
        const events = self.loop.submitAndPoll(self.batch.slice(), timeout_ms) catch |err| {
            log.err("event loop poll failed: {}", .{err});
            return err;
        };
        self.batch.reset();

        for (events) |ev| {
            switch (ev) {
                .signal => |s| {
                    if (s.signo == posix.SIG.TERM or s.signo == posix.SIG.INT) {
                        log.info("received signal {d}, shutting down", .{s.signo});
                        self.running = false;
                    } else if (s.signo == posix.SIG.HUP) {
                        log.info("received SIGHUP (no-op for OIDC backend)", .{});
                    }
                },
                .fd_readable => |e| {
                    if (e.udata == LISTENER_UDATA) {
                        self.acceptClient();
                    } else if (e.udata == POOL_UDATA) {
                        self.pumpCompletions();
                    } else if (e.udata >= CLIENT_UDATA_BASE) {
                        const slot = e.udata - CLIENT_UDATA_BASE;
                        self.handleIpcClient(slot);
                    }
                },
                .fd_writable => |e| {
                    if (e.udata >= CLIENT_UDATA_BASE) {
                        const slot = e.udata - CLIENT_UDATA_BASE;
                        self.flushIpcClient(slot);
                    }
                },
                else => {},
            }
        }

        // Coalesced flush (same shape as xmppd-auth, S22): a lane still
        // holding backlog gets a one-shot write arm; a staging failure
        // strands its replies, so close it loudly.
        for (&self.flush_pending, 0..) |*dirty, slot| {
            if (!dirty.*) continue;
            dirty.* = false;
            const conn = self.ipc.getClient(slot) orelse continue;
            _ = conn.flush() catch {
                log.err("IPC client {d} flush error: closing", .{slot});
                self.closeLane(slot);
                continue;
            };
            if (conn.hasPendingSend()) {
                self.batch.addWriteOnce(conn.fd, CLIENT_UDATA_BASE + slot) catch {
                    log.err("change list full arming write for IPC slot {d}: closing the lane", .{slot});
                    self.closeLane(slot);
                    continue;
                };
            }
        }
    }

    pub fn run(self: *Daemon) void {
        while (self.running) {
            self.step(null) catch break;
        }
    }

    pub fn deinit(self: *Daemon) void {
        // Pool first: closing the cancel pipe ends in-flight HTTP so the
        // worker join returns promptly.
        self.pool.stop();
        var it = self.pending.iterator();
        var guard: usize = self.pending.count() + 1;
        while (guard > 0) : (guard -= 1) {
            const e = it.next() orelse break;
            self.freePending(e.value_ptr.*);
        }
        self.pending.deinit(self.allocator);
        self.ipc.deinit();
        self.allocator.destroy(self.ipc);
        self.loop.deinit();
    }

    fn acceptClient(self: *Daemon) void {
        const slot = (self.ipc.accept() catch |err| {
            log.err("IPC accept failed: {s}", .{@errorName(err)});
            return;
        }) orelse return;
        self.ipc_gens[slot] +%= 1;
        const conn = self.ipc.getClient(slot) orelse return;
        self.batch.addRead(conn.fd, CLIENT_UDATA_BASE + slot) catch {
            log.err("change list full accepting IPC slot {d}: closing the lane", .{slot});
            self.closeLane(slot);
            return;
        };

        // Send MechanismList: OAUTHBEARER + PLAIN
        const mechs = [_]protocol.MechanismId{ .oauthbearer, .plain };
        const ml_msg = protocol.Message{ .mechanism_list = protocol.MechanismList.init(&mechs) };
        conn.queueSend(ml_msg) catch {
            self.closeLane(slot);
            return;
        };
        if (conn.hasPendingSend()) {
            self.flush_pending[slot] = true;
        }
    }

    /// Close an IPC client lane: its sessions and staged changes die with
    /// it, and pending exchanges for it are orphaned (their jobs still
    /// spend the caps until the completions are consumed).
    fn closeLane(self: *Daemon, slot: usize) void {
        self.handler.closeLaneSessions(slot);
        if (self.ipc.getClient(slot)) |conn| self.batch.purgeFd(conn.fd);
        self.ipc.closeClient(slot);
        self.flush_pending[slot] = false;
        self.dropPending(@intCast(slot), null);
    }

    fn handleIpcClient(self: *Daemon, slot: usize) void {
        const conn = self.ipc.getClient(slot) orelse return;

        const n = conn.recv() catch {
            self.closeLane(slot);
            return;
        };
        if (n == 0) {
            self.closeLane(slot);
            return;
        }

        // Process all complete messages
        while (true) {
            const msg = conn.nextMessage() catch {
                self.closeLane(slot);
                return;
            };
            if (msg == null) break;
            self.dispatch(msg.?, @intCast(slot));
            // dispatch may have closed the lane on a send failure.
            if (self.ipc.getClient(slot) == null) return;
        }
    }

    /// Route one message: IdP-bound mechanisms go to the pool, aborts drop
    /// their pending entry, everything else goes straight to the handler.
    fn dispatch(self: *Daemon, msg: protocol.Message, slot: u16) void {
        switch (msg) {
            .auth_request => |req| {
                switch (req.mechanism) {
                    .plain, .oauthbearer => {
                        if (self.tryQueueIdp(req, slot)) return;
                    },
                    else => {},
                }
            },
            .auth_abort => |a| {
                self.dropPending(slot, a.conn_id);
            },
            else => {},
        }
        self.deliver(msg, slot);
    }

    /// Intercept a PLAIN or OAUTHBEARER auth_request: run the handler's own
    /// admission in its own order so the attempt is charged exactly once
    /// before the IdP is asked, bound in-flight work, and queue the
    /// exchange. Returns true when the message was consumed (queued or
    /// answered directly); false means the handler should process it.
    fn tryQueueIdp(self: *Daemon, req: protocol.AuthRequest, slot: u16) bool {
        var cred: oidc.Credential = undefined;
        var account_identity: []const u8 = "";
        switch (req.mechanism) {
            .plain => {
                // Parse first, exactly like the handler: a malformed
                // payload is invalid-encoding before anything is counted,
                // so it falls through to the handler's own answer.
                const creds = oidc.plainCredentials(req.payload) orelse return false;
                // The same admission the handler runs before the IdP call:
                // count the IP attempt, then re-check the locks. A denial
                // is answered here because the replay no longer re-counts.
                if (self.handler.policy.admitIp(req.client_ip)) |reason| {
                    self.replyAuthFailure(req.conn_id, slot, reason);
                    return true;
                }
                if (self.handler.policy.check(creds.username, req.client_ip)) |reason| {
                    self.replyAuthFailure(req.conn_id, slot, reason);
                    return true;
                }
                cred = .{ .password = .{
                    .username = creds.username,
                    .password = creds.password,
                } };
                account_identity = creds.username;
            },
            .oauthbearer => {
                // The handler admits the IP before parsing, so a malformed
                // payload still spends one attempt.
                if (self.handler.policy.admitIp(req.client_ip)) |reason| {
                    self.replyAuthFailure(req.conn_id, slot, reason);
                    return true;
                }
                const token = oidc.bearerToken(req.payload) orelse {
                    self.replyAuthFailure(req.conn_id, slot, "invalid-encoding");
                    return true;
                };
                cred = .{ .token = token };
            },
            else => return false,
        }

        // In-flight caps: queued and running exchanges per account key and
        // per client IP. Over the cap answers directly; the attempt stays
        // admitted but no outcome is recorded.
        var account_key_buf: [policy_mod.account_key_max]u8 = undefined;
        const full_key: []const u8 = if (account_identity.len > 0)
            policy_mod.accountKey(account_identity, &account_key_buf)
        else
            "";
        // The cap table key is bounded like the lock store's; an
        // untrackable key simply never matches a cap bucket.
        const account_key: []const u8 = if (full_key.len <= lock_store_mod.MAX_KEY_LEN) full_key else "";

        var same_account: usize = 0;
        var same_ip: usize = 0;
        var it = self.pending.valueIterator();
        while (it.next()) |pend| {
            if (account_key.len > 0 and std.mem.eql(u8, pend.accountKey(), account_key)) same_account += 1;
            if (std.mem.eql(u8, pend.clientIp(), req.client_ip)) same_ip += 1;
        }
        if (same_account >= max_inflight_per_account or same_ip >= max_inflight_per_ip) {
            self.replyTemporary(req.conn_id, slot);
            return true;
        }

        // Own the request bytes for the replay: the recv buffer is
        // recycled. Copied before queueing so an OOM here cannot leave an
        // orphan job running against the IdP.
        const owned_len = req.client_ip.len + req.username.len + req.payload.len + req.cb_data.len;
        const owned = self.allocator.alloc(u8, owned_len) catch {
            self.replyTemporary(req.conn_id, slot);
            return true;
        };
        var off: usize = 0;
        @memcpy(owned[off..][0..req.client_ip.len], req.client_ip);
        off += req.client_ip.len;
        @memcpy(owned[off..][0..req.username.len], req.username);
        off += req.username.len;
        @memcpy(owned[off..][0..req.payload.len], req.payload);
        off += req.payload.len;
        @memcpy(owned[off..][0..req.cb_data.len], req.cb_data);

        var pend = Pending{
            .slot = slot,
            .slot_gen = self.ipc_gens[slot],
            .conn_id = req.conn_id,
            .mechanism = req.mechanism,
            .cb_type = req.cb_type,
            .owned = owned,
            .client_ip_len = @intCast(req.client_ip.len),
            .username_len = @intCast(req.username.len),
            .payload_len = @intCast(req.payload.len),
            .cb_data_len = @intCast(req.cb_data.len),
            .account_key_len = @intCast(account_key.len),
        };
        @memcpy(pend.account_key[0..account_key.len], account_key);

        const job_id = self.pool.put(cred) catch {
            std.crypto.secureZero(u8, owned);
            self.allocator.free(owned);
            self.replyTemporary(req.conn_id, slot);
            return true;
        };

        // Capacity was ensured for the pool bound at init; outstanding jobs
        // can never exceed it.
        self.pending.putAssumeCapacity(job_id, pend);
        return true;
    }

    /// Answer a request with an auth_failure reason without handler
    /// involvement. Pre-gate denials carry the policy's own reason so the
    /// client sees what a direct request would have seen.
    fn replyAuthFailure(self: *Daemon, conn_id: u32, slot: u16, reason: []const u8) void {
        const conn = self.ipc.getClient(slot) orelse return;
        conn.queueSend(.{ .auth_failure = .{
            .conn_id = conn_id,
            .reason = reason,
        } }) catch {
            self.closeLane(slot);
            return;
        };
        if (conn.hasPendingSend()) self.flush_pending[slot] = true;
    }

    /// Answer a request temporary-auth-failure without handler involvement:
    /// in-flight caps and a full pool are transport backpressure, not a
    /// failed credential, so nothing is counted or recorded.
    fn replyTemporary(self: *Daemon, conn_id: u32, slot: u16) void {
        self.replyAuthFailure(conn_id, slot, "temporary-auth-failure");
    }

    /// Deliver a message to the handler and queue its reply.
    fn deliver(self: *Daemon, msg: protocol.Message, slot: u16) void {
        const conn = self.ipc.getClient(slot) orelse return;
        switch (self.handler.handleMessage(msg, slot, self.ipc_gens[slot])) {
            .reply => |response| {
                conn.queueSend(response) catch {
                    self.closeLane(slot);
                    return;
                };
                // Clean up session after sending success/failure
                // (lane, conn_id) keyed, matching xmppd-auth (T279).
                switch (response) {
                    .auth_success => |s| self.handler.cleanupSession(slot, s.conn_id),
                    .auth_failure => |f| self.handler.cleanupSession(slot, f.conn_id),
                    else => {},
                }
                if (conn.hasPendingSend()) self.flush_pending[slot] = true;
            },
            .deferred, .none => {},
        }
    }

    /// Drain finished exchanges and replay each through the handler with
    /// its answer parked in store.answer.
    fn pumpCompletions(self: *Daemon) void {
        self.pool.drainWake();
        while (self.pool.popCompletion()) |job_in| {
            var job = job_in;
            defer IdpPool.releaseJob(&job);

            const kv = self.pending.fetchRemove(job.id) orelse {
                log.debug("stale IdP completion {d} dropped (aborted or lane closed)", .{job.id});
                continue;
            };
            const pend = kv.value;
            defer self.freePending(pend);

            // An orphaned exchange ran to completion anyway: consume it to
            // release its cap slot, but never replay or answer it.
            if (pend.orphaned) continue;

            const slot: usize = pend.slot;
            if (slot >= MAX_IPC_CLIENTS or self.ipc_gens[slot] != pend.slot_gen) {
                log.debug("IdP completion {d} dropped: lane recycled", .{job.id});
                continue;
            }
            const conn = self.ipc.getClient(slot) orelse continue;

            // Rebuild the request from the owned copy and replay it through
            // the handler, which is the only place that counts attempts.
            var off: usize = 0;
            const client_ip = pend.owned[off..][0..pend.client_ip_len];
            off += pend.client_ip_len;
            const username = pend.owned[off..][0..pend.username_len];
            off += pend.username_len;
            const payload = pend.owned[off..][0..pend.payload_len];
            off += pend.payload_len;
            const cb_data = pend.owned[off..][0..pend.cb_data_len];

            // An IP lock that engaged since admission denies the parked
            // verdict, exactly as the handler's own lock check would have
            // for a direct request.
            if (self.handler.policy.check("", client_ip)) |reason| {
                self.replyAuthFailure(pend.conn_id, pend.slot, reason);
                continue;
            }

            const req = protocol.AuthRequest{
                .conn_id = pend.conn_id,
                .mechanism = pend.mechanism,
                // The attempt was already admitted at dispatch; an empty
                // IP keeps the replay's admitIp free and its lock checks
                // account-only, so nothing is counted twice.
                .client_ip = "",
                .cb_type = pend.cb_type,
                .cb_data = cb_data,
                .username = username,
                .payload = payload,
            };

            self.store.answer = &job.answer;
            const result = self.handler.handleMessage(.{ .auth_request = req }, pend.slot, pend.slot_gen);
            self.store.answer = null;

            switch (result) {
                .reply => |response| {
                    // Mirror the IP-side outcome the handler could not see
                    // with an empty client_ip: credential verdicts only,
                    // matching where a direct request records.
                    switch (response) {
                        .auth_success => self.handler.policy.recordOutcome("", client_ip, .success),
                        .auth_failure => |f| {
                            if (std.mem.eql(u8, f.reason, "not-authorized")) {
                                self.handler.policy.recordOutcome("", client_ip, .failure);
                            }
                        },
                        else => {},
                    }
                    conn.queueSend(response) catch {
                        self.closeLane(slot);
                        continue;
                    };
                    switch (response) {
                        .auth_success => |s| self.handler.cleanupSession(pend.slot, s.conn_id),
                        .auth_failure => |f| self.handler.cleanupSession(pend.slot, f.conn_id),
                        else => {},
                    }
                    if (conn.hasPendingSend()) self.flush_pending[slot] = true;
                },
                .deferred, .none => {
                    // Unreachable for a real mechanism, but a replay that
                    // produced no reply must never leave the client hanging.
                    log.err("IdP replay produced no reply for conn_id {d}", .{pend.conn_id});
                    self.replyTemporary(pend.conn_id, pend.slot);
                },
            }
        }
    }

    fn flushIpcClient(self: *Daemon, slot: usize) void {
        const conn = self.ipc.getClient(slot) orelse return;

        _ = conn.flush() catch {
            self.closeLane(slot);
            return;
        };

        if (conn.hasPendingSend()) {
            self.batch.addWriteOnce(conn.fd, CLIENT_UDATA_BASE + slot) catch {
                log.err("change list full arming write for IPC slot {d}: closing the lane", .{slot});
                self.closeLane(slot);
            };
        }
    }

    fn freePending(self: *Daemon, pend: Pending) void {
        std.crypto.secureZero(u8, pend.owned);
        self.allocator.free(pend.owned);
    }

    /// Orphan pending entries for a lane, or one exchange on a lane when
    /// conn_id is given (auth_abort). Their jobs keep running and keep
    /// spending the in-flight caps; the completions are consumed without
    /// a replay.
    fn dropPending(self: *Daemon, slot: u16, conn_id: ?u32) void {
        var it = self.pending.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.slot != slot) continue;
            if (conn_id) |cid| {
                if (e.value_ptr.conn_id != cid) continue;
            }
            e.value_ptr.orphaned = true;
            if (conn_id != null) return;
        }
    }
};

/// Open the lock store the handler checks against. This daemon is the writer
/// of record for the locks namespace in an OIDC deployment, so the legacy-key
/// migration runs here on a short-lived read-write handle: legacy rows would
/// otherwise stay in place and every lock-check miss would scan the whole
/// namespace on the auth loop thread (S3). The store is then opened read-only
/// and told the namespace is canonical when the migration ran, so its misses
/// skip the legacy scan from the first check on.
fn openLockStore(
    comptime Backend: type,
    allocator: std.mem.Allocator,
    auth_path: []const u8,
    map_size: usize,
    backend: *Backend,
) !lock_store_mod.LockStore(Backend) {
    const canonical = try lock_store_mod.migrateIfWritable(Backend, allocator, auth_path, .{
        .map_size = map_size,
    });
    backend.* = try lock_store_mod.openReadOnlyProvisioned(Backend, auth_path, .{
        .map_size = map_size,
    });
    var store = lock_store_mod.LockStore(Backend).init(backend);
    if (canonical) store.learnLegacyFree();
    return store;
}

fn printUsage() void {
    const usage =
        \\Usage: xmppd-auth-oidc [OPTIONS]
        \\
        \\Options:
        \\  --config PATH     Config file path (default: /usr/local/etc/xmppd/xmppd.conf)
        \\  --socket PATH     IPC socket path (default: /var/run/xmppd/auth.sock)
        \\  --help, -h        Show this help
        \\
        \\Required config [oidc] section:
        \\  issuer            OIDC issuer URL
        \\  client_id         OAuth2 client ID
        \\  client_secret     OAuth2 client secret
        \\  token_endpoint    Token endpoint URL (for ROPC)
        \\  jwks_uri          JWKS endpoint URL
        \\
        \\Optional config [oidc] section:
        \\  ca_file           CA bundle path (default: system)
        \\  socket            Override IPC socket path
        \\  rate_max_per_account  Rate limit per account (default: 60)
        \\  rate_max_per_ip       Rate limit per IP (default: 200)
        \\  idp_threads           IdP worker threads (default: 8, range 1..32)
        \\  idp_max_outstanding   Max queued+running IdP exchanges (default: 256, range 1..4096)
        \\  idp_connect_timeout_ms  Connect+handshake budget (default: 3000, range 100..60000)
        \\  idp_timeout_ms          Whole-exchange deadline (default: 10000, <= 120000)
        \\
    ;
    var buf: [0]u8 = .{};
    var stdout = std.fs.File.stdout().writer(&buf);
    stdout.interface.writeAll(usage) catch {};
}

// ============================================================================
// Tests
// ============================================================================

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
});

test "oidc daemon: the start path migrates legacy lock keys before the read-only open" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const store_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(store_path);

    // One canonical row and one written before keys were case-folded.
    {
        var rw = try OpBackendType.open(store_path, .{ .map_size = 1024 * 1024 });
        defer rw.close();
        var seed = LockStore.init(&rw);
        try seed.lock("bob", .permanent);
        try rw.put(lock_store_mod.NAMESPACE, "Alice", &[_]u8{ 0x01, 0, 0, 0, 7 });
    }

    var backend: OpBackendType = undefined;
    var store = try openLockStore(OpBackendType, allocator, store_path, 1024 * 1024, &backend);
    defer backend.close();

    // The migration ran before the read-only open: the pre-fold row is gone
    // and its canonical key carries the record.
    const legacy = try store.backend.get(allocator, lock_store_mod.NAMESPACE, "Alice");
    defer if (legacy) |v| allocator.free(v);
    try std.testing.expect(legacy == null);
    const canon = try store.backend.get(allocator, lock_store_mod.NAMESPACE, "alice");
    defer if (canon) |v| allocator.free(v);
    try std.testing.expect(canon != null);

    // The read-only handle serves both accounts.
    const alice = (try store.isLocked(allocator, "ALICE")) orelse return error.NotLocked;
    try std.testing.expectEqual(@as(u32, 7), alice.locked_epoch);
    try std.testing.expect((try store.isLocked(allocator, "bob")) != null);
}

// --- Test harness: raw unix-socket IPC client + TCP/TLS IdP stubs ---------

const IpcTestClient = struct {
    fd: posix.fd_t,
    conn: IpcConn,

    fn connect(allocator: Allocator, path: []const u8) !IpcTestClient {
        const fd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
        errdefer posix.close(fd);
        var addr: std.c.sockaddr.un = std.mem.zeroes(std.c.sockaddr.un);
        addr.family = posix.AF.UNIX;
        if (path.len >= addr.path.len) return error.PathTooLong;
        @memcpy(addr.path[0..path.len], path);
        posix.connect(fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.un)) catch |err| switch (err) {
            error.WouldBlock, error.ConnectionPending => {},
            else => return err,
        };
        return .{
            .fd = fd,
            .conn = .{
                .fd = fd,
                .alloc = allocator,
                .recv_buf = try allocator.alloc(u8, protocol.MAX_FRAME_SIZE),
            },
        };
    }

    fn close(self: *IpcTestClient) void {
        self.conn.close();
    }

    fn send(self: *IpcTestClient, msg: protocol.Message) !void {
        try self.conn.queueSend(msg);
        var tries: usize = 100;
        while (self.conn.hasPendingSend() and tries > 0) : (tries -= 1) {
            _ = try self.conn.flush();
        }
        if (self.conn.hasPendingSend()) return error.SendStalled;
    }

    /// Next reply message, stepping the daemon between reads; null on timeout.
    fn nextReply(self: *IpcTestClient, daemon: *Daemon, timeout_ms: i64) !?protocol.Message {
        const deadline = std.time.milliTimestamp() + timeout_ms;
        while (std.time.milliTimestamp() < deadline) {
            if (try self.conn.nextMessage()) |m| return m;
            _ = self.conn.recv() catch 0;
            try daemon.step(10);
        }
        return null;
    }
};

/// A daemon wired for tests: no lock checker, a rate limiter behind
/// handler.policy, and a fresh unix socket under tmpDir. Initialized in
/// place: handler and daemon hold pointers into this struct.
var fixture_counter = std.atomic.Value(u32).init(0);

const DaemonFixture = struct {
    tmp: std.testing.TmpDir,
    sock_path: []u8 = &.{},
    limiter: RateLimiter = undefined,
    store: OidcStore = undefined,
    handler: AuthHandler = undefined,
    daemon: Daemon = undefined,

    fn init(self: *DaemonFixture, allocator: Allocator, token_endpoint: []const u8, ca_file: ?[]const u8, limiter_policy: ?RatePolicy, pool_options: IdpPool.Options) !void {
        self.* = .{ .tmp = std.testing.tmpDir(.{}) };
        errdefer self.tmp.cleanup();

        // Short unique path: unix socket paths are capped at sun_path.
        const n = fixture_counter.fetchAdd(1, .monotonic);
        self.sock_path = try std.fmt.allocPrint(allocator, "/tmp/oidc-test-{d}-{d}.sock", .{ std.c.getpid(), n });
        errdefer allocator.free(self.sock_path);

        self.store = OidcStore.init(allocator, .{
            .issuer = "https://idp.example/",
            .client_id = "xmppd",
            .client_secret = "secret",
            .token_endpoint = token_endpoint,
            .jwks_uri = token_endpoint,
            .ca_file = ca_file,
        });
        try self.store.start();
        errdefer self.store.deinit();

        self.limiter = try RateLimiter.init(allocator, limiter_policy orelse .{});
        errdefer self.limiter.deinit();

        self.handler = AuthHandler.init(allocator, &self.store);
        self.handler.setRateLimiter(&self.limiter);
        errdefer self.handler.deinit();

        try self.daemon.init(allocator, &self.store, &self.handler, self.sock_path, pool_options);
    }

    fn deinit(self: *DaemonFixture, allocator: Allocator) void {
        self.daemon.deinit();
        self.handler.deinit();
        self.limiter.deinit();
        self.store.deinit();
        allocator.free(self.sock_path);
        self.tmp.cleanup();
    }
};

/// Connect a test client and read back its mechanism_list.
fn connectClient(allocator: Allocator, fx: *DaemonFixture) !IpcTestClient {
    var client = try IpcTestClient.connect(allocator, fx.sock_path);
    errdefer client.close();
    // Drive the accept and the mechanism_list flush.
    const dl = std.time.milliTimestamp() + 2000;
    while (std.time.milliTimestamp() < dl) {
        try fx.daemon.step(10);
        _ = client.conn.recv() catch 0;
        if (try client.conn.nextMessage()) |m| {
            try std.testing.expect(std.meta.activeTag(m) == .mechanism_list);
            return client;
        }
    }
    return error.AcceptTimeout;
}

fn plainAuth(conn_id: u32, username: []const u8, password: []const u8, client_ip: []const u8) protocol.Message {
    var payload_buf: [512]u8 = undefined;
    const payload = std.fmt.bufPrint(&payload_buf, "\x00{s}\x00{s}", .{ username, password }) catch unreachable;
    const owned = std.testing.allocator.dupe(u8, payload) catch unreachable;
    return .{ .auth_request = .{
        .conn_id = conn_id,
        .mechanism = .plain,
        .client_ip = client_ip,
        .cb_type = 0,
        .cb_data = "",
        .username = username,
        .payload = owned,
    } };
}

/// Test allocator that fails every allocation of `bad_len` while armed.
const FailOnLen = struct {
    inner: Allocator,
    armed: bool = false,
    bad_len: usize = 0,

    fn allocator(self: *FailOnLen) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = allocFn,
                .resize = resizeFn,
                .remap = remapFn,
                .free = freeFn,
            },
        };
    }

    fn allocFn(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *FailOnLen = @ptrCast(@alignCast(ctx));
        if (self.armed and len == self.bad_len) return null;
        return self.inner.rawAlloc(len, alignment, ra);
    }

    fn resizeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *FailOnLen = @ptrCast(@alignCast(ctx));
        return self.inner.rawResize(memory, alignment, new_len, ra);
    }

    fn remapFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *FailOnLen = @ptrCast(@alignCast(ctx));
        return self.inner.rawRemap(memory, alignment, new_len, ra);
    }

    fn freeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *FailOnLen = @ptrCast(@alignCast(ctx));
        self.inner.rawFree(memory, alignment, ra);
    }
};

fn rawAuth(conn_id: u32, mechanism: protocol.MechanismId, username: []const u8, payload: []const u8, client_ip: []const u8) protocol.Message {
    return .{ .auth_request = .{
        .conn_id = conn_id,
        .mechanism = mechanism,
        .client_ip = client_ip,
        .cb_type = 0,
        .cb_data = "",
        .username = username,
        .payload = payload,
    } };
}

/// Loopback TCP listener that accepts into a hold array and never answers;
/// after `hold_ms` it drops everything so a blocking build under test fails
/// on elapsed time instead of hanging forever.
fn serveHangingTcp(hold_ms: u64, port_out: *std.atomic.Value(u16)) void {
    const listen_fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(listen_fd);
    var addr: std.c.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch return;
    posix.listen(listen_fd, 8) catch return;
    var alen: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    posix.getsockname(listen_fd, @ptrCast(&addr), &alen) catch return;
    port_out.store(std.mem.bigToNative(u16, addr.port), .release);

    const deadline = std.time.milliTimestamp() + @as(i64, @intCast(hold_ms));
    var held: [32]posix.fd_t = undefined;
    var held_len: usize = 0;
    defer for (held[0..held_len]) |fd| posix.close(fd);
    while (std.time.milliTimestamp() < deadline) {
        var fds = [_]posix.pollfd{.{ .fd = listen_fd, .events = posix.POLL.IN, .revents = 0 }};
        const pn = posix.poll(&fds, 100) catch 0;
        if (pn <= 0) continue;
        if (held_len >= held.len) continue;
        const conn_fd = posix.accept(listen_fd, null, null, 0) catch continue;
        held[held_len] = conn_fd;
        held_len += 1;
    }
}

fn startHangingStub(port_out: *std.atomic.Value(u16), hold_ms: u64) !std.Thread {
    const th = try std.Thread.spawn(.{}, serveHangingTcp, .{ hold_ms, port_out });
    const dl = std.time.milliTimestamp() + 3000;
    while (port_out.load(.acquire) == 0 and std.time.milliTimestamp() < dl) std.Thread.sleep(std.time.ns_per_ms);
    try std.testing.expect(port_out.load(.acquire) != 0);
    return th;
}

/// A loopback port that refuses connections (bound then closed).
fn refusedPort() !u16 {
    const listen_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    var addr: std.c.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    try posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in));
    var alen: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    try posix.getsockname(listen_fd, @ptrCast(&addr), &alen);
    const port = std.mem.bigToNative(u16, addr.port);
    posix.close(listen_fd);
    return port;
}

test "a hanging IdP does not stall the loop" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    const stub = try startHangingStub(&port, 3000);
    defer stub.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/token", .{port.load(.acquire)});

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, .{
        .lockout_threshold = 1,
        .max_per_account = 100,
        .max_per_ip = 100,
    }, .{
        .threads = 2,
        .max_outstanding = 16,
        .connect_timeout_ms = 150,
        .timeout_ms = 300,
    });
    defer fx.deinit(allocator);

    var client = try connectClient(allocator, &fx);
    defer client.close();

    // alice's exchange is queued: the IdP never answers inside the test.
    const m1 = plainAuth(1, "alice", "pw", "10.0.0.1");
    defer allocator.free(m1.auth_request.payload);
    try client.send(m1);
    try fx.daemon.step(10);
    try std.testing.expectEqual(@as(usize, 1), fx.daemon.pending.count());

    // The loop keeps serving: a malformed PLAIN is answered by the handler
    // while alice's exchange is still parked.
    const t0 = std.time.milliTimestamp();
    const bad = rawAuth(2, .plain, "mallory", "no-nuls", "10.0.0.1");
    try client.send(bad);
    const reply_bad = (try client.nextReply(&fx.daemon, 300)).?;
    const elapsed = std.time.milliTimestamp() - t0;
    try std.testing.expect(elapsed < 200);
    try std.testing.expect(std.meta.activeTag(reply_bad) == .auth_failure);
    try std.testing.expectEqualStrings("invalid-encoding", reply_bad.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 2), reply_bad.auth_failure.conn_id);

    // alice's exchange dies on its deadline and replays as a temporary
    // failure: the IdP outage is not a failed credential.
    const reply_a = (try client.nextReply(&fx.daemon, 3000)).?;
    try std.testing.expect(std.meta.activeTag(reply_a) == .auth_failure);
    try std.testing.expectEqual(@as(u32, 1), reply_a.auth_failure.conn_id);
    try std.testing.expectEqualStrings("temporary-auth-failure", reply_a.auth_failure.reason);

    // Nothing was recorded: with lockout_threshold 1 a counted failure
    // would have locked alice.
    try std.testing.expect(fx.handler.policy.check("alice", "10.0.0.1") == null);
}

test "a refusing IdP answers temporary-auth-failure and records no failure" {
    const allocator = std.testing.allocator;
    const port = try refusedPort();
    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/token", .{port});

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, .{
        .lockout_threshold = 1,
        .max_per_account = 100,
        .max_per_ip = 100,
    }, .{
        .threads = 4,
        .max_outstanding = 16,
        .connect_timeout_ms = 1000,
        .timeout_ms = 3000,
    });
    defer fx.deinit(allocator);

    var client = try connectClient(allocator, &fx);
    defer client.close();

    for (0..3) |i| {
        const m = plainAuth(@intCast(i + 1), "alice", "pw", "10.0.0.2");
        defer allocator.free(m.auth_request.payload);
        try client.send(m);
        const reply = (try client.nextReply(&fx.daemon, 3000)).?;
        try std.testing.expect(std.meta.activeTag(reply) == .auth_failure);
        try std.testing.expectEqualStrings("temporary-auth-failure", reply.auth_failure.reason);
    }
    // Three IdP outages, zero recorded failures: alice is not locked.
    try std.testing.expect(fx.handler.policy.check("alice", "10.0.0.2") == null);
}

test "a full pool answers temporary-auth-failure at once" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    const stub = try startHangingStub(&port, 5000);
    defer stub.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/token", .{port.load(.acquire)});

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, .{
        .threads = 1,
        .max_outstanding = 2,
        .connect_timeout_ms = 2000,
        .timeout_ms = 8000,
    });
    defer fx.deinit(allocator);

    var client = try connectClient(allocator, &fx);
    defer client.close();

    const m1 = plainAuth(1, "alice", "pw", "10.0.0.1");
    defer allocator.free(m1.auth_request.payload);
    try client.send(m1);
    const m2 = plainAuth(2, "bob", "pw", "10.0.0.2");
    defer allocator.free(m2.auth_request.payload);
    try client.send(m2);
    try fx.daemon.step(10);

    const m3 = plainAuth(3, "carol", "pw", "10.0.0.3");
    defer allocator.free(m3.auth_request.payload);
    const t0 = std.time.milliTimestamp();
    try client.send(m3);
    const reply = (try client.nextReply(&fx.daemon, 500)).?;
    const elapsed = std.time.milliTimestamp() - t0;
    try std.testing.expect(elapsed < 100);
    try std.testing.expect(std.meta.activeTag(reply) == .auth_failure);
    try std.testing.expectEqualStrings("temporary-auth-failure", reply.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 3), reply.auth_failure.conn_id);
}

test "a completion for a closed or reused lane is dropped" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    const stub = try startHangingStub(&port, 3000);
    defer stub.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/token", .{port.load(.acquire)});

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, .{
        .threads = 1,
        .max_outstanding = 8,
        .connect_timeout_ms = 100,
        .timeout_ms = 200,
    });
    defer fx.deinit(allocator);

    // Client A queues an exchange then vanishes before it completes.
    {
        var client_a = try connectClient(allocator, &fx);
        const m = plainAuth(1, "alice", "pw", "10.0.0.1");
        defer allocator.free(m.auth_request.payload);
        try client_a.send(m);
        try fx.daemon.step(10);
        client_a.close();
        // Drive the EOF through the loop.
        try fx.daemon.step(20);
    }

    // Client B reuses the slot at a new generation; only its
    // mechanism_list may ever arrive.
    var client_b = try connectClient(allocator, &fx);
    defer client_b.close();

    // Past the exchange deadline the completion drops as stale.
    const dl = std.time.milliTimestamp() + 1500;
    while (std.time.milliTimestamp() < dl) {
        try fx.daemon.step(10);
        _ = client_b.conn.recv() catch 0;
        if (try client_b.conn.nextMessage()) |_| {
            return error.UnexpectedReply;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), fx.daemon.pending.count());
}

test "an auth_abort orphans the exchange but the cap still counts it" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    const stub = try startHangingStub(&port, 5000);
    defer stub.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/token", .{port.load(.acquire)});

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, .{
        .threads = 1,
        .max_outstanding = 8,
        .connect_timeout_ms = 2000,
        .timeout_ms = 2000,
    });
    defer fx.deinit(allocator);

    var client = try connectClient(allocator, &fx);
    defer client.close();

    // Fill alice's in-flight cap, then abort every exchange. The jobs keep
    // running against the hanging IdP and must keep spending the cap.
    for (0..max_inflight_per_account) |i| {
        const m = plainAuth(@intCast(i + 1), "alice", "pw", "10.0.0.1");
        defer allocator.free(m.auth_request.payload);
        try client.send(m);
        try fx.daemon.step(10);
        try client.send(.{ .auth_abort = .{ .conn_id = @intCast(i + 1) } });
        try fx.daemon.step(10);
    }
    try std.testing.expectEqual(max_inflight_per_account, fx.daemon.pending.count());

    // A further request for alice is backpressured even though every
    // earlier exchange was aborted.
    const m5 = plainAuth(9, "alice", "pw", "10.0.0.9");
    defer allocator.free(m5.auth_request.payload);
    try client.send(m5);
    const reply = (try client.nextReply(&fx.daemon, 500)).?;
    try std.testing.expect(std.meta.activeTag(reply) == .auth_failure);
    try std.testing.expectEqualStrings("temporary-auth-failure", reply.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 9), reply.auth_failure.conn_id);

    // The orphaned completions are consumed, never answered, and release
    // their cap slots.
    const dl = std.time.milliTimestamp() + 3500;
    while (std.time.milliTimestamp() < dl) {
        try fx.daemon.step(10);
        _ = client.conn.recv() catch 0;
        if (try client.conn.nextMessage()) |_| {
            return error.UnexpectedReply;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), fx.daemon.pending.count());
}

test "an OOM on the pending copy queues no orphan job" {
    const allocator = std.testing.allocator;
    const port = try refusedPort();
    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/token", .{port});

    var falloc = FailOnLen{ .inner = allocator };
    const test_alloc = falloc.allocator();

    var fx: DaemonFixture = undefined;
    try fx.init(test_alloc, url, null, null, .{
        .threads = 1,
        .max_outstanding = 8,
        .connect_timeout_ms = 500,
        .timeout_ms = 2000,
    });
    defer fx.deinit(test_alloc);

    var client = try connectClient(test_alloc, &fx);
    defer client.close();

    const m = plainAuth(1, "alice", "pw", "10.0.0.1");
    defer allocator.free(m.auth_request.payload);
    try client.send(m);

    // Fail exactly the pending-copy allocation while the dispatch runs.
    falloc.bad_len = m.auth_request.client_ip.len + m.auth_request.username.len +
        m.auth_request.payload.len + m.auth_request.cb_data.len;
    falloc.armed = true;
    try fx.daemon.step(10);
    falloc.armed = false;

    const reply = (try client.nextReply(&fx.daemon, 1000)).?;
    try std.testing.expectEqual(@as(u32, 1), reply.auth_failure.conn_id);
    try std.testing.expectEqualStrings("temporary-auth-failure", reply.auth_failure.reason);

    // Nothing ever reached the pool: a job queued before the failed copy
    // would run as an orphan and spend an exchange against the IdP.
    const drain = std.time.milliTimestamp() + 500;
    while (std.time.milliTimestamp() < drain) try fx.daemon.step(10);
    try std.testing.expectEqual(@as(usize, 0), fx.daemon.pool.exchanges_run.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), fx.daemon.pool.outstanding());
    try std.testing.expectEqual(@as(usize, 0), fx.daemon.pending.count());
}

test "shutdown with exchanges in flight cancels them" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    const stub = try startHangingStub(&port, 15000);
    defer stub.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/token", .{port.load(.acquire)});

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, .{
        .threads = 2,
        .max_outstanding = 8,
        .connect_timeout_ms = 5000,
        .timeout_ms = 10000,
    });
    // No defer: the test asserts on deinit's own cost.

    var client = try connectClient(allocator, &fx);
    defer client.close();

    for (0..4) |i| {
        const name = try std.fmt.allocPrint(allocator, "u{d}", .{i});
        defer allocator.free(name);
        const m = plainAuth(@intCast(i + 1), name, "pw", "10.0.0.1");
        defer allocator.free(m.auth_request.payload);
        try client.send(m);
        try fx.daemon.step(10);
    }
    try std.testing.expectEqual(@as(usize, 4), fx.daemon.pending.count());

    const t0 = std.time.milliTimestamp();
    fx.deinit(allocator);
    const elapsed = std.time.milliTimestamp() - t0;
    try std.testing.expect(elapsed < 1000);
}

// --- TLS IdP stub for the replay path ------------------------------------

fn genIdpTestCert(dir: std.fs.Dir) !void {
    const r = std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &.{ "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1", "-keyout", "key.pem", "-out", "cert.pem" },
        .cwd_dir = dir,
        .max_output_bytes = 64 * 1024,
    }) catch return error.SkipZigTest;
    defer std.testing.allocator.free(r.stdout);
    defer std.testing.allocator.free(r.stderr);
    switch (r.term) {
        .Exited => |code| {
            if (code != 0) return error.SkipZigTest;
        },
        else => return error.SkipZigTest,
    }
}

/// Serve one HTTPS response on a loopback TLS listener, then return.
fn serveOneTlsResponse(cert_path: [*:0]const u8, key_path: [*:0]const u8, status_line: []const u8, body: []const u8, port_out: *std.atomic.Value(u16)) void {
    const method = c.TLS_server_method() orelse return;
    const ctx = c.SSL_CTX_new(method) orelse return;
    defer c.SSL_CTX_free(ctx);
    if (c.SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1) return;
    if (c.SSL_CTX_use_PrivateKey_file(ctx, key_path, c.SSL_FILETYPE_PEM) != 1) return;

    const listen_fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(listen_fd);
    var addr: std.c.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch return;
    posix.listen(listen_fd, 4) catch return;
    var alen: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    posix.getsockname(listen_fd, @ptrCast(&addr), &alen) catch return;
    port_out.store(std.mem.bigToNative(u16, addr.port), .release);

    const deadline = std.time.milliTimestamp() + 10000;
    while (std.time.milliTimestamp() < deadline) {
        var fds = [_]posix.pollfd{.{ .fd = listen_fd, .events = posix.POLL.IN, .revents = 0 }};
        const pn = posix.poll(&fds, 500) catch 0;
        if (pn <= 0) continue;
        const conn_fd = posix.accept(listen_fd, null, null, 0) catch continue;
        defer posix.close(conn_fd);
        const ssl_ptr = c.SSL_new(ctx) orelse continue;
        defer c.SSL_free(ssl_ptr);
        _ = c.SSL_set_fd(ssl_ptr, conn_fd);
        if (c.SSL_accept(ssl_ptr) != 1) continue;
        var buf: [4096]u8 = undefined;
        var total: usize = 0;
        while (total < buf.len and std.time.milliTimestamp() < deadline) {
            const r = c.SSL_read(ssl_ptr, @ptrCast(buf[total..].ptr), @intCast(buf.len - total));
            if (r <= 0) break;
            total += @intCast(r);
            if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n") != null) break;
        }
        var resp_buf: [8192]u8 = undefined;
        const resp = std.fmt.bufPrint(&resp_buf, "HTTP/1.1 {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ status_line, body.len, body }) catch return;
        _ = c.SSL_write(ssl_ptr, resp.ptr, @intCast(resp.len));
        return;
    }
}

test "a rejected credential replays as not-authorized and records the failure" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genIdpTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(allocator, "{s}/cert.pem", .{base}, 0);
    defer allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(allocator, "{s}/key.pem", .{base}, 0);
    defer allocator.free(key_path);

    var port = std.atomic.Value(u16).init(0);
    const stub = try std.Thread.spawn(.{}, serveOneTlsResponse, .{ cert_path.ptr, key_path.ptr, "400 Bad Request", "{\"error\":\"invalid_grant\"}", &port });
    defer stub.join();
    const dl = std.time.milliTimestamp() + 3000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) std.Thread.sleep(std.time.ns_per_ms);
    const p = port.load(.acquire);
    try std.testing.expect(p != 0);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/token", .{p});

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, cert_path, .{
        .lockout_threshold = 1,
        .max_per_account = 100,
        .max_per_ip = 100,
    }, .{
        .threads = 2,
        .max_outstanding = 8,
        .connect_timeout_ms = 2000,
        .timeout_ms = 5000,
    });
    defer fx.deinit(allocator);

    var client = try connectClient(allocator, &fx);
    defer client.close();

    const m = plainAuth(1, "alice", "wrong-pw", "10.0.0.9");
    defer allocator.free(m.auth_request.payload);
    try client.send(m);
    const reply = (try client.nextReply(&fx.daemon, 5000)).?;
    try std.testing.expect(std.meta.activeTag(reply) == .auth_failure);
    try std.testing.expectEqualStrings("not-authorized", reply.auth_failure.reason);

    // The replayed failure is the handler's own accounting: with
    // lockout_threshold 1 alice is now locked.
    try std.testing.expectEqualStrings("account-disabled", fx.handler.policy.check("alice", "10.0.0.9") orelse return error.ExpectedLock);
}

test "a rate-limited or locked request is denied before the IdP is asked" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    const stub = try startHangingStub(&port, 3000);
    defer stub.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/token", .{port.load(.acquire)});

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, .{
        .max_per_ip = 2,
        .max_per_account = 100,
        .window_seconds = 120,
        .lockout_threshold = 1,
        .ip_lockout_threshold = 1,
    }, .{
        .threads = 1,
        .max_outstanding = 8,
        .connect_timeout_ms = 1500,
        .timeout_ms = 2000,
    });
    defer fx.deinit(allocator);

    var client = try connectClient(allocator, &fx);
    defer client.close();

    // Two admitted attempts fill the IP window; the third is denied at
    // dispatch and never spends an IdP exchange.
    for (0..2) |i| {
        const m = plainAuth(@intCast(i + 1), "alice", "pw", "10.0.0.5");
        defer allocator.free(m.auth_request.payload);
        try client.send(m);
        try fx.daemon.step(10);
    }
    const m3 = plainAuth(3, "alice", "pw", "10.0.0.5");
    defer allocator.free(m3.auth_request.payload);
    try client.send(m3);
    const reply_limited = (try client.nextReply(&fx.daemon, 500)).?;
    try std.testing.expectEqual(@as(u32, 3), reply_limited.auth_failure.conn_id);
    try std.testing.expectEqualStrings("policy-violation", reply_limited.auth_failure.reason);

    // A locked IP is denied at dispatch even for a well-formed request.
    fx.handler.policy.recordOutcome("", "10.0.0.6", .failure);
    const m4 = plainAuth(4, "bob", "pw", "10.0.0.6");
    defer allocator.free(m4.auth_request.payload);
    try client.send(m4);
    const reply_locked_ip = (try client.nextReply(&fx.daemon, 500)).?;
    try std.testing.expectEqualStrings("policy-violation", reply_locked_ip.auth_failure.reason);

    // A locked account is denied at dispatch with the handler's own reason.
    fx.handler.policy.recordOutcome("carol", "", .failure);
    const m5 = plainAuth(5, "carol", "pw", "10.0.0.7");
    defer allocator.free(m5.auth_request.payload);
    try client.send(m5);
    const reply_locked_acct = (try client.nextReply(&fx.daemon, 500)).?;
    try std.testing.expectEqualStrings("account-disabled", reply_locked_acct.auth_failure.reason);

    // A locked IP also denies a well-formed OAUTHBEARER before parsing.
    fx.handler.policy.recordOutcome("", "10.0.0.8", .failure);
    const m6 = rawAuth(6, .oauthbearer, "", "n,,\x01auth=Bearer tok\x01\x01", "10.0.0.8");
    try client.send(m6);
    const reply_bearer = (try client.nextReply(&fx.daemon, 500)).?;
    try std.testing.expectEqualStrings("policy-violation", reply_bearer.auth_failure.reason);

    // Only the two window-filling requests ever reached the pool.
    try std.testing.expect(fx.daemon.pool.exchanges_run.load(.monotonic) <= 2);
    try std.testing.expect(fx.daemon.pending.count() <= 2);
}

test "admission is charged at dispatch; the replay does not charge again" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genIdpTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(allocator, "{s}/cert.pem", .{base}, 0);
    defer allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(allocator, "{s}/key.pem", .{base}, 0);
    defer allocator.free(key_path);

    var port = std.atomic.Value(u16).init(0);
    const stub = try std.Thread.spawn(.{}, serveOneTlsResponse, .{ cert_path.ptr, key_path.ptr, "400 Bad Request", "{\"error\":\"invalid_grant\"}", &port });
    defer stub.join();
    const dl = std.time.milliTimestamp() + 3000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) std.Thread.sleep(std.time.ns_per_ms);
    const p = port.load(.acquire);
    try std.testing.expect(p != 0);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/token", .{p});

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, cert_path, .{
        .max_per_ip = 4,
        .max_per_account = 100,
        .window_seconds = 120,
        .lockout_threshold = 50,
        .ip_lockout_threshold = 50,
    }, .{
        .threads = 1,
        .max_outstanding = 8,
        .connect_timeout_ms = 2000,
        .timeout_ms = 5000,
    });
    defer fx.deinit(allocator);

    var client = try connectClient(allocator, &fx);
    defer client.close();

    const m1 = plainAuth(1, "alice", "wrong-pw", "10.0.0.9");
    defer allocator.free(m1.auth_request.payload);
    try client.send(m1);
    try fx.daemon.step(10);
    try std.testing.expectEqual(@as(usize, 1), fx.daemon.pending.count());

    // While the exchange is in flight, other attempts fill the IP window.
    // The admitted request must still land its own verdict; a fourth
    // attempt beyond the window is denied without touching the IdP.
    _ = fx.handler.policy.admitIp("10.0.0.9");
    _ = fx.handler.policy.admitIp("10.0.0.9");
    _ = fx.handler.policy.admitIp("10.0.0.9");

    const m2 = plainAuth(2, "mallory", "pw", "10.0.0.9");
    defer allocator.free(m2.auth_request.payload);
    try client.send(m2);

    var saw_attacker = false;
    var saw_victim = false;
    const reply_dl = std.time.milliTimestamp() + 8000;
    while (std.time.milliTimestamp() < reply_dl and !(saw_attacker and saw_victim)) {
        const reply = (try client.nextReply(&fx.daemon, 500)) orelse continue;
        if (reply.auth_failure.conn_id == 2) {
            saw_attacker = true;
            try std.testing.expectEqualStrings("policy-violation", reply.auth_failure.reason);
        } else if (reply.auth_failure.conn_id == 1) {
            saw_victim = true;
            // Not the rate-limit denial: the parked verdict is delivered.
            try std.testing.expectEqualStrings("not-authorized", reply.auth_failure.reason);
        }
    }
    try std.testing.expect(saw_attacker);
    try std.testing.expect(saw_victim);

    // Drain completions; the denied request never spent an exchange.
    const drain_dl = std.time.milliTimestamp() + 2000;
    while (fx.daemon.pending.count() > 0 and std.time.milliTimestamp() < drain_dl) {
        try fx.daemon.step(10);
    }
    try std.testing.expectEqual(@as(usize, 1), fx.daemon.pool.exchanges_run.load(.monotonic));

    // Exactly one charge: the counted attempt plus the three window fills
    // is the whole window; the replay added nothing.
    try std.testing.expect(fx.handler.policy.admitIp("10.0.0.9") != null);
}
