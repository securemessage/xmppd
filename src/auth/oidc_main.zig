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
const root_allocator = @import("root_allocator");
pub const std_options = xmppd_log.std_options;

const posix = std.posix;
const Allocator = std.mem.Allocator;
const IpcConn = @import("ipc_server").IpcConn;
const MAX_IPC_CLIENTS = @import("ipc_server").MAX_IPC_CLIENTS;
const handler_mod = @import("handler");
const oidc = @import("oidc");
const OidcStore = oidc.OidcStore;
const OidcConfig = oidc.OidcConfig;
const IdpPool = oidc.IdpPool;
const AuthHandler = handler_mod.AuthHandler(OidcStore);
const protocol = @import("ipc_protocol");
const runner_mod = @import("runner");
const conf = @import("conf");
const schema = @import("schema");
const metrics = @import("auth_metrics");
const RateLimiter = @import("rate_limiter").RateLimiter;
const RatePolicy = @import("rate_limiter").RatePolicy;
const policy_mod = @import("policy");
const OpBackendType = @import("op_backend").Backend;
const ArchiveBackendType = @import("archive_backend").Backend;
const backend_mod = @import("backend");
const lock_store_mod = @import("lock_store");
const oidc_ids = @import("oidc_identity_store");
const LockStore = lock_store_mod.LockStore(OpBackendType);
const BindingStore = oidc_ids.Store(OpBackendType);
const BindingResolver = oidc_ids.Resolver(OpBackendType, ArchiveBackendType);
const MemBindingStore = oidc_ids.Store(backend_mod.MemoryBackend);
const MemBindingResolver = oidc_ids.Resolver(backend_mod.MemoryBackend, backend_mod.MemoryBackend);

/// Mechanisms this daemon advertises on connect; each must have a store
/// capability behind it (checked at compile time).
const AUTH_MECHS = [_]protocol.MechanismId{ .oauthbearer, .plain };

comptime {
    handler_mod.assertMechanisms(OidcStore, &AUTH_MECHS);
}

const log = std.log.scoped(.xmppd_auth_oidc);

/// In-flight IdP exchange caps: a queued or running exchange spends pool
/// capacity, so one account or one client IP may only park so many before
/// the newest request is answered temporary-auth-failure with no
/// rate-limiter outcome recorded.
const max_inflight_per_account: usize = 4;
const max_inflight_per_ip: usize = 16;

const default_config_path = "/usr/local/etc/xmppd/xmppd.conf";

fn helpRequested(argv: []const []const u8) bool {
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) return true;
    }
    return false;
}

/// Standalone OIDC keeps its historical default file. A supervised child
/// with only --conf-fd needs no file, and generated --help never requires
/// the host's default file to exist.
fn oidcConfigPath(argv: []const []const u8) ?[]const u8 {
    if (schema.configPathArg(argv)) |path| return path;
    if (schema.confFdArg(argv) != null or helpRequested(argv)) return null;
    return default_config_path;
}

noinline fn loadOidcConfig(loaded: *schema.OidcLoader, gpa: Allocator, argv: []const []const u8, diag: *conf.Diag) conf.Error!void {
    loaded.* = schema.OidcLoader.init(gpa);
    errdefer loaded.deinit();
    try loaded.loadInto(.{
        .conf_fd = schema.confFdArg(argv),
        .path = oidcConfigPath(argv),
        .args = argv,
    }, diag);
}

pub fn main() !void {
    // A1: block SIGUSR1 before any thread exists so the IdP pool inherits
    // the mask; the loop's EVFILT_SIGNAL knote records it for the dump.
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
        loader: schema.OidcLoader,
    };
    const cfg = try allocator.create(Cfg);
    cfg.diag = .{};
    loadOidcConfig(&cfg.loader, allocator, argv.items, &cfg.diag) catch |err| {
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
    try requireOidcConfig(v);

    const config_path = oidcConfigPath(argv.items);
    const pool_options = parsePoolOptions(&cfg.loader, config_path, &cfg.diag) catch |err| {
        log.err("{f}", .{&cfg.diag});
        return err;
    };
    const lockout_duration = schema.validateOidcRate(&cfg.loader, config_path, &cfg.diag) catch |err| {
        log.err("{f}", .{&cfg.diag});
        return err;
    };
    const map_size_bytes = schema.mapSizeBytes(&cfg.loader, config_path, &cfg.diag) catch |err| {
        log.err("{f}", .{&cfg.diag});
        return err;
    };
    const issuer = v.oidc.issuer;
    const client_id = v.oidc.client_id;
    const client_secret = v.oidc.client_secret;
    const token_endpoint = v.oidc.token_endpoint;
    const jwks_uri = v.oidc.jwks_uri;
    const ca_file: ?[]const u8 = if (v.oidc.ca_file.len != 0) v.oidc.ca_file else null;
    const introspection_endpoint: ?[]const u8 = if (v.oidc.introspection_endpoint.len != 0) v.oidc.introspection_endpoint else null;
    const user_domain: ?[]const u8 = if (v.oidc.user_domain.len != 0) v.oidc.user_domain else null;
    const localpart_claim = v.oidc.localpart_claim;
    const localpart_claim_prefix = v.oidc.localpart_claim_prefix;
    const localpart_auto_suffix = v.oidc.localpart_auto_suffix;
    const socket_path = schema.oidcSocket(v);
    const db_path = v.server.db_path;
    const rate_cfg = resolveOidcRateConfig(&cfg.loader, lockout_duration);

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
        .localpart_claim = localpart_claim,
        .localpart_claim_prefix = localpart_claim_prefix,
        .localpart_auto_suffix = localpart_auto_suffix,
    });
    defer oidc_store.deinit();
    oidc_store.start() catch {
        log.err("OIDC HTTPS client init failed, refusing to start", .{});
        return error.TlsInitFailed;
    };

    // The shared [auth] policy and old [oidc] aliases resolve before
    // the limiter is built; invalid values have already refused startup.
    var rate_limiter = try RateLimiter.init(allocator, rate_cfg.policy);
    defer rate_limiter.deinit();

    // Initialize auth handler (generic over OidcStore)
    var handler = AuthHandler.init(allocator, &oidc_store);
    if (rate_cfg.enabled) {
        handler.setRateLimiter(&rate_limiter);
        log.info("rate policy: {d}/account, {d}/ip, window={d}s, lockout={d}s after {d} account / {d} ip failures", .{
            rate_cfg.policy.max_per_account,
            rate_cfg.policy.max_per_ip,
            rate_cfg.policy.window_seconds,
            rate_cfg.policy.lockout_duration,
            rate_cfg.policy.lockout_threshold,
            rate_cfg.policy.ip_lockout_threshold,
        });
    } else {
        log.warn(
            "auth rate limiting DISABLED -- no brute-force protection (benchmark/testing only)",
            .{},
        );
    }
    defer handler.deinit();

    // Permanent account locks come from the shared store, read-only, no
    // creation: an OIDC daemon seeing an empty/missing store must not boot
    // into fail-open (S3). A startup error kills the daemon outright. A
    // fresh install (missing environment or namespaces) is provisioned once
    // read-write and reopened read-only; every other open fault kills the
    // daemon instead of being provisioned over.
    var auth_path_buf: [1024]u8 = undefined;
    const auth_path = std.fmt.bufPrint(
        &auth_path_buf,
        "{s}/auth",
        .{db_path},
    ) catch return error.InvalidArgs;
    var lock_backend: OpBackendType = undefined;
    var lock_store = openLockStore(
        OpBackendType,
        allocator,
        auth_path,
        map_size_bytes,
        &lock_backend,
    ) catch |err| {
        log.err("lock store open failed for {s}, refusing to start: {}", .{ auth_path, err });
        return err;
    };
    defer lock_backend.close();
    var lock_checker: handler_mod.LockStoreChecker(OpBackendType) = undefined;
    lock_checker.init(&lock_store, allocator);
    handler.setLockChecker(lock_checker.checker);

    // The (iss, sub) -> localpart binding map lives in the same {db}/auth
    // env. It needs the read-write handle: first-login claims write both
    // index rows, and the users-namespace check shares the env (S3). The
    // claim has to hold against every process that can open the env, so a
    // backend whose putIfAbsent is only in-process cannot serve bindings.
    requireClaimAtomicity(OpBackendType) catch |err| {
        log.err(
            "OIDC account binding needs a backend with cross-process claim atomicity " ++
                "(LMDB or SQLite); refusing to start on this storage backend: {}",
            .{err},
        );
        return err;
    };
    var binding_backend = openReadWriteProvisioned(OpBackendType, auth_path, .{
        .map_size = map_size_bytes,
    }) catch |err| {
        log.err("OIDC binding store open failed for {s}, refusing to start: {}", .{ auth_path, err });
        return err;
    };
    defer binding_backend.close();

    // Upgrade probes: existing account data in {db}/op and {db}/archive
    // blocks auto-claim. A missing env is a fresh install (no data); any
    // other open fault refuses startup rather than probing blind.
    var op_path_buf: [1024]u8 = undefined;
    const op_path = std.fmt.bufPrint(&op_path_buf, "{s}/op", .{db_path}) catch return error.InvalidArgs;
    var op_probe = openProbe(OpBackendType, op_path) catch |err| {
        log.err("op env open failed for {s}, refusing to start: {}", .{ op_path, err });
        return err;
    };
    defer if (op_probe) |*b| b.close();

    var archive_path_buf: [1024]u8 = undefined;
    const archive_path = std.fmt.bufPrint(&archive_path_buf, "{s}/archive", .{db_path}) catch return error.InvalidArgs;
    var archive_probe = openProbe(ArchiveBackendType, archive_path) catch |err| {
        log.err("archive env open failed for {s}, refusing to start: {}", .{ archive_path, err });
        return err;
    };
    defer if (archive_probe) |*b| b.close();

    var binding_resolver = BindingResolver{
        .store = BindingStore.init(&binding_backend),
        .op_backend = if (op_probe) |*b| b else null,
        .archive_backend = if (archive_probe) |*b| b else null,
        .user_domain = user_domain,
        .localpart_claim_prefix = localpart_claim_prefix,
        .auto_suffix = localpart_auto_suffix,
    };
    oidc_store.bindings = binding_resolver.bindingOps();

    var daemon: Daemon = undefined;
    try daemon.init(allocator, &oidc_store, &handler, socket_path, pool_options);
    defer daemon.deinit();
    daemon.run();

    log.info("xmppd-auth-oidc shutdown complete", .{});
}

fn requireOidcConfig(v: *const schema.Sections) error{InvalidArgs}!void {
    inline for ([_][]const u8{ "issuer", "client_id", "client_secret", "token_endpoint", "jwks_uri" }) |field| {
        if (@field(v.oidc, field).len == 0) {
            log.err("missing required config: [oidc] {s}", .{field});
            return error.InvalidArgs;
        }
    }
}

/// IdP worker pool configuration is typed by the loader; these bounds keep
/// the pool's own clamps from hiding an invalid configured value.
fn parsePoolOptions(loader: *const schema.OidcLoader, path: ?[]const u8, diag: *conf.Diag) error{BadValue}!IdpPool.Options {
    const v = &loader.values.oidc;
    if (v.idp_threads == 0 or v.idp_threads > IdpPool.max_threads) {
        return schema.failField(loader, path, diag, "oidc", "idp_threads", "want 1..32");
    }
    if (v.idp_max_outstanding == 0 or v.idp_max_outstanding > 4096) {
        return schema.failField(loader, path, diag, "oidc", "idp_max_outstanding", "want 1..4096");
    }
    if (v.idp_connect_timeout_ms < 100 or v.idp_connect_timeout_ms > 60000) {
        return schema.failField(loader, path, diag, "oidc", "idp_connect_timeout_ms", "want 100..60000");
    }
    if (v.idp_timeout_ms < v.idp_connect_timeout_ms or v.idp_timeout_ms > 120000) {
        return schema.failField(loader, path, diag, "oidc", "idp_timeout_ms", "want connect timeout..120000");
    }
    return .{
        .threads = v.idp_threads,
        .max_outstanding = v.idp_max_outstanding,
        .connect_timeout_ms = v.idp_connect_timeout_ms,
        .timeout_ms = v.idp_timeout_ms,
    };
}

/// Resolved rate-limit config: the policy plus the enable flag.
const OidcRateConfig = struct {
    policy: RatePolicy,
    enabled: bool,
};

/// Equal file sources prefer the shared auth key. Equal forwarded sources
/// use the master's normalized OIDC view. Otherwise the higher source wins.
fn useAuthRateValue(loader: *const schema.OidcLoader, comptime field: []const u8) bool {
    const auth_source = loader.provenanceOf("auth", field);
    const oidc_source = loader.provenanceOf("oidc", field);
    if (auth_source == oidc_source) return auth_source != .forwarded;
    return @intFromEnum(auth_source) > @intFromEnum(oidc_source);
}

fn resolveOidcRateConfig(loader: *const schema.OidcLoader, lockout_duration: u32) OidcRateConfig {
    const v = &loader.values;
    return .{
        .policy = .{
            .max_per_account = if (useAuthRateValue(loader, "max_per_account")) v.auth.max_per_account else v.oidc.max_per_account,
            .max_per_ip = if (useAuthRateValue(loader, "max_per_ip")) v.auth.max_per_ip else v.oidc.max_per_ip,
            .window_seconds = v.auth.window_seconds,
            .lockout_duration = lockout_duration,
            .lockout_threshold = v.auth.lockout_threshold,
            .ip_lockout_threshold = v.auth.ip_lockout_threshold,
        },
        .enabled = v.auth.rate_limit and v.oidc.rate_limit,
    };
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

/// The OIDC auth daemon: the shared runner (src/auth/runner.zig) owns the
/// kqueue loop and the IPC lanes, a bounded worker pool runs the blocking
/// IdP exchanges, and a pending table correlates jobs back to the request
/// that queued them. Built in place.
pub const Daemon = struct {
    allocator: Allocator,
    store: *OidcStore,
    handler: *AuthHandler,

    runner: runner_mod.Runner(OidcStore, Daemon),
    pool: IdpPool,

    /// Dispatched exchanges awaiting a completion, keyed by job id.
    /// Capacity is ensured at init for the pool bound; it never grows on
    /// the hot path.
    pending: std.AutoHashMapUnmanaged(u64, Pending) = .empty,

    pub const log = std.log.scoped(.xmppd_auth_oidc);

    /// Everything init() can fail with: the pool start, the IPC listener
    /// socket, the kqueue and the pending-table capacity.
    pub const InitError = IdpPool.StartError || runner_mod.Runner(OidcStore, Daemon).InitError ||
        error{OutOfMemory};

    pub fn init(
        self: *Daemon,
        allocator: Allocator,
        store: *OidcStore,
        handler: *AuthHandler,
        socket_path: []const u8,
        pool_options: IdpPool.Options,
    ) InitError!void {
        self.allocator = allocator;
        self.store = store;
        self.handler = handler;
        self.pending = .empty;

        self.pool = .{};
        try self.pool.start(allocator, store, pool_options);
        errdefer self.pool.stop();

        try self.runner.init(allocator, self, handler, socket_path, &AUTH_MECHS, self.pool.wake_rd);
        errdefer self.runner.deinit();

        try self.pending.ensureTotalCapacity(allocator, pool_options.max_outstanding);
    }

    /// One poll iteration: submit staged changes, dispatch the events, then
    /// flush every lane that gained backlog once.
    pub fn step(self: *Daemon, timeout_ms: ?u32) !void {
        return self.runner.step(timeout_ms);
    }

    pub fn run(self: *Daemon) void {
        self.runner.run();
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
        self.runner.deinit();
    }

    // -- runner hooks -----------------------------------------------------

    /// Route one message before the runner delivers it to the handler:
    /// IdP-bound mechanisms go to the pool and aborts drop their pending
    /// entry (but still reach the handler, which releases the session).
    pub fn intercept(self: *Daemon, runner: anytype, msg: protocol.Message, slot: u16) bool {
        _ = runner;
        switch (msg) {
            .auth_request => |req| {
                switch (req.mechanism) {
                    .plain, .oauthbearer => return self.tryQueueIdp(req, slot),
                    else => {},
                }
            },
            .auth_abort => |a| self.dropPending(slot, a.conn_id),
            else => {},
        }
        return false;
    }

    /// Drain finished exchanges and replay each through the handler with
    /// its answer parked in store.answer.
    pub fn onPoolWake(self: *Daemon, runner: anytype) void {
        self.pool.drainWake();
        while (self.pool.popCompletion()) |job_in| {
            var job = job_in;
            defer IdpPool.releaseJob(&job);

            const kv = self.pending.fetchRemove(job.id) orelse {
                Daemon.log.debug("stale IdP completion {d} dropped (aborted or lane closed)", .{job.id});
                continue;
            };
            const pend = kv.value;
            defer self.freePending(pend);

            // An orphaned exchange ran to completion anyway: consume it to
            // release its cap slot, but never replay or answer it.
            if (pend.orphaned) continue;

            const slot: usize = pend.slot;
            if (slot >= MAX_IPC_CLIENTS or runner.ipc_gens[slot] != pend.slot_gen) {
                Daemon.log.debug("IdP completion {d} dropped: lane recycled", .{job.id});
                continue;
            }
            if (runner.ipc.getClient(slot) == null) continue;

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
                self.replyAuthFailure(pend.conn_id, pend.slot, pend.mechanism, reason);
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
            const result = self.handler.handleMessage(
                .{ .auth_request = req },
                pend.slot,
                pend.slot_gen,
            );
            self.store.answer = null;

            switch (result) {
                .reply => |response| {
                    // Mirror the IP-side outcome the handler could not see
                    // with an empty client_ip: credential verdicts only,
                    // matching where a direct request records.
                    switch (response) {
                        .auth_success => self.handler.policy.recordOutcome("", client_ip, .success),
                        .auth_failure => |f| {
                            if (std.mem.eql(u8, f.reason, policy_mod.FailureReason.not_authorized.text())) {
                                self.handler.policy.recordOutcome("", client_ip, .failure);
                            }
                        },
                        else => {},
                    }
                    runner.replyToLane(slot, response);
                },
                .deferred, .none => {
                    // Unreachable for a real mechanism, but a replay that
                    // produced no reply must never leave the client hanging.
                    Daemon.log.err("IdP replay produced no reply for conn_id {d}", .{pend.conn_id});
                    self.replyTemporary(pend.conn_id, pend.slot, pend.mechanism);
                },
            }
        }
    }

    /// Lane teardown: pending exchanges for the lane are orphaned (their
    /// jobs still spend the caps until the completions are consumed).
    pub fn onLaneClose(self: *Daemon, slot: usize) void {
        self.dropPending(@intCast(slot), null);
    }

    pub fn onSighup(self: *Daemon) void {
        _ = self;
        Daemon.log.info("received SIGHUP (no-op for OIDC backend)", .{});
    }

    pub fn onSigusr1(self: *Daemon) void {
        metrics.dump();
        self.store.dumpResolverCounters();
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
                    self.replyAuthFailure(req.conn_id, slot, req.mechanism, reason);
                    return true;
                }
                if (self.checkAccountAdmission(creds.username, req.client_ip)) |reason| {
                    self.replyAuthFailure(req.conn_id, slot, req.mechanism, reason);
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
                    self.replyAuthFailure(req.conn_id, slot, req.mechanism, reason);
                    return true;
                }
                const token = oidc.bearerToken(req.payload) orelse {
                    self.replyAuthFailure(req.conn_id, slot, req.mechanism, .invalid_encoding);
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
        const account_key: []const u8 = if (full_key.len <= lock_store_mod.MAX_KEY_LEN)
            full_key
        else
            "";

        var same_account: usize = 0;
        var same_ip: usize = 0;
        var it = self.pending.valueIterator();
        while (it.next()) |pend| {
            if (account_key.len > 0 and
                std.mem.eql(u8, pend.accountKey(), account_key)) same_account += 1;
            if (std.mem.eql(u8, pend.clientIp(), req.client_ip)) same_ip += 1;
        }
        if (same_account >= max_inflight_per_account or same_ip >= max_inflight_per_ip) {
            self.replyTemporary(req.conn_id, slot, req.mechanism);
            return true;
        }

        // Own the request bytes for the replay: the recv buffer is
        // recycled. Copied before queueing so an OOM here cannot leave an
        // orphan job running against the IdP.
        const owned_len = req.client_ip.len + req.username.len + req.payload.len + req.cb_data.len;
        const owned = self.allocator.alloc(u8, owned_len) catch {
            self.replyTemporary(req.conn_id, slot, req.mechanism);
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
            .slot_gen = self.runner.ipc_gens[slot],
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
            self.replyTemporary(req.conn_id, slot, req.mechanism);
            return true;
        };

        // Capacity was ensured for the pool bound at init; outstanding jobs
        // can never exceed it.
        self.pending.putAssumeCapacity(job_id, pend);
        return true;
    }

    /// The pre-dispatch account admission check: one call site so the
    /// account identity the policy sees is decided in one place. After
    /// PR #30 merges this must check the prepared localpart
    /// (precis.xmppLocalpart), not the raw typed name.
    fn checkAccountAdmission(
        self: *Daemon,
        typed_name: []const u8,
        client_ip: []const u8,
    ) ?policy_mod.FailureReason {
        return self.handler.policy.check(typed_name, client_ip);
    }

    /// Answer a request with an auth_failure reason without handler
    /// involvement. Pre-gate denials carry the policy's own reason so the
    /// client sees what a direct request would have seen. An intercepted
    /// exchange never reaches the handler's dispatch, so its terminal
    /// counters land here.
    fn replyAuthFailure(self: *Daemon, conn_id: u32, slot: u16, mech: protocol.MechanismId, reason: policy_mod.FailureReason) void {
        metrics.exchangeStarted(@intFromEnum(mech));
        metrics.exchangeCompleted(@intFromEnum(mech), false);
        metrics.failure(@intFromEnum(reason));
        self.runner.replyToLane(slot, .{ .auth_failure = .{
            .conn_id = conn_id,
            .reason = reason.text(),
        } });
    }

    /// Answer a request temporary-auth-failure without handler involvement:
    /// in-flight caps and a full pool are transport backpressure, not a
    /// failed credential, so the rate limiter records no outcome.
    fn replyTemporary(self: *Daemon, conn_id: u32, slot: u16, mech: protocol.MechanismId) void {
        self.replyAuthFailure(conn_id, slot, mech, .temporary_auth_failure);
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

/// Open the shared op-storage backend read-write for the OIDC binding
/// store. Same provisioning rule as the lock store: a missing environment
/// is provisioned once read-write and reopened; any other failure is a
/// real fault, never provisioned over. Unlike the lock handle this one
/// stays writable for first-login claims, and every write goes through
/// the identity store's oidc_identities-only API.
fn openReadWriteProvisioned(
    comptime Backend: type,
    auth_path: []const u8,
    opts: backend_mod.OpenOptions,
) !Backend {
    var rw = opts;
    rw.read_only = false;
    rw.create = false;
    return Backend.open(auth_path, rw) catch |first_err| blk: {
        if (!lock_store_mod.isMissingStoreError(first_err)) return first_err;
        log.warn("auth store at {s} not created yet ({}); provisioning read-write once", .{ auth_path, first_err });
        var provision_opts = opts;
        provision_opts.read_only = false;
        provision_opts.create = true;
        var provision = try Backend.open(auth_path, provision_opts);
        provision.close();
        break :blk Backend.open(auth_path, rw);
    };
}

/// OIDC first-login binding claims a localpart through putIfAbsent. On a
/// backend whose claim check is serialized only inside the process
/// (RocksDB's claim_mutex, the memory backend), a second daemon on the
/// same store could interleave a claim and two identities would land on
/// one account. Refuse startup unless the backend serializes claims
/// across processes; an undeclared capability counts as unsafe.
fn requireClaimAtomicity(comptime Backend: type) !void {
    const capable = if (@hasDecl(Backend, "cross_process_claims"))
        Backend.cross_process_claims
    else
        false;
    if (!capable) return error.ClaimNotCrossProcess;
}

/// Read-only probe handle on an account-data environment: null when the
/// environment does not exist yet (fresh install means no claimable
/// data); any other failure propagates so a blind probe never allows a
/// claim.
fn openProbe(comptime Backend: type, path: []const u8) !?Backend {
    return Backend.open(path, .{ .read_only = true, .create = false }) catch |err| blk: {
        if (lock_store_mod.isMissingStoreError(err)) break :blk null;
        return err;
    };
}

fn printUsage(allocator: Allocator) std.Io.Writer.Error!void {
    var gen = schema.OidcLoader.init(allocator);
    defer gen.deinit();
    var buf: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&buf);
    try stdout.interface.writeAll("Usage: xmppd-auth-oidc [OPTIONS]\n\n");
    try gen.writeHelp(&stdout.interface);
    try stdout.interface.flush();
}

// ============================================================================
// Tests
// ============================================================================

test "OIDC startup: bad file rate values fail with file and line" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][]const u8{ "max_per_account = nope", "max_per_ip = 65536" }) |setting| {
        const file = try tmp.dir.createFile("bad.ini", .{ .truncate = true });
        try file.writeAll(
            \\[oidc]
            \\issuer = https://idp.test/
            \\client_id = xmppd
            \\client_secret = secret
            \\token_endpoint = https://idp.test/token
            \\jwks_uri = https://idp.test/jwks
            \\
        );
        try file.writeAll(setting);
        try file.writeAll("\n");
        file.close();
        const path = try tmp.dir.realpathAlloc(allocator, "bad.ini");
        defer allocator.free(path);

        const result = try std.process.Child.run(.{
            .allocator = allocator,
            .argv = &.{ "zig-out/bin/xmppd-auth-oidc", "--config", path },
            .max_output_bytes = 64 * 1024,
        });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        switch (result.term) {
            .Exited => |code| try std.testing.expect(code != 0),
            else => return error.TestUnexpectedResult,
        }
        const location = try std.fmt.allocPrint(allocator, "{s}:7:", .{path});
        defer allocator.free(location);
        try std.testing.expect(std.mem.indexOf(u8, result.stderr, location) != null);
        try std.testing.expect(std.mem.indexOf(u8, result.stderr, "invalid value") != null or
            std.mem.indexOf(u8, result.stderr, "exceeds 65535") != null);
    }
}

test "OIDC startup: generated help lists every schema CLI spelling without a config file" {
    const allocator = std.testing.allocator;
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "zig-out/bin/xmppd-auth-oidc", "--help" },
        .max_output_bytes = 64 * 1024,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        else => return error.TestUnexpectedResult,
    }
    inline for (schema.oidc_cli) |spec| {
        var buf: [128]u8 = undefined;
        const option = try std.fmt.bufPrint(&buf, "--{s}", .{spec.name});
        try std.testing.expect(std.mem.indexOf(u8, result.stdout, option) != null);
        for (spec.aliases) |alias| {
            const short = try std.fmt.bufPrint(&buf, "-{s}", .{alias});
            try std.testing.expect(std.mem.indexOf(u8, result.stdout, short) != null);
        }
    }
}

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

const RocksLikeBackend = struct {
    pub const cross_process_claims = false;
};

const SqliteLikeBackend = struct {
    pub const cross_process_claims = true;
};

const UndeclaredBackend = struct {};

test "startup refuses binding backends without cross-process claims" {
    // The configured op backend is the one main() gates on; the outcome
    // must track its declared capability under any -Dop-storage choice.
    const op_capable = if (@hasDecl(OpBackendType, "cross_process_claims"))
        OpBackendType.cross_process_claims
    else
        false;
    if (op_capable) {
        try requireClaimAtomicity(OpBackendType);
    } else {
        try std.testing.expectError(
            error.ClaimNotCrossProcess,
            requireClaimAtomicity(OpBackendType),
        );
    }
    try requireClaimAtomicity(SqliteLikeBackend);
    try std.testing.expectError(
        error.ClaimNotCrossProcess,
        requireClaimAtomicity(backend_mod.MemoryBackend),
    );
    try std.testing.expectError(
        error.ClaimNotCrossProcess,
        requireClaimAtomicity(RocksLikeBackend),
    );
    // A backend that never declares the capability counts as unsafe.
    try std.testing.expectError(
        error.ClaimNotCrossProcess,
        requireClaimAtomicity(UndeclaredBackend),
    );
}

/// Write "[oidc]\n`body`\n" into the tmp dir and return the file path.
fn writeTmpConfig(allocator: Allocator, tmp: *std.testing.TmpDir, body: []const u8) ![]u8 {
    const f = try tmp.dir.createFile("t.cfg", .{ .truncate = true });
    defer f.close();
    var wbuf: [0]u8 = .{};
    var w = f.writer(&wbuf);
    try w.interface.print("[oidc]\n{s}\n", .{body});
    try w.interface.flush();
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    return std.fmt.allocPrint(allocator, "{s}/t.cfg", .{base});
}

test "pool options reject out-of-range values" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const bad = [_][]const u8{
        "idp_threads = 0",
        "idp_threads = 33",
        "idp_max_outstanding = 0",
        "idp_max_outstanding = 4097",
        "idp_connect_timeout_ms = 99",
        "idp_connect_timeout_ms = 60001",
        "idp_timeout_ms = 120001",
        "idp_threads = eight",
        // The exchange deadline must cover the connect budget.
        "idp_connect_timeout_ms = 3000\nidp_timeout_ms = 2000",
    };
    for (bad) |kv| {
        const path = try writeTmpConfig(allocator, &tmp, kv);
        defer allocator.free(path);
        const expected_line: u32 = if (std.mem.indexOfScalar(u8, kv, '\n') != null) 3 else 2;
        var diag: conf.Diag = .{};
        var loader: schema.OidcLoader = undefined;
        loadOidcConfig(&loader, allocator, &.{ "--config", path }, &diag) catch |err| {
            try std.testing.expectEqual(error.BadValue, err);
            try std.testing.expectEqual(expected_line, diag.line);
            continue;
        };
        defer loader.deinit();
        try std.testing.expectError(error.BadValue, parsePoolOptions(&loader, path, &diag));
        try std.testing.expectEqual(expected_line, diag.line);
    }

    // In-range values parse through; absent keys keep the defaults.
    const path = try writeTmpConfig(
        allocator,
        &tmp,
        "idp_threads = 16\nidp_max_outstanding = 64\n" ++
            "idp_connect_timeout_ms = 1500\nidp_timeout_ms = 2000",
    );
    defer allocator.free(path);
    var diag: conf.Diag = .{};
    var loader: schema.OidcLoader = undefined;
    try loadOidcConfig(&loader, allocator, &.{ "--config", path }, &diag);
    defer loader.deinit();
    const opts = try parsePoolOptions(&loader, path, &diag);
    try std.testing.expectEqual(@as(u8, 16), opts.threads);
    try std.testing.expectEqual(@as(u16, 64), opts.max_outstanding);
    try std.testing.expectEqual(@as(u32, 1500), opts.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 2000), opts.timeout_ms);
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
                .reader = protocol.FrameReader.init(try allocator.alloc(u8, protocol.MAX_FRAME_SIZE)),
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
            _ = self.conn.recv() catch .would_block;
            try daemon.step(10);
        }
        return null;
    }

    /// Next reply the daemon produces inside its own event processing
    /// (dispatch denials, backpressure, direct handler answers): pump
    /// daemon steps until the reply parses or the bound runs out. The
    /// bound counts loop iterations, not wall time, so a loaded host
    /// cannot stretch it; a reply that never comes still fails on it.
    fn nextReplyPumped(self: *IpcTestClient, daemon: *Daemon, max_steps: usize) !?protocol.Message {
        var steps: usize = 0;
        while (steps < max_steps) : (steps += 1) {
            if (try self.conn.nextMessage()) |m| return m;
            _ = self.conn.recv() catch |err| switch (err) {
                error.WouldBlock => .would_block,
                else => return err,
            };
            try daemon.step(10);
        }
        return null;
    }

    /// Negative assertion: pump `steps` daemon iterations and fail on
    /// any reply, for completions that must be dropped, never answered.
    fn expectNoReply(self: *IpcTestClient, daemon: *Daemon, steps: usize) !void {
        var i: usize = 0;
        while (i < steps) : (i += 1) {
            try daemon.step(10);
            _ = self.conn.recv() catch |err| switch (err) {
                error.WouldBlock => .would_block,
                else => return err,
            };
            if (try self.conn.nextMessage()) |_| return error.UnexpectedReply;
        }
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
    // Binding seam: in-memory envs stand in for {db}/auth, {db}/op and
    // {db}/archive so verified exchanges resolve through the real
    // Resolver exactly as main() wires it.
    bind_backend: backend_mod.MemoryBackend = undefined,
    op_probe: backend_mod.MemoryBackend = undefined,
    archive_probe: backend_mod.MemoryBackend = undefined,
    binding_resolver: MemBindingResolver = undefined,

    fn init(
        self: *DaemonFixture,
        allocator: Allocator,
        token_endpoint: []const u8,
        ca_file: ?[]const u8,
        introspection_endpoint: ?[]const u8,
        limiter_policy: ?RatePolicy,
        pool_options: IdpPool.Options,
    ) !void {
        self.* = .{ .tmp = std.testing.tmpDir(.{}) };
        errdefer self.tmp.cleanup();

        // Short unique path: unix socket paths are capped at sun_path.
        const n = fixture_counter.fetchAdd(1, .monotonic);
        self.sock_path = try std.fmt.allocPrint(
            allocator,
            "/tmp/oidc-test-{d}-{d}.sock",
            .{ std.c.getpid(), n },
        );
        errdefer allocator.free(self.sock_path);

        self.store = OidcStore.init(allocator, .{
            .issuer = "https://idp.example/",
            .client_id = "xmppd",
            .client_secret = "secret",
            .token_endpoint = token_endpoint,
            .jwks_uri = token_endpoint,
            .introspection_endpoint = introspection_endpoint,
            .ca_file = ca_file,
        });
        try self.store.start();
        errdefer self.store.deinit();

        self.limiter = try RateLimiter.init(allocator, limiter_policy orelse .{});
        errdefer self.limiter.deinit();

        self.handler = AuthHandler.init(allocator, &self.store);
        self.handler.setRateLimiter(&self.limiter);
        errdefer self.handler.deinit();

        self.bind_backend = try backend_mod.MemoryBackend.open("", .{});
        errdefer self.bind_backend.close();
        self.op_probe = try backend_mod.MemoryBackend.open("", .{});
        errdefer self.op_probe.close();
        self.archive_probe = try backend_mod.MemoryBackend.open("", .{});
        errdefer self.archive_probe.close();
        self.binding_resolver = .{
            .store = MemBindingStore.init(&self.bind_backend),
            .op_backend = &self.op_probe,
            .archive_backend = &self.archive_probe,
            .user_domain = "localhost",
        };
        self.store.bindings = self.binding_resolver.bindingOps();

        try self.daemon.init(allocator, &self.store, &self.handler, self.sock_path, pool_options);
    }

    fn deinit(self: *DaemonFixture, allocator: Allocator) void {
        self.daemon.deinit();
        self.handler.deinit();
        self.limiter.deinit();
        self.store.deinit();
        self.bind_backend.close();
        self.op_probe.close();
        self.archive_probe.close();
        allocator.free(self.sock_path);
        self.tmp.cleanup();
    }
};

/// Connect a test client and read back its mechanism_list.
fn connectClient(allocator: Allocator, fx: *DaemonFixture) !IpcTestClient {
    var client = try IpcTestClient.connect(allocator, fx.sock_path);
    errdefer client.close();
    // Drive the accept and the mechanism_list flush; both are produced
    // inside daemon steps, so the bound counts iterations, not wall time.
    var steps: usize = 0;
    while (steps < 128) : (steps += 1) {
        try fx.daemon.step(10);
        _ = client.conn.recv() catch .would_block;
        if (try client.conn.nextMessage()) |m| {
            try std.testing.expect(std.meta.activeTag(m) == .mechanism_list);
            return client;
        }
    }
    return error.AcceptTimeout;
}

fn plainAuth(
    conn_id: u32,
    username: []const u8,
    password: []const u8,
    client_ip: []const u8,
) protocol.Message {
    var payload_buf: [512]u8 = undefined;
    const payload = std.fmt.bufPrint(
        &payload_buf,
        "\x00{s}\x00{s}",
        .{ username, password },
    ) catch unreachable;
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

    fn resizeFn(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ra: usize,
    ) bool {
        const self: *FailOnLen = @ptrCast(@alignCast(ctx));
        return self.inner.rawResize(memory, alignment, new_len, ra);
    }

    fn remapFn(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ra: usize,
    ) ?[*]u8 {
        const self: *FailOnLen = @ptrCast(@alignCast(ctx));
        return self.inner.rawRemap(memory, alignment, new_len, ra);
    }

    fn freeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *FailOnLen = @ptrCast(@alignCast(ctx));
        self.inner.rawFree(memory, alignment, ra);
    }
};

fn rawAuth(
    conn_id: u32,
    mechanism: protocol.MechanismId,
    username: []const u8,
    payload: []const u8,
    client_ip: []const u8,
) protocol.Message {
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
    const dl = std.time.milliTimestamp() + 10000;
    while (port_out.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
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
    const hold_ms: u64 = 10_000;
    const stub = try startHangingStub(&port, hold_ms);
    defer stub.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &url_buf,
        "https://127.0.0.1:{d}/token",
        .{port.load(.acquire)},
    );

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, .{
        .lockout_threshold = 1,
        .max_per_account = 100,
        .max_per_ip = 100,
    }, .{
        .threads = 2,
        .max_outstanding = 16,
        .connect_timeout_ms = 150,
        // Parked for the whole hold so a step blocked on the exchange
        // waits ~hold_ms; the wall bound below sits halfway to it.
        .timeout_ms = 10_000,
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
    // while alice's exchange is still parked. The answer is produced in
    // the daemon step that reads the request, so the step bound proves
    // the loop iterated; the wall bound proves it did not stall: a step
    // blocked on the exchange returns only after ~hold_ms, and a loaded
    // host cannot push a healthy loop to half of that.
    const bad = rawAuth(2, .plain, "mallory", "no-nuls", "10.0.0.1");
    const t0 = std.time.milliTimestamp();
    try client.send(bad);
    const reply_bad = (try client.nextReplyPumped(&fx.daemon, 32)).?;
    const elapsed = std.time.milliTimestamp() - t0;
    try std.testing.expect(elapsed < @as(i64, @intCast(hold_ms / 2)));
    try std.testing.expect(std.meta.activeTag(reply_bad) == .auth_failure);
    try std.testing.expectEqualStrings("invalid-encoding", reply_bad.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 2), reply_bad.auth_failure.conn_id);

    // alice's exchange dies on its deadline and replays as a temporary
    // failure: the IdP outage is not a failed credential.
    const reply_a = (try client.nextReply(&fx.daemon, 15_000)).?;
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
    try fx.init(allocator, url, null, null, .{
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
    const url = try std.fmt.bufPrint(
        &url_buf,
        "https://127.0.0.1:{d}/token",
        .{port.load(.acquire)},
    );

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, null, .{
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
    try client.send(m3);
    // The denial is produced in the daemon step that reads the request;
    // the only slower path is a real exchange, which cannot answer
    // before its 8 s deadline, and 32 pumped steps cannot span that.
    const reply = (try client.nextReplyPumped(&fx.daemon, 32)).?;
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
    const url = try std.fmt.bufPrint(
        &url_buf,
        "https://127.0.0.1:{d}/token",
        .{port.load(.acquire)},
    );

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, null, .{
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

    // Past the exchange deadline the completion drops as stale. The
    // drain waits on pending state (the exchange must reach its 300 ms
    // deadline in the worker, so the bound stays generous); the negative
    // part is step-bounded like every other quiet check.
    const dl = std.time.milliTimestamp() + 10000;
    while (fx.daemon.pending.count() > 0 and std.time.milliTimestamp() < dl) {
        try fx.daemon.step(10);
        _ = client_b.conn.recv() catch .would_block;
        if (try client_b.conn.nextMessage()) |_| {
            return error.UnexpectedReply;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), fx.daemon.pending.count());
    try client_b.expectNoReply(&fx.daemon, 8);
}

test "an auth_abort orphans the exchange but the cap still counts it" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    const stub = try startHangingStub(&port, 5000);
    defer stub.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &url_buf,
        "https://127.0.0.1:{d}/token",
        .{port.load(.acquire)},
    );

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, null, .{
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
    const reply = (try client.nextReplyPumped(&fx.daemon, 32)).?;
    try std.testing.expect(std.meta.activeTag(reply) == .auth_failure);
    try std.testing.expectEqualStrings("temporary-auth-failure", reply.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 9), reply.auth_failure.conn_id);

    // The orphaned completions are consumed, never answered, and release
    // their cap slots. The drain bound must outlive the 2000 ms exchange
    // deadline in the worker; the quiet check is step-bounded.
    const dl = std.time.milliTimestamp() + 15000;
    while (fx.daemon.pending.count() > 0 and std.time.milliTimestamp() < dl) {
        try fx.daemon.step(10);
        _ = client.conn.recv() catch .would_block;
        if (try client.conn.nextMessage()) |_| {
            return error.UnexpectedReply;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), fx.daemon.pending.count());
    try client.expectNoReply(&fx.daemon, 8);
}

test "an OOM on the pending copy queues no orphan job" {
    const allocator = std.testing.allocator;
    const port = try refusedPort();
    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/token", .{port});

    var falloc = FailOnLen{ .inner = allocator };
    const test_alloc = falloc.allocator();

    var fx: DaemonFixture = undefined;
    try fx.init(test_alloc, url, null, null, null, .{
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

    const reply = (try client.nextReplyPumped(&fx.daemon, 32)).?;
    try std.testing.expectEqual(@as(u32, 1), reply.auth_failure.conn_id);
    try std.testing.expectEqualStrings("temporary-auth-failure", reply.auth_failure.reason);

    // Nothing ever reached the pool: a job queued before the failed copy
    // would run as an orphan and spend an exchange against the IdP. A few
    // pumped steps give a hypothetical orphan its completions.
    try client.expectNoReply(&fx.daemon, 16);
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
    const url = try std.fmt.bufPrint(
        &url_buf,
        "https://127.0.0.1:{d}/token",
        .{port.load(.acquire)},
    );

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, null, .{
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

    // deinit must cancel the exchanges, not wait out the 10 s exchange
    // deadline; a bound halfway to it still separates the two outcomes
    // even on a loaded host.
    const t0 = std.time.milliTimestamp();
    fx.deinit(allocator);
    const elapsed = std.time.milliTimestamp() - t0;
    try std.testing.expect(elapsed < 5000);
}

// --- TLS IdP stub for the replay path ------------------------------------

fn genIdpTestCert(dir: std.fs.Dir) !void {
    const r = std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &.{
            "openssl",                      "req",           "-x509",
            "-newkey",                      "rsa:2048",      "-nodes",
            "-subj",                        "/CN=localhost", "-addext",
            "subjectAltName=DNS:localhost", "-days",         "1",
            "-keyout",                      "key.pem",       "-out",
            "cert.pem",
        },
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
fn serveOneTlsResponse(
    cert_path: [*:0]const u8,
    key_path: [*:0]const u8,
    status_line: []const u8,
    body: []const u8,
    port_out: *std.atomic.Value(u16),
) void {
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
        const resp = std.fmt.bufPrint(
            &resp_buf,
            "HTTP/1.1 {s}\r\nContent-Type: application/json\r\n" ++
                "Content-Length: {d}\r\nConnection: close\r\n\r\n{s}",
            .{ status_line, body.len, body },
        ) catch return;
        _ = c.SSL_write(ssl_ptr, resp.ptr, @intCast(resp.len));
        return;
    }
}

/// Serve `count` HTTPS responses on one loopback TLS listener, counting
/// answered connections so a test can prove how many exchanges reached
/// the IdP, then return.
fn serveTlsResponsesCounted(
    cert_path: [*:0]const u8,
    key_path: [*:0]const u8,
    status_line: []const u8,
    body: []const u8,
    count: usize,
    port_out: *std.atomic.Value(u16),
    served: *std.atomic.Value(usize),
) void {
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

    const deadline = std.time.milliTimestamp() + 15000;
    while (served.load(.monotonic) < count and std.time.milliTimestamp() < deadline) {
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
        const resp = std.fmt.bufPrint(
            &resp_buf,
            "HTTP/1.1 {s}\r\nContent-Type: application/json\r\n" ++
                "Content-Length: {d}\r\nConnection: close\r\n\r\n{s}",
            .{ status_line, body.len, body },
        ) catch return;
        _ = c.SSL_write(ssl_ptr, resp.ptr, @intCast(resp.len));
        _ = served.fetchAdd(1, .monotonic);
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
    const stub = try std.Thread.spawn(
        .{},
        serveOneTlsResponse,
        .{ cert_path.ptr, key_path.ptr, "400 Bad Request", "{\"error\":\"invalid_grant\"}", &port },
    );
    defer stub.join();
    const dl = std.time.milliTimestamp() + 10000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = port.load(.acquire);
    try std.testing.expect(p != 0);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/token", .{p});

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, cert_path, null, .{
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
    try std.testing.expectEqualStrings(
        "account-disabled",
        (fx.handler.policy.check("alice", "10.0.0.9") orelse return error.ExpectedLock).text(),
    );
}

test "a rate-limited or locked request is denied before the IdP is asked" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    const stub = try startHangingStub(&port, 3000);
    defer stub.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &url_buf,
        "https://127.0.0.1:{d}/token",
        .{port.load(.acquire)},
    );

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, .{
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
    const reply_limited = (try client.nextReplyPumped(&fx.daemon, 32)).?;
    try std.testing.expectEqual(@as(u32, 3), reply_limited.auth_failure.conn_id);
    try std.testing.expectEqualStrings("policy-violation", reply_limited.auth_failure.reason);

    // A locked IP is denied at dispatch even for a well-formed request.
    fx.handler.policy.recordOutcome("", "10.0.0.6", .failure);
    const m4 = plainAuth(4, "bob", "pw", "10.0.0.6");
    defer allocator.free(m4.auth_request.payload);
    try client.send(m4);
    const reply_locked_ip = (try client.nextReplyPumped(&fx.daemon, 32)).?;
    try std.testing.expectEqualStrings("policy-violation", reply_locked_ip.auth_failure.reason);

    // A locked account is denied at dispatch with the handler's own reason.
    fx.handler.policy.recordOutcome("carol", "", .failure);
    const m5 = plainAuth(5, "carol", "pw", "10.0.0.7");
    defer allocator.free(m5.auth_request.payload);
    try client.send(m5);
    const reply_locked_acct = (try client.nextReplyPumped(&fx.daemon, 32)).?;
    try std.testing.expectEqualStrings("account-disabled", reply_locked_acct.auth_failure.reason);

    // A locked IP also denies a well-formed OAUTHBEARER before parsing.
    fx.handler.policy.recordOutcome("", "10.0.0.8", .failure);
    const m6 = rawAuth(6, .oauthbearer, "", "n,,\x01auth=Bearer tok\x01\x01", "10.0.0.8");
    try client.send(m6);
    const reply_bearer = (try client.nextReplyPumped(&fx.daemon, 32)).?;
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
    const stub = try std.Thread.spawn(
        .{},
        serveOneTlsResponse,
        .{ cert_path.ptr, key_path.ptr, "400 Bad Request", "{\"error\":\"invalid_grant\"}", &port },
    );
    defer stub.join();
    const dl = std.time.milliTimestamp() + 10000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = port.load(.acquire);
    try std.testing.expect(p != 0);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/token", .{p});

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, cert_path, null, .{
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
    const drain_dl = std.time.milliTimestamp() + 10000;
    while (fx.daemon.pending.count() > 0 and std.time.milliTimestamp() < drain_dl) {
        try fx.daemon.step(10);
    }
    try std.testing.expectEqual(@as(usize, 1), fx.daemon.pool.exchanges_run.load(.monotonic));

    // Exactly one charge: the counted attempt plus the three window fills
    // is the whole window; the replay added nothing.
    try std.testing.expect(fx.handler.policy.admitIp("10.0.0.9") != null);
}

test "a completion with a stale lane generation is dropped without a reply" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    const stub = try startHangingStub(&port, 3000);
    defer stub.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &url_buf,
        "https://127.0.0.1:{d}/token",
        .{port.load(.acquire)},
    );

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, null, .{
        .threads = 1,
        .max_outstanding = 8,
        .connect_timeout_ms = 150,
        .timeout_ms = 300,
    });
    defer fx.deinit(allocator);

    var client = try connectClient(allocator, &fx);
    defer client.close();

    const m = plainAuth(1, "alice", "pw", "10.0.0.1");
    defer allocator.free(m.auth_request.payload);
    try client.send(m);
    try fx.daemon.step(10);
    try std.testing.expectEqual(@as(usize, 1), fx.daemon.pending.count());

    // A recycled lane bumps ipc_gens: the parked generation no longer
    // matches, so the exchange's completion drops instead of answering
    // the wrong connection.
    var it = fx.daemon.pending.valueIterator();
    const pend = it.next() orelse return error.NoPending;
    pend.slot_gen +%= 1;

    const dl = std.time.milliTimestamp() + 10000;
    while (fx.daemon.pending.count() > 0 and std.time.milliTimestamp() < dl) {
        try fx.daemon.step(10);
        _ = client.conn.recv() catch .would_block;
        if (try client.conn.nextMessage()) |_| return error.UnexpectedReply;
    }
    try std.testing.expectEqual(@as(usize, 0), fx.daemon.pending.count());

    // One more beat: the dropped completion must leave no reply behind.
    try client.expectNoReply(&fx.daemon, 8);
}

test "a closed lane keeps its in-flight cap until the completions drain" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    const stub = try startHangingStub(&port, 6000);
    defer stub.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &url_buf,
        "https://127.0.0.1:{d}/token",
        .{port.load(.acquire)},
    );

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, null, .{
        .threads = 1,
        .max_outstanding = 8,
        .connect_timeout_ms = 2000,
        .timeout_ms = 4000,
    });
    defer fx.deinit(allocator);

    // Client A fills alice's in-flight cap and then vanishes: the pool
    // jobs keep running and keep spending the cap.
    {
        var client_a = try connectClient(allocator, &fx);
        for (0..max_inflight_per_account) |i| {
            const m = plainAuth(@intCast(i + 1), "alice", "pw", "10.0.0.1");
            defer allocator.free(m.auth_request.payload);
            try client_a.send(m);
            try fx.daemon.step(10);
        }
        client_a.close();
        try fx.daemon.step(20);
    }
    try std.testing.expectEqual(max_inflight_per_account, fx.daemon.pending.count());

    // A new lane for the same account is backpressured by the orphans.
    var client_b = try connectClient(allocator, &fx);
    defer client_b.close();
    const m = plainAuth(1, "alice", "pw", "10.0.0.2");
    defer allocator.free(m.auth_request.payload);
    try client_b.send(m);
    const reply = (try client_b.nextReplyPumped(&fx.daemon, 32)).?;
    try std.testing.expect(std.meta.activeTag(reply) == .auth_failure);
    try std.testing.expectEqualStrings("temporary-auth-failure", reply.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 1), reply.auth_failure.conn_id);
    try std.testing.expectEqual(max_inflight_per_account, fx.daemon.pending.count());
}

test "sixteen in-flight exchanges on one IP deny the seventeenth" {
    const allocator = std.testing.allocator;
    metrics.reset();
    defer metrics.reset();

    var port = std.atomic.Value(u16).init(0);
    const stub = try startHangingStub(&port, 8000);
    defer stub.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &url_buf,
        "https://127.0.0.1:{d}/token",
        .{port.load(.acquire)},
    );

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, null, .{
        .threads = 4,
        .max_outstanding = 32,
        .connect_timeout_ms = 2000,
        .timeout_ms = 6000,
    });
    defer fx.deinit(allocator);

    var client = try connectClient(allocator, &fx);
    defer client.close();

    for (0..max_inflight_per_ip) |i| {
        var name_buf: [16]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "u{d}", .{i}) catch unreachable;
        const m = plainAuth(@intCast(i + 1), name, "pw", "10.0.0.7");
        defer allocator.free(m.auth_request.payload);
        try client.send(m);
        try fx.daemon.step(10);
    }
    try std.testing.expectEqual(max_inflight_per_ip, fx.daemon.pending.count());

    const m17 = plainAuth(17, "zed", "pw", "10.0.0.7");
    defer allocator.free(m17.auth_request.payload);
    try client.send(m17);
    const reply = (try client.nextReplyPumped(&fx.daemon, 32)).?;
    try std.testing.expect(std.meta.activeTag(reply) == .auth_failure);
    try std.testing.expectEqualStrings("temporary-auth-failure", reply.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 17), reply.auth_failure.conn_id);
    try std.testing.expectEqual(max_inflight_per_ip, fx.daemon.pending.count());

    // A1: an intercept denial is a terminal exchange the handler never
    // saw, so its counters land in replyAuthFailure (PLAIN index 0).
    const ctr = &metrics.counters;
    try std.testing.expectEqual(@as(u64, 1), ctr.exchanges_started[0].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), ctr.exchanges_completed[0].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), ctr.outcomes[@intFromEnum(policy_mod.FailureReason.temporary_auth_failure)].load(.monotonic));
}

test "four in-flight exchanges on one account deny the fifth" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    const stub = try startHangingStub(&port, 8000);
    defer stub.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &url_buf,
        "https://127.0.0.1:{d}/token",
        .{port.load(.acquire)},
    );

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, null, .{
        .threads = 2,
        .max_outstanding = 8,
        .connect_timeout_ms = 2000,
        .timeout_ms = 6000,
    });
    defer fx.deinit(allocator);

    var client = try connectClient(allocator, &fx);
    defer client.close();

    for (0..max_inflight_per_account) |i| {
        var ip_buf: [16]u8 = undefined;
        const ip = std.fmt.bufPrint(&ip_buf, "10.0.1.{d}", .{i}) catch unreachable;
        const m = plainAuth(@intCast(i + 1), "alice", "pw", ip);
        defer allocator.free(m.auth_request.payload);
        try client.send(m);
        try fx.daemon.step(10);
    }
    try std.testing.expectEqual(max_inflight_per_account, fx.daemon.pending.count());

    const m5 = plainAuth(5, "alice", "pw", "10.0.2.1");
    defer allocator.free(m5.auth_request.payload);
    try client.send(m5);
    const reply = (try client.nextReplyPumped(&fx.daemon, 32)).?;
    try std.testing.expect(std.meta.activeTag(reply) == .auth_failure);
    try std.testing.expectEqualStrings("temporary-auth-failure", reply.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 5), reply.auth_failure.conn_id);
    try std.testing.expectEqual(max_inflight_per_account, fx.daemon.pending.count());
}

test "a full-pool denial records no outcome" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    const stub = try startHangingStub(&port, 5000);
    defer stub.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &url_buf,
        "https://127.0.0.1:{d}/token",
        .{port.load(.acquire)},
    );

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, .{
        .lockout_threshold = 1,
        .ip_lockout_threshold = 1,
        .max_per_account = 100,
        .max_per_ip = 100,
    }, .{
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
    try client.send(m3);
    const reply = (try client.nextReplyPumped(&fx.daemon, 32)).?;
    try std.testing.expect(std.meta.activeTag(reply) == .auth_failure);
    try std.testing.expectEqualStrings("temporary-auth-failure", reply.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 3), reply.auth_failure.conn_id);

    // Backpressure is not a failed credential: with lockout_threshold 1
    // a recorded outcome would have locked carol or her IP outright.
    try std.testing.expect(fx.handler.policy.check("carol", "10.0.0.3") == null);
}

test "cap slots release when the completions drain" {
    const allocator = std.testing.allocator;
    const port = try refusedPort();
    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/token", .{port});

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, .{
        .lockout_threshold = 50,
        .ip_lockout_threshold = 50,
        .max_per_account = 100,
        .max_per_ip = 100,
    }, .{
        .threads = 2,
        .max_outstanding = 4,
        .connect_timeout_ms = 1000,
        .timeout_ms = 3000,
    });
    defer fx.deinit(allocator);

    var client = try connectClient(allocator, &fx);
    defer client.close();

    // Four exchanges for alice run to completion against the refusing
    // IdP and drain out of both the pool and the pending table.
    for (0..4) |i| {
        const m = plainAuth(@intCast(i + 1), "alice", "pw", "10.0.0.4");
        defer allocator.free(m.auth_request.payload);
        try client.send(m);
        const reply = (try client.nextReply(&fx.daemon, 3000)).?;
        try std.testing.expectEqualStrings("temporary-auth-failure", reply.auth_failure.reason);
    }
    const drain = std.time.milliTimestamp() + 10000;
    while (fx.daemon.pending.count() > 0 and std.time.milliTimestamp() < drain) {
        try fx.daemon.step(10);
    }
    try std.testing.expectEqual(@as(usize, 0), fx.daemon.pending.count());
    try std.testing.expectEqual(@as(usize, 4), fx.daemon.pool.exchanges_run.load(.monotonic));

    // The fifth must queue and run: a leaked pool slot or a leaked
    // pending entry would deny it at dispatch and keep the count at 4.
    const m5 = plainAuth(5, "alice", "pw", "10.0.0.4");
    defer allocator.free(m5.auth_request.payload);
    try client.send(m5);
    const reply5 = (try client.nextReply(&fx.daemon, 3000)).?;
    try std.testing.expectEqualStrings("temporary-auth-failure", reply5.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 5), reply5.auth_failure.conn_id);
    const ran5 = fx.daemon.pool.exchanges_run.load(.monotonic);
    try std.testing.expectEqual(@as(usize, 5), ran5);
}

test "a correct password answers auth_success end to end" {
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

    // The token stub accepts the ROPC grant and returns an opaque
    // access_token; the introspection stub vouches for alice.
    var token_port = std.atomic.Value(u16).init(0);
    const token_stub = try std.Thread.spawn(.{}, serveOneTlsResponse, .{
        cert_path.ptr,
        key_path.ptr,
        "200 OK",
        "{\"access_token\":\"opaque-at\",\"token_type\":\"Bearer\"}",
        &token_port,
    });
    defer token_stub.join();
    var intro_port = std.atomic.Value(u16).init(0);
    const intro_stub = try std.Thread.spawn(.{}, serveOneTlsResponse, .{
        cert_path.ptr,
        key_path.ptr,
        "200 OK",
        "{\"active\":true,\"sub\":\"sub-alice\",\"username\":\"alice\"}",
        &intro_port,
    });
    defer intro_stub.join();

    const dl = std.time.milliTimestamp() + 10000;
    while ((token_port.load(.acquire) == 0 or intro_port.load(.acquire) == 0) and
        std.time.milliTimestamp() < dl) std.Thread.sleep(std.time.ns_per_ms);
    try std.testing.expect(token_port.load(.acquire) != 0);
    try std.testing.expect(intro_port.load(.acquire) != 0);

    var token_buf: [128]u8 = undefined;
    const token_url = try std.fmt.bufPrint(
        &token_buf,
        "https://localhost:{d}/token",
        .{token_port.load(.acquire)},
    );
    var intro_buf: [128]u8 = undefined;
    const intro_url = try std.fmt.bufPrint(
        &intro_buf,
        "https://localhost:{d}/introspect",
        .{intro_port.load(.acquire)},
    );

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, token_url, cert_path, intro_url, .{
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

    const m = plainAuth(1, "alice", "correct-pw", "10.0.0.9");
    defer allocator.free(m.auth_request.payload);
    try client.send(m);
    const reply = (try client.nextReply(&fx.daemon, 8000)).?;
    try std.testing.expect(std.meta.activeTag(reply) == .auth_success);
    try std.testing.expectEqual(@as(u32, 1), reply.auth_success.conn_id);
    try std.testing.expectEqualStrings("alice", reply.auth_success.username);
}

test "replayed credential failures engage the IP lockout" {
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
    var served = std.atomic.Value(usize).init(0);
    const stub = try std.Thread.spawn(.{}, serveTlsResponsesCounted, .{
        cert_path.ptr,
        key_path.ptr,
        "400 Bad Request",
        "{\"error\":\"invalid_grant\"}",
        3,
        &port,
        &served,
    });
    defer stub.join();
    const dl = std.time.milliTimestamp() + 10000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const p = port.load(.acquire);
    try std.testing.expect(p != 0);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/token", .{p});

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, cert_path, null, .{
        .lockout_threshold = 50,
        .ip_lockout_threshold = 3,
        .max_per_account = 100,
        .max_per_ip = 100,
    }, .{
        .threads = 1,
        .max_outstanding = 8,
        .connect_timeout_ms = 2000,
        .timeout_ms = 5000,
    });
    defer fx.deinit(allocator);

    var client = try connectClient(allocator, &fx);
    defer client.close();

    // Each replayed not-authorized mirrors one IP failure; the lock the
    // handler's empty-IP replay cannot see engages on the third.
    const reasons = [_][]const u8{
        "not-authorized",
        "not-authorized",
        "not-authorized",
        "policy-violation",
    };
    for (reasons, 0..) |want, i| {
        var name_buf: [16]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "u{d}", .{i}) catch unreachable;
        const m = plainAuth(@intCast(i + 1), name, "wrong-pw", "10.0.3.1");
        defer allocator.free(m.auth_request.payload);
        try client.send(m);
        const reply = (try client.nextReply(&fx.daemon, 8000)).?;
        try std.testing.expect(std.meta.activeTag(reply) == .auth_failure);
        try std.testing.expectEqual(@as(u32, @intCast(i + 1)), reply.auth_failure.conn_id);
        try std.testing.expectEqualStrings(want, reply.auth_failure.reason);
    }
    // Without the mirror the fourth request would have reached the IdP.
    try std.testing.expectEqual(@as(usize, 3), served.load(.monotonic));
}

test "an IP lock engaged mid-flight denies the parked verdict" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    const stub = try startHangingStub(&port, 3000);
    defer stub.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &url_buf,
        "https://127.0.0.1:{d}/token",
        .{port.load(.acquire)},
    );

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, .{
        .lockout_threshold = 50,
        .ip_lockout_threshold = 1,
        .max_per_account = 100,
        .max_per_ip = 100,
    }, .{
        .threads = 1,
        .max_outstanding = 8,
        .connect_timeout_ms = 150,
        .timeout_ms = 300,
    });
    defer fx.deinit(allocator);

    var client = try connectClient(allocator, &fx);
    defer client.close();

    const m = plainAuth(1, "alice", "pw", "10.0.4.1");
    defer allocator.free(m.auth_request.payload);
    try client.send(m);
    try fx.daemon.step(10);
    try std.testing.expectEqual(@as(usize, 1), fx.daemon.pending.count());

    // The lock engages while the exchange is parked; the replay re-check
    // must answer with the denial, not the parked timeout verdict.
    fx.handler.policy.recordOutcome("", "10.0.4.1", .failure);
    const reply = (try client.nextReply(&fx.daemon, 3000)).?;
    try std.testing.expect(std.meta.activeTag(reply) == .auth_failure);
    try std.testing.expectEqual(@as(u32, 1), reply.auth_failure.conn_id);
    try std.testing.expectEqualStrings("policy-violation", reply.auth_failure.reason);
}

test "an account lock engaged mid-flight replays account-disabled only" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    const stub = try startHangingStub(&port, 3000);
    defer stub.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &url_buf,
        "https://127.0.0.1:{d}/token",
        .{port.load(.acquire)},
    );

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, .{
        .lockout_threshold = 1,
        .ip_lockout_threshold = 1,
        .max_per_account = 100,
        .max_per_ip = 100,
    }, .{
        .threads = 1,
        .max_outstanding = 8,
        .connect_timeout_ms = 150,
        .timeout_ms = 300,
    });
    defer fx.deinit(allocator);

    var client = try connectClient(allocator, &fx);
    defer client.close();

    const m = plainAuth(1, "alice", "pw", "10.0.5.1");
    defer allocator.free(m.auth_request.payload);
    try client.send(m);
    try fx.daemon.step(10);
    try std.testing.expectEqual(@as(usize, 1), fx.daemon.pending.count());

    // alice locks while her exchange is parked. The replay answers with
    // the account denial and the mirror must not charge her IP for it:
    // with ip_lockout_threshold 1 a mirrored failure would lock the IP.
    fx.handler.policy.recordOutcome("alice", "", .failure);
    const reply = (try client.nextReply(&fx.daemon, 3000)).?;
    try std.testing.expect(std.meta.activeTag(reply) == .auth_failure);
    try std.testing.expectEqual(@as(u32, 1), reply.auth_failure.conn_id);
    try std.testing.expectEqualStrings("account-disabled", reply.auth_failure.reason);
    try std.testing.expect(fx.handler.policy.check("", "10.0.5.1") == null);
}

test "a full-pool denial does not count the IP attempt again" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    const stub = try startHangingStub(&port, 5000);
    defer stub.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &url_buf,
        "https://127.0.0.1:{d}/token",
        .{port.load(.acquire)},
    );

    var fx: DaemonFixture = undefined;
    try fx.init(allocator, url, null, null, .{
        .lockout_threshold = 50,
        .ip_lockout_threshold = 50,
        .max_per_account = 100,
        .max_per_ip = 3,
    }, .{
        .threads = 1,
        .max_outstanding = 1,
        .connect_timeout_ms = 2000,
        .timeout_ms = 4000,
    });
    defer fx.deinit(allocator);

    var client = try connectClient(allocator, &fx);
    defer client.close();

    const m1 = plainAuth(1, "alice", "pw", "10.0.6.1");
    defer allocator.free(m1.auth_request.payload);
    try client.send(m1);
    try fx.daemon.step(10);
    try std.testing.expectEqual(@as(usize, 1), fx.daemon.pending.count());

    // The pool is full: requests two and three are backpressured, and
    // backpressure must not spend window attempts beyond the one counted
    // at dispatch. A denial handed to the handler would count twice and
    // the third request would come back policy-violation instead.
    for (2..4) |i| {
        var name_buf: [16]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "u{d}", .{i}) catch unreachable;
        const m = plainAuth(@intCast(i), name, "pw", "10.0.6.1");
        defer allocator.free(m.auth_request.payload);
        try client.send(m);
        const reply = (try client.nextReplyPumped(&fx.daemon, 32)).?;
        try std.testing.expect(std.meta.activeTag(reply) == .auth_failure);
        try std.testing.expectEqual(@as(u32, @intCast(i)), reply.auth_failure.conn_id);
        try std.testing.expectEqualStrings("temporary-auth-failure", reply.auth_failure.reason);
    }
}

test "rate config reads the shared [auth] keys with the old [oidc] spellings as aliases" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Shared [auth] keys win over the [oidc] aliases for the same field.
    const path = try writeTmpConfig(
        allocator,
        &tmp,
        "rate_max_per_account = 99\nrate_max_per_ip = 88\n" ++
            "[auth]\n" ++
            "max_per_account = 7\nmax_per_ip = 9\nwindow_seconds = 30\n" ++
            "lockout_duration = 120\nlockout_threshold = 4\n" ++
            "ip_lockout_threshold = 11\nrate_limit = true\n",
    );
    defer allocator.free(path);
    var diag: conf.Diag = .{};
    var loader: schema.OidcLoader = undefined;
    try loadOidcConfig(&loader, allocator, &.{ "--config", path }, &diag);
    defer loader.deinit();
    const lockout = try schema.validateOidcRate(&loader, path, &diag);
    const r = resolveOidcRateConfig(&loader, lockout);
    try std.testing.expectEqual(@as(u32, 7), r.policy.max_per_account);
    try std.testing.expectEqual(@as(u32, 9), r.policy.max_per_ip);
    try std.testing.expectEqual(@as(u32, 30), r.policy.window_seconds);
    try std.testing.expectEqual(@as(u32, 120), r.policy.lockout_duration);
    try std.testing.expectEqual(@as(u16, 4), r.policy.lockout_threshold);
    try std.testing.expectEqual(@as(u16, 11), r.policy.ip_lockout_threshold);
    try std.testing.expect(r.enabled);

    // Alias-only configs still apply to the maxes and to the kill switch.
    const path2 = try writeTmpConfig(
        allocator,
        &tmp,
        "rate_max_per_account = 42\nrate_max_per_ip = 77\nrate_limit = false\n",
    );
    defer allocator.free(path2);
    var loader2: schema.OidcLoader = undefined;
    try loadOidcConfig(&loader2, allocator, &.{ "--config", path2 }, &diag);
    defer loader2.deinit();
    const lockout2 = try schema.validateOidcRate(&loader2, path2, &diag);
    const r2 = resolveOidcRateConfig(&loader2, lockout2);
    try std.testing.expectEqual(@as(u32, 42), r2.policy.max_per_account);
    try std.testing.expectEqual(@as(u32, 77), r2.policy.max_per_ip);
    try std.testing.expect(!r2.enabled);
}

test "rate config treats an out-of-range lockout threshold as a bad value" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try writeTmpConfig(
        allocator,
        &tmp,
        "[auth]\nlockout_threshold = 70000\nip_lockout_threshold = 70000\n",
    );
    defer allocator.free(path);
    var diag: conf.Diag = .{};
    var loader: schema.OidcLoader = undefined;
    try std.testing.expectError(
        error.BadValue,
        loadOidcConfig(&loader, allocator, &.{ "--config", path }, &diag),
    );
    try std.testing.expectEqual(@as(u32, 3), diag.line);
}

test "OIDC forwarded values beat the file and lose to CLI flags" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try writeTmpConfig(allocator, &tmp, "socket = /file/oidc.sock\n[server]\ndb_path = /file/db\n");
    defer allocator.free(path);
    const blob = "--server.db_path=/fwd/db\n--oidc.socket=/fwd/oidc.sock\n";
    var diag: conf.Diag = .{};

    var forwarded = try schema.OidcLoader.load(allocator, .{
        .path = path,
        .conf_fd = (try conf.ConfFd.create(blob)).fd,
    }, &diag);
    defer forwarded.deinit();
    try std.testing.expectEqualStrings("/fwd/db", forwarded.values.server.db_path);
    try std.testing.expectEqualStrings("/fwd/oidc.sock", schema.oidcSocket(&forwarded.values));

    var cli = try schema.OidcLoader.load(allocator, .{
        .path = path,
        .conf_fd = (try conf.ConfFd.create(blob)).fd,
        .args = &.{ "--db", "/cli/db", "--socket", "/cli.sock" },
    }, &diag);
    defer cli.deinit();
    try std.testing.expectEqualStrings("/cli/db", cli.values.server.db_path);
    try std.testing.expectEqualStrings("/cli.sock", schema.oidcSocket(&cli.values));
}

test "OIDC aliases and shared auth maxima survive master forwarding" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try writeTmpConfig(allocator, &tmp, "rate_max_per_account = 42\nrate_max_per_ip = 77\n");
    defer allocator.free(path);
    var diag: conf.Diag = .{};
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var parent: schema.MasterLoader = undefined;
    parent = try schema.MasterLoader.load(allocator, .{ .path = path }, &diag);
    defer parent.deinit();
    schema.normalizeForwardedOidcRates(&parent);
    const alias_blob = try parent.forwardBlob(arena.allocator(), &diag);
    var alias_child = try schema.OidcLoader.load(allocator, .{ .conf_fd = (try conf.ConfFd.create(alias_blob)).fd }, &diag);
    defer alias_child.deinit();
    const alias_seconds = try schema.validateOidcRate(&alias_child, null, &diag);
    const aliases = resolveOidcRateConfig(&alias_child, alias_seconds);
    try std.testing.expectEqual(@as(u32, 42), aliases.policy.max_per_account);
    try std.testing.expectEqual(@as(u32, 77), aliases.policy.max_per_ip);

    var shared = try schema.MasterLoader.load(allocator, .{ .path = path, .args = &.{"--auth.max_per_account=7"} }, &diag);
    defer shared.deinit();
    schema.normalizeForwardedOidcRates(&shared);
    const shared_blob = try shared.forwardBlob(arena.allocator(), &diag);
    var shared_child = try schema.OidcLoader.load(allocator, .{ .conf_fd = (try conf.ConfFd.create(shared_blob)).fd }, &diag);
    defer shared_child.deinit();
    const shared_seconds = try schema.validateOidcRate(&shared_child, null, &diag);
    const resolved = resolveOidcRateConfig(&shared_child, shared_seconds);
    try std.testing.expectEqual(@as(u32, 7), resolved.policy.max_per_account);
    try std.testing.expectEqual(@as(u32, 77), resolved.policy.max_per_ip);
}

/// Which IPC lane the fixture's single client occupies.
fn clientSlot(fx: *DaemonFixture) ?usize {
    for (&fx.daemon.runner.ipc.clients, 0..) |*conn, i| {
        if (conn.active) return i;
    }
    return null;
}

test "the runner pauses lane intake at the high watermark and resumes on drain" {
    const allocator = std.testing.allocator;
    var fx: DaemonFixture = undefined;
    // No IdP traffic is needed: mechanism_not_supported replies are
    // produced on the loop itself, which is the output path under test.
    try fx.init(allocator, "http://127.0.0.1:1/token", null, null, null, .{
        .threads = 1,
        .max_outstanding = 8,
        .connect_timeout_ms = 100,
        .timeout_ms = 500,
    });
    defer fx.deinit(allocator);

    var client = try connectClient(allocator, &fx);
    defer client.close();

    const slot = clientSlot(&fx) orelse return error.ClientDropped;

    // Shrink the window: the assertion is about behavior, not capacity.
    fx.daemon.runner.rx_pause_at = 4096;
    fx.daemon.runner.rx_resume_at = 512;
    const pauses_before = metrics.counters.ipc_intake_pauses.load(.monotonic);

    const req = protocol.Message{ .auth_request = .{
        .conn_id = 1,
        .mechanism = .scram_sha_256,
        .client_ip = "10.0.0.7",
        .cb_type = 0,
        .cb_data = "",
        .username = "alice",
        .payload = "n,,n=alice,r=0123456789abcdef",
    } };

    // The client never reads, so replies pile onto the lane's send
    // backlog until intake pauses.
    var guard: usize = 2048;
    while (!fx.daemon.runner.read_paused[slot] and guard > 0) : (guard -= 1) {
        var i: usize = 0;
        while (i < 16) : (i += 1) client.send(req) catch break;
        try fx.daemon.step(10);
    }
    try std.testing.expect(fx.daemon.runner.read_paused[slot]);
    try std.testing.expectEqual(slot, clientSlot(&fx).?);
    // A1: the pause edge moved the intake-pause counter.
    try std.testing.expect(metrics.counters.ipc_intake_pauses.load(.monotonic) > pauses_before);

    // Draining the replies lets the backlog fall under the resume mark;
    // the lane's write handling then re-enables intake.
    guard = 4096;
    while (fx.daemon.runner.read_paused[slot] and guard > 0) : (guard -= 1) {
        _ = client.conn.recv() catch .would_block;
        while (try client.conn.nextMessage()) |_| {}
        try fx.daemon.step(10);
    }
    try std.testing.expect(!fx.daemon.runner.read_paused[slot]);
    try std.testing.expectEqual(slot, clientSlot(&fx).?);
}
