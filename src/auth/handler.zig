//! # Auth Handler — SASL authentication request processor
//!
//! Handles IPC auth requests from xmppd-core. Protocol v2: SCRAM is a
//! stateless one-round-trip verify (ADR-6), so the only per-mechanism state
//! left is the bounded server-nonce replay cache.
//!
//! ## Flow
//!
//! **PLAIN:** AuthRequest → lookup → AuthSuccess/AuthFailure (one step)
//!
//! **SCRAM-SHA-256:** ScramParamsRequest → ScramParams (cache-miss lookup)
//!                    ScramVerify → verify vs StoredKey → AuthSuccess/AuthFailure
//!
//! ## Layout
//!
//! The handler owns the shared state (replay cache, credential
//! cache, deferred PLAIN jobs) and dispatches each request to the module
//! that owns the concern: mech/plain.zig, mech/scram.zig,
//! mech/oauthbearer.zig and account.zig. Admission policy lives in
//! policy.zig.

const std = @import("std");
const sasl = @import("sasl");
const precis = @import("precis_username");

/// Per-thread auth scratch. IdP PLAIN copies the typed authcid into a small
/// local buffer before reusing it, so nested lock-store preparation stays
/// independent without a third 64 KiB thread-local instance. The lock store
/// owns the only other instance: it is called from inside this prepared
/// authcid and therefore cannot share the same buffer.
pub threadlocal var auth_precis_scratch: precis.Scratch = undefined;

const protocol = @import("ipc_protocol");
const RateLimiter = @import("rate_limiter").RateLimiter;
const policy_mod = @import("policy");
const crypto_pool_mod = @import("crypto_pool");
const metrics = @import("auth_metrics");

const plain_mech = @import("mech/plain.zig");
pub const scram_mech = @import("mech/scram.zig");
const oauthbearer_mech = @import("mech/oauthbearer.zig");
const account_mod = @import("account.zig");

const log = std.log.scoped(.auth_handler);

// The metrics API takes u8 ids so it can stay a leaf shared by both auth
// module graphs; pin the index space to the enums here.
comptime {
    std.debug.assert(@typeInfo(protocol.MechanismId).@"enum".fields.len == metrics.MECH_COUNT);
    std.debug.assert(@typeInfo(FailureReason).@"enum".fields.len == metrics.REASON_COUNT);
}

/// The lock and failure types live in the policy module; these aliases keep
/// the daemon and test call sites stable.
pub const LockCheckResult = policy_mod.LockCheckResult;
pub const LockChecker = policy_mod.LockChecker;
pub const LockStoreChecker = policy_mod.LockStoreChecker;
pub const localpartOf = policy_mod.localpartOf;
pub const FailureReason = policy_mod.FailureReason;

/// The account-management types live in the account module; these aliases
/// keep the daemon call sites stable.
pub const InviteValidator = account_mod.InviteValidator;
pub const RegistrationConfig = account_mod.RegistrationConfig;

/// Store capabilities, declared by every auth store as
/// `pub const capabilities = .{ .lookup = true, ... }`. Each flag names the
/// store decl a mechanism or account operation needs; dispatch consults
/// flags instead of probing decls, and a flag without its decl is a
/// compile error.
pub const Capabilities = struct {
    /// Credential lookup for SCRAM and local PLAIN (store.lookup).
    lookup: bool = false,
    /// IdP password validation for PLAIN (store.validatePassword).
    validate_password: bool = false,
    /// IdP token validation for OAUTHBEARER (store.validateToken).
    validate_token: bool = false,
    /// Photo URL attached to OAUTHBEARER success (store.getPhotoUrl).
    photo_url: bool = false,
    /// In-band registration (store.addUser).
    add_user: bool = false,
    /// Password change (store.changePassword).
    change_password: bool = false,
    /// Account delete (store.removeUser).
    remove_user: bool = false,
};

fn isCapField(comptime name: []const u8) bool {
    inline for (@typeInfo(Capabilities).@"struct".fields) |cf| {
        if (std.mem.eql(u8, name, cf.name)) return true;
    }
    return false;
}

fn capabilitiesOf(comptime Store: type) Capabilities {
    if (!@hasDecl(Store, "capabilities"))
        @compileError(@typeName(Store) ++ " must declare 'pub const capabilities' (see handler.Capabilities)");
    const info = @typeInfo(@TypeOf(Store.capabilities));
    if (info != .@"struct")
        @compileError(@typeName(Store) ++ " capabilities must be a struct literal of handler.Capabilities flags");
    var caps = Capabilities{};
    inline for (info.@"struct".fields) |f| {
        if (!comptime isCapField(f.name))
            @compileError(@typeName(Store) ++ " declares unknown capability '" ++ f.name ++ "'");
        @field(caps, f.name) = @field(Store.capabilities, f.name);
    }
    return caps;
}

/// Compile-time check that every mechanism a daemon advertises has a store
/// capability behind it. Each main calls this next to its MechanismList.
pub fn assertMechanisms(comptime Store: type, comptime mechs: []const protocol.MechanismId) void {
    const caps = capabilitiesOf(Store);
    inline for (mechs) |m| {
        switch (m) {
            .plain => if (!caps.lookup and !caps.validate_password)
                @compileError(@typeName(Store) ++ " cannot serve PLAIN: declare the lookup or validate_password capability"),
            .scram_sha_256 => if (!caps.lookup)
                @compileError(@typeName(Store) ++ " cannot serve SCRAM-SHA-256: declare the lookup capability"),
            .oauthbearer => if (!caps.validate_token)
                @compileError(@typeName(Store) ++ " cannot serve OAUTHBEARER: declare the validate_token capability"),
        }
    }
}

/// What handleMessage instructs the IPC loop to do next.
pub const HandleResult = union(enum) {
    /// Not an auth message — nothing to send.
    none,
    /// Send this reply now.
    reply: protocol.Message,
    /// Deferred to the crypto pool; the reply arrives via takeCryptoReply().
    deferred,
};

/// A completion-side reply rendered in the event loop (T121). On success the
/// message borrows owned_username — callers queueSend before deinit.
pub const DeferredReply = struct {
    slot: u32,
    slot_gen: u32,
    msg: protocol.Message,
    owned_username: ?[]u8 = null,

    pub fn deinit(self: *DeferredReply, allocator: std.mem.Allocator) void {
        if (self.owned_username) |u| allocator.free(u);
    }
};

/// Number of credential cache entries (power of 2 for fast modulo).
const CRED_CACHE_SIZE = 64;

/// Credential cache TTL in seconds.
const CRED_CACHE_TTL_SECONDS = 30;

/// Cached credential entry — avoids store lookups for repeated auth.
const CachedCredential = struct {
    username_hash: u64,
    creds: sasl.StoredCredentials,
    timestamp: i64,
    occupied: bool,
};

pub fn AuthHandler(comptime Store: type) type {
    const caps = capabilitiesOf(Store);
    comptime {
        if (caps.lookup and !@hasDecl(Store, "lookup"))
            @compileError(@typeName(Store) ++ " declares capabilities.lookup but has no 'lookup' decl");
        if (caps.validate_password and !@hasDecl(Store, "validatePassword"))
            @compileError(@typeName(Store) ++ " declares capabilities.validate_password but has no 'validatePassword' decl");
        if (caps.validate_token and !@hasDecl(Store, "validateToken"))
            @compileError(@typeName(Store) ++ " declares capabilities.validate_token but has no 'validateToken' decl");
        if (caps.photo_url and !@hasDecl(Store, "getPhotoUrl"))
            @compileError(@typeName(Store) ++ " declares capabilities.photo_url but has no 'getPhotoUrl' decl");
        if (caps.add_user and !@hasDecl(Store, "addUser"))
            @compileError(@typeName(Store) ++ " declares capabilities.add_user but has no 'addUser' decl");
        if (caps.change_password and !@hasDecl(Store, "changePassword"))
            @compileError(@typeName(Store) ++ " declares capabilities.change_password but has no 'changePassword' decl");
        if (caps.remove_user and !@hasDecl(Store, "removeUser"))
            @compileError(@typeName(Store) ++ " declares capabilities.remove_user but has no 'removeUser' decl");
    }
    return struct {
        store: *Store,
        allocator: std.mem.Allocator,
        /// Secret for the deterministic fake credentials and the keyed
        /// replay-cache tags (ADR-6); drawn at init or loaded from the
        /// persisted {db}/auth key, never leaves the daemon.
        scram_secret: [32]u8 = undefined,
        /// Server-nonce replay cache, capacity sized from config at init
        /// (mech/scram.zig owns the probe rules). Empty slice means every
        /// insert refuses. The only SCRAM state the daemon holds.
        replay_entries: []scram_mech.ReplayEntry = &.{},
        /// Freshness window for the timestamp inside server nonces
        /// (auth.scram_nonce_window_seconds) and the forward skew
        /// tolerance (auth.scram_nonce_skew_seconds).
        replay_window_seconds: i64 = scram_mech.DEFAULT_NONCE_WINDOW_SECONDS,
        nonce_skew_seconds: i64 = scram_mech.DEFAULT_NONCE_SKEW_SECONDS,
        /// Server nonces issued before this wall second are refused: set
        /// to boot time, so a restarted verifier whose replay table is
        /// empty cannot let a pre-boot challenge pass when the table
        /// cannot prove it was never consumed.
        replay_floor_seconds: i64 = 0,
        /// Admission policy: permanent locks and the rate limiter.
        policy: policy_mod.Policy = .{},
        /// Registration configuration.
        reg_config: RegistrationConfig = .{},
        /// Invite code validator (optional — required when reg_config.require_invite is true).
        invite_validator: ?InviteValidator = null,
        /// Credential lookup cache — avoids store reads for rapid reconnections.
        cred_cache: [CRED_CACHE_SIZE]CachedCredential = [_]CachedCredential{.{
            .username_hash = 0,
            .creds = undefined,
            .timestamp = 0,
            .occupied = false,
        }} ** CRED_CACHE_SIZE,

        /// T121: optional crypto offload pool. With a pool attached, local-store
        /// PLAIN derives run on pool threads and the reply is deferred; without
        /// one the derive runs inline in the loop (OIDC daemon, tests).
        crypto_pool: ?*crypto_pool_mod.CryptoPool = null,
        /// Deferred PLAIN auths awaiting pool completion, keyed by job id.
        pending_plain: std.AutoHashMapUnmanaged(u64, plain_mech.PendingPlain) = .{},

        const Self = @This();

        /// The store's declared capabilities, resolved by capabilitiesOf.
        pub const capabilities = caps;

        /// Replay-cache sizing and nonce freshness, derived from config by
        /// the daemon main (auth.login_rate_ceiling x
        /// auth.scram_nonce_window_seconds entries; the window and skew
        /// bound the embedded timestamp check).
        pub const InitOpts = struct {
            replay_capacity: usize = scram_mech.DEFAULT_REPLAY_CAPACITY,
            nonce_window_seconds: i64 = scram_mech.DEFAULT_NONCE_WINDOW_SECONDS,
            nonce_skew_seconds: i64 = scram_mech.DEFAULT_NONCE_SKEW_SECONDS,
            /// Boot-time floor for timed server nonces; null stamps the
            /// init timestamp. Tests set it to pin the boundary.
            nonce_floor_seconds: ?i64 = null,
            /// The persisted {db}/auth fake-derivation key; null mints a
            /// per-boot one (tests, OIDC daemon).
            scram_secret: ?[32]u8 = null,
        };

        /// The replay table is required for SCRAM when replay_capacity is
        /// nonzero: failing its allocation fails init, so the daemon
        /// cannot start up silently refusing every verify.
        pub fn init(allocator: std.mem.Allocator, store: *Store, opts: InitOpts) !Self {
            var handler = Self{
                .store = store,
                .allocator = allocator,
                .scram_secret = undefined,
                .replay_window_seconds = opts.nonce_window_seconds,
                .nonce_skew_seconds = opts.nonce_skew_seconds,
                .replay_floor_seconds = opts.nonce_floor_seconds orelse std.time.timestamp(),
            };
            if (opts.replay_capacity > 0) {
                handler.replay_entries = try allocator.alloc(scram_mech.ReplayEntry, opts.replay_capacity);
                for (handler.replay_entries) |*e| e.* = .{};
            }
            if (opts.scram_secret) |s| {
                handler.scram_secret = s;
            } else {
                std.crypto.random.bytes(&handler.scram_secret);
            }
            return handler;
        }

        /// Set the rate limiter (call after init).
        pub fn setRateLimiter(self: *Self, limiter: *RateLimiter) void {
            self.policy.limiter = limiter;
        }

        /// Set the lock checker (call after init).
        pub fn setLockChecker(self: *Self, checker: LockChecker) void {
            self.policy.lock_checker = checker;
        }

        /// Look up credentials in cache by precomputed hash.
        /// Returns cached creds if entry matches and is within TTL, null otherwise.
        pub fn cacheLookup(self: *Self, hash: u64, now: i64) ?sasl.StoredCredentials {
            const entry = &self.cred_cache[hash & (CRED_CACHE_SIZE - 1)];
            if (!entry.occupied or entry.username_hash != hash) return null;
            if (now - entry.timestamp > CRED_CACHE_TTL_SECONDS) {
                entry.occupied = false;
                return null;
            }
            return entry.creds;
        }

        /// Store credentials in cache by precomputed hash.
        pub fn cacheStore(self: *Self, hash: u64, now: i64, creds: sasl.StoredCredentials) void {
            self.cred_cache[hash & (CRED_CACHE_SIZE - 1)] = .{
                .username_hash = hash,
                .creds = creds,
                .timestamp = now,
                .occupied = true,
            };
        }

        /// Invalidate cache entry for a username (on password change).
        pub fn cacheInvalidate(self: *Self, username: []const u8) void {
            const hash = hashUsername(username);
            const entry = &self.cred_cache[hash & (CRED_CACHE_SIZE - 1)];
            if (entry.occupied and entry.username_hash == hash) {
                entry.occupied = false;
            }
        }

        pub fn deinit(self: *Self) void {
            std.crypto.secureZero(u8, &self.scram_secret);
            if (self.replay_entries.len > 0) self.allocator.free(self.replay_entries);
            var pend_it = self.pending_plain.iterator();
            while (pend_it.next()) |kv| {
                self.allocator.free(kv.value_ptr.username);
                self.allocator.free(kv.value_ptr.client_ip);
            }
            self.pending_plain.deinit(self.allocator);
        }

        /// Attach a crypto pool (T121). Local-store PLAIN derives start
        /// deferring after this; the IPC loop must poll takeCryptoReply()
        /// whenever the pool's wake pipe fires.
        pub fn enableCryptoPool(self: *Self, pool: *crypto_pool_mod.CryptoPool) void {
            self.crypto_pool = pool;
        }

        /// Render the reply for a finished crypto job (T121), or null if the
        /// job id is unknown (stale/abandoned). Rate-limit bookkeeping runs
        /// here on the loop thread, same as the inline path.
        pub fn takeCryptoReply(self: *Self, completion: crypto_pool_mod.Completion) ?DeferredReply {
            metrics.poolJobDone(completion.latency_us);
            const reply = plain_mech.takeCryptoReply(Store, self, completion) orelse return null;
            switch (reply.msg) {
                .auth_success => metrics.exchangeCompleted(@intFromEnum(protocol.MechanismId.plain), true),
                .auth_failure => metrics.exchangeCompleted(@intFromEnum(protocol.MechanismId.plain), false),
                else => {},
            }
            return reply;
        }

        /// Process an incoming IPC message. slot/slot_gen identify the IPC
        /// client for deferred (crypto pool) replies.
        pub fn handleMessage(self: *Self, msg: protocol.Message, slot: u32, slot_gen: u32) HandleResult {
            return switch (msg) {
                .auth_request => |req| self.handleAuthRequest(req, slot, slot_gen),
                .scram_params_request => |req| .{ .reply = scram_mech.handleScramParams(Store, self, req) },
                .scram_verify => |req| blk: {
                    metrics.exchangeStarted(@intFromEnum(protocol.MechanismId.scram_sha_256));
                    const reply = scram_mech.handleScramVerify(Store, self, req);
                    switch (reply) {
                        .auth_success => metrics.exchangeCompleted(@intFromEnum(protocol.MechanismId.scram_sha_256), true),
                        .auth_failure => metrics.exchangeCompleted(@intFromEnum(protocol.MechanismId.scram_sha_256), false),
                        else => {},
                    }
                    break :blk .{ .reply = reply };
                },
                .auth_abort => .none,
                .password_change_request => |req| .{ .reply = account_mod.handlePasswordChange(Store, self, req) },
                .account_delete_request => |req| .{ .reply = account_mod.handleAccountDelete(Store, self, req) },
                .register_request => |req| .{ .reply = account_mod.handleRegisterRequest(Store, self, req) },
                else => .none,
            };
        }

        fn handleAuthRequest(self: *Self, req: protocol.AuthRequest, slot: u32, slot_gen: u32) HandleResult {
            metrics.exchangeStarted(@intFromEnum(req.mechanism));
            const result = self.dispatchAuth(req, slot, slot_gen);
            if (result == .reply) switch (result.reply) {
                .auth_success => metrics.exchangeCompleted(@intFromEnum(req.mechanism), true),
                .auth_failure => metrics.exchangeCompleted(@intFromEnum(req.mechanism), false),
                // A challenge leaves the exchange open; it completes at the
                // scram_verify or dies abandoned.
                else => {},
            };
            return result;
        }

        fn dispatchAuth(self: *Self, req: protocol.AuthRequest, slot: u32, slot_gen: u32) HandleResult {
            // Each mechanism admits the IP before doing work and the account
            // once the identity is known, so every key is counted once.
            return switch (req.mechanism) {
                .plain => plain_mech.handlePlainAuth(Store, self, req, slot, slot_gen),
                .scram_sha_256 => .{ .reply = authFailure(req.conn_id, .mechanism_not_supported) },
                .oauthbearer => if (comptime caps.validate_token)
                    .{ .reply = oauthbearer_mech.handleOAuthBearerAuth(Store, self, req) }
                else
                    .{ .reply = authFailure(req.conn_id, .mechanism_not_supported) },
            };
        }

        /// Queued PLAIN jobs for this account, keyed by the folded localpart.
        /// Counts in-flight crypto-pool work against the lockout threshold.
        pub fn pendingFor(self: *Self, username: []const u8) usize {
            return plain_mech.pendingFor(Store, self, username);
        }
    };
}

/// Render an auth_failure message for a wire reason. The one constructor
/// every mechanism shares, so the outcome counter lives here.
pub fn authFailure(conn_id: u32, reason: FailureReason) protocol.Message {
    metrics.failure(@intFromEnum(reason));
    return protocol.Message{ .auth_failure = .{
        .conn_id = conn_id,
        .reason = reason.text(),
    } };
}

/// FNV-1a hash of a username string for cache indexing.
pub fn hashUsername(username: []const u8) u64 {
    var h: u64 = 0xcbf29ce484222325;
    for (username) |byte| {
        h ^= byte;
        h *%= 0x100000001b3;
    }
    return if (h == 0) 1 else h;
}

// The tests live beside their code in the mech/account files; pull those
// namespaces in so the test suite collects them.
comptime {
    _ = plain_mech;
    _ = scram_mech;
    _ = oauthbearer_mech;
    _ = account_mod;
}

// ============================================================================
// Tests
// ============================================================================

const testkit = @import("testkit.zig");
const backend_mod = @import("backend");
const user_store_mod = @import("user_store");
const MemoryBackend = backend_mod.MemoryBackend;
const TestUserStore = user_store_mod.UserStore(MemoryBackend);
const TestHandler = AuthHandler(TestUserStore);
const handleSync = testkit.handleSync;

fn counterValue(c: *const std.atomic.Value(u64)) u64 {
    return c.load(.monotonic);
}

test "AuthMetrics: PLAIN moves the started, completed and outcome counters" {
    const allocator = std.testing.allocator;
    metrics.reset();
    defer metrics.reset();

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");
    var handler = try TestHandler.init(allocator, &store, .{});
    defer handler.deinit();

    const c = &metrics.counters;
    const plain: usize = @intFromEnum(protocol.MechanismId.plain) - 1;

    var ok_buf: [64]u8 = undefined;
    const ok = handleSync(&handler, testkit.plainRequest(1, "10.0.0.1", testkit.plainPayload(&ok_buf, "alice", "secret123"))) orelse return error.NoResponse;
    try std.testing.expect(ok == .auth_success);
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.exchanges_started[plain]));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.exchanges_completed[plain]));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.auth_success));

    var bad_buf: [64]u8 = undefined;
    const bad = handleSync(&handler, testkit.plainRequest(2, "10.0.0.2", testkit.plainPayload(&bad_buf, "alice", "wrong"))) orelse return error.NoResponse;
    try std.testing.expect(bad == .auth_failure);
    try std.testing.expectEqual(@as(u64, 2), counterValue(&c.exchanges_started[plain]));
    try std.testing.expectEqual(@as(u64, 2), counterValue(&c.exchanges_completed[plain]));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.auth_success));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.outcomes[@intFromEnum(FailureReason.not_authorized)]));

    const malformed = handleSync(&handler, testkit.plainRequest(3, "10.0.0.3", "noseparators")) orelse return error.NoResponse;
    try std.testing.expect(malformed == .auth_failure);
    try std.testing.expectEqual(@as(u64, 3), counterValue(&c.exchanges_completed[plain]));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.outcomes[@intFromEnum(FailureReason.invalid_encoding)]));
}

test "AuthMetrics: SCRAM v2 counts one exchange per verify" {
    const allocator = std.testing.allocator;
    metrics.reset();
    defer metrics.reset();

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");
    var handler = try TestHandler.init(allocator, &store, .{});
    defer handler.deinit();

    const c = &metrics.counters;
    const scram: usize = @intFromEnum(protocol.MechanismId.scram_sha_256) - 1;

    var client = sasl.ScramClient.init(allocator, "alice", "secret123");
    defer client.deinit();
    var sf1: [512]u8 = undefined;
    var nb1: [testkit.SNONCE_B64_LEN]u8 = undefined;
    const ok = try testkit.scramV2Exchange(&handler, &client, 5, "10.0.0.5", "secret123", testkit.mintSnonce(&nb1, std.time.timestamp()), &sf1);
    try std.testing.expect(ok.verify_msg.? == .auth_success);
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.exchanges_started[scram]));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.exchanges_completed[scram]));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.auth_success));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.replay_occupied));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.replay_high_water));

    // A failed exchange completes the same counters, minus auth_success.
    var bad = sasl.ScramClient.init(allocator, "alice", "wrong-pass");
    defer bad.deinit();
    var sf2: [512]u8 = undefined;
    var nb2: [testkit.SNONCE_B64_LEN]u8 = undefined;
    const ko = try testkit.scramV2Exchange(&handler, &bad, 6, "10.0.0.6", "wrong-pass", testkit.mintSnonce(&nb2, std.time.timestamp()), &sf2);
    try std.testing.expect(ko.verify_msg.? == .auth_failure);
    try std.testing.expectEqual(@as(u64, 2), counterValue(&c.exchanges_started[scram]));
    try std.testing.expectEqual(@as(u64, 2), counterValue(&c.exchanges_completed[scram]));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.auth_success));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.outcomes[@intFromEnum(FailureReason.not_authorized)]));
}

test "AuthMetrics: OAUTHBEARER moves its own mechanism counters" {
    const allocator = std.testing.allocator;
    metrics.reset();
    defer metrics.reset();

    var store = testkit.TestIdpStore{ .token_user = "bob@idp.example" };
    var handler = try testkit.TestIdpHandler.init(allocator, &store, .{});
    defer handler.deinit();

    const c = &metrics.counters;
    const oauth: usize = @intFromEnum(protocol.MechanismId.oauthbearer) - 1;

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 43,
        .mechanism = .oauthbearer,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = "n,,\x01auth=Bearer tok123\x01\x01",
    } }) orelse return error.NoResponse;
    try std.testing.expect(result == .auth_success);
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.exchanges_started[oauth]));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.exchanges_completed[oauth]));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.auth_success));
    try std.testing.expectEqual(@as(u64, 0), counterValue(&c.exchanges_started[0]));
    try std.testing.expectEqual(@as(u64, 0), counterValue(&c.exchanges_started[1]));
}

test "AuthMetrics: limiter admits, refusals and lockouts move under driven exchanges" {
    const allocator = std.testing.allocator;
    metrics.reset();
    defer metrics.reset();

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "pw");
    var limiter = try RateLimiter.init(allocator, .{
        .max_per_account = 1,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 1,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    var handler = try TestHandler.init(allocator, &store, .{});
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    const c = &metrics.counters;

    // First attempt: both keys admitted.
    var buf1: [64]u8 = undefined;
    const ok = handleSync(&handler, testkit.plainRequest(1, "10.0.0.1", testkit.plainPayload(&buf1, "alice", "pw"))) orelse return error.NoResponse;
    try std.testing.expect(ok == .auth_success);
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.ip_admits));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.account_admits));
    try std.testing.expectEqual(@as(u64, 0), counterValue(&c.ip_refusals));
    try std.testing.expectEqual(@as(u64, 0), counterValue(&c.account_refusals));

    // Second attempt inside the window: the account key refuses (not a lock).
    var buf2: [64]u8 = undefined;
    const refused = handleSync(&handler, testkit.plainRequest(2, "10.0.0.2", testkit.plainPayload(&buf2, "alice", "pw"))) orelse return error.NoResponse;
    try std.testing.expect(refused == .auth_failure);
    try std.testing.expectEqualStrings("policy-violation", refused.auth_failure.reason);
    try std.testing.expectEqual(@as(u64, 2), counterValue(&c.ip_admits));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.account_refusals));
    try std.testing.expectEqual(@as(u64, 0), counterValue(&c.lockout_refusals));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.outcomes[@intFromEnum(FailureReason.policy_violation)]));

    // One recorded failure meets the threshold and locks the account.
    limiter.recordOutcome("alice", "10.0.0.9", false);
    var buf3: [64]u8 = undefined;
    const locked = handleSync(&handler, testkit.plainRequest(3, "10.0.0.3", testkit.plainPayload(&buf3, "alice", "pw"))) orelse return error.NoResponse;
    try std.testing.expect(locked == .auth_failure);
    try std.testing.expectEqualStrings("account-disabled", locked.auth_failure.reason);
    try std.testing.expectEqual(@as(u64, 2), counterValue(&c.account_refusals));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.lockout_refusals));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.outcomes[@intFromEnum(FailureReason.account_disabled)]));
}

test "AuthMetrics: a locked account's verify counts the refusal and lockout" {
    const allocator = std.testing.allocator;
    metrics.reset();
    defer metrics.reset();

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");
    var limiter = try RateLimiter.init(allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 1,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    var handler = try TestHandler.init(allocator, &store, .{});
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    const c = &metrics.counters;

    // The account locks before the verify; admission denies as locked and
    // counts the account refusal plus its lockout split.
    limiter.recordOutcome("alice", "10.0.0.60", false);

    var client = sasl.ScramClient.init(allocator, "alice", "secret123");
    defer client.deinit();
    var sf: [512]u8 = undefined;
    const ex = try testkit.scramV2Exchange(&handler, &client, 60, "10.0.0.60", "secret123", "srvnonceCCC=", &sf);
    try std.testing.expect(ex.verify_msg.? == .auth_failure);
    try std.testing.expectEqualStrings("account-disabled", ex.verify_msg.?.auth_failure.reason);
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.account_refusals));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.lockout_refusals));
}

test "AuthMetrics: an IP window denial and IP lockout move their counters" {
    const allocator = std.testing.allocator;
    metrics.reset();
    defer metrics.reset();

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "pw");
    var limiter = try RateLimiter.init(allocator, .{
        .max_per_account = 100,
        .max_per_ip = 1,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 1,
    });
    defer limiter.deinit();
    var handler = try TestHandler.init(allocator, &store, .{});
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    const c = &metrics.counters;

    // First attempt from the IP is admitted; the second spends the window.
    var buf1: [64]u8 = undefined;
    const ok = handleSync(&handler, testkit.plainRequest(1, "10.0.9.1", testkit.plainPayload(&buf1, "alice", "pw"))) orelse return error.NoResponse;
    try std.testing.expect(ok == .auth_success);
    var buf2: [64]u8 = undefined;
    const refused = handleSync(&handler, testkit.plainRequest(2, "10.0.9.1", testkit.plainPayload(&buf2, "alice", "pw"))) orelse return error.NoResponse;
    try std.testing.expect(refused == .auth_failure);
    try std.testing.expectEqualStrings("policy-violation", refused.auth_failure.reason);
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.ip_admits));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.ip_refusals));
    try std.testing.expectEqual(@as(u64, 0), counterValue(&c.lockout_refusals));

    // A recorded failure meets the IP lockout threshold; the next request
    // from that IP is denied as locked, not rate limited.
    limiter.recordOutcome("alice", "10.0.9.9", false);
    var buf3: [64]u8 = undefined;
    const locked = handleSync(&handler, testkit.plainRequest(3, "10.0.9.9", testkit.plainPayload(&buf3, "alice", "pw"))) orelse return error.NoResponse;
    try std.testing.expect(locked == .auth_failure);
    try std.testing.expectEqual(@as(u64, 2), counterValue(&c.ip_refusals));
    try std.testing.expectEqual(@as(u64, 1), counterValue(&c.lockout_refusals));
}

test "AuthMetrics: crypto-pool completions move jobs, high-water and latency" {
    const allocator = std.testing.allocator;
    metrics.reset();
    defer metrics.reset();

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "pooler", "pw");

    var pool = crypto_pool_mod.CryptoPool{ .allocator = allocator };
    try pool.start(1);
    defer pool.stop();
    var handler = try TestHandler.init(allocator, &store, .{});
    handler.enableCryptoPool(&pool);
    defer handler.deinit();

    const c = &metrics.counters;
    const plain: usize = @intFromEnum(protocol.MechanismId.plain) - 1;

    var conn: u32 = 1;
    while (conn <= 8) : (conn += 1) {
        var buf: [64]u8 = undefined;
        const reply = handleSync(&handler, testkit.plainRequest(conn, "10.0.0.8", testkit.plainPayload(&buf, "pooler", "pw")));
        try std.testing.expect(reply == null); // deferred to the pool
    }
    try std.testing.expectEqual(@as(u64, 8), counterValue(&c.exchanges_started[plain]));
    try std.testing.expect(counterValue(&c.pool_queue_high_water) >= 1);

    var done: usize = 0;
    while (done < 8) {
        testkit.waitForPoolWake(&pool) catch |err| switch (err) {
            error.PoolWakeTimeout => break,
            else => return err,
        };
        pool.drainPipe();
        while (pool.popCompletion()) |comp| {
            var reply = handler.takeCryptoReply(comp) orelse return error.UnknownJob;
            defer reply.deinit(allocator);
            try std.testing.expect(reply.msg == .auth_success);
            done += 1;
        }
    }

    try std.testing.expectEqual(@as(usize, 8), done);
    try std.testing.expectEqual(@as(u64, 8), counterValue(&c.pool_jobs));
    try std.testing.expectEqual(@as(u64, 8), counterValue(&c.exchanges_completed[plain]));
    try std.testing.expectEqual(@as(u64, 8), counterValue(&c.auth_success));
    var latency_total: u64 = 0;
    for (&c.pool_latency_us) |*b| latency_total += counterValue(b);
    try std.testing.expectEqual(@as(u64, 8), latency_total);
    // A PBKDF2 derive cannot finish inside 2 us, so an all-bucket-0
    // histogram means the latency stamp was dropped, not measured.
    try std.testing.expect(counterValue(&c.pool_latency_us[0]) < 8);
}
