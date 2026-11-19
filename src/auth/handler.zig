//! # Auth Handler — SASL authentication request processor
//!
//! Handles IPC auth requests from xmppd-core. Maintains per-connection
//! SCRAM state for multi-step exchanges.
//!
//! ## Flow
//!
//! **PLAIN:** AuthRequest → lookup → AuthSuccess/AuthFailure (one step)
//!
//! **SCRAM-SHA-256:** AuthRequest → ScramServer.handleClientFirst → AuthChallenge
//!                    SaslResponse → ScramServer.handleClientFinal → AuthSuccess/AuthFailure
//!
//! ## Layout
//!
//! The handler owns the shared state (SCRAM session table, credential
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

const plain_mech = @import("mech/plain.zig");
const scram_mech = @import("mech/scram.zig");
const oauthbearer_mech = @import("mech/oauthbearer.zig");
const account_mod = @import("account.zig");

const log = std.log.scoped(.auth_handler);

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
        /// Active SCRAM sessions indexed by slot.
        scram_sessions: [scram_mech.MAX_SCRAM_SESSIONS]scram_mech.ScramSession = undefined,
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

        pub fn init(allocator: std.mem.Allocator, store: *Store) Self {
            var handler = Self{
                .store = store,
                .allocator = allocator,
                .scram_sessions = undefined,
            };
            for (&handler.scram_sessions) |*s| {
                s.active = false;
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
            for (&self.scram_sessions) |*s| {
                if (s.active) s.deinit();
            }
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
            return plain_mech.takeCryptoReply(Store, self, completion);
        }

        /// Process an incoming IPC message. slot/slot_gen identify the IPC
        /// client for deferred (crypto pool) replies.
        pub fn handleMessage(self: *Self, msg: protocol.Message, slot: u32, slot_gen: u32) HandleResult {
            return switch (msg) {
                .auth_request => |req| self.handleAuthRequest(req, slot, slot_gen),
                .sasl_response => |resp| .{ .reply = scram_mech.handleSaslResponse(Store, self, @intCast(slot), resp) },
                .auth_abort => |a| blk: {
                    // The XMPP connection vanished mid-exchange; release its
                    // SCRAM slot immediately instead of waiting for the stale
                    // sweep — the core may already be reusing the conn.id.
                    scram_mech.cleanupSession(Store, self, @intCast(slot), a.conn_id);
                    break :blk .none;
                },
                .password_change_request => |req| .{ .reply = account_mod.handlePasswordChange(Store, self, req) },
                .account_delete_request => |req| .{ .reply = account_mod.handleAccountDelete(Store, self, req) },
                .register_request => |req| .{ .reply = account_mod.handleRegisterRequest(Store, self, req) },
                else => .none,
            };
        }

        fn handleAuthRequest(self: *Self, req: protocol.AuthRequest, slot: u32, slot_gen: u32) HandleResult {
            // Each mechanism admits the IP before doing work and the account
            // once the identity is known, so every key is counted once.
            return switch (req.mechanism) {
                .plain => plain_mech.handlePlainAuth(Store, self, req, slot, slot_gen),
                .scram_sha_256 => if (comptime caps.lookup)
                    .{ .reply = scram_mech.handleScramInit(Store, self, req, slot) }
                else
                    .{ .reply = authFailure(req.conn_id, .mechanism_not_supported) },
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

        /// Find or create a session slot for (lane, conn_id); null when the
        /// table is genuinely full (mech/scram.zig owns the probe rules).
        pub fn findOrCreateScramSlot(self: *Self, lane: u16, conn_id: u32) ?usize {
            return scram_mech.findOrCreateScramSlot(Store, self, lane, conn_id);
        }

        /// Find the live session slot for (lane, conn_id), or null.
        pub fn findScramSlot(self: *Self, lane: u16, conn_id: u32) ?usize {
            return scram_mech.findScramSlot(Store, self, lane, conn_id);
        }

        /// Clean up a SCRAM session after the response has been sent.
        /// Lookup is keyed on (lane, conn_id): conn_id alone collides
        /// across core worker lanes each numbering from 1 (T279).
        pub fn cleanupSession(self: *Self, lane: u16, conn_id: u32) void {
            scram_mech.cleanupSession(Store, self, lane, conn_id);
        }

        /// Deinit every in-flight SCRAM session the given IPC lane owns;
        /// called before closing that IPC client so dead lanes cannot wedge
        /// sessions into the 60 s stale probe (T279).
        pub fn closeLaneSessions(self: *Self, lane: usize) void {
            scram_mech.closeLaneSessions(Store, self, lane);
        }
    };
}

/// Render an auth_failure message for a wire reason.
pub fn authFailure(conn_id: u32, reason: FailureReason) protocol.Message {
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
