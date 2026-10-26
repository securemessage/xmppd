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

const std = @import("std");
const sasl = @import("sasl");
const protocol = @import("ipc_protocol");
const RateLimiter = @import("rate_limiter").RateLimiter;
const policy_mod = @import("policy");
const lock_store_mod = @import("lock_store");
const crypto_pool_mod = @import("crypto_pool");

const log = std.log.scoped(.auth_handler);

/// The lock types live in the policy module; these aliases keep the daemon
/// and test call sites stable.
pub const LockCheckResult = policy_mod.LockCheckResult;
pub const LockChecker = policy_mod.LockChecker;
pub const makeLockChecker = policy_mod.makeLockChecker;
pub const localpartOf = policy_mod.localpartOf;

/// Interface for invite code validation. The auth daemon sets this to
/// a closure over the InviteStore.
pub const InviteValidator = struct {
    ctx: *anyopaque,
    validateFn: *const fn (ctx: *anyopaque, code: []const u8) bool,

    pub fn validate(self: InviteValidator, code: []const u8) bool {
        return self.validateFn(self.ctx, code);
    }
};

/// Registration configuration.
pub const RegistrationConfig = struct {
    enabled: bool = false,
    require_invite: bool = true,
};

/// A PLAIN auth parked while the crypto pool derives its key (T121). Owned
/// by the handler; all memory comes from the handler's allocator and is only
/// touched on the event-loop thread.
const PendingPlain = struct {
    slot: u32,
    /// Accept-generation of the IPC client slot at request time — guards
    /// against a deferred reply landing on a different core connection that
    /// reused the slot.
    slot_gen: u32,
    conn_id: u32,
    username: []u8,
    client_ip: []u8,
};

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

/// Maximum concurrent SCRAM exchanges (one per XMPP connection doing auth).
/// Must cover a full-worker login burst — xmppd-core defaults to 4096
/// sessions per worker, and every one of them can be mid-SASL at once.
const MAX_SCRAM_SESSIONS = 8192;

/// A slot whose owner connection vanished mid-exchange (core only reports
/// auth outcomes for live connections) is reclaimed lazily on the probe
/// path once it has been stale this long. Event-driven: no sweep timer, and
/// idle daemons (no new auths) pay nothing.
const SCRAM_SLOT_STALE_SECONDS: i64 = 60;

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

/// Per-connection SCRAM state. Keyed by conn_id.
const ScramSession = struct {
    conn_id: u32,
    server: sasl.ScramServer,
    active: bool = false,
    /// IPC lane slot of the client that started the exchange: lets a dead
    /// lane sweep its in-flight sessions on close (T279).
    lane: u16 = 0,
    /// Last activity (unix seconds); drives lazy reclamation of slots whose
    /// XMPP connection died mid-exchange (see SCRAM_SLOT_STALE_SECONDS).
    touched_at: i64 = 0,
    /// Client address from the auth request, kept for the client-final
    /// outcome. The request buffer does not outlive the first message.
    client_ip: [64]u8 = undefined,
    client_ip_len: u8 = 0,

    fn deinit(self: *ScramSession) void {
        self.server.deinit();
        self.active = false;
        self.touched_at = 0;
        self.client_ip_len = 0;
    }

    fn setClientIp(self: *ScramSession, ip: []const u8) void {
        const n = @min(ip.len, self.client_ip.len);
        @memcpy(self.client_ip[0..n], ip[0..n]);
        self.client_ip_len = @intCast(n);
    }

    fn clientIp(self: *const ScramSession) []const u8 {
        return self.client_ip[0..self.client_ip_len];
    }
};

pub fn AuthHandler(comptime Store: type) type {
    return struct {
        store: *Store,
        allocator: std.mem.Allocator,
        /// Active SCRAM sessions indexed by slot.
        scram_sessions: [MAX_SCRAM_SESSIONS]ScramSession = undefined,
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
        pending_plain: std.AutoHashMapUnmanaged(u64, PendingPlain) = .{},

        const Self = @This();

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
        fn cacheLookup(self: *Self, hash: u64, now: i64) ?sasl.StoredCredentials {
            const entry = &self.cred_cache[hash & (CRED_CACHE_SIZE - 1)];
            if (!entry.occupied or entry.username_hash != hash) return null;
            if (now - entry.timestamp > CRED_CACHE_TTL_SECONDS) {
                entry.occupied = false;
                return null;
            }
            return entry.creds;
        }

        /// Store credentials in cache by precomputed hash.
        fn cacheStore(self: *Self, hash: u64, now: i64, creds: sasl.StoredCredentials) void {
            self.cred_cache[hash & (CRED_CACHE_SIZE - 1)] = .{
                .username_hash = hash,
                .creds = creds,
                .timestamp = now,
                .occupied = true,
            };
        }

        /// Invalidate cache entry for a username (on password change).
        fn cacheInvalidate(self: *Self, username: []const u8) void {
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

        /// Queued PLAIN jobs for this account, keyed by the folded localpart.
        /// Counts in-flight crypto-pool work against the lockout threshold.
        fn pendingFor(self: *Self, username: []const u8) usize {
            var current_buf: [policy_mod.account_key_max]u8 = undefined;
            const current = policy_mod.accountKey(username, &current_buf);
            var count: usize = 0;
            var it = self.pending_plain.iterator();
            while (it.next()) |kv| {
                var key_buf: [policy_mod.account_key_max]u8 = undefined;
                const key = policy_mod.accountKey(kv.value_ptr.username, &key_buf);
                if (std.mem.eql(u8, key, current)) count += 1;
            }
            return count;
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
            const kv = self.pending_plain.fetchRemove(completion.id) orelse return null;
            const pend = kv.value;
            defer self.allocator.free(pend.client_ip);

            if (completion.ok) {
                log.info("PLAIN auth success: '{s}'", .{pend.username});
                self.policy.recordOutcome(pend.username, pend.client_ip, .success);
                return .{
                    .slot = pend.slot,
                    .slot_gen = pend.slot_gen,
                    .owned_username = pend.username,
                    .msg = .{ .auth_success = .{
                        .conn_id = pend.conn_id,
                        .username = pend.username,
                        .server_final = "",
                    } },
                };
            }

            log.info("PLAIN auth failed: wrong password for '{s}'", .{pend.username});
            self.policy.recordOutcome(pend.username, pend.client_ip, .failure);
            self.allocator.free(pend.username);
            return .{
                .slot = pend.slot,
                .slot_gen = pend.slot_gen,
                .msg = authFailure(pend.conn_id, "not-authorized"),
            };
        }

        /// Process an incoming IPC message. slot/slot_gen identify the IPC
        /// client for deferred (crypto pool) replies.
        pub fn handleMessage(self: *Self, msg: protocol.Message, slot: u32, slot_gen: u32) HandleResult {
            return switch (msg) {
                .auth_request => |req| self.handleAuthRequest(req, slot, slot_gen),
                .sasl_response => |resp| .{ .reply = self.handleSaslResponse(@intCast(slot), resp) },
                .auth_abort => |a| blk: {
                    // The XMPP connection vanished mid-exchange; release its
                    // SCRAM slot immediately instead of waiting for the stale
                    // sweep — the core may already be reusing the conn.id.
                    self.cleanupSession(@intCast(slot), a.conn_id);
                    break :blk .none;
                },
                .password_change_request => |req| .{ .reply = self.handlePasswordChange(req) },
                .account_delete_request => |req| .{ .reply = self.handleAccountDelete(req) },
                .register_request => |req| .{ .reply = self.handleRegisterRequest(req) },
                else => .none,
            };
        }

        fn handleAuthRequest(self: *Self, req: protocol.AuthRequest, slot: u32, slot_gen: u32) HandleResult {
            // Each mechanism admits the IP before doing work and the account
            // once the identity is known, so every key is counted once.
            return switch (req.mechanism) {
                .plain => self.handlePlainAuth(req, slot, slot_gen),
                .scram_sha_256 => if (comptime @hasDecl(Store, "lookup"))
                    .{ .reply = self.handleScramInit(req, slot) }
                else
                    .{ .reply = authFailure(req.conn_id, "mechanism-not-supported") },
                .oauthbearer => if (comptime @hasDecl(Store, "validateToken"))
                    .{ .reply = self.handleOAuthBearerAuth(req) }
                else
                    .{ .reply = authFailure(req.conn_id, "mechanism-not-supported") },
            };
        }

        fn handlePlainAuth(self: *Self, req: protocol.AuthRequest, slot: u32, slot_gen: u32) HandleResult {
            // PLAIN payload format: [authzid]\0authcid\0passwd
            // We only use authcid (username) and passwd
            const payload = req.payload;

            // Find the two NUL separators
            var nul1: ?usize = null;
            var nul2: ?usize = null;
            for (payload, 0..) |byte, i| {
                if (byte == 0) {
                    if (nul1 == null) {
                        nul1 = i;
                    } else {
                        nul2 = i;
                        break;
                    }
                }
            }

            const authcid_start = (nul1 orelse return .{ .reply = authFailure(req.conn_id, "invalid-encoding") }) + 1;
            const authcid_end = nul2 orelse return .{ .reply = authFailure(req.conn_id, "invalid-encoding") };
            const passwd_start = authcid_end + 1;

            if (authcid_start >= payload.len or passwd_start >= payload.len) {
                return .{ .reply = authFailure(req.conn_id, "invalid-encoding") };
            }

            const username = payload[authcid_start..authcid_end];
            const password = payload[passwd_start..];

            // Count the IP attempt before any lookup or KDF.
            if (self.policy.admitIp(req.client_ip)) |reason| {
                return .{ .reply = authFailure(req.conn_id, reason) };
            }

            // If the store supports validatePassword (OIDC/IdP delegation), use that
            if (comptime @hasDecl(Store, "validatePassword")) {
                // A lock on the supplied localpart must reject before the
                // IdP call, or a right password for a locked account is
                // distinguishable from a wrong one.
                if (self.policy.check(username, req.client_ip)) |reason| {
                    return .{ .reply = authFailure(req.conn_id, reason) };
                }

                const result = self.store.validatePassword(self.allocator, username, password) catch {
                    return .{ .reply = authFailure(req.conn_id, "temporary-auth-failure") };
                };
                if (result) |validated_user| {
                    // S3: locks bind to the identity the IdP handed
                    // back, normalized to its localpart ("Alice@domain" and
                    // "Alice" resolve to the same "alice" admission every
                    // mechanism enforces).
                    const identity = localpartOf(validated_user);
                    // The IdP may resolve an alias to a different account
                    // than the typed name. If that identity is locked, reply
                    // exactly as for a wrong password and charge both keys;
                    // otherwise the alias is an oracle and gets its own
                    // failure budget.
                    var typed_buf: [policy_mod.account_key_max]u8 = undefined;
                    var identity_buf: [policy_mod.account_key_max]u8 = undefined;
                    const typed_key = policy_mod.accountKey(username, &typed_buf);
                    const identity_key = policy_mod.accountKey(identity, &identity_buf);
                    if (!std.mem.eql(u8, typed_key, identity_key)) {
                        if (self.policy.check(identity, "")) |reason| {
                            if (std.mem.eql(u8, reason, "account-disabled")) {
                                log.info("PLAIN auth failed (IdP alias): '{s}' maps to locked '{s}'", .{ username, identity });
                                self.policy.recordAliasFailure(username, identity, req.client_ip);
                                return .{ .reply = authFailure(req.conn_id, "not-authorized") };
                            }
                            return .{ .reply = authFailure(req.conn_id, reason) };
                        }
                    }
                    if (self.policy.admitAccount(identity)) |reason| {
                        return .{ .reply = authFailure(req.conn_id, reason) };
                    }
                    log.info("PLAIN auth success (IdP): '{s}' as '{s}'", .{ username, identity });
                    self.policy.recordOutcome(identity, req.client_ip, .success);
                    return .{ .reply = protocol.Message{ .auth_success = .{
                        .conn_id = req.conn_id,
                        .username = identity,
                        .server_final = "",
                    } } };
                } else {
                    log.info("PLAIN auth failed (IdP): '{s}'", .{username});
                    self.policy.recordOutcome(username, req.client_ip, .failure);
                    return .{ .reply = authFailure(req.conn_id, "not-authorized") };
                }
            }

            // Traditional credential lookup + SCRAM derive
            if (comptime @hasDecl(Store, "lookup")) {
                // Count the account attempt and enforce the lock before the
                // lookup and KDF. A crypto-pool job also counts against the
                // lockout threshold while it is in flight.
                const account_reason = if (self.crypto_pool != null)
                    self.policy.admitAccountPending(username, self.pendingFor(username))
                else
                    self.policy.admitAccount(username);
                if (account_reason) |reason| {
                    return .{ .reply = authFailure(req.conn_id, reason) };
                }

                const maybe_creds = self.store.lookup(self.allocator, username) catch {
                    return .{ .reply = authFailure(req.conn_id, "temporary-auth-failure") };
                };
                const creds = maybe_creds orelse {
                    log.info("PLAIN auth failed: user '{s}' not found", .{username});
                    self.policy.recordOutcome(username, req.client_ip, .failure);
                    return .{ .reply = authFailure(req.conn_id, "not-authorized") };
                };

                // T121: with a pool attached, the loop returns immediately and
                // the derive runs on a pool thread; the reply is rendered by
                // takeCryptoReply when the completion wakes the loop. The pool
                // deep-copies the password — payload's backing buffer dies
                // with this dispatch.
                if (self.crypto_pool) |pool| {
                    const job_id = pool.put(password, creds.salt, creds.iteration_count, creds.stored_key) catch {
                        return .{ .reply = authFailure(req.conn_id, "temporary-auth-failure") };
                    };
                    const username_owned = self.allocator.dupe(u8, username) catch {
                        log.err("pending auth alloc failed; job {d} completes orphaned", .{job_id});
                        return .{ .reply = authFailure(req.conn_id, "temporary-auth-failure") };
                    };
                    const ip_owned = self.allocator.dupe(u8, req.client_ip) catch {
                        self.allocator.free(username_owned);
                        log.err("pending auth alloc failed; job {d} completes orphaned", .{job_id});
                        return .{ .reply = authFailure(req.conn_id, "temporary-auth-failure") };
                    };
                    self.pending_plain.put(self.allocator, job_id, .{
                        .slot = slot,
                        .slot_gen = slot_gen,
                        .conn_id = req.conn_id,
                        .username = username_owned,
                        .client_ip = ip_owned,
                    }) catch {
                        self.allocator.free(username_owned);
                        self.allocator.free(ip_owned);
                        return .{ .reply = authFailure(req.conn_id, "temporary-auth-failure") };
                    };
                    return .deferred;
                }

                // No pool: verify inline by deriving with the same salt.
                // A password that fails OpaqueString prep cannot match a
                // prepped stored credential: treat as a failed auth.
                const test_creds = sasl.StoredCredentials.derive(password, creds.salt, creds.iteration_count) catch {
                    log.info("PLAIN auth failed: wrong password for '{s}'", .{username});
                    self.policy.recordOutcome(username, req.client_ip, .failure);
                    return .{ .reply = authFailure(req.conn_id, "not-authorized") };
                };
                // T211 follow-up: constant-time compare for StoredKey.
                if (!std.crypto.timing_safe.eql([32]u8, test_creds.stored_key, creds.stored_key)) {
                    log.info("PLAIN auth failed: wrong password for '{s}'", .{username});
                    self.policy.recordOutcome(username, req.client_ip, .failure);
                    return .{ .reply = authFailure(req.conn_id, "not-authorized") };
                }

                log.info("PLAIN auth success: '{s}'", .{username});
                self.policy.recordOutcome(username, req.client_ip, .success);
                return .{ .reply = protocol.Message{ .auth_success = .{
                    .conn_id = req.conn_id,
                    .username = username,
                    .server_final = "",
                } } };
            }

            return .{ .reply = authFailure(req.conn_id, "mechanism-not-supported") };
        }

        /// Handle OAUTHBEARER mechanism — delegates to Store.validateToken.
        /// The SASL initial response is RFC 7628 format:
        ///   gs2-header kvsep "auth=Bearer " token kvsep kvsep
        ///   n,,\x01auth=Bearer TOKEN\x01\x01
        fn handleOAuthBearerAuth(self: *Self, req: protocol.AuthRequest) protocol.Message {
            if (comptime !@hasDecl(Store, "validateToken")) {
                return authFailure(req.conn_id, "mechanism-not-supported");
            }

            // Count the IP attempt before the IdP call: a locked IP must not
            // spend token-validation work.
            if (self.policy.admitIp(req.client_ip)) |reason| {
                log.info("OAUTHBEARER rejected before token validation: {s}", .{reason});
                return authFailure(req.conn_id, reason);
            }

            // Extract bearer token from RFC 7628 OAUTHBEARER initial response
            const payload = req.payload;
            if (payload.len == 0) {
                return authFailure(req.conn_id, "invalid-encoding");
            }

            // Find "auth=Bearer " after the first \x01 separator
            const bearer_prefix = "auth=Bearer ";
            const token = blk: {
                if (std.mem.indexOf(u8, payload, bearer_prefix)) |pos| {
                    const start = pos + bearer_prefix.len;
                    // Token ends at the next \x01 separator
                    const rest = payload[start..];
                    const end = std.mem.indexOfScalar(u8, rest, 0x01) orelse rest.len;
                    break :blk rest[0..end];
                }
                // Fallback: treat entire payload as token (for simple clients)
                break :blk payload;
            };
            if (token.len == 0) {
                return authFailure(req.conn_id, "invalid-encoding");
            }

            const result = self.store.validateToken(self.allocator, token) catch {
                return authFailure(req.conn_id, "temporary-auth-failure");
            };

            if (result) |validated_user| {
                // Lock check on the IdP-verified identity (S3).
                const identity = localpartOf(validated_user);
                if (self.policy.admitAccount(identity)) |reason| {
                    return authFailure(req.conn_id, reason);
                }
                log.info("OAUTHBEARER auth success: '{s}'", .{validated_user});
                self.policy.recordOutcome(identity, req.client_ip, .success);
                const photo_url = if (comptime @hasDecl(Store, "getPhotoUrl"))
                    self.store.getPhotoUrl()
                else
                    "";
                return protocol.Message{ .auth_success = .{
                    .conn_id = req.conn_id,
                    .username = validated_user,
                    .server_final = "",
                    .photo_url = photo_url,
                } };
            } else {
                log.info("OAUTHBEARER auth failed", .{});
                self.policy.recordOutcome(req.username, req.client_ip, .failure);
                return authFailure(req.conn_id, "not-authorized");
            }
        }

        fn handleScramInit(self: *Self, req: protocol.AuthRequest, ipc_slot: usize) protocol.Message {
            if (comptime !@hasDecl(Store, "lookup")) {
                return authFailure(req.conn_id, "mechanism-not-supported");
            } else {
                // Count the IP attempt before creating exchange state.
                if (self.policy.admitIp(req.client_ip)) |reason| {
                    return authFailure(req.conn_id, reason);
                }

                // Find or create a SCRAM session for this conn_id
                const slot = self.findOrCreateScramSlot(@intCast(ipc_slot), req.conn_id) orelse {
                    return authFailure(req.conn_id, "temporary-auth-failure");
                };

                var session = &self.scram_sessions[slot];
                // Re-auth on an already-live conn_id: the previous exchange's
                // ScramServer must go before we overwrite it (T279).
                if (session.active) session.deinit();
                session.server = sasl.ScramServer.init(self.allocator);
                session.conn_id = req.conn_id;
                session.lane = @intCast(ipc_slot);
                session.active = true;
                session.touched_at = std.time.timestamp();

                // Set channel binding data from TLS session
                session.server.setChannelBinding(req.cb_type, req.cb_data);

                // Process client-first-message
                const username = session.server.handleClientFirst(req.payload) catch {
                    session.deinit();
                    return authFailure(req.conn_id, "invalid-encoding");
                };

                // Count the account attempt and enforce the lock before any
                // store lookup or challenge work.
                if (self.policy.admitAccount(username)) |reason| {
                    session.deinit();
                    return authFailure(req.conn_id, reason);
                }
                session.setClientIp(req.client_ip);

                // Look up credentials — try cache first, fall back to store
                const name_hash = hashUsername(username);
                const now = std.time.timestamp();
                const creds = self.cacheLookup(name_hash, now) orelse blk: {
                    const maybe_creds = self.store.lookup(self.allocator, username) catch {
                        session.deinit();
                        return authFailure(req.conn_id, "temporary-auth-failure");
                    };
                    const c = maybe_creds orelse {
                        log.info("SCRAM auth failed: user '{s}' not found", .{username});
                        // The attempt was counted at admission; an unknown
                        // user is still a failed authentication.
                        self.policy.recordOutcome(username, req.client_ip, .failure);
                        session.deinit();
                        return authFailure(req.conn_id, "not-authorized");
                    };
                    self.cacheStore(name_hash, now, c);
                    break :blk c;
                };

                session.server.setCredentials(creds);

                // Generate server-first-message
                const server_first = session.server.serverFirst() catch {
                    session.deinit();
                    return authFailure(req.conn_id, "temporary-auth-failure");
                };

                log.info("SCRAM challenge sent for '{s}' conn={d}", .{ username, req.conn_id });

                return protocol.Message{ .auth_challenge = .{
                    .conn_id = req.conn_id,
                    .challenge = server_first,
                } };
            }
        }

        fn handleSaslResponse(self: *Self, lane: u16, resp: protocol.SaslResponse) protocol.Message {
            // Find the SCRAM session for this lane's conn_id (T279:
            // another lane's identical conn_id must not qualify).
            const slot = self.findScramSlot(lane, resp.conn_id) orelse {
                // No exchange for this conn: aborted, swept as stale, or the
                // auth_request never arrived. Was completely silent.
                log.warn("SCRAM final for conn={d} has no exchange (aborted/swept/lost)", .{resp.conn_id});
                return authFailure(resp.conn_id, "not-authorized");
            };

            var session = &self.scram_sessions[slot];
            session.touched_at = std.time.timestamp();

            const username = session.server.username;
            // S3/A1: re-check both keys without counting before the proof is
            // verified, so a lock that arrived between challenge and final
            // gets the same reply for a right and a wrong password.
            if (self.policy.check(username, session.clientIp())) |reason| {
                session.deinit();
                return authFailure(resp.conn_id, reason);
            }

            // Process client-final-message
            const server_final = session.server.handleClientFinal(resp.payload) catch {
                log.info("SCRAM auth failed: proof verification for conn={d}", .{resp.conn_id});
                self.policy.recordOutcome(username, session.clientIp(), .failure);
                session.deinit();
                return authFailure(resp.conn_id, "not-authorized");
            };

            log.info("SCRAM auth success: '{s}' conn={d}", .{ username, resp.conn_id });
            self.policy.recordOutcome(username, session.clientIp(), .success);

            // Keep session alive briefly for the username reference, then clean up
            const result = protocol.Message{ .auth_success = .{
                .conn_id = resp.conn_id,
                .username = username,
                .server_final = server_final,
            } };

            // Don't deinit yet — the username/server_final slices are borrowed from the arena.
            // They'll be valid until the next message for this slot.

            return result;
        }

        fn handlePasswordChange(self: *Self, req: protocol.PasswordChangeRequest) protocol.Message {
            if (req.username.len == 0 or req.new_password.len == 0) {
                return protocol.Message{ .password_change_result = .{
                    .conn_id = req.conn_id,
                    .success = false,
                    .reason = "bad-request",
                } };
            }

            if (comptime !@hasDecl(Store, "changePassword")) {
                return protocol.Message{ .password_change_result = .{
                    .conn_id = req.conn_id,
                    .success = false,
                    .reason = "not-allowed",
                } };
            }

            self.store.changePassword(self.allocator, req.username, req.new_password) catch |err| {
                const reason: []const u8 = switch (err) {
                    error.UserNotFound => "item-not-found",
                    else => "internal-server-error",
                };
                log.info("password change failed for '{s}': {s}", .{ req.username, reason });
                return protocol.Message{ .password_change_result = .{
                    .conn_id = req.conn_id,
                    .success = false,
                    .reason = reason,
                } };
            };

            self.cacheInvalidate(req.username);
            log.info("password changed for '{s}'", .{req.username});
            return protocol.Message{ .password_change_result = .{
                .conn_id = req.conn_id,
                .success = true,
                .reason = "",
            } };
        }

        fn handleAccountDelete(self: *Self, req: protocol.AccountDeleteRequest) protocol.Message {
            if (req.username.len == 0) {
                return protocol.Message{ .account_delete_result = .{
                    .conn_id = req.conn_id,
                    .success = false,
                    .reason = "bad-request",
                } };
            }

            if (comptime !@hasDecl(Store, "removeUser")) {
                return protocol.Message{ .account_delete_result = .{
                    .conn_id = req.conn_id,
                    .success = false,
                    .reason = "not-allowed",
                } };
            }

            // Remove from UserStore (ignore UserNotFound — may be external auth)
            self.store.removeUser(self.allocator, req.username) catch |err| {
                switch (err) {
                    error.UserNotFound => {},
                    else => {
                        log.err("account delete failed for '{s}': store error", .{req.username});
                        return protocol.Message{ .account_delete_result = .{
                            .conn_id = req.conn_id,
                            .success = false,
                            .reason = "internal-server-error",
                        } };
                    },
                }
            };

            // Remove from LockStore (if lock_checker is configured, the LockStore exists)
            // The lock checker holds a reference to LockStore — we use a dedicated
            // delete callback for cleanup. For now, locks are cleaned via xmppctl unlock
            // or naturally don't apply once the account is gone.

            log.info("account deleted (auth): '{s}'", .{req.username});
            return protocol.Message{ .account_delete_result = .{
                .conn_id = req.conn_id,
                .success = true,
                .reason = "",
            } };
        }

        fn handleRegisterRequest(self: *Self, req: protocol.RegisterRequest) protocol.Message {
            const regResult = protocol.RegisterResult;

            // OIDC backends don't support registration
            if (comptime !@hasDecl(Store, "addUser")) {
                return protocol.Message{ .register_result = regResult{
                    .conn_id = req.conn_id,
                    .success = false,
                    .reason = "not-allowed",
                } };
            }

            // Privileged admin requests (xmppctl) bypass registration policy.
            // The marker remains a convention between local daemons; the
            // socket itself is now peer-credential checked at accept (T258),
            // so only root or the daemon uid may even open it.
            const is_admin = std.mem.eql(u8, req.client_ip, "ctl");

            // Check if registration is enabled (skip for admin)
            if (!is_admin and !self.reg_config.enabled) {
                return protocol.Message{ .register_result = regResult{
                    .conn_id = req.conn_id,
                    .success = false,
                    .reason = "not-allowed",
                } };
            }

            // Count and rate limit registration attempts (skip for admin).
            // Registration outcomes are not authentication outcomes.
            if (!is_admin) {
                if (self.policy.admitIp(req.client_ip)) |reason| {
                    return protocol.Message{ .register_result = regResult{
                        .conn_id = req.conn_id,
                        .success = false,
                        .reason = reason,
                    } };
                }
            }

            // Validate input
            if (req.username.len == 0 or req.password.len == 0) {
                return protocol.Message{ .register_result = regResult{
                    .conn_id = req.conn_id,
                    .success = false,
                    .reason = "bad-request",
                } };
            }

            // Validate invitation code if required (skip for admin)
            if (!is_admin and self.reg_config.require_invite) {
                if (req.invite_code.len == 0) {
                    return protocol.Message{ .register_result = regResult{
                        .conn_id = req.conn_id,
                        .success = false,
                        .reason = "not-allowed",
                    } };
                }
                if (self.invite_validator) |validator| {
                    if (!validator.validate(req.invite_code)) {
                        log.info("registration rejected: invalid invite code for '{s}'", .{req.username});
                        return protocol.Message{ .register_result = regResult{
                            .conn_id = req.conn_id,
                            .success = false,
                            .reason = "not-allowed",
                        } };
                    }
                } else {
                    // No validator configured but invites required — reject
                    return protocol.Message{ .register_result = regResult{
                        .conn_id = req.conn_id,
                        .success = false,
                        .reason = "not-allowed",
                    } };
                }
            }

            // Create the user
            self.store.addUser(self.allocator, req.username, req.password) catch |err| {
                const reason: []const u8 = switch (err) {
                    error.UserExists => "conflict",
                    else => "internal-server-error",
                };
                log.info("registration failed for '{s}': {s}", .{ req.username, reason });
                return protocol.Message{ .register_result = regResult{
                    .conn_id = req.conn_id,
                    .success = false,
                    .reason = reason,
                } };
            };

            log.info("user registered: '{s}'", .{req.username});
            return protocol.Message{ .register_result = regResult{
                .conn_id = req.conn_id,
                .success = true,
                .reason = "",
            } };
        }

        /// Clean up a SCRAM session after the response has been sent.
        /// Lookup is keyed on (lane, conn_id): conn_id alone collides
        /// across core worker lanes each numbering from 1 (T279).
        pub fn cleanupSession(self: *Self, lane: u16, conn_id: u32) void {
            if (self.findScramSlot(lane, conn_id)) |slot| {
                self.scram_sessions[slot].deinit();
            }
        }

        /// Deinit every in-flight SCRAM session the given IPC lane owns;
        /// called before closing that IPC client so dead lanes cannot wedge
        /// sessions into the 60 s stale probe (T279).
        pub fn closeLaneSessions(self: *Self, lane: usize) void {
            const lane_u16: u16 = @intCast(lane);
            for (&self.scram_sessions) |*s| {
                if (s.active and s.lane == lane_u16) s.deinit();
            }
        }

        /// conn_id packs generation<<16|session_slot, so a burst of >256
        /// concurrent logins on one worker aliases mod MAX_SCRAM_SESSIONS
        /// by construction. The table must probe instead of failing on the
        /// first occupied home slot (birthday collisions are guaranteed);
        /// null now means the table is genuinely full.
        /// (lane, conn_id) is the key: the same conn_id legimately recurs
        /// once per core worker lane (T279).
        fn findOrCreateScramSlot(self: *Self, lane: u16, conn_id: u32) ?usize {
            if (self.findScramSlot(lane, conn_id)) |slot| return slot;
            const now = std.time.timestamp();
            const start = (conn_id & 0xFFFF) % MAX_SCRAM_SESSIONS;
            var i: usize = 0;
            while (i < MAX_SCRAM_SESSIONS) : (i += 1) {
                const slot = (start + i) % MAX_SCRAM_SESSIONS;
                const s = &self.scram_sessions[slot];
                if (!s.active) return slot;
                // Reclaim slots abandoned by connections that died before a
                // final auth response — otherwise they leak until restart.
                if (now - s.touched_at > SCRAM_SLOT_STALE_SECONDS) {
                    s.deinit();
                    return slot;
                }
            }
            return null;
        }

        fn findScramSlot(self: *Self, lane: u16, conn_id: u32) ?usize {
            // Probing leaves holes on cleanup; a full scan over 256 entries
            // is cheaper than tombstone bookkeeping. (lane, conn_id) key
            // (T279): never hand another lane's active exchange back here.
            for (&self.scram_sessions, 0..) |*s, slot| {
                if (s.active and s.conn_id == conn_id and s.lane == lane) return slot;
            }
            return null;
        }
    };
}

fn authFailure(conn_id: u32, reason: []const u8) protocol.Message {
    return protocol.Message{ .auth_failure = .{
        .conn_id = conn_id,
        .reason = reason,
    } };
}

/// FNV-1a hash of a username string for cache indexing.
fn hashUsername(username: []const u8) u64 {
    var h: u64 = 0xcbf29ce484222325;
    for (username) |byte| {
        h ^= byte;
        h *%= 0x100000001b3;
    }
    return if (h == 0) 1 else h;
}

// ============================================================================
// Tests
// ============================================================================

const backend_mod = @import("backend");
const user_store_mod = @import("user_store");
const MemoryBackend = backend_mod.MemoryBackend;
const TestUserStore = user_store_mod.UserStore(MemoryBackend);
const TestHandler = AuthHandler(TestUserStore);
const TestCryptoPool = crypto_pool_mod.CryptoPool;

/// Test helper: drive the synchronous variant of handleMessage.
fn handleSync(handler: anytype, msg: protocol.Message) ?protocol.Message {
    return switch (handler.handleMessage(msg, 0, 1)) {
        .reply => |m| m,
        .deferred, .none => null,
    };
}

/// Wait for the pool's completion wake byte. The read end is non-blocking.
fn waitForPoolWake(pool: *TestCryptoPool) !void {
    var buf: [8]u8 = undefined;
    const deadline = std.time.milliTimestamp() + 3000;
    while (std.time.milliTimestamp() < deadline) {
        const n = std.posix.read(pool.pipe_rd, &buf) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => return err,
        };
        if (n > 0) return;
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    return error.PoolWakeTimeout;
}

/// IdP-delegating test store: credentials and tokens are answered by the
/// identity provider instead of a local user table, so the
/// @hasDecl(Store, "validatePassword"/"validateToken") admit paths compile
/// and run (the local UserStore never reaches them).
const TestIdpStore = struct {
    password_user: ?[]const u8 = null,
    password_secret: ?[]const u8 = null,
    token_user: ?[]const u8 = null,
    /// Number of IdP calls, so a test can prove a lock is checked before
    /// any IdP work.
    password_calls: u32 = 0,
    token_calls: u32 = 0,

    pub fn validatePassword(self: *@This(), allocator: std.mem.Allocator, username: []const u8, password: []const u8) !?[]const u8 {
        _ = allocator;
        _ = username;
        self.password_calls += 1;
        if (self.password_secret) |secret| {
            if (!std.mem.eql(u8, password, secret)) return null;
        }
        return self.password_user;
    }

    pub fn validateToken(self: *@This(), allocator: std.mem.Allocator, token: []const u8) !?[]const u8 {
        _ = allocator;
        _ = token;
        self.token_calls += 1;
        return self.token_user;
    }
};
const TestIdpHandler = AuthHandler(TestIdpStore);

test "AuthHandler: SCRAM slot table probes past conn_id home-slot collisions" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "burst", "pass123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    // conn_id packs generation<<16|session_slot; a login burst on one worker
    // hands out sequential slots, so conn_ids 1, 257, 513, ... all collide on
    // the same home slot mod MAX_SCRAM_SESSIONS. Every one must still get a
    // challenge (probing), not a collision rejection.
    var client = sasl.ScramClient.init(allocator, "burst", "pass123");
    defer client.deinit();
    const conn_ids = [_]u32{ 1, 257, 513, 769 };
    for (conn_ids) |cid| {
        const reply = handleSync(&handler, .{ .auth_request = .{
            .conn_id = cid,
            .mechanism = .scram_sha_256,
            .client_ip = "10.0.0.9",
            .cb_type = 0,
            .cb_data = "",
            .username = "burst",
            .payload = try client.clientFirst(),
        } }) orelse return error.NoResponse;
        switch (reply) {
            .auth_challenge => {},
            .auth_failure => |f| {
                std.debug.print("conn_id {d} wrongly failed: {s}\n", .{ cid, f.reason });
                return error.UnexpectedAuthFailure;
            },
            else => return error.UnexpectedReply,
        }
    }
    for (conn_ids) |cid| handler.cleanupSession(0, cid);
}

test "AuthHandler: SCRAM slot table full means null, not aliasing" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "fullhouse", "pass123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var client = sasl.ScramClient.init(allocator, "fullhouse", "pass123");
    defer client.deinit();
    const client_first = try client.clientFirst();

    // Fill all MAX_SCRAM_SESSIONS slots with genuinely concurrent exchanges.
    var cid: u32 = 1;
    while (cid <= MAX_SCRAM_SESSIONS) : (cid += 1) {
        const reply = handleSync(&handler, .{ .auth_request = .{
            .conn_id = cid,
            .mechanism = .scram_sha_256,
            .client_ip = "10.0.0.10",
            .cb_type = 0,
            .cb_data = "",
            .username = "fullhouse",
            .payload = client_first,
        } }) orelse return error.NoResponse;
        try std.testing.expect(reply == .auth_challenge);
    }

    // One more: the table is uniquely exhausted — temporary-auth-failure.
    const overflow = handleSync(&handler, .{
        .auth_request = .{
            .conn_id = 65537, // generation 1, slot 1
            .mechanism = .scram_sha_256,
            .client_ip = "10.0.0.10",
            .cb_type = 0,
            .cb_data = "",
            .username = "fullhouse",
            .payload = client_first,
        },
    }) orelse return error.NoResponse;
    try std.testing.expect(overflow == .auth_failure);
    try std.testing.expectEqualStrings("temporary-auth-failure", overflow.auth_failure.reason);

    cid = 1;
    while (cid <= MAX_SCRAM_SESSIONS) : (cid += 1) handler.cleanupSession(0, cid);
}

test "AuthHandler: abandoned SCRAM slots are reclaimed lazily on the probe path" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    // Simulate a connection that died mid-exchange: its slot stays active.
    const dead_conn: u32 = 42;
    const dead_slot = handler.findOrCreateScramSlot(0, dead_conn).?;
    handler.scram_sessions[dead_slot] = .{
        .conn_id = dead_conn,
        .server = sasl.ScramServer.init(allocator),
        .active = true,
        .touched_at = std.time.timestamp() - 2 * SCRAM_SLOT_STALE_SECONDS,
    };

    // A fresh login aliasing the same home slot (same low 16 bits = same
    // session slot, newer generation) must reclaim it, not fail.
    const fresh_conn: u32 = 42 + (1 << 16);
    const got = handler.findOrCreateScramSlot(0, fresh_conn).?;
    try std.testing.expectEqual(dead_slot, got);
    try std.testing.expect(!handler.scram_sessions[got].active); // reclaimed, caller activates

    // A still-fresh slot on the probe path is NOT reclaimed.
    handler.scram_sessions[got] = .{
        .conn_id = fresh_conn,
        .server = sasl.ScramServer.init(allocator),
        .active = true,
        .touched_at = std.time.timestamp(),
    };
    const blocked_conn: u32 = 43 + (1 << 16); // aliases neighbor slot 43
    const alt = handler.findOrCreateScramSlot(0, blocked_conn).?;
    try std.testing.expect(alt != dead_slot);
    handler.scram_sessions[dead_slot].deinit();
    handler.scram_sessions[alt].deinit();
}

test "AuthHandler: PLAIN auth success" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    // Build PLAIN payload: \0alice\0secret123
    var plain_payload: [20]u8 = undefined;
    plain_payload[0] = 0; // authzid empty
    const user = "alice";
    @memcpy(plain_payload[1 .. 1 + user.len], user);
    plain_payload[1 + user.len] = 0;
    const pass = "secret123";
    @memcpy(plain_payload[2 + user.len .. 2 + user.len + pass.len], pass);

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 1,
        .mechanism = .plain,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "alice",
        .payload = plain_payload[0 .. 2 + user.len + pass.len],
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("alice", result.auth_success.username);
}

test "AuthHandler: PLAIN auth wrong password" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "bob", "correct");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    // Build PLAIN payload with wrong password
    var plain_payload: [15]u8 = undefined;
    plain_payload[0] = 0;
    @memcpy(plain_payload[1..4], "bob");
    plain_payload[4] = 0;
    @memcpy(plain_payload[5..10], "wrong");

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 2,
        .mechanism = .plain,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "bob",
        .payload = plain_payload[0..10],
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("not-authorized", result.auth_failure.reason);
}

test "AuthHandler: locked account rejected at PLAIN regardless of credentials (T352)" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "lockeduser", "secret123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var dummy: u8 = 0;
    handler.setLockChecker(.{ .ctx = @ptrCast(&dummy), .checkFn = struct {
        fn f(_: *anyopaque, username: []const u8) LockCheckResult {
            return if (std.mem.eql(u8, username, "lockeduser")) .locked else .unlocked;
        }
    }.f });

    var payload: [25]u8 = undefined;
    payload[0] = 0;
    @memcpy(payload[1..11], "lockeduser");
    payload[11] = 0;
    @memcpy(payload[12..21], "secret123");

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 1,
        .mechanism = .plain,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = payload[0..21],
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("account-disabled", result.auth_failure.reason);
}

test "AuthHandler: locked account rejected at SCRAM before the challenge is issued (T352)" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "lockedscram", "secret123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var dummy: u8 = 0;
    handler.setLockChecker(.{ .ctx = @ptrCast(&dummy), .checkFn = struct {
        fn f(_: *anyopaque, username: []const u8) LockCheckResult {
            return if (std.mem.eql(u8, username, "lockedscram")) .locked else .unlocked;
        }
    }.f });

    var client = sasl.ScramClient.init(allocator, "lockedscram", "secret123");
    defer client.deinit();

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 7,
        .mechanism = .scram_sha_256,
        .client_ip = "10.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = try client.clientFirst(),
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("account-disabled", result.auth_failure.reason);
    // No challenge state may linger for the rejected conn_id.
    try std.testing.expect(handler.findScramSlot(0, 7) == null);
}

test "AuthHandler: lock store error fails closed (T352)" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var dummy: u8 = 0;
    handler.setLockChecker(.{ .ctx = @ptrCast(&dummy), .checkFn = struct {
        fn f(_: *anyopaque, _: []const u8) LockCheckResult {
            return .store_error;
        }
    }.f });

    var payload: [16]u8 = undefined;
    payload[0] = 0;
    @memcpy(payload[1..6], "alice");
    payload[6] = 0;
    @memcpy(payload[7..16], "secret123");

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 2,
        .mechanism = .plain,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = payload[0..16],
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("temporary-auth-failure", result.auth_failure.reason);
}

test "AuthHandler: locks catch case and domain variants of the typed name" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");

    // A real LockStore on its own backend: xmppctl locks the canonical name
    // and every variant of it must hit the same row.
    var lock_db = try MemoryBackend.open("", .{});
    defer lock_db.close();
    var locks = lock_store_mod.LockStore(MemoryBackend).init(&lock_db);
    try locks.lock("alice", .permanent);

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();
    handler.setLockChecker(makeLockChecker(MemoryBackend, &locks, allocator));

    // Case variant of the locked name, correct password.
    {
        var payload: [16]u8 = undefined;
        payload[0] = 0;
        @memcpy(payload[1..6], "Alice");
        payload[6] = 0;
        @memcpy(payload[7..16], "secret123");
        const result = handleSync(&handler, .{ .auth_request = .{
            .conn_id = 21,
            .mechanism = .plain,
            .client_ip = "127.0.0.1",
            .cb_type = 0,
            .cb_data = "",
            .username = "",
            .payload = payload[0..16],
        } }) orelse return error.NoResponse;
        try std.testing.expectEqualStrings("account-disabled", result.auth_failure.reason);
    }
    // Domain form of the locked name.
    {
        const user = "ALICE@us.example";
        const pass = "secret123";
        var payload: [64]u8 = undefined;
        payload[0] = 0;
        @memcpy(payload[1 .. 1 + user.len], user);
        payload[1 + user.len] = 0;
        @memcpy(payload[2 + user.len .. 2 + user.len + pass.len], pass);
        const result = handleSync(&handler, .{ .auth_request = .{
            .conn_id = 22,
            .mechanism = .plain,
            .client_ip = "127.0.0.1",
            .cb_type = 0,
            .cb_data = "",
            .username = "",
            .payload = payload[0 .. 2 + user.len + pass.len],
        } }) orelse return error.NoResponse;
        try std.testing.expectEqualStrings("account-disabled", result.auth_failure.reason);
    }
}

test "AuthHandler: IdP PLAIN admits the localpart of the returned identity" {
    const allocator = std.testing.allocator;

    var store = TestIdpStore{ .password_user = "alice@idp.example" };
    var handler = TestIdpHandler.init(allocator, &store);
    defer handler.deinit();

    const user = "alice";
    const pass = "anypassword";
    var payload: [64]u8 = undefined;
    payload[0] = 0;
    @memcpy(payload[1 .. 1 + user.len], user);
    payload[1 + user.len] = 0;
    @memcpy(payload[2 + user.len .. 2 + user.len + pass.len], pass);

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 41,
        .mechanism = .plain,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = payload[0 .. 2 + user.len + pass.len],
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("alice", result.auth_success.username);
}

test "AuthHandler: a lock on the IdP identity rejects PLAIN" {
    const allocator = std.testing.allocator;

    var lock_db = try MemoryBackend.open("", .{});
    defer lock_db.close();
    var locks = lock_store_mod.LockStore(MemoryBackend).init(&lock_db);
    try locks.lock("alice", .permanent);

    // The IdP hands the identity back with a domain and mixed case: the
    // admission check runs on its localpart, not on the requested name.
    var store = TestIdpStore{ .password_user = "Alice@idp.example" };
    var handler = TestIdpHandler.init(allocator, &store);
    defer handler.deinit();
    handler.setLockChecker(makeLockChecker(MemoryBackend, &locks, allocator));

    const user = "alicework";
    const pass = "anypassword";
    var payload: [64]u8 = undefined;
    payload[0] = 0;
    @memcpy(payload[1 .. 1 + user.len], user);
    payload[1 + user.len] = 0;
    @memcpy(payload[2 + user.len .. 2 + user.len + pass.len], pass);

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 42,
        .mechanism = .plain,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = payload[0 .. 2 + user.len + pass.len],
    } }) orelse return error.NoResponse;
    if (result != .auth_failure) return error.ExpectedAuthFailure;

    // alicework is an alias for the locked alice: reply exactly as for a
    // wrong password, not with a lock reason that reveals the password.
    try std.testing.expectEqualStrings("not-authorized", result.auth_failure.reason);
}

test "AuthHandler: OAUTHBEARER admits the identity the IdP returns" {
    const allocator = std.testing.allocator;

    var store = TestIdpStore{ .token_user = "bob@idp.example" };
    var handler = TestIdpHandler.init(allocator, &store);
    defer handler.deinit();

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 43,
        .mechanism = .oauthbearer,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = "n,,\x01auth=Bearer tok123\x01\x01",
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("bob@idp.example", result.auth_success.username);
}

test "AuthHandler: a lock on the IdP identity rejects OAUTHBEARER" {
    const allocator = std.testing.allocator;

    var lock_db = try MemoryBackend.open("", .{});
    defer lock_db.close();
    var locks = lock_store_mod.LockStore(MemoryBackend).init(&lock_db);
    try locks.lock("bob", .permanent);

    var store = TestIdpStore{ .token_user = "Bob@idp.example" };
    var handler = TestIdpHandler.init(allocator, &store);
    defer handler.deinit();
    handler.setLockChecker(makeLockChecker(MemoryBackend, &locks, allocator));

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 44,
        .mechanism = .oauthbearer,
        .client_ip = "127.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = "n,,\x01auth=Bearer tok456\x01\x01",
    } }) orelse return error.NoResponse;
    if (result != .auth_failure) return error.ExpectedAuthFailure;

    try std.testing.expectEqualStrings("account-disabled", result.auth_failure.reason);
}

test "AuthHandler: a lock landing between challenge and client-final rejects" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    const Gate = struct { locked: bool = false };
    var gate = Gate{};
    handler.setLockChecker(.{ .ctx = @ptrCast(&gate), .checkFn = struct {
        fn f(ctx: *anyopaque, _: []const u8) LockCheckResult {
            const g: *const Gate = @ptrCast(@alignCast(ctx));
            return if (g.locked) .locked else .unlocked;
        }
    }.f });

    var client = sasl.ScramClient.init(allocator, "alice", "secret123");
    defer client.deinit();

    const challenge_msg = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 23,
        .mechanism = .scram_sha_256,
        .client_ip = "10.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = try client.clientFirst(),
    } }) orelse return error.NoResponse;
    const challenge = challenge_msg.auth_challenge.challenge;
    try std.testing.expect(challenge.len > 0);

    // The account is locked while the exchange is in flight.
    gate.locked = true;

    const result = handleSync(&handler, .{ .sasl_response = .{
        .conn_id = 23,
        .payload = try client.handleServerFirst(challenge),
    } }) orelse return error.NoResponse;
    try std.testing.expectEqualStrings("account-disabled", result.auth_failure.reason);
    // The rejected exchange leaves no session behind.
    try std.testing.expect(handler.findScramSlot(0, 23) == null);
}

test "AuthHandler: re-auth on a live conn_id deinits the previous exchange (T279)" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var client_a = sasl.ScramClient.init(allocator, "alice", "secret123");
    defer client_a.deinit();
    var client_b = sasl.ScramClient.init(allocator, "alice", "secret123");
    defer client_b.deinit();

    for ([_]*sasl.ScramClient{ &client_a, &client_b }) |client| {
        const reply = handleSync(&handler, .{ .auth_request = .{
            .conn_id = 42,
            .mechanism = .scram_sha_256,
            .client_ip = "127.0.0.1",
            .cb_type = 0,
            .cb_data = "",
            .username = "",
            .payload = try client.clientFirst(),
        } }) orelse return error.NoResponse;
        try std.testing.expect(reply == .auth_challenge);
    }
}

test "AuthHandler: closing an IPC lane sweeps its in-flight SCRAM sessions (T279)" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var other_lane = sasl.ScramClient.init(allocator, "alice", "secret123");
    defer other_lane.deinit();
    var doomed_lane = sasl.ScramClient.init(allocator, "alice", "secret123");
    defer doomed_lane.deinit();

    // conn 1 rides lane 3, conn 2 rides lane 4 (the slot arg of
    // handleMessage is the IPC lane).
    const conn1 = 42;
    const conn2 = 43;
    {
        const r1 = handler.handleMessage(.{ .auth_request = .{
            .conn_id = conn1,
            .mechanism = .scram_sha_256,
            .client_ip = "10.0.0.1",
            .cb_type = 0,
            .cb_data = "",
            .username = "",
            .payload = try doomed_lane.clientFirst(),
        } }, 3, 1);
        try std.testing.expect(r1 == .reply);
        _ = handler.handleMessage(.{ .auth_request = .{
            .conn_id = conn2,
            .mechanism = .scram_sha_256,
            .client_ip = "10.0.0.1",
            .cb_type = 0,
            .cb_data = "",
            .username = "",
            .payload = try other_lane.clientFirst(),
        } }, 4, 1);
    }

    try std.testing.expect(handler.findScramSlot(3, conn1) != null);
    try std.testing.expect(handler.findScramSlot(4, conn2) != null);

    handler.closeLaneSessions(3);
    try std.testing.expect(handler.findScramSlot(3, conn1) == null);
    try std.testing.expect(handler.findScramSlot(4, conn2) != null);
}

test "AuthHandler: identical conn_id on two lanes holds two exchanges; abort(kill) on one leaves the other (T279)" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var lane_a = sasl.ScramClient.init(allocator, "alice", "secret123");
    defer lane_a.deinit();
    var lane_b = sasl.ScramClient.init(allocator, "alice", "secret123");
    defer lane_b.deinit();

    // Each worker lane numbers its connections from 1; conn_id 7 exists
    // once per lane legitimately. Both exchanges must be alive at once.
    _ = handler.handleMessage(.{ .auth_request = .{
        .conn_id = 7,
        .mechanism = .scram_sha_256,
        .client_ip = "10.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = try lane_a.clientFirst(),
    } }, 3, 1);
    _ = handler.handleMessage(.{ .auth_request = .{
        .conn_id = 7,
        .mechanism = .scram_sha_256,
        .client_ip = "10.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = try lane_b.clientFirst(),
    } }, 4, 1);

    try std.testing.expect(handler.findScramSlot(3, 7) != null);
    try std.testing.expect(handler.findScramSlot(4, 7) != null);

    // Killing lane 3's client mid-exchange must not disturb lane 4's
    // exchange with the same conn_id.
    _ = handler.handleMessage(.{ .auth_abort = .{ .conn_id = 7 } }, 3, 1);
    try std.testing.expect(handler.findScramSlot(3, 7) == null);
    try std.testing.expect(handler.findScramSlot(4, 7) != null);
}

test "AuthHandler: SCRAM-SHA-256 full exchange" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "testuser", "testpassword");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    // Client side
    var client = sasl.ScramClient.init(allocator, "testuser", "testpassword");
    defer client.deinit();
    const client_first = try client.clientFirst();

    // Step 1: AuthRequest with client-first-message
    const challenge_msg = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 5,
        .mechanism = .scram_sha_256,
        .client_ip = "10.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "testuser",
        .payload = client_first,
    } }) orelse return error.NoResponse;

    // Should get a challenge
    const challenge = challenge_msg.auth_challenge.challenge;
    try std.testing.expect(challenge.len > 0);

    // Step 2: Client processes challenge, generates client-final
    const client_final = try client.handleServerFirst(challenge);

    // Step 3: SaslResponse with client-final-message
    const success_msg = handleSync(&handler, .{ .sasl_response = .{
        .conn_id = 5,
        .payload = client_final,
    } }) orelse return error.NoResponse;

    // Should succeed
    try std.testing.expectEqualStrings("testuser", success_msg.auth_success.username);
    try std.testing.expect(success_msg.auth_success.server_final.len > 0);

    // Verify server final
    try client.handleServerFinal(success_msg.auth_success.server_final);
    try std.testing.expect(client.isComplete());

    handler.cleanupSession(0, 5);
}

test "AuthHandler: SCRAM unknown user" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var client = sasl.ScramClient.init(allocator, "ghost", "whatever");
    defer client.deinit();
    const client_first = try client.clientFirst();

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 10,
        .mechanism = .scram_sha_256,
        .client_ip = "10.0.0.2",
        .cb_type = 0,
        .cb_data = "",
        .username = "ghost",
        .payload = client_first,
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("not-authorized", result.auth_failure.reason);
}

test "AuthHandler: credential cache hit on second SCRAM auth" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "cached", "pass123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    // First auth — populates cache
    {
        var client = sasl.ScramClient.init(allocator, "cached", "pass123");
        defer client.deinit();
        const client_first = try client.clientFirst();

        const challenge_msg = handleSync(&handler, .{ .auth_request = .{
            .conn_id = 20,
            .mechanism = .scram_sha_256,
            .client_ip = "10.0.0.5",
            .cb_type = 0,
            .cb_data = "",
            .username = "cached",
            .payload = client_first,
        } }) orelse return error.NoResponse;

        const client_final = try client.handleServerFirst(challenge_msg.auth_challenge.challenge);
        const success_msg = handleSync(&handler, .{ .sasl_response = .{
            .conn_id = 20,
            .payload = client_final,
        } }) orelse return error.NoResponse;

        try std.testing.expectEqualStrings("cached", success_msg.auth_success.username);
        handler.cleanupSession(0, 20);
    }

    // Verify cache is populated
    try std.testing.expect(handler.cacheLookup(hashUsername("cached"), std.time.timestamp()) != null);

    // Second auth — uses cache (store lookup skipped)
    {
        var client = sasl.ScramClient.init(allocator, "cached", "pass123");
        defer client.deinit();
        const client_first = try client.clientFirst();

        const challenge_msg = handleSync(&handler, .{ .auth_request = .{
            .conn_id = 21,
            .mechanism = .scram_sha_256,
            .client_ip = "10.0.0.5",
            .cb_type = 0,
            .cb_data = "",
            .username = "cached",
            .payload = client_first,
        } }) orelse return error.NoResponse;

        const client_final = try client.handleServerFirst(challenge_msg.auth_challenge.challenge);
        const success_msg = handleSync(&handler, .{ .sasl_response = .{
            .conn_id = 21,
            .payload = client_final,
        } }) orelse return error.NoResponse;

        try std.testing.expectEqualStrings("cached", success_msg.auth_success.username);
        handler.cleanupSession(0, 21);
    }
}

test "AuthHandler: credential cache invalidated on password change" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "rotate", "oldpass");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    // Auth to populate cache
    {
        var client = sasl.ScramClient.init(allocator, "rotate", "oldpass");
        defer client.deinit();
        const client_first = try client.clientFirst();

        const challenge_msg = handleSync(&handler, .{ .auth_request = .{
            .conn_id = 30,
            .mechanism = .scram_sha_256,
            .client_ip = "10.0.0.6",
            .cb_type = 0,
            .cb_data = "",
            .username = "rotate",
            .payload = client_first,
        } }) orelse return error.NoResponse;

        const client_final = try client.handleServerFirst(challenge_msg.auth_challenge.challenge);
        _ = handleSync(&handler, .{ .sasl_response = .{
            .conn_id = 30,
            .payload = client_final,
        } }) orelse return error.NoResponse;

        handler.cleanupSession(0, 30);
    }

    // Cache should be populated
    try std.testing.expect(handler.cacheLookup(hashUsername("rotate"), std.time.timestamp()) != null);

    // Change password — invalidates cache
    _ = handleSync(&handler, .{ .password_change_request = .{
        .conn_id = 31,
        .username = "rotate",
        .new_password = "newpass",
    } });

    // Cache should be invalidated
    try std.testing.expect(handler.cacheLookup(hashUsername("rotate"), std.time.timestamp()) == null);
}

test "AuthHandler: unlimited attempts when rate limiter is not attached" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "hammer", "pass");

    // No setRateLimiter call — the [auth] rate_limit = false configuration.
    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var payload: [12]u8 = undefined;
    payload[0] = 0;
    const user = "hammer";
    @memcpy(payload[1 .. 1 + user.len], user);
    payload[1 + user.len] = 0;
    const pass = "pass";
    @memcpy(payload[2 + user.len .. 2 + user.len + pass.len], pass);
    const auth_b64 = payload[0 .. 2 + user.len + pass.len];

    // Far beyond the default per-IP limit (20); every attempt must succeed.
    var i: u32 = 0;
    while (i < 30) : (i += 1) {
        const result = handleSync(&handler, .{ .auth_request = .{
            .conn_id = 100 + i,
            .mechanism = .plain,
            .client_ip = "127.0.0.1",
            .cb_type = 0,
            .cb_data = "",
            .username = "hammer",
            .payload = auth_b64,
        } }) orelse return error.NoResponse;
        try std.testing.expectEqualStrings("hammer", result.auth_success.username);
    }
}

/// Build a PLAIN payload "\0user\0pass" for tests.
fn plainPayload(buf: []u8, user: []const u8, pass: []const u8) []const u8 {
    buf[0] = 0;
    @memcpy(buf[1 .. 1 + user.len], user);
    buf[1 + user.len] = 0;
    @memcpy(buf[2 + user.len .. 2 + user.len + pass.len], pass);
    return buf[0 .. 2 + user.len + pass.len];
}

fn plainRequest(conn_id: u32, ip: []const u8, payload: []const u8) protocol.Message {
    return .{ .auth_request = .{
        .conn_id = conn_id,
        .mechanism = .plain,
        .client_ip = ip,
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = payload,
    } };
}

test "AuthHandler: PLAIN auth defers to crypto pool and completes (T121)" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "dave", "pw123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var pool = TestCryptoPool{ .allocator = std.testing.allocator };
    try pool.start(2);
    defer pool.stop();
    handler.enableCryptoPool(&pool);

    var buf: [16]u8 = undefined;
    const res = handleSync(&handler, plainRequest(42, "10.0.0.9", plainPayload(&buf, "dave", "pw123")));
    // With a pool attached the sync helper reports no immediate reply...
    try std.testing.expect(res == null);
    // ...because the request went deferred.
    try std.testing.expectEqual(@as(usize, 1), handler.pending_plain.count());

    var completion: ?crypto_pool_mod.Completion = null;
    const deadline = std.time.milliTimestamp() + 10000;
    while (completion == null and std.time.milliTimestamp() < deadline) {
        completion = pool.popCompletion();
        if (completion == null) std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    try std.testing.expect(completion != null);

    var reply = handler.takeCryptoReply(completion.?).?;
    defer reply.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 0), reply.slot);
    try std.testing.expectEqual(@as(u32, 1), reply.slot_gen);
    try std.testing.expectEqualStrings("dave", reply.msg.auth_success.username);
    try std.testing.expectEqual(@as(u32, 42), reply.msg.auth_success.conn_id);
    try std.testing.expectEqual(@as(usize, 0), handler.pending_plain.count());
}

test "AuthHandler: PLAIN per-account rate limit engages on parsed username" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "carol", "pw");

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 2,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 100,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var buf: [16]u8 = undefined;
    const req = plainPayload(&buf, "carol", "pw");

    // First two attempts pass the rate check (auth itself succeeds)
    try std.testing.expectEqualStrings("carol", (handleSync(&handler, plainRequest(1, "10.9.0.1", req)) orelse return error.NoResponse).auth_success.username);
    try std.testing.expectEqualStrings("carol", (handleSync(&handler, plainRequest(2, "10.9.0.1", req)) orelse return error.NoResponse).auth_success.username);

    // Third exceeds max_per_account = 2
    const third = handleSync(&handler, plainRequest(3, "10.9.0.1", req)) orelse return error.NoResponse;
    try std.testing.expectEqualStrings("policy-violation", third.auth_failure.reason);
}

test "AuthHandler: PLAIN account lockout engages on parsed username" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "dave", "rightpw");

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 2,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var buf: [20]u8 = undefined;
    const wrong = plainPayload(&buf, "dave", "wrongpw");

    // Two consecutive failures hit the lockout threshold
    _ = handleSync(&handler, plainRequest(10, "10.9.0.2", wrong));
    _ = handleSync(&handler, plainRequest(11, "10.9.0.2", wrong));

    const locked = handleSync(&handler, plainRequest(12, "10.9.0.3", wrong)) orelse return error.NoResponse;
    try std.testing.expectEqualStrings("account-disabled", locked.auth_failure.reason);
}

test "AuthHandler: SCRAM counts the attempt at client-first" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 3,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        var client = sasl.ScramClient.init(allocator, "alice", "secret123");
        defer client.deinit();
        const reply = handleSync(&handler, .{ .auth_request = .{
            .conn_id = 100 + i,
            .mechanism = .scram_sha_256,
            .client_ip = "10.0.0.1",
            .cb_type = 0,
            .cb_data = "",
            .username = "",
            .payload = try client.clientFirst(),
        } }) orelse return error.NoResponse;
        if (i < 3) {
            try std.testing.expect(reply == .auth_challenge);
        } else {
            if (reply != .auth_failure) return error.ExpectedAuthFailure;
            try std.testing.expectEqualStrings("policy-violation", reply.auth_failure.reason);
        }
    }
}

test "AuthHandler: SCRAM final lock reply is uniform for right and wrong passwords" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 1,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var right = sasl.ScramClient.init(allocator, "alice", "secret123");
    defer right.deinit();
    var wrong = sasl.ScramClient.init(allocator, "alice", "wrongpw");
    defer wrong.deinit();

    const right_challenge = (handleSync(&handler, .{ .auth_request = .{
        .conn_id = 110,
        .mechanism = .scram_sha_256,
        .client_ip = "10.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = try right.clientFirst(),
    } }) orelse return error.NoResponse).auth_challenge.challenge;
    const wrong_challenge = (handleSync(&handler, .{ .auth_request = .{
        .conn_id = 111,
        .mechanism = .scram_sha_256,
        .client_ip = "10.0.0.1",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = try wrong.clientFirst(),
    } }) orelse return error.NoResponse).auth_challenge.challenge;

    // One failure locks the account while both exchanges are in flight.
    limiter.recordOutcome("alice", "10.0.0.1", false);

    const right_reply = handleSync(&handler, .{ .sasl_response = .{
        .conn_id = 110,
        .payload = try right.handleServerFirst(right_challenge),
    } }) orelse return error.NoResponse;
    if (right_reply != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("account-disabled", right_reply.auth_failure.reason);

    const wrong_reply = handleSync(&handler, .{ .sasl_response = .{
        .conn_id = 111,
        .payload = try wrong.handleServerFirst(wrong_challenge),
    } }) orelse return error.NoResponse;
    if (wrong_reply != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("account-disabled", wrong_reply.auth_failure.reason);
}

test "AuthHandler: PLAIN crypto-pool admission counts before the job" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "dave", "pw123");

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 3,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var pool = TestCryptoPool{ .allocator = std.testing.allocator };
    try pool.start(2);
    defer pool.stop();
    handler.enableCryptoPool(&pool);

    var buf: [24]u8 = undefined;
    const payload = plainPayload(&buf, "dave", "wrongpw");

    // Three attempts are counted and deferred; the fourth is denied before
    // a job is queued.
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        try std.testing.expect(handleSync(&handler, plainRequest(120 + i, "10.0.0.9", payload)) == null);
    }
    try std.testing.expectEqual(@as(usize, 3), handler.pending_plain.count());

    const fourth = handleSync(&handler, plainRequest(123, "10.0.0.9", payload)) orelse return error.NoResponse;
    if (fourth != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("policy-violation", fourth.auth_failure.reason);
}

test "AuthHandler: denied registrations do not count as auth failures" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 2,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    // Registration is disabled (the default): two denied registrations from
    // the same IP must not count as authentication failures.
    var i: u32 = 0;
    while (i < 2) : (i += 1) {
        const reply = handleSync(&handler, .{ .register_request = .{
            .conn_id = 150 + i,
            .username = "newuser",
            .password = "pw",
            .invite_code = "",
            .client_ip = "10.0.0.9",
        } }) orelse return error.NoResponse;
        if (reply != .register_result) return error.UnexpectedReply;
        try std.testing.expect(!reply.register_result.success);
        try std.testing.expectEqualStrings("not-allowed", reply.register_result.reason);
    }

    var buf: [24]u8 = undefined;
    const success = handleSync(&handler, plainRequest(152, "10.0.0.9", plainPayload(&buf, "alice", "secret123"))) orelse return error.NoResponse;
    if (success != .auth_success) return error.ExpectedAuthSuccess;
    try std.testing.expectEqualStrings("alice", success.auth_success.username);
}

test "AuthHandler: OAUTHBEARER denies a locked IP before validating the token" {
    const allocator = std.testing.allocator;

    var store = TestIdpStore{ .token_user = "bob@idp.example" };

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 1,
    });
    defer limiter.deinit();
    limiter.recordOutcome("anyone", "10.0.0.7", false);

    var handler = TestIdpHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 130,
        .mechanism = .oauthbearer,
        .client_ip = "10.0.0.7",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = "n,,\x01auth=Bearer tok\x01\x01",
    } }) orelse return error.NoResponse;
    if (result != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("policy-violation", result.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 0), store.token_calls);
}

test "AuthHandler: SCRAM unknown user records a failure" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 1,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var i: u32 = 0;
    while (i < 2) : (i += 1) {
        var client = sasl.ScramClient.init(allocator, "ghost", "whatever");
        defer client.deinit();
        const reply = handleSync(&handler, .{ .auth_request = .{
            .conn_id = 140 + i,
            .mechanism = .scram_sha_256,
            .client_ip = "10.0.0.8",
            .cb_type = 0,
            .cb_data = "",
            .username = "",
            .payload = try client.clientFirst(),
        } }) orelse return error.NoResponse;
        if (reply != .auth_failure) return error.ExpectedAuthFailure;
        if (i == 0) {
            try std.testing.expectEqualStrings("not-authorized", reply.auth_failure.reason);
        } else {
            try std.testing.expectEqualStrings("account-disabled", reply.auth_failure.reason);
        }
    }
}

test "AuthHandler: SCRAM abandoned client-firsts count against the IP" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 2,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    const names = [_][]const u8{ "ghost1", "ghost2", "ghost3" };
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        var client = sasl.ScramClient.init(allocator, names[i], "whatever");
        defer client.deinit();
        const reply = handleSync(&handler, .{ .auth_request = .{
            .conn_id = 160 + i,
            .mechanism = .scram_sha_256,
            .client_ip = "10.0.0.10",
            .cb_type = 0,
            .cb_data = "",
            .username = "",
            .payload = try client.clientFirst(),
        } }) orelse return error.NoResponse;
        if (reply != .auth_failure) return error.ExpectedAuthFailure;
        if (i < 2) {
            try std.testing.expectEqualStrings("not-authorized", reply.auth_failure.reason);
        } else {
            // The third abandoned exchange is denied by the IP window before
            // the unknown-user lookup.
            try std.testing.expectEqualStrings("policy-violation", reply.auth_failure.reason);
        }
    }
}

test "AuthHandler: PLAIN counts the IP before the lookup" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 1,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var buf: [24]u8 = undefined;
    const payload = plainPayload(&buf, "alice", "secret123");

    const first = handleSync(&handler, plainRequest(170, "10.0.0.11", payload)) orelse return error.NoResponse;
    if (first != .auth_success) return error.ExpectedAuthSuccess;

    const second = handleSync(&handler, plainRequest(171, "10.0.0.11", payload)) orelse return error.NoResponse;
    if (second != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("policy-violation", second.auth_failure.reason);
}

test "AuthHandler: registration counts the IP before adding a user" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 1,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    handler.reg_config = .{ .enabled = true, .require_invite = false };
    defer handler.deinit();

    const first = handleSync(&handler, .{ .register_request = .{
        .conn_id = 180,
        .username = "new1",
        .password = "pw",
        .invite_code = "",
        .client_ip = "10.0.0.12",
    } }) orelse return error.NoResponse;
    if (first != .register_result or !first.register_result.success) return error.ExpectedRegisterSuccess;

    const second = handleSync(&handler, .{ .register_request = .{
        .conn_id = 181,
        .username = "new2",
        .password = "pw",
        .invite_code = "",
        .client_ip = "10.0.0.12",
    } }) orelse return error.NoResponse;
    if (second != .register_result) return error.UnexpectedReply;
    try std.testing.expect(!second.register_result.success);
    try std.testing.expectEqualStrings("policy-violation", second.register_result.reason);
}

test "AuthHandler: SCRAM client-final ignores a filled IP window" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "secret123");

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 1,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 100,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var alice = sasl.ScramClient.init(allocator, "alice", "secret123");
    defer alice.deinit();
    var bob = sasl.ScramClient.init(allocator, "bob", "whatever");
    defer bob.deinit();

    const challenge = (handleSync(&handler, .{ .auth_request = .{
        .conn_id = 300,
        .mechanism = .scram_sha_256,
        .client_ip = "10.0.0.20",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = try alice.clientFirst(),
    } }) orelse return error.NoResponse).auth_challenge.challenge;

    // A second client-first fills the IP window; alice's exchange is still
    // in flight and must be allowed to finish.
    const blocked = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 301,
        .mechanism = .scram_sha_256,
        .client_ip = "10.0.0.20",
        .cb_type = 0,
        .cb_data = "",
        .username = "",
        .payload = try bob.clientFirst(),
    } }) orelse return error.NoResponse;
    if (blocked != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("policy-violation", blocked.auth_failure.reason);

    const success = handleSync(&handler, .{ .sasl_response = .{
        .conn_id = 300,
        .payload = try alice.handleServerFirst(challenge),
    } }) orelse return error.NoResponse;
    if (success != .auth_success) return error.ExpectedAuthSuccess;
    try std.testing.expectEqualStrings("alice", success.auth_success.username);
}

test "AuthHandler: PLAIN-IdP rejects a locked supplied name before the IdP" {
    const allocator = std.testing.allocator;

    var lock_db = try MemoryBackend.open("", .{});
    defer lock_db.close();
    var locks = lock_store_mod.LockStore(MemoryBackend).init(&lock_db);
    try locks.lock("alice", .permanent);

    var store = TestIdpStore{
        .password_user = "alice@idp.example",
        .password_secret = "right",
    };
    var handler = TestIdpHandler.init(allocator, &store);
    defer handler.deinit();
    handler.setLockChecker(makeLockChecker(MemoryBackend, &locks, allocator));

    var buf: [64]u8 = undefined;
    const right_reply = handleSync(&handler, plainRequest(200, "127.0.0.1", plainPayload(&buf, "alice", "right"))) orelse return error.NoResponse;
    const wrong_reply = handleSync(&handler, plainRequest(200, "127.0.0.1", plainPayload(&buf, "alice", "wrong"))) orelse return error.NoResponse;

    if (right_reply != .auth_failure or wrong_reply != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualDeep(right_reply, wrong_reply);
    try std.testing.expectEqualStrings("account-disabled", right_reply.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 0), store.password_calls);
}

test "AuthHandler: crypto-pool pending jobs count against the lockout threshold" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "dave", "pw123");

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 2,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var pool = TestCryptoPool{ .allocator = std.testing.allocator };
    try pool.start(2);
    defer pool.stop();
    handler.enableCryptoPool(&pool);

    var buf: [24]u8 = undefined;
    const payload = plainPayload(&buf, "dave", "wrongpw");

    var i: u32 = 0;
    while (i < 2) : (i += 1) {
        try std.testing.expect(handleSync(&handler, plainRequest(310 + i, "10.0.0.30", payload)) == null);
    }
    try std.testing.expectEqual(@as(usize, 2), handler.pending_plain.count());

    // Two jobs are in flight, equal to the lockout threshold: the next
    // attempt must not be queued.
    const third = handleSync(&handler, plainRequest(312, "10.0.0.30", payload)) orelse return error.NoResponse;
    if (third != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("policy-violation", third.auth_failure.reason);
    try std.testing.expectEqual(@as(usize, 2), handler.pending_plain.count());
}

test "AuthHandler: a PLAIN prep failure completes and replies" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "dave", "pw123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var pool = TestCryptoPool{ .allocator = std.testing.allocator };
    try pool.start(2);
    defer pool.stop();
    handler.enableCryptoPool(&pool);

    var buf: [32]u8 = undefined;
    const payload = plainPayload(&buf, "dave", "x\x07y");
    try std.testing.expect(handleSync(&handler, plainRequest(400, "10.0.0.40", payload)) == null);
    try std.testing.expectEqual(@as(usize, 1), handler.pending_plain.count());

    try waitForPoolWake(&pool);
    const completion = pool.popCompletion() orelse return error.NoCompletion;
    try std.testing.expect(!completion.ok);

    var reply = handler.takeCryptoReply(completion) orelse return error.NoReply;
    defer reply.deinit(allocator);
    if (reply.msg != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("not-authorized", reply.msg.auth_failure.reason);
    try std.testing.expectEqual(@as(usize, 0), handler.pending_plain.count());
}

test "AuthHandler: a locked IdP alias gets the wrong-password reply" {
    const allocator = std.testing.allocator;

    var lock_db = try MemoryBackend.open("", .{});
    defer lock_db.close();
    var locks = lock_store_mod.LockStore(MemoryBackend).init(&lock_db);
    try locks.lock("alice", .permanent);

    var store = TestIdpStore{
        .password_user = "alice@idp.example",
        .password_secret = "right",
    };
    var handler = TestIdpHandler.init(allocator, &store);
    defer handler.deinit();
    handler.setLockChecker(makeLockChecker(MemoryBackend, &locks, allocator));

    var buf: [64]u8 = undefined;
    const right_reply = handleSync(&handler, plainRequest(410, "127.0.0.1", plainPayload(&buf, "a.smith", "right"))) orelse return error.NoResponse;
    const wrong_reply = handleSync(&handler, plainRequest(410, "127.0.0.1", plainPayload(&buf, "a.smith", "wrong"))) orelse return error.NoResponse;

    if (right_reply != .auth_failure or wrong_reply != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualDeep(right_reply, wrong_reply);
    try std.testing.expectEqualStrings("not-authorized", right_reply.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 2), store.password_calls);
}

test "AuthHandler: a failed crypto-pool completion leaves no pending entry" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "dave", "pw123");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    var pool = TestCryptoPool{ .allocator = std.testing.allocator };
    try pool.start(2);
    defer pool.stop();
    handler.enableCryptoPool(&pool);

    var buf: [24]u8 = undefined;
    const payload = plainPayload(&buf, "dave", "wrongpw");
    try std.testing.expect(handleSync(&handler, plainRequest(420, "10.0.0.50", payload)) == null);
    try std.testing.expectEqual(@as(usize, 1), handler.pending_plain.count());

    try waitForPoolWake(&pool);
    const completion = pool.popCompletion() orelse return error.NoCompletion;
    try std.testing.expect(!completion.ok);

    var reply = handler.takeCryptoReply(completion) orelse return error.NoReply;
    defer reply.deinit(allocator);
    if (reply.msg != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualStrings("not-authorized", reply.msg.auth_failure.reason);
    try std.testing.expectEqual(@as(usize, 0), handler.pending_plain.count());
}

test "AuthHandler: PLAIN-IdP pre-check sees a temporary lock" {
    const allocator = std.testing.allocator;

    var store = TestIdpStore{
        .password_user = "alice@idp.example",
        .password_secret = "right",
    };

    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 120,
        .lockout_duration = 300,
        .lockout_threshold = 1,
        .ip_lockout_threshold = 100,
    });
    defer limiter.deinit();
    limiter.recordOutcome("alice", "10.0.0.1", false);

    var handler = TestIdpHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var buf: [64]u8 = undefined;
    const right_reply = handleSync(&handler, plainRequest(430, "10.0.0.2", plainPayload(&buf, "alice", "right"))) orelse return error.NoResponse;
    const wrong_reply = handleSync(&handler, plainRequest(430, "10.0.0.2", plainPayload(&buf, "alice", "wrong"))) orelse return error.NoResponse;

    if (right_reply != .auth_failure or wrong_reply != .auth_failure) return error.ExpectedAuthFailure;
    try std.testing.expectEqualDeep(right_reply, wrong_reply);
    try std.testing.expectEqualStrings("account-disabled", right_reply.auth_failure.reason);
    try std.testing.expectEqual(@as(u32, 0), store.password_calls);
}
