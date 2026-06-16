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
const lock_store_mod = @import("lock_store");

const log = std.log.scoped(.auth_handler);

/// Interface for permanent lock checking. The auth daemon sets this to
/// a closure over the LockStore. Decouples handler from Backend type.
pub const LockChecker = struct {
    ctx: *anyopaque,
    checkFn: *const fn (ctx: *anyopaque, username: []const u8) bool,

    pub fn isLocked(self: LockChecker, username: []const u8) bool {
        return self.checkFn(self.ctx, username);
    }
};

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

/// Maximum concurrent SCRAM exchanges (one per XMPP connection doing auth).
const MAX_SCRAM_SESSIONS = 256;

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

    fn deinit(self: *ScramSession) void {
        self.server.deinit();
        self.active = false;
    }
};

pub fn AuthHandler(comptime Store: type) type {
    return struct {
        store: *Store,
        allocator: std.mem.Allocator,
        /// Active SCRAM sessions indexed by slot.
        scram_sessions: [MAX_SCRAM_SESSIONS]ScramSession = undefined,
        /// Rate limiter (optional — null disables rate limiting).
        rate_limiter: ?*RateLimiter = null,
        /// Permanent lock checker (optional — null disables lock checking).
        lock_checker: ?LockChecker = null,
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
            self.rate_limiter = limiter;
        }

        /// Set the lock checker (call after init).
        pub fn setLockChecker(self: *Self, checker: LockChecker) void {
            self.lock_checker = checker;
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
        }

        /// Process an incoming IPC message and return a response message.
        pub fn handleMessage(self: *Self, msg: protocol.Message) ?protocol.Message {
            return switch (msg) {
                .auth_request => |req| self.handleAuthRequest(req),
                .sasl_response => |resp| self.handleSaslResponse(resp),
                .password_change_request => |req| self.handlePasswordChange(req),
                .account_delete_request => |req| self.handleAccountDelete(req),
                .register_request => |req| self.handleRegisterRequest(req),
                else => null,
            };
        }

        fn handleAuthRequest(self: *Self, req: protocol.AuthRequest) protocol.Message {
            // Permanent lock check (if enabled)
            if (self.lock_checker) |checker| {
                if (req.username.len > 0 and checker.isLocked(req.username)) {
                    log.info("auth rejected: account '{s}' is permanently locked", .{req.username});
                    return authFailure(req.conn_id, "account-disabled");
                }
            }

            // Rate limiting check (if enabled)
            if (self.rate_limiter) |rl| {
                if (rl.checkAllowed(req.username, req.client_ip)) |reason| {
                    return authFailure(req.conn_id, reason);
                }
                rl.recordAttempt(req.username, req.client_ip);
            }

            return switch (req.mechanism) {
                .plain => self.handlePlainAuth(req),
                .scram_sha_256 => if (comptime @hasDecl(Store, "lookup"))
                    self.handleScramInit(req)
                else
                    authFailure(req.conn_id, "mechanism-not-supported"),
                .oauthbearer => if (comptime @hasDecl(Store, "validateToken"))
                    self.handleOAuthBearerAuth(req)
                else
                    authFailure(req.conn_id, "mechanism-not-supported"),
            };
        }

        fn handlePlainAuth(self: *Self, req: protocol.AuthRequest) protocol.Message {
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

            const authcid_start = (nul1 orelse return authFailure(req.conn_id, "invalid-encoding")) + 1;
            const authcid_end = nul2 orelse return authFailure(req.conn_id, "invalid-encoding");
            const passwd_start = authcid_end + 1;

            if (authcid_start >= payload.len or passwd_start >= payload.len) {
                return authFailure(req.conn_id, "invalid-encoding");
            }

            const username = payload[authcid_start..authcid_end];
            const password = payload[passwd_start..];

            // If the store supports validatePassword (OIDC/IdP delegation), use that
            if (comptime @hasDecl(Store, "validatePassword")) {
                const result = self.store.validatePassword(self.allocator, username, password) catch {
                    return authFailure(req.conn_id, "temporary-auth-failure");
                };
                if (result) |validated_user| {
                    log.info("PLAIN auth success (IdP): '{s}'", .{validated_user});
                    if (self.rate_limiter) |rl| rl.recordSuccess(username);
                    return protocol.Message{ .auth_success = .{
                        .conn_id = req.conn_id,
                        .username = validated_user,
                        .server_final = "",
                    } };
                } else {
                    log.info("PLAIN auth failed (IdP): '{s}'", .{username});
                    if (self.rate_limiter) |rl| rl.recordFailure(username, req.client_ip);
                    return authFailure(req.conn_id, "not-authorized");
                }
            }

            // Traditional credential lookup + SCRAM derive
            if (comptime @hasDecl(Store, "lookup")) {
                const maybe_creds = self.store.lookup(self.allocator, username) catch {
                    return authFailure(req.conn_id, "temporary-auth-failure");
                };
                const creds = maybe_creds orelse {
                    log.info("PLAIN auth failed: user '{s}' not found", .{username});
                    if (self.rate_limiter) |rl| rl.recordFailure(username, req.client_ip);
                    return authFailure(req.conn_id, "not-authorized");
                };

                // Verify by deriving with the same salt and comparing
                const test_creds = sasl.StoredCredentials.derive(password, creds.salt, creds.iteration_count);
                if (!std.mem.eql(u8, &test_creds.stored_key, &creds.stored_key)) {
                    log.info("PLAIN auth failed: wrong password for '{s}'", .{username});
                    if (self.rate_limiter) |rl| rl.recordFailure(username, req.client_ip);
                    return authFailure(req.conn_id, "not-authorized");
                }

                log.info("PLAIN auth success: '{s}'", .{username});
                if (self.rate_limiter) |rl| rl.recordSuccess(username);
                return protocol.Message{ .auth_success = .{
                    .conn_id = req.conn_id,
                    .username = username,
                    .server_final = "",
                } };
            }

            return authFailure(req.conn_id, "mechanism-not-supported");
        }

        /// Handle OAUTHBEARER mechanism — delegates to Store.validateToken.
        /// The SASL initial response is RFC 7628 format:
        ///   gs2-header kvsep "auth=Bearer " token kvsep kvsep
        ///   n,,\x01auth=Bearer TOKEN\x01\x01
        fn handleOAuthBearerAuth(self: *Self, req: protocol.AuthRequest) protocol.Message {
            if (comptime !@hasDecl(Store, "validateToken")) {
                return authFailure(req.conn_id, "mechanism-not-supported");
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
                log.info("OAUTHBEARER auth success: '{s}'", .{validated_user});
                if (self.rate_limiter) |rl| rl.recordSuccess(validated_user);
                return protocol.Message{ .auth_success = .{
                    .conn_id = req.conn_id,
                    .username = validated_user,
                    .server_final = "",
                } };
            } else {
                log.info("OAUTHBEARER auth failed", .{});
                if (self.rate_limiter) |rl| rl.recordFailure(req.username, req.client_ip);
                return authFailure(req.conn_id, "not-authorized");
            }
        }

        fn handleScramInit(self: *Self, req: protocol.AuthRequest) protocol.Message {
            if (comptime !@hasDecl(Store, "lookup")) {
                return authFailure(req.conn_id, "mechanism-not-supported");
            } else {
                // Find or create a SCRAM session for this conn_id
                const slot = self.findOrCreateScramSlot(req.conn_id) orelse {
                    return authFailure(req.conn_id, "temporary-auth-failure");
                };

                var session = &self.scram_sessions[slot];
                session.server = sasl.ScramServer.init(self.allocator);
                session.conn_id = req.conn_id;
                session.active = true;

                // Set channel binding data from TLS session
                session.server.setChannelBinding(req.cb_type, req.cb_data);

                // Process client-first-message
                const username = session.server.handleClientFirst(req.payload) catch {
                    session.deinit();
                    return authFailure(req.conn_id, "invalid-encoding");
                };

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

        fn handleSaslResponse(self: *Self, resp: protocol.SaslResponse) protocol.Message {
            // Find the SCRAM session for this conn_id
            const slot = self.findScramSlot(resp.conn_id) orelse {
                return authFailure(resp.conn_id, "not-authorized");
            };

            var session = &self.scram_sessions[slot];

            // Process client-final-message
            const server_final = session.server.handleClientFinal(resp.payload) catch {
                log.info("SCRAM auth failed: proof verification for conn={d}", .{resp.conn_id});
                const username = session.server.username;
                if (self.rate_limiter) |rl| rl.recordFailure(username, "");
                session.deinit();
                return authFailure(resp.conn_id, "not-authorized");
            };

            const username = session.server.username;
            log.info("SCRAM auth success: '{s}' conn={d}", .{ username, resp.conn_id });
            if (self.rate_limiter) |rl| rl.recordSuccess(username);

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

            // Privileged admin requests (xmppctl) bypass registration policy
            const is_admin = std.mem.eql(u8, req.client_ip, "ctl");

            // Check if registration is enabled (skip for admin)
            if (!is_admin and !self.reg_config.enabled) {
                return protocol.Message{ .register_result = regResult{
                    .conn_id = req.conn_id,
                    .success = false,
                    .reason = "not-allowed",
                } };
            }

            // Rate limit registration attempts (skip for admin)
            if (!is_admin) {
                if (self.rate_limiter) |rl| {
                    if (rl.checkAllowed("", req.client_ip)) |reason| {
                        return protocol.Message{ .register_result = regResult{
                            .conn_id = req.conn_id,
                            .success = false,
                            .reason = reason,
                        } };
                    }
                    rl.recordAttempt("", req.client_ip);
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
        pub fn cleanupSession(self: *Self, conn_id: u32) void {
            if (self.findScramSlot(conn_id)) |slot| {
                self.scram_sessions[slot].deinit();
            }
        }

        fn findOrCreateScramSlot(self: *Self, conn_id: u32) ?usize {
            const slot = (conn_id & 0xFFFF) % MAX_SCRAM_SESSIONS;
            const s = &self.scram_sessions[slot];
            if (s.active and s.conn_id != conn_id) return null; // Collision
            return slot;
        }

        fn findScramSlot(self: *Self, conn_id: u32) ?usize {
            const slot = (conn_id & 0xFFFF) % MAX_SCRAM_SESSIONS;
            const s = &self.scram_sessions[slot];
            if (s.active and s.conn_id == conn_id) return slot;
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

    const result = handler.handleMessage(.{ .auth_request = .{
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

    const result = handler.handleMessage(.{ .auth_request = .{
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
    const challenge_msg = handler.handleMessage(.{ .auth_request = .{
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
    const success_msg = handler.handleMessage(.{ .sasl_response = .{
        .conn_id = 5,
        .payload = client_final,
    } }) orelse return error.NoResponse;

    // Should succeed
    try std.testing.expectEqualStrings("testuser", success_msg.auth_success.username);
    try std.testing.expect(success_msg.auth_success.server_final.len > 0);

    // Verify server final
    try client.handleServerFinal(success_msg.auth_success.server_final);
    try std.testing.expect(client.isComplete());

    handler.cleanupSession(5);
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

    const result = handler.handleMessage(.{ .auth_request = .{
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

        const challenge_msg = handler.handleMessage(.{ .auth_request = .{
            .conn_id = 20,
            .mechanism = .scram_sha_256,
            .client_ip = "10.0.0.5",
            .cb_type = 0,
            .cb_data = "",
            .username = "cached",
            .payload = client_first,
        } }) orelse return error.NoResponse;

        const client_final = try client.handleServerFirst(challenge_msg.auth_challenge.challenge);
        const success_msg = handler.handleMessage(.{ .sasl_response = .{
            .conn_id = 20,
            .payload = client_final,
        } }) orelse return error.NoResponse;

        try std.testing.expectEqualStrings("cached", success_msg.auth_success.username);
        handler.cleanupSession(20);
    }

    // Verify cache is populated
    try std.testing.expect(handler.cacheLookup(hashUsername("cached"), std.time.timestamp()) != null);

    // Second auth — uses cache (store lookup skipped)
    {
        var client = sasl.ScramClient.init(allocator, "cached", "pass123");
        defer client.deinit();
        const client_first = try client.clientFirst();

        const challenge_msg = handler.handleMessage(.{ .auth_request = .{
            .conn_id = 21,
            .mechanism = .scram_sha_256,
            .client_ip = "10.0.0.5",
            .cb_type = 0,
            .cb_data = "",
            .username = "cached",
            .payload = client_first,
        } }) orelse return error.NoResponse;

        const client_final = try client.handleServerFirst(challenge_msg.auth_challenge.challenge);
        const success_msg = handler.handleMessage(.{ .sasl_response = .{
            .conn_id = 21,
            .payload = client_final,
        } }) orelse return error.NoResponse;

        try std.testing.expectEqualStrings("cached", success_msg.auth_success.username);
        handler.cleanupSession(21);
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

        const challenge_msg = handler.handleMessage(.{ .auth_request = .{
            .conn_id = 30,
            .mechanism = .scram_sha_256,
            .client_ip = "10.0.0.6",
            .cb_type = 0,
            .cb_data = "",
            .username = "rotate",
            .payload = client_first,
        } }) orelse return error.NoResponse;

        const client_final = try client.handleServerFirst(challenge_msg.auth_challenge.challenge);
        _ = handler.handleMessage(.{ .sasl_response = .{
            .conn_id = 30,
            .payload = client_final,
        } }) orelse return error.NoResponse;

        handler.cleanupSession(30);
    }

    // Cache should be populated
    try std.testing.expect(handler.cacheLookup(hashUsername("rotate"), std.time.timestamp()) != null);

    // Change password — invalidates cache
    _ = handler.handleMessage(.{ .password_change_request = .{
        .conn_id = 31,
        .username = "rotate",
        .new_password = "newpass",
    } });

    // Cache should be invalidated
    try std.testing.expect(handler.cacheLookup(hashUsername("rotate"), std.time.timestamp()) == null);
}
