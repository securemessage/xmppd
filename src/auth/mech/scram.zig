//! # SCRAM-SHA-256 mechanism
//!
//! Two-step challenge-response over per-connection state: the auth request
//! opens a ScramServer and emits the server-first challenge; the SASL
//! response completes the proof. Sessions live in the handler-owned table
//! keyed by (lane, conn_id). The same conn_id legitimately recurs once per
//! core worker lane (T279).

const std = @import("std");
const sasl = @import("sasl");
const protocol = @import("ipc_protocol");
const metrics = @import("auth_metrics");
const handler_mod = @import("../handler.zig");

const log = std.log.scoped(.auth_handler);
const authFailure = handler_mod.authFailure;
const hashUsername = handler_mod.hashUsername;

/// Maximum concurrent SCRAM exchanges (one per XMPP connection doing auth).
/// Must cover a full-worker login burst: xmppd-core defaults to 4096
/// sessions per worker, and every one of them can be mid-SASL at once.
pub const MAX_SCRAM_SESSIONS = 8192;

/// A slot whose owner connection vanished mid-exchange (core only reports
/// auth outcomes for live connections) is reclaimed lazily on the probe
/// path once it has been stale this long. Event-driven: no sweep timer, and
/// idle daemons (no new auths) pay nothing.
const SCRAM_SLOT_STALE_SECONDS: i64 = 60;

/// Per-connection SCRAM state. Keyed by conn_id.
pub const ScramSession = struct {
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

    pub fn deinit(self: *ScramSession) void {
        self.server.deinit();
        self.active = false;
        self.touched_at = 0;
        self.client_ip_len = 0;
    }

    pub fn setClientIp(self: *ScramSession, ip: []const u8) void {
        const n = @min(ip.len, self.client_ip.len);
        @memcpy(self.client_ip[0..n], ip[0..n]);
        self.client_ip_len = @intCast(n);
    }

    pub fn clientIp(self: *const ScramSession) []const u8 {
        return self.client_ip[0..self.client_ip_len];
    }
};

/// Release a live session slot: deinit and drop the occupancy gauge.
/// Every production deinit of a slot activated by handleScramInit runs
/// here so scram_active stays exact.
pub fn releaseSession(s: *ScramSession) void {
    if (!s.active) return;
    s.deinit();
    metrics.scramReleased();
}

/// Handle SCRAM-SHA-256 mechanism (multi-step challenge-response).
pub fn handleScramInit(comptime Store: type, self: *handler_mod.AuthHandler(Store), req: protocol.AuthRequest, ipc_slot: usize) protocol.Message {
    const caps = handler_mod.AuthHandler(Store).capabilities;
    const auth_precis_scratch = &handler_mod.auth_precis_scratch;
    if (comptime !caps.lookup) {
        return authFailure(req.conn_id, .mechanism_not_supported);
    } else {
        // Count the IP attempt before creating exchange state.
        if (self.policy.admitIp(req.client_ip)) |reason| {
            return authFailure(req.conn_id, reason);
        }

        // Find or create a SCRAM session for this conn_id
        const slot = self.findOrCreateScramSlot(@intCast(ipc_slot), req.conn_id) orelse {
            return authFailure(req.conn_id, .temporary_auth_failure);
        };

        var session = &self.scram_sessions[slot];
        // Re-auth on an already-live conn_id: the previous exchange's
        // ScramServer must go before we overwrite it (T279).
        releaseSession(session);
        session.server = sasl.ScramServer.init(self.allocator);
        session.conn_id = req.conn_id;
        session.lane = @intCast(ipc_slot);
        session.active = true;
        metrics.scramActivated();
        session.touched_at = std.time.timestamp();

        // Set channel binding data from TLS session
        session.server.setChannelBinding(req.cb_type, req.cb_data);

        // Process client-first-message
        const username = session.server.handleClientFirst(req.payload) catch {
            releaseSession(session);
            return authFailure(req.conn_id, .invalid_encoding);
        };

        // Look up by the RFC 7622 localpart, but keep the raw n= name
        // in the SCRAM exchange: client-first remains part of the
        // AuthMessage. An unpreparable name gets the same reply as a
        // wrong password, with IP-only bookkeeping and no account key.
        const account_username = auth_precis_scratch.localpart(
            username,
        ) catch {
            log.info("SCRAM auth failed: invalid account name", .{});
            self.policy.recordOutcome("", req.client_ip, .failure);
            releaseSession(session);
            return authFailure(req.conn_id, .not_authorized);
        };

        // Count the account attempt and enforce the lock before any
        // store lookup or challenge work.
        if (self.policy.admitAccount(account_username)) |reason| {
            releaseSession(session);
            return authFailure(req.conn_id, reason);
        }
        session.setClientIp(req.client_ip);

        // Look up credentials: try cache first, fall back to store
        const name_hash = hashUsername(account_username);
        const now = std.time.timestamp();
        const creds = self.cacheLookup(name_hash, now) orelse blk: {
            const maybe_creds = self.store.lookup(self.allocator, account_username) catch {
                releaseSession(session);
                return authFailure(req.conn_id, .temporary_auth_failure);
            };
            const c = maybe_creds orelse {
                log.info("SCRAM auth failed: user '{s}' not found", .{account_username});
                // The attempt was counted at admission; an unknown
                // user is still a failed authentication.
                self.policy.recordOutcome(account_username, req.client_ip, .failure);
                releaseSession(session);
                return authFailure(req.conn_id, .not_authorized);
            };
            self.cacheStore(name_hash, now, c);
            break :blk c;
        };

        session.server.setCredentials(creds);

        // Generate server-first-message
        const server_first = session.server.serverFirst() catch {
            releaseSession(session);
            return authFailure(req.conn_id, .temporary_auth_failure);
        };

        log.info("SCRAM challenge sent for '{s}' conn={d}", .{ username, req.conn_id });

        return protocol.Message{ .auth_challenge = .{
            .conn_id = req.conn_id,
            .challenge = server_first,
        } };
    }
}

pub fn handleSaslResponse(comptime Store: type, self: *handler_mod.AuthHandler(Store), lane: u16, resp: protocol.SaslResponse) protocol.Message {
    const auth_precis_scratch = &handler_mod.auth_precis_scratch;
    // Find the SCRAM session for this lane's conn_id (T279:
    // another lane's identical conn_id must not qualify).
    const slot = self.findScramSlot(lane, resp.conn_id) orelse {
        // No exchange for this conn: aborted, swept as stale, or the
        // auth_request never arrived. Was completely silent.
        log.warn("SCRAM final for conn={d} has no exchange (aborted/swept/lost)", .{resp.conn_id});
        return authFailure(resp.conn_id, .not_authorized);
    };

    var session = &self.scram_sessions[slot];
    session.touched_at = std.time.timestamp();

    const username = session.server.username;
    // The SCRAM proof uses the raw n= name above. Account policy and
    // the bound identity use its RFC 7622 localpart, as at init.
    const account_username = auth_precis_scratch.localpart(
        username,
    ) catch {
        self.policy.recordOutcome("", session.clientIp(), .failure);
        releaseSession(session);
        return authFailure(resp.conn_id, .not_authorized);
    };

    // S3/A1: re-check both keys without counting before the proof is
    // verified, so a lock that arrived between challenge and final
    // gets the same reply for a right and a wrong password.
    if (self.policy.check(account_username, session.clientIp())) |reason| {
        releaseSession(session);
        return authFailure(resp.conn_id, reason);
    }

    // Process client-final-message
    const server_final = session.server.handleClientFinal(resp.payload) catch {
        log.info("SCRAM auth failed: proof verification for conn={d}", .{resp.conn_id});
        self.policy.recordOutcome(account_username, session.clientIp(), .failure);
        releaseSession(session);
        return authFailure(resp.conn_id, .not_authorized);
    };

    log.info("SCRAM auth success: '{s}' conn={d}", .{ account_username, resp.conn_id });
    self.policy.recordOutcome(account_username, session.clientIp(), .success);

    // Keep session alive for server_final's arena-backed slice.
    const result = protocol.Message{ .auth_success = .{
        .conn_id = resp.conn_id,
        .username = account_username,
        .server_final = server_final,
    } };

    // Don't deinit yet: the username/server_final slices are borrowed from the arena.
    // They'll be valid until the next message for this slot.

    return result;
}

/// Clean up a SCRAM session after the response has been sent.
/// Lookup is keyed on (lane, conn_id): conn_id alone collides
/// across core worker lanes each numbering from 1 (T279).
pub fn cleanupSession(comptime Store: type, self: *handler_mod.AuthHandler(Store), lane: u16, conn_id: u32) void {
    if (self.findScramSlot(lane, conn_id)) |slot| {
        releaseSession(&self.scram_sessions[slot]);
    }
}

/// Deinit every in-flight SCRAM session the given IPC lane owns;
/// called before closing that IPC client so dead lanes cannot wedge
/// sessions into the 60 s stale probe (T279).
pub fn closeLaneSessions(comptime Store: type, self: *handler_mod.AuthHandler(Store), lane: usize) void {
    const lane_u16: u16 = @intCast(lane);
    for (&self.scram_sessions) |*s| {
        if (s.active and s.lane == lane_u16) releaseSession(s);
    }
}

/// conn_id packs generation<<16|session_slot, so a burst of >256
/// concurrent logins on one worker aliases mod MAX_SCRAM_SESSIONS
/// by construction. The table must probe instead of failing on the
/// first occupied home slot (birthday collisions are guaranteed);
/// null now means the table is genuinely full.
/// (lane, conn_id) is the key: the same conn_id legimately recurs
/// once per core worker lane (T279).
pub fn findOrCreateScramSlot(comptime Store: type, self: *handler_mod.AuthHandler(Store), lane: u16, conn_id: u32) ?usize {
    if (findScramSlot(Store, self, lane, conn_id)) |slot| return slot;
    const now = std.time.timestamp();
    const start = (conn_id & 0xFFFF) % MAX_SCRAM_SESSIONS;
    var i: usize = 0;
    while (i < MAX_SCRAM_SESSIONS) : (i += 1) {
        const slot = (start + i) % MAX_SCRAM_SESSIONS;
        const s = &self.scram_sessions[slot];
        if (!s.active) return slot;
        // Reclaim slots abandoned by connections that died before a
        // final auth response; otherwise they leak until restart.
        if (now - s.touched_at > SCRAM_SLOT_STALE_SECONDS) {
            releaseSession(s);
            return slot;
        }
    }
    return null;
}

pub fn findScramSlot(comptime Store: type, self: *handler_mod.AuthHandler(Store), lane: u16, conn_id: u32) ?usize {
    // Probing leaves holes on cleanup; a full scan over 256 entries
    // is cheaper than tombstone bookkeeping. (lane, conn_id) key
    // (T279): never hand another lane's active exchange back here.
    for (&self.scram_sessions, 0..) |*s, slot| {
        if (s.active and s.conn_id == conn_id and s.lane == lane) return slot;
    }
    return null;
}

// ============================================================================
// Tests
// ============================================================================

const testkit = @import("../testkit.zig");
const backend_mod = @import("backend");
const user_store_mod = @import("user_store");
const MemoryBackend = backend_mod.MemoryBackend;
const TestUserStore = user_store_mod.UserStore(MemoryBackend);
const TestHandler = handler_mod.AuthHandler(TestUserStore);
const handleSync = testkit.handleSync;
const RateLimiter = @import("rate_limiter").RateLimiter;
const LockCheckResult = handler_mod.LockCheckResult;
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

    // One more: the table is uniquely exhausted, so temporary-auth-failure.
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

test "AuthHandler: SCRAM prepares the account name but preserves the exchange" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "testuser", "testpassword");

    var handler = TestHandler.init(allocator, &store);
    defer handler.deinit();

    // The client proves the exchange with its typed n= spelling while the
    // server looks up and returns the prepared localpart.
    var client = sasl.ScramClient.init(allocator, "TestUser", "testpassword");
    defer client.deinit();
    const client_first = try client.clientFirst();
    const challenge_msg = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 15,
        .mechanism = .scram_sha_256,
        .client_ip = "10.0.0.15",
        .cb_type = 0,
        .cb_data = "",
        .username = "TestUser",
        .payload = client_first,
    } }) orelse return error.NoResponse;

    const client_final = try client.handleServerFirst(challenge_msg.auth_challenge.challenge);
    const success_msg = handleSync(&handler, .{ .sasl_response = .{
        .conn_id = 15,
        .payload = client_final,
    } }) orelse return error.NoResponse;

    try std.testing.expectEqualStrings("testuser", success_msg.auth_success.username);
    try client.handleServerFinal(success_msg.auth_success.server_final);
    try std.testing.expect(client.isComplete());
    handler.cleanupSession(0, 15);
}

test "AuthHandler: SCRAM invalid names fail closed to not-authorized with IP-only charge" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    // A raw legacy row still cannot make the invalid name match an account.
    try store.addUser(allocator, "bad name", "pw");
    var limiter = try RateLimiter.init(allocator, .{
        .max_per_account = 100,
        .max_per_ip = 100,
        .window_seconds = 60,
        .lockout_duration = 300,
        .lockout_threshold = 1,
        .ip_lockout_threshold = 1,
    });
    defer limiter.deinit();
    var handler = TestHandler.init(allocator, &store);
    handler.setRateLimiter(&limiter);
    defer handler.deinit();

    var client = sasl.ScramClient.init(allocator, "bad name", "pw");
    defer client.deinit();
    const client_first = try client.clientFirst();
    const result = handleSync(&handler, .{ .auth_request = .{
        .conn_id = 16,
        .mechanism = .scram_sha_256,
        .client_ip = "10.0.0.16",
        .cb_type = 0,
        .cb_data = "",
        .username = "bad name",
        .payload = client_first,
    } }) orelse return error.NoResponse;

    try std.testing.expect(result == .auth_failure);
    try std.testing.expectEqualStrings("not-authorized", result.auth_failure.reason);
    try std.testing.expect(handler.policy.admitAccount("bad name") == null);
    try std.testing.expectEqual(.policy_violation, handler.policy.admitIp("10.0.0.16") orelse return error.ExpectedDenial);
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

    // First auth populates the cache
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

    // Second auth uses the cache (store lookup skipped)
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

    // Change password invalidates the cache
    _ = handleSync(&handler, .{ .password_change_request = .{
        .conn_id = 31,
        .username = "rotate",
        .new_password = "newpass",
    } });

    // Cache should be invalidated
    try std.testing.expect(handler.cacheLookup(hashUsername("rotate"), std.time.timestamp()) == null);
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
