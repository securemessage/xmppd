//! # SCRAM-SHA-256 mechanism, protocol v2 (ADR-6)
//!
//! Stateless one-round-trip verify: the core caches (salt, iterations) per
//! username, builds server-first itself and sends one scram_verify carrying
//! client-first-bare, the gs2 flag, server-first, client-final and the
//! channel-binding data. This daemon checks the nonce and parameters, runs
//! policy.admit, verifies against StoredKey and returns the ServerSignature.
//! It holds no per-exchange state; the only SCRAM structure left here is the
//! bounded server-nonce replay cache. StoredKey and ServerKey never leave
//! this daemon.

const std = @import("std");
const sasl = @import("sasl");
const stringprep = sasl.stringprep;
const protocol = @import("ipc_protocol");
const metrics = @import("auth_metrics");
const handler_mod = @import("../handler.zig");

const log = std.log.scoped(.auth_handler);
const authFailure = handler_mod.authFailure;
const hashUsername = handler_mod.hashUsername;

/// Reply bodies must outlive the handler call: the runner encodes the frame
/// after handleMessage returns, so reply slices point into these
/// threadlocals (valid until the next message on this loop), not into
/// per-call stack buffers.
threadlocal var scram_salt_buf: [32]u8 = undefined;
threadlocal var scram_sfinal_buf: [64]u8 = undefined;

/// Server-nonce replay cache: open-addressed, expiry checked at insert and
/// lookup, no timer. Capacity comes from config at handler init
/// (auth.login_rate_ceiling x auth.scram_nonce_window_seconds); this is the
/// fallback default.
pub const DEFAULT_REPLAY_CAPACITY = 16384;
/// A server nonce is consumable for this long after core mints it; matches
/// the old exchange staleness deadline (SCRAM_SLOT_STALE_SECONDS). The
/// handler's configured window replaces this at runtime.
pub const DEFAULT_NONCE_WINDOW_SECONDS: i64 = 60;
/// Forward tolerance for a nonce timestamped a little ahead of the auth
/// daemon's clock.
pub const DEFAULT_NONCE_SKEW_SECONDS: i64 = 15;
/// Bounded probe window for insert and lookup.
const REPLAY_PROBE = 8;
/// Iteration count served for unknown users; the same constant the store
/// derives at account creation so fakes are indistinguishable.
const FAKE_ITERATIONS: u32 = sasl.scram.default_iteration_count;

/// The persisted fake-derivation key inside {db}/auth: loaded at init or
/// created once, so a fake salt is as stable across restarts as a real
/// one (review 770 item 2).
pub const SECRET_FILE = "scram_secret";

/// Load the persisted secret from dir, or mint and store it once with
/// mode 0600. dir is the opened {db}/auth directory; a concurrent creator
/// wins and the loser reads what it wrote.
pub fn loadOrCreateSecret(dir: std.fs.Dir) ![32]u8 {
    if (dir.openFile(SECRET_FILE, .{})) |file| {
        defer file.close();
        var secret: [32]u8 = undefined;
        const n = try file.readAll(&secret);
        if (n != secret.len) return error.InvalidSecretFile;
        return secret;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    var secret: [32]u8 = undefined;
    std.crypto.random.bytes(&secret);
    const file = dir.createFile(SECRET_FILE, .{ .mode = 0o600, .exclusive = true }) catch |err| switch (err) {
        error.PathAlreadyExists => return loadOrCreateSecret(dir),
        else => return err,
    };
    defer file.close();
    try file.writeAll(&secret);
    try file.sync();
    return secret;
}

/// One replay-cache slot. The tag is HMAC(secret, nonce) truncated to 16 B:
/// keyed, so an attacker cannot steer inserts into one probe window.
pub const ReplayEntry = struct {
    tag: [16]u8 = undefined,
    touched_at: i64 = 0,
    occupied: bool = false,
};

fn nonceTag(secret: *const [32]u8, nonce: []const u8) [16]u8 {
    var mac: [32]u8 = undefined;
    var h = std.crypto.auth.hmac.sha2.HmacSha256.init(secret);
    h.update("a5-scram-nonce");
    h.update(nonce);
    h.final(&mac);
    var tag: [16]u8 = undefined;
    @memcpy(&tag, mac[0..16]);
    return tag;
}

fn replayHome(tag: *const [16]u8, capacity: usize) usize {
    return std.mem.readInt(u64, tag[0..8], .little) % capacity;
}

/// Free an entry in place and drop the occupancy gauge.
fn replayFree(e: *ReplayEntry) void {
    if (!e.occupied) return;
    e.occupied = false;
    metrics.replayRemoved();
}

/// True when nonce is already consumed and unexpired; expired hits are
/// reclaimed in place so lookup also refreshes occupancy.
fn replaySeen(comptime Store: type, self: *handler_mod.AuthHandler(Store), nonce: []const u8, now: i64) bool {
    const capacity = self.replay_entries.len;
    if (capacity == 0) return false;
    const tag = nonceTag(&self.scram_secret, nonce);
    const home = replayHome(&tag, capacity);
    var i: usize = 0;
    while (i < REPLAY_PROBE) : (i += 1) {
        const e = &self.replay_entries[(home + i) % capacity];
        if (!e.occupied) continue;
        if (now - e.touched_at > self.replay_window_seconds) {
            replayFree(e);
            continue;
        }
        if (std.mem.eql(u8, &e.tag, &tag)) return true;
    }
    return false;
}

/// Consume nonce into the replay cache. First free-or-expired slot inside
/// the probe window wins. A window of all-live entries is error.CacheFull:
/// evicting a live tag would reopen it to replay, so the verify is refused
/// with temporary-auth-failure instead and counted (review 770).
fn replayInsert(comptime Store: type, self: *handler_mod.AuthHandler(Store), nonce: []const u8, now: i64) error{CacheFull}!void {
    const capacity = self.replay_entries.len;
    if (capacity == 0) return error.CacheFull;
    const tag = nonceTag(&self.scram_secret, nonce);
    const home = replayHome(&tag, capacity);
    var i: usize = 0;
    while (i < REPLAY_PROBE) : (i += 1) {
        const e = &self.replay_entries[(home + i) % capacity];
        if (!e.occupied or now - e.touched_at > self.replay_window_seconds) {
            replayFree(e);
            e.* = .{ .tag = tag, .touched_at = now, .occupied = true };
            metrics.replayInserted();
            return;
        }
    }
    metrics.replayRefused();
    return error.CacheFull;
}

/// Credentials for a username that does not exist, derived from the
/// per-boot secret so the verify path runs the same work and fails the same
/// way as a wrong password, and repeated probes cannot tell a missing
/// account from a real one.
fn fakeCredentials(secret: *const [32]u8, username: []const u8) sasl.scram.StoredCredentials {
    var creds: sasl.scram.StoredCredentials = undefined;
    fakeInto(secret, "a5-scram-salt", username, &creds.salt);
    fakeInto(secret, "a5-scram-stored", username, &creds.stored_key);
    fakeInto(secret, "a5-scram-server", username, &creds.server_key);
    creds.iteration_count = FAKE_ITERATIONS;
    return creds;
}

fn fakeInto(secret: *const [32]u8, label: []const u8, username: []const u8, out: *[32]u8) void {
    var h = std.crypto.auth.hmac.sha2.HmacSha256.init(secret);
    h.update(label);
    h.update(username);
    h.final(out);
}

/// Resolve the account username for a raw n= name: unescape the SCRAM wire
/// form, then RFC 7622 localpart. Null when the name cannot carry an account.
fn accountName(req_name: []const u8, uname_buf: []u8) ?[]const u8 {
    const uname = if (stringprep.unescapeScramName(req_name, uname_buf)) |u| u else |_| return null;
    return if (handler_mod.auth_precis_scratch.localpart(uname)) |a| a else |_| null;
}

/// Fetch real credentials for an account name through the daemon cache and
/// store; null on a lookup miss, error.StoreFailed on a backend error.
fn lookupCredentials(comptime Store: type, self: *handler_mod.AuthHandler(Store), account_username: []const u8, name_hash: u64) error{StoreFailed}!?sasl.scram.StoredCredentials {
    const now = std.time.timestamp();
    if (self.cacheLookup(name_hash, now)) |c| return c;
    const maybe = if (self.store.lookup(self.allocator, account_username)) |m| m else |_| return error.StoreFailed;
    const c = maybe orelse return null;
    self.cacheStore(name_hash, now, c);
    return c;
}

/// Auth->Core scram_params: public (salt, iterations) for one username on a
/// core cache miss. Unknown or unformattable names get the deterministic
/// fake so the reply shape never reveals an account.
pub fn handleScramParams(comptime Store: type, self: *handler_mod.AuthHandler(Store), req: protocol.ScramParamsRequest) protocol.Message {
    const caps = handler_mod.AuthHandler(Store).capabilities;
    if (comptime !caps.lookup) return authFailure(req.conn_id, .mechanism_not_supported);

    // Non-counting lock check only: this is a public-data read; the real
    // admission is scram_verify's policy.admit.
    if (self.policy.check("", req.client_ip)) |reason| {
        return authFailure(req.conn_id, reason);
    }

    var uname_buf: [512]u8 = undefined;
    const account_username = accountName(req.username, &uname_buf) orelse {
        // A name that can never be an account still gets a fake pair so the
        // reply shape stays uniform.
        const fake = fakeCredentials(&self.scram_secret, req.username);
        return paramsReply(req.conn_id, &fake);
    };

    const creds = lookupCredentials(Store, self, account_username, hashUsername(account_username)) catch |err| switch (err) {
        error.StoreFailed => return authFailure(req.conn_id, .temporary_auth_failure),
    } orelse fakeCredentials(&self.scram_secret, account_username);
    return paramsReply(req.conn_id, &creds);
}

fn paramsReply(conn_id: u32, creds: *const sasl.scram.StoredCredentials) protocol.Message {
    scram_salt_buf = creds.salt;
    return protocol.Message{ .scram_params = .{
        .conn_id = conn_id,
        .salt = &scram_salt_buf,
        .iteration_count = creds.iteration_count,
    } };
}

/// Core->Auth scram_verify: the one-round-trip stateless verify (ADR-6).
/// Order of checks mirrors the v1 two-step path so outcome reasons stay
/// identical.
pub fn handleScramVerify(comptime Store: type, self: *handler_mod.AuthHandler(Store), req: protocol.ScramVerify) protocol.Message {
    const caps = handler_mod.AuthHandler(Store).capabilities;
    if (comptime !caps.lookup) return authFailure(req.conn_id, .mechanism_not_supported);

    const first = sasl.scram.parseClientFirstBare(req.client_first_bare) catch {
        self.policy.recordOutcome("", req.client_ip, .failure);
        return authFailure(req.conn_id, .invalid_encoding);
    };
    switch (req.gs2_flag) {
        'n', 'y', 'p' => {},
        else => {
            self.policy.recordOutcome("", req.client_ip, .failure);
            return authFailure(req.conn_id, .invalid_encoding);
        },
    }

    var uname_buf: [512]u8 = undefined;
    const account_username = accountName(first.raw_name, &uname_buf) orelse {
        log.info("SCRAM auth failed: invalid account name", .{});
        self.policy.recordOutcome("", req.client_ip, .failure);
        return authFailure(req.conn_id, .not_authorized);
    };

    // One admission per exchange: IP and account are each counted once, the
    // permanent lock and both windows are consulted.
    if (self.policy.admit(account_username, req.client_ip)) |reason| {
        return authFailure(req.conn_id, reason);
    }

    const creds = lookupCredentials(Store, self, account_username, hashUsername(account_username)) catch |err| switch (err) {
        error.StoreFailed => {
            self.policy.recordOutcome(account_username, req.client_ip, .failure);
            return authFailure(req.conn_id, .temporary_auth_failure);
        },
    } orelse fakeCredentials(&self.scram_secret, account_username);

    var am_buf: [4096]u8 = undefined;
    const parsed = sasl.scram.parseExchange(
        req.gs2_flag,
        req.cb_type,
        req.cb_data,
        req.client_first_bare,
        req.server_first,
        req.client_final,
        &creds,
        &am_buf,
    ) catch {
        self.policy.recordOutcome(account_username, req.client_ip, .failure);
        return authFailure(req.conn_id, .not_authorized);
    };

    // Freshness covered by the proof: the core embeds its issue time in the
    // server nonce, which the client signs inside server-first. A nonce
    // outside [now - window, now + skew] is refused; so is one that does
    // not decode to the timed layout at all.
    const now = std.time.timestamp();
    if (!sasl.scram.serverNonceFresh(parsed.server_nonce, now, self.replay_window_seconds, self.nonce_skew_seconds)) {
        log.info("SCRAM auth failed: stale or undecodable server nonce conn={d}", .{req.conn_id});
        self.policy.recordOutcome(account_username, req.client_ip, .failure);
        return authFailure(req.conn_id, .not_authorized);
    }

    // The exchange is well-formed and fresh now: consume the server nonce
    // before the proof runs, so a retry needs a fresh challenge either way.
    if (replaySeen(Store, self, parsed.server_nonce, now)) {
        log.info("SCRAM auth failed: replayed server nonce conn={d}", .{req.conn_id});
        self.policy.recordOutcome(account_username, req.client_ip, .failure);
        return authFailure(req.conn_id, .not_authorized);
    }
    replayInsert(Store, self, parsed.server_nonce, now) catch {
        // A live-tag eviction would reopen that tag to replay; refuse the
        // verify instead (counted by authFailure + metrics.replayRefused).
        log.info("SCRAM auth failed: replay cache probe window full conn={d}", .{req.conn_id});
        self.policy.recordOutcome(account_username, req.client_ip, .failure);
        return authFailure(req.conn_id, .temporary_auth_failure);
    };

    const server_sig = sasl.scram.verifyProof(&creds, parsed.auth_message, &parsed.client_proof) catch {
        log.info("SCRAM auth failed: proof verification for conn={d}", .{req.conn_id});
        self.policy.recordOutcome(account_username, req.client_ip, .failure);
        return authFailure(req.conn_id, .not_authorized);
    };

    log.info("SCRAM auth success: '{s}' conn={d}", .{ account_username, req.conn_id });
    self.policy.recordOutcome(account_username, req.client_ip, .success);

    // server-final-message: v=base64(ServerSignature)
    const encoder = std.base64.standard.Encoder;
    const sig_b64_len = encoder.calcSize(32);
    const sig_b64 = encoder.encode(scram_sfinal_buf[2 .. 2 + sig_b64_len], &server_sig);
    scram_sfinal_buf[0] = 'v';
    scram_sfinal_buf[1] = '=';
    const server_final = scram_sfinal_buf[0 .. 2 + sig_b64.len];

    return protocol.Message{ .auth_success = .{
        .conn_id = req.conn_id,
        .username = account_username,
        .server_final = server_final,
    } };
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

/// The RFC 7677 client nonce, reused so vector-shaped messages stay pinned.
const RFC_CNONCE = "rOprNGfwEbeRWgbNEkqO";

/// A fresh timed server nonce for tests; caller keeps the buffer alive for
/// the exchange.
fn testSnonce(buf: *[testkit.SNONCE_B64_LEN]u8) []const u8 {
    return testkit.mintSnonce(buf, std.time.timestamp());
}

test "SCRAM v2: full login verifies a proof computed independently of the library" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "user", "pencil");
    var handler = TestHandler.init(allocator, &store, .{});
    defer handler.deinit();

    const params = handleSync(&handler, .{ .scram_params_request = .{
        .conn_id = 1,
        .username = "user",
        .client_ip = "10.1.0.1",
    } }) orelse return error.NoResponse;
    try std.testing.expect(params == .scram_params);

    // RFC-7677-shaped exchange: the wire layout is the RFC's, the salt is
    // 32 bytes because StoredCredentials pins that length. Every expected
    // value below is computed from std.crypto directly, never through the
    // scram library under test.
    const bare = "n=user,r=" ++ RFC_CNONCE;
    const enc = std.base64.standard.Encoder;
    var nb: [testkit.SNONCE_B64_LEN]u8 = undefined;
    const snonce = testSnonce(&nb);
    var salt_b64: [64]u8 = undefined;
    const salt_enc = enc.encode(salt_b64[0..enc.calcSize(params.scram_params.salt.len)], params.scram_params.salt);
    const sfirst = try std.fmt.allocPrint(allocator, "r={s}{s},s={s},i={d}", .{
        RFC_CNONCE, snonce, salt_enc, params.scram_params.iteration_count,
    });
    defer allocator.free(sfirst);

    // SaltedPassword = Hi(password, salt, i); ClientKey = HMAC(sp, "Client
    // Key"); StoredKey = H(ck); AuthMessage; ClientSignature = HMAC(sk, am);
    // ClientProof = ck xor sig.
    const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
    var salted: [32]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&salted, "pencil", params.scram_params.salt, params.scram_params.iteration_count, std.crypto.auth.hmac.sha2.HmacSha256);
    var ckey: [32]u8 = undefined;
    Hmac.create(&ckey, "Client Key", &salted);
    var stored_key: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&ckey, &stored_key, .{});

    const client_final_no_proof = try std.fmt.allocPrint(allocator, "c=biws,r={s}{s}", .{ RFC_CNONCE, snonce });
    defer allocator.free(client_final_no_proof);
    const auth_message = try std.fmt.allocPrint(allocator, "{s},{s},{s}", .{ bare, sfirst, client_final_no_proof });
    defer allocator.free(auth_message);
    var csig: [32]u8 = undefined;
    Hmac.create(&csig, auth_message, &stored_key);
    var proof: [32]u8 = undefined;
    for (0..32) |i| proof[i] = ckey[i] ^ csig[i];
    var proof_b64_buf: [64]u8 = undefined;
    const proof_b64 = enc.encode(proof_b64_buf[0..enc.calcSize(32)], &proof);
    const client_final = try std.fmt.allocPrint(allocator, "{s},p={s}", .{ client_final_no_proof, proof_b64 });
    defer allocator.free(client_final);

    const reply = handleSync(&handler, .{ .scram_verify = .{
        .conn_id = 1,
        .client_ip = "10.1.0.1",
        .cb_type = 0,
        .cb_data = "",
        .gs2_flag = 'n',
        .client_first_bare = bare,
        .server_first = sfirst,
        .client_final = client_final,
    } }) orelse return error.NoResponse;
    try std.testing.expect(reply == .auth_success);
    try std.testing.expectEqualStrings("user", reply.auth_success.username);

    // ServerSignature = HMAC(ServerKey, AuthMessage), ServerKey =
    // HMAC(salted, "Server Key"): check the v= value byte for byte.
    var skey: [32]u8 = undefined;
    Hmac.create(&skey, "Server Key", &salted);
    var expected_sig: [32]u8 = undefined;
    Hmac.create(&expected_sig, auth_message, &skey);
    var sig_b64_buf: [64]u8 = undefined;
    const sig_b64 = enc.encode(sig_b64_buf[0..enc.calcSize(32)], &expected_sig);
    const expected_final = try std.fmt.allocPrint(allocator, "v={s}", .{sig_b64});
    defer allocator.free(expected_final);
    try std.testing.expectEqualStrings(expected_final, reply.auth_success.server_final);
}

test "SCRAM v2: a replayed client-final is refused by the nonce cache" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "pw");
    var handler = TestHandler.init(allocator, &store, .{});
    defer handler.deinit();

    // Drive one real exchange, capturing the verify message byte for byte.
    var client = sasl.ScramClient.init(allocator, "alice", "pw");
    defer client.deinit();
    const cf = try client.clientFirst();
    const first = try sasl.scram.parseClientFirst(cf);
    const params = handleSync(&handler, .{ .scram_params_request = .{
        .conn_id = 7,
        .username = first.raw_name,
        .client_ip = "10.0.0.7",
    } }) orelse return error.NoResponse;
    var sf: [512]u8 = undefined;
    var nb: [testkit.SNONCE_B64_LEN]u8 = undefined;
    const sfirst = testkit.serverFirst(&sf, first.client_nonce, testSnonce(&nb), params.scram_params.salt, params.scram_params.iteration_count);
    try client.parseServerFirst(sfirst);
    var salted: [32]u8 = undefined;
    sasl.scram.pbkdf2("pw", client.salt_raw[0..client.salt_raw_len], client.iteration_count, &salted);
    const final = try client.clientFinal(salted);

    const verify = protocol.Message{ .scram_verify = .{
        .conn_id = 7,
        .client_ip = "10.0.0.7",
        .cb_type = 0,
        .cb_data = "",
        .gs2_flag = first.gs2_flag,
        .client_first_bare = first.bare,
        .server_first = sfirst,
        .client_final = final,
    } };
    const ok = handleSync(&handler, verify) orelse return error.NoResponse;
    try std.testing.expect(ok == .auth_success);

    // The identical verify resent verbatim: the server nonce is consumed.
    const replay = handleSync(&handler, verify) orelse return error.NoResponse;
    try std.testing.expect(replay == .auth_failure);
    try std.testing.expectEqualStrings("not-authorized", replay.auth_failure.reason);
}

test "SCRAM v2: unknown user's params are deterministic and same-shaped" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "pw");
    var handler = TestHandler.init(allocator, &store, .{});
    defer handler.deinit();

    // Reply slices borrow a threadlocal buffer that the next reply reuses:
    // snapshot the bytes each time before asking for the next reply.
    const req = protocol.Message{ .scram_params_request = .{
        .conn_id = 1,
        .username = "alice",
        .client_ip = "10.0.0.1",
    } };
    const real = handleSync(&handler, req) orelse return error.NoResponse;
    try std.testing.expect(real == .scram_params);
    var real_salt: [32]u8 = undefined;
    @memcpy(&real_salt, real.scram_params.salt);
    const real_iters = real.scram_params.iteration_count;

    const ghost_req = protocol.Message{ .scram_params_request = .{
        .conn_id = 1,
        .username = "nosuchuser",
        .client_ip = "10.0.0.1",
    } };
    const fake1 = handleSync(&handler, ghost_req) orelse return error.NoResponse;
    try std.testing.expect(fake1 == .scram_params);
    var fake1_salt: [32]u8 = undefined;
    @memcpy(&fake1_salt, fake1.scram_params.salt);
    const fake_iters = fake1.scram_params.iteration_count;
    const fake2 = handleSync(&handler, ghost_req) orelse return error.NoResponse;
    try std.testing.expect(fake2 == .scram_params);

    // Shape: same field sizes, same iteration magnitude; content differs
    // but a fake is deterministic across calls so the cache cannot be
    // probed into an oracle.
    try std.testing.expectEqual(@as(usize, 32), fake1.scram_params.salt.len);
    try std.testing.expectEqual(real_iters, fake_iters);
    try std.testing.expectEqualSlices(u8, &fake1_salt, fake2.scram_params.salt);
    try std.testing.expectEqual(fake_iters, fake2.scram_params.iteration_count);
    try std.testing.expect(!std.mem.eql(u8, &real_salt, &fake1_salt));
}

test "SCRAM v2: a mismatched channel binding fails the exchange" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "pw");
    var handler = TestHandler.init(allocator, &store, .{});
    defer handler.deinit();

    var client = sasl.ScramClient.init(allocator, "alice", "pw");
    defer client.deinit();
    var sf: [512]u8 = undefined;
    // Drive the exchange but lie at the verify: claim gs2 'p' with no
    // binding data. checkChannelBinding refuses before the proof runs.
    const cf = try client.clientFirst();
    const first = try sasl.scram.parseClientFirst(cf);
    const params = handleSync(&handler, .{ .scram_params_request = .{
        .conn_id = 5,
        .username = first.raw_name,
        .client_ip = "10.0.0.5",
    } }) orelse return error.NoResponse;
    var nb: [testkit.SNONCE_B64_LEN]u8 = undefined;
    const sfirst = testkit.serverFirst(&sf, first.client_nonce, testSnonce(&nb), params.scram_params.salt, params.scram_params.iteration_count);
    try client.parseServerFirst(sfirst);
    var salted: [32]u8 = undefined;
    sasl.scram.pbkdf2("pw", client.salt_raw[0..client.salt_raw_len], client.iteration_count, &salted);
    const final = try client.clientFinal(salted);

    const reply = handleSync(&handler, .{ .scram_verify = .{
        .conn_id = 5,
        .client_ip = "10.0.0.5",
        .cb_type = 0,
        .cb_data = "",
        .gs2_flag = 'p',
        .client_first_bare = first.bare,
        .server_first = sfirst,
        .client_final = final,
    } }) orelse return error.NoResponse;
    try std.testing.expect(reply == .auth_failure);
    try std.testing.expectEqualStrings("not-authorized", reply.auth_failure.reason);
}

test "SCRAM v2: the daemon holds no per-exchange state after a reply" {
    // The v1 session table is gone by construction: no scram_sessions field
    // may exist on the handler, and no find/cleanup functions.
    try std.testing.expect(!@hasField(TestHandler, "scram_sessions"));
    try std.testing.expect(!@hasDecl(TestHandler, "findOrCreateScramSlot"));
    try std.testing.expect(!@hasDecl(TestHandler, "cleanupSession"));
    try std.testing.expect(!@hasDecl(TestHandler, "closeLaneSessions"));

    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "pw");
    var handler = TestHandler.init(allocator, &store, .{});
    defer handler.deinit();

    var client = sasl.ScramClient.init(allocator, "alice", "pw");
    defer client.deinit();
    var sf: [512]u8 = undefined;
    var nb1: [testkit.SNONCE_B64_LEN]u8 = undefined;
    _ = try testkit.scramV2Exchange(&handler, &client, 1, "10.0.0.1", "pw", testkit.mintSnonce(&nb1, std.time.timestamp()), &sf);
    // Replay consumption is the only footprint left: one occupied entry.
    var occupied: usize = 0;
    for (handler.replay_entries) |*e| {
        if (e.occupied) occupied += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), occupied);
}

test "SCRAM v2: prepared account name is returned while the exchange keeps the wire name" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "testuser", "testpassword");
    var handler = TestHandler.init(allocator, &store, .{});
    defer handler.deinit();

    var client = sasl.ScramClient.init(allocator, "TestUser", "testpassword");
    defer client.deinit();
    var sf: [512]u8 = undefined;
    var nb2: [testkit.SNONCE_B64_LEN]u8 = undefined;
    const ex = try testkit.scramV2Exchange(&handler, &client, 5, "10.0.0.5", "testpassword", testkit.mintSnonce(&nb2, std.time.timestamp()), &sf);
    try std.testing.expect(ex.verify_msg.? == .auth_success);
    try std.testing.expectEqualStrings("testuser", ex.verify_msg.?.auth_success.username);
    try std.testing.expect(ex.verify_msg.?.auth_success.server_final.len > 0);
}

test "SCRAM v2: an unformattable account name fails not-authorized" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    var handler = TestHandler.init(allocator, &store, .{});
    defer handler.deinit();

    // U+E000 is prohibited by OpaqueString; the verify must refuse
    // not-authorized rather than leak anything.
    const bad_bare = "n=\xEE\x80\x80,r=abcdefghijklmnop";
    const reply = handleSync(&handler, .{ .scram_verify = .{
        .conn_id = 9,
        .client_ip = "10.0.0.9",
        .cb_type = 0,
        .cb_data = "",
        .gs2_flag = 'n',
        .client_first_bare = bad_bare,
        .server_first = "r=abcdefghijklmnopZZZZ,s=AAAA,i=4096",
        .client_final = "c=biws,r=abcdefghijklmnopZZZZ,p=AAAA",
    } }) orelse return error.NoResponse;
    try std.testing.expect(reply == .auth_failure);
    try std.testing.expectEqualStrings("not-authorized", reply.auth_failure.reason);
}

test "SCRAM v2: unknown user verify fails the same way a wrong password does" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    var handler = TestHandler.init(allocator, &store, .{});
    defer handler.deinit();

    var client = sasl.ScramClient.init(allocator, "ghost", "pw");
    defer client.deinit();
    var sf: [512]u8 = undefined;
    var nb3: [testkit.SNONCE_B64_LEN]u8 = undefined;
    const ex = try testkit.scramV2Exchange(&handler, &client, 3, "10.0.0.3", "pw", testkit.mintSnonce(&nb3, std.time.timestamp()), &sf);
    try std.testing.expect(ex.params_msg.? == .scram_params);
    try std.testing.expect(ex.verify_msg.? == .auth_failure);
    try std.testing.expectEqualStrings("not-authorized", ex.verify_msg.?.auth_failure.reason);
}

test "SCRAM v2: credential cache is invalidated on password change" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "old-pass");
    var handler = TestHandler.init(allocator, &store, .{});
    defer handler.deinit();

    var c1 = sasl.ScramClient.init(allocator, "alice", "old-pass");
    defer c1.deinit();
    var sf1: [512]u8 = undefined;
    var nb4: [testkit.SNONCE_B64_LEN]u8 = undefined;
    const ok = try testkit.scramV2Exchange(&handler, &c1, 1, "10.0.0.1", "old-pass", testkit.mintSnonce(&nb4, std.time.timestamp()), &sf1);
    try std.testing.expect(ok.verify_msg.? == .auth_success);

    // Password rotation over the account IPC invalidates the daemon's
    // credential cache; the next verify must not see the stale entry.
    _ = handleSync(&handler, .{ .password_change_request = .{
        .conn_id = 31,
        .username = "alice",
        .new_password = "new-pass",
    } });

    var c2 = sasl.ScramClient.init(allocator, "alice", "old-pass");
    defer c2.deinit();
    var sf2: [512]u8 = undefined;
    var nb5: [testkit.SNONCE_B64_LEN]u8 = undefined;
    const stale = try testkit.scramV2Exchange(&handler, &c2, 2, "10.0.0.2", "old-pass", testkit.mintSnonce(&nb5, std.time.timestamp()), &sf2);
    try std.testing.expect(stale.verify_msg.? == .auth_failure);

    var c3 = sasl.ScramClient.init(allocator, "alice", "new-pass");
    defer c3.deinit();
    var sf3: [512]u8 = undefined;
    var nb6: [testkit.SNONCE_B64_LEN]u8 = undefined;
    const fresh = try testkit.scramV2Exchange(&handler, &c3, 3, "10.0.0.3", "new-pass", testkit.mintSnonce(&nb6, std.time.timestamp()), &sf3);
    try std.testing.expect(fresh.verify_msg.? == .auth_success);
}

test "SCRAM v2: replay cache expires entries lazily and stays bounded" {
    const allocator = std.testing.allocator;
    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    var handler = TestHandler.init(allocator, &store, .{});
    defer handler.deinit();

    const now = std.time.timestamp();
    const ttl = handler.replay_window_seconds;

    // Insert then seen: same nonce is a replay within the window.
    try replayInsert(TestUserStore, &handler, "nonce-one", now);
    try std.testing.expect(replaySeen(TestUserStore, &handler, "nonce-one", now));
    try std.testing.expect(!replaySeen(TestUserStore, &handler, "nonce-two", now));

    // Past the window the entry is reclaimed at lookup and can be
    // re-consumed.
    const later = now + ttl + 1;
    try std.testing.expect(!replaySeen(TestUserStore, &handler, "nonce-one", later));
    try replayInsert(TestUserStore, &handler, "nonce-one", later);
    try std.testing.expect(replaySeen(TestUserStore, &handler, "nonce-one", later));

    // Flood past capacity: inserts refuse before evicting a live tag, so
    // the table never grows past its bound and live tags stay consumed.
    var i: usize = 0;
    var buf: [32]u8 = undefined;
    var refusals: usize = 0;
    while (i < handler.replay_entries.len * 2) : (i += 1) {
        const nonce = std.fmt.bufPrint(&buf, "flood-{d}", .{i}) catch unreachable;
        replayInsert(TestUserStore, &handler, nonce, later) catch {
            refusals += 1;
            continue;
        };
    }
    var occupied: usize = 0;
    for (handler.replay_entries) |*e| {
        if (e.occupied) occupied += 1;
    }
    try std.testing.expect(occupied <= handler.replay_entries.len);
    try std.testing.expect(refusals > 0);
    try std.testing.expect(replaySeen(TestUserStore, &handler, "nonce-one", later));
}

test "SCRAM v2: a server nonce older than the freshness window is refused" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "pw");
    var handler = TestHandler.init(allocator, &store, .{});
    defer handler.deinit();

    // The exchange is otherwise well-formed: proof, params and binding all
    // check out. Only the embedded issue time sits past the window, so a
    // replayer cannot replay a week-old capture.
    var client = sasl.ScramClient.init(allocator, "alice", "pw");
    defer client.deinit();
    var sf: [512]u8 = undefined;
    var nb: [testkit.SNONCE_B64_LEN]u8 = undefined;
    const stale = std.time.timestamp() - handler.replay_window_seconds - 1;
    const ex = try testkit.scramV2Exchange(&handler, &client, 11, "10.0.0.11", "pw", testkit.mintSnonce(&nb, stale), &sf);
    try std.testing.expect(ex.verify_msg.? == .auth_failure);
    try std.testing.expectEqualStrings("not-authorized", ex.verify_msg.?.auth_failure.reason);
}

test "SCRAM v2: a future-dated server nonce beyond skew is refused" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "pw");
    var handler = TestHandler.init(allocator, &store, .{});
    defer handler.deinit();

    var client = sasl.ScramClient.init(allocator, "alice", "pw");
    defer client.deinit();
    var sf: [512]u8 = undefined;
    var nb: [testkit.SNONCE_B64_LEN]u8 = undefined;
    const future = std.time.timestamp() + handler.nonce_skew_seconds + 60;
    const ex = try testkit.scramV2Exchange(&handler, &client, 12, "10.0.0.12", "pw", testkit.mintSnonce(&nb, future), &sf);
    try std.testing.expect(ex.verify_msg.? == .auth_failure);
    try std.testing.expectEqualStrings("not-authorized", ex.verify_msg.?.auth_failure.reason);
}

test "SCRAM v2: a full probe window refuses the verify rather than evicting a live tag" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "pw");
    // Capacity equal to the probe window: every nonce's window covers the
    // whole table, so a full table is a full probe window by construction.
    var handler = TestHandler.init(allocator, &store, .{ .replay_capacity = REPLAY_PROBE });
    defer handler.deinit();

    const now = std.time.timestamp();
    var buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < REPLAY_PROBE) : (i += 1) {
        const nonce = std.fmt.bufPrint(&buf, "live-{d}", .{i}) catch unreachable;
        try replayInsert(TestUserStore, &handler, nonce, now);
    }

    // The next insert cannot evict a live tag: it refuses, and the tags it
    // would have displaced still read as consumed.
    const ninth = std.fmt.bufPrint(&buf, "live-{d}", .{REPLAY_PROBE}) catch unreachable;
    try std.testing.expectError(error.CacheFull, replayInsert(TestUserStore, &handler, ninth, now));
    try std.testing.expect(replaySeen(TestUserStore, &handler, "live-0", now));

    // At the verify level the refusal is temporary-auth-failure, counted.
    metrics.reset();
    var client = sasl.ScramClient.init(allocator, "alice", "pw");
    defer client.deinit();
    var sf: [512]u8 = undefined;
    var nb: [testkit.SNONCE_B64_LEN]u8 = undefined;
    const ex = try testkit.scramV2Exchange(&handler, &client, 13, "10.0.0.13", "pw", testSnonce(&nb), &sf);
    try std.testing.expect(ex.verify_msg.? == .auth_failure);
    try std.testing.expectEqualStrings("temporary-auth-failure", ex.verify_msg.?.auth_failure.reason);
    try std.testing.expectEqual(@as(u64, 1), metrics.counters.replay_refusals.load(.monotonic));
}

test "SCRAM: persisted fake secret is created once and stable across loads" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const first = try loadOrCreateSecret(tmp.dir);
    const second = try loadOrCreateSecret(tmp.dir);
    try std.testing.expectEqualSlices(u8, &first, &second);

    const stat = try tmp.dir.statFile(SECRET_FILE);
    try std.testing.expectEqual(@as(u64, 32), stat.size);
    try std.testing.expectEqual(@as(u32, 0o600), @as(u32, @intCast(stat.mode)) & 0o777);

    // The same secret yields identical fake credentials, so a fake salt is
    // as stable across daemon restarts as a real one.
    const a = fakeCredentials(&first, "mallory");
    const b = fakeCredentials(&second, "mallory");
    try std.testing.expectEqualSlices(u8, &a.salt, &b.salt);
    try std.testing.expectEqualSlices(u8, &a.stored_key, &b.stored_key);
    try std.testing.expectEqual(a.iteration_count, b.iteration_count);
}

test "SCRAM: advertised iteration count is identical for real and fake accounts" {
    const allocator = std.testing.allocator;

    var db = try MemoryBackend.open("", .{});
    defer db.close();
    var store = TestUserStore.init(&db);
    try store.addUser(allocator, "alice", "pw");
    var handler = TestHandler.init(allocator, &store, .{});
    defer handler.deinit();

    const real = handleSync(&handler, .{ .scram_params_request = .{
        .conn_id = 1,
        .username = "alice",
        .client_ip = "10.0.0.1",
    } }) orelse return error.NoResponse;
    const fake = handleSync(&handler, .{ .scram_params_request = .{
        .conn_id = 2,
        .username = "mallory",
        .client_ip = "10.0.0.2",
    } }) orelse return error.NoResponse;
    try std.testing.expect(real == .scram_params);
    try std.testing.expect(fake == .scram_params);
    try std.testing.expectEqual(real.scram_params.iteration_count, fake.scram_params.iteration_count);
    try std.testing.expectEqual(sasl.scram.default_iteration_count, fake.scram_params.iteration_count);
}
