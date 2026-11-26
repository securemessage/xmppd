//! # Auth test kit: shared helpers for the handler test files
//!
//! The memory-backed user store, the synchronous handleMessage driver, the
//! crypto-pool wake waiter, the IdP-delegating store, and the PLAIN payload
//! builders. Imported only by test code; production never reaches it.

const std = @import("std");
const sasl = @import("sasl");
const protocol = @import("ipc_protocol");
const backend_mod = @import("backend");
const user_store_mod = @import("user_store");
const crypto_pool_mod = @import("crypto_pool");
const handler_mod = @import("handler.zig");

pub const MemoryBackend = backend_mod.MemoryBackend;
pub const TestUserStore = user_store_mod.UserStore(MemoryBackend);
pub const TestHandler = handler_mod.AuthHandler(TestUserStore);
pub const TestCryptoPool = crypto_pool_mod.CryptoPool;

/// Move the verifier restart cutoff behind every current test nonce; the
/// boundary tests pin their own floors explicitly.
pub const test_handler_opts: TestHandler.InitOpts = .{ .nonce_floor_seconds = 1 };

/// Test helper: drive the synchronous variant of handleMessage.
pub fn handleSync(handler: anytype, msg: protocol.Message) ?protocol.Message {
    return switch (handler.handleMessage(msg, 0, 1)) {
        .reply => |m| m,
        .deferred, .none => null,
    };
}

/// Wait for the pool's completion wake byte. The read end is non-blocking.
pub fn waitForPoolWake(pool: *TestCryptoPool) !void {
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
/// capabilities.validate_password/validate_token admit paths compile
/// and run (the local UserStore never reaches them).
pub const TestIdpStore = struct {
    pub const capabilities = .{
        .validate_password = true,
        .validate_token = true,
    };

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
pub const TestIdpHandler = handler_mod.AuthHandler(TestIdpStore);

pub fn plainPayload(buf: []u8, user: []const u8, pass: []const u8) []const u8 {
    buf[0] = 0;
    @memcpy(buf[1 .. 1 + user.len], user);
    buf[1 + user.len] = 0;
    @memcpy(buf[2 + user.len .. 2 + user.len + pass.len], pass);
    return buf[0 .. 2 + user.len + pass.len];
}

pub fn plainRequest(conn_id: u32, ip: []const u8, payload: []const u8) protocol.Message {
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

/// Buffer length for a minted server nonce (b64).
pub const SNONCE_B64_LEN = sasl.scram.server_nonce_b64_len;

/// Mint a timed server nonce (v2 freshness layout) issued at `now`.
pub fn mintSnonce(buf: *[SNONCE_B64_LEN]u8, now: i64) []const u8 {
    return sasl.scram.mintServerNonce(buf, now);
}

/// Test helper: build the server-first-message exactly the way core does
/// under protocol v2 (ADR-6): combined nonce = client nonce + server nonce,
/// then the cached (salt, iterations).
pub fn serverFirst(buf: []u8, client_nonce: []const u8, server_nonce_b64: []const u8, salt: []const u8, iterations: u32) []const u8 {
    const encoder = std.base64.standard.Encoder;
    var salt_b64: [64]u8 = undefined;
    const enc = encoder.encode(salt_b64[0..encoder.calcSize(salt.len)], salt);
    var fbs = std.io.fixedBufferStream(buf);
    fbs.writer().print("r={s}{s},s={s},i={d}", .{ client_nonce, server_nonce_b64, enc, iterations }) catch unreachable;
    return fbs.getWritten();
}

/// One driven v2 exchange against the handler: params lookup (as core does
/// on a cache miss), server-first build, client-final, scram_verify. The
/// caller keeps client parsed fields for assertions.
pub const V2Exchange = struct {
    first: @import("sasl").scram.ClientFirst,
    server_first: []const u8,
    params_msg: ?protocol.Message,
    verify_msg: ?protocol.Message,
};

pub fn scramV2Exchange(
    handler: anytype,
    client: anytype,
    conn_id: u32,
    client_ip: []const u8,
    password: []const u8,
    server_nonce_b64: []const u8,
    sf_buf: []u8,
) !V2Exchange {
    const cf = try client.clientFirst();
    const first = try sasl.scram.parseClientFirst(cf);

    var ex = V2Exchange{
        .first = first,
        .server_first = "",
        .params_msg = null,
        .verify_msg = null,
    };

    ex.params_msg = handleSync(handler, .{ .scram_params_request = .{
        .conn_id = conn_id,
        .username = first.raw_name,
        .client_ip = client_ip,
    } });
    const params = ex.params_msg orelse return error.NoResponse;
    if (params != .scram_params) return error.UnexpectedReply;

    ex.server_first = serverFirst(sf_buf, first.client_nonce, server_nonce_b64, params.scram_params.salt, params.scram_params.iteration_count);
    try client.parseServerFirst(ex.server_first);
    var salted: [32]u8 = undefined;
    sasl.scram.pbkdf2(password, client.salt_raw[0..client.salt_raw_len], client.iteration_count, &salted);
    const final = try client.clientFinal(salted);

    ex.verify_msg = handleSync(handler, .{ .scram_verify = .{
        .conn_id = conn_id,
        .client_ip = client_ip,
        .cb_type = 0,
        .cb_data = "",
        .gs2_flag = first.gs2_flag,
        .client_first_bare = first.bare,
        .server_first = ex.server_first,
        .client_final = final,
    } });
    return ex;
}
