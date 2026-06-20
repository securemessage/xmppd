//! # JWT — JSON Web Token parser + RS256 signature verification
//!
//! Minimal JWT library for OIDC token validation. Supports:
//! - JWT structure parsing (header.payload.signature)
//! - Base64url decoding
//! - RS256 (RSASSA-PKCS1-v1_5 with SHA-256) signature verification via OpenSSL EVP
//! - Claim extraction: exp, iss, aud, sub, preferred_username, kid
//!
//! Does NOT support: JWE (encrypted tokens), ES256, EdDSA, nested JWTs.
//! These can be added later if needed.

const std = @import("std");
const Allocator = std.mem.Allocator;

const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/rsa.h");
    @cInclude("openssl/bn.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/param_build.h");
    @cInclude("openssl/core_names.h");
});

pub const JwtError = error{
    InvalidFormat,
    InvalidBase64,
    InvalidJson,
    UnsupportedAlgorithm,
    SignatureVerificationFailed,
    TokenExpired,
    InvalidIssuer,
    InvalidAudience,
    OutOfMemory,
};

pub const JwtHeader = struct {
    alg: []const u8,
    kid: []const u8,
};

pub const JwtClaims = struct {
    sub: []const u8,
    iss: []const u8,
    aud: []const u8,
    exp: i64,
    preferred_username: []const u8,
    picture: []const u8,
};

/// A parsed (but not yet verified) JWT.
pub const Jwt = struct {
    header_b64: []const u8,
    payload_b64: []const u8,
    signature_b64: []const u8,
    header: JwtHeader,
    claims: JwtClaims,

    /// The signed portion (header.payload) for signature verification.
    signed_portion: []const u8,
};

/// Parse a JWT token string into its components.
/// Does NOT verify the signature — call verifyRs256() after parsing.
/// The returned Jwt borrows slices from the token string.
pub fn parse(token: []const u8) JwtError!Jwt {
    // Split on dots: header.payload.signature
    var dot1: ?usize = null;
    var dot2: ?usize = null;
    for (token, 0..) |ch, i| {
        if (ch == '.') {
            if (dot1 == null) {
                dot1 = i;
            } else if (dot2 == null) {
                dot2 = i;
            } else {
                return JwtError.InvalidFormat; // More than 2 dots
            }
        }
    }

    const d1 = dot1 orelse return JwtError.InvalidFormat;
    const d2 = dot2 orelse return JwtError.InvalidFormat;

    const header_b64 = token[0..d1];
    const payload_b64 = token[d1 + 1 .. d2];
    const signature_b64 = token[d2 + 1 ..];

    // Decode header JSON
    var header_buf: [512]u8 = undefined;
    const header_len = b64urlDecode(header_b64, &header_buf) orelse return JwtError.InvalidBase64;
    const header_json = header_buf[0..header_len];

    const header = parseHeader(header_json) orelse return JwtError.InvalidJson;

    // Decode payload JSON
    var payload_buf: [4096]u8 = undefined;
    const payload_len = b64urlDecode(payload_b64, &payload_buf) orelse return JwtError.InvalidBase64;
    const payload_json = payload_buf[0..payload_len];

    const claims = parseClaims(payload_json) orelse return JwtError.InvalidJson;

    return Jwt{
        .header_b64 = header_b64,
        .payload_b64 = payload_b64,
        .signature_b64 = signature_b64,
        .header = header,
        .claims = claims,
        .signed_portion = token[0..d2],
    };
}

/// Verify an RS256 JWT signature against an RSA public key (n, e in base64url).
/// Returns true if signature is valid, false otherwise.
pub fn verifyRs256(jwt: *const Jwt, n_b64: []const u8, e_b64: []const u8) bool {
    // Decode signature from base64url
    var sig_buf: [512]u8 = undefined;
    const sig_len = b64urlDecode(jwt.signature_b64, &sig_buf) orelse return false;
    const signature = sig_buf[0..sig_len];

    // Decode RSA modulus (n) and exponent (e)
    var n_buf: [4096]u8 = undefined;
    const n_len = b64urlDecode(n_b64, &n_buf) orelse return false;

    var e_buf: [16]u8 = undefined;
    const e_len = b64urlDecode(e_b64, &e_buf) orelse return false;

    // Build RSA public key via OpenSSL BIGNUM + EVP_PKEY
    const bn_n = c.BN_bin2bn(&n_buf, @intCast(n_len), null) orelse return false;
    defer c.BN_free(bn_n);

    const bn_e = c.BN_bin2bn(&e_buf, @intCast(e_len), null) orelse return false;
    defer c.BN_free(bn_e);

    // Create EVP_PKEY with RSA components
    const pkey_ctx = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_RSA, null) orelse return false;
    defer c.EVP_PKEY_CTX_free(pkey_ctx);

    if (c.EVP_PKEY_fromdata_init(pkey_ctx) != 1) return false;

    // Use OSSL_PARAM_BLD to set n and e
    const bld = c.OSSL_PARAM_BLD_new() orelse return false;
    defer c.OSSL_PARAM_BLD_free(bld);

    if (c.OSSL_PARAM_BLD_push_BN(bld, "n", bn_n) != 1) return false;
    if (c.OSSL_PARAM_BLD_push_BN(bld, "e", bn_e) != 1) return false;

    const params = c.OSSL_PARAM_BLD_to_param(bld) orelse return false;
    defer c.OSSL_PARAM_free(params);

    var pkey: ?*c.EVP_PKEY = null;
    if (c.EVP_PKEY_fromdata(pkey_ctx, &pkey, c.EVP_PKEY_PUBLIC_KEY, params) != 1) return false;
    defer if (pkey) |p| c.EVP_PKEY_free(p);

    if (pkey == null) return false;

    // Verify signature: SHA-256 digest of signed_portion, verified against RSA signature
    const md_ctx = c.EVP_MD_CTX_new() orelse return false;
    defer c.EVP_MD_CTX_free(md_ctx);

    if (c.EVP_DigestVerifyInit(md_ctx, null, c.EVP_sha256(), null, pkey) != 1) return false;
    if (c.EVP_DigestVerifyUpdate(md_ctx, jwt.signed_portion.ptr, jwt.signed_portion.len) != 1) return false;

    const verify_result = c.EVP_DigestVerifyFinal(md_ctx, signature.ptr, signature.len);
    return verify_result == 1;
}

/// Verify an EdDSA (Ed25519) JWT signature against a raw public key (x in base64url).
/// Returns true if signature is valid, false otherwise.
pub fn verifyEdDSA(jwt_token: *const Jwt, x_b64: []const u8) bool {
    // Decode signature from base64url (Ed25519 signatures are 64 bytes)
    var sig_buf: [128]u8 = undefined;
    const sig_len = b64urlDecode(jwt_token.signature_b64, &sig_buf) orelse return false;
    if (sig_len != 64) return false; // Ed25519 signatures are always 64 bytes
    const signature = sig_buf[0..sig_len];

    // Decode the raw Ed25519 public key (32 bytes)
    var key_buf: [64]u8 = undefined;
    const key_len = b64urlDecode(x_b64, &key_buf) orelse return false;
    if (key_len != 32) return false; // Ed25519 public keys are always 32 bytes

    // Create EVP_PKEY from raw Ed25519 public key
    const pkey = c.EVP_PKEY_new_raw_public_key(
        c.EVP_PKEY_ED25519,
        null,
        &key_buf,
        32,
    ) orelse return false;
    defer c.EVP_PKEY_free(pkey);

    // Ed25519 uses EVP_DigestVerify with NULL digest (pure signature scheme)
    const md_ctx = c.EVP_MD_CTX_new() orelse return false;
    defer c.EVP_MD_CTX_free(md_ctx);

    // Init with NULL md — Ed25519 doesn't use a separate hash
    if (c.EVP_DigestVerifyInit(md_ctx, null, null, null, pkey) != 1) return false;

    // Ed25519 uses the one-shot EVP_DigestVerify (not Update+Final)
    const verify_result = c.EVP_DigestVerify(
        md_ctx,
        signature.ptr,
        signature.len,
        jwt_token.signed_portion.ptr,
        jwt_token.signed_portion.len,
    );
    return verify_result == 1;
}

/// Validate token expiration. Returns error if expired.
pub fn validateExpiry(claims: *const JwtClaims) JwtError!void {
    const now = std.time.timestamp();
    if (claims.exp != 0 and now > claims.exp) {
        return JwtError.TokenExpired;
    }
}

/// Validate issuer claim.
pub fn validateIssuer(claims: *const JwtClaims, expected: []const u8) JwtError!void {
    if (!std.mem.eql(u8, claims.iss, expected)) {
        return JwtError.InvalidIssuer;
    }
}

/// Validate audience claim.
pub fn validateAudience(claims: *const JwtClaims, expected: []const u8) JwtError!void {
    if (claims.aud.len == 0) return; // No audience claim — skip validation
    if (!std.mem.eql(u8, claims.aud, expected)) {
        return JwtError.InvalidAudience;
    }
}

// ============================================================================
// Base64url decoding
// ============================================================================

/// Decode base64url (no padding) into output buffer. Returns decoded length or null.
pub fn b64urlDecode(input: []const u8, output: []u8) ?usize {
    if (input.len == 0) return 0;

    // Convert base64url alphabet to standard base64 with padding
    var padded_buf: [8192]u8 = undefined;
    const pad_count = (4 - input.len % 4) % 4;
    const padded_len = input.len + pad_count;
    if (padded_len > padded_buf.len) return null;

    for (input, 0..) |ch, i| {
        padded_buf[i] = switch (ch) {
            '-' => '+',
            '_' => '/',
            else => ch,
        };
    }
    for (input.len..padded_len) |i| {
        padded_buf[i] = '=';
    }

    const padded = padded_buf[0..padded_len];

    // Exact decoded size: (padded_len / 4) * 3 - padding bytes
    const exact_len = (padded_len / 4) * 3 - pad_count;
    if (exact_len > output.len) return null;

    std.base64.standard.Decoder.decode(output[0..exact_len], padded) catch return null;
    return exact_len;
}

// ============================================================================
// JSON claim extraction (minimal — no full JSON parser)
// ============================================================================

fn parseHeader(json: []const u8) ?JwtHeader {
    return JwtHeader{
        .alg = extractStringField(json, "\"alg\"") orelse "none",
        .kid = extractStringField(json, "\"kid\"") orelse "",
    };
}

fn parseClaims(json: []const u8) ?JwtClaims {
    return JwtClaims{
        .sub = extractStringField(json, "\"sub\"") orelse "",
        .iss = extractStringField(json, "\"iss\"") orelse "",
        .aud = extractStringField(json, "\"aud\"") orelse "",
        .exp = extractIntField(json, "\"exp\"") orelse 0,
        .preferred_username = extractStringField(json, "\"preferred_username\"") orelse
            extractStringField(json, "\"email\"") orelse "",
        .picture = extractStringField(json, "\"picture\"") orelse "",
    };
}

/// Extract a string value from a JSON object by key. Minimal — handles "key":"value" patterns.
fn extractStringField(json: []const u8, key: []const u8) ?[]const u8 {
    const key_pos = std.mem.indexOf(u8, json, key) orelse return null;
    const after_key = json[key_pos + key.len ..];

    // Skip ':'  and optional whitespace
    var i: usize = 0;
    while (i < after_key.len and (after_key[i] == ':' or after_key[i] == ' ' or after_key[i] == '\t')) : (i += 1) {}

    if (i >= after_key.len or after_key[i] != '"') return null;
    i += 1; // Skip opening quote

    const value_start = i;
    while (i < after_key.len and after_key[i] != '"') : (i += 1) {
        if (after_key[i] == '\\') i += 1; // Skip escaped char
    }

    if (i >= after_key.len) return null;
    return after_key[value_start..i];
}

/// Extract an integer value from a JSON object by key.
fn extractIntField(json: []const u8, key: []const u8) ?i64 {
    const key_pos = std.mem.indexOf(u8, json, key) orelse return null;
    const after_key = json[key_pos + key.len ..];

    // Skip ':' and whitespace
    var i: usize = 0;
    while (i < after_key.len and (after_key[i] == ':' or after_key[i] == ' ' or after_key[i] == '\t')) : (i += 1) {}

    if (i >= after_key.len) return null;

    const num_start = i;
    while (i < after_key.len and (after_key[i] >= '0' and after_key[i] <= '9')) : (i += 1) {}

    if (i == num_start) return null;
    return std.fmt.parseInt(i64, after_key[num_start..i], 10) catch null;
}

// ============================================================================
// Tests
// ============================================================================

test "b64urlDecode: basic" {
    var buf: [256]u8 = undefined;
    // "hello" in base64url is "aGVsbG8"
    const len = b64urlDecode("aGVsbG8", &buf).?;
    try std.testing.expectEqualStrings("hello", buf[0..len]);
}

test "b64urlDecode: with url-safe chars" {
    var buf: [256]u8 = undefined;
    // base64url uses - and _ instead of + and /
    // "test?>" in standard base64 is "dGVzdD4+" → base64url is "dGVzdD4-"
    // But let's just verify a known value with url-safe chars
    // "\xfb\xff\xfe" → standard b64 = "+//+" → base64url = "-__-"
    const len = b64urlDecode("-__-", &buf);
    try std.testing.expect(len != null);
    try std.testing.expectEqual(@as(usize, 3), len.?);
    try std.testing.expectEqual(@as(u8, 0xfb), buf[0]);
    try std.testing.expectEqual(@as(u8, 0xff), buf[1]);
    try std.testing.expectEqual(@as(u8, 0xfe), buf[2]);
}

test "parse: JWT structure" {
    // A minimal test JWT (header.payload.signature — signature won't verify without key)
    const header = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0"; // {"alg":"RS256","kid":"test-key"}
    const payload = "eyJzdWIiOiJhbGljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC5leGFtcGxlLmNvbSIsImV4cCI6OTk5OTk5OTk5OSwiYXVkIjoieG1wcGQiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGljZSJ9";
    const sig = "dGVzdA"; // "test" — won't verify but parses

    var token_buf: [1024]u8 = undefined;
    const token = std.fmt.bufPrint(&token_buf, "{s}.{s}.{s}", .{ header, payload, sig }) catch unreachable;

    const jwt = try parse(token);
    try std.testing.expectEqualStrings("RS256", jwt.header.alg);
    try std.testing.expectEqualStrings("test-key", jwt.header.kid);
    try std.testing.expectEqualStrings("alice", jwt.claims.sub);
    try std.testing.expectEqualStrings("https://auth.example.com", jwt.claims.iss);
    try std.testing.expectEqualStrings("xmppd", jwt.claims.aud);
    try std.testing.expectEqual(@as(i64, 9999999999), jwt.claims.exp);
    try std.testing.expectEqualStrings("alice", jwt.claims.preferred_username);
}

test "parse: invalid format" {
    try std.testing.expectError(JwtError.InvalidFormat, parse("no-dots"));
    try std.testing.expectError(JwtError.InvalidFormat, parse("one.dot"));
}

test "validateExpiry: not expired" {
    const claims = JwtClaims{ .sub = "", .iss = "", .aud = "", .exp = 9999999999, .preferred_username = "", .picture = "" };
    try validateExpiry(&claims);
}

test "validateExpiry: expired" {
    const claims = JwtClaims{ .sub = "", .iss = "", .aud = "", .exp = 1000000000, .preferred_username = "", .picture = "" };
    try std.testing.expectError(JwtError.TokenExpired, validateExpiry(&claims));
}

test "validateIssuer: match" {
    const claims = JwtClaims{ .sub = "", .iss = "https://auth.example.com", .aud = "", .exp = 0, .preferred_username = "", .picture = "" };
    try validateIssuer(&claims, "https://auth.example.com");
}

test "validateIssuer: mismatch" {
    const claims = JwtClaims{ .sub = "", .iss = "https://wrong.com", .aud = "", .exp = 0, .preferred_username = "", .picture = "" };
    try std.testing.expectError(JwtError.InvalidIssuer, validateIssuer(&claims, "https://auth.example.com"));
}

test "extractStringField: basic" {
    const json = "{\"sub\":\"alice\",\"iss\":\"https://auth.example.com\"}";
    try std.testing.expectEqualStrings("alice", extractStringField(json, "\"sub\"").?);
    try std.testing.expectEqualStrings("https://auth.example.com", extractStringField(json, "\"iss\"").?);
    try std.testing.expect(extractStringField(json, "\"nonexistent\"") == null);
}

test "extractIntField: basic" {
    const json = "{\"exp\":1234567890,\"iat\":1234567800}";
    try std.testing.expectEqual(@as(i64, 1234567890), extractIntField(json, "\"exp\"").?);
    try std.testing.expectEqual(@as(i64, 1234567800), extractIntField(json, "\"iat\"").?);
    try std.testing.expect(extractIntField(json, "\"nonexistent\"") == null);
}
