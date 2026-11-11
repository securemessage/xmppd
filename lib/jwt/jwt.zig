//! # JWT -- JSON Web Token parser + RS256 signature verification
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
    /// Display data only: email is never an identity claim (OIDC Core 5.7).
    email: []const u8 = "",
    email_verified: bool = false,
    picture: []const u8,
};

/// Caller-owned decode memory for parse(). The returned Jwt borrows these
/// buffers, so the DecodeBuffer must outlive every use of the parsed claims.
pub const DecodeBuffer = struct {
    header: [512]u8 = undefined,
    payload: [4096]u8 = undefined,
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
/// Does NOT verify the signature -- call verifyRs256() after parsing.
/// The returned Jwt borrows slices from `token` and `buf`; both must outlive it.
pub fn parse(token: []const u8, buf: *DecodeBuffer) JwtError!Jwt {
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
    const header_len = b64urlDecode(header_b64, &buf.header) orelse return JwtError.InvalidBase64;
    const header_json = buf.header[0..header_len];

    const header = parseHeader(header_json) orelse return JwtError.InvalidJson;

    // Decode payload JSON
    const payload_len = b64urlDecode(
        payload_b64,
        &buf.payload,
    ) orelse return JwtError.InvalidBase64;
    const payload_json = buf.payload[0..payload_len];

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
    // Decode signature from base64url. 1024 bytes covers RSA signatures
    // up to 8192 bits, the same bound as the modulus below.
    var sig_buf: [1024]u8 = undefined;
    const sig_len = b64urlDecode(jwt.signature_b64, &sig_buf) orelse return false;
    const signature = sig_buf[0..sig_len];

    // Decode RSA modulus (n) and exponent (e). 1024 bytes of decoded
    // modulus covers RSA keys up to 8192 bits.
    var n_buf: [1024]u8 = undefined;
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
    if (c.EVP_DigestVerifyUpdate(
        md_ctx,
        jwt.signed_portion.ptr,
        jwt.signed_portion.len,
    ) != 1) return false;

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

    // Init with NULL md -- Ed25519 doesn't use a separate hash
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
    if (claims.aud.len == 0) return; // No audience claim -- skip validation
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

    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = decoder.calcSizeForSlice(input) catch return null;
    if (decoded_len > output.len) return null;
    decoder.decode(output[0..decoded_len], input) catch return null;
    return decoded_len;
}

// ============================================================================
// JSON claim extraction (minimal -- no full JSON parser)
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
        .preferred_username = extractStringField(json, "\"preferred_username\"") orelse "",
        .email = extractStringField(json, "\"email\"") orelse "",
        .email_verified = extractBoolField(json, "\"email_verified\""),
        .picture = extractStringField(json, "\"picture\"") orelse "",
    };
}

/// Extract a string value from a JSON object by key. Minimal -- handles "key":"value" patterns.
fn extractStringField(json: []const u8, key: []const u8) ?[]const u8 {
    const key_pos = std.mem.indexOf(u8, json, key) orelse return null;
    const after_key = json[key_pos + key.len ..];

    // Skip ':'  and optional whitespace
    var i: usize = 0;
    while (i < after_key.len and
        (after_key[i] == ':' or after_key[i] == ' ' or after_key[i] == '\t')) : (i += 1)
    {}

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
    while (i < after_key.len and
        (after_key[i] == ':' or after_key[i] == ' ' or after_key[i] == '\t')) : (i += 1)
    {}

    if (i >= after_key.len) return null;

    const num_start = i;
    while (i < after_key.len and (after_key[i] >= '0' and after_key[i] <= '9')) : (i += 1) {}

    if (i == num_start) return null;
    return std.fmt.parseInt(i64, after_key[num_start..i], 10) catch null;
}

/// Extract a boolean claim value. Accepts the true literal and the "true"
/// string form; everything else (false, absent, other values) is false.
fn extractBoolField(json: []const u8, key: []const u8) bool {
    const key_pos = std.mem.indexOf(u8, json, key) orelse return false;
    const after_key = json[key_pos + key.len ..];

    var i: usize = 0;
    while (i < after_key.len and (after_key[i] == ':' or after_key[i] == ' ' or after_key[i] == '\t')) : (i += 1) {}

    const rest = after_key[i..];
    if (rest.len >= 4 and std.mem.eql(u8, rest[0..4], "true")) return true;
    if (rest.len >= 6 and std.mem.eql(u8, rest[0..6], "\"true\"")) return true;
    return false;
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
    // "\xfb\xff\xfe" → standard b64 = "+//+" → base64url = "-__-"
    const len = b64urlDecode("-__-", &buf);
    try std.testing.expect(len != null);
    try std.testing.expectEqual(@as(usize, 3), len.?);
    try std.testing.expectEqual(@as(u8, 0xfb), buf[0]);
    try std.testing.expectEqual(@as(u8, 0xff), buf[1]);
    try std.testing.expectEqual(@as(u8, 0xfe), buf[2]);
}

test "b64urlDecode: strict base64url -- padding and standard alphabet rejected" {
    var buf: [256]u8 = undefined;
    // RFC 7515 segments are unpadded base64url: '=' never appears, and the
    // standard-alphabet '+' and '/' are not the '-' and '_' the wire uses.
    try std.testing.expect(b64urlDecode("aGVsbG8=", &buf) == null);
    try std.testing.expect(b64urlDecode("aGVsbG8==", &buf) == null);
    try std.testing.expect(b64urlDecode("+//+", &buf) == null);
    try std.testing.expect(b64urlDecode("aGVs+bG8", &buf) == null);
    try std.testing.expect(b64urlDecode("aGVs/bG8", &buf) == null);

    // parse() applies the same strictness: a padded header segment is a
    // malformed token, not a tolerated variant.
    var decode: DecodeBuffer = undefined;
    try std.testing.expectError(
        JwtError.InvalidBase64,
        parse("eyJhbGciOiJSUzI1NiJ9=.eyJzdWIiOiJhIn0.c2ln", &decode),
    );
}

test "parse: JWT structure" {
    // A minimal test JWT (header.payload.signature -- signature won't verify without key)
    // {"alg":"RS256","kid":"test-key"}
    const header = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0";
    const payload = "eyJzdWIiOiJhbGljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC5leGFtcGxlLmNvbSIs" ++
        "ImV4cCI6OTk5OTk5OTk5OSwiYXVkIjoieG1wcGQiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGljZSJ9";
    const sig = "dGVzdA"; // "test" -- won't verify but parses

    var token_buf: [1024]u8 = undefined;
    const token = std.fmt.bufPrint(
        &token_buf,
        "{s}.{s}.{s}",
        .{ header, payload, sig },
    ) catch unreachable;

    var decode: DecodeBuffer = undefined;
    const jwt = try parse(token, &decode);
    try std.testing.expectEqualStrings("RS256", jwt.header.alg);
    try std.testing.expectEqualStrings("test-key", jwt.header.kid);
    try std.testing.expectEqualStrings("alice", jwt.claims.sub);
    try std.testing.expectEqualStrings("https://auth.example.com", jwt.claims.iss);
    try std.testing.expectEqualStrings("xmppd", jwt.claims.aud);
    try std.testing.expectEqual(@as(i64, 9999999999), jwt.claims.exp);
    try std.testing.expectEqualStrings("alice", jwt.claims.preferred_username);
}

/// Overwrite an 8 KiB stack frame so any claim slice that borrowed a dead
/// parse()-local buffer reads back 'Z' instead of the original claim bytes.
/// noinline so the frame cannot be folded into the caller's.
noinline fn smashStack() void {
    var buf: [8192]u8 = undefined;
    @memset(&buf, 'Z');
    std.mem.doNotOptimizeAway(&buf);
}

test "parse: claims stay valid after the call returns" {
    const header = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0";
    const payload = "eyJzdWIiOiJhbGljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC5leGFtcGxlLmNvbSIs" ++
        "ImV4cCI6OTk5OTk5OTk5OSwiYXVkIjoieG1wcGQiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGljZSJ9";
    const sig = "dGVzdA";

    var token_buf: [1024]u8 = undefined;
    const token = std.fmt.bufPrint(
        &token_buf,
        "{s}.{s}.{s}",
        .{ header, payload, sig },
    ) catch unreachable;

    // The caller owns the decode memory; clobbering the stack afterwards
    // must not touch it.
    var decode: DecodeBuffer = undefined;
    const jwt = try parse(token, &decode);

    smashStack();

    try std.testing.expectEqualStrings("alice", jwt.claims.sub);
    try std.testing.expectEqualStrings("https://auth.example.com", jwt.claims.iss);
    try std.testing.expectEqualStrings("alice", jwt.claims.preferred_username);
}

test "parse: email is never merged into preferred_username" {
    const header = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0";
    // {"sub":"s1","iss":"https://idp.example","exp":9999999999,"email":"victim@example.com","email_verified":true}
    const payload = "eyJzdWIiOiJzMSIsImlzcyI6Imh0dHBzOi8vaWRwLmV4YW1wbGUiLCJleHAiOjk5OTk5OTk5OTksImVtYWlsIjoidmljdGltQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWV9";
    const sig = "dGVzdA";

    var token_buf: [1024]u8 = undefined;
    const token = std.fmt.bufPrint(&token_buf, "{s}.{s}.{s}", .{ header, payload, sig }) catch unreachable;

    var decode: DecodeBuffer = undefined;
    const parsed = try parse(token, &decode);

    try std.testing.expectEqualStrings("", parsed.claims.preferred_username);
    try std.testing.expectEqualStrings("victim@example.com", parsed.claims.email);
    try std.testing.expect(parsed.claims.email_verified);
}

test "parse: email_verified absent and false stay false" {
    const header = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0";
    // {"sub":"s2","iss":"https://idp.example","exp":9999999999,"email":"mallory@example.com","email_verified":false}
    const payload = "eyJzdWIiOiJzMiIsImlzcyI6Imh0dHBzOi8vaWRwLmV4YW1wbGUiLCJleHAiOjk5OTk5OTk5OTksImVtYWlsIjoibWFsbG9yeUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZX0";
    const sig = "dGVzdA";

    var token_buf: [1024]u8 = undefined;
    const token = std.fmt.bufPrint(&token_buf, "{s}.{s}.{s}", .{ header, payload, sig }) catch unreachable;

    var decode: DecodeBuffer = undefined;
    const parsed = try parse(token, &decode);

    try std.testing.expectEqualStrings("mallory@example.com", parsed.claims.email);
    try std.testing.expect(!parsed.claims.email_verified);
}

test "parse: invalid format" {
    var decode: DecodeBuffer = undefined;
    try std.testing.expectError(JwtError.InvalidFormat, parse("no-dots", &decode));
    try std.testing.expectError(JwtError.InvalidFormat, parse("one.dot", &decode));
}

test "validateExpiry: not expired" {
    const claims = JwtClaims{
        .sub = "",
        .iss = "",
        .aud = "",
        .exp = 9999999999,
        .preferred_username = "",
        .picture = "",
    };
    try validateExpiry(&claims);
}

test "validateExpiry: expired" {
    const claims = JwtClaims{
        .sub = "",
        .iss = "",
        .aud = "",
        .exp = 1000000000,
        .preferred_username = "",
        .picture = "",
    };
    try std.testing.expectError(JwtError.TokenExpired, validateExpiry(&claims));
}

test "validateIssuer: match" {
    const claims = JwtClaims{
        .sub = "",
        .iss = "https://auth.example.com",
        .aud = "",
        .exp = 0,
        .preferred_username = "",
        .picture = "",
    };
    try validateIssuer(&claims, "https://auth.example.com");
}

test "validateIssuer: mismatch" {
    const claims = JwtClaims{
        .sub = "",
        .iss = "https://wrong.com",
        .aud = "",
        .exp = 0,
        .preferred_username = "",
        .picture = "",
    };
    try std.testing.expectError(
        JwtError.InvalidIssuer,
        validateIssuer(&claims, "https://auth.example.com"),
    );
}

test "extractStringField: basic" {
    const json = "{\"sub\":\"alice\",\"iss\":\"https://auth.example.com\"}";
    try std.testing.expectEqualStrings("alice", extractStringField(json, "\"sub\"").?);
    try std.testing.expectEqualStrings(
        "https://auth.example.com",
        extractStringField(json, "\"iss\"").?,
    );
    try std.testing.expect(extractStringField(json, "\"nonexistent\"") == null);
}

test "extractIntField: basic" {
    const json = "{\"exp\":1234567890,\"iat\":1234567800}";
    try std.testing.expectEqual(@as(i64, 1234567890), extractIntField(json, "\"exp\"").?);
    try std.testing.expectEqual(@as(i64, 1234567800), extractIntField(json, "\"iat\"").?);
    try std.testing.expect(extractIntField(json, "\"nonexistent\"") == null);
}

// Real RSA keys (public modulus only) and tokens they signed, generated
// once with openssl for this test. Signatures above 4096 bits are longer
// than the old 512-byte sig_buf, so the two larger cases only verify with
// the widened buffer.
const rs_t4096 =
    "eyJhbGciOiJSUzI1NiIsImtpZCI6Ims0MDk2IiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImlzcyI6Imh0" ++
    "dHBzOi8vaWRwLmV4YW1wbGUvIiwiYXVkIjoieG1wcGQiLCJleHAiOjQxMDI0NDQ4MDB9.GNl1yts_EfdCgiMatnW" ++
    "f2mxuZo-" ++
    "N9pqvC7PvCfg_lvX3iQBmgREhmbIVV3vOiPzxVj0gowHTRK86yICPL5goY8SWo88toAbvH_Z_jagntJxNjV2tAcn" ++
    "8_GvTe55Ci4R8aafQljwDayOVbdAlgXo4H4KFIue5xrxBUTv5G6mOW92iVvwsVUo0M_-" ++
    "sSWWcZZU6NODhs3OeFQsi2ZsqRnrfNN_ajihJjkWotQCQQ-xBDRbMQys-kmw5QCLoyS-3fWtmn-dM5ebZJn7ZqR1" ++
    "9j4wt3N-" ++
    "GehZlu7YIA8_qSV9jQHrgkp6SFgO_PxP2BStnG00lBbn9cYN0lK4yAXW7oqSavjPUtaLAi0KtdWMBt7zsnE8-" ++
    "sTyZSDGSlM_o8N1WpnYTIxkg9B3FoSvLzu8-" ++
    "cIt_Ne7ZAwl8rJAKgsm2GCG4IbPcKmql1XeXhac5Wpi8bp_x9pKCNKZb-" ++
    "edxhm5z7mBfA2Xvoe8cvvt8OX6Yeg2wOAHQguGmfxMlGYkLfoooWXcxw20woq7m1i2npU3ky2qqKP-C_PjGd2QQo" ++
    "2F3HGOHt0OsxuZQ0LqWbo3Krcn0RUVH9ehewD4AqZKgcqgB9MqBUHY6J6PxU2Vfrjy3N0Y1vDdfD14JJhRPWnaoE" ++
    "5hpz7ENRLFUlos9DUbzA0pRGumDiZ-2Ku8btTK9ZfeV_RnnqVs";

const rs_n4096 =
    "i_ARz2bpwBTsJAFetoeIUeu-Z-" ++
    "tVFfXdaIWsQjSFz94BMywErYb74JyfivzzryqykAZP8GyEKE91vehXuKvrjRdAZRGAgalhAmNNez-ZGu6b7jc4Ry" ++
    "4gFTqR9cpkimZ0-" ++
    "o32BsdAb1HZxGjHrFv6OsoFml3g2CjOwWECZeOBHsXaK6Op9PHKZAjuS0LA2dixwziHyPNT0AV8eq3SnucTRrGWN" ++
    "A-8Ro4xF6YgTcxC6xAc1ldMRo4sNdz0bUskie4vDcgYqVEixs2XcSNO44h2m2rUtlStZ4My39-" ++
    "P3r_oFLjlZqm4JmQagLBQQE4_w6diUz6GSs0NZLSgIcsZAnqe-wHEqwHW48U6yKWmPV35gZt12NAx-" ++
    "x3H1biaCRcvE730eIvNaG7pFYr3B7dHagKpPUh3tCP0FTIneqtIVps11YFvQlHyjUP49EzUWd66PVyjIzMZiPZMU" ++
    "qNcqKK_aDHxg06PeTneCj37Fkzq4NNyRLiwKn7Pr_k1Q2CM7K7o4n5jkh8cmkCPMyhibQgXZugfTqXcRrK-" ++
    "mjo2nWNHcuwJtqP0iuhbGS5ipsp3wZ6H8pz460DSzYcp_y2qx9BFEJ1ze6ZLPGOxNxVvcPsOVgX-" ++
    "moBEJgWSBSPthjqKGGHxanthDFh0oxUl-EivZf287TLa8O62OgMhG_8HegWv5iQHc7s";

const rs_t6144 =
    "eyJhbGciOiJSUzI1NiIsImtpZCI6Ims2MTQ0IiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImlzcyI6Imh0" ++
    "dHBzOi8vaWRwLmV4YW1wbGUvIiwiYXVkIjoieG1wcGQiLCJleHAiOjQxMDI0NDQ4MDB9.lX4dSdJXF8a80qVgPZk" ++
    "NYonRIn8FJjAmscqLynQbtIEgcEiWca3_At9TCETmVWe2HYoo7HlreAxonHEiLDJXa3ee0ImsTP658y65L6dlyvs" ++
    "m97iBzY36t1G2U1YTRKWlYECzBWUaO72G0DWdF77q1YYcH76eQ_YbXJKaSOl6hZCO4DkbDWlPso9WGzZAhKV6DhX" ++
    "ctUzHJgku9JS-e3-kQrAvvjcq6BHALS-" ++
    "3l3BwWQiXT8kq7RXmV5h6SMNw1hUYXvxZZkZYqmq3eVzrzMeuj9Bw4TLM4dlqwQYICaQ8Fxd_5jsQDqmJ1qTHKCM" ++
    "9hc0jd8u-uTfGkBOnqEoqIxWr2KD8DtrLa38HvqEuDBltYEyl9RiltwZvNU95zrzI5odaZt0EKTQwffo-" ++
    "cTthUwpjxtJHFiP_PYPp4MYmuJoN4ROYwf-QmxbBzcMzXK8ELTjeIOHnCPGd4AGjdOg0KqGoagqdRtObIvQKgkpW" ++
    "10YiBkIJnFo4hK9sq6UUj1ge_wrMiyc3q5Epe9zZ8FFzCUtlqIyLS83_TwA7BkMfveIhzOCTKKNwqfZXvbmpF_vX" ++
    "JCBzxzXrFokjnuT3nROfJOawe0uObwQFAbcDkU3K-" ++
    "oBIj9fcm5UyTTjyEVkyZ8Te99wuK4hXgeDYF_UZsdGhb9N94KedEJKC-" ++
    "a4d1IPETMh_FkkFQ3evdqY0R4HdtrCtnOpekm7wApJJBIQgWbPkclfHolB-KRqEN3Ep9tq_FW5LvnUPYWC-" ++
    "nAx7duW0pDu-OnQHldyns_7Ns3Q8rul8_Iy_MMjtXypa0HDe02_nhnGan_ZcajkbXxowldlVO9fChnFjxc9IAayc" ++
    "1EAHCRYjsBsJzBldYHSAk_m1ur67sUec2NER8hC8QooWlT2vBCRDvw1K-" ++
    "XzS0lXEf8kzwo5dchKvS9t5dbwN6ih4Ndim-CwAvJ5PTyftoMH0tNmalnwP1lSePgURQuQPRXYUtxJ90veO5zqw9" ++
    "xDzBxQRJv0oKKH9THDKC1Zbp_1hthKZIVjUT5ha";

const rs_n6144 =
    "xVF5Gj4Q-f034VsiWKTEl7SpzqGZpVtW_uC3v9DaKHbfnkvfiy5Tx4jv4qXN5xum-" ++
    "afAJdqIXYfIUaYVRqvYEagcpR9a0S9TqWHKtBKOInoWiF8Kc7IxQN6cgB2bVQYsjajjPHvM-dAEY9gpe8D5h4PjB" ++
    "GzbTfhKTAbiFsIKR6uMqYVBS9U9MJiYUNDKAOSQl2nLdESIwBXbgF7XKm1JGL6zpzVf2O3shhWZg-" ++
    "0uOpldEGy3D7t85GIHUG8nOAg7r8tGUVzCp18WgJLSZs9JF0A2WesnYJ7H_c8xyUeayrItWIgKLtjrRIk8CY6gS0" ++
    "Ew-fPCIrplwesYBCW9OIPT6aT0t6bBzXm7OgFsGXIT6p0k1-" ++
    "wbZiBOOV3fvYUE3wWUOkisq8MDls_Gumz0F1mM6asiveTPPKVyUbNusCihkyG1gklbZnXUacnYvQ5gYwPNEEOnjC" ++
    "Nii3QClf92yfZjAn6hWVKrjqRzOHpHb8K34gb658cV6y7H72zgVkQLWbeaDUu1ussOxl3lwVGkNzFyGzyz9Ft7al" ++
    "xf13xqusexEhXzHayAwbD5YK_8oNe5PGAPO4KeQMEQxVueoj74Xrew90uwiq2pw3RH9bxqdJDB8zSb0zH-" ++
    "IS4fPICXYn_1UvF63AodiQEGYfXyDiKrElDo7LV1i4C5gkVZBJeHf3cFYvLcyLBX7vginI-AEMcgtGumryEvYOCL" ++
    "fKksjsHerbyKkt7mAAPYIH0n6f34jQD_xY5C_BrHkdKhwJbLWxUC194UhM4q3zWQH1q08S7xnHvVFDwitMUoU2vK" ++
    "uVf_Fv7Tu8TjDa5ST0TTjE51ea-_K1_8gG-" ++
    "QiokGvuuwT2xDdKj0deYI5KQFAPQA2vmNMmz4wcxRxW8KzQFfJ0S-5fKL8re4G1--h8Ym0E5D_jZyzwTw81e2TjL" ++
    "db8WHk_Azpt5WKaNVDQO8ANQmSemLdVL_Lja7rzZR15SvIR0YWusPVeowXJ4kUbWuWU0AjqxSQxBwI8R_0ZOPqqB" ++
    "MsP_jg8k9uUGJ";

const rs_t8192 =
    "eyJhbGciOiJSUzI1NiIsImtpZCI6Ims4MTkyIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImlzcyI6Imh0" ++
    "dHBzOi8vaWRwLmV4YW1wbGUvIiwiYXVkIjoieG1wcGQiLCJleHAiOjQxMDI0NDQ4MDB9.FhVlGLUVw8lvXnazV1F" ++
    "U70Ku_Fj8QjYUVVG-HOYrXI3_EwIsB4PyW0pGjuiciSg1MbAM4JyXaxv9KrM7uh7xaKwQG61s-a9Kq-" ++
    "6AmL8M7AH9wiL9xl2R_RxrT91MxxewiQScx9WMxVRTm6yt_QUYoWaTktLZ_5OifOvleGxLM6MDKswpLVz72ba88c" ++
    "bH9NYQSCwP3r5cXmXOzYnISnZyRQDsN7U_xNj8oz4A6fIX4mNkg2Quxx1Jj1i0aqJgVYL92KPYeifqsK9a3lNoxt" ++
    "Wn9h4_C2HMqknOCgYuh4n04bwF5ViBJxFsbranlxRnllWskXCpk8E4AN9znfc2KjI4G7dBr_8FY0wIACemkx0d27" ++
    "BwdI_tA2OINKLnQQg6WcWSw_s104Cjwj9WtDanf_jVSgaao0aVbJs7Cqkag0vDu4f5O_F6MqBUgtashxkBnGZ9yh" ++
    "FGyuyYf2BMRYH6EAM756JtMlhnKrT4hAvnrvV-" ++
    "9W_v8_QzVeJRJ2BY7DSIygZuvHxjv_Qbctv4vOdb69AFJ7aCLw3Mhl7WhPHcQYZAXPhHA-" ++
    "1E86W63Xmd5qbnvCMkmWRp3HcimYH1J700Qh5oFxSQxXXJxWPWAzl9B5D0z8zmneMafzt8bEel4TIZVmotl9BJIh" ++
    "OKJ7h7gUdCEwqxqeNNRoJHoKnW9MPUEYVpG_R9koBCPjHc4tT-VUvTAWHe7M-" ++
    "Kc8OHZHE5bakXkUodslGadW0C9qwCyPuDTBDlWW_fTEweqqYtN2gnZdI_TGncDbwaB3nTJW2hkM29cBbIjqcqptO" ++
    "fHsw4HEJq1FCy9qX_4CYAj2IimW6_rGc9i4NQV1JxD8S2EPXUffRS3LrsxD9e8fqv80uxfcL9EwjueiCeabFlr5d" ++
    "Tr3E46hinypugwkyzRc4nWuc92LmliFEWHYRvyeeG3uoMMvg9Y1onHdNJWSNOeU7un9IHkLntfuUWJ3aG5-" ++
    "0HGyYyQpPnXX1URjXlFvqXxPOsWsFxsHfHBN8OyB1NRqm3CIN6cBE4CXasosE20rQoZiWULbTvvTVPsba6w80PRo" ++
    "r9goJtdHsWhZT5eKPFAptttt1TQjoQCMpggSTuVT21-" ++
    "wNhEyf95Es_4IofJCIXKfb5hXgaUCrbmD_Zrn8w63JpzEKpQch4tJmyk5xZXYD9_n2hz24MD-TO096V8x9UaQuNL" ++
    "lmGm2PYs4pmwr7bN-" ++
    "7Wl6XXqGn47EVQo_al4BFYMp8X6EEEtIXmYjKJgtaKbSVjHhx1PhEztcNHbUpR_wQ5jx38tPP_-zJ9ZsCCN3XWL1" ++
    "LiQGoEz2TM6cjGLvgnUgrxUBKikfki2E6UlJgnKXQxKticH1zLILnsEj-92FzHksGkd7vrhiNo5A";

const rs_n8192 =
    "yfFmrIBMqnyi8hsEwGSC0YOAEJesFTC8Vp_dJkTmBxZwTE5p3x-_ei8RLxc9DuDaOlZe40SrnFrV-" ++
    "2WhBp_Y7552KXnN__3-Fj8GTddwcH8iH4KqQ6Fc-3sDXGTW3fBqZVG1TrZGDaRRs-ZbCBeqQaGp4BxsStWulY3KP" ++
    "s9gIj2x7F8z9jSlpZqCsijK3TRMR3DiGgRdV7Jy2Kgqq_A7syM7HPcwlkN30g3LMVtza20ytu8anXUkJ1G96o6Ie" ++
    "LeEbujDfmSGpMGwlCV1RKMADL7Fu810GaC4hpmZKs_KvUj5Cpniala8v9PepRiRRUS_feRSjoKoS04s05a8rtXja" ++
    "SLTaapiZnmnBTwcP3qfI7AWQ7vgN-OsSjSK7TdYT1zND6PSbe1KkdxxZEt_rSXYGLTpMkoqsqaLr37yyEbQ04Ydv" ++
    "OnT1OxrXfjWqBqMQshP8RuCkNcjd1-YnZg4AKkZqsGrh1fITFQuufxlm6rPu0mzHSwt_5d56BuB0ht8q-" ++
    "cTHMyKuAH1vO30n5ZRzVhl4_5jzyOgdo9n9AU-18iPmSg1DLhOqi-L0UP1095S3RvJMNPgM3UNvEWk-" ++
    "L_BnJ5GC-1gx5mKbwoi0feR57ervwohdun7uLT2Z0NT_QH7VfWT0KRnNje2RxUVPEwZQ-qdsORa09x_axh1Zd4Ip" ++
    "oSyqoXZ0rtuYDCxX3E8chNKMNuJ4XTs2lycYB2dvwNlmCDdjso54P7_OI-5O6Nrb3cmxN4-" ++
    "Zj3KUwYJNbz_mab3cVKL1W8cfEhblegY0cZ3Qh8066jY50VXaNQs_yF1xpV4hE0fCWUhTUITprGqkIOKNYXt_qzA" ++
    "es5KfAZZOutN2y_OeL5ueXLL6xmOiWSCfumaEc_mQmhcGSCBtoqdlWJzh2HlPgs7UUNQe7ro2rz_O2ebW090gWg6" ++
    "lyi18Ms2jD1X5gpnjACKOgEwSeW8gDTPYrXKc_d7v_3D_gTz0EIywFJOjrHQsDXP-0-EPly_y-TqJubniSaDZGjK" ++
    "DTzim0zq9yn6AnoJ5Dr0WNzLMTf7Fh1tNVE4u5QOovn8PSqxF3cFy36zjpsk_t7nFnO5_JWozIblu9o3reg1Lhiq" ++
    "Uy3iTK7nZzrslHiUfAqnUCinvnvmQIFtx10qdQqDkiEjZHWqHCX3NLrLHqGiX4DGE2nEt8zNoo2TmDrjBH07yOS1" ++
    "Em0oTNk3kND3sjQ-RlQZJavSokzsH28hQkSw40SjngqZGpBzY1fQ5rJfFihV3k3MjOAxeXwKfIVz87sG_-" ++
    "U7zYoz_mqv5d85m_Iybky20Q14y82h--" ++
    "2A1SRcSOrz_fm4TuK_k0N1T_HHAAkolNOxd9Vy0fbCsyop-0Ce20QZBdTzecImkQ";
test "verifyRs256: real 4096, 6144 and 8192-bit signatures verify" {
    const Case = struct { token: []const u8, n: []const u8 };
    const cases = [_]Case{
        .{ .token = rs_t4096, .n = rs_n4096 },
        .{ .token = rs_t6144, .n = rs_n6144 },
        .{ .token = rs_t8192, .n = rs_n8192 },
    };
    for (cases) |case| {
        var decode: DecodeBuffer = undefined;
        const parsed = try parse(case.token, &decode);
        try std.testing.expect(verifyRs256(&parsed, case.n, "AQAB"));
    }
    // A token checked against the wrong key must still fail.
    var decode: DecodeBuffer = undefined;
    const parsed = try parse(rs_t4096, &decode);
    try std.testing.expect(!verifyRs256(&parsed, rs_n8192, "AQAB"));
}
