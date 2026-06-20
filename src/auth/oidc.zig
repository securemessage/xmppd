//! # OidcStore — OIDC/OAuth2 authentication backend
//!
//! Implements token validation (OAUTHBEARER) and password delegation (PLAIN → ROPC)
//! against an external Identity Provider. Used by xmppd-auth-oidc.
//!
//! ## Features
//!
//! - JWKS key cache with refresh-on-kid-miss
//! - JWT validation (RS256, exp, iss, aud)
//! - ROPC (Resource Owner Password Credentials) grant delegation
//! - Username extraction from configurable claim (preferred_username or email)
//!
//! ## Store Interface
//!
//! Provides `lookup`, `validateToken`, and `validatePassword` — the AuthHandler
//! uses `@hasDecl` at comptime to route OAUTHBEARER and PLAIN accordingly.

const std = @import("std");
const Allocator = std.mem.Allocator;
const http = @import("http");
const jwt = @import("jwt");

const log = std.log.scoped(.oidc_store);

pub const OidcConfig = struct {
    /// OIDC issuer URL (must match token `iss` claim).
    issuer: []const u8,
    /// OAuth2 client_id (audience check).
    client_id: []const u8,
    /// OAuth2 client_secret (for ROPC grant).
    client_secret: []const u8,
    /// Token endpoint URL (for ROPC grant).
    token_endpoint: []const u8,
    /// JWKS endpoint URL (for key fetching).
    jwks_uri: []const u8,
    /// Introspection endpoint URL (for opaque token validation, optional).
    introspection_endpoint: ?[]const u8 = null,
    /// CA file for TLS verification (null = system default).
    ca_file: ?[]const u8 = null,
    /// Claim to extract username from (default: preferred_username, fallback: email).
    username_claim: []const u8 = "preferred_username",
    /// Domain to append to bare usernames for ROPC (e.g., "morante.dev" → alice@morante.dev).
    user_domain: ?[]const u8 = null,
};

/// Cached JWK key (supports RSA and EdDSA/OKP).
const JwkKey = struct {
    kid: []const u8,
    kty: KeyType,
    // RSA fields
    n: []const u8 = "",
    e: []const u8 = "",
    // EdDSA (OKP) field
    x: []const u8 = "",
};

const KeyType = enum { rsa, okp };

/// Maximum number of cached JWKS keys.
const MAX_JWKS_KEYS = 16;

/// JWKS cache max age in seconds (1 hour).
const JWKS_MAX_AGE_SECONDS: i64 = 3600;

pub const OidcStore = struct {
    config: OidcConfig,
    allocator: Allocator,

    /// Cached JWKS keys.
    keys: [MAX_JWKS_KEYS]JwkKey = undefined,
    key_count: usize = 0,

    /// Raw JWKS response body (owns key slice memory).
    jwks_body: ?[]const u8 = null,

    /// Timestamp of last JWKS refresh (Unix seconds).
    jwks_last_refresh: i64 = 0,

    /// Stable buffer for the last validated username (JWT claim slices
    /// point into stack-local buffers that die when validateToken returns).
    username_buf: [256]u8 = undefined,
    username_len: usize = 0,

    /// Stable buffer for the last validated user's profile photo URL.
    /// Extracted from the OIDC `picture` claim (standard OpenID Connect claim).
    photo_url_buf: [512]u8 = undefined,
    photo_url_len: usize = 0,

    pub fn init(allocator: Allocator, config: OidcConfig) OidcStore {
        return OidcStore{
            .config = config,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *OidcStore) void {
        if (self.jwks_body) |body| {
            self.allocator.free(body);
            self.jwks_body = null;
        }
        self.key_count = 0;
    }

    /// Validate an OAUTHBEARER token. Returns the extracted username on success.
    /// The returned slice borrows from internal state — valid until next validateToken call.
    /// Tries JWT validation first; falls back to token introspection for opaque tokens.
    pub fn validateToken(self: *OidcStore, allocator: Allocator, token: []const u8) !?[]const u8 {
        // Parse the JWT
        const parsed = jwt.parse(token) catch |err| {
            // JWT parsing failed — token may be opaque. Try introspection.
            log.info("OAUTHBEARER: JWT parse failed ({}) — trying introspection", .{err});
            return self.introspectToken(allocator, token);
        };

        // Validate expiry
        jwt.validateExpiry(&parsed.claims) catch {
            log.info("OAUTHBEARER: token expired for sub='{s}'", .{parsed.claims.sub});
            return null;
        };

        // Validate issuer
        jwt.validateIssuer(&parsed.claims, self.config.issuer) catch {
            log.info("OAUTHBEARER: issuer mismatch: got '{s}', expected '{s}'", .{ parsed.claims.iss, self.config.issuer });
            return null;
        };

        // Validate audience
        jwt.validateAudience(&parsed.claims, self.config.client_id) catch {
            log.info("OAUTHBEARER: audience mismatch: got '{s}', expected '{s}'", .{ parsed.claims.aud, self.config.client_id });
            return null;
        };

        // Verify signature — find the matching key (refreshes JWKS on kid miss)
        const signing_key = self.getSigningKey(parsed.header.kid) orelse {
            log.info("OAUTHBEARER: no matching key for kid='{s}'", .{parsed.header.kid});
            return null;
        };

        const sig_valid = switch (signing_key.kty) {
            .rsa => jwt.verifyRs256(&parsed, signing_key.n, signing_key.e),
            .okp => jwt.verifyEdDSA(&parsed, signing_key.x),
        };
        if (!sig_valid) {
            log.info("OAUTHBEARER: signature verification failed for sub='{s}'", .{parsed.claims.sub});
            return null;
        }

        // Extract username: preferred_username/email (jwt parser tries both) → sub
        const raw_username = if (parsed.claims.preferred_username.len > 0)
            parsed.claims.preferred_username
        else
            parsed.claims.sub;

        if (raw_username.len == 0) {
            log.info("OAUTHBEARER: no username in token claims", .{});
            return null;
        }

        // Strip domain from email-style usernames to get JID localpart
        // e.g., "alice@morante.dev" → "alice"
        // Copy into stable buffer — JWT claim slices point into stack-local
        // buffers inside jwt.parse() that die when this function returns.
        const localpart = extractLocalpart(raw_username);
        if (localpart.len > self.username_buf.len) return null;
        @memcpy(self.username_buf[0..localpart.len], localpart);
        self.username_len = localpart.len;
        const username = self.username_buf[0..self.username_len];

        // Capture profile photo URL from OIDC `picture` claim (standard OpenID Connect).
        // Copy into stable buffer for the same lifetime reason as username.
        const picture = parsed.claims.picture;
        if (picture.len > 0 and picture.len <= self.photo_url_buf.len) {
            @memcpy(self.photo_url_buf[0..picture.len], picture);
            self.photo_url_len = picture.len;
        } else {
            self.photo_url_len = 0;
        }

        log.info("OAUTHBEARER: validated token for '{s}'", .{username});
        return username;
    }

    /// Validate a password via ROPC (Resource Owner Password Credentials) grant.
    /// Sends credentials to the IdP token endpoint; returns username on success.
    pub fn validatePassword(self: *OidcStore, allocator: Allocator, username: []const u8, password: []const u8) !?[]const u8 {
        // Build form-urlencoded body with proper percent-encoding
        var body_buf: [4096]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        const w = fbs.writer();

        w.writeAll("grant_type=password&client_id=") catch return null;
        percentEncode(w, self.config.client_id) catch return null;
        w.writeAll("&client_secret=") catch return null;
        percentEncode(w, self.config.client_secret) catch return null;
        w.writeAll("&username=") catch return null;
        // Append @domain if configured and username is bare (no @)
        if (self.config.user_domain != null and std.mem.indexOfScalar(u8, username, '@') == null) {
            percentEncode(w, username) catch return null;
            w.writeAll("%40") catch return null;
            percentEncode(w, self.config.user_domain.?) catch return null;
        } else {
            percentEncode(w, username) catch return null;
        }
        w.writeAll("&password=") catch return null;
        percentEncode(w, password) catch return null;
        w.writeAll("&scope=openid%20email%20profile") catch return null;

        const body = fbs.getWritten();

        var response = http.post(allocator, self.config.token_endpoint, body, self.config.ca_file) catch |err| {
            log.err("ROPC: HTTP request failed: {}", .{err});
            return null;
        };
        defer response.deinit();

        if (response.status != 200) {
            log.info("ROPC: token endpoint returned {d} for user '{s}'", .{ response.status, username });
            return null;
        }

        // Success — the IdP authenticated the user. Return the username as-is.
        log.info("ROPC: password validated for '{s}'", .{username});
        return username;
    }

    /// Validate a token via the introspection endpoint (RFC 7662).
    /// Used as fallback when JWT parsing fails (opaque tokens).
    fn introspectToken(self: *OidcStore, allocator: Allocator, token: []const u8) ?[]const u8 {
        const endpoint = self.config.introspection_endpoint orelse {
            log.info("OAUTHBEARER: no introspection endpoint configured", .{});
            return null;
        };

        // Build introspection request body
        var body_buf: [4096]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        const w = fbs.writer();

        w.writeAll("token=") catch return null;
        percentEncode(w, token) catch return null;
        w.writeAll("&client_id=") catch return null;
        percentEncode(w, self.config.client_id) catch return null;
        w.writeAll("&client_secret=") catch return null;
        percentEncode(w, self.config.client_secret) catch return null;

        const body = fbs.getWritten();

        var response = http.post(allocator, endpoint, body, self.config.ca_file) catch |err| {
            log.err("introspection: HTTP request failed: {}", .{err});
            return null;
        };
        defer response.deinit();

        if (response.status != 200) {
            log.info("introspection: endpoint returned {d}", .{response.status});
            return null;
        }

        // Parse introspection response — check "active":true and extract username
        const resp_body = response.body;

        // Check active flag
        if (std.mem.indexOf(u8, resp_body, "\"active\":true") == null and
            std.mem.indexOf(u8, resp_body, "\"active\": true") == null)
        {
            log.info("introspection: token is not active", .{});
            return null;
        }

        // Extract username from response (try username, then sub)
        const username_claim = extractNamedField(resp_body, "\"username\"") orelse
            extractNamedField(resp_body, "\"sub\"") orelse {
            log.info("introspection: no username in response", .{});
            return null;
        };

        const username = extractLocalpart(username_claim);
        log.info("OAUTHBEARER: introspection validated for '{s}'", .{username});
        return username;
    }

    /// Return the photo URL from the last successful token validation, or empty slice.
    pub fn getPhotoUrl(self: *const OidcStore) []const u8 {
        return self.photo_url_buf[0..self.photo_url_len];
    }

    // NOTE: No `lookup` function — OIDC backends don't support SCRAM-SHA-256.
    // The absence of `lookup` causes AuthHandler to skip SCRAM at comptime.

    // ========================================================================
    // JWKS key management
    // ========================================================================

    /// Get signing key by kid, refreshing JWKS if cache is stale or kid not found.
    fn getSigningKey(self: *OidcStore, kid: []const u8) ?*const JwkKey {
        const now = std.time.timestamp();
        const cache_stale = (now - self.jwks_last_refresh) > JWKS_MAX_AGE_SECONDS;

        // If cache is stale, refresh before lookup
        if (cache_stale) {
            self.refreshJwks() catch {
                log.err("JWKS stale refresh failed", .{});
            };
        }

        // Try cached keys
        if (self.findKeyDirect(kid)) |k| return k;

        // Kid not found — refresh and retry (may be newly rotated key)
        if (!cache_stale) {
            self.refreshJwks() catch {
                log.err("JWKS kid-miss refresh failed", .{});
                return null;
            };
        }

        return self.findKeyDirect(kid);
    }

    /// Direct cache lookup (no refresh).
    fn findKeyDirect(self: *OidcStore, kid: []const u8) ?*const JwkKey {
        for (self.keys[0..self.key_count]) |*k| {
            if (std.mem.eql(u8, k.kid, kid)) return k;
        }
        return null;
    }

    /// Fetch JWKS from the IdP and update the key cache.
    fn refreshJwks(self: *OidcStore) !void {
        log.info("refreshing JWKS from {s}", .{self.config.jwks_uri});

        var response = http.get(self.allocator, self.config.jwks_uri, self.config.ca_file) catch |err| {
            log.err("JWKS fetch failed: {}", .{err});
            return error.OutOfMemory;
        };
        defer response.deinit();

        if (response.status != 200) {
            log.err("JWKS endpoint returned {d}", .{response.status});
            return error.OutOfMemory;
        }

        // Copy response body into our own allocation (response.deinit frees its copy)
        const body_copy = self.allocator.alloc(u8, response.body.len) catch return error.OutOfMemory;
        @memcpy(body_copy, response.body);

        // Replace old JWKS body
        if (self.jwks_body) |old| {
            self.allocator.free(old);
        }
        self.jwks_body = body_copy;
        self.jwks_last_refresh = std.time.timestamp();

        // Parse keys from JWKS JSON
        self.key_count = 0;
        self.parseJwksKeys();
    }

    /// Parse JWKS JSON and extract key components (RSA and EdDSA/OKP).
    fn parseJwksKeys(self: *OidcStore) void {
        const body = self.jwks_body orelse return;

        // Find each key block by looking for "kid" fields
        var pos: usize = 0;
        while (self.key_count < MAX_JWKS_KEYS) {
            // Find next "kid" occurrence
            const kid_start = std.mem.indexOf(u8, body[pos..], "\"kid\"") orelse break;
            const abs_kid_start = pos + kid_start;

            const kid_value = extractFieldValue(body[abs_kid_start..]) orelse {
                pos = abs_kid_start + 5;
                continue;
            };

            // Determine key type from surrounding context
            const search_start = if (abs_kid_start > 200) abs_kid_start - 200 else 0;
            const search_end = @min(body.len, abs_kid_start + 4096);
            const key_region = body[search_start..search_end];

            const kty_value = extractNamedField(key_region, "\"kty\"") orelse {
                pos = abs_kid_start + 5;
                continue;
            };

            if (std.mem.eql(u8, kty_value, "RSA")) {
                // RSA key — need n and e
                const n_value = extractNamedField(key_region, "\"n\"") orelse {
                    pos = abs_kid_start + 5;
                    continue;
                };
                const e_value = extractNamedField(key_region, "\"e\"") orelse {
                    pos = abs_kid_start + 5;
                    continue;
                };

                self.keys[self.key_count] = JwkKey{
                    .kid = kid_value,
                    .kty = .rsa,
                    .n = n_value,
                    .e = e_value,
                };
                self.key_count += 1;
            } else if (std.mem.eql(u8, kty_value, "OKP")) {
                // EdDSA (Ed25519) key — need x
                const x_value = extractNamedField(key_region, "\"x\"") orelse {
                    pos = abs_kid_start + 5;
                    continue;
                };

                self.keys[self.key_count] = JwkKey{
                    .kid = kid_value,
                    .kty = .okp,
                    .x = x_value,
                };
                self.key_count += 1;
            }
            // Skip unknown key types

            pos = abs_kid_start + 5;
        }

        log.info("JWKS: cached {d} keys", .{self.key_count});
    }
};

/// Extract the string value after a JSON field key (assumes "key":"value" pattern).
fn extractFieldValue(data: []const u8) ?[]const u8 {
    // Skip the key itself (e.g., "kid")
    var i: usize = 0;
    // Skip key string
    if (i >= data.len or data[i] != '"') return null;
    i += 1;
    while (i < data.len and data[i] != '"') : (i += 1) {}
    if (i >= data.len) return null;
    i += 1; // closing quote of key

    // Skip : and whitespace
    while (i < data.len and (data[i] == ':' or data[i] == ' ' or data[i] == '\t')) : (i += 1) {}

    // Read value string
    if (i >= data.len or data[i] != '"') return null;
    i += 1;
    const start = i;
    while (i < data.len and data[i] != '"') : (i += 1) {
        if (data[i] == '\\') i += 1;
    }
    if (i >= data.len) return null;
    return data[start..i];
}

/// Extract a named field value from a JSON region.
fn extractNamedField(data: []const u8, key: []const u8) ?[]const u8 {
    const key_pos = std.mem.indexOf(u8, data, key) orelse return null;
    const after_key = data[key_pos + key.len ..];

    // Skip : and whitespace
    var i: usize = 0;
    while (i < after_key.len and (after_key[i] == ':' or after_key[i] == ' ' or after_key[i] == '\t')) : (i += 1) {}

    if (i >= after_key.len or after_key[i] != '"') return null;
    i += 1;
    const start = i;
    while (i < after_key.len and after_key[i] != '"') : (i += 1) {
        if (after_key[i] == '\\') i += 1;
    }
    if (i >= after_key.len) return null;
    return after_key[start..i];
}

// ============================================================================
// URL Encoding
// ============================================================================

/// RFC 3986 percent-encoding for form-urlencoded values.
/// Writes encoded bytes to the writer. Unreserved chars pass through.
fn percentEncode(writer: anytype, input: []const u8) !void {
    const hex = "0123456789ABCDEF";
    for (input) |ch| {
        if (isUnreserved(ch)) {
            try writer.writeByte(ch);
        } else {
            try writer.writeByte('%');
            try writer.writeByte(hex[ch >> 4]);
            try writer.writeByte(hex[ch & 0x0F]);
        }
    }
}

/// RFC 3986 unreserved characters (pass through without encoding).
fn isUnreserved(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_', '.', '~' => true,
        else => false,
    };
}

// ============================================================================
// Username / JID Extraction
// ============================================================================

/// Extract the localpart from an email-style identifier.
/// "alice@morante.dev" → "alice"
/// "alice" → "alice" (no @, returned as-is)
fn extractLocalpart(input: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, input, '@')) |at_pos| {
        return input[0..at_pos];
    }
    return input;
}

// ============================================================================
// Tests
// ============================================================================

test "OidcStore: init and deinit" {
    const allocator = std.testing.allocator;
    var store = OidcStore.init(allocator, .{
        .issuer = "https://auth.example.com/",
        .client_id = "xmppd",
        .client_secret = "secret",
        .token_endpoint = "https://auth.example.com/token",
        .jwks_uri = "https://auth.example.com/certs",
    });
    defer store.deinit();

    try std.testing.expectEqual(@as(usize, 0), store.key_count);
}

test "OidcStore: no lookup (SCRAM not supported)" {
    // OidcStore deliberately has no `lookup` function.
    // AuthHandler uses @hasDecl to skip SCRAM when lookup is absent.
    try std.testing.expect(!@hasDecl(OidcStore, "lookup"));
}

test "extractFieldValue: basic" {
    const data = "\"kid\":\"test-key-id\"";
    const result = extractFieldValue(data);
    try std.testing.expectEqualStrings("test-key-id", result.?);
}

test "extractFieldValue: with spaces" {
    const data = "\"kid\" : \"spaced-key\"";
    const result = extractFieldValue(data);
    try std.testing.expectEqualStrings("spaced-key", result.?);
}

test "extractNamedField: basic" {
    const data = "{\"kid\":\"k1\",\"n\":\"modulus_value\",\"e\":\"AQAB\"}";
    try std.testing.expectEqualStrings("modulus_value", extractNamedField(data, "\"n\"").?);
    try std.testing.expectEqualStrings("AQAB", extractNamedField(data, "\"e\"").?);
    try std.testing.expectEqualStrings("k1", extractNamedField(data, "\"kid\"").?);
}

test "extractNamedField: missing field" {
    const data = "{\"kid\":\"k1\",\"n\":\"modulus\"}";
    try std.testing.expect(extractNamedField(data, "\"e\"") == null);
}

test "percentEncode: unreserved chars pass through" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try percentEncode(fbs.writer(), "alice");
    try std.testing.expectEqualStrings("alice", fbs.getWritten());
}

test "percentEncode: special chars encoded" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try percentEncode(fbs.writer(), "p@ss w0rd!");
    try std.testing.expectEqualStrings("p%40ss%20w0rd%21", fbs.getWritten());
}

test "percentEncode: all reserved form chars" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try percentEncode(fbs.writer(), "&=+%");
    try std.testing.expectEqualStrings("%26%3D%2B%25", fbs.getWritten());
}

test "extractLocalpart: email" {
    try std.testing.expectEqualStrings("alice", extractLocalpart("alice@morante.dev"));
}

test "extractLocalpart: bare username" {
    try std.testing.expectEqualStrings("alice", extractLocalpart("alice"));
}

test "extractLocalpart: empty" {
    try std.testing.expectEqualStrings("", extractLocalpart(""));
}
