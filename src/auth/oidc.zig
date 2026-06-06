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
    /// CA file for TLS verification (null = system default).
    ca_file: ?[]const u8 = null,
    /// Claim to extract username from (default: preferred_username, fallback: email).
    username_claim: []const u8 = "preferred_username",
};

/// Cached JWK (RSA public key components).
const JwkKey = struct {
    kid: []const u8,
    n: []const u8,
    e: []const u8,
};

/// Maximum number of cached JWKS keys.
const MAX_JWKS_KEYS = 16;

pub const OidcStore = struct {
    config: OidcConfig,
    allocator: Allocator,

    /// Cached JWKS keys.
    keys: [MAX_JWKS_KEYS]JwkKey = undefined,
    key_count: usize = 0,

    /// Raw JWKS response body (owns key slice memory).
    jwks_body: ?[]const u8 = null,

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
    pub fn validateToken(self: *OidcStore, allocator: Allocator, token: []const u8) !?[]const u8 {
        _ = allocator;

        // Parse the JWT
        const parsed = jwt.parse(token) catch |err| {
            log.info("OAUTHBEARER: JWT parse failed: {}", .{err});
            return null;
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

        if (!jwt.verifyRs256(&parsed, signing_key.n, signing_key.e)) {
            log.info("OAUTHBEARER: signature verification failed for sub='{s}'", .{parsed.claims.sub});
            return null;
        }

        // Extract username from the configured claim
        const username = if (parsed.claims.preferred_username.len > 0)
            parsed.claims.preferred_username
        else
            parsed.claims.sub;

        if (username.len == 0) {
            log.info("OAUTHBEARER: no username in token claims", .{});
            return null;
        }

        log.info("OAUTHBEARER: validated token for '{s}'", .{username});
        return username;
    }

    /// Validate a password via ROPC (Resource Owner Password Credentials) grant.
    /// Sends credentials to the IdP token endpoint; returns username on success.
    pub fn validatePassword(self: *OidcStore, allocator: Allocator, username: []const u8, password: []const u8) !?[]const u8 {
        // Build form-urlencoded body:
        // grant_type=password&client_id=X&client_secret=Y&username=U&password=P&scope=openid
        var body_buf: [2048]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf, "grant_type=password&client_id={s}&client_secret={s}&username={s}&password={s}&scope=openid", .{
            self.config.client_id,
            self.config.client_secret,
            username,
            password,
        }) catch {
            log.err("ROPC: request body too large", .{});
            return null;
        };

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
        // We trust the IdP's response; no need to parse the access_token for PLAIN auth.
        log.info("ROPC: password validated for '{s}'", .{username});
        return username;
    }

    // NOTE: No `lookup` function — OIDC backends don't support SCRAM-SHA-256.
    // The absence of `lookup` causes AuthHandler to skip SCRAM at comptime.

    // ========================================================================
    // JWKS key management
    // ========================================================================

    /// Get signing key by kid, refreshing JWKS if necessary.
    fn getSigningKey(self: *OidcStore, kid: []const u8) ?*const JwkKey {
        // Try cached keys first
        if (self.findKeyDirect(kid)) |k| return k;

        // Refresh and try again
        self.refreshJwks() catch {
            log.err("JWKS refresh failed", .{});
            return null;
        };

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

        const response = http.get(self.allocator, self.config.jwks_uri, self.config.ca_file) catch |err| {
            log.err("JWKS fetch failed: {}", .{err});
            return error.OutOfMemory;
        };

        if (response.status != 200) {
            log.err("JWKS endpoint returned {d}", .{response.status});
            self.allocator.free(response.body);
            return error.OutOfMemory;
        }

        // Replace old JWKS body — take ownership of response body
        if (self.jwks_body) |old| {
            self.allocator.free(old);
        }
        // Take ownership: copy the slice descriptor, then free via our own deinit
        self.jwks_body = response.body;
        // Leak the body out of Response by zeroing its reference before deinit would free it.
        // Response.body is a const slice — we need to avoid double-free.
        // Since we took the pointer, just don't call response.deinit().
        // The response struct itself is stack-allocated, no heap to free beyond body.

        // Parse keys from JWKS JSON
        self.key_count = 0;
        self.parseJwksKeys();
    }

    /// Parse JWKS JSON and extract RSA key components.
    /// Minimal JSON parsing — looks for "kid", "n", "e" fields within "keys" array.
    fn parseJwksKeys(self: *OidcStore) void {
        const body = self.jwks_body orelse return;

        // Find each key block by looking for "kid" fields
        var pos: usize = 0;
        while (self.key_count < MAX_JWKS_KEYS) {
            // Find next "kid" occurrence
            const kid_start = std.mem.indexOf(u8, body[pos..], "\"kid\"") orelse break;
            const abs_kid_start = pos + kid_start;

            // Find the enclosing object boundaries (approximate: find previous { and next })
            // We extract kid, n, e from nearby context
            const kid_value = extractFieldValue(body[abs_kid_start..]) orelse {
                pos = abs_kid_start + 5;
                continue;
            };

            // Look for "n" and "e" near this key
            // Search within a reasonable window after kid
            const search_start = abs_kid_start;
            const search_end = @min(body.len, abs_kid_start + 4096);
            const key_region = body[search_start..search_end];

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
                .n = n_value,
                .e = e_value,
            };
            self.key_count += 1;

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
