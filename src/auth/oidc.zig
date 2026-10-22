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
const ssl = @import("ssl");

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

    /// One shared HTTPS client for the daemon (T357/S8): the SSL_CTX and its
    /// parsed CA bundle cost is paid once, not per token/introspection/JWKS
    /// request. Lazily created on first use; OidcStore.init stays infallible.
    http_client: ?http.Client = null,

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
        if (self.http_client) |*cl| cl.deinit();
        if (self.jwks_body) |body| {
            self.allocator.free(body);
            self.jwks_body = null;
        }
        self.key_count = 0;
    }

    /// The daemon's shared HTTPS client (T357/S8).
    fn httpClient(self: *OidcStore) ?*http.Client {
        if (self.http_client) |*cl| return cl;
        self.http_client = http.Client.init(self.config.ca_file) catch |err| {
            log.err("OIDC HTTPS client init failed: {}", .{err});
            return null;
        };
        return &self.http_client.?;
    }

    /// Derive the local identity from an IdP claim (S3): a claim
    /// that carries a domain must name the configured user_domain, and the
    /// localpart is copied into the stable username buffer (claim slices
    /// borrow request-scoped memory). Null on mismatch or oversize.
    fn claimIdentity(self: *OidcStore, raw_username: []const u8) ?[]const u8 {
        if (raw_username.len == 0) return null;
        if (self.config.user_domain) |dom| {
            if (std.mem.indexOfScalar(u8, raw_username, '@')) |at| {
                if (!std.ascii.eqlIgnoreCase(raw_username[at + 1 ..], dom)) {
                    log.info("OIDC: claim '{s}' is outside user_domain '{s}'; rejected", .{ raw_username, dom });
                    return null;
                }
            }
        }
        const localpart = extractLocalpart(raw_username);
        if (localpart.len == 0 or localpart.len > self.username_buf.len) return null;
        @memcpy(self.username_buf[0..localpart.len], localpart);
        self.username_len = localpart.len;
        return self.username_buf[0..self.username_len];
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

        // Domain-checked claim identity, copied into the stable buffer (JWT
        // claim slices die with jwt.parse's stack locals) (S3).
        const username = self.claimIdentity(raw_username) orelse {
            log.info("OAUTHBEARER: claim identity rejected for sub='{s}'", .{parsed.claims.sub});
            return null;
        };

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

        const client = self.httpClient() orelse return null;
        var response = client.post(allocator, self.config.token_endpoint, body) catch |err| {
            log.err("ROPC: HTTP request failed: {}", .{err});
            return null;
        };
        defer response.deinit();

        if (response.status != 200) {
            log.info("ROPC: token endpoint returned {d} for user '{s}'", .{ response.status, username });
            return null;
        }

        // S3: the authenticated identity comes from the IdP's token
        // claims, exactly like OAUTHBEARER. The typed username is never
        // returned as-is: a case or domain variant of a locked account must
        // not slip past the lock check.
        return self.identityFromTokenResponse(allocator, response.body);
    }

    /// Derive the authenticated identity from an ROPC token response: the
    /// id_token claims when present (full JWT validation), else the
    /// access_token via introspection when an endpoint is configured. Null
    /// when neither yields a validated identity (S3).
    fn identityFromTokenResponse(self: *OidcStore, allocator: Allocator, body: []const u8) !?[]const u8 {
        if (extractNamedField(body, "\"id_token\"")) |id_token| {
            if (id_token.len > 0) return self.validateToken(allocator, id_token);
        }
        if (extractNamedField(body, "\"access_token\"")) |access_token| {
            if (access_token.len > 0 and self.config.introspection_endpoint != null) {
                return self.introspectToken(allocator, access_token);
            }
        }
        log.info("ROPC: token response carries no usable id_token or access_token", .{});
        return null;
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

        const client = self.httpClient() orelse return null;
        var response = client.post(allocator, endpoint, body) catch |err| {
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

        // Copy into the stable buffer: the claim slice borrows the response
        // body, which dies with this scope. Domain-checked like every claim
        // identity (S3).
        const username = self.claimIdentity(username_claim) orelse {
            log.info("introspection: claim identity rejected", .{});
            return null;
        };
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

        const client = self.httpClient() orelse return error.TlsInitFailed;
        var response = client.get(self.allocator, self.config.jwks_uri) catch |err| {
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

// --- S3 tests: claim identity and the ROPC identity path ------------

test "OidcStore: claim identity enforces user_domain and keeps the localpart" {
    const allocator = std.testing.allocator;
    var store = OidcStore.init(allocator, .{
        .issuer = "https://idp.example/",
        .client_id = "xmppd",
        .client_secret = "secret",
        .token_endpoint = "https://idp.example/token",
        .jwks_uri = "https://idp.example/certs",
        .user_domain = "us.example",
    });
    defer store.deinit();

    try std.testing.expectEqualStrings("alice", store.claimIdentity("alice").?);
    try std.testing.expectEqualStrings("alice", store.claimIdentity("alice@us.example").?);
    // Claim case is preserved; folding is the lock store's job.
    try std.testing.expectEqualStrings("Alice", store.claimIdentity("Alice@US.EXAMPLE").?);
    // A foreign domain in the claim is rejected when user_domain is set.
    try std.testing.expect(store.claimIdentity("alice@other.example") == null);
    try std.testing.expect(store.claimIdentity("") == null);

    // Without user_domain configured any claim domain passes and is stripped.
    store.config.user_domain = null;
    try std.testing.expectEqualStrings("alice", store.claimIdentity("alice@wherever.example").?);
}

/// Write a fresh self-signed cert+key for "localhost" into `dir` via the
/// system OpenSSL CLI. error.SkipZigTest when the tool is missing.
fn genIdpTestCert(dir: std.fs.Dir) !void {
    const r = std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &.{ "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1", "-keyout", "key.pem", "-out", "cert.pem" },
        .cwd_dir = dir,
        .max_output_bytes = 4096,
    }) catch return error.SkipZigTest;
    defer std.testing.allocator.free(r.stdout);
    defer std.testing.allocator.free(r.stderr);
    switch (r.term) {
        .Exited => |code| {
            if (code != 0) return error.SkipZigTest;
        },
        else => return error.SkipZigTest,
    }
}

/// Serve one HTTPS JSON response on a loopback TLS listener, then return.
/// The bound port is published via port_out; a deadline keeps the test from
/// hanging when the client never connects. kTLS stays off on this end (one
/// userland TLS end avoids FreeBSD PR 296498 on loopback).
fn serveOneTlsResponse(cert_path: [*:0]const u8, key_path: [*:0]const u8, body: []const u8, port_out: *std.atomic.Value(u16)) void {
    const posix = std.posix;
    var ctx = ssl.SslContext.initServer(cert_path, key_path) catch return;
    defer ctx.deinit();
    ctx.disableKtls();

    const listen_fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(listen_fd);
    var addr: std.c.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch return;
    posix.listen(listen_fd, 4) catch return;
    var alen: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    posix.getsockname(listen_fd, @ptrCast(&addr), &alen) catch return;
    port_out.store(std.mem.bigToNative(u16, addr.port), .release);

    const deadline = std.time.milliTimestamp() + 10000;
    while (std.time.milliTimestamp() < deadline) {
        var fds = [_]posix.pollfd{.{ .fd = listen_fd, .events = posix.POLL.IN, .revents = 0 }};
        const pn = posix.poll(&fds, 500) catch 0;
        if (pn <= 0) continue;
        const conn_fd = posix.accept(listen_fd, null, null, 0) catch continue;
        defer posix.close(conn_fd);
        var conn = ssl.SslConn.init(ctx, conn_fd) catch continue;
        defer {
            conn.shutdown();
            conn.deinit();
        }
        // Drive the server-side handshake to completion.
        var hs_done = false;
        while (!hs_done and std.time.milliTimestamp() < deadline) {
            const hs = conn.doHandshake() catch break;
            hs_done = hs == .complete;
        }
        if (!hs_done) continue;
        // Consume the request head (the form body is irrelevant here).
        var buf: [4096]u8 = undefined;
        var total: usize = 0;
        while (total < buf.len and std.time.milliTimestamp() < deadline) {
            const rr = conn.read(buf[total..]) catch break;
            switch (rr) {
                .ok => |n| {
                    if (n == 0) break;
                    total += n;
                    if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n") != null) break;
                },
                .want_read, .want_write => {},
            }
        }
        var resp: [8192]u8 = undefined;
        const out = std.fmt.bufPrint(&resp, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ body.len, body }) catch return;
        var sent: usize = 0;
        while (sent < out.len and std.time.milliTimestamp() < deadline) {
            const wr = conn.write(out[sent..]) catch break;
            switch (wr) {
                .ok => |n| sent += n,
                .want_read, .want_write => {},
            }
        }
        return;
    }
}

test "OidcStore: ROPC identity comes from token claims, never the typed name" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    genIdpTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const cert_path = try std.fmt.allocPrintSentinel(allocator, "{s}/cert.pem", .{base}, 0);
    defer allocator.free(cert_path);
    const key_path = try std.fmt.allocPrintSentinel(allocator, "{s}/key.pem", .{base}, 0);
    defer allocator.free(key_path);

    var port = std.atomic.Value(u16).init(0);
    const body = "{\"access_token\":\"opaque-token\",\"token_type\":\"Bearer\"}";
    const th = try std.Thread.spawn(.{}, serveOneTlsResponse, .{ cert_path.ptr, key_path.ptr, body, &port });
    defer th.join();
    const dl = std.time.milliTimestamp() + 5000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) std.Thread.sleep(std.time.ns_per_ms);
    try std.testing.expect(port.load(.acquire) != 0);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/token", .{port.load(.acquire)});

    var store = OidcStore.init(allocator, .{
        .issuer = "https://idp.example/",
        .client_id = "xmppd",
        .client_secret = "secret",
        .token_endpoint = url,
        .jwks_uri = url,
        .ca_file = cert_path,
        .user_domain = "us.example",
    });
    defer store.deinit();

    // The IdP answered 200, but the response carries no id_token and no
    // introspection endpoint is configured: no claim identity can be
    // derived, so the typed name must never come back. A typed case
    // variant of a locked account ("ALICE@us.example" vs locked "alice")
    // would otherwise ride it straight past the lock check.
    const result = try store.validatePassword(allocator, "ALICE@us.example", "pw");
    try std.testing.expect(result == null);
}
