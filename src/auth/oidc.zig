//! # OidcStore -- OIDC/OAuth2 authentication backend
//!
//! Implements token validation (OAUTHBEARER) and password delegation (PLAIN → ROPC)
//! against an external Identity Provider. Used by xmppd-auth-oidc.
//!
//! ## Threads
//!
//! Blocking IdP work runs on IdpPool worker threads via `exchange`, which is
//! thread-safe: it touches no loop state and serializes the JWKS cache under
//! `jwks_mutex`. The daemon's event loop only calls `validatePassword` /
//! `validateToken`, which read the Answer parked in `store.answer` by the
//! completion replay and never do I/O.
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
//! Provides `validateToken` and `validatePassword` -- the AuthHandler
//! uses `@hasDecl` at comptime to route OAUTHBEARER and PLAIN accordingly.

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const http = @import("http");
const jwt = @import("jwt");
const ssl = @import("ssl");

const log = std.log.scoped(.oidc_store);

/// Per-worker JWT decode scratch: parsed claims borrow the buffer, so it
/// must be thread-private and not a per-call stack array (4.5 KiB).
threadlocal var jwt_decode_buf: jwt.DecodeBuffer = undefined;

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

/// What the IdP decided about one credential.
pub const Verdict = enum { verified, rejected, unavailable, timed_out };

/// The authenticated identity an exchange derived from IdP claims.
pub const Identity = struct {
    username_buf: [256]u8 = undefined,
    username_len: u16 = 0,
    photo_buf: [512]u8 = undefined,
    photo_len: u16 = 0,

    pub fn username(self: *const Identity) []const u8 {
        return self.username_buf[0..self.username_len];
    }

    pub fn photoUrl(self: *const Identity) []const u8 {
        return self.photo_buf[0..self.photo_len];
    }
};

/// One exchange's outcome plus the digest of the credential it answered.
/// The digest lets the replay seam prove the credential the handler
/// presents is the one that was dispatched.
pub const Answer = struct {
    verdict: Verdict,
    identity: Identity = .{},
    input_digest: [32]u8,
};

/// A credential handed to a worker for an IdP exchange.
pub const Credential = union(enum) {
    password: struct { username: []const u8, password: []const u8 },
    token: []const u8,
};

/// SHA-256 over the credential with a kind tag: "p\x00"++username++"\x00"++password
/// or "t\x00"++token.
pub fn credentialDigest(cred: Credential) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    switch (cred) {
        .password => |p| {
            h.update("p\x00");
            h.update(p.username);
            h.update("\x00");
            h.update(p.password);
        },
        .token => |t| {
            h.update("t\x00");
            h.update(t);
        },
    }
    return h.finalResult();
}

/// authcid and passwd out of a PLAIN payload ([authzid]\0authcid\0passwd),
/// under the handler's exact split rules (handler.zig).
pub fn plainCredentials(payload: []const u8) ?PlainCredentials {
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
    const authcid_start = (nul1 orelse return null) + 1;
    const authcid_end = nul2 orelse return null;
    const passwd_start = authcid_end + 1;
    if (authcid_start >= payload.len or passwd_start >= payload.len) return null;
    return .{
        .username = payload[authcid_start..authcid_end],
        .password = payload[passwd_start..],
    };
}

pub const PlainCredentials = struct {
    username: []const u8,
    password: []const u8,
};

/// Bearer token out of an RFC 7628 OAUTHBEARER payload ("auth=Bearer "
/// after the first \x01, terminated by \x01), with the whole payload as
/// fallback for simple clients -- the handler's exact rules. Null when
/// empty.
pub fn bearerToken(payload: []const u8) ?[]const u8 {
    if (payload.len == 0) return null;

    const bearer_prefix = "auth=Bearer ";
    const token = blk: {
        if (std.mem.indexOf(u8, payload, bearer_prefix)) |pos| {
            const start = pos + bearer_prefix.len;
            const rest = payload[start..];
            const end = std.mem.indexOfScalar(u8, rest, 0x01) orelse rest.len;
            break :blk rest[0..end];
        }
        break :blk payload;
    };
    if (token.len == 0) return null;
    return token;
}

/// Per-request knobs every HTTP call in one exchange shares: the same
/// absolute deadline, connect budget and cancellation pipe. `deadline_ns`
/// is stamped when the job is queued, not when a worker picks it up, so
/// queue time counts against the exchange budget.
pub const ExchangeOptions = struct {
    connect_timeout_ms: u32,
    deadline_ns: u64,
    cancel_fd: posix.fd_t = -1,
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

/// Worker-owned copy of a cached key: verification must not read jwks_body
/// slices after the mutex is released, so the matched key's components are
/// copied out under the lock.
const KeyCopy = struct {
    kty: KeyType,
    /// base64url modulus; 1408 bytes covers an 8192-bit RSA key (1366
    /// chars) with headroom. Anything larger is unusable, see KeyLookup.
    n_buf: [1408]u8 = undefined,
    n_len: u16 = 0,
    e_buf: [16]u8 = undefined,
    e_len: u8 = 0,
    x_buf: [64]u8 = undefined,
    x_len: u8 = 0,

    fn n(self: *const KeyCopy) []const u8 {
        return self.n_buf[0..self.n_len];
    }

    fn e(self: *const KeyCopy) []const u8 {
        return self.e_buf[0..self.e_len];
    }

    fn x(self: *const KeyCopy) []const u8 {
        return self.x_buf[0..self.x_len];
    }
};

/// Result of a signing-key lookup under the JWKS lock.
const KeyFetch = union(enum) {
    key: KeyCopy,
    /// kid genuinely absent after the refresh attempts the cache allows.
    absent,
    /// JWKS fetch failed; carries the transport verdict.
    failed: JwksFail,
};

/// Result of a direct cache lookup under jwks_mutex.
const KeyLookup = union(enum) {
    found: KeyCopy,
    /// The kid exists but a component exceeds the copy bound: an unusable
    /// cached key is a service problem, never a bad credential.
    oversize,
    absent,
};

/// JWT validation outcome for exchange callers.
const JwtCheck = enum {
    /// Signature and claims verified; identity written into out.
    verified,
    /// Not a JWT at all: the token may be opaque (introspection candidate).
    malformed,
    /// A JWT whose claims or signature failed validation.
    invalid,
    unavailable,
    timed_out,
};

const JwksError = error{ Timeout, FetchFailed, OutOfMemory };

/// Transport verdicts a JWKS failure can carry.
const JwksFail = enum { unavailable, timed_out };

/// Map an HTTP transport failure to a verdict: the deadline produces
/// timed_out, everything else is a generic IdP outage.
fn httpVerdict(err: http.HttpError) Verdict {
    return switch (err) {
        error.Timeout => .timed_out,
        error.InvalidUrl,
        error.DnsResolutionFailed,
        error.ConnectionFailed,
        error.Cancelled,
        error.TlsInitFailed,
        error.TlsHandshakeFailed,
        error.TlsWriteFailed,
        error.TlsReadFailed,
        error.ResponseTooLarge,
        error.InvalidResponse,
        error.OutOfMemory,
        => .unavailable,
    };
}

/// http.RequestOptions for one HTTP call: every call in the exchange
/// shares the absolute deadline stamped at queue time.
fn requestOptions(options: ExchangeOptions) http.RequestOptions {
    return .{
        .deadline_ns = options.deadline_ns,
        .connect_timeout_ms = options.connect_timeout_ms,
        .cancel_fd = options.cancel_fd,
    };
}

pub const OidcStore = struct {
    config: OidcConfig,
    allocator: Allocator,

    /// One shared HTTPS client for the daemon (T357/S8): the SSL_CTX and its
    /// parsed CA bundle cost is paid once, not per token/introspection/JWKS
    /// request. Created by start() before the workers spawn; read-only
    /// afterwards, so workers share it safely.
    http_client: ?http.Client = null,

    /// Guards the JWKS cache below (keys, key_count, jwks_body,
    /// jwks_last_refresh). Workers hold it for cache reads and for the whole
    /// serialized refresh, HTTP GET included.
    jwks_mutex: std.Thread.Mutex = .{},

    /// Cached JWKS keys (jwks_mutex).
    keys: [MAX_JWKS_KEYS]JwkKey = undefined,
    key_count: usize = 0,

    /// Raw JWKS response body; owns the key slice memory (jwks_mutex).
    jwks_body: ?[]const u8 = null,

    /// Timestamp of last JWKS refresh, Unix seconds (jwks_mutex).
    jwks_last_refresh: i64 = 0,

    /// Set by the daemon only around the replay of a completed exchange:
    /// handleMessage then calls validatePassword/validateToken, which read
    /// this answer instead of doing IdP I/O. Event-loop thread only.
    answer: ?*const Answer = null,

    /// Stable buffers holding the replayed identity between validate* and
    /// getPhotoUrl. Event-loop thread only.
    username_buf: [256]u8 = undefined,
    username_len: usize = 0,
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

    /// Create the shared HTTPS client. Called once before the IdP workers
    /// start; afterwards http_client is only read.
    pub fn start(self: *OidcStore) error{TlsInitFailed}!void {
        std.debug.assert(self.http_client == null);
        self.http_client = http.Client.init(self.config.ca_file) catch return error.TlsInitFailed;
    }

    fn httpClient(self: *OidcStore) *http.Client {
        std.debug.assert(self.http_client != null);
        return &self.http_client.?;
    }

    /// Derive the local identity from an IdP claim (S3): a claim
    /// that carries a domain must name the configured user_domain, and the
    /// localpart is copied into `out`. False on mismatch or oversize.
    fn claimIdentity(self: *const OidcStore, raw_username: []const u8, out: *Identity) bool {
        if (raw_username.len == 0) return false;
        if (self.config.user_domain) |dom| {
            if (std.mem.indexOfScalar(u8, raw_username, '@')) |at| {
                if (!std.ascii.eqlIgnoreCase(raw_username[at + 1 ..], dom)) {
                    log.info("OIDC: claim '{s}' is outside user_domain '{s}'; rejected", .{ raw_username, dom });
                    return false;
                }
            }
        }
        const localpart = extractLocalpart(raw_username);
        if (localpart.len == 0 or localpart.len > out.username_buf.len) return false;
        @memcpy(out.username_buf[0..localpart.len], localpart);
        out.username_len = @intCast(localpart.len);
        return true;
    }

    fn copyPhoto(picture: []const u8, out: *Identity) void {
        if (picture.len > 0 and picture.len <= out.photo_buf.len) {
            @memcpy(out.photo_buf[0..picture.len], picture);
            out.photo_len = @intCast(picture.len);
        } else {
            out.photo_len = 0;
        }
    }

    // ========================================================================
    // Worker-side IdP exchange (thread-safe, no loop state)
    // ========================================================================

    /// Run one credential against the IdP and classify the outcome. Called
    /// on IdpPool workers only; writes `out` on .verified.
    pub fn exchange(self: *OidcStore, allocator: Allocator, cred: Credential, options: ExchangeOptions, out: *Identity) Verdict {
        return switch (cred) {
            .password => |p| self.exchangePassword(allocator, p.username, p.password, options, out),
            .token => |t| self.exchangeToken(allocator, t, options, out),
        };
    }

    /// ROPC grant: POST the password to the token endpoint and classify the
    /// response.
    fn exchangePassword(self: *OidcStore, allocator: Allocator, username: []const u8, password: []const u8, options: ExchangeOptions, out: *Identity) Verdict {
        const body = self.buildRopcBody(allocator, username, password) orelse {
            log.warn("ROPC: could not build the token request body", .{});
            return .unavailable;
        };
        defer {
            std.crypto.secureZero(u8, body.buf);
            allocator.free(body.buf);
        }

        var response = self.httpClient().post(allocator, self.config.token_endpoint, body.slice(), requestOptions(options)) catch |err| {
            log.warn("ROPC: token endpoint request failed: {s}", .{@errorName(err)});
            return httpVerdict(err);
        };
        defer response.deinit();

        if (response.status != 200) {
            log.info("ROPC: token endpoint returned {d} for user '{s}'", .{ response.status, username });
            return classifyTokenError(response.status, response.body);
        }

        return self.identityFromTokenResponse(allocator, response.body, options, out);
    }

    const RopcBody = struct {
        buf: []u8,
        len: usize,
        fn slice(self: *const RopcBody) []const u8 {
            return self.buf[0..self.len];
        }
    };

    /// Form-urlencoded ROPC body on the heap (the password can be large and
    /// percent-encoding triples the worst case). Caller wipes and frees
    /// body.buf.
    fn buildRopcBody(self: *const OidcStore, allocator: Allocator, username: []const u8, password: []const u8) ?RopcBody {
        const domain = self.config.user_domain orelse "";
        const cap = 256 +
            3 * (self.config.client_id.len + self.config.client_secret.len +
                username.len + domain.len + password.len);
        const buf = allocator.alloc(u8, cap) catch return null;

        var w: std.Io.Writer = .fixed(buf);
        self.writeRopcBody(&w, username, password) catch {
            allocator.free(buf);
            return null;
        };
        return .{ .buf = buf, .len = w.buffered().len };
    }

    fn writeRopcBody(self: *const OidcStore, w: *std.Io.Writer, username: []const u8, password: []const u8) !void {
        try w.writeAll("grant_type=password&client_id=");
        try percentEncode(w, self.config.client_id);
        try w.writeAll("&client_secret=");
        try percentEncode(w, self.config.client_secret);
        try w.writeAll("&username=");
        // Append @domain if configured and username is bare (no @)
        if (self.config.user_domain) |dom| {
            if (std.mem.indexOfScalar(u8, username, '@') == null) {
                try percentEncode(w, username);
                try w.writeAll("%40");
                try percentEncode(w, dom);
            } else {
                try percentEncode(w, username);
            }
        } else {
            try percentEncode(w, username);
        }
        try w.writeAll("&password=");
        try percentEncode(w, password);
        try w.writeAll("&scope=openid%20email%20profile");
    }

    /// OAUTHBEARER path: JWT validation first, introspection for opaque
    /// tokens.
    fn exchangeToken(self: *OidcStore, allocator: Allocator, token: []const u8, options: ExchangeOptions, out: *Identity) Verdict {
        return switch (self.checkJwt(token, options, out)) {
            .verified => .verified,
            .malformed => self.introspect(allocator, token, options, out),
            .invalid => .rejected,
            .unavailable => .unavailable,
            .timed_out => .timed_out,
        };
    }

    /// Full JWT validation against the JWKS cache: parse, exp, iss, aud,
    /// signature, then the claim identity and picture claim.
    fn checkJwt(self: *OidcStore, token: []const u8, options: ExchangeOptions, out: *Identity) JwtCheck {
        const parsed = jwt.parse(token, &jwt_decode_buf) catch return .malformed;

        jwt.validateExpiry(&parsed.claims) catch {
            log.info("JWT: token expired for sub='{s}'", .{parsed.claims.sub});
            return .invalid;
        };
        jwt.validateIssuer(&parsed.claims, self.config.issuer) catch {
            log.info("JWT: issuer mismatch: got '{s}', expected '{s}'", .{ parsed.claims.iss, self.config.issuer });
            return .invalid;
        };
        jwt.validateAudience(&parsed.claims, self.config.client_id) catch {
            log.info("JWT: audience mismatch: got '{s}', expected '{s}'", .{ parsed.claims.aud, self.config.client_id });
            return .invalid;
        };

        const key = switch (self.signingKey(parsed.header.kid, options)) {
            .key => |k| k,
            .absent => {
                log.info("JWT: no matching key for kid='{s}'", .{parsed.header.kid});
                return .invalid;
            },
            .failed => |v| return switch (v) {
                .unavailable => .unavailable,
                .timed_out => .timed_out,
            },
        };

        const sig_valid = switch (key.kty) {
            .rsa => jwt.verifyRs256(&parsed, key.n(), key.e()),
            .okp => jwt.verifyEdDSA(&parsed, key.x()),
        };
        if (!sig_valid) {
            log.info("JWT: signature verification failed for sub='{s}'", .{parsed.claims.sub});
            return .invalid;
        }

        const raw_username = if (parsed.claims.preferred_username.len > 0)
            parsed.claims.preferred_username
        else
            parsed.claims.sub;
        if (raw_username.len == 0) {
            log.info("JWT: no username in token claims", .{});
            return .invalid;
        }
        if (!self.claimIdentity(raw_username, out)) {
            log.info("JWT: claim identity rejected for sub='{s}'", .{parsed.claims.sub});
            return .invalid;
        }
        copyPhoto(parsed.claims.picture, out);
        return .verified;
    }

    /// Derive the authenticated identity from an ROPC 200 response: the
    /// id_token claims when present (full JWT validation), else the
    /// access_token via introspection when an endpoint is configured. The
    /// IdP accepted the password at this point, so a token that then fails
    /// validation is an IdP fault, not a bad credential: .unavailable.
    fn identityFromTokenResponse(self: *OidcStore, allocator: Allocator, body: []const u8, options: ExchangeOptions, out: *Identity) Verdict {
        if (extractNamedField(body, "\"id_token\"")) |id_token| {
            if (id_token.len > 0) {
                return switch (self.checkJwt(id_token, options, out)) {
                    .verified => .verified,
                    .invalid => blk: {
                        log.warn("OIDC: IdP accepted the password but its id_token failed validation", .{});
                        break :blk .unavailable;
                    },
                    .malformed => blk: {
                        log.warn("OIDC: IdP accepted the password but its id_token is not a JWT", .{});
                        break :blk .unavailable;
                    },
                    .unavailable => .unavailable,
                    .timed_out => .timed_out,
                };
            }
        }
        if (extractNamedField(body, "\"access_token\"")) |access_token| {
            if (access_token.len > 0 and self.config.introspection_endpoint != null) {
                return self.introspect(allocator, access_token, options, out);
            }
        }
        log.warn("OIDC: IdP accepted the password but returned no usable id_token or access_token", .{});
        return .unavailable;
    }

    /// Validate a token via the introspection endpoint (RFC 7662).
    fn introspect(self: *OidcStore, allocator: Allocator, token: []const u8, options: ExchangeOptions, out: *Identity) Verdict {
        const endpoint = self.config.introspection_endpoint orelse {
            log.info("OIDC: no introspection endpoint configured", .{});
            return .rejected;
        };

        const cap = 64 + 3 * (token.len + self.config.client_id.len + self.config.client_secret.len);
        const body_buf = allocator.alloc(u8, cap) catch return .unavailable;
        defer {
            std.crypto.secureZero(u8, body_buf);
            allocator.free(body_buf);
        }
        var w: std.Io.Writer = .fixed(body_buf);
        w.writeAll("token=") catch return .unavailable;
        percentEncode(&w, token) catch return .unavailable;
        w.writeAll("&client_id=") catch return .unavailable;
        percentEncode(&w, self.config.client_id) catch return .unavailable;
        w.writeAll("&client_secret=") catch return .unavailable;
        percentEncode(&w, self.config.client_secret) catch return .unavailable;

        var response = self.httpClient().post(allocator, endpoint, w.buffered(), requestOptions(options)) catch |err| {
            log.warn("introspection: HTTP request failed: {s}", .{@errorName(err)});
            return httpVerdict(err);
        };
        defer response.deinit();

        if (response.status != 200) {
            log.info("introspection: endpoint returned {d}", .{response.status});
            return .unavailable;
        }

        const resp_body = response.body;
        if (std.mem.indexOf(u8, resp_body, "\"active\":true") == null and
            std.mem.indexOf(u8, resp_body, "\"active\": true") == null)
        {
            log.info("introspection: token is not active", .{});
            return .rejected;
        }

        const username_claim = extractNamedField(resp_body, "\"username\"") orelse
            extractNamedField(resp_body, "\"sub\"") orelse {
            log.info("introspection: no username in response", .{});
            return .rejected;
        };

        if (!self.claimIdentity(username_claim, out)) {
            log.info("introspection: claim identity rejected", .{});
            return .rejected;
        }
        return .verified;
    }

    /// Classify a non-200 token endpoint response. invalid_grant is a bad
    /// password; the configuration errors are our problem, never the user's
    /// credential; transient statuses are an IdP outage.
    fn classifyTokenError(status: u16, body: []const u8) Verdict {
        const err_field = extractNamedField(body, "\"error\"");
        if ((status == 400 or status == 401) and err_field != null and
            std.mem.eql(u8, err_field.?, "invalid_grant"))
        {
            return .rejected;
        }
        if (err_field) |e| {
            const config_errors = [_][]const u8{
                "invalid_client",
                "unauthorized_client",
                "unsupported_grant_type",
                "invalid_scope",
                "invalid_request",
            };
            for (config_errors) |ce| {
                if (std.mem.eql(u8, e, ce)) {
                    log.warn("OIDC: token endpoint reports a client configuration error '{s}' (status {d})", .{ e, status });
                    return .unavailable;
                }
            }
        }
        if (status == 408 or status == 429 or
            (status >= 500 and status < 600) or
            (status >= 100 and status < 200) or
            (status >= 300 and status < 400))
        {
            return .unavailable;
        }
        if (status >= 400 and status < 500) {
            // Unknown 4xx bodies are how some IdPs answer unknown users
            // (Rauthy's non-RFC body); count it as a bad credential.
            return .rejected;
        }
        return .unavailable;
    }

    // ========================================================================
    // Loop-side replay seam (event-loop thread only)
    // ========================================================================

    pub const ValidateError = error{IdpUnavailable};

    /// Handler seam for a replayed PLAIN exchange: no I/O, reads the Answer
    /// the daemon parked in `answer` before calling handleMessage. The
    /// returned slice borrows store-internal buffers.
    pub fn validatePassword(self: *OidcStore, allocator: Allocator, username: []const u8, password: []const u8) ValidateError!?[]const u8 {
        _ = allocator;
        const answer = self.answer orelse {
            log.warn("PLAIN reached validatePassword without a dispatched exchange (programmer error)", .{});
            return error.IdpUnavailable;
        };
        const digest = credentialDigest(.{ .password = .{
            .username = username,
            .password = password,
        } });
        if (!std.crypto.timing_safe.eql([32]u8, digest, answer.input_digest)) {
            log.warn("PLAIN replay digest mismatch (programmer error)", .{});
            return error.IdpUnavailable;
        }
        return self.replayAnswer(answer);
    }

    /// Handler seam for a replayed OAUTHBEARER exchange.
    pub fn validateToken(self: *OidcStore, allocator: Allocator, token: []const u8) ValidateError!?[]const u8 {
        _ = allocator;
        const answer = self.answer orelse {
            log.warn("OAUTHBEARER reached validateToken without a dispatched exchange (programmer error)", .{});
            return error.IdpUnavailable;
        };
        const digest = credentialDigest(.{ .token = token });
        if (!std.crypto.timing_safe.eql([32]u8, digest, answer.input_digest)) {
            log.warn("OAUTHBEARER replay digest mismatch (programmer error)", .{});
            return error.IdpUnavailable;
        }
        return self.replayAnswer(answer);
    }

    /// Render the replayed answer: copy the verified identity into the
    /// stable buffers for the handler (and getPhotoUrl).
    fn replayAnswer(self: *OidcStore, answer: *const Answer) ValidateError!?[]const u8 {
        switch (answer.verdict) {
            .verified => {
                const name = answer.identity.username();
                @memcpy(self.username_buf[0..name.len], name);
                self.username_len = name.len;
                const photo = answer.identity.photoUrl();
                if (photo.len <= self.photo_url_buf.len) {
                    @memcpy(self.photo_url_buf[0..photo.len], photo);
                    self.photo_url_len = photo.len;
                } else {
                    self.photo_url_len = 0;
                }
                return self.username_buf[0..self.username_len];
            },
            .rejected => return null,
            .unavailable, .timed_out => return error.IdpUnavailable,
        }
    }

    /// Return the photo URL from the last replayed identity, or empty slice.
    pub fn getPhotoUrl(self: *const OidcStore) []const u8 {
        return self.photo_url_buf[0..self.photo_url_len];
    }

    // NOTE: No `lookup` function -- OIDC backends don't support SCRAM-SHA-256.
    // The absence of `lookup` causes AuthHandler to skip SCRAM at comptime.

    // ========================================================================
    // JWKS key management (jwks_mutex)
    // ========================================================================

    /// Signing key for `kid` as a worker-local copy: stale caches refresh
    /// once (a refresh failure still serves cached keys), a kid miss on a
    /// fresh cache refreshes once more for a possible rotation.
    fn signingKey(self: *OidcStore, kid: []const u8, options: ExchangeOptions) KeyFetch {
        self.jwks_mutex.lock();
        defer self.jwks_mutex.unlock();

        const now = std.time.timestamp();
        const cache_stale = (now - self.jwks_last_refresh) > JWKS_MAX_AGE_SECONDS;
        if (cache_stale) {
            self.refreshJwksLocked(options) catch |err| {
                log.warn("JWKS stale refresh failed: {s}; serving cached keys", .{@errorName(err)});
            };
        }

        switch (self.findKeyLocked(kid)) {
            .found => |k| return .{ .key = k },
            .oversize => return .{ .failed = .unavailable },
            .absent => {},
        }
        if (cache_stale) {
            // The refresh above already ran; the kid is genuinely absent.
            return .absent;
        }

        // Kid miss on a fresh cache: the IdP may have rotated keys.
        self.refreshJwksLocked(options) catch |err| {
            return .{ .failed = switch (err) {
                error.Timeout => .timed_out,
                error.FetchFailed, error.OutOfMemory => .unavailable,
            } };
        };
        return switch (self.findKeyLocked(kid)) {
            .found => |k| .{ .key = k },
            .oversize => .{ .failed = .unavailable },
            .absent => .absent,
        };
    }

    /// Direct cache lookup; copies the matched key's components so no
    /// jwks_body slice escapes the lock. Caller holds jwks_mutex.
    fn findKeyLocked(self: *OidcStore, kid: []const u8) KeyLookup {
        for (self.keys[0..self.key_count]) |*k| {
            if (!std.mem.eql(u8, k.kid, kid)) continue;
            var copy: KeyCopy = .{ .kty = k.kty };
            switch (k.kty) {
                .rsa => {
                    if (k.n.len > copy.n_buf.len or k.e.len > copy.e_buf.len) {
                        log.warn("JWKS: key '{s}' component exceeds the {d}-byte bound", .{ kid, copy.n_buf.len });
                        return .oversize;
                    }
                    @memcpy(copy.n_buf[0..k.n.len], k.n);
                    copy.n_len = @intCast(k.n.len);
                    @memcpy(copy.e_buf[0..k.e.len], k.e);
                    copy.e_len = @intCast(k.e.len);
                },
                .okp => {
                    if (k.x.len > copy.x_buf.len) {
                        log.warn("JWKS: key '{s}' component exceeds the {d}-byte bound", .{ kid, copy.x_buf.len });
                        return .oversize;
                    }
                    @memcpy(copy.x_buf[0..k.x.len], k.x);
                    copy.x_len = @intCast(k.x.len);
                },
            }
            return .{ .found = copy };
        }
        return .absent;
    }

    /// Fetch JWKS from the IdP and replace the key cache. Caller holds
    /// jwks_mutex; the HTTP GET is serialized with every other refresh and
    /// bounded by the request deadline.
    fn refreshJwksLocked(self: *OidcStore, options: ExchangeOptions) JwksError!void {
        log.info("refreshing JWKS from {s}", .{self.config.jwks_uri});

        var response = self.httpClient().get(self.allocator, self.config.jwks_uri, requestOptions(options)) catch |err| {
            log.warn("JWKS fetch failed: {s}", .{@errorName(err)});
            return switch (httpVerdict(err)) {
                .timed_out => JwksError.Timeout,
                .verified, .rejected, .unavailable => JwksError.FetchFailed,
            };
        };
        defer response.deinit();

        if (response.status != 200) {
            log.warn("JWKS endpoint returned {d}", .{response.status});
            return JwksError.FetchFailed;
        }

        // Copy response body into our own allocation (response.deinit frees its copy)
        const body_copy = self.allocator.alloc(u8, response.body.len) catch return JwksError.OutOfMemory;
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
    /// Caller holds jwks_mutex.
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
                // RSA key -- need n and e
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
                // EdDSA (Ed25519) key -- need x
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

// ============================================================================
// IdpPool -- bounded worker pool for blocking IdP exchanges
// ============================================================================

/// One queued exchange. `secret` is pool-owned (secret_alloc): for .password
/// it is `username ++ 0x00 ++ password` with `username_len` marking the
/// split; for .token it is the token bytes (username_len unused). Wiped and
/// freed by releaseJob.
pub const IdpJob = struct {
    id: u64,
    secret: []u8,
    kind: IdpJobKind,
    username_len: usize,
    /// Absolute CLOCK_MONOTONIC deadline stamped at put(): queue time
    /// counts against the exchange budget.
    deadline_ns: u64,
    answer: Answer,
    /// Allocator `secret` was allocated with; stamped at put() so every
    /// releaseJob frees with the same one.
    secret_alloc: Allocator = std.heap.c_allocator,
};

pub const IdpJobKind = enum { password, token };

/// Bounded pool of worker threads running OidcStore.exchange off the
/// daemon's event loop. put() runs on the loop thread and never blocks;
/// workers publish completions through a fixed ring and wake the loop with
/// one pipe byte (the completion is pushed before the wake write). Closing
/// the cancel pipe's write end broadcasts EOF into every in-flight HTTP
/// exchange's wait loop.
///
/// Threads and ownership: the loop thread produces jobs and consumes
/// completions; workers only read jobs, run exchange and publish. Secrets
/// are deep-copied with the pool's secret allocator (c_allocator by
/// default, so loop and workers share no allocator state) and are wiped
/// with secureZero before every free.
///
/// Invariants and bound:
/// - outstanding (queued + running + completed-not-popped) <= max_outstanding
/// - job and completion rings are fixed FIFO buffers of max_outstanding
///   entries preallocated at start, so publishing can never allocate or fail
/// - a completion for a dropped job id is a stale completion and is ignored
pub const IdpPool = struct {
    allocator: Allocator = undefined,
    store: *OidcStore = undefined,
    options: Options = undefined,

    /// Allocator for job secrets; c_allocator by default so workers can
    /// free without sharing allocator state with the loop thread. May be
    /// swapped before jobs are queued to observe or bound the copies.
    secret_alloc: Allocator = std.heap.c_allocator,

    /// FIFO job ring (loop produces, workers consume; job_mutex).
    jobs: []IdpJob = &.{},
    jobs_head: usize = 0,
    jobs_count: usize = 0,
    job_mutex: std.Thread.Mutex = .{},
    job_cond: std.Thread.Condition = .{},

    /// FIFO completion ring (workers produce, loop consumes; completion_mutex).
    completions: []IdpJob = &.{},
    completions_head: usize = 0,
    completions_count: usize = 0,
    completion_mutex: std.Thread.Mutex = .{},

    /// Queued + running + completed-not-popped. Read and written on the
    /// loop thread only (put and popCompletion).
    outstanding_count: usize = 0,

    stopping: bool = false,
    next_job_id: u64 = 1,

    /// Exchanges a worker actually ran; observability for tests and
    /// metrics. Written by workers, read by anyone.
    exchanges_run: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    /// Wake pipe: worker writes one byte per completion; the loop reads.
    wake_rd: posix.fd_t = -1,
    wake_wr: posix.fd_t = -1,
    /// Cancel pipe: closing the write end broadcasts EOF into every
    /// in-flight request's wait.
    cancel_rd: posix.fd_t = -1,
    cancel_wr: posix.fd_t = -1,

    threads_buf: [max_threads]std.Thread = undefined,
    thread_count: usize = 0,
    started: bool = false,

    pub const max_threads = 32;

    pub const Options = struct {
        threads: u8,
        max_outstanding: u16,
        connect_timeout_ms: u32,
        timeout_ms: u32,
    };

    /// Everything start() can fail with: the two pipes, the ring
    /// allocations and the worker spawns.
    pub const StartError = posix.PipeError || std.Thread.SpawnError || error{OutOfMemory};

    /// Spawn the workers and open the wake and cancel pipes.
    pub fn start(self: *IdpPool, allocator: Allocator, store: *OidcStore, options: Options) StartError!void {
        self.allocator = allocator;
        self.store = store;
        self.options = options;

        const wake = try posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
        errdefer posix.close(wake[0]);
        errdefer posix.close(wake[1]);
        self.wake_rd = wake[0];
        self.wake_wr = wake[1];

        const cancel = try posix.pipe2(.{ .CLOEXEC = true });
        errdefer posix.close(cancel[0]);
        errdefer posix.close(cancel[1]);
        self.cancel_rd = cancel[0];
        self.cancel_wr = cancel[1];

        self.jobs = try allocator.alloc(IdpJob, options.max_outstanding);
        errdefer allocator.free(self.jobs);
        self.completions = try allocator.alloc(IdpJob, options.max_outstanding);
        errdefer allocator.free(self.completions);

        const n = @min(options.threads, max_threads);
        errdefer {
            // Undo spawned threads on a partial-start failure.
            self.job_mutex.lock();
            self.stopping = true;
            self.job_cond.broadcast();
            self.job_mutex.unlock();
            for (self.threads_buf[0..self.thread_count]) |t| t.join();
        }
        for (0..n) |i| {
            self.threads_buf[i] = std.Thread.spawn(.{}, workerMain, .{self}) catch |err| {
                // Pool with zero threads is useless; errdefer closes everything.
                if (i == 0) return err;
                break;
            };
            self.thread_count += 1;
        }

        self.started = true;
    }

    /// Queue a credential exchange. The secret is deep-copied with the
    /// pool's secret allocator; the pool owns it until releaseJob or
    /// stop. QueueFull when outstanding == max_outstanding. Never blocks;
    /// allocates nothing besides the secret copy.
    pub fn put(self: *IdpPool, cred: Credential) error{ QueueFull, OutOfMemory }!u64 {
        var kind: IdpJobKind = undefined;
        var username_len: usize = 0;
        var secret_len: usize = 0;
        switch (cred) {
            .password => |p| {
                kind = .password;
                username_len = p.username.len;
                secret_len = p.username.len + 1 + p.password.len;
            },
            .token => |t| {
                kind = .token;
                secret_len = t.len;
            },
        }

        const secret = self.secret_alloc.alloc(u8, secret_len) catch return error.OutOfMemory;
        errdefer {
            std.crypto.secureZero(u8, secret);
            self.secret_alloc.free(secret);
        }
        switch (cred) {
            .password => |p| {
                @memcpy(secret[0..p.username.len], p.username);
                secret[p.username.len] = 0;
                @memcpy(secret[p.username.len + 1 ..][0..p.password.len], p.password);
            },
            .token => |t| @memcpy(secret, t),
        }

        const id = self.next_job_id;
        self.job_mutex.lock();
        defer self.job_mutex.unlock();
        if (self.outstanding_count >= self.options.max_outstanding) return error.QueueFull;
        // The ring cannot overflow: outstanding < max_outstanding == ring len.
        const tail = (self.jobs_head + self.jobs_count) % self.jobs.len;
        self.jobs[tail] = .{
            .id = id,
            .secret = secret,
            .kind = kind,
            .username_len = username_len,
            .secret_alloc = self.secret_alloc,
            .deadline_ns = http.monotonicNs() + @as(u64, self.options.timeout_ms) * std.time.ns_per_ms,
            .answer = .{
                .verdict = .unavailable,
                .input_digest = credentialDigest(cred),
            },
        };
        self.jobs_count += 1;
        self.outstanding_count += 1;
        self.next_job_id +%= 1;
        self.job_cond.signal();
        return id;
    }

    /// Drain the wake pipe after its EVFILT_READ fires.
    pub fn drainWake(self: *IdpPool) void {
        var buf: [64]u8 = undefined;
        while (true) {
            const n = posix.read(self.wake_rd, &buf) catch |err| {
                if (err == error.WouldBlock) break;
                log.err("IdP wake pipe drain failed: {s}", .{@errorName(err)});
                break;
            };
            if (n <= 0) break;
            if (n < buf.len) break;
        }
    }

    /// Pop a finished exchange, or null when the drain is done. The caller
    /// must releaseJob the returned value after consuming its answer.
    pub fn popCompletion(self: *IdpPool) ?IdpJob {
        self.completion_mutex.lock();
        defer self.completion_mutex.unlock();
        if (self.completions_count == 0) return null;
        const job = self.completions[self.completions_head];
        self.completions_head = (self.completions_head + 1) % self.completions.len;
        self.completions_count -= 1;
        self.outstanding_count -= 1;
        return job;
    }

    /// Wipe and free a job's secret after its completion was consumed.
    pub fn releaseJob(job: *IdpJob) void {
        std.crypto.secureZero(u8, job.secret);
        job.secret_alloc.free(job.secret);
        job.secret = undefined;
    }

    /// Queued + running + completed-not-popped jobs.
    pub fn outstanding(self: *IdpPool) usize {
        return self.outstanding_count;
    }

    /// Cancel in-flight exchanges (broadcast EOF through the cancel pipe),
    /// join the workers, and free queued and completed jobs. Idempotent.
    pub fn stop(self: *IdpPool) void {
        if (!self.started) return;
        self.started = false;

        {
            self.job_mutex.lock();
            self.stopping = true;
            self.job_cond.broadcast();
            self.job_mutex.unlock();
        }
        // Closing the write end wakes every worker waiting on the read end
        // inside an in-flight HTTP exchange.
        if (self.cancel_wr >= 0) {
            posix.close(self.cancel_wr);
            self.cancel_wr = -1;
        }
        for (self.threads_buf[0..self.thread_count]) |t| t.join();
        self.thread_count = 0;

        for (0..self.jobs_count) |i| {
            releaseJob(&self.jobs[(self.jobs_head + i) % self.jobs.len]);
        }
        self.jobs_count = 0;
        self.jobs_head = 0;
        for (0..self.completions_count) |i| {
            releaseJob(&self.completions[(self.completions_head + i) % self.completions.len]);
        }
        self.completions_count = 0;
        self.completions_head = 0;
        self.outstanding_count = 0;

        self.allocator.free(self.jobs);
        self.allocator.free(self.completions);
        self.jobs = &.{};
        self.completions = &.{};

        if (self.wake_rd >= 0) posix.close(self.wake_rd);
        if (self.wake_wr >= 0) posix.close(self.wake_wr);
        if (self.cancel_rd >= 0) posix.close(self.cancel_rd);
        self.wake_rd = -1;
        self.wake_wr = -1;
        self.cancel_rd = -1;
    }

    /// Publish a completion then write one wake byte. The push cannot fail
    /// (bounded rings, never more than max_outstanding outstanding); the
    /// byte only has to reach a pipe that already holds pending wakes, so a
    /// full pipe needs no write.
    fn finish(self: *IdpPool, job: IdpJob) void {
        self.completion_mutex.lock();
        const tail = (self.completions_head + self.completions_count) % self.completions.len;
        self.completions[tail] = job;
        self.completions_count += 1;
        self.completion_mutex.unlock();

        _ = posix.write(self.wake_wr, "\x00") catch |err| {
            if (err == error.WouldBlock) return; // pending bytes already wake the loop
            log.err("IdP completion wake write failed for job {d}: {s}", .{ job.id, @errorName(err) });
        };
    }

    fn jobCredential(job: *const IdpJob) Credential {
        return switch (job.kind) {
            .password => .{ .password = .{
                .username = job.secret[0..job.username_len],
                .password = job.secret[job.username_len + 1 ..],
            } },
            .token => .{ .token = job.secret },
        };
    }

    fn workerMain(self: *IdpPool) void {
        while (true) {
            const entry = blk: {
                self.job_mutex.lock();
                defer self.job_mutex.unlock();
                while (self.jobs_count == 0 and !self.stopping) {
                    self.job_cond.wait(&self.job_mutex);
                }
                if (self.jobs_count == 0) break :blk null;
                const j = self.jobs[self.jobs_head];
                self.jobs_head = (self.jobs_head + 1) % self.jobs.len;
                self.jobs_count -= 1;
                break :blk .{ .job = j, .stopping = self.stopping };
            } orelse return;

            var owned_job = entry.job;
            if (entry.stopping) {
                // Shutdown: queued exchanges are cancelled, never run
                // (no blocking DNS on the way out).
                releaseJob(&owned_job);
                continue;
            }
            var identity: Identity = .{};
            if (http.monotonicNs() >= owned_job.deadline_ns) {
                // The queue time already ate the whole budget: complete
                // as timed_out without contacting the IdP.
                owned_job.answer.verdict = .timed_out;
            } else {
                _ = self.exchanges_run.fetchAdd(1, .monotonic);
                owned_job.answer.verdict = self.store.exchange(std.heap.c_allocator, jobCredential(&owned_job), .{
                    .connect_timeout_ms = self.options.connect_timeout_ms,
                    .deadline_ns = owned_job.deadline_ns,
                    .cancel_fd = self.cancel_rd,
                }, &identity);
            }
            owned_job.answer.identity = identity;
            self.finish(owned_job);
        }
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
fn percentEncode(writer: *std.Io.Writer, input: []const u8) !void {
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

fn testStore(allocator: Allocator, extra: struct {
    token_endpoint: []const u8 = "https://idp.example/token",
    jwks_uri: []const u8 = "https://idp.example/certs",
    introspection_endpoint: ?[]const u8 = null,
    ca_file: ?[]const u8 = null,
    user_domain: ?[]const u8 = null,
}) OidcStore {
    return OidcStore.init(allocator, .{
        .issuer = "https://idp.example/",
        .client_id = "xmppd",
        .client_secret = "secret",
        .token_endpoint = extra.token_endpoint,
        .jwks_uri = extra.jwks_uri,
        .introspection_endpoint = extra.introspection_endpoint,
        .ca_file = extra.ca_file,
        .user_domain = extra.user_domain,
    });
}

fn testOptions(timeout_ms: u32) ExchangeOptions {
    return .{
        .connect_timeout_ms = @min(timeout_ms, 3000),
        .deadline_ns = http.monotonicNs() + @as(u64, timeout_ms) * std.time.ns_per_ms,
    };
}

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

test "plainCredentials: the handler's split rules" {
    const creds = plainCredentials("\x00alice\x00secret").?;
    try std.testing.expectEqualStrings("alice", creds.username);
    try std.testing.expectEqualStrings("secret", creds.password);
    try std.testing.expect(plainCredentials("no-nuls") == null);
    try std.testing.expect(plainCredentials("\x00alice\x00") == null); // empty password
    try std.testing.expect(plainCredentials("") == null);
}

test "bearerToken: RFC 7628 and raw-token fallback" {
    try std.testing.expectEqualStrings("tok123", bearerToken("n,,\x01auth=Bearer tok123\x01\x01").?);
    try std.testing.expectEqualStrings("opaque", bearerToken("opaque").?);
    try std.testing.expect(bearerToken("") == null);
    try std.testing.expect(bearerToken("n,,\x01auth=Bearer \x01") == null);
}

test "credentialDigest: kinds tag the input" {
    const a = credentialDigest(.{ .password = .{ .username = "alice", .password = "pw" } });
    const b = credentialDigest(.{ .password = .{ .username = "alice", .password = "pw" } });
    const other = credentialDigest(.{ .password = .{ .username = "alice", .password = "pw2" } });
    const as_token = credentialDigest(.{ .token = "pw" });
    try std.testing.expect(std.crypto.timing_safe.eql([32]u8, a, b));
    try std.testing.expect(!std.crypto.timing_safe.eql([32]u8, a, other));
    try std.testing.expect(!std.crypto.timing_safe.eql([32]u8, a, as_token));
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
    var w: std.Io.Writer = .fixed(&buf);
    try percentEncode(&w, "alice");
    try std.testing.expectEqualStrings("alice", w.buffered());
}

test "percentEncode: special chars encoded" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try percentEncode(&w, "p@ss w0rd!");
    try std.testing.expectEqualStrings("p%40ss%20w0rd%21", w.buffered());
}

test "percentEncode: all reserved form chars" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try percentEncode(&w, "&=+%");
    try std.testing.expectEqualStrings("%26%3D%2B%25", w.buffered());
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

    var id: Identity = .{};
    try std.testing.expect(store.claimIdentity("alice", &id));
    try std.testing.expectEqualStrings("alice", id.username());
    id = .{};
    try std.testing.expect(store.claimIdentity("alice@us.example", &id));
    try std.testing.expectEqualStrings("alice", id.username());
    // Claim case is preserved; folding is the lock store's job.
    id = .{};
    try std.testing.expect(store.claimIdentity("Alice@US.EXAMPLE", &id));
    try std.testing.expectEqualStrings("Alice", id.username());
    // A foreign domain in the claim is rejected when user_domain is set.
    try std.testing.expect(!store.claimIdentity("alice@other.example", &id));
    try std.testing.expect(!store.claimIdentity("", &id));

    // Without user_domain configured any claim domain passes and is stripped.
    store.config.user_domain = null;
    id = .{};
    try std.testing.expect(store.claimIdentity("alice@wherever.example", &id));
    try std.testing.expectEqualStrings("alice", id.username());
}

// --- Replay seam tests ------------------------------------------------

test "OidcStore: validate without a dispatched exchange fails closed" {
    const allocator = std.testing.allocator;
    var store = testStore(allocator, .{});
    defer store.deinit();

    try std.testing.expectError(
        OidcStore.ValidateError.IdpUnavailable,
        store.validatePassword(allocator, "alice", "pw"),
    );
    try std.testing.expectError(
        OidcStore.ValidateError.IdpUnavailable,
        store.validateToken(allocator, "opaque-token"),
    );
}

test "OidcStore: a digest mismatch fails closed" {
    const allocator = std.testing.allocator;
    var store = testStore(allocator, .{});
    defer store.deinit();

    const answer = Answer{
        .verdict = .rejected,
        .input_digest = credentialDigest(.{ .password = .{ .username = "alice", .password = "other-pw" } }),
    };
    store.answer = &answer;
    defer store.answer = null;

    try std.testing.expectError(
        OidcStore.ValidateError.IdpUnavailable,
        store.validatePassword(allocator, "alice", "pw"),
    );
}

test "OidcStore: a token digest mismatch fails closed" {
    const allocator = std.testing.allocator;
    var store = testStore(allocator, .{});
    defer store.deinit();

    // The parked answer was computed for a different token than the one
    // the replaying request carries; validateToken must not consult it.
    const answer = Answer{
        .verdict = .rejected,
        .input_digest = credentialDigest(.{ .token = "other-token" }),
    };
    store.answer = &answer;
    defer store.answer = null;

    try std.testing.expectError(
        OidcStore.ValidateError.IdpUnavailable,
        store.validateToken(allocator, "the-token"),
    );
}

test "OidcStore: an oversized JWKS key is unavailable, never a rejection" {
    const allocator = std.testing.allocator;
    var store = testStore(allocator, .{});
    defer store.deinit();
    try store.start();

    // One modulus past the copy bound, one exactly at an 8192-bit RSA
    // modulus (1366 base64url chars) that must still verify.
    const body = try std.fmt.allocPrint(allocator,
        \\{{"keys":[{{"kty":"RSA","kid":"huge","n":"{s}","e":"AQAB"}},{{"kty":"RSA","kid":"rsa8k","n":"{s}","e":"AQAB"}}]}}
    , .{ "A" ** 3000, "A" ** 1366 });
    store.jwks_body = body; // deinit frees it
    store.jwks_last_refresh = 0; // stale: a failed refresh still serves the cache
    store.parseJwksKeys();
    try std.testing.expectEqual(@as(usize, 2), store.key_count);

    // The oversized kid reads as an IdP outage, so the user attempt is
    // answered temporary-auth-failure rather than counted as a rejection.
    switch (store.signingKey("huge", testOptions(5000))) {
        .failed => |v| try std.testing.expect(v == .unavailable),
        else => return error.ExpectedUnavailable,
    }
    // The 8192-bit key fits the copy bound and is served normally.
    switch (store.signingKey("rsa8k", testOptions(5000))) {
        .key => |k| try std.testing.expectEqual(@as(usize, 1366), k.n().len),
        else => return error.ExpectedKey,
    }
}

fn fetchSigningKey(store: *OidcStore, kid: []const u8, hits: *std.atomic.Value(usize)) void {
    switch (store.signingKey(kid, testOptions(8000))) {
        .key => _ = hits.fetchAdd(1, .monotonic),
        else => {},
    }
}

test "OidcStore: concurrent kid misses fetch the JWKS once" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const paths = try makeIdpTlsPaths(allocator, &tmp);
    defer allocator.free(paths.cert);
    defer allocator.free(paths.key);

    const jwks = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k1\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}";
    var fetches = std.atomic.Value(usize).init(0);
    var port = std.atomic.Value(u16).init(0);
    const stub = try std.Thread.spawn(
        .{},
        serveJwksCounted,
        .{ paths.cert.ptr, paths.key.ptr, jwks, 800, &fetches, &port },
    );
    defer stub.join();
    const dl = std.time.milliTimestamp() + 5000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) std.Thread.sleep(std.time.ns_per_ms);
    try std.testing.expect(port.load(.acquire) != 0);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/certs", .{port.load(.acquire)});
    var store = testStore(allocator, .{ .jwks_uri = url, .ca_file = paths.cert });
    defer store.deinit();
    try store.start();

    // Two workers race a cold cache for the same kid: jwks_mutex makes
    // the second wait out the whole refresh and find the key cached, so
    // the IdP sees exactly one GET and jwks_body is never freed under a
    // reader.
    var hits = std.atomic.Value(usize).init(0);
    const t1 = try std.Thread.spawn(.{}, fetchSigningKey, .{ &store, "k1", &hits });
    const t2 = try std.Thread.spawn(.{}, fetchSigningKey, .{ &store, "k1", &hits });
    t1.join();
    t2.join();
    try std.testing.expectEqual(@as(usize, 2), hits.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), fetches.load(.acquire));
}

test "OidcStore: replay returns identity, rejection and temporary failure" {
    const allocator = std.testing.allocator;
    var store = testStore(allocator, .{});
    defer store.deinit();

    const cred = Credential{ .password = .{ .username = "alice", .password = "pw" } };
    const digest = credentialDigest(cred);

    var id: Identity = .{};
    try std.testing.expect(store.claimIdentity("alice", &id));

    const verified = Answer{ .verdict = .verified, .identity = id, .input_digest = digest };
    store.answer = &verified;
    const name = (try store.validatePassword(allocator, "alice", "pw")).?;
    try std.testing.expectEqualStrings("alice", name);
    store.answer = null;

    const rejected = Answer{ .verdict = .rejected, .input_digest = digest };
    store.answer = &rejected;
    try std.testing.expect((try store.validatePassword(allocator, "alice", "pw")) == null);
    store.answer = null;

    const timed = Answer{ .verdict = .timed_out, .input_digest = digest };
    store.answer = &timed;
    try std.testing.expectError(
        OidcStore.ValidateError.IdpUnavailable,
        store.validatePassword(allocator, "alice", "pw"),
    );
    store.answer = null;
}

/// Write a fresh self-signed cert+key for "localhost" into `dir` via the
/// system OpenSSL CLI. error.SkipZigTest when the tool is missing.
/// openssl writes key-generation progress to stderr, which can exceed a
/// small output cap under load, so allow generous room for it.
fn genIdpTestCert(dir: std.fs.Dir) !void {
    const r = std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &.{ "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1", "-keyout", "key.pem", "-out", "cert.pem" },
        .cwd_dir = dir,
        .max_output_bytes = 64 * 1024,
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
/// `status_line` is the response's status text ("200 OK"). The bound port
/// is published via port_out; a deadline keeps the test from hanging when
/// the client never connects. kTLS stays off on this end (one userland TLS
/// end avoids FreeBSD PR 296498 on loopback).
fn serveOneTlsResponse(cert_path: [*:0]const u8, key_path: [*:0]const u8, status_line: []const u8, body: []const u8, port_out: *std.atomic.Value(u16)) void {
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
        const out = std.fmt.bufPrint(&resp, "HTTP/1.1 {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ status_line, body.len, body }) catch return;
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

/// Serve `body` as a JWKS document on every accepted connection, counting
/// fetches and stalling before each response: the first caller holds
/// jwks_mutex through the stall, so a racing caller on the same cold
/// cache reaches the IdP only when the lock is missing. Exits once the
/// backlog stays quiet after the first fetch.
fn serveJwksCounted(
    cert_path: [*:0]const u8,
    key_path: [*:0]const u8,
    body: []const u8,
    stall_ms: u64,
    fetches: *std.atomic.Value(usize),
    port_out: *std.atomic.Value(u16),
) void {
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

    const deadline = std.time.milliTimestamp() + 15000;
    var quiet_polls: usize = 0;
    while (std.time.milliTimestamp() < deadline) {
        var fds = [_]posix.pollfd{.{ .fd = listen_fd, .events = posix.POLL.IN, .revents = 0 }};
        const pn = posix.poll(&fds, 300) catch 0;
        if (pn <= 0) {
            if (fetches.load(.acquire) > 0) {
                quiet_polls += 1;
                if (quiet_polls > 4) return;
            }
            continue;
        }
        quiet_polls = 0;
        const conn_fd = posix.accept(listen_fd, null, null, 0) catch continue;
        defer posix.close(conn_fd);
        _ = fetches.fetchAdd(1, .monotonic);
        var conn = ssl.SslConn.init(ctx, conn_fd) catch continue;
        defer {
            conn.shutdown();
            conn.deinit();
        }
        var hs_done = false;
        while (!hs_done and std.time.milliTimestamp() < deadline) {
            const hs = conn.doHandshake() catch break;
            hs_done = hs == .complete;
        }
        if (!hs_done) continue;
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
        std.Thread.sleep(stall_ms * std.time.ns_per_ms);
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
    }
}

/// Cert/key paths for a one-shot TLS IdP stub; caller frees with deinitPaths.
const IdpTlsPaths = struct {
    cert: [:0]u8,
    key: [:0]u8,
};

fn makeIdpTlsPaths(allocator: Allocator, tmp: *std.testing.TmpDir) !IdpTlsPaths {
    genIdpTestCert(tmp.dir) catch return error.SkipZigTest;
    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    return .{
        .cert = try std.fmt.allocPrintSentinel(allocator, "{s}/cert.pem", .{base}, 0),
        .key = try std.fmt.allocPrintSentinel(allocator, "{s}/key.pem", .{base}, 0),
    };
}

/// Run one ROPC exchange against a TLS stub answering `status_line` + `body`.
fn exchangeAgainstTlsStub(allocator: Allocator, tmp: *std.testing.TmpDir, status_line: []const u8, body: []const u8, cred: Credential) !Verdict {
    const paths = try makeIdpTlsPaths(allocator, tmp);
    defer allocator.free(paths.cert);
    defer allocator.free(paths.key);

    var port = std.atomic.Value(u16).init(0);
    const th = try std.Thread.spawn(.{}, serveOneTlsResponse, .{ paths.cert.ptr, paths.key.ptr, status_line, body, &port });
    defer th.join();
    const dl = std.time.milliTimestamp() + 5000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) std.Thread.sleep(std.time.ns_per_ms);
    try std.testing.expect(port.load(.acquire) != 0);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://localhost:{d}/token", .{port.load(.acquire)});

    var store = testStore(allocator, .{ .token_endpoint = url, .ca_file = paths.cert });
    defer store.deinit();
    try store.start();

    var identity: Identity = .{};
    return store.exchange(allocator, cred, testOptions(8000), &identity);
}

test "OidcStore: token endpoint classification" {
    const allocator = std.testing.allocator;
    const cred = Credential{ .password = .{ .username = "alice", .password = "pw" } };

    // A bad password is a clean rejection.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const v = try exchangeAgainstTlsStub(allocator, &tmp, "400 Bad Request", "{\"error\":\"invalid_grant\"}", cred);
        try std.testing.expectEqual(Verdict.rejected, v);
    }
    // A client configuration error is our fault, never the user's credential.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const v = try exchangeAgainstTlsStub(allocator, &tmp, "401 Unauthorized", "{\"error\":\"invalid_client\"}", cred);
        try std.testing.expectEqual(Verdict.unavailable, v);
    }
    // A 5xx is an IdP outage.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const v = try exchangeAgainstTlsStub(allocator, &tmp, "503 Service Unavailable", "{}", cred);
        try std.testing.expectEqual(Verdict.unavailable, v);
    }
    // A non-RFC 4xx body is how some IdPs answer unknown users: rejected.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const v = try exchangeAgainstTlsStub(allocator, &tmp, "404 Not Found", "{\"error\":\"NotFound\",\"message\":\"no rows returned\"}", cred);
        try std.testing.expectEqual(Verdict.rejected, v);
    }
}

test "OidcStore: a 200 with a bad id_token is unavailable, never a rejection" {
    const allocator = std.testing.allocator;
    const cred = Credential{ .password = .{ .username = "alice", .password = "pw" } };

    // The IdP accepted the password, so an id_token that then fails
    // validation is an IdP fault: the attempt must be answered
    // temporary-auth-failure, not counted as a bad credential.
    const bad_iss =
        "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0" ++
        ".eyJzdWIiOiJhbGljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC5leGFtcGxlLmNvbSIsImV4cCI6OTk5OTk5OTk5OSwiYXVkIjoieG1wcGQiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGljZSJ9" ++
        ".dGVzdA";
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const body = try std.fmt.allocPrint(allocator, "{{\"id_token\":\"{s}\"}}", .{bad_iss});
        defer allocator.free(body);
        const v = try exchangeAgainstTlsStub(allocator, &tmp, "200 OK", body, cred);
        try std.testing.expectEqual(Verdict.unavailable, v);
    }
    // The same when the id_token is not a JWT at all.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const v = try exchangeAgainstTlsStub(allocator, &tmp, "200 OK", "{\"id_token\":\"not-a-jwt\"}", cred);
        try std.testing.expectEqual(Verdict.unavailable, v);
    }
}

test "OidcStore: a 200 without id_token or introspection is unavailable, never the typed name" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cred = Credential{ .password = .{ .username = "ALICE@us.example", .password = "pw" } };
    const v = try exchangeAgainstTlsStub(allocator, &tmp, "200 OK", "{\"access_token\":\"opaque-token\",\"token_type\":\"Bearer\"}", cred);
    try std.testing.expectEqual(Verdict.unavailable, v);

    // Replay of that verdict through the handler seam errors out; the
    // typed name must never come back as an identity -- a case or domain
    // variant of a locked account would ride it past the lock check.
    var store = testStore(allocator, .{});
    defer store.deinit();
    const answer = Answer{ .verdict = v, .input_digest = credentialDigest(cred) };
    store.answer = &answer;
    defer store.answer = null;
    try std.testing.expectError(
        OidcStore.ValidateError.IdpUnavailable,
        store.validatePassword(allocator, "ALICE@us.example", "pw"),
    );
}

// --- IdpPool tests -----------------------------------------------------

/// A loopback port that refuses connections (bound then closed): an
/// exchange against it fails fast, so tests can turn jobs around quickly.
fn refusedPort() !u16 {
    const listen_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    var addr: std.c.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    try posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in));
    var alen: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    try posix.getsockname(listen_fd, @ptrCast(&addr), &alen);
    const port = std.mem.bigToNative(u16, addr.port);
    posix.close(listen_fd);
    return port;
}

/// Store whose token and JWKS endpoints point at a refused port: every
/// exchange completes .unavailable without waiting on a deadline.
fn refusedStore(allocator: Allocator, port: u16, url_buf: []u8) !OidcStore {
    const url = try std.fmt.bufPrint(url_buf, "https://127.0.0.1:{d}/", .{port});
    var store = testStore(allocator, .{ .token_endpoint = url, .jwks_uri = url });
    try store.start();
    return store;
}

/// Test allocator that snapshots every freed buffer before releasing it,
/// so wipe paths can be proven: any secret left in a freed buffer is found.
const FreeSnapshot = struct {
    inner: Allocator,
    mutex: std.Thread.Mutex = .{},
    freed: std.ArrayListUnmanaged([]u8) = .empty,

    fn allocator(self: *FreeSnapshot) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = allocFn,
                .resize = resizeFn,
                .remap = remapFn,
                .free = freeFn,
            },
        };
    }

    fn allocFn(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *FreeSnapshot = @ptrCast(@alignCast(ctx));
        return self.inner.rawAlloc(len, alignment, ra);
    }

    fn resizeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *FreeSnapshot = @ptrCast(@alignCast(ctx));
        return self.inner.rawResize(memory, alignment, new_len, ra);
    }

    fn remapFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *FreeSnapshot = @ptrCast(@alignCast(ctx));
        return self.inner.rawRemap(memory, alignment, new_len, ra);
    }

    fn freeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *FreeSnapshot = @ptrCast(@alignCast(ctx));
        if (memory.len > 0) {
            const copy = self.inner.alloc(u8, memory.len) catch @panic("snapshot");
            @memcpy(copy, memory);
            self.mutex.lock();
            defer self.mutex.unlock();
            self.freed.append(self.inner, copy) catch @panic("snapshot");
        }
        self.inner.rawFree(memory, alignment, ra);
    }

    fn deinit(self: *FreeSnapshot) void {
        for (self.freed.items) |buf| self.inner.free(buf);
        self.freed.deinit(self.inner);
    }

    /// No freed buffer may still carry the marker bytes.
    fn assertFreedWiped(self: *FreeSnapshot, marker: []const u8) !void {
        for (self.freed.items) |buf| {
            try std.testing.expect(std.mem.indexOf(u8, buf, marker) == null);
        }
    }
};

/// Loopback TCP listener that accepts into a hold array and never answers,
/// so a worker's TLS handshake waits until the cancel pipe or the deadline
/// fires it.
fn serveHanging(port_out: *std.atomic.Value(u16)) void {
    const listen_fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(listen_fd);
    var addr: std.c.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch return;
    posix.listen(listen_fd, 8) catch return;
    var alen: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    posix.getsockname(listen_fd, @ptrCast(&addr), &alen) catch return;
    port_out.store(std.mem.bigToNative(u16, addr.port), .release);

    const deadline = std.time.milliTimestamp() + 15000;
    var held: [32]posix.fd_t = undefined;
    var held_len: usize = 0;
    defer for (held[0..held_len]) |conn_fd| posix.close(conn_fd);
    while (std.time.milliTimestamp() < deadline) {
        var fds = [_]posix.pollfd{.{ .fd = listen_fd, .events = posix.POLL.IN, .revents = 0 }};
        const pn = posix.poll(&fds, 250) catch 0;
        if (pn <= 0) continue;
        if (held_len >= held.len) continue;
        const conn_fd = posix.accept(listen_fd, null, null, 0) catch continue;
        held[held_len] = conn_fd;
        held_len += 1;
    }
}

fn startHangingStub(port_out: *std.atomic.Value(u16)) !std.Thread {
    const th = try std.Thread.spawn(.{}, serveHanging, .{port_out});
    const dl = std.time.milliTimestamp() + 3000;
    while (port_out.load(.acquire) == 0 and std.time.milliTimestamp() < dl) std.Thread.sleep(std.time.ns_per_ms);
    try std.testing.expect(port_out.load(.acquire) != 0);
    return th;
}

fn hangingStore(allocator: Allocator, port: u16, url_buf: []u8) !OidcStore {
    const url = try std.fmt.bufPrint(url_buf, "https://127.0.0.1:{d}/token", .{port});
    var store = testStore(allocator, .{ .token_endpoint = url, .jwks_uri = url });
    try store.start();
    return store;
}

test "IdpPool: releaseJob wipes the secret before free" {
    const allocator = std.testing.allocator;
    const port = try refusedPort();
    var url_buf: [128]u8 = undefined;
    var store = try refusedStore(allocator, port, &url_buf);
    defer store.deinit();

    var snap = FreeSnapshot{ .inner = allocator };
    defer snap.deinit();

    var pool = IdpPool{ .allocator = undefined, .store = undefined, .options = undefined };
    try pool.start(allocator, &store, .{
        .threads = 1,
        .max_outstanding = 4,
        .connect_timeout_ms = 1000,
        .timeout_ms = 3000,
    });
    defer pool.stop();
    pool.secret_alloc = snap.allocator();

    const cred = Credential{ .password = .{ .username = "alice", .password = "s3cr3t-m30-marker" } };
    _ = try pool.put(cred);

    const dl = std.time.milliTimestamp() + 5000;
    while (std.time.milliTimestamp() < dl) {
        if (pool.popCompletion()) |job_in| {
            var job = job_in;
            IdpPool.releaseJob(&job);
            break;
        }
        std.Thread.sleep(5 * std.time.ns_per_ms);
    }
    // The freed secret blob must read back wiped, never the credential.
    try snap.assertFreedWiped("s3cr3t-m30-marker");
    try snap.assertFreedWiped("alice");
}

test "IdpPool: popping a completion releases the outstanding slot" {
    const allocator = std.testing.allocator;
    const port = try refusedPort();
    var url_buf: [128]u8 = undefined;
    var store = try refusedStore(allocator, port, &url_buf);
    defer store.deinit();

    var pool = IdpPool{ .allocator = undefined, .store = undefined, .options = undefined };
    try pool.start(allocator, &store, .{
        .threads = 2,
        .max_outstanding = 2,
        .connect_timeout_ms = 1000,
        .timeout_ms = 5000,
    });
    defer pool.stop();

    const cred = Credential{ .password = .{ .username = "alice", .password = "pw" } };
    _ = try pool.put(cred);
    _ = try pool.put(cred);
    try std.testing.expectError(error.QueueFull, pool.put(cred));

    var popped: usize = 0;
    const dl = std.time.milliTimestamp() + 5000;
    while (popped < 2 and std.time.milliTimestamp() < dl) {
        if (pool.popCompletion()) |job_in| {
            var job = job_in;
            IdpPool.releaseJob(&job);
            popped += 1;
        } else {
            std.Thread.sleep(5 * std.time.ns_per_ms);
        }
    }
    try std.testing.expectEqual(@as(usize, 2), popped);
    try std.testing.expectEqual(@as(usize, 0), pool.outstanding());

    // The released slots admit new jobs; a leak would leave the pool
    // permanently full.
    _ = try pool.put(cred);
    _ = try pool.put(cred);
    try std.testing.expectError(error.QueueFull, pool.put(cred));
}

test "IdpPool: put rejects at max_outstanding" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    const th = try startHangingStub(&port);
    defer th.join();

    var url_buf: [128]u8 = undefined;
    var store = try hangingStore(allocator, port.load(.acquire), &url_buf);
    defer store.deinit();

    var pool = IdpPool{ .allocator = undefined, .store = undefined, .options = undefined };
    try pool.start(allocator, &store, .{
        .threads = 1,
        .max_outstanding = 2,
        .connect_timeout_ms = 3000,
        .timeout_ms = 10000,
    });
    defer pool.stop();

    const cred = Credential{ .password = .{ .username = "alice", .password = "pw" } };
    _ = try pool.put(cred);
    _ = try pool.put(cred);
    try std.testing.expectError(error.QueueFull, pool.put(cred));
}

test "IdpPool: stop with jobs in flight cancels them" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    const th = try startHangingStub(&port);
    defer th.join();

    var url_buf: [128]u8 = undefined;
    var store = try hangingStore(allocator, port.load(.acquire), &url_buf);
    defer store.deinit();

    var pool = IdpPool{ .allocator = undefined, .store = undefined, .options = undefined };
    try pool.start(allocator, &store, .{
        .threads = 2,
        .max_outstanding = 8,
        .connect_timeout_ms = 3000,
        .timeout_ms = 10000,
    });

    const cred = Credential{ .password = .{ .username = "alice", .password = "pw" } };
    _ = try pool.put(cred);
    _ = try pool.put(cred);
    _ = try pool.put(cred);

    // The in-flight workers hold 10 s deadlines; the cancel broadcast must
    // end them well under a second.
    const t0 = http.monotonicNs();
    pool.stop();
    const elapsed_ms = (http.monotonicNs() - t0) / std.time.ns_per_ms;
    try std.testing.expect(elapsed_ms < 1000);
    try std.testing.expectEqual(@as(usize, 0), pool.outstanding());
}

/// A loopback listener that counts accepted connections and never answers,
/// so a test can prove how many exchanges actually reached the IdP.
fn serveHangingCounting(port_out: *std.atomic.Value(u16), accepted: *std.atomic.Value(usize)) void {
    const listen_fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return;
    defer posix.close(listen_fd);
    var addr: std.c.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch return;
    posix.listen(listen_fd, 8) catch return;
    var alen: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    posix.getsockname(listen_fd, @ptrCast(&addr), &alen) catch return;
    port_out.store(std.mem.bigToNative(u16, addr.port), .release);

    const deadline = std.time.milliTimestamp() + 15000;
    var held: [32]posix.fd_t = undefined;
    var held_len: usize = 0;
    defer for (held[0..held_len]) |conn_fd| posix.close(conn_fd);
    while (std.time.milliTimestamp() < deadline) {
        var fds = [_]posix.pollfd{.{ .fd = listen_fd, .events = posix.POLL.IN, .revents = 0 }};
        const pn = posix.poll(&fds, 250) catch 0;
        if (pn <= 0) continue;
        if (held_len >= held.len) continue;
        const conn_fd = posix.accept(listen_fd, null, null, 0) catch continue;
        held[held_len] = conn_fd;
        held_len += 1;
        _ = accepted.fetchAdd(1, .monotonic);
    }
}

test "IdpPool: queue time counts against the exchange deadline" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    var accepted = std.atomic.Value(usize).init(0);
    const th = try std.Thread.spawn(.{}, serveHangingCounting, .{ &port, &accepted });
    defer th.join();
    const dl = std.time.milliTimestamp() + 3000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) std.Thread.sleep(std.time.ns_per_ms);
    try std.testing.expect(port.load(.acquire) != 0);

    var url_buf: [128]u8 = undefined;
    var store = try hangingStore(allocator, port.load(.acquire), &url_buf);
    defer store.deinit();

    var pool = IdpPool{ .allocator = undefined, .store = undefined, .options = undefined };
    try pool.start(allocator, &store, .{
        .threads = 1,
        .max_outstanding = 8,
        .connect_timeout_ms = 300,
        .timeout_ms = 300,
    });
    defer pool.stop();

    const cred = Credential{ .password = .{ .username = "alice", .password = "pw" } };
    const t0 = http.monotonicNs();
    _ = try pool.put(cred);
    _ = try pool.put(cred);
    _ = try pool.put(cred);

    // All three deadlines were stamped at put(): the queued jobs time out
    // with the first, they do not each burn a fresh budget at pickup, and
    // an expired queued job never dials the IdP.
    var done: usize = 0;
    const deadline = std.time.milliTimestamp() + 5000;
    while (done < 3 and std.time.milliTimestamp() < deadline) {
        if (pool.popCompletion()) |job_in| {
            var job = job_in;
            defer IdpPool.releaseJob(&job);
            try std.testing.expectEqual(Verdict.timed_out, job.answer.verdict);
            done += 1;
        } else {
            std.Thread.sleep(5 * std.time.ns_per_ms);
        }
    }
    const elapsed_ms = (http.monotonicNs() - t0) / std.time.ns_per_ms;
    try std.testing.expectEqual(@as(usize, 3), done);
    try std.testing.expect(elapsed_ms < 700);
    try std.testing.expectEqual(@as(usize, 1), accepted.load(.monotonic));
}

test "IdpPool: stop never runs the queued exchanges" {
    const allocator = std.testing.allocator;
    var port = std.atomic.Value(u16).init(0);
    var accepted = std.atomic.Value(usize).init(0);
    const th = try std.Thread.spawn(.{}, serveHangingCounting, .{ &port, &accepted });
    defer th.join();
    const dl = std.time.milliTimestamp() + 3000;
    while (port.load(.acquire) == 0 and std.time.milliTimestamp() < dl) std.Thread.sleep(std.time.ns_per_ms);
    try std.testing.expect(port.load(.acquire) != 0);

    var url_buf: [128]u8 = undefined;
    var store = try hangingStore(allocator, port.load(.acquire), &url_buf);
    defer store.deinit();

    var pool = IdpPool{ .allocator = undefined, .store = undefined, .options = undefined };
    try pool.start(allocator, &store, .{
        .threads = 1,
        .max_outstanding = 8,
        .connect_timeout_ms = 3000,
        .timeout_ms = 10000,
    });

    const cred = Credential{ .password = .{ .username = "alice", .password = "pw" } };
    _ = try pool.put(cred);
    // Let the single worker pick up job 1 so the rest stay queued.
    var spins: usize = 0;
    while (accepted.load(.monotonic) == 0 and spins < 200) : (spins += 1) {
        std.Thread.sleep(5 * std.time.ns_per_ms);
    }
    _ = try pool.put(cred);
    _ = try pool.put(cred);

    const t0 = http.monotonicNs();
    pool.stop();
    const elapsed_ms = (http.monotonicNs() - t0) / std.time.ns_per_ms;
    try std.testing.expect(elapsed_ms < 1000);

    // Only the exchange already running ran; the two queued jobs were
    // cancelled before any DNS or connect.
    try std.testing.expectEqual(@as(usize, 1), pool.exchanges_run.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), pool.outstanding());
}
