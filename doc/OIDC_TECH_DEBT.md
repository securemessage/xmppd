# OIDC Authentication — Technical Debt

Shortcuts taken during Phase 11 implementation (2026-06-06).
Each item MUST be addressed before production deployment.

## Critical (security/correctness)

### ~~1. ROPC body not URL-encoded~~ ✅ FIXED (6082e15)
**File:** `src/auth/oidc.zig` — `validatePassword()`
**Impact:** Passwords containing `&`, `=`, `+`, `%`, `@`, spaces, or non-ASCII
will corrupt the form body, causing auth failures or injection.
**Fix:** Implement percent-encoding for username and password fields before
inserting into the form body. Standard RFC 3986 unreserved set.

### ~~2. No JWKS TTL / periodic refresh~~ ✅ FIXED (6082e15)
**File:** `src/auth/oidc.zig` — `refreshJwks()`
**Impact:** Key rotation with same kid is invisible. Compromised keys stay
cached indefinitely. Only a kid-miss triggers refresh.
**Fix:** Track `last_refresh_time`. Refresh if >1h elapsed on any validation.
Also refresh on signature verification failure (key may have been rotated).

### ~~3. JWT only supports RS256 — no EdDSA~~ ✅ FIXED (90d2ed5)
**File:** `lib/jwt/jwt.zig` — `verifyRs256()`
**Impact:** Cannot validate Ed25519-signed tokens (Rauthy default, industry
trend). Had to force Rauthy to RS256 as workaround.
**Fix:** Add `verifyEdDSA()` using OpenSSL EVP_PKEY_new_raw_public_key with
NID_ED25519. Ed25519 public keys in JWKS are the raw `x` parameter (32 bytes,
base64url-encoded). OpenSSL 3.0 supports this natively.

## Important (functionality)

### ~~4. Username extraction — no JID mapping~~ ✅ FIXED (6082e15)
**File:** `src/auth/oidc.zig` — `validateToken()`
**Impact:** Returns raw `email` claim (`alice@morante.dev`) as username.
XMPP expects bare localpart (`alice`). Different IdPs use different claims.
**Fix:** Add configurable `username_claim` with post-processing options:
- `strip_domain`: `alice@morante.dev` → `alice`
- `claim_name`: choose which claim to extract from (sub, email, preferred_username)
- `jid_domain_check`: reject tokens where email domain ≠ XMPP domain

### ~~5. No token introspection fallback~~ ✅ FIXED (90d2ed5)
**File:** `src/auth/oidc.zig` — `validateToken()`
**Impact:** Opaque (non-JWT) tokens are rejected. Some IdPs issue opaque
access tokens that require introspection.
**Fix:** After JWT parse failure, call the introspection endpoint
(`POST /introspect` with `token=X&client_id=Y&client_secret=Z`).
Only if introspection returns `"active": true`, accept the token.

### ~~6. Response body ownership in refreshJwks~~ ✅ FIXED (6082e15)
**File:** `src/auth/oidc.zig` — `refreshJwks()`
**Impact:** Takes ownership of Response.body by not calling deinit(). Relies
on the assumption that Response only heap-allocates body. Fragile if
Response struct gains other allocations.
**Fix:** Copy body into OidcStore-owned allocation, then call response.deinit()
normally. Slight extra copy but correct ownership semantics.

## Testing

### 7. No IPC-level integration test
**File:** `test/integration/oidc-auth-test.sh`
**Impact:** Only tests HTTP-level ROPC and daemon startup. Does not verify:
- IPC MechanismList announcement (OAUTHBEARER + PLAIN)
- Binary protocol AuthRequest → AuthSuccess/AuthFailure roundtrip
- OAUTHBEARER token validation through full IPC path
- Rate limiting behavior with OIDC backend
**Fix:** Write a Zig test binary that connects to the IPC socket, sends
protocol-level auth requests, and validates responses. Model after the
existing `test/integration/muc-test.py` pattern.

### 8. OidcStore unit tests don't cover auth flows
**File:** `src/auth/oidc.zig` (test section)
**Impact:** Only tests init/deinit and JSON helpers. validateToken and
validatePassword require network — but mocking is possible by injecting
test JWKS data directly and pre-setting keys.
**Fix:** Add tests that:
- Pre-populate `keys[]` with a test RSA key
- Create a valid JWT signed with that key
- Call `validateToken()` and verify username extraction
- Test expired token rejection
- Test issuer/audience mismatch rejection
