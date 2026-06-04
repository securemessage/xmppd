# Phase 9 — Auth Hardening Design

Last updated: 2026-06-04

## Overview

Phase 9 hardens xmppd's authentication subsystem. The current system
supports SCRAM-SHA-256 and PLAIN via a dedicated auth daemon, but lacks
rate limiting, account registration, token auth, external backends,
channel binding, and account privacy protections.

This document evaluates each topic, decides what belongs in Phase 9 vs
later phases, and provides an implementation plan.

## Current State

| Feature | Status |
|---------|--------|
| SCRAM-SHA-256 | ✅ Working (multi-step, 256 concurrent) |
| PLAIN | ✅ Working (single-step) |
| SASL EXTERNAL (S2S) | ✅ Working (DANE + cert) |
| Credential storage | ✅ Generic UserStore(Backend) |
| User management | ✅ `xmppctl adduser/deluser/passwd/listusers` |
| Rate limiting | ❌ None |
| Account locking | ❌ None |
| In-band registration | ❌ Not supported |
| Token auth | ❌ Not supported |
| External auth backends | ❌ Only built-in UserStore |
| SASL EXTERNAL (C2S) | ❌ Not supported |
| Channel binding | ❌ Not supported |
| JID enumeration protection | ❌ Not implemented |

## Design Decisions

### What to implement in Phase 9

| # | Feature | Priority | Rationale |
|---|---------|----------|-----------|
| 9a | Rate limiting + brute force protection | **Must** | Security baseline — prevents password grinding |
| 9b | Account lockout | **Must** | Complements rate limiting — temporary and permanent locks |
| 9c | In-band registration (XEP-0077) | **Should** | Needed before public deployment; gated by invitation codes |
| 9d | Password change (XEP-0077 §3.3) | **Should** | Basic account self-service |
| 9e | Account deletion (XEP-0077 §3.2) | **Should** | GDPR-style account removal |
| 9f | Channel binding (XEP-0440) | **Should** | MITM protection, modern clients expect it |

### Deferred to later phases

| Feature | Defer to | Rationale |
|---------|----------|-----------|
| Token auth (OAUTHBEARER, HT-SHA-256) | Phase 11+ | Needs IdP / token issuer — premature without infrastructure |
| External auth backends (LDAP, OIDC, PAM) | Phase 11+ | Enterprise feature — trait interface is ready when needed |
| SASL EXTERNAL for C2S (mTLS) | Phase 11+ | Rare in practice, complex PKI setup |
| JID enumeration protection | Phase 11+ | Low urgency — roster probing is mostly theoretical |
| Presence leak prevention | Phase 11+ | Requires subscription policy framework |

**Rationale for deferring token auth:** Token-based mechanisms (OAUTHBEARER,
HT-SHA-256-ENDP) require a token issuer. Without an IdP (Rauthy, Keycloak,
or custom), implementing the SASL mechanism side alone provides no value.
The auth daemon's `AuthHandler(Store)` pattern makes adding new mechanisms
trivial when the time comes.

**Rationale for deferring external backends:** The `AuthHandler` is already
generic over `Store`. Adding an LDAP backend means implementing a
`LdapAuthStore` that satisfies the same `lookup()` interface. The
architecture supports this without changes. Not worth implementing until
there's an actual LDAP deployment target.

---

## 9a — Rate Limiting + Brute Force Protection

### Design

Rate limiting lives in `xmppd-auth`, not in `xmppd-core`. The auth daemon
is the single choke point for all authentication — it already sees every
attempt, and keeping rate state here avoids IPC overhead.

**Two dimensions:**
1. **Per-account** — protects individual accounts from password grinding
2. **Per-IP** — protects against distributed attacks on many accounts

Per-IP requires the core to send the client's IP address in the
`AuthRequest` IPC message.

### Data Structures

```
// Fixed-size ring buffer per tracked entity (account or IP)
const RateEntry = struct {
    key_hash: u64,          // hash of username or IP string
    attempts: [8]u32,       // timestamps of last N attempts (ring)
    failures: u16,          // consecutive failure count
    locked_until: u32,      // epoch when lockout expires (0 = not locked)
    ring_pos: u8,
};

// Fixed-size hash table — no allocator, O(1) lookup
const RATE_TABLE_SIZE = 4096;  // power-of-2, open addressing
var account_rates: [RATE_TABLE_SIZE]RateEntry = zeroed;
var ip_rates: [RATE_TABLE_SIZE]RateEntry = zeroed;
```

### Policy (configurable via CLI flags, sane defaults)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--max-auth-per-account` | 5 | Max attempts per account per window |
| `--max-auth-per-ip` | 20 | Max attempts per IP per window |
| `--auth-window` | 120 | Window in seconds |
| `--lockout-duration` | 300 | Account lockout duration (seconds) |
| `--lockout-threshold` | 10 | Consecutive failures before lockout |

### Auth flow with rate limiting

```
AuthRequest arrives:
  1. Check ip_rates → if exceeded → AuthFailure("policy-violation")
  2. Check account_rates → if locked → AuthFailure("account-disabled")
  3. Check account_rates → if exceeded → AuthFailure("policy-violation")
  4. Proceed with normal SCRAM/PLAIN flow
  5. On failure → increment counters
  6. On success → reset account failure counter
```

### IPC Protocol Change

`AuthRequest` needs a new field for the client IP:

| Field | Type | Description |
|-------|------|-------------|
| conn_id | u32 | Connection ID |
| mechanism | u8 | SASL mechanism |
| client_ip | len16 + bytes | Client IP address string |
| username | len16 + bytes | SASL username |
| payload | len16 + bytes | SASL payload |

This is a **breaking IPC change** — auth daemon and core must be updated
together. The tag byte (0x01) stays the same; the field order changes.

### LOC Estimate

| File | Change | LOC |
|------|--------|-----|
| src/auth/rate_limiter.zig | New — rate table + policy | ~200 |
| src/auth/handler.zig | Add rate checks to handleAuthRequest | +30 |
| src/auth/main.zig | CLI flags for rate policy | +20 |
| src/ipc/protocol.zig | Add client_ip to AuthRequest | +15 |
| src/core/server.zig | Send client IP in AuthRequest | +10 |
| **Total** | | **~275** |

---

## 9b — Account Lockout

Account lockout is a sub-feature of rate limiting (9a). When consecutive
failures exceed `--lockout-threshold`, the account is locked for
`--lockout-duration` seconds. The lock is stored in the rate table
(in-memory, not persisted).

Additionally, `xmppctl` gets a manual lock/unlock command:

```
xmppctl lock alice          # permanent lock (until unlock)
xmppctl unlock alice        # remove lock
```

Permanent locks are stored in the UserStore as a flag byte prepended to
the credential record. This survives daemon restarts.

### LOC Estimate

| File | Change | LOC |
|------|--------|-----|
| src/store/user_store.zig | Lock flag in credential format | +30 |
| src/ctl/main.zig | lock/unlock subcommands | +40 |
| **Total** | | **~70** |

---

## 9c — In-Band Registration (XEP-0077)

### Design

In-band registration allows XMPP clients to create accounts via the
stream before authentication. This is the standard XMPP account creation
mechanism.

**Security model: invitation codes.** Open registration on the public
internet is a spam magnet. xmppd will require a pre-shared invitation
code for registration. The admin generates codes via `xmppctl`:

```
xmppctl invite create --max-uses 1 --expires 24h
# → INV-a1b2c3d4e5f6

xmppctl invite list
xmppctl invite revoke INV-a1b2c3d4e5f6
```

Invitation codes are stored in a new `InviteStore(Backend)`.

### Registration flow

```
Client sends:  <iq type='get'><query xmlns='jabber:iq:register'/></iq>
Server sends:  <iq type='result'><query><instructions>...</instructions>
                 <username/><password/><x:code/></query></iq>

Client sends:  <iq type='set'><query xmlns='jabber:iq:register'>
                 <username>alice</username>
                 <password>secret</password>
                 <x:code>INV-a1b2c3d4e5f6</x:code>
               </query></iq>
Server:        Validates code → creates account → <iq type='result'/>
```

### IPC: registration requests go through auth daemon

A new IPC message type is needed:

| Tag | Direction | Message |
|-----|-----------|---------|
| 0x06 | Core→Auth | RegisterRequest |
| 0x07 | Auth→Core | RegisterResult |

```
RegisterRequest { conn_id: u32, username: []u8, password: []u8, invite_code: []u8 }
RegisterResult  { conn_id: u32, success: bool, reason: []u8 }
```

### Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--enable-registration` | false | Enable in-band registration |
| `--require-invite` | true | Require invitation code |

Registration is **off by default** — must be explicitly enabled.

### LOC Estimate

| File | Change | LOC |
|------|--------|-----|
| src/store/invite_store.zig | New — invitation code store | ~150 |
| src/auth/handler.zig | handleRegisterRequest | +60 |
| src/ipc/protocol.zig | RegisterRequest/RegisterResult messages | +40 |
| src/core/server.zig | IQ handler for jabber:iq:register | +80 |
| src/ctl/main.zig | invite create/list/revoke | +60 |
| src/auth/main.zig | --enable-registration, --require-invite | +10 |
| **Total** | | **~400** |

---

## 9d — Password Change (XEP-0077 §3.3)

Authenticated users can change their password by sending a `set` IQ to
`jabber:iq:register` with a new `<password>` element. This reuses the
registration namespace but happens post-authentication.

### Flow

```
<iq type='set'>
  <query xmlns='jabber:iq:register'>
    <username>alice</username>
    <password>newpassword</password>
  </query>
</iq>
```

The auth daemon receives a new IPC message:

| Tag | Direction | Message |
|-----|-----------|---------|
| 0x08 | Core→Auth | PasswordChangeRequest |
| 0x09 | Auth→Core | PasswordChangeResult |

```
PasswordChangeRequest { conn_id: u32, username: []u8, new_password: []u8 }
PasswordChangeResult  { conn_id: u32, success: bool, reason: []u8 }
```

### LOC Estimate

| File | Change | LOC |
|------|--------|-----|
| src/auth/handler.zig | handlePasswordChange | +30 |
| src/ipc/protocol.zig | PasswordChange messages | +30 |
| src/core/server.zig | IQ dispatch for password change | +40 |
| **Total** | | **~100** |

---

## 9e — Account Deletion (XEP-0077 §3.2)

Authenticated users can delete their own account. The `<remove/>` element
in the registration IQ triggers account deletion.

### Flow

```
<iq type='set'>
  <query xmlns='jabber:iq:register'>
    <remove/>
  </query>
</iq>
```

### Cleanup

Account deletion must cascade:
1. Remove user from UserStore
2. Remove all roster entries (both directions — notify contacts)
3. Remove offline messages
4. Remove MAM archive
5. Remove vCard
6. Disconnect all sessions for this user

This is a multi-store operation routed through auth daemon IPC:

| Tag | Direction | Message |
|-----|-----------|---------|
| 0x0A | Core→Auth | AccountDeleteRequest |
| 0x0B | Auth→Core | AccountDeleteResult |

The auth daemon performs the UserStore deletion and responds. The core
daemon handles roster cleanup and session disconnection locally.

### LOC Estimate

| File | Change | LOC |
|------|--------|-----|
| src/auth/handler.zig | handleAccountDelete | +20 |
| src/ipc/protocol.zig | AccountDelete messages | +25 |
| src/core/server.zig | IQ dispatch + cascade cleanup | +80 |
| **Total** | | **~125** |

---

## 9f — Channel Binding (XEP-0440)

### Design

Channel binding ties the SASL exchange to the TLS session, preventing
MITM attacks where an attacker intercepts TLS and proxies SASL.

Two binding types:
- **tls-server-end-point** — hash of server's TLS certificate (RFC 5929)
- **tls-exporter** — TLS 1.3 exported keying material (RFC 9266)

`tls-exporter` is preferred for TLS 1.3 connections. `tls-server-end-point`
is the fallback for TLS 1.2.

### How it works

1. Server advertises `<sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'>`
   in stream features with supported binding types
2. Client selects `SCRAM-SHA-256-PLUS` and includes channel binding data
   in the `c=` field of client-first-message
3. Server verifies the binding data matches the TLS session

### Implementation

The SCRAM implementation (`lib/sasl/scram.zig`) already handles the `c=`
field but currently only accepts `biws` (no binding). Need to:

1. Extract binding data from OpenSSL: `SSL_get_peer_certificate()` for
   tls-server-end-point, `SSL_export_keying_material()` for tls-exporter
2. Pass binding data through IPC along with the AuthRequest
3. Validate binding in ScramServer.handleClientFinal

### IPC Change

The `AuthRequest` message gains an optional channel binding field:

| Field | Type | Description |
|-------|------|-------------|
| cb_type | u8 | 0=none, 1=tls-server-end-point, 2=tls-exporter |
| cb_data | len16 + bytes | Binding data (empty if cb_type=0) |

### LOC Estimate

| File | Change | LOC |
|------|--------|-----|
| lib/sasl/scram.zig | Channel binding verification | +60 |
| src/core/connection.zig | Extract TLS binding data | +30 |
| src/core/server.zig | Include binding in AuthRequest | +15 |
| src/ipc/protocol.zig | cb_type + cb_data in AuthRequest | +15 |
| src/auth/handler.zig | Pass binding to ScramServer | +10 |
| **Total** | | **~130** |

---

## Implementation Order

| Step | Feature | Depends on | Est. LOC |
|------|---------|------------|----------|
| 1 | 9a — Rate limiting | — | ~275 |
| 2 | 9b — Account lockout | 9a | ~70 |
| 3 | 9d — Password change | — | ~100 |
| 4 | 9e — Account deletion | — | ~125 |
| 5 | 9c — In-band registration | — | ~400 |
| 6 | 9f — Channel binding | — | ~130 |
| **Total** | | | **~1,100** |

**Order rationale:**
- Rate limiting first — most critical for security
- Password change + deletion before registration — simpler, exercises
  the new IPC message pattern
- Registration last among the "must/should" items — most complex
- Channel binding last — independent, can be done in parallel with testing

---

## IPC Protocol Summary

New tags needed:

| Tag | Direction | Message |
|-----|-----------|---------|
| 0x06 | Core→Auth | RegisterRequest |
| 0x07 | Auth→Core | RegisterResult |
| 0x08 | Core→Auth | PasswordChangeRequest |
| 0x09 | Auth→Core | PasswordChangeResult |
| 0x0A | Core→Auth | AccountDeleteRequest |
| 0x0B | Auth→Core | AccountDeleteResult |

Modified messages:
- **AuthRequest (0x01)** — add `client_ip` field + `cb_type` + `cb_data`

---

## Storage Schema

### InviteStore namespace: `invite\x00`

Key: `invite\x00{code}`
Value: `max_uses(u16) | current_uses(u16) | expires_epoch(u32) | created_epoch(u32)`

### UserStore changes

The existing 100-byte credential record gains a 1-byte flags prefix:

```
byte 0:     flags (0x00=active, 0x01=locked)
bytes 1-32: salt
bytes 33-64: stored_key
bytes 65-96: server_key
bytes 97-100: iteration_count (BE u32)
```

Total: 101 bytes (was 100). This is a **breaking schema change** —
existing databases need migration via `xmppctl migrate`.

---

## Security Model

1. **Defense in depth** — rate limiting in auth daemon, not firewall
2. **Fail closed** — rate table full → reject (not allow)
3. **No timing oracle** — SCRAM already has constant-time comparison
4. **Invitation codes** — registration gated, not open
5. **Channel binding** — prevents MITM on SASL exchange
6. **Lockout is temporary by default** — permanent only via `xmppctl lock`
7. **Rate state is ephemeral** — survives HUP but not daemon restart
   (this is intentional — restart clears lockouts, which is a valid
   admin recovery action)

---

## Test Plan

| Test | Type | Coverage |
|------|------|----------|
| Rate limiter unit tests | Unit | Window, threshold, lockout, reset |
| Rate limiter overflow | Unit | Full table behavior (eviction) |
| IPC roundtrip for new messages | Unit | Encode/decode RegisterRequest, etc. |
| InviteStore CRUD | Unit | Create, validate, expire, revoke |
| Password change flow | Integration | Authenticated IQ → verify new creds |
| Account deletion cascade | Integration | Delete → roster cleanup → MAM purge |
| Registration with invite | Integration | Valid code → account created |
| Registration without invite | Integration | Rejected when required |
| Channel binding SCRAM-PLUS | Unit | Correct binding accepted, wrong rejected |
| Lockout via xmppctl | Integration | lock → auth fails → unlock → auth succeeds |
