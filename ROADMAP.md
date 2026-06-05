# xmppd Roadmap

This document tracks the development roadmap for xmppd. Each phase builds on
the previous one. Phases are not versioned — they represent implementation
milestones, not releases.

Last updated: 2026-06-05

## Current Status

| Phase | Status | Summary |
|-------|--------|---------|
| 1. Protocol Library | ✅ Complete | XML parser, JID, stanzas, SASL, TLS, DNS |
| 2. Core Daemon | ✅ Complete | kqueue event loop, C2S, master supervisor |
| 3. S2S Federation | ✅ Complete | DANE + EXTERNAL + dialback + E2E tested |
| 4. Client Interop | ✅ Complete | slixmpp 23/23, profanity 14/14, gajim ✓, dino ✓ |
| 5. Storage | ✅ Complete | Comptime generic stores, LMDB/RocksDB/SQLite backends |
| 6. Auth Daemon + IPC | ✅ Complete | xmppd-auth, SCRAM-SHA-256, PLAIN, binary IPC |
| 7. Messaging + IM | ✅ Complete | Routing, presence, roster, offline, MAM (XEP-0313) |
| 8. S2S Hardening | ✅ Complete | DANE-EE, SASL EXTERNAL, dialback, Prosody interop |
| 9. Auth Hardening | ✅ Complete | Rate limiting, lockout, registration, passwd, delete, channel binding |
| 10. MUC | ⬜ Not started | Multi-User Chat (XEP-0045) |
| 11. External Auth | ⬜ Not started | OIDC/OAuth, LDAP/AD, SQL backends |
| 12. Polish & Deploy | ⬜ Not started | Config, RC script, port, privilege separation, docs |

---

## Phase 1 — Protocol Library ✅

Reusable XMPP protocol library under `lib/`.

- [x] Streaming XML parser (XMPP subset, namespace-aware)
- [x] JID parsing and validation
- [x] Stanza types (Message, Presence, IQ)
- [x] SASL framework (SCRAM-SHA-256, PLAIN, EXTERNAL)
- [x] TLS integration (STARTTLS, OpenSSL FFI)
- [x] DANE/TLSA verification
- [x] DNS SRV + TLSA resolution (res_query FFI)

## Phase 2 — Core Daemon ✅

Multi-process XMPP server that handles C2S connections.

- [x] kqueue/kevent event loop (`src/core/event_loop.zig`)
- [x] TCP listener with non-blocking I/O
- [x] Connection management with TLS-aware buffered I/O
- [x] Stream negotiation (STARTTLS → SASL → bind)
- [x] Master process supervisor with restart backoff
- [x] IPC framework (Unix domain sockets, length-prefixed binary)
- [x] Auth daemon (`xmppd-auth`) with SCRAM-SHA-256 + PLAIN
- [x] User store (flat-file, PBKDF2-SHA-256 derived credentials)
- [x] `xmppctl` admin CLI (adduser, deluser, passwd, listusers)
- [x] Session registry for JID-based routing
- [x] Message routing between local users
- [x] Presence engine (available/unavailable, fan-out)
- [x] Roster store with subscription state machine
- [x] Offline message storage and delivery
- [x] vCard-temp stubs, disco#info/items, software version

**Binaries:** `xmppd`, `xmppd-core`, `xmppd-auth`, `xmppctl`

## Phase 3 — S2S Federation ✅

Server-to-server federation for cross-domain messaging.

- [x] S2S stream FSM (initiating + receiving roles)
- [x] Outbound connector (DNS SRV → TCP → TLS → auth pipeline)
- [x] Inbound listener on port 5269 with TLS
- [x] DANE-EE verification (outbound + inbound)
- [x] SASL EXTERNAL authentication (both directions)
- [x] Connection pool (domain → outbound connection)
- [x] Core routing: remote stanzas forwarded via IPC
- [x] `xmppd-s2s` daemon with full event loop
- [x] XEP-0220 dialback: outbound key generation + sending
- [x] XEP-0220 dialback: inbound db:verify callback verification
- [x] XEP-0220 dialback: inbound db:result verification (outbound callback)
- [x] Inbound stanza forwarding (S2S→core IPC pipeline)
- [x] Offline delivery across federation
- [x] E2E integration test (`test/integration/s2s-federation.py` — 9/9)
- [x] Interop tested against Prosody 13.0.6 (DANE + EXTERNAL path)

**Binaries:** `xmppd-s2s`

### S2S Interop Status

| Path | Auth | Status |
|------|------|--------|
| Outbound (xmppd → Prosody) | SASL EXTERNAL / DANE-EE | ✅ Verified |
| Inbound (Prosody → xmppd) | SASL EXTERNAL / DANE-EE | ✅ Verified |
| Outbound (no DANE) | Dialback | ✅ Key sent + verified |
| Inbound (no DANE) | Dialback | ✅ Callback verification |

## Phase 4 — Client Interop ✅

Validate the server against real XMPP clients before adding features.

- [x] slixmpp library (23/23 tests — see `test/integration/client-interop.py`)
  - [x] STARTTLS + SASL PLAIN authentication
  - [x] STARTTLS + SASL SCRAM-SHA-256 authentication
  - [x] Wrong password rejection
  - [x] Resource binding
  - [x] Service Discovery — disco#info (identity + 7 features)
  - [x] Service Discovery — disco#items
  - [x] XMPP Ping (XEP-0199)
  - [x] Software Version (XEP-0092)
  - [x] vCard-temp (XEP-0054)
  - [x] Roster get + set
  - [x] Initial presence
  - [x] Two-way messaging (alice↔bob with body verification)
- [x] Profanity (terminal client, FreeBSD native — 14/14 tests)
- [x] Gajim (desktop, GTK — connected via Windows, full session)
- [x] Dino (desktop, GTK — connected via FreeBSD, full session)
- [ ] Conversations (Android — deferred, needs Android dev environment)

### Bugs Found and Fixed

- **IPC recv buffer use-after-compact** — `nextMessage()` compacted the
  receive buffer before returning, corrupting borrowed Message slices
  when two IPC responses arrived simultaneously (concurrent SASL auth).
  Fix: deferred compaction to the start of the next `nextMessage()` or
  `recv()` call.
- **Post-SASL SSL drain** — Added `SSL_pending()` check after SASL
  success to drain OpenSSL-buffered data that kqueue won't fire for.

This phase gates further feature work. No point building on a foundation
that doesn't interoperate with real clients.

## Phase 5 — Storage ✅

Pluggable storage subsystem with comptime generic stores and multiple
backends. Build flag `-Dop-storage` selects the operational backend.

- [x] Comptime `StorageBackend` trait (`src/store/backend.zig`) with `assertBackend()`
- [x] `MemoryBackend` — reference implementation and test double
- [x] `LmdbBackend` — LMDB via zig-lmdb v0.3.2, auto-resize on MDB_MAP_FULL
- [x] `RocksDbBackend` — RocksDB via system librocksdb C API
- [x] `SqliteBackend` — SQLite3 via system libsqlite3
- [x] `UserStore(Backend)` — SCRAM credential storage (binary format)
- [x] `RosterStore(Backend)` — composite key, subscription state machine
- [x] `VCardStore(Backend)` — raw XML blob storage
- [x] `OfflineStore(Backend)` — offline message queue with per-user cap
- [x] `ArchiveStore(Backend)` — MAM archive with paginated query + retention
- [x] `MamHandler` — XEP-0313 IQ handler wired into core
- [x] Auth daemon migrated to `UserStore(LmdbBackend)`
- [x] Core daemon wired with generic RosterStore, VCardStore, OfflineStore, ArchiveStore
- [x] `-Dop-storage` build flag (lmdb, rocksdb, sqlite)

**Key files:** `src/store/` (10 files, ~3,663 LOC)

## Phase 6 — Auth Daemon + IPC ✅

Separate auth daemon with binary IPC protocol and kqueue event loop.

- [x] IPC framework (`src/ipc/`) — length-prefixed binary framing
- [x] 5 auth message types: AuthRequest, AuthChallenge, AuthSuccess, AuthFailure, SaslResponse
- [x] `xmppd-auth` daemon with kqueue event loop, SIGHUP, graceful shutdown
- [x] `AuthHandler(Store)` — generic over store type, SCRAM + PLAIN dispatch
- [x] SCRAM-SHA-256 multi-step exchange (256 concurrent sessions)
- [x] PLAIN single-step authentication
- [x] `xmppctl` admin CLI (adduser, deluser, passwd, listusers)
- [x] Core daemon wired to auth via async IPC calls

**Binaries:** `xmppd-auth`, `xmppctl`

## Phase 7 — Messaging + IM ✅

Core XMPP instant messaging functionality.

- [x] Session registry for JID-based routing
- [x] Message routing between local users
- [x] Presence engine (available/unavailable broadcast, fan-out)
- [x] Roster management with subscription state machine
- [x] Offline message storage and delivery (XEP-0160)
- [x] Message Archive Management / MAM (XEP-0313)
- [x] IQ dispatch framework (`src/core/iq_handler.zig`)
- [x] Service Discovery — disco#info/items (XEP-0030)
- [x] vCard-temp (XEP-0054)
- [x] Software Version (XEP-0092)
- [x] XMPP Ping (XEP-0199)

## Phase 8 — S2S Hardening ✅

Server-to-server federation hardening and interop.

- [x] DANE-EE verification (outbound + inbound)
- [x] SASL EXTERNAL authentication (both directions)
- [x] XEP-0220 dialback (outbound key generation, inbound callback verification)
- [x] Post-SASL stream restart (RFC 6120 compliance)
- [x] Inbound stanza forwarding (S2S→core IPC pipeline)
- [x] Offline delivery across federation
- [x] E2E integration test (`test/integration/s2s-federation.py`)
- [x] Interop tested against Prosody 13.0.6

### S2S Interop Status

| Path | Auth | Status |
|------|------|--------|
| Outbound (xmppd → Prosody) | SASL EXTERNAL / DANE-EE | ✅ Verified |
| Inbound (Prosody → xmppd) | SASL EXTERNAL / DANE-EE | ✅ Verified |
| Outbound (no DANE) | Dialback | ✅ Key sent + verified |
| Inbound (no DANE) | Dialback | ✅ Callback verification |

## Phase 9 — Auth Hardening

Harden the authentication subsystem within `xmppd-auth`. All new auth
logic lives in the auth daemon — core remains a pure XML/IPC relay.

Design document: `~/.windsurf/plans/xmppd-phase9-auth-hardening-809458.md`

### Sub-steps

| Step | Feature | Status |
|------|---------|--------|
| 9a | Rate limiting — per-IP + per-account, fixed-size hash tables | ✅ |
| 9b | Account lockout — temp (rate-based) + permanent (LockStore) | ✅ |
| 9c | In-band registration (XEP-0077) — invitation codes, InviteStore | ✅ |
| 9d | Password change (XEP-0077 §3.3) — IPC tags 0x08/0x09 | ✅ |
| 9e | Account deletion (XEP-0077 §3.2) — cascade cleanup | ✅ |
| 9f | Channel binding (XEP-0440) — tls-server-end-point + tls-exporter | ✅ |

### Key Design Decisions

- **LockStore** — permanent locks stored in separate `locks` namespace
  (not embedded in credential format). Works for both local and future
  external auth users. No breaking schema change.
- **Single IPC breaking change** — `client_ip`, `cb_type`, `cb_data`
  added to AuthRequest (0x01) in step 9a.
- **Forward-compatible** — all designs work with future Phase 11
  external auth backends.

### Deferred to Phase 11

- Token-based auth (OAUTHBEARER, HT-SHA-256)
- External auth backends (OIDC, LDAP, SQL, PAM)
- SASL EXTERNAL for C2S (mTLS)

### Deferred to Phase 12

- JID enumeration protection
- Presence leak prevention

### Dependencies

- Phase 5 (Storage) — LockStore, InviteStore use storage backend
- Phase 6 (Auth Daemon) — IPC protocol gains 6 new message types

## Phase 10 — Multi-User Chat (MUC)

XEP-0045 implementation for group messaging.

### Dependencies

- Phase 5 (Storage) — room persistence, message history
- Phase 9 (Auth Hardening) — room access control

### Planned Features

- [ ] Room creation, configuration, destruction
- [ ] Join / part / presence in rooms
- [ ] Room message delivery (fan-out to occupants)
- [ ] Message history (scrollback via storage)
- [ ] Room persistence across server restarts
- [ ] Basic moderation (kick, ban, voice)
- [ ] Room discovery (disco#items)

## Phase 11 — External Auth Backends

Pluggable authentication backends for enterprise and federated identity.
The `AuthHandler(Store)` generic pattern from Phase 6 means adding
backends is purely additive — no refactoring needed.

### Priority Order

1. **OIDC/OAuth** — OAUTHBEARER SASL mechanism, token validation against IdP
2. **LDAP/AD** — bind authentication, group-based authorization
3. **SQL** — external database credential lookup (PostgreSQL/MariaDB)
4. **Token auth** — HT-SHA-256 for mobile clients (needs token issuer)
5. **SASL EXTERNAL for C2S** — client certificate authentication (mTLS)
6. **PAM** — system-level auth integration (pending SASL vs PAM discussion)

### Configuration

```ini
# xmppd.conf
auth_backend = internal          # or: oidc, ldap, sql, pam
# auth_oidc_issuer = https://idp.example.com
# auth_ldap_url = ldap://ldap.example.com
# auth_sql_dsn = postgresql://...
```

### Dependencies

- Phase 9 (Auth Hardening) — LockStore and rate limiting apply to all backends
- External infrastructure — IdP, LDAP server, or database must exist

## Phase 12 — Polish & Deploy

Production readiness.

### Configuration

- [ ] Configuration file system (single `xmppd.conf`)
- [ ] Sensible defaults (Postfix model: works out of the box)
- [ ] Runtime config validation

### Privilege Separation

- [ ] SCM_RIGHTS fd passing (master binds privileged ports → passes to children)
- [ ] Per-daemon UID (xmppd-core, xmppd-auth, xmppd-s2s as separate users)

### Deployment

- [ ] FreeBSD RC script (`etc/rc.d/xmppd`)
- [ ] FreeBSD port (Makefile, pkg-plist, pkg-descr)
- [ ] Systemd unit file (Linux)

### Standards

- [ ] XEP-0198: Stream Management (mobile reconnection)
- [ ] XEP-0280: Message Carbons (multi-device)
- [ ] XEP-0363: HTTP File Upload (media sharing)

### Documentation

- [ ] `doc/ARCHITECTURE.md` — multi-process design, IPC protocol
- [ ] `doc/CONFIGURATION.md` — all config options
- [ ] `doc/DEPLOYMENT.md` — FreeBSD setup guide
- [ ] `doc/FEDERATION.md` — S2S setup, DANE, dialback
- [ ] Man pages for all binaries

### Testing

- [ ] XMPP Compliance Suite verification
- [ ] Performance benchmarks (connections/sec, message throughput)
- [ ] Fuzz testing on XML parser

### Account Privacy

- [ ] JID enumeration protection
- [ ] Presence leak prevention

---

## Post-MVP

These items are out of scope for the initial release but are on the
long-term radar.

- **Clustering** — multi-node via shared storage + message bus
- **epoll backend** — Linux support (secondary platform)
- **WebSocket** (RFC 7395) — web client connectivity
- **BOSH** (XEP-0124/0206) — legacy web client support
- **Push Notifications** (XEP-0357) — mobile background delivery
- **A/V Calling** — Jingle (XEP-0166) + TURN/STUN
- **OMEMO key distribution** — PEP for end-to-end encryption
- **Admin Web UI** — monitoring dashboard
- **Prometheus metrics** — observability
- **S2S dialback error recovery** — retry/backoff on callback connection failure

---

## XEPs Supported

| XEP | Name | Phase |
|-----|------|-------|
| RFC 6120 | XMPP Core | 1–2 |
| RFC 6121 | XMPP IM | 7 |
| XEP-0030 | Service Discovery | 7 |
| XEP-0054 | vcard-temp | 7 |
| XEP-0092 | Software Version | 7 |
| XEP-0160 | Offline Message Storage | 7 |
| XEP-0199 | XMPP Ping | 7 |
| XEP-0220 | Server Dialback | 8 |
| XEP-0313 | Message Archive Management | 5+7 |
| XEP-0077 | In-Band Registration | 9 |
| XEP-0440 | SASL Channel-Binding Type Capability | 9 |

## Metrics

| Metric | Value |
|--------|-------|
| Language | Zig 0.15.2 |
| Source files | 49 |
| Lines of code | ~23,600 |
| Unit tests | 78 build steps, 591 tests (all pass) |
| Integration tests | 9/9 S2S federation + 23 C2S interop |
| Binaries | 5 (`xmppd`, `xmppd-core`, `xmppd-auth`, `xmppd-s2s`, `xmppctl`) |
| Primary platform | FreeBSD (kqueue) |
| License | BSD-2-Clause |
