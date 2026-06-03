# xmppd Roadmap

This document tracks the development roadmap for xmppd. Each phase builds on
the previous one. Phases are not versioned — they represent implementation
milestones, not releases.

Last updated: 2026-06-03

## Current Status

| Phase | Status | Summary |
|-------|--------|---------|
| 1. Protocol Library | ✅ Complete | XML parser, JID, stanzas, SASL, TLS, DNS |
| 2. Core Daemon | ✅ Complete | kqueue event loop, C2S, master supervisor |
| 3. S2S Federation | 🟡 ~90% | DANE + SASL EXTERNAL verified both directions |
| 4. Client Interop | ⬜ Not started | Real XMPP client testing |
| 5. Storage | ⬜ Not started | Pluggable storage interface + backends |
| 6. Auth | ⬜ Not started | Pluggable auth backends |
| 7. MUC | ⬜ Not started | Multi-User Chat (XEP-0045) |
| 8. Polish & Deploy | ⬜ Not started | Config, RC script, port, XEPs, docs |

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

## Phase 3 — S2S Federation 🟡

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
- [ ] XEP-0220 dialback: inbound db:result verification (outbound callback)
- [x] Interop tested against Prosody 13.0.6 (DANE + EXTERNAL path)
- [ ] E2E integration test (Python: message delivery both directions)
- [ ] Offline delivery across federation

**Binaries:** `xmppd-s2s`

### S2S Interop Status

| Path | Auth | Status |
|------|------|--------|
| Outbound (xmppd → Prosody) | SASL EXTERNAL / DANE-EE | ✅ Verified |
| Inbound (Prosody → xmppd) | SASL EXTERNAL / DANE-EE | ✅ Verified |
| Outbound (no DANE) | Dialback | 🟡 Key sent, callback arrives |
| Inbound (no DANE) | Dialback | ⬜ Needs outbound callback |

## Phase 4 — Client Interop

Validate the server against real XMPP clients before adding features.

- [ ] Aparte (terminal client, FreeBSD native)
- [ ] Gajim (desktop, GTK)
- [ ] Dino (desktop, GTK)
- [ ] Conversations (Android)
- [ ] Document any standards compliance gaps found
- [ ] Fix issues surfaced by client testing

This phase gates further feature work. No point building on a foundation
that doesn't interoperate with real clients.

## Phase 5 — Storage

Replace flat-file stores with a proper storage subsystem. This phase
requires a dedicated design session before implementation begins.

### Design Goals

- Pluggable storage interface (comptime traits, zero runtime dispatch)
- Separate `xmppd-store` daemon process (privilege separation)
- IPC protocol for store operations (same pattern as auth IPC)
- Default backend that works with zero external dependencies

### Planned Backends

| Backend | Use Case | Dependencies |
|---------|----------|--------------|
| RocksDB | Default, zero-ops | librocksdb (static) |
| PostgreSQL | Large deployments, clustering | libpq |
| MariaDB/MySQL | Existing infrastructure | libmariadb |
| SQLite | Single-server, lightweight | libsqlite3 (base) |

### What Moves to Storage

- User accounts and credentials (currently flat-file in auth)
- Rosters and subscription state (currently flat-file in core)
- Offline messages (currently flat-file in core)
- vCards (currently stubbed)
- Message Archive Management / XEP-0313 (new)
- MUC room configuration and history (Phase 7 dependency)

## Phase 6 — Auth

Replace the single-backend auth daemon with pluggable authentication.
This phase also requires a design session.

### Design Goals

- Pluggable auth backend interface
- Multiple backends configurable per domain
- Standard protocols for enterprise integration

### Planned Backends

| Backend | Use Case |
|---------|----------|
| Internal | Stored credentials (via storage layer) |
| LDAP | Active Directory / OpenLDAP |
| OIDC | Modern identity providers |
| PAM | System accounts |
| RADIUS | Legacy enterprise |

### Dependencies

- Phase 5 (Storage) must be complete — internal auth backend reads
  credentials from the storage layer, not a flat file.

## Phase 7 — Multi-User Chat (MUC)

XEP-0045 implementation for group messaging.

### Dependencies

- Phase 5 (Storage) — room persistence, message history
- Phase 6 (Auth) — room access control, member management

### Planned Features

- [ ] Room creation, configuration, destruction
- [ ] Join / part / presence in rooms
- [ ] Room message delivery (fan-out to occupants)
- [ ] Message history (scrollback via storage)
- [ ] Room persistence across server restarts
- [ ] Basic moderation (kick, ban, voice)
- [ ] Room discovery (disco#items)

## Phase 8 — Polish & Deploy

Production readiness.

### Configuration

- [ ] Configuration file system (single `xmppd.conf`)
- [ ] Sensible defaults (Postfix model: works out of the box)
- [ ] Runtime config validation

### Deployment

- [ ] FreeBSD RC script (`etc/rc.d/xmppd`)
- [ ] FreeBSD port (Makefile, pkg-plist, pkg-descr)
- [ ] Systemd unit file (Linux)

### Standards

- [ ] XEP-0198: Stream Management (mobile reconnection)
- [ ] XEP-0280: Message Carbons (multi-device)
- [ ] XEP-0313: Message Archive Management (history)
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
- **Bidirectional S2S dialback** — full XEP-0220 with outbound callbacks

---

## Metrics

| Metric | Value |
|--------|-------|
| Language | Zig 0.15.2 |
| Source files | 36 |
| Lines of code | ~17,650 |
| Unit tests | 425 (26 test suites) |
| Binaries | 5 (`xmppd`, `xmppd-core`, `xmppd-auth`, `xmppd-s2s`, `xmppctl`) |
| Primary platform | FreeBSD (kqueue) |
| License | BSD-2-Clause |
