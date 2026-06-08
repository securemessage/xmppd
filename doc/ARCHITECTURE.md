# xmppd Architecture

## Overview

xmppd is a multi-process XMPP server inspired by Postfix's design philosophy:
one package, one config, one service — complexity is internal.

## Process Model

```
                ┌──────────────────────────┐
                │       xmppd (master)     │
                │  PID file, privsep,      │
                │  supervisor, signals     │
                └─────┬──────────┬─────────┘
                      │          │
              ┌───────┘          └───────┐
              ▼                          ▼
    ┌──────────────────┐      ┌──────────────────┐
    │   xmppd-core     │      │   xmppd-auth     │
    │   (C2S, router,  │◄────►│   (SASL, rate    │
    │    MUC, stores)  │ IPC  │    limit, locks)  │
    │   kqueue loop    │      │   kqueue loop     │
    └──────────────────┘      └──────────────────┘
                                      OR
                              ┌──────────────────┐
                              │ xmppd-auth-oidc  │
                              │ (OAUTHBEARER,    │
                              │  PLAIN→ROPC)     │
                              └──────────────────┘
```

### Responsibilities

| Process | Role | Privilege |
|---------|------|-----------|
| `xmppd` | Master supervisor. Spawns/monitors children, handles signals, PID file, privsep (setuid). | root (drops to `jabber` for children) |
| `xmppd-core` | Hot path. TCP listener, TLS, XML parsing, session management, stanza routing, presence engine, MUC, in-process stores (roster, MAM, offline, vCard). | unprivileged (`jabber`) |
| `xmppd-auth` | Cold path. SASL SCRAM-SHA-256 + PLAIN, rate limiting, account lockout, registration, password change, channel binding. | unprivileged (`jabber`) |
| `xmppd-auth-oidc` | Alternative auth. OAUTHBEARER (JWT validation) + PLAIN→ROPC delegation to external IdP. | unprivileged (`jabber`) |
| `xmppd-s2s` | S2S federation. Outbound connections, DANE/TLSA, SASL EXTERNAL, dialback. | unprivileged (`jabber`) |
| `xmppctl` | CLI admin tool. User management (adduser, deluser, passwd, listusers, lock, unlock, invite). | user |

### IPC Protocol

Binary length-prefixed messages over Unix domain sockets (`/var/run/xmppd/auth.sock`):

- **4 bytes**: message length (little-endian)
- **1 byte**: message tag
- **N bytes**: tag-specific fields

Tags: AuthRequest (0x01), AuthChallenge (0x02), AuthSuccess (0x03), AuthFailure (0x04), SaslResponse (0x05), Register (0x06–0x07), PasswordChange (0x08–0x09), AccountDelete (0x0A–0x0B), MechanismList (0x0C).

### Event Loop

Single kqueue per process. Non-blocking I/O with:
- `EVFILT_READ` for incoming data
- `EVFILT_WRITE` (oneshot) for outbound buffer flush
- `EVFILT_SIGNAL` for SIGTERM/SIGHUP
- Bounded continuation for fan-out (yield after N occupants per tick)

## Storage

Comptime generic stores with pluggable backends:

| Store | Purpose | Key Format |
|-------|---------|-----------|
| UserStore | SCRAM credentials | `user:{localpart}` |
| RosterStore | Contacts + subscriptions | `roster:{owner}\x00{contact}` |
| VCardStore | vCard XML blobs | `vcard:{localpart}` |
| OfflineStore | Queued messages | `offline:{localpart}:{timestamp}` |
| ArchiveStore | MAM history | `mam:{bare_jid}:{timestamp}:{id}` |
| RoomStore | MUC room config + affiliations | `room:{room_jid}` |
| LockStore | Permanent account locks | `locks:{localpart}` |
| InviteStore | Registration codes | `invite:{code}` |

### Backends

Selected at build time via `-Dop-storage=` and `-Darchive-storage=`:

- **LMDB** — default for operational data (fast, zero-config, ACID)
- **RocksDB** — archive/MAM (better for large sequential writes)
- **SQLite** — alternative single-file backend

## Security Model

- TLS 1.3 mandatory (STARTTLS required, no plaintext auth)
- DANE/TLSA first-class for S2S trust
- Rate limiting per-IP + per-account (fixed-size hash tables, O(1))
- Account lockout (temporary + permanent via LockStore)
- Channel binding (XEP-0440: tls-server-end-point + tls-exporter)
- Registration gated by invitation codes
- Privilege separation (master=root, children=jabber)

## Performance

Single-threaded benchmark (FreeBSD, kqueue):
- Message routing: ~17,000 msg/sec (1:1 delivery)
- Connection establishment: ~4 conn/sec (TLS + SCRAM, rate-limited)
- MUC fan-out: bounded continuation prevents event loop starvation
