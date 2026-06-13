# xmppd

A carrier-grade XMPP server written in Zig, inspired by Postfix's architecture.

[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)

## Overview

xmppd is a modern XMPP server designed for carrier-grade deployments. It draws
architectural inspiration from Postfix — separation of concerns, privilege
separation, sensible defaults — while leveraging Zig's async I/O and compile-time
polymorphism for performance at scale.

### Key Features (planned)

- **Hybrid process model** — master daemon supervises isolated components
- **Async I/O** — kqueue/kevent event loop handles millions of concurrent connections
- **DANE-first** — TLSA certificate validation as primary trust path for S2S federation
- **Pluggable storage** — RocksDB (default), PostgreSQL, MariaDB, LDAP
- **Pluggable auth** — internal, LDAP, OIDC, PAM
- **Postfix admin UX** — one package, one config, one service

### Target Platforms

- **Primary:** FreeBSD (kqueue)
- **Secondary:** Linux (epoll, post-MVP)

## Standards Compliance

| Standard | Description | Support | Tested |
|----------|-------------|---------|--------|
| RFC 6120 | XMPP Core (STARTTLS, SASL, resource binding) | Full | E2E, Unit |
| RFC 6121 | XMPP IM (roster, presence, messaging) | Partial¹ | Interop, E2E, Unit |
| XEP-0030 | Service Discovery | Full | Interop |
| XEP-0045 | Multi-User Chat | Partial² | Interop, E2E, Unit |
| XEP-0054 | vCard-temp | Full | Interop |
| XEP-0077 | In-Band Registration | Full | E2E, Unit |
| XEP-0084 | User Avatar (via PEP) | Full | E2E |
| XEP-0085 | Chat State Notifications | Full | Interop |
| XEP-0092 | Software Version | Full | Interop |
| XEP-0160 | Offline Message Storage | Full | E2E, Unit |
| XEP-0163 | Personal Eventing Protocol | Partial³ | E2E |
| XEP-0184 | Message Delivery Receipts | Pass-through | E2E |
| XEP-0191 | Blocking Command | Full | E2E, Unit |
| XEP-0198 | Stream Management | Partial⁴ | E2E |
| XEP-0199 | XMPP Ping | Full | Interop |
| XEP-0220 | Server Dialback | Partial | E2E |
| XEP-0280 | Message Carbons | Full | E2E, Unit |
| XEP-0308 | Last Message Correction | Pass-through | E2E |
| XEP-0313 | Message Archive Management | Full | E2E, Unit |
| XEP-0359 | Unique and Stable Stanza IDs | Full | Unit |
| XEP-0440 | SASL Channel-Binding Type Negotiation | Full | Unit |

**Interop** = automated [smack-sint-server-extensions](https://github.com/XMPP-Interop-Testing/smack-sint-server-extensions) v1.7.2 (495 tests available),
**E2E** = verified with Gajim, Conversations, and/or Dino,
**Unit** = Zig unit tests (738 tests),
**Pass-through** = server forwards stanzas without interpretation; no server-side logic required.

¹ Single-resource messaging and presence work. Multi-resource routing (§8.5) has known
issues: presence to bare JIDs is not broadcast to all resources, messages to offline
resources are stored instead of routed to the highest-priority online resource (T118).

² MUC core functionality works (join, part, groupchat, kick, ban, history, MAM, disco).
Missing: room configuration forms (XEP-0045 §10), invitations (§7.8), voice requests.

³ PEP supports publish, subscribe, auto-subscribe, auto-create, persistent items, and
avatar metadata notifications. Not a full XEP-0060 PubSub service.

⁴ SM supports enable, ack requests (`<r/>`), and ack responses (`<a/>`). Session resume
is **not implemented** — sessions cannot be resumed after disconnection.

## Building

Requires Zig 0.15.2+.

```sh
zig build
```

Run tests:

```sh
zig build test
```

## Project Structure

```
lib/          XMPP protocol library (reusable)
  xml/        Streaming XML parser (XMPP subset)
  xmpp/       Stanza types, JID, protocol state machine
  sasl/       SASL mechanisms (SCRAM-SHA-256, PLAIN, EXTERNAL)
  tls/        STARTTLS + DANE/TLSA
  dns/        SRV, TLSA record resolution
src/          Server daemons
  master/     Master process supervisor
  core/       C2S listener, stanza router, presence engine
  auth/       Authentication daemon
  store/      Storage daemon + backends
  s2s/        S2S federation daemon
  muc/        Multi-User Chat service
  ctl/        xmppctl admin CLI
config/       Sample configuration
doc/          Documentation
test/         Integration and compliance tests
```

## License

BSD-2-Clause. See [LICENSE](LICENSE).

Copyright (c) 2026, Daniel Morante.
