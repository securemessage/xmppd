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
