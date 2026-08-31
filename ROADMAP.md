# xmppd Roadmap

This document tracks the development roadmap for xmppd. Each phase builds on
the previous one. Phases are not versioned — they represent implementation
milestones, not releases.

Last updated: 2026-08-30

## Current Status

| Phase | Status | Summary |
|-------|--------|---------|
| 1. Protocol Library | ✅ Complete | XML parser, JID, stanzas, SASL, TLS, DNS |
| 2. Core Daemon | ✅ Complete | kqueue event loop, C2S, master supervisor |
| 3. S2S Federation | ✅ Complete | DANE + EXTERNAL + dialback + E2E tested |
| 4. Client Interop | ✅ Complete | slixmpp 23/23, profanity 14/14, gajim ✓, dino ✓, Conversations ✓ |
| 5. Storage | ✅ Complete | Comptime generic stores, LMDB/RocksDB/SQLite backends |
| 6. Auth Daemon + IPC | ✅ Complete | xmppd-auth, SCRAM-SHA-256, PLAIN, binary IPC |
| 7. Messaging + IM | ✅ Complete | Routing, presence, roster, offline, MAM (XEP-0313) |
| 8. S2S Hardening | ✅ Complete | DANE-EE, SASL EXTERNAL, dialback, Prosody interop |
| 9. Auth Hardening | ✅ Complete | Rate limiting, lockout, registration, passwd, delete, channel binding |
| 10. MUC | ✅ Complete | Multi-User Chat (XEP-0045) — rooms, join/part, groupchat, kick |
| 11. External Auth | ✅ Complete (OIDC) | OAUTHBEARER + PLAIN-to-IdP, EdDSA + RS256, introspection |
| 12. Polish & Deploy | ✅ Complete (MVP) | Fan-out, config, privsep, port, V1 pre-reqs. Tagged v0.1.0 |
| 13. Session Robustness Hardening | ✅ Complete | SM resume dispatch bug, stream ID reuse, stale-bind eviction, detached-session delivery. Tagged v0.8.6 |

**Current tree:** `master` = **v0.8.8** (`95e9c5c`, tagged 2026-08-30) +
CHANGELOG backfill. v0.8.8 collects the TLS session-id-context fix, XEP-0077
IBR advertisement, SM-resume dangling JID fix, T156 IPC pool bump, the
T155/T153 stale-fd/detached-session delivery hardening, and the slixmpp 1.17
suite port. Deployed to the freebsd-dev1 test jail (10.10.219.38) from a
ReleaseSafe tarball build.

---

## Next Up

All phases 1–13 are closed, and every plan in
[windsurf-plans](https://git.morante.net/daniel/windsurf-plans) is marked complete
or superseded. The live work item backlog is in Phorge (T-numbers); this section
tracks the release-level shape.

### Immediate

- [x] Verify the T155 fix (`zig build test`) on the FreeBSD host, then tag **v0.8.8**
      — verified and tagged 2026-08-30 (see Phase 13 Deferred Follow-ups for the
      full test matrix), deployed to the test jail the same day
- [x] T153 follow-up — detached-session guards in MUC/presence/IQ fan-out
      (shipped in v0.8.8; see Phase 13 Deferred Follow-ups)
- [x] Integration-harness rot — the six slixmpp suites had rotted against
      slixmpp 1.17 and could not run at all. Ported on branch
      `fix/integration-suite-slixmpp-1.17`: `connect()` takes `(host, port)`
      rather than a tuple (a tuple silently falls back to DNS and hits
      whatever is on port 5222); `enable_direct_tls = False` so clients stop
      sending a TLS ClientHello at the STARTTLS port, which the server logged
      as `error.InvalidEntityReference` (filed as T160) and which was the source of the flaky
      connect timeouts; and `e2e-subscription.py` now uses STARTTLS instead of
      a plaintext path that modern slixmpp cannot open. All six are
      parameterised via `XMPP_HOST`/`XMPP_PORT`/`XMPP_DOMAIN` and no longer
      default at the shared test jail.
- [x] SINT full XEP-0198 run — **DONE 2026-08-31: 10/10 pass** against a
      throwaway instance (domain xmppd.test via the existing SRV override,
      workers=1, IBR with `[auth] registration=true require_invite=false`).
      Invocation: `java -Dsinttest.service=xmppd.test -Dsinttest.dnsResolver=javax
      -Dsinttest.enabledSpecifications=XEP-0198 -Dsinttest.accountRegistration=inBandRegistration
      -Dsinttest.acceptAllCertificates=true
      -Dsinttest.disableHostnameVerificationForTlsCertificates=true
      -Dsinttest.securityMode=required -jar ci/smack-sint-server-extensions.jar`.
      Note: `securityMode=ifPossible` is rejected by this jar's enum; use
      `required`. The run also caught the T179 regression (v0.8.9's malformed
      registration form broke SINT's IBR account provisioning).

### v0.8.10 — Bugfix (cross-worker + regression)

- [x] **T173** — MUC admin IQ result dropped cross-worker (generation carried
      in actor replies) — merged 2026-08-31 (bf77eae)
- [x] **T176** — cross-worker subscription-cache invalidation — merged
      2026-08-31 (c6fc287); found by the new multi-worker lane
- [x] Multi-worker e2e lane in CI (`.forgejo/workflows/multiworker.yml`,
      `test/integration/run-multiworker.sh`, `--run-dir` flag, build.zig
      same-backend module sharing) — merged 2026-08-31
- [ ] **T179** — v0.8.9 regression: malformed registration form XML (stray
      `</field>`) breaks strict parsers (Smack proven) — fix on branch
      `fix/t179-register-form-xml`, verified (incl. SINT 10/10)
- [ ] **T178** — XEP-0198 unacked-queue overflow: fail the stream instead of
      silently discarding stanzas (ejabberd/Prosody behavior)
- [ ] **T180** — XEP-0054 §3.3: another user's missing vCard must return
      `service-unavailable` (both no-vCard and no-such-user), not an empty
      vCard / item-not-found (spec tightened in v1.3.0; found by T175's
      full-spec SINT run)

### v0.8.9 — Bugfix + Doc-Consistency — SHIPPED 2026-08-30

A code audit at `e922681` (v0.8.8+2) filed T163–T170: feature-list drift,
stubbed features with overclaiming docs, and small operational gaps. All
eleven items landed; see CHANGELOG for details:

- [x] **T163** (High) — caps/disco drift: disco#info now iterates
      `caps.SERVER_FEATURES` (single source; `writeDiscoFeatures`) + unit tests
- [x] **T165** — invite code parsed from the `jabber:x:data` registration form
      and passed to the auth daemon; form advertises the invite field;
      new `e2e-register-invite.py` (6/6)
- [x] **T166** — remote directed presence routes via the S2S outbound path
- [x] **T167** — `std.net.Address.parseIp4/parseIp6` bind parsing + IPv6-safe
      accept() + tests
- [x] **T168** — single build-time version constant in `build.zig`; XEP-0092
      and new `xmppd --version` both consume it
- [x] **T169** — README footnote ¹ corrected (roster push + roster set
      validation both verified implemented; remaining gap: §2.6 versioning)
- [x] **T164** — README XEP-0012 downgraded to Partial; full implementation
      stays open on the task for v0.9.0
- [x] **T170** — CI consistency check landed (sh+awk on the FreeBSD runner),
      adapted to the single-source disco wiring
- [x] **T161** — `IpcServer` heap-allocated in all three daemons; s2s IPC
      fan-out de-hardcoded from 16 slots to `MAX_IPC_CLIENTS`
- [x] **T160** — TLS ClientHello on the STARTTLS port gets a clear log line
      and close instead of an XML parse error
- [x] **T151** — evaluated: keep eager `flushSend()` (verdict recorded on the
      task; no code change)

### v0.9.0 — Performance + Refactor

Deferred out of the v0.8.0 feature release:

- [ ] T112 — MUC MAM routing
- [ ] T130 — batch presence
- [ ] T121 — auth thread pool
- [ ] T110 — backpressure
- [ ] T87 — async archive writer
- [ ] T154 — cross-worker resource eviction (workers>1)
- [ ] T164 (full) — XEP-0012 last-activity tracking (per-user `last_online`
      store, offline elapsed seconds, privacy rules)

### v0.10.0 — Feature: Web Transport

Per `xmppd-marketing-webclient-ae17e5.md`, the one plan with open items:

- [ ] **T40** — `xmppd-ws` — RFC 7395 XMPP-over-WebSocket process (`src/ws/`, `[ws]` config
      section, port 5280). Not yet scaffolded.
- [ ] **T37** — XEP-0363 HTTP File Upload — slot-allocation IQ handler in core plus an
      `xmppd-httpupload` binary (~1100–1500 LOC)
- [ ] **T162** — XEP-0049 Private XML Storage

### Non-code

- [x] xmppd.org refresh — HydePHP site live at xmppd.org, repo
      `pacyworld.dev/xmppd/website`, CI deploy to web03 via Fabrix. Keep
      version references current as releases ship (v0.8.8 latest)
- [ ] `securemessage/chat` web client — repo exists on pacyworld but is scaffold
      only (last touched 2026-06-19)


---

## Phase 13 — Session Robustness Hardening (v0.8.6) ✅

Critical reconnection-stability fixes discovered via real-world client testing
(Conversations Android) and a new comprehensive E2E regression suite
(`test/integration/e2e-sm-resume.py`). Full investigation writeup:
BookStack → xmppd → "v0.8.6 Bug Investigation: SM Resume Stall on Reconnection".

- [x] **SM resume silently dropped** — `handleElementStart`'s pre-bind IQ
  catch-all had an unconditional `return` that consumed ALL elements at
  `features_bind` state, including `<resume/>`. Fixed by reordering the
  SM resume check before the catch-all.
- [x] **Stream ID reuse across restarts** — same stream ID reused across
  STARTTLS/SASL stream restarts, violating RFC 6120 §4.7.3. Fixed via
  `regenerateStreamId()` called on every `handleStreamOpen()`.
- [x] **T152 — stale resource not evicted on rebind conflict** — a
  reconnect racing ahead of the old session's cleanup got `AlreadyBound`
  and was silently left unregistered in `SessionMap` despite the client
  believing it was bound. Fixed via `evictStaleResource()` (RFC 6120
  §7.7.3 — evict old resource, send `<conflict/>`, retry bind). New
  `conflict` `StreamError` variant added (was missing from the enum).
  Cross-worker eviction deferred (T154).
- [x] **T153 — message to detached session corrupts kqueue via stale fd
  reuse** — found via the new E2E suite's stanza-replay test. Delivering
  a stanza to a detached (SM-resume-pending) session used the session's
  stale, already-`close()`d fd for `changes.addWrite()`. If the OS
  recycled that fd for an unrelated connection, this misrouted kqueue
  events and caused premature session destruction (`item-not-found` on
  the client's subsequent resume). Fixed by tracking outbound stanzas to
  detached sessions via `smTrackOutbound()` for replay instead of
  attempting live delivery, in both the same-worker (`router.zig`) and
  cross-thread (`server.zig` MPSC unicast) delivery paths. Root-cause fd
  hazard in `Connection.close()` deferred as hardening follow-up (T155).

### Test Verification (T158)

- [x] SM detach-timer (300s) correctness — unit tests added
  (`session_lifecycle.zig`): boundary checks at 299s (survive), 300s (expire),
  and mixed-set selective expiry. No clock injection needed — tests set
  `sm_detach_time` directly to simulate elapsed time.
- [ ] SINT full run with `enabledSpecifications="XEP-0198"` — blocked: Smack
  Superseded — see "Next Up". SINT follows SRV, and an `xmppd.test` SRV
  record pointing at port 15222 already exists on freebsd-dev1; the port was
  never the real blocker. What SINT actually needs is in-band registration
  enabled on the auth daemon.

### Deferred Follow-ups

- [ ] T154 — cross-worker resource eviction (needs new cross-thread kick
  message type; only relevant with `[core] workers > 1`)
- [x] T155 — `Connection.close()` now resets `fd` to -1, and
  `Connection.queueSend()` rejects writes to a closed connection with
  `error.ConnectionClosed` (mirroring `S2sSession.queueSend`). Together these
  turn the stale-fd hazard from silent kqueue corruption into a loud, harmless
  error at every delivery site. Verified on freebsd-dev1: `zig build test`
  105/105 steps, 809/809 tests pass (master baseline 795).
- [x] T153 follow-up — the detached-session guard had only been applied at two
  delivery sites (`router.zig` unicast, `server.zig` MPSC unicast); every other
  fan-out path wrote to `target.conn` unguarded. Introduced
  `fanout.deliverToSession()` / `fanout.deliverPrebuiltToSession()` as the single
  delivery primitive (detached → `smTrackOutbound()` for replay; live → send,
  track, arm kqueue) and routed **21 call sites** through it: 9 in
  `muc_handler.zig`, 4 in `presence_handler.zig`, 4 in `iq_handler.zig`, 3 in
  `server.zig` (S2S inbound, S2S delivery-error, cross-worker multicast), and
  the XEP-0280 carbons path in `router.zig`. The now-dead `fanout.deliverPrebuilt()`
  was removed so the unguarded path cannot be reintroduced.

  This also fixes a **latent XEP-0198 counter bug**: MUC fan-out, presence
  broadcast and S2S inbound never called `smTrackOutbound()`, so `sm_out_seq`
  ran behind the client's count. `SmUnackedQueue.ack()` treats an `h` larger
  than the buffered range as "client acked more than we have" and calls
  `discardAll()` — silently dropping genuinely unacked *unicast* stanzas from
  the replay queue. All delivery paths now count.

  Verified on freebsd-dev1 against a throwaway single-worker instance on port
  15222 (built from this branch, local `xmppd-auth` backend):
  - `zig build test` — 105/105 steps, 809/809 tests pass, no pre-existing test
    changed count (master baseline 795)
  - `e2e-sm-resume.py` — **29/29 assertions, 0 failed**, matching the v0.8.6
    baseline. Test 6 (stanza replay to a detached session) is the test that
    originally caught T153 and exercises the rewritten path directly.
  - `e2e-chat.py` — all pass (routing, full stanza forwarding)
  - `muc-test.py` — 12/12, covering groupchat fan-out, occupant join/leave
    presence and kick — 9 of the 21 rerouted sites

  - `e2e-subscription.py` — 29/29, covering the `presence_handler` sites
    (available/unavailable broadcast, directed presence, roster-subscriber
    routing)
  - `e2e-quick-wins.py` — 12/12 and `e2e-mam.py` — 7/7, covering the
    `iq_handler` sites (PEP notification, roster push) plus MUC history and MAM

  All six suites match the master baseline exactly, with zero server-side
  errors logged across the run. Still not exercised: the two S2S sites in
  `server.zig`, which need a federation peer (`s2s-federation.py` expects a
  Prosody instance).
- [ ] T151 — evaluate reverting eager `flushSend()` in `handleReadable`
  (harmless but unnecessary micro-optimization from the v0.8.6 debug session)

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
- [x] Conversations (Android — SCRAM-SHA-256, multi-resource, MUC join, reconnection)

### Bugs Found and Fixed

- **MUC room name case-sensitivity** — Conversations lowercases room
  names per RFC 7622, but xmppd stored/matched them case-sensitively.
  `FirstRoom` (Thunderbird) vs `firstroom` (Conversations) created two
  separate rooms instead of joining the same one. Fix: case-fold the
  localpart in `buildRoomJid()` before lookup/creation.
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

## Phase 10 — Multi-User Chat (MUC) ✅

XEP-0045 implementation for group messaging. MUC lives inline in
xmppd-core (not a separate process) since it's fundamentally routing/fan-out,
tightly coupled to the C2S session lifecycle.

Design document: `~/.windsurf/plans/xmppd-phase10-muc-design.md`

### Sub-steps

| Step | Feature | Status |
|------|---------|--------|
| 10a | XML namespace constants (muc_user, muc_admin, muc_owner) | ✅ |
| 10b | RoomStore(Backend) — room config + affiliation persistence | ✅ |
| 10c | RoomRegistry — in-memory room + occupant tracking (heap-alloc) | ✅ |
| 10d | MUC handler — join, part, groupchat fan-out, disco, kick | ✅ |
| 10e | server.zig — MUC subdomain routing, closeSession cleanup | ✅ |
| 10f | iq_handler.zig — MUC IQ dispatch (disco, admin) | ✅ |
| 10g | main.zig — --muc-host CLI flag, RoomRegistry init | ✅ |
| 10h | build.zig — room_store + room_registry modules | ✅ |
| 10i | Unit tests (28 tests for RoomStore + RoomRegistry) | ✅ |
| 10j | Integration test (slixmpp, 12 assertions) | ✅ |

### Implemented Features

- [x] Room creation (instant, transient by default)
- [x] Join with nick conflict / capacity / members-only checks
- [x] Part (explicit + auto-part on disconnect)
- [x] Groupchat message fan-out (all occupants including echo)
- [x] Moderated room voice check (visitors blocked)
- [x] Admin kick (role=none, status 307)
- [x] Grant/revoke voice
- [x] Transient room auto-destroy on last occupant leave
- [x] Room discovery (disco#info/items for MUC service + rooms)
- [x] Server disco#items advertises MUC service
- [x] Session disconnect auto-parts all rooms

### Deferred (Post-MVP)

- [ ] Room history on join (wire ArchiveStore query)
- [ ] Persistent affiliation lookup on join (RoomStore.getAffiliation)
- [ ] Load persistent rooms from RoomStore on startup
- [x] Room name case-folding (RFC 7622 — JID localpart is case-insensitive)
- [ ] Room configuration form (XEP-0045 §10.1 dataforms)
- [ ] Ban (outcast affiliation + persist)
- [ ] Password-protected rooms
- [ ] S2S room federation

### Key Files

- `src/store/room_store.zig` — ~620 LOC
- `src/core/room_registry.zig` — ~500 LOC
- `src/core/muc_handler.zig` — ~900 LOC
- `test/integration/muc-test.py` — slixmpp integration test

## Phase 11 — External Auth (OIDC) ✅

Pluggable authentication via external Identity Providers. Multi-binary
architecture: each auth backend is a separate executable selected by
the master supervisor via `--auth-path`.

Design document: `~/.windsurf/plans/xmppd-phase11-external-auth-4f6f38.md`

### Sub-steps

| Step | Feature | Status |
|------|---------|--------|
| 11a | `src/config/parser.zig` — INI config parser (sections, key=value, #comments) | ✅ |
| 11b | Master passes `--config` to children via execve argv | ✅ |
| 11c | `MechanismId.oauthbearer` (0x03) + IPC tag 0x0C (MechanismList) | ✅ |
| 11d | Auth sends MechanismList on IPC connect → core uses for stream features | ✅ |
| 11e | `lib/http/client.zig` — blocking HTTPS GET/POST over OpenSSL | ✅ |
| 11f | `lib/jwt/jwt.zig` — JWT parse + RS256/EdDSA signature verification | ✅ |
| 11g | `src/auth/oidc.zig` — OidcStore (JWKS cache, JWT validation, ROPC, introspection) | ✅ |
| 11h | AuthHandler refactor — comptime `@hasDecl` for validatePassword/validateToken | ✅ |
| 11i | `src/auth/oidc_main.zig` — xmppd-auth-oidc entry point | ✅ |
| 11j | Build system — `xmppd-auth-oidc` executable in build.zig | ✅ |
| 11k | Integration test — OAUTHBEARER + ROPC against Rauthy | ✅ |

### Implemented Features

- [x] OAUTHBEARER SASL mechanism (RFC 7628) — JWT validation
- [x] PLAIN-to-IdP delegation via ROPC (Resource Owner Password Credentials)
- [x] Token introspection fallback (RFC 7662) for opaque tokens
- [x] JWKS key cache with 1-hour TTL + kid-miss refresh
- [x] EdDSA (Ed25519) + RS256 JWT signature verification
- [x] JID localpart extraction from email claims
- [x] RFC 3986 percent-encoding for ROPC form bodies
- [x] Dynamic mechanism advertisement via IPC MechanismList
- [x] Shared INI config parser for all daemons
- [x] Rate limiting applies to OIDC backend (reuses Phase 9 infrastructure)

### Key Files

- `src/auth/oidc.zig` — ~460 LOC (OidcStore, JWKS, introspection)
- `src/auth/oidc_main.zig` — ~240 LOC (entry point, event loop)
- `lib/http/client.zig` — ~360 LOC (HTTPS client)
- `lib/jwt/jwt.zig` — ~410 LOC (JWT parse + RS256 + EdDSA verify)
- `src/config/parser.zig` — ~190 LOC (shared INI parser)

**Binaries:** `xmppd-auth-oidc` (4.3MB)

### Future Backends (Not This Phase)

- **LDAP/AD** — bind authentication, group-based authorization
- **SQL** — external database credential lookup (PostgreSQL/MariaDB)
- **Token auth** — HT-SHA-256 for mobile clients
- **SASL EXTERNAL for C2S** — client certificate authentication (mTLS)
- **PAM** — system-level auth integration

## Phase 12 — Polish & Deploy (MVP Complete)

Production readiness. The "Giant Thread" problem (event loop starvation
during MUC fan-out) was solved as part of this phase. FreeBSD port
created, jail tested, privilege separation implemented, process lifecycle
hardened. Tagged `v0.1.0`.

### Fan-out Scalability (Done)

- [x] Bounded continuation — yield after N occupants per event loop tick (`src/core/fanout.zig`)
- [x] Pre-built common stanza — prefix/JID/suffix assembly eliminates per-occupant serialization
- [x] Configurable `max_sessions` — heap-allocated, default 4096 (was hard-coded 1024)

### Configuration (Done)

- [x] Configuration file system (single `xmppd.conf` with INI sections)
- [x] All daemons read `--config` (xmppd, xmppd-core, xmppd-auth, xmppd-auth-oidc)
- [x] CLI flags override config file values (Postfix convention)
- [x] Sensible defaults (works out of the box without config for dev mode)
- [x] `config/xmppd.conf.sample` with all sections documented

### Deployment (Done)

- [x] FreeBSD RC script (`etc/rc.d/xmppd`) — no daemon(8), master self-daemonizes
- [x] FreeBSD port (`net-im/xmppd` in deluxe ports tree) — builds all 6 binaries
- [x] Jail installation and end-to-end testing (xmppd jail on freebsd-dev1)
- [x] `v0.1.0` tagged and pushed to all 3 remotes

### Privilege Separation (Done)

- [x] `user` config option in `[server]` section — children drop to unprivileged user
- [x] Master resolves user via `getpwnam()`, passes uid/gid to Supervisor
- [x] `Supervisor.initWithUser()` — `setgid()`/`setuid()` in child fork before `execve()`
- [x] Signal mask reset in child fork — children don't inherit parent's blocked signals

### Process Lifecycle (Done)

- [x] Self-daemonizing master (`--background`/`-b`) — `fork()` + `setsid()` + stdio → `/dev/null`
- [x] Single-instance via PID file `flock(LOCK_EX|LOCK_NB)` — refuses to start if locked
- [x] Child PID files (`auth.pid`, `core.pid`) written after spawn
- [x] Orphan cleanup on startup — SIGTERM → 2s grace → SIGKILL for stale children
- [x] Clean PID file removal on graceful shutdown

### V1 Pre-requisites (Done)

- [x] S2S supervisor wiring — master spawns xmppd-s2s as third child (auth → s2s → core)
- [x] Privileged port binding — master binds 5222/5269 while root, passes fds via `--listen-fd`
- [x] xmppctl IPC-based management — tries auth daemon IPC first, falls back to direct DB
- [x] Auth-OIDC cosmetic fix — master skips `--db` for OIDC backend

### Standards (Post-MVP)

- [x] XEP-0198: Stream Management (mobile reconnection) — v0.6.0, hardened v0.8.6
- [x] XEP-0280: Message Carbons (multi-device)
- [ ] XEP-0363: HTTP File Upload (media sharing) — planned for v0.10.0

### Documentation (Post-MVP)

- [x] `doc/ARCHITECTURE.md` — multi-process design, IPC protocol
- [x] `doc/CONFIGURATION.md` — all config options
- [x] `doc/DEPLOYMENT.md` — FreeBSD setup guide
- [ ] `doc/FEDERATION.md` — S2S setup, DANE, dialback
- [ ] Man pages for all binaries

### Testing (Post-MVP)

- [ ] XMPP Compliance Suite verification
- [ ] Performance benchmarks (connections/sec, message throughput)
- [ ] Fuzz testing on XML parser

### Account Privacy (Post-MVP)

- [ ] JID enumeration protection
- [ ] Presence leak prevention

---

## V1 — Thread-Per-Core ✅ (shipped v0.5.0)

**Status:** Shipped in v0.5.0 (SO_REUSEPORT_LB, per-worker kqueue loops, MPSC
cross-thread delivery, shared SessionMap) and superseded by the v0.6.0 actor
refactor. This section is retained as design history, not as pending work.

Multi-threaded xmppd-core for horizontal scaling across CPU cores.
Design document: `windsurf-plans/xmppd-giant-thread-fix-1e17cd.md`
(git.morante.net/daniel/windsurf-plans).

### Pre-requisites ✅

All completed in commit a24fa94:

- [x] S2S supervisor wiring — master spawns xmppd-s2s as third child
- [x] Privileged port binding + fd passing (`--listen-fd`)
- [x] xmppctl IPC-based management (IPC first, DB fallback)
- [x] Auth-OIDC `--db` cosmetic fix

### Avatar System (V1)

Unified avatar resolution with fallback chain. Clients see a single canonical
avatar via standard XEPs; the server handles sourcing transparently.

**Resolution order (highest priority wins):**

1. **Client-set** — user uploads via XEP-0084 (User Avatar / PEP) or XEP-0153
   (vCard-Based Avatars). Overrides everything. Updates external auth if supported.
2. **External auth (OIDC)** — on first login, fetch `picture` claim from IdP
   userinfo. Cache locally. Only used if no client-set avatar exists.
3. **Gravatar** — hash user's email (MD5 per Gravatar spec), fetch from
   `gravatar.com/avatar/{hash}`. Enabled by default, toggle via
   `[avatar] gravatar = true|false` in xmppd.conf.

**XEPs:**

- [ ] XEP-0084: User Avatar (PEP publish/subscribe for avatar data + metadata)
- [ ] XEP-0153: vCard-Based Avatars (presence `<photo>` hash, legacy clients)
- [ ] XEP-0054: vcard-temp PHOTO element (already stubbed, needs real storage)

**Behavior:**

- [ ] Gravatar fetch on session bind if no stored avatar (async, cache result)
- [ ] OIDC avatar fetch on first auth success (from `picture` claim URL)
- [ ] Client avatar upload persists to VCardStore (PHOTO element) + PEP node
- [ ] If external auth supports avatar update (Rauthy API), push client-set avatar upstream
- [ ] Presence broadcasts include `<photo>` hash per XEP-0153 for legacy clients

**Notes:**

- Client-local overrides are purely client-side behavior (not server-enforced).
  The server always serves the canonical avatar; clients may display a local
  override per their own UX preference.
- Post-V1: admin policies for avatar size limits, allowed formats, corporate branding

### Thread-Per-Core (single process, multiple threads)

V1 targets single-process multi-thread. All threads share one address space,
one storage handle, one session registry. This dramatically simplifies storage
(no cross-process coordination, no IPC for store access, no distributed cache
invalidation) and routing (direct pointer lookup, no serialization).

**Why single-process for V1:**
- Storage — LMDB/RocksDB handle shared across threads. No exclusive lock
  conflicts. One thread writes, all threads see it immediately.
- Session routing — shared in-memory registry with mutex/lock-free access.
  Cross-thread message delivery is MPSC push + kqueue wakeup, not IPC.
- MUC fan-out — occupants on different threads reached via MPSC, not
  Unix socket marshaling.
- Simpler to implement — delete more IPC code than you add thread sync code.

**Trade-off:** A crash takes down all threads (no fault isolation). Acceptable
at V1 scale. Multi-process + multi-thread is the Post-V1 evolution.

**Stage 1 — PoC (fd inheritance, isolate threading from fd-passing):**

Use existing `--listen-fd` mechanism. Master creates N SO_REUSEPORT sockets,
passes all N fds to one xmppd-core child. xmppd-core spawns N threads,
each taking one fd. Proves threading works before changing fd-passing mechanism.

- [x] SO_REUSEPORT_LB — master creates N sockets, passes via `--listen-fd 5,6,7,8`
- [x] Per-thread kqueue event loop — each thread owns one listener fd + its sessions
- [x] MPSC channels — lock-free cross-thread stanza delivery (pipe wakeup, always-wake)
- [x] Shared SessionMap — JID-keyed hash table with RwLock, resource inline in entry
- [x] Two-pass event processing — drain MPSC before socket events (prevents ABA races)
- [x] Cross-thread presence, subscription, MUC fan-out via MPSC
- [x] S2S presence broadcast — available/unavailable/probes forwarded to remote domains
- [x] S2S subscription forwarding — subscribe/subscribed/unsubscribe/unsubscribed via S2S
- [x] S2S inbound round-robin — single-worker delivery (was N-duplicate broadcast)
- [x] Integration tested — 8 clients, 4 workers, 64/64 messages delivered
- [x] MUC per-room worker-level multicast (T62 — Option A worker_mask)
- [ ] Thread-local allocation (per-event scratch arena + session-lifetime slab pool)
- [ ] Optional CPU affinity (cpuset_setaffinity, configurable)
- [ ] Testing + benchmarks

**Stage 2 — SCM_RIGHTS migration (after Stage 1 is stable):**

Replace fd inheritance with explicit fd passing over Unix socketpair.
Enables hot restart, zero-downtime upgrades, and Post-V1 multi-process.

- [ ] `sendfd()`/`recvfd()` helpers (`sendmsg`/`recvmsg` + `CMSG_DATA(SCM_RIGHTS)`)
- [ ] Master creates socketpair per child, sends bound fds after fork+exec
- [ ] Child receives fds via `recvfd()` on startup (replaces fd inheritance)

---

## Post-V1

These items are out of scope for V1 but are on the long-term radar.

### Multi-Process + Multi-Thread

Combine process-level fault isolation with thread-level shared memory.
Natural evolution of V1's single-process thread-per-core once scale
demands fault isolation between worker groups.

```
xmppd (master, root)
  ├── xmppd-auth
  ├── xmppd-s2s
  ├── xmppd-core worker 0  (N threads, fds 5..8)
  └── xmppd-core worker 1  (N threads, fds 9..12)
```

**Process boundary** gives fault isolation (worker 0 crashes, worker 1
keeps serving) and security separation (different UIDs possible).

**Thread boundary** gives shared memory for the session registry within
a worker (no IPC for same-worker routing), shared storage handle, and
zero-copy stanza delivery.

**Cross-worker routing** requires IPC (Unix socket or shared memory
ring buffer). Intra-worker routing is a pointer dereference through
the shared registry — no serialization.

**Topology tuning:** On a 32-core box, run 4 workers × 8 threads.
More processes = better fault isolation. More threads per process =
fewer IPC hops for routing. The sweet spot depends on workload.

**fd passing works for both topologies:** Master creates N SO_REUSEPORT
sockets, distributes them. Whether a given fd goes to a different
process or a different thread is transparent — the `--listen-fd`
infrastructure from V1 pre-requisites is reused unchanged.

**Storage complexity (the reason V1 is single-process first):**
- LMDB supports concurrent readers across processes (OK).
- RocksDB needs shared-nothing (separate DB dir per worker) or a
  dedicated storage service process.
- Single-process avoids this entirely — one handle, all threads see
  writes immediately via shared memory.

**Prior art:** Nginx (multi-process, per-worker threads for async I/O),
HAProxy (added threads within workers), Envoy (thread-per-core within
one process). The hybrid model is where large servers converge.

### Other Post-V1

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
- **S2S async DNS + probe throttling** — blocking DNS stalls event loop; batch probes (T65)
- **Sharded SessionMap** — reduce RwLock contention at 64+ cores (T56)

---

## XEPs Supported

| XEP | Name | Phase |
|-----|------|-------|
| RFC 6120 | XMPP Core | 1–2 |
| RFC 6121 | XMPP IM | 7 |
| XEP-0012 | Last Activity | v0.8.0 |
| XEP-0030 | Service Discovery | 7 |
| XEP-0045 | Multi-User Chat | 10 |
| XEP-0054 | vcard-temp | 7 |
| XEP-0077 | In-Band Registration | 9 |
| XEP-0084 | User Avatar (PEP) | V1 |
| XEP-0085 | Chat State Notifications | V1 |
| XEP-0092 | Software Version | 7 |
| XEP-0115 | Entity Capabilities | v0.8.0 |
| XEP-0160 | Offline Message Storage | 7 |
| XEP-0163 | Personal Eventing Protocol | V1 |
| XEP-0184 | Message Delivery Receipts | pass-through |
| XEP-0191 | Blocking Command | V1 |
| XEP-0198 | Stream Management | V1 |
| XEP-0199 | XMPP Ping | 7 |
| XEP-0220 | Server Dialback | 8 |
| XEP-0280 | Message Carbons | V1 |
| XEP-0308 | Last Message Correction | pass-through |
| XEP-0313 | Message Archive Management | 5+7 |
| XEP-0333 | Chat Markers | v0.8.0 |
| XEP-0334 | Message Processing Hints | v0.8.0 |
| XEP-0352 | Client State Indication | v0.8.0 |
| XEP-0359 | Unique Message and Stanza IDs | V1 |
| XEP-0402 | PEP Native Bookmarks | v0.8.0 |
| XEP-0440 | SASL Channel-Binding Type Capability | 9 |

"V1" in the Phase column refers to the thread-per-core / actor work that shipped
in v0.5.0–v0.6.0, not to pending work.

## Metrics

| Metric | Value |
|--------|-------|
| Language | Zig 0.15.2 |
| Source files | ~60 |
| Lines of code | ~30,000 |
| Unit tests | 105 build steps, 809 tests (all pass) |
| Integration tests | 20 slixmpp E2E (incl. e2e-sm-resume.py) + 64 cross-thread + Tsung load tests |
| Binaries | 6 (`xmppd`, `xmppd-core`, `xmppd-auth`, `xmppd-auth-oidc`, `xmppd-s2s`, `xmppctl`) |
| Primary platform | FreeBSD (kqueue) |
| License | BSD-2-Clause |
