# Changelog

## Unreleased (v0.9.0)

### Features

- T164 XEP-0012 last-activity: the jabber:iq:last handler was a stub that
  answered seconds='0' to everything (README had already been downgraded
  to Partial for this). Server-directed queries now answer real domain
  uptime; other-account queries are server-answered with 0 while online
  and seconds-since-last-teardown while offline (durable record in the
  ops DB written when an account's final resource unbinds — consistent
  across workers with no new actor traffic). Disclosure follows presence
  visibility (target's roster entry for the requester must be from/both,
  else forbidden; nonexistent accounts are indistinguishable). Full-JID
  queries forward to the addressed resource per RFC 6121 §8.5.3 — the
  resource's client answers its own idle time (XEP-0012 §2.1), so no
  server-side idle clock is kept (9d6daff).
- T177 MUC occupant migration: cross-worker XEP-0198 resume now works for
  sessions that occupy MUC rooms (previously refused, forcing a full
  re-bind + rejoin). The handoff bundle carries the detached session's room
  list; after the resuming worker re-binds (generation known), it replays
  one `room_occupant_move` actor message per room's owning worker, which
  updates the canonical occupant record's (worker, session, generation)
  triple in place and syncs shadow copies — a move, not a join/part: no
  presence fan-out, no new-member handling. Ghost-leak safety: if the
  resumed connection dies before the moves apply, the session_close
  broadcast still removes the occupant by full JID everywhere. Occupancy
  over 64 rooms per session falls back to the full re-bind behavior.
- T177 redirect breadcrumbs: a relocated session's SM-ID keeps the issuing
  worker's prefix, so repeat resumes now follow per-worker previd → worker
  redirects (chained, bounded hops, expire with the resume window) instead
  of failing `item-not-found` on the second cross-worker hop.
- T130 batch presence delivery: subscriber resolution resolves a chunk of
  32 bare JIDs in one session-map lock hold (batched lookup) and each
  remote worker's MPSC queue gets ONE pipe wake per chunk instead of one
  per target session; presence probes use the same batching (52d6896).
- T110 client-side backpressure: when a connection's write buffer crosses
  75%, its EVFILT_READ is disabled — the server stops consuming stanzas it
  cannot forward and TCP flow control pushes back on the sender; reading
  resumes at 50% (8e6fb7c).
- T121 auth crypto pool: PLAIN credential derivation (PBKDF2) runs on a
  fixed pool of worker threads (default 4, `[auth] crypto_threads`, 0
  disables) instead of blocking the auth daemon's event loop; bounded
  256-job queue answers temporary-auth-failure on overflow. SCRAM is
  unaffected (server-side verify is cheap HMAC) (39e7e6d).
- T87 async archive writer: a single writer thread with a bounded
  deep-copy queue owns all archive stores; event loops never block on
  storage I/O (compaction stalls no longer freeze sessions), and archive
  writes became single-threaded (previously N concurrent writers)
  (c0a9223). MAM/history reads stay inline (eventually consistent).
- T154 cross-worker resource takeover: a bind conflicting with a resource
  held by another worker now parks and evicts the holder via a
  session_kick actor round-trip (RFC 6120 §7.7.3) instead of failing the
  client with <conflict/> (e2e-resource-takeover 25/25 at workers=4)
  (307a717).
- T198: per-account resource cap raised from hardcoded 16 to
  `[core] max_resources_per_account` (default 256) backed by a heap-grown
  entry list — multi-resource accounts (agent/bot deployments) no longer
  hit the wall (a3babac).

### Fixes

- T112: MUC MAM queries routed to a room's owning worker were degraded at
  the actor-message boundary: the response IQ id was the client's MAM
  queryid (XEP-0313 allows queryid != stanza id, breaking IQ matching),
  RSM <max/> was replaced by a hardcoded 50, <after/>/<before/> paging was
  dropped, and the no-archive answer diverged from the local path. The
  room_mam_query actor message now carries iq_id + full RSM text; local
  and remote answers are identical (e2e-muc-mam-routing 82/82 at
  workers=4, wired into the CI multiworker lane) (c1f53e9).
- T198: a bind whose session-map registration failed (e.g. over the
  resource cap) previously sent the success IQ first and only logged —
  the client believed itself bound while inbound stanzas were silently
  unroutable. Registration now precedes the result; over-cap binds get a
  stanza error (resource-constraint) and may retry with another resource
  (a3babac). Also rolled back partial full_map/bare_map registration on
  mid-bind failures (latent inconsistency).
- T152/T154: evicted sessions got their <conflict/> stream error queued
  but never flushed before the teardown closed the fd — the client closed
  with no explanation. Now flushed synchronously before teardown
  (307a717).
- SM resume restored the session resource from the transient bind
  accumulator, which is zeroed after a successful bind — resumed sessions
  ended up with an EMPTY resource (`user@host/`). The resource now comes
  from the detached session's bound JID — MUC fan-in and fan-out stay
  correct after resume (T177 work, 02893d9).

### Testing

- New `e2e-muc-resume.py`: alice joins a room with SM resume enabled and
  loops abrupt-disconnect + resume; asserts the resumed session keeps
  receiving and sending groupchat without rejoining, detached-era stanzas
  replay, and other occupants never see a rebroadcast join presence.
  Cross-worker handoff is verified via server-log evidence.
- New `e2e-resource-takeover.py`: repeated same-resource bind takeovers,
  cross-worker kick evidence via server log.

## v0.8.11 — 2026-09-30

Hardening release. **Operationally significant:** the authentication
rate limiter was silently inert in all previous releases and now actually
enforces. Deployments upgrading from ≤ 0.8.10 gain brute-force protection
for the first time: 5 attempts per account and 20 per IP per 120s window,
temporary account lockout after 10 consecutive failures. Clients that
repeatedly fail auth will now see `policy-violation` / `account-disabled`
instead of unlimited `not-authorized` retries.

### Fixes

- Auth rate limiting was inert on the live path: core sends an empty
  username in the auth request (the daemon extracts the identity from the
  SASL payload), so per-account rate checks and lockouts evaluated an
  empty key and never engaged; and the per-IP attempt ring (8 slots) could
  never count up to the default per-IP limit (20). Per-IP checks still run
  at request entry; per-account checks and lockouts now run in the
  PLAIN/SCRAM handlers once the username is parsed, and the ring holds 32
  entries so configured maxima up to 32 engage (8a100f4)
- SASL failure reason is now passed through to the wire: rate-limit denial
  surfaces as `policy-violation` / `account-disabled` (RFC 6120 §6.5
  conditions, whitelisted) instead of a generic `not-authorized` (8a100f4)

### Tooling

- New `[auth] rate_limit = false` config switch (and `--no-rate-limit` on
  xmppd-auth, `[oidc] rate_limit = false` on xmppd-auth-oidc) to disable
  auth rate limiting for benchmark/load-test rigs; the multi-worker e2e
  lane enables it since connect-heavy suites now trip the real limits
  (ee4d113). Logs a prominent warning at startup when disabled. Never use
  on a reachable deployment.

Verified on freebsd-dev1 (Zig 0.15.2): `zig build test` all steps
(including new rate-limiter enforcement and SASL-condition tests);
live 25-attempt single-IP auth hammer: unlimited when disabled, exactly
5× `not-authorized` then `policy-violation` with defaults; seven e2e
suites at workers=1, cross-worker subset at workers=4.

## v0.8.10 — 2026-08-31

Bugfix release: cross-worker delivery, a v0.8.9 regression, and four
stanza error-handling correctness fixes found by the first full-spec
SINT runs (T175 follow-ups).

### Fixes

- T173 (High): MUC admin IQ results (kick/ban/voice) were dropped when
  the room shard lived on a different worker than the requester — the
  cross-worker reply carried a hardcoded generation 0 and the ABA-guarded
  drain discarded it. The admin actor message now carries the requester's
  generation (bf77eae)
- T176: per-worker subscription cache was never invalidated cross-worker,
  so presence routing on other workers used stale subscription state
  (c6fc287, found by the new multi-worker lane)
- T179 (v0.8.9 regression): the XEP-0077 registration data form emitted
  malformed XML (stray `</field>`), breaking strict parsers (Smack/StAX
  proven) and SINT's IBR provisioning (7bc5980)
- T178: XEP-0198 unacked-queue overflow silently discarded the oldest
  stanza, invisibly breaking the at-least-once promise. The queue now
  reports overflow and the session is failed (ejabberd/Prosody behavior):
  live sessions get a `resource-constraint` stream error and close;
  detached sessions are destroyed, so a later `<resume/>` fails
  `item-not-found` and the client resyncs via MAM (cc70366). The server
  also now sends `<r/>` ack requests once the queue crosses half capacity
  (4c54410) — XEP-0198 only obliges clients to ack on request, so without
  this the overflow policy would kill compliant clients that never ack
  unsolicited (SINT-proven with Smack: busy SM sessions died after ~256
  unacked stanzas in ~20s of presence flood)
- T180: XEP-0054 §3.3 (v1.3.0) — vCard GET for another user now returns
  `service-unavailable` for both no-vCard and no-such-user
  (anti-harvesting; the two cases must be indistinguishable). The
  own-vCard path keeps its empty-vCard/Gravatar behavior (cc70366)
- T181: RFC 6121 §8.5.2.2.1 — groupchat to a bare JID with no available
  resources bounces `service-unavailable` instead of being stored
  offline; type='error' stanzas are silently dropped instead of stored
  (cc70366)
- T182: stanzas received before authentication/resource binding were
  silently dropped. Per RFC 6120 §7.1, message/IQ addressed to a third
  party now close the stream with a `not-authorized` stream error;
  server/account-addressed IQs get a `not-authorized` stanza error (IQs
  must always be answered) and the connection stays open; presence stays
  ignored (cc70366, §7.1 rework)

### CI

- New multi-worker e2e lane (`.forgejo/workflows/multiworker.yml`,
  `test/integration/run-multiworker.sh`): spins a workers=4 throwaway
  instance so the cross-worker surface (room sharding, actor messages,
  MPSC delivery with generation validation) is exercised — at workers=1
  every route is local, which is how T173 shipped

Verified on freebsd-dev1 (Zig 0.15.2): `zig build test` all steps;
e2e-sm-resume 29/29; e2e-chat all pass; muc-test 12/12; e2e-quick-wins
12/12; e2e-mam 7/7; e2e-subscription 29/29; e2e-register-invite 6/6;
multi-worker lane (workers=4) green; SINT XEP-0198 10/10.

## v0.8.9 — 2026-08-30

Bugfix/doc-consistency release (T163–T170 audit batch + T160/T161/T151).

### Fixes

- T163 (High): XEP-0115 caps `ver` omitted `jabber:iq:register` which
  disco#info advertised — the hash could never verify (clients doing §5
  verification discarded the caps). disco#info now iterates
  `caps.SERVER_FEATURES` via `caps.writeDiscoFeatures`, one list by
  construction
- T165: invite-gated IBR (XEP-0077, the secure default) could never succeed —
  the invite code in the `jabber:x:data` form was never parsed. The
  invite/token field is now passed through to the auth daemon, and the
  registration form advertises an optional `invite` field
- T166: directed presence to remote domains was silently dropped; it now
  routes through the S2S outbound path like subscription/broadcast presence
- T167: listener bind address parsing — any IPv4 dotted-quad and IPv6 literals
  now work (was: only `0.0.0.0`/`127.0.0.1`); accept() no longer truncates
  IPv6 peers
- T168: XEP-0092 Software Version reported a hardcoded `0.1.0`; single
  build-time version constant in `build.zig` now feeds both
  `jabber:iq:version` and the new `xmppd --version`
- T161: `IpcServer` (~1.97 MB since T156) heap-allocated in xmppd-auth,
  xmppd-auth-oidc, xmppd-s2s (was stack-resident). Also fixes s2s IPC fan-out
  still limited to the first 16 client slots (workers 17+ never received
  federated stanzas)
- T160: TLS ClientHello on the STARTTLS port now logs "TLS handshake on the
  STARTTLS port — client is configured for direct TLS" and closes, instead of
  a misleading `error.InvalidEntityReference` XML parse failure

### Docs / CI

- T170: CI feature-matrix consistency check (`.forgejo/workflows/consistency.yml`,
  `test/consistency/`, base-system sh+awk on the FreeBSD runner) — guards
  caps/disco#info/README drift; adapted to the single-source disco features
- T169/T164: README XEP matrix corrections — RFC 6121 footnote 1 stale clauses
  removed (roster push and roster set validation are implemented; remaining
  gap is roster versioning §2.6), XEP-0012 downgraded to Partial (online-self
  stub; full implementation deferred to v0.9.0)
- T151 evaluated and closed: keep the eager `flushSend()` in `handleReadable`
  (fewer syscalls in the common request/response case; verdict on the task)
- New `test/integration/e2e-register-invite.py` (raw-socket suite, 6/6)

Verified on freebsd-dev1 (Zig 0.15.2): `zig build test` all steps;
e2e-sm-resume 29/29; e2e-chat all pass; muc-test 12/12; e2e-quick-wins 12/12;
e2e-mam 7/7; e2e-subscription 29/29; e2e-register-invite 6/6.

## v0.8.8 — 2026-08-30

Bugfix/hardening release on top of v0.8.7 (8 commits). Tagged from `95e9c5c`;
deployed to the freebsd-dev1 test jail (10.10.219.38).

### Fixes

- Concurrent TLS handshake failure (SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED)
- T158: SM resume dangling JID; advertise XEP-0077 IBR in stream features and
  disco#info (when registration enabled)
- T156: `MAX_IPC_CLIENTS` 16 → 80; reject pre-auth SM enable with `<failed/>`
- T155: `Connection.close()` resets `fd` to −1 and `queueSend()` rejects closed
  connections with `error.ConnectionClosed` — turns the stale-fd hazard class
  from silent kqueue corruption into a loud, harmless error
- T153 follow-up: single session-delivery primitive
  (`fanout.deliverToSession()` / `deliverPrebuiltToSession()`) across 21 call
  sites (MUC fan-out, presence broadcast, PEP/block/roster push, S2S inbound,
  cross-worker multicast, XEP-0280 carbons). Detached SM sessions now buffer
  for replay instead of being written to dead fds. Also fixes a latent
  XEP-0198 counter bug: fan-out paths never called `smTrackOutbound()`, letting
  `SmUnackedQueue.ack()` discard genuinely unacked unicast stanzas
- T157: `[oidc] import_avatar` config gate (default off)

### Tests / Docs

- Integration suites ported to slixmpp 1.17; parameterised via `XMPP_*` env
  vars (default: local throwaway instance, no longer the shared test jail)
- New `doc/TESTING.md` — throwaway-instance e2e procedure
- README/ROADMAP corrections; ROADMAP gained a forward-looking "Next Up"

Verified on freebsd-dev1 (Zig 0.15.2): `zig build test` 105/105 steps;
e2e-sm-resume 29/29; e2e-chat all pass; muc-test 12/12; e2e-quick-wins 12/12;
e2e-mam 7/7; e2e-subscription 29/29.

## v0.8.7 — 2026-07-01

- T152: stale-bind eviction — reconnecting with the same resource before the
  old session was cleaned up got `AlreadyBound` and was left unregistered in
  SessionMap; fixed with RFC 6120 §7.7.3-style eviction (`<conflict/>` + retry)
- T153: detached-session delivery corruption — stanzas routed to a detached
  (SM resume pending) session were written to its dead connection; guarded at
  the router and MPSC unicast delivery sites
- New `e2e-sm-resume.py` regression suite (29 assertions)

## v0.8.6 — 2026-07-01

- SM resume silently dropped at features_bind: the pre-bind IQ catch-all in
  `handleElementStart` consumed `<resume/>`; clients timed out waiting for a
  reply
- Stream ID reuse fix (RFC 6120)

## v0.8.5 — 2026-06-19

- XEP-0115 Entity Capabilities: server caps hash (SHA-1 over disco features),
  pre-built `<c>` element for presence injection, node-based disco#info
  response for caps verification (§5.3), disco query mechanism
- OIDC profile photo import

## v0.6.0 — 2026-06-14

RFC 6121 interop compliance and XEP-0198 session resumption.

### XEP-0198: Session Resume

- Full session resume implementation: detach on abnormal disconnect, resume on
  reconnect without full re-authentication
- SM-ID generation (worker_id-prefixed for multi-threaded routing)
- Unacked stanza queue (bounded ring buffer, 256 entries) with heap-allocated copies
- Resume flow: find detached session by SM-ID, verify authenticated user, transfer
  session state (counters, bound JID, roster interest, carbons, presence), re-bind
  in session map, replay unacked stanzas
- Periodic expiry sweep (30s timer) destroys detached sessions after 300s timeout
- Outbound stanza sequence tracking at dispatch, carbon copy, and MPSC delivery paths
- `forceCloseSession` for intentional/protocol-error closes (no detach on stream close,
  XML parse errors, depth exceeded)

### RFC 6121 Interop (SINT Compliance)

- **360/367 tests pass** (both workers=1 and workers=4)
- 1 failure: upstream Smack test bug (filed as SINT #166)
- Extension element forwarding in subscription stanzas
- Idempotent subscription handlers (skip no-op roster modifications)
- Presence with status after subscription approval
- Full roster group storage, retrieval, and push
- Roster delete with unsubscribe/unsubscribed cascade
- Subscription dispatch normalizes to bare JID (RFC 6121 §3.1)
- Roster push preserves display names across subscription operations

### Metrics

| Metric | Value |
|--------|-------|
| Unit tests | 744 (was 738) |
| SINT interop | 360/367 RFC 6121 |

## v0.5.0 — 2026-06-11

Functional XMPP server with real client interop. Multi-process architecture,
thread-per-core scaling, and zero external runtime dependencies beyond OpenSSL
and the chosen storage backend.

**Not production-ready.** See Phorge XMPP project milestones for roadmap to v1.0.0.
Missing: SM session resume, Entity Capabilities, persistent MUC restart, PEP
contact notifications, HTTP File Upload, documentation.

### Architecture

- **Multi-process:** `xmppd` (master supervisor), `xmppd-core` (C2S workers),
  `xmppd-auth` (local SCRAM/PLAIN), `xmppd-auth-oidc` (OIDC delegation),
  `xmppd-s2s` (federation), `xmppctl` (admin CLI)
- **Thread-per-core:** SO_REUSEPORT_LB load balancing, per-worker kqueue event
  loops, MPSC cross-thread delivery with pipe wakeup, shared SessionMap
- **Configurable workers:** `workers = 1|4|auto` in xmppd.conf
- **Privilege separation:** master binds ports as root, children drop to
  configured user via setuid/setgid
- **Self-daemonizing:** `--background`/`-b` flag, PID file locking, orphan cleanup

### Core Protocol (RFC 6120/6121)

- Streaming XML parser (XMPP subset, namespace-aware)
- STARTTLS with OpenSSL
- SASL: SCRAM-SHA-256, PLAIN, OAUTHBEARER, EXTERNAL
- Resource binding, session establishment
- Message routing between local users
- Presence engine with subscription state machine
- Roster management (get/set/remove, subscription lifecycle)
- IQ dispatch framework

### Storage

- Comptime generic `StorageBackend` trait with `assertBackend()`
- **LMDB** backend — operational data (users, roster, vcard, rooms, offline)
- **RocksDB** backend — message archive (MAM)
- **SQLite** backend — lightweight alternative
- **Memory** backend — test double
- Build flag `-Dop-storage=lmdb|rocksdb|sqlite`
- Auto-resize on LMDB MDB_MAP_FULL (3 retries, double map size)

### XEPs Supported

| XEP | Name |
|-----|------|
| RFC 6120 | XMPP Core |
| RFC 6121 | XMPP IM |
| XEP-0030 | Service Discovery |
| XEP-0045 | Multi-User Chat |
| XEP-0054 | vcard-temp |
| XEP-0077 | In-Band Registration |
| XEP-0084 | User Avatar (PEP) |
| XEP-0085 | Chat State Notifications |
| XEP-0092 | Software Version |
| XEP-0160 | Offline Message Storage |
| XEP-0163 | Personal Eventing Protocol |
| XEP-0191 | Blocking Command |
| XEP-0198 | Stream Management |
| XEP-0199 | XMPP Ping |
| XEP-0220 | Server Dialback |
| XEP-0280 | Message Carbons |
| XEP-0313 | Message Archive Management |
| XEP-0359 | Unique Message and Stanza IDs |
| XEP-0440 | SASL Channel-Binding Type Capability |

### Multi-User Chat (XEP-0045)

- Room creation (instant, transient by default)
- Join with nick conflict/capacity/members-only checks
- Groupchat message fan-out with worker-level multicast (O(workers) not O(occupants))
- Moderated room voice check, admin kick, grant/revoke voice
- Transient room auto-destroy on last occupant leave
- Room discovery via disco#info/items
- Room history on join (last N messages)
- JID-based occupant lookup (globally unique, no session ID collisions)

### S2S Federation

- DANE-EE verification (outbound + inbound)
- SASL EXTERNAL authentication (both directions)
- XEP-0220 dialback (outbound key generation, inbound callback verification)
- Connection pool (domain → outbound connection)
- Inbound stanza forwarding via IPC
- Offline delivery across federation
- Interop tested against Prosody 13.0.6

### Authentication

- Local auth: SCRAM-SHA-256 + PLAIN via `xmppd-auth`
- OIDC auth: OAUTHBEARER + PLAIN-to-IdP via `xmppd-auth-oidc`
  - JWT validation (RS256 + EdDSA/Ed25519)
  - Token introspection fallback (RFC 7662)
  - JWKS key cache with 1-hour TTL
- Per-IP + per-account rate limiting
- Account lockout (temporary + permanent via LockStore)
- In-band registration with invitation codes
- Password change and account deletion
- SASL channel binding (tls-server-end-point + tls-exporter)

### Admin CLI (xmppctl)

- `adduser`, `deluser`, `passwd`, `listusers`
- `lock`, `unlock`
- `invite create`, `invite list`, `invite revoke`
- IPC-based (connects to auth daemon, falls back to direct DB)
- `--password`/`--password-file` for non-interactive use

### Deployment

- FreeBSD RC script (`etc/rc.d/xmppd`)
- INI configuration file with sections (server, tls, core, auth, muc, master)
- CLI flags override config file values
- `--no-tls` mode for development/benchmarking
- Sensible defaults (works without config in dev mode)

### Benchmarks (Tsung, 50 users, FreeBSD, no-TLS)

| Scenario | Workers | Users | Messages | Msg Latency |
|----------|---------|-------|----------|-------------|
| 1:1 Chat | 1 | 50 | 495 | 0.33ms |
| 1:1 Chat | 4 | 50 | 500 | 0.35ms |
| 1:1 Chat | 16 | 50 | 500 | 0.36ms |
| MUC | 1 | 48 | 240 | 0.35ms |
| MUC | 4 | 49 | 245 | 0.31ms |
| MUC | 16 | 47 | 223 | 0.30ms |
| Combo | 4 | 50 | 413 | 0.37ms |

### Client Compatibility

Tested and verified with:
- **slixmpp** — 23/23 automated tests
- **Profanity** — 14/14 tests (FreeBSD terminal client)
- **Gajim** — full session (Windows/Linux desktop)
- **Dino** — full session (FreeBSD/Linux desktop)
- **Conversations** — SCRAM-SHA-256, multi-resource, MUC (Android)

### Metrics

| Metric | Value |
|--------|-------|
| Language | Zig 0.15.2 |
| Source files | ~60 |
| Lines of code | ~30,000 |
| Unit tests | 97 build steps, 690 tests |
| Integration tests | 19 slixmpp E2E + 64 cross-thread |
| Binaries | 6 |
| Platform | FreeBSD (kqueue) |
| License | BSD-2-Clause |
