# Changelog

## v0.9.1 - unreleased

### Security

- T-FB6FD8B2 OIDC account binding: local XMPP accounts now bind
  permanently to the `(iss, sub)` pair instead of mutable claims
  (preferred_username/email/username). Previously an IdP user who could
  rename a claim could log in as another account's localpart and inherit
  its roster, MAM archive and MUC affiliations. First logins now claim a
  localpart through a two-way mapping in `{db}/auth` (namespace
  `oidc_identities`): an existing mapping always wins, a suggestion
  collision, a provisioned `users` row, or any existing account data
  refuses the claim and points the operator at `xmppctl oidc-link`.
- T-52633E2B: registration (XEP-0077 IBR and `xmppctl add`) now refuses a
  localpart bound to an OIDC `(iss, sub)` in the `oidc_identities`
  reverse index. A local users row under a bound name would have handed
  a password credential into the bound account.
  The introspection path applies the same rules (sub required).
  `localpart_claim = email` is gated on `email_verified` and documented
  as the weakest choice. See doc/UPGRADING.md for the required
  `oidc-unclaimed` / `oidc-link` migration steps.
- Q7 hardening follow-up (PR #27, T-8DE2C892): PBKDF2 outputs and the
  buffers that carry them are zeroed before release, and the KDF test
  vectors were made independent of the implementation under test.

### Upgrade notes

- **Passwords with conjoining jamo or a composable vowel-sign pair prepare
  differently than in v0.9.0.** The shared Unicode NFC engine gained
  algorithmic Hangul composition and starter-second pair composition
  (canonically equivalent passwords used to prepare to different strings).
  The same engine prepares SASL credentials (RFC 8265 OpaqueString: SCRAM
  derivation at registration and `xmppctl`, PLAIN verification, xmppc
  client preparation). Affected inputs: any password containing conjoining
  jamo (U+1100..U+11FF) that now composes - e.g. L+V jamo now form a
  precomposed syllable, and a precomposed syllable followed by a trailing
  jamo now forms an LVT syllable - or a two-part vowel-sign pair that now
  composes (e.g. U+09C7 U+09BE -> U+09CB). For such a password the prepared
  form differs from the v0.9.0 form, so its stored SCRAM credentials
  (derived under the old preparation) stop matching: PLAIN login fails and
  server-derived SCRAM material no longer lines up. Remedy: reset the
  password after upgrading. Precomposed Hangul syllables on their own, and
  every other input, prepare exactly as in v0.9.0 (c1fe1e2).

- **Account names are now RFC 7622 localparts.** Registration, login,
  locks, rate limiting, `xmppctl`, and the bound JID all use one PRECIS
  UsernameCaseMapped function plus the eight localpart exclusions of RFC
  7622 section 3.3.1 (`"`, `&`, `'`, `/`, `:`, `<`, `>`, `@`). Printable
  ASCII such as `a!` remains valid. A client that logs in as `NaplesTB`
  is bound as `naplestb@domain/resource`; use the JID returned by the
  server. Existing account-bearing keys must be migrated before starting
  xmppd-auth, including the archive database:
  1. Stop every xmppd daemon. `migrate-precis` refuses to run while any
     daemon pid file is live and holds an exclusive LMDB lock for the whole
     run. A daemon started during the run blocks in env open, then exits
     with LMDB EINVAL once xmppctl finishes; restart it after the tool
     exits.
  2. Dry-run `xmppctl migrate-precis --hosted-domain example.org`
     (repeat `--hosted-domain` for each hosted domain). It prints every
     planned rename and every collision or invalid localpart without
     changing anything.
  3. Resolve each reported identity. A collision exists between distinct
     accounts: two users rows that fold together, or account-owned data
     (roster, blocklist, vCard, PEP, lastact) that folds onto another
     account. Data-only spellings (offline, archive and pending-sub rows
     written by third parties) merge into the account they fold to, and two
     data-only spellings with no users row merge with each other. Duplicate
     reference rows are deduplicated: the prepared-key row wins and the
     duplicate is printed as `deduplicated`. Offline pointers and archive
     messages whose sender-chosen id collides with different content get one
     shared reserved `~mig-...` id across the pointer, message key and
     by_contact value; they are printed as `rekeyed`. Held payloads and the
     merged offline queue follow the pointer's final sequence. `--apply`
     refuses and lists
     every remaining collision. **Prefer `--rename`** with `xmppctl
     migrate-precis --hosted-domain example.org --rename OLD NEW --apply`:
     it moves the account and every reference while preserving locks. If
     deletion is required, use `xmppctl deluser --raw EXACT-KEY
     --hosted-domain example.org` offline. If EXACT-KEY is a users row, it
     deletes rows that spelling owns plus reference rows naming exactly that
     raw spelling; it never removes another account's prepared lock. If
     EXACT-KEY is a data-only spelling with no users row, it deletes only
     rows keyed by that exact spelling and leaves every reference, lock and
     account intact. It fails if data remains and prints what was removed.
     Never delete only the users row: that would move the deleted person's
     data into the surviving account. Any collision makes `--apply` change
     nothing.
  4. Apply with `xmppctl migrate-precis --hosted-domain example.org
     --apply`, then rerun the dry run; it must report 0 renames. The plan,
     a digest and `migrate-precis.pending` are written before the first
     commit; completion markers are committed with the data they describe.
     If the run is interrupted, rerun `xmppctl migrate-precis
     --hosted-domain example.org --apply`: it loads the stored plan and
     finishes only the unfinished batches. If the interrupted run used
     `--rename`, omit it on the resume. While the marker exists,
     `--rename`, `deluser --raw`, adduser, deluser, passwd, lock, unlock and
     invite are refused, and xmppd-auth/xmppd-core refuse to start. Do not
     delete the marker or resume file manually; a torn marker reports that
     no data was committed and names the safe recovery.
  5. Start the daemons. xmppd-auth scans the users namespace once at
     startup and **refuses to start** if any key is not in prepared form,
     logging one error that names `xmppctl migrate-precis`. There is no
     raw-name read fallback.

- **Ingress preparation landed with F6 (PR #46).** Stanzas and payload
  JIDs that name the hosted domain are prepared at ingress: the domain is
  rewritten to the configured spelling (matched case-insensitively, one
  trailing dot ignored per RFC 7622 section 3.2) and the localpart gets
  the same UsernameCaseMapped preparation the account store applies, so
  `NaplesTB@EXAMPLE.ORG` resolves to `naplestb@example.org` in routing,
  roster, offline and archive. Remote-domain JIDs pass through unchanged,
  as does the MUC domain. Rows written under an old spelling before the
  upgrade still need one `xmppctl migrate-precis` run; nothing written
  afterwards does.

- **The MAM `by_contact` index gained a v2 key.** The v1 layout
  `owner\0with\0timestamp_be(8)` put two messages indexed in the same
  second on one key, so the second store overwrote the first's index row
  and the message vanished from `with`-filtered queries. The v2 key
  appends the stanza id. Surviving v1 rows still answer queries, so reads
  keep working, but the rows the v1 overwrite already destroyed only come
  back through the offline migration: stop every xmppd daemon, run
  `xmppctl migrate-archive --hosted-domain example.org` to see the plan,
  then `--apply`. The plan is journaled before the first commit and every
  op is idempotent, so an interrupted run resumes with a repeated
  `--apply` (PR #59).

- **The master validates its configuration file strictly.** An unknown
  section or key, a bad value or a malformed line is a startup error
  printed with `file:line` and the master exits non-zero; v0.9.0 ignored
  or silently defaulted these. Pre-flight check before restarting:
  `xmppd -c <conf> --help` exits 0 and prints the generated option list
  when the file parses, or the same `file:line` diagnostic with a
  non-zero exit when it does not. Two file keys also changed meaning:
  `[s2s] enabled = false` now suppresses the s2s child (v0.9.0 read only
  `--no-s2s`; the file key was ignored), and `[core] workers` accepts a
  number or `auto`; any other value is a startup error (v0.9.0 treated
  it as `auto`). See doc/UPGRADING.md.

- **core, s2s and xmppctl share the strict configuration loader.** The
  master serializes the resolved configuration once into a sealed fd
  that `xmppd-core` and `xmppd-s2s` inherit as `--conf-fd`, so a file
  key or a master CLI override reaches them exactly once; their argv now
  carries only the listen-fd remap slots and the conf fd itself, and on
  SIGHUP the fd is rebuilt before the signal is forwarded. Three fixes
  ride along: core honors `[tls] cert`/`key` from the file (previously
  ignored), `xmppd-s2s --config` is honored (previously consumed and
  ignored), and unknown arguments to core, s2s or xmppctl are startup
  errors instead of silent warnings or a mistaken command. `xmppctl`
  gained `-c`/`--config` and `--help`, and its storage default follows
  the shared `[server] db_path` default `/var/db/xmppd`. See
  doc/UPGRADING.md.

- **Both auth daemons share the strict configuration loader.** The master
  forwards the same sealed `--conf-fd` to `xmppd-auth` and
  `xmppd-auth-oidc` and no longer places resolved values on their argv.
  Precedence is default < file < forwarded < CLI, the old
  `[oidc] rate_max_*` spellings remain aliases, and both `--help` outputs
  are generated from the schema. Bad auth values are now startup errors
  with `file:line` diagnostics instead of silent defaults or clamps. An
  unset `[oidc] socket` inherits `[auth] socket`. See doc/UPGRADING.md.

### Features

- F6 local-domain ingress preparation (PR #46): stanza `to`/`from` and
  the payload JIDs that name the hosted domain are prepared at ingress on
  both c2s and s2s (iq_handler, muc_handler, presence, router, session).
  See the Upgrade notes entry for the migration impact.
- X3 event-driven master (PR #72, T282): the supervisor loop runs on the
  lib/net Loop; child startup is gated on readiness pipes instead of
  sleeps; shutdown and orphan cleanup are deadline-driven with SIGHUP
  fan-out; the master binds the c2s and s2s listeners itself through the
  shared bindTcp (honoring `[server] bind_address` and IPv6) and passes
  them to the children as `--listen-fd`. A gated startup ends cleanly on
  TERM without spawning.
- M1 per-worker counters and SIGUSR1 dump (PR #64): xmppd-core keeps
  per-worker session/stanza/drop counters and writes a dump on SIGUSR1
  for live diagnosis; unbound conns are only ever read by that dump.
- S35 XEP-0203 delay stamps on offline delivery (PR #48, forge #25):
  offline messages delivered at login now carry a `<delay>` stamp so
  clients can show the real send time.
- s2s outbound retry (PR #71, T416/T417): a temporary connect or DNS
  failure retries the domain on a 5 s / 15 s / 45 s backoff and the
  outbound queue survives across retries; non-fatal dialback error
  verdicts no longer tear the stream down.
- ADR-13 shared async DNS resolver and cache v2 with serve-stale
  (PRs #15, #32, #33, #52): lib/dns resolves SRV chains off the event
  loop, caches positive and negative answers and serves stale entries
  (RFC 8767) while a refresh is in flight; s2s resolves through it.
- xmppc: consumer one-shot timers on the engine loop (PR #5,
  T-A9AE7D9C) and `SessionConfig.allow_plain` for PLAIN-only auth
  backends such as OIDC rigs (d3c08d7).
- Q1 root allocator selection (PR #68): `-Dallocator=debug|c|smp` picks
  the root allocator for all daemons (debug in Debug builds, c in
  release builds).
- kTLS observability (Q11): the c2s handshake logs kTLS TX/RX engagement
  and the negotiated cipher, so a silent fallback to userland TLS shows
  up in the log.

### Changed

- F5 typed configuration (PR #17, ADR-9): the INI file is parsed once
  into typed values through lib/conf, and doc/CONFIGURATION.md is
  generated from src/config/schema.zig. New keys: `[s2s] bind_address`,
  `[auth] ip_lockout_threshold`, `[auth] users_scan_limit`,
  `[server] lmdb_map_size_mb`, and the OIDC `localpart_*`/`idp_*`
  family (see UPGRADING.md and CONFIGURATION.md).
- X4 completed the lib/conf migration (PRs #87, #92, #96): one
  `Sections` struct and `file_spec` table in src/config/schema.zig
  describe every file key; the master, xmppd-core, xmppd-s2s, both auth
  daemons and xmppctl all load it through lib/conf, and the master
  forwards the resolved values once through a sealed `--conf-fd`
  instead of argv flags. See the strict-loader Upgrade notes above.
- A3 auth policy module and rate limiter v2 (PR #21, T-0D7A44BE, T281):
  per-IP failures now lock out the address after
  `[auth] ip_lockout_threshold` consecutive failures (default 20), on
  top of the existing per-account lockout.
- OIDC IdP exchanges moved off the event loop (PR #34, T-8E43C580):
  token, JWKS and introspection calls run on a worker pool
  (`[oidc] idp_threads`, `idp_max_outstanding`, `idp_connect_timeout_ms`,
  `idp_timeout_ms`) instead of stalling the auth daemon.
- Master hardening: running the supervisor as root without a configured
  `[server] user` is refused (run-user aliases that resolve to uid/gid 0
  are refused by id, not by name), and the respawn path does no NSS or
  pid-file I/O on the supervisor loop (PR #85, T431; PR #8, C5/F3/B8).
- s2s verification moved to the shared DANE module (S29, PR #56): xmppc
  and s2s both verify through lib/dane instead of local copies.
- Message carbons apply the XEP-0280 policy on the cross-worker delivery
  path (PR #53, T-D689B13D).
- S34 part 2 (PR #45, forge #23): the non-standard `db:features` stream
  feature is no longer advertised on dialback streams.
- A9 crypto pool (PR #39): bounded job rings, zeroed inline credential
  buffers and coalesced wakes on the PBKDF2 pool.
- Q2 (PR #68): cross-thread queue wakeups coalesce, so a burst of
  completions costs one wake instead of one per item.

### Fixed

- S33 disco/caps: removed the `http://jabber.org/protocol/pubsub#subscribe`
  claim from `caps.SERVER_FEATURES` (forge #22). No XEP-0060 `<subscribe/>`
  or `<unsubscribe/>` handler exists, so the advertisement was false. The
  remaining pubsub claims are backed: `publish` and `retrieve-items` have
  iq dispatch branches, `auto-create` and `persistent-items` are covered by
  the PEP store upsert on publish, and `auto-subscribe` is the XEP-0163
  roster-derived notify model. A caps.zig consistency test now requires
  every advertised `pubsub#*` feature to name its dispatch branch. The
  XEP-0115 `ver` hash changes as a result of the removed feature.
- DANE TLSA selector-1 never matched: `extractSpki` did not descend into
  the certificate's outer SEQUENCE, so SPKI hashes silently fell back to
  full-cert hashes and externally computed selector-1 records failed
  verification (c04b243).
- Storage: account and roster JIDs are no longer clipped at 256 bytes
  (PR #51, T-A6201BB0); iterators keep full prefixes up to the 511-byte
  key cap (PR #47, T-5A36FA65) and every backend's prefix-scan edge cases
  are pinned (PR #50); a failed batch commit now ends the batch on every
  backend, and a write batch reports a BEGIN that could not start
  (PR #8, C4/F4); a second SQLite connection provably surfaces a busy
  BEGIN; a failed LMDB open closes the env it created.
- MAM archive (PR #59): the `by_contact` v2 index (see Upgrade notes),
  plus offline-migration coverage for interrupted runs and restarts.
- MUC nick takeover: a same-nick resource takeover now repairs the
  jid_map and tells the replaced resource it left, so index updates
  cannot leave a ghost occupant (T413, S30; e2e-muc-nick-takeover wired
  into the multiworker CI lane).
- XEP-0198: every outbound stanza is counted for `h` accounting, an ack
  with a backwards `h` no longer wipes the replay queue, and the SM-ID
  map survives more than 64 detached sessions and removals (S15/S24/S17,
  PR #9).
- Offline queue (PR #9): delivery works without an archive present (G2);
  hold dedup keys on a minted dispatch token so one held copy serves
  every resource of a bare JID; a drain stops when a delivered pointer
  cannot be deleted, arms a retry when its count fails, and clears the
  pending flag only after re-counting the tail; a stuck delete is redone
  without resending the stanza.
- Cross-worker delivery (PR #9): a failed remote delivery no longer
  reports success (S14), and room-mailbox overflow bounces to the sender
  instead of silently dropping (S16).
- Core loop and routing (PRs #8, #9): a full write buffer flushes before
  the peer is torn down; a stanza that cannot be accumulated closes the
  stream (H6); route buffers size to the resource cap instead of 16
  (S18); a rolled-back `bare_map` append no longer strands registration
  (T254); STARTTLS upgrades only after `<proceed/>` has fully flushed
  (T215); `purgeFd` compacts in place so a staged EV_DELETE/EV_ADD pair
  cannot invert across fds (S20).
- XML layer (PR #9): element and attribute names validate against the
  XML Name production (S21), numeric character references parse as u21
  and UTF-8 encode, a nested `stream:stream` inside an open stream is
  rejected (S27), a namespace-stack overflow is a hard error sized to
  max depth (S12), and the per-stanza reader-arena reset is restored
  with cross-stanza borrowers copied (S11). Stored values that carry
  markup (MUC room config, PEP payload/item id/avatar) are stored
  decoded and escaped on output (S1).
- TLS: a WANT_WRITE write is retried with the identical slice (S23, the
  kTLS rule), and kTLS engagement is logged after the handshake (Q11).
- Auth daemon (PR #8): `unlock` removes every fold-equal legacy lock row
  including duplicates (D3), the OIDC daemon migrates legacy lock keys
  at start (D4), privilege-drop refusals log at err (D8), a failed SASL
  exchange leaves no stream state behind and a full pending-verify table
  answers the submission invalid (C6), out-of-order SASL, STARTTLS and
  dialback outcomes are rejected (F1), and queued work is answered when
  an outbound connection cannot be initiated (F2).
- s2s dialback: `db:verify` never travels before the post-TLS auth
  phase (C1), an undeliverable `db:verify` is answered and retried (B3),
  a callback connection teardown answers its exchanges invalid (C2),
  and the IPC write filter drops once the backlog drains (S10).
- OIDC (T428, PR #70): a token whose `aud` claim is a JSON array is
  accepted.
- xmppctl (PR #83, T438): `oidc-links` reports every row in the
  namespace, and `oidc-unclaimed` fails when the namespace cannot be
  scanned instead of reporting zero unclaimed accounts.
- migrate-precis review follow-ups (PR #57).
- Store hot paths (PR #65, T-944ED1A2, T-E32A817D): hot info logs moved
  off the read path, every remaining silent stanza drop is counted and
  logged, and an oversize write-buffer refusal keeps the session.
- Archive writer (PR #14, S31/Q8): a rejected store no longer breaks
  later archive writes, the lost-wakeup window on the writer queue is
  closed, and drop/failure logging is rate-limited.
- LMDB operator experience (PRs #36, #37, #40, #43): maps are excluded
  from core dumps, the vmmap lookup retries on ENOMEM, and map
  exhaustion is pinned and warned distinctly.
- lib/http: response-head grammar follow-ups and the LOW/NIT items from
  the re-review (PRs #42, #55).
- xmppc: MAM result wrappers unwrap into archived stanzas (PR #6).
- Crypto-pool failed start, SCRAM documentation and LMDB bounds
  follow-ups (PR #54, T-13A2BD7A).
- Supervisor lane (T-62A50554): the drop-probe wait is EINTR-safe and
  status-checked, the capture drain is proven to reach EOF past cap plus
  pipe buffer, and the capture read end closes before waitpid.

### Internal

- lib/net (F2/F3, ADR-8; PRs #31, #41): shared connection and frame
  primitives; the auth IPC, s2s and xmppc now run on FrameReader /
  FrameWriter with a comptime codec (A2, PR #70).
- F4 StanzaWriter (PRs #16, #29): serializer with a SIMD escaper in
  lib/xml/writer.zig.
- A6 (PRs #86, #89): the auth handler is split into mech, account and
  policy modules with explicit capabilities, and one runner now drives
  both xmppd-auth and xmppd-auth-oidc.
- C2 core Outbox (ADR-2, PR #81): outbound stanzas queue per session and
  flush at the end of the event-loop iteration.
- C7 (PR #73): move-only split of server.zig and Session into the
  ADR-12 layout; no behavior change.
- X2b (PR #52): s2s DNS moved onto lib/dns async.

### Testing

- Deflake sweeps: lib/net deadline, accept-queue and handshake-driver
  tests (PRs #58, #60), s2s SO_ERROR last-target tests (PR #76, T432),
  OIDC reply waits made load-independent (PR #78, T433), unix-socket
  test paths made independent of checkout depth (PR #82, T436), stale
  ICMP refusals drained and chain deadlines pinned in lib/dns
  (PR #66), s2s callback teardown moved to event drive with
  fabricated-target listener fixtures (PR #67), and the forked
  event-loop child exits via `_exit`.
- M2 load-driver scenarios (PR #63), M3 microbenchmark suite (PR #61),
  and M4 CI quality ratchets (PR #62): counting-allocator check,
  stack-frame audit and catch ratchet wired into the quality job.
- CI: the multiworker-e2e and quality jobs are green on master again
  (PRs #79, #80).

### Documentation

- doc/ARCHITECTURE.md rewritten for the ADR-12 layout (Outbox, envelope
  ring, shared auth runner, lib/conf, lib/net), doc/STORAGE_DESIGN.md
  corrected against the code, and doc/CONFIGURATION.md generated from
  src/config/schema.zig by `zig build docs-config` with a staleness
  check (R8).
- DOAP project description (XEP-0453) with a compliance-table sync
  (PR #18), and the remaining XEP-0440 mentions plus the roadmap
  phase-history table aligned (PR #28).
- The primary repo URL moved to github.com/xmppd/xmppd (PR #77) and
  Codeberg references were dropped (PR #74).
- The v0.9.1 plan, its findings and the ADR records live in
  doc/T197_QUALITY_SWEEP.md.

## v0.9.0 - 2026-10-04

### Features

- T164 XEP-0012 last-activity: the jabber:iq:last handler was a stub that
  answered seconds='0' to everything (README had already been downgraded
  to Partial for this). Server-directed queries now answer real domain
  uptime; other-account queries are server-answered with 0 while online
  and seconds-since-last-teardown while offline (durable record in the
  ops DB written when an account's final resource unbinds - consistent
  across workers with no new actor traffic). Disclosure follows presence
  visibility (target's roster entry for the requester must be from/both,
  else forbidden; nonexistent accounts are indistinguishable). Full-JID
  queries forward to the addressed resource per RFC 6121 §8.5.3 - the
  resource's client answers its own idle time (XEP-0012 §2.1), so no
  server-side idle clock is kept (9d6daff).
- T177 MUC occupant migration: cross-worker XEP-0198 resume now works for
  sessions that occupy MUC rooms (previously refused, forcing a full
  re-bind + rejoin). The handoff bundle carries the detached session's room
  list; after the resuming worker re-binds (generation known), it replays
  one `room_occupant_move` actor message per room's owning worker, which
  updates the canonical occupant record's (worker, session, generation)
  triple in place and syncs shadow copies - a move, not a join/part: no
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
  75%, its EVFILT_READ is disabled - the server stops consuming stanzas it
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
  entry list - multi-resource accounts (agent/bot deployments) no longer
  hit the wall (a3babac).
- lib/xmppc client library: reusable client core in `lib/xmppc` - one
  kqueue engine driving N sessions (generational slot handles, threaded or
  inline loop, thread-safe `startSession`/`postStanza`/`stopSession`),
  async DNS resolution with SRV chain, DANE-first TLS with PKIX fallback,
  SCRAM-SHA-256/-1 client SASL with channel binding (tls-exporter /
  tls-server-end-point), XEP-0198 enable/resume with an engine-owned
  unacked queue and replay, event-funnel consumer API, stable TLS write
  pinning, application-level raw stanza access (PR #3, PR #4, T2xx).
- T32 load driver (`test/xmppc/load.zig`, `zig build xmppc-load`): paced
  multi-thousand-session ramps against a live rig with engine stats,
  per-phase establishment histograms, true-loss hold accounting, and
  multi-engine sharding (`-engines E`).
- SASL expansion: SCRAM-SHA-1 client + SCRAM-PLUS channel binding
  (9435631), OpaqueString profile + SCRAM `n=`/`r=` escaping (42e1ba6),
  RFC 5802 conformance vector + live interop evidence (297c6a3).

### Fixes

- T196: auth rate-limit defaults relaxed (user decision 2026-09-30):
  max_per_account 5 → 60, max_per_ip 20 → 200 per 120s window; the
  consecutive-failure lockout (10 → 300s) is unchanged and remains the
  brute-force control. The per-key ring grew 32 → 256 so the new per-IP
  ceiling is actually observable (a policy above the ring was inert), and
  the limiter tables are heap-allocated (~8 MB pair, no longer on any
  stack). Config/CLI precedence sentinels (auth + oidc daemons) now
  compare against the struct defaults instead of copy-pasted literals
  that would have rotted again. Guard test proves both default caps
  engage. (e19f17a)

- T112: MUC MAM queries routed to a room's owning worker were degraded at
  the actor-message boundary: the response IQ id was the client's MAM
  queryid (XEP-0313 allows queryid != stanza id, breaking IQ matching),
  RSM <max/> was replaced by a hardcoded 50, <after/>/<before/> paging was
  dropped, and the no-archive answer diverged from the local path. The
  room_mam_query actor message now carries iq_id + full RSM text; local
  and remote answers are identical (e2e-muc-mam-routing 82/82 at
  workers=4, wired into the CI multiworker lane) (c1f53e9).
- T198: a bind whose session-map registration failed (e.g. over the
  resource cap) previously sent the success IQ first and only logged -
  the client believed itself bound while inbound stanzas were silently
  unroutable. Registration now precedes the result; over-cap binds get a
  stanza error (resource-constraint) and may retry with another resource
  (a3babac). Also rolled back partial full_map/bare_map registration on
  mid-bind failures (latent inconsistency).
- T152/T154: evicted sessions got their <conflict/> stream error queued
  but never flushed before the teardown closed the fd - the client closed
  with no explanation. Now flushed synchronously before teardown
  (307a717).
- SM resume restored the session resource from the transient bind
  accumulator, which is zeroed after a successful bind - resumed sessions
  ended up with an EMPTY resource (`user@host/`). The resource now comes
  from the detached session's bound JID - MUC fan-in and fan-out stay
  correct after resume (T177 work, 02893d9).
- Auth rate limiting vs SCRAM concurrency under load: the slot table's
  home-slot probing now scales to 8192 entries with lazy stale reclaim
  (54c5ccb/a293b02), a connection that dies mid-exchange is dropped
  daemon-side via the auth_abort IPC message (3104120), and both growable
  IPC backlogs no longer lie not-authorized under SASL bursts
  (05a455c/6cf6b6c - overflow answers temporary-auth-failure).
- Core loop churn (w4/N=5000 class): closers purge their staged kqueue
  entries instead of staging EV_DELETEs of soon-closed fds (same-iteration
  fd reuse would disarm a fresh connection) and kevent per-entry batch
  failure is surfaced as EV_ERROR receipts handled without a full replay
  (899fe48, also fixes the accept-side session-id pool leak that froze
  busy workers for minutes); kevent batch hardening + real listen backlog
  (18e24ce).
- Auth-IPC resilience: a dead xmppd-auth no longer leaves workers
  unable to authenticate until restart - each worker fails in-flight SASL
  with retryable temporary-auth-failure and re-links on a 1 s reconnect
  timer (228827d).
- xmppc client library fixes: PBKDF2 salt truncation past 252 bytes
  (c1baf03), staged-changelist tail livelock at 32 sessions (f2a8ae9),
  drain-phase stopSession hang (1ada2af), wake-pipe blocking-write
  deadlock at ~8192 pending sessions and the coalescing-flag teardown
  livelock (7349477/d3286a3), thread-safe engine splicing with chunked
  session storage (d3286a3).
- c2s: kept bind IQ id across the cross-worker kick (T220, cbff998); s2s:
  remote_domain copied off the reader arena across stream restarts
  (T221, 2efbad2); lib/xml: namespace prefix bindings scoped to their
  element (T232, 6190d36).

### Testing

- New `e2e-muc-resume.py`: alice joins a room with SM resume enabled and
  loops abrupt-disconnect + resume; asserts the resumed session keeps
  receiving and sending groupchat without rejoining, detached-era stanzas
  replay, and other occupants never see a rebroadcast join presence.
  Cross-worker handoff is verified via server-log evidence.
- New `e2e-resource-takeover.py`: repeated same-resource bind takeovers,
  cross-worker kick evidence via server log.
- T32 load driver matrix (T242 v2 method: ECDSA rig cert, paced engine-first
  ramp, one build, 3 runs/cell, median): 10,000 sessions establish at
  ~480 logins/s on both workers=1 and workers=4 rigs; hold loss zero, dupes
  zero, median delivery 1.0–1.4 ms. SINT (Smack 4.5.0-beta9 extensions):
  461/554 pass (8 failed, 85 skipped by feature detection); filed T245
  (low-level modular stress loss), T246 (XEP-0410 self-ping), T247
  (PEP disco identity), T248 (pre-bind policy vs Smack modular).

## v0.8.11 - 2026-09-30

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

## v0.8.10 - 2026-08-31

Bugfix release: cross-worker delivery, a v0.8.9 regression, and four
stanza error-handling correctness fixes found by the first full-spec
SINT runs (T175 follow-ups).

### Fixes

- T173 (High): MUC admin IQ results (kick/ban/voice) were dropped when
  the room shard lived on a different worker than the requester - the
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
  (4c54410) - XEP-0198 only obliges clients to ack on request, so without
  this the overflow policy would kill compliant clients that never ack
  unsolicited (SINT-proven with Smack: busy SM sessions died after ~256
  unacked stanzas in ~20s of presence flood)
- T180: XEP-0054 §3.3 (v1.3.0) - vCard GET for another user now returns
  `service-unavailable` for both no-vCard and no-such-user
  (anti-harvesting; the two cases must be indistinguishable). The
  own-vCard path keeps its empty-vCard/Gravatar behavior (cc70366)
- T181: RFC 6121 §8.5.2.2.1 - groupchat to a bare JID with no available
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
  MPSC delivery with generation validation) is exercised - at workers=1
  every route is local, which is how T173 shipped

Verified on freebsd-dev1 (Zig 0.15.2): `zig build test` all steps;
e2e-sm-resume 29/29; e2e-chat all pass; muc-test 12/12; e2e-quick-wins
12/12; e2e-mam 7/7; e2e-subscription 29/29; e2e-register-invite 6/6;
multi-worker lane (workers=4) green; SINT XEP-0198 10/10.

## v0.8.9 - 2026-08-30

Bugfix/doc-consistency release (T163–T170 audit batch + T160/T161/T151).

### Fixes

- T163 (High): XEP-0115 caps `ver` omitted `jabber:iq:register` which
  disco#info advertised - the hash could never verify (clients doing §5
  verification discarded the caps). disco#info now iterates
  `caps.SERVER_FEATURES` via `caps.writeDiscoFeatures`, one list by
  construction
- T165: invite-gated IBR (XEP-0077, the secure default) could never succeed -
  the invite code in the `jabber:x:data` form was never parsed. The
  invite/token field is now passed through to the auth daemon, and the
  registration form advertises an optional `invite` field
- T166: directed presence to remote domains was silently dropped; it now
  routes through the S2S outbound path like subscription/broadcast presence
- T167: listener bind address parsing - any IPv4 dotted-quad and IPv6 literals
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
  STARTTLS port - client is configured for direct TLS" and closes, instead of
  a misleading `error.InvalidEntityReference` XML parse failure

### Docs / CI

- T170: CI feature-matrix consistency check (`.forgejo/workflows/consistency.yml`,
  `test/consistency/`, base-system sh+awk on the FreeBSD runner) - guards
  caps/disco#info/README drift; adapted to the single-source disco features
- T169/T164: README XEP matrix corrections - RFC 6121 footnote 1 stale clauses
  removed (roster push and roster set validation are implemented; remaining
  gap is roster versioning §2.6), XEP-0012 downgraded to Partial (online-self
  stub; full implementation deferred to v0.9.0)
- T151 evaluated and closed: keep the eager `flushSend()` in `handleReadable`
  (fewer syscalls in the common request/response case; verdict on the task)
- New `test/integration/e2e-register-invite.py` (raw-socket suite, 6/6)

Verified on freebsd-dev1 (Zig 0.15.2): `zig build test` all steps;
e2e-sm-resume 29/29; e2e-chat all pass; muc-test 12/12; e2e-quick-wins 12/12;
e2e-mam 7/7; e2e-subscription 29/29; e2e-register-invite 6/6.

## v0.8.8 - 2026-08-30

Bugfix/hardening release on top of v0.8.7 (8 commits). Tagged from `95e9c5c`;
deployed to the freebsd-dev1 test jail (10.10.219.38).

### Fixes

- Concurrent TLS handshake failure (SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED)
- T158: SM resume dangling JID; advertise XEP-0077 IBR in stream features and
  disco#info (when registration enabled)
- T156: `MAX_IPC_CLIENTS` 16 → 80; reject pre-auth SM enable with `<failed/>`
- T155: `Connection.close()` resets `fd` to −1 and `queueSend()` rejects closed
  connections with `error.ConnectionClosed` - turns the stale-fd hazard class
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
- New `doc/TESTING.md` - throwaway-instance e2e procedure
- README/ROADMAP corrections; ROADMAP gained a forward-looking "Next Up"

Verified on freebsd-dev1 (Zig 0.15.2): `zig build test` 105/105 steps;
e2e-sm-resume 29/29; e2e-chat all pass; muc-test 12/12; e2e-quick-wins 12/12;
e2e-mam 7/7; e2e-subscription 29/29.

## v0.8.7 - 2026-07-01

- T152: stale-bind eviction - reconnecting with the same resource before the
  old session was cleaned up got `AlreadyBound` and was left unregistered in
  SessionMap; fixed with RFC 6120 §7.7.3-style eviction (`<conflict/>` + retry)
- T153: detached-session delivery corruption - stanzas routed to a detached
  (SM resume pending) session were written to its dead connection; guarded at
  the router and MPSC unicast delivery sites
- New `e2e-sm-resume.py` regression suite (29 assertions)

## v0.8.6 - 2026-07-01

- SM resume silently dropped at features_bind: the pre-bind IQ catch-all in
  `handleElementStart` consumed `<resume/>`; clients timed out waiting for a
  reply
- Stream ID reuse fix (RFC 6120)

## v0.8.5 - 2026-06-19

- XEP-0115 Entity Capabilities: server caps hash (SHA-1 over disco features),
  pre-built `<c>` element for presence injection, node-based disco#info
  response for caps verification (§5.3), disco query mechanism
- OIDC profile photo import

## v0.6.0 - 2026-06-14

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

## v0.5.0 - 2026-06-11

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
- **LMDB** backend - operational data (users, roster, vcard, rooms, offline)
- **RocksDB** backend - message archive (MAM)
- **SQLite** backend - lightweight alternative
- **Memory** backend - test double
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
- **slixmpp** - 23/23 automated tests
- **Profanity** - 14/14 tests (FreeBSD terminal client)
- **Gajim** - full session (Windows/Linux desktop)
- **Dino** - full session (FreeBSD/Linux desktop)
- **Conversations** - SCRAM-SHA-256, multi-resource, MUC (Android)

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
