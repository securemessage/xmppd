# T197 Quality Sweep — v0.9.1 Plan

Date: 2026-10-04. Tree: v0.9.0 (commit 3f14f21).
Phorge: findings report posted as a T197 comment; one task per finding,
all tagged into the `v0.9.1` milestone (PHID-PROJ-mfsmx2n2yicpsqhyll4k)
and the XMPP project.

## Method

Six read-only module audits (lib/*, src/core split A hot-path/B handlers,
src/auth + src/ipc, src/s2s + src/master), then **every claimed finding was
verified by a direct read of the cited site before admission**. Sweep axes:
hot-path allocation churn; lock map / contention / hold times; event-loop
hygiene (single staged-changelist kevent per iteration, no timers/select/
poll/sleep on loop threads); anti-patterns; readability/layering; Zig
allocator discipline (ownership, errdefer, borrowed-after-free).

## Verified clean (no action)

- **kTLS**: `SSL_OP_ENABLE_KTLS` present in both `SSL_CTX` initializers
  (lib/tls/ssl.zig:139, 199) with accurate PR-296498 comments and a
  `disableKtls()` escape hatch (204-215). Socket-BIO only; no
  `SSL_key_update`; no `SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER`; no
  `max_send_fragment`; RX always via `SSL_read`. The old stale
  "Linux-only flag" comment is gone. Gap: engagement only logged in
  lib/xmppc (see T262).
- **Event loops**: core worker, auth, and xmppc engine each do one
  `kevent()` per iteration with a staged changelist. No `select`/`poll`.
  `Thread.sleep` outside tests exists only in src/master/main.zig
  (4 sites — see T282, T259, T336).
- **Zero TODO/FIXME/HACK/DEFERRED markers** in src/, lib/, test/.
- allocPrint on hot paths: only lib/sasl/scram.zig (9, all arena-backed)
  and lib/xmppc/engine.zig:655 (SCRAM cache key, uncached derivations).
- Locks: short holds, none across I/O; MUC rooms sharded per worker,
  lock-free; MPSC delivery ring lock-free (head non-atomic — T287-adjacent
  note, see T287/T289 cluster notes).

## P1 — fix-now (v0.9.1 batch)

| # | Task | Module:file:line | Finding | Proposed fix |
|---|------|------------------|---------|--------------|
| 1 | T249 | lib/xml scanner.zig:88-121, reader.zig:290-308 | Per-connection arena growth: `Scanner.resetArena()` has zero call sites; `Reader.reset()` runs only at stream restart. Every token/attr is arena-duped and never reclaimed. Unbounded memory growth on long-lived sessions. | Reset both arenas at each stanza boundary; document Event payload lifetimes first (T303). Long-term: borrow tokens from the input buffer. |
| 2 | T250 | s2s/main.zig:1289, connector.zig:399-403, 1601-1602; core server.zig:1088-1089 | T215 class on s2s, both directions: `flushWrite()==false` ignored before `upgradeToTls`; leftover plaintext later emitted through `SSL_write`. Plaintext read-ahead silently discarded on all three upgrade paths instead of a protocol error. | Gate upgrade on full flush (EVFILT_WRITE retry, then upgrade); error-close on non-empty read buffer at upgrade (`<policy-violation>`); tests with tiny SO_SNDBUF. |
| 3 | T251 | lib/xmppc/engine.zig:69-86, 964-982 | `resolveHost` = synchronous `getaddrinfo(AF.INET)` run on the engine thread for every literal-IP connect (redundant after `parseIp`) — and IPv6 literals always fail. | Build sockaddr from the `std.net.Address` parse result; delete `resolveHost`. IPv6-literal smoke test. |
| 4 | T252 | lib/xmppc/engine.zig:511-515 | `Engine.deinit` joins the loop thread without `requestWake` while live sessions exist — indefinite hang. `waitLoopExit` (1060-1066) gets it right. | `requestWake()` before join, or route through `waitLoopExit()`. |
| 5 | T253 | lib/xmppc/transport.zig:124-127, session.zig:712-805, 1187-1196 | TLS write retry may pass a longer length than the pinned SSL_write: `queue()` appends in place while pinned when capacity exists. No `SSL_MODE_ENABLE_PARTIAL_WRITE` is set, so userland OpenSSL dies with bad-write-retry; under kTLS violates the identical pointer+length rule. The unit test asserts the wrong behavior. | Retry exactly `write_buf[write_start .. write_start+tls_pending]` while pinned; new bytes go to overflow unconditionally. Fix the test. |
| 6 | T254 | src/core/session_map.zig:179-204 | `bind()` dangling key: append failure after `bare_map.getOrPut` leaves the map holding a freed key plus an orphaned empty entry (fresh-entry case); entry object leaks. Reachable by binding > max_resources. | Mirror the full_map rollback: fetchRemove the fresh entry and free its key; free the entry. Test at the cap boundary. |
| 7 | T255 | src/core/session_map.zig:455-476; call at server.zig:2934 | `getGenerationById` iterates the whole full_map under the shared lock for every cross-worker unicast; at 10k sessions it serializes against every bind/unbind/presence writer. | Per-worker generation array indexed by local_session_id validated locally by the consumer, or a small (worker,id)->gen side map. |
| 8 | T256 | room_registry.zig:197-198 vs muc_handler.zig:968-972 | Nick-collapse mutates `real_jid_buf` in place while jid_map keys point into it — hash/key desync, fetchRemove misses, stale entries accumulate; worker_mask old bit never cleared. | fetchRemove old key before mutation, put after; clear the old worker bit (or route through updateOccupantMove). |
| 9 | T257 | src/ipc/client.zig:104, server.zig:102 | 4 KiB stack encode buffers vs MAX_PAYLOAD_SIZE 65536: frames >4 KiB fail encode; s2s stanzas dropped silently. Companion: T330 buffer-size alignment. | Size to MAX_PAYLOAD_SIZE+HEADER_SIZE or encode straight into the backlog; log oversize explicitly. |
| 10 | T258 | src/ipc/server.zig:181-214, auth/handler.zig:702 | No peer credentials on the auth IPC unix socket; admin privilege is the client-supplied string `client_ip == "ctl"`. Protected only by directory perms. | getpeereid on accept; separate admin channel/socket; drop the ctl sentinel; chmod 0660 at bind. |
| 11 | T259 | src/master/main.zig:589-610 vs 523/533/541; 658-692 | Respawned children never rewrite their pid files; cleanupOrphan kills whatever recycled the stale pid without an identity check. | writeChildPid on every respawn; verify binary identity (kern.proc.pathname) before signaling. |
| 12 | T260 | lib/sasl/scram.zig:185-187, 339-387 | Unknown gs2 channel-binding flag skips all c= validation branches — silent success. | Reject flags ∉ {n,y,p} at handleClientFirst; final `else return error.ChannelBindingMismatch`. |
| 13 | T211 (existing) + T261 | scram.zig:319; s2s/dialback.zig:106 | Non-constant-time compare of StoredKey (T211) and dialback HMAC key (T261). | `std.crypto.timing_safe.eql` both; unit tests. Ships with T211. |

## P2 — should fix soon

| Task | Module | Finding summary | Proposed fix |
|------|--------|-----------------|--------------|
| T262 | tls/core+s2s | ktlsSend/ktlsRecv logged only in lib/xmppc; c2s/s2s silently fall back | Log ktls state + cipher at server.zig:1082 and s2s completion sites (main.zig:890, 1673). |
| T263 | lib/tls/ssl.zig:507-526 | Client-mode TLS 1.2 `tls-server-end-point` hashes the LOCAL cert (SCRAM-PLUS wrong/absent) | `SSL_get0_peer_certificate` in client mode. |
| T264 | lib/xmpp/stream.zig:321-341 | Bound resource never validated nor XML-escaped on output | isValidResource on bind + escape element text on emit. |
| T265 | lib/xmpp/stream.zig:366-378 | Client `to=` echoed unescaped into stream-response attributes | Escape all attribute values on output. |
| T266 | src/core/server.zig:2632-2661 | PEP accumulation re-serializes entity-decoded attr values/text raw | XML-escape attrs + text during accumulation. |
| T267 | src/core/delivery_queue.zig:163-179 | WakePipe write end blocking: full pipe blocks a producer event loop in write() | O_NONBLOCK fds[1]; treat EAGAIN as already-signaled. |
| T268 | src/core/session_map.zig:370-403 | Two exclusive session_map locks per presence stanza + redundant inner re-lookup | Single setPresenceState(available, prio) under one lock. |
| T269 | router.zig:104, presence_handler.zig:1207, iq_handler.zig:1862 | Blocklist isBlocked = sync LMDB read per stanza/subscriber on the loop | Per-worker blocked-pair cache, invalidated on XEP-0191 set/unset. |
| T270 | muc_handler.zig:1176, 1246 | Avatar hash LMDB read + dupe per occupant per join fanout | Cache avatar hash per bare JID, invalidated on pep_published. |
| T271 | iq_handler roster/vcard/pep, muc affiliation writes | Sync LMDB writes commit inline on the worker loop (fsync-class) | Route mutations through a writer queue (archive_queue pattern). |
| T272 | auth/handler.zig:817-824 | findScramSlot linear scan over 8192 slots ~3x/login (comment wrongly says 256; MAX_SCRAM_SESSIONS=8192 at :90) | AutoHashMapUnmanaged(conn_id -> slot); fix comment. |
| T273 | auth/oidc.zig:210, 248 | ROPC token POST + introspection + JWKS block the OIDC loop thread per login | Worker pool (CryptoPool shape), or document serial OAUTHBEARER. |
| T274 | core server.zig:761-825 | s2s IPC has no reconnect (T243 covered auth only); dead s2s = federation down until restart | Mirror auth reconnect: retain path, one-shot timer, purgeFd, re-addRead. |
| T275 | s2s/connector.zig:65, 518-532, 302-310 | Pool map keys / conn.remote_domain / queueStanza from-to borrow the IPC recv buffer, mutated by compaction | dupe on insert (key + field); free on remove; capture from/to at queue time. |
| T276 | s2s/main.zig:303, 592, 1806 | Blocking getaddrinfo + full SRV/TLSA chains on the s2s loop; no res cache | Worker-pool resolution or short-TTL per-domain cache. |
| T277 | s2s close paths | No purgeFd anywhere in s2s (T238 fd-reuse class unported) | batch.purgeFd(fd) in closeInbound/closeOutbound/closeClient. |
| T278 | connector.zig:418+132-136, main.zig:399-411 | Failed conns drop queued stanzas silently; queueWrite failure leaks stanza.xml | emit delivery-failed per stanza (needs T275's from/to capture); free before break. |
| T279 | auth/handler.zig:504-513, main.zig:401-412,444-448 | Re-auth overwrites live ScramServer without deinit; close-on-send-fail skips cleanupSession | deinit before re-init; sweep scram sessions on closeClient. |
| T280 | auth/handler.zig:183-201 | cred_cache identity = bare u64 FNV hash → collision serves wrong user's creds (fails closed) | Store + compare username bytes alongside the hash. |
| T281 | auth/rate_limiter.zig | Doc vs behavior: table-full is fail-OPEN, per-IP lockout never engages, no exponential backoff | Reconcile: fail closed, check IP lockout, fix doc or implement backoff. |
| T282 | master/main.zig:527, 535 | 100 ms sleeps after spawnChild as socket-readiness race | Verify T243 covers initial ECONNREFUSED; if so delete sleeps, else bounded socket wait / ready pipe. |
| T283 | xmppc/engine.zig:900-917 | prepareSession leaks initialized Session when allocSlot fails (pool full) | errdefer destroy / slot-first ordering. |
| T284 | xmppc/session.zig:245-256 | Session.init lacks errdefer — partial failure leaks parser/buffers | errdefer chain per allocation step. |
| T285 | xmppc/resolver.zig:172-185 | resolv.conf disk read on the engine thread (first resolve) | Read at Resolver.init on the caller thread. |
| T286 | xmppc/engine.zig:672-697 | Registration-only bare kevent() inside requestWake lazy pipe create, under lock, from foreign threads | Stage the READ registration into self.changes under changes_lock; loop folds it in. |
| T287 | xmppc/engine.zig:408, 1073, 1099 | run_gen u32 crossed threads non-atomically (data race by the book) | std.atomic.Value(u32) acq_rel. |

## P3 — notes / later (~50 items; all verified)

| Task | Summary |
|------|---------|
| T288 | xmppc resolver 1 s tick never disarms (wake 1x/s forever) |
| T289 | xmppc SM-enabled send path dupes every stanza twice (mailbox + SM queue) |
| T290 | xmppc allocations under slots/cmd/crypto mutexes (short; tighten slots chunk alloc) |
| T291 | xmppc wake_pipe publish non-atomic (torn read theoretical) |
| T292 | xmppc sendTlsa OOM leaks x2 (ta block, host dupe) |
| T293 | xmppc stale comment: engine allocator "not required thread-safe" is false under T237 use |
| T294 | xmppc write_buf shrink-realloc per full drain (allocator oscillation) |
| T295 | xmppc overflow requeue aliases the array's own backing store through appendSlice |
| T296 | xmppc DNS response demux by 16-bit id only (no qname/qtype check) |
| T297 | xmppc .connecting-phase read level-trigger re-fire (note; bounded by dispatch order) |
| T298 | xmppc trace printf junk: truncated format; unconditional EV_ERROR print |
| T299 | xmppc Session.fail dead allocator param; Parser.deinit mixes two allocators |
| T300 | xmppc WANT_WRITE-on-read would not re-arm write filter post-handshake (note) |
| T301 | xml scanner: dead `ally` struct; O(n) pending-token pop |
| T302 | xml scanner: numeric char refs parse as u8 (&#233; rejected) |
| T303 | xml reader: Event payload lifetimes undocumented — prerequisite for T249 |
| T304 | xml scanner: per-token accumulation buffers uncapped |
| T305 | xmpp/jid: byte-exact eql/hash; domains not case-folded (documented MVP) |
| T306 | xmpp/stream: saslSuccess stores a caller-borrowed username slice (undocumented) |
| T307 | xmpp/stanza: serializeIq has no payload writer (self-closing only) |
| T308 | sasl/scram: AuthMessage allocPrint chain could be stack-fixed (already arena-backed — optional) |
| T309 | sasl/plain: build() owned-slice contract undocumented |
| T310 | tls: kTLS set/clear via literal 0x8 instead of the named constant |
| T311 | tls: header doc claims libressl wrapper (stale) |
| T312 | tls/DANE: PKIX-TA/EE usages accepted without PKIX chain validation — implement or document |
| T313 | core connection.flushSync bounded 100x spin on the event thread (shutdown path) |
| T314 | core reapSmOverflow scans all sessions per batch even when idle (fast-exit flag) |
| T315 | core sm_handoff leaks previd key on overwrite + on put failure |
| T316 | core destroySession free_ids push unbounded (no guard; double-destroy would OOB) |
| T317 | core SM-resume re-bind failure → unroutable session with only log.err (2 sites) |
| T318 | core sm_handoff/archive_queue lock holds wrap c_allocator dupe/free |
| T319 | core router `<message>` serializer copy-pasted 6x; MUC dispatch dance 5x (one missing guard) |
| T320 | core RoomRegistry.findByJid linear scan per groupchat stanza |
| T321 | core nick_map/jid_map index puts swallow alloc failure |
| T322 | core presence stanza_to aliases the shared write_scratch |
| T323 | core store-read errors eaten by `catch false` with no log/metric |
| T324 | auth crypto pool: GPA-backed ArrayLists + O(n) orderedRemove dequeue (move to rings) |
| T325 | auth registration/password change run PBKDF2 on the loop thread |
| T326 | auth credential lookup = LMDB read per cache-miss on the loop thread |
| T327 | auth ~4 heap allocations per PLAIN login (note) |
| T328 | ipc readFrame: oversize header indistinguishable from partial frame |
| T329 | ipc one read() per readable event; drain to EAGAIN instead |
| T330 | ipc recv buffer sizes inconsistent 8K/32K/64K (companion to T257) |
| T331 | s2s dialback callback multiplexes onto the pooled conn; second callback overwrites slot; stanzas strand |
| T332 | s2s parse-error path never closes the session despite its comment |
| T333 | s2s outbound tries targets[0] only; no connect/idle timers |
| T334 | s2s 16 KiB inner stanza buffer truncates silently mid-content |
| T335 | s2s handleInboundReadable recursive re-entry (style) |
| T336 | master orphan-kill grace could poll kill-0 and exit early (defer ok) |
| T337 | master run_dir not threaded through pid-file paths |

## Cross-references / not new tasks

- **T215** (c2s STARTTLS flush-before-upgrade) predates this sweep; T250 extends
  the same defect class into s2s. Fix all sites in one design pass.
- **T211** (SCRAM timing-safe StoredKey) predates this sweep; T261 is its s2s
  sibling. Ship together.
- **T245** (SINT modular-stress message loss) has a code-level correlate seen
  in the sweep: room mailbox full → drop at server.zig:3011-3013.
- **lib/xmppc ~600-line/file exit-gate** still unmet (engine.zig 1335,
  session.zig 1234, parser.zig 1220, stream.zig 853 incl. tests). Tracked via
  the Continuum T-5B0B9B64 refactor family; out of v0.9.1 fix scope.
- Parser test-fixture key-name mismatch ([auth] rate_max_* vs max_per_*)
  remains under T-1BD5AFD5 pre-existing work; not a sweep finding.

## Proposed v0.9.1 fix-now batch (awaiting owner approval)

P1 table in full (T249-T261 + T211 + T215-extended-by-T250), plus cheap P2s:
T262 (kTLS logging), T263 (client CB cert), T264/T265/T266 (escaping trio),
T267 (WakePipe nonblock), T281 (rate-limiter doc reconcile),
T282 (master readiness waits). Everything P3 files as-is for later releases.

Release does not tag until the owner approves this batch.
