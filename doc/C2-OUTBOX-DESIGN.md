# C2 design: core Outbox (ADR-2, plan 5.5)

C2 puts the ADR-2 outbox behind every core c2s send. It subsumes S13, S15,
S23, T313 and the T215/T250 STARTTLS upgrade rules, and it is the
structural fix for the R1/S1 loss measured in Phorge T430 (24 percent of
slowread messages lost, blocking gates R4/R5).

Two stages, matching the task card:

- **Step 1**: the `Outbox` sits behind today's semantics plus per-worker
  drop counters. Every `queueSend` call site is routed through it
  mechanically. Behavior is unchanged apart from counting; the suites
  pass unmodified.
- **Step 2**: bounded spill up to `max_outbound_bytes`, fail-closed to
  offline storage, SM counting on every `stanza()`, end-of-iteration
  flush with `EVFILT_WRITE` armed only after a real EAGAIN, the TLS pin
  and the `startTls` rule.

## 1. Adopt lib/net's Outbox directly

ADR-8 makes `lib/net` the shared library, and F3 already shipped the
exact type ADR-2 specifies: `lib/net/conn.zig` `Outbox` (inline ring +
bounded spill + the TLS `(ptr, len)` pin), `Transport`, `Tls`,
`Counters`, `AppendResult`, `FlushResult`. Core adopts those types; it
does not wrap or copy them.

Core does **not** adopt `net.Conn`, `net.Inbox`, `net.ConnList` or
`net.Loop` in this lane. The core worker owns its event machinery
(`worker/loop.zig` `EventLoop`/`ChangeList`, `Server.sessions` slot
array, generation checks, `sm_handoff`); swapping it for `net.Conn` is a
loop rewrite, not the outbox migration this task is.

What core needs that lib/net lacks (stays in `src/core`):

1. **`tracked_detached`.** `AppendResult` is `queued | spilled |
   failed_closed`; SM tracking is a core concept. `Session.stanza()`
   wraps `Outbox.append` + `smTrackOutbound` and returns the ADR-2
   four-case result `{ queued, tracked_detached, spilled,
   failed_closed }`. A detached session (`sm_detached`, conn closed for
   SM resume) counts and tracks without touching the conn; this
   replaces the special-casing at `routing/router.zig` (detached branch
   in the delivery loop) and `routing/deliver.zig` (`sm_detached` in the
   MPSC drain) with one path.
2. **A dirty list over `*Connection`.** `net.ConnList` links `*net.Conn`;
   the M3 end-of-iteration flush needs the same intrusive list over core
   `Connection`, walked next to `reapOutboundOverflow` in the worker
   batch tail (`worker.zig`).
3. **The `startTls` rule without `net.Handshake`.** Core's stream FSM
   owns `starttls_pending`; `startTlsUpgrade` gains the same
   preconditions `net.Conn.startTls` enforces (empty outbox, no buffered
   read-ahead) instead of adopting the lib handshake object, which is
   the F7 pool seam.
4. **An unacked-queue drain to offline storage** for the fail-closed
   path (section 4).
5. **A build fix:** `build.zig` creates `ssl_mod` and `ssl_test_mod` as
   two identical `createModule` instances over `lib/tls/ssl.zig`. Zig
   compiles them as distinct modules, so `ssl.SslConn` in `core_mod`
   (which imports `ssl_test_mod`) is a different type than the one
   `net.Tls.conn` declares (via `ssl_mod`). The two definitions are
   verbatim identical (same root, imports, links); the core modules that
   adopt `net` take `ssl_mod` for their `ssl` import so the types
   unify. `lib/net` itself needs no change.

### Ring backing, allocation, pinning

`Connection.write_buf` is a 16 KiB heap block allocated lazily on the
first append (`ensureWriteBuf`), so it is not moved by `Session.init`'s
by-value return: the pointer is stable from allocation until `deinit()`.
`Outbox.init` takes the ring as a `[]u8` the consumer owns; `Connection`
starts with an empty ring and `ob()` rebinds `outbox.ring = write_buf`
on every use, so the binding self-heals across the `sessions[]` move.
The invariant that makes the TLS pin proof hold is unchanged from F3:
a Session is heap-allocated once, stored as `*Session` in `sessions[]`,
and never moved afterward. `deinit()` closes the fd, frees the spill
list, then frees the ring block.

`Connection.init` gains the allocator `Session.init` already receives
(for M3 spill growth and the ring block). Counters: connection.zig owns
a static array of per-worker `net.Counters` slots, bound once the
Connection lands in its heap slot by
`conn.bindOutbox(countersForWorker(server.worker_id))`; unbound
connections fall back to a `threadlocal` counter block so tests need no
ceremony. `Outbox.counters` is always non-null; nothing on the send path
dereferences an undefined pointer. The per-worker static keeps `Server`
at its master size (the stack-frame ratchet caps it exactly).

## 2. The send API and its result type

```zig
pub const SendResult = enum { queued, tracked_detached, spilled, failed_closed };

// On Session (has SM state, bound JID, scratch):
fn stanza(session: *Session, changes: *ChangeList, data: []const u8) SendResult;
fn nonza(session: *Session, changes: *ChangeList, data: []const u8) SendResult; // never tracked_detached
```

- `stanza()` always counts for XEP-0198. It tracks first
  (`smTrackOutbound`, which increments `sm_out_seq` and pushes the
  stanza copy onto the bounded `SmUnackedQueue`), then appends to the
  outbox. Tracking first means a `failed_closed` stanza is still in the
  unacked queue, which is the authoritative list of undelivered stanzas
  the fail-closed path drains to offline storage (section 4). It also
  fixes the S15 ordering hole: today `queueSend` failure skips
  `smTrackOutbound` (an untracked-but-counted gap class) while
  `smTrackOutbound` bumps `sm_out_seq` before `push` can fail.
  `sm_detached` returns `tracked_detached`: counted, queued for replay,
  nothing appended to a dead conn.
- `nonza()` never counts. Stream features, `<r/>`, `<a/>`, SASL
  elements, stream errors and closing tags keep going through it, and
  so does SM replay (`c2s/sm.zig` resend sites), because replayed
  stanzas are already in the unacked queue and must not be tracked a
  second time.
- `failed_closed` covers both today's `ConnectionClosed` (conn closed,
  not detached) and `WriteBufferFull` (over the append bound). Callers
  that classify keep classifying: a stanza with `len >
  outboxCapacity()` is the oversize case (`oversize_queue_drops`, IQ
  result answered `resource-constraint`, session lives); a fitting
  stanza refused is the slow-reader case (`sm_overflow = true`, session
  torn down by `reapOutboundOverflow`). Step 1 keeps the bound at the
  ring capacity so the same split is byte-identical to today.
- `spilled` cannot occur in step 1 (`spill_limit == ring.len`); it is
  the success-but-backlogged result in step 2 and needs no distinct
  handling anywhere.
- Drop counters stay central: `stanza()`/`nonza()` bump
  `drop_send_closed` / `drop_send_buffer_full` exactly where `queueSend`
  does today, so a caller that discards the result still produces a
  counted drop. What every call site loses is the ability to swallow
  the result silently: `SendResult` is a value, `catch` disappears, and
  each site states its outcome in a switch or an explicit `_ =`.

Census of production call sites (send helpers and arming copies):
`c2s` ~44 (`session` 26, `sm` 10, `lifecycle` 8), `iq` ~31, `muc` ~16
(`handler` 15, `fanout` 1), `presence` ~7, `routing` ~14 (`router` 12,
`deliver` 2), `worker` ~8, `connection` ~4; plus about 65 copies of the
`if (hasPendingWrite()) changes.addWrite(...)` arming idiom. Step 1
commits one directory at a time: `c2s`, `iq`, `muc`, `presence`,
`routing`, then `worker`/`xworker`.

`queueSendWithFlush` (one caller, `routing/router.zig` delivery loop)
keeps its semantics: append, one inline `flushSend` on `failed_closed`,
append again.

`flushSend` is reimplemented over `outbox.flush(&transport, budget)`
with the same `!usize` signature: `drained`/short write returns the
byte count, `want_read`/`want_write`/`budget_left` maps to
`error.WouldBlock`, `err` maps to `ConnectionReset`/`ConnectionClosed`.
The lib already implements the S23 rule: the pin is formed only from
ring memory, the retry presents the identical `(ptr, len)`, and new
bytes append behind `tail`, so `tls_write_pending` and `compactWriteBuf`
are deleted.

`hasPendingWrite()`/`pendingWriteBytes()` become thin wrappers over
`outbox.empty()`/`outbox.bytes()` so step-1 call sites and the T110
watermark checks read unchanged.

### Drop reasons vs Appendix C

| Reason | Counter (M1 per-worker unless noted) | App. C row |
|--------|--------------------------------------|------------|
| conn closed, stanza/nonza refused | `drop_send_closed` | write buffer full or connection closed |
| over append bound (slow reader) | `drop_send_buffer_full` + `sm_overflow` teardown | same |
| `write_buf` lazy alloc OOM | `drop_send_alloc` | write buffer full or connection closed (memory pressure, not backpressure) |
| stanza over the cap outright | `oversize_queue_drops` (module global) | same |
| stanza tracked for a detached session | `send_tracked_detached` (new) | not a drop; visibility for R1 |
| `net.Outbox` `failed_closed` | `net.Counters.outbox_failed_closed` per worker | same |
| changelist append refused | `drop_changelist_full` (already central) | change list full |
| cross-worker ring full / over slot | `ring_drops_full` / `ring_drops_payload` / `cross_worker_drops` (module globals) | cross-worker ring |
| room mailbox full | `mailbox_drops` (module global) | room mailbox |
| offline store refused / hold bounced / drain drop | `offline_not_stored` / `offline_hold_bounces` / `offline_drain_drops` | no error to the sender |

## 3. Step 2 mechanics

- `spill_limit` becomes `max_outbound_bytes` (per F3's c2s row, default
  1 MiB, configurable). `spilled` is then a live result.
- `failed_closed` -> `sm_overflow` -> `reapOutboundOverflow`: live
  sessions get `sendStreamError(.resource_constraint)`, `flushSync`,
  `forceCloseSession`; detached sessions are destroyed.
- End-of-iteration flush: `stanza()`/`nonza()` link the conn on an
  intrusive dirty list instead of arming `EVFILT_WRITE`. The worker's
  batch tail walks it, calling `outbox.flush(&transport,
  flush_budget)`; `EVFILT_WRITE` is armed only when a flush returns
  `want_write` (a real EAGAIN), `want_read` keeps read interest,
  `budget_left` re-links, `err` closes. That deletes the ~65 arming
  copies and the per-stanza `EV_ADD`/`EV_DELETE` pair (ADR-2). The T110
  watermarks stay absolute (`WRITE_SUPPRESS_HIGH=12288`,
  `LOW=8192`) on `outbox.bytes()`: suppression is inbound pushback and
  should engage long before the 1 MiB death cap.
- `startTlsUpgrade` gains the rule: refuse/error when the outbox is not
  empty or bytes sit past the upgrade point (`ReadAhead`), matching
  `net.Conn.startTls`'s checks. Today's `starttls_pending` drain wait
  already provides the first half; the check makes it structural.
- `flushSync` keeps its bounded-attempt contract for the shutdown path
  (T313); it iterates `outbox.flush` with the same bound.

## 4. Over-cap policy: where undelivered messages go

The session fails with `resource-constraint` (the existing
`reapOutboundOverflow` path). Undelivered **messages** go to offline
storage through `OfflineStore.storeHeldPointer`, the same path
`holdBehindOfflineTail` (`routing/deliver.zig`) and the router's
no-available-resource branch (`routing/router.zig`) use, keyed
`(recipient_bare, sender_bare, stanza_id)` with the held payload
authoritative. The SM unacked queue supplies the stanza list: on
teardown of a session with `sm_unacked`, pending entries that are
`<message>` stanzas are offered to `storeHeldPointer` (dedup by
`storeHeldPointerOnce`'s token where the dispatch minted one);
non-message stanzas follow the RFC rules (errors never stored, presence
never stored). Sessions without SM have no unacked list: their
in-outbox stanza bytes are unrecoverable and die with the session,
counted, identical to today's loss, not a regression. C11 builds the
full XEP-0198 section 5 policy (replay-through-Outbox, expiry timer
wheel, offline/bounce on expiry) on this drain; C2 does not implement
it.

## 5. Scale litmus (event-driven-systems section 0)

1. **Execution model.** Thread per core, already shipped: N workers,
   each with its own `EventLoop` and `SO_REUSEPORT_LB` listener. C2
   changes nothing about it; the outbox is per-conn, owned by the
   worker's loop thread.
2. **Linear scaling.** The send path gains no lock, atomic or shared
   map. `net.Counters` is a plain-u64 block per worker, `metrics.bump`
   is the existing single-writer per-worker pattern, and the module
   globals that already exist (`oversize_queue_drops` etc.) are
   cold-path atomics only.
3. **Shared resources.** None added. `SSL_CTX` remains per-process
   read-only (ADR-11/F7 owns its sharing story); the offline store is
   reached only on the fail-closed path, which is cold.
4. **Nothing blocks a loop.** `storeHeldPointer` on fail-closed runs
   once per dying session, not per stanza on the hot path; the
   end-of-iteration flush is bounded by `flush_budget_bytes` per conn
   per pass.
5. **Connection economics.** Idle: no ring block at all until the first
   append, then one 16 KiB heap block per conn + ~80 B of `Outbox`
   bookkeeping (the removed `write_start`/`write_end`/`tls_write_pending`/
   `compactWriteBuf` state offsets most of it), flat or better vs today
   (inline 16 KiB at idle). Step 1 cap: one 16 KiB ring + `Outbox` spill
   list disabled (`spill_limit == ring.len`). Step 2 cap: up to
   `max_outbound_bytes` (1 MiB) of spill per conn, freed back to a 64 KiB
   high-water mark on drain. The connection cap itself is unchanged
   (`max_sessions`).
6. **Many requests per connection.** Unchanged; XMPP pipelining is
   unaffected.
7. **Backpressure.** T110 watermarks keep their absolute thresholds on
   `outbox.bytes()`; `failed_closed` is the last resort, never the
   first. Drop counters are per worker (M1).
8. **Measurement.** M3 re-runs the M2 driver cells R1, S1 and C1
   (3 runs each, ReleaseSafe, server on cores 0-7, driver on 8-11).
   R1's lost count is the headline; the release-gate target is 0 lost
   or all loss converted to counted offline/bounce outcomes.
