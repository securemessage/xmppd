# C11: SM replay through the Outbox, expiry wheel, offline or bounce on expiry

Plan: `doc/T197_QUALITY_SWEEP.md` §5.5 row C11 (Phorge T400; Continuum
T-684D1A21; subsumes T317 and V19; with C4 it closes T429/T430).

## Scale model (event-driven-systems §0 litmus)

1. **Execution model.** Thread-per-core workers, unchanged. C11 only moves
   where unacked stanzas live (refcounted Blobs instead of per-session heap
   copies) and how detached-session deadlines reach the loop (one deadline
   timer per worker instead of a 30 s scan of every session slot).
2. **Linear scaling.** The unacked queue is worker-local session state; the
   only shared objects are Blobs, which use atomic refcount + a per-producer
   atomic byte counter (ADR-3, already on the hot path since C4). The expiry
   wheel is worker-local and lock-free by ownership. No new shared state.
3. **Shared resources.** `BlobBudget` is per producing worker
   (`DeliverySystem.budgets[w]`), already sharded. Unacked-queue bytes now
   charge that budget: replay memory is bounded the same way ring payloads
   are, instead of living outside every bound.
4. **Nothing blocks a loop.** Replay and drain are the same memory writes
   they were (blob bytes are contiguous). Offline stores go through the
   existing `storeHeldPointer` path (no new I/O on the loop).
5. **Connection economics.** A Blob is a reference (~24 B header), not a
   copy: a detached session with 256 unacked stanzas pins ~24 B per stanza
   header plus the shared payload once, rather than a private copy per
   recipient. Wheel adds three words per session slot.
6. **Many requests per connection.** Unchanged (XEP-0198 already streams).
7. **Beyond one host.** Cross-worker resume already hands off state; with
   Blobs the handoff transfers references instead of copies (same process,
   atomic refcounts make that safe).
8. **Expensive operations priced.** No new expensive ops. The wheel turns a
   30 s O(sessions) scan into O(due) work.
9. **Overload behavior.** The unacked queue keeps its 256 bound; a produce
   that hits the blob budget fails the session (same fail-closed class as
   the existing `.alloc_failed`/`.overflow`). Offline refusals now bounce
   to the sender instead of being counted-but-lost (the #81 gap).
10. **Measured.** R1/S1/C1/Z1 rig cells, 3 runs each on master and on this
    head, in the same session; R1 reports lost / stored-offline / bounced
    separately.

## Design

### Unacked queue holds Blob references (item a)

`SmUnackedQueue` entries become `?*delivery_queue.Blob` (atomic refcounted,
ADR-3). `init` takes a `*BlobBudget` instead of an `Allocator`:

- `push(data)` produces a Blob on the queue's budget. Budget or allocation
  failure maps to the existing `.alloc_failed` push result, which already
  fails the session (T178 fail-closed).
- `pushBlob(blob)` takes a reference on an existing Blob: cross-worker
  deliveries share the ring slot's Blob instead of copying
  (`drainDeliveryQueue` passes `queue.current_slot_blob` to
  `Session.stanzaBlob`), and the cross-worker resume rebuild re-references
  the handoff blobs instead of duplicating them.
- `deinit`/`discardHead` release references; bytes return to whichever
  worker's budget produced the blob. `UnackedIterator.next()` yields
  `*Blob`; callers read `blob.bytes()`.

`Session.smTrackOutbound` gains a `?*Blob` parameter; `stanza()` and
`stanzaWithFlush()` route through `stanzaBlob(data, ?*Blob)`. `Server`
gets `smBlobBudget()`: `delivery_system.budgets[worker_id]` when a
delivery system exists, else a server-owned fallback `BlobBudget` (tests
and single-worker rigs without a delivery system still get the bound).

`ResumeBundle.stanzas` becomes `[]*Blob` (sm_handoff.zig). Blobs are
process-lifetime safe across workers: refs are atomic and release() returns
the charge to the producing worker's budget on any thread.

### Replay through the Outbox (item b)

New `Session.stanzaReplay(data)` appends to the conn outbox untracked
(stanza-classed like `stanza()`, not `nonza()`): replayed stanzas are
already counted in `sm_unacked`, so re-tracking would double-count. Both
replay sites (local `handleSmResume`, cross-worker `handleSmResumeReply`)
use it. Replay order and the `<resumed/>`-then-stanzas wire order are
unchanged. `ResumeBundle.stanzas` carry `*Blob`; the rebuild uses
`pushBlob`, which is infallible for a source already bounded by
`UNACKED_CAPACITY`.

### Detached-session expiry wheel (item c)

New `src/core/c2s/sm_wheel.zig`: a 512-slot-per-second timing wheel
(512 s > 300 s `DEFAULT_RESUME_TIMEOUT`, so every deadline fits one
revolution and each bucket's entries are all due at its tick). Intrusive
`sm_expiry_prev/next/deadline/bucket` fields on `Session`;
`Server.sm_expiry` holds the wheel.

- `detachSession` inserts at `sm_detach_time + DEFAULT_RESUME_TIMEOUT`.
- `destroySession` unlinks centrally (flag-guarded, so wheel-free sessions
  are a no-op).
- `expireDetachedSessions` drains due buckets and destroys those sessions
  (which already runs `drainUnackedToOffline`), then re-arms.
- The worker keeps ONE one-shot `EVFILT_TIMER` on `SM_EXPIRY_TIMER_IDENT`,
  re-armed to the wheel's next deadline after every insert/remove/drain
  (`armSmExpiry`); empty wheel disarms. The 30 s periodic registration and
  its whole-session-table scan go away. No per-session timers, no polling:
  the loop sleeps until the next deadline.
- `SM_EXPIRY_SWEEP_MS` is removed; worker test sites that used it as
  changelist filler use any other interval.

### Offline-or-bounce drain policy (item d)

`drainUnackedToOffline` becomes the XEP-0198 §5 policy point, per stanza,
counted per outcome (nothing lost silently; this is the #81 fix: the 3120
counted-but-lost offline-quota drops now bounce):

- `<message>` (not `error`/`groupchat`): `storeHeldPointer`. Stored ->
  `sm_unacked_stored`. Refusal or error -> `sm_offline_refused`, then the
  stanza bounces like any other non-message below.
- `type='error'` or `type='result'` stanzas: counted drop
  (`sm_unacked_dropped`), since RFC 6120 forbids an error for an error.
- Everything else (IQ get/set, presence, other messages): bounce
  `service-unavailable` to the stanza's `from` via the existing
  `writeCrossWorkerError` shape; local senders route through session_map
  (full JID: `stanza()` same worker, `ds.deliver` remote worker), remote
  domains through `s2s_ipc` `s2s_deliver` (`sendS2sError`). Success ->
  `sm_unacked_bounced`; unroutable sender (gone, bare, unparsable, no S2S)
  -> `sm_unacked_bounce_failed`.
- `<message type='groupchat'>` keeps the counted-drop class (bounce target
  would be a room JID).

New module atomics in ring.zig (`sm_unacked_stored`, `sm_unacked_bounced`,
`sm_unacked_dropped`, `sm_unacked_bounce_failed`, `sm_offline_refused`),
exported through `metrics.Externals` and the SIGUSR1 dump.

### T317: force-close on resume re-bind failure (item e)

Both `session_map.bind` failure sites now fail the resuming session
instead of leaving it bound to nothing:

- Local `handleSmResume`: on re-bind failure the detached slot is
  dismantled (unbind already happened; `sm_resume_enabled = false`,
  `smIdMapRemove`, `smRedirectDrop`, destroy + slot release), then the new
  session gets `internal-server-error` + `flushSync`, its transferred
  unacked queue drains through the §5 policy, and `forceCloseSession`.
- Cross-worker `handleSmResumeReply`: same stream-error + drain +
  force-close; the bundle was already consumed on the owning worker.

### V19: xmppc re-bind after a failed `<resume/>` (item f)

Root cause is client-side (`lib/xmppc`), not the server: `feedSm`'s
`.failed` branch set `.active` + `.established` even when the element that
failed was a pre-bind `<resume/>`, leaving the client unbound; the
server's `not-authorized` on IQ is correct. Fix: on `.failed` with
`resume_id` set, the FSM saves the id in `failed_sm_id`, clears
`resume_id`, and takes the normal bind path (`send_bind`, or the
session/`no-bind` tail). A successful bind reaches `afterBind()`, whose
`smAction()` now sends a fresh `<enable/>`. `Session`'s `.established`
handler drops the old queue via `failed_sm_id` (before the fresh-enable
registration) and still reports `.sm_failed` with the drop count.

## Item map

| Commit | Item | Files |
|---|---|---|
| a | Blob unacked queue + shared-ring sharing | sm_state.zig, session.zig, deliver.zig, worker.zig, build.zig |
| b | stanzaReplay + blob handoff | session.zig, sm.zig, sm_handoff.zig |
| c | expiry wheel | sm_wheel.zig (new), session.zig, lifecycle.zig, worker.zig |
| d | offline-or-bounce drain + counters | lifecycle.zig, ring.zig, metrics.zig, worker.zig |
| e | T317 force-close on re-bind failure | sm.zig |
| f | V19 xmppc re-bind after failed resume | lib/xmppc/stream.zig, lib/xmppc/session.zig |

## Revert-check tests (each fails when its change is reverted)

1. Unacked queue entries are `*Blob`: `pushBlob` shares, refcount counts
   refs (queue entry + producer handle == 2), deinit releases.
2. Cross-worker delivery to a resumable session shares the ring Blob:
   `refs` reaches 2 during the drain handler, not a copy.
3. Replay after resume delivers every unacked stanza exactly once through
   `stanzaReplay` (outbox), from a shared blob.
4. `ResumeBundle` round-trip carries `*Blob` stanzas; rebuild via
   `pushBlob` preserves base_seq/last_h.
5. Wheel: detach inserts at the deadline bucket; the worker stages exactly
   one one-shot EVFILT_TIMER arm (not a 30 s periodic, not per-session
   timers); `expireDetachedSessions` destroys due entries and leaves the
   rest linked.
6. Expiry stores messages offline and bounces IQs: a detached queue with a
   message + an IQ stores the message (counter) and routes a
   `service-unavailable` error to the IQ sender.
7. Offline-quota refusal bounces: `storeHeldPointer` returning false
   produces an error stanza to the sender, counted (`sm_offline_refused`,
   `sm_unacked_bounced`), nothing lost.
8. Error/result stanzas drop counted, never bounced.
9. T317: `session_map.bind` failure on resume sends `internal-server-error`
   and destroys both slots (no unroutable session survives).
10. V19: `.failed` on a `<resume/>` transitions to `awaiting_bind_result`,
    emits `send_bind`, then a fresh `send_sm_enable`; `.established` drops
    the old SM queue and reports `.sm_failed`.

## Frames / caps

Only downward movement: no buffer, ring, budget, or timeout cap rises.
The SM expiry timer remains a single one-shot knote per worker; the 30 s
periodic timer is deleted.

## Already landed (kept, not redone)

- S17: `sm_id_map` is `std.AutoHashMapUnmanaged([32]u8, usize)`
  (worker.zig:395), so C11's "SM-ID hash map if S17 not landed" clause is
  satisfied; nothing to do.
- S24: `SmUnackedQueue.last_h` wrap-aware backwards-h guard.
