# C4: Envelope ring with refcounted blobs and room deques (ADR-3)

Milestone-1 design note for plan item C4 (doc/T197_QUALITY_SWEEP.md ADR-3 and
section 5.5; Continuum T-69508FD4; Phorge T393). Stacked on PR #91 (C3 tokens).

Subsumes: S14, S16, T245 (correlate), T287, the sentinel session ids, the
1 MiB inline ring per worker and the 65 KiB inline mailbox per room. It is the
structural step for T429/T430 together with C11.

## Scale litmus (skill section 0)

1. Execution model: unchanged, thread per core. Each worker already owns its
   connections, sessions, rooms and queues. C4 changes what crosses the
   boundary, not the model.
2. Linear scaling: the shared mutable state on the delivery path today is
   the MPSC ring `tail` (CAS) plus per-slot `ready` flags. After C4 the same
   single atomic tail remains; `head` becomes atomic so the producer full
   check reads published state instead of a consumer-owned plain field.
   Blob refcounts are atomics on shared payloads; the 1:1 local path never
   touches them. Drop counters stay process-wide atomics but are cold
   (drop paths only); per-class accept counters go through the existing
   per-worker `envelope_hook`, no new hot-path atomic.
3. Shared resources: blob storage is per-producer budgeted; the allocator
   is the process `smp_allocator`, which is thread-safe and sharded. Room
   mailboxes stay worker-owned.
4. Nothing blocks a loop: no new blocking work. Serialization moves from
   the consumer-side stack buffer to producer-side heap blobs; the same
   bytes move once. Codec decode on the consumer is proportional to the
   message (bounded by the blob budget).
5. Connection economics: per-worker ring memory drops from 1,052,672 B
   resident to 12,288 B resident plus bounded in-flight blobs (budget
   below). Idle rooms cost zero mailbox bytes instead of 65,312 B.
6. Many requests per connection: unchanged (stanzas per stream, SM h).
7. Beyond one host: unchanged (s2s). Large stanzas that previously died
   at the ring boundary (S14) now survive cross-worker, which is required
   for federated traffic that carries them.
8. Expensive operations priced: serialization cost is paid once per
   dispatch by the producer instead of per target copy; the multicast
   fan-out no longer memcpy's up to 4 KiB into every target ring.
9. Overload behavior: every queue stays bounded; the new failure surface
   is the per-worker blob budget, which fails closed into the same
   per-class QueueFull policy as a full ring. Backpressure reaches the
   sender (offline/bounce/error reply) instead of a warning.
10. Measured: the C1/S1/R1/MUC/Z1 rig runs master vs head in the same
    session, ReleaseSafe, 3 runs per cell; Z1's >4080 B classes must stop
    losing, and no cell may regress.

## Layouts

### Envelope ring (replaces `DeliverySlot`)

```zig
pub const Envelope = struct {
    target: Token,                 // session token or a *_TARGET pseudo-target
    blob: *Blob,                   // refcounted payload, valid while slot live
    hold_token: u64 = 0,           // dispatch identity for the offline hold
    receipt_ts: u64 = 0,           // producer receipt time, epoch seconds
    len: u32,                      // payload length (== blob.len, asserted)
    class: DeliveryClass,          // consumer-side policy and filter class
    ready: std.atomic.Value(bool), // publish flag, same protocol as today
};
comptime assert(@sizeOf(Envelope) <= 48);
```

- `slots: [QUEUE_SLOTS]Envelope` with `QUEUE_SLOTS = 256`: 12,288 B per
  worker, down from 1,052,672 B (256 x 4112).
- Producers: CAS-reserve on `tail` (unchanged), write the descriptor,
  `ready.store(true, .release)` (unchanged).
- Consumer: owns `head`, now `std.atomic.Value(u32)` so the producer full
  check `tail -% head >= QUEUE_SLOTS` reads the published value
  (.acquire). The consumer stores `head` with .release after the slot's
  blob reference is released, so a producer reusing the slot sees the
  release ordering.
- Wakes: unchanged. `wake_pending` still coalesces to one pipe write per
  idle-to-busy transition.

### Blob

```zig
pub const Blob = struct {
    refs: std.atomic.Value(u32), // acq_rel on add, release on drop, acquire on last
    home: u8,                    // producing worker id (budget accounting)
    len: u32,
    data: [0]u8,                 // payload follows the header in one allocation
};
```

- One `alloc(u8, header + len)` per blob; no separate header free.
- Ownership rules:
  - The producer holds one reference while the value is in hand.
  - Each successful ring publish (or room-mailbox / SM-queue / retry-list
    link) takes one reference before the slot is made visible.
  - The consumer releases after the drain handler returns; decoded
    slices borrow the blob, so nothing outlives the handler.
  - Last release frees the allocation on `smp_allocator` (thread-safe)
    and decrements the home worker's `blob_bytes_in_flight` atomic.
- Budget: per producing worker `BLOB_BUDGET_BYTES` in flight. Exceeding it
  returns `error.QueueFull` from the produce step, which lands in the
  same per-class policy table as a full ring. Nothing is allocated
  unboundedly and nothing fails silently.
- Producer-side short path: a 1:1 stanza delivered to a session on the
  same worker never allocates a blob; the existing `session.stanza(bytes)`
  path stays. A blob is created only when the payload crosses a worker
  boundary or must be retained (SM replay queue, room mailbox, retry
  list), matching the section-6 target of zero allocations on the 1:1
  steady-state path beyond the one shared blob when cross-worker or
  SM-tracked.

### DeliveryClass (replaces `DeliveryKind { stanza, carbon }`)

```zig
pub const DeliveryClass = enum(u8) {
    normal = 0,      // stanza under RFC 6121 rules (hold, SM replay, bounce)
    carbon = 1,      // XEP-0280 copy: carbons_enabled sessions only, live only
    roster_push = 2, // server roster push (IQ set) to a target session
    chatstate = 3,   // ephemeral typing/activity stanza
    pep = 4,         // PEP notification stanza
    room_actor = 5,  // envelope.zig codec message for a room mailbox
    sm_actor = 6,    // envelope.zig codec message for the SM handoff path
    store_done = 7,  // ADR-5 storage completion (reserved; producer lands with WS5)
};
```

- `kind` on the token still selects the dispatch channel (session,
  multicast, room_actor, sm_actor); `class` selects the consumer's
  per-session filter and the QueueFull policy. The pseudo-target sentinels
  keep working but stop carrying policy meaning: policy lives in `class`.
- Consumer-side per-session filters (V14): the receiving worker applies
  the same predicates the local path uses today, because only it can see
  the target `Session`:
  - `carbon`: drop unless `session.carbons_enabled` (today's rule).
  - `chatstate`: drop typing-only stanzas when `!session.csi_active`
    (today applied at `router.zig` for local targets only).
  - `pep`: drop unless the session is present/subscribed per the local
    PEP delivery predicate.
  - `roster_push`: no extra filter; the class exists so QueueFull policy
    and counters differ from `normal`.
  - `normal`: existing hold/offline/SM logic, unchanged semantics.

## QueueFull policy per class

Every full-ring, oversized-allocation, or budget-exhaustion outcome takes
the class policy below and increments a counter (existing
`ring_drops_full`/`ring_drops_payload` split into per-class counters plus
`actor_retry_*`). Nothing is dropped silently.

| class | QueueFull outcome | Appendix C row |
|---|---|---|
| normal | Message stanzas: offline hold / offline store, else bounce `service-unavailable` to sender. IQs: `resource-constraint` error reply. | "Cross-worker ring: queue full" and "No error to the sender" |
| carbon | Count and drop (live-only by XEP-0280 section 7; never stored, never bounced). | "Cross-worker ring: carbons" |
| roster_push | Count and drop; the roster change is already stored and a roster get re-syncs the client. | "Cross-worker ring: roster push" |
| chatstate | Count and drop (ephemeral). | "Cross-worker ring: presence/chatstate" |
| pep | Count and drop (ephemeral notification). | "Fixed buffers: PEP notifications" + ring row |
| room_actor | Bounded per-worker retry list (below); a `room_message` that still cannot enqueue takes the S16 path: error reply to the sender + `mailbox_drops`. | "Cross-worker ring: room actor enqueue failure" + "Room mailbox full (S16)" |
| sm_actor | Bounded retry list; on exhaustion, a request carrying `reply_to_*` gets a `<failed/>`/error reply where one exists, and `actor_retry_drops` counts the outcome. | "Cross-worker ring: SM actor reply failure" |
| store_done | Bounded retry list (a lost completion wedges a waiter); exhaustion counts `actor_retry_drops`. | New counted outcome |

### Bounded actor retry list

Per consuming worker: `ACTOR_RETRY_MAX = 64` envelopes, retried once per
drain tick for up to `ACTOR_RETRY_ATTEMPTS = 8` ticks, then the class
fallback (bounce with reply where one exists, else counted drop).
`room_actor` retries re-attempt `mailbox.push`; `sm_actor`/`store_done`
retries re-attempt their handlers. Envelope blob refs pin the payload for
the retry window; no copy.

## Room mailboxes

- `RoomMailbox` becomes a heap deque of envelope items instead of
  `slots: [16][4080]u8`:

```zig
const MailboxItem = struct { next: ?*MailboxItem, blob: *Blob, len: u32, class: DeliveryClass };
const RoomMailbox = struct {
    head: ?*MailboxItem, tail: ?*MailboxItem, count: u16, bytes: u32,
};
```

- Items come from a per-worker bounded `std.heap.MemoryPool` sized
  `MAILBOX_ITEMS_PER_WORKER` (default 4096 = 256 rooms x 16). Pool
  exhaustion is the same event as the byte budget: the S16 policy runs.
- Byte budget per room `MAILBOX_BYTE_BUDGET = 262,144` (4x today's
  65,280 B capacity, allocated on demand). `enqueue` checks
  `bytes + len <= budget` and `count < MAILBOX_ITEMS_MAX_PER_ROOM`
  (64, so one room cannot monopolize the pool).
- Pending-room list: `Room` gains `pending_next: ?*Room` and
  `mailbox_pending: bool`; the worker keeps an intrusive FIFO of rooms
  with pending mail. `enqueue` links the room on the empty-to-nonempty
  edge; `drainRoomMailboxes` pops rooms, processes one message, re-links
  non-empty rooms at the tail (same round-robin fairness, `MAX_DRAIN_PER_TICK`
  still applies). The per-tick scan of all `MAX_ROOMS = 256` slots goes
  away, including the trailing hasPending re-scan in `actor.zig`.
- S16 policy, explicit: on budget/pool exhaustion the producer path
  (MPSC drain -> `handleRoomActorMessage`) bounces a `room_message` with
  an error to the sender and counts `mailbox_drops`; non-stanza actor
  messages (join/part/disco) get the actor retry list first because a
  lost `session_closed` leaves ghost occupants, matching the existing
  comment in Appendix C.

## Comptime actor codec (xworker/envelope.zig)

- `encode`/`decode` are generated at comptime from the `Message` union:
  fields serialize in declaration order; `[]const u8` -> u16-BE length +
  bytes, `u8/u16/u32/u64` -> BE integers, `bool` -> byte, `enum(u8)` ->
  byte, `Token` -> `writeU64(toUdata())`. The wire format is unchanged
  (same tag bytes, same field order), so peers on a mixed build still
  inter-operate; the existing round-trip tests pin it.
- `MAX_ENCODED_SIZE` becomes `BLOB_BUDGET`-bounded rather than 4080:
  actor messages that outgrew the slot (a MAM query with long `with`
  JIDs, a large `inner_xml`) stop being truncated by the slot and are
  bounded by the same per-worker blob budget; `encode` keeps returning
  failure on overflow so `enqueueRoomActorMessage` keeps its error path.
- Unused tags deleted: `session_bound`, `presence_available`,
  `presence_unavailable`, `message_received`, `message_routed`,
  `room_disco_items`, `pep_published`, `stanza_archived` (8 of 24 have no
  producer). Their decode dispatch branches go with them; `actor.zig`
  keeps `room_disco_info` only. `DiscoRequest`, `PresenceEvent`, etc.
  stay where a used tag shares the struct.

## Memory before and after

| object | before (resident) | after (resident) | after (in-flight bound) |
|---|---|---|---|
| worker MPSC ring | 256 x 4112 = 1,052,672 B | 256 x 48 = 12,288 B | + `BLOB_BUDGET_BYTES` per producer |
| room mailbox | 16 x 4080 + 32 = 65,312 B | 0 B idle | <= 262,144 B + 64 items per room |
| 256-room worker worst case | ~16.7 MB mailboxes | ~12.3 KB rings | bounded by item pool + byte budgets |

`BLOB_BUDGET_BYTES` default 4 MiB per producing worker; the number is a
config-adjacent constant written here so a future size change is a
one-line diff with its own measurement. Frames only go down: the
`mcast_buf: [4080]u8` producer stack buffers and the 4080 B slot memcpy
disappear; the stack-frame ratchet must show no NEW/GREW entries.

## Item order (one commit each)

1. Blob + Envelope ring + per-class counters (S14 fixed: cross-worker
   payload cap removed; `dropOversize` deleted).
2. DeliveryClass set + consumer-side class filters (V14).
3. Per-class QueueFull policies + actor retry list.
4. Room mailbox heap deque + byte budget + pending-room list (S16).
5. Comptime codec + unused-tag deletion.
6. SM replay queue shares blobs (sm_unacked entries hold `*Blob`).
7. Rig run + report.

## Tests (each must FAIL when its production change is reverted)

- `deliver.zig`: a >4080 B stanza across workers is delivered (S14);
  reverting the blob path returns `error.PayloadTooLarge` and the test
  fails.
- `ring.zig`: multicast to N target workers serializes once; a
  serialization counter proves one `Blob` produced and N descriptors
  published.
- `mailbox.zig`/`actor.zig`: a full room mailbox bounces the sender with
  an error stanza and bumps `mailbox_drops` (S16); the pending list
  drains a busy room without scanning empty slots.
- `deliver.zig`: a chatstate stanza to a remote session with CSI inactive
  is dropped by the consumer filter (V14), and a carbon to a remote
  non-carbons session is too.
- `ring.zig`: QueueFull on each class takes its policy outcome and
  increments its counter.
- `envelope.zig`: the comptime codec round-trips every union tag.
- `sm_state.zig`: an SM replay queue entry references a shared blob and
  survives alongside a second reference taken by a room mailbox.
