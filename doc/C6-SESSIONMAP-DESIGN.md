# C6: SessionMap v2 (ADR-4 items 2-5)

Design note for plan item C6 (doc/T197_QUALITY_SWEEP.md ADR-4 and section 5.5;
Continuum T-5737697D; Phorge T395; structural for S18, T305, T268, T254).
ADR-4 item 1 (generational tokens) landed as C3; this note covers items 2-5:

1. A normalized `Jid` value (case-folded domain, precomputed full and bare
   hashes) computed once at bind or ingress and hashed outside the lock;
   `HashMapUnmanaged` with a precomputed-hash context; one entry store plus a
   bare index of entry ids (no duplicated `SessionEntry` kept in sync by
   hand).
2. Lock sharding by bare-JID hash (per-shard `RwLock`); no logging under any
   shard lock.
3. Copy-out fan-out API `collectAvailable(bare, out)`; no fixed result
   buffers (S18).
4. `Session` caches its full and bare JID strings at bind.

## Scale litmus (skill section 0)

1. Execution model: unchanged, thread per core. Each worker owns its
   connections, sessions and queues. C6 changes how the shared routing table
   is indexed, not the model.
2. Linear scaling: the one global `RwLock` on the route lookup path is the
   shared state this item removes. After C6 the table is sharded by bare-JID
   hash; a lookup, bind, unbind or presence update touches one shard's
   `RwLock`. A writer stalls a reader only on a same-shard collision
   (~1/shards of accounts), down from every writer stalling every reader.
   Hashing happens before the lock is taken, so no hash CPU time is spent
   inside a critical section. No new hot-path atomics.
3. Shared resources: the map is the only shared routing table. Reads and
   writes reach it directly under the owning shard's lock; delivery itself
   flows through the existing per-worker rings. The allocator stays the
   process `smp_allocator` (sharded, thread-safe); key/entry allocations are
   per-bind (a cold path relative to stanza routing).
4. Nothing blocks a loop: no new blocking work enters any lock. A collect
   hold does bounded work only (index probe plus a `SessionEntry` memcpy);
   callers serialize, enqueue, deliver and log on the copies after the
   lock is released, so no shard hold ever covers delivery or a failure
   path. Logging moves outside the lock (Q5).
5. Connection economics: per bound resource the map keeps one heap key
   (~bare+full bytes once) and one `SessionEntry` (~104 B) instead of a key
   plus two duplicated entries and a 16-slot inline array head. A bare JID
   with R resources costs one bare key plus R pointers. Idle accounts cost
   nothing.
6. Many requests per connection: unchanged.
7. Beyond one host: unchanged (s2s addressing is by JID either way).
8. Expensive operations priced: JID hashing and case-folding are O(JID
   bytes), done once per call outside the lock. Collect fan-out work is
   O(resources of one account), bounded by `max_resources_per_account`
   (config, default 256).
9. Overload behavior: the resource cap is unchanged and fails closed with
   `TooManyResources`; the T254 rollback invariants are kept and tested.
10. Measured: the existing module tests plus the full Debug and ReleaseSafe
    suites cover correctness; the S18 batch regression test (640 entries
    across 32 accounts) is kept through per-JID collects.

## Layouts

### Normalized key (ADR-4 item 2)

```zig
pub const Key = struct {
    /// "local@domain/resource" (or "local@domain" when resource is empty),
    /// domain part ASCII-lowercased at build time (T305).
    bytes: []const u8,
    /// Length of the bare JID prefix inside `bytes`.
    bare_len: u16,
    full_hash: u64,
    bare_hash: u64,
};
```

- `Key.initBuf(&buf, local, domain, resource)` writes the normalized string
  into a caller stack buffer and computes both Wyhashes there, before any
  lock. Every public entry point builds a stack `Key` first; map operations
  then do no hashing under a lock.
- The localpart and resource are not folded: the localpart's spelling is
  owned by the RFC 7622 UsernameCaseMapped preparation at ingress, and the
  resource is case-sensitive.
- `Key.dupe` heap-copies the bytes for storage; the map owns stored keys
  and frees them on unbind/deinit.

### One entry store plus a bare index (ADR-4 item 2, T268, T254)

Per shard:

```zig
full_map: std.HashMapUnmanaged(Key, *SessionEntry, FullCtx, 80),
bare_map: std.HashMapUnmanaged(Key, EntryList, BareCtx, 80),
```

- `FullCtx.hash` returns `key.full_hash`, `eql` compares `key.bytes`.
  `BareCtx` does the same on `bare_hash`/`bare()`.
- `SessionEntry` is one heap object per bound resource. `full_map` is both
  the exact-JID index and the ownership index; `bare_map`'s `EntryList`
  holds `*SessionEntry` (entry ids), so the same account's resources are
  found from one bare key.
- `setPresenceState(local, domain, resource, available, prio)` covers the
  common "set both" case in one exclusive hold, one lookup, one object
  mutated (T268's two locks and inner re-lookup are gone by construction).
  The granular `setPresenceAvailable` and `setPriority` setters are kept
  for the call sites that change only one field.
- T254 rollback is preserved: a `TooManyResources` append failure on a
  fresh bare entry removes the entry and frees its key; a `full_map.put`
  failure backs out the bare append. The OOM-path test still walks every
  allocation point.

### Sharding (ADR-4 item 3)

```zig
shards: []Shard,
shard_mask: usize, // shard_count - 1, shard_count is a power of two
```

- `shard = key.bare_hash & shard_mask`. Every JID of one account resolves
  to one shard; full-JID operations derive their shard from the same bare
  hash so a bind and a later unbind always meet.
- Shard count derives from the configured worker count: `pow2ceil(8 x
  workers)`, clamped to [8, 256]; 1 shard when `workers == 1` (locks then
  never taken, same as today's `multi_worker` fast path). The bound is
  config-derived: workers come from `[core] workers`, and 8 shards per
  worker keeps a fan-out's lock hold from colliding with a same-shard
  writer except on ~1/shard_count of accounts. Memory: 256 shards x the
  two empty maps is a few KiB at startup.
- `multi_worker` is derived as `workers > 1` and `init` takes
  `(allocator, workers, max_resources)`.
- No logging under any shard lock: `bind`/`unbind` log after the lock is
  released, which also removes the write(2) the sweep flagged under the
  exclusive lock (Q5 piece).
- Re-entrancy is asserted: a thread-local hold depth checked at lock
  acquisition panics in safe builds on any nested hold, since a nested
  hold can deadlock across shards.

### Copy-out fan-out API (ADR-4 item 4, S18)

```zig
pub fn collectBound(self, local, domain, out: []SessionEntry) usize
pub fn collectAvailable(self, local, domain, out: []SessionEntry) usize
```

- Under one shared-lock hold the map copies the account's `SessionEntry`
  values into the caller's buffer and returns the count. The locked
  section only selects and copies bounded routing state; the caller then
  iterates the copies to serialize, enqueue, deliver and log, so delivery
  and its failure paths never extend a shard hold.
- `out` must have room for the per-account resource cap: the bind path
  caps each account's entry list there, so a `max_resources` buffer always
  receives the complete fan-out. Each Server keeps a lazily grown
  `fanout_entries` scratch at that bound for its fan-out sites, grown on
  the `delivered_targets` pattern.
- The token in a copied entry stays authoritative: the owning worker still
  validates generations at delivery (`sessionForEventToken`, cross-worker
  slot dispatch), so an unbind between copy and delivery resolves to a
  counted stale-token skip exactly as a mid-iteration removal did before.
- T130 presence batching keeps its shape: callers chunk JIDs and collect
  per JID (one shared-lock hold per JID's shard), then deliver each JID's
  copies; remote workers still get one pipe wake per chunk.
- `findByFullJid` keeps its signature (one entry copied out is a point
  lookup, not a result buffer). `hasBound(local, domain)` replaces the
  `[1]SessionEntry` probes; `isAvailable` stays.
- `findByBareJid`, `findAvailableByBareJid` and
  `findAvailableByBareJidBatch` are deleted, and with them the worker
  scratch-entry banks (`scratch_entries_a/b/c`, `scratch_ids_a`,
  `scratch_jid_idxs_a`, `leaseScratch`, `growScratch`). The S18 640-entry
  batch test runs on per-JID collects.

### Cached bound JID strings (ADR-4 item 5)

- `Stream` gains `bound_jid_buf: [jid.max_jid_octets]u8` plus
  `bound_full_len`/`bound_bare_len` and the `boundFull()`/`boundBare()`
  views; `boundFull` is "local@domain/resource" and `boundBare` its bare
  prefix. Both assert the stream is bound.
- `setBoundJid(?Jid)` is the only writer of `bound_jid`. It formats the
  strings into `bound_jid_buf` once and repoints the stored `Jid`'s part
  slices into that buffer, so callers can pass JIDs borrowed from parse or
  bind scratch that dies before the session does. `null` unbinds and clears
  the cached lengths. A JID too large for the buffer is a caller bug:
  `handleBind` and parse reject oversized parts before this point, so the
  setter asserts rather than absorbing it.
- Sites that hand-built `local@domain`/`local@domain/resource` from
  `stream.bound_jid` switch to the cached strings: the IQ header writers
  (`writeIqHeader`, `writePepIqHeader`, `writeSessionJid`, the bind result
  and IQ error `to=`), the roster/vCard/PEP/blocklist/last-activity store
  keys, the MUC owner/moderator/participant JIDs, the SM-replay occupant
  moves, the cross-worker bounce, offline delivery and the presence
  fan-outs. `bound_jid` stays pub-readable for part-wise access
  (SM lookups, comparisons); only the setter writes it.
- Behavior change worth noting: the deleted scratch buffers capped the
  formatted bare JID at 512 bytes and the full JID at 1024; the bound cache
  holds the RFC 7622 limits (bare 2047, full 3071), so over-512-byte bound
  bares now flow where they used to be skipped. Downstream bounded buffers
  still guard: store keys reject over 511 bytes, stanza and scratch buffers
  fail the build and count the drop the same as before.

## Commit order

1. This note.
2. Normalized `Key`, `HashMapUnmanaged` contexts, single entry store +
   bare index, `setPresenceState`, logging moved out of the lock; storage
   rewrite keeps the current public API so call sites still compile.
3. Shard the lock and maps.
4. Visitor API; delete the buffer APIs, the scratch banks and convert all
   call sites.
5. Cached bound JID strings in `Stream` + call-site conversion.
