# xmppd Storage Design

Dual-role storage: an operational engine for bounded, read-heavy data and
an archive engine for unbounded, append-heavy message history, both
behind a unified comptime backend interface that allows any shipped
backend for either role.

---

## 1. Design Principles

- **Library, not daemon** - Storage is linked directly into each binary.
  No IPC overhead.
- **Comptime backend selection** - Zero runtime dispatch. Build flags
  select engines.
- **Two storage roles** - Operational and archive are independent, each
  with their own engine.
- **Works out of the box** - `pkg install xmppd` -> add user -> start.
  Zero config.

## 2. Engines and Build Flags

| Role | Default | Alternatives |
|------|---------|--------------|
| **Operational** (users, rosters, offline pointers, vcards, rooms, blocklist, PEP, locks, invites, OIDC bindings) | LMDB | RocksDB, SQLite |
| **Archive** (MAM for 1:1 and MUC) | RocksDB | LMDB, SQLite |

Any shipped engine can serve either role. In-memory `MemoryBackend`
exists for tests only. There is no flat-file or SQL-server backend.

```sh
zig build -Dop-storage=lmdb -Darchive-storage=rocksdb     # default
zig build -Dop-storage=sqlite -Darchive-storage=sqlite     # all-SQLite
zig build -Dop-storage=lmdb -Darchive-storage=lmdb         # all-LMDB
```

Backend choice is compile-time only; there is no `[storage]` config
section. The LMDB map size is set by `[server] lmdb_map_size_mb`
(default 8192 MiB, fixed at open; a map above 80 percent used logs a
warning to raise it before `MDB_MAP_FULL`).

## 3. Why Two Roles

| | Operational Data | Message Archive |
|-|------------------|-----------------|
| **Growth** | Bounded (proportional to users) | Unbounded |
| **Access** | Random read-heavy | Append-heavy + range scan |
| **Latency** | Sub-millisecond (hot path) | Tens of ms acceptable |
| **Ideal engine** | B+ tree (LMDB) | LSM tree (RocksDB) |

## 4. The Engines

### LMDB
- Memory-mapped B+ tree; roster lookups are pointer dereferences.
- Crash-safe via copy-on-write (no WAL needed).
- Linked through `nDimensional/zig-lmdb` v0.3.2 (`build.zig.zon`).
- `cross_process_claims = true`: conditional writes serialize across
  processes, which the OIDC binding claim requires.

### RocksDB
- LSM tree for append-heavy + range-scan workloads.
- LZ4 block compression enabled at open.
- Linked against system `librocksdb` (`databases/rocksdb` in ports) via
  the C API.
- `cross_process_claims = false`: `putIfAbsent` is ordered by an
  in-process mutex, so `xmppd-auth-oidc` refuses to start when the
  operational backend is RocksDB.

### SQLite
- In FreeBSD base; zero external deps; single file.
- `cross_process_claims = true`.

### Memory isolation

LMDB env maps are excluded from core dumps (`madvise(MADV_NOCORE)` in
`LmdbBackend.open`), so touched LMDB pages never land in a core file.
RocksDB block cache and memtables are heap memory and still appear in
cores. On `ENOMEM` at map-lookup the open retries (vmmap exhaustion can
be transient).

## 5. Layout

```
{db}/auth/      User credentials, locks, invites, OIDC bindings.
                Opened by xmppd-auth / xmppd-auth-oidc and xmppctl on
                the operational backend.
{db}/op/        Everything else operational: rosters, offline pointers
                and held payloads, vcards, rooms, affiliations,
                blocklist, PEP, lastact, pending_sub.
                Opened by xmppd-core on the operational backend.
{db}/archive/   MAM messages and the by_contact index.
                Opened by xmppd-core on the archive backend.
```

The master creates the three directories at startup. Every env
creates every namespace in `canonical_namespaces`
(`src/store/backend.zig`) at open, so no worker ever creates a
container mid-operation; a store declares its namespaces through
`backend.registered()` and a name missing from the registry is a
compile error.

## 6. Backend Interface

`src/store/backend.zig` defines the contract; `assertBackend()` checks
it at comptime (duck typing, no wrapper struct):

```zig
open(path, OpenOptions) !Self          // read_only option for ctl/tools
close() void
get(allocator, ns, key) !?[]u8         // caller-owned copy; mmap is txn-scoped
put(ns, key, value) !void
delete(ns, key) !void
iterator(ns, prefix) Iterator          // prefix-bounded prefix scan
writeBatch() WriteBatch                // put / delete / get / putIfAbsent /
                                       // commit / abort
```

Domain stores are comptime-parameterized over the backend:

```zig
pub fn RosterStore(comptime Backend: type) type { ... }
```

`putIfAbsent` is the conditional write the OIDC localpart claim and the
invite replay guard build on; `cross_process_claims` declares whether a
backend serializes it across processes.

## 7. Data Model

### `{db}/auth` (operational backend)

| Namespace | Key | Value |
|-----------|-----|-------|
| `users` | `localpart` | `salt(32) \| stored_key(32) \| server_key(32) \| iter_count_be(4)` |
| `locks` | `username` | `lock_type(1) \| locked_epoch(4 BE)` |
| `invites` | invite code | `max_uses(2) \| current_uses(2) \| expires_epoch(4) \| created_epoch(4)` |
| `oidc_identities` | forward `s \|\| u16be(iss.len) \|\| iss \|\| sub`; reverse `l \|\| localpart` | forward -> `localpart`; reverse -> `u16be(iss.len) \|\| iss \|\| sub \|\| source(1) \|\| bound_at(8)` |

The `users` key is the RFC 7622 prepared localpart; xmppd-auth scans the
namespace at startup and refuses to start on a key that is not in
prepared form (`[auth] users_scan_limit` bounds the scan, default
100000).

### `{db}/op` (operational backend)

| Namespace | Key | Value |
|-----------|-----|-------|
| `rosters` | `owner\x00contact` | `subscription(1) \| ask(1) \| name_len_be(2) \| name \| group_count(1) \| {group_len_be(2) \| group}*` |
| `vcards` | `bare_jid` | vCard XML |
| `pep` | `user_bare_jid\x00node\x00item_id` | item payload XML |
| `blocklist` | `user\x00blocked_jid` | single zero byte |
| `lastact` | `bare_jid` | epoch seconds (8 BE) |
| `pending_sub` | `contact_bare\x00subscriber_bare` | raw subscribe presence XML (RFC 6121 §3.1.3 deferred delivery) |
| `rooms` | `room_jid` | serialized `RoomConfig` |
| `room_affiliations` | `room_jid\x00bare_jid` | affiliation byte |
| `offline` | legacy v1 pointer rows | readable; drained before v2 |
| `offline_v2` | `recipient\x00sequence_be(8)` | `timestamp_be(8) \|\| stanza_id_len_be(4) \|\| stanza_id \|\| from_jid` |
| `offline_hold_v2` | held-stanza payload rows | stanza bytes |
| `offline_hold` | legacy v1 hold rows | stanza bytes |
| `offline_seq` | per-recipient sequence | counter |
| `offline_hold_token` | `recipient\x00sequence_be(8)` dedup token | token |

### `{db}/archive` (archive backend)

| Namespace | Key | Value |
|-----------|-----|-------|
| `messages` | `bare_jid\x00timestamp_be(8)\x00stanza_id` | stanza XML |
| `by_contact` | `bare_jid\x00with_jid\x00timestamp_be(8)\x00stanza_id` | `stanza_id` |

- Timestamps are big-endian u64 so lexicographic order is chronological.
- The v2 `by_contact` key appends the stanza id so two messages from one
  contact in the same second no longer overwrite each other. v1 rows
  (`bare_jid\x00with_jid\x00timestamp_be(8)`) still answer `with`
  queries: the timestamp sits at the same offset and the stanza id lives
  in the value, so readers honor both formats. `xmppctl migrate-archive`
  rewrites the index on the v2 format.

### Offline delivery

The operational DB stores pointers and held payloads, not bulk stanza
queues:

1. A stanza for an unavailable user lands in the archive like any other
   MAM write.
2. A v2 pointer `(recipient, sequence) -> metadata` records it; a hold
   request additionally stores the stanza bytes under
   `offline_hold_v2` so a delivery holds its exact serialization.
3. On reconnect the consumer scans the recipient prefix, fetches each
   held payload or archive row, delivers, and deletes the pointers.
   Legacy v1 rows drain first.

The per-pointer `offline_hold_token` row collapses duplicate hold
requests from several resources or workers into one row. Pointer
sequences come from `offline_seq` so queue order survives restarts.

## 8. MAM (XEP-0313)

- Paginated read with RSM cursors, `with`-partner filtering through
  `by_contact`, and time-range filtering on the timestamp key.
- MUC history is the same store keyed on room JIDs.
- Retention is `ArchiveStore.deleteOlderThan(owner, cutoff)`: a bounded
  prefix scan plus a batch delete, oldest-first. It is a store
  primitive; no daemon schedules it and there is no config key.
- One writer thread (`archive_queue.zig`) owns all archive writes;
  workers enqueue deep-copied jobs. Write failures are counted, not
  dropped silently.

## 9. Tools

- `xmppctl migrate-precis --hosted-domain D [--apply] [--rename OLD NEW]`:
  plans and applies RFC 7622 key renames across every namespace;
  `migrate-precis.pending` in the db root marks an interrupted run,
  blocks daemons and writes, and resumes by rerun.
- `xmppctl migrate-archive --hosted-domain D [--apply]`: rebuilds the
  `by_contact` index on the v2 key format.
- `deluser --raw KEY --hosted-domain D`: offline exact-key delete across
  namespaces when an account cannot be addressed by its prepared form.

## 10. Implementation notes

- `get()` returns an allocator-owned `!?[]u8`; LMDB mmap pointers are
  only valid inside the read transaction.
- Named module imports (`@import("backend")`) are mandatory: one file
  cannot belong to two modules.
- The `roster_rev` reverse index never landed: forward prefix scans on
  `rosters` cover presence queries.
- Handler code is generic over the store type, not the backend type.
