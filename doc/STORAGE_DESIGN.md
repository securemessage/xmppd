# xmppd Phase 5 — Storage Subsystem (Final Design)

Dual-engine storage: LMDB for operational data (bounded, read-heavy) + RocksDB for message archives (unbounded, append-heavy), both behind a unified comptime trait interface that allows any backend for either role.

---

## 1. Design Principles

- **Library, not daemon** — Storage is linked directly into each binary. No IPC overhead.
- **Comptime backend selection** — Zero runtime dispatch. Build flags select engines.
- **Two storage roles** — Operational and archive are independent, each with their own engine.
- **User decides** — Any backend can be used for either role. We ship sensible defaults.
- **Works out of the box** — `pkg install xmppd` → add user → start. Zero config.
- **Postfix-inspired, not Postfix-complex** — Two roles (not per-table selection).

## 2. Defaults and Options

| Role | Default (MVP) | Also in MVP | Post-MVP |
|------|--------------|-------------|----------|
| **Operational** (users, rosters, offline, vcards) | LMDB | SQLite | PostgreSQL, MariaDB |
| **Archive** (MAM for DMs + MUC history) | RocksDB | SQLite | PostgreSQL, MariaDB |

Any engine can be used for either role. A user could run SQLite for both, or RocksDB for both, or LMDB for operational + PostgreSQL for archive — their choice.

### Build Flags

```sh
zig build -Dop-storage=lmdb -Darchive-storage=rocksdb     # default
zig build -Dop-storage=sqlite -Darchive-storage=sqlite     # all-SQLite
zig build -Dop-storage=lmdb -Darchive-storage=sqlite       # mix
```

## 3. Why Two Engines

| | Operational Data | Message Archive |
|-|-----------------|-----------------|
| **Growth** | Bounded (proportional to users) | Unbounded (grows forever) |
| **Access** | Random read-heavy | Append-heavy + sequential range scan |
| **Size** | KB per user | MB–GB per user over time |
| **Latency** | Sub-millisecond (hot path) | Tens of ms acceptable |
| **Ideal engine** | B+ tree (LMDB) | LSM tree (RocksDB) |

**Lesson from ejabberd:** Mnesia (their embedded DB) works for operational data but **corrupts at 2GB** for archives. Their own docs say "SQL backend is recommended" for mod_mam.

## 4. Why These Engines

### LMDB (operational default)
- 32KB object code. Postfix's default since v2.11.
- Memory-mapped B+ tree — roster lookups are pointer dereferences.
- Crash-safe via copy-on-write (no WAL needed).
- `databases/lmdb` in FreeBSD ports. Zig bindings: `nDimensional/zig-lmdb` v0.3.2 (targets 0.15.1).

### RocksDB (archive default)
- LSM tree — purpose-built for append-heavy + range-scan workloads.
- Built-in compression (Snappy/LZ4/Zstd) — XML messages compress 3-5x.
- Built-in TTL via CompactionFilter — retention policy is a config option.
- Column families for namespace isolation (archive data vs. indexes).
- Proven Raft log store (TiKV). Future clustering path.
- `databases/rocksdb` in FreeBSD ports. Zig bindings: `Syndica/rocksdb-zig` (targets 0.15).
- ~12MB added to binary size (acceptable — NATS is 20MB, Consul is 80MB).

### SQLite (MVP alternative for both)
- In FreeBSD base. Zero external deps.
- WAL mode handles concurrent access well.
- SQL makes range queries and retention cleanup natural.
- Good "I just want one DB file" option for small deployments.

## 5. Architecture

```
┌─────────────────────────┐   ┌─────────────────────────┐
│ xmppd-auth              │   │ xmppd-core              │
│  UserStore(OpBackend)   │   │  RosterStore(OpBackend)  │
│                         │   │  OfflineStore(OpBackend) │
│                         │   │  VCardStore(OpBackend)   │
│  ┌───────────────────┐  │   │  ┌───────────────────┐  │
│  │ OpBackend (LMDB)  │  │   │  │ OpBackend (LMDB)  │  │
│  └───────────────────┘  │   │  └───────────────────┘  │
└─────────────────────────┘   │                         │
                              │  ArchiveStore(ArchBackend)│
                              │  ┌───────────────────┐  │
                              │  │ArchBackend(RocksDB)│  │
                              │  └───────────────────┘  │
                              └─────────────────────────┘

/var/db/xmppd/
├── op/              # LMDB environment (operational)
│   ├── data.mdb
│   └── data.mdb-lock
└── archive/         # RocksDB directory (message archive)
    ├── 000003.sst
    ├── MANIFEST-000001
    └── ...
```

## 6. Comptime Trait Interface

```zig
/// Unified storage backend trait. Both LMDB and RocksDB implement this.
pub fn StorageBackend(comptime Impl: type) type {
    return struct {
        impl: Impl,

        pub fn open(path: []const u8, opts: OpenOptions) !@This() { ... }
        pub fn close(self: *@This()) void { ... }

        // Core operations
        pub fn get(self: *@This(), ns: []const u8, key: []const u8) !?[]const u8 { ... }
        pub fn put(self: *@This(), ns: []const u8, key: []const u8, val: []const u8) !void { ... }
        pub fn delete(self: *@This(), ns: []const u8, key: []const u8) !void { ... }

        // Range iteration (prefix scan — essential for both roster enum and MAM paging)
        // INVARIANT: Iterator is prefix-bounded. next() returns null when the
        // cursor key no longer starts with `prefix`. Each backend enforces this
        // internally so callers never leak data from adjacent namespaces.
        pub fn iterator(self: *@This(), ns: []const u8, prefix: []const u8) !Iterator { ... }

        // Batch writes (RocksDB WriteBatch, LMDB write txn)
        pub fn batch(self: *@This()) !WriteBatch { ... }
    };
}
```

Each domain store (UserStore, RosterStore, ArchiveStore, etc.) is parameterized:

```zig
pub fn RosterStore(comptime Backend: type) type {
    return struct {
        backend: *Backend,
        pub fn getItem(self: *@This(), owner: []const u8, contact: []const u8) !?RosterItem { ... }
        pub fn setItem(self: *@This(), owner: []const u8, item: RosterItem) !void { ... }
        // ...
    };
}
```

## 7. Data Model

### Operational (LMDB namespaces)

| Namespace | Key | Value |
|-----------|-----|-------|
| `users` | `username` | binary: `salt(32) \| stored_key(32) \| server_key(32) \| iter_count(4)` |
| `rosters` | `owner\x00contact` | binary: `subscription(1) \| ask(1) \| name_len(2) \| name` |
| `roster_rev` | `contact\x00owner` | `""` (reverse index for presence fan-out) |
| `offline` | `recipient\x00timestamp_be(8)\x00msg_id` | `""` (delivery flag — payload lives in archive) |
| `vcards` | `bare_jid` | vCard XML blob |
| `meta` | `schema_version` | version u32 |

### Archive (RocksDB column families)

| Column Family | Key | Value |
|---------------|-----|-------|
| `messages` | `bare_jid\x00timestamp_be(8)\x00stanza_id` | compressed stanza XML |
| `by_contact` | `bare_jid\x00with_jid\x00timestamp_be(8)` | `stanza_id` |
| `metadata` | `bare_jid` | `first_id \| last_id \| count` |

- Timestamps: big-endian u64 for lexicographic = chronological ordering
- Compression: RocksDB's built-in LZ4 at block level (transparent)
- Retention: RocksDB CompactionFilter deletes expired entries during compaction

### Offline Message Strategy

Offline stanza payloads are stored in the **archive** DB, not the operational DB.
The operational `offline` namespace holds only lightweight delivery pointers
(empty values keyed by `recipient\x00timestamp\x00msg_id`). On reconnect:

1. Scan `offline` prefix for the recipient → collect message keys
2. Fetch each stanza from the archive by `recipient\x00timestamp\x00stanza_id`
3. Deliver to client, then delete the offline pointer

This keeps LMDB strictly bounded and lean — no unbounded stanza XML accumulating
in the operational B+ tree. LMDB's B+ tree does not reclaim disk space on deletion
(freed pages are reused internally), so keeping large payloads out prevents the
operational DB file from growing permanently due to offline message churn.

## 8. XEP-0313 (MAM) — The "Slack Scrollback"

MAM is a stable XMPP standard providing:
- **Infinite scrollback** for both 1:1 DMs and MUC rooms
- **Cursor-based pagination** via RSM (XEP-0059)
- **Filtering** by time range, conversation partner, or ID range
- **Multi-device sync** combined with Carbons (XEP-0280) + Stream Management (XEP-0198)

MUC history is MAM applied to room JIDs — same storage, same query API.

### Retention
- **Default: indefinite** (Slack/Matrix model)
- **Configurable:** `archive_retention = 365d` or `archive_retention = unlimited`
- **No gaps:** Per spec, deletions must be oldest-first (§3.2)

## 9. Migration

```sh
# Flat-file → LMDB (one-time upgrade)
xmppctl migrate --from-flat /var/db/xmppd-users.db --to /var/db/xmppd/op/

# Offline messages move to archive (consolidation)
xmppctl archive-import --from-offline /var/db/xmppd/op/
```

Flat-file backend remains available as `-Dop-storage=flatfile` for backward compatibility.

## 10. Implementation Order

| Step | What | ~LOC |
|------|------|------|
| **10a** | `src/store/backend.zig` — comptime trait interface + Iterator + WriteBatch | 150 |
| **10b** | `src/store/lmdb.zig` — LMDB backend impl (zig-lmdb dep) | 350 |
| **10c** | `src/store/rocksdb.zig` — RocksDB backend impl (rocksdb-zig dep) | 400 |
| **10d** | `src/store/flatfile.zig` — Wrap existing flat-file stores | 200 |
| **10e** | Migrate `UserStore` → `UserStore(Backend)` | 150 |
| **10f** | Migrate `RosterStore` → `RosterStore(Backend)` | 200 |
| **10g** | Migrate `OfflineStore` → `OfflineStore(Backend)` — pointer in op DB, payload in archive | 200 |
| **10h** | New: `VCardStore(Backend)` | 100 |
| **10i** | New: `ArchiveStore(Backend)` — MAM write + paginated read + retention | 500 |
| **10j** | MAM query handler in core (XEP-0313 IQ handling + RSM pagination) | 400 |
| **10k** | `src/store/sqlite.zig` — SQLite backend impl | 350 |
| **10l** | `build.zig` — `-Dop-storage` + `-Darchive-storage` flags, zig-lmdb + rocksdb-zig deps | 80 |
| **10m** | `xmppctl migrate` + `xmppctl archive-import` | 200 |
| **10n** | Tests: each backend × each store + MAM query pagination | 600 |

**Total: ~3,830 LOC**

### Suggested execution order
1. Trait interface (10a) → LMDB backend (10b) → migrate UserStore (10e) — proves the pattern
2. RosterStore (10f) → VCardStore (10h) — operational stores (no archive dependency)
3. RocksDB backend (10c) → ArchiveStore (10i) → MAM handler (10j) — archive layer
4. OfflineStore (10g) — depends on ArchiveStore (pointers in op DB, payloads in archive)
5. SQLite (10k) → flat-file compat (10d) → migration tooling (10m)
6. build.zig integration (10l) → comprehensive tests (10n)

## 11. Build Integration

```zig
// build.zig
const op_storage = b.option([]const u8, "op-storage",
    "Operational storage: lmdb (default), sqlite, flatfile") orelse "lmdb";
const archive_storage = b.option([]const u8, "archive-storage",
    "Archive storage: rocksdb (default), sqlite") orelse "rocksdb";
```

The zig-lmdb and rocksdb-zig packages both bundle their C/C++ sources and compile from source via the Zig build system. No system library dependencies for the default build. FreeBSD ports can optionally link against system libraries.

## 12. User Experience

### Self-hosted (zero config, defaults)
```sh
pkg install xmppd
xmppctl adduser alice@example.com
service xmppd start
# LMDB for ops, RocksDB for archive — just works
```

### Mixed backends (config file)
```ini
# xmppd.conf
[storage]
operational = lmdb
operational_path = /var/db/xmppd/op

archive = rocksdb
archive_path = /var/db/xmppd/archive
archive_retention = unlimited
# archive_compression = lz4
```

### All-SQLite (simple)
```sh
zig build -Dop-storage=sqlite -Darchive-storage=sqlite
```
```ini
[storage]
operational = sqlite
operational_path = /var/db/xmppd/xmppd.db
archive = sqlite
archive_path = /var/db/xmppd/archive.db
```

### Scaled (PostgreSQL, post-MVP)
```ini
[storage]
operational = lmdb
operational_path = /var/db/xmppd/op
archive = postgresql
archive_dsn = postgresql://xmppd:pass@db/xmppd_archive
```

## 13. Open Questions

1. ~~**zig-lmdb** v0.3.2 targets Zig 0.15.1~~ — **RESOLVED:** builds clean on 0.15.2
2. **rocksdb-zig** (Syndica) targets Zig 0.15 — verify FreeBSD cross-compile of C++ sources via Zig build
3. ~~**LMDB map size**~~ — **RESOLVED:** auto-resize on `MDB_MAP_FULL` implemented (3 retries, double map size)
4. ~~**Value serialization**~~ — **RESOLVED:** compact binary: users=100B packed, roster=4+name_len, vcard=raw XML
5. **Archive stanza format** — store verbatim XML (spec-compliant) with RocksDB block compression
6. **Config file format** — INI (shown above) vs. TOML vs. custom. Postfix uses `main.cf` (key=value). INI is simplest.

## 14. Implementation Notes

- **Trait pattern diverges from §6:** Implementation uses `assertBackend()` comptime validation + duck typing rather than the `StorageBackend(Impl)` wrapper. Simpler, same zero-cost result.
- **`get()` takes allocator:** Returns allocator-owned `!?[]u8`. Caller frees. Needed because LMDB mmap pointers are only valid during the read transaction.
- **Named module imports:** Use `@import("backend")` not `@import("backend.zig")` — Zig disallows a file belonging to two modules when referenced via both paths.
- **AuthHandler generic over Store type** (not Backend) — handler doesn't know or care about the storage engine, only the store interface.
- **`roster_rev` deferred:** Forward prefix scan on `owner\x00` in the `rosters` namespace handles all current presence queries. Reverse index for inbound presence probes can be added later.
