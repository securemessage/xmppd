# xmppd Architecture

## Overview

xmppd is a multi-process XMPP server inspired by Postfix's design
philosophy: one package, one config, one service - complexity is
internal. FreeBSD only (kqueue, `SO_REUSEPORT_LB`, `LOCAL_PEERCRED`).

## Process model

```
                +----------------------------+
                |       xmppd (master)       |
                |  event loop, supervisors,  |
                |  fd passing, signals       |
                +--+-----------+-----------+-+
                   |           |           |
        +----------+  +--------+  +---------+
        |             |                 |
+-------+-------+ +---+---------+ +-------+--------+
|  xmppd-core   | | xmppd-auth  | |   xmppd-s2s    |
|  N workers on | |    or       | |  federation,   |
|  lib/net loop | |xmppd-auth-  | |  DANE, dialback|
|               | |  oidc       | |                |
+-------+-------+ +-------------+ +----------------+
        |  auth.sock (IPC)  s2s.sock (IPC)
```

| Process | Role | Privilege |
|---------|------|-----------|
| `xmppd` | Master. Binds the c2s and s2s listeners while privileged, spawns the children with the fds remapped to 3.., watches them on its own kqueue loop, escalates shutdown to SIGKILL on a deadline, reaps orphans by identity check, writes `{run_dir}/xmppd.pid`. | root; children run as `[server] user` |
| `xmppd-core` | Hot path. c2s sessions, TLS, XML, stanza routing, presence, MUC, IQ dispatch, storage. | unprivileged |
| `xmppd-auth` | SASL SCRAM-SHA-256 + PLAIN, rate limiting, lockout, registration, password change. | unprivileged |
| `xmppd-auth-oidc` | Alternative auth daemon. OAUTHBEARER (JWT) + PLAIN via IdP delegation; same IPC contract as xmppd-auth. | unprivileged |
| `xmppd-s2s` | Federation. Outbound and inbound s2s, STARTTLS, DANE, SASL EXTERNAL, dialback. | unprivileged |
| `xmppctl` | Admin CLI. Talks to the auth daemon over IPC when it is up, else opens the DB directly. | operator |

### The master

`src/master/` splits into `main.zig` (argument/config resolution,
privilege-drop decision, listener setup), `runtime.zig` (the
single-threaded kqueue loop: readiness pipes per child, respawn, timed
SIGKILL escalation, SIGHUP forwarding only to children that declare
`forward_hup`), `supervisor.zig` (per-child spawn/exec/fd contract) and
`procinfo.zig` (identity checks for orphan cleanup). No NSS lookups or
pid-file I/O happen on the runtime loop.

## lib/net: the shared event-loop substrate (ADR-8)

All daemons build on `lib/net` (`lib/net/net.zig`), a FreeBSD-only
substrate:

- `loop.zig` - `Loop`: one kqueue per thread; all interest changes stage
  in a `ChangeList` and land in a single `kevent()` per iteration.
  Timers are deadlines (`TimerWheel`), never I/O drivers. Signals arrive
  as `EVFILT_SIGNAL` events.
- `conn.zig` - `Transport` (plain or `Tls`), `Inbox`, `Outbox`, kTLS
  policy and probes. `want_*` retries present the identical (ptr, len)
  the Outbox pin keeps.
- `frame.zig` - `FrameReader`/`FrameWriter`: the length-prefixed framing
  every IPC peer shares (drains to EAGAIN, oversize header is a protocol
  error).
- `token.zig` + `slotmap.zig` - `Token` is a `packed struct(u64)` of
  `index: u32, gen: u24, kind: u8`; `SlotMap` issues generational tokens
  so a stale handle can never address a reused slot.
- `wake.zig` - `Wake` (coalescing `EVFILT_USER`) and `Broadcast`
  (cross-loop fan-out).
- `bind.zig` - `bindTcp`/`bindUnix` and the accept-draining `Listener`.

Only `Token` values, detached fds, `*Wake` and `*Broadcast` may cross
threads; everything else is owned by its loop thread.

## xmppd-core

### Worker model

The master creates one c2s socket per worker (`SO_REUSEPORT`) and execs
xmppd-core once; `src/core/main.zig` spawns one thread per inherited
listen fd (the last runs on the main thread). Each worker owns an
independent `Server` (`src/core/worker/worker.zig`): its own kqueue
loop, connection table, sessions, `RoomRegistry` and counters.
`[core] workers` sets the count (auto = CPUs, cap 64); `[core]
max_sessions` is divided evenly across workers.

Storage backends open once on the main thread and are shared by all
workers; the backend implementations are thread-safe. A single archive
writer thread (`archive_queue.zig`) owns all MAM writes: workers enqueue
bounded deep-copy jobs so a compaction stall never blocks a loop.
Per-worker counters dump on SIGUSR1.

### Module layout (ADR-12)

```
src/core/
  worker/{loop,metrics,worker}.zig   per-worker Server, loop, counters
  c2s/{session,lifecycle,sm,sm_handoff,sm_state}.zig
                                     connection FSM, XEP-0198
  stanza/{writer,facts}.zig          StanzaWriter serializer, ingress
                                     prepared-JID facts (F6)
  routing/{address,router,deliver}.zig
  xworker/{envelope,ring}.zig        cross-worker delivery (see below)
  presence/{broadcast,handler,subscription}.zig
  muc/{actor,fanout,handler,mailbox,registry}.zig
  iq/{dispatch,carbons}.zig          namespace-dispatched IQ handlers
  session_map.zig  caps.zig  subscription_cache.zig
  connection.zig  listener.zig  archive_queue.zig
```

### The Outbox and the end-of-iteration flush (ADR-2)

Session writes never `send()` directly. Stanzas serialize into the
connection's `Outbox` (a ring with a heap spill for overflow), the
connection is marked dirty, and `Server` drains every dirty outbox in
one pass at the end of the loop iteration (`flushDirtyOutboxes`). A
stalled connection stops consuming reads (backpressure) instead of
growing memory; a bounded queue protects the spill.

### SessionMap and generational tokens

`src/core/session_map.zig` is the single JID-keyed routing table: full
JID to `SessionEntry` (`worker_id`, `local_session_id`, `generation`),
plus a bounded bare-JID index for multi-resource delivery. All locking
is internal; a `multi_worker` flag removes lock cost in single-worker
mode. The generation stamps every entry, and every cross-worker delivery
carries the generation the producer saw: a delivery that arrives after
disconnect and slot reuse is dropped, so a stale message can never reach
the wrong session (ABA protection, ADR-4).

### Cross-worker delivery (xworker)

`xworker/ring.zig` gives each worker a bounded MPSC ring of fixed
4080-byte slots. Producers reserve a slot by CAS, `memcpy` the payload
and publish a release flag; on the `wake_pending` edge they write one
byte to the target's pipe, so a burst costs one wakeup per drain cycle.
`xworker/envelope.zig` defines the actor vocabulary (`SessionBound`,
`SessionClosed`, stanza deliveries, MUC moves) and its wire codec; actors
exchange these messages only, never shared pointers. Oversized payloads
are counted in `cross_worker_drops` and the M1 dump exports all
drop counters.

### MUC

Each worker owns a `RoomRegistry` sharded by `roomOwner(room_jid,
worker_count)`; a room's state changes only on its owning worker, with
mailbox delivery for the rest. Occupant fan-out yields every
`fan_out_batch_size` rooms members per tick so large rooms cannot
starve the loop. Persistent rooms write through `RoomStore`; transient
rooms live in memory only.

### Presence and IQ

`presence/` handles broadcast, probes and subscriptions (including the
`pending_sub` store); `iq/dispatch.zig` routes on the query namespace to
the handlers (roster, MAM, PEP, vCard, blocking, register, disco, last,
carbons).

## IPC

Core talks to auth on `[auth] socket` and to s2s on `[s2s] socket`, both
Unix domain sockets with the shared framing: `u32le length | u8 tag |
fields`, read and written through lib/net `FrameReader`/`FrameWriter`.
Auth tags: AuthRequest 0x01, AuthChallenge 0x02, AuthSuccess 0x03,
AuthFailure 0x04, SaslResponse 0x05, Register 0x06/0x07,
PasswordChange 0x08/0x09, AccountDelete 0x0A/0x0B, MechanismList 0x0C.

## Auth daemons

`src/auth/runner.zig` is the shared event loop for both auth daemons:
the IPC listener and client lanes (accept, generations, intake
backpressure at 768/256 KiB watermarks, coalesced flush), plus signal
handling. Per-daemon `Hooks` own the store, the worker-pool drain and
message interception; the OIDC daemon parks IdP-bound requests in
`intercept` and answers them from `onPoolWake`.

`src/auth/` splits into `mech/` (SASL mechanisms), `account.zig`,
`policy.zig`, `rate_limiter.zig` (bounded hash tables, temporary and
permanent lockout), `crypto_pool.zig` (PBKDF2 derivation off the loop,
default 4 threads), `handler.zig` and `user_store.zig`.
`xmppd-auth-oidc` adds `oidc.zig`/`oidc_main.zig`: JWT validation against
the IdP JWKS, an IdP exchange pool (threads/outstanding/timeout keys
under `[oidc]`), and `(iss, sub)` account binding in
`oidc_identity_store`.

## s2s and DANE-first TLS

`src/s2s/` (`main`, `connector`, `session`, `stream`, `dialback`) runs
the same lib/net loop for both directions. Name resolution goes through
the shared async resolver `lib/dns/async.zig` with a bounded cache and
serve-stale (ADR-13): per-target `tlsa_status` decides verification -
matching TLSA records verify through the shared `dane` package
(a `build.zig.zon` dependency), TLSA present-but-unmatched fails the
target, authenticated absence falls back to PKIX, and a failed lookup is
a temporary failure of that target, retried with backoff (5/15/45 s,
120 s queue lifetime) instead of bouncing queued stanzas. TLS context
comes from `lib/tls` (`ssl.zig`/`tls.zig`), which probes and logs kTLS
engagement after the handshake.

## Storage

Storage is a library linked into each binary, not a daemon. Two
independent roles, each bound to a backend at build time
(`-Dop-storage`, `-Darchive-storage`; LMDB, RocksDB or SQLite):
operational (`{db}/op`) and archive (`{db}/archive`); the auth daemons
open `{db}/auth` on the operational backend. Domain stores
(`UserStore`, `RosterStore`, `OfflineStore`, `VCardStore`,
`ArchiveStore`, `RoomStore`, `BlockStore`, `PepStore`, `LockStore`,
`InviteStore`, `OidcIdentityStore`, `LastActivityStore`) are comptime
parameterized over the backend trait in `src/store/backend.zig`.
See `doc/STORAGE_DESIGN.md` for the data model.

## Configuration

All daemons share one INI file and one schema
(`src/config/schema.zig`, ADR-9): a `Sections` struct whose field
initializers are the only defaults, plus a `file_spec` table that gives
each key its section, aliases, `in_file` flag and help text. Every
daemon loads the full table through the `lib/conf` loader with its own
CLI table (`MasterLoader`, `CoreLoader`, `S2sLoader`, `AuthLoader`,
`OidcLoader`, `CtlLoader`), so one file serves all of them; a key or
section the schema does not name, a bad value or a malformed line is a
startup error with a `file:line` diagnostic. The legacy
`src/config/parser.zig` remains only for its test suite.

Precedence is default < file < forwarded < CLI, tracked per field as
provenance (`conf.Source`). The master resolves the file and its own
flags, then serializes the effective values once into a sealed
anonymous fd (`conf.ConfFd`) that `xmppd-core`, `xmppd-s2s`,
`xmppd-auth` and `xmppd-auth-oidc` inherit through the `pass_fds`
remap, named on their argv as `--conf-fd N`. Child argv then carries
only fd remap slots (`--listen-fd`, `--conf-fd`); a child started by
hand reads `--config` directly. On SIGHUP the master reloads the file,
rebuilds the fd, then forwards the signal, so a respawned child sees
fresh values and no supervised child re-reads the file.

`doc/CONFIGURATION.md` is rendered from the same schema
(`zig build docs-config`), so the documented keys, defaults and
`--help` output cannot drift from the loader.

## Security model

- STARTTLS mandatory for c2s authentication; TLS 1.3 on both c2s and
  s2s; kTLS offloads the record layer on FreeBSD (see AGENTS.md rules).
- DANE-first verification on s2s (TLSA primary, PKIX only on
  authenticated absence).
- Auth is a separate process: SCRAM-SHA-256 plus channel binding
  plumbing (XEP-0440, not negotiated), rate limiting per account and per
  IP, temporary and permanent lockout.
- OIDC accounts bind to `(iss, sub)`, never to mutable claims.
- Registration is gated by invitation codes.
- Privilege separation: master runs as root and every child drops to the
  configured user; children inherit only the fds they need.

## Failure accounting

No silent drops on the data path: cross-worker overflows, offline
failures, oversize payloads and IPC backpressure are counted on
atomics exported by the per-worker SIGUSR1 dump.
