# lib/net design (F2 core, ADR-8)

Status: API proposal for review (STOP POINT of task T-B59BC9A1). No implementation
exists yet. F3 (`conn`, `frame`, TLS) builds on this and is out of scope here.

Evidence tags: **[src]** read in `/usr/src/sys` or Zig 0.15.2 std on freebsd-dev1;
**[V]** read in this repository; **[infer]** reasoning, to be proven by the tests listed.

## 1. Scope and layout

```
lib/net/
  net.zig           root module, re-exports the public API below
  token.zig         Token (ADR-4)
  slotmap.zig       SlotMap(T): fixed-capacity generational table
  kevent.zig        hardened kevent(2) wrapper over std.c.kevent
  loop.zig          Loop: kqueue, interest reconciliation, events, signals, processes
  wake.zig          Wake (EVFILT_USER, coalescing), Broadcast (pipe close for N loops)
  timer_wheel.zig   TimerWheel: lifecycle deadlines, O(1) cancel
  bind.zig          bindTcp, bindUnix, Listener (accept drain, pause and resume)
tools/net_loop_bench.zig   loop iteration micro-benchmark (`zig build bench-net-loop`)
```

Build registration: one `net_mod` (`lib/net/net.zig`) and a `net-tests` test artifact
added to the existing `test` step, plus `bench-net-loop` next to `bench-xml-escape`.
No daemon imports `net_mod` in this PR; `src/` is untouched.

Target: FreeBSD 14+ only (`kqueuex`, `SO_REUSEPORT_LB`, `LOCAL_PEERCRED`,
64-byte `struct kevent`). Other targets fail at comptime with a clear message (see Q4).

## 2. Common rules

- **Allocation.** Every buffer is allocated in `init` from the options; nothing in
  `wait`, `next`, `attach`, `setInterest`, `close`, `schedule`, `cancel`, `notify`
  or `acceptNext` allocates. Capacities are stated per type below; exhaustion returns
  an explicit error (`HandleTableFull`, `TimerTableFull`), never a silent drop.
- **Init in place.** `Loop`, `TimerWheel` and `SlotMap` are initialized through
  `fn init(self: *T, ...)`; `Wake` lives inside `Loop` so its address is stable.
- **Errors.** Each operation has its own error set; every errno is listed in an
  exhaustive switch with no `else => unreachable`. Unknown errnos map to
  `error.Unexpected` and the raw errno is kept in `Loop.stats.last_errno`.
- **Assertions** guard invariants only (owner thread, handle state, capacity math with
  `comptime assert`); untrusted input is validated and returns errors.
- **No logging** inside lib/net. Every refusal reaches the caller as an error or an
  event; counters live in `Loop.Stats`.

## 3. token.zig

```zig
pub const Token = packed struct(u64) {
    index: u32,
    gen: u24,
    kind: u8,

    pub const none: Token = @bitCast(@as(u64, 0));
    pub fn toUdata(token: Token) usize;
    pub fn fromUdata(udata: usize) Token;
    pub fn eql(a: Token, b: Token) bool;
};
comptime { assert(@sizeOf(usize) == 8); } // udata carries a whole Token
```

- `gen == 0` is never issued, so `Token.none` and zeroed udata never resolve.
- `kind` names the table a token belongs to. Consumers define their own kinds
  (session, ipc peer, s2s link, ...); the loop uses its own private kind for handles.

## 4. slotmap.zig

```zig
pub fn SlotMap(comptime T: type) type {
    return struct {
        pub const Error = error{Full};

        /// Owns `values`, `gens` and the free ring; borrows nothing.
        pub fn init(self: *Self, gpa: Allocator, slot_count_max: u32, kind: u8) Allocator.Error!void;
        pub fn deinit(self: *Self, gpa: Allocator) void;
        pub fn insert(self: *Self, value: T) Error!Token;
        pub fn get(self: *Self, token: Token) ?*T;        // null when stale or wrong kind
        pub fn remove(self: *Self, token: Token) ?T;      // null when stale or wrong kind
        pub fn count(self: *const Self) u32;
        pub fn capacity(self: *const Self) u32;           // shrinks only by retired slots
    };
}
```

- **Capacity:** fixed at init, `1 <= capacity <= maxInt(u32) - 1`. Memory: `@sizeOf(T)`
  + 8 B per slot (u32 generation, u32 free-ring entry).
- **Stale tokens never resolve to a reused slot.** `remove` increments the slot's
  generation. When the generation would wrap past `maxInt(u24)`, the slot is retired
  (never returned to the free ring) instead of wrapping, so the guarantee holds without
  an ABA window. Cost: one slot lost per 16.7M reuses of that slot (`stats.retired`).
- **Free ring is FIFO**, so a freed index is reused as late as possible; the generation
  check is the guarantee, FIFO only spreads reuse.

## 5. kevent.zig

Zig 0.15.2 `std.posix.kevent` maps `EBADF` and `EINVAL` to `unreachable`
(`std/posix.zig:4595-4597`) [src]; lib/net calls `std.c.kevent` directly.

```zig
pub const SubmitWaitError = error{
    KqueueInvalid,      // EBADF on the kqueue descriptor
    InvalidArgument,    // EINVAL (bad timeout or count)
    ChangeRejected,     // a change failed with no eventlist room (cannot happen with Loop sizing)
    SystemResources,    // ENOMEM
    Unexpected,
};
/// One kevent(2): apply `changes`, harvest into `events`. EINTR retries with an empty
/// changelist, because the kernel applies every change before it sleeps.
pub fn submitWait(kq: fd_t, changes: []const Kevent, events: []Kevent,
                  timeout: ?*const timespec, errno_out: *u32) SubmitWaitError!usize;

pub const ApplyError = error{ NotFound, BadDescriptor, InvalidArgument, ProcessNotFound,
                              AccessDenied, SystemResources, KqueueInvalid, Unexpected };
/// Immediate single change with an empty eventlist (signal watch, process watch,
/// detach, EVFILT_USER trigger). Each errno is its own error.
pub fn applyNow(kq: fd_t, change: *const Kevent) ApplyError!void;
```

Kernel facts this relies on [src `kern_event.c:1498-1528`]: every change in the list is
attempted; a failing change is written to the eventlist as `EV_ERROR` (errno in `data`,
the original `udata` preserved) while room remains, and the call fails as a whole only
when `nevents == 0`. When at least one change failed, the call returns the error records
**without scanning** for ready events. `Loop` therefore always passes
`nevents >= changes.len`, so no change is ever skipped or lost, and an error iteration is
simply followed by a normal wait.

## 6. loop.zig

### 6.1 Types

```zig
pub const Handle = Token;           // loop-private kind; stale handles never resolve
pub const Interest = packed struct(u8) { read: bool = false, write: bool = false, _pad: u6 = 0 };
pub const Filter = enum(u8) { read, write };

pub const Event = union(enum) {
    readable: Io,
    writable: Io,
    change_failed: ChangeFailure,   // a staged change for a handle was rejected
    deadline: Deadline,             // TimerWheel entry expired
    wake,                           // coalesced: at most one per batch
    broadcast_closed,               // Broadcast write end closed (shutdown)
    signal: u8,
    process_exit: ProcessExit,
};
pub const Io = struct {
    handle: Handle,
    ctx: Token,         // consumer token given at attach
    data: i64,          // bytes readable, listener backlog, or send space
    eof: bool,          // EV_EOF
    errno: u32,         // socket error from fflags when eof, else 0
};
pub const ChangeFailure = struct { handle: Handle, ctx: Token, filter: Filter, op: Op, errno: u32 };
pub const Op = enum(u8) { add, enable, disable };
pub const Deadline = struct { timer: TimerId, ctx: Token };
pub const ProcessExit = struct { pid: pid_t, status: u32 };
```

### 6.2 Loop API

```zig
pub const Loop = struct {
    pub const Options = struct {
        handles_max: u32,            // <= 1 << 20 per loop
        timers_max: u32,
        events_max: u32 = 256,       // ready events harvested per wait (lower bound)
        paused_max: u16 = 16,        // handles paused until a close (listeners)
        on_flush: ?FlushHook = null, // end-of-iteration hook
    };
    pub const FlushHook = struct { ctx: *anyopaque, func: *const fn (ctx: *anyopaque) void };

    pub fn init(self: *Loop, gpa: Allocator, options: *const Options) InitError!void;
    pub fn deinit(self: *Loop, gpa: Allocator) void;   // closes attached fds and the kqueue

    // Handles. The loop owns an attached fd until close or detach.
    pub fn attach(self: *Loop, fd: fd_t, ctx: Token, interest: Interest) AttachError!Handle;
    pub fn setInterest(self: *Loop, handle: Handle, interest: Interest) HandleError!void;
    pub fn requeue(self: *Loop, handle: Handle, filter: Filter) HandleError!void;
    pub fn pauseReadUntilClose(self: *Loop, handle: Handle) PauseError!void;
    pub fn close(self: *Loop, handle: Handle) HandleError!void;
    pub fn detach(self: *Loop, handle: Handle) DetachError!fd_t;
    pub fn fdOf(self: *const Loop, handle: Handle) ?fd_t;

    // Lifecycle deadlines (TimerWheel inside the loop).
    pub fn scheduleIn(self: *Loop, delay_ms: u64, ctx: Token) error{TimerTableFull}!TimerId;
    pub fn scheduleAt(self: *Loop, deadline_ms: u64, ctx: Token) error{TimerTableFull}!TimerId;
    pub fn cancelTimer(self: *Loop, timer: TimerId) bool;   // false when stale or fired
    pub fn nowMs(self: *const Loop) u64;                    // CLOCK_MONOTONIC, read once per wait

    // Immediate registrations (section 2.2 of event-driven-systems).
    pub fn watchSignal(self: *Loop, signo: u8) WatchSignalError!void;
    pub fn unwatchSignal(self: *Loop, signo: u8) void;
    pub fn watchProcess(self: *Loop, pid: pid_t) WatchProcessError!void;

    // Cross-thread entry points.
    pub fn waker(self: *Loop) *Wake;
    pub fn watchBroadcast(self: *Loop, broadcast: *const Broadcast) AttachError!void;

    // Iteration.
    pub fn requestImmediate(self: *Loop) void;   // next wait uses a zero timeout
    pub fn wait(self: *Loop) WaitError!void;
    pub fn next(self: *Loop) ?Event;
    pub fn stats(self: *const Loop) *const Stats;
};

pub const AttachError = error{HandleTableFull};
pub const HandleError = error{StaleHandle};
pub const PauseError = error{ StaleHandle, PausedListFull };
pub const DetachError = error{StaleHandle} || kevent.ApplyError;
pub const WaitError = kevent.SubmitWaitError || error{ TimerArmFailed, WakeFailed };
pub const InitError = Allocator.Error || error{ SystemResources, Unexpected };
```

Consumer iteration shape:

```zig
while (true) {
    try loop.wait();                  // flush hook, commit, one kevent()
    while (loop.next()) |event| switch (event) { ... };
}
```

### 6.3 Interest reconciliation

Each handle stores `wanted: Interest` and `registered: {read, write} in {none, enabled,
disabled}`. `attach` and `setInterest` only update `wanted` and put the handle on the
dirty list once (a dirty bit prevents duplicates). Nothing touches the kernel until
`wait()`.

At commit, for each live dirty handle, at most one change per filter:

| filter | wanted | registered | change |
|---|---|---|---|
| read | yes | none | `EV_ADD \| EV_CLEAR` (persistent, edge; handler drains to EAGAIN) |
| read | yes | disabled | `EV_ENABLE` |
| read | no | enabled | `EV_DISABLE` |
| write | yes | none | `EV_ADD \| EV_DISPATCH` (level, disarmed by the kernel after delivery) |
| write | yes | disabled | `EV_ENABLE` |
| write | no | enabled | `EV_DISABLE` |

- **Change buffer cannot overflow:** capacity is `2 * handles_max + extras_max` with
  `extras_max = 2` (timer arm, broadcast attach); `comptime`/init asserts state it.
- **EV_DISPATCH write:** when `next()` delivers a writable event, the handle's
  `registered.write` becomes `disabled`. It is re-enabled at the next commit only if the
  consumer still wants write after handling the event (write first; want write only after
  a real EAGAIN). Today's persistent write knotes (S10) cannot happen.
- **Enable re-evaluates the filter:** `EV_ENABLE` runs `f_event` and queues the knote
  when the condition already holds [src `kern_event.c:1882-1925`], so data that arrived
  while read was disabled, or connections queued while a listener was paused, are
  reported on resume.
- **Read pause and backpressure** are `setInterest(.{ .read = false })`, which disables
  rather than deletes the knote.
- **Change failures:** each `EV_ERROR` record carries the handle token in `udata`. The
  handle is marked broken (no further changes are generated for it), the registered state
  is left as the kernel has it, and a `change_failed` event is delivered. The consumer
  closes the handle. Failures of loop-internal changes (timer arm, broadcast) return
  `error.TimerArmFailed` from `wait()`.

### 6.4 Close, purge and detach

- `close(handle)`: removes the handle from the dirty and requeue lists, then `close(2)`.
  Because raw kevents are only materialized during commit, inside `wait()`, no staged
  entry can exist for a closed fd outside that window: purge is the dirty-list removal,
  which tombstones the entry so the remaining handles keep their order (S20). `close(2)`
  removes the live knotes.
- Events for a handle closed earlier in the same batch carry its old token; `next()`
  fails the generation check, skips them and counts `stats.stale_events`. A new
  connection that reuses the fd number gets a new handle token, so it can never receive
  the old connection's events.
- `close` of any handle also resumes every handle paused by `pauseReadUntilClose`
  (listeners paused on EMFILE, see 9.3).
- `detach(handle)`: for handing an fd to another loop (ADR-11 handshake pool). It issues
  an **immediate** `EV_DELETE` for each registered filter (ENOENT counts as success),
  frees the handle and returns the fd. Immediate, because a staged delete could reach the
  kernel after the receiving thread closed the fd and this loop attached a new fd with the
  same number.

### 6.5 wait() and next()

`wait()`:
1. Asserts the previous batch was fully consumed (`next()` returned null).
2. Calls `on_flush` (end-of-iteration hook: Outbox flush in C2). The hook may change
   interest; those changes join this commit.
3. Reconciles dirty handles into the change buffer and adds the timer arm change when
   the wheel's earliest deadline changed.
4. One `submitWait` with `nevents = max(changes.len, events_max)` and timeout `null`, or
   zero when `requestImmediate` was called or the requeue list is not empty.
5. Reads `CLOCK_MONOTONIC` once (`CLOCK_MONOTONIC_FAST` ticks at `kern.hz`, 100 on dev1).

`next()` translates one raw kevent at a time, so the generation check runs at delivery
time, not at harvest time. Order inside a batch: kernel events in kernel order, then
timer expirations (emitted when the timer kevent is reached, in deadline order), then
synthetic readable/writable events for requeued handles. `wake` appears at most once
per batch.

## 7. wake.zig

```zig
pub const Wake = struct {
    pub const NotifyError = error{ LoopClosed, SystemResources, Unexpected };
    /// Any thread. Writes to the kernel only on the false -> true transition.
    pub fn notify(self: *Wake) NotifyError!void;
};

pub const Broadcast = struct {
    pub fn init(self: *Broadcast) error{ SystemResources, Unexpected }!void; // pipe2(O_NONBLOCK | O_CLOEXEC)
    pub fn close(self: *Broadcast) void;   // any thread, idempotent: closes the write end
    pub fn deinit(self: *Broadcast) void;  // after every loop has stopped watching
};
```

- **Mechanism:** `EVFILT_USER` (`EV_ADD | EV_CLEAR`, registered at `Loop.init`);
  `notify` triggers it with `NOTE_TRIGGER` through `kevent.applyNow`. No pipe and no
  drain `read()` per wake.
- **Coalescing:** `pending: std.atomic.Value(bool)`. Producer: enqueue its item, then
  `pending.swap(true, .acq_rel)`; only a previous `false` issues the trigger. Consumer:
  `next()` performs `pending.swap(false, .acq_rel)` before it returns `.wake`, and the
  consumer drains its queues after that. Both sides use read-modify-write on the same
  flag, so either the producer sees `false` and triggers again, or its enqueue
  happens-before the consumer's drain. No wake is lost and N producers between two
  drains cost one syscall.
- **Broadcast shutdown:** one pipe per process; each loop registers the read end
  (`EVFILT_READ`, `EV_CLEAR`, loop-private udata kind). Closing the write end gives every
  watching kqueue a persistent `EV_EOF`; each loop reports `broadcast_closed` once.
  One byte would wake only one reader, which is why this is not `EVFILT_USER`.
- **Lifetime:** producers stop (threads joined) before `Loop.deinit`.

## 8. timer_wheel.zig

```zig
pub const TimerId = Token;   // timer kind; stale ids never cancel a reused entry
pub const TimerWheel = struct {
    pub const tick_ms = 1;
    pub const slot_count = 64;
    pub const level_count = 4;                                 // horizon 64^4 ms = 4.66 h
    pub fn init(self: *TimerWheel, gpa: Allocator, timers_max: u32, now_ms: u64) Allocator.Error!void;
    pub fn deinit(self: *TimerWheel, gpa: Allocator) void;
    pub fn schedule(self: *TimerWheel, deadline_ms: u64, ctx: Token) error{TimerTableFull}!TimerId;
    pub fn cancel(self: *TimerWheel, timer: TimerId) bool;     // O(1) unlink
    pub fn nextDeadline(self: *const TimerWheel) ?u64;         // per-level u64 occupancy masks, @ctz
    pub fn popExpired(self: *TimerWheel, now_ms: u64) ?Deadline;
};
```

- **Lifecycle deadlines only:** connect and handshake deadlines, SM expiry, reconnect and
  ADR-13 backoff, master SIGKILL escalation. Nothing in lib/net uses a timer to check I/O
  readiness.
- **Kernel side:** one `EVFILT_TIMER` (fixed ident, `EV_ADD | EV_ONESHOT`, milliseconds)
  armed to `nextDeadline - now`, rounded up, so it never fires before the deadline and an
  early wake cannot spin. Re-armed only when the earliest deadline changes; disarmed with
  `EV_DELETE` only while armed and not yet fired (no ENOENT noise).
- **Order:** entries expire in non-decreasing deadline order; equal deadlines in schedule
  order (FIFO lists per slot, exact level-0 slots after cascading). A deadline in the
  past expires at the next `wait`. Deadlines beyond the horizon park in the top level and
  are re-placed when it cascades.
- **Collect cost:** one collect walks every chain whose `slot_min` says it can hold a
  due entry. Worst batch is O(longest chain), O(`timers_max`) when all timers share one
  chain (a reconnect storm); amortized cost is a few entries per fired timer. A
  cancelled minimum leaves `slot_min` stale-low and costs one empty O(chain) rescan;
  the walk rebuilds the minimum, so it is charged once, not once per pass. Emission is
  bounded per pass: a deadline scheduled while a batch drains is collected at the next
  wait, so a handler re-adding a past deadline yields one event per pass.
- **Capacity:** `timers_max` entries of 32 B (deadline, ctx, prev, next) plus 8 B of
  slot-map overhead; `TimerTableFull` when exhausted.

## 9. bind.zig

### 9.1 TCP

```zig
pub const TcpOptions = struct {
    address: []const u8,          // IPv4 or IPv6 literal from bind_address; names are rejected (no DNS)
    port: u16,
    backlog: u31 = 4096,
    reuse_port_lb: bool = true,   // SO_REUSEPORT_LB: one listener per loop
    v6_only: bool = true,         // IPV6_V6ONLY set explicitly
    nodelay: bool = true,         // TCP_NODELAY on the listener only
};
pub const BindTcpError = error{ InvalidAddress, AddressInUse, AddressNotAvailable,
                                AccessDenied, SystemResources, Unexpected };
pub fn bindTcp(options: *const TcpOptions) BindTcpError!fd_t;
```

`socket(SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC)`, `SO_REUSEADDR`, `SO_REUSEPORT_LB`,
`TCP_NODELAY`, bind, listen. FreeBSD copies `TF_NODELAY` from the listener to accepted
sockets (`tcp_syncache.c:909`) [src], so accept does not set it again (today
`listener.zig:125` sets it per accept and ignores the error [V]).

### 9.2 Unix

```zig
pub const UnixOptions = struct { path: []const u8, mode: mode_t, backlog: u31 = 128 };
pub const BindUnixError = error{ PathTooLong, AddressInUse, NotASocket, AccessDenied,
                                 SystemResources, Unexpected };
pub fn bindUnix(options: *const UnixOptions) BindUnixError!fd_t;
pub const PeerCred = struct { uid: uid_t, gid: gid_t, groups: [16]gid_t, group_count: u8, pid: pid_t };
```

Order: path checked against `sun_path` (104 B) and refused, never truncated; bind;
`chmod(mode)`; listen (no window with the wrong mode). On `EADDRINUSE` a connect probe
decides: `ECONNREFUSED` means stale, unlink once and retry; a live listener is
`AddressInUse`; a non-socket file is `NotASocket` and is never unlinked.

Peer identity on accept: `LOCAL_PEERCRED` (`xucred`: uid, effective gid first, then the
supplementary groups, pid). It is a superset of `getpeereid`, which exposes only the
effective gid; T258 moved the IPC gate to `LOCAL_PEERCRED` for exactly that reason
(`src/ipc/server.zig:28-43`) [V]. See Q2.

### 9.3 Listener and accept

```zig
pub const Listener = struct {
    handle: Handle,
    family: enum { tcp, unix },
    pub const accept_batch_max = 256;
    /// Takes ownership of a listening fd (from bindTcp/bindUnix or inherited from the
    /// master); sets O_NONBLOCK and FD_CLOEXEC; registers read interest.
    pub fn attach(self: *Listener, loop: *Loop, fd: fd_t, ctx: Token, family: Family) AttachError!void;
    pub fn acceptNext(self: *Listener, loop: *Loop) AcceptError!AcceptOutcome;
};
pub const AcceptOutcome = union(enum) {
    accepted: Accepted,      // fd is O_NONBLOCK | O_CLOEXEC, owned by the caller
    drained,                 // EAGAIN
    batch_limit,             // accept_batch_max reached; listener requeued for the next iteration
    paused: PauseReason,     // EMFILE, ENFILE, ENOBUFS, ENOMEM: read interest disabled
    peer_rejected: u32,      // unix: LOCAL_PEERCRED failed (errno); the fd was closed
};
pub const Accepted = struct { fd: fd_t, peer: union(enum) { ip: std.net.Address, unix: PeerCred } };
pub const AcceptError = error{ ListenerInvalid, Unexpected };   // EBADF, ENOTSOCK, EINVAL, EOPNOTSUPP
```

- `accept4(SOCK_NONBLOCK | SOCK_CLOEXEC)` until `EAGAIN`. `ECONNABORTED` and `EPROTO`
  (peer reset before accept) are skipped and counted; `EINTR` retries.
- **Bounded drain:** after `accept_batch_max` accepts in one readable event the listener
  is requeued (`loop.requeue`) and the loop does a zero-timeout wait, so other handles are
  served and no backlog is stranded under `EV_CLEAR`.
- **EMFILE / ENFILE / ENOBUFS / ENOMEM:** `pauseReadUntilClose` disables read interest
  instead of spinning; the next `close()` of any handle on that loop re-enables it, and
  `EV_ENABLE` reports the queued connections. Every exhaustion pause also arms a
  250 ms fallback deadline: the relieving close may happen on another loop's thread
  (thread-per-core model), which this loop cannot see (see Q3).

## 10. Ownership, capacity and threading

| Object | Owner | Owns | Borrows |
|---|---|---|---|
| `Loop` | one thread (asserted in Debug) | kqueue, attached fds, handle table, change and event buffers, dirty/requeue/paused lists, `TimerWheel`, `Wake` | consumer `ctx` tokens (opaque values) |
| `SlotMap(T)` | the thread of the table's owner | values, generations, free ring | nothing |
| `TimerWheel` | inside `Loop` | entries and slot lists | nothing |
| `Wake` | inside `Loop` | the pending flag | the loop's kqueue fd |
| `Broadcast` | process (created before loops start) | the pipe | nothing |
| `Listener` | the loop's thread | its handle (fd owned by the loop) | nothing |

Per-loop memory for `H = handles_max`, `T = timers_max`:
handle state 16 B, slot overhead 8 B, dirty and requeue entries 8 B, change buffer
`2 x 64 B`, event buffer `2 x 64 B` (needed so every change can report an error): about
**288 B per handle**, plus `40 B x T`. 100k handles across all loops: about 29 MB. The
kevent buffers dominate; Q7 asks whether that is the right trade.

**Threading model:** one `Loop` per thread, never shared. What may cross threads:
- `Token` values (plain u64), validated by the owning thread on arrival;
- an fd after `detach` (ownership moves with it; the receiver `attach`es it);
- `*Wake` (`notify` is the only cross-thread call);
- `*Broadcast` (`close` from any thread).
Everything else (`Loop`, `SlotMap`, `TimerWheel`, `Listener`) is touched only by its
owner. Cross-thread data travels in the consumer's bounded queues (ADR-3 envelope ring),
signalled with `Wake`.

**Signals** are process-wide: `watchSignal` claims the signal in a process-global
`std.atomic.Value(u64)` owner mask (the one global in lib/net, because the resource is
global) and fails with `error.SignalOwned` on a second owner. Attach is immediate, then
`SIG_IGN` (`SIGCHLD` stays `SIG_DFL`); unwatch restores the disposition and deletes
immediately, treating ENOENT as success.

## 11. Mapping of the daemons

**xmppd-core.** Each worker thread owns one `Loop` and one `SO_REUSEPORT_LB` listener
(bound by the master, adopted with `Listener.attach`). Sessions live in a per-worker
`SlotMap(Session)`; their `Token` is the handle `ctx` and the cross-worker address (C3,
ADR-4), replacing `free_ids`, the `usize` conn ids and the generation scan (T255). The
delivery ring (C4) signals with `loop.waker()`, which is the Q2 coalescing for core
(T267). The Outbox flush (C2) is the `on_flush` hook, and write interest is only wanted
after EAGAIN. SM expiry, stream and auth timeouts use the wheel (C11). IPC links to auth
and s2s are handles (F3 frame). The archive writer thread becomes a `Loop` with no
handles, woken by `Wake`; the F7 handshake pool threads are loops receiving fds through
`detach`/`attach`.

**xmppd-s2s.** Today one `EventLoop(64)` [V `s2s/main.zig:841`]. On lib/net (X1) the
inbound listener, outbound connects (write interest for connect completion,
`SO_ERROR` latched once), the DNS resolver sockets (X2) and the core IPC link are
handles; connect deadlines and ADR-13 retry backoff are wheel deadlines; close purges
through the same dirty-list path, which fixes the T238/T277 purge gap by construction.
The library imposes no single-loop limit; the s2s execution model is X1's decision.

**xmppd-auth (and auth-oidc).** The IPC listener is `bindUnix` with `LOCAL_PEERCRED`
peer checks (T258 gate kept), each core connection is a handle with frame I/O (A2); the
crypto pool completes through `Wake` instead of its pipe (`crypto_pool.zig:125` [V]).
Replies arm nothing: they are flushed in `on_flush` and want write only after EAGAIN,
which removes the S22 16-entry changelist and its `catch {}`. OIDC uses the same loop
for its HTTP client sockets and IdP deadlines (A8).

**master.** One `Loop`: `watchSignal` for TERM, INT, HUP; `watchProcess` per child;
`bindTcp` for c2s (one per worker, `reuse_port_lb`, `bind_address` and IPv6 honored, V16)
and s2s listeners, replacing `bindListenerSocket` [V `master/main.zig:924`]. The
`Thread.sleep(100 ms)` startup waits [V `master/main.zig:542,551`] become readiness pipes
as handles (X3); SIGKILL escalation on shutdown is a wheel deadline.

**xmppc (lib/xmppc).** The engine thread owns one `Loop`. Connections and resolver
sockets are handles; `Engine.schedule`/`cancelTimer` map onto `scheduleIn`/`cancelTimer`
(one kernel timer instead of one knote per consumer timer); the 1 s housekeeping tick
(`TICK_UDATA`) becomes wheel deadlines; the 64-entry staged-change cap and the
"do not block while changes remain" workaround (805e2d2, T240) disappear because the
change buffer is sized from `handles_max`; the wake pipe and its `wake_pending` become
`Wake`. Public xmppc API stays as listed in plan section 5.9.

## 12. What this replaces

| Today [V] | Replaced by | Adopted in |
|---|---|---|
| `src/core/event_loop.zig` `EventLoop.addFd/removeFd/modifyFd/addFdOneshot` (one kevent per call) | staged `attach`/`setInterest`, committed once per `wait` | per daemon, ADR-8 order |
| `ChangeList` (raw kevents, fixed buffer, `ChangeListFull`, `reserve`/`beginReserved`) | dirty list plus reconciliation; buffer sized `2 x handles_max`, cannot overflow | same |
| `ChangeList.purgeFd` swap-remove (S20) and `assertNoPurgedEntries` | tombstoned dirty-list removal; raw kevents only exist inside `wait` | same |
| `keventHardened` (drops receipts, logs, re-issues, isolates one by one) | eventlist always `>= changes`; every failure is a `change_failed` event | same |
| `addSignal` with `sigprocmask` | `watchSignal`: immediate attach, `SIG_IGN`, single owner | master (X3) |
| `addProcess`, `addTimer`/`removeTimer` (one EVFILT_TIMER per ident) | `watchProcess`; `TimerWheel` with one kernel timer | master, core, xmppc |
| `poll`/`submitAndPoll` returning a slice of translated events | `wait` + `next` with delivery-time generation checks | all |
| `makeChangeEvent`, `FdRegistration`, `addFds`/`removeFds` (`catch {}` at :569) | not needed | all |
| `core/listener.zig`, `master/main.zig:bindListenerSocket`, `ipc/server.zig` accept | `bindTcp`, `bindUnix`, `Listener` | master, core, auth |
| Wake pipes in `delivery_queue.zig`, `archive_queue.zig`, `crypto_pool.zig`, `lib/xmppc/engine.zig` | `Wake` | C4, Q8/D2, A9, WS8 |
| private kqueues in `archive_queue.zig`, `lib/xmppc/engine.zig` (`catch {}` at :699) | `Loop` | D2, WS8 |

`src/core/event_loop.zig` is deleted when its last consumer moves (core, C2/C3).

## 13. Scale model (event-driven-systems section 0)

lib/net is the loop substrate, so the test is answered for what the library permits and
enforces; each daemon's own answers stay with its workstream.

1. **Execution model.** One loop per thread, no global mutable state besides the signal
   owner mask. xmppd is a hybrid: processes per failure domain (master, auth, s2s, core),
   core thread per core with one `SO_REUSEPORT_LB` listener per worker. Nothing in the
   library assumes a single loop. PASS.
2. **Hot path.** A loop iteration takes no lock and touches no shared atomic. Atomics:
   `Wake.pending` (one swap per notify, one per drained wake), the signal mask (setup
   only). Counters are plain per-loop integers; aggregation is F6/M1. PASS.
3. **Shared resources.** None inside lib/net; the kernel kqueue is per loop, listeners are
   per loop. Shared stores and the handshake pool are consumer services reached through
   bounded queues plus `Wake`. PASS for the library.
4. **Nothing blocks.** The only blocking call is the kevent wait. Everything else is
   non-blocking (`accept4` on non-blocking listeners, `EVFILT_USER` trigger) or setup-only
   (`bindTcp`, `bindUnix` with its local connect probe, `kqueuex`). No DNS (literals
   only), no file I/O, no logging. PASS.
5. **Connection economics.** About 288 B per handle in lib/net (section 10); capacities are
   derived from `handles_max`, which the consumer derives from its memory budget and
   `RLIMIT_NOFILE`, not a hard-coded cap. Accept drains in bounded batches and pauses on
   descriptor exhaustion. PASS, Q7 open on the kevent-buffer share.
6. **Many requests per connection.** Protocol property of XMPP streams; the loop supports
   it with `EV_CLEAR` reads drained fully and writes coalesced in `on_flush`. N/A for the
   library.
7. **Beyond one host.** No host-local assumption: TCP and Unix are both first class; Unix
   is only used for intra-host IPC between xmppd processes. N/A for the library.
8. **Expensive operations.** None in F2. TLS handshakes move to the F7 pool built on
   these loops.
9. **Overload.** Every capacity is fixed and returns an explicit error when exhausted;
   listeners pause instead of spinning; `Broadcast` drains N loops; listener fds can be
   adopted from a parent for seamless reload. PASS.
10. **Measured.** `tools/net_loop_bench.zig`, ReleaseFast, 3 runs, `cpuset -l` pinned,
    `CLOCK_MONOTONIC`, on freebsd-dev1 (Xeon E5-2620 v4, 20 threads, `kern.hz=100`):
    (a) iteration cost with one active socketpair and N idle handles,
    N in {0, 1k, 10k, 50k}; target: flat in N within 5 percent;
    (b) cost per ready event with N active socketpairs, N in {1, 64, 1k};
    target: lib/net overhead (excluding the syscall) at most 50 ns per event;
    (c) wake round trip with 1 and 8 producers. Median and spread reported in the PR.

Result: **PASS** for the library, with Q7 to settle.

## 14. Tests (each must fail when its production change is reverted)

- token/slotmap: none never resolves; stale token after remove and after reuse of the
  same index is rejected; wrong kind rejected; generation retire at `maxInt(u24)`;
  Full at capacity; FIFO reuse order.
- kevent: EBADF and EINVAL return errors (no panic); EINTR retry does not re-apply
  changes; per-change error records keep `udata`.
- loop (socketpairs and pipes): readable with byte count; EOF flag and errno on peer
  close and on reset; write interest delivered once with EV_DISPATCH and re-armed only
  while wanted; change-buffer bound under churn (all handles toggling every iteration,
  attach/close storms, changes per commit never above `2 x live dirty`); purge on close
  keeps the order of other handles' changes; fd number reuse in the same batch gets no
  stale events; stale-token rejection after slot reuse; change failure surfaces as
  `change_failed` with the right handle; read pause and resume reports buffered data;
  detach then attach on a second loop; requeue delivers a synthetic event and forces a
  zero timeout; flush hook runs once per wait before the commit.
- wake: N producer threads times M notifies cause at most one trigger per drain and no
  lost wake (counter equality); broadcastClose reaches every one of N loops.
- timer wheel: ordering across levels and ties; cancel O(1) including cancel after fire
  and stale id; past deadline; beyond-horizon deadline; kernel timer re-armed only when
  the earliest deadline changes.
- signals/process: self-`kill` delivery; second owner refused; child exit status.
- bind: IPv4 and IPv6 literal, `bind_address` honored, names rejected, CLOEXEC and
  NODELAY set, NODELAY inherited by accepted sockets; Unix mode applied before listen,
  long path refused, stale socket replaced, live socket and regular file refused;
  `LOCAL_PEERCRED` uid and groups on accept; accept drains to EAGAIN; batch limit
  requeues; EMFILE pause and resume in a forked child with a lowered `RLIMIT_NOFILE`.

## 15. Commit plan (one item per commit, pushed after each)

1. `lib/net/DESIGN.md` (this commit, STOP POINT).
2. token + slotmap, `net_mod` and `net-tests` registration in `build.zig`.
3. kevent wrapper.
4. loop: handles, reconciliation, events, close/purge/detach, requeue, flush hook.
5. wake + Broadcast.
6. timer wheel and its loop integration.
7. signals and processes.
8. bind + Listener.
9. `tools/net_loop_bench.zig` and `bench-net-loop`, numbers in the PR.

## 16. Open questions for review

- **Q1 born.** event-driven-systems section 9 says new Zig code should use born. ADR-8
  (approved) and this order specify a repository-local lib/net with its own kevent
  wrapper. Proposal: self-contained lib/net (xmppd is kqueue only; born has no
  generational handles, reconciliation, EV_DISPATCH write model or timer wheel), and file
  born issues for the pieces worth upstreaming after F3. Confirm or redirect.
- **Q2 peer credentials.** The order says `getpeereid` on accept; T258 showed it is not
  enough for the IPC gate. Proposal: `LOCAL_PEERCRED` (`PeerCred` above, includes the
  getpeereid fields).
- **Q3 descriptor-exhaustion pauses.** Resume on the loop's next close plus a 250 ms
  fallback deadline for every exhaustion reason including EMFILE: the relieving close
  may land on another loop's thread and never be seen here. This is a backoff
  deadline, not an I/O driver.
- **Q4 targets.** FreeBSD 14+ only, comptime error elsewhere. Do any lib/xmppc consumers
  (Kumiko Chat, continuum-xmpp-bridge) need macOS or Linux before WS8? If yes, the
  kqueue core can stay portable to macOS at small cost; Linux would be a separate
  backend.
- **Q5 signals and processes.** Not in the F2 list, but the master mapping needs them and
  `src/core/event_loop.zig` cannot be deleted without them. Proposal: include (item 7).
- **Q6 read model.** Persistent `EV_CLEAR` read plus `requeue` for fairness budgets
  (F3 Inbox can stop after N bytes and requeue). Alternative: `EV_DISPATCH` read with
  explicit re-arm per read, which costs one change per read. Proposal: EV_CLEAR.
- **Q7 kevent buffer memory.** Sizing for the worst case (every handle dirty) costs about
  256 B per handle and makes overflow impossible. The alternative is a smaller buffer with
  chunked zero-timeout commits, which complicates harvest (ready events can arrive in the
  chunk calls). Proposal: keep the worst-case sizing.
