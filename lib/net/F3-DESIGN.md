# F3 design: `lib/net` conn and frame (ADR-8, T197 5.4)

F3 adds the per-connection I/O layer on top of the F2 substrate: `conn`
(Transport, Inbox, Outbox, the STARTTLS rule) and `frame` (IPC
`FrameReader`/`FrameWriter`). Nothing here adopts itself into a daemon; C2
(core) and the s2s teardown consume it.

## 0. Scale model (event-driven-systems section 0 litmus)

1. **Execution model.** Thread per core. The F2 `Loop` is already a
   per-thread instance with no global mutable state; conn objects are owned
   one per loop thread and never shared. The process model (N workers, each
   with its own loop and `SO_REUSEPORT_LB` listener) is decided in ADR-8 and
   already shipped in F2's `bindTcp`. Nothing in F3 changes or weakens it.
2. **Linear scaling.** No lock, atomic, shared map or shared allocator on
   the data path. `Outbox`/`Inbox` buffers are per-conn heap allocations
   from the loop thread's allocator. The only cross-thread object is the
   F7 handshake pool seam (a bounded queue plus `Wake`, below), which is
   off the data path by definition.
3. **Shared resources.** `SSL_CTX` is one per process (ADR-11, F7
   delivers it); it is read-only after init so sharing needs no lock.
   `Outbox` spill is per-conn, not a shared pool: backpressure policy is
   per-connection by design, so one stalled reader cannot starve others.
4. **Nothing blocks a loop.** TLS handshake CPU is the one heavy step:
   M5 measured a login burst spending 50% of core time in the handshake
   (Appendix D.1), which is why F7 exists. The design isolates the
   handshake behind an fd handoff seam (section 7) so the pool can take
   the fd without reworking conn. The data path itself (SSL_read/SSL_write,
   read/writev, frame encode) is bounded per call and per pass by the
   inbox budget and the outbox flush budget.
5. **Timers** stay on the F2 wheel as lifecycle deadlines owned by the
   consumer (connect timeout, handshake deadline, SM expiry). conn owns no
   timers; it exposes the ctx the consumer schedules against.
6. **Measurement.** The bench extends with an echo-pass row (read ->
   outbox -> write through both transports) once C2 exists to give it a
   consumer shape, and reports bytes per idle connection so any inbox or
   ring growth is measured against today's per-connection memory.

## 1. Files and ownership

- `lib/net/conn.zig`: `Transport`, `Tls`, `Inbox`, `Outbox`, `Conn`,
  `ConnList`, `Handshake`. Imports `lib/tls/ssl.zig` (`SslConn`,
  `SslContext`) and the F2 `Loop`/`Handle`/`Interest`/`Event`.
- `lib/net/frame.zig`: `FrameReader`, `FrameWriter`. No dependency on
  conn or the loop: usable on any fd, including the IPC unix socket.
- `lib/net/net.zig`: re-exports.
- `build.zig`: the net module gains no new dependencies beyond the
  existing `tls` import used by `ssl.zig` today (same link line).

Ownership: the consumer allocates `Conn` objects (one per accepted fd,
from its own slab or arena on the loop thread) and frees them on close.
The inbox slice and the outbox ring are allocated once at `Conn.init`
from the consumer's allocator with sizes from `Conn.Options`; a slice
allocated once never moves, which is what the outbox pin proof relies
on. lib/net owns nothing global; `ConnList` is an intrusive per-loop
dirty list whose links live inside `Conn` (the same pattern the F2 loop
uses for its handle dirty list).

### Per-consumer sizes (PR #41)

`Conn.Options` carries `inbox_bytes`, `outbox_ring_bytes` and
`max_outbound_bytes`. The defaults equal today's per-connection memory;
an earlier 64 KiB inbox plus 32 KiB inline ring would have been 96 KiB
per conn against today's 24 KiB, a 4x regression at 10k sessions per
worker. Any increase needs an M-series measurement that shows the win.

| consumer  | inbox                       | outbox ring     | max_outbound_bytes |
|-----------|-----------------------------|-----------------|--------------------|
| c2s, s2s  | 8 KiB                       | 16 KiB          | 1 MiB              |
| IPC       | `MAX_FRAME_SIZE` (65540 B)  | `MAX_FRAME_SIZE`| 4 MiB              |

`max_outbound_bytes` is the current `max_outbound_bytes` per consumer:
c2s 1 MiB, IPC 4 MiB (`CLIENT_SEND_CAP`), both configurable. Spill is
`.empty` until first use, so idle connections pay nothing; when the
outbox drains to empty, spill capacity above a small high-water mark
(default 64 KiB) is freed, so one burst does not pin memory for the life
of the session.

## 2. Transport

```zig
pub const Transport = union(enum) {
    plain: posix.fd_t,
    tls: *Tls,   // points into Conn; socket BIO only, never memory BIO
};

pub const Tls = struct {
    conn: ssl.SslConn,     // SSL_set_fd at init; already non-blocking
    ktls_tx: bool,         // read once after the handshake completes
    ktls_rx: bool,
    policy: KtlsPolicy,    // require | prefer (default: prefer)
};
```

```zig
pub const IoResult = union(enum) {
    n: usize,          // bytes moved
    want_read,         // drive me on EVFILT_READ
    want_write,        // drive me on EVFILT_WRITE (SSL_read can want this)
    eof,
    err: SslError,
};

pub fn read(t: *Transport, buf: []u8) IoResult;
pub fn write(t: *Transport, buf: []const u8) IoResult; // plain: writev path
pub fn pending(t: *const Transport) usize;             // SSL_pending
pub fn shutdown(t: *Transport) void;                   // SSL_shutdown once
```

Rules enforced structurally:

- TLS RX is always `SSL_read`. No read path exists that calls `read()` on
  a TLS conn, so post-handshake records cannot leak as payload (kTLS D2).
- `SSL_read` may answer `want_write` (post-handshake reply needed): the
  caller arms write interest and re-drives the read on the write event.
  `SSL_write` may answer `want_read` symmetrically.
- TLS TX is always `SSL_write`; no mode bits are required. After a
  `want_*` the retry presents the identical `(ptr, len)`, a short write
  just advances the head, and `ACCEPT_MOVING_WRITE_BUFFER` is **never**
  relied on. The Outbox pin below is what makes that guarantee possible.
- Raw `send()` on a ktls_tx socket is allowed by the kernel but is NOT
  offered by this layer: one write path keeps the pin story single and
  testable. (Sendfile stays an F7+ evaluation, never in this design.)
- No `SSL_key_update` API exists. A peer-initiated KeyUpdate surfaces as a
  mid-stream `bad record mac`/`no suitable record layer` error
  (PR-unfixable per kTLS D9); the conn reports `err` and the consumer
  reconnects. Documented, not hidden.
- After `doHandshake` returns `ok`, the conn reads
  `BIO_get_ktls_send`/`BIO_get_ktls_recv` once and records exactly one
  token per connection (`ktls`, `ktls-tx`, `ktls-rx`, `sw`) in the
  consumer's counter registry (the M1 counter-block pattern) plus one
  debug-level log line. There is no per-conn log callback: at 5000
  handshakes per second an info line per conn is 5000 lines per second,
  so counters are the record and the line is debug. `prefer` (the
  default) never refuses a connection for missing offload: fallback to
  userland TLS is silent apart from the `sw` counter and the debug line.
  `require` is opt-in per listener and fails the conn at this point.
- Plain transport: `read()`/`writev()` with `MSG_NOSIGNAL` equivalent.
  `SO_NOSIGPIPE` is asserted in `Conn.init`, where the fd is adopted, so
  connect()ed s2s outbound fds are covered the same as accepted ones,
  not only sockets that passed through the accept helper.

`Transport` deliberately has no `attach`/`interest` knowledge: interest
reconciliation stays on the F2 `Loop`, and `Conn` translates results into
`setInterest` calls.

## 3. Inbox

```zig
pub const Inbox = struct {
    buf: []u8,       // owned slice, allocated once at Conn.init
                     // (Options.inbox_bytes; c2s/s2s default 8 KiB)
    len: usize,
    consumed: usize, // deferred compaction: parses borrow buf until consumed()
    eof: bool,
};

pub const DrainResult = enum { drained, budget_left, eof, err };

/// Read until EAGAIN, until the budget is spent, or until the inbox is
/// full. A `budget_left` result means more data may be pending, or the
/// inbox is holding bytes the consumer has not consumed yet, and the
/// conn must be re-driven before the loop sleeps.
pub fn drain(in: *Inbox, t: *Transport, budget: *Budget) DrainResult;
pub fn unread(in: *const Inbox) []const u8;   // bytes available to parse
pub fn consume(in: *Inbox, n: usize) void;    // mark n parsed
pub fn compact(in: *Inbox) void;              // moves only unconsumed bytes
```

Fairness: `drain` stops at `budget` (consumer-tuned, default 64 KiB or
16 reads per conn per pass, whichever first), so one fast sender cannot
hold a pass that serves thousands of connections. With an 8 KiB inbox it
also stops when the inbox is full: `drain` returns `budget_left`, the
consumer parses and `consume()`s, and the loop continues the conn. On
`budget_left` the conn is linked on the `ConnList`; the end-of-iteration
walk calls `Loop.requeue(handle, .read)`, which emits a synthetic
readable event on the next pass after a zero-timeout `kevent`, never a
timer. This matters on FreeBSD because `EVFILT_READ | EV_CLEAR` is
transition-armed: data left unread produces no new event, so requeue
must be explicit. A stalled conn therefore gets exactly one extra pass
at a time and never starves the batch.

`unread()` hands the parser a stable slice; `consume(n)` records parsed
bytes without moving memory, so parsed spans stay valid until the next
`drain`/`compact`. Compaction happens once per `drain`, not per message:
the order's "compact once per read".

## 4. Outbox and the pin

```zig
pub const Outbox = struct {
    ring: []u8,                       // owned slice, allocated once at Conn.init
    head: usize, tail: usize,         // [head, tail) unsent in ring
    spill: std.ArrayListUnmanaged(u8), // .empty until first use
    spill_limit: usize,               // Options.max_outbound_bytes beyond the ring
    pin: ?Pin,                        // in-flight TLS write
    stats: Stats,
};

const Pin = struct { ptr: [*]const u8, len: usize };

pub const AppendResult = enum { queued, spilled, failed_closed };
pub fn append(o: *Outbox, parts: []const []const u8) AppendResult; // gather
pub fn flush(o: *Outbox, t: *Transport) FlushResult;
pub fn empty(o: *const Outbox) bool;
pub fn bytes(o: *const Outbox) usize;
```

`append` is a gather write: caller passes part slices (prefix, JID,
payload) and they are copied once into ring or spill, never staged
through a scratch buffer. Over `spill_limit` the result is
`failed_closed` and `stats.failed_closed += 1`; C2 maps that to
`resource-constraint` + offline storage. Nothing is dropped silently.

**Pinning proof.** A pending `want_*` TLS write retains the caller's
`(ptr, len)` until the retry succeeds, so while `pin != null` the backing
memory for exactly those bytes must be stable:

- `flush` presents `o.pin.?` verbatim on every retry; it only forms a new
  pin when the previous call completed. Pin formation takes
  `ring[head..]` (the contiguous head run of unsent bytes), records it,
  then issues `SSL_write`.
- While `pin != null`: (a) no ring compaction moves bytes at or before
  the pin (the pinned run is by definition the head of unsent data);
  (b) `append` may only write behind `tail` in the ring or grow `spill`.
  **The pin is only ever formed from `ring`, never from `spill`**: the
  ring is one heap slice allocated at `Conn.init` and its addresses
  cannot move, so a spill realloc can never invalidate the pin. `flush`
  writes ring runs first and only drains `spill` when the ring is empty,
  reloading it into the ring's free space (a bounded copy) rather than
  pinning spill memory.
- On completion the pin's bytes are consumed, `pin` clears, and the next
  head run forms a fresh pin. New bytes appended during a pending write
  simply sit behind `tail`; they are not part of the retry (S23's exact
  rule: the retry never grows).
- Plain transport needs no pin (`writev` never retains the buffer) but
  uses the same head-run structure so the code path is shared.

Consequence for tests: the pin proof is *only* about the ring. The fuzz
test pins the head, appends + flushes under a tiny `SO_SNDBUF`, and
verifies the peer receives byte-identical data.

`flush` budget: at most `flush_budget` bytes per call (consumer-tuned);
`ConnList` requeue on exhaustion, same mechanism as Inbox.

Spill memory: `spill` starts `.empty` and grows on demand. When `flush`
leaves the outbox empty, spill capacity above `spill_high_water`
(default 64 KiB) is released (`shrinkAndFree` to the mark), so a single
burst does not hold its peak for the session lifetime.

## 5. Conn, ConnList, and the event contract

```zig
pub const Options = struct {
    inbox_bytes: usize,          // slice allocated once at init
    outbox_ring_bytes: usize,
    max_outbound_bytes: usize,   // ring + spill bound (fail closed past it)
    read_budget_bytes: usize,    // per-pass inbox drain budget (default 64 KiB)
    read_budget_reads: u32,      // per-pass read call budget (default 16)
    flush_budget_bytes: usize,   // per-pass outbox flush budget
    ktls: KtlsPolicy,            // default .prefer
};

pub const Conn = struct {
    loop: *Loop,
    handle: loop.Handle,
    transport: Transport,
    inbox: Inbox,
    outbox: Outbox,
    state: State,
    ctx: Token,                 // consumer's ctx token, echoed to it
    dirty_next: u32, dirty_prev: u32, on_dirty: bool, // ConnList links
};

pub const State = enum { cleartext, handshake, established, closing };

pub const CloseReason = union(enum) {
    eof,                        // peer closed cleanly
    err: anyerror,              // socket or TLS error (errno captured)
    outbox_full,                // failed_closed past max_outbound_bytes
    consumer,                   // Conn.close called by the consumer
};

pub const Outcome = union(enum) {
    none,           // event absorbed: interest change only, or stale
    readable,       // new bytes in inbox; consumer parses + consume()s
    handshake_done, // .handshake -> .established; kTLS token recorded
    closed: CloseReason,
};

pub fn init(c: *Conn, loop: *Loop, fd: posix.fd_t, ctx: Token,
            opts: *const Options) InitError!void;
pub fn onEvent(c: *Conn, ev: Event) Outcome;    // state machine driver
pub fn close(c: *Conn) void;                    // mark closing, link ConnList
pub fn startTls(c: *Conn, hs: *Handshake) StartError!void;
```

`onEvent` returns the `Outcome`; the consumer's dispatch switches on it.
There are no per-conn callbacks and no event queue: a callback that
closes or frees the conn inside `onEvent` is the UAF class PR #9 fixed
(T215: `closeSession` then `handleWritable` dereferencing a freed
session), so every terminal effect goes through the return value and
the end-of-iteration walk.

`onEvent` translates loop events into drain/flush calls and interest
updates: a readable event drains Inbox within the budget and reports
whether more remains; a writable event drives either the handshake or an
Outbox flush; `eof`/`err` surfaces `.closed`. When the outbox has data
`Conn` sets write interest; when it drains it drops it - the loop's
`EV_DISPATCH` write interest (F2) keeps registration cheap.

Close is deferred by construction: `Conn.close` (or a `.closed` outcome
the consumer acts on) marks the conn `.closing` and links it on the
`ConnList`. `SSL_shutdown` (once), the fd close and the consumer's free
all run in the end-of-iteration walk, after every event for that conn in
the batch has been handled. A batch that holds both a read and a write
event for a conn closed by the first skips the second two ways, both
tested: `onEvent` on a `.closing` conn returns `.none` without touching
I/O, and the consumer's ctx -> conn resolution is generation-checked
(F2 token), so a slot freed and reused across iterations can never
deliver to the wrong conn.

`ConnList` is the intrusive per-loop dirty list (head/tail/count, O(1)
link/unlink, order-preserving). The consumer walks it at end-of-iteration
for outbox flushes, inbox-budget re-drives and deferred closes; it is the
conn-level analog of the loop's dirty list, and it is what makes the
end-of-iteration flush rule from ADR-2 mechanical rather than "the
consumer remembered to".

## 6. STARTTLS rule

`startTls` refuses (`StartError.OutboxNotEmpty` / `ReadAhead`) unless:

1. `outbox.empty()` - nothing queued behind the upgrade point;
2. `inbox.unread().len == 0` **and** the conn has consumed nothing past
   the upgrade point - any buffered post-upgrade bytes are a protocol
   error and a command-injection risk (kTLS skill section 6), so both
   conditions fail closed.

On acceptance the conn moves to `.handshake`; the `Handshake` (below)
takes ownership of the fd and the `SslConn` for the upgrade. The
cleartext phase is unaffected because kTLS engages only after the
handshake completes.

## 7. Handshake and the F7 pool seam

`SSL_do_handshake` on a socket BIO does socket I/O and returns
WANT_READ/WANT_WRITE, so `step()` is not pure CPU and cannot run on a
pool thread blindly. The seam is therefore a handoff of the fd (ADR-11
step 1-3, restated for this API):

1. `conn.releaseFd()` detaches the handle on the loop (immediate
   EV_DELETE per registered filter, the F2 `Loop.detach`) and returns
   the fd; the conn moves to `.handshake` and holds no registration.
2. `Handshake` owns the fd and the `SslConn` while it runs. Whoever owns
   the fd enforces the deadline: on the consumer's loop it is the
   consumer's timer ctx; on a pool thread it is that thread's deadline
   wheel.
3. The driver registers the fd on its own kqueue and drives
   `SSL_do_handshake` event-driven to completion or deadline. F3 ships
   the same object driven on the consumer's loop; the API is identical
   either way because the driver only ever sees `Handshake` and `Done`.
4. `Done` is posted back through `loop.wake`/`Broadcast`; it is the only
   cross-thread channel, and the posted value is a token plus result,
   never a pointer the worker did not already own.
5. `conn.adoptFd(fd)` re-attaches the handle on the owning loop;
   `conn.finishHandshake(hs)` installs the `Tls` transport, reads and
   records the kTLS flags once (token plus counter, section 2), applies
   the `require|prefer` check and moves to `.established`.

```zig
pub const Handshake = struct {
    conn: ssl.SslConn,
    fd: posix.fd_t,        // owned until adoptFd or error close
    deadline_ctx: Token,   // consumer-owned; enforced by the fd owner
    done: Done,            // result slot the driver posts back
};

pub const Done = union(enum) { ok, want_read, want_write, err: SslError };

pub fn releaseFd(c: *Conn) error{StaleHandle}!posix.fd_t;
pub fn adoptFd(c: *Conn, fd: posix.fd_t) error{StaleHandle}!void;
```

F3 proves the seam, not just ships it: a test runs a handshake to
completion on a second thread driving its own `Loop`, posts `Done` back
through `Wake`, and has the first loop adopt the fd and finish the
handshake. The release gate stands: no consumer ships in v0.9.1 with
on-loop handshakes (ADR-11 has no exception); C2 adoption in core may
use the on-loop path only until F7 lands.

## 8. Frame format (IPC)

Wire-compatible with `src/ipc/protocol.zig` today; no IPC protocol
change in F3:

```
frame  := header payload
header := u32 little-endian payload_len        (HEADER_SIZE = 4)
payload_len <= MAX_PAYLOAD_SIZE                (= 65536, unchanged)
payload := protocol.encode bytes
```

```zig
pub const FrameReader = struct {
    buf: []u8, len: usize, consumed: usize,   // like Inbox but fd-agnostic
    eof: bool,
};
pub fn recv(r: *FrameReader, fd) ReadResult;   // read until EAGAIN
pub fn next(r: *FrameReader) ?Frame;           // parse by offset, borrows buf
pub fn consume(r: *FrameReader, n: usize) void;
pub const Frame = struct { payload: []const u8, consumed: usize };

pub const FrameWriter = struct {
    buf: std.ArrayListUnmanaged(u8), start: usize,
};
pub fn begin(w: *FrameWriter, alloc, cap) ![]u8; // reserve space for header+payload
pub fn commit(w: *FrameWriter, payload_len: usize) void; // patch the u32 len
pub fn drain(w: *FrameWriter, fd) WriteResult;             // write until EAGAIN
```

Reader: `recv` compacts the consumed prefix once per call (never per
frame), reads until `EAGAIN`, reports `.eof` distinctly from
`.would_block`. `next` parses by offset: returns the payload slice
borrowing `buf` (process before the next `recv`/`next`), records
`consumed` for the deferred compaction. A header with
`payload_len > MAX_PAYLOAD_SIZE` is a protocol error, not a skip.

Writer: `begin` grows the backlog once and returns the scratch for
in-place `protocol.encode` (no 64 KiB stack buffer, T257); `commit`
writes the LE length over the reserved header and extends the queue.
`drain` writevs the backlog until `EAGAIN`, with `.eof`/error distinct
from `.would_block`.

## 9. Test plan

Unit (all revert-verified against the production change they pin):

- Transport over socketpair, plain: read/write/eof/error paths; write
  after close is an error, not a panic.
- TLS transport with a userland peer (one userland OpenSSL end per the
  PR 296498 rule; in-process `SslConn` peer on a second thread against a
  listening `Conn`): handshake completion, kTLS token + counter recorded
  exactly once, `SSL_read` after `want_write` re-drive, `SSL_write`
  after `want_read` re-drive, clean close.
- Tiny-`SO_SNDBUF` tests: `setsockopt(SO_SNDBUF, 1 KiB)` on the accepted
  side so the kernel accepts less than the outbox holds. Required for
  - the pin proof: append a large gather, flush to WANT_WRITE, append
    more behind it, drive writable events, peer receives byte-identical
    data; kills a "retry with a moved slice" revert;
  - the partial-write path: a `want_write` mid-slice retry presents the
    identical `(ptr, len)`;
  - inbox/outbox budgets: `budget_left` requeues via `Loop.requeue` and
    completes without busy-looping (assert pass counts).
- Inbox: fill/compaction/unread stability across parses; EOF mid-frame;
  drain stops on a full inbox and resumes after `consume`.
- Outbox: gather order, ring wrap, spill bound -> `failed_closed`,
  spill-reload-into-ring after drain, spill capacity freed above the
  high-water mark once empty, `empty()`/`bytes()` accounting.
- ConnList fuzz: seeded mix of readable/writable/close/requeue with a
  full link-invariant walk after every op (the F2 dirty-list fuzz shape).
- Close deferral: a batch delivering read+write for a conn closed by the
  first event skips the second (`.closing` short-circuit plus the ctx
  generation check), and the fd close + consumer free happen only in the
  end-of-iteration walk.
- STARTTLS: refusal on non-empty outbox and on unread bytes; upgrade on
  clean state moves the fd to `Handshake` and lands in `.established`.
- Handshake seam: a `Handshake` driven to completion on a second thread
  with its own `Loop`, `Done` posted back through `Wake`, fd re-adopted
  by the first loop.
- Frame: roundtrip, split header, split payload, coalesced frames,
  oversize header rejection, drain-to-EAGAIN backlog growth, writer
  encode-in-place produces wire-identical bytes vs `protocol.encode`.
- kTLS engagement test on the loopback path runs with ONE userland end
  only (PR 296498): assert `ktls_*` flags and the one-shot counter, plus
  a `prefer` fallback row with kTLS disabled via `kern.ipc.tls.enable=0`
  context or a userland-only ctx, and a `require` row that fails the
  conn on `sw`.

Gates: module tests Debug + ReleaseSafe, full suite Debug + ReleaseSafe
under `lockf -k -t 14400 /tmp/rv-suite.lock` (the 3600 s timeout has
timed out on this host: rv-suite.lock is queued behind several agents),
with `ZIG_GLOBAL_CACHE_DIR=/tmp/zig-gc-f3`.

## 10. Review decisions (zed, PR #41, 2026-11-05)

The design was approved with these changes; all are folded in above.

1. Outbox and inbox are runtime-sized slices allocated once at
   `Conn.init` from `Conn.Options`; defaults equal today's per-consumer
   memory (c2s/s2s 8 KiB + 16 KiB, IPC `MAX_FRAME_SIZE` + 4 MiB cap).
   Spill is `.empty` until first use and freed above a 64 KiB high-water
   mark when the outbox drains empty. `max_outbound_bytes` is the
   `spill_limit`; past it the result is `failed_closed`.
2. Inbox budget default is 64 KiB or 16 reads per conn per pass; `drain`
   also stops when the inbox is full and returns `budget_left`. Requeue
   is the ConnList end-of-iteration walk through `Loop.requeue`
   (zero-timeout kevent), never a timer.
3. `MAX_PAYLOAD_SIZE` keeps its wire value 65536; no IPC protocol change.
4. The handshake seam hands off the fd (`releaseFd`/`adoptFd`, `Done`
   through `Wake`, deadline enforced by the fd owner); F3 drives it on
   the loop and proves the seam with a second-thread test. No v0.9.1
   consumer ships on-loop handshakes; C2 may only until F7 lands.
5. `onEvent` returns an `Outcome` union; no per-conn callbacks.
   `Conn.close` marks `.closing` and defers the fd close and consumer
   free to the end-of-iteration walk; a second batched event for a
   closing conn is skipped by state check plus ctx generation check.
6. kTLS default is `prefer`, `require` opt-in per listener. kTLS
   engagement is recorded as a per-conn token in the consumer's counter
   registry plus a debug-level line; no per-conn log callback.
7. `SO_NOSIGPIPE` is asserted in `Conn.init` (fd adoption), covering
   connect()ed fds, not only accepted ones.
