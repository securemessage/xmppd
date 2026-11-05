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
4. **Nothing blocks a loop.** TLS handshake CPU is the one heavy step;
   the design isolates it behind the `Handshake` seam so F7 can move it to
   a pool without reworking conn. The data path itself (SSL_read/SSL_write,
   read/writev, frame encode) is bounded per call and per pass by the
   inbox budget and the outbox flush budget.
5. **Timers** stay on the F2 wheel as lifecycle deadlines owned by the
   consumer (connect timeout, handshake deadline, SM expiry). conn owns no
   timers; it exposes the ctx the consumer schedules against.
6. **Measurement.** The bench extends with an echo-pass row (read ->
   outbox -> write through both transports) once C2 exists to give it a
   consumer shape.

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
lib/net owns nothing global; `ConnList` is an intrusive per-loop dirty
list whose links live inside `Conn` (the same pattern the F2 loop uses
for its handle dirty list).

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
    policy: KtlsPolicy,    // require | prefer (house default: require)
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
- TLS TX is always `SSL_write` with `SSL_MODE_ENABLE_PARTIAL_WRITE` set at
  ctx setup and `ACCEPT_MOVING_WRITE_BUFFER` **never** relied on: after a
  `want_*`, the retry presents the identical `(ptr, len)`. The Outbox pin
  below is what makes that guarantee possible.
- Raw `send()` on a ktls_tx socket is allowed by the kernel but is NOT
  offered by this layer: one write path keeps the pin story single and
  testable. (Sendfile stays an F7+ evaluation, never in this design.)
- No `SSL_key_update` API exists. A peer-initiated KeyUpdate surfaces as a
  mid-stream `bad record mac`/`no suitable record layer` error
  (PR-unfixable per kTLS D9); the conn reports `err` and the consumer
  reconnects. Documented, not hidden.
- After `doHandshake` returns `ok`, the conn reads
  `BIO_get_ktls_send`/`BIO_get_ktls_recv` once and logs one token per
  connection (`ktls`, `ktls-tx`, `ktls-rx`, `sw`) through a caller-supplied
  log callback. Under `ktls=require` (the default) a `0` on either flag
  fails the conn at this point; `prefer` records `sw` and continues.
- Plain transport: `read()`/`writev()` with `MSG_NOSIGNAL` equivalent
  (`SO_NOSIGPIPE` is set on the accepted socket by the listener side; the
  design asserts it in the accept helper).

`Transport` deliberately has no `attach`/`interest` knowledge: interest
reconciliation stays on the F2 `Loop`, and `Conn` translates results into
`setInterest` calls.

## 3. Inbox

```zig
pub const Inbox = struct {
    buf: []u8,       // owned, allocated once at conn init (default 64 KiB)
    len: usize,
    consumed: usize, // deferred compaction: parses borrow buf until consumed()
    eof: bool,
};

pub const DrainResult = enum { drained, budget_left, eof, err };

/// Read until EAGAIN or until `budget` bytes are moved. Returns whether
/// the socket is drained; a `budget_left` result means more data is
/// pending and the conn must be re-driven before the loop sleeps.
pub fn drain(in: *Inbox, t: *Transport, budget: usize) DrainResult;
pub fn unread(in: *const Inbox) []const u8;   // bytes available to parse
pub fn consume(in: *Inbox, n: usize) void;    // mark n parsed
pub fn compact(in: *Inbox) void;              // moves only unconsumed bytes
```

Fairness: `drain` stops at `budget` (consumer-tuned, default 256 KiB or 64
reads, whichever first). On `budget_left` the conn is marked on the
consumer's `ConnList` and the loop is asked for one more pass
(`requestImmediate`). This matters on FreeBSD because `EVFILT_READ |
EV_CLEAR` is transition-armed: data left unread produces no new event, so
requeue must be explicit. A stalled conn therefore gets exactly one extra
pass at a time and never starves the batch.

`unread()` hands the parser a stable slice; `consume(n)` records parsed
bytes without moving memory, so parsed spans stay valid until the next
`drain`/`compact`. Compaction happens once per `drain`, not per message:
the order's "compact once per read".

## 4. Outbox and the pin

```zig
pub const Outbox = struct {
    ring: [ring_size]u8,           // inline, default 32 KiB
    head: usize, tail: usize,      // [head, tail) unsent in ring
    spill: std.ArrayListUnmanaged(u8),
    spill_limit: usize,            // max_outbound_bytes beyond the ring
    pin: ?Pin,                     // in-flight TLS write
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
  ring is a fixed inline array and its addresses cannot move, so a spill
  realloc can never invalidate the pin. `flush` writes ring runs first
  and only drains `spill` when the ring is empty, reloading it into the
  ring's free space (a bounded copy) rather than pinning spill memory.
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

## 5. Conn, ConnList, and the event contract

```zig
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

pub fn onEvent(c: *Conn, ev: Event) void;      // state machine driver
pub fn close(c: *Conn) void;                   // SSL_shutdown once, loop.close
pub fn startTls(c: *Conn, hs: *Handshake) StartError!void;
```

`onEvent` translates loop events into drain/flush calls and interest
updates: a readable event drains Inbox within the budget and reports
whether more remains; a writable event drives either the handshake or an
Outbox flush; `eof`/`err` surfaces one terminal event to the consumer via
its ctx. When the inbox is partially consumed and the outbox has data,
`Conn` sets write interest; when both are satisfied it drops it - the
loop's `EV_DISPATCH` write interest (F2) keeps registration cheap.

`ConnList` is the intrusive per-loop dirty list (head/tail/count, O(1)
link/unlink, order-preserving). The consumer walks it at end-of-iteration
for outbox flushes and inbox-budget re-drives; it is the conn-level
analog of the loop's dirty list, and it is what makes the
end-of-iteration flush rule from ADR-2 mechanical rather than "the
consumer remembered to".

## 6. STARTTLS rule

`startTls` refuses (`StartError.OutboxNotEmpty` / `ReadAhead`) unless:

1. `outbox.empty()` - nothing queued behind the upgrade point;
2. `inbox.unread().len == 0` **and** the conn has consumed nothing past
   the upgrade point - any buffered post-upgrade bytes are a protocol
   error and a command-injection risk (kTLS skill section 6), so both
   conditions fail closed.

On acceptance the conn moves to `.handshake` on the same fd; the
cleartext phase is unaffected because kTLS engages only after the
handshake completes. `Handshake` (below) owns the `SslConn` during the
upgrade.

## 7. Handshake and the F7 pool seam

```zig
pub const Handshake = struct {
    conn: ssl.SslConn,
    deadline_ctx: Token,   // consumer-owned
    done: Done,            // result slot the pool posts back
};

pub const Done = union(enum) { ok, want_read, want_write, err: SslError };
```

`Handshake.init(ctx, fd, mode)` builds the `SslConn` (SSL_set_fd,
SSL_accept/SSL_connect selection, hostname/DANE hooks live with the
caller). `Handshake.step()` runs one `SSL_do_handshake` and is pure CPU:
it touches no loop state, so F7 can run `step()` on a pool thread and
post the `Done` through `loop.wake`/`Broadcast`. F3 ships `step` driven
on the loop (acceptably cheap for the measured ~240 us handshake in
ADR-11) plus the seam: the object is already thread-movable and the
result arrives only through `Done`, never through side effects on the
conn. `conn.finishHandshake(hs)` installs the `Tls` transport, reads and
logs the kTLS flags once, applies the `require|prefer` check, and moves
to `.established`.

## 8. Frame format (IPC)

Wire-compatible with `src/ipc/protocol.zig` today:

```
frame  := header payload
header := u32 little-endian payload_len        (HEADER_SIZE = 4)
payload_len <= MAX_PAYLOAD_SIZE                (64 KiB - 4)
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
  listening `Conn`): handshake completion, kTLS flags logged exactly
  once, `SSL_read` after `want_write` re-drive, `SSL_write` after
  `want_read` re-drive, clean close.
- Tiny-`SO_SNDBUF` tests: `setsockopt(SO_SNDBUF, 1 KiB)` on the accepted
  side so the kernel accepts less than the outbox holds. Required for
  - the pin proof: append a large gather, flush to WANT_WRITE, append
    more behind it, drive writable events, peer receives byte-identical
    data; kills a "retry with a moved slice" revert;
  - the partial-write path: a `want_write` mid-slice retry presents the
    identical `(ptr, len)`;
  - inbox/outbox budgets: `budget_left` requeues via `requestImmediate`
    and completes without busy-looping (assert pass counts).
- Inbox: fill/compaction/unread stability across parses; EOF mid-frame.
- Outbox: gather order, ring wrap, spill bound -> `failed_closed`,
  spill-reload-into-ring after drain, `empty()`/`bytes()` accounting.
- ConnList fuzz: seeded mix of readable/writable/close/requeue with a
  full link-invariant walk after every op (the F2 dirty-list fuzz shape).
- STARTTLS: refusal on non-empty outbox and on unread bytes; upgrade on
  clean state drives `Handshake.step` and lands in `.established`.
- Frame: roundtrip, split header, split payload, coalesced frames,
  oversize header rejection, drain-to-EAGAIN backlog growth, writer
  encode-in-place produces wire-identical bytes vs `protocol.encode`.
- kTLS engagement test on the loopback path runs with ONE userland end
  only (PR 296498): assert `ktls_*` flags and the one-shot log, plus a
  `prefer` fallback row with kTLS disabled via `kern.ipc.tls.enable=0`
  context or a userland-only ctx.

Gates: module tests Debug + ReleaseSafe, full suite Debug + ReleaseSafe
under `lockf -k -t 3600 /tmp/rv-suite.lock`, with
`ZIG_GLOBAL_CACHE_DIR=/home/admin/tmp/zig-gc-net` (the shared cache holds
a stale `libcompiler_rt.a` manifest; same workaround as F3's gates need).

## 10. Open questions for zed

1. `Outbox` sizes: 32 KiB inline ring + `spill_limit` default. ADR-2
   says bounded to `max_outbound_bytes`; the IPC conn today allows
   4 MiB. Proposal: `ring_size = 32 KiB`, `spill_limit = 4 MiB` total
   outbound, both configurable per conn.
2. `Inbox` default budget: 256 KiB or 64 read calls per pass, whichever
   first. OK?
3. `MAX_PAYLOAD_SIZE`: keep 64 KiB-4 wire-compatible, or raise now that
   the buffer is sized per reader? (Keeping it is simplest and matches
   the running protocol.)
4. `Handshake` drives `step()` on the loop in F3 by design (F7 owns the
   pool). Any objection to shipping the seam-only version?
5. `Conn.onEvent` delivers consumer outcomes through a callback on
   `ctx` resolution (consumer registers per-conn ctx handlers), not a
   queued event type. Alternative: a small `ConnEvent` union the
   consumer drains. Preference?
