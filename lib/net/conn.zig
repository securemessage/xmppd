//! Conn: per-connection I/O on the F2 loop substrate (ADR-8, F3).
//!
//! `Transport` is the byte mover: plain fd or TLS over a socket BIO. All
//! TLS traffic goes through `SSL_read`/`SSL_write` (kTLS D2); the retry
//! after `want_*` presents the identical (ptr, len) the Outbox pin keeps
//! stable (kTLS D3); there is no `SSL_key_update` path (kTLS D9); and
//! kTLS engagement is proven once per handshake through
//! `BIO_get_ktls_send`/`BIO_get_ktls_recv` and recorded as a token.
//! See F3-DESIGN.md for the full contract.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const ssl = @import("ssl");
const loop_mod = @import("loop.zig");
const Token = @import("token.zig").Token;
const SlotMap = @import("slotmap.zig").SlotMap;

pub const Loop = loop_mod.Loop;
pub const Handle = loop_mod.Handle;
pub const Interest = loop_mod.Interest;
pub const Event = loop_mod.Event;
pub const SslError = ssl.SslError;

/// Every error a transport read or write can surface: TLS-layer failures
/// plus the errno-mapped socket errors.
pub const IoError = ssl.SslError || posix.ReadError || posix.WriteError;

pub const KtlsPolicy = enum {
    /// Never refuse a conn for missing offload; record the `sw` token.
    prefer,
    /// Opt-in per listener: fail the conn when either direction did not
    /// offload.
    require,
};

/// The one token recorded per TLS conn (plus a debug log line):
/// which directions kernel-TLS engaged.
pub const KtlsToken = enum { ktls, ktls_tx, ktls_rx, sw };

/// Per-worker counter block the consumer owns (M1 pattern): the record
/// for silent kTLS fallback and fail-closed drops. One pointer in
/// `Options`; nothing here allocates or locks.
pub const Counters = struct {
    ktls: u64 = 0,
    ktls_tx: u64 = 0,
    ktls_rx: u64 = 0,
    sw: u64 = 0,
    outbox_failed_closed: u64 = 0,

    pub fn countKtls(c: *Counters, token: KtlsToken) void {
        switch (token) {
            .ktls => c.ktls += 1,
            .ktls_tx => c.ktls_tx += 1,
            .ktls_rx => c.ktls_rx += 1,
            .sw => c.sw += 1,
        }
    }
};

/// Result of a non-blocking transport read or write.
pub const IoResult = union(enum) {
    /// Bytes moved.
    n: usize,
    /// Drive me on EVFILT_READ.
    want_read,
    /// Drive me on EVFILT_WRITE (SSL_read can want this).
    want_write,
    /// Orderly peer shutdown (read returned 0, or TLS close_notify).
    eof,
    /// Socket or TLS failure; the conn is finished.
    err: IoError,
};

pub const Tls = struct {
    /// `SSL_set_fd` at init; the fd is already non-blocking.
    conn: ssl.SslConn,
    /// Read once after the handshake completes.
    ktls_tx: bool = false,
    ktls_rx: bool = false,
    policy: KtlsPolicy = .prefer,

    /// The token this conn counts once at `finishHandshake`.
    pub fn ktlsToken(t: *const Tls) KtlsToken {
        if (t.ktls_tx and t.ktls_rx) return .ktls;
        if (t.ktls_tx) return .ktls_tx;
        if (t.ktls_rx) return .ktls_rx;
        return .sw;
    }
};

/// Plain fd or TLS, one write path each so the pin story stays single.
/// `tls` points into the owning `Conn`.
pub const Transport = union(enum) {
    plain: posix.fd_t,
    tls: *Tls,

    /// TLS RX is always `SSL_read`; there is no `read()` path on a TLS
    /// conn, so post-handshake records cannot leak as payload (kTLS D2).
    pub fn read(t: *Transport, buf: []u8) IoResult {
        switch (t.*) {
            .plain => |fd| {
                const n = posix.read(fd, buf) catch |err| return switch (err) {
                    error.WouldBlock => .want_read,
                    else => .{ .err = err },
                };
                if (n == 0) return .eof;
                return .{ .n = n };
            },
            .tls => |tls| {
                const r = tls.conn.read(buf) catch |err| return switch (err) {
                    error.ConnectionClosed => .eof,
                    else => .{ .err = err },
                };
                return switch (r) {
                    .ok => |n| .{ .n = n },
                    .want_read => .want_read,
                    .want_write => .want_write,
                };
            },
        }
    }

    /// TLS TX is always `SSL_write` (`SSL_MODE_ENABLE_PARTIAL_WRITE` is
    /// set at ctx setup by the caller; moving-buffer mode is never relied
    /// on). After `want_*` the retry presents the identical (ptr, len);
    /// the Outbox pin is what keeps the slice stable (kTLS D3).
    pub fn write(t: *Transport, buf: []const u8) IoResult {
        switch (t.*) {
            .plain => |fd| {
                const n = posix.write(fd, buf) catch |err| return switch (err) {
                    error.WouldBlock => .want_write,
                    else => .{ .err = err },
                };
                return .{ .n = n };
            },
            .tls => |tls| {
                const r = tls.conn.write(buf) catch |err| return .{ .err = err };
                return switch (r) {
                    .ok => |n| .{ .n = n },
                    .want_read => .want_read,
                    .want_write => .want_write,
                };
            },
        }
    }

    /// Decrypted bytes held inside OpenSSL (`SSL_pending`); always 0 on
    /// the plain transport.
    pub fn pending(t: *const Transport) usize {
        return switch (t.*) {
            .plain => 0,
            .tls => |tls| tls.conn.pending(),
        };
    }

    /// `SSL_shutdown` once, non-blocking, never waited on (kTLS D6).
    /// No-op on the plain transport.
    pub fn shutdown(t: *Transport) void {
        switch (t.*) {
            .plain => {},
            .tls => |tls| tls.conn.shutdown(),
        }
    }
};

/// Per-pass inbound fairness budget (Options.read_budget_*): bytes or
/// read calls, whichever is spent first, so one fast sender cannot hold
/// a pass that serves thousands of connections.
pub const ReadBudget = struct {
    bytes: usize = 64 << 10,
    reads: u32 = 16,
};

/// What a drain pass ended on.
pub const DrainResult = union(enum) {
    /// EAGAIN: the socket is dry and EV_CLEAR will report new data.
    drained,
    /// Budget spent: more data may be pending; re-drive the conn
    /// before the loop sleeps (ConnList + Loop.requeue).
    budget_left,
    /// Inbox cannot take more until the consumer consumes. The conn
    /// parks its read interest and re-drives only from `Conn.consume`;
    /// re-queuing every pass would busy-loop the worker.
    full,
    /// The TLS read needed a write event first.
    want_write,
    /// Orderly peer shutdown; `eof` latches on the inbox.
    eof,
    /// Socket or TLS failure; the conn is finished.
    err: IoError,
};

/// Reads plaintext or decrypted bytes into a caller-owned slice.
///
/// `consumed` is the deferred-compaction cursor: bytes below it were
/// parsed already; `drain` folds them away once per call, never per
/// message, so parsed spans stay valid until the next drain.
pub const Inbox = struct {
    /// Owned slice, allocated once at Conn.init (Options.inbox_bytes).
    buf: []u8,
    len: usize = 0,
    consumed: usize = 0,
    eof: bool = false,

    pub fn init(buf: []u8) Inbox {
        return .{ .buf = buf };
    }

    /// Bytes available to parse. Borrows `buf` and stays valid until the
    /// next `drain`/`compact`.
    pub fn unread(in: *const Inbox) []const u8 {
        return in.buf[in.consumed..in.len];
    }

    /// Mark `n` parsed bytes consumed; compaction is deferred to drain.
    pub fn consume(in: *Inbox, n: usize) void {
        std.debug.assert(in.consumed + n <= in.len);
        in.consumed += n;
    }

    /// True when the buffer holds `buf.len` bytes: a drain can move
    /// nothing until bytes are consumed. A consumer that finds nothing
    /// parseable in a full inbox should close with a stream error.
    pub fn full(in: *const Inbox) bool {
        return in.len == in.buf.len;
    }

    /// Move unconsumed bytes to the front and clear the cursor.
    pub fn compact(in: *Inbox) void {
        if (in.consumed == 0) return;
        const remaining = in.len - in.consumed;
        if (remaining > 0) {
            std.mem.copyForwards(u8, in.buf[0..remaining], in.buf[in.consumed..in.len]);
        }
        in.len = remaining;
        in.consumed = 0;
    }

    /// Read until EAGAIN, the budget is spent, the inbox fills, or EOF.
    /// A `budget_left` result means more data may be pending and the conn
    /// must be re-driven before the loop sleeps: EV_CLEAR is
    /// transition-armed, so leftover data raises no new event. A `full`
    /// result means nothing can move until the consumer consumes.
    pub fn drain(in: *Inbox, t: *Transport, budget: *ReadBudget) DrainResult {
        if (in.eof) return .eof;
        in.compact();
        while (true) {
            if (budget.reads == 0 or budget.bytes == 0) return .budget_left;
            const space = in.buf.len - in.len;
            if (space == 0) return .full;
            budget.reads -= 1;
            const want = @min(space, budget.bytes);
            switch (t.read(in.buf[in.len .. in.len + want])) {
                .n => |n| {
                    in.len += n;
                    budget.bytes -= n;
                },
                .want_read => return .drained,
                .want_write => return .want_write,
                .eof => {
                    in.eof = true;
                    return .eof;
                },
                .err => |e| return .{ .err = e },
            }
        }
    }
};

/// What an append did with the bytes.
pub const AppendResult = enum {
    /// All parts fit in the ring.
    queued,
    /// Ring was full; parts went to the bounded spill.
    spilled,
    /// Past max_outbound_bytes: fail closed, nothing dropped silently.
    failed_closed,
};

/// What a flush pass ended on.
pub const FlushResult = union(enum) {
    /// Ring and spill are both empty.
    drained,
    /// TLS write needs a read event (post-handshake traffic); arm read.
    want_read,
    /// Kernel send buffer full or TLS wants a write; arm write.
    want_write,
    /// The per-pass flush budget was spent; re-drive via ConnList.
    budget_left,
    /// Socket or TLS failure; the conn is finished.
    err: IoError,
};

/// The retained (ptr, len) of an in-flight write that returned want_*.
/// Formed only from `ring`, never from `spill`: the ring is one heap
/// slice allocated at Conn.init and its addresses cannot move, so a
/// spill realloc can never invalidate the pin (kTLS D3).
const Pin = struct { ptr: [*]const u8, len: usize };

/// Queues outbound bytes: a fixed ring first, a bounded spill behind
/// it. The pin holds the head run across a want_* retry so the TLS
/// retry presents an identical (ptr, len); new bytes sit behind it
/// and are never part of the retry (S23's rule).
pub const Outbox = struct {
    /// Owned slice, allocated once at Conn.init (Options.outbox_ring_bytes).
    ring: []u8,
    /// Index of the first unsent byte.
    head: usize = 0,
    /// Unsent bytes in the ring.
    used: usize = 0,
    /// Backlog behind the ring: [spill_head, items.len) unsent.
    /// `.empty` until first use, so idle conns pay nothing.
    spill: std.ArrayList(u8) = .empty,
    spill_head: usize = 0,
    /// Options.max_outbound_bytes: the spill bound (fail closed past it).
    spill_limit: usize,
    /// Spill capacity kept once the outbox drains empty (default 64 KiB).
    spill_high_water: usize = 64 << 10,
    pin: ?Pin = null,
    counters: *Counters,
    alloc: std.mem.Allocator,

    pub fn init(ring: []u8, alloc: std.mem.Allocator, spill_limit: usize, counters: *Counters) Outbox {
        return .{ .ring = ring, .spill_limit = spill_limit, .counters = counters, .alloc = alloc };
    }

    pub fn deinit(o: *Outbox) void {
        o.spill.deinit(o.alloc);
    }

    /// Total unsent bytes (ring plus pending spill).
    pub fn bytes(o: *const Outbox) usize {
        return o.used + o.spill.items.len - o.spill_head;
    }

    pub fn empty(o: *const Outbox) bool {
        return o.bytes() == 0;
    }

    fn ringFree(o: *const Outbox) usize {
        return o.ring.len - o.used;
    }

    fn ringTail(o: *const Outbox) usize {
        return (o.head + o.used) % o.ring.len;
    }

    /// Gather append: parts are copied once, whole-append into the ring
    /// when it all fits (keeps frames contiguous), otherwise all of it
    /// into the bounded spill. Once spill holds bytes every append goes
    /// to spill: flush sends the ring first, so a ring append would
    /// overtake the earlier spill bytes on the wire. Over `spill_limit`
    /// the result is `failed_closed` and the counter moves; nothing is
    /// dropped silently.
    pub fn append(o: *Outbox, parts: []const []const u8) AppendResult {
        var total: usize = 0;
        for (parts) |p| total += p.len;
        if (total == 0) return .queued;

        const pending = o.spill.items.len - o.spill_head;
        if (pending == 0 and total <= o.ringFree()) {
            for (parts) |p| o.ringWrite(p);
            return .queued;
        }

        if (pending + total > o.spill_limit) {
            o.counters.outbox_failed_closed += 1;
            return .failed_closed;
        }
        for (parts) |p| {
            o.spill.appendSlice(o.alloc, p) catch {
                o.counters.outbox_failed_closed += 1;
                return .failed_closed;
            };
        }
        return .spilled;
    }

    /// Copy `data` into the ring's free space (wrapping); caller checked
    /// it fits.
    fn ringWrite(o: *Outbox, data: []const u8) void {
        const cap = o.ring.len;
        var pos = o.ringTail();
        var rest = data;
        while (rest.len > 0) {
            const run = @min(rest.len, cap - pos);
            @memcpy(o.ring[pos .. pos + run], rest[0..run]);
            pos = (pos + run) % cap;
            rest = rest[run..];
        }
        o.used += data.len;
    }

    /// Move spill into the empty ring (bounded copy); the pin is only
    /// ever formed from ring memory, so spill bytes must pass through
    /// the ring before they can be written.
    fn reloadRing(o: *Outbox) void {
        std.debug.assert(o.used == 0);
        const pending = o.spill.items.len - o.spill_head;
        if (pending == 0) return;
        const n = @min(pending, o.ring.len);
        @memcpy(o.ring[0..n], o.spill.items[o.spill_head .. o.spill_head + n]);
        o.head = 0;
        o.used = n;
        o.spill_head += n;
        if (o.spill_head == o.spill.items.len) {
            o.spill.clearRetainingCapacity();
            o.spill_head = 0;
        } else if (o.spill_head >= o.spill.items.len - o.spill_head) {
            // Half or more of the allocation is sent bytes: fold the
            // pending tail to the front. Without this a steady backlog
            // (peer drains about as fast as we produce) lets items.len
            // grow with total traffic forever.
            const rest = o.spill.items.len - o.spill_head;
            std.mem.copyForwards(u8, o.spill.items[0..rest], o.spill.items[o.spill_head..]);
            o.spill.items.len = rest;
            o.spill_head = 0;
        }
    }

    /// Once the outbox drains empty, release spill capacity above the
    /// high-water mark: one burst must not pin memory for the session.
    fn releaseSpill(o: *Outbox) void {
        if (o.spill.capacity <= o.spill_high_water) return;
        if (o.alloc.resize(o.spill.allocatedSlice(), o.spill_high_water)) {
            o.spill.capacity = o.spill_high_water;
            return;
        }
        o.spill.shrinkAndFree(o.alloc, 0);
        // Best-effort retention of the high-water arena; an alloc
        // failure is not fatal, the spill just re-grows next burst.
        o.spill.ensureTotalCapacityPrecise(o.alloc, o.spill_high_water) catch {};
    }

    /// Write out until empty, want_*, or the per-call byte budget is
    /// spent. A pending pin is retried verbatim before any new slice is
    /// formed; the retry never grows (S23).
    pub fn flush(o: *Outbox, t: *Transport, budget: usize) FlushResult {
        var left = budget;
        while (true) {
            if (o.pin == null) {
                if (o.used == 0) {
                    o.reloadRing();
                    if (o.used == 0) {
                        o.releaseSpill();
                        return .drained;
                    }
                }
                const run = @min(o.used, o.ring.len - o.head);
                const want = @min(run, left);
                if (want == 0) return .budget_left;
                o.pin = .{ .ptr = @ptrCast(o.ring.ptr + o.head), .len = want };
            }
            if (left == 0) return .budget_left;
            const p = o.pin.?;
            switch (t.write(p.ptr[0..p.len])) {
                .n => |n| {
                    if (n == 0) return .want_write;
                    o.head = (o.head + n) % o.ring.len;
                    o.used -= n;
                    o.pin = null;
                    left -= n;
                },
                .want_write => return .want_write,
                .want_read => return .want_read,
                .eof => return .{ .err = error.WriteFailed },
                .err => |e| return .{ .err = e },
            }
        }
    }
};

/// Per-consumer sizes and budgets (F3-DESIGN section 1): defaults equal
/// today's per-connection memory; any increase needs an M-series
/// measurement.
pub const Options = struct {
    inbox_bytes: usize = 8 << 10,
    outbox_ring_bytes: usize = 16 << 10,
    max_outbound_bytes: usize = 1 << 20,
    read_budget_bytes: usize = 64 << 10,
    read_budget_reads: u32 = 16,
    flush_budget_bytes: usize = 64 << 10,
    ktls: KtlsPolicy = .prefer,
    counters: *Counters,
};

pub const State = enum { cleartext, handshake, established, closing };

pub const CloseReason = union(enum) {
    /// Orderly peer shutdown.
    eof,
    /// Socket or TLS failure; the error is captured for the consumer.
    err: anyerror,
    /// Outbox append exceeded max_outbound_bytes (fail closed).
    outbox_full,
    /// `Conn.close` called by the consumer.
    consumer,
};

/// What `onEvent` wants the consumer's dispatch to do. There are no
/// per-conn callbacks and no event queue: a callback that closes or
/// frees the conn inside `onEvent` is the UAF class T215 fixed, so every
/// terminal effect goes through this return value and the
/// end-of-iteration ConnList walk.
pub const Outcome = union(enum) {
    /// Event absorbed: interest change only, or a stale event on a
    /// closing conn.
    none,
    /// New bytes sit in `inbox.unread()`; consumer parses + consume()s.
    readable,
    /// Handshake completed: `.handshake` -> `.established`; the kTLS
    /// token was recorded.
    handshake_done,
    /// The conn is on the closing list; the consumer frees it in the
    /// end-of-iteration walk.
    closed: CloseReason,
};

/// The handoff object for the TLS handshake (F3-DESIGN section 7).
/// Owns the fd and the SslConn while the upgrade runs; whoever holds
/// the fd enforces the deadline through `deadline_ctx`. `done` is the
/// only cross-thread channel: the driving thread posts it, never a
/// side effect on the conn.
pub const Handshake = struct {
    conn: ssl.SslConn,
    fd: posix.fd_t,
    deadline_ctx: Token,
    done: Done = .want_read,

    /// One `SSL_do_handshake` call. On a socket BIO this does socket
    /// I/O, so it runs where the fd is registered: the consumer's loop
    /// in F3, a pool thread's own kqueue in F7.
    pub fn step(hs: *Handshake) Done {
        const r = hs.conn.doHandshake() catch |e| {
            hs.done = .{ .err = e };
            return hs.done;
        };
        hs.done = switch (r) {
            .complete => .ok,
            .want_read => .want_read,
            .want_write => .want_write,
        };
        return hs.done;
    }
};

pub const Done = union(enum) {
    ok,
    want_read,
    want_write,
    err: SslError,
};

pub const StartError = error{
    /// STARTTLS requires an empty outbox (the ADR-2 upgrade-point rule).
    OutboxNotEmpty,
    /// Bytes buffered past the upgrade point are a protocol error.
    ReadAhead,
    /// SslConn init failed on the fd.
    SslInitFailed,
    /// The fd was released to a handshake driver already.
    Detached,
};

/// One connection's I/O state on its owning loop. Must not move after
/// init: `Transport.tls` points into the struct and ConnList links live
/// inside it.
pub const Conn = struct {
    loop: *Loop,
    handle: loop_mod.Handle,
    transport: Transport,
    tls_storage: Tls,
    hs: ?Handshake,
    inbox: Inbox,
    outbox: Outbox,
    state: State,
    /// Consumer's ctx token, attached as the handle's ctx and echoed.
    ctx: Token,
    opts: Options,
    /// ConnList dirty links (intrusive; consumer owns the list).
    dirty_next: ?*Conn = null,
    dirty_prev: ?*Conn = null,
    on_dirty: bool = false,
    /// Deferred end-of-iteration work the consumer's walk performs.
    requeue_read: bool = false,
    requeue_write: bool = false,
    /// `tls_storage.conn` owns a live SSL*; deinit frees it. Keyed on a
    /// flag, not state: teardown requires `.closing`, so no conn closed
    /// through the contract is ever `.established` at deinit.
    tls_live: bool = false,
    /// Last write interest passed to `interest`, kept so a read
    /// suppression can re-arm without clobbering it.
    want_write: bool = false,
    /// Read is parked: the last drain found the inbox full. Lifted only
    /// by `Conn.consume`; a parked read must not wake the loop.
    inbox_stalled: bool = false,

    /// Adopt `fd` (accepted or connect()ed): asserts SO_NOSIGPIPE so
    /// outbound s2s fds are covered the same as accepted ones, and
    /// attaches read interest on the loop. The fd must already be
    /// non-blocking; `alloc` backs inbox, ring and spill for the conn's
    /// lifetime.
    pub fn init(c: *Conn, loop: *Loop, fd: posix.fd_t, ctx: Token, alloc: std.mem.Allocator, opts: Options) !void {
        try setNoSigpipe(fd);
        if (builtin.mode == .Debug) {
            const fl = std.c.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
            std.debug.assert(fl >= 0 and fl & o_nonblock != 0);
        }
        const inbox_buf = try alloc.alloc(u8, opts.inbox_bytes);
        errdefer alloc.free(inbox_buf);
        const ring_buf = try alloc.alloc(u8, opts.outbox_ring_bytes);
        errdefer alloc.free(ring_buf);
        const handle = try loop.attach(fd, ctx, .{ .read = true });
        c.* = .{
            .loop = loop,
            .handle = handle,
            .transport = .{ .plain = fd },
            .tls_storage = .{ .conn = undefined, .policy = opts.ktls },
            .hs = null,
            .inbox = Inbox.init(inbox_buf),
            .outbox = Outbox.init(ring_buf, alloc, opts.max_outbound_bytes, opts.counters),
            .state = .cleartext,
            .ctx = ctx,
            .opts = opts,
        };
    }

    /// Free inbox/ring/spill memory. Only valid after `teardown` (the
    /// fd is already closed) or when init's attach never ran.
    pub fn deinit(c: *Conn) void {
        if (c.tls_live) c.tls_storage.conn.deinit();
        if (c.hs) |*hs| hs.conn.deinit();
        const alloc = c.outbox.alloc;
        c.outbox.deinit();
        alloc.free(c.inbox.buf);
        alloc.free(c.outbox.ring);
    }

    /// Record the wanted interest and reconcile it with the loop. Read
    /// is armed only while the inbox is not parked: a full inbox cannot
    /// move, and re-driving it every pass spins the worker.
    fn interest(c: *Conn, read: bool, write: bool) void {
        c.want_write = write;
        c.loop.setInterest(c.handle, .{ .read = read and !c.inbox_stalled, .write = write }) catch {};
    }

    fn markClosing(c: *Conn, list: *ConnList) void {
        c.state = .closing;
        list.link(c);
    }

    /// State machine driver: translates loop events into drain/flush
    /// calls and interest updates, returning the Outcome the consumer
    /// switches on. A second batched event for a conn closed by the
    /// first hits the `.closing` short-circuit and is skipped.
    pub fn onEvent(c: *Conn, ev: Event, list: *ConnList) Outcome {
        if (c.state == .closing) return .none;
        return switch (ev) {
            .readable => c.onReadable(list),
            .writable => c.onWritable(list),
            // The loop marked the handle broken: its kevent changes can
            // no longer reach the kernel, so the conn cannot be driven.
            .change_failed => {
                c.markClosing(list);
                return .{ .closed = .{ .err = error.ChangeFailed } };
            },
            else => .none,
        };
    }

    fn onReadable(c: *Conn, list: *ConnList) Outcome {
        if (c.state == .handshake) return c.driveHandshake(list);
        var budget: ReadBudget = .{ .bytes = c.opts.read_budget_bytes, .reads = c.opts.read_budget_reads };
        return switch (c.inbox.drain(&c.transport, &budget)) {
            .drained => .readable,
            .full => {
                // Nothing can move until the consumer consumes: park the
                // read (interest() applies the suppression) and report
                // the buffered bytes; re-queuing here would busy-loop.
                c.inbox_stalled = true;
                c.interest(true, c.want_write);
                return .readable;
            },
            .budget_left => {
                // EV_CLEAR raises no new event for data left pending:
                // the end-of-iteration walk re-drives this conn.
                c.requeue_read = true;
                list.link(c);
                return .readable;
            },
            .want_write => {
                // TLS read needs a write event (post-handshake reply):
                // arm write interest; the writable pass re-drives.
                c.requeue_read = true;
                c.interest(true, true);
                return .readable;
            },
            .eof => {
                c.markClosing(list);
                return .{ .closed = .eof };
            },
            .err => |e| {
                c.markClosing(list);
                return .{ .closed = .{ .err = e } };
            },
        };
    }

    fn onWritable(c: *Conn, list: *ConnList) Outcome {
        if (c.state == .handshake) return c.driveHandshake(list);
        const r = c.outbox.flush(&c.transport, c.opts.flush_budget_bytes);
        switch (r) {
            .drained => {
                if (c.requeue_read) {
                    // The write the TLS read was waiting for happened:
                    // the walk re-drives the stalled read. The flag
                    // stays set so the walk can see it.
                    list.link(c);
                }
                c.interest(true, false);
                return .none;
            },
            .want_write => return .none, // write interest stays armed
            .want_read => return .none,  // read interest already armed
            .budget_left => {
                c.requeue_write = true;
                list.link(c);
                return .none;
            },
            .err => |e| {
                c.markClosing(list);
                return .{ .closed = .{ .err = e } };
            },
        }
    }

    fn driveHandshake(c: *Conn, list: *ConnList) Outcome {
        const hs = &c.hs.?;
        switch (hs.step()) {
            .ok => {
                c.finishHandshake();
                if (c.state == .closing) {
                    // require failed inside finishHandshake: link so the
                    // walk tears the conn down (fd and SSL would leak).
                    list.link(c);
                    return .{ .closed = .{ .err = error.KtlsRequired } };
                }
                // OpenSSL consumed the Finished record and may have left
                // a coalesced app-data record in the socket; EV_CLEAR
                // already fired for it, so re-drive one read through the
                // walk. The same link makes the walk flush any outbox
                // bytes queued during the upgrade.
                c.requeue_read = true;
                list.link(c);
                return .handshake_done;
            },
            .want_read => {
                c.interest(true, false);
                return .none;
            },
            .want_write => {
                c.interest(true, true);
                return .none;
            },
            .err => |e| {
                c.markClosing(list);
                return .{ .closed = .{ .err = e } };
            },
        }
    }

    /// Install the Tls transport after Handshake reports .ok: read the
    /// kTLS flags once, record the one-shot token in the consumer's
    /// counter registry plus a debug line, and apply the policy.
    /// `prefer` never refuses; `require` closes the conn on `sw` or a
    /// partial offload.
    pub fn finishHandshake(c: *Conn) void {
        const hs = &c.hs.?;
        c.tls_storage = .{
            .conn = hs.conn,
            .ktls_tx = hs.conn.ktlsSend(),
            .ktls_rx = hs.conn.ktlsRecv(),
            .policy = c.opts.ktls,
        };
        hs.conn = undefined;
        c.hs = null;
        c.tls_live = true;
        const token = c.tls_storage.ktlsToken();
        c.opts.counters.countKtls(token);
        std.log.scoped(.net_conn).debug("tls established fd={d} ktls={s} {s}/{s}", .{
            c.sockFd(), @tagName(token), c.tls_storage.conn.versionName(), c.tls_storage.conn.cipherName(),
        });
        if (c.opts.ktls == .require and token != .ktls) {
            c.state = .closing;
            return;
        }
        c.transport = .{ .tls = &c.tls_storage };
        c.state = .established;
        c.interest(true, false);
    }

    /// STARTTLS upgrade point (the single rule): refuse when anything
    /// is queued behind the upgrade or buffered past it. On acceptance
    /// the conn moves to `.handshake`; `Handshake` owns the fd and the
    /// SslConn for the upgrade.
    pub fn startTls(c: *Conn, sctx: ssl.SslContext, mode: enum { accept, connect }, hostname: ?[*:0]const u8, deadline_ctx: Token) StartError!void {
        if (!c.outbox.empty()) return StartError.OutboxNotEmpty;
        if (c.inbox.unread().len != 0) return StartError.ReadAhead;
        const fd = switch (c.transport) {
            .plain => |fd| fd,
            .tls => return StartError.ReadAhead, // already upgraded
        };
        const sc = switch (mode) {
            .accept => ssl.SslConn.init(sctx, fd),
            .connect => ssl.SslConn.initClient(sctx, fd, hostname),
        } catch return StartError.SslInitFailed;
        c.hs = .{ .conn = sc, .fd = fd, .deadline_ctx = deadline_ctx };
        c.state = .handshake;
    }

    /// The conn's socket, or -1 while released to a handshake driver.
    pub fn sockFd(c: *const Conn) posix.fd_t {
        return c.loop.fdOf(c.handle) orelse (if (c.hs) |*hs| hs.fd else -1);
    }

    /// Hand the fd to a handshake driver (ADR-11 step 1): the loop
    /// detaches it (immediate EV_DELETE per filter) so a pool thread can
    /// register it on its own kqueue. The conn keeps `ctx`; the driver
    /// posts `Done` back through `loop.wake` and the consumer re-adopts.
    pub fn releaseFd(c: *Conn) loop_mod.DetachError!posix.fd_t {
        const fd = try c.loop.detach(c.handle);
        if (c.hs) |*hs| hs.fd = fd;
        return fd;
    }

    /// Re-attach the fd on the owning loop after a handshake driver
    /// posts `Done` back.
    pub fn adoptFd(c: *Conn, fd: posix.fd_t) loop_mod.AttachError!void {
        c.handle = try c.loop.attach(fd, c.ctx, .{ .read = true });
        c.want_write = false;
    }

    /// Consumer-initiated close: marks `.closing` and links the conn on
    /// the ConnList; the fd close and the consumer's free happen in the
    /// end-of-iteration walk, after every batched event ran.
    pub fn close(c: *Conn, list: *ConnList) void {
        c.markClosing(list);
    }

    /// Mark `n` inbox bytes parsed (the only supported consume path).
    /// Lifts a full-inbox park: read interest is re-armed and the conn
    /// is re-driven once, since EV_CLEAR's edge is already gone.
    pub fn consume(c: *Conn, list: *ConnList, n: usize) void {
        const stalled = c.inbox_stalled;
        c.inbox.consume(n);
        if (stalled) {
            c.inbox_stalled = false;
            c.interest(true, c.want_write);
            c.requeue_read = true;
            list.link(c);
        }
    }

    /// End-of-iteration teardown for a closing conn: `SSL_shutdown`
    /// once (plain: no-op), then close the loop handle and fd. The
    /// consumer frees the Conn after this.
    pub fn teardown(c: *Conn) void {
        std.debug.assert(c.state == .closing);
        c.transport.shutdown();
        c.loop.close(c.handle) catch |err| switch (err) {
            // A released fd freed its handle slot at detach, so the loop
            // cannot close it. The Handshake still owns it: close it
            // here or a conn torn down mid-upgrade leaks the fd.
            error.StaleHandle => if (c.hs) |*hs| {
                if (hs.fd >= 0) {
                    posix.close(hs.fd);
                    hs.fd = -1;
                }
            },
        };
    }

    /// Queue outbound bytes through the outbox and link the conn so the
    /// end-of-iteration walk flushes (ADR-2): write interest is armed
    /// only when the flush stalls on `want_write`, not per send.
    /// `failed_closed` moves to `.closing` and reports `outbox_full`.
    pub fn send(c: *Conn, list: *ConnList, parts: []const []const u8) Outcome {
        if (c.state == .closing) return .none;
        return switch (c.outbox.append(parts)) {
            .queued, .spilled => {
                list.link(c);
                return .none;
            },
            .failed_closed => {
                c.markClosing(list);
                return .{ .closed = .outbox_full };
            },
        };
    }
};

/// The intrusive per-loop dirty list (FIFO, O(1) link/unlink,
/// order-preserving). The consumer walks it at end-of-iteration for
/// outbox flushes, inbox-budget re-drives and deferred closes; the
/// walk is what makes the ADR-2 end-of-iteration flush rule
/// mechanical.
pub const ConnList = struct {
    head: ?*Conn = null,
    tail: ?*Conn = null,
    count: usize = 0,

    /// Append `c` if it is not linked already (idempotent).
    pub fn link(l: *ConnList, c: *Conn) void {
        if (c.on_dirty) return;
        c.on_dirty = true;
        c.dirty_prev = l.tail;
        c.dirty_next = null;
        if (l.tail) |t| t.dirty_next = c else l.head = c;
        l.tail = c;
        l.count += 1;
    }

    /// Detach `c` without disturbing the order of the rest.
    pub fn unlink(l: *ConnList, c: *Conn) void {
        if (!c.on_dirty) return;
        if (c.dirty_prev) |p| p.dirty_next = c.dirty_next else l.head = c.dirty_next;
        if (c.dirty_next) |n| n.dirty_prev = c.dirty_prev else l.tail = c.dirty_prev;
        c.dirty_next = null;
        c.dirty_prev = null;
        c.on_dirty = false;
        l.count -= 1;
    }

    /// Remove and return the head, or null.
    pub fn pop(l: *ConnList) ?*Conn {
        const c = l.head orelse return null;
        l.unlink(c);
        return c;
    }

    pub fn empty(l: *const ConnList) bool {
        return l.head == null;
    }

    /// The end-of-iteration walk (ADR-2): tear down closing conns,
    /// flush dirty outboxes (the flush `send` defers to), and turn
    /// deferred work flags into `Loop.requeue` calls so each conn is
    /// re-driven once on the next pass. Bounded by membership: a conn
    /// links at most once and `pop` unlinks it. A StaleHandle requeue
    /// means the fd was released to a handshake driver and cannot be
    /// driven anyway.
    pub fn service(l: *ConnList) void {
        while (l.pop()) |c| {
            if (c.state == .closing) {
                c.teardown();
                continue;
            }
            // Mid-upgrade the transport is still plain: queued bytes
            // wait for `.established` rather than leave as cleartext.
            if (c.state != .handshake and !c.outbox.empty()) {
                switch (c.outbox.flush(&c.transport, c.opts.flush_budget_bytes)) {
                    .drained => c.interest(true, false),
                    .want_write => c.interest(true, true),
                    .want_read => c.interest(true, c.want_write),
                    .budget_left => c.requeue_write = true,
                    .err => {
                        c.state = .closing;
                        c.teardown();
                        continue;
                    },
                }
            }
            if (c.requeue_read) {
                c.requeue_read = false;
                c.loop.requeue(c.handle, .read) catch {};
            }
            if (c.requeue_write) {
                c.requeue_write = false;
                c.loop.requeue(c.handle, .write) catch {};
            }
        }
    }

    fn serviceHook(ctx: *anyopaque) void {
        const l: *ConnList = @ptrCast(@alignCast(ctx));
        l.service();
    }

    /// Install as `Loop.Options.on_flush`: the dirty list is serviced at
    /// every end-of-iteration, which makes the ADR-2 flush/requeue rule
    /// mechanical rather than the consumer remembered.
    pub fn flushHook(l: *ConnList) loop_mod.FlushHook {
        return .{ .ctx = l, .func = serviceHook };
    }
};

const o_nonblock: c_int = 0x4; // O_NONBLOCK
const so_nosigpipe: c_int = 0x0800; // SO_NOSIGPIPE (FreeBSD)

fn setNonBlocking(fd: posix.fd_t) !void {
    const fl = std.c.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
    if (fl < 0) return error.Unexpected;
    if (fl & o_nonblock == 0) {
        if (std.c.fcntl(fd, posix.F.SETFL, fl | o_nonblock) != 0) return error.Unexpected;
    }
}

fn setNoSigpipe(fd: posix.fd_t) !void {
    const one: c_int = 1;
    try posix.setsockopt(fd, posix.SOL.SOCKET, so_nosigpipe, std.mem.asBytes(&one));
}

fn socketpair() ![2]posix.fd_t {
    var pair: [2]std.c.fd_t = undefined;
    const flags = posix.SOCK.STREAM | posix.SOCK.CLOEXEC;
    if (std.c.socketpair(posix.AF.UNIX, flags, 0, &pair) != 0) return error.Unexpected;
    try setNonBlocking(pair[0]);
    try setNonBlocking(pair[1]);
    try setNoSigpipe(pair[0]);
    try setNoSigpipe(pair[1]);
    return pair;
}

/// A connected TCP pair over 127.0.0.1: the only test transport where
/// kTLS can engage (unix sockets cannot offload). Pair the server end
/// with a `disableKtls` client: two kTLS ends on loopback hit the
/// PR 296498 kernel bug.
fn tcpPair() ![2]posix.fd_t {
    const l = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(l);
    var addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    try posix.bind(l, &addr.any, addr.getOsSockLen());
    try posix.listen(l, 1);
    var sl: posix.socklen_t = addr.getOsSockLen();
    try posix.getsockname(l, &addr.any, &sl);
    const cfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    try posix.connect(cfd, &addr.any, addr.getOsSockLen());
    const sfd = try posix.accept(l, null, null, posix.SOCK.CLOEXEC);
    try setNonBlocking(sfd);
    try setNonBlocking(cfd);
    try setNoSigpipe(sfd);
    try setNoSigpipe(cfd);
    return .{ sfd, cfd };
}

// ---------------------------------------------------------------------------
// Test PKI: a throwaway self-signed cert (CN=localhost) generated in memory
// per test through libcrypto and written to a tmp dir. Nothing key-shaped
// lives in the source tree.
// ---------------------------------------------------------------------------

const tc = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/objects.h");
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
});

fn bioDrain(bio: *tc.BIO, buf: []u8) ![]u8 {
    const n = tc.BIO_read(bio, buf.ptr, @intCast(buf.len));
    if (n <= 0) return error.SslInitFailed;
    return buf[0..@intCast(n)];
}

const TestPki = struct {
    tmp: std.testing.TmpDir,
    ctx: ssl.SslContext,

    fn deinit(pki: *TestPki) void {
        pki.ctx.deinit();
        pki.tmp.cleanup();
    }
};

fn makeTestPki(alloc: std.mem.Allocator) !TestPki {
    const kctx = tc.EVP_PKEY_CTX_new_id(tc.EVP_PKEY_RSA, null) orelse return error.SslInitFailed;
    defer tc.EVP_PKEY_CTX_free(kctx);
    if (tc.EVP_PKEY_keygen_init(kctx) != 1) return error.SslInitFailed;
    var pkey: ?*tc.EVP_PKEY = null;
    if (tc.EVP_PKEY_keygen(kctx, &pkey) != 1) return error.SslInitFailed;
    defer tc.EVP_PKEY_free(pkey);

    const x509 = tc.X509_new() orelse return error.SslInitFailed;
    defer tc.X509_free(x509);
    _ = tc.X509_set_version(x509, 2);
    _ = tc.ASN1_INTEGER_set(tc.X509_get_serialNumber(x509), 1);
    _ = tc.X509_gmtime_adj(tc.X509_getm_notBefore(x509), -60);
    _ = tc.X509_gmtime_adj(tc.X509_getm_notAfter(x509), 60 * 60 * 24 * 365);
    _ = tc.X509_set_pubkey(x509, pkey);
    const name = tc.X509_get_subject_name(x509) orelse return error.SslInitFailed;
    _ = tc.X509_NAME_add_entry_by_txt(name, "CN", tc.MBSTRING_ASC, "localhost", -1, -1, 0);
    _ = tc.X509_set_issuer_name(x509, name);
    if (tc.X509_sign(x509, pkey, tc.EVP_sha256()) == 0) return error.SslInitFailed;

    var pem_buf: [16384]u8 = undefined;
    var tmp = std.testing.tmpDir(.{});
    errdefer tmp.cleanup();
    {
        const bio = tc.BIO_new(tc.BIO_s_mem()) orelse return error.SslInitFailed;
        defer _ = tc.BIO_free(bio);
        if (tc.PEM_write_bio_X509(bio, x509) != 1) return error.SslInitFailed;
        const f = try tmp.dir.createFile("cert.pem", .{});
        defer f.close();
        try f.writeAll(try bioDrain(bio, &pem_buf));
    }
    {
        const bio = tc.BIO_new(tc.BIO_s_mem()) orelse return error.SslInitFailed;
        defer _ = tc.BIO_free(bio);
        if (tc.PEM_write_bio_PrivateKey(bio, pkey, null, null, 0, null, null) != 1) return error.SslInitFailed;
        const f = try tmp.dir.createFile("key.pem", .{});
        defer f.close();
        try f.writeAll(try bioDrain(bio, &pem_buf));
    }
    const cert_pre = try tmp.dir.realpathAlloc(alloc, "cert.pem");
    defer alloc.free(cert_pre);
    const key_pre = try tmp.dir.realpathAlloc(alloc, "key.pem");
    defer alloc.free(key_pre);
    const cert_path = try alloc.dupeZ(u8, cert_pre);
    defer alloc.free(cert_path);
    const key_path = try alloc.dupeZ(u8, key_pre);
    defer alloc.free(key_path);
    return .{ .tmp = tmp, .ctx = try ssl.SslContext.initServer(cert_path, key_path) };
}

/// Drive two non-blocking SslConns' handshakes alternately until both
/// complete. Bounded so a stuck peer cannot hang the suite.
fn driveHandshake(a: *ssl.SslConn, b: *ssl.SslConn) !void {
    var ra: ssl.HandshakeResult = .want_read;
    var rb: ssl.HandshakeResult = .want_read;
    for (0..10_000) |_| {
        if (ra == .complete and rb == .complete) return;
        if (ra != .complete) ra = try a.doHandshake();
        if (rb != .complete) rb = try b.doHandshake();
    }
    return error.HandshakeStuck;
}

test "Transport plain: read, write, eof, and error after close" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var t: Transport = .{ .plain = pair[0] };
    var buf: [64]u8 = undefined;

    // Nothing pending: want_read, not eof or err.
    try std.testing.expectEqual(IoResult.want_read, t.read(&buf));

    const msg = "transport bytes";
    _ = try posix.write(pair[1], msg);
    switch (t.read(&buf)) {
        .n => |n| try std.testing.expectEqualStrings(msg, buf[0..n]),
        else => return error.TestUnexpectedResult,
    }

    switch (t.write("reply")) {
        .n => |n| try std.testing.expectEqual(@as(usize, 5), n),
        else => return error.TestUnexpectedResult,
    }

    posix.shutdown(pair[1], .both) catch {};
    try std.testing.expectEqual(IoResult.eof, t.read(&buf));
}

test "Transport plain: a full send buffer reports want_write" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    // FreeBSD clamps SO_SNDBUF; write enough to outrun any clamp.
    const one_k: c_int = 1024;
    try posix.setsockopt(pair[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&one_k));

    var t: Transport = .{ .plain = pair[0] };
    const bulk = [_]u8{0xab} ** (1 << 20);
    var saw_want = false;
    for (0..1000) |_| {
        switch (t.write(&bulk)) {
            .n => {},
            .want_write => {
                saw_want = true;
                break;
            },
            else => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(saw_want);
}

test "Transport plain: write to a dead peer is an error, not a panic" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    posix.close(pair[1]);

    var t: Transport = .{ .plain = pair[0] };
    switch (t.write("dead")) {
        .err => {},
        else => return error.TestUnexpectedResult,
    }
}

test "Transport tls: handshake, echo, pending, eof" {
    const alloc = std.testing.allocator;
    var pki = try makeTestPki(alloc);
    defer pki.deinit();

    // One userland end (PR 296498): the client context disarms kTLS.
    var client_ctx = try ssl.SslContext.initClient();
    defer client_ctx.deinit();
    client_ctx.disableKtls();

    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var tls: Tls = .{ .conn = try ssl.SslConn.init(pki.ctx, pair[0]), .policy = .prefer };
    defer tls.conn.deinit();
    var client = try ssl.SslConn.initClient(client_ctx, pair[1], null);
    defer client.deinit();
    try driveHandshake(&tls.conn, &client);

    var t: Transport = .{ .tls = &tls };

    var buf: [64]u8 = undefined;
    _ = try client.write("ping");
    switch (t.read(&buf)) {
        .n => |n| try std.testing.expectEqualStrings("ping", buf[0..n]),
        else => return error.TestUnexpectedResult,
    }
    // Read a slice smaller than the record: the rest stays in SSL_pending.
    _ = try client.write("buffered");
    switch (t.read(buf[0..3])) {
        .n => |n| try std.testing.expectEqual(@as(usize, 3), n),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 5), t.pending());
    _ = t.read(&buf);

    switch (t.write("pong")) {
        .n => |n| try std.testing.expectEqual(@as(usize, 4), n),
        else => return error.TestUnexpectedResult,
    }

    // Unix sockets cannot offload: the token is sw under prefer.
    try std.testing.expectEqual(KtlsToken.sw, tls.ktlsToken());

    client.shutdown();
    try std.testing.expectEqual(IoResult.eof, t.read(&buf));
}

test "Inbox: drain to EAGAIN, unread stability, consume, compact" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var t: Transport = .{ .plain = pair[0] };
    var buf: [64]u8 = undefined;
    var in = Inbox.init(&buf);
    var budget: ReadBudget = .{};

    _ = try posix.write(pair[1], "first");
    try std.testing.expectEqual(DrainResult.drained, in.drain(&t, &budget));
    try std.testing.expectEqualStrings("first", in.unread());

    // Parsed spans stay valid until the next drain: consume defers.
    in.consume(3);
    try std.testing.expectEqualStrings("st", in.unread());

    _ = try posix.write(pair[1], "second");
    try std.testing.expectEqual(DrainResult.drained, in.drain(&t, &budget));
    // Compaction ran once per drain: "st" moved to the front.
    try std.testing.expectEqualStrings("stsecond", in.unread());

    // A chunk larger than the pre-compaction free space only fits
    // because drain folded the consumed prefix away first.
    in.consume(8);
    const tail = [_]u8{0x30} ** 56;
    _ = try posix.write(pair[1], &tail);
    try std.testing.expectEqual(DrainResult.drained, in.drain(&t, &budget));
    try std.testing.expectEqualStrings(&tail, in.unread());
}

test "Inbox: a spent read budget stops the drain" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var t: Transport = .{ .plain = pair[0] };
    var buf: [32]u8 = undefined;
    var in = Inbox.init(&buf);

    // One read allowed: even with more data pending the drain stops.
    var budget: ReadBudget = .{ .bytes = 64 << 10, .reads = 1 };
    _ = try posix.write(pair[1], "0123456789abcdef");
    try std.testing.expectEqual(DrainResult.budget_left, in.drain(&t, &budget));
    try std.testing.expectEqual(@as(u32, 0), budget.reads);

    in.consume(in.len);
    budget.reads = 8;
    try std.testing.expectEqual(DrainResult.drained, in.drain(&t, &budget));
}

test "Inbox: a full inbox stops the drain until consume" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var t: Transport = .{ .plain = pair[0] };
    var buf: [16]u8 = undefined;
    var in = Inbox.init(&buf);
    var budget: ReadBudget = .{};

    // Consumer left the inbox full: the drain cannot make progress.
    in.len = in.buf.len;
    try std.testing.expectEqual(DrainResult.full, in.drain(&t, &budget));
    try std.testing.expect(in.full());
    in.consume(in.len);
    try std.testing.expectEqualStrings("", in.unread());
    try std.testing.expectEqual(DrainResult.drained, in.drain(&t, &budget));
}

test "Inbox: byte budget is spent by bytes moved, not calls" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var t: Transport = .{ .plain = pair[0] };
    var buf: [64]u8 = undefined;
    var in = Inbox.init(&buf);
    var budget: ReadBudget = .{ .bytes = 5, .reads = 16 };

    _ = try posix.write(pair[1], "0123456789");
    try std.testing.expectEqual(DrainResult.budget_left, in.drain(&t, &budget));
    try std.testing.expectEqual(@as(usize, 5), in.len);
}

test "Inbox: eof is distinct and latches" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var t: Transport = .{ .plain = pair[0] };
    var buf: [16]u8 = undefined;
    var in = Inbox.init(&buf);
    var budget: ReadBudget = .{};

    posix.shutdown(pair[1], .both) catch {};
    try std.testing.expectEqual(DrainResult.eof, in.drain(&t, &budget));
    try std.testing.expectEqual(DrainResult.eof, in.drain(&t, &budget));
}

/// Fold `bytes` into a rolling last-`tail.len` window of the stream.
fn feedTail(tail: *[4]u8, tail_len: *usize, bytes: []const u8) void {
    if (bytes.len >= tail.len) {
        @memcpy(tail, bytes[bytes.len - tail.len ..]);
        tail_len.* = tail.len;
        return;
    }
    const keep = @min(tail_len.*, tail.len - bytes.len);
    std.mem.copyForwards(u8, tail[0..keep], tail[tail_len.* - keep .. tail_len.*]);
    @memcpy(tail[keep .. keep + bytes.len], bytes);
    tail_len.* = keep + bytes.len;
}

/// Read until `buf` is full, the peer stops sending, or a bounded spin
/// runs out (a hung producer must fail the suite, not stall it).
fn readAll(fd: posix.fd_t, buf: []u8) !usize {
    var got: usize = 0;
    var spins: usize = 0;
    while (got < buf.len and spins < 100_000) {
        const n = posix.read(fd, buf[got..]) catch |err| switch (err) {
            error.WouldBlock => {
                spins += 1;
                continue;
            },
            else => return err,
        };
        if (n == 0) break;
        got += n;
    }
    return got;
}

test "Outbox: gather order, bytes accounting, drain" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var ring: [64]u8 = undefined;
    var o = Outbox.init(&ring, std.testing.allocator, 1 << 20, &counters);
    defer o.deinit();

    const parts = [_][]const u8{ "he", "llo", " ", "world" };
    try std.testing.expectEqual(AppendResult.queued, o.append(&parts));
    try std.testing.expectEqual(@as(usize, 11), o.bytes());
    try std.testing.expect(!o.empty());

    var t: Transport = .{ .plain = pair[0] };
    try std.testing.expectEqual(FlushResult.drained, o.flush(&t, 1 << 20));
    try std.testing.expect(o.empty());

    var buf: [64]u8 = undefined;
    const n = try readAll(pair[1], buf[0..11]);
    try std.testing.expectEqualStrings("hello world", buf[0..n]);
}

test "Outbox: ring wrap keeps order" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var ring: [16]u8 = undefined;
    var o = Outbox.init(&ring, std.testing.allocator, 1 << 20, &counters);
    defer o.deinit();
    var t: Transport = .{ .plain = pair[0] };

    const first = [_][]const u8{"0123456789"};
    try std.testing.expectEqual(AppendResult.queued, o.append(&first));
    _ = o.flush(&t, 1 << 20);
    _ = try readAll(pair[1], &ring); // peer drains (reuse ring as scratch)

    // Head now sits mid-ring; a 10-byte append wraps around the end.
    const second = [_][]const u8{"abcdefghij"};
    try std.testing.expectEqual(AppendResult.queued, o.append(&second));
    _ = o.flush(&t, 1 << 20);
    var buf: [16]u8 = undefined;
    const n = try readAll(pair[1], buf[0..10]);
    try std.testing.expectEqualStrings("abcdefghij", buf[0..n]);
}

test "Outbox: spill bound fails closed and counts" {
    var counters: Counters = .{};
    var ring: [8]u8 = undefined;
    var o = Outbox.init(&ring, std.testing.allocator, 64, &counters);
    defer o.deinit();

    const big_data = [_]u8{0x41} ** 100;
    const big = [_][]const u8{&big_data};
    try std.testing.expectEqual(AppendResult.failed_closed, o.append(&big));
    try std.testing.expectEqual(@as(u64, 1), counters.outbox_failed_closed);
    try std.testing.expectEqual(@as(usize, 0), o.bytes());
}

test "Outbox: spill reloads through the ring, high-water frees capacity" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var ring: [16]u8 = undefined;
    var o = Outbox.init(&ring, std.testing.allocator, 1 << 20, &counters);
    defer o.deinit();
    o.spill_high_water = 32;
    var t: Transport = .{ .plain = pair[0] };

    // 48 bytes with a 16-byte ring: all of it spills (whole-append
    // rule), then reloads through the ring in order.
    var data: [48]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i);
    const parts = [_][]const u8{&data};
    try std.testing.expectEqual(AppendResult.spilled, o.append(&parts));
    try std.testing.expectEqual(@as(usize, 48), o.bytes());
    const cap_after_spill = o.spill.capacity;
    try std.testing.expect(cap_after_spill > o.spill_high_water);

    try std.testing.expectEqual(FlushResult.drained, o.flush(&t, 1 << 20));
    // Drained: the reload passed spill bytes through the ring in order,
    // and capacity above the high-water mark was released.
    try std.testing.expectEqual(@as(usize, 0), o.bytes());
    try std.testing.expect(o.spill.capacity <= o.spill_high_water);
    var buf: [48]u8 = undefined;
    const n = try readAll(pair[1], &buf);
    try std.testing.expectEqual(@as(usize, 48), n);
    try std.testing.expectEqualSlices(u8, &data, buf[0..n]);
}

test "Outbox: an append behind a pending spill keeps wire order" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var ring: [16]u8 = undefined;
    var o = Outbox.init(&ring, std.testing.allocator, 1 << 20, &counters);
    defer o.deinit();
    var t: Transport = .{ .plain = pair[0] };

    // 10 bytes queue in the ring, the next 10 spill, and a 4-byte
    // append that would still fit the ring must go to spill instead:
    // the ring flushes first, so queuing it there would reorder.
    const a = [_][]const u8{"AAAAAAAAAA"};
    const b = [_][]const u8{"BBBBBBBBBB"};
    const cc = [_][]const u8{"CCCC"};
    try std.testing.expectEqual(AppendResult.queued, o.append(&a));
    try std.testing.expectEqual(AppendResult.spilled, o.append(&b));
    try std.testing.expectEqual(AppendResult.spilled, o.append(&cc));
    try std.testing.expectEqual(FlushResult.drained, o.flush(&t, 1 << 20));
    var buf: [24]u8 = undefined;
    const n = try readAll(pair[1], &buf);
    try std.testing.expectEqualStrings("AAAAAAAAAABBBBBBBBBBCCCC", buf[0..n]);
}

test "Outbox: a steady backlog compacts the spill instead of growing it" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var ring: [1024]u8 = undefined;
    const limit: usize = 64 << 10;
    var o = Outbox.init(&ring, std.testing.allocator, limit, &counters);
    defer o.deinit();
    var t: Transport = .{ .plain = pair[0] };
    const small: c_int = 1024;
    try posix.setsockopt(pair[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&small));

    // Producer appends 2 KiB per pass while the peer drains 1 KiB:
    // pending stays under the limit, but a spill that never folds its
    // sent prefix grows linearly with total traffic (the H1 OOM path).
    var chunk: [2048]u8 = undefined;
    @memset(&chunk, 0x61);
    const parts = [_][]const u8{&chunk};
    for (0..16) |_| _ = o.append(&parts);
    var max_cap: usize = 0;
    var max_pending: usize = 0;
    var sink: [1024]u8 = undefined;
    for (0..4000) |_| {
        _ = o.append(&parts);
        _ = o.flush(&t, 1 << 20);
        _ = posix.read(pair[1], &sink) catch 0;
        max_cap = @max(max_cap, o.spill.capacity);
        max_pending = @max(max_pending, o.spill.items.len - o.spill_head);
    }
    try std.testing.expect(max_pending <= limit);
    try std.testing.expect(max_cap <= 4 * limit);
}

test "Outbox: pin retries the identical slice across want_write" {
    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);
    const one_k: c_int = 1024;
    try posix.setsockopt(pair[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&one_k));

    var counters: Counters = .{};
    var ring: [128]u8 = undefined;
    var o = Outbox.init(&ring, std.testing.allocator, 1 << 20, &counters);
    defer o.deinit();
    var t: Transport = .{ .plain = pair[0] };

    // Fill the kernel buffer directly so flushes stall: FreeBSD clamps
    // SO_SNDBUF, so keep writing until the fd itself says EAGAIN.
    const big = [_]u8{0x77} ** (1 << 20);
    var sent: usize = 0;
    while (sent < big.len) {
        sent += posix.write(pair[0], big[sent..]) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
    }

    // An append that stalls mid-way leaves a pin; a second stalled
    // flush must present the identical (ptr, len).
    const a = [_][]const u8{"0123456789abcdef"};
    _ = o.append(&a);
    try std.testing.expectEqual(FlushResult.want_write, o.flush(&t, 1 << 20));
    const pin_ptr = o.pin.?.ptr;
    const pin_len = o.pin.?.len;
    try std.testing.expectEqual(FlushResult.want_write, o.flush(&t, 1 << 20));
    try std.testing.expectEqual(pin_ptr, o.pin.?.ptr);
    try std.testing.expectEqual(pin_len, o.pin.?.len);

    // Bytes appended behind a pending pin are never part of its retry.
    const b = [_][]const u8{"APPENDED-BEHIND"};
    _ = o.append(&b);

    // Interleave flush and peer-read until the outbox drains; the peer
    // must receive byte-identical data, ordered, pin bytes first.
    var scratch: [4096]u8 = undefined;
    var tail: [31]u8 = undefined;
    var idle: usize = 0;
    while (idle < 1000) {
        _ = o.flush(&t, 1 << 20);
        const n = posix.read(pair[1], &scratch) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => return err,
        };
        if (n == 0) {
            idle += 1;
            continue;
        }
        idle = 0;
        if (n >= tail.len) {
            @memcpy(&tail, scratch[n - tail.len .. n]);
        } else {
            const keep = tail.len - n;
            std.mem.copyForwards(u8, tail[0..keep], tail[n..]);
            @memcpy(tail[keep..], scratch[0..n]);
        }
    }
    // The last bytes out are the two appends (16 + 15 = 31).
    try std.testing.expectEqualStrings("0123456789abcdefAPPENDED-BEHIND", &tail);
}

fn mkLoop(alloc: std.mem.Allocator) !Loop {
    var l: Loop = undefined;
    try l.init(alloc, &.{ .handles_max = 8, .timers_max = 4 });
    return l;
}

fn mkConnCtx(index: u32) Token {
    return .{ .index = index, .gen = 1, .kind = 0x7c };
}

// Test helpers: an SSL ex_data slot whose free callback counts frees,
// so a leaked SSL object is observable in-process.
var ssl_mark_frees: usize = 0;
var ssl_mark_byte: u8 = 0;
var ssl_mark_idx: c_int = -1;

fn sslMarkFree(parent: ?*anyopaque, ptr: ?*anyopaque, ad: [*c]tc.CRYPTO_EX_DATA, idx: c_int, argl: c_long, argp: ?*anyopaque) callconv(.c) void {
    _ = parent;
    _ = ad;
    _ = idx;
    _ = argl;
    _ = argp;
    if (ptr == @as(?*anyopaque, @ptrCast(&ssl_mark_byte))) ssl_mark_frees += 1;
}

fn sslMark(sc: *ssl.SslConn) void {
    if (ssl_mark_idx < 0) {
        ssl_mark_idx = tc.CRYPTO_get_ex_new_index(tc.CRYPTO_EX_INDEX_SSL, 0, null, null, null, sslMarkFree);
    }
    _ = tc.SSL_set_ex_data(@ptrCast(sc.ssl), ssl_mark_idx, @ptrCast(&ssl_mark_byte));
}

/// Synthetic loop event for a conn, so a test can drive onEvent without
/// a kevent round trip.
fn synthIo(c: *Conn, kind: enum { r, w }) Event {
    const io: loop_mod.Io = .{ .handle = c.handle, .ctx = c.ctx, .data = 0, .eof = false, .errno = 0 };
    return switch (kind) {
        .r => .{ .readable = io },
        .w => .{ .writable = io },
    };
}

/// Drive a server-side handshake through synthetic readable events until
/// onEvent reports something, pumping the client end between steps.
fn hsToEnd(c: *Conn, client: *ssl.SslConn, list: *ConnList) !Outcome {
    for (0..100) |_| {
        _ = client.doHandshake() catch {};
        const out = c.onEvent(synthIo(c, .r), list);
        if (out != .none) return out;
    }
    return error.HandshakeStuck;
}

test "Conn: readable event delivers .readable and inbox bytes" {
    const alloc = std.testing.allocator;
    var loop = try mkLoop(alloc);
    defer loop.deinit(alloc);

    const pair = try socketpair();
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var c: Conn = undefined;
    try c.init(&loop, pair[0], mkConnCtx(1), alloc, .{ .counters = &counters });
    defer c.deinit();

    _ = try posix.write(pair[1], "hi");
    var list: ConnList = .{};
    try loop.wait();
    var got_readable = false;
    while (loop.next()) |ev| {
        switch (c.onEvent(ev, &list)) {
            .readable => {
                got_readable = true;
                try std.testing.expectEqualStrings("hi", c.inbox.unread());
            },
            else => {},
        }
    }
    try std.testing.expect(got_readable);
    posix.close(pair[0]);
}

test "Conn: a second batched event on a closing conn is skipped" {
    const alloc = std.testing.allocator;
    var loop = try mkLoop(alloc);
    defer loop.deinit(alloc);

    const pair = try socketpair();
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var c: Conn = undefined;
    try c.init(&loop, pair[0], mkConnCtx(1), alloc, .{ .counters = &counters });
    defer c.deinit();

    // Arm write interest, then have the peer write AND close: the batch
    // can carry a readable-with-EOF and a writable for the same conn.
    const parts = [_][]const u8{"x"};
    var list: ConnList = .{};
    _ = c.send(&list, &parts);
    _ = try posix.write(pair[1], "last");
    posix.shutdown(pair[1], .both) catch {};

    var outcomes: [8]Outcome = undefined;
    var n: usize = 0;
    try loop.wait();
    while (loop.next()) |ev| {
        outcomes[n] = c.onEvent(ev, &list);
        n += 1;
    }
    // The first event that reached the conn closed it; every later
    // event in the batch must be absorbed, never driven to I/O.
    var saw_closed = false;
    for (outcomes[0..n], 0..) |o, i| switch (o) {
        .closed => |reason| {
            try std.testing.expect(!saw_closed);
            saw_closed = true;
            try std.testing.expect(reason == .eof);
            for (outcomes[i + 1 .. n]) |o2| try std.testing.expect(o2 == .none);
        },
        else => {},
    };
    try std.testing.expect(saw_closed);
    try std.testing.expectEqual(State.closing, c.state);
    // Deferred close: teardown shuts down and closes the fd here, in
    // the end-of-iteration walk position, not inside onEvent.
    c.teardown();
    // The fd is already gone; no further close.
    try std.testing.expectEqual(@as(?posix.fd_t, null), c.loop.fdOf(c.handle));
}

test "Conn: send reaches the wire in the end-of-iteration walk (ADR-2)" {
    const alloc = std.testing.allocator;
    var loop = try mkLoop(alloc);
    defer loop.deinit(alloc);

    const pair = try socketpair();
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var c: Conn = undefined;
    try c.init(&loop, pair[0], mkConnCtx(1), alloc, .{ .counters = &counters });
    defer c.deinit();

    // Settle the attach registration so the send below stages nothing.
    loop.requestImmediate();
    try loop.wait();
    while (loop.next()) |_| {}
    const committed0 = loop.stats().changes_committed;

    // One iteration: the consumer sends during dispatch and the walk
    // flushes it before the next wait, without an EVFILT_WRITE staged
    // by send (ADR-2).
    const parts = [_][]const u8{"stanza"};
    var list: ConnList = .{};
    try std.testing.expectEqual(Outcome.none, c.send(&list, &parts));
    list.service();

    var buf: [16]u8 = undefined;
    const n = posix.read(pair[1], &buf) catch 0;
    try std.testing.expectEqual(@as(usize, 6), n);
    try std.testing.expectEqualStrings("stanza", buf[0..n]);
    // A pass to commit anything send or the walk staged: nothing may.
    loop.requestImmediate();
    try loop.wait();
    while (loop.next()) |_| {}
    try std.testing.expectEqual(committed0, loop.stats().changes_committed);
    c.state = .closing;
    c.teardown();
}

test "Conn: a stalled flush arms write; the writable pass drains" {
    const alloc = std.testing.allocator;
    var loop = try mkLoop(alloc);
    defer loop.deinit(alloc);

    const pair = try socketpair();
    defer posix.close(pair[1]);
    const one_k: c_int = 1024;
    try posix.setsockopt(pair[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&one_k));

    var counters: Counters = .{};
    var c: Conn = undefined;
    try c.init(&loop, pair[0], mkConnCtx(1), alloc, .{ .counters = &counters });
    defer c.deinit();

    // Fill the kernel send buffer so the walk's flush stalls.
    const filler = [_]u8{0x55} ** (1 << 20);
    while (true) {
        _ = posix.write(pair[0], &filler) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
    }

    const parts = [_][]const u8{"tail"};
    var list: ConnList = .{};
    _ = c.send(&list, &parts);
    list.service();
    try std.testing.expect(c.want_write);
    try std.testing.expect(!c.outbox.empty());

    // The peer drains; each freed window raises a writable event that
    // resumes the flush until the outbox empties in order.
    var sink: [8192]u8 = undefined;
    var tail: [4]u8 = undefined;
    var tail_len: usize = 0;
    var writables: usize = 0;
    var passes: usize = 0;
    while (passes < 400 and !c.outbox.empty()) : (passes += 1) {
        const n = posix.read(pair[1], &sink) catch 0;
        feedTail(&tail, &tail_len, sink[0..n]);
        const tid = try loop.scheduleIn(20, mkConnCtx(9));
        try loop.wait();
        var fired = false;
        while (loop.next()) |ev| {
            switch (ev) {
                .deadline => fired = true,
                .writable => {
                    writables += 1;
                    _ = c.onEvent(ev, &list);
                },
                else => {},
            }
        }
        if (!fired) _ = loop.cancelTimer(tid);
        list.service();
    }
    // The last bytes may still be in the kernel when the outbox empties.
    var spins: usize = 0;
    while (spins < 100_000) : (spins += 1) {
        const n = posix.read(pair[1], &sink) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        if (n == 0) break;
        feedTail(&tail, &tail_len, sink[0..n]);
    }
    try std.testing.expect(writables > 0);
    try std.testing.expect(c.outbox.empty());
    try std.testing.expect(!c.want_write);
    try std.testing.expectEqualStrings("tail", &tail);
    c.state = .closing;
    c.teardown();
}

test "Conn: a rejected registration closes through the ConnList" {
    const alloc = std.testing.allocator;
    var loop = try mkLoop(alloc);
    defer loop.deinit(alloc);

    const pair = try socketpair();
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var c: Conn = undefined;
    try c.init(&loop, pair[0], mkConnCtx(1), alloc, .{ .counters = &counters });
    defer c.deinit();
    var list: ConnList = .{};

    // The fd vanishes before the staged EV_ADD reaches the kernel:
    // wait() delivers the rejection as change_failed, which the loop
    // marks broken. Ignoring it leaves a cleartext conn that can never
    // be driven; it must close through the list.
    posix.close(pair[0]);
    _ = try loop.scheduleIn(20, mkConnCtx(9));
    try loop.wait();
    var saw_fail = false;
    var outcome: Outcome = .none;
    while (loop.next()) |ev| switch (ev) {
        .change_failed => {
            saw_fail = true;
            outcome = c.onEvent(ev, &list);
        },
        else => {},
    };
    try std.testing.expect(saw_fail);
    try std.testing.expect(outcome == .closed);
    try std.testing.expectEqual(State.closing, c.state);
    try std.testing.expect(c.on_dirty);
    list.service();
}

test "Conn: an event with a stale ctx generation is dropped at the table" {
    const alloc = std.testing.allocator;
    var loop = try mkLoop(alloc);
    defer loop.deinit(alloc);
    var counters: Counters = .{};
    var list: ConnList = .{};

    // The consumer's conn table, capacity 1: c1's free reissues the
    // same index at the next generation, so t1 can never resolve again
    // (decision 5).
    var conns: SlotMap(*Conn) = undefined;
    try conns.init(alloc, 1, 0x7c);
    defer conns.deinit(alloc);

    const pair1 = try socketpair();
    defer posix.close(pair1[1]);
    var c1: Conn = undefined;
    const t1 = try conns.insert(&c1);
    try c1.init(&loop, pair1[0], t1, alloc, .{ .counters = &counters });
    defer c1.deinit();
    _ = conns.remove(t1);

    const pair2 = try socketpair();
    defer posix.close(pair2[1]);
    var c2: Conn = undefined;
    const t2 = try conns.insert(&c2);
    try c2.init(&loop, pair2[0], t2, alloc, .{ .counters = &counters });
    defer c2.deinit();
    try std.testing.expectEqual(t1.index, t2.index);
    try std.testing.expect(t2.gen > t1.gen);

    // A readable event carrying c1's dead ctx must die in the table
    // lookup; reaching c2 through the reused index is the ABA the
    // generation exists to kill.
    const stale: Event = .{ .readable = .{
        .handle = c2.handle, .ctx = t1, .data = 0, .eof = false, .errno = 0,
    } };
    try std.testing.expect(conns.get(stale.readable.ctx) == null);

    // The live generation resolves and drives the real conn.
    _ = try posix.write(pair2[1], "hi");
    const live: Event = .{ .readable = .{
        .handle = c2.handle, .ctx = t2, .data = 0, .eof = false, .errno = 0,
    } };
    const owner = conns.get(live.readable.ctx) orelse return error.StaleCtx;
    try std.testing.expectEqual(&c2, owner.*);
    try std.testing.expectEqual(Outcome.readable, owner.*.onEvent(live, &list));
    try std.testing.expectEqualStrings("hi", c2.inbox.unread());

    // A close through the same path: .closed must arrive with the conn
    // already on the dirty list, or the walk can never tear it down
    // (markClosing without the link strands fd and SSL).
    posix.shutdown(pair2[1], .both) catch {};
    const closing_ev: Event = .{ .readable = .{
        .handle = c2.handle, .ctx = t2, .data = 0, .eof = true, .errno = 0,
    } };
    const out = conns.get(closing_ev.readable.ctx).?.*.onEvent(closing_ev, &list);
    try std.testing.expect(out == .closed);
    try std.testing.expect(c2.on_dirty);
    list.service();
    try std.testing.expectEqual(@as(?posix.fd_t, null), c2.loop.fdOf(c2.handle));
}

test "ConnList: FIFO order, unlink preserves the rest, fuzz invariants" {
    const alloc = std.testing.allocator;
    var conns: [8]Conn = undefined;
    // ConnList only touches the link fields; initialize those alone so
    // an undefined on_dirty in non-Debug builds cannot fake "linked".
    for (&conns) |*c| {
        c.on_dirty = false;
        c.dirty_next = null;
        c.dirty_prev = null;
    }
    var list: ConnList = .{};

    // FIFO pop order.
    for (conns[0..4]) |*c| list.link(c);
    try std.testing.expectEqual(@as(usize, 4), list.count);
    for (0..4) |i| try std.testing.expectEqual(&conns[i], list.pop().?);
    try std.testing.expect(list.empty());

    // unlink preserves the order of survivors.
    for (&conns) |*c| list.link(c);
    list.unlink(&conns[2]);
    list.unlink(&conns[5]);
    const order = [_]usize{ 0, 1, 3, 4, 6, 7 };
    for (order) |i| try std.testing.expectEqual(&conns[i], list.pop().?);
    try std.testing.expectEqual(@as(usize, 0), list.count);

    // Seeded fuzz: link/unlink/pop mix, invariant walk after every op.
    var rng = std.Random.DefaultPrng.init(0xF3);
    const r = rng.random();
    var live: [8]bool = [_]bool{false} ** 8;
    for (0..2000) |_| {
        const i = r.intRangeLessThan(usize, 0, 8);
        switch (r.intRangeLessThan(u8, 0, 3)) {
            0 => {
                list.link(&conns[i]);
                live[i] = true;
            },
            1 => {
                list.unlink(&conns[i]);
                live[i] = false;
            },
            else => {
                if (list.pop()) |c| {
                    const idx = (@intFromPtr(c) - @intFromPtr(&conns)) / @sizeOf(Conn);
                    live[idx] = false;
                }
            },
        }
        // Invariant walk: count links, check forward/backward agree.
        var fwd: usize = 0;
        var prev: ?*Conn = null;
        var it = list.head;
        while (it) |c| {
            try std.testing.expect(c.on_dirty);
            try std.testing.expect(c.dirty_prev == prev);
            prev = c;
            it = c.dirty_next;
            fwd += 1;
        }
        try std.testing.expect(prev == list.tail);
        try std.testing.expectEqual(list.count, fwd);
    }
    _ = alloc;
}

test "Conn: startTls refuses a non-empty outbox and read-ahead" {
    const alloc = std.testing.allocator;
    var loop = try mkLoop(alloc);
    defer loop.deinit(alloc);
    var pki = try makeTestPki(alloc);
    defer pki.deinit();

    const pair = try socketpair();
    defer posix.close(pair[0]);
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var c: Conn = undefined;
    try c.init(&loop, pair[0], mkConnCtx(1), alloc, .{ .counters = &counters });
    defer c.deinit();

    // Outbox not empty: refuse before even looking at the inbox.
    const parts = [_][]const u8{"queued"};
    var list: ConnList = .{};
    _ = c.send(&list, &parts);
    try std.testing.expectError(StartError.OutboxNotEmpty, c.startTls(pki.ctx, .accept, null, mkConnCtx(2)));
    _ = c.outbox.flush(&c.transport, 1 << 20);

    // Buffered read-ahead past the upgrade point: refuse.
    _ = try posix.write(pair[1], "GET / HTTP/1.0");
    var budget: ReadBudget = .{};
    _ = c.inbox.drain(&c.transport, &budget);
    try std.testing.expectError(StartError.ReadAhead, c.startTls(pki.ctx, .accept, null, mkConnCtx(2)));
    c.inbox.consume(c.inbox.len);

    // Clean state: accepted, moves to handshake owning the fd.
    try c.startTls(pki.ctx, .accept, null, mkConnCtx(2));
    try std.testing.expectEqual(State.handshake, c.state);
    try std.testing.expectEqual(pair[0], c.hs.?.fd);
}

const SeamPayload = struct {
    hs: *Handshake,
    fd: posix.fd_t,
    wake: *wake_mod.Wake,
    err: ?anyerror = null,
};

const wake_mod = @import("wake.zig");

fn seamDriver(p: *SeamPayload) void {
    seamDrive(p);
    p.wake.notify() catch |e| {
        if (p.err == null) p.err = e;
    };
}

/// The F7 pool-side driver (decision 4): the released fd registers on
/// the thread's own Loop — `assertOwner` is per-thread, so the driver
/// cannot touch the consumer's Loop — and `hs.step()` runs on the fd's
/// real readiness events under a 10 s deadline. The fd is detached back
/// before the Done post so `adoptFd` never races a live knote.
fn seamDrive(p: *SeamPayload) void {
    var dloop: Loop = undefined;
    dloop.init(std.testing.allocator, &.{ .handles_max = 4, .timers_max = 2 }) catch |e| {
        p.err = e;
        return;
    };
    defer dloop.deinit(std.testing.allocator);
    const dh = dloop.attach(p.fd, mkConnCtx(7), .{ .read = true, .write = true }) catch |e| {
        p.err = e;
        return;
    };
    _ = dloop.scheduleIn(10_000, mkConnCtx(9)) catch |e| {
        p.err = e;
        return;
    };
    drive: while (true) {
        dloop.wait() catch |e| {
            p.err = e;
            break;
        };
        while (dloop.next()) |ev| {
            switch (ev) {
                .readable, .writable => switch (p.hs.step()) {
                    .ok => break :drive,
                    .want_read => dloop.setInterest(dh, .{ .read = true }) catch |e| {
                        p.err = e;
                        break :drive;
                    },
                    .want_write => dloop.setInterest(dh, .{ .read = true, .write = true }) catch |e| {
                        p.err = e;
                        break :drive;
                    },
                    .err => |e| {
                        p.err = e;
                        break :drive;
                    },
                },
                .deadline => break :drive,
                else => {},
            }
        }
        if (p.hs.done == .ok) break;
    }
    if (p.err == null and p.hs.done != .ok) p.err = error.HandshakeStuck;
    _ = dloop.detach(dh) catch |e| {
        if (p.err == null) p.err = e;
    };
}

test "Conn: handshake seam hands the fd to a second thread and back" {
    const alloc = std.testing.allocator;
    var loop = try mkLoop(alloc);
    defer loop.deinit(alloc);
    var pki = try makeTestPki(alloc);
    defer pki.deinit();
    var client_ctx = try ssl.SslContext.initClient();
    defer client_ctx.deinit();
    client_ctx.disableKtls(); // one userland end (PR 296498)

    const pair = try socketpair();
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var c: Conn = undefined;
    try c.init(&loop, pair[0], mkConnCtx(1), alloc, .{ .counters = &counters });
    defer c.deinit();

    try c.startTls(pki.ctx, .accept, null, mkConnCtx(2));
    // The loop deregisters the fd; the Handshake owns it while it runs.
    const fd = try c.releaseFd();
    try std.testing.expectEqual(@as(?posix.fd_t, null), c.loop.fdOf(c.handle));

    var client = try ssl.SslConn.initClient(client_ctx, pair[1], null);
    defer client.deinit();

    var payload: SeamPayload = .{
        .hs = &c.hs.?,
        .fd = fd,
        .wake = loop.waker(),
    };
    const thread = try std.Thread.spawn(.{}, seamDriver, .{&payload});

    // The client end is driven by this (the consumer's) loop, not by a
    // thread polling `hs.done`: its doHandshake steps on the fd's real
    // readiness events, and a 10 s deadline bounds a stalled driver.
    const ch = try loop.attach(pair[1], mkConnCtx(8), .{ .read = true, .write = true });
    _ = try loop.scheduleIn(10_000, mkConnCtx(9));
    var client_done = false;
    var client_err: ?SslError = null;
    var woke = false;
    var timed_out = false;
    while (!woke and !timed_out and client_err == null) {
        try loop.wait();
        while (loop.next()) |ev| {
            switch (ev) {
                .readable, .writable => |io| {
                    if (!io.handle.eql(ch)) continue;
                    const r = client.doHandshake() catch |e| {
                        client_err = e;
                        break;
                    };
                    switch (r) {
                        .complete => {
                            client_done = true;
                            try loop.setInterest(ch, .{ .read = true });
                        },
                        .want_read => try loop.setInterest(ch, .{ .read = true }),
                        .want_write => try loop.setInterest(ch, .{ .read = true, .write = true }),
                    }
                },
                .wake => woke = true,
                .deadline => timed_out = true,
                else => {},
            }
        }
    }
    thread.join();
    if (payload.err) |e| std.debug.print("seam driver err={s}\n", .{@errorName(e)});
    if (client_err) |e| std.debug.print("seam client err={s}\n", .{@errorName(e)});
    try std.testing.expect(!timed_out);
    try std.testing.expect(client_err == null);
    try std.testing.expect(client_done);
    try std.testing.expect(woke);
    try std.testing.expect(payload.err == null);
    try std.testing.expectEqual(Done.ok, c.hs.?.done);

    // The loop re-adopts the fd; the conn finishes the upgrade.
    try c.adoptFd(fd);
    c.finishHandshake();
    try std.testing.expectEqual(State.established, c.state);
    try std.testing.expectEqual(KtlsToken.sw, c.tls_storage.ktlsToken());
    try std.testing.expectEqual(@as(u64, 1), counters.sw);

    // Established TLS transport echoes through the userland client end.
    _ = try client.write("seam ok");
    var budget: ReadBudget = .{};
    _ = c.inbox.drain(&c.transport, &budget);
    try std.testing.expectEqualStrings("seam ok", c.inbox.unread());

    // Hand the client fd back to the test before teardown.
    const back = try loop.detach(ch);
    try std.testing.expectEqual(pair[1], back);
    c.state = .closing;
    c.teardown();
}

test "Conn: teardown closes the fd while it is released to a driver" {
    const alloc = std.testing.allocator;
    var loop = try mkLoop(alloc);
    defer loop.deinit(alloc);
    var pki = try makeTestPki(alloc);
    defer pki.deinit();

    const pair = try socketpair();
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var c: Conn = undefined;
    try c.init(&loop, pair[0], mkConnCtx(1), alloc, .{ .counters = &counters });
    defer c.deinit();

    try c.startTls(pki.ctx, .accept, null, mkConnCtx(2));
    const fd = try c.releaseFd();

    // Torn down while the fd is released (the peer is replaced
    // mid-upgrade): the handle slot is gone, so teardown must close the
    // Handshake-owned fd itself instead of leaking it.
    var list: ConnList = .{};
    c.close(&list);
    list.service();
    try std.testing.expectEqual(@as(posix.fd_t, -1), c.hs.?.fd);
    try std.testing.expect(std.c.fcntl(fd, posix.F.GETFL, @as(c_int, 0)) == -1);
}

test "Conn: a require-policy failure closes through ConnList and frees the SSL" {
    const alloc = std.testing.allocator;
    var loop = try mkLoop(alloc);
    defer loop.deinit(alloc);
    var pki = try makeTestPki(alloc);
    defer pki.deinit();
    var client_ctx = try ssl.SslContext.initClient();
    defer client_ctx.deinit();
    client_ctx.disableKtls(); // one userland end (PR 296498)

    const pair = try socketpair();
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var c: Conn = undefined;
    try c.init(&loop, pair[0], mkConnCtx(1), alloc, .{ .counters = &counters, .ktls = .require });
    try c.startTls(pki.ctx, .accept, null, mkConnCtx(2));
    sslMark(&c.hs.?.conn);

    var client = try ssl.SslConn.initClient(client_ctx, pair[1], null);
    defer client.deinit();
    var list: ConnList = .{};

    const before = ssl_mark_frees;
    const out = try hsToEnd(&c, &client, &list);
    // A unix socket cannot offload: require closes the conn through the
    // dirty list so the end-of-iteration walk tears it down.
    try std.testing.expect(out == .closed);
    try std.testing.expectEqual(error.KtlsRequired, out.closed.err);
    try std.testing.expectEqual(State.closing, c.state);
    try std.testing.expect(c.on_dirty);
    list.service();
    try std.testing.expectEqual(@as(?posix.fd_t, null), c.loop.fdOf(c.handle));
    c.deinit();
    try std.testing.expectEqual(@as(usize, 1), ssl_mark_frees - before);
}

test "Conn: an established TLS conn frees the SSL at teardown" {
    const alloc = std.testing.allocator;
    var loop = try mkLoop(alloc);
    defer loop.deinit(alloc);
    var pki = try makeTestPki(alloc);
    defer pki.deinit();
    var client_ctx = try ssl.SslContext.initClient();
    defer client_ctx.deinit();
    client_ctx.disableKtls(); // one userland end (PR 296498)

    const pair = try socketpair();
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var c: Conn = undefined;
    try c.init(&loop, pair[0], mkConnCtx(1), alloc, .{ .counters = &counters });
    try c.startTls(pki.ctx, .accept, null, mkConnCtx(2));
    sslMark(&c.hs.?.conn);

    var client = try ssl.SslConn.initClient(client_ctx, pair[1], null);
    defer client.deinit();
    var list: ConnList = .{};

    const before = ssl_mark_frees;
    try std.testing.expectEqual(Outcome.handshake_done, try hsToEnd(&c, &client, &list));
    c.close(&list);
    list.service();
    try std.testing.expectEqual(@as(?posix.fd_t, null), c.loop.fdOf(c.handle));
    c.deinit();
    try std.testing.expectEqual(@as(usize, 1), ssl_mark_frees - before);
}

test "Conn: prefer records full kTLS on TCP loopback with a userland client" {
    const alloc = std.testing.allocator;
    var loop = try mkLoop(alloc);
    defer loop.deinit(alloc);
    var pki = try makeTestPki(alloc);
    defer pki.deinit();
    var client_ctx = try ssl.SslContext.initClient();
    defer client_ctx.deinit();
    client_ctx.disableKtls(); // one userland end (PR 296498)

    const pair = try tcpPair();
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var c: Conn = undefined;
    try c.init(&loop, pair[0], mkConnCtx(1), alloc, .{ .counters = &counters });
    defer c.deinit();
    try c.startTls(pki.ctx, .accept, null, mkConnCtx(2));

    var client = try ssl.SslConn.initClient(client_ctx, pair[1], null);
    defer client.deinit();
    var list: ConnList = .{};

    // One userland end over TCP lets both directions offload on the
    // server: prefer establishes and counts the full ktls token (R16
    // pinned: the tx/rx flags must both read true).
    try std.testing.expectEqual(Outcome.handshake_done, try hsToEnd(&c, &client, &list));
    try std.testing.expectEqual(State.established, c.state);
    try std.testing.expect(c.tls_storage.ktls_tx);
    try std.testing.expect(c.tls_storage.ktls_rx);
    try std.testing.expectEqual(KtlsToken.ktls, c.tls_storage.ktlsToken());
    try std.testing.expectEqual(@as(u64, 1), counters.ktls);
    c.state = .closing;
    c.teardown();
}

test "Conn: require establishes when both directions offload" {
    const alloc = std.testing.allocator;
    var loop = try mkLoop(alloc);
    defer loop.deinit(alloc);
    var pki = try makeTestPki(alloc);
    defer pki.deinit();
    var client_ctx = try ssl.SslContext.initClient();
    defer client_ctx.deinit();
    client_ctx.disableKtls(); // one userland end (PR 296498)

    const pair = try tcpPair();
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var c: Conn = undefined;
    try c.init(&loop, pair[0], mkConnCtx(1), alloc, .{ .counters = &counters, .ktls = .require });
    defer c.deinit();
    try c.startTls(pki.ctx, .accept, null, mkConnCtx(2));

    var client = try ssl.SslConn.initClient(client_ctx, pair[1], null);
    defer client.deinit();
    var list: ConnList = .{};

    // require accepts the conn only when the token is .ktls; on a
    // socketpair the same policy closes through the list (the H4 test).
    try std.testing.expectEqual(Outcome.handshake_done, try hsToEnd(&c, &client, &list));
    try std.testing.expectEqual(State.established, c.state);
    try std.testing.expectEqual(@as(u64, 1), counters.ktls);
    c.state = .closing;
    c.teardown();
}

test "Transport tls: one conn's failure does not poison another conn's read" {
    const alloc = std.testing.allocator;
    var pki = try makeTestPki(alloc);
    defer pki.deinit();
    var client_ctx = try ssl.SslContext.initClient();
    defer client_ctx.deinit();
    client_ctx.disableKtls(); // one userland end (PR 296498)

    const pa = try socketpair();
    defer posix.close(pa[0]);
    defer posix.close(pa[1]);
    const pb = try socketpair();
    defer posix.close(pb[0]);
    defer posix.close(pb[1]);

    var ta: Tls = .{ .conn = try ssl.SslConn.init(pki.ctx, pa[0]) };
    defer ta.conn.deinit();
    var tb: Tls = .{ .conn = try ssl.SslConn.init(pki.ctx, pb[0]) };
    defer tb.conn.deinit();
    var ca = try ssl.SslConn.initClient(client_ctx, pa[1], null);
    defer ca.deinit();
    var cb = try ssl.SslConn.initClient(client_ctx, pb[1], null);
    defer cb.deinit();
    try driveHandshake(&ta.conn, &ca);
    try driveHandshake(&tb.conn, &cb);
    tc.ERR_clear_error();

    var A: Transport = .{ .tls = &ta };
    var B: Transport = .{ .tls = &tb };
    var buf: [64]u8 = undefined;
    _ = A.read(&buf);
    _ = B.read(&buf);

    // A takes a bogus application record: the OpenSSL error queue is
    // per-thread, so a stale entry would mis-classify B's next read as
    // an error instead of want_read.
    const bogus = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x20 } ++ [_]u8{0x41} ** 32;
    _ = try posix.write(pa[1], &bogus);
    try std.testing.expect(A.read(&buf) == .err);
    try std.testing.expect(ta.conn.fatal);
    try std.testing.expectEqual(IoResult.want_read, B.read(&buf));
}

test "Conn: app data coalesced with the client Finished is delivered" {
    const alloc = std.testing.allocator;
    var loop = try mkLoop(alloc);
    defer loop.deinit(alloc);
    var pki = try makeTestPki(alloc);
    defer pki.deinit();
    var client_ctx = try ssl.SslContext.initClient();
    defer client_ctx.deinit();
    client_ctx.disableKtls(); // one userland end (PR 296498)

    const pair = try socketpair();
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var c: Conn = undefined;
    try c.init(&loop, pair[0], mkConnCtx(1), alloc, .{ .counters = &counters });
    defer c.deinit();
    try c.startTls(pki.ctx, .accept, null, mkConnCtx(2));

    var client = try ssl.SslConn.initClient(client_ctx, pair[1], null);
    defer client.deinit();
    var list: ConnList = .{};

    var client_done = false;
    var sent = false;
    var hs_done = false;
    var timer_fired: usize = 0;
    for (0..40) |_| {
        if (!client_done) {
            client_done = (try client.doHandshake()) == .complete;
        }
        if (client_done and !sent) {
            // XMPP clients send <stream:stream> right behind the Finished;
            // OpenSSL may read it with the Finished and leave it socketed.
            _ = try client.write("<stream:stream>");
            sent = true;
        }
        const tid = try loop.scheduleIn(50, mkConnCtx(9));
        try loop.wait();
        var fired = false;
        while (loop.next()) |ev| {
            switch (ev) {
                .deadline => fired = true,
                .readable, .writable => switch (c.onEvent(ev, &list)) {
                    .handshake_done => hs_done = true,
                    else => {},
                },
                else => {},
            }
        }
        if (fired) timer_fired += 1 else _ = loop.cancelTimer(tid);
        list.service();
        if (c.inbox.unread().len > 0) break;
        if (hs_done and timer_fired >= 3) break;
    }
    try std.testing.expect(hs_done);
    try std.testing.expectEqualStrings("<stream:stream>", c.inbox.unread());
    c.state = .closing;
    c.teardown();
}

test "Conn: a full inbox the consumer cannot consume does not spin the loop" {
    const alloc = std.testing.allocator;
    var loop = try mkLoop(alloc);
    defer loop.deinit(alloc);

    const pair = try socketpair();
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var c: Conn = undefined;
    try c.init(&loop, pair[0], mkConnCtx(1), alloc, .{ .counters = &counters, .inbox_bytes = 64 });
    defer c.deinit();

    // 1000 pending bytes against a 64-byte inbox; the consumer parses
    // nothing yet. A requeue-on-full conn would burn a pass per
    // synthetic event until the deadline.
    var big: [1000]u8 = undefined;
    @memset(&big, 0x3c);
    _ = try posix.write(pair[1], &big);
    var list: ConnList = .{};
    _ = try loop.scheduleIn(100, mkConnCtx(9));
    var passes: usize = 0;
    var done = false;
    while (!done and passes < 100_000) : (passes += 1) {
        try loop.wait();
        while (loop.next()) |ev| {
            switch (ev) {
                .deadline => done = true,
                .readable, .writable => _ = c.onEvent(ev, &list),
                else => {},
            }
        }
        list.service();
    }
    try std.testing.expect(passes < 50);
    try std.testing.expect(c.inbox_stalled);
    try std.testing.expect(c.inbox.full());
    try std.testing.expect(c.inbox.unread().len == 64);

    // Consume through Conn: the park lifts and the drain resumes into
    // the freed space (it parks again on the next full inbox).
    c.consume(&list, 32);
    try std.testing.expect(!c.inbox_stalled);
    try std.testing.expect(c.requeue_read);
    try std.testing.expect(c.on_dirty);
    list.service();
    try loop.wait();
    while (loop.next()) |ev| {
        switch (ev) {
            .readable, .writable => _ = c.onEvent(ev, &list),
            else => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 64), c.inbox.unread().len);
    c.state = .closing;
    c.teardown();
}

test "ConnList: service re-drives a budget-stopped read once per pass" {
    const alloc = std.testing.allocator;
    var list: ConnList = .{};
    var loop: Loop = undefined;
    // on_flush makes the walk mechanical: service runs inside wait().
    try loop.init(alloc, &.{ .handles_max = 8, .timers_max = 4, .on_flush = list.flushHook() });
    defer loop.deinit(alloc);

    const pair = try socketpair();
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var c: Conn = undefined;
    try c.init(&loop, pair[0], mkConnCtx(1), alloc, .{
        .counters = &counters,
        .read_budget_bytes = 8,
        .read_budget_reads = 16,
    });
    defer c.deinit();

    const big = [_]u8{0x3c} ** 200;
    _ = try posix.write(pair[1], &big);

    const syn0 = loop.stats().synthetic_events;
    var got: usize = 0;
    var passes: usize = 0;
    while ((got < big.len or !list.empty()) and passes < 40) : (passes += 1) {
        const tid = try loop.scheduleIn(50, mkConnCtx(9));
        try loop.wait();
        var fired = false;
        while (loop.next()) |ev| {
            switch (ev) {
                .deadline => fired = true,
                .readable => {
                    _ = c.onEvent(ev, &list);
                    got += c.inbox.unread().len;
                    c.consume(&list, c.inbox.unread().len);
                },
                else => {},
            }
        }
        if (!fired) _ = loop.cancelTimer(tid);
    }
    // Every pass after the first kernel event was driven by exactly one
    // requeued synthetic read; the walk did the re-driving.
    try std.testing.expectEqual(big.len, got);
    try std.testing.expect(list.empty());
    try std.testing.expectEqual(passes - 1, loop.stats().synthetic_events - syn0);
    c.state = .closing;
    c.teardown();
}

test "ConnList: a drained flush re-drives the stalled read through service" {
    const alloc = std.testing.allocator;
    var loop = try mkLoop(alloc);
    defer loop.deinit(alloc);

    const pair = try socketpair();
    defer posix.close(pair[1]);

    var counters: Counters = .{};
    var c: Conn = undefined;
    try c.init(&loop, pair[0], mkConnCtx(1), alloc, .{ .counters = &counters });
    defer c.deinit();

    // A TLS read that wanted a write leaves requeue_read set; the next
    // writable pass drains the outbox and the walk must re-drive it.
    const parts = [_][]const u8{"x"};
    var list: ConnList = .{};
    _ = c.send(&list, &parts);
    c.requeue_read = true;
    _ = c.onEvent(synthIo(&c, .w), &list);
    try std.testing.expect(c.requeue_read);
    try std.testing.expect(c.on_dirty);
    list.service();
    try std.testing.expect(!c.requeue_read);

    _ = try loop.scheduleIn(50, mkConnCtx(9));
    try loop.wait();
    var saw_readable = false;
    while (loop.next()) |ev| {
        if (ev == .readable and ev.readable.handle.eql(c.handle)) saw_readable = true;
    }
    try std.testing.expect(saw_readable);
    c.state = .closing;
    c.teardown();
}
