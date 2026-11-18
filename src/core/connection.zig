//! # Connection — Per-client connection state
//!
//! Represents a single XMPP client TCP connection. Owns the socket fd,
//! read/write buffers, and provides transparent I/O that works over both
//! plain TCP and TLS (after STARTTLS upgrade).
//!
//! ## Lifecycle
//!
//! 1. `init()` — created after `accept()` by the listener
//! 2. `recv()` — called when kqueue signals fd_readable
//! 3. `send()` / `queueSend()` — buffer outgoing data
//! 4. `flushSend()` — called when kqueue signals fd_writable
//! 5. `close()` — teardown (close fd, free resources)
//!
//! ## Buffer Design
//!
//! - **Read buffer**: Fixed 8KB. Data is consumed from the front by the XML
//!   parser; unconsumed bytes are compacted (shifted to front) after each parse.
//! - **Outbox**: a lib/net Outbox whose ring borrows a lazily allocated
//!   16KB heap block (`write_buf`). Data is appended by the stream handler
//!   and drained to the socket when writable. When it fills beyond
//!   WRITE_SUPPRESS_HIGH the worker disables EVFILT_READ for the fd (T110):
//!   TCP flow control pushes back on the sender until the outbox drains
//!   below WRITE_SUPPRESS_LOW. If it fills completely, queueSend() fails
//!   with error.WriteBufferFull.
//!
//! ## TLS
//!
//! The `tls` field is null for plain TCP. After STARTTLS, `upgradeToTls()`
//! sets it and all subsequent `recv()` / `flushSend()` calls go through
//! the TLS layer transparently.

const std = @import("std");
const posix = std.posix;
const ssl = @import("ssl");
const net = @import("net");
const metrics = @import("worker/metrics.zig");

/// The counter block a bound outbox reports to (lib/net Counters).
pub const OutboxCounters = net.Counters;

/// Outbox accounting for a Connection never bound to a worker's counter
/// block (unit tests, the window before bindOutbox). threadlocal keeps
/// it per-worker in production anyway.
threadlocal var fallback_outbox_counters: net.Counters = .{};

/// Zero-length ring placeholder for Outbox.init inside Connection.init:
/// the real ring borrows write_buf once ensureWriteBuf has allocated it
/// (ob() re-derives the binding on every use).
var placeholder_outbox_ring: [0]u8 = .{};

/// One counter block per worker, padded like metrics.workers: the owning
/// loop thread is the only writer (its conns bind here at accept via
/// bindOutbox) and the SIGUSR1 dump the only reader. Unbound conns (unit
/// tests, the window before bindOutbox) report to the threadlocal
/// fallback block instead.
const OutboxCounterSlot = struct {
    counters: OutboxCounters align(std.atomic.cache_line) = .{},
    /// The worker's ADR-2 end-of-iteration flush list; kept in the slot so
    /// Server stays the same size as before the outbox work.
    dirty: DirtyList = .{},
};
pub var worker_outbox_counters: [metrics.MAX_WORKERS]OutboxCounterSlot = @splat(.{});

/// Dirty list for a Connection never bound to a worker (unit tests, the
/// window before bindOutbox). threadlocal matches fallback_outbox_counters.
threadlocal var fallback_dirty_list: DirtyList = .{};

/// The counter block a connection on `worker_id` binds at accept. Ids past
/// the table share the threadlocal fallback so a misconfigured worker can
/// never index out of bounds.
pub fn countersForWorker(worker_id: u16) *OutboxCounters {
    if (worker_id < metrics.MAX_WORKERS) return &worker_outbox_counters[worker_id].counters;
    return &fallback_outbox_counters;
}

/// The dirty list a connection on `worker_id` binds at accept. Ids past
/// the table share the threadlocal fallback.
pub fn dirtyForWorker(worker_id: u16) *DirtyList {
    if (worker_id < metrics.MAX_WORKERS) return &worker_outbox_counters[worker_id].dirty;
    return &fallback_dirty_list;
}

/// Create a non-blocking Unix socketpair. Used in tests.
fn makeSocketPair() ![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    return fds;
}

/// TLS handshake state for non-blocking integration with kqueue.
pub const TlsState = enum {
    /// TLS handshake in progress — waiting for socket readability.
    handshake_want_read,
    /// TLS handshake in progress — waiting for socket writability.
    handshake_want_write,
    /// TLS handshake complete — connection is encrypted.
    established,
};

/// Read buffer size — 8KB per connection.
/// XMPP stanzas are typically small (<4KB); 8KB handles even large presence payloads.
const READ_BUF_SIZE = 8192;

/// Write buffer size — 16KB per connection.
/// Larger than read because the server may need to send stream features + multiple
/// stanzas before the client has a chance to ACK at the TCP level.
pub const WRITE_BUF_SIZE = 16384;

/// Per-connection outbound bound (ring plus spill) — the lib/net
/// max_outbound_bytes default for c2s (F3-DESIGN section 1). An append
/// that cannot fit fails closed and the session is failed with
/// resource-constraint; undelivered messages drain to offline storage.
pub const MAX_OUTBOUND_BYTES: usize = 1 << 20;

/// Per-connection, per-pass flush budget for the end-of-iteration dirty
/// walk (F3 flush_budget_bytes). Bounds how long one conn can hold the
/// batch tail before the walk moves on.
pub const FLUSH_BUDGET_BYTES: usize = 64 << 10;

/// T110 backpressure: at/above this buffered-bytes level the server disables
/// EVFILT_READ for the connection, so TCP-level flow control propagates to
/// the sender's kernel instead of us reading ever more stanzas we cannot
/// forward. 75% of the write buffer.
pub const WRITE_SUPPRESS_HIGH: usize = WRITE_BUF_SIZE * 3 / 4;

/// T110 backpressure: reading resumes once the buffer drained to or below
/// this level. 50% — hysteresis against flapping at the threshold.
pub const WRITE_SUPPRESS_LOW: usize = WRITE_BUF_SIZE / 2;

/// Intrusive per-worker dirty list over `*Connection` (FIFO, O(1)
/// link/unlink): an append links its conn, and the worker's
/// end-of-iteration walk pops and flushes each link once (ADR-2), so
/// EVFILT_WRITE arms only after a real EAGAIN instead of per send.
/// Same shape as lib/net's ConnList.
pub const DirtyList = struct {
    head: ?*Connection = null,
    tail: ?*Connection = null,
    /// Linked-conn count; a flush walk bounded by the count at its start
    /// leaves mid-walk links (re-drives, close broadcasts) to the next
    /// iteration instead of popping them twice.
    count: usize = 0,

    /// Append `c` if it is not linked already (idempotent).
    pub fn link(l: *DirtyList, c: *Connection) void {
        if (c.on_dirty) return;
        c.on_dirty = true;
        c.dirty_prev = l.tail;
        c.dirty_next = null;
        if (l.tail) |t| t.dirty_next = c else l.head = c;
        l.tail = c;
        l.count += 1;
    }

    /// Detach `c` without disturbing the order of the rest.
    pub fn unlink(l: *DirtyList, c: *Connection) void {
        if (!c.on_dirty) return;
        if (c.dirty_prev) |p| p.dirty_next = c.dirty_next else l.head = c.dirty_next;
        if (c.dirty_next) |n| n.dirty_prev = c.dirty_prev else l.tail = c.dirty_prev;
        c.dirty_next = null;
        c.dirty_prev = null;
        c.on_dirty = false;
        l.count -= 1;
    }

    /// Remove and return the head, or null.
    pub fn pop(l: *DirtyList) ?*Connection {
        const c = l.head orelse return null;
        l.unlink(c);
        return c;
    }

    pub fn empty(l: *const DirtyList) bool {
        return l.head == null;
    }
};

/// Per-client XMPP connection state.
pub const Connection = struct {
    /// The client socket file descriptor. Set to -1 by `close()` (T155) so a
    /// stale Connection cannot leak a recycled descriptor number to kqueue.
    fd: posix.fd_t,

    /// Incoming data buffer. Data arrives from the socket at `read_end`,
    /// and is consumed from position `read_start` by the XML parser.
    read_buf: [READ_BUF_SIZE]u8 = undefined,
    /// Start of unconsumed data in read_buf.
    read_start: usize = 0,
    /// End of valid data in read_buf (next write position).
    read_end: usize = 0,

    /// Outgoing data buffer. Backing storage for `outbox`'s ring: a lazy
    /// heap block allocated on first send (ensureWriteBuf) and freed by
    /// deinit(). Keeping it out of the struct lets the M4 stack-frame caps
    /// hold where by-value Connection moves occur (accept, Session.init);
    /// heap memory is also what makes the TLS (ptr, len) pin stable across
    /// every by-value move. Null means "never sent" — recv-only
    /// connections never pay for it.
    write_buf: ?*[WRITE_BUF_SIZE]u8 = null,

    /// Outbound queue over `write_buf` (lib/net Outbox): a fixed ring
    /// first, a bounded spill behind it up to MAX_OUTBOUND_BYTES. The
    /// ring binding is re-derived on each use via ob() because a
    /// Connection is moved by value before the owning Session is placed
    /// on the heap.
    outbox: net.Outbox,

    /// Intrusive links for the owning worker's dirty list, bound at
    /// accept by bindOutbox. An append links the conn so the batch tail
    /// flushes it; close()/deinit() unlink.
    dirty_next: ?*Connection = null,
    dirty_prev: ?*Connection = null,
    on_dirty: bool = false,
    /// The worker's dirty list, or null before bindOutbox and in unit
    /// tests — unbound conns link nowhere.
    dirty_list: ?*DirtyList = null,

    /// The last flush stalled on TLS want_read (a write that needs a
    /// read event); the next readable event re-links the conn so the
    /// tail retries the flush.
    flush_want_read: bool = false,

    /// TLS state — null for plain TCP, set after STARTTLS upgrade.
    tls: ?net.Tls = null,

    /// TLS handshake progress — only meaningful when tls is set.
    tls_state: ?TlsState = null,

    /// Unique connection ID (for use as kqueue udata).
    id: usize,

    /// Whether the connection is in a closed/error state.
    closed: bool = false,

    /// T110: EVFILT_READ for this fd is currently disabled because the write
    /// buffer exceeded WRITE_SUPPRESS_HIGH. Set/cleared by the worker
    /// (Server.applyReadBackpressure) — Connection itself never touches
    /// kqueue.
    read_suppressed: bool = false,

    /// Peer address string (e.g., "192.168.1.100"). Stored from accept().
    peer_addr_buf: [64]u8 = undefined,
    peer_addr_len: usize = 0,

    /// Stable buffer for channel binding data (outlives the getChannelBinding
    /// call). Lazy like write_buf: only TLS sessions doing SASL channel
    /// binding ever allocate it.
    cb_data_buf: ?*[32]u8 = null,

    /// Initialize a new connection from an accepted socket.
    ///
    /// - `fd` — the accepted client socket (must already be non-blocking)
    /// - `id` — unique identifier for this connection (used as kqueue udata)
    /// - `alloc` — allocator for outbox spill growth (bounded by the
    ///   outbox's own spill_limit)
    pub fn init(fd: posix.fd_t, id: usize, alloc: std.mem.Allocator) Connection {
        return .{
            .fd = fd,
            .id = id,
            .outbox = net.Outbox.init(placeholder_outbox_ring[0..], alloc, MAX_OUTBOUND_BYTES, &fallback_outbox_counters),
        };
    }

    /// The outbox ring borrows `write_buf` storage; the binding is
    /// re-derived on each use so a Connection moved by value before heap
    /// placement (the Session.init return, the accept-time field copy)
    /// never leaves a dangling ring slice behind.
    fn ob(self: *Connection) *net.Outbox {
        self.outbox.ring = if (self.write_buf) |p| p[0..] else placeholder_outbox_ring[0..];
        return &self.outbox;
    }

    /// ob() for the append path: grows the ring backing on first send.
    /// Null on allocation failure, which callers surface as failed_closed.
    fn obSend(self: *Connection) ?*net.Outbox {
        if (!self.ensureWriteBuf()) return null;
        return self.ob();
    }

    /// Allocate the ring backing once; later calls are a no-op. The block
    /// comes from the outbox's allocator and is freed by deinit().
    pub fn ensureWriteBuf(self: *Connection) bool {
        if (self.write_buf != null) return true;
        if (self.outbox.alloc.create([WRITE_BUF_SIZE]u8)) |buf| {
            self.write_buf = buf;
            return true;
        } else |_| {
            return false;
        }
    }

    /// Bind the per-worker counter block and dirty list once the
    /// Connection has reached its permanent home (the heap Session
    /// slot). ob() keeps the ring binding self-healing; this call is
    /// what points counters at the worker-owned block and dirty links
    /// at the worker's end-of-iteration flush list.
    pub fn bindOutbox(self: *Connection, counters: *OutboxCounters, dirty: *DirtyList) void {
        self.outbox.ring = if (self.write_buf) |p| p[0..] else placeholder_outbox_ring[0..];
        self.outbox.counters = counters;
        self.dirty_list = dirty;
    }

    /// Link this conn on the bound dirty list so the worker's batch
    /// tail flushes it once (ADR-2). A no-op for unbound conns (unit
    /// tests); idempotent through DirtyList.link.
    pub fn linkDirty(self: *Connection) void {
        if (self.dirty_list) |l| l.link(self);
    }

    /// Detach from the bound dirty list (close/deinit paths). Safe on
    /// unbound or unlinked conns.
    fn unlinkDirty(self: *Connection) void {
        if (self.dirty_list) |l| l.unlink(self);
    }

    /// Derived fresh on each call: the .tls arm points at this
    /// Connection's own Tls, so the union can never hold a stale pointer
    /// across the same by-value moves ob() guards against.
    fn transport(self: *Connection) net.Transport {
        if (self.tls) |*t| return .{ .tls = t };
        return .{ .plain = self.fd };
    }

    /// Returns the peer address as a string slice, or empty if unknown.
    pub fn peerAddr(self: *const Connection) []const u8 {
        return self.peer_addr_buf[0..self.peer_addr_len];
    }

    /// Extract channel binding data from the TLS session.
    /// Returns cb_type (0=none, 1=tls-server-end-point, 2=tls-exporter) and
    /// a pointer to 32 bytes of binding data. Returns (0, empty) if no TLS or
    /// binding data unavailable.
    pub fn getChannelBinding(self: *Connection) struct { cb_type: u8, data: []const u8 } {
        if (self.tls) |*t| {
            if (t.conn.getChannelBinding()) |cb| {
                // Store in a stable buffer so the slice outlives this call
                const buf = self.cb_data_buf orelse blk: {
                    const b = self.outbox.alloc.create([32]u8) catch
                        return .{ .cb_type = 0, .data = "" };
                    self.cb_data_buf = b;
                    break :blk b;
                };
                buf.* = cb.data;
                return .{ .cb_type = @intFromEnum(cb.cb_type), .data = buf[0..] };
            }
        }
        return .{ .cb_type = 0, .data = "" };
    }

    /// Read data from the socket into the read buffer.
    ///
    /// Returns the number of bytes read, or 0 if the peer closed the connection.
    /// The caller should then call `readableSlice()` to get the unconsumed data
    /// and `consume()` after processing.
    ///
    /// If the read buffer is full (no space to read into), returns
    /// `error.ReadBufferFull`. The caller should process/consume existing data first.
    ///
    /// ## Errors
    /// - `error.ReadBufferFull` — buffer has no space; consume data first
    /// - `error.ConnectionReset` — peer reset the connection
    /// - `error.WouldBlock` — no data available (non-blocking, try again later)
    pub fn recv(self: *Connection) !usize {
        // Compact: shift unconsumed data to front if we've consumed some
        if (self.read_start > 0) {
            const remaining = self.read_end - self.read_start;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.read_buf[0..remaining], self.read_buf[self.read_start..self.read_end]);
            }
            self.read_end = remaining;
            self.read_start = 0;
        }

        // Check if there's space to read into
        if (self.read_end >= READ_BUF_SIZE) {
            return error.ReadBufferFull;
        }

        const buf = self.read_buf[self.read_end..READ_BUF_SIZE];

        if (self.tls) |*t| {
            const result = t.conn.read(buf) catch |err| {
                return switch (err) {
                    ssl.SslError.ConnectionClosed => @as(usize, 0), // EOF
                    else => error.ConnectionReset,
                };
            };
            return switch (result) {
                .ok => |n| blk: {
                    self.read_end += n;
                    if (metrics.get()) |c| metrics.bump(&c.bytes_in, n);
                    break :blk n;
                },
                .want_read => error.WouldBlock,
                .want_write => error.WouldBlock,
            };
        }

        // Plain TCP read
        const n = posix.read(self.fd, buf) catch |err| {
            return switch (err) {
                error.WouldBlock => error.WouldBlock,
                error.ConnectionResetByPeer => error.ConnectionReset,
                error.NotOpenForReading => error.ConnectionReset,
                else => error.ConnectionReset,
            };
        };

        if (n == 0) return 0; // EOF — peer closed

        self.read_end += n;
        if (metrics.get()) |c| metrics.bump(&c.bytes_in, n);
        return n;
    }

    /// Returns the slice of data available for parsing (between read_start and read_end).
    /// This slice is valid until the next call to `recv()` or `consume()`.
    pub fn readableSlice(self: *const Connection) []const u8 {
        return self.read_buf[self.read_start..self.read_end];
    }

    /// Mark `n` bytes as consumed from the front of the read buffer.
    /// Called after the XML parser has processed data from `readableSlice()`.
    pub fn consume(self: *Connection, n: usize) void {
        self.read_start += n;
        std.debug.assert(self.read_start <= self.read_end);
    }

    /// Append data to the outbox for later sending.
    ///
    /// Returns `error.WriteBufferFull` if there is not enough space — the
    /// caller should wait for `flushSend()` to drain some data before queueing
    /// more. Returns `error.ConnectionClosed` if the connection is already
    /// closed; the stanza should be dropped or tracked for SM replay instead.
    pub fn queueSend(self: *Connection, data: []const u8) !void {
        // T155: refuse to buffer for a closed connection. Without this the data
        // lands in the outbox, hasPendingWrite() then reports true, and the
        // caller arms kqueue on a dead fd. Mirrors S2sSession.queueSend.
        if (self.closed) {
            if (metrics.get()) |c| metrics.bump(&c.drop_send_closed, 1);
            return error.ConnectionClosed;
        }
        return switch (self.append(data)) {
            .queued, .spilled => {},
            .failed_closed => error.WriteBufferFull,
        };
    }

    /// Append `data` to the outbox and report the ADR-2 outcome instead of
    /// an error: the SendResult layer folds a dead fd and a full ring into
    /// failed_closed (noteQueueDrop uses isClosed() to split them). A
    /// refused append bumps the per-worker drop counter by reason here, so
    /// every call site gets counted whether it inspects the result or not.
    pub fn append(self: *Connection, data: []const u8) net.AppendResult {
        if (self.closed) {
            if (metrics.get()) |c| metrics.bump(&c.drop_send_closed, 1);
            return .failed_closed;
        }
        const parts = [_][]const u8{data};
        const o = self.obSend() orelse {
            // OOM on the lazy ring backing: counted like a full buffer.
            if (metrics.get()) |c| metrics.bump(&c.drop_send_buffer_full, 1);
            return .failed_closed;
        };
        const r = o.append(&parts);
        if (r == .failed_closed) {
            if (metrics.get()) |c| metrics.bump(&c.drop_send_buffer_full, 1);
            return r;
        }
        // Accepted bytes owe the worker's batch tail one flush; the tail
        // arms EVFILT_WRITE only when the flush stalls on a real EAGAIN.
        self.linkDirty();
        return r;
    }

    /// Queue `data`, first making room with one non-blocking flush when the
    /// buffer is full. Data already buffered is deliverable, so a buffer the
    /// server filled itself is not by itself a slow reader: a single flush
    /// buys another attempt. The caller still treats a second WriteBufferFull
    /// as a slow reader, whatever the flush freed.
    pub fn queueSendWithFlush(self: *Connection, data: []const u8) !void {
        self.queueSend(data) catch |err| {
            if (err != error.WriteBufferFull) return err;
            _ = self.flushSend() catch 0;
            return self.queueSend(data);
        };
    }

    /// append() with the queueSendWithFlush policy: one non-blocking flush
    /// when the first append is refused on a live conn, then a second
    /// append. A dead conn returns the first failed_closed as-is so the
    /// drop counter is bumped once, not twice.
    pub fn appendWithFlush(self: *Connection, data: []const u8) net.AppendResult {
        const r = self.append(data);
        if (r != .failed_closed or self.closed) return r;
        _ = self.flushSend() catch 0;
        return self.append(data);
    }

    /// Returns true if there is unsent data in the write buffer.
    /// When true, the caller should register this fd for EVFILT_WRITE.
    pub fn hasPendingWrite(self: *const Connection) bool {
        // A closed connection has no writable fd, so buffered bytes are
        // undeliverable, not pending. A detached SM session retains those bytes
        // for resume but must not arm EVFILT_WRITE until it has a new fd (S28).
        if (self.closed) return false;
        return !self.outbox.empty();
    }

    /// Bytes currently buffered for writing (T110 backpressure thresholds).
    /// Zero once closed: there is no fd left to drain them to (S28).
    pub fn pendingWriteBytes(self: *const Connection) usize {
        if (self.closed) return 0;
        return self.outbox.bytes();
    }

    /// Flush the outbox to the socket with a byte budget, reporting the
    /// lib/net FlushResult so the caller arms the right interest: the
    /// batch tail arms EVFILT_WRITE only on want_write or a spent
    /// budget, and marks flush_want_read for the next readable event
    /// (ADR-2).
    ///
    /// The outbox owns the TLS (ptr, len) pin: a pending want_* retry
    /// presents the identical slice OpenSSL was first given, formed
    /// only from ring memory (S23, kTLS D3).
    pub fn flushOutbox(self: *Connection, budget: usize) net.FlushResult {
        if (self.closed) return .{ .err = error.ConnectionClosed };
        const o = self.ob();
        const before = o.bytes();
        var tr = self.transport();
        const result = o.flush(&tr, budget);
        const wrote = before - o.bytes();
        if (wrote > 0) {
            if (metrics.get()) |c| metrics.bump(&c.bytes_out, wrote);
        }
        return result;
    }

    /// Flush the write buffer to the socket.
    ///
    /// Returns the number of bytes written. The caller should keep this fd
    /// registered for EVFILT_WRITE until `hasPendingWrite()` returns false.
    ///
    /// ## Errors
    /// - `error.WouldBlock` — socket send buffer is full, try again later
    /// - `error.ConnectionReset` — peer reset the connection
    /// - `error.ConnectionClosed` - the fd is already closed (S28)
    pub fn flushSend(self: *Connection) !usize {
        // Nothing to do on a closed fd. posix.write(-1) would fail EBADF and
        // be reported as ConnectionReset, which drives the caller to close a
        // session that may still be resumable.
        if (self.closed) return error.ConnectionClosed;
        if (!self.hasPendingWrite()) return 0;

        const o = self.ob();
        const before = o.bytes();
        const result = self.flushOutbox(WRITE_BUF_SIZE);
        const wrote = before - o.bytes();
        return switch (result) {
            .drained, .budget_left => wrote,
            .want_read, .want_write => if (wrote > 0) wrote else error.WouldBlock,
            .err => error.ConnectionReset,
        };
    }

    /// Synchronous flush — blocks until all pending write data is sent.
    /// Used for graceful shutdown (sending </stream:stream> before close).
    pub fn flushSync(self: *Connection) void {
        var attempts: u32 = 0;
        while (self.hasPendingWrite() and attempts < 100) : (attempts += 1) {
            _ = self.flushSend() catch return;
        }
    }

    /// Upgrade the connection to TLS.
    ///
    /// Creates an SSL session from the given context and begins a non-blocking
    /// TLS handshake. The caller must then call `continueHandshake()` when
    /// kqueue signals the appropriate filter (read or write).
    ///
    /// After the handshake completes, `recv()` and `flushSend()` transparently
    /// use the TLS layer.
    pub fn upgradeToTls(self: *Connection, ctx: ssl.SslContext) !void {
        const conn = ssl.SslConn.init(ctx, self.fd) catch return error.ConnectionReset;
        self.tls = .{ .conn = conn };
        self.tls_state = .handshake_want_read; // Start expecting readable
    }

    /// Continue a non-blocking TLS handshake.
    ///
    /// Returns `true` when the handshake is complete. Returns `false` if
    /// more I/O is needed (check `tls_state` for the required kqueue filter).
    pub fn continueHandshake(self: *Connection) !bool {
        const tls = if (self.tls) |*t| &t.conn else return error.ConnectionReset;
        const result = tls.doHandshake() catch return error.ConnectionReset;
        switch (result) {
            .complete => {
                self.tls_state = .established;
                // Record kTLS offload on the Tls wrapper so the token
                // reflects what the socket actually negotiated; userland
                // fallback is silent without checking both directions.
                if (self.tls) |*t| {
                    t.ktls_tx = t.conn.ktlsSend();
                    t.ktls_rx = t.conn.ktlsRecv();
                }
                return true;
            },
            .want_read => {
                self.tls_state = .handshake_want_read;
                return false;
            },
            .want_write => {
                self.tls_state = .handshake_want_write;
                return false;
            },
        }
    }

    /// Returns the number of bytes buffered inside OpenSSL's internal read
    /// buffer (already decrypted but not yet returned to the application).
    /// Non-zero means read() can return data without a syscall — and kqueue
    /// won't fire because the socket buffer is empty.
    pub fn tlsPending(self: *Connection) usize {
        if (self.tls) |*t| return t.conn.pending();
        return 0;
    }

    /// Returns true if TLS is active (handshake complete).
    pub fn isTlsEstablished(self: *const Connection) bool {
        return self.tls_state == .established;
    }

    /// Returns true if a TLS handshake is in progress.
    pub fn isTlsHandshaking(self: *const Connection) bool {
        if (self.tls_state) |state| {
            return state == .handshake_want_read or state == .handshake_want_write;
        }
        return false;
    }

    /// Close the connection and release resources.
    pub fn close(self: *Connection) void {
        // A closed fd cannot drain; leave nothing linked that the
        // worker's dirty walk could pop after the Session is freed.
        self.unlinkDirty();
        if (!self.closed) {
            if (self.tls) |*t| {
                t.conn.shutdown();
                t.conn.deinit();
                self.tls = null;
                self.tls_state = null;
            }
            // fd -1 is already the "gone" sentinel (T155); posix.close on a
            // dead descriptor panics on EBADF.
            if (self.fd >= 0) posix.close(self.fd);
            // T155: reset fd to a sentinel. Any code path still holding this
            // Connection (a detached SM session lingering in server.sessions,
            // a room occupant slot) would otherwise hand a recycled descriptor
            // number to kqueue. EBADF is a loud, harmless failure; a recycled
            // fd silently misroutes events onto an unrelated connection (T153).
            self.fd = -1;
            self.closed = true;
        }
    }

    /// Full teardown: close the fd (if not already) and release the heap
    /// ring backing and any outbox spill. Kept separate from close()
    /// because a detached SM session closes its fd while the buffered
    /// bytes stay queued for the resume window; deinit runs when the
    /// owning Session is destroyed for real. Idempotent.
    pub fn deinit(self: *Connection) void {
        self.close();
        self.outbox.deinit();
        if (self.write_buf) |p| {
            self.outbox.alloc.free(p[0..]);
            self.write_buf = null;
            // A freed conn reports an empty outbox rather than a dangling ring.
            self.outbox.ring = &.{};
            self.outbox.head = 0;
            self.outbox.used = 0;
            self.outbox.pin = null;
        }
        if (self.cb_data_buf) |p| {
            self.outbox.alloc.destroy(p);
            self.cb_data_buf = null;
        }
    }

    /// Returns true if the connection has been closed.
    pub fn isClosed(self: *const Connection) bool {
        return self.closed;
    }

    /// Copy the queued outbox bytes (ring order) into `buf`, returning
    /// the slice written. Tests inspect queued output without draining
    /// a socketpair; production sends go through flushSend instead.
    pub fn pendingOutboxCopy(self: *Connection, buf: []u8) []const u8 {
        const o = self.ob();
        const n = @min(o.used, buf.len);
        const first = @min(n, o.ring.len - o.head);
        @memcpy(buf[0..first], o.ring[o.head..][0..first]);
        @memcpy(buf[first..n], o.ring[0..][0 .. n - first]);
        return buf[0..n];
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Connection: init" {
    var conn = Connection.init(42, 1, std.testing.allocator);
    try std.testing.expectEqual(@as(posix.fd_t, 42), conn.fd);
    try std.testing.expectEqual(@as(usize, 1), conn.id);
    try std.testing.expect(!conn.closed);
    try std.testing.expect(!conn.hasPendingWrite());
    try std.testing.expectEqual(@as(usize, 0), conn.readableSlice().len);
}

test "Connection: recv and readableSlice over socketpair" {
    const fds = try makeSocketPair();
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var conn = Connection.init(fds[0], 100, std.testing.allocator);

    // Write from peer side
    _ = try posix.write(fds[1], "hello xmpp");

    // Read into connection
    const n = try conn.recv();
    try std.testing.expectEqual(@as(usize, 10), n);
    try std.testing.expectEqualStrings("hello xmpp", conn.readableSlice());
}

test "Connection: consume advances read position" {
    const fds = try makeSocketPair();
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var conn = Connection.init(fds[0], 1, std.testing.allocator);
    _ = try posix.write(fds[1], "ABCDE");
    _ = try conn.recv();

    // Consume first 3 bytes
    conn.consume(3);
    try std.testing.expectEqualStrings("DE", conn.readableSlice());

    // Next recv should compact and append
    _ = try posix.write(fds[1], "FG");
    _ = try conn.recv();
    try std.testing.expectEqualStrings("DEFG", conn.readableSlice());
}

test "Connection: queueSend and flushSend" {
    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    var conn = Connection.init(fds[0], 1, std.testing.allocator);
    defer conn.deinit();

    // Queue data
    try conn.queueSend("<stream:stream>");
    try std.testing.expect(conn.hasPendingWrite());

    // Flush to socket
    const written = try conn.flushSend();
    try std.testing.expectEqual(@as(usize, 15), written);
    try std.testing.expect(!conn.hasPendingWrite());

    // Verify peer received it
    var buf: [64]u8 = undefined;
    const n = try posix.read(fds[1], &buf);
    try std.testing.expectEqualStrings("<stream:stream>", buf[0..n]);
}

test "Connection: multiple queueSend accumulates" {
    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    var conn = Connection.init(fds[0], 1, std.testing.allocator);
    defer conn.deinit();

    try conn.queueSend("<a>");
    try conn.queueSend("<b>");
    try conn.queueSend("<c>");

    _ = try conn.flushSend();

    var buf: [64]u8 = undefined;
    const n = try posix.read(fds[1], &buf);
    try std.testing.expectEqualStrings("<a><b><c>", buf[0..n]);
}

test "Connection: close sets closed flag" {
    const fds = try makeSocketPair();
    // Don't defer close fds[0] — connection will close it
    defer posix.close(fds[1]);

    var conn = Connection.init(fds[0], 1, std.testing.allocator);
    try std.testing.expect(!conn.isClosed());
    conn.close();
    try std.testing.expect(conn.isClosed());
}

test "Connection: recv returns 0 on peer close (EOF)" {
    const fds = try makeSocketPair();
    defer posix.close(fds[0]);

    var conn = Connection.init(fds[0], 1, std.testing.allocator);

    // Close peer side
    posix.close(fds[1]);

    // Should get EOF
    const n = try conn.recv();
    try std.testing.expectEqual(@as(usize, 0), n);
}

test "Connection: recv WouldBlock when no data" {
    const fds = try makeSocketPair();
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var conn = Connection.init(fds[0], 1, std.testing.allocator);
    const result = conn.recv();
    try std.testing.expectError(error.WouldBlock, result);
}

test "Connection: close resets fd to sentinel (T155)" {
    const fds = try makeSocketPair();
    // Don't defer close fds[0] — connection will close it
    defer posix.close(fds[1]);

    var conn = Connection.init(fds[0], 1, std.testing.allocator);
    try std.testing.expect(conn.fd >= 0);
    conn.close();
    // The descriptor number must not survive close — a recycled fd handed to
    // kqueue misroutes events onto an unrelated connection (T153).
    try std.testing.expectEqual(@as(posix.fd_t, -1), conn.fd);
}

test "Connection: queueSend on closed connection is rejected (T155)" {
    const fds = try makeSocketPair();
    // Don't defer close fds[0] — connection will close it
    defer posix.close(fds[1]);

    var conn = Connection.init(fds[0], 1, std.testing.allocator);
    conn.close();

    try std.testing.expectError(error.ConnectionClosed, conn.queueSend("<message/>"));
    // Critically, the rejected data must not leave the connection looking
    // writable — the dirty-list flush is gated on this.
    try std.testing.expect(!conn.hasPendingWrite());
}

test "Connection: M1 counters track bytes and queueSend drops" {
    metrics.bind(7);
    defer metrics.current = null;
    const c = metrics.get().?;
    const base_in = c.bytes_in.load(.monotonic);
    const base_out = c.bytes_out.load(.monotonic);
    const base_closed = c.drop_send_closed.load(.monotonic);
    const base_full = c.drop_send_buffer_full.load(.monotonic);

    const fds = try makeSocketPair();
    // fds[0] is closed by conn.close() below; do not double-close.
    defer posix.close(fds[1]);

    var conn = Connection.init(fds[0], 1, std.testing.allocator);
    defer conn.deinit();

    try conn.queueSend("hello");
    _ = try conn.flushSend();
    try std.testing.expectEqual(base_out + 5, c.bytes_out.load(.monotonic));

    _ = try posix.write(fds[1], "ping");
    _ = try conn.recv();
    try std.testing.expectEqual(base_in + 4, c.bytes_in.load(.monotonic));

    // The bounded spill makes the ring stop being the refusal bound;
    // shrink it so an oversized append still exercises failed_closed.
    conn.outbox.spill_limit = WRITE_BUF_SIZE;
    const big = [_]u8{'x'} ** (WRITE_BUF_SIZE + 1);
    try std.testing.expectError(error.WriteBufferFull, conn.queueSend(&big));
    try std.testing.expectEqual(base_full + 1, c.drop_send_buffer_full.load(.monotonic));

    conn.deinit();
    try std.testing.expectError(error.ConnectionClosed, conn.queueSend("x"));
    try std.testing.expectEqual(base_closed + 1, c.drop_send_closed.load(.monotonic));
}

test "Connection: a closed connection with a full buffer is not pending (S28)" {
    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    var conn = Connection.init(fds[0], 1, std.testing.allocator);
    try conn.queueSend("<message><body>still buffered</body></message>");
    try std.testing.expect(conn.hasPendingWrite());
    try std.testing.expect(conn.pendingWriteBytes() > 0);

    // An SM-detached session keeps its write buffer while its fd is gone.
    conn.close();
    try std.testing.expectEqual(@as(posix.fd_t, -1), conn.fd);

    // There is no fd to drain those bytes to, so they are not pending.
    // Reporting them as pending is what armed EVFILT_WRITE on fd -1 and drove
    // flushSend to destroy a resumable session.
    try std.testing.expect(!conn.hasPendingWrite());
    try std.testing.expectEqual(@as(usize, 0), conn.pendingWriteBytes());

    // Flushing says so explicitly rather than surfacing EBADF as a reset.
    try std.testing.expectError(error.ConnectionClosed, conn.flushSend());

    // The buffered bytes are untouched: a resume still has them if it wants.
    try std.testing.expect(conn.outbox.bytes() > 0);
    conn.deinit();
}

test "Connection: flushSync on a dead descriptor returns instead of spinning" {
    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    var conn = Connection.init(fds[0], 1, std.testing.allocator);
    defer conn.deinit();
    try conn.queueSend("<stream:error/>");

    // The fd dies mid-flush (peer teardown raced the graceful close).
    // flushSend surfaces EBADF as an error and flushSync must give up
    // immediately, not retry the dead descriptor 100 times.
    posix.close(fds[0]);
    conn.fd = -1;
    conn.flushSync();
    try std.testing.expect(conn.hasPendingWrite());
}

test "Connection: flushSync makes short-write progress then exits bounded" {
    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    // Fill the kernel buffer so only part of the payload fits.
    var filler: [4096]u8 = @splat('x');
    var filled: usize = 0;
    while (posix.write(fds[0], &filler)) |n| {
        filled += n;
    } else |_| {}
    try std.testing.expect(filled > 0);

    // Free a slice of space: one short write's worth, not the whole queue.
    var drain: [4096]u8 = undefined;
    _ = try posix.read(fds[1], &drain);

    var conn = Connection.init(fds[0], 1, std.testing.allocator);
    defer conn.deinit();
    // Bigger than the freed window, smaller than the 16KB write buffer.
    var payload_buf: [8192]u8 = @splat('y');
    const marker = "<stream:error";
    @memcpy(payload_buf[0..marker.len], marker);
    try conn.queueSend(&payload_buf);

    conn.flushSync();

    // Progress happened (a short write drained into the freed space) but
    // the peer never reads the rest, so flushSync must exit via its
    // attempt cap with data still pending, never spin forever.
    try std.testing.expect(conn.hasPendingWrite());
    var all: [262144]u8 = undefined;
    var total: usize = 0;
    while (posix.read(fds[1], all[total..])) |n| {
        if (n == 0) break;
        total += n;
    } else |_| {}
    try std.testing.expect(std.mem.indexOf(u8, all[0..total], marker) != null);
}

test "Connection: flushSync on a blocking fd coalesces short writes to completion" {
    // Blocking pair: a write that cannot complete waits for the peer, so
    // a slow reader turns one big payload into many short writes.
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM, 0, &fds);
    try std.testing.expectEqual(@as(isize, 0), rc);
    defer posix.close(fds[1]);

    const payload_len = 12 * 1024;
    var payload: [payload_len]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);

    // Slow reader: small reads so the writer never lands one big write.
    const Drainer = struct {
        fn run(fd: posix.fd_t, want: usize, got: *usize) void {
            var buf: [97]u8 = undefined;
            got.* = 0;
            while (got.* < want) {
                const n = std.posix.read(fd, &buf) catch return;
                if (n == 0) return;
                got.* += n;
            }
        }
    };
    var got: usize = 0;
    const t = try std.Thread.spawn(.{}, Drainer.run, .{ fds[1], payload_len, &got });

    var conn = Connection.init(fds[0], 1, std.testing.allocator);
    defer conn.deinit();
    try conn.queueSend(&payload);
    conn.flushSync();

    // Signal end-of-payload so a writer that reports completion but
    // under-delivers cannot leave the reader blocked forever; a short
    // transfer fails the count below instead of hanging (ce03221).
    std.posix.shutdown(fds[0], .send) catch {};
    t.join();

    try std.testing.expect(!conn.hasPendingWrite());
    try std.testing.expectEqual(payload_len, got);
}

// ---------------------------------------------------------------------------
// S23: TLS write retry pinning (real TLS over a socketpair)
// ---------------------------------------------------------------------------

const tls_test_c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/obj_mac.h");
    @cInclude("openssl/bio.h");
});

/// Generate a self-signed EC cert + key as one combined PEM inside `dir` and
/// return its path (caller frees). Test-only fixture for TLS socketpair tests.
pub fn makeTestPem(allocator: std.mem.Allocator, dir: std.fs.Dir) ![:0]u8 {
    const cc = tls_test_c;

    const pctx = cc.EVP_PKEY_CTX_new_id(cc.EVP_PKEY_EC, null) orelse return error.SslInitFailed;
    defer cc.EVP_PKEY_CTX_free(pctx);
    if (cc.EVP_PKEY_keygen_init(pctx) != 1) return error.SslInitFailed;
    if (cc.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, cc.NID_X9_62_prime256v1) != 1) return error.SslInitFailed;
    var pkey: ?*cc.EVP_PKEY = null;
    if (cc.EVP_PKEY_keygen(pctx, &pkey) != 1) return error.SslInitFailed;
    defer cc.EVP_PKEY_free(pkey);

    const x509 = cc.X509_new() orelse return error.SslInitFailed;
    defer cc.X509_free(x509);
    _ = cc.X509_set_version(x509, 2);
    _ = cc.ASN1_INTEGER_set(cc.X509_get_serialNumber(x509), 1);
    const now = std.time.timestamp();
    _ = cc.ASN1_TIME_set(cc.X509_get_notBefore(x509), now - 60);
    _ = cc.ASN1_TIME_set(cc.X509_get_notAfter(x509), now + 3600);
    const name = cc.X509_get_subject_name(x509);
    _ = cc.X509_NAME_add_entry_by_txt(name, "CN", cc.MBSTRING_ASC, "localhost", -1, -1, 0);
    _ = cc.X509_set_issuer_name(x509, name);
    _ = cc.X509_set_pubkey(x509, pkey);
    if (cc.X509_sign(x509, pkey, cc.EVP_sha256()) == 0) return error.SslInitFailed;

    const bio = cc.BIO_new(cc.BIO_s_mem()) orelse return error.SslInitFailed;
    defer _ = cc.BIO_free(bio);
    if (cc.PEM_write_bio_X509(bio, x509) != 1) return error.SslInitFailed;
    if (cc.PEM_write_bio_PrivateKey(bio, pkey, null, null, 0, null, null) != 1) return error.SslInitFailed;
    var mem_ptr: ?*anyopaque = null;
    const mem_len = cc.BIO_ctrl(bio, cc.BIO_CTRL_INFO, 0, @ptrCast(&mem_ptr));
    if (mem_len <= 0) return error.SslInitFailed;
    const pem_bytes = @as([*]const u8, @ptrCast(mem_ptr.?))[0..@intCast(mem_len)];

    const f = try dir.createFile("test.pem", .{});
    defer f.close();
    try f.writeAll(pem_bytes);

    const dir_path = try dir.realpathAlloc(allocator, ".");
    defer allocator.free(dir_path);
    return std.fmt.allocPrintSentinel(allocator, "{s}/test.pem", .{dir_path}, 0);
}

test "S23: TLS write retry resends only the pinned slice" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const pem_path = try makeTestPem(allocator, tmp.dir);
    defer allocator.free(pem_path);

    var server_ctx = try ssl.SslContext.initServer(pem_path, pem_path);
    defer server_ctx.deinit();
    var client_ctx = try ssl.SslContext.initClient();
    defer client_ctx.deinit();

    const fds = try makeSocketPair();
    var server_conn = Connection.init(fds[0], 1, std.testing.allocator);
    defer server_conn.deinit();
    var client_tls = try ssl.SslConn.initClient(client_ctx, fds[1], null);
    defer client_tls.deinit();

    try server_conn.upgradeToTls(server_ctx);

    // Drive both handshakes to completion.
    var client_done = false;
    var iter: usize = 0;
    while (iter < 10000 and !(server_conn.isTlsEstablished() and client_done)) : (iter += 1) {
        if (!server_conn.isTlsEstablished()) _ = server_conn.continueHandshake() catch {};
        if (!client_done) {
            client_done = (client_tls.doHandshake() catch .want_read) == .complete;
        }
    }
    try std.testing.expect(server_conn.isTlsEstablished());
    try std.testing.expect(client_done);

    // Q11: the accessors behind the post-handshake kTLS log line.
    {
        const tls = &(server_conn.tls orelse unreachable).conn;
        try std.testing.expect(tls.versionName().len > 0);
        try std.testing.expect(tls.cipherName().len > 0);
        _ = tls.ktlsSend();
        _ = tls.ktlsRecv();
    }

    // Tiny buffers both directions: the first large TLS write must
    // WANT_WRITE (unix sockets buffer on both the send and receive side).
    {
        const sndbuf: c_int = 1024;
        try posix.setsockopt(fds[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&sndbuf));
        try posix.setsockopt(fds[1], posix.SOL.SOCKET, posix.SO.RCVBUF, std.mem.asBytes(&sndbuf));
    }

    const a = "A" ** 12000;
    const b = "B" ** 4096;
    try server_conn.queueSend(a);
    try std.testing.expectError(error.WouldBlock, server_conn.flushSend());
    // The failed write pinned exactly the queued slice...
    try std.testing.expectEqual(@as(usize, a.len), server_conn.ob().pin.?.len);

    // ...and bytes queued afterwards must not extend the retried slice.
    try server_conn.queueSend(b);
    try std.testing.expectEqual(@as(usize, a.len), server_conn.ob().pin.?.len);

    // Drain: alternate server flushes with client reads; collect everything.
    var received = std.ArrayList(u8){};
    defer received.deinit(allocator);
    var rbuf: [16384]u8 = undefined;
    iter = 0;
    while (iter < 100000 and received.items.len < a.len + b.len) : (iter += 1) {
        _ = server_conn.flushSend() catch {};
        switch (client_tls.read(&rbuf) catch .want_read) {
            .ok => |n| try received.appendSlice(allocator, rbuf[0..n]),
            else => {},
        }
    }

    try std.testing.expectEqual(a.len + b.len, received.items.len);
    try std.testing.expectEqualSlices(u8, a, received.items[0..a.len]);
    try std.testing.expectEqualSlices(u8, b, received.items[a.len..]);
    try std.testing.expect(server_conn.ob().pin == null);
    try std.testing.expect(!server_conn.hasPendingWrite());
}

test "S23: TLS connection wraps the outbox ring after a pinned retry" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const pem_path = try makeTestPem(allocator, tmp.dir);
    defer allocator.free(pem_path);

    var server_ctx = try ssl.SslContext.initServer(pem_path, pem_path);
    defer server_ctx.deinit();
    var client_ctx = try ssl.SslContext.initClient();
    defer client_ctx.deinit();

    const fds = try makeSocketPair();
    var server_conn = Connection.init(fds[0], 1, std.testing.allocator);
    defer server_conn.deinit();
    var client_tls = try ssl.SslConn.initClient(client_ctx, fds[1], null);
    defer client_tls.deinit();

    try server_conn.upgradeToTls(server_ctx);

    var client_done = false;
    var iter: usize = 0;
    while (iter < 10000 and !(server_conn.isTlsEstablished() and client_done)) : (iter += 1) {
        if (!server_conn.isTlsEstablished()) _ = server_conn.continueHandshake() catch {};
        if (!client_done) {
            client_done = (client_tls.doHandshake() catch .want_read) == .complete;
        }
    }
    try std.testing.expect(server_conn.isTlsEstablished());
    try std.testing.expect(client_done);

    {
        const sndbuf: c_int = 1024;
        try posix.setsockopt(fds[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&sndbuf));
        try posix.setsockopt(fds[1], posix.SOL.SOCKET, posix.SO.RCVBUF, std.mem.asBytes(&sndbuf));
    }

    const a = "A" ** 12000;
    const b = "B" ** 512;
    try server_conn.queueSend(a);
    try std.testing.expectError(error.WouldBlock, server_conn.flushSend());
    try std.testing.expectEqual(@as(usize, a.len), server_conn.ob().pin.?.len);
    try server_conn.queueSend(b);

    // Drain only the pinned slice, then stop: the ring head has crept
    // past 0 with no retry pinned.
    var received = std.ArrayList(u8){};
    defer received.deinit(allocator);
    var rbuf: [16384]u8 = undefined;
    iter = 0;
    while (iter < 100000) : (iter += 1) {
        _ = server_conn.flushSend() catch {};
        if (server_conn.ob().pin == null and server_conn.ob().head > 0) break;
        switch (client_tls.read(&rbuf) catch .want_read) {
            .ok => |n| try received.appendSlice(allocator, rbuf[0..n]),
            else => {},
        }
    }
    // The pin is cleared and at least the pinned slice drained; a single
    // flush pass may also have written some or all of b behind it.
    try std.testing.expect(server_conn.ob().pin == null);
    try std.testing.expect(server_conn.ob().head >= a.len);
    try std.testing.expect(server_conn.ob().used <= b.len);

    // The tail of the ring has no contiguous room for c (the append
    // point is 3872 bytes from the end); the ring wraps it into the
    // freed front instead of failing WriteBufferFull.
    const c = "C" ** 4096;
    const used_before = server_conn.ob().used;
    try server_conn.queueSend(c);
    try std.testing.expectEqual(used_before + c.len, server_conn.ob().used);

    // Everything queued still arrives, in order.
    iter = 0;
    while (iter < 100000 and received.items.len < a.len + b.len + c.len) : (iter += 1) {
        _ = server_conn.flushSend() catch {};
        switch (client_tls.read(&rbuf) catch .want_read) {
            .ok => |n| try received.appendSlice(allocator, rbuf[0..n]),
            else => {},
        }
    }
    try std.testing.expectEqual(a.len + b.len + c.len, received.items.len);
    try std.testing.expectEqualSlices(u8, a, received.items[0..a.len]);
    try std.testing.expectEqualSlices(u8, b, received.items[a.len..][0..b.len]);
    try std.testing.expectEqualSlices(u8, c, received.items[a.len + b.len ..]);
}
