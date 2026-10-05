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
//! - **Write buffer**: Fixed 16KB. Data is appended by the stream handler and
//!   drained to the socket when writable. When it fills beyond WRITE_SUPPRESS_HIGH
//!   the worker disables EVFILT_READ for the fd (T110): TCP flow control
//!   pushes back on the sender until the buffer drains below WRITE_SUPPRESS_LOW.
//!   If it fills completely, queueSend() fails with error.WriteBufferFull.
//!
//! ## TLS
//!
//! The `tls` field is null for plain TCP. After STARTTLS, `upgradeToTls()`
//! sets it and all subsequent `recv()` / `flushSend()` calls go through
//! the TLS layer transparently. The TLS implementation comes in step 5f/5g.

const std = @import("std");
const posix = std.posix;
const ssl = @import("ssl");

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
const WRITE_BUF_SIZE = 16384;

/// T110 backpressure: at/above this buffered-bytes level the server disables
/// EVFILT_READ for the connection, so TCP-level flow control propagates to
/// the sender's kernel instead of us reading ever more stanzas we cannot
/// forward. 75% of the write buffer.
pub const WRITE_SUPPRESS_HIGH: usize = WRITE_BUF_SIZE * 3 / 4;

/// T110 backpressure: reading resumes once the buffer drained to or below
/// this level. 50% — hysteresis against flapping at the threshold.
pub const WRITE_SUPPRESS_LOW: usize = WRITE_BUF_SIZE / 2;

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

    /// Outgoing data buffer. Stream handler appends at `write_end`,
    /// socket drains from `write_start`.
    write_buf: [WRITE_BUF_SIZE]u8 = undefined,
    /// Start of unsent data in write_buf.
    write_start: usize = 0,
    /// Length of the TLS write slice pinned by an in-flight `SSL_write`
    /// (0 = none). While > 0, flushSend retries exactly
    /// `write_buf[write_start..][0..tls_write_pending]`: OpenSSL retains the
    /// buffer across WANT_WRITE, and retrying the same pointer with a longer
    /// length violates the identical pointer-and-length rule and corrupts the
    /// stream with kTLS (S23). Bytes queued after the pin stay behind it.
    tls_write_pending: usize = 0,
    /// End of buffered data in write_buf (next append position).
    write_end: usize = 0,

    /// TLS connection — null for plain TCP, set after STARTTLS upgrade.
    tls_conn: ?ssl.SslConn = null,

    /// TLS handshake progress — only meaningful when tls_conn is set.
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

    /// Stable buffer for channel binding data (outlives the getChannelBinding call).
    cb_data_buf: [32]u8 = undefined,

    /// Initialize a new connection from an accepted socket.
    ///
    /// - `fd` — the accepted client socket (must already be non-blocking)
    /// - `id` — unique identifier for this connection (used as kqueue udata)
    pub fn init(fd: posix.fd_t, id: usize) Connection {
        return .{
            .fd = fd,
            .id = id,
        };
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
        if (self.tls_conn) |*tls| {
            if (tls.getChannelBinding()) |cb| {
                // Store in a stable buffer so the slice outlives this call
                self.cb_data_buf = cb.data;
                return .{ .cb_type = @intFromEnum(cb.cb_type), .data = &self.cb_data_buf };
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

        if (self.tls_conn) |*tls| {
            const result = tls.read(buf) catch |err| {
                return switch (err) {
                    ssl.SslError.ConnectionClosed => @as(usize, 0), // EOF
                    else => error.ConnectionReset,
                };
            };
            return switch (result) {
                .ok => |n| blk: {
                    self.read_end += n;
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

    /// Append data to the write buffer for later sending.
    ///
    /// Returns `error.WriteBufferFull` if there is not enough space — the
    /// caller should wait for `flushSend()` to drain some data before queueing
    /// more. Returns `error.ConnectionClosed` if the connection is already
    /// closed; the stanza should be dropped or tracked for SM replay instead.
    pub fn queueSend(self: *Connection, data: []const u8) !void {
        // T155: refuse to buffer for a closed connection. Without this the data
        // lands in write_buf, hasPendingWrite() then reports true, and the
        // caller arms kqueue on a dead fd. Mirrors S2sSession.queueSend.
        if (self.closed) return error.ConnectionClosed;

        const space = WRITE_BUF_SIZE - self.write_end;
        if (data.len > space) {
            // Try compacting first
            self.compactWriteBuf();
            const space_after = WRITE_BUF_SIZE - self.write_end;
            if (data.len > space_after) {
                return error.WriteBufferFull;
            }
        }
        @memcpy(self.write_buf[self.write_end .. self.write_end + data.len], data);
        self.write_end += data.len;
    }

    /// Returns true if there is unsent data in the write buffer.
    /// When true, the caller should register this fd for EVFILT_WRITE.
    pub fn hasPendingWrite(self: *const Connection) bool {
        return self.write_start < self.write_end;
    }

    /// Bytes currently buffered for writing (T110 backpressure thresholds).
    pub fn pendingWriteBytes(self: *const Connection) usize {
        return self.write_end - self.write_start;
    }

    /// Flush the write buffer to the socket.
    ///
    /// Returns the number of bytes written. The caller should keep this fd
    /// registered for EVFILT_WRITE until `hasPendingWrite()` returns false.
    ///
    /// ## Errors
    /// - `error.WouldBlock` — socket send buffer is full, try again later
    /// - `error.ConnectionReset` — peer reset the connection
    pub fn flushSend(self: *Connection) !usize {
        if (!self.hasPendingWrite()) return 0;

        if (self.tls_conn) |*tls| {
            // A pending WANT_WRITE retry must use the identical (pointer,
            // length) pair OpenSSL was first given; bytes appended since are
            // not part of the retried slice (S23).
            std.debug.assert(self.tls_write_pending == 0 or
                self.tls_write_pending <= self.write_end - self.write_start);
            const data = if (self.tls_write_pending > 0)
                self.write_buf[self.write_start..][0..self.tls_write_pending]
            else
                self.write_buf[self.write_start..self.write_end];
            const result = tls.write(data) catch {
                return error.ConnectionReset;
            };
            return switch (result) {
                .ok => |n| blk: {
                    self.tls_write_pending = 0;
                    self.write_start += n;
                    if (self.write_start == self.write_end) {
                        self.write_start = 0;
                        self.write_end = 0;
                    }
                    break :blk n;
                },
                .want_read, .want_write => blk: {
                    // Pin the exact slice for the retry (only on the first
                    // WANT; later WANTs keep the original pin).
                    if (self.tls_write_pending == 0) self.tls_write_pending = data.len;
                    break :blk error.WouldBlock;
                },
            };
        }

        const data = self.write_buf[self.write_start..self.write_end];
        const n = posix.write(self.fd, data) catch |err| {
            return switch (err) {
                error.WouldBlock => error.WouldBlock,
                error.BrokenPipe => error.ConnectionReset,
                error.ConnectionResetByPeer => error.ConnectionReset,
                error.NotOpenForWriting => error.ConnectionReset,
                else => error.ConnectionReset,
            };
        };

        self.write_start += n;

        // If fully drained, reset positions to reclaim buffer space
        if (self.write_start == self.write_end) {
            self.write_start = 0;
            self.write_end = 0;
        }

        return n;
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
        self.tls_conn = ssl.SslConn.init(ctx, self.fd) catch return error.ConnectionReset;
        self.tls_state = .handshake_want_read; // Start expecting readable
    }

    /// Continue a non-blocking TLS handshake.
    ///
    /// Returns `true` when the handshake is complete. Returns `false` if
    /// more I/O is needed (check `tls_state` for the required kqueue filter).
    pub fn continueHandshake(self: *Connection) !bool {
        var tls = &(self.tls_conn orelse return error.ConnectionReset);
        const result = tls.doHandshake() catch return error.ConnectionReset;
        switch (result) {
            .complete => {
                self.tls_state = .established;
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
        if (self.tls_conn) |*tls| return tls.pending();
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
        if (!self.closed) {
            if (self.tls_conn) |*tls| {
                tls.shutdown();
                tls.deinit();
                self.tls_conn = null;
                self.tls_state = null;
            }
            posix.close(self.fd);
            // T155: reset fd to a sentinel. Any code path still holding this
            // Connection (a detached SM session lingering in server.sessions,
            // a room occupant slot) would otherwise hand a recycled descriptor
            // number to kqueue. EBADF is a loud, harmless failure; a recycled
            // fd silently misroutes events onto an unrelated connection (T153).
            self.fd = -1;
            self.closed = true;
        }
    }

    /// Returns true if the connection has been closed.
    pub fn isClosed(self: *const Connection) bool {
        return self.closed;
    }

    // --- Private helpers ---

    fn compactWriteBuf(self: *Connection) void {
        // A TLS write retried after WANT_WRITE must keep the pinned
        // (pointer, length) pair; moving it gives "bad write retry" (or
        // corrupt data with kTLS). Only an active pin blocks compaction:
        // gating on tls_conn left write_start to creep until queueSend
        // failed with the front of the buffer free.
        if (self.tls_write_pending != 0) return;
        if (self.write_start == 0) return;
        const remaining = self.write_end - self.write_start;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.write_buf[0..remaining], self.write_buf[self.write_start..self.write_end]);
        }
        self.write_end = remaining;
        self.write_start = 0;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Connection: init" {
    var conn = Connection.init(42, 1);
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

    var conn = Connection.init(fds[0], 100);

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

    var conn = Connection.init(fds[0], 1);
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
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var conn = Connection.init(fds[0], 1);

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
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var conn = Connection.init(fds[0], 1);

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

    var conn = Connection.init(fds[0], 1);
    try std.testing.expect(!conn.isClosed());
    conn.close();
    try std.testing.expect(conn.isClosed());
}

test "Connection: recv returns 0 on peer close (EOF)" {
    const fds = try makeSocketPair();
    defer posix.close(fds[0]);

    var conn = Connection.init(fds[0], 1);

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

    var conn = Connection.init(fds[0], 1);
    const result = conn.recv();
    try std.testing.expectError(error.WouldBlock, result);
}

test "Connection: close resets fd to sentinel (T155)" {
    const fds = try makeSocketPair();
    // Don't defer close fds[0] — connection will close it
    defer posix.close(fds[1]);

    var conn = Connection.init(fds[0], 1);
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

    var conn = Connection.init(fds[0], 1);
    conn.close();

    try std.testing.expectError(error.ConnectionClosed, conn.queueSend("<message/>"));
    // Critically, the rejected data must not leave the connection looking
    // writable — callers gate `changes.addWrite(conn.fd, ..)` on this.
    try std.testing.expect(!conn.hasPendingWrite());
}

test "Connection: flushSync on a dead descriptor returns instead of spinning" {
    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    var conn = Connection.init(fds[0], 1);
    try conn.queueSend("<stream:error/>");

    // The fd dies mid-flush (peer teardown raced the graceful close).
    // flushSend surfaces EBADF as an error and flushSync must give up
    // immediately, not retry the dead descriptor 100 times.
    posix.close(fds[0]);
    conn.flushSync();
    try std.testing.expect(conn.hasPendingWrite());
}

test "Connection: flushSync makes short-write progress then exits bounded" {
    const fds = try makeSocketPair();
    defer posix.close(fds[0]);
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

    var conn = Connection.init(fds[0], 1);
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
    defer posix.close(fds[0]);
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

    var conn = Connection.init(fds[0], 1);
    try conn.queueSend(&payload);
    conn.flushSync();

    try std.testing.expect(!conn.hasPendingWrite());
    t.join();
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
    var server_conn = Connection.init(fds[0], 1);
    defer server_conn.close();
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
        const tls = &(server_conn.tls_conn orelse unreachable);
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
    try std.testing.expectEqual(@as(usize, a.len), server_conn.tls_write_pending);

    // ...and bytes queued afterwards must not extend the retried slice.
    try server_conn.queueSend(b);
    try std.testing.expectEqual(@as(usize, a.len), server_conn.tls_write_pending);

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
    try std.testing.expectEqual(@as(usize, 0), server_conn.tls_write_pending);
    try std.testing.expect(!server_conn.hasPendingWrite());
}

test "S23: TLS connection with no pinned retry compacts the write buffer" {
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
    var server_conn = Connection.init(fds[0], 1);
    defer server_conn.close();
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
    try std.testing.expectEqual(@as(usize, a.len), server_conn.tls_write_pending);
    try server_conn.queueSend(b);

    // Drain only the pinned slice, then stop: write_start has crept past
    // 0 with no retry pinned.
    var received = std.ArrayList(u8){};
    defer received.deinit(allocator);
    var rbuf: [16384]u8 = undefined;
    iter = 0;
    while (iter < 100000) : (iter += 1) {
        _ = server_conn.flushSend() catch {};
        if (server_conn.tls_write_pending == 0 and server_conn.write_start > 0) break;
        switch (client_tls.read(&rbuf) catch .want_read) {
            .ok => |n| try received.appendSlice(allocator, rbuf[0..n]),
            else => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 0), server_conn.tls_write_pending);
    try std.testing.expectEqual(a.len, server_conn.write_start);
    try std.testing.expectEqual(a.len + b.len, server_conn.write_end);

    // Fewer than c.len bytes remain at the tail; queueSend must compact
    // the freed front instead of failing WriteBufferFull.
    const c = "C" ** 4096;
    try server_conn.queueSend(c);
    try std.testing.expectEqual(@as(usize, 0), server_conn.write_start);
    try std.testing.expectEqual(b.len + c.len, server_conn.write_end);

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
