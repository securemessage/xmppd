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
//!   drained to the socket when writable. If the buffer fills, backpressure
//!   is applied (stop reading from this connection until writes drain).
//!
//! ## TLS
//!
//! The `tls` field is null for plain TCP. After STARTTLS, `upgradeToTls()`
//! sets it and all subsequent `recv()` / `flushSend()` calls go through
//! the TLS layer transparently. The TLS implementation comes in step 5f/5g.

const std = @import("std");
const posix = std.posix;

/// Create a non-blocking Unix socketpair. Used in tests.
fn makeSocketPair() ![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    return fds;
}

/// Opaque TLS connection handle — implemented in step 5f (lib/tls/ssl.zig).
/// For now this is a placeholder type; Connection compiles and works without TLS.
pub const TlsConn = opaque {};

/// Read buffer size — 8KB per connection.
/// XMPP stanzas are typically small (<4KB); 8KB handles even large presence payloads.
const READ_BUF_SIZE = 8192;

/// Write buffer size — 16KB per connection.
/// Larger than read because the server may need to send stream features + multiple
/// stanzas before the client has a chance to ACK at the TCP level.
const WRITE_BUF_SIZE = 16384;

/// Per-client XMPP connection state.
pub const Connection = struct {
    /// The client socket file descriptor.
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
    /// End of buffered data in write_buf (next append position).
    write_end: usize = 0,

    /// TLS state — null for plain TCP, set after STARTTLS upgrade.
    tls: ?*TlsConn = null,

    /// Unique connection ID (for use as kqueue udata).
    id: usize,

    /// Whether the connection is in a closed/error state.
    closed: bool = false,

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

        if (self.tls) |_| {
            // TLS read — implemented in step 5g
            @panic("TLS not yet implemented");
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
    /// Returns `error.WriteBufferFull` if there isn't enough space.
    /// In that case, the caller should wait for `flushSend()` to drain
    /// some data before queueing more.
    pub fn queueSend(self: *Connection, data: []const u8) !void {
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

        const data = self.write_buf[self.write_start..self.write_end];

        if (self.tls) |_| {
            // TLS write — implemented in step 5g
            @panic("TLS not yet implemented");
        }

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

    /// Close the connection and release resources.
    pub fn close(self: *Connection) void {
        if (!self.closed) {
            posix.close(self.fd);
            self.closed = true;
        }
    }

    /// Returns true if the connection has been closed.
    pub fn isClosed(self: *const Connection) bool {
        return self.closed;
    }

    // --- Private helpers ---

    fn compactWriteBuf(self: *Connection) void {
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
