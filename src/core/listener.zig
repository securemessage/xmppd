//! # Listener — TCP socket bind/listen/accept
//!
//! Manages a listening socket for incoming XMPP client connections.
//! One listener per port — typically two: port 5222 (STARTTLS) and
//! port 5223 (direct TLS).
//!
//! ## Non-blocking accept
//!
//! The listening socket is set to non-blocking mode. When kqueue signals
//! `EVFILT_READ` on the listener fd, the `data` field contains the number
//! of pending connections. The caller should call `accept()` in a loop
//! until it returns `error.WouldBlock` to drain the backlog.
//!
//! ## Integration with EventLoop
//!
//! Register the listener fd with the event loop for read events:
//! ```zig
//! try batch.addRead(listener.fd, LISTENER_UDATA);
//! ```
//! When `fd_readable` fires for the listener fd, call `listener.accept()`
//! to get new `Connection` objects.

const std = @import("std");
const posix = std.posix;
const Connection = @import("connection.zig").Connection;

/// A TCP listening socket that accepts new connections.
pub const Listener = struct {
    /// The listening socket file descriptor.
    fd: posix.fd_t,
    /// Whether this listener is for direct TLS (port 5223).
    direct_tls: bool,

    /// Bind and listen on the given address and port.
    ///
    /// - `address` — bind address (e.g., `0.0.0.0` for all interfaces, `127.0.0.1` for local only)
    /// - `port` — TCP port number
    /// - `direct_tls` — if true, accepted connections start in TLS mode (port 5223 behavior)
    /// - `backlog` — listen backlog size (pending connections queue)
    ///
    /// The socket is created with `SO_REUSEADDR` and set to non-blocking mode.
    ///
    /// ## Errors
    /// - `error.AddressInUse` — port is already bound
    /// - `error.PermissionDenied` — binding to port <1024 without root
    /// - `error.SystemResources` — fd exhaustion
    pub fn init(address: []const u8, port: u16, direct_tls: bool, backlog: u31) !Listener {
        // Create IPv4 socket
        const fd = try posix.socket(
            posix.AF.INET,
            posix.SOCK.STREAM | posix.SOCK.NONBLOCK,
            0,
        );
        errdefer posix.close(fd);

        // SO_REUSEADDR — allow immediate rebind after restart
        const one: c_int = 1;
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));

        // Build bind address
        const ip = parseIPv4(address) orelse return error.InvalidAddress;
        var addr = std.c.sockaddr.in{
            .port = std.mem.nativeToBig(u16, port),
            .addr = ip,
        };

        // Bind
        posix.bind(fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch |err| {
            return switch (err) {
                error.AddressInUse => error.AddressInUse,
                error.AccessDenied => error.PermissionDenied,
                else => error.SystemResources,
            };
        };

        // Listen
        posix.listen(fd, backlog) catch {
            return error.SystemResources;
        };

        return Listener{
            .fd = fd,
            .direct_tls = direct_tls,
        };
    }

    /// Wrap a pre-bound, pre-listening fd (received from the master via fd inheritance).
    /// The fd must already be bound, listening, and non-blocking.
    pub fn initFromFd(fd: posix.fd_t, direct_tls: bool) Listener {
        return Listener{
            .fd = fd,
            .direct_tls = direct_tls,
        };
    }

    /// Accept a pending connection.
    ///
    /// Returns a new `Connection` wrapping the accepted client socket.
    /// The socket is set to non-blocking mode. The peer IP address is
    /// captured and stored on the Connection.
    ///
    /// - `conn_id` — unique ID to assign to this connection (used as kqueue udata)
    ///
    /// Call this in a loop after `EVFILT_READ` fires on the listener fd,
    /// until it returns `error.WouldBlock`.
    ///
    /// ## Errors
    /// - `error.WouldBlock` — no more pending connections
    /// - `error.SystemResources` — fd exhaustion
    pub fn accept(self: *const Listener, conn_id: usize) !Connection {
        var addr: std.c.sockaddr.in = undefined;
        var addr_len: posix.socklen_t = @sizeOf(std.c.sockaddr.in);

        const client_fd = posix.accept(self.fd, @ptrCast(&addr), &addr_len, posix.SOCK.NONBLOCK) catch |err| {
            return switch (err) {
                error.WouldBlock => error.WouldBlock,
                error.ProcessFdQuotaExceeded => error.SystemResources,
                error.SystemFdQuotaExceeded => error.SystemResources,
                error.ConnectionAborted => error.WouldBlock,
                else => error.SystemResources,
            };
        };

        // Disable Nagle's algorithm — XMPP is interactive, small stanzas
        // should be sent immediately without coalescing delay.
        // TCP_NODELAY = 1 (netinet/tcp.h), IPPROTO_TCP = 6
        const nodelay: c_int = 1;
        posix.setsockopt(client_fd, 6, 1, std.mem.asBytes(&nodelay)) catch {};

        // Format peer IP into the connection
        var conn = Connection.init(client_fd, conn_id);
        const ip_bytes = @as(*const [4]u8, @ptrCast(&addr.addr));
        const written = std.fmt.bufPrint(&conn.peer_addr_buf, "{d}.{d}.{d}.{d}", .{
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
        }) catch "";
        conn.peer_addr_len = written.len;
        return conn;
    }

    /// Close the listening socket.
    pub fn deinit(self: *Listener) void {
        posix.close(self.fd);
        self.fd = -1;
    }
};

/// Parse an IPv4 address string to a network-order u32.
/// Returns null for unrecognized formats.
fn parseIPv4(address: []const u8) ?u32 {
    if (address.len == 0 or std.mem.eql(u8, address, "0.0.0.0")) {
        return 0; // INADDR_ANY
    }
    if (std.mem.eql(u8, address, "127.0.0.1")) {
        return std.mem.nativeToBig(u32, 0x7f000001);
    }
    // TODO: general dotted-quad parser for arbitrary IPs
    return null;
}

// ============================================================================
// Tests
// ============================================================================

test "Listener: bind and accept on high port" {
    // Bind to a random high port on localhost
    var listener = try Listener.init("127.0.0.1", 0, false, 5);
    defer listener.deinit();

    // Get the actual bound port
    var addr: std.c.sockaddr.in = undefined;
    var addr_len: posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    const rc = std.c.getsockname(listener.fd, @ptrCast(&addr), &addr_len);
    try std.testing.expect(rc == 0);
    const bound_port = std.mem.bigToNative(u16, addr.port);
    try std.testing.expect(bound_port > 0);

    // Connect a client
    const client_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(client_fd);

    var connect_addr = std.c.sockaddr.in{
        .port = addr.port,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    posix.connect(client_fd, @ptrCast(&connect_addr), @sizeOf(std.c.sockaddr.in)) catch |err| {
        // Non-blocking connect returns EINPROGRESS
        if (err != error.WouldBlock) return err;
    };

    // Give the kernel a moment to complete the handshake
    std.Thread.sleep(10 * std.time.ns_per_ms);

    // Accept should succeed
    var conn = try listener.accept(42);
    defer conn.close();

    try std.testing.expectEqual(@as(usize, 42), conn.id);
    try std.testing.expect(conn.fd >= 0);
    try std.testing.expect(!conn.isClosed());
}

test "Listener: accept returns WouldBlock when no clients" {
    var listener = try Listener.init("127.0.0.1", 0, false, 5);
    defer listener.deinit();

    const result = listener.accept(1);
    try std.testing.expectError(error.WouldBlock, result);
}

test "Listener: direct_tls flag preserved" {
    var listener = try Listener.init("127.0.0.1", 0, true, 5);
    defer listener.deinit();

    try std.testing.expect(listener.direct_tls);
}
