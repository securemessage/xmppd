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
    /// - `address` — bind address: IPv4 or IPv6 literal (`0.0.0.0`/empty for all
    ///   IPv4 interfaces, `127.0.0.1` for local only, `::` for all IPv6 interfaces)
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
        const bind_addr = parseBindAddress(address, port) orelse return error.InvalidAddress;

        // Create socket matching the address family (IPv4 or IPv6)
        const fd = try posix.socket(
            bind_addr.any.family,
            posix.SOCK.STREAM | posix.SOCK.NONBLOCK,
            0,
        );
        errdefer posix.close(fd);

        // SO_REUSEADDR — allow immediate rebind after restart
        const one: c_int = 1;
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));

        // Bind
        posix.bind(fd, &bind_addr.any, bind_addr.getOsSockLen()) catch |err| {
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
        // sockaddr.storage so IPv6 peers (sockaddr.in6) fit without truncation
        var addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);

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
        formatPeerAddr(&addr, &conn.peer_addr_buf, &conn.peer_addr_len);
        return conn;
    }

    /// Close the listening socket.
    pub fn deinit(self: *Listener) void {
        posix.close(self.fd);
        self.fd = -1;
    }
};

/// Parse a bind address string into a std.net.Address (T167).
/// Empty or "0.0.0.0" → IPv4 any; "::" → IPv6 any; otherwise a literal
/// IPv4 or IPv6 address. Returns null for unrecognized input.
fn parseBindAddress(address: []const u8, port: u16) ?std.net.Address {
    if (address.len == 0) return std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
    if (std.net.Address.parseIp4(address, port)) |addr| {
        return addr;
    } else |_| {
        return std.net.Address.parseIp6(address, port) catch null;
    }
}

/// Format the peer address from an accepted socket into buf (IPv4 dotted-quad
/// or IPv6 literal). Sets out_len to the written length (0 on unknown family).
fn formatPeerAddr(sa: *const posix.sockaddr.storage, buf: []u8, out_len: *usize) void {
    out_len.* = 0;
    switch (sa.family) {
        posix.AF.INET => {
            const in: *const posix.sockaddr.in = @ptrCast(@alignCast(sa));
            const ip_bytes = @as(*const [4]u8, @ptrCast(&in.addr));
            const written = std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
                ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
            }) catch return;
            out_len.* = written.len;
        },
        posix.AF.INET6 => {
            const in6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(sa));
            const addr = std.net.Address.initIp6(in6.addr, 0, 0, in6.scope_id);
            // std formats IPv6 as "[addr]:port" — strip to the bare literal
            // to match the IPv4 peer format (no port).
            var tmp: [64]u8 = undefined;
            const s = std.fmt.bufPrint(&tmp, "{f}", .{addr}) catch return;
            if (s.len > 2 and s[0] == '[') {
                if (std.mem.indexOfScalar(u8, s, ']')) |close| {
                    const bare = s[1..close];
                    @memcpy(buf[0..bare.len], bare);
                    out_len.* = bare.len;
                    return;
                }
            }
            @memcpy(buf[0..s.len], s);
            out_len.* = s.len;
        },
        else => {},
    }
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

test "parseBindAddress: IPv4" {
    const any4 = parseBindAddress("", 5222).?;
    try std.testing.expectEqual(posix.AF.INET, any4.any.family);
    try std.testing.expectEqual(@as(u16, 5222), any4.in.getPort());
    try std.testing.expectEqual(@as(u32, 0), any4.in.sa.addr);

    const any4_explicit = parseBindAddress("0.0.0.0", 5222).?;
    try std.testing.expectEqual(@as(u32, 0), any4_explicit.in.sa.addr);

    const loopback = parseBindAddress("127.0.0.1", 5222).?;
    try std.testing.expectEqual(posix.AF.INET, loopback.any.family);
    try std.testing.expectEqual(std.mem.nativeToBig(u32, 0x7f000001), loopback.in.sa.addr);

    // Arbitrary dotted-quad (was unsupported pre-T167)
    const specific = parseBindAddress("192.0.2.10", 5223).?;
    try std.testing.expectEqual(posix.AF.INET, specific.any.family);
    try std.testing.expectEqual(std.mem.nativeToBig(u32, 0xC000020A), specific.in.sa.addr);
    try std.testing.expectEqual(@as(u16, 5223), specific.in.getPort());
}

test "parseBindAddress: IPv6" {
    const any6 = parseBindAddress("::", 5222).?;
    try std.testing.expectEqual(posix.AF.INET6, any6.any.family);
    try std.testing.expectEqual(@as(u16, 5222), any6.in6.getPort());

    const loop6 = parseBindAddress("::1", 5222).?;
    try std.testing.expectEqual(posix.AF.INET6, loop6.any.family);

    const full6 = parseBindAddress("2001:db8::1", 5222).?;
    try std.testing.expectEqual(posix.AF.INET6, full6.any.family);
}

test "parseBindAddress: rejects invalid input" {
    try std.testing.expect(parseBindAddress("not-an-ip", 5222) == null);
    try std.testing.expect(parseBindAddress("999.1.1.1", 5222) == null);
    try std.testing.expect(parseBindAddress("1.2.3", 5222) == null);
    try std.testing.expect(parseBindAddress("example.com", 5222) == null);
    try std.testing.expect(parseBindAddress("127.0.0.1:5222", 5222) == null);
}

test "Listener: bind and accept on IPv6 loopback" {
    var listener = Listener.init("::1", 0, false, 5) catch |err| {
        // Host without an IPv6 loopback — nothing to test
        if (err == error.SystemResources or err == error.AddressInUse) return;
        return err;
    };
    defer listener.deinit();

    // Get the actual bound port
    var bound: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    const rc = std.c.getsockname(listener.fd, @ptrCast(&bound), &bound_len);
    try std.testing.expect(rc == 0);
    const bound_in6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(&bound));
    const bound_port = std.mem.bigToNative(u16, bound_in6.port);
    try std.testing.expect(bound_port > 0);

    // Connect a client over IPv6
    const client_fd = try posix.socket(posix.AF.INET6, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(client_fd);

    const connect_addr = std.net.Address.parseIp6("::1", bound_port) catch unreachable;
    posix.connect(client_fd, &connect_addr.any, connect_addr.getOsSockLen()) catch |err| {
        if (err != error.WouldBlock) return err;
    };

    std.Thread.sleep(10 * std.time.ns_per_ms);

    var conn = try listener.accept(43);
    defer conn.close();

    try std.testing.expectEqual(@as(usize, 43), conn.id);
    try std.testing.expectEqualStrings("::1", conn.peerAddr());
}
