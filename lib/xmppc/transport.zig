//! # xmppc Transport — one I/O result type over plain TCP or TLS (T-DFD903DC)
//!
//! Both variants deliver the same result: bytes, would-block, or closed.
//! EOF (TCP FIN) and TLS close_notify are `.closed` — never a bare 0 that
//! callers could mistake for would-block. TLS WANT_READ/WANT_WRITE fold into
//! `.would_block`; the engine keeps both filters registered, so no extra
//! re-arming is needed for a WANT_WRITE-on-read.
//!
//! The "identical pointer + length on retry" rule (OpenSSL/kTLS, guardrails
//! rule 6) is owned here: `write` records the outstanding length on TLS
//! WANT_*; while `hasPendingWrite()` is true the caller's write buffer must
//! not move (grow, rebase, compact). `writeCompleted` clears the mark once
//! the pending bytes are confirmed consumed.

const std = @import("std");
const posix = std.posix;
const ssl = @import("ssl");

pub const Result = union(enum) {
    data: usize,
    would_block,
    closed,
};

pub const Transport = struct {
    link: Link,
    /// Bytes of the currently pending TLS write retry (0 = none). The same
    /// buffer address must be retried with at least this length.
    tls_pending: usize = 0,

    pub const Kind = enum { plain, tls };

    pub const Link = union(Kind) {
        plain: posix.fd_t,
        tls: ssl.SslConn,
    };

    pub fn initPlain(sock: posix.fd_t) Transport {
        return .{ .link = .{ .plain = sock } };
    }

    pub fn kind(self: *const Transport) Kind {
        return self.link;
    }

    pub fn isTls(self: *const Transport) bool {
        return self.link == .tls;
    }

    /// The fd regardless of variant (kqueue registration target).
    pub fn fd(self: *const Transport) posix.fd_t {
        return switch (self.link) {
            .plain => |f| f,
            .tls => |*t| t.sockFd(),
        };
    }

    /// STARTTLS upgrade: swap the plain link for a client-mode TLS session.
    /// Call between the server's `<proceed/>` and the restart of the stream.
    pub fn upgradeToTls(self: *Transport, ctx: ssl.SslContext, hostname: ?[*:0]const u8) !void {
        const plain_fd = self.fd();
        const conn = ssl.SslConn.initClient(ctx, plain_fd, hostname) catch return error.TlsInit;
        self.link = .{ .tls = conn };
        self.tls_pending = 0;
    }

    /// Borrow the TLS connection handle (shutdown/flags on teardown).
    pub fn tlsConn(self: *Transport) ?*ssl.SslConn {
        switch (self.link) {
            .tls => |*t| return t,
            else => return null,
        }
    }

    /// While true, the caller's write buffer must not move — the same
    /// pointer will be retried when the socket drains.
    pub fn hasPendingWrite(self: *const Transport) bool {
        return self.tls_pending > 0;
    }

    /// Read into buf. EOF/TLS close_notify is .closed (not 0).
    pub fn read(self: *Transport, buf: []u8) !Result {
        switch (self.link) {
            .plain => |f| {
                const n = posix.recv(f, buf, 0) catch |err| switch (err) {
                    error.WouldBlock => return .would_block,
                    else => return err,
                };
                if (n == 0) return .closed;
                return .{ .data = n };
            },
            .tls => |*t| {
                const r = t.read(buf) catch |e| switch (e) {
                    ssl.SslError.ConnectionClosed => return .closed,
                    else => return error.TlsRead,
                };
                return switch (r) {
                    .ok => |n| .{ .data = n },
                    .want_read, .want_write => .would_block,
                };
            },
        }
    }

    /// Write as much as the transport takes right now (may be partial).
    /// TLS WANT_* marks the pending-retry state; the caller must keep the
    /// buffer address stable until writeCompleted.
    pub fn write(self: *Transport, data: []const u8) !Result {
        switch (self.link) {
            .plain => |f| {
                const n = posix.send(f, data, 0) catch |err| switch (err) {
                    error.WouldBlock => return .would_block,
                    else => return err,
                };
                return .{ .data = n };
            },
            .tls => |*t| {
                const r = t.write(data) catch return error.TlsWrite;
                return switch (r) {
                    .ok => |n| blk: {
                        if (n == data.len) self.tls_pending = 0;
                        break :blk .{ .data = n };
                    },
                    .want_read, .want_write => blk: {
                        self.tls_pending = data.len;
                        break :blk .would_block;
                    },
                };
            },
        }
    }

    /// `n` bytes of the pending write were consumed; release the pin when
    /// nothing remains outstanding.
    pub fn writeCompleted(self: *Transport, n: usize) void {
        if (n >= self.tls_pending) {
            self.tls_pending = 0;
        } else {
            self.tls_pending -= n;
        }
    }
};

// --- Tests ---

test "transport: plain round trip over socketpair" {
    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0, &fds) != 0)
        return error.Socketpair;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var a = Transport.initPlain(fds[0]);
    var b = Transport.initPlain(fds[1]);

    _ = try a.write("hello");
    var buf: [16]u8 = undefined;
    switch (try b.read(&buf)) {
        .data => |n| try std.testing.expectEqualStrings("hello", buf[0..n]),
        else => return error.ExpectedData,
    }
}

test "transport: peer close reads as .closed, never zero bytes" {
    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0, &fds) != 0)
        return error.Socketpair;

    var a = Transport.initPlain(fds[0]);
    posix.close(fds[1]);

    var buf: [16]u8 = undefined;
    defer posix.close(fds[0]);
    try std.testing.expectEqual(Result.closed, try a.read(&buf));
}

test "transport: empty socket reads as would_block" {
    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0, &fds) != 0)
        return error.Socketpair;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var a = Transport.initPlain(fds[0]);
    var buf: [16]u8 = undefined;
    try std.testing.expectEqual(Result.would_block, try a.read(&buf));
}

test "transport: write pin lifecycle" {
    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0, &fds) != 0)
        return error.Socketpair;
    defer posix.close(fds[0]);
    defer posix.close(fds[1]);

    var a = Transport.initPlain(fds[0]);
    try std.testing.expect(!a.hasPendingWrite());
    // The pin only lives on the TLS variant; on plain sockets write never
    // records it. Drive the bookkeeping directly.
    a.tls_pending = 10;
    a.writeCompleted(4);
    try std.testing.expect(a.hasPendingWrite());
    a.writeCompleted(6);
    try std.testing.expect(!a.hasPendingWrite());
}
