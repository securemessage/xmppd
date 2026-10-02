//! # xmppc Engine — ONE kqueue loop driving N client sessions
//!
//! Owns the kqueue, the session table, the cross-thread wake pipe, and the
//! connect/registration helpers. Session lifecycle and protocol handling
//! live in session.zig; parser/ stream state in parser.zig / stream.zig.

const std = @import("std");
const ssl = @import("ssl");

const Session = @import("session.zig").Session;

const Kevent = std.posix.Kevent;
const posix = std.posix;

fn kev(ident: usize, filter: i16, flags: u16, udata: usize) Kevent {
    return .{ .ident = ident, .filter = filter, .flags = flags, .fflags = 0, .data = 0, .udata = udata };
}

/// Synchronous hostname resolution (the one blocking call in the client).
fn resolveHost(host: []const u8) !std.c.sockaddr.in {
    var name_buf: [256]u8 = undefined;
    if (host.len >= name_buf.len) return error.NameTooLong;
    @memcpy(name_buf[0..host.len], host);
    name_buf[host.len] = 0;

    var hints: std.c.addrinfo = std.mem.zeroes(std.c.addrinfo);
    hints.family = posix.AF.INET;
    hints.socktype = posix.SOCK.STREAM;

    var result: ?*std.c.addrinfo = null;
    const rc = std.c.getaddrinfo(@ptrCast(&name_buf), null, &hints, &result);
    if (@intFromEnum(rc) != 0 or result == null) return error.ResolutionFailed;
    defer std.c.freeaddrinfo(result.?);

    const addr_in: *const std.c.sockaddr.in = @ptrCast(@alignCast(result.?.addr.?));
    return .{ .port = 0, .addr = addr_in.addr };
}

// ============================================================================
// Engine
// ============================================================================

pub const Engine = struct {
    kq: posix.fd_t,
    allocator: std.mem.Allocator,
    sessions: std.ArrayList(Session),
    tls_ctx: ?ssl.SslContext = null,
    thread: ?std.Thread = null,
    // Self-pipe for cross-thread wake-up (N-worker shutdown / stopSession
    // from a foreign thread). EVFILT_SIGNAL is unreliable across threads;
    // a real kqueue event on the pipe read-end is not.
    wake_pipe: [2]posix.fd_t = .{ -1, -1 },
    const WAKE_UDATA: usize = std.math.maxInt(usize);

    pub fn init(allocator: std.mem.Allocator) !Engine {
        const kq = posix.kqueue() catch return error.KqueueInit;
        return .{ .kq = kq, .allocator = allocator, .sessions = .{} };
    }

    pub fn deinit(self: *Engine) void {
        if (self.thread) |*t| {
            t.join();
            self.thread = null;
        }
        self.stopAll();
        self.sessions.deinit(self.allocator);
        self.sessions = .{};
        if (self.tls_ctx) |*c| c.deinit();
        if (self.wake_pipe[0] >= 0) posix.close(self.wake_pipe[0]);
        if (self.wake_pipe[1] >= 0) posix.close(self.wake_pipe[1]);
        posix.close(self.kq);
    }

    /// Wake the kqueue loop from any thread (no-op if the loop is not
    /// blocked, e.g. between run() iterations).
    pub fn requestWake(self: *Engine) void {
        if (self.wake_pipe[1] < 0) {
            self.wake_pipe = posix.pipe() catch return;
            // Non-blocking read end so the drain loop in loopOnce() never stalls.
            _ = std.c.fcntl(self.wake_pipe[0], std.c.F.SETFL, @as(c_int, @bitCast(std.c.O{ .NONBLOCK = true })));
            const ev = kev(@intCast(self.wake_pipe[0]), std.c.EVFILT.READ, std.c.EV.ADD, WAKE_UDATA);
            _ = posix.kevent(self.kq, &.{ev}, &.{}, null) catch return;
        }
        _ = posix.write(self.wake_pipe[1], &.{1}) catch {};
    }

    pub fn stopAll(self: *Engine) void {
        for (self.sessions.items) |*s| s.destroy(self.allocator);
        self.sessions.items.len = 0;
    }

    /// Install a client TLS context (DANE-first: PKIX verify disabled, so
    /// self-signed / DANE-validated certs both work).
    ///
    /// The shared initializers arm KTLS unconditionally (battle-tested server
    /// behavior), but a client must not offload when its peer might: two
    /// KTLS-armed endpoints desync across lo0/epair/bridge (FreeBSD PR
    /// 296498). Offload is therefore disabled here unless `ktls` is true —
    /// opt in only against non-KTLS peers or real-NIC paths (IFCAP_MEXTPG).
    pub fn useTls(self: *Engine, ktls: ?bool) !void {
        if (self.tls_ctx) |_| return;
        self.tls_ctx = ssl.SslContext.initClient() catch return error.TlsInit;
        if (!(ktls orelse false)) self.tls_ctx.?.disableKtls();
    }

    pub fn sessionCount(self: *const Engine) usize {
        return self.sessions.items.len;
    }
    /// Access a live session by its engine index (from startSession).
    /// Returns null once the session is dead/reaped.
    pub fn sessionAt(self: *Engine, idx: usize) ?*Session {
        if (idx >= self.sessions.items.len) return null;
        const s = &self.sessions.items[idx];
        if (!s.alive) return null;
        return s;
    }
    /// Mark a session dead and wake the loop to reap it. Safe from any thread:
    /// fail() is idempotent and reapDead() runs on the engine thread.
    pub fn stopSession(self: *Engine, idx: usize, reason: []const u8) void {
        if (idx < self.sessions.items.len) {
            self.sessions.items[idx].fail(self.allocator, reason);
        }
        self.requestWake();
    }

    /// Begin a client session toward host:port. `domain` is the stream's
    /// `to=` JID domain (RFC 6120 §4.2) — distinct from the TCP connect
    /// target `host` (e.g. host "127.0.0.1" but domain "localhost"). Returns
    /// the session index.
    pub fn startSession(self: *Engine, host: []const u8, port: u16, domain: []const u8, user: []const u8, password: []const u8, resource: []const u8, sm_resume_id: []const u8) !usize {
        var s = try Session.init(self.allocator);
        s.engine = self;
        s.host = host;
        s.domain = domain;
        s.user = user;
        s.password = password;
        s.resource = resource;
        s.fsm.resume_id = sm_resume_id;

        var addr = resolveHost(host) catch {
            s.destroy(self.allocator);
            return error.NameResolutionFailed;
        };
        addr.port = std.mem.nativeToBig(u16, port);

        const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0) catch {
            s.destroy(self.allocator);
            return error.SocketCreate;
        };
        posix.connect(fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) catch |err| {
            if (err != error.WouldBlock) {
                posix.close(fd);
                s.destroy(self.allocator);
                return error.ConnectFailed;
            }
        };
        return self.attachPrepared(&s, fd);
    }

    /// Attach a pre-connected fd — the test seam for driving a Session over
    /// socketpair(2) with a scripted fake server (no network, no certs for
    /// the plaintext cases). The fd must be non-blocking and connected (or a
    /// socketpair/stream fd); the session then runs the same post-connect
    /// path as startSession (stream open on first writability).
    pub fn attachFd(self: *Engine, fd: posix.fd_t, domain: []const u8, user: []const u8, password: []const u8, resource: []const u8, sm_resume_id: []const u8) !usize {
        var s = try Session.init(self.allocator);
        s.engine = self;
        s.host = "";
        s.domain = domain;
        s.user = user;
        s.password = password;
        s.resource = resource;
        s.fsm.resume_id = sm_resume_id;
        return self.attachPrepared(&s, fd);
    }

    fn attachPrepared(self: *Engine, s: *Session, fd: posix.fd_t) !usize {
        s.fd = fd;
        s.phase = .connecting;

        const idx = self.sessions.items.len;
        self.sessions.append(self.allocator, s.*) catch {
            posix.close(fd);
            s.destroy(self.allocator);
            return error.OutOfMemory;
        };
        self.sessions.items[idx].engine_index = idx;
        self.addRead(fd, idx);
        self.addWrite(fd, idx);
        return idx;
    }

    /// Run the kqueue loop on a dedicated thread.
    pub fn run(self: *Engine) !void {
        const t = std.Thread.spawn(.{}, Engine.runLoop, .{self}) catch return error.ThreadSpawn;
        self.thread = t;
    }

    /// Run the kqueue loop inline on the caller thread until all sessions die.
    pub fn runSync(self: *Engine) !void {
        while (self.sessions.items.len > 0) {
            self.loopOnce() catch {
                // kevent error — fail every session and stop rather than spin.
                for (self.sessions.items) |*s| s.fail(self.allocator, "kqueue-error");
                self.reapDead();
                break;
            };
            self.reapDead();
        }
    }

    fn runLoop(self: *Engine) void {
        while (self.sessions.items.len > 0) {
            self.loopOnce() catch break;
            self.reapDead();
        }
    }

    fn loopOnce(self: *Engine) !void {
        // Drain the self-pipe first: a wake is a "re-examine" request, not
        // data. The read end is non-blocking, so this terminates on EAGAIN.
        if (self.wake_pipe[0] >= 0) {
            var wbuf: [128]u8 = undefined;
            while (true) {
                _ = posix.read(self.wake_pipe[0], &wbuf) catch break;
            }
        }
        var evbuf: [64]Kevent = undefined;
        const n = posix.kevent(self.kq, &.{}, &evbuf, null) catch |err| {
            if (err == error.SystemResources or err == error.EventNotFound) return error.SystemResources;
            return error.SystemResources;
        };
        for (evbuf[0..n]) |ev| {
            const idx = ev.udata;
            if (idx >= self.sessions.items.len) continue;
            const s = &self.sessions.items[idx];
            if (!s.alive) continue;
            switch (ev.filter) {
                std.c.EVFILT.READ => s.onRead(self) catch s.fail(self.allocator, "read-error"),
                std.c.EVFILT.WRITE => s.onWritable(self) catch s.fail(self.allocator, "write-error"),
                else => {},
            }
            // EV_EOF lives in ev.flags (not fflags): the peer shut down the
            // read direction. Checked after dispatch so any last buffered
            // data is drained before the session is failed. sys/event.h
            // EV_EOF — not exposed as std.c.EV.EOF for FreeBSD in this zig
            // std; the value is stable ABI.
            if (ev.flags & 0x8000 != 0) s.fail(self.allocator, "peer-closed");
            if (ev.flags & std.c.EV.ERROR != 0) s.fail(self.allocator, "socket-error");
        }
    }

    /// Destroy + remove dead sessions (swap-with-last). Idempotent.
    fn reapDead(self: *Engine) void {
        var i: usize = 0;
        while (i < self.sessions.items.len) {
            if (self.sessions.items[i].alive) {
                i += 1;
                continue;
            }
            self.removeSession(i);
            // index i now holds the swapped-in session (or is past the end);
            // re-examine it.
        }
    }

    fn removeSession(self: *Engine, idx: usize) void {
        if (idx >= self.sessions.items.len) return;
        const n = self.sessions.items.len;
        const dead = &self.sessions.items[idx];
        if (dead.alive) return; // already removed / never marked dead
        dead.destroy(self.allocator);
        if (idx + 1 == n) {
            _ = self.sessions.pop();
            return;
        }
        self.sessions.items[idx] = self.sessions.items[n - 1];
        _ = self.sessions.pop();
        const moved = &self.sessions.items[idx];
        moved.engine_index = idx;
        if (moved.alive and moved.fd >= 0) {
            self.addRead(moved.fd, idx);
            if (moved.write_len > 0) self.addWrite(moved.fd, idx);
        }
    }

    // --- kqueue changelist helpers (single-event submit) ---

    pub fn addRead(self: *Engine, fd: posix.fd_t, idx: usize) void {
        self.submit(kev(@intCast(fd), std.c.EVFILT.READ, std.c.EV.ADD | std.c.EV.ENABLE, idx));
    }
    pub fn addWrite(self: *Engine, fd: posix.fd_t, idx: usize) void {
        self.submit(kev(@intCast(fd), std.c.EVFILT.WRITE, std.c.EV.ADD | std.c.EV.ENABLE, idx));
    }
    pub fn removeRead(self: *Engine, fd: posix.fd_t) void {
        self.submit(kev(@intCast(fd), std.c.EVFILT.READ, std.c.EV.DELETE, 0));
    }
    pub fn removeWrite(self: *Engine, fd: posix.fd_t) void {
        self.submit(kev(@intCast(fd), std.c.EVFILT.WRITE, std.c.EV.DELETE, 0));
    }
    // TODO(phase 2): stage changes in a changelist buffer and fold them into
    // the ONE kevent() wait call (project kqueue rule) instead of one
    // kevent() per registration. Fine at smoke scale; required before the
    // T32 load driver.
    fn submit(self: *Engine, ev: Kevent) void {
        var one = [_]Kevent{ev};
        _ = posix.kevent(self.kq, &one, &.{}, null) catch {};
    }
};
