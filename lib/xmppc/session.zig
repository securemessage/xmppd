//! # xmppc Session — kqueue-driven client session engine
//!
//! Turns the pure `ClientStream` FSM + `SaslClient` into a real XMPP client:
//!
//!   TCP (non-blocking) → [STARTTLS] → SASL → bind → [session] → SM → active
//!
//! `Engine` owns ONE kqueue and drives ANY number of `Session`s on it (the
//! "N clients on one kqueue loop" requirement the T32 load driver needs).
//! Each `Session` is a value in `Engine.sessions`; its list index is the
//! kqueue `udata`. A dead session is swapped with the last live one and
//! destroyed; indices stay stable for a session's lifetime, and `removeSession`
//! is idempotent (guarded by `alive`).
//!
//! ## Constraints (task-brief-91e96a28)
//! * Own API boundary: imports only `std` + shared protocol modules (xml,
//!   xmpp, sasl, tls/ssl). Does NOT import src/.
//! * Event-driven only: kqueue, no thread per connection, no polling. The one
//!   blocking call is `getaddrinfo` in `startSession` (documented; the load
//!   driver replaces it with a non-blocking resolver in phase 2).
//!
//! ## Stream restarts (RFC 6120 §4.7)
//! The client opens a FRESH `<stream:stream>` after STARTTLS and after SASL
//! success. The server resets its XML reader on both, so the client does the
//! same the moment the FSM returns `.send_stream_open` in a restart context.
//! The `Reader` only emits `stream_open` at depth 1, which is exactly why the
//! reset is mandatory — without it the second `<stream:stream>` would parse at
//! depth 2 and be ignored.

const std = @import("std");
const xml = @import("xml");
const xmpp = @import("xmpp");
const sasl = @import("sasl");
const ssl = @import("ssl");
const stream = @import("stream.zig");
const saslmod = @import("sasl.zig");

const Jid = xmpp.Jid;
const Reader = xml.Reader;
const Kevent = std.posix.Kevent;
const posix = std.posix;

const READ_BUF_SIZE = 1 << 16;

fn kev(ident: usize, filter: i16, flags: u16, udata: usize) Kevent {
    return .{ .ident = ident, .filter = filter, .flags = flags, .fflags = 0, .data = 0, .udata = udata };
}

fn b64enc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const enc = std.base64.standard.Encoder;
    const buf = try allocator.alloc(u8, enc.calcSize(input.len));
    _ = enc.encode(buf, input);
    return buf;
}

fn b64dec(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const dec = std.base64.standard.Decoder;
    const len = try dec.calcSizeForSlice(input);
    const buf = try allocator.alloc(u8, len);
    try dec.decode(buf, input);
    return buf[0..len];
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
    pub fn useTls(self: *Engine) !void {
        if (self.tls_ctx) |_| return;
        self.tls_ctx = ssl.SslContext.initClient() catch return error.TlsInit;
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
        s.fd = fd;
        s.phase = .connecting;

        const idx = self.sessions.items.len;
        self.sessions.append(self.allocator, s) catch {
            posix.close(fd);
            s.destroy(self.allocator);
            return error.OutOfMemory;
        };
        s.engine_index = idx;
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
            // sys/event.h NOTE_EOF — not exposed as std.c.NOTE.EOF for FreeBSD
            // in this zig std; the value is stable ABI.
            if (ev.fflags & 0x8000 != 0) s.fail(self.allocator, "peer-closed");
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

    fn addRead(self: *Engine, fd: posix.fd_t, idx: usize) void {
        self.submit(kev(@intCast(fd), std.c.EVFILT.READ, std.c.EV.ADD | std.c.EV.ENABLE, idx));
    }
    fn addWrite(self: *Engine, fd: posix.fd_t, idx: usize) void {
        self.submit(kev(@intCast(fd), std.c.EVFILT.WRITE, std.c.EV.ADD | std.c.EV.ENABLE, idx));
    }
    fn removeRead(self: *Engine, fd: posix.fd_t) void {
        self.submit(kev(@intCast(fd), std.c.EVFILT.READ, std.c.EV.DELETE, 0));
    }
    fn removeWrite(self: *Engine, fd: posix.fd_t) void {
        self.submit(kev(@intCast(fd), std.c.EVFILT.WRITE, std.c.EV.DELETE, 0));
    }
    fn submit(self: *Engine, ev: Kevent) void {
        var one = [_]Kevent{ev};
        _ = posix.kevent(self.kq, &one, &.{}, null) catch {};
    }
};

// ============================================================================
// Session
// ============================================================================

pub const Session = struct {
    const Phase = enum {
        connecting,
        established,
        dead,
    };

    engine: *Engine,
    engine_index: usize = 0,
    alive: bool = true,
    phase: Phase = .connecting,
    failed: bool = false,

    fd: posix.fd_t = -1,
    tls: ?ssl.SslConn = null,
    tls_handshake: bool = false,

    host: []const u8 = "",
    domain: []const u8 = "",
    user: []const u8 = "",
    password: []const u8 = "",
    resource: []const u8 = "",

    fsm: stream.ClientStream = .{},
    /// Heap pointers: the FSM mutates these in place; copying them (a
    /// `|x|` / `orelse` on a value) would silently drop state.
    sasl: ?*saslmod.SaslClient = null,
    reader: Reader,
    parser: ?*Parser = null,

    read_buf: []u8,
    read_len: usize = 0,
    write_buf: []u8,
    write_len: usize = 0,
    write_registered: bool = false,

    /// Bound full JID (set when the bind result is parsed).
    bound_jid: ?Jid = null,
    /// SM session id (set when `<enabled id='…'>` / `<resumed previd='…'>`).
    sm_id: []const u8 = "",
    sm_enabled: bool = false,
    sm_resumed: bool = false,

    /// Fired on the engine thread once the stream is active.
    on_established: ?*const fn (engine: *Engine, index: usize, session: *Session) void = null,
    /// Fired on the engine thread when the stream dies.
    on_closed: ?*const fn (engine: *Engine, index: usize, session: *Session, reason: []const u8) void = null,

    pub fn init(allocator: std.mem.Allocator) !Session {
        const parser = try allocator.create(Parser);
        parser.* = Parser.init(allocator);
        return .{
            .engine = undefined, // set by Engine.startSession
            .reader = Reader.init(allocator),
            .parser = parser,
            .read_buf = try allocator.alloc(u8, READ_BUF_SIZE),
            .write_buf = try allocator.alloc(u8, READ_BUF_SIZE),
        };
    }

    pub fn destroy(self: *Session, allocator: std.mem.Allocator) void {
        if (!self.alive) return;
        self.alive = false;
        self.reader.deinit();
        if (self.parser) |pr| {
            pr.deinit(allocator);
            allocator.destroy(pr);
        }
        self.parser = null;
        if (self.sasl) |sc| {
            sc.deinit();
            allocator.destroy(sc);
        }
        if (self.tls) |*tc| {
            tc.shutdown();
            tc.deinit();
        }
        if (self.fd >= 0) posix.close(self.fd);
        allocator.free(self.read_buf);
        allocator.free(self.write_buf);
    }

    pub fn fail(self: *Session, allocator: std.mem.Allocator, reason: []const u8) void {
        _ = allocator;
        if (self.failed) return;
        self.failed = true;
        self.alive = false;
        self.phase = .dead;
        if (self.on_closed) |cb| cb(self.engine, self.engine_index, self, reason);
        // The engine's reapDead() destroys + removes this slot.
    }

    /// Install the established/closed callbacks. Must be called on the engine
    /// thread (or before runSync) after startSession, before the stream
    /// completes; the engine hands out sessions by index.
    pub fn setCallbacks(self: *Session, est: ?*const fn (*Engine, usize, *Session) void, closed: ?*const fn (*Engine, usize, *Session, []const u8) void) void {
        self.on_established = est;
        self.on_closed = closed;
    }

    pub fn isEstablished(self: *const Session) bool {
        return self.phase == .established;
    }
    pub fn isDead(self: *const Session) bool {
        return !self.alive or self.failed;
    }
    /// Bound full JID, or null until the bind result arrives.
    pub fn boundJid(self: *const Session) ?Jid {
        return self.bound_jid;
    }
    /// SM session id (empty until <enabled id='…'/> or <resumed/>).
    pub fn smId(self: *const Session) []const u8 {
        return self.sm_id;
    }
    pub fn smEnabled(self: *const Session) bool {
        return self.sm_enabled;
    }
    pub fn smResumed(self: *const Session) bool {
        return self.sm_resumed;
    }

    // ------------------------------------------------------------------
    // Read path
    // ------------------------------------------------------------------

    fn onRead(self: *Session, engine: *Engine) !void {
        // TLS handshake in flight: drive it, re-arm, and stop.
        if (self.tls_handshake) {
            var tc = self.tls orelse return self.fail(engine.allocator, "tls-missing");
            const res = tc.doHandshake() catch {
                self.fail(engine.allocator, "tls-handshake-failed");
                return;
            };
            switch (res) {
                .complete => {
                    self.tls_handshake = false;
                    engine.removeWrite(self.fd);
                    self.write_registered = false;
                    // Reset the reader, then tell the FSM TLS is up; the FSM
                    // action re-sends <stream:stream> (RFC 6120 §4.6).
                    self.reader.reset();
                    self.read_len = 0;
                    if (self.parser) |pr| pr.reset();
                    self.handleAction(engine, self.fsm.feed(.tls_established));
                    return;
                },
                .want_read => {
                    // Read interest is already registered; the next read event
                    // re-drives the handshake.
                    return;
                },
                .want_write => {
                    if (!self.write_registered) {
                        engine.addWrite(self.fd, self.engine_index);
                        self.write_registered = true;
                    }
                    return;
                },
            }
        }

        while (true) {
            if (self.read_len >= self.read_buf.len) {
                const nb = engine.allocator.realloc(self.read_buf, self.read_buf.len * 2) catch return error.OutOfMemory;
                self.read_buf = nb;
            }
            const space = self.read_buf.len - self.read_len;
            const n = self.recv(self.read_buf[self.read_len..]) catch |err| {
                if (err == error.WouldBlock) break;
                if (err == error.ConnectionClosed) {
                    self.fail(engine.allocator, "peer-closed");
                    return;
                }
                self.fail(engine.allocator, "recv-error");
                return;
            };
            if (n == 0) break;
            self.read_len += n;
            // Drain whatever is immediately available, then parse.
            if (space - n == 0) continue; // buffer full; loop grows it
        }
        // Parse even when got == 0: the parser may still hold a pending event
        // (e.g. an `<enabled>` closed) that hasn't been fed to the FSM, and
        // OpenSSL may have decrypted bytes buffered across a WANT_READ boundary.
        try self.parseAll(engine);
    }

    fn recv(self: *Session, buf: []u8) !usize {
        if (self.tls) |*tc| {
            const r = tc.read(buf) catch |e| switch (e) {
                ssl.SslError.ConnectionClosed => return 0,
                else => return error.TlsRead,
            };
            return switch (r) {
                .ok => |n| n,
                .want_read, .want_write => return 0,
            };
        }
        return posix.recv(self.fd, buf, 0) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => err,
        };
    }

    /// Feed the reader, map events to ServerEvents, drive the FSM, execute
    /// actions. Compacts the read buffer by the consumed boundary `pos`.
    fn parseAll(self: *Session, engine: *Engine) !void {
        const allocator = engine.allocator;
        const parser = self.parser orelse return;
        var pos: usize = 0;
        while (true) {
            const ev = self.reader.next(self.read_buf[0..self.read_len], &pos) catch {
                self.fail(allocator, "xml-parse-error");
                return;
            };
            if (ev == null) break;
            if (!parser.onReaderEvent(ev.?)) {
                self.fail(allocator, "protocol-error");
                return;
            }
            if (parser.pending) |sev| {
                parser.pending = null;
                self.handleServerEvent(engine, sev);
                if (self.failed) return;
            }
        }
        if (pos > 0) {
            std.mem.copyForwards(u8, self.read_buf, self.read_buf[pos..self.read_len]);
            self.read_len -= pos;
        }
    }

    fn handleServerEvent(self: *Session, engine: *Engine, ev: stream.ServerEvent) void {
        if (ev == .sasl_success) {
            if (self.sasl) |sc| {
                sc.verifyServerFinal(ev.sasl_success) catch {
                    self.fail(engine.allocator, "sasl-verify-failed");
                    return;
                };
            }
        }
        const action = self.fsm.feed(ev);
        self.handleAction(engine, action);
    }

    // ------------------------------------------------------------------
    // Write path
    // ------------------------------------------------------------------

    fn onWritable(self: *Session, engine: *Engine) !void {
        if (self.tls_handshake) {
            // Drive the handshake from write-ready too (SSL_ERROR_WANT_WRITE).
            _ = self.onRead(engine) catch return;
            return;
        }
        if (self.phase == .connecting) {
            var err_opt: c_int = 0;
            var optlen: posix.socklen_t = @sizeOf(c_int);
            const rc = std.c.getsockopt(self.fd, posix.SOL.SOCKET, posix.SO.ERROR, std.mem.asBytes(&err_opt), &optlen);
            if (rc != 0 or err_opt != 0) {
                self.fail(engine.allocator, "connect-failed");
                return;
            }
            // TCP up — open the stream. The connect-writable is consumed; write
            // interest is re-armed by flushWrites only if bytes are pending.
            const action = self.fsm.openStream();
            self.handleAction(engine, action);
            engine.removeWrite(self.fd);
            self.write_registered = self.write_len > 0;
            return;
        }
        self.flushWrites(engine);
    }

    fn queue(self: *Session, data: []const u8) !void {
        if (self.write_len + data.len > self.write_buf.len) {
            var need = self.write_len + data.len;
            while (need > self.write_buf.len) need *= 2;
            const nb = self.engine.allocator.realloc(self.write_buf, need) catch return error.OutOfMemory;
            self.write_buf = nb;
        }
        std.mem.copyForwards(u8, self.write_buf[self.write_len..], data);
        self.write_len += data.len;
    }

    fn queuef(self: *Session, comptime fmt: []const u8, args: anytype) !void {
        var tmp: [1024]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&tmp);
        std.fmt.format(fbs.writer(), fmt, args) catch return error.FormatTooLong;
        return self.queue(fbs.getWritten());
    }

    fn flushWrites(self: *Session, engine: *Engine) void {
        while (self.write_len > 0) {
            const n = self.sendSome() catch |err| {
                if (err == error.WouldBlock or err == error.TlsWrite or err == error.TlsRead) return;
                self.fail(self.engine.allocator, "write-error");
                return;
            };
            if (n == 0) return;
            std.mem.copyForwards(u8, self.write_buf, self.write_buf[n..]);
            self.write_len -= n;
        }
        if (self.write_registered) {
            engine.removeWrite(self.fd);
            self.write_registered = false;
        }
    }

    fn sendSome(self: *Session) !usize {
        if (self.tls) |*tc| {
            const r = tc.write(self.write_buf[0..self.write_len]) catch |e| switch (e) {
                ssl.SslError.ConnectionClosed => return 0,
                else => return error.TlsWrite,
            };
            return switch (r) {
                .ok => |n| n,
                .want_read, .want_write => return 0,
            };
        }
        const n = posix.send(self.fd, self.write_buf[0..self.write_len], 0) catch |err| switch (err) {
            error.WouldBlock => return 0,
            else => return err,
        };
        return n;
    }

    // ------------------------------------------------------------------
    // Action execution — turn FSM actions into I/O
    // ------------------------------------------------------------------

    fn handleAction(self: *Session, engine: *Engine, action: stream.ClientAction) void {
        const allocator = engine.allocator;
        switch (action) {
            .none => {},
            .send_stream_open => {
                // Restart after TLS or auth: reset parser + reader state (the
                // server resets its own reader on both).
                if (self.tls != null or self.fsm.state == .awaiting_stream_header_auth) {
                    self.reader.reset();
                    if (self.parser) |pr| pr.reset();
                }
                self.queuef("<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='{s}' version='1.0'>", .{self.domain}) catch {
                    self.fail(allocator, "queue-error");
                    return;
                };
                self.writeAfter(engine);
            },
            .send_starttls => {
                self.queue("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>") catch {
                    self.fail(allocator, "queue-error");
                    return;
                };
                self.writeAfter(engine);
            },
            .send_sasl_auth => |mech| {
                const sc = allocator.create(saslmod.SaslClient) catch {
                    self.fail(allocator, "sasl-init-failed");
                    return;
                };
                // SASL authcid is the bare localpart (RFC 6120 §6.2: the server
                // prepends its own domain); the full JID is only used after bind.
                const at = std.mem.indexOfScalar(u8, self.user, '@');
                const authcid = if (at) |i| self.user[0..i] else self.user;
                sc.* = saslmod.SaslClient.init(allocator, mech, authcid, self.password) catch {
                    allocator.destroy(sc);
                    self.fail(allocator, "sasl-init-failed");
                    return;
                };
                self.sasl = sc;
                const raw = sc.initial() catch {
                    self.fail(allocator, "sasl-init-failed");
                    return;
                };
                const b64 = b64enc(allocator, raw) catch {
                    self.fail(allocator, "b64-error");
                    return;
                };
                defer allocator.free(b64);
                self.queuef("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='{s}'>{s}</auth>", .{ mech, b64 }) catch {
                    self.fail(allocator, "queue-error");
                    return;
                };
                self.writeAfter(engine);
            },
            .send_sasl_response => {
                const sc = self.sasl orelse return self.fail(allocator, "sasl-not-active");
                const raw = self.parser.?.sasl_challenge_raw orelse return self.fail(allocator, "sasl-no-challenge");
                const next = sc.handleChallenge(raw) catch {
                    self.fail(allocator, "sasl-challenge-error");
                    return;
                } orelse return; // client-final already sent; await <success>
                const b64 = b64enc(allocator, next) catch {
                    self.fail(allocator, "b64-error");
                    return;
                };
                defer allocator.free(b64);
                self.queuef("<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{s}</response>", .{b64}) catch {
                    self.fail(allocator, "queue-error");
                    return;
                };
                self.writeAfter(engine);
            },
            .send_bind => {
                self.queuef("<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>{s}</resource></bind></iq>", .{self.resource}) catch {
                    self.fail(allocator, "queue-error");
                    return;
                };
                self.writeAfter(engine);
            },
            .send_session => {
                self.queue("<iq type='set' id='sess1'><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>") catch {
                    self.fail(allocator, "queue-error");
                    return;
                };
                self.writeAfter(engine);
            },
            .send_sm_enable => {
                // resume='true' so the server returns an SM id for reconnect.
                self.queue("<enable xmlns='urn:xmpp:sm:3' resume='true'/>") catch {
                    self.fail(allocator, "queue-error");
                    return;
                };
                self.writeAfter(engine);
            },
            .send_sm_resume => {
                self.queuef("<resume xmlns='urn:xmpp:sm:3' previd='{s}' h='0'/>", .{self.fsm.resume_id}) catch {
                    self.fail(allocator, "queue-error");
                    return;
                };
                self.writeAfter(engine);
            },
            .begin_tls => {
                const ctx = engine.tls_ctx orelse return self.fail(allocator, "tls-not-configured");
                const tc = ssl.SslConn.initClient(ctx, self.fd, null) catch return self.fail(allocator, "tls-init-failed");
                self.tls = tc;
                self.tls_handshake = true;
                _ = self.onRead(engine) catch return;
            },
            .established => {
                self.phase = .established;
                self.sm_enabled = self.fsm.sm_enabled;
                self.sm_resumed = self.fsm.sm_resumed;
                self.sm_id = self.fsm.sm_id;
                self.bound_jid = self.fsm.bound_jid;
                if (self.on_established) |cb| cb(engine, self.engine_index, self);
            },
            .close => {
                self.fail(allocator, "stream-closed");
            },
        }
    }

    /// After queueing bytes: flush now, and re-arm write interest if pending.
    fn writeAfter(self: *Session, engine: *Engine) void {
        self.flushWrites(engine);
        if (self.write_len > 0 and !self.write_registered) {
            engine.addWrite(self.fd, self.engine_index);
            self.write_registered = true;
        }
    }
};

// ============================================================================
// Parser — protocol state machine over Reader events
// ============================================================================

const Parser = struct {
    allocator: std.mem.Allocator,

    // Features block
    in_features: bool = false,
    feats: stream.Features = .{},
    mech_names: std.ArrayListUnmanaged([]const u8) = .{},
    in_mechanism: bool = false,

    // SASL stanza payloads (base64 text)
    sasl_kind: enum { none, auth, challenge, success, failure } = .none,
    sasl_text: std.ArrayListUnmanaged(u8) = .{},
    sasl_cond: []const u8 = "",
    sasl_challenge_raw: ?[]const u8 = null,
    sasl_success_raw: ?[]const u8 = null,

    // IQ stanza (bind/session result)
    in_iq: bool = false,
    iq_type: []const u8 = "",
    iq_id: []const u8 = "",
    iq_is_bind: bool = false,
    iq_is_session: bool = false,
    iq_is_error: bool = false,
    in_jid: bool = false,
    jid_text: std.ArrayListUnmanaged(u8) = .{},

    // SM bare stanzas
    sm_kind: enum { none, enabled, resumed, failed } = .none,
    sm_id: []const u8 = "",
    sm_failed_cond: []const u8 = "",

    // Stream error
    in_stream_error: bool = false,
    stream_err_cond: []const u8 = "",

    /// The next ServerEvent to feed the FSM (one at a time).
    pending: ?stream.ServerEvent = null,

    pub fn init(allocator: std.mem.Allocator) Parser {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Parser, allocator: std.mem.Allocator) void {
        if (self.sasl_challenge_raw) |raw| allocator.free(raw);
        if (self.sasl_success_raw) |raw| allocator.free(raw);
        for (self.mech_names.items) |name| allocator.free(name);
        self.mech_names.deinit(self.allocator);
        self.sasl_text.deinit(self.allocator);
        self.jid_text.deinit(self.allocator);
    }

    pub fn reset(self: *Parser) void {
        if (self.sasl_challenge_raw) |raw| self.allocator.free(raw);
        if (self.sasl_success_raw) |raw| self.allocator.free(raw);
        self.in_features = false;
        self.feats = .{};
        self.mech_names.clearRetainingCapacity();
        self.in_mechanism = false;
        self.sasl_kind = .none;
        self.sasl_text.clearRetainingCapacity();
        self.sasl_cond = "";
        self.sasl_challenge_raw = null;
        self.sasl_success_raw = null;
        self.pending = null;
        self.in_iq = false;
        self.iq_type = "";
        self.iq_id = "";
        self.iq_is_bind = false;
        self.iq_is_session = false;
        self.iq_is_error = false;
        self.in_jid = false;
        self.jid_text.clearRetainingCapacity();
        self.sm_kind = .none;
        self.sm_id = "";
        self.sm_failed_cond = "";
        self.in_stream_error = false;
        self.stream_err_cond = "";
    }

    pub fn onReaderEvent(self: *Parser, ev: xml.Event) bool {
        switch (ev) {
            .xml_declaration => return true,
            .stream_open => |el| {
                var hdr = stream.StreamHeader{};
                for (el.attributes) |a| {
                    if (std.mem.eql(u8, a.local_name, "id")) {
                        hdr.id = a.value;
                    } else if (std.mem.eql(u8, a.local_name, "to")) {
                        hdr.to = a.value;
                    } else if (std.mem.eql(u8, a.local_name, "from")) {
                        hdr.from = a.value;
                    } else if (std.mem.eql(u8, a.local_name, "version")) {
                        hdr.version = a.value;
                    }
                }
                self.reset();
                self.pending = .{ .stream_header = hdr };
                return true;
            },
            .stream_close => {
                self.pending = .stream_closed;
                return true;
            },
            .element_start => |el| return self.onElementStart(el),
            .element_end => |name| return self.onElementEnd(name),
            .text => |t| return self.onText(t),
        }
    }

    fn onElementStart(self: *Parser, el: xml.Element) bool {
        const ns = el.namespace_uri;
        const name = el.local_name;
        const closed = el.self_closing;

        // --- Features block (children of <stream:features>) ---
        // Checked BEFORE the protocol-stanza blocks below, because
        // <starttls/>, <mechanisms/>, <mechanism/> and <sm/> share their
        // namespaces with the stanzas they advertise; while inside the
        // features block they are feature declarations, not stanzas.
        if (self.in_features) {
            if (std.mem.eql(u8, name, "starttls") and std.mem.eql(u8, ns, xml.ns.tls)) {
                self.feats.starttls = true;
                return true;
            }
            if (std.mem.eql(u8, name, "required") and std.mem.eql(u8, ns, xml.ns.tls)) {
                self.feats.starttls_required = true;
                return true;
            }
            if (std.mem.eql(u8, name, "mechanisms") and std.mem.eql(u8, ns, xml.ns.sasl)) {
                // Container; <mechanism> children are collected below.
                return true;
            }
            if (std.mem.eql(u8, name, "mechanism") and std.mem.eql(u8, ns, xml.ns.sasl)) {
                self.in_mechanism = true;
                self.sasl_text.clearRetainingCapacity();
                return true;
            }
            if (std.mem.eql(u8, name, "bind") and std.mem.eql(u8, ns, xml.ns.bind)) {
                self.feats.bind = true;
                return true;
            }
            if (std.mem.eql(u8, name, "session") and std.mem.eql(u8, ns, xml.ns.session)) {
                self.feats.session = true;
                return true;
            }
            if (std.mem.eql(u8, name, "optional")) {
                self.feats.session_optional = true;
                return true;
            }
            if (std.mem.eql(u8, name, "sm") and std.mem.eql(u8, ns, xml.ns.sm)) {
                self.feats.stream_mgmt = true;
                return true;
            }
            // Unknown feature child (e.g. <c/> for MUC user): ignored.
            return true;
        }

        // --- Features opener ---
        if (std.mem.eql(u8, name, "features") and std.mem.eql(u8, ns, xml.ns.streams)) {
            self.in_features = true;
            self.mech_names.clearRetainingCapacity();
            self.feats = .{};
            return true;
        }

        // --- Stream Management (XEP-0198): bare stanzas, no IQ. ---
        // The reader emits only element_start (self_closing=true) for the
        // self-closing forms, so the closed cases are settled here; the
        // non-self-closing forms are settled in onElementEnd.
        if (std.mem.eql(u8, ns, xml.ns.sm)) {
            if (std.mem.eql(u8, name, "enabled")) {
                for (el.attributes) |a| {
                    if (std.mem.eql(u8, a.local_name, "id")) self.sm_id = a.value;
                }
                self.sm_kind = .enabled;
                if (closed) {
                    self.pending = .{ .sm_result = .{ .enabled = self.sm_id } };
                    self.sm_id = "";
                    self.sm_kind = .none;
                }
                return true;
            }
            if (std.mem.eql(u8, name, "resumed")) {
                for (el.attributes) |a| {
                    if (std.mem.eql(u8, a.local_name, "previd")) self.sm_id = a.value;
                }
                self.sm_kind = .resumed;
                if (closed) {
                    self.pending = .{ .sm_result = .{ .resumed = self.sm_id } };
                    self.sm_id = "";
                    self.sm_kind = .none;
                }
                return true;
            }
            if (std.mem.eql(u8, name, "failed")) {
                self.sm_failed_cond = "";
                self.sm_kind = .failed;
                if (closed) {
                    self.pending = .{ .sm_result = .{ .failed = self.sm_failed_cond } };
                    self.sm_failed_cond = "";
                    self.sm_kind = .none;
                }
                return true;
            }
            // A self-closing condition child of <failed> (e.g. <item-not-found/>).
            if (self.sm_kind == .failed and closed) {
                self.sm_failed_cond = name;
                return true;
            }
            return true;
        }

        // --- SASL stanza (accumulate base64 payload) ---
        if (self.sasl_kind != .none) {
            if (self.sasl_kind == .failure and std.mem.eql(u8, ns, xml.ns.sasl)) {
                self.sasl_cond = name;
            }
            return true;
        }

        // --- IQ stanza opener ---
        if (std.mem.eql(u8, name, "iq") and std.mem.eql(u8, ns, xml.ns.client)) {
            self.in_iq = true;
            self.iq_is_bind = false;
            self.iq_is_session = false;
            self.iq_is_error = false;
            self.in_jid = false;
            for (el.attributes) |a| {
                if (std.mem.eql(u8, a.local_name, "type")) self.iq_type = a.value;
                if (std.mem.eql(u8, a.local_name, "id")) self.iq_id = a.value;
            }
            return true;
        }

        // --- IQ children ---
        if (self.in_iq) {
            if (std.mem.eql(u8, name, "bind") and std.mem.eql(u8, ns, xml.ns.bind)) {
                self.iq_is_bind = true;
            } else if (std.mem.eql(u8, name, "session") and std.mem.eql(u8, ns, xml.ns.session)) {
                self.iq_is_session = true;
            } else if (std.mem.eql(u8, name, "error") and std.mem.eql(u8, ns, xml.ns.stanzas)) {
                self.iq_is_error = true;
            } else if (std.mem.eql(u8, name, "jid")) {
                self.in_jid = true;
                self.jid_text.clearRetainingCapacity();
            }
            return true;
        }

        // --- Stream error ---
        if (std.mem.eql(u8, name, "error") and std.mem.eql(u8, ns, xml.ns.streams)) {
            self.in_stream_error = true;
            self.stream_err_cond = "";
            return true;
        }
        if (self.in_stream_error) {
            self.stream_err_cond = name;
            self.pending = .{ .stream_error = .{ .condition = stream.StreamError.Condition.fromString(name), .raw = name } };
            self.in_stream_error = false;
            return true;
        }

        // --- SASL stanza openers ---
        if (std.mem.eql(u8, ns, xml.ns.sasl)) {
            self.sasl_text.clearRetainingCapacity();
            self.sasl_cond = "";
            if (std.mem.eql(u8, name, "auth")) {
                self.sasl_kind = .auth;
            } else if (std.mem.eql(u8, name, "challenge")) {
                self.sasl_kind = .challenge;
            } else if (std.mem.eql(u8, name, "success")) {
                self.sasl_kind = .success;
            } else if (std.mem.eql(u8, name, "failure")) {
                self.sasl_kind = .failure;
            }
            return true;
        }

        // --- STARTTLS ---
        if (std.mem.eql(u8, ns, xml.ns.tls)) {
            if (std.mem.eql(u8, name, "proceed")) {
                self.pending = .starttls_proceed;
            } else if (std.mem.eql(u8, name, "failure")) {
                self.pending = .starttls_failure;
            }
            return true;
        }

        return true;
    }

    /// The close token's `name` may carry a prefix (`stream:features`); reduce
    /// to the local part for comparison.
    fn localOf(name: []const u8) []const u8 {
        if (std.mem.lastIndexOfScalar(u8, name, ':')) |i| return name[i + 1 ..];
        return name;
    }

    fn onElementEnd(self: *Parser, name: []const u8) bool {
        const local = localOf(name);
        // SASL stanza closes
        switch (self.sasl_kind) {
            .none => {},
            .auth => self.sasl_kind = .none,
            .challenge => {
                const b64 = std.mem.trim(u8, self.sasl_text.items, " \t\r\n");
                const raw = b64dec(self.allocator, b64) catch return false;
                if (self.sasl_challenge_raw) |old| self.allocator.free(old);
                self.sasl_challenge_raw = raw;
                self.pending = .{ .sasl_challenge = raw };
                self.sasl_kind = .none;
            },
            .success => {
                // base64 server-final; the Session verifies via SaslClient.
                const b64 = std.mem.trim(u8, self.sasl_text.items, " \t\r\n");
                const raw = b64dec(self.allocator, b64) catch return false;
                if (self.sasl_success_raw) |old| self.allocator.free(old);
                self.sasl_success_raw = raw;
                self.pending = .{ .sasl_success = raw };
                self.sasl_kind = .none;
            },
            .failure => {
                const cond = self.sasl_cond;
                self.sasl_cond = "";
                self.pending = .{ .sasl_failure = .{ .payload = "", .condition = cond } };
                self.sasl_kind = .none;
            },
        }

        // Mechanism name close (features block)
        if (self.in_mechanism and std.mem.eql(u8, local, "mechanism")) {
            const mtext = std.mem.trim(u8, self.sasl_text.items, " \t\r\n");
            const dup = self.allocator.dupe(u8, mtext) catch return false;
            self.mech_names.append(self.allocator, dup) catch return false;
            self.in_mechanism = false;
            return true;
        }

        // IQ stanza close
        if (self.in_iq) {
            if (std.mem.eql(u8, local, "iq")) {
                self.in_iq = false;
                if (std.mem.eql(u8, self.iq_type, "result")) {
                    var res = stream.IqResult{ .id = self.iq_id };
                    res.is_error = self.iq_is_error;
                    if (self.iq_is_bind and !self.iq_is_error) {
                        const jt = std.mem.trim(u8, self.jid_text.items, " \t\r\n");
                        res.bound_jid = Jid.parse(jt) catch null;
                    }
                    self.pending = .{ .iq_result = res };
                }
                self.iq_is_bind = false;
                self.iq_is_session = false;
                self.iq_is_error = false;
                self.in_jid = false;
                self.jid_text.clearRetainingCapacity();
            }
            return true;
        }

        // SM stanza closes
        switch (self.sm_kind) {
            .none => {},
            .enabled => {
                if (std.mem.eql(u8, local, "enabled")) {
                    self.pending = .{ .sm_result = .{ .enabled = self.sm_id } };
                    self.sm_id = "";
                    self.sm_kind = .none;
                }
            },
            .resumed => {
                if (std.mem.eql(u8, local, "resumed")) {
                    self.pending = .{ .sm_result = .{ .resumed = self.sm_id } };
                    self.sm_id = "";
                    self.sm_kind = .none;
                }
            },
            .failed => {
                if (std.mem.eql(u8, local, "failed")) {
                    self.pending = .{ .sm_result = .{ .failed = self.sm_failed_cond } };
                    self.sm_failed_cond = "";
                    self.sm_kind = .none;
                }
            },
        }

        // Features block close
        if (self.in_features and std.mem.eql(u8, local, "features")) {
            self.emitFeatures();
            return true;
        }
        return true;
    }

    fn onText(self: *Parser, t: []const u8) bool {
        if (self.in_jid) {
            self.jid_text.appendSlice(self.allocator, t) catch return false;
            return true;
        }
        if (self.in_mechanism) {
            self.sasl_text.appendSlice(self.allocator, t) catch return false;
            return true;
        }
        if (self.sasl_kind != .none) {
            self.sasl_text.appendSlice(self.allocator, t) catch return false;
            return true;
        }
        return true;
    }

    fn emitFeatures(self: *Parser) void {
        if (!self.in_features) return;
        self.in_features = false;
        self.in_mechanism = false;
        var f = self.feats;
        f.mechanisms = self.mech_names.items;
        self.feats = .{};
        self.pending = .{ .features = f };
    }

};

// ============================================================================
// Tests (unit; end-to-end lives in the smoke client + xmppd rig)
// ============================================================================
//
// These drive the real xml.Reader through the same parse loop the Session uses,
// so they exercise the actual event sequence (stream_open, element_start, text,
// element_end) rather than hand-constructed Elements.

test "parser: pre-TLS features → starttls" {
    const allocator = std.testing.allocator;
    const input =
        "<?xml version='1.0'?>" ++
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s1' from='localhost' version='1.0'>" ++
        "<stream:features>" ++
        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>" ++
        "</stream:features>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var got_header = false;
    var got_feats: ?stream.Features = null;
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch unreachable;
        if (ev == null) break;
        if (!parser.onReaderEvent(ev.?)) unreachable;
        if (parser.pending) |sev| {
            parser.pending = null;
            switch (sev) {
                .stream_header => got_header = true,
                .features => |f| got_feats = f,
                else => {},
            }
        }
    }
    try std.testing.expect(got_header);
    try std.testing.expect(got_feats != null);
    try std.testing.expect(got_feats.?.starttls);
    try std.testing.expect(got_feats.?.starttls_required);
    try std.testing.expect(!got_feats.?.bind);
}

test "parser: post-auth features (bind+session-optional+sm)" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s2' from='localhost'>" ++
        "<stream:features>" ++
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>" ++
        "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'><optional/></session>" ++
        "<sm xmlns='urn:xmpp:sm:3'/>" ++
        "</stream:features>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var got_feats: ?stream.Features = null;
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch unreachable;
        if (ev == null) break;
        if (!parser.onReaderEvent(ev.?)) unreachable;
        if (parser.pending) |sev| {
            parser.pending = null;
            if (sev == .features) got_feats = sev.features;
        }
    }
    try std.testing.expect(got_feats != null);
    try std.testing.expect(got_feats.?.bind);
    try std.testing.expect(got_feats.?.session);
    try std.testing.expect(got_feats.?.session_optional);
    try std.testing.expect(got_feats.?.stream_mgmt);
    try std.testing.expect(!got_feats.?.starttls);
}

test "parser: mechanisms list accumulates" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s3' from='localhost'>" ++
        "<stream:features>" ++
        "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" ++
        "<mechanism>SCRAM-SHA-256</mechanism>" ++
        "<mechanism>PLAIN</mechanism>" ++
        "</mechanisms>" ++
        "</stream:features>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var got_feats: ?stream.Features = null;
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch unreachable;
        if (ev == null) break;
        if (!parser.onReaderEvent(ev.?)) unreachable;
        if (parser.pending) |sev| {
            parser.pending = null;
            if (sev == .features) got_feats = sev.features;
        }
    }
    try std.testing.expect(got_feats != null);
    const m = got_feats.?.mechanisms;
    try std.testing.expectEqual(@as(usize, 2), m.len);
    try std.testing.expectEqualStrings("SCRAM-SHA-256", m[0]);
    try std.testing.expectEqualStrings("PLAIN", m[1]);
}

test "parser: bind result IQ → bound_jid" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s4' from='localhost'>" ++
        "<iq type='result' id='bind1'>" ++
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>" ++
        "<jid>alice@example.com/phone</jid>" ++
        "</bind>" ++
        "</iq>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var got: ?stream.IqResult = null;
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch unreachable;
        if (ev == null) break;
        if (!parser.onReaderEvent(ev.?)) unreachable;
        if (parser.pending) |sev| {
            parser.pending = null;
            if (sev == .iq_result) got = sev.iq_result;
        }
    }
    try std.testing.expect(got != null);
    try std.testing.expectEqualStrings("bind1", got.?.id);
    try std.testing.expect(got.?.bound_jid != null);
    try std.testing.expectEqualStrings("alice", got.?.bound_jid.?.local);
    try std.testing.expectEqualStrings("example.com", got.?.bound_jid.?.domain);
    try std.testing.expectEqualStrings("phone", got.?.bound_jid.?.resource);
}

test "parser: SM enabled" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s5' from='localhost'>" ++
        "<enabled xmlns='urn:xmpp:sm:3' id='sm42' resume='true' max='300'/>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var got: ?stream.SmResult = null;
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch unreachable;
        if (ev == null) break;
        if (!parser.onReaderEvent(ev.?)) unreachable;
        if (parser.pending) |sev| {
            parser.pending = null;
            if (sev == .sm_result) got = sev.sm_result;
        }
    }
    try std.testing.expect(got != null);
    switch (got.?) {
        .enabled => |id| try std.testing.expectEqualStrings("sm42", id),
        else => return error.TestFail,
    }
}

test "parser: SM resumed" {
    const allocator = std.testing.allocator;
    const input =
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' id='s6' from='localhost'>" ++
        "<resumed xmlns='urn:xmpp:sm:3' h='0' previd='prev-id'/>";
    var reader = Reader.init(allocator);
    defer reader.deinit();
    var parser = Parser.init(allocator);
    defer parser.deinit(allocator);
    var got: ?stream.SmResult = null;
    var pos: usize = 0;
    while (true) {
        const ev = reader.next(input, &pos) catch unreachable;
        if (ev == null) break;
        if (!parser.onReaderEvent(ev.?)) unreachable;
        if (parser.pending) |sev| {
            parser.pending = null;
            if (sev == .sm_result) got = sev.sm_result;
        }
    }
    try std.testing.expect(got != null);
    switch (got.?) {
        .resumed => |id| try std.testing.expectEqualStrings("prev-id", id),
        else => return error.TestFail,
    }
}

