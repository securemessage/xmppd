//! # xmppc Engine — ONE kqueue loop driving N client sessions
//!
//! Owns the kqueue, the session slot map, the cross-thread wake pipe, and the
//! connect/registration helpers. Session lifecycle and protocol handling
//! live in session.zig; protocol parsing in parser.zig; the stream FSM in
//! stream.zig; I/O in transport.zig.
//!
//! ## Slot map (T-80EFEC29)
//! Sessions live in stable slots behind generational `Handle`s — the public
//! session id and the kqueue `udata`. A freed slot bumps its generation, so
//! a stale event or a stale handle is dropped by a cheap check; removal
//! never moves a live session, never invalidates a `*Session` handed to a
//! callback, and never touches kqueue.
//!
//! ## Changelist (T-65F61479)
//! kqueue registrations are STAGED into a buffer and applied by the ONE
//! `kevent()` wait per loop iteration (project kqueue rule: never a kevent
//! call without an eventlist). The wake pipe's one-time registration is the
//! single deliberate exception (created lazily on first use).

const std = @import("std");
const ssl = @import("ssl");

const Session = @import("session.zig").Session;
const Transport = @import("transport.zig").Transport;

const Kevent = std.posix.Kevent;
const posix = std.posix;

fn kev(ident: usize, filter: i16, flags: u16, udata: usize) Kevent {
    return .{ .ident = ident, .filter = filter, .flags = flags, .fflags = 0, .data = 0, .udata = udata };
}

/// A generationally-tagged session slot. Stale handles fail `Engine.get`
/// and late kqueue events fail the same check — the slot was reused.
pub const Handle = packed struct {
    index: u32,
    generation: u32,

    pub fn encode(h: Handle) usize {
        return @intCast(@as(u64, @bitCast(h)));
    }
    pub fn decode(v: usize) Handle {
        return @bitCast(@as(u64, v));
    }
};

/// One kqueue registration change, staged until the waiting kevent() call.
const Change = Kevent;

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
    const WAKE_UDATA: usize = std.math.maxInt(usize);
    const Slot = struct {
        session: Session,
        generation: u32,
        live: bool,
    };

    kq: posix.fd_t,
    allocator: std.mem.Allocator,
    slots: std.ArrayListUnmanaged(Slot),
    free_slots: std.ArrayListUnmanaged(u32),
    live_count: usize = 0,

    tls_ctx: ?ssl.SslContext = null,
    thread: ?std.Thread = null,
    // Self-pipe for cross-thread wake-up (N-worker shutdown / stopSession
    // from a foreign thread). EVFILT_SIGNAL is unreliable across threads;
    // a real kqueue event on the pipe read-end is not.
    wake_pipe: [2]posix.fd_t = .{ -1, -1 },

    /// Staged kqueue registration changes, folded into the next waiting
    /// kevent() call. Mutex-guarded: attachFromThreadFd callers may stage
    /// from foreign threads.
    changes: std.ArrayListUnmanaged(Change) = .{},
    changes_lock: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator) !Engine {
        const kq = posix.kqueue() catch return error.KqueueInit;
        return .{ .kq = kq, .allocator = allocator, .slots = .{}, .free_slots = .{} };
    }

    pub fn deinit(self: *Engine) void {
        if (self.thread) |*t| {
            t.join();
            self.thread = null;
        }
        self.stopAll();
        self.slots.deinit(self.allocator);
        self.free_slots.deinit(self.allocator);
        self.changes.deinit(self.allocator);
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
        for (self.slots.items) |*slot| {
            if (slot.live) slot.session.destroy(self.allocator);
            slot.live = false;
        }
        self.live_count = 0;
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
        return self.live_count;
    }

    /// Access a live session by its handle (from startSession/attachFd).
    /// Returns null for dead/reaped sessions and for stale handles.
    pub fn sessionAt(self: *Engine, h: Handle) ?*Session {
        if (h.index >= self.slots.items.len) return null;
        const slot = &self.slots.items[@intCast(h.index)];
        if (!slot.live or slot.generation != h.generation) return null;
        if (!slot.session.alive) return null;
        return &slot.session;
    }

    /// Mark a session dead and wake the loop to reap it. Safe from any thread:
    /// fail() is idempotent and the reap runs on the engine thread.
    pub fn stopSession(self: *Engine, h: Handle, reason: []const u8) void {
        if (self.sessionAt(h)) |s| s.fail(self.allocator, reason);
        self.requestWake();
    }

    /// Begin a client session toward host:port. `domain` is the stream's
    /// `to=` JID domain (RFC 6120 §4.2) — distinct from the TCP connect
    /// target `host` (e.g. host "127.0.0.1" but domain "localhost"). Returns
    /// the session handle.
    pub fn startSession(self: *Engine, host: []const u8, port: u16, domain: []const u8, user: []const u8, password: []const u8, resource: []const u8, sm_resume_id: []const u8) !Handle {
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
    pub fn attachFd(self: *Engine, fd: posix.fd_t, domain: []const u8, user: []const u8, password: []const u8, resource: []const u8, sm_resume_id: []const u8) !Handle {
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

    fn attachPrepared(self: *Engine, s: *Session, fd: posix.fd_t) !Handle {
        s.fd = fd;
        s.tport = Transport.initPlain(fd);
        s.phase = .connecting;

        const h = try self.allocSlot();
        const slot = &self.slots.items[@intCast(h.index)];
        slot.session = s.*;
        slot.session.handle = h;
        slot.live = true;
        // Both filters are registered below — keep the session's bookkeeping
        // in step (disarm/arm are idempotent guards).
        slot.session.write_registered = true;
        slot.session.read_registered = true;
        self.live_count += 1;
        self.addRead(fd, h);
        self.addWrite(fd, h);
        return h;
    }

    fn allocSlot(self: *Engine) !Handle {
        if (self.free_slots.items.len > 0) {
            const idx = self.free_slots.items[self.free_slots.items.len - 1];
            self.free_slots.items.len -= 1;
            const slot = &self.slots.items[@intCast(idx)];
            return .{ .index = idx, .generation = slot.generation };
        }
        // Placeholder session is overwritten by the caller before use.
        try self.slots.append(self.allocator, .{ .session = undefined, .generation = 0, .live = false });
        return .{ .index = @intCast(self.slots.items.len - 1), .generation = 0 };
    }

    fn freeSlot(self: *Engine, h: Handle) void {
        const slot = &self.slots.items[@intCast(h.index)];
        slot.live = false;
        slot.generation +%= 1;
        self.free_slots.append(self.allocator, h.index) catch {};
        self.live_count -= 1;
    }

    /// Run the kqueue loop on a dedicated thread.
    pub fn run(self: *Engine) !void {
        const t = std.Thread.spawn(.{}, Engine.runLoop, .{self}) catch return error.ThreadSpawn;
        self.thread = t;
    }

    /// Run the kqueue loop inline on the caller thread until all sessions die.
    pub fn runSync(self: *Engine) !void {
        while (self.live_count > 0) {
            self.loopOnce() catch {
                // kevent error — fail every session and stop rather than spin.
                for (self.slots.items) |*slot| {
                    if (slot.live) slot.session.fail(self.allocator, "kqueue-error");
                }
                self.reapDead();
                break;
            };
            self.reapDead();
        }
    }

    fn runLoop(self: *Engine) void {
        while (self.live_count > 0) {
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

        // Fold everything staged since the last iteration into THIS kevent:
        // snapshot the buffer, then release the lock — event handlers stage
        // new changes during dispatch (they'd otherwise self-deadlock).
        var evbuf: [64]Kevent = undefined;
        var staged: [64]Change = undefined;
        self.changes_lock.lock();
        const staged_count = @min(self.changes.items.len, staged.len);
        @memcpy(staged[0..staged_count], self.changes.items[0..staged_count]);
        self.changes.items.len -= staged_count;
        self.changes_lock.unlock();

        const n = posix.kevent(self.kq, staged[0..staged_count], &evbuf, null) catch {
            return error.SystemResources;
        };
        if (std.posix.getenv("XMPPC_EVTRACE") != null) {
            std.debug.print("[engine] staged={d} returned={d}\n", .{ staged_count, n });
            for (evbuf[0..n]) |ev| std.debug.print("  ev fd={d} filter={d} flags=0x{x} reg={} wan=\n", .{ ev.ident, ev.filter, ev.flags, ev.udata });
        }

        for (evbuf[0..n]) |ev| {
            if (ev.udata == WAKE_UDATA) continue;
            const h = Handle.decode(ev.udata);
            const s = self.sessionAt(h) orelse continue;
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
            if (ev.flags & std.c.EV.ERROR != 0) {
                std.debug.print("[engine] EV_ERROR fd={d} filter={d} data={d}\n", .{ ev.ident, ev.filter, ev.data });
                s.fail(self.allocator, "socket-error");
            }
        }
    }

    /// Destroy + release dead sessions. Slots stay; generations advance.
    fn reapDead(self: *Engine) void {
        for (self.slots.items, 0..) |*slot, i| {
            if (!slot.live) continue;
            if (slot.session.alive) continue;
            slot.session.destroy(self.allocator);
            self.freeSlot(.{ .index = @intCast(i), .generation = slot.generation });
        }
    }

    // --- kqueue helpers: stage registration changes (applied at the wait) ---

    pub fn addRead(self: *Engine, fd: posix.fd_t, h: Handle) void {
        self.stage(kev(@intCast(fd), std.c.EVFILT.READ, std.c.EV.ADD | std.c.EV.ENABLE, h.encode()));
    }
    pub fn addWrite(self: *Engine, fd: posix.fd_t, h: Handle) void {
        self.stage(kev(@intCast(fd), std.c.EVFILT.WRITE, std.c.EV.ADD | std.c.EV.ENABLE, h.encode()));
    }
    pub fn removeRead(self: *Engine, fd: posix.fd_t) void {
        self.stage(kev(@intCast(fd), std.c.EVFILT.READ, std.c.EV.DELETE, 0));
    }
    pub fn removeWrite(self: *Engine, fd: posix.fd_t) void {
        self.stage(kev(@intCast(fd), std.c.EVFILT.WRITE, std.c.EV.DELETE, 0));
    }

    /// Stage a registration change for the next loop iteration's kevent(),
    /// then wake the loop: a kevent() blocked on a drained changelist would
    /// otherwise not apply the registration until an unrelated fd event.
    /// Never calls kevent for registration alone (project kqueue rule).
    fn stage(self: *Engine, ev: Change) void {
        self.changes_lock.lock();
        defer self.changes_lock.unlock();
        self.changes.append(self.allocator, ev) catch {};
        self.requestWake();
    }
};
