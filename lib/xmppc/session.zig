//! # xmppc Session — client session lifecycle on the engine's kqueue loop
//!
//! Turns the pure ClientStream FSM + SaslClient into a real XMPP client:
//!
//!   TCP (non-blocking) -> [STARTTLS] -> SASL -> bind -> [session] -> SM -> active
//!
//! The Engine (engine.zig) owns the kqueue; many Sessions run on it. Protocol
//! parsing lives in parser.zig; the stream FSM in stream.zig.
//!
//! ## Constraints (task-brief-91e96a28)
//! * Own API boundary: imports only std + the shared protocol modules. No src/.
//! * Event-driven only: kqueue, no thread per connection, no polling.
//!
//! ## Stream restarts (RFC 6120 4.7)
//! The client opens a FRESH <stream:stream> after STARTTLS and after SASL
//! success. The server resets its XML reader on both, so the client does the
//! same the moment the FSM returns .send_stream_open in a restart context.
//! The Reader only emits stream_open at depth 1.

const std = @import("std");
const xml = @import("xml");

const log = std.log.scoped(.xmppc);
const xmpp = @import("xmpp");
const ssl = @import("ssl");
const stream = @import("stream.zig");
const saslmod = @import("sasl.zig");

const Engine = @import("engine.zig").Engine;
const Handle = @import("engine.zig").Handle;
const Parser = @import("parser.zig").Parser;
const Transport = @import("transport.zig").Transport;
const resolver_mod = @import("resolver.zig");
const Resolution = resolver_mod.Resolution;

const Jid = xmpp.Jid;
const Reader = xml.Reader;
const posix = std.posix;

const READ_BUF_SIZE = 1 << 16;

/// Buffers start small and grow on demand; shrink back when fully drained.
/// (T-09BD8909: a session must not cost 128 KiB at rest.)
const BUF_INITIAL_SIZE = 1 << 12; // 4 KiB
/// Hard cap on a single incoming element's buffered bytes; a larger element
/// fails the session with policy-violation (an unlimited growth was a DoS
/// vector). Sized far above any legal stanza (~10 KiB is typical).
const MAX_READ_BUF_SIZE = 1 << 20; // 1 MiB

/// Max wire footprint of one SASL strophe after base64 (~1.34× the raw cap).
const SASL_ENC_MAX = 2048;

/// Encode base64 into a caller-owned fixed buffer (no heap on the hot path).
fn b64encInto(out: []u8, input: []const u8) ![]const u8 {
    const enc = std.base64.standard.Encoder;
    const len = enc.calcSize(input.len);
    if (len > out.len) return error.SaslMessageTooLong;
    _ = enc.encode(out[0..len], input);
    return out[0..len];
}

/// Decode is the parser's job (parser.zig owns its own fixed scratch).
/// session.zig encodes into SASL_ENC_MAX-sized stack buffers.

// ============================================================================
// Session
// ============================================================================

pub const Session = struct {
    const Phase = enum {
        connecting,
        /// DNS in flight for a hostname (T-16C82690/T201).
        resolving,
        /// TCP up + stream open written; FSM-driven establishment pending.
        connected,
        /// Full protocol establishment (bind + SM).
        established,
        dead,
    };

    engine: *Engine,
    /// This session's slot handle on the engine (public id + kqueue udata).
    handle: Handle = .{ .index = 0, .generation = 0 },
    alive: bool = true,
    /// Freed exactly once (destroy idempotence). Separate from `alive`:
    /// fail() only marks dead; destroy still has resources to free.
    destructed: bool = false,
    phase: Phase = .connecting,
    failed: bool = false,

    /// Copy of the last fail() reason — callbacks and post-mortem readers
    /// (e.g. smoke's summary line) may outlive the parser buffers the
    /// original slice borrows from.
    fail_reason_buf: [128]u8 = undefined,
    fail_reason_len: u8 = 0,

    fd: posix.fd_t = -1,
    /// The I/O link — plain TCP until STARTTLS upgrades it in place
    /// (Transport owns the "identical pointer on TLS retry" pin state).
    tport: ?Transport = null,
    tls_handshake: bool = false,

    /// Requested TCP port for direct connects (kept for target iteration).
    port: u16 = 0,
    /// DNS resolution result (owned; TLSA records included per target).
    /// Freed in destroy.
    resolution: ?Resolution = null,
    target_index: usize = 0,

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
    /// Write start offset: sends consume [write_start..write_len]; the
    /// consumed prefix compacts lazily (never while a TLS write is pinned).
    write_start: usize = 0,
    /// Registration bookkeeping: stage writes only on transitions so that a
    /// duplicate EV_DELETE can't surface as a changelist EV_ERROR (ENOENT).
    read_registered: bool = false,
    write_registered: bool = false,
    /// Bytes queued while write_buf is pinned by a pending TLS write and
    /// full, in order; moved into write_buf once the pending write completes.
    overflow: std.ArrayListUnmanaged(u8) = .{},

    /// Bound full JID (set when the bind result is parsed).
    bound_jid: ?Jid = null,
    /// SM session id (set when `<enabled id='…'>` / `<resumed previd='…'>`).
    sm_id: []const u8 = "",
    sm_enabled: bool = false,
    sm_resumed: bool = false,

    /// Fired on the engine thread once the stream is active.
    on_established: ?*const fn (engine: *Engine, handle: Handle, session: *Session) void = null,
    /// Fired on the engine thread when the stream dies.
    on_closed: ?*const fn (engine: *Engine, handle: Handle, session: *Session, reason: []const u8) void = null,

    pub fn init(allocator: std.mem.Allocator) !Session {
        const parser = try allocator.create(Parser);
        parser.* = Parser.init(allocator);
        return .{
            .engine = undefined, // set by Engine.startSession
            .reader = Reader.init(allocator),
            .parser = parser,
            .read_buf = try allocator.alloc(u8, BUF_INITIAL_SIZE),
            .write_buf = try allocator.alloc(u8, BUF_INITIAL_SIZE),
        };
    }

    pub fn destroy(self: *Session, allocator: std.mem.Allocator) void {
        if (self.destructed) return; // exactly-once free (fail() may precede)
        self.destructed = true;
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
        if (self.tport) |*tp| {
            if (tp.tlsConn()) |tc| {
                tc.shutdown();
                tc.deinit();
            }
        }
        if (self.resolution) |*r| r.deinitOn(allocator);
        if (self.fd >= 0) posix.close(self.fd);
        allocator.free(self.read_buf);
        allocator.free(self.write_buf);
        self.overflow.deinit(allocator);
    }

    pub fn fail(self: *Session, allocator: std.mem.Allocator, reason: []const u8) void {
        _ = allocator;
        if (self.failed) return;
        self.failed = true;
        self.alive = false;
        self.phase = .dead;
        const n: u8 = @intCast(@min(reason.len, self.fail_reason_buf.len));
        @memcpy(self.fail_reason_buf[0..n], reason[0..n]);
        self.fail_reason_len = n;
        const owned = self.fail_reason_buf[0..n];
        if (self.on_closed) |cb| cb(self.engine, self.handle, self, owned);
        // The engine's reapDead() destroys + removes this slot.
    }

    /// Install the established/closed callbacks. Must be called on the engine
    /// thread (or before runSync) after startSession, before the stream
    /// completes; the engine hands out sessions by index.
    pub fn setCallbacks(self: *Session, est: ?*const fn (*Engine, Handle, *Session) void, closed: ?*const fn (*Engine, Handle, *Session, []const u8) void) void {
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

    pub fn onRead(self: *Session, engine: *Engine) !void {
        // TLS handshake in flight: drive it, re-arm, and stop.
        if (self.tls_handshake) {
            const tc = blk: {
                const tp = if (self.tport) |*t| t else return self.fail(engine.allocator, "tls-missing");
                break :blk tp.tlsConn() orelse return self.fail(engine.allocator, "tls-missing");
            };
            const res = tc.doHandshake() catch {
                self.fail(engine.allocator, "tls-handshake-failed");
                return;
            };
            switch (res) {
                .complete => {
                    self.tls_handshake = false;
                    self.disarmWrite(engine);
                    // Guardrail rule 3: right after the handshake, check and
                    // log kernel-TLS offload per direction — fallback to
                    // userland crypto is silent, so this is the only way to
                    // tell an armed context really offloaded.
                    log.info("fd={d} tls established ktls_send={} ktls_recv={}", .{ self.fd, tc.ktlsSend(), tc.ktlsRecv() });
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
                    self.armWrite(engine);
                    return;
                },
            }
        }

        // Not connected yet — the (batch-parallel) connect-writable event
        // hasn't run. Leave bytes unread; the fd stays readable and we'll
        // be back. Reading now would feed server bytes to an idle FSM.
        if (self.phase == .connecting) return;

        while (true) {
            if (self.read_len >= self.read_buf.len) {
                // A session sock the parser refuses to finish could otherwise
                // grow without bound (craft a huge element): cap it.
                if (self.read_buf.len >= MAX_READ_BUF_SIZE) {
                    self.fail(engine.allocator, "policy-violation");
                    return;
                }
                const nb = engine.allocator.realloc(self.read_buf, @min(self.read_buf.len * 2, MAX_READ_BUF_SIZE)) catch return error.OutOfMemory;
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
        // Shrink back to the idle footprint once the buffer fully drained.
        if (self.read_len == 0 and self.read_buf.len > BUF_INITIAL_SIZE) {
            self.read_buf = engine.allocator.realloc(self.read_buf, BUF_INITIAL_SIZE) catch self.read_buf;
        }
    }

    /// Kernel-TLS offload state per direction. Both false when not using
    /// TLS or when offload was disabled (see Engine.useTls). Meaningful
    /// once the handshake has completed.
    pub fn ktlsState(self: *Session) struct { send: bool, recv: bool } {
        if (self.tport) |*tp| {
            if (tp.tlsConn()) |tc| return .{ .send = tc.ktlsSend(), .recv = tc.ktlsRecv() };
        }
        return .{ .send = false, .recv = false };
    }

    /// DNS completion callback from the engine's resolver (engine thread).
    /// Takes ownership of the Resolution (targets + TLSA per target).
    pub fn onResolution(self: *Session, res: ?Resolution, status: resolver_mod.Status) void {
        switch (status) {
            .resolved => {
                const r = res orelse return self.fail(self.engine.allocator, "resolve-failed");
                if (r.targets.len == 0) return self.fail(self.engine.allocator, "resolve-failed");
                self.resolution = r;
                self.target_index = 0;
                self.connectNextTarget(true);
            },
            .nxdomain, .failed => self.fail(self.engine.allocator, "resolve-failed"),
        }
    }

    /// Connect to targets[target_index], advancing past failures.
    /// `first` means there is no prior fd to drop.
    fn connectNextTarget(self: *Session, first: bool) void {
        const engine = self.engine;
        const res = &(self.resolution.?);
        while (self.target_index < res.targets.len) {
            const t = res.targets[self.target_index];
            if (!first and self.fd >= 0) posix.close(self.fd);

            self.fd = posix.socket(t.addr.any.family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0) catch {
                self.target_index += 1;
                continue;
            };
            self.tport = Transport.initPlain(self.fd);
            self.read_registered = false;
            self.write_registered = false;

            const conn_result = posix.connect(self.fd, &t.addr.any, t.addr.getOsSockLen());
            if (conn_result) {} else |err| {
                if (err != error.WouldBlock) {
                    self.target_index += 1;
                    continue;
                }
            }
            self.phase = .connecting;
            engine.addRead(self.fd, self.handle);
            engine.addWrite(self.fd, self.handle);
            self.read_registered = true;
            self.write_registered = true;
            return;
        }
        self.fail(engine.allocator, "connect-failed");
    }

    fn armWrite(self: *Session, engine: *Engine) void {
        if (self.write_registered) return;
        engine.addWrite(self.fd, self.handle);
        self.write_registered = true;
    }
    fn disarmWrite(self: *Session, engine: *Engine) void {
        if (!self.write_registered) return;
        engine.removeWrite(self.fd);
        self.write_registered = false;
    }

    /// Returns 0 only when the peer is drained for now (would_block).
    /// A peer close — TCP FIN or TLS close_notify — is error.ConnectionClosed:
    /// it must never be conflated with "drained", because a level-triggered
    /// read filter stays readable on a closed socket and would busy-loop a
    /// session that is never failed.
    fn recv(self: *Session, buf: []u8) !usize {
        const tp = if (self.tport) |*t| t else return error.NoTransport;
        return switch (try tp.read(buf)) {
            .data => |n| n,
            .would_block => 0,
            .closed => error.ConnectionClosed,
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
        if (std.posix.getenv("XMPPC_EVTRACE") != null)
            std.debug.print("[fsm {s} ev={s}]\n", .{ @tagName(self.fsm.state), @tagName(ev) });
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

    pub fn onWritable(self: *Session, engine: *Engine) !void {
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
                // Connect failed — walk the target list when we have one
                // (DNS-given alternatives), otherwise fail.
                if (self.resolution != null) {
                    self.target_index += 1;
                    self.connectNextTarget(false);
                } else {
                    self.fail(engine.allocator, "connect-failed");
                }
                return;
            }
            // TCP up — open the stream and leave the connecting phase so a
            // later write event goes to flushWrites, not back through here
            // (the old code left phase stuck until .established, which
            // re-ran this branch and staged duplicate EV_DELETEs — with a
            // changelist those surface as spurious EV_ERROR events).
            self.phase = .connected;
            const action = self.fsm.openStream();
            self.handleAction(engine, action);
            self.disarmWrite(engine);
            return;
        }
        self.flushWrites(engine);
    }

    fn queue(self: *Session, data: []const u8) !void {
        // Once anything overflowed, later data follows it to keep order.
        if (self.overflow.items.len > 0) {
            try self.overflow.appendSlice(self.engine.allocator, data);
            return;
        }
        if (self.write_len + data.len > self.write_buf.len) {
            // Growing would move write_buf under a pending TLS retry.
            const tls_pinned = self.tport != null and self.tport.?.hasPendingWrite();
            if (tls_pinned) {
                try self.overflow.appendSlice(self.engine.allocator, data);
                return;
            }
            // Compact the consumed prefix first — growth is the last resort.
            if (self.write_start > 0) {
                std.mem.copyForwards(u8, self.write_buf, self.write_buf[self.write_start..self.write_len]);
                self.write_len -= self.write_start;
                self.write_start = 0;
            }
            if (self.write_len + data.len > self.write_buf.len) {
                const need = self.write_len + data.len;
                var cap = @max(self.write_buf.len, 1);
                while (cap < need) cap *= 2;
                const nb = self.engine.allocator.realloc(self.write_buf, cap) catch return error.OutOfMemory;
                self.write_buf = nb;
            }
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
        const trace = std.posix.getenv("XMPPC_EVTRACE") != null;
        while (self.write_start < self.write_len) {
            // sendSome returns 0 only for would-block / TLS WANT_*; any error
            // is fatal (a swallowed TLS write error would stall the session).
            const n = self.sendSome() catch {
                self.fail(self.engine.allocator, "write-error");
                return;
            };
            if (n == 0) {
                // Stalled on a full send buffer — WRITE interest must be armed.
                self.armWrite(engine);
                return;
            }
            if (trace) std.debug.print("[flush wrote {d}, left {d}]\n", .{ n, self.write_len - self.write_start - n });
            self.consumeWritten(n) catch {
                self.fail(self.engine.allocator, "queue-error");
                return;
            };
        }
        self.disarmWrite(engine);
    }

    /// Drop `n` written bytes; the pending TLS retry (if any) is credited,
    /// and overflowed bytes rejoin write_buf when the pin fully releases.
    /// The consumed prefix is tracked by offset — write_buf is only
    /// compacted/shrunk lazily, never under a pending TLS write.
    fn consumeWritten(self: *Session, n: usize) !void {
        if (self.tport) |*tp| tp.writeCompleted(n);
        self.write_start += n;
        if (self.write_start == self.write_len) {
            self.write_start = 0;
            self.write_len = 0;
            // Back to the idle footprint when the pipe drained fully.
            if (self.overflow.items.len == 0 and self.write_buf.len > BUF_INITIAL_SIZE) {
                const t = self.engine.allocator.realloc(self.write_buf, BUF_INITIAL_SIZE);
                if (t) |nb| self.write_buf = nb else |_| {}
            }
        }
        if (self.overflow.items.len > 0) {
            const pending = self.overflow.items;
            // Capacity is retained, so `pending` stays valid for the copy.
            self.overflow.clearRetainingCapacity();
            try self.queue(pending);
        }
    }

    fn sendSome(self: *Session) !usize {
        const tp = if (self.tport) |*t| t else return error.NoTransport;
        return switch (try tp.write(self.write_buf[self.write_start..self.write_len])) {
            .data => |n| n,
            .would_block => 0,
            .closed => error.ConnectionClosed,
        };
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
                const have_tls = self.tport != null and self.tport.?.isTls();
                if (have_tls or self.fsm.state == .awaiting_stream_header_auth) {
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
                // Stack-scratch encoding (T-09BD8909: no heap per step).
                var enc_buf: [SASL_ENC_MAX]u8 = undefined;
                const b64 = b64encInto(&enc_buf, raw) catch {
                    self.fail(allocator, "b64-error");
                    return;
                };
                self.queuef("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='{s}'>{s}</auth>", .{ mech, b64 }) catch {
                    self.fail(allocator, "queue-error");
                    return;
                };
                self.writeAfter(engine);
            },
            .send_sasl_response => {
                const sc = self.sasl orelse return self.fail(allocator, "sasl-not-active");
                const pr = self.parser orelse return self.fail(allocator, "sasl-no-parser");
                const raw = pr.saslChallengeRaw() orelse return self.fail(allocator, "sasl-no-challenge");
                const next = sc.handleChallenge(raw) catch {
                    self.fail(allocator, "sasl-challenge-error");
                    return;
                } orelse return; // client-final already sent; await <success>
                var enc_buf: [SASL_ENC_MAX]u8 = undefined;
                const b64 = b64encInto(&enc_buf, next) catch {
                    self.fail(allocator, "b64-error");
                    return;
                };
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
                const tp = if (self.tport) |*t| t else return self.fail(allocator, "tls-missing");
                tp.upgradeToTls(ctx, null) catch return self.fail(allocator, "tls-init-failed");
                self.tls_handshake = true;
                _ = self.onRead(engine) catch return;
            },
            .established => {
                self.phase = .established;
                self.sm_enabled = self.fsm.sm_enabled;
                self.sm_resumed = self.fsm.sm_resumed;
                self.sm_id = self.fsm.sm_id;
                self.bound_jid = self.fsm.bound_jid;
                if (self.on_established) |cb| cb(engine, self.handle, self);
            },
            .close => {
                // Prefer the protocol reason the FSM already recorded
                // (stream error condition, SASL failure) — failing with a
                // bare "stream-closed" hides the actual error from callers.
                if (self.fsm.failure_reason.len > 0)
                    self.fail(allocator, self.fsm.failure_reason)
                else
                    self.fail(allocator, "stream-closed");
            },
        }
    }

    /// Test seam (socketpair harness): queue raw bytes through the same path
    /// the FSM actions use — respects overflow ordering and the TLS pinned
    /// buffer, flushes immediately, re-arms write interest when pending.
    pub fn testQueue(self: *Session, data: []const u8) !void {
        try self.queue(data);
        self.writeAfter(self.engine);
    }

    /// After queueing bytes: flush now, and re-arm write interest if pending.
    fn writeAfter(self: *Session, engine: *Engine) void {
        self.flushWrites(engine);
        if (self.write_len > 0) self.armWrite(engine);
    }
};
// ============================================================================
// Tests (unit; end-to-end lives in test/xmppc/smoke.zig + xmppd rig)
// ============================================================================

test "write path: write_buf never moves while a TLS write is pending" {
    const a = std.testing.allocator;
    var engine = try Engine.init(a);
    defer engine.deinit();
    var s = try Session.init(a);
    s.engine = &engine;
    defer s.destroy(a);

    const filler = try a.alloc(u8, s.write_buf.len - 10);
    defer a.free(filler);
    @memset(filler, 'a');
    try s.queue(filler);
    // As if SSL_write(write_buf, write_len) had returned WANT_WRITE.
    s.tport = Transport.initPlain(-1); // only the pin bookkeeping is used
    s.tport.?.tls_pending = s.write_len;
    const pinned = s.write_buf.ptr;

    try s.queue("0123456789ABCDEF"); // does not fit: overflows
    try s.queue("xy"); // would fit, but must follow the overflow to keep order
    try std.testing.expect(s.write_buf.ptr == pinned);
    try std.testing.expectEqual(filler.len, s.write_len);
    try std.testing.expectEqualStrings("0123456789ABCDEFxy", s.overflow.items);

    // The retried write completes in full; overflow rejoins write_buf.
    try s.consumeWritten(s.write_len);
    try std.testing.expect(!s.tport.?.hasPendingWrite());
    try std.testing.expectEqual(@as(usize, 0), s.overflow.items.len);
    try std.testing.expectEqualStrings("0123456789ABCDEFxy", s.write_buf[0..s.write_len]);
}

test "write path: appending in place during a pending TLS write keeps the buffer" {
    const a = std.testing.allocator;
    var engine = try Engine.init(a);
    defer engine.deinit();
    var s = try Session.init(a);
    s.engine = &engine;
    defer s.destroy(a);

    try s.queue("<presence/>");
    s.tport = Transport.initPlain(-1); // only the pin bookkeeping is used
    s.tport.?.tls_pending = s.write_len;
    const pinned = s.write_buf.ptr;
    // Fits: the retry may legally pass a longer length from the same address.
    try s.queue("<message/>");
    try std.testing.expect(s.write_buf.ptr == pinned);
    try std.testing.expectEqual(@as(usize, 0), s.overflow.items.len);
    try std.testing.expectEqualStrings("<presence/><message/>", s.write_buf[0..s.write_len]);
}

test "write path: buffer grows normally when no TLS write is pending" {
    const a = std.testing.allocator;
    var engine = try Engine.init(a);
    defer engine.deinit();
    var s = try Session.init(a);
    s.engine = &engine;
    defer s.destroy(a);

    const big = try a.alloc(u8, s.write_buf.len + 1);
    defer a.free(big);
    @memset(big, 'b');
    try s.queue(big);
    try std.testing.expectEqual(big.len, s.write_len);
    try std.testing.expectEqual(@as(usize, 0), s.overflow.items.len);
}
