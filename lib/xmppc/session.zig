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
//! ## Thread ownership
//! All Session state is touched ONLY on the engine thread. Foreign threads
//! never call into a Session directly; they post commands to the Engine
//! (postStanza and stopSession are both outbox commands + wake pipe).
//! Every Event is delivered on the engine thread.
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
const tls = @import("tls");
const dns = @import("dns");
const stream = @import("stream.zig");
const saslmod = @import("sasl.zig");
const sasl = @import("sasl");

const Engine = @import("engine.zig").Engine;
const Handle = @import("engine.zig").Handle;
const Parser = @import("parser.zig").Parser;
const Transport = @import("transport.zig").Transport;
const resolver_mod = @import("resolver.zig");
const Resolution = resolver_mod.Resolution;

const Jid = xmpp.Jid;
const Reader = xml.Reader;
const posix = std.posix;

/// Buffers start small and grow on demand; shrink back when fully drained.
/// (T-09BD8909: a session must not cost 128 KiB at rest.)
const BUF_INITIAL_SIZE = 1 << 12; // 4 KiB
/// Hard cap on a single incoming element's buffered bytes; a larger element
/// fails the session with policy-violation (an unlimited growth was a DoS
/// vector). Sized far above any legal stanza (~10 KiB is typical).
const MAX_READ_BUF_SIZE = 1 << 20; // 1 MiB

/// Max wire footprint of one SASL strophe after base64 (~1.34× the raw cap).
const SASL_ENC_MAX = 2048;

/// Connection and identity for one session. Every field is borrowed on the
/// call and arena-copied into the Session, so the caller's storage may die
/// the moment startSession/attachFd returns (T-25A16875).
pub const SessionConfig = struct {
    /// TCP connect target. Empty for attachFd (the fd is already connected).
    host: []const u8 = "",
    port: u16 = 5222,
    /// Stream `to=` domain (RFC 6120 4.2); distinct from `host` (e.g. host
    /// "127.0.0.1" but domain "localhost").
    domain: []const u8,
    user: []const u8,
    password: []const u8,
    resource: []const u8 = "",
    /// XEP-0198 resume id when reattaching to a detached stream.
    sm_resume_id: []const u8 = "",
    /// The OLD session's inbound stanza count ('h'), paired with
    /// sm_resume_id. The server uses h to know which queued stanzas the
    /// client already handled; sending h='0' when the client DID ack some
    /// wraps the server's unacked queue into discardAll (silent loss).
    sm_resume_h: u32 = 0,
};

/// One application-level stanza (post-establishment message/presence/iq).
/// Payload slices borrow parser/reader buffers: they are valid only while
/// the Event callback runs; copy what the consumer keeps.
pub const Stanza = @import("parser.zig").Stanza;

/// Everything a consumer can observe. Delivered through the ONE Engine-level
/// event handler (T-25A16875 c); a C-ABI wrapper maps 1:1 onto this union.
pub const Event = union(enum) {
    /// Stream active (bind + SM done); stanza traffic may flow.
    established,
    /// Stream died. The reason slice is valid for the callback only.
    closed: []const u8,
    /// Inbound application stanza (see Stanza for payload lifetime).
    stanza: Stanza,
    /// SM resume was rejected (`<failed/>`): the server discarded these
    /// many of our unacked outbound stanzas (T-9BC4D065). Delivered just
    /// before .established (the stream continues without SM).
    sm_failed: u32,
};

/// Signature of the Engine event sink. Runs on the engine thread (see the
/// thread-ownership note above for the stopSession exception).
pub const EventHandler = *const fn (ctx: ?*anyopaque, engine: *Engine, handle: Handle, ev: Event) void;

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

    /// Per-phase establishment steps for Session.milestones (T-E232E8AE).
    pub const Milestone = enum(u8) { start, tcp_up, tls_start, tls_done, sasl_done, established };

    engine: *Engine,
    /// This session's slot handle on the engine (public id + kqueue udata).
    handle: Handle = .{ .index = 0, .generation = 0 },
    alive: bool = true,
    /// Freed exactly once (destroy idempotence). Separate from `alive`:
    /// fail() only marks dead; destroy still has resources to free.
    destructed: bool = false,
    phase: Phase = .connecting,
    failed: bool = false,

    /// Establishment-step timestamps, ns since epoch; 0 = not reached yet.
    /// The load driver reads these at .established for per-phase latency
    /// histograms (T-E232E8AE). Written on the engine thread except .start
    /// (setConfig, caller thread during prepare).
    milestones: [@typeInfo(Milestone).@"enum".fields.len]u64 = @splat(0),

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

    /// Server-authentication policy for the TLS handshake (T202). Seeded
    /// from Engine.default_tls_policy: dane_first matches the peer chain
    /// against the resolution's TLSA records and falls back to PKIX
    /// (system CA + hostname) only when none exist; none is lab-only.
    tls_policy: tls.VerifyMode = .dane_first,
    /// TLSA records to authenticate with when no resolution is attached
    /// (test seam; hostname sessions get records per target from DNS).
    dane_records: []const dns.TlsaRecord = &.{},
    /// True while the handshake runs in DANE mode (VERIFY_NONE context):
    /// the TLSA match runs on this thread the moment it completes.
    pending_dane: bool = false,

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
    /// TLS channel binding state captured at handshake completion
    /// (T-D61734DE): cb_mode mirrors the SslConn binding type, cb_data_buf
    /// owns the 32 binding bytes for the SASL exchange's lifetime.
    cb_mode: sasl.scram.CbMode = .none,
    cb_data_buf: [32]u8 = undefined,
    /// OpaqueString-prepped credentials (T-12C2E0C6): SaslClient borrows
    /// these slices, so they must live on the Session.
    prep_authcid_buf: [2048]u8 = undefined,
    prep_password_buf: [2048]u8 = undefined,
    /// True while a SaltedPassword derivation runs on the engine's crypto
    /// worker; the SASL exchange resumes in onSaslDerived.
    sasl_deriving: bool = false,
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
    /// h carried into <resume>; from SessionConfig.sm_resume_h.
    resume_h: u32 = 0,

    /// Per-session arena owning the SessionConfig copies (setConfig); the
    /// caller's config storage is never retained (T-25A16875).
    arena_state: std.heap.ArenaAllocator,

    fn mark(self: *Session, m: Milestone) void {
        self.milestones[@intFromEnum(m)] = @intCast(@max(0, std.time.nanoTimestamp()));
    }
    /// ns epoch of one establishment milestone, 0 while unreached.
    pub fn milestoneNs(self: *const Session, m: Milestone) u64 {
        return self.milestones[@intFromEnum(m)];
    }

    pub fn init(allocator: std.mem.Allocator) !Session {
        const parser = try allocator.create(Parser);
        parser.* = Parser.init(allocator);
        return .{
            .engine = undefined, // set by Engine.startSession
            .reader = Reader.init(allocator),
            .parser = parser,
            .read_buf = try allocator.alloc(u8, BUF_INITIAL_SIZE),
            .write_buf = try allocator.alloc(u8, BUF_INITIAL_SIZE),
            .arena_state = std.heap.ArenaAllocator.init(allocator),
        };
    }

    /// Copy the config into the session arena and bind the FSM resume id.
    /// Called by the Engine before the session is slotted.
    pub fn setConfig(self: *Session, config: SessionConfig) !void {
        const a = self.arena_state.allocator();
        self.mark(.start);
        self.host = try a.dupe(u8, config.host);
        self.domain = try a.dupe(u8, config.domain);
        self.user = try a.dupe(u8, config.user);
        self.password = try a.dupe(u8, config.password);
        self.resource = try a.dupe(u8, config.resource);
        self.fsm.resume_id = try a.dupe(u8, config.sm_resume_id);
        self.resume_h = config.sm_resume_h;
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
        self.arena_state.deinit();
    }

    pub fn fail(self: *Session, allocator: std.mem.Allocator, reason: []const u8) void {
        _ = allocator;
        if (self.failed) return;
        self.failed = true;
        self.alive = false;
        self.phase = .dead;
        self.engine.reap_pending = true;
        self.engine.noteFail();
        const n: u8 = @intCast(@min(reason.len, self.fail_reason_buf.len));
        @memcpy(self.fail_reason_buf[0..n], reason[0..n]);
        self.fail_reason_len = n;
        const owned = self.fail_reason_buf[0..n];
        self.engine.dispatchEvent(self.handle, .{ .closed = owned });
        // The engine's reapDead() destroys + removes this slot.
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
    /// Current inbound stanza count h — with smId(), this is what the
    /// consumer carries into the NEXT session's SessionConfig for a
    /// resumption that does not lose in-flight stanzas.
    pub fn smH(self: *const Session) u32 {
        const pr = self.parser orelse return 0;
        return pr.sm_stanza_count;
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
                    self.mark(.tls_done);
                    self.disarmWrite(engine);
                    // Guardrail rule 3: right after the handshake, check and
                    // log kernel-TLS offload per direction — fallback to
                    // userland crypto is silent, so this is the only way to
                    // tell an armed context really offloaded.
                    log.info("fd={d} tls established ktls_send={} ktls_recv={}", .{ self.fd, tc.ktlsSend(), tc.ktlsRecv() });
                    // Channel binding for SCRAM -PLUS / gs2 'y' (T-D61734DE):
                    // tls-exporter on TLS 1.3, tls-server-end-point on 1.2.
                    if (tc.getChannelBinding()) |cb| {
                        self.cb_data_buf = cb.data;
                        self.cb_mode = switch (cb.cb_type) {
                            .tls_exporter => .tls_exporter,
                            .tls_server_end_point => .tls_server_end_point,
                            .none => .none,
                        };
                        self.fsm.cb_available = self.cb_mode.isPlus();
                    }
                    // DANE mode authenticated nothing yet: match the peer
                    // chain against the TLSA records now, fail closed.
                    if (self.pending_dane) {
                        self.pending_dane = false;
                        self.verifyDane(engine, tc) orelse return;
                    }
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
            engine.noteRx(n);
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

    /// TLSA records authenticating the current connection target: the test
    /// seam's override first, then the resolution's per-target set.
    fn currentTlsa(self: *const Session) []const dns.TlsaRecord {
        if (self.dane_records.len > 0) return self.dane_records;
        if (self.resolution) |*r| {
            if (self.target_index < r.targets.len) return r.targets[self.target_index].tlsa;
        }
        return &.{};
    }

    /// Zero-terminated copy of the stream domain for SNI / hostname checks.
    fn domainZ(buf: []u8, domain: []const u8) ?[*:0]const u8 {
        if (domain.len == 0 or domain.len >= buf.len) return null;
        @memcpy(buf[0..domain.len], domain);
        buf[domain.len] = 0;
        return buf[0..domain.len :0].ptr;
    }

    /// DANE match of the just-presented peer chain against the TLSA records
    /// (engine thread, at handshake completion). Fails the session and
    /// returns null on mismatch; logs which path validated (T202).
    fn verifyDane(self: *Session, engine: *Engine, tc: *ssl.SslConn) ?void {
        const allocator = engine.allocator;
        const leaf = (tc.getPeerCertDer(allocator) catch null) orelse {
            log.warn("fd={d} tls: no peer certificate for DANE match", .{self.fd});
            self.fail(allocator, "tls-dane-mismatch");
            return null;
        };
        defer allocator.free(leaf);
        const chain = tc.getPeerChainDer(allocator) catch &.{};
        defer {
            for (chain) |cert| allocator.free(cert);
            if (chain.len > 0) allocator.free(chain);
        }

        // Convert lib/dns records to lib/tls records, dropping any with
        // out-of-range fields (their bytes never authenticate anything).
        var converted: [16]tls.TlsaRecord = undefined;
        var n: usize = 0;
        for (self.currentTlsa()) |r| {
            if (n == converted.len) break;
            converted[n] = .{
                .usage = std.enums.fromInt(tls.TlsaCertUsage, r.usage) orelse continue,
                .selector = std.enums.fromInt(tls.TlsaSelector, r.selector) orelse continue,
                .matching_type = std.enums.fromInt(tls.TlsaMatchingType, r.matching_type) orelse continue,
                .association_data = r.association_data,
            };
            n += 1;
        }
        if (n == 0) {
            log.warn("fd={d} tls: TLSA present for {s} but none usable — refusing", .{ self.fd, self.domain });
            self.fail(allocator, "tls-dane-mismatch");
            return null;
        }

        switch (tls.validateDane(leaf, chain, converted[0..n])) {
            .dane_ee_match => log.info("fd={d} tls: DANE-EE match for {s}", .{ self.fd, self.domain }),
            .dane_ta_match => log.info("fd={d} tls: DANE-TA match for {s}", .{ self.fd, self.domain }),
            .no_tlsa_records => unreachable, // n > 0 above
            .dane_failed => {
                log.warn("fd={d} tls: DANE mismatch for {s} — refusing connection", .{ self.fd, self.domain });
                self.fail(allocator, "tls-dane-mismatch");
                return null;
            },
        }
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
            const ev_start = pos;
            const ev = self.reader.next(self.read_buf[0..self.read_len], &pos) catch {
                self.fail(allocator, "xml-parse-error");
                return;
            };
            if (ev == null) break;
            if (!parser.onReaderEvent(ev.?, self.read_buf[ev_start..pos])) {
                self.fail(allocator, "protocol-error");
                return;
            }
            if (parser.pending_stanza) |st| {
                parser.pending_stanza = null;
                // Stanzas are application traffic: only delivered once the
                // stream is active (bind/session IQs during establishment
                // stay with the FSM even when the parser captures them).
                if (self.phase == .established) {
                    engine.dispatchEvent(self.handle, .{ .stanza = st });
                    if (self.failed) return;
                } else {
                    log.debug("dropping stanza received before establishment ({s})", .{@tagName(st.kind)});
                }
            }
            if (parser.pending_sm_r) {
                parser.pending_sm_r = false;
                if (self.sm_enabled) {
                    // Answer the server's ack request with the running 'h'.
                    self.queuef("<a xmlns='urn:xmpp:sm:3' h='{d}'/>", .{parser.sm_stanza_count}) catch {
                        self.fail(allocator, "queue-error");
                        return;
                    };
                    self.writeAfter(engine);
                }
            }
            if (parser.pending_sm_a) |h| {
                parser.pending_sm_a = null;
                if (self.sm_enabled) engine.smAck(self.sm_id, h);
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
        if (engine.trace)
            std.debug.print("[fsm {s} ev={s}]\n", .{ @tagName(self.fsm.state), @tagName(ev) });
        if (ev == .sasl_success) {
            if (self.sasl) |sc| {
                sc.verifyServerFinal(ev.sasl_success) catch {
                    self.fail(engine.allocator, "sasl-verify-failed");
                    return;
                };
            }
            self.mark(.sasl_done);
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
            self.mark(.tcp_up);
            engine.noteConnect();
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
        const trace = engine.trace;
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
        self.engine.noteTx(n);
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
    //
    // Error funnel (T-25A16875): each handler returns and the ONE catch
    // here maps error -> failure reason; handlers never call fail() for
    // their own I/O errors.
    // ------------------------------------------------------------------

    const ActionError = error{
        QueueFailed,
        SaslInitFailed,
        SaslNotActive,
        SaslNoParser,
        SaslNoPassword,
        SaslNoChallenge,
        SaslChallengeFailed,
        SaslDeriveQueue,
        Base64Failed,
        TlsNotConfigured,
        TlsMissing,
        TlsInitFailed,
        TlsDriveFailed,
        TlsDomainTooLong,
    };

    fn actionFailReason(err: ActionError) []const u8 {
        return switch (err) {
            error.QueueFailed => "queue-error",
            error.SaslInitFailed => "sasl-init-failed",
            error.SaslNotActive => "sasl-not-active",
            error.SaslNoParser => "sasl-no-parser",
            error.SaslNoPassword => "sasl-no-password",
            error.SaslNoChallenge => "sasl-no-challenge",
            error.SaslChallengeFailed => "sasl-challenge-error",
            error.SaslDeriveQueue => "sasl-derive-queue",
            error.Base64Failed => "b64-error",
            error.TlsNotConfigured => "tls-not-configured",
            error.TlsMissing => "tls-missing",
            error.TlsInitFailed => "tls-init-failed",
            error.TlsDriveFailed => "tls-handshake-failed",
            error.TlsDomainTooLong => "tls-domain-too-long",
        };
    }

    fn handleAction(self: *Session, engine: *Engine, action: stream.ClientAction) void {
        switch (action) {
            .established => {
                self.phase = .established;
                self.mark(.established);
                engine.noteEstablished();
                const a = self.arena_state.allocator();
                // The FSM's sm_id/bound_jid borrow parser buffers that the
                // per-stanza arena reset later frees; consumers hold these
                // across the session, so copy them (PR #4 review A). OOM
                // here fails the session (T233): a silently empty sm_id
                // would make the next resume replay everything.
                self.sm_enabled = self.fsm.sm_enabled;
                self.sm_resumed = self.fsm.sm_resumed;
                self.sm_id = a.dupe(u8, self.fsm.sm_id) catch {
                    self.fail(engine.allocator, "alloc-failed");
                    return;
                };
                self.bound_jid = if (self.fsm.bound_jid) |bj| blk: {
                    const j = Jid{
                        .local = a.dupe(u8, bj.local) catch break :blk null,
                        .domain = a.dupe(u8, bj.domain) catch break :blk null,
                        .resource = a.dupe(u8, bj.resource) catch break :blk null,
                    };
                    if (j.local.len == 0 or j.domain.len == 0 or j.resource.len == 0) {
                        self.fail(engine.allocator, "alloc-failed");
                        return;
                    }
                    break :blk j;
                } else null;
                // 'h' counts stanzas handled since SM enablement. A resume
                // keeps counting from where the previous session left it
                // (resume_h); only a fresh .enabled starts at zero
                // (PR #4 review B: resetting h on resume wraps xmppd's
                // unacked queue into discardAll and silently loses mail).
                if (self.parser) |pr| {
                    pr.sm_stanza_count = if (self.fsm.sm_resumed) self.resume_h else 0;
                    pr.after_establishment = true;
                }
                // Outbound side (T-9BC4D065). Fresh enable: start an empty
                // unacked queue. Resume: drop the stanzas the server acked
                // via <resumed h=.../> and replay the rest before the
                // consumer sees .established, preserving order against any
                // stanza it sends next. Rejected resume (<failed/>): the
                // server discarded its side, so drop ours and say how many.
                if (self.sm_enabled) {
                    if (self.fsm.sm_resumed) {
                        if (engine.smReplayQueue(self.sm_id, self.fsm.sm_resumed_h)) |q| {
                            for (q.entries.items) |*e| {
                                self.queue(e.bytes) catch {
                                    self.fail(engine.allocator, "queue-error");
                                    return;
                                };
                                e.seq = q.next_seq;
                                q.next_seq +%= 1;
                            }
                            self.queue("<r xmlns='urn:xmpp:sm:3'/>") catch {
                                self.fail(engine.allocator, "queue-error");
                                return;
                            };
                            self.writeAfter(engine);
                        }
                    } else {
                        engine.smRegisterFresh(self.sm_id) catch {
                            self.fail(engine.allocator, "alloc-failed");
                            return;
                        };
                    }
                } else if (self.fsm.resume_id.len > 0) {
                    const dropped = engine.smDrop(self.fsm.resume_id);
                    if (dropped > 0) engine.dispatchEvent(self.handle, .{ .sm_failed = dropped });
                }
                engine.dispatchEvent(self.handle, .established);
            },
            .close => {
                // Prefer the protocol reason the FSM already recorded
                // (stream error condition, SASL failure) — failing with a
                // bare "stream-closed" hides the actual error from callers.
                if (self.fsm.failure_reason.len > 0)
                    self.fail(engine.allocator, self.fsm.failure_reason)
                else
                    self.fail(engine.allocator, "stream-closed");
            },
            else => self.executeAction(engine, action) catch |err|
                self.fail(engine.allocator, actionFailReason(err)),
        }
    }

    fn executeAction(self: *Session, engine: *Engine, action: stream.ClientAction) ActionError!void {
        switch (action) {
            .none, .established, .close => {}, // handled in handleAction
            .send_stream_open => {
                // Restart after TLS or auth: reset parser + reader state (the
                // server resets its own reader on both).
                const have_tls = self.tport != null and self.tport.?.isTls();
                if (have_tls or self.fsm.state == .awaiting_stream_header_auth) {
                    self.reader.reset();
                    if (self.parser) |pr| pr.reset();
                }
                self.queuef("<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='{s}' version='1.0'>", .{self.domain}) catch return error.QueueFailed;
                self.writeAfter(engine);
            },
            .send_starttls => {
                self.queue("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>") catch return error.QueueFailed;
                self.writeAfter(engine);
            },
            .send_sasl_auth => |mech| {
                try self.doSaslAuth(engine, mech);
                self.writeAfter(engine);
            },
            .send_sasl_response => try self.doSaslResponse(engine),
            .send_bind => {
                self.queuef("<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>{s}</resource></bind></iq>", .{self.resource}) catch return error.QueueFailed;
                self.writeAfter(engine);
            },
            .send_session => {
                self.queue("<iq type='set' id='sess1'><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>") catch return error.QueueFailed;
                self.writeAfter(engine);
            },
            .send_sm_enable => {
                // resume='true' so the server returns an SM id for reconnect.
                self.queue("<enable xmlns='urn:xmpp:sm:3' resume='true'/>") catch return error.QueueFailed;
                self.writeAfter(engine);
            },
            .send_sm_resume => {
                self.queuef("<resume xmlns='urn:xmpp:sm:3' previd='{s}' h='{d}'/>", .{ self.fsm.resume_id, self.resume_h }) catch return error.QueueFailed;
                self.writeAfter(engine);
            },
            .begin_tls => {
                const tp = if (self.tport) |*t| t else return error.TlsMissing;
                // T202 verification decision (before the handshake, since
                // the PKIX path must verify during it):
                //   dane_first + TLSA records  -> VERIFY_NONE ctx, manual
                //     TLSA match at completion (fail closed on mismatch);
                //   dane_first, no records   -> PKIX ctx (system CA) +
                //     hostname check on the stream domain;
                //   none                     -> lab path, no verification.
                const records = self.currentTlsa();
                const use_dane = self.tls_policy == .dane_first and records.len > 0;
                var sni_buf: [256]u8 = undefined;
                const sni = domainZ(&sni_buf, self.domain);
                const ctx = if (use_dane or self.tls_policy == .none)
                    engine.tls_ctx orelse return error.TlsNotConfigured
                else
                    engine.clientCaTlsContext() catch return error.TlsNotConfigured;
                self.mark(.tls_start);
                tp.upgradeToTls(ctx, sni) catch return error.TlsInitFailed;
                if (!use_dane and self.tls_policy != .none) {
                    const tc = tp.tlsConn() orelse return error.TlsMissing;
                    const host = sni orelse return error.TlsDomainTooLong;
                    tc.setHostname(host) catch return error.TlsInitFailed;
                }
                self.pending_dane = use_dane;
                self.tls_handshake = true;
                _ = self.onRead(engine) catch return error.TlsDriveFailed;
            },
        }
    }

    fn doSaslAuth(self: *Session, engine: *Engine, mech: []const u8) ActionError!void {
        const allocator = engine.allocator;
        const sc = allocator.create(saslmod.SaslClient) catch return error.SaslInitFailed;
        // SASL authcid is the bare localpart (RFC 6120 §6.2: the server
        // prepends its own domain); the full JID is only used after bind.
        const at = std.mem.indexOfScalar(u8, self.user, '@');
        const authcid = if (at) |i| self.user[0..i] else self.user;
        // gs2 flag (RFC 5802 §6): 'p' for a -PLUS mechanism (the FSM only
        // selects one when channel binding data exists), 'y' when the client
        // supports CB but the server advertised no -PLUS variant, else 'n'.
        var opts: saslmod.SaslClient.Options = .{};
        if (saslmod.SaslClient.isPlusMech(mech)) {
            if (!self.cb_mode.isPlus()) return error.SaslInitFailed;
            opts.cb_mode = self.cb_mode;
            opts.cb_data = &self.cb_data_buf;
        } else if (saslmod.SaslClient.hashOf(mech) != null and self.cb_mode.isPlus()) {
            opts.cb_mode = .unsupported_by_server;
        }
        // RFC 8265 OpaqueString prep (T-12C2E0C6): identical to the prep
        // StoredCredentials.derive applies at credential creation, so NFC /
        // space-mapped forms of the same password verify. Prep failure
        // (prohibited input) fails before anything is sent.
        var prep_cps: [3072]u21 = undefined;
        var prep_cccs: [3072]u8 = undefined;
        const prepped_cid = sasl.stringprep.prepareOpaqueString(authcid, &self.prep_authcid_buf, &prep_cps, &prep_cccs) catch {
            allocator.destroy(sc);
            return error.SaslInitFailed;
        };
        if (self.password.len > self.prep_password_buf.len / 2) {
            allocator.destroy(sc);
            return error.SaslInitFailed;
        }
        const prepped_pw = sasl.stringprep.prepareOpaqueString(self.password, &self.prep_password_buf, &prep_cps, &prep_cccs) catch {
            allocator.destroy(sc);
            return error.SaslInitFailed;
        };
        sc.* = saslmod.SaslClient.init(allocator, mech, prepped_cid, prepped_pw, opts) catch {
            allocator.destroy(sc);
            return error.SaslInitFailed;
        };
        self.sasl = sc;
        const raw = sc.initial() catch return error.SaslInitFailed;
        // Stack-scratch encoding (T-09BD8909: no heap per step).
        var enc_buf: [SASL_ENC_MAX]u8 = undefined;
        const b64 = b64encInto(&enc_buf, raw) catch return error.Base64Failed;
        self.queuef("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='{s}'>{s}</auth>", .{ mech, b64 }) catch return error.QueueFailed;
    }

    /// Drive one SASL <challenge/> answer. `.none` parks until <success>;
    /// a `.derive` step runs PBKDF2 on the engine's crypto worker (or its
    /// cache) and resumes in onSaslDerived.
    fn doSaslResponse(self: *Session, engine: *Engine) ActionError!void {
        const sc = self.sasl orelse return error.SaslNotActive;
        const pr = self.parser orelse return error.SaslNoParser;
        const raw = pr.saslChallengeRaw() orelse return error.SaslNoChallenge;
        const step = sc.handleChallenge(raw) catch return error.SaslChallengeFailed;
        switch (step) {
            .none => {},
            .message => |msg| try self.queueSaslResponse(engine, msg),
            .derive => |d| {
                const pw = sc.derivePassword() orelse return error.SaslNoPassword;
                if (engine.scramCached(pw, d.salt[0..d.salt_len], d.iterations, d.hash)) |salted| {
                    engine.scram_cache_hits += 1;
                    try self.finishSaslDerive(engine, salted);
                } else {
                    // Hi() runs on the engine's crypto worker; the
                    // exchange parks until onSaslDerived resumes it.
                    self.sasl_deriving = true;
                    engine.queueDerive(self.handle, pw, d.salt[0..d.salt_len], d.iterations, d.hash) catch {
                        self.sasl_deriving = false;
                        return error.SaslDeriveQueue;
                    };
                }
            },
        }
    }

    /// Queue one application stanza for delivery. Established streams only;
    /// stanzas queue through the same pinned-buffer/overflow path as the
    /// protocol FSM's own writes, flush immediately, and re-arm kqueue write
    /// interest when the kernel send buffer is full.
    ///
    /// With SM enabled the stanza is tracked in the engine's unacked queue
    /// (T-9BC4D065): acked entries drop on the server's <a h=.../>, the rest
    /// replays automatically after a successful <resumed/>. error.SmBacklog
    /// when the server has stopped acking (SM_UNACKED_MAX deep).
    pub fn sendStanza(self: *Session, stanza: []const u8) !void {
        if (self.phase != .established) return error.NotEstablished;
        if (self.sm_enabled) {
            const depth = try self.engine.smTrackSend(self.sm_id, stanza);
            // Nudge the server for an ack every 16 unacked stanzas so the
            // queue can't grow silently on a quiet peer.
            if (depth % 16 == 0) try self.queue("<r xmlns='urn:xmpp:sm:3'/>");
        }
        try self.queue(stanza);
        self.writeAfter(self.engine);
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

    /// Base64 + queue + flush one SASL <response> message.
    fn queueSaslResponse(self: *Session, engine: *Engine, msg: []const u8) ActionError!void {
        var enc_buf: [SASL_ENC_MAX]u8 = undefined;
        const b64 = b64encInto(&enc_buf, msg) catch return error.Base64Failed;
        self.queuef("<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{s}</response>", .{b64}) catch return error.QueueFailed;
        self.writeAfter(engine);
    }

    fn finishSaslDerive(self: *Session, engine: *Engine, salted_password: sasl.scram.SaltedPassword) ActionError!void {
        const sc = self.sasl orelse return error.SaslNotActive;
        const msg = sc.finishChallenge(salted_password) catch return error.SaslChallengeFailed;
        try self.queueSaslResponse(engine, msg);
    }

    /// Engine-thread callback from drainCryptoDone: the crypto worker
    /// finished this session's parked SaltedPassword derivation.
    pub fn onSaslDerived(self: *Session, engine: *Engine, salted_password: sasl.scram.SaltedPassword) void {
        if (!self.sasl_deriving) return; // stale completion (re-derive raced)
        self.sasl_deriving = false;
        self.finishSaslDerive(engine, salted_password) catch |err|
            self.fail(engine.allocator, actionFailReason(err));
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

test "establishment: allocator failure fails the session (T233)" {
    const a = std.testing.allocator;
    var engine = try Engine.init(a);
    defer engine.deinit();
    var s = try Session.init(a);
    s.engine = &engine;
    defer s.destroy(a);

    s.fsm.sm_enabled = true;
    s.fsm.sm_id = "sm-under-oom";
    s.fsm.sm_resumed = false;
    // The arena's copy of sm_id/bound_jid must fail the session, never
    // produce a silently empty identity (a resume keyed on "" replays
    // everything).
    s.arena_state.child_allocator = std.testing.failing_allocator;
    s.handleAction(&engine, .established);

    try std.testing.expect(s.isDead());
    try std.testing.expectEqualStrings("alloc-failed", s.fail_reason_buf[0..s.fail_reason_len]);
    try std.testing.expect(s.phase == .dead);
}
