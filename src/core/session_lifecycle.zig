//! # Session Lifecycle — accept, bind, close, offline delivery
//!
//! Manages session creation (accept), binding (resource assignment),
//! teardown (close + cleanup), and offline message delivery.
//! Extracted from server.zig as part of T51 decomposition.
//!
//! ## Entry Points
//!
//! - `acceptConnections` — drain pending connections from the listener
//! - `handleBind` — process resource bind and register in session map
//! - `closeSession` — full session teardown (MUC cleanup, presence, kqueue, dealloc)
//! - `deliverOfflineMessages` — deliver queued messages on presence available

const std = @import("std");
const xmpp = @import("xmpp");

const server_mod = @import("server.zig");
const Server = server_mod.Server;
const Session = server_mod.Session;
const sm_state = server_mod.sm_state;
const ChangeList = @import("event_loop.zig").ChangeList;
const muc_handler = @import("muc_handler.zig");
const presence_handler = @import("presence_handler.zig");
const lastact_store = @import("last_activity_store");

const log = std.log.scoped(.lifecycle);

/// Drain all pending connections from the listener socket.
pub fn acceptConnections(server: *Server, changes: *ChangeList) void {
    while (true) {
        const id = allocateId(server) orelse {
            log.warn("connection limit reached ({d})", .{server.max_sessions});
            break;
        };

        var conn = server.listener.accept(id) catch |err| {
            switch (err) {
                error.WouldBlock => break,
                else => {
                    log.err("accept failed: {}", .{err});
                    break;
                },
            }
        };

        const session = server.allocator.create(Session) catch {
            log.err("out of memory for session", .{});
            conn.close();
            break;
        };
        session.* = Session.init(conn.fd, id, server.server_host, server.listener.direct_tls, server.allocator);
        // Random seed decorrelates the auth-IPC generation from session slot
        // reuse: a recycled conn.id previously restarted at gen 0, aliasing
        // any aborted zombie exchange the auth daemon still held (T32).
        session.auth_ipc_gen = std.crypto.random.int(u16);
        session.conn = conn;
        server.sessions[id] = session;

        changes.addRead(conn.fd, id) catch {
            log.err("changelist full on accept", .{});
            session.deinit();
            server.allocator.destroy(session);
            server.sessions[id] = null;
            break;
        };

        log.info("accepted connection id={d} fd={d}", .{ id, conn.fd });
    }
}

/// Process resource bind and register session in the unified session map.
///
/// T152: if the JID/resource is already bound (e.g. a stale session left over
/// from an unclean disconnect), evict the old resource per RFC 6120 §7.7.3
/// ("the server MAY terminate the old session in favor of the new") rather
/// than silently leaving the new (already-acknowledged-to-the-client) bind
/// unregistered in the session map.
///
/// T198: the session-map registration happens BEFORE the success IQ is sent.
/// On failure the client now gets a real answer — stanza error
/// resource-constraint when the account is over its resource cap (stream
/// stays open; the client may retry with a different resource), conflict
/// stream error when a cross-worker eviction is impossible (T154).
/// Returns `false` if the session was destroyed as part of handling the bind
/// (e.g. an unrecoverable AlreadyBound conflict) — callers MUST NOT touch
/// `session` again if this returns false.
pub fn handleBind(server: *Server, session: *Session, resource: []const u8, changes: *ChangeList) bool {
    // Only resource-binding happens through this path; anything else keeps
    // the original stream-state-machine behavior.
    if (session.stream.state != .features_bind) {
        const action = session.stream.handleBind(resource);
        server.executeAction(session, action);
        return true;
    }

    const sm = server.session_map orelse {
        log.err("connection {d} bind failed: session_map not configured", .{session.conn.id});
        return true;
    };

    // The stream FSM applies the same defaulting rule; do the sm work first.
    const eff_resource: []const u8 = if (resource.len > 0) resource else "default";
    const local = session.stream.authenticated_jid orelse {
        const action = session.stream.handleBind(resource);
        server.executeAction(session, action);
        return true;
    };

    if (sm.bind(server.worker_id, @intCast(session.conn.id), local.local, local.domain, eff_resource)) |_| {
        const action = session.stream.handleBind(eff_resource);
        server.executeAction(session, action);
        log.info("connection {d} session established: {s}@{s}/{s}", .{
            session.conn.id, local.local, local.domain, eff_resource,
        });
        return true;
    } else |err| {
        if (err == error.AlreadyBound) {
            // T154: entry lives on ANOTHER worker — cannot touch that session
            // locally. Ask the holder to destroy it (session_kick); the bind
            // completes in completeBindAfterKick when the reply lands. The
            // client waits bind-pending until then.
            const existing = sm.findByFullJid(local.local, local.domain, eff_resource);
            if (existing != null and existing.?.worker_id != server.worker_id) {
                if (!server.startSessionKick(session, local.local, local.domain, eff_resource, existing.?.worker_id, changes)) {
                    log.err("connection {d} session_map bind failed: resource held by another worker, kick unavailable", .{session.conn.id});
                    server.sendStreamError(session, .conflict);
                    forceCloseSession(server, session.conn.id, changes);
                    return false;
                }
                return true;
            }

            // local (or vanished) entry — the T152 in-worker eviction path
            if (evictStaleResource(server, sm, local.local, local.domain, eff_resource, changes)) {
                _ = sm.bind(server.worker_id, @intCast(session.conn.id), local.local, local.domain, eff_resource) catch |err2| {
                    log.err("connection {d} session_map bind failed after eviction: {}", .{ session.conn.id, err2 });
                    server.sendStreamError(session, .conflict);
                    forceCloseSession(server, session.conn.id, changes);
                    return false;
                };
                const action = session.stream.handleBind(eff_resource);
                server.executeAction(session, action);
                log.info("connection {d} session established (evicted stale resource): {s}@{s}/{s}", .{
                    session.conn.id, local.local, local.domain, eff_resource,
                });
                return true;
            }

            // Eviction found nothing local that we could close (entry vanished
            // between findByFullJid and evict attempt): retry path handled none
            // of this — close with conflict rather than desync the client.
            log.err("connection {d} session_map bind failed: entry raced away", .{session.conn.id});
            server.sendStreamError(session, .conflict);
            forceCloseSession(server, session.conn.id, changes);
            return false;
        }

        // T198: capacity/other registration failure — answer the bind IQ with
        // a stanza error; do NOT mark the stream active. The client sees the
        // failure instead of believing it holds an unregistered binding, and
        // may retry with another resource.
        log.err("connection {d} bind rejected for {s}@{s}/{s}: {}", .{
            session.conn.id, local.local, local.domain, eff_resource, err,
        });
        sendBindRejected(session);
        return true;
    }
}

/// Stanza-level rejection of a resource bind (T198). Stream stays open.
fn sendBindRejected(session: *Session) void {
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    w.writeAll("<iq type='error'") catch return;
    if (session.bind_iq_id.len > 0) {
        w.writeAll(" id='") catch return;
        w.writeAll(session.bind_iq_id) catch return;
        w.writeByte('\'') catch return;
    }
    w.writeAll("><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>" ++
        "<error type='cancel'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>" ++
        "</error></iq>") catch return;
    session.conn.queueSend(fbs.getWritten()) catch return;
}

/// T154: the session_kick reply arrived — the full JID is free now. Retry
/// the parked bind; if yet another worker won meanwhile, kick again up to
/// the round cap, then give up with conflict.
pub fn completeBindAfterKick(server: *Server, session: *Session, changes: *ChangeList) void {
    const resource = session.bind_kick_resource_buf[0..session.bind_kick_resource_len];
    const local = session.stream.authenticated_jid orelse return;
    const sm = server.session_map orelse return;

    const bind_and_finish = struct {
        fn run(srv: *Server, sess: *Session, res: []const u8, changes_: *ChangeList) void {
            const action = sess.stream.handleBind(res);
            srv.executeAction(sess, action);
            log.info("connection {d} session established (kicked remote resource)", .{sess.conn.id});
            if (sess.conn.hasPendingWrite()) {
                _ = sess.conn.flushSend() catch {};
                if (sess.conn.hasPendingWrite()) {
                    changes_.addWrite(sess.conn.fd, sess.conn.id) catch {};
                }
            }
            // Answered — the id's job is done.
            sess.bind_iq_id = "";
            sess.bind_iq_id_len = 0;
        }
    }.run;

    if (sm.bind(server.worker_id, @intCast(session.conn.id), local.local, local.domain, resource)) |_| {
        bind_and_finish(server, session, resource, changes);
        return;
    } else |err| {
        if (err == error.AlreadyBound and session.bind_kick_rounds < MAX_BIND_KICK_ROUNDS) {
            if (sm.findByFullJid(local.local, local.domain, resource)) |entry| {
                if (entry.worker_id != server.worker_id and
                    server.startSessionKick(session, local.local, local.domain, resource, entry.worker_id, changes))
                {
                    return; // parked again — id intentionally survives
                }
                if (entry.worker_id == server.worker_id and evictStaleResource(server, sm, local.local, local.domain, resource, changes)) {
                    if (sm.bind(server.worker_id, @intCast(session.conn.id), local.local, local.domain, resource)) |_| {
                        bind_and_finish(server, session, resource, changes);
                        return;
                    } else |_| {}
                }
            }
        }
        log.err("connection {d} bind after kick failed: {} (rounds={d})", .{ session.conn.id, err, session.bind_kick_rounds });
        if (err == error.AlreadyBound) {
            server.sendStreamError(session, .conflict);
            forceCloseSession(server, session.conn.id, changes);
            return;
        }
        sendBindRejected(session);
        session.bind_iq_id = "";
        session.bind_iq_id_len = 0;
        if (session.conn.hasPendingWrite()) {
            changes.addWrite(session.conn.fd, session.conn.id) catch {};
        }
    }
}

/// Max cross-worker kick rounds per bind attempt. Each round requires a real
/// registration by somebody in between, but cap anyway — two live takers can
/// otherwise ping-pong a JID indefinitely.
pub const MAX_BIND_KICK_ROUNDS: u8 = 3;

/// Evict a stale same-worker session occupying the target full JID so a new
/// bind can take its place. Returns true if eviction happened locally (the
/// caller should retry the bind), false if the entry belongs to another
/// worker (cannot be safely evicted from here).
fn evictStaleResource(
    server: *Server,
    sm: *@import("session_map").SessionMap,
    local: []const u8,
    domain: []const u8,
    resource: []const u8,
    changes: *ChangeList,
) bool {
    const entry = sm.findByFullJid(local, domain, resource) orelse return false;
    if (entry.worker_id != server.worker_id) return false;

    const old_id: usize = @intCast(entry.local_session_id);
    const old_session = server.sessions[old_id] orelse {
        // Entry is stale but the slot is already empty — just unbind and retry.
        _ = sm.unbind(local, domain, resource);
        return true;
    };

    log.warn("evicting stale resource {s}@{s}/{s} (old session {d}) for new bind", .{
        local, domain, resource, old_id,
    });
    server.sendStreamError(old_session, .conflict);
    old_session.conn.flushSync(); // deliver the conflict before teardown closes the fd
    forceCloseSession(server, old_id, changes);
    return true;
}

/// Session close: either detach for SM resume or full teardown.
///
/// If the session has SM resume enabled and is not already detached, the session
/// is "detached" — connection resources are freed but the session state is preserved
/// for potential reconnection within the resume timeout window.
///
/// Otherwise, performs full teardown: MUC cleanup, presence broadcast, session map
/// unbind, kqueue deregistration, and memory deallocation.
pub fn closeSession(server: *Server, id: usize, changes: *ChangeList) void {
    const session = server.sessions[id] orelse return;

    // Detach for SM resume if eligible (resume enabled, not already detached, not closing gracefully)
    if (session.sm_resume_enabled and !session.sm_detached and session.stream.isActive()) {
        abortAuthIfInFlight(server, session, changes);
        detachSession(server, id, session, changes);
        return;
    }

    abortAuthIfInFlight(server, session, changes);
    destroySession(server, id, session, changes);
}

/// Force-close a session without SM resume consideration.
/// Used for intentional closes (stream close, protocol errors) where detach is inappropriate.
pub fn forceCloseSession(server: *Server, id: usize, changes: *ChangeList) void {
    const session = server.sessions[id] orelse return;
    abortAuthIfInFlight(server, session, changes);
    session.sm_resume_enabled = false; // Prevent detach
    destroySession(server, id, session, changes);
}

/// Release the auth daemon's per-connection state when a session dies
/// mid-exchange. Without this the SCRAM slot lingers until the stale sweep,
/// and a conn.id reused inside that window aliases the zombie exchange —
/// observed as not-authorized storms under churn (T32).
fn abortAuthIfInFlight(server: *Server, session: *Session, changes: *ChangeList) void {
    if (session.auth_state == .none) return;
    session.auth_state = .none;
    if (!server.ipc.connected) return;
    server.ipc.send(.{ .auth_abort = .{ .conn_id = session.ipcConnId() } }) catch return;
    if (server.ipc.hasPendingSend()) {
        changes.addWrite(server.ipc.fd, server_mod.IPC_AUTH_UDATA) catch {};
    }
}

/// Detach a session for SM resume: free connection resources, preserve session state.
/// The session remains in sessions[] and session_map for the resume timeout period.
fn detachSession(server: *Server, id: usize, session: *Session, changes: *ChangeList) void {
    session.sm_detached = true;
    server.detached_count += 1;
    server.smIdMapInsert(session.sm_id[0..session.sm_id_len], id);
    session.sm_detach_time = std.time.timestamp();

    // Remove from kqueue and close the fd
    changes.removeRead(session.conn.fd) catch {};
    changes.removeWrite(session.conn.fd) catch {};
    session.conn.close();

    log.info("session {d} detached for SM resume (id={s}, timeout={d}s)", .{
        id,
        session.sm_id[0..session.sm_id_len],
        sm_state.DEFAULT_RESUME_TIMEOUT,
    });
}

/// Full session teardown: MUC cleanup, presence broadcast, session map unbind,
/// kqueue deregistration, and memory deallocation.
fn destroySession(server: *Server, id: usize, session: *Session, changes: *ChangeList) void {
    if (session.sm_detached and server.detached_count > 0) {
        server.detached_count -= 1;
        server.smIdMapRemove(session.sm_id[0..session.sm_id_len]);
    }

    // Remove from all MUC rooms (broadcasts unavailable to room occupants)
    if (session.stream.bound_jid) |bound| {
        var close_jid_buf: [256]u8 = undefined;
        var close_jid_fbs = std.io.fixedBufferStream(&close_jid_buf);
        const cw = close_jid_fbs.writer();
        cw.writeAll(bound.local) catch {};
        cw.writeByte('@') catch {};
        cw.writeAll(bound.domain) catch {};
        cw.writeByte('/') catch {};
        cw.writeAll(bound.resource) catch {};
        muc_handler.handleSessionClose(server, close_jid_fbs.getWritten(), changes);
    }

    // Unregister from session map and broadcast unavailable presence
    if (session.stream.bound_jid) |bound| {
        if (server.session_map) |sm| {
            const removed = sm.unbind(bound.local, bound.domain, bound.resource);
            if (removed) |entry| {
                if (entry.presence_available) {
                    presence_handler.broadcastUnavailable(server, bound.local, bound.domain, bound.resource, changes);
                }
            }
            // T164: when the account's last resource tears down, record when it
            // went offline (XEP-0012). Written to the shared op DB so any
            // worker answers last-activity without cross-worker routing.
            var probe_buf: [1]@import("session_map").SessionEntry = undefined;
            if (sm.findByBareJid(bound.local, bound.domain, &probe_buf) == 0) {
                if (server.roster) |roster| {
                    recordLastOffline(roster, bound);
                }
            }
        }
    }

    // Remove from kqueue (closing fd does this implicitly, but be explicit)
    if (!session.conn.isClosed()) {
        changes.removeRead(session.conn.fd) catch {};
        changes.removeWrite(session.conn.fd) catch {};
    }

    session.deinit();
    server.allocator.destroy(session);
    server.sessions[id] = null;

    // Return ID to free-list (T128)
    server.free_ids[server.free_count] = id;
    server.free_count += 1;
}

/// T164: write the account's last-offline timestamp after its final resource
/// unbound (best-effort; on error the next teardown retries).
fn recordLastOffline(roster: anytype, bound: anytype) void {
    var bare_buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&bare_buf);
    fbs.writer().writeAll(bound.local) catch return;
    fbs.writer().writeByte('@') catch return;
    fbs.writer().writeAll(bound.domain) catch return;
    const now: u64 = @intCast(@max(std.time.timestamp(), 0));
    lastact_store.record(roster.backend, fbs.getWritten(), now) catch |err| {
        log.warn("last-activity record failed for {s}@{s}: {}", .{ bound.local, bound.domain, err });
    };
}

/// Reap sessions whose SM unacked queue overflowed (T178). XEP-0198 has no
/// gap signaling, so silently evicting the oldest stanza would break the
/// at-least-once promise invisibly — fail the session instead, like
/// ejabberd/Prosody:
/// - Live session: close the stream with resource-constraint; the client
///   reconnects and resyncs (MAM covers message history).
/// - Detached session: destroy it via the normal path (which also emits the
///   unavailable-presence broadcast — correct semantics for a session that
///   is really gone). A later <resume/> then fails with item-not-found and
///   the client does a full bind + MAM catch-up.
/// Called once per event batch from the worker event loop. Destroying is
/// self-limiting: the queue is freed with the session, so this fires once.
pub fn reapSmOverflow(server: *Server, changes: *ChangeList) void {
    for (server.sessions, 0..) |slot, i| {
        const session = slot orelse continue;
        if (!session.sm_overflow) continue;
        session.sm_overflow = false;
        if (session.sm_detached) {
            log.warn("session {d} SM unacked queue overflowed while detached — destroying (resume will fail item-not-found)", .{i});
            session.sm_resume_enabled = false; // Prevent re-detach
            destroySession(server, i, session, changes);
        } else {
            log.warn("connection {d} SM unacked queue overflowed — closing stream (resource-constraint)", .{i});
            server.sendStreamError(session, .resource_constraint);
            // Flush the stream error before teardown so the client sees it.
            session.conn.flushSync();
            forceCloseSession(server, i, changes);
        }
    }
}

/// Sweep detached sessions that have exceeded the resume timeout.
/// Called periodically from the event loop (e.g., every 30 seconds via timer).
pub fn expireDetachedSessions(server: *Server, changes: *ChangeList) void {
    if (server.detached_count == 0) return;
    const now = std.time.timestamp();
    for (server.sessions, 0..) |slot, i| {
        const session = slot orelse continue;
        if (!session.sm_detached) continue;
        const elapsed = now - session.sm_detach_time;
        if (elapsed >= sm_state.DEFAULT_RESUME_TIMEOUT) {
            log.info("session {d} SM resume expired (id={s}, elapsed={d}s)", .{
                i,
                session.sm_id[0..session.sm_id_len],
                elapsed,
            });
            session.sm_resume_enabled = false; // Prevent re-detach
            destroySession(server, i, session, changes);
        }
    }
}

/// Deliver queued offline messages to a user who just became available.
pub fn deliverOfflineMessages(server: *Server, session: *Session, local: []const u8, domain: []const u8, changes: *ChangeList) void {
    const store = server.offline orelse return;
    const archive = server.archive orelse return;

    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(domain) catch return;
    const bare_jid = bare_fbs.getWritten();

    const count = store.countMessages(bare_jid) catch return;
    if (count == 0) return;

    const pointers = store.getPointers(bare_jid) catch return;
    defer store.freePointers(pointers);

    var delivered: usize = 0;
    for (pointers) |ptr| {
        const stanza_xml = archive.getMessage(ptr.recipient, ptr.timestamp, ptr.stanza_id) catch continue;
        if (stanza_xml) |xml_data| {
            defer server.allocator.free(xml_data);
            session.conn.queueSend(xml_data) catch continue;
            delivered += 1;
        }
    }

    if (session.conn.hasPendingWrite()) {
        changes.addWrite(session.conn.fd, session.conn.id) catch {};
    }

    store.clearAll(bare_jid) catch {};
    log.info("delivered {d} offline messages to {s}", .{ delivered, bare_jid });
}

/// Allocate a free session ID slot. O(1) via free-list stack (T128).
fn allocateId(server: *Server) ?usize {
    if (server.free_count == 0) return null;
    server.free_count -= 1;
    return server.free_ids[server.free_count];
}

// ============================================================================
// Tests
// ============================================================================

const posix = std.posix;
const ChangeListT = @import("event_loop.zig").ChangeList;
const SessionMap = @import("session_map").SessionMap;
const xmpp_lib = @import("xmpp");

fn testSocketPair() ![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    return fds;
}

/// Puts a session's stream into an authenticated, features_bind-ready state
/// without going through the full STARTTLS/SASL negotiation, for test setup.
fn makeAuthenticatedSession(server: *Server, id: usize, local: []const u8) !*Session {
    const fds = try testSocketPair();
    posix.close(fds[1]); // unused peer end, avoid leaking fds across test cases
    const session = try server.allocator.create(Session);
    session.* = Session.init(fds[0], @intCast(id), server.server_host, false, server.allocator);
    session.stream.state = .features_bind;
    session.stream.authenticated = true;
    session.stream.authenticated_jid = xmpp_lib.Jid{ .local = local, .domain = server.server_host };
    server.sessions[id] = session;
    return session;
}

// T158 regression test: SM detach timer (300s) must expire sessions correctly —
// not early (which would kill resumable sessions) and not late/never (memory leak).
test "T158: detach timer expires sessions at 300s, not before" {
    const allocator = std.testing.allocator;
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeListT.init(&change_buf);

    const now = std.time.timestamp();

    // Session 1: detached 301 seconds ago — MUST be expired
    const s1 = try makeAuthenticatedSession(&server, 1, "alice");
    s1.sm_resume_enabled = true;
    s1.sm_detached = true;
    s1.sm_detach_time = now - 301;
    s1.sm_id_len = sm_state.SM_ID_HEX_LEN;
    const id1 = "aaaa1111bbbb2222cccc3333dddd4444";
    @memcpy(&s1.sm_id, id1);
    server.detached_count = 2;
    server.smIdMapInsert(&s1.sm_id, 1);

    // Session 2: detached only 10 seconds ago — MUST NOT be expired
    const s2 = try makeAuthenticatedSession(&server, 2, "bob");
    s2.sm_resume_enabled = true;
    s2.sm_detached = true;
    s2.sm_detach_time = now - 10;
    s2.sm_id_len = sm_state.SM_ID_HEX_LEN;
    const id2 = "eeee5555ffff6666aaaa7777bbbb8888";
    @memcpy(&s2.sm_id, id2);
    server.smIdMapInsert(&s2.sm_id, 2);

    // Mark slots 1 and 2 as consumed from the free list (tests bypass normal alloc)
    server.free_count -= 2;

    // Run expiry sweep
    expireDetachedSessions(&server, &changes);

    // Session 1 must be destroyed (expired)
    try std.testing.expect(server.sessions[1] == null);

    // Session 2 must still be alive (not expired)
    try std.testing.expect(server.sessions[2] != null);
    try std.testing.expect(server.sessions[2].?.sm_detached);

    // Detached count must reflect only the surviving session
    try std.testing.expectEqual(@as(u16, 1), server.detached_count);

    // Clean up session 2 manually to avoid allocator leak
    server.sessions[2].?.sm_resume_enabled = false;
    destroySession(&server, 2, server.sessions[2].?, &changes);
}

test "T158: detach timer does not expire session at exactly 299s" {
    const allocator = std.testing.allocator;
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeListT.init(&change_buf);

    const now = std.time.timestamp();

    // Session detached 299 seconds ago — must NOT be expired (boundary check)
    const s1 = try makeAuthenticatedSession(&server, 1, "carol");
    s1.sm_resume_enabled = true;
    s1.sm_detached = true;
    s1.sm_detach_time = now - 299;
    s1.sm_id_len = sm_state.SM_ID_HEX_LEN;
    const id1 = "cccc3333dddd4444eeee5555ffff6666";
    @memcpy(&s1.sm_id, id1);
    server.detached_count = 1;
    server.smIdMapInsert(&s1.sm_id, 1);
    server.free_count -= 1;

    expireDetachedSessions(&server, &changes);

    // Session must survive — 299 < 300 (DEFAULT_RESUME_TIMEOUT)
    try std.testing.expect(server.sessions[1] != null);
    try std.testing.expect(server.sessions[1].?.sm_detached);
    try std.testing.expectEqual(@as(u16, 1), server.detached_count);

    // Clean up
    server.sessions[1].?.sm_resume_enabled = false;
    destroySession(&server, 1, server.sessions[1].?, &changes);
}

test "T158: detach timer expires session at exactly 300s" {
    const allocator = std.testing.allocator;
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeListT.init(&change_buf);

    const now = std.time.timestamp();

    // Session detached exactly 300 seconds ago — MUST be expired (>= comparison)
    const s1 = try makeAuthenticatedSession(&server, 1, "dave");
    s1.sm_resume_enabled = true;
    s1.sm_detached = true;
    s1.sm_detach_time = now - 300;
    s1.sm_id_len = sm_state.SM_ID_HEX_LEN;
    const id1 = "dddd4444eeee5555ffff6666aaaa7777";
    @memcpy(&s1.sm_id, id1);
    server.detached_count = 1;
    server.smIdMapInsert(&s1.sm_id, 1);
    server.free_count -= 1;

    expireDetachedSessions(&server, &changes);

    // Session must be destroyed — 300 >= 300 (exact boundary)
    try std.testing.expect(server.sessions[1] == null);
    try std.testing.expectEqual(@as(u16, 0), server.detached_count);
}

// T152 regression test: a stale (already-bound) resource must be evicted so
// the new connection is actually registered in the session map, instead of
// silently leaving the client believing it's bound while unroutable.
test "T152: rebind with same resource evicts stale session" {
    const allocator = std.testing.allocator;
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();

    var sm = SessionMap.init(allocator, false, 0);
    defer sm.deinit();
    server.session_map = &sm;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeListT.init(&change_buf);

    // First connection binds resource "phone".
    const session1 = try makeAuthenticatedSession(&server, 1, "alice");
    const alive1 = handleBind(&server, session1, "phone", &changes);
    try std.testing.expect(alive1);
    try std.testing.expect(server.sessions[1] != null);
    const entry1 = sm.findByFullJid("alice", "localhost", "phone").?;
    try std.testing.expectEqual(@as(u32, 1), entry1.local_session_id);

    // Second connection (same worker) binds the SAME resource — simulates a
    // reconnect racing ahead of the old session's cleanup.
    const session2 = try makeAuthenticatedSession(&server, 2, "alice");
    const alive2 = handleBind(&server, session2, "phone", &changes);
    try std.testing.expect(alive2);

    // The old session must have been evicted (force-closed, slot freed)...
    try std.testing.expect(server.sessions[1] == null);

    // ...and the session map must now point at the NEW session, not be left
    // stale or unregistered.
    const entry2 = sm.findByFullJid("alice", "localhost", "phone").?;
    try std.testing.expectEqual(@as(u32, 2), entry2.local_session_id);
}
