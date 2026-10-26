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
const xml = @import("xml");
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
            releaseId(server, id);
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
            releaseId(server, id);
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
            releaseId(server, id);
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
        server.executeAction(session, action, changes);
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
        server.executeAction(session, action, changes);
        return true;
    };

    if (sm.bind(server.worker_id, @intCast(session.conn.id), local.local, local.domain, eff_resource)) |_| {
        const action = session.stream.handleBind(eff_resource);
        server.executeAction(session, action, changes);
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
                server.executeAction(session, action, changes);
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
        xml.escapeWrite(w, session.bind_iq_id) catch return;
        w.writeByte('\'') catch return;
    }
    w.writeAll("><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>" ++
        "<error type='cancel'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>" ++
        "</error></iq>") catch return;
    session.queueSendStanza(fbs.getWritten()) catch return;
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
            srv.executeAction(sess, action, changes_);
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
        abortAuthIfInFlight(server, session);
        detachSession(server, id, session, changes);
        return;
    }

    abortAuthIfInFlight(server, session);
    destroySession(server, id, session, changes);
}

/// Force-close a session without SM resume consideration.
/// Used for intentional closes (stream close, protocol errors) where detach is inappropriate.
pub fn forceCloseSession(server: *Server, id: usize, changes: *ChangeList) void {
    const session = server.sessions[id] orelse return;
    abortAuthIfInFlight(server, session);
    session.sm_resume_enabled = false; // Prevent detach
    destroySession(server, id, session, changes);
}

/// Release the auth daemon's per-connection state when a session dies
/// mid-exchange. Without this the SCRAM slot lingers until the stale sweep,
/// and a conn.id reused inside that window aliases the zombie exchange —
/// observed as not-authorized storms under churn (T32).
fn abortAuthIfInFlight(server: *Server, session: *Session) void {
    if (session.auth_state == .none) return;
    session.auth_state = .none;
    if (!server.ipc.connected) return;
    server.ipc.send(.{ .auth_abort = .{ .conn_id = session.ipcConnId() } }) catch return;
    // Write interest is armed by reconcileIpcWriteInterest, once per loop
    // iteration (S10). Arming here would leave a persistent filter with
    // ipc_write_armed still false, so nothing would ever remove it.
}

/// Detach a session for SM resume: free connection resources, preserve session state.
/// The session remains in sessions[] and session_map for the resume timeout period.
fn detachSession(server: *Server, id: usize, session: *Session, changes: *ChangeList) void {
    session.sm_detached = true;
    server.detached_count += 1;
    server.smIdMapInsert(session.sm_id[0..session.sm_id_len], id);
    session.sm_detach_time = std.time.timestamp();

    // Remove from kqueue and close the fd. Purge instead of staging deletes:
    // close(2) drops the knotes, and a staged delete/add for this number
    // could otherwise land on a connection that reuses the fd this same
    // iteration (T238).
    changes.purgeFd(session.conn.fd);
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

    cancelOfflineRetryTimer(session, changes);

    // Drop any staged kqueue entries for this fd even when already closed:
    // close(2) drops the kernel-side knotes; the staged ones would hit
    // whichever connection reuses the fd number in this iteration (T238).
    changes.purgeFd(session.conn.fd);

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

/// Reap sessions whose outbound delivery overflowed. Such a gap must not be
/// left for the client to discover as inconsistent stream or room state.
/// Live sessions close with resource-constraint so they reconnect and resync.
/// Detached sessions are destroyed; a later resume fails with item-not-found
/// and the client performs a full bind and MAM catch-up.
/// Called once per event batch from the worker event loop.
pub fn reapOutboundOverflow(server: *Server, changes: *ChangeList) void {
    for (server.sessions, 0..) |slot, i| {
        const session = slot orelse continue;
        if (!session.sm_overflow) continue;
        session.sm_overflow = false;
        if (session.sm_detached) {
            log.warn("session {d} outbound queue overflowed while detached: destroying (resume will fail item-not-found)", .{i});
            session.sm_resume_enabled = false; // Prevent re-detach
            destroySession(server, i, session, changes);
        } else {
            log.warn("connection {d} outbound queue overflowed: closing stream (resource-constraint)", .{i});
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

    const pointers = store.getPointers(bare_jid) catch |err| {
        stallOnStoreError(server, session, bare_jid, err, changes);
        return;
    };
    defer store.freePointers(pointers);

    var delivered: usize = 0;
    var completed = true;
    for (pointers) |ptr| {
        // The held copy comes first. A message parked behind a draining tail
        // (S13) points at an archive row that the async writer queue may not
        // have committed yet, and reading the archive alone would see a
        // dangling pointer and destroy a stanza that is still on its way.
        var stanza_xml = store.getHeldStanza(ptr) catch |err| {
            log.warn("offline delivery to {s} stalled: getHeldStanza failed: {s}", .{ bare_jid, @errorName(err) });
            stallOnStoreError(server, session, bare_jid, err, changes);
            return;
        };
        if (stanza_xml == null) {
            stanza_xml = archive.getMessage(ptr.recipient, ptr.timestamp, ptr.stanza_id) catch |err| {
                // Transient store failure: stop the drain and retry. Continuing
                // would deliver later messages ahead of this one, and skipping
                // it would retry the same pointer on every pass forever.
                log.warn("offline delivery to {s} stalled: getMessage failed: {s}", .{ bare_jid, @errorName(err) });
                stallOnStoreError(server, session, bare_jid, err, changes);
                return;
            };
        }
        if (stanza_xml) |xml_data| {
            defer server.allocator.free(xml_data);
            session.queueSendStanza(xml_data) catch {
                // Send buffer full: stop here and let the writable handler
                // drain the tail at the low-water mark. This message and the
                // rest stay in the store, so nothing is lost.
                log.warn("offline delivery to {s} paused at {d}/{d} messages (send buffer full)", .{ bare_jid, delivered, pointers.len });
                session.offline_pending = true;
                session.offline_store_stalls = 0;
                completed = false;
                break;
            };
            // Only delete what was actually handed to the connection.
            store.deletePointer(ptr) catch |err| {
                log.warn("offline pointer delete failed for {s}: {s}", .{ bare_jid, @errorName(err) });
            };
            delivered += 1;
        } else {
            // Neither copy exists: the archive entry is genuinely gone. A
            // dangling pointer would stall every future drain, so drop it.
            store.deletePointer(ptr) catch |err| {
                log.warn("offline pointer delete failed for {s}: {s}", .{ bare_jid, @errorName(err) });
            };
        }
    }

    if (completed) {
        cancelOfflineRetryTimer(session, changes);
        session.offline_pending = false;
        session.offline_store_stalls = 0;
    }

    if (session.conn.hasPendingWrite()) {
        changes.addWrite(session.conn.fd, session.conn.id) catch {};
    }

    log.info("delivered {d} offline messages to {s}", .{ delivered, bare_jid });
}

/// Bounded prompt retries for an offline drain stalled on a store error.
/// Beyond this a one-shot deadline retries without scanning other sessions.
const OFFLINE_STALL_RETRY_MAX: u8 = 8;
pub const OFFLINE_RETRY_DELAY_MS: u32 = 5_000;

/// Mark the drain stalled after a store error and make sure something will
/// retry it. A buffer-full stall leaves data in the write buffer, so
/// EVFILT_WRITE fires again; a store error with an empty buffer leaves
/// nothing armed and the tail would sit undelivered until the next presence
/// stanza or reconnect.
fn stallOnStoreError(
    server: *Server,
    session: *Session,
    bare_jid: []const u8,
    err: anyerror,
    changes: *ChangeList,
) void {
    session.offline_pending = true;
    if (session.offline_store_stalls < std.math.maxInt(u8)) {
        session.offline_store_stalls += 1;
    }
    if (session.conn.hasPendingWrite()) {
        changes.addWrite(session.conn.fd, session.conn.id) catch |stage_err| {
            server.offline_retry_sweep_needed = true;
            log.warn("offline retry write arm for {s} failed: {s}; using the fallback sweep", .{ bare_jid, @errorName(stage_err) });
        };
        return;
    }
    if (session.offline_store_stalls > OFFLINE_STALL_RETRY_MAX) {
        if (!session.offline_retry_timer_armed) {
            changes.addTimer(session.conn.id, OFFLINE_RETRY_DELAY_MS, true) catch |stage_err| {
                server.offline_retry_sweep_needed = true;
                log.warn("offline retry timer for {s} failed: {s}; using the fallback sweep", .{ bare_jid, @errorName(stage_err) });
                return;
            };
            session.offline_retry_timer_armed = true;
        }
        log.warn("offline delivery to {s} stalled {d} times on {s}; retrying in {d}ms", .{
            bare_jid, session.offline_store_stalls, @errorName(err), OFFLINE_RETRY_DELAY_MS,
        });
        return;
    }
    // One-shot so the retry is a single prompt attempt, not a level-triggered
    // wake that fires on every loop pass while the store stays broken.
    changes.addWriteOnce(session.conn.fd, session.conn.id) catch |stage_err| {
        server.offline_retry_sweep_needed = true;
        log.warn("offline prompt retry for {s} failed: {s}; using the fallback sweep", .{ bare_jid, @errorName(stage_err) });
    };
}

fn cancelOfflineRetryTimer(session: *Session, changes: *ChangeList) void {
    if (!session.offline_retry_timer_armed) return;
    session.offline_retry_timer_armed = false;
    changes.removeTimer(session.conn.id) catch |err| {
        log.warn("offline retry timer cancel for session {d} failed: {s}", .{ session.conn.id, @errorName(err) });
    };
}

/// Fire one session's offline retry. The armed flag rejects stale timers after
/// teardown or session-slot reuse; a one-shot timer is already removed by kqueue.
pub fn retryOfflineDrain(server: *Server, id: usize, changes: *ChangeList) void {
    if (id >= server.sessions.len) return;
    const session = server.sessions[id] orelse return;
    if (!session.offline_retry_timer_armed) return;
    session.offline_retry_timer_armed = false;
    if (!session.offline_pending) return;
    if (session.offline_store_stalls == 0) return;
    if (session.conn.isClosed()) return;
    session.offline_store_stalls = 0;
    drainOfflinePending(server, session, changes);
}

/// Fallback for retry events that could not be staged. Normal retries use
/// per-session timers, so the periodic event returns without scanning slots.
pub fn retryStalledOfflineDrains(server: *Server, changes: *ChangeList) void {
    if (server.offline == null) return;
    if (!server.offline_retry_sweep_needed) return;
    server.offline_retry_sweep_needed = false;
    for (server.sessions) |slot| {
        const session = slot orelse continue;
        if (!session.offline_pending) continue;
        if (session.offline_store_stalls == 0) continue;
        if (session.offline_retry_timer_armed) continue;
        if (session.conn.isClosed()) continue;
        session.offline_store_stalls = 0;
        drainOfflinePending(server, session, changes);
    }
}

/// S13: continue a stalled offline drain once the connection's write
/// buffer has drained. Called from the writable handler at the
/// low-water mark, so delivery resumes without waiting for the next
/// presence or reconnect.
pub fn drainOfflinePending(server: *Server, session: *Session, changes: *ChangeList) void {
    if (!session.offline_pending) return;
    const bound = session.stream.bound_jid orelse return;
    deliverOfflineMessages(server, session, bound.local, bound.domain, changes);
}

/// Allocate a free session ID slot. O(1) via free-list stack (T128).
fn allocateId(server: *Server) ?usize {
    if (server.free_count == 0) return null;
    server.free_count -= 1;
    return server.free_ids[server.free_count];
}

/// Return a session ID allocated by acceptConnections that never became a
/// session (accept WouldBlock/errors, OOM, changelist-full). Without this
/// every false wakeup of the level-triggered listener leaked one slot —
/// under connect bursts the per-worker pool drained in seconds and the
/// worker stopped accepting entirely ("connection limit reached" flood).
fn releaseId(server: *Server, id: usize) void {
    server.free_ids[server.free_count] = id;
    server.free_count += 1;
}

// ============================================================================
// Tests
// ============================================================================

const posix = std.posix;
const ChangeListT = @import("event_loop.zig").ChangeList;
const SessionMap = @import("session_map").SessionMap;
const xmpp_lib = @import("xmpp");
const op_backend = @import("op_backend");
const archive_backend = @import("archive_backend");
const offline_store_mod = @import("generic_offline_store");
const archive_store_mod = @import("archive_store");

fn testSocketPair() ![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    const rc = std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds);
    if (rc != 0) return error.SocketPairFailed;
    return fds;
}

fn repairFirstOfflinePointerForTest(db: *op_backend.Backend) !void {
    const recipient = "bob@localhost";
    const stanza_id = "s1";
    const from_jid = "alice@localhost";
    var key: [recipient.len + 1 + 8]u8 = undefined;
    @memcpy(key[0..recipient.len], recipient);
    key[recipient.len] = 0;
    std.mem.writeInt(u64, key[recipient.len + 1 ..][0..8], 1, .big);

    var value: [12 + stanza_id.len + from_jid.len]u8 = undefined;
    std.mem.writeInt(u64, value[0..8], 1001, .big);
    std.mem.writeInt(u32, value[8..12], stanza_id.len, .big);
    @memcpy(value[12..][0..stanza_id.len], stanza_id);
    @memcpy(value[12 + stanza_id.len ..][0..from_jid.len], from_jid);

    var batch = try db.writeBatch();
    {
        // Abort only put failures; commit ends the batch either way (C4).
        errdefer batch.abort();
        try batch.put(offline_store_mod.NS_OFFLINE_V2, &key, &value);
    }
    try batch.commit();
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

// S13 regression test: an offline backlog larger than the connection write
// buffer must not be deleted wholesale. Only handed-to-the-connection
// messages may be removed; the rest deliver on a later available event.
test "S13: offline delivery keeps undelivered messages when the send buffer fills" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    try tmp.dir.makePath("archive");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    const arch_path = try tmp.dir.realpathAlloc(allocator, "archive");
    defer allocator.free(arch_path);

    var op_db = try op_backend.Backend.open(op_path, .{});
    defer op_db.close();
    var arch_db = try archive_backend.Backend.open(arch_path, .{});
    defer arch_db.close();

    var offline_store = offline_store_mod.GenericOfflineStore(op_backend.Backend).init(&op_db, allocator);
    var arch_store = archive_store_mod.ArchiveStore(archive_backend.Backend).init(&arch_db, allocator);

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();
    server.offline = &offline_store;
    server.archive = &arch_store;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeListT.init(&change_buf);

    const session = try makeAuthenticatedSession(&server, 1, "bob");
    server.free_count -= 1;
    defer {
        session.sm_resume_enabled = false;
        destroySession(&server, 1, session, &changes);
    }

    // 40 messages of ~1 KiB each: roughly 40 KiB of backlog against the
    // 16 KiB connection write buffer, so delivery must pause partway.
    const total: usize = 40;
    var stanza_buf: [1024]u8 = undefined;
    const pad = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    var i: usize = 0;
    while (i < total) : (i += 1) {
        var id_buf: [16]u8 = undefined;
        const stanza_id = std.fmt.bufPrint(&id_buf, "s{d}", .{i}) catch unreachable;
        const stanza = std.fmt.bufPrint(&stanza_buf, "<message from='alice@localhost' to='bob@localhost' id='{s}'><body>{s}</body></message>", .{ stanza_id, pad }) catch unreachable;
        const ts: u64 = 1000 + @as(u64, @intCast(i));
        try arch_store.store("bob@localhost", "alice@localhost", stanza_id, ts, stanza);
        _ = try offline_store.storePointer("bob@localhost", "alice@localhost", stanza_id, ts);
    }

    deliverOfflineMessages(&server, session, "bob", "localhost", &changes);

    // Delivery must have stopped at the buffer limit: some messages were
    // handed to the connection and deleted, the rest are still queued.
    const remaining = try offline_store.countMessages("bob@localhost");
    try std.testing.expect(remaining > 0);
    try std.testing.expect(remaining < total);
    try std.testing.expect(session.conn.hasPendingWrite());

    // The survivors must be the tail of the backlog (oldest delivered first).
    const survivors = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(survivors);
    try std.testing.expectEqual(remaining, survivors.len);
    var id_expect_buf: [16]u8 = undefined;
    const expect_id = std.fmt.bufPrint(&id_expect_buf, "s{d}", .{total - remaining}) catch unreachable;
    try std.testing.expectEqualStrings(expect_id, survivors[0].stanza_id);
}

// S13: the stalled tail must resume without waiting for the next presence
// or reconnect. Simulates the writable-handler cycle: flush to the peer,
// read it out, drain again at the low-water mark.
test "S13: stalled offline drain resumes via drainOfflinePending" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    try tmp.dir.makePath("archive");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    const arch_path = try tmp.dir.realpathAlloc(allocator, "archive");
    defer allocator.free(arch_path);

    var op_db = try op_backend.Backend.open(op_path, .{});
    defer op_db.close();
    var arch_db = try archive_backend.Backend.open(arch_path, .{});
    defer arch_db.close();

    var offline_store = offline_store_mod.GenericOfflineStore(op_backend.Backend).init(&op_db, allocator);
    var arch_store = archive_store_mod.ArchiveStore(archive_backend.Backend).init(&arch_db, allocator);

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();
    server.offline = &offline_store;
    server.archive = &arch_store;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeListT.init(&change_buf);

    // Live peer end so flushSend has somewhere to drain to.
    const fds = try testSocketPair();
    defer posix.close(fds[1]);
    const session = try server.allocator.create(Session);
    session.* = Session.init(fds[0], 1, server.server_host, false, server.allocator);
    session.stream.state = .active;
    session.stream.authenticated = true;
    session.stream.authenticated_jid = .{ .local = "bob", .domain = server.server_host };
    session.stream.bound_jid = .{ .local = "bob", .domain = server.server_host, .resource = "res" };
    server.sessions[1] = session;
    server.free_count -= 1;
    defer {
        session.sm_resume_enabled = false;
        destroySession(&server, 1, session, &changes);
    }

    const total: usize = 40;
    var stanza_buf: [4096]u8 = undefined;
    const pad = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    var i: usize = 0;
    while (i < total) : (i += 1) {
        var id_buf: [16]u8 = undefined;
        const stanza_id = std.fmt.bufPrint(&id_buf, "s{d}", .{i}) catch unreachable;
        const stanza = std.fmt.bufPrint(&stanza_buf, "<message from='alice@localhost' to='bob@localhost' id='{s}'><body>{s}</body></message>", .{ stanza_id, pad }) catch unreachable;
        const ts: u64 = 1000 + @as(u64, @intCast(i));
        try arch_store.store("bob@localhost", "alice@localhost", stanza_id, ts, stanza);
        _ = try offline_store.storePointer("bob@localhost", "alice@localhost", stanza_id, ts);
    }

    deliverOfflineMessages(&server, session, "bob", "localhost", &changes);
    try std.testing.expect(session.offline_pending);
    try std.testing.expect(try offline_store.countMessages("bob@localhost") > 0);

    // Writable-handler cycle: read the peer out, flush more, drain again.
    var rounds: usize = 0;
    var buf: [65536]u8 = undefined;
    while (session.offline_pending and rounds < 64) : (rounds += 1) {
        while (true) {
            const n = posix.read(fds[1], &buf) catch break;
            if (n == 0) break;
        }
        _ = session.conn.flushSend() catch |err| switch (err) {
            error.WouldBlock => 0,
            else => break,
        };
        drainOfflinePending(&server, session, &changes);
    }

    try std.testing.expect(!session.offline_pending);
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));
    try std.testing.expect(rounds > 1);
}

// S13: a pointer whose archive entry is gone must not be skipped on every
// pass forever; it is dropped and the rest of the backlog still delivers.
test "S13: dangling offline pointer is dropped, not skipped forever" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    try tmp.dir.makePath("archive");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    const arch_path = try tmp.dir.realpathAlloc(allocator, "archive");
    defer allocator.free(arch_path);

    var op_db = try op_backend.Backend.open(op_path, .{});
    defer op_db.close();
    var arch_db = try archive_backend.Backend.open(arch_path, .{});
    defer arch_db.close();

    var offline_store = offline_store_mod.GenericOfflineStore(op_backend.Backend).init(&op_db, allocator);
    var arch_store = archive_store_mod.ArchiveStore(archive_backend.Backend).init(&arch_db, allocator);

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();
    server.offline = &offline_store;
    server.archive = &arch_store;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeListT.init(&change_buf);

    const session = try makeAuthenticatedSession(&server, 1, "bob");
    server.free_count -= 1;
    defer {
        session.sm_resume_enabled = false;
        destroySession(&server, 1, session, &changes);
    }

    // One real message, one pointer to an archive entry that does not exist.
    try arch_store.store("bob@localhost", "alice@localhost", "s1", 1001, "<message from='alice@localhost' to='bob@localhost' id='s1'><body>hi</body></message>");
    _ = try offline_store.storePointer("bob@localhost", "alice@localhost", "gone", 1000);
    _ = try offline_store.storePointer("bob@localhost", "alice@localhost", "s1", 1001);

    deliverOfflineMessages(&server, session, "bob", "localhost", &changes);

    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));
    try std.testing.expect(!session.offline_pending);
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

test "S19: startup loader loads more than 256 persistent rooms" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);

    var db = try op_backend.Backend.open(path, .{});
    defer db.close();
    const RoomStore = @import("room_store").RoomStore(op_backend.Backend);
    var store = RoomStore.init(&db, allocator);

    // 300 rooms: the old [256] jid_buf in the startup loader silently
    // skipped every room past 256.
    const total: usize = 300;
    var i: usize = 0;
    while (i < total) : (i += 1) {
        var jid_buf: [64]u8 = undefined;
        const jid = std.fmt.bufPrint(&jid_buf, "room{d}@conf.localhost", .{i}) catch unreachable;
        const config = @import("room_store").RoomConfig{ .persistent = true };
        try store.saveRoom(jid, &config);
    }

    // Drive the same loader configureServer uses. Decoding inside the
    // iteration must not open a nested read txn (MDB_BAD_RSLOT on LMDB);
    // with the old loadRoom-inside-iterate code this loads zero rooms.
    const room_registry_mod = @import("room_registry");
    var reg = try allocator.create(room_registry_mod.RoomRegistry);
    defer allocator.destroy(reg);
    reg.* = room_registry_mod.RoomRegistry.init(allocator);
    defer reg.deinit();

    const worker_count: u16 = 4;
    const worker_id: u16 = 2;
    const loaded = room_registry_mod.loadPersistentRooms(reg, &store, worker_count, worker_id);

    var expected: usize = 0;
    i = 0;
    while (i < total) : (i += 1) {
        var jid_buf: [64]u8 = undefined;
        const jid = std.fmt.bufPrint(&jid_buf, "room{d}@conf.localhost", .{i}) catch unreachable;
        if (room_registry_mod.roomOwner(jid, worker_count) == worker_id) expected += 1;
    }
    try std.testing.expect(expected > 0);
    try std.testing.expectEqual(expected, loaded);
    try std.testing.expectEqual(expected, reg.count);

    // Rooms must be addressable by JID; other workers' rooms must not be.
    i = 0;
    while (i < total) : (i += 17) {
        var jid_buf: [64]u8 = undefined;
        const jid = std.fmt.bufPrint(&jid_buf, "room{d}@conf.localhost", .{i}) catch unreachable;
        const owned = room_registry_mod.roomOwner(jid, worker_count) == worker_id;
        try std.testing.expectEqual(owned, reg.findByJid(jid) != null);
    }
}

// S13: a message parked behind a draining tail points at an archive row the
// async writer queue may not have committed yet. Reading the archive alone
// saw a dangling pointer and deleted it, destroying the stanza. The held copy
// is stored with the pointer, so the drain delivers it regardless.
test "S13: held stanza is delivered before the archive row is committed" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    try tmp.dir.makePath("archive");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    const arch_path = try tmp.dir.realpathAlloc(allocator, "archive");
    defer allocator.free(arch_path);

    var op_db = try op_backend.Backend.open(op_path, .{});
    defer op_db.close();
    var arch_db = try archive_backend.Backend.open(arch_path, .{});
    defer arch_db.close();

    var offline_store = offline_store_mod.GenericOfflineStore(op_backend.Backend).init(&op_db, allocator);
    var arch_store = archive_store_mod.ArchiveStore(archive_backend.Backend).init(&arch_db, allocator);

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();
    server.offline = &offline_store;
    server.archive = &arch_store;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeListT.init(&change_buf);

    // Live peer end so delivered bytes can be read back.
    const fds = try testSocketPair();
    defer posix.close(fds[1]);
    const session = try server.allocator.create(Session);
    session.* = Session.init(fds[0], 1, server.server_host, false, server.allocator);
    session.stream.state = .active;
    session.stream.authenticated = true;
    session.stream.authenticated_jid = .{ .local = "bob", .domain = server.server_host };
    session.stream.bound_jid = .{ .local = "bob", .domain = server.server_host, .resource = "res" };
    server.sessions[1] = session;
    server.free_count -= 1;
    defer {
        session.sm_resume_enabled = false;
        destroySession(&server, 1, session, &changes);
    }

    // The stanza exists only as a held copy: no archive row was ever written.
    const held = "<message from='alice@localhost' to='bob@localhost' id='h1'><body>held</body></message>";
    const ok = try offline_store.storeHeldPointer("bob@localhost", "alice@localhost", "h1", 2000, held);
    try std.testing.expect(ok);
    const pointers = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 1), pointers.len);

    deliverOfflineMessages(&server, session, "bob", "localhost", &changes);

    _ = session.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    const got = buf[0..n];

    try std.testing.expect(std.mem.indexOf(u8, got, "<body>held</body>") != null);
    try std.testing.expect(!session.offline_pending);
    // The held payload goes with the pointer, or the row leaks forever.
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));
    const still_held = try offline_store.getHeldStanza(pointers[0]);
    try std.testing.expect(still_held == null);
    if (still_held) |h| allocator.free(h);
}

test "G2: a legacy offline row drains before newly sequenced rows" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    try tmp.dir.makePath("archive");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    const arch_path = try tmp.dir.realpathAlloc(allocator, "archive");
    defer allocator.free(arch_path);

    var op_db = try op_backend.Backend.open(op_path, .{});
    defer op_db.close();
    var arch_db = try archive_backend.Backend.open(arch_path, .{});
    defer arch_db.close();
    var offline_store = offline_store_mod.GenericOfflineStore(op_backend.Backend).init(&op_db, allocator);
    var arch_store = archive_store_mod.ArchiveStore(archive_backend.Backend).init(&arch_db, allocator);

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();
    server.offline = &offline_store;
    server.archive = &arch_store;
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeListT.init(&change_buf);

    const fds = try testSocketPair();
    defer posix.close(fds[1]);
    const session = try server.allocator.create(Session);
    session.* = Session.init(fds[0], 1, server.server_host, false, server.allocator);
    session.stream.state = .active;
    session.stream.authenticated = true;
    session.stream.authenticated_jid = .{ .local = "bob", .domain = server.server_host };
    session.stream.bound_jid = .{ .local = "bob", .domain = server.server_host, .resource = "res" };
    server.sessions[1] = session;
    server.free_count -= 1;
    defer {
        session.sm_resume_enabled = false;
        destroySession(&server, 1, session, &changes);
    }

    const recipient = "bob@localhost";
    const legacy_id = "legacy";
    const legacy_xml = "<message id='legacy'><body>legacy-first</body></message>";
    const legacy_key = try allocator.alloc(u8, recipient.len + 1 + 8 + 1 + legacy_id.len);
    defer allocator.free(legacy_key);
    @memcpy(legacy_key[0..recipient.len], recipient);
    legacy_key[recipient.len] = 0;
    std.mem.writeInt(u64, legacy_key[recipient.len + 1 ..][0..8], 3000, .big);
    legacy_key[recipient.len + 1 + 8] = 0;
    @memcpy(legacy_key[recipient.len + 1 + 8 + 1 ..], legacy_id);
    try op_db.put(offline_store_mod.NS_OFFLINE, legacy_key, "alice@localhost");
    try op_db.put(offline_store_mod.NS_OFFLINE_HOLD, legacy_key, legacy_xml);

    const new_xml = "<message id='new'><body>new-second</body></message>";
    try std.testing.expect(try offline_store.storeHeldPointer(recipient, "alice@localhost", "new", 1000, new_xml));
    const ordered = try offline_store.getPointers(recipient);
    defer offline_store.freePointers(ordered);
    try std.testing.expectEqual(@as(usize, 2), ordered.len);
    try std.testing.expectEqualStrings("legacy", ordered[0].stanza_id);
    try std.testing.expectEqualStrings("new", ordered[1].stanza_id);
    try std.testing.expectEqual(@as(u64, 3000), ordered[0].timestamp);
    try std.testing.expectEqual(@as(u64, 1000), ordered[1].timestamp);
    deliverOfflineMessages(&server, session, "bob", "localhost", &changes);

    _ = session.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    const got = buf[0..n];
    const legacy_pos = std.mem.indexOf(u8, got, "legacy-first") orelse return error.MissingLegacyStanza;
    const new_pos = std.mem.indexOf(u8, got, "new-second") orelse return error.MissingNewStanza;
    try std.testing.expect(legacy_pos < new_pos);
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));
}

// S13: a drain that stalls on a store error with an empty write buffer has no
// EVFILT_WRITE left to wake it, so it must stage its own retry. Without this
// the tail sat undelivered until the next presence stanza or reconnect.
test "S13: store-error stall with an empty buffer re-arms the drain" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    try tmp.dir.makePath("archive");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    const arch_path = try tmp.dir.realpathAlloc(allocator, "archive");
    defer allocator.free(arch_path);

    var op_db = try op_backend.Backend.open(op_path, .{});
    defer op_db.close();
    var arch_db = try archive_backend.Backend.open(arch_path, .{});
    defer arch_db.close();

    var offline_store = offline_store_mod.GenericOfflineStore(op_backend.Backend).init(&op_db, allocator);
    var arch_store = archive_store_mod.ArchiveStore(archive_backend.Backend).init(&arch_db, allocator);

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();
    server.offline = &offline_store;
    server.archive = &arch_store;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeListT.init(&change_buf);

    // Live peer end so delivered bytes can be read back.
    const fds = try testSocketPair();
    defer posix.close(fds[1]);
    const session = try server.allocator.create(Session);
    session.* = Session.init(fds[0], 1, server.server_host, false, server.allocator);
    session.stream.state = .active;
    session.stream.authenticated = true;
    session.stream.authenticated_jid = .{ .local = "bob", .domain = server.server_host };
    session.stream.bound_jid = .{ .local = "bob", .domain = server.server_host, .resource = "res" };
    server.sessions[1] = session;
    server.free_count -= 1;
    defer {
        session.sm_resume_enabled = false;
        destroySession(&server, 1, session, &changes);
    }

    try arch_store.store("bob@localhost", "alice@localhost", "s1", 1001, "<message from='alice@localhost' to='bob@localhost' id='s1'><body>hi</body></message>");
    const oversized_id = [_]u8{'x'} ** 600;
    _ = try offline_store.storePointer("bob@localhost", "alice@localhost", &oversized_id, 1001);

    deliverOfflineMessages(&server, session, "bob", "localhost", &changes);

    // Still pending, and the pointer survives for the retry.
    try std.testing.expect(session.offline_pending);
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    try std.testing.expect(!session.conn.hasPendingWrite());

    // Nothing else can wake this session, so the drain armed its own retry.
    var armed = false;
    for (changes.slice()) |ev| {
        if (ev.ident != @as(usize, @intCast(session.conn.fd))) continue;
        if (ev.filter != std.c.EVFILT.WRITE) continue;
        if ((ev.flags & std.c.EV.ONESHOT) == 0) continue;
        if (ev.udata != 1) continue;
        armed = true;
    }
    try std.testing.expect(armed);

    // Repair the pointer metadata, then the retry finds the archived stanza.
    try repairFirstOfflinePointerForTest(&op_db);
    changes.reset();
    drainOfflinePending(&server, session, &changes);
    try std.testing.expect(!session.offline_pending);
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));

    _ = session.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "<body>hi</body>") != null);
}

// S13: prompt retries are bounded so a persistently failing store cannot
// spin the event loop; a one-shot deadline owns retries after that.
test "S13: store-error retries are bounded, then a one-shot timer resumes" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    try tmp.dir.makePath("archive");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    const arch_path = try tmp.dir.realpathAlloc(allocator, "archive");
    defer allocator.free(arch_path);

    var op_db = try op_backend.Backend.open(op_path, .{});
    defer op_db.close();
    var arch_db = try archive_backend.Backend.open(arch_path, .{});
    defer arch_db.close();

    var offline_store = offline_store_mod.GenericOfflineStore(op_backend.Backend).init(&op_db, allocator);
    var arch_store = archive_store_mod.ArchiveStore(archive_backend.Backend).init(&arch_db, allocator);

    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();
    server.offline = &offline_store;
    server.archive = &arch_store;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeListT.init(&change_buf);

    // Live peer end so delivered bytes can be read back.
    const fds = try testSocketPair();
    defer posix.close(fds[1]);
    const session = try server.allocator.create(Session);
    session.* = Session.init(fds[0], 1, server.server_host, false, server.allocator);
    session.stream.state = .active;
    session.stream.authenticated = true;
    session.stream.authenticated_jid = .{ .local = "bob", .domain = server.server_host };
    session.stream.bound_jid = .{ .local = "bob", .domain = server.server_host, .resource = "res" };
    server.sessions[1] = session;
    server.free_count -= 1;
    defer {
        session.sm_resume_enabled = false;
        destroySession(&server, 1, session, &changes);
    }

    try arch_store.store("bob@localhost", "alice@localhost", "s1", 1001, "<message from='alice@localhost' to='bob@localhost' id='s1'><body>hi</body></message>");
    const oversized_id = [_]u8{'x'} ** 600;
    _ = try offline_store.storePointer("bob@localhost", "alice@localhost", &oversized_id, 1001);

    var stalls: usize = 0;
    while (stalls < 40) : (stalls += 1) {
        changes.reset();
        deliverOfflineMessages(&server, session, "bob", "localhost", &changes);

        var armed = false;
        for (changes.slice()) |ev| {
            if (ev.filter == std.c.EVFILT.WRITE and (ev.flags & std.c.EV.ONESHOT) != 0) armed = true;
        }
        if (!armed) break;
    }

    // Bounded: the retry budget ran out well before the loop cap.
    try std.testing.expect(stalls == OFFLINE_STALL_RETRY_MAX);
    try std.testing.expect(session.offline_pending);
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    var retry_timer = false;
    for (changes.slice()) |ev| {
        if (ev.filter == std.c.EVFILT.TIMER and
            ev.ident == @as(usize, @intCast(session.conn.id)) and
            (ev.flags & std.c.EV.ONESHOT) != 0) retry_timer = true;
    }
    try std.testing.expect(retry_timer);
    try std.testing.expect(session.offline_retry_timer_armed);
    try std.testing.expect(!server.offline_retry_sweep_needed);

    // Repair the pointer metadata, then fire the session's retry deadline.
    try repairFirstOfflinePointerForTest(&op_db);
    retryOfflineDrain(&server, session.conn.id, &changes);
    try std.testing.expect(!session.offline_pending);
    try std.testing.expect(!session.offline_retry_timer_armed);
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));
}

test "S13: full changelist preserves the offline retry fallback" {
    const allocator = std.testing.allocator;
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();

    const fds = try testSocketPair();
    defer posix.close(fds[1]);
    const session = try server.allocator.create(Session);
    session.* = Session.init(fds[0], 1, server.server_host, false, server.allocator);
    server.sessions[1] = session;
    server.free_count -= 1;

    var change_buf: [1]posix.Kevent = undefined;
    var changes = ChangeListT.init(&change_buf);
    defer destroySession(&server, 1, session, &changes);
    try changes.addTimer(42, 1, true);

    session.offline_store_stalls = OFFLINE_STALL_RETRY_MAX;
    stallOnStoreError(&server, session, "bob@localhost", error.StorageError, &changes);

    try std.testing.expect(session.offline_pending);
    try std.testing.expectEqual(OFFLINE_STALL_RETRY_MAX + 1, session.offline_store_stalls);
    try std.testing.expect(!session.offline_retry_timer_armed);
    try std.testing.expect(server.offline_retry_sweep_needed);
}
