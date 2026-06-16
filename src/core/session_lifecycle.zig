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
pub fn handleBind(server: *Server, session: *Session, resource: []const u8) void {
    const action = session.stream.handleBind(resource);
    server.executeAction(session, action);

    if (session.stream.isActive()) {
        if (session.stream.bound_jid) |bound| {
            const sm = server.session_map orelse {
                log.err("connection {d} bind failed: session_map not configured", .{session.conn.id});
                return;
            };
            _ = sm.bind(server.worker_id, @intCast(session.conn.id), bound.local, bound.domain, bound.resource) catch |err| {
                log.err("connection {d} session_map bind failed: {}", .{ session.conn.id, err });
                return;
            };
            log.info("connection {d} session established: {s}@{s}/{s}", .{
                session.conn.id, bound.local, bound.domain, bound.resource,
            });
        }
    }
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
        detachSession(server, id, session, changes);
        return;
    }

    destroySession(server, id, session, changes);
}

/// Force-close a session without SM resume consideration.
/// Used for intentional closes (stream close, protocol errors) where detach is inappropriate.
pub fn forceCloseSession(server: *Server, id: usize, changes: *ChangeList) void {
    const session = server.sessions[id] orelse return;
    session.sm_resume_enabled = false; // Prevent detach
    destroySession(server, id, session, changes);
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
