//! # MUC Handler — Multi-User Chat (XEP-0045)
//!
//! Handles MUC presence (join/part), groupchat messages (fan-out), and
//! admin IQ commands (kick/ban). Imported by server.zig.
//!
//! ## Entry Points
//!
//! Called from server.zig's dispatchStanza/handlePresence when the target
//! domain matches the MUC service domain (conference.{host}).
//!
//! - `handleMucPresence` — join (available), part (unavailable)
//! - `handleMucGroupchat` — message fan-out to all room occupants
//! - `handleMucDiscoInfo` — disco#info for the MUC service itself
//! - `handleMucDiscoItems` — disco#items listing public rooms
//! - `handleRoomDiscoInfo` — disco#info for a specific room

const std = @import("std");
const xml = @import("xml");
const room_registry = @import("room_registry");
const Room = room_registry.Room;
const Occupant = room_registry.Occupant;
const RoomRegistry = room_registry.RoomRegistry;
const room_store = @import("room_store");
const RoomConfig = room_store.RoomConfig;
const Role = room_store.Role;
const Affiliation = room_store.Affiliation;

const server_mod = @import("server.zig");
const Server = server_mod.Server;
const Session = server_mod.Session;
const ChangeList = @import("event_loop.zig").ChangeList;
const fanout = @import("fanout.zig");
const FanoutQueue = fanout.FanoutQueue;
const PendingFanout = fanout.PendingFanout;

const log = std.log.scoped(.muc);

/// Handle a presence stanza addressed to a MUC room JID.
/// Called when to_domain matches the MUC service host.
///
/// - Available presence (no type or type='') with <x xmlns='muc'/> = JOIN
/// - type='unavailable' = PART
pub fn handleMucPresence(
    server: *Server,
    session: *Session,
    to_local: []const u8,
    to_resource: []const u8,
    type_str: []const u8,
    changes: *ChangeList,
) void {
    const reg = server.room_registry orelse return;
    const muc_host = server.muc_host orelse return;

    if (server.delivery_system != null) reg.lock.lock();
    defer if (server.delivery_system != null) reg.lock.unlock();

    if (to_resource.len == 0) {
        // Presence to bare room JID (no nick) — error
        sendPresenceError(server, session, to_local, muc_host, "jid-malformed", changes);
        return;
    }

    if (std.mem.eql(u8, type_str, "unavailable")) {
        handlePart(server, reg, session, to_local, muc_host, changes);
    } else if (type_str.len == 0) {
        handleJoin(server, reg, session, to_local, muc_host, to_resource, changes);
    }
}

/// Handle a groupchat message addressed to a room bare JID.
/// Uses pre-built stanza + bounded continuation to prevent event loop starvation.
/// Delivers to the first batch_size occupants immediately, then queues the
/// remainder for delivery in subsequent event loop ticks.
pub fn handleMucGroupchat(
    server: *Server,
    session: *Session,
    to_local: []const u8,
    inner_xml: []const u8,
    id_str: []const u8,
    changes: *ChangeList,
) void {
    const reg = server.room_registry orelse return;
    const muc_host = server.muc_host orelse return;

    if (server.delivery_system != null) reg.lock.lockShared();
    defer if (server.delivery_system != null) reg.lock.unlockShared();

    // Build room JID
    var room_jid_buf: [320]u8 = undefined;
    const room_jid = buildRoomJid(&room_jid_buf, to_local, muc_host) orelse return;

    const room = reg.findByJid(room_jid) orelse {
        sendMessageError(server, session, to_local, muc_host, id_str, "item-not-found", changes);
        return;
    };

    // Find sender's occupant entry (occupant stores global session ID)
    const sender_local: usize = session.conn.id;
    const sender_idx = room.findBySessionId(sender_local) orelse {
        sendMessageError(server, session, to_local, muc_host, id_str, "not-acceptable", changes);
        return;
    };
    const sender = room.occupants[sender_idx].?;

    // Check role: in moderated rooms, visitors cannot speak
    if (room.config.moderated and sender.role == .visitor) {
        sendMessageError(server, session, to_local, muc_host, id_str, "forbidden", changes);
        return;
    }

    // Build the from JID: room@conference.host/sender_nick
    var from_buf: [384]u8 = undefined;
    var from_fbs = std.io.fixedBufferStream(&from_buf);
    const fw = from_fbs.writer();
    fw.writeAll(room_jid) catch return;
    fw.writeByte('/') catch return;
    fw.writeAll(sender.getNick()) catch return;
    const from_str = from_fbs.getWritten();

    // Build pre-built stanza: prefix (before recipient JID) + suffix (after)
    var prefix_buf: [512]u8 = undefined;
    const prefix_len = fanout.buildPrefix(&prefix_buf, from_str) orelse return;
    var suffix_buf: [16500]u8 = undefined;
    const suffix_len = fanout.buildSuffix(&suffix_buf, id_str, inner_xml) orelse return;
    const prefix = prefix_buf[0..prefix_len];
    const suffix = suffix_buf[0..suffix_len];

    // Cross-thread multicast: one MPSC enqueue per remote worker (not per occupant)
    server.deliverMulticastToWorkers(room, prefix, suffix);

    // Local fan-out: deliver to occupants on this worker (bounded continuation)
    const batch_size = server.fanout_queue.batch_size;
    var delivered: u8 = 0;
    var resume_slot: u8 = 0;
    var all_done = true;

    for (&room.occupants, 0..) |*slot, idx| {
        const occ = slot.* orelse continue;
        if (occ.session_id == room_registry.REMOTE_OCCUPANT) continue;
        if (occ.worker_id != server.worker_id) continue;

        const local_sid = occ.session_id;
        const target_session = server.sessions[local_sid] orelse continue;
        fanout.deliverPrebuilt(prefix, occ.getRealJid(), suffix, &target_session.conn) catch continue;
        if (target_session.conn.hasPendingWrite()) {
            changes.addWrite(target_session.conn.fd, local_sid) catch {};
        }

        delivered += 1;
        if (delivered >= batch_size) {
            resume_slot = @intCast(idx + 1);
            if (resume_slot < room_registry.MAX_OCCUPANTS) {
                for (room.occupants[resume_slot..]) |remaining| {
                    if (remaining) |r| {
                        if (r.worker_id == server.worker_id) {
                            all_done = false;
                            break;
                        }
                    }
                }
            }
            break;
        }
    }

    // If more local occupants remain, queue a continuation
    if (!all_done) {
        if (server.fanout_queue.alloc()) |pf| {
            @memcpy(pf.room_jid_buf[0..room_jid.len], room_jid);
            pf.room_jid_len = @intCast(room_jid.len);
            @memcpy(pf.prefix_buf[0..prefix_len], prefix);
            pf.prefix_len = prefix_len;
            @memcpy(pf.suffix_buf[0..suffix_len], suffix);
            pf.suffix_len = suffix_len;
            pf.next_slot = resume_slot;
            log.debug("queued fan-out continuation for {s} from slot {d}", .{ room_jid, resume_slot });
        } else {
            deliverRemainingSync(server, room, resume_slot, prefix, suffix, changes);
        }
    }

    // Store in archive for room history replay (T44)
    if (server.archive) |archive| {
        const timestamp: u64 = @intCast(std.time.timestamp());
        const stanza_id = if (id_str.len > 0) id_str else "muc";
        // Build full stanza XML: <message from='room/nick' type='groupchat' id='...'>inner</message>
        var arch_buf: [17200]u8 = undefined;
        var arch_fbs = std.io.fixedBufferStream(&arch_buf);
        const aw = arch_fbs.writer();
        aw.writeAll("<message from='") catch return;
        aw.writeAll(from_str) catch return;
        aw.writeAll("' type='groupchat'") catch return;
        if (id_str.len > 0) {
            aw.writeAll(" id='") catch return;
            aw.writeAll(id_str) catch return;
            aw.writeByte('\'') catch return;
        }
        aw.writeByte('>') catch return;
        aw.writeAll(inner_xml) catch return;
        aw.writeAll("</message>") catch return;
        archive.store(room_jid, from_str, stanza_id, timestamp, arch_fbs.getWritten()) catch {};
    }
}

/// Drain one batch of a pending fan-out. Called from the server main loop.
/// Returns true if the fan-out completed (slot freed), false if more work remains.
pub fn drainPendingFanout(
    server: *Server,
    pf: *PendingFanout,
    changes: *ChangeList,
) bool {
    const reg = server.room_registry orelse {
        pf.complete();
        return true;
    };

    if (server.delivery_system != null) reg.lock.lockShared();
    defer if (server.delivery_system != null) reg.lock.unlockShared();

    // Re-find the room by JID (it may have been destroyed between ticks)
    const room = reg.findByJid(pf.getRoomJid()) orelse {
        log.debug("fan-out target room gone: {s}", .{pf.getRoomJid()});
        pf.complete();
        return true;
    };

    const batch_size = server.fanout_queue.batch_size;
    const prefix = pf.getPrefix();
    const suffix = pf.getSuffix();
    var delivered: u8 = 0;

    // Continuation only handles local occupants — multicast was sent in initial call
    var i: usize = pf.next_slot;
    while (i < room_registry.MAX_OCCUPANTS) : (i += 1) {
        const occ = room.occupants[i] orelse continue;
        if (occ.session_id == room_registry.REMOTE_OCCUPANT) continue;
        if (occ.worker_id != server.worker_id) continue;

        const local_sid = occ.session_id;
        const target_session = server.sessions[local_sid] orelse continue;
        fanout.deliverPrebuilt(prefix, occ.getRealJid(), suffix, &target_session.conn) catch continue;
        if (target_session.conn.hasPendingWrite()) {
            changes.addWrite(target_session.conn.fd, local_sid) catch {};
        }

        delivered += 1;
        if (delivered >= batch_size) {
            pf.next_slot = @intCast(i + 1);
            if (pf.next_slot < room_registry.MAX_OCCUPANTS) {
                for (room.occupants[pf.next_slot..]) |remaining| {
                    if (remaining) |r| {
                        if (r.worker_id == server.worker_id) return false;
                    }
                }
            }
            pf.complete();
            return true;
        }
    }

    // Reached end of occupant array
    pf.complete();
    return true;
}

/// Synchronous fallback: deliver to remaining occupants when the fan-out queue is full.
fn deliverRemainingSync(
    server: *Server,
    room: *const Room,
    start_slot: u8,
    prefix: []const u8,
    suffix: []const u8,
    changes: *ChangeList,
) void {
    // Only local occupants — multicast was already sent in initial call
    var i: usize = start_slot;
    while (i < room_registry.MAX_OCCUPANTS) : (i += 1) {
        const occ = room.occupants[i] orelse continue;
        if (occ.session_id == room_registry.REMOTE_OCCUPANT) continue;
        if (occ.worker_id != server.worker_id) continue;

        const local_sid = occ.session_id;
        const target_session = server.sessions[local_sid] orelse continue;
        fanout.deliverPrebuilt(prefix, occ.getRealJid(), suffix, &target_session.conn) catch continue;
        if (target_session.conn.hasPendingWrite()) {
            changes.addWrite(target_session.conn.fd, local_sid) catch {};
        }
    }
}

/// Handle disco#info for the MUC service domain itself.
pub fn handleMucDiscoInfo(
    server: *Server,
    session: *Session,
    iq_id: []const u8,
    changes: *ChangeList,
) void {
    const muc_host = server.muc_host orelse return;
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    w.writeAll("<iq type='result' from='") catch return;
    w.writeAll(muc_host) catch return;
    w.writeAll("' to='") catch return;
    writeSessionJid(w, session) catch return;
    w.writeAll("' id='") catch return;
    w.writeAll(iq_id) catch return;
    w.writeAll("'><query xmlns='http://jabber.org/protocol/disco#info'>") catch return;
    w.writeAll("<identity category='conference' type='text' name='Chat Rooms'/>") catch return;
    w.writeAll("<feature var='http://jabber.org/protocol/muc'/>") catch return;
    w.writeAll("</query></iq>") catch return;

    session.conn.queueSend(fbs.getWritten()) catch return;
    if (session.conn.hasPendingWrite()) {
        changes.addWrite(session.conn.fd, session.conn.id) catch {};
    }
}

/// Handle disco#items for the MUC service domain (list public rooms).
pub fn handleMucDiscoItems(
    server: *Server,
    session: *Session,
    iq_id: []const u8,
    changes: *ChangeList,
) void {
    const reg = server.room_registry orelse return;
    const muc_host = server.muc_host orelse return;

    if (server.delivery_system != null) reg.lock.lockShared();
    defer if (server.delivery_system != null) reg.lock.unlockShared();

    var buf: [8192]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    w.writeAll("<iq type='result' from='") catch return;
    w.writeAll(muc_host) catch return;
    w.writeAll("' to='") catch return;
    writeSessionJid(w, session) catch return;
    w.writeAll("' id='") catch return;
    w.writeAll(iq_id) catch return;
    w.writeAll("'><query xmlns='http://jabber.org/protocol/disco#items'>") catch return;

    // List public rooms
    var room_ptrs: [256]*const Room = undefined;
    const count = reg.listPublicRooms(&room_ptrs);
    for (room_ptrs[0..count]) |room| {
        w.writeAll("<item jid='") catch break;
        w.writeAll(room.getJid()) catch break;
        w.writeAll("' name='") catch break;
        const name = room.config.getName();
        if (name.len > 0) {
            w.writeAll(name) catch break;
        } else {
            // Use localpart of JID as display name
            const jid = room.getJid();
            if (std.mem.indexOfScalar(u8, jid, '@')) |at| {
                w.writeAll(jid[0..at]) catch break;
            } else {
                w.writeAll(jid) catch break;
            }
        }
        w.writeAll("'/>") catch break;
    }

    w.writeAll("</query></iq>") catch return;

    session.conn.queueSend(fbs.getWritten()) catch return;
    if (session.conn.hasPendingWrite()) {
        changes.addWrite(session.conn.fd, session.conn.id) catch {};
    }
}

/// Handle disco#info for a specific room.
pub fn handleRoomDiscoInfo(
    server: *Server,
    session: *Session,
    room_local: []const u8,
    iq_id: []const u8,
    changes: *ChangeList,
) void {
    const reg = server.room_registry orelse return;
    const muc_host = server.muc_host orelse return;

    if (server.delivery_system != null) reg.lock.lockShared();
    defer if (server.delivery_system != null) reg.lock.unlockShared();

    var room_jid_buf: [320]u8 = undefined;
    const room_jid = buildRoomJid(&room_jid_buf, room_local, muc_host) orelse return;

    var buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    w.writeAll("<iq type='result' from='") catch return;
    w.writeAll(room_jid) catch return;
    w.writeAll("' to='") catch return;
    writeSessionJid(w, session) catch return;
    w.writeAll("' id='") catch return;
    w.writeAll(iq_id) catch return;
    w.writeAll("'><query xmlns='http://jabber.org/protocol/disco#info'>") catch return;

    if (reg.findByJid(room_jid)) |room| {
        const name = room.config.getName();
        w.writeAll("<identity category='conference' type='text'") catch return;
        if (name.len > 0) {
            w.writeAll(" name='") catch return;
            w.writeAll(name) catch return;
            w.writeByte('\'') catch return;
        }
        w.writeAll("/>") catch return;
        w.writeAll("<feature var='http://jabber.org/protocol/muc'/>") catch return;
        if (room.config.moderated) {
            w.writeAll("<feature var='muc_moderated'/>") catch return;
        } else {
            w.writeAll("<feature var='muc_unmoderated'/>") catch return;
        }
        if (room.config.anonymous) {
            w.writeAll("<feature var='muc_semianonymous'/>") catch return;
        } else {
            w.writeAll("<feature var='muc_nonanonymous'/>") catch return;
        }
        if (room.config.persistent) {
            w.writeAll("<feature var='muc_persistent'/>") catch return;
        } else {
            w.writeAll("<feature var='muc_temporary'/>") catch return;
        }
        if (room.config.members_only) {
            w.writeAll("<feature var='muc_membersonly'/>") catch return;
        } else {
            w.writeAll("<feature var='muc_open'/>") catch return;
        }
        if (room.config.password_protected) {
            w.writeAll("<feature var='muc_passwordprotected'/>") catch return;
        } else {
            w.writeAll("<feature var='muc_unsecured'/>") catch return;
        }
        w.writeAll("<feature var='urn:xmpp:mam:2'/>") catch return;
    } else {
        // Room doesn't exist — still return valid response per XEP-0045
        w.writeAll("<identity category='conference' type='text'/>") catch return;
        w.writeAll("<feature var='http://jabber.org/protocol/muc'/>") catch return;
        w.writeAll("<feature var='urn:xmpp:mam:2'/>") catch return;
    }

    w.writeAll("</query></iq>") catch return;

    session.conn.queueSend(fbs.getWritten()) catch return;
    if (session.conn.hasPendingWrite()) {
        changes.addWrite(session.conn.fd, session.conn.id) catch {};
    }
}

/// Handle MUC admin IQ (kick/ban/voice).
/// Processes <query xmlns='...muc#admin'><item nick='...' role='none'/></query>
pub fn handleMucAdminIq(
    server: *Server,
    session: *Session,
    room_local: []const u8,
    iq_id: []const u8,
    changes: *ChangeList,
) void {
    const reg = server.room_registry orelse return;
    const muc_host = server.muc_host orelse return;

    if (server.delivery_system != null) reg.lock.lock();
    defer if (server.delivery_system != null) reg.lock.unlock();

    var room_jid_buf: [320]u8 = undefined;
    const room_jid = buildRoomJid(&room_jid_buf, room_local, muc_host) orelse return;

    const room = reg.findByJid(room_jid) orelse {
        sendIqErrorFromRoom(server, session, room_jid, iq_id, "item-not-found", changes);
        return;
    };

    // Verify requester is moderator+ (for kick) or admin+ (for ban)
    const requester_local: usize = session.conn.id;
    const requester_idx = room.findBySessionId(requester_local) orelse {
        sendIqErrorFromRoom(server, session, room_jid, iq_id, "not-allowed", changes);
        return;
    };
    const requester = room.occupants[requester_idx].?;

    // For MVP: only moderators can kick, only admins can ban
    if (requester.role != .moderator and requester.affiliation != .admin and requester.affiliation != .owner) {
        sendIqErrorFromRoom(server, session, room_jid, iq_id, "forbidden", changes);
        return;
    }

    // Parse the <item> from the accumulated IQ child data.
    // The iq_roster_item_* fields are reused for MUC admin item parsing.
    // nick is in iq_roster_item_jid (overloaded), role in iq_roster_item_sub
    const target_nick = session.iq_roster_item_jid;
    const new_role_str = session.iq_roster_item_sub;

    if (target_nick.len == 0 and new_role_str.len == 0) {
        sendIqErrorFromRoom(server, session, room_jid, iq_id, "bad-request", changes);
        return;
    }

    // Find the target occupant by nick
    const target_idx = room.findByNick(target_nick) orelse {
        sendIqErrorFromRoom(server, session, room_jid, iq_id, "item-not-found", changes);
        return;
    };

    // Parse the requested action
    if (std.mem.eql(u8, new_role_str, "none")) {
        // Kick — remove occupant and broadcast with status 307
        const removed = room.removeOccupant(target_idx) orelse return;
        broadcastOccupantLeave(server, room, &removed, muc_host, "307", changes);

        // Auto-destroy transient empty rooms
        if (room.occupant_count == 0 and !room.config.persistent) {
            _ = reg.destroyRoom(room_jid);
        }
    } else if (std.mem.eql(u8, new_role_str, "visitor")) {
        // Revoke voice — set role to visitor
        if (room.occupants[target_idx]) |*occ| {
            occ.role = .visitor;
        }
    } else if (std.mem.eql(u8, new_role_str, "participant")) {
        // Grant voice
        if (room.occupants[target_idx]) |*occ| {
            occ.role = .participant;
        }
    }

    // Send IQ result
    var result_buf: [512]u8 = undefined;
    var result_fbs = std.io.fixedBufferStream(&result_buf);
    const rw = result_fbs.writer();
    rw.writeAll("<iq type='result' from='") catch return;
    rw.writeAll(room_jid) catch return;
    rw.writeAll("' to='") catch return;
    writeSessionJid(rw, session) catch return;
    rw.writeAll("' id='") catch return;
    rw.writeAll(iq_id) catch return;
    rw.writeAll("'/>") catch return;

    session.conn.queueSend(result_fbs.getWritten()) catch return;
    if (session.conn.hasPendingWrite()) {
        changes.addWrite(session.conn.fd, session.conn.id) catch {};
    }
}

fn sendIqErrorFromRoom(
    server: *Server,
    session: *Session,
    room_jid: []const u8,
    iq_id: []const u8,
    condition: []const u8,
    changes: *ChangeList,
) void {
    _ = server;
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    w.writeAll("<iq type='error' from='") catch return;
    w.writeAll(room_jid) catch return;
    w.writeAll("' to='") catch return;
    writeSessionJid(w, session) catch return;
    w.writeAll("' id='") catch return;
    w.writeAll(iq_id) catch return;
    w.writeAll("'><error type='cancel'><") catch return;
    w.writeAll(condition) catch return;
    w.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>") catch return;

    session.conn.queueSend(fbs.getWritten()) catch return;
    if (session.conn.hasPendingWrite()) {
        changes.addWrite(session.conn.fd, session.conn.id) catch {};
    }
}

// ============================================================================
// Join / Part
// ============================================================================

fn handleJoin(
    server: *Server,
    reg: *RoomRegistry,
    session: *Session,
    room_local: []const u8,
    muc_host: []const u8,
    nick: []const u8,
    changes: *ChangeList,
) void {
    var room_jid_buf: [320]u8 = undefined;
    const room_jid = buildRoomJid(&room_jid_buf, room_local, muc_host) orelse return;

    // Get sender's full and bare JID
    const bound = session.stream.bound_jid orelse return;
    var real_jid_buf: [256]u8 = undefined;
    var bare_jid_buf: [256]u8 = undefined;
    const real_jid = buildFullJid(&real_jid_buf, bound.local, bound.domain, bound.resource) orelse return;
    const bare_jid = buildBareJid(&bare_jid_buf, bound.local, bound.domain) orelse return;

    // Find or create room
    var room = reg.findByJid(room_jid);
    var is_new_room = false;
    if (room == null) {
        // Create new room — creator gets owner affiliation
        var config = RoomConfig{};
        config.persistent = false; // instant room, transient by default
        config.setName(room_local);
        config.created_at = @intCast(std.time.timestamp());
        room = reg.createRoom(room_jid, config) catch {
            sendPresenceError(server, session, room_local, muc_host, "resource-constraint", changes);
            return;
        };
        is_new_room = true;
    }
    const r = room.?;

    // Check if already in room (rejoin = no-op with self-presence)
    const local_check: usize = session.conn.id;
    if (r.findBySessionId(local_check)) |_| {
        sendSelfPresence(server, session, r, nick, muc_host, changes);
        return;
    }

    // Nickname conflict check — allow same bare JID to share nick (XEP-0045 §7.2.14 multi-session)
    if (r.findByNick(nick)) |existing_idx| {
        const existing = r.occupants[existing_idx].?;
        if (!std.mem.eql(u8, existing.getBareJid(), bare_jid)) {
            sendPresenceError(server, session, room_local, muc_host, "conflict", changes);
            return;
        }
    }

    // Determine affiliation and role
    var affiliation: Affiliation = .none;
    var role: Role = .participant;
    if (is_new_room) {
        affiliation = .owner;
        role = .moderator;
    } else {
        // Look up persistent affiliation from RoomStore
        if (server.room_store) |store| {
            affiliation = store.getAffiliation(room_jid, bare_jid) catch .none;
        }
        if (affiliation == .outcast) {
            sendPresenceError(server, session, room_local, muc_host, "forbidden", changes);
            return;
        }
        role = affiliation.defaultRole();
        if (r.config.moderated and role == .participant and affiliation == .none) {
            role = .visitor;
        }
    }

    // Members-only check
    if (r.config.members_only and affiliation == .none) {
        sendPresenceError(server, session, room_local, muc_host, "registration-required", changes);
        return;
    }

    // Add occupant — store local session ID directly (no global mapping).
    const local_sid: usize = session.conn.id;
    // Look up generation from session map for ABA-safe cross-thread delivery.
    const join_gen: u32 = if (server.session_map) |sm| sm.getGeneration(bound.local, bound.domain, bound.resource) orelse 0 else 0;
    _ = r.addOccupant(nick, real_jid, bare_jid, local_sid, server.worker_id, join_gen, role, affiliation) catch {
        sendPresenceError(server, session, room_local, muc_host, "service-unavailable", changes);
        return;
    };

    log.info("{s} joined {s} as '{s}'", .{ real_jid, room_jid, nick });

    // 1. Send existing occupants' presence to the new joiner
    for (&r.occupants) |*slot| {
        const occ = slot.* orelse continue;
        if (occ.session_id == local_sid) continue; // skip self
        sendOccupantPresence(server, session, r, &occ, muc_host, null, changes);
    }

    // 2. Broadcast the new occupant's presence to ALL (including self with status 110)
    broadcastOccupantJoin(server, r, nick, real_jid, role, affiliation, muc_host, session.conn.id, changes);

    // 3. Replay room history (XEP-0045 §7.2.14, before subject)
    sendRoomHistory(server, session, r, muc_host, changes);

    // 4. Send room subject
    sendRoomSubject(server, session, r, muc_host, changes);
}

fn handlePart(
    server: *Server,
    reg: *RoomRegistry,
    session: *Session,
    room_local: []const u8,
    muc_host: []const u8,
    changes: *ChangeList,
) void {
    var room_jid_buf: [320]u8 = undefined;
    const room_jid = buildRoomJid(&room_jid_buf, room_local, muc_host) orelse return;

    const room = reg.findByJid(room_jid) orelse return;
    const local_sid: usize = session.conn.id;
    const removed = room.removeBySessionId(local_sid) orelse return;

    log.info("{s} left {s}", .{ removed.getRealJid(), room_jid });

    // Broadcast unavailable presence to remaining occupants
    broadcastOccupantLeave(server, room, &removed, muc_host, null, changes);

    // Auto-destroy transient empty rooms
    if (room.occupant_count == 0 and !room.config.persistent) {
        _ = reg.destroyRoom(room_jid);
    }
}

/// Remove occupant from all rooms on session disconnect (called from server.closeSession).
pub fn handleSessionClose(server: *Server, session_id: usize, changes: *ChangeList) void {
    const reg = server.room_registry orelse return;
    const muc_host = server.muc_host orelse return;

    if (server.delivery_system != null) reg.lock.lock();
    defer if (server.delivery_system != null) reg.lock.unlock();

    // Occupants store local session IDs directly (no global mapping)
    for (&reg.rooms) |*slot| {
        const room = slot.* orelse continue;
        if (!room.active) continue;

        const removed = room.removeBySessionId(session_id) orelse continue;

        broadcastOccupantLeave(server, room, &removed, muc_host, null, changes);

        // Auto-destroy transient empty rooms
        if (room.occupant_count == 0 and !room.config.persistent) {
            log.info("transient room destroyed (empty): {s}", .{room.getJid()});
            server.room_registry.?.allocator.destroy(room);
            slot.* = null;
            reg.count -= 1;
        }
    }
}

// ============================================================================
// Presence helpers
// ============================================================================

fn sendOccupantPresence(
    server: *Server,
    target: *Session,
    room: *const Room,
    occ: *const Occupant,
    muc_host: []const u8,
    status_code: ?[]const u8,
    changes: *ChangeList,
) void {
    _ = server;
    _ = muc_host;
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // from = room@host/nick
    w.writeAll("<presence from='") catch return;
    w.writeAll(room.getJid()) catch return;
    w.writeByte('/') catch return;
    w.writeAll(occ.getNick()) catch return;
    w.writeAll("' to='") catch return;
    writeSessionJid(w, target) catch return;
    w.writeAll("'><x xmlns='http://jabber.org/protocol/muc#user'><item affiliation='") catch return;
    w.writeAll(occ.affiliation.toName()) catch return;
    w.writeAll("' role='") catch return;
    w.writeAll(occ.role.toName()) catch return;
    w.writeAll("'/>") catch return;
    if (status_code) |code| {
        w.writeAll("<status code='") catch return;
        w.writeAll(code) catch return;
        w.writeAll("'/>") catch return;
    }
    w.writeAll("</x></presence>") catch return;

    target.conn.queueSend(fbs.getWritten()) catch return;
    if (target.conn.hasPendingWrite()) {
        changes.addWrite(target.conn.fd, target.conn.id) catch {};
    }
}

fn sendSelfPresence(
    server: *Server,
    session: *Session,
    room: *const Room,
    nick: []const u8,
    muc_host: []const u8,
    changes: *ChangeList,
) void {
    _ = muc_host;
    _ = server;
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    w.writeAll("<presence from='") catch return;
    w.writeAll(room.getJid()) catch return;
    w.writeByte('/') catch return;
    w.writeAll(nick) catch return;
    w.writeAll("' to='") catch return;
    writeSessionJid(w, session) catch return;
    w.writeAll("'><x xmlns='http://jabber.org/protocol/muc#user'><item affiliation='owner' role='moderator'/><status code='110'/></x></presence>") catch return;

    session.conn.queueSend(fbs.getWritten()) catch return;
    if (session.conn.hasPendingWrite()) {
        changes.addWrite(session.conn.fd, session.conn.id) catch {};
    }
}

fn broadcastOccupantJoin(
    server: *Server,
    room: *const Room,
    nick: []const u8,
    real_jid: []const u8,
    role: Role,
    affiliation: Affiliation,
    muc_host: []const u8,
    new_session_id: usize,
    changes: *ChangeList,
) void {
    _ = real_jid;
    _ = muc_host;

    // Build prefix/suffix for multicast (no status 110 — self is always local)
    var prefix_buf: [512]u8 = undefined;
    var prefix_fbs = std.io.fixedBufferStream(&prefix_buf);
    const pw = prefix_fbs.writer();
    pw.writeAll("<presence from='") catch return;
    pw.writeAll(room.getJid()) catch return;
    pw.writeByte('/') catch return;
    pw.writeAll(nick) catch return;
    pw.writeAll("' to='") catch return;
    const prefix = prefix_fbs.getWritten();

    var suffix_buf: [512]u8 = undefined;
    var suffix_fbs = std.io.fixedBufferStream(&suffix_buf);
    const sw = suffix_fbs.writer();
    sw.writeAll("'><x xmlns='http://jabber.org/protocol/muc#user'><item affiliation='") catch return;
    sw.writeAll(affiliation.toName()) catch return;
    sw.writeAll("' role='") catch return;
    sw.writeAll(role.toName()) catch return;
    sw.writeAll("'/></x></presence>") catch return;
    const suffix = suffix_fbs.getWritten();

    // Multicast to remote workers
    server.deliverMulticastToWorkers(room, prefix, suffix);

    // Local fan-out (includes status 110 for the joining user)
    var suffix_110_buf: [512]u8 = undefined;
    var suffix_110_fbs = std.io.fixedBufferStream(&suffix_110_buf);
    const s110w = suffix_110_fbs.writer();
    s110w.writeAll("'><x xmlns='http://jabber.org/protocol/muc#user'><item affiliation='") catch return;
    s110w.writeAll(affiliation.toName()) catch return;
    s110w.writeAll("' role='") catch return;
    s110w.writeAll(role.toName()) catch return;
    s110w.writeAll("'/><status code='110'/></x></presence>") catch return;
    const suffix_110 = suffix_110_fbs.getWritten();

    for (&room.occupants) |*slot| {
        const occ = slot.* orelse continue;
        if (occ.session_id == room_registry.REMOTE_OCCUPANT) continue;
        if (occ.worker_id != server.worker_id) continue;
        const target = server.sessions[occ.session_id] orelse continue;

        const use_suffix = if (occ.session_id == new_session_id) suffix_110 else suffix;
        fanout.deliverPrebuilt(prefix, occ.getRealJid(), use_suffix, &target.conn) catch continue;
        if (target.conn.hasPendingWrite()) {
            changes.addWrite(target.conn.fd, occ.session_id) catch {};
        }
    }
}

fn broadcastOccupantLeave(
    server: *Server,
    room: *const Room,
    removed: *const Occupant,
    muc_host: []const u8,
    status_code: ?[]const u8,
    changes: *ChangeList,
) void {
    _ = muc_host;

    // Build prefix/suffix for multicast (no status 110)
    var prefix_buf: [512]u8 = undefined;
    var prefix_fbs = std.io.fixedBufferStream(&prefix_buf);
    const pw = prefix_fbs.writer();
    pw.writeAll("<presence from='") catch return;
    pw.writeAll(room.getJid()) catch return;
    pw.writeByte('/') catch return;
    pw.writeAll(removed.getNick()) catch return;
    pw.writeAll("' to='") catch return;
    const prefix = prefix_fbs.getWritten();

    var suffix_buf: [512]u8 = undefined;
    var suffix_fbs = std.io.fixedBufferStream(&suffix_buf);
    const sw = suffix_fbs.writer();
    sw.writeAll("' type='unavailable'><x xmlns='http://jabber.org/protocol/muc#user'><item affiliation='") catch return;
    sw.writeAll(removed.affiliation.toName()) catch return;
    sw.writeAll("' role='none'/>") catch return;
    if (status_code) |code| {
        sw.writeAll("<status code='") catch return;
        sw.writeAll(code) catch return;
        sw.writeAll("'/>") catch return;
    }
    sw.writeAll("</x></presence>") catch return;
    const suffix = suffix_fbs.getWritten();

    // Multicast to remote workers
    server.deliverMulticastToWorkers(room, prefix, suffix);

    // Local fan-out to remaining occupants on this worker
    for (&room.occupants) |*slot| {
        const occ = slot.* orelse continue;
        if (occ.session_id == room_registry.REMOTE_OCCUPANT) continue;
        if (occ.worker_id != server.worker_id) continue;
        const target = server.sessions[occ.session_id] orelse continue;

        fanout.deliverPrebuilt(prefix, occ.getRealJid(), suffix, &target.conn) catch continue;
        if (target.conn.hasPendingWrite()) {
            changes.addWrite(target.conn.fd, occ.session_id) catch {};
        }
    }

    // Send unavailable presence to the removed occupant themselves (with status 110)
    // The removed occupant is always on the current worker (they initiated part/were kicked locally)
    if (removed.session_id != room_registry.REMOTE_OCCUPANT and removed.worker_id == server.worker_id) {
        const self_target = server.sessions[removed.session_id] orelse return;

        // Build suffix with status 110
        var suffix_110_buf: [512]u8 = undefined;
        var suffix_110_fbs = std.io.fixedBufferStream(&suffix_110_buf);
        const s110w = suffix_110_fbs.writer();
        s110w.writeAll("' type='unavailable'><x xmlns='http://jabber.org/protocol/muc#user'><item affiliation='") catch return;
        s110w.writeAll(removed.affiliation.toName()) catch return;
        s110w.writeAll("' role='none'/><status code='110'/>") catch return;
        if (status_code) |code| {
            s110w.writeAll("<status code='") catch return;
            s110w.writeAll(code) catch return;
            s110w.writeAll("'/>") catch return;
        }
        s110w.writeAll("</x></presence>") catch return;

        fanout.deliverPrebuilt(prefix, removed.getRealJid(), suffix_110_fbs.getWritten(), &self_target.conn) catch return;
        if (self_target.conn.hasPendingWrite()) {
            changes.addWrite(self_target.conn.fd, removed.session_id) catch {};
        }
    }
}

/// Replay recent room history to a joining occupant (XEP-0045 §7.2.14).
/// Queries the archive store for the last history_length messages and delivers
/// each with a XEP-0203 delay stamp.
fn sendRoomHistory(
    server: *Server,
    session: *Session,
    room: *const Room,
    muc_host: []const u8,
    changes: *ChangeList,
) void {
    _ = muc_host;
    const archive = server.archive orelse return;
    const history_max = room.config.history_length;
    if (history_max == 0) return;

    const room_jid = room.getJid();

    // Query archive for most recent messages (backward = newest first, then we reverse)
    const result = archive.query(room_jid, .{
        .max = @as(u32, history_max),
        .backward = true,
    }) catch return;
    defer {
        for (result.messages) |msg| {
            server.allocator.free(msg.stanza_id);
            if (msg.stanza_xml.len > 0) server.allocator.free(@constCast(msg.stanza_xml));
        }
        server.allocator.free(result.messages);
    }

    if (result.messages.len == 0) return;

    // Deliver in chronological order (reverse of backward query)
    var i: usize = result.messages.len;
    while (i > 0) {
        i -= 1;
        const msg = result.messages[i];
        if (msg.stanza_xml.len == 0) continue;

        // Format XEP-0203 delay stamp from unix timestamp
        var delay_buf: [64]u8 = undefined;
        const delay_str = formatDelayStamp(&delay_buf, msg.timestamp) orelse continue;

        // The stored stanza is: <message from='room/nick' type='groupchat' ...>body</message>
        // We need to inject to='recipient' and a <delay/> element.
        // Find the first '>' to inject 'to' attribute and append delay before </message>
        const stanza = msg.stanza_xml;
        const close_tag = "</message>";
        const close_pos = std.mem.lastIndexOf(u8, stanza, close_tag) orelse continue;
        const first_gt = std.mem.indexOfScalar(u8, stanza, '>') orelse continue;

        var buf: [20480]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        const w = fbs.writer();

        // Write up to first '>', injecting to='jid'
        w.writeAll(stanza[0..first_gt]) catch continue;
        w.writeAll(" to='") catch continue;
        writeSessionJid(w, session) catch continue;
        w.writeByte('\'') catch continue;
        // Write rest of tag opening + body
        w.writeAll(stanza[first_gt..close_pos]) catch continue;
        // Append delay stamp
        w.writeAll("<delay xmlns='urn:xmpp:delay' from='") catch continue;
        w.writeAll(room_jid) catch continue;
        w.writeAll("' stamp='") catch continue;
        w.writeAll(delay_str) catch continue;
        w.writeAll("'/>") catch continue;
        w.writeAll(close_tag) catch continue;

        session.conn.queueSend(fbs.getWritten()) catch continue;
    }

    if (session.conn.hasPendingWrite()) {
        changes.addWrite(session.conn.fd, session.conn.id) catch {};
    }
}

/// Format a unix timestamp as ISO 8601 (XEP-0203): YYYY-MM-DDThh:mm:ssZ
fn formatDelayStamp(buf: []u8, timestamp: u64) ?[]const u8 {
    const ts: i64 = @intCast(timestamp);
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(ts) };
    const day = es.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();

    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    std.fmt.format(w, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,
        @as(u32, @intFromEnum(md.month)),
        @as(u32, md.day_index) + 1,
        ds.getHoursIntoDay(),
        ds.getMinutesIntoHour(),
        ds.getSecondsIntoMinute(),
    }) catch return null;
    return fbs.getWritten();
}

fn sendRoomSubject(
    server: *Server,
    session: *Session,
    room: *const Room,
    muc_host: []const u8,
    changes: *ChangeList,
) void {
    _ = server;
    _ = muc_host;
    const subject = room.config.getSubject();

    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    w.writeAll("<message from='") catch return;
    w.writeAll(room.getJid()) catch return;
    w.writeAll("' to='") catch return;
    writeSessionJid(w, session) catch return;
    w.writeAll("' type='groupchat'><subject>") catch return;
    w.writeAll(subject) catch return;
    w.writeAll("</subject></message>") catch return;

    session.conn.queueSend(fbs.getWritten()) catch return;
    if (session.conn.hasPendingWrite()) {
        changes.addWrite(session.conn.fd, session.conn.id) catch {};
    }
}

// ============================================================================
// Error helpers
// ============================================================================

fn sendPresenceError(
    server: *Server,
    session: *Session,
    room_local: []const u8,
    muc_host: []const u8,
    condition: []const u8,
    changes: *ChangeList,
) void {
    _ = server;
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    w.writeAll("<presence from='") catch return;
    w.writeAll(room_local) catch return;
    w.writeByte('@') catch return;
    w.writeAll(muc_host) catch return;
    w.writeAll("' to='") catch return;
    writeSessionJid(w, session) catch return;
    w.writeAll("' type='error'><error type='cancel'><") catch return;
    w.writeAll(condition) catch return;
    w.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>") catch return;

    session.conn.queueSend(fbs.getWritten()) catch return;
    if (session.conn.hasPendingWrite()) {
        changes.addWrite(session.conn.fd, session.conn.id) catch {};
    }
}

fn sendMessageError(
    server: *Server,
    session: *Session,
    room_local: []const u8,
    muc_host: []const u8,
    id_str: []const u8,
    condition: []const u8,
    changes: *ChangeList,
) void {
    _ = server;
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    w.writeAll("<message from='") catch return;
    w.writeAll(room_local) catch return;
    w.writeByte('@') catch return;
    w.writeAll(muc_host) catch return;
    w.writeAll("' to='") catch return;
    writeSessionJid(w, session) catch return;
    w.writeAll("' type='error'") catch return;
    if (id_str.len > 0) {
        w.writeAll(" id='") catch return;
        w.writeAll(id_str) catch return;
        w.writeByte('\'') catch return;
    }
    w.writeAll("><error type='cancel'><") catch return;
    w.writeAll(condition) catch return;
    w.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>") catch return;

    session.conn.queueSend(fbs.getWritten()) catch return;
    if (session.conn.hasPendingWrite()) {
        changes.addWrite(session.conn.fd, session.conn.id) catch {};
    }
}

// ============================================================================
// Utility
// ============================================================================

fn buildRoomJid(buf: *[320]u8, local: []const u8, host: []const u8) ?[]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    for (local) |c| {
        w.writeByte(std.ascii.toLower(c)) catch return null;
    }
    w.writeByte('@') catch return null;
    w.writeAll(host) catch return null;
    return fbs.getWritten();
}

fn buildFullJid(buf: *[256]u8, local: []const u8, domain: []const u8, resource: []const u8) ?[]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    w.writeAll(local) catch return null;
    w.writeByte('@') catch return null;
    w.writeAll(domain) catch return null;
    if (resource.len > 0) {
        w.writeByte('/') catch return null;
        w.writeAll(resource) catch return null;
    }
    return fbs.getWritten();
}

fn buildBareJid(buf: *[256]u8, local: []const u8, domain: []const u8) ?[]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    w.writeAll(local) catch return null;
    w.writeByte('@') catch return null;
    w.writeAll(domain) catch return null;
    return fbs.getWritten();
}

fn writeSessionJid(w: anytype, session: *const Session) !void {
    const bound = session.stream.bound_jid orelse return;
    try w.writeAll(bound.local);
    try w.writeByte('@');
    try w.writeAll(bound.domain);
    if (bound.resource.len > 0) {
        try w.writeByte('/');
        try w.writeAll(bound.resource);
    }
}

fn writeOccupantRealJid(w: anytype, occ: *const Occupant) !void {
    try w.writeAll(occ.getRealJid());
}
