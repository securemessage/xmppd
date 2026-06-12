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
const actor_message = @import("message.zig");
const delivery_queue = @import("delivery_queue");

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

    if (to_resource.len == 0) {
        sendPresenceError(server, session, to_local, muc_host, "jid-malformed", changes);
        return;
    }

    // Build room JID for ownership check
    var room_jid_buf: [320]u8 = undefined;
    const room_jid = buildRoomJid(&room_jid_buf, to_local, muc_host) orelse return;
    const owner = room_registry.roomOwner(room_jid, server.getWorkerCount());

    if (owner != server.worker_id and server.delivery_system != null) {
        // Route to owning worker via MPSC
        const bound = session.stream.bound_jid orelse return;
        var real_jid_buf: [256]u8 = undefined;
        const real_jid = buildFullJid(&real_jid_buf, bound.local, bound.domain, bound.resource) orelse return;
        const join_gen: u32 = if (server.session_map) |sm| sm.getGeneration(bound.local, bound.domain, bound.resource) orelse 0 else 0;

        if (std.mem.eql(u8, type_str, "unavailable")) {
            server.enqueueRoomActorMessage(owner, .{ .room_part = .{
                .room_jid = room_jid,
                .real_jid = real_jid,
                .nick = to_resource,
                .worker_id = server.worker_id,
                .session_id = @intCast(session.conn.id),
                .generation = join_gen,
            } });
        } else if (type_str.len == 0) {
            server.enqueueRoomActorMessage(owner, .{ .room_join = .{
                .room_jid = room_jid,
                .real_jid = real_jid,
                .nick = to_resource,
                .worker_id = server.worker_id,
                .session_id = @intCast(session.conn.id),
                .generation = join_gen,
            } });
        }
        return;
    }

    // Local: this worker owns the room
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

    // Build room JID
    var room_jid_buf: [320]u8 = undefined;
    const room_jid = buildRoomJid(&room_jid_buf, to_local, muc_host) orelse return;
    const owner = room_registry.roomOwner(room_jid, server.getWorkerCount());

    if (owner != server.worker_id and server.delivery_system != null) {
        // Route to owning worker via MPSC
        const bound = session.stream.bound_jid orelse return;
        var sender_jid_buf: [256]u8 = undefined;
        const sender_jid = buildFullJid(&sender_jid_buf, bound.local, bound.domain, bound.resource) orelse return;
        server.enqueueRoomActorMessage(owner, .{ .room_message = .{
            .room_jid = room_jid,
            .from_jid = sender_jid,
            .inner_xml = inner_xml,
            .stanza_id = id_str,
        } });
        return;
    }

    const room = reg.findByJid(room_jid) orelse {
        sendMessageError(server, session, to_local, muc_host, id_str, "item-not-found", changes);
        return;
    };

    // Find sender's occupant entry by full JID (globally unique, no worker awareness needed)
    const bound = session.stream.bound_jid orelse return;
    var sender_jid_buf: [256]u8 = undefined;
    const sender_jid = buildFullJid(&sender_jid_buf, bound.local, bound.domain, bound.resource) orelse return;
    const sender_idx = room.findByRealJid(sender_jid) orelse {
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

    // List local public rooms (owned by this worker)
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
            const jid = room.getJid();
            if (std.mem.indexOfScalar(u8, jid, '@')) |at| {
                w.writeAll(jid[0..at]) catch break;
            } else {
                w.writeAll(jid) catch break;
            }
        }
        w.writeAll("'/>") catch break;
    }

    // List directory entries (rooms from other workers, via broadcast updates)
    var dir_entries: [256]room_registry.DirectoryEntry = undefined;
    const dir_count = reg.listDirectory(&dir_entries);
    for (dir_entries[0..dir_count]) |entry| {
        // Skip rooms that are also in our local shard (avoid duplicates)
        if (reg.findByJid(entry.getJid()) != null) continue;
        w.writeAll("<item jid='") catch break;
        w.writeAll(entry.getJid()) catch break;
        w.writeAll("' name='") catch break;
        const dname = entry.getName();
        if (dname.len > 0) {
            w.writeAll(dname) catch break;
        } else {
            const djid = entry.getJid();
            if (std.mem.indexOfScalar(u8, djid, '@')) |at| {
                w.writeAll(djid[0..at]) catch break;
            } else {
                w.writeAll(djid) catch break;
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

    var room_jid_buf: [320]u8 = undefined;
    const room_jid = buildRoomJid(&room_jid_buf, room_local, muc_host) orelse return;
    const owner = room_registry.roomOwner(room_jid, server.getWorkerCount());

    if (owner != server.worker_id and server.delivery_system != null) {
        var reply_jid_buf: [256]u8 = undefined;
        const bound = session.stream.bound_jid orelse return;
        const reply_jid = buildFullJid(&reply_jid_buf, bound.local, bound.domain, bound.resource) orelse return;
        server.enqueueRoomActorMessage(owner, .{ .room_disco_info = .{
            .room_jid = room_jid,
            .iq_id = iq_id,
            .reply_to_worker = server.worker_id,
            .reply_to_session = @intCast(session.conn.id),
            .reply_to_jid = reply_jid,
        } });
        return;
    }

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
/// Routes to owning worker if the room is not on this worker's shard.
pub fn handleMucAdminIq(
    server: *Server,
    session: *Session,
    room_local: []const u8,
    iq_id: []const u8,
    changes: *ChangeList,
) void {
    const muc_host = server.muc_host orelse return;

    var room_jid_buf: [320]u8 = undefined;
    const room_jid = buildRoomJid(&room_jid_buf, room_local, muc_host) orelse return;

    // Ownership routing
    const owner = room_registry.roomOwner(room_jid, server.getWorkerCount());
    if (owner != server.worker_id) {
        // Route to owning worker
        const req_bound = session.stream.bound_jid orelse return;
        var req_jid_buf: [256]u8 = undefined;
        const req_jid = buildFullJid(&req_jid_buf, req_bound.local, req_bound.domain, req_bound.resource) orelse return;

        const target_nick = session.iq_roster_item_jid;
        const new_role_str = session.iq_roster_item_sub;

        server.enqueueRoomActorMessage(owner, .{ .room_admin = .{
            .room_jid = room_jid,
            .actor_jid = req_jid,
            .target_nick = target_nick,
            .new_role = new_role_str,
            .iq_id = iq_id,
            .reply_to_worker = server.worker_id,
            .reply_to_session = @intCast(session.conn.id),
        } });
        return;
    }

    const reg = server.room_registry orelse return;
    const room = reg.findByJid(room_jid) orelse {
        sendIqErrorFromRoom(server, session, room_jid, iq_id, "item-not-found", changes);
        return;
    };

    // Verify requester is moderator+ (for kick) or admin+ (for ban)
    const req_bound = session.stream.bound_jid orelse return;
    var req_jid_buf: [256]u8 = undefined;
    const req_jid = buildFullJid(&req_jid_buf, req_bound.local, req_bound.domain, req_bound.resource) orelse return;
    const requester_idx = room.findByRealJid(req_jid) orelse {
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
        // T114: Send shadow_part to the kicked occupant's worker
        if (removed.worker_id != server.worker_id) {
            server.enqueueRoomActorMessage(removed.worker_id, .{ .shadow_part = .{
                .room_jid = room_jid,
                .real_jid = removed.getRealJid(),
                .nick = removed.getNick(),
                .worker_id = removed.worker_id,
                .session_id = @intCast(removed.session_id),
                .generation = 0,
            } });
        }

        // Auto-destroy transient empty rooms
        if (room.occupant_count == 0 and !room.config.persistent) {
            broadcastDirectoryUpdate(server, room_jid, room.config.getName(), false);
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
        broadcastDirectoryUpdate(server, room_jid, room_local, true);
    }
    const r = room.?;

    // Check if already in room (rejoin = no-op with self-presence)
    if (r.findByRealJid(real_jid)) |_| {
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
    const part_bound = session.stream.bound_jid orelse return;
    var part_jid_buf: [256]u8 = undefined;
    const part_jid = buildFullJid(&part_jid_buf, part_bound.local, part_bound.domain, part_bound.resource) orelse return;
    const removed = room.removeByRealJid(part_jid) orelse return;

    log.info("{s} left {s}", .{ removed.getRealJid(), room_jid });

    // Broadcast unavailable presence to remaining occupants
    broadcastOccupantLeave(server, room, &removed, muc_host, null, changes);

    // Auto-destroy transient empty rooms
    if (room.occupant_count == 0 and !room.config.persistent) {
        broadcastDirectoryUpdate(server, room_jid, room.config.getName(), false);
        _ = reg.destroyRoom(room_jid);
    }
}

/// Remove occupant from all rooms on session disconnect (called from server.closeSession).
/// In multi-thread mode, broadcasts SessionClosed to all OTHER workers so they can
/// clean up both canonical rooms (on the owning worker) and shadow rooms (on this worker).
pub fn handleSessionClose(server: *Server, real_jid: []const u8, changes: *ChangeList) void {
    // Broadcast to all other workers so owning workers remove occupant from canonical rooms
    // and all workers remove from their shadow rooms.
    if (server.delivery_system) |ds| {
        // Parse JID components for the SessionClosed message
        const at_pos = std.mem.indexOfScalar(u8, real_jid, '@') orelse return;
        const local = real_jid[0..at_pos];
        const rest = real_jid[at_pos + 1 ..];
        const slash_pos = std.mem.indexOfScalar(u8, rest, '/');
        const domain = if (slash_pos) |sp| rest[0..sp] else rest;
        const resource = if (slash_pos) |sp| rest[sp + 1 ..] else "";

        var i: u16 = 0;
        while (i < ds.worker_count) : (i += 1) {
            if (i == server.worker_id) continue;
            server.enqueueRoomActorMessage(i, .{ .session_closed = .{
                .local = local,
                .domain = domain,
                .resource = resource,
                .worker_id = server.worker_id,
                .session_id = 0,
            } });
        }
    }

    handleSessionCloseLocal(server, real_jid, changes);
}

/// Remove occupant from local rooms only (no cross-thread broadcast).
/// Called when processing a session_closed message received via MPSC from the
/// originating worker. Must NOT re-broadcast to avoid infinite cascade.
pub fn handleSessionCloseLocal(server: *Server, real_jid: []const u8, changes: *ChangeList) void {
    const reg = server.room_registry orelse return;
    const muc_host = server.muc_host orelse return;

    for (&reg.rooms) |*slot| {
        const room = slot.* orelse continue;
        if (!room.active) continue;

        const removed = room.removeByRealJid(real_jid) orelse continue;

        broadcastOccupantLeave(server, room, &removed, muc_host, null, changes);

        // Auto-destroy transient empty rooms
        if (room.occupant_count == 0 and !room.config.persistent) {
            broadcastDirectoryUpdate(server, room.getJid(), room.config.getName(), false);
            room.deinit();
            reg.allocator.destroy(room);
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
    _ = muc_host;
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Look up avatar hash for this occupant
    const avatar_hash = getAvatarHash(server, occ.getBareJid());
    defer if (avatar_hash) |h| server.allocator.free(h);

    // from = room@host/nick
    w.writeAll("<presence from='") catch return;
    w.writeAll(room.getJid()) catch return;
    w.writeByte('/') catch return;
    w.writeAll(occ.getNick()) catch return;
    w.writeAll("' to='") catch return;
    writeSessionJid(w, target) catch return;
    w.writeAll("'>") catch return;
    writeVcardUpdate(w, avatar_hash);
    w.writeAll("<x xmlns='http://jabber.org/protocol/muc#user'><item affiliation='") catch return;
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
    _ = muc_host;

    // Look up avatar hash for the joining user
    const bare_end = std.mem.indexOfScalar(u8, real_jid, '/') orelse real_jid.len;
    const avatar_hash = getAvatarHash(server, real_jid[0..bare_end]);
    defer if (avatar_hash) |h| server.allocator.free(h);

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
    sw.writeAll("'>") catch return;
    writeVcardUpdate(sw, avatar_hash);
    sw.writeAll("<x xmlns='http://jabber.org/protocol/muc#user'><item affiliation='") catch return;
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
    s110w.writeAll("'>") catch return;
    writeVcardUpdate(s110w, avatar_hash);
    s110w.writeAll("<x xmlns='http://jabber.org/protocol/muc#user'><item affiliation='") catch return;
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
// Room Actor — Cross-thread message processing
// ============================================================================
//
// These functions are called on the OWNING worker via handleRoomActorMessage()
// when a MUC operation arrives from a non-owning worker through the MPSC queue.
// They process the operation locally (no locks needed) and send responses back
// to the originating session via MPSC unicast + shadow room notifications.

/// Process a remote join request on the owning worker.
/// Called when a session on another worker wants to join a room owned by this worker.
pub fn processRemoteJoin(
    server: *Server,
    ev: actor_message.RoomEvent,
    changes: *ChangeList,
) void {
    const reg = server.room_registry orelse return;
    const muc_host = server.muc_host orelse return;
    const ds = server.delivery_system orelse return;

    // Extract bare JID from real JID (everything before '/')
    const slash_pos = std.mem.indexOfScalar(u8, ev.real_jid, '/') orelse ev.real_jid.len;
    const bare_jid = ev.real_jid[0..slash_pos];

    // Find or create room (may already exist from handleRoomActorMessage pre-creation)
    var room = reg.findByJid(ev.room_jid);
    if (room == null) {
        var config = room_store.RoomConfig{};
        config.persistent = false;
        const room_local = if (std.mem.indexOfScalar(u8, ev.room_jid, '@')) |at| ev.room_jid[0..at] else ev.room_jid;
        config.setName(room_local);
        config.created_at = @intCast(std.time.timestamp());
        room = reg.createRoom(ev.room_jid, config) catch return;
    }
    const r = room.?;
    // Detect new room by occupant count — the room may have been pre-created
    // by handleRoomActorMessage for its mailbox, but has no occupants yet.
    const is_new_room = (r.occupant_count == 0);

    // Check if already in room (rejoin)
    if (r.findByRealJid(ev.real_jid)) |_| {
        // Send self-presence back via MPSC unicast
        var buf: [2048]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        const w = fbs.writer();
        w.writeAll("<presence from='") catch return;
        w.writeAll(ev.room_jid) catch return;
        w.writeByte('/') catch return;
        w.writeAll(ev.nick) catch return;
        w.writeAll("' to='") catch return;
        w.writeAll(ev.real_jid) catch return;
        w.writeAll("'><x xmlns='http://jabber.org/protocol/muc#user'><item affiliation='owner' role='moderator'/><status code='110'/></x></presence>") catch return;
        ds.deliver(ev.worker_id, @intCast(ev.session_id), ev.generation, fbs.getWritten()) catch {};
        return;
    }

    // Nickname conflict check
    if (r.findByNick(ev.nick)) |existing_idx| {
        const existing = r.occupants[existing_idx].?;
        if (!std.mem.eql(u8, existing.getBareJid(), bare_jid)) {
            // Send conflict error back via MPSC
            var err_buf: [1024]u8 = undefined;
            var err_fbs = std.io.fixedBufferStream(&err_buf);
            const ew = err_fbs.writer();
            ew.writeAll("<presence from='") catch return;
            ew.writeAll(ev.room_jid) catch return;
            ew.writeAll("' to='") catch return;
            ew.writeAll(ev.real_jid) catch return;
            ew.writeAll("' type='error'><error type='cancel'><conflict xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>") catch return;
            ds.deliver(ev.worker_id, @intCast(ev.session_id), ev.generation, err_fbs.getWritten()) catch {};
            return;
        }
    }

    // Determine affiliation and role
    var affiliation: Affiliation = .none;
    var role: Role = .participant;
    if (is_new_room) {
        affiliation = .owner;
        role = .moderator;
        const room_local = if (std.mem.indexOfScalar(u8, ev.room_jid, '@')) |at| ev.room_jid[0..at] else ev.room_jid;
        broadcastDirectoryUpdate(server, ev.room_jid, room_local, true);
    } else {
        if (server.room_store) |store| {
            affiliation = store.getAffiliation(ev.room_jid, bare_jid) catch .none;
        }
        if (affiliation == .outcast) {
            var err_buf: [1024]u8 = undefined;
            var err_fbs = std.io.fixedBufferStream(&err_buf);
            const ew = err_fbs.writer();
            ew.writeAll("<presence from='") catch return;
            ew.writeAll(ev.room_jid) catch return;
            ew.writeAll("' to='") catch return;
            ew.writeAll(ev.real_jid) catch return;
            ew.writeAll("' type='error'><error type='cancel'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>") catch return;
            ds.deliver(ev.worker_id, @intCast(ev.session_id), ev.generation, err_fbs.getWritten()) catch {};
            return;
        }
        role = affiliation.defaultRole();
        if (r.config.moderated and role == .participant and affiliation == .none) {
            role = .visitor;
        }
    }

    // Members-only check
    if (r.config.members_only and affiliation == .none) {
        var err_buf: [1024]u8 = undefined;
        var err_fbs = std.io.fixedBufferStream(&err_buf);
        const ew = err_fbs.writer();
        ew.writeAll("<presence from='") catch return;
        ew.writeAll(ev.room_jid) catch return;
        ew.writeAll("' to='") catch return;
        ew.writeAll(ev.real_jid) catch return;
        ew.writeAll("' type='error'><error type='cancel'><registration-required xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>") catch return;
        ds.deliver(ev.worker_id, @intCast(ev.session_id), ev.generation, err_fbs.getWritten()) catch {};
        return;
    }

    // Add occupant to canonical room on owning worker
    _ = r.addOccupant(ev.nick, ev.real_jid, bare_jid, ev.session_id, ev.worker_id, 0, role, affiliation) catch {
        var err_buf: [1024]u8 = undefined;
        var err_fbs = std.io.fixedBufferStream(&err_buf);
        const ew = err_fbs.writer();
        ew.writeAll("<presence from='") catch return;
        ew.writeAll(ev.room_jid) catch return;
        ew.writeAll("' to='") catch return;
        ew.writeAll(ev.real_jid) catch return;
        ew.writeAll("' type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>") catch return;
        ds.deliver(ev.worker_id, @intCast(ev.session_id), ev.generation, err_fbs.getWritten()) catch {};
        return;
    };

    log.info("{s} joined {s} as '{s}' (remote, worker {d})", .{ ev.real_jid, ev.room_jid, ev.nick, ev.worker_id });

    // Send shadow_join to the remote worker so multicast fan-out works
    server.enqueueRoomActorMessage(ev.worker_id, .{ .shadow_join = .{
        .room_jid = ev.room_jid,
        .real_jid = ev.real_jid,
        .nick = ev.nick,
        .worker_id = ev.worker_id,
        .session_id = ev.session_id,
        .generation = ev.generation,
    } });

    // Send existing occupants' presence to the joiner (via MPSC unicast)
    for (&r.occupants) |*slot| {
        const occ = slot.* orelse continue;
        if (std.mem.eql(u8, occ.getRealJid(), ev.real_jid)) continue; // skip self
        var occ_buf: [2048]u8 = undefined;
        var occ_fbs = std.io.fixedBufferStream(&occ_buf);
        const ow = occ_fbs.writer();
        ow.writeAll("<presence from='") catch continue;
        ow.writeAll(r.getJid()) catch continue;
        ow.writeByte('/') catch continue;
        ow.writeAll(occ.getNick()) catch continue;
        ow.writeAll("' to='") catch continue;
        ow.writeAll(ev.real_jid) catch continue;
        ow.writeAll("'><x xmlns='http://jabber.org/protocol/muc#user'><item affiliation='") catch continue;
        ow.writeAll(occ.affiliation.toName()) catch continue;
        ow.writeAll("' role='") catch continue;
        ow.writeAll(occ.role.toName()) catch continue;
        ow.writeAll("'/></x></presence>") catch continue;
        ds.deliver(ev.worker_id, @intCast(ev.session_id), ev.generation, occ_fbs.getWritten()) catch continue;
    }

    // Broadcast new occupant's presence to ALL occupants (multicast + local)
    broadcastOccupantJoin(server, r, ev.nick, ev.real_jid, role, affiliation, muc_host, ev.session_id, changes);

    // Send self-presence with status 110 to the joiner
    {
        var self_buf: [2048]u8 = undefined;
        var self_fbs = std.io.fixedBufferStream(&self_buf);
        const sw = self_fbs.writer();
        sw.writeAll("<presence from='") catch return;
        sw.writeAll(r.getJid()) catch return;
        sw.writeByte('/') catch return;
        sw.writeAll(ev.nick) catch return;
        sw.writeAll("' to='") catch return;
        sw.writeAll(ev.real_jid) catch return;
        sw.writeAll("'><x xmlns='http://jabber.org/protocol/muc#user'><item affiliation='") catch return;
        sw.writeAll(affiliation.toName()) catch return;
        sw.writeAll("' role='") catch return;
        sw.writeAll(role.toName()) catch return;
        sw.writeAll("'/><status code='110'/></x></presence>") catch return;
        ds.deliver(ev.worker_id, @intCast(ev.session_id), ev.generation, self_fbs.getWritten()) catch {};
    }

    // Room history + subject sent via MPSC unicast
    sendRoomHistoryRemote(server, ev.real_jid, ev.worker_id, ev.session_id, ev.generation, r);
    {
        const subject = r.config.getSubject();
        var subj_buf: [2048]u8 = undefined;
        var subj_fbs = std.io.fixedBufferStream(&subj_buf);
        const sjw = subj_fbs.writer();
        sjw.writeAll("<message from='") catch return;
        sjw.writeAll(r.getJid()) catch return;
        sjw.writeAll("' to='") catch return;
        sjw.writeAll(ev.real_jid) catch return;
        sjw.writeAll("' type='groupchat'><subject>") catch return;
        sjw.writeAll(subject) catch return;
        sjw.writeAll("</subject></message>") catch return;
        ds.deliver(ev.worker_id, @intCast(ev.session_id), ev.generation, subj_fbs.getWritten()) catch {};
    }
}

/// Process a remote part request on the owning worker.
pub fn processRemotePart(
    server: *Server,
    ev: actor_message.RoomEvent,
    changes: *ChangeList,
) void {
    const reg = server.room_registry orelse return;
    const muc_host = server.muc_host orelse return;

    const room = reg.findByJid(ev.room_jid) orelse return;
    const removed = room.removeByRealJid(ev.real_jid) orelse return;

    log.info("{s} left {s} (remote, worker {d})", .{ ev.real_jid, ev.room_jid, ev.worker_id });

    // Send shadow_part to the remote worker
    server.enqueueRoomActorMessage(ev.worker_id, .{ .shadow_part = .{
        .room_jid = ev.room_jid,
        .real_jid = ev.real_jid,
        .nick = ev.nick,
        .worker_id = ev.worker_id,
        .session_id = ev.session_id,
        .generation = ev.generation,
    } });

    broadcastOccupantLeave(server, room, &removed, muc_host, null, changes);

    if (room.occupant_count == 0 and !room.config.persistent) {
        broadcastDirectoryUpdate(server, ev.room_jid, room.config.getName(), false);
        _ = reg.destroyRoom(ev.room_jid);
    }
}

/// Process a remote groupchat message on the owning worker.
pub fn processRemoteGroupchat(
    server: *Server,
    ev: actor_message.RoomMessageEvent,
    changes: *ChangeList,
) void {
    const reg = server.room_registry orelse return;
    const muc_host = server.muc_host orelse return;
    _ = muc_host;

    const room = reg.findByJid(ev.room_jid) orelse return;

    // Find sender's occupant entry
    const sender_idx = room.findByRealJid(ev.from_jid) orelse return;
    const sender = room.occupants[sender_idx].?;

    // Check role: in moderated rooms, visitors cannot speak
    if (room.config.moderated and sender.role == .visitor) return;

    // Build the from JID: room@conference.host/sender_nick
    var from_buf: [384]u8 = undefined;
    var from_fbs = std.io.fixedBufferStream(&from_buf);
    const fw = from_fbs.writer();
    fw.writeAll(ev.room_jid) catch return;
    fw.writeByte('/') catch return;
    fw.writeAll(sender.getNick()) catch return;
    const from_str = from_fbs.getWritten();

    var prefix_buf: [512]u8 = undefined;
    const prefix_len = fanout.buildPrefix(&prefix_buf, from_str) orelse return;
    var suffix_buf: [16500]u8 = undefined;
    const suffix_len = fanout.buildSuffix(&suffix_buf, ev.stanza_id, ev.inner_xml) orelse return;
    const prefix = prefix_buf[0..prefix_len];
    const suffix = suffix_buf[0..suffix_len];

    // Cross-thread multicast
    server.deliverMulticastToWorkers(room, prefix, suffix);

    // Local fan-out (same bounded continuation as handleMucGroupchat)
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

    if (!all_done) {
        if (server.fanout_queue.alloc()) |pf| {
            @memcpy(pf.room_jid_buf[0..ev.room_jid.len], ev.room_jid);
            pf.room_jid_len = @intCast(ev.room_jid.len);
            @memcpy(pf.prefix_buf[0..prefix_len], prefix);
            pf.prefix_len = prefix_len;
            @memcpy(pf.suffix_buf[0..suffix_len], suffix);
            pf.suffix_len = suffix_len;
            pf.next_slot = resume_slot;
        } else {
            deliverRemainingSync(server, room, resume_slot, prefix, suffix, changes);
        }
    }

    // Archive
    if (server.archive) |archive| {
        const timestamp: u64 = @intCast(std.time.timestamp());
        const stanza_id = if (ev.stanza_id.len > 0) ev.stanza_id else "muc";
        var arch_buf: [17200]u8 = undefined;
        var arch_fbs = std.io.fixedBufferStream(&arch_buf);
        const aw = arch_fbs.writer();
        aw.writeAll("<message from='") catch return;
        aw.writeAll(from_str) catch return;
        aw.writeAll("' type='groupchat'") catch return;
        if (ev.stanza_id.len > 0) {
            aw.writeAll(" id='") catch return;
            aw.writeAll(ev.stanza_id) catch return;
            aw.writeByte('\'') catch return;
        }
        aw.writeByte('>') catch return;
        aw.writeAll(ev.inner_xml) catch return;
        aw.writeAll("</message>") catch return;
        archive.store(ev.room_jid, from_str, stanza_id, timestamp, arch_fbs.getWritten()) catch {};
    }
}

/// Process a remote disco#info request on the owning worker.
/// Builds the IQ result and sends it back to the requesting session via MPSC unicast.
pub fn processRemoteDiscoInfo(
    server: *Server,
    ev: actor_message.DiscoRequest,
    changes: *ChangeList,
) void {
    _ = changes;
    const reg = server.room_registry orelse return;
    const ds = server.delivery_system orelse return;

    var buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    w.writeAll("<iq type='result' from='") catch return;
    w.writeAll(ev.room_jid) catch return;
    w.writeAll("' to='") catch return;
    w.writeAll(ev.reply_to_jid) catch return;
    w.writeAll("' id='") catch return;
    w.writeAll(ev.iq_id) catch return;
    w.writeAll("'><query xmlns='http://jabber.org/protocol/disco#info'>") catch return;

    if (reg.findByJid(ev.room_jid)) |room| {
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
        w.writeAll("<identity category='conference' type='text'/>") catch return;
        w.writeAll("<feature var='http://jabber.org/protocol/muc'/>") catch return;
        w.writeAll("<feature var='urn:xmpp:mam:2'/>") catch return;
    }

    w.writeAll("</query></iq>") catch return;
    ds.deliver(ev.reply_to_worker, @intCast(ev.reply_to_session), 0, fbs.getWritten()) catch {};
}

/// Process a remote disco#items request.
/// With the broadcast room directory model, disco#items is handled entirely
/// locally by handleMucDiscoItems (which reads both local rooms + directory).
/// This function should not be called in normal operation — it exists only
/// as a safety net for messages already in flight during deployment transitions.
pub fn processRemoteDiscoItems(
    server: *Server,
    ev: actor_message.DiscoRequest,
    changes: *ChangeList,
) void {
    _ = changes;
    _ = server;
    _ = ev;
    log.debug("processRemoteDiscoItems called (should not happen with directory model)", .{});
}

/// Handle shadow_join: add a local occupant to the shadow room on this worker.
/// Called when the owning worker notifies us that one of our sessions joined a room.
pub fn handleShadowJoin(server: *Server, ev: actor_message.RoomEvent) void {
    const reg = server.room_registry orelse return;

    // Find or create shadow room
    var room = reg.findByJid(ev.room_jid);
    if (room == null) {
        room = reg.createRoom(ev.room_jid, .{ .persistent = false }) catch return;
    }
    const r = room.?;

    // Extract bare JID
    const slash_pos = std.mem.indexOfScalar(u8, ev.real_jid, '/') orelse ev.real_jid.len;
    const bare_jid = ev.real_jid[0..slash_pos];

    // Add occupant to shadow (ignore errors — shadow is best-effort)
    _ = r.addOccupant(ev.nick, ev.real_jid, bare_jid, ev.session_id, ev.worker_id, 0, .participant, .none) catch {};
}

/// Handle shadow_part: remove a local occupant from the shadow room on this worker.
pub fn handleShadowPart(server: *Server, ev: actor_message.RoomEvent) void {
    const reg = server.room_registry orelse return;

    const room = reg.findByJid(ev.room_jid) orelse return;
    _ = room.removeByRealJid(ev.real_jid);

    // Destroy shadow room if empty (no more local occupants)
    if (room.occupant_count == 0) {
        _ = reg.destroyRoom(ev.room_jid);
    }
}

/// Send room history to a remote joiner via MPSC unicast.
fn sendRoomHistoryRemote(
    server: *Server,
    real_jid: []const u8,
    target_worker: u16,
    target_session: u32,
    target_generation: u32,
    room: *const Room,
) void {
    const archive = server.archive orelse return;
    const ds = server.delivery_system orelse return;
    const history_max = room.config.history_length;
    if (history_max == 0) return;

    const room_jid = room.getJid();
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

    var i: usize = result.messages.len;
    while (i > 0) {
        i -= 1;
        const msg = result.messages[i];
        if (msg.stanza_xml.len == 0) continue;

        var delay_buf: [64]u8 = undefined;
        const delay_str = formatDelayStamp(&delay_buf, msg.timestamp) orelse continue;

        const stanza = msg.stanza_xml;
        const close_tag = "</message>";
        const close_pos = std.mem.lastIndexOf(u8, stanza, close_tag) orelse continue;
        const first_gt = std.mem.indexOfScalar(u8, stanza, '>') orelse continue;

        var buf: [delivery_queue.MAX_PAYLOAD_SIZE]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        const w = fbs.writer();

        w.writeAll(stanza[0..first_gt]) catch continue;
        w.writeAll(" to='") catch continue;
        w.writeAll(real_jid) catch continue;
        w.writeByte('\'') catch continue;
        w.writeAll(stanza[first_gt..close_pos]) catch continue;
        w.writeAll("<delay xmlns='urn:xmpp:delay' from='") catch continue;
        w.writeAll(room_jid) catch continue;
        w.writeAll("' stamp='") catch continue;
        w.writeAll(delay_str) catch continue;
        w.writeAll("'/>") catch continue;
        w.writeAll(close_tag) catch continue;

        ds.deliver(target_worker, @intCast(target_session), target_generation, fbs.getWritten()) catch continue;
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

/// Look up a user's XEP-0084 avatar hash from PEP metadata node.
/// Returns the SHA-1 hash string (hex) or null if no avatar published.
fn getAvatarHash(server: *Server, bare_jid: []const u8) ?[]const u8 {
    const pep = server.pep_store orelse return null;
    const maybe_metadata = pep.getItem(
        server.allocator,
        bare_jid,
        "urn:xmpp:avatar:metadata",
        "current",
    ) catch return null;
    const metadata = maybe_metadata orelse return null;
    defer server.allocator.free(metadata);

    // Extract id='...' from <info id='HASH' .../>
    const id_attr = "id='";
    const id_start = std.mem.indexOf(u8, metadata, id_attr) orelse return null;
    const hash_start = id_start + id_attr.len;
    if (hash_start >= metadata.len) return null;
    const remaining = metadata[hash_start..];
    const hash_end = std.mem.indexOfScalar(u8, remaining, '\'') orelse return null;
    if (hash_end == 0 or hash_end > 64) return null;

    // Copy to a server-allocator-owned slice (caller-free'd per stanza)
    return server.allocator.dupe(u8, remaining[0..hash_end]) catch return null;
}

/// Write XEP-0153 vcard-temp:x:update element with avatar photo hash.
fn writeVcardUpdate(w: anytype, avatar_hash: ?[]const u8) void {
    const hash = avatar_hash orelse return;
    w.writeAll("<x xmlns='vcard-temp:x:update'><photo>") catch return;
    w.writeAll(hash) catch return;
    w.writeAll("</photo></x>") catch return;
}

// ============================================================================
// Room directory + admin routing (Step 3 completion)
// ============================================================================

/// Handle a room directory update broadcast from another worker.
/// Updates the local room directory projection for disco#items.
pub fn handleRoomDirectoryUpdate(server: *Server, ev: actor_message.RoomDirectoryUpdate) void {
    const reg = server.room_registry orelse return;
    if (ev.active) {
        // Room created on another worker — add to local directory
        reg.updateDirectory(ev.room_jid, ev.room_name, true);
    } else {
        // Room destroyed on another worker — remove from local directory
        reg.updateDirectory(ev.room_jid, ev.room_name, false);
    }
}

/// Process a remote admin action (kick/ban/voice) on the owning worker.
pub fn processRemoteAdminAction(
    server: *Server,
    ev: actor_message.AdminAction,
    changes: *ChangeList,
) void {
    const reg = server.room_registry orelse return;
    const muc_host = server.muc_host orelse return;
    const room = reg.findByJid(ev.room_jid) orelse {
        // Room doesn't exist — send error back
        sendIqErrorToRemote(server, ev.room_jid, ev.iq_id, ev.reply_to_worker, ev.reply_to_session, "item-not-found");
        return;
    };

    // Verify requester is in the room
    const requester_idx = room.findByRealJid(ev.actor_jid) orelse {
        sendIqErrorToRemote(server, ev.room_jid, ev.iq_id, ev.reply_to_worker, ev.reply_to_session, "not-allowed");
        return;
    };
    const requester = room.occupants[requester_idx].?;

    // Moderator for kick, admin/owner for ban
    if (requester.role != .moderator and requester.affiliation != .admin and requester.affiliation != .owner) {
        sendIqErrorToRemote(server, ev.room_jid, ev.iq_id, ev.reply_to_worker, ev.reply_to_session, "forbidden");
        return;
    }

    // Find target by nick
    const target_idx = room.findByNick(ev.target_nick) orelse {
        sendIqErrorToRemote(server, ev.room_jid, ev.iq_id, ev.reply_to_worker, ev.reply_to_session, "item-not-found");
        return;
    };

    if (std.mem.eql(u8, ev.new_role, "none")) {
        // Kick
        const removed = room.removeOccupant(target_idx) orelse return;
        broadcastOccupantLeave(server, room, &removed, muc_host, "307", changes);
        // T114: Send shadow_part to the kicked occupant's worker so it removes the
        // stale shadow entry. Without this, the shadow room retains a ghost occupant.
        if (removed.worker_id != server.worker_id) {
            server.enqueueRoomActorMessage(removed.worker_id, .{ .shadow_part = .{
                .room_jid = ev.room_jid,
                .real_jid = removed.getRealJid(),
                .nick = removed.getNick(),
                .worker_id = removed.worker_id,
                .session_id = @intCast(removed.session_id),
                .generation = 0,
            } });
        }
        if (room.occupant_count == 0 and !room.config.persistent) {
            broadcastDirectoryUpdate(server, ev.room_jid, room.config.getName(), false);
            _ = reg.destroyRoom(ev.room_jid);
        }
    } else if (std.mem.eql(u8, ev.new_role, "visitor")) {
        if (room.occupants[target_idx]) |*occ| {
            occ.role = .visitor;
        }
    } else if (std.mem.eql(u8, ev.new_role, "participant")) {
        if (room.occupants[target_idx]) |*occ| {
            occ.role = .participant;
        }
    }

    // Send IQ result back to requester
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();
    w.writeAll("<iq type='result' from='") catch return;
    w.writeAll(ev.room_jid) catch return;
    w.writeAll("' id='") catch return;
    w.writeAll(ev.iq_id) catch return;
    w.writeAll("'/>") catch return;

    const ds = server.delivery_system orelse return;
    ds.deliver(ev.reply_to_worker, @intCast(ev.reply_to_session), 0, fbs.getWritten()) catch {};
}

/// Process a remote MUC MAM query on the owning worker (T112).
/// Queries the local archive (authoritative for this room) and sends each
/// result message + final fin IQ back to the querying session via MPSC unicast.
pub fn processRemoteMamQuery(
    server: *Server,
    ev: actor_message.MamQuery,
    changes: *ChangeList,
) void {
    _ = changes;
    const reg = server.room_registry orelse return;
    if (reg.findByJid(ev.room_jid) == null) {
        sendIqErrorToRemote(server, ev.room_jid, ev.query_id, ev.reply_to_worker, ev.reply_to_session, "item-not-found");
        return;
    }

    const ds = server.delivery_system orelse return;
    const archive = server.archive orelse {
        // No archive configured — send empty fin
        var buf: [512]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        const fw = fbs.writer();
        fw.writeAll("<iq type='result' from='") catch return;
        fw.writeAll(ev.room_jid) catch return;
        fw.writeAll("' to='") catch return;
        fw.writeAll(ev.reply_to_jid) catch return;
        fw.writeAll("' id='") catch return;
        fw.writeAll(ev.query_id) catch return;
        fw.writeAll("'><fin xmlns='urn:xmpp:mam:2' complete='true'><set xmlns='http://jabber.org/protocol/rsm'><count>0</count></set></fin></iq>") catch return;
        ds.deliver(ev.reply_to_worker, @intCast(ev.reply_to_session), 0, fbs.getWritten()) catch {};
        return;
    };

    // Parse timestamps from ISO text
    const mam_handler = @import("mam_handler");
    const parseTs = @import("iq_handler.zig").parseTimestamp;
    const start_ts = if (ev.start.len > 0) parseTs(ev.start) else null;
    const end_ts = if (ev.end_field.len > 0) parseTs(ev.end_field) else null;

    const query = mam_handler.MamQuery{
        .iq_id = ev.query_id,
        .owner = ev.room_jid,
        .query_id = ev.query_id,
        .with = if (ev.with.len > 0) ev.with else null,
        .start = start_ts,
        .end = end_ts,
        .after_id = null,
        .before_id = null,
        .max = 50,
    };

    const ArchBackend = @import("archive_backend").Backend;
    var response = mam_handler.handleMamQuery(ArchBackend, archive, query, server.allocator) catch {
        sendIqErrorToRemote(server, ev.room_jid, ev.query_id, ev.reply_to_worker, ev.reply_to_session, "internal-server-error");
        return;
    };
    defer response.deinit();

    // Send each result message via MPSC unicast
    for (response.messages) |msg| {
        ds.deliver(ev.reply_to_worker, @intCast(ev.reply_to_session), 0, msg.xml) catch continue;
    }

    // Send the fin IQ
    ds.deliver(ev.reply_to_worker, @intCast(ev.reply_to_session), 0, response.fin_iq) catch {};
}

/// Broadcast a room directory update to all other workers.
/// Called when a canonical (non-shadow) public room is created or destroyed.
fn broadcastDirectoryUpdate(server: *Server, room_jid: []const u8, room_name: []const u8, active: bool) void {
    const ds = server.delivery_system orelse return;
    const wc = server.getWorkerCount();
    if (wc <= 1) return;

    var buf: [actor_message.MAX_ENCODED_SIZE]u8 = undefined;
    const msg = actor_message.Message{ .room_directory_update = .{
        .room_jid = room_jid,
        .room_name = room_name,
        .active = active,
    } };
    const len = actor_message.encode(&buf, msg) orelse return;

    var w: u16 = 0;
    while (w < wc) : (w += 1) {
        if (w == server.worker_id) continue;
        ds.deliver(w, delivery_queue.ROOM_ACTOR_SENTINEL, 0, buf[0..len]) catch {};
    }
}

/// Send an IQ error back to a remote worker via MPSC unicast.
fn sendIqErrorToRemote(server: *Server, room_jid: []const u8, iq_id: []const u8, target_worker: u16, target_session: u32, error_type: []const u8) void {
    const ds = server.delivery_system orelse return;
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();
    w.writeAll("<iq type='error' from='") catch return;
    w.writeAll(room_jid) catch return;
    w.writeAll("' id='") catch return;
    w.writeAll(iq_id) catch return;
    w.writeAll("'><error type='cancel'><") catch return;
    w.writeAll(error_type) catch return;
    w.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>") catch return;
    ds.deliver(target_worker, @intCast(target_session), 0, fbs.getWritten()) catch {};
}
