//! # Router — Stanza routing, delivery, and S2S forwarding
//!
//! Routes accumulated stanzas to target session(s) via SessionMap lookup,
//! handles cross-thread MPSC delivery, S2S federation forwarding, message
//! archiving (XEP-0313), offline storage, and carbon copies (XEP-0280).
//! Extracted from server.zig as part of T51 decomposition.
//!
//! ## Entry Points
//!
//! - `dispatchStanza` — route a fully accumulated stanza (called from handleElementEnd)
//! - `forwardToS2s` — forward a stanza to a remote domain via S2S IPC

const std = @import("std");
const xml = @import("xml");
const xmpp = @import("xmpp");

const server_mod = @import("server.zig");
const Server = server_mod.Server;
const Session = server_mod.Session;
const StanzaKind = server_mod.StanzaKind;
const IPC_S2S_UDATA = server_mod.IPC_S2S_UDATA;
const ChangeList = @import("event_loop.zig").ChangeList;

const session_map_mod = @import("session_map");
const SessionEntry = session_map_mod.SessionEntry;
const delivery_queue_mod = @import("delivery_queue");
const muc_handler = @import("muc_handler.zig");
const ipc_protocol = @import("ipc_protocol");

const log = std.log.scoped(.router);

/// Route a fully accumulated stanza to target session(s).
/// Reconstructs the opening tag with the sender's full JID as 'from',
/// appends the accumulated child XML, and closes the stanza.
pub fn dispatchStanza(server: *Server, session: *Session, changes: *ChangeList) void {
    defer session.resetStanza();

    const to_str = session.stanza_to;
    const id_str = session.stanza_id;
    const type_str = session.stanza_type;
    const inner_xml = session.stanza_buf[0..session.stanza_buf_len];

    if (to_str.len == 0) return;

    // Parse target JID
    const to_jid = xmpp.Jid.parse(to_str) catch {
        log.warn("connection {d} stanza with invalid 'to': {s}", .{ session.conn.id, to_str });
        return;
    };

    // Get the sender's bound JID
    const from_jid = session.stream.bound_jid orelse return;

    // Build the from string (full JID: local@domain/resource)
    var from_buf: [256]u8 = undefined;
    var from_fbs = std.io.fixedBufferStream(&from_buf);
    const from_w = from_fbs.writer();
    from_w.writeAll(from_jid.local) catch return;
    from_w.writeByte('@') catch return;
    from_w.writeAll(from_jid.domain) catch return;
    if (from_jid.resource.len > 0) {
        from_w.writeByte('/') catch return;
        from_w.writeAll(from_jid.resource) catch return;
    }
    const from_str = from_fbs.getWritten();

    // XEP-0191: Block check — silently drop stanzas from blocked contacts.
    if (server.block_store) |bs| {
        var rblk_buf: [256]u8 = undefined;
        var rblk_fbs = std.io.fixedBufferStream(&rblk_buf);
        rblk_fbs.writer().writeAll(to_jid.local) catch {};
        rblk_fbs.writer().writeByte('@') catch {};
        rblk_fbs.writer().writeAll(to_jid.domain) catch {};
        const recip_bare = rblk_fbs.getWritten();

        var sblk_buf: [256]u8 = undefined;
        var sblk_fbs = std.io.fixedBufferStream(&sblk_buf);
        sblk_fbs.writer().writeAll(from_jid.local) catch {};
        sblk_fbs.writer().writeByte('@') catch {};
        sblk_fbs.writer().writeAll(from_jid.domain) catch {};
        const sender_bare = sblk_fbs.getWritten();

        if (bs.isBlocked(server.allocator, recip_bare, sender_bare) catch false) {
            return;
        }
    }

    // MUC domain? Route to MUC handler for groupchat fan-out.
    if (server.muc_host) |muc_host| {
        if (std.mem.eql(u8, to_jid.domain, muc_host)) {
            if (session.stanza_kind == .message and std.mem.eql(u8, type_str, "groupchat")) {
                muc_handler.handleMucGroupchat(server, session, to_jid.local, inner_xml, id_str, changes);
            }
            return;
        }
    }

    // Remote domain? Forward via S2S IPC instead of local delivery.
    if (!std.mem.eql(u8, to_jid.domain, server.server_host)) {
        forwardToS2s(server, session, from_str, to_str, type_str, id_str, inner_xml, changes);
        return;
    }

    // Route: find target session(s) via unified session map.
    const sm = server.session_map orelse return;
    var entries_buf: [16]SessionEntry = undefined;
    var local_ids: [16]usize = undefined;
    var target_count: usize = 0;

    var remote_delivered: bool = false;

    const route_count = if (to_jid.resource.len > 0) blk: {
        if (sm.findByFullJid(to_jid.local, to_jid.domain, to_jid.resource)) |e| {
            entries_buf[0] = e;
            break :blk @as(usize, 1);
        }
        break :blk @as(usize, 0);
    } else sm.findAvailableByBareJid(to_jid.local, to_jid.domain, &entries_buf);

    // Determine if this message should be archived (XEP-0313) and get a stanza-id (XEP-0359).
    const is_archivable = session.stanza_kind == .message and
        inner_xml.len > 0 and
        (std.mem.eql(u8, type_str, "chat") or type_str.len == 0) and
        std.mem.indexOf(u8, inner_xml, "<body") != null;

    var sid_buf: [32]u8 = undefined;
    const archive_stanza_id: []const u8 = if (is_archivable) server.generateStanzaId(&sid_buf) else "";

    // Build augmented inner_xml with stanza-id appended (for delivery to recipients)
    var aug_buf: [16512]u8 = undefined;
    var aug_fbs = std.io.fixedBufferStream(&aug_buf);
    const delivery_inner_xml: []const u8 = if (archive_stanza_id.len > 0) blk: {
        const aw = aug_fbs.writer();
        aw.writeAll(inner_xml) catch break :blk inner_xml;
        aw.writeAll("<stanza-id xmlns='urn:xmpp:sid:0' id='") catch break :blk inner_xml;
        aw.writeAll(archive_stanza_id) catch break :blk inner_xml;
        aw.writeAll("' by='") catch break :blk inner_xml;
        aw.writeAll(server.server_host) catch break :blk inner_xml;
        aw.writeAll("'/>") catch break :blk inner_xml;
        break :blk aug_fbs.getWritten();
    } else inner_xml;

    for (entries_buf[0..route_count]) |entry| {
        if (entry.worker_id == server.worker_id) {
            if (target_count < local_ids.len) {
                local_ids[target_count] = entry.local_session_id;
                target_count += 1;
            }
        } else {
            enqueueCrossThreadStanza(
                server,
                entry,
                from_str,
                to_str,
                type_str,
                id_str,
                delivery_inner_xml,
                session.stanza_kind,
            );
            remote_delivered = true;
        }
    }

    // Build sender bare JID for archive
    var sender_bare_buf: [256]u8 = undefined;
    var sender_bare_fbs = std.io.fixedBufferStream(&sender_bare_buf);
    sender_bare_fbs.writer().writeAll(from_jid.local) catch {};
    sender_bare_fbs.writer().writeByte('@') catch {};
    sender_bare_fbs.writer().writeAll(from_jid.domain) catch {};
    const sender_bare = sender_bare_fbs.getWritten();

    // Archive under both sender and recipient bare JIDs (T81 + T82)
    if (is_archivable) {
        if (server.archive) |archive| {
            var recip_buf: [256]u8 = undefined;
            var recip_fbs = std.io.fixedBufferStream(&recip_buf);
            recip_fbs.writer().writeAll(to_jid.local) catch {};
            recip_fbs.writer().writeByte('@') catch {};
            recip_fbs.writer().writeAll(to_jid.domain) catch {};
            const recipient_bare = recip_fbs.getWritten();

            // Build full stanza XML for archive (includes stanza-id element)
            var stanza_buf: [20480]u8 = undefined;
            var stanza_fbs = std.io.fixedBufferStream(&stanza_buf);
            const sw = stanza_fbs.writer();
            sw.writeAll("<message from='") catch {};
            sw.writeAll(from_str) catch {};
            sw.writeAll("' to='") catch {};
            sw.writeAll(to_str) catch {};
            sw.writeByte('\'') catch {};
            if (type_str.len > 0) {
                sw.writeAll(" type='") catch {};
                sw.writeAll(type_str) catch {};
                sw.writeByte('\'') catch {};
            }
            if (id_str.len > 0) {
                sw.writeAll(" id='") catch {};
                sw.writeAll(id_str) catch {};
                sw.writeByte('\'') catch {};
            }
            sw.writeByte('>') catch {};
            sw.writeAll(inner_xml) catch {};
            sw.writeAll("<stanza-id xmlns='urn:xmpp:sid:0' id='") catch {};
            sw.writeAll(archive_stanza_id) catch {};
            sw.writeAll("' by='") catch {};
            sw.writeAll(server.server_host) catch {};
            sw.writeAll("'/>") catch {};
            sw.writeAll("</message>") catch {};
            const full_stanza = stanza_fbs.getWritten();

            const timestamp: u64 = @intCast(std.time.timestamp());

            archive.store(recipient_bare, sender_bare, archive_stanza_id, timestamp, full_stanza) catch {};
            archive.store(sender_bare, recipient_bare, archive_stanza_id, timestamp, full_stanza) catch {};
        }
    }

    if (target_count == 0 and !remote_delivered) {
        // Offline storage for messages
        if (session.stanza_kind == .message) {
            if (server.offline) |store| {
                if (is_archivable and archive_stanza_id.len > 0) {
                    var recip_buf2: [256]u8 = undefined;
                    var recip_fbs2 = std.io.fixedBufferStream(&recip_buf2);
                    recip_fbs2.writer().writeAll(to_jid.local) catch {};
                    recip_fbs2.writer().writeByte('@') catch {};
                    recip_fbs2.writer().writeAll(to_jid.domain) catch {};
                    const recipient_bare2 = recip_fbs2.getWritten();
                    const timestamp: u64 = @intCast(std.time.timestamp());
                    if (store.storePointer(recipient_bare2, sender_bare, archive_stanza_id, timestamp) catch false) {
                        log.info("connection {d} message to {s} stored offline", .{ session.conn.id, to_str });
                        return;
                    }
                } else if (server.archive) |archive| {
                    var recip_buf2: [256]u8 = undefined;
                    var recip_fbs2 = std.io.fixedBufferStream(&recip_buf2);
                    recip_fbs2.writer().writeAll(to_jid.local) catch {};
                    recip_fbs2.writer().writeByte('@') catch {};
                    recip_fbs2.writer().writeAll(to_jid.domain) catch {};
                    const recipient_bare2 = recip_fbs2.getWritten();

                    var stanza_buf2: [20480]u8 = undefined;
                    var stanza_fbs2 = std.io.fixedBufferStream(&stanza_buf2);
                    const sw2 = stanza_fbs2.writer();
                    sw2.writeAll("<message from='") catch {};
                    sw2.writeAll(from_str) catch {};
                    sw2.writeAll("' to='") catch {};
                    sw2.writeAll(to_str) catch {};
                    sw2.writeByte('\'') catch {};
                    if (type_str.len > 0) {
                        sw2.writeAll(" type='") catch {};
                        sw2.writeAll(type_str) catch {};
                        sw2.writeByte('\'') catch {};
                    }
                    if (id_str.len > 0) {
                        sw2.writeAll(" id='") catch {};
                        sw2.writeAll(id_str) catch {};
                        sw2.writeByte('\'') catch {};
                    }
                    if (inner_xml.len == 0) {
                        sw2.writeAll("/>") catch {};
                    } else {
                        sw2.writeByte('>') catch {};
                        sw2.writeAll(inner_xml) catch {};
                        sw2.writeAll("</message>") catch {};
                    }
                    const full_stanza2 = stanza_fbs2.getWritten();
                    const timestamp: u64 = @intCast(std.time.timestamp());
                    const offline_id = if (id_str.len > 0) id_str else "offline";
                    archive.store(recipient_bare2, sender_bare, offline_id, timestamp, full_stanza2) catch {};
                    if (store.storePointer(recipient_bare2, sender_bare, offline_id, timestamp) catch false) {
                        log.info("connection {d} message to {s} stored offline", .{ session.conn.id, to_str });
                        return;
                    }
                }
            }
        }
        // No offline store configured or store full — bounce
        log.info("connection {d} message to {s} — recipient unavailable", .{ session.conn.id, to_str });
        sendServiceUnavailable(session, id_str, to_str, from_str);
        if (session.conn.hasPendingWrite()) {
            changes.addWrite(session.conn.fd, session.conn.id) catch {};
        }
        return;
    }

    const tag_name: []const u8 = switch (session.stanza_kind) {
        .message => "message",
        .presence => "presence",
        .none => return,
    };

    // Forward to each local target session
    for (local_ids[0..target_count]) |tid| {
        const target_session = server.sessions[tid] orelse continue;
        var msg_buf: [20480]u8 = undefined;
        var msg_fbs = std.io.fixedBufferStream(&msg_buf);
        const mw = msg_fbs.writer();

        mw.writeByte('<') catch continue;
        mw.writeAll(tag_name) catch continue;
        mw.writeAll(" from='") catch continue;
        mw.writeAll(from_str) catch continue;
        mw.writeAll("' to='") catch continue;
        mw.writeAll(to_str) catch continue;
        mw.writeByte('\'') catch continue;
        if (type_str.len > 0) {
            if (!(session.stanza_kind == .message and std.mem.eql(u8, type_str, "normal"))) {
                mw.writeAll(" type='") catch continue;
                mw.writeAll(type_str) catch continue;
                mw.writeByte('\'') catch continue;
            }
        }
        if (id_str.len > 0) {
            mw.writeAll(" id='") catch continue;
            mw.writeAll(id_str) catch continue;
            mw.writeByte('\'') catch continue;
        }

        if (delivery_inner_xml.len == 0) {
            mw.writeAll("/>") catch continue;
        } else {
            mw.writeByte('>') catch continue;
            mw.writeAll(delivery_inner_xml) catch continue;
            mw.writeAll("</") catch continue;
            mw.writeAll(tag_name) catch continue;
            mw.writeByte('>') catch continue;
        }

        target_session.conn.queueSend(msg_fbs.getWritten()) catch continue;
        if (target_session.conn.hasPendingWrite()) {
            changes.addWrite(target_session.conn.fd, tid) catch {};
        }
    }

    // XEP-0280: Message Carbons — send copies to sender's and recipient's other resources
    if (session.stanza_kind == .message and
        (std.mem.eql(u8, type_str, "chat") or type_str.len == 0))
    {
        sendCarbons(server, "sent", session, from_jid.local, from_jid.domain, from_str, to_str, type_str, id_str, delivery_inner_xml, changes);
        sendCarbons(server, "received", session, to_jid.local, to_jid.domain, from_str, to_str, type_str, id_str, delivery_inner_xml, changes);
    }
}

/// Forward a stanza to a remote domain via the S2S daemon IPC.
pub fn forwardToS2s(server: *Server, session: *Session, from_str: []const u8, to_str: []const u8, type_str: []const u8, id_str: []const u8, inner_xml: []const u8, changes: *ChangeList) void {
    if (!server.s2s_ipc.connected) {
        log.info("connection {d} stanza to remote {s} — no S2S daemon", .{ session.conn.id, to_str });
        sendServiceUnavailable(session, id_str, to_str, from_str);
        if (session.conn.hasPendingWrite()) {
            changes.addWrite(session.conn.fd, session.conn.id) catch {};
        }
        return;
    }

    const tag_name: []const u8 = switch (session.stanza_kind) {
        .message => "message",
        .presence => "presence",
        .none => return,
    };

    var stanza_buf: [20480]u8 = undefined;
    var stanza_fbs = std.io.fixedBufferStream(&stanza_buf);
    const sw = stanza_fbs.writer();

    sw.writeByte('<') catch return;
    sw.writeAll(tag_name) catch return;
    sw.writeAll(" from='") catch return;
    sw.writeAll(from_str) catch return;
    sw.writeAll("' to='") catch return;
    sw.writeAll(to_str) catch return;
    sw.writeByte('\'') catch return;
    if (type_str.len > 0) {
        if (!(session.stanza_kind == .message and std.mem.eql(u8, type_str, "normal"))) {
            sw.writeAll(" type='") catch return;
            sw.writeAll(type_str) catch return;
            sw.writeByte('\'') catch return;
        }
    }
    if (id_str.len > 0) {
        sw.writeAll(" id='") catch return;
        sw.writeAll(id_str) catch return;
        sw.writeByte('\'') catch return;
    }
    if (inner_xml.len == 0) {
        sw.writeAll("/>") catch return;
    } else {
        sw.writeByte('>') catch return;
        sw.writeAll(inner_xml) catch return;
        sw.writeAll("</") catch return;
        sw.writeAll(tag_name) catch return;
        sw.writeByte('>') catch return;
    }

    const stanza_xml = stanza_fbs.getWritten();

    server.s2s_ipc.send(.{ .s2s_deliver = .{
        .from_jid = from_str,
        .to_jid = to_str,
        .stanza_xml = stanza_xml,
    } }) catch {
        log.err("connection {d} failed to forward stanza to S2S daemon", .{session.conn.id});
        sendServiceUnavailable(session, id_str, to_str, from_str);
        if (session.conn.hasPendingWrite()) {
            changes.addWrite(session.conn.fd, session.conn.id) catch {};
        }
        return;
    };

    if (server.s2s_ipc.hasPendingSend()) {
        changes.addWrite(server.s2s_ipc.fd, IPC_S2S_UDATA) catch {};
    }

    log.info("connection {d} stanza to remote {s} forwarded via S2S", .{ session.conn.id, to_str });
}

/// Serialize a stanza and enqueue for cross-thread delivery via MPSC.
fn enqueueCrossThreadStanza(
    server: *Server,
    route: SessionEntry,
    from_str: []const u8,
    to_str: []const u8,
    type_str: []const u8,
    id_str: []const u8,
    inner_xml: []const u8,
    kind: StanzaKind,
) void {
    const ds = server.delivery_system orelse return;

    const tag_name: []const u8 = switch (kind) {
        .message => "message",
        .presence => "presence",
        .none => return,
    };

    var buf: [delivery_queue_mod.MAX_PAYLOAD_SIZE]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    w.writeByte('<') catch return;
    w.writeAll(tag_name) catch return;
    w.writeAll(" from='") catch return;
    w.writeAll(from_str) catch return;
    w.writeAll("' to='") catch return;
    w.writeAll(to_str) catch return;
    w.writeByte('\'') catch return;
    if (type_str.len > 0) {
        if (!(kind == .message and std.mem.eql(u8, type_str, "normal"))) {
            w.writeAll(" type='") catch return;
            w.writeAll(type_str) catch return;
            w.writeByte('\'') catch return;
        }
    }
    if (id_str.len > 0) {
        w.writeAll(" id='") catch return;
        w.writeAll(id_str) catch return;
        w.writeByte('\'') catch return;
    }
    if (inner_xml.len == 0) {
        w.writeAll("/>") catch return;
    } else {
        w.writeByte('>') catch return;
        w.writeAll(inner_xml) catch return;
        w.writeAll("</") catch return;
        w.writeAll(tag_name) catch return;
        w.writeByte('>') catch return;
    }

    ds.deliver(route.worker_id, route.local_session_id, route.generation, fbs.getWritten()) catch |err| {
        log.warn("cross-thread delivery failed to worker {d} session {d}: {}", .{ route.worker_id, route.local_session_id, err });
    };
}

/// XEP-0280: Send a carbon copy of a message to other resources of a user.
fn sendCarbons(
    server: *Server,
    carbon_type: []const u8,
    sender_session: *const Session,
    user_local: []const u8,
    user_domain: []const u8,
    from_str: []const u8,
    to_str: []const u8,
    type_str: []const u8,
    id_str: []const u8,
    delivery_inner_xml: []const u8,
    changes: *ChangeList,
) void {
    const sm = server.session_map orelse return;
    var entries: [16]SessionEntry = undefined;
    const count = sm.findAvailableByBareJid(user_local, user_domain, &entries);
    if (count == 0) return;

    for (entries[0..count]) |entry| {
        if (entry.worker_id == server.worker_id) {
            const target = server.sessions[entry.local_session_id] orelse continue;
            if (&target.conn == &sender_session.conn) continue;
            if (!target.carbons_enabled) continue;

            var cbuf: [20480]u8 = undefined;
            var cfbs = std.io.fixedBufferStream(&cbuf);
            const cw = cfbs.writer();

            cw.writeAll("<message from='") catch continue;
            cw.writeAll(user_local) catch continue;
            cw.writeByte('@') catch continue;
            cw.writeAll(user_domain) catch continue;
            cw.writeAll("' to='") catch continue;
            cw.writeAll(user_local) catch continue;
            cw.writeByte('@') catch continue;
            cw.writeAll(user_domain) catch continue;
            cw.writeByte('/') catch continue;
            cw.writeAll(entry.resource()) catch continue;
            cw.writeAll("' type='chat'>") catch continue;

            cw.writeByte('<') catch continue;
            cw.writeAll(carbon_type) catch continue;
            cw.writeAll(" xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'>") catch continue;

            cw.writeAll("<message from='") catch continue;
            cw.writeAll(from_str) catch continue;
            cw.writeAll("' to='") catch continue;
            cw.writeAll(to_str) catch continue;
            cw.writeByte('\'') catch continue;
            if (type_str.len > 0) {
                cw.writeAll(" type='") catch continue;
                cw.writeAll(type_str) catch continue;
                cw.writeByte('\'') catch continue;
            }
            if (id_str.len > 0) {
                cw.writeAll(" id='") catch continue;
                cw.writeAll(id_str) catch continue;
                cw.writeByte('\'') catch continue;
            }
            if (delivery_inner_xml.len == 0) {
                cw.writeAll("/>") catch continue;
            } else {
                cw.writeByte('>') catch continue;
                cw.writeAll(delivery_inner_xml) catch continue;
                cw.writeAll("</message>") catch continue;
            }

            cw.writeAll("</forwarded></") catch continue;
            cw.writeAll(carbon_type) catch continue;
            cw.writeAll("></message>") catch continue;

            target.conn.queueSend(cfbs.getWritten()) catch continue;
            if (target.conn.hasPendingWrite()) {
                changes.addWrite(target.conn.fd, entry.local_session_id) catch {};
            }
        }
        // Cross-thread carbon delivery would go via MPSC here (T89)
    }
}

/// Send a service-unavailable error for a message that can't be delivered.
pub fn sendServiceUnavailable(session: *Session, id_str: []const u8, to_str: []const u8, from_str: []const u8) void {
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    w.writeAll("<message type='error'") catch return;
    if (id_str.len > 0) {
        w.writeAll(" id='") catch return;
        w.writeAll(id_str) catch return;
        w.writeByte('\'') catch return;
    }
    w.writeAll(" from='") catch return;
    w.writeAll(to_str) catch return;
    w.writeAll("' to='") catch return;
    w.writeAll(from_str) catch return;
    w.writeAll("'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>") catch return;
    session.conn.queueSend(fbs.getWritten()) catch return;
}
