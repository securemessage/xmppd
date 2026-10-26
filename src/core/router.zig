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
const ChangeList = @import("event_loop.zig").ChangeList;

const session_map_mod = @import("session_map");
const SessionEntry = session_map_mod.SessionEntry;
const delivery_queue_mod = @import("delivery_queue");
const muc_handler = @import("muc_handler.zig");
const fanout = @import("fanout.zig");
const ipc_protocol = @import("ipc_protocol");

const log = std.log.scoped(.router);

/// A bare JID that can be a store key is at most MAX_KEY_LEN (511) bytes, so
/// this buffer holds every valid key in full (S4).
pub const BARE_JID_MAX = 512;

/// Build a bare JID "local@domain" into out. A JID that does not fit returns
/// NoSpaceLeft rather than a truncated prefix (S4).
pub fn buildBareJid(local: []const u8, domain: []const u8, out: *[BARE_JID_MAX]u8) ![]const u8 {
    var fbs = std.io.fixedBufferStream(out);
    const w = fbs.writer();
    try w.writeAll(local);
    try w.writeByte('@');
    try w.writeAll(domain);
    return fbs.getWritten();
}

test "router: bare JID buffers hold a full store-key JID without truncation" {
    var out: [BARE_JID_MAX]u8 = undefined;
    // A bare JID just under the store-key limit builds in full.
    var local: [300]u8 = undefined;
    @memset(&local, 'l');
    var domain: [200]u8 = undefined;
    @memset(&domain, 'd');
    const jid = try buildBareJid(&local, &domain, &out);
    try std.testing.expectEqual(@as(usize, 300 + 1 + 200), jid.len);
    // A full store-key-length bare JID (511) also fits.
    var local2: [280]u8 = undefined;
    @memset(&local2, 'l');
    var domain2: [230]u8 = undefined;
    @memset(&domain2, 'd');
    const jid2 = try buildBareJid(&local2, &domain2, &out);
    try std.testing.expectEqual(@as(usize, 511), jid2.len);

    var local3: [300]u8 = undefined;
    @memset(&local3, 'l');
    var domain3: [300]u8 = undefined;
    @memset(&domain3, 'd');
    try std.testing.expectError(error.NoSpaceLeft, buildBareJid(&local3, &domain3, &out));
}

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

    // Get the sender's bound JID. Stanzas received before resource binding
    // MUST NOT be processed (RFC 6120 §7.1 / T182). Unreachable in practice —
    // the handleElementStart gates close third-party-addressed streams and
    // bounce server-addressed ones upstream — but if a message/IQ ever gets
    // here unbound, answer with a not-authorized stanza error (IQs must
    // always be answered); presence stays silently ignored.
    const from_jid = session.stream.bound_jid orelse {
        if (session.stanza_kind == .message and !std.mem.eql(u8, type_str, "error")) {
            sendNotAuthorized(session, id_str, to_str);
            if (session.conn.hasPendingWrite()) {
                changes.addWrite(session.conn.fd, session.conn.id) catch {};
            }
        } else if (session.stanza_kind == .iq and
            (std.mem.eql(u8, type_str, "get") or std.mem.eql(u8, type_str, "set")))
        {
            sendNotAuthorized(session, id_str, to_str);
            if (session.conn.hasPendingWrite()) {
                changes.addWrite(session.conn.fd, session.conn.id) catch {};
            }
        }
        return;
    };

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
    var lease_a = server.leaseScratch(.a);
    defer lease_a.release();
    const entries_buf = lease_a.entries;
    const local_ids = server.scratchIdsA();
    var target_count: usize = 0;

    var remote_delivered: bool = false;

    const route_count = if (to_jid.resource.len > 0) blk: {
        // RFC 6121 §8.5.3: Message addressed to full JID — deliver to that resource only.
        if (sm.findByFullJid(to_jid.local, to_jid.domain, to_jid.resource)) |e| {
            entries_buf[0] = e;
            break :blk @as(usize, 1);
        }
        // Resource not found (§8.5.3.2). For type='chat', fall back to best
        // available resource (§8.5.3.2.1). For others, store offline or bounce.
        if (session.stanza_kind == .message and std.mem.eql(u8, type_str, "chat")) {
            const avail_count = sm.findAvailableByBareJid(to_jid.local, to_jid.domain, entries_buf);
            if (avail_count > 0) {
                var best_idx: usize = 0;
                var best_prio: i8 = -128;
                for (entries_buf[0..avail_count], 0..) |entry, i| {
                    if (entry.priority >= 0 and entry.priority > best_prio) {
                        best_prio = entry.priority;
                        best_idx = i;
                    }
                }
                if (best_prio >= 0) {
                    entries_buf[0] = entries_buf[best_idx];
                    break :blk @as(usize, 1);
                }
            }
        }
        break :blk @as(usize, 0);
    } else blk: {
        // RFC 6121 §8.5.2: Stanza addressed to bare JID — deliver to available resources.
        const avail_count = sm.findAvailableByBareJid(to_jid.local, to_jid.domain, entries_buf);
        if (avail_count == 0) break :blk @as(usize, 0);

        if (session.stanza_kind == .iq) {
            // RFC 6121 §8.5.2.1.3: IQ to bare JID — deliver to ONE best resource.
            var best_idx: usize = 0;
            var best_prio: i8 = -128;
            for (entries_buf[0..avail_count], 0..) |entry, i| {
                if (entry.priority > best_prio) {
                    best_prio = entry.priority;
                    best_idx = i;
                }
            }
            if (best_prio < 0) break :blk @as(usize, 0);
            entries_buf[0] = entries_buf[best_idx];
            break :blk @as(usize, 1);
        }

        // For messages, select best resource(s) by priority (§8.5.2.1.1).
        if (session.stanza_kind == .message) {
            // RFC 6121 §8.5.2.1.1: groupchat and error to bare JID MUST NOT be delivered.
            if (std.mem.eql(u8, type_str, "groupchat") or std.mem.eql(u8, type_str, "error")) {
                if (std.mem.eql(u8, type_str, "groupchat")) {
                    sendServiceUnavailable(session, id_str, to_str, from_str);
                    if (session.conn.hasPendingWrite()) {
                        changes.addWrite(session.conn.fd, session.conn.id) catch {};
                    }
                }
                // type='error' to bare JID: silently drop (no error response for error stanzas)
                return;
            }
            // Find highest non-negative priority
            var best_prio: i8 = -128;
            for (entries_buf[0..avail_count]) |entry| {
                if (entry.priority > best_prio) best_prio = entry.priority;
            }
            // If all priorities are negative, don't deliver (§8.5.2.1.1)
            if (best_prio < 0) break :blk @as(usize, 0);
        }
        break :blk avail_count;
    };

    // XEP-0334: Message Processing Hints
    const has_no_store = std.mem.indexOf(u8, inner_xml, "urn:xmpp:hints") != null and
        std.mem.indexOf(u8, inner_xml, "<no-store") != null;
    const has_no_copy = std.mem.indexOf(u8, inner_xml, "urn:xmpp:hints") != null and
        std.mem.indexOf(u8, inner_xml, "<no-copy") != null;

    // Determine if this message should be archived (XEP-0313) and get a stanza-id (XEP-0359).
    const is_archivable = session.stanza_kind == .message and
        inner_xml.len > 0 and
        (std.mem.eql(u8, type_str, "chat") or type_str.len == 0) and
        std.mem.indexOf(u8, inner_xml, "<body") != null and
        !has_no_store;

    var sid_buf: [32]u8 = undefined;
    const archive_stanza_id: []const u8 = if (is_archivable) server.generateStanzaId(&sid_buf) else "";

    // Build augmented inner_xml with stanza-id appended (for delivery to recipients)
    var aug_lease = server.leaseByteScratch() orelse return;
    defer aug_lease.release();
    var aug_fbs = std.io.fixedBufferStream(aug_lease.buf);
    const delivery_inner_xml: []const u8 = if (archive_stanza_id.len > 0) blk: {
        const aw = aug_fbs.writer();
        aw.writeAll(inner_xml) catch break :blk inner_xml;
        aw.writeAll("<stanza-id xmlns='urn:xmpp:sid:0' id='") catch break :blk inner_xml;
        xml.escapeWrite(aw, archive_stanza_id) catch break :blk inner_xml;
        aw.writeAll("' by='") catch break :blk inner_xml;
        xml.escapeWrite(aw, server.server_host) catch break :blk inner_xml;
        aw.writeAll("'/>") catch break :blk inner_xml;
        break :blk aug_fbs.getWritten();
    } else inner_xml;

    var delivery_failed = false;
    for (entries_buf[0..route_count]) |entry| {
        // RFC 6121 §8.5.2.1.1: Skip resources with negative priority for bare-JID messages.
        if (session.stanza_kind == .message and to_jid.resource.len == 0 and entry.priority < 0) continue;

        if (entry.worker_id == server.worker_id) {
            if (target_count < local_ids.len) {
                local_ids[target_count] = entry.local_session_id;
                target_count += 1;
            }
        } else {
            if (enqueueCrossThreadStanza(
                server,
                entry,
                from_str,
                to_str,
                type_str,
                id_str,
                delivery_inner_xml,
                session.stanza_kind,
            )) {
                remote_delivered = true;
            } else {
                // Other local and remote resources still get their copies;
                // the sender gets an error if no resource accepts the stanza.
                delivery_failed = true;
            }
        }
    }

    // Build sender bare JID for archive
    var sender_bare_buf: [BARE_JID_MAX]u8 = undefined;
    const sender_bare = buildBareJid(from_jid.local, from_jid.domain, &sender_bare_buf) catch return;

    // Single timestamp for all archive operations in this dispatch (T123)
    const archive_timestamp: u64 = @intCast(std.time.timestamp());

    // One serialization buffer for this dispatch. The archive form is built
    // and consumed (copied by the writer queue, or stored) before the
    // delivery form is built below, and the offline-store branch returns
    // before the delivery loop runs, so the lifetimes never overlap.
    var out_lease = server.leaseByteScratch() orelse return;
    defer out_lease.release();
    const out_buf = out_lease.buf;

    // Build the archived form of the stanza (includes the stanza-id element).
    // A form that does not fit the scratch bank is not archived at all: the
    // truncated bytes would otherwise be written to the archive and replayed
    // to the recipient on the next drain (E2d).
    var archive_stanza: []const u8 = "";
    if (is_archivable) {
        if (server.archive != null) {
            archive_stanza = buildStoredStanza(out_buf, from_str, to_str, type_str, id_str, inner_xml, archive_stanza_id, server.server_host) orelse blk: {
                log.warn("connection {d} archive form for {s} exceeds the serialization buffer, not archived", .{ session.conn.id, to_str });
                break :blk "";
            };

            if (archive_stanza.len > 0) {
                var recip_buf: [BARE_JID_MAX]u8 = undefined;
                const recipient_bare = buildBareJid(to_jid.local, to_jid.domain, &recip_buf) catch return;
                server.archiveStore(recipient_bare, sender_bare, archive_stanza_id, archive_timestamp, archive_stanza);
                server.archiveStore(sender_bare, recipient_bare, archive_stanza_id, archive_timestamp, archive_stanza);
            }
        }
    }

    if (target_count == 0 and !remote_delivered) {
        // RFC 6121 §8.5.2.1a: Presence stanzas to non-existent users are silently ignored.
        if (session.stanza_kind == .presence) return;

        // RFC 6121 §8.5.2.2.1: type='error' to an unavailable bare JID is
        // silently dropped; type='groupchat' bounces service-unavailable.
        // Neither may be stored offline or answered with further errors.
        if (session.stanza_kind == .message) {
            if (std.mem.eql(u8, type_str, "error")) return;
            if (std.mem.eql(u8, type_str, "groupchat")) {
                sendServiceUnavailable(session, id_str, to_str, from_str);
                if (session.conn.hasPendingWrite()) {
                    changes.addWrite(session.conn.fd, session.conn.id) catch {};
                }
                return;
            }
        }

        // Offline storage for messages
        if (session.stanza_kind == .message) {
            if (server.offline) |store| {
                var recip_buf2: [BARE_JID_MAX]u8 = undefined;
                const recipient_bare2 = buildBareJid(to_jid.local, to_jid.domain, &recip_buf2) catch return;

                // The payload goes down with the pointer: the archive row this
                // stanza was also handed to may still be sitting in the async
                // writer queue, and a drain that read the archive alone would
                // see a dangling pointer and delete a message that is merely
                // in flight (S13).
                var stored_form: []const u8 = "";
                var stored_id: []const u8 = "";
                if (is_archivable and archive_stanza_id.len > 0) {
                    // Empty here means the archived form did not fit the
                    // scratch bank, and a payloadless pointer would replay
                    // nothing (E2d).
                    stored_form = archive_stanza;
                    stored_id = archive_stanza_id;
                } else if (server.archive != null) {
                    // Not archivable, so no stanza-id was minted and the
                    // stored form carries none.
                    stored_form = buildStoredStanza(out_buf, from_str, to_str, type_str, id_str, inner_xml, "", server.server_host) orelse "";
                    stored_id = if (id_str.len > 0) id_str else "offline";
                    if (stored_form.len > 0) {
                        // archiveStore counts failures and rate-limits its log;
                        // a per-stanza log line here would be unbounded.
                        server.archiveStore(recipient_bare2, sender_bare, stored_id, archive_timestamp, stored_form);
                    }
                }

                if (stored_form.len > 0) {
                    if (store.storeHeldPointer(recipient_bare2, sender_bare, stored_id, archive_timestamp, stored_form) catch false) {
                        log.info("connection {d} message to {s} stored offline", .{ session.conn.id, to_str });
                        return;
                    }
                } else {
                    _ = delivery_queue_mod.offline_not_stored.fetchAdd(1, .monotonic);
                    log.warn("connection {d} message to {s} has no storable form, not stored offline", .{ session.conn.id, to_str });
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
        .iq => "iq",
        .none => return,
    };

    // XEP-0352 CSI: for bodyless messages (typing indicators), skip delivery to inactive sessions
    const is_typing_only = session.stanza_kind == .message and !is_archivable and
        std.mem.indexOf(u8, inner_xml, "<body") == null;

    // Serialize the delivery copy once: every branch below sends or stores the
    // same bytes. RFC 6121 section 8.5.2.1.1 omits type='normal' on messages.
    const emit_type = type_str.len > 0 and
        !(session.stanza_kind == .message and std.mem.eql(u8, type_str, "normal"));
    const built = buildDeliveryStanza(out_buf, tag_name, from_str, to_str, type_str, emit_type, id_str, delivery_inner_xml);
    if (built == null) {
        log.warn("connection {d} stanza to {s} exceeds the delivery buffer, not routed", .{ session.conn.id, to_str });
    }

    var hold_bounced = false;
    var local_delivery_succeeded = false;
    // Forward to each local target session
    for (local_ids[0..target_count]) |tid| {
        const target_session = server.sessions[tid] orelse continue;
        if (is_typing_only and !target_session.csi_active) continue;
        const sent_data = built orelse {
            delivery_failed = true;
            continue;
        };
        // A session whose offline tail is still draining must not be overtaken.
        if (target_session.offline_pending and session.stanza_kind == .message and
            !std.mem.eql(u8, type_str, "error"))
        {
            const hold_id = if (is_archivable)
                archive_stanza_id
            else if (id_str.len > 0)
                id_str
            else
                "offline";
            if (server.holdBehindOfflineTail(target_session, to_jid.local, to_jid.domain, sender_bare, hold_id, archive_timestamp, sent_data)) {
                local_delivery_succeeded = true;
                log.info("message to {s} held behind draining offline tail (S13)", .{to_str});
                continue;
            }
            // No offline store, or the recipient's queue is at quota. The
            // stanza can neither be held nor sent without overtaking the
            // tail, so tell the sender instead of dropping it silently.
            if (!hold_bounced) {
                hold_bounced = true;
                _ = delivery_queue_mod.offline_hold_bounces.fetchAdd(1, .monotonic);
                log.info("connection {d} message to {s} not held, offline queue unavailable or full", .{ session.conn.id, to_str });
                sendServiceUnavailable(session, id_str, to_str, from_str);
                if (session.conn.hasPendingWrite()) {
                    changes.addWrite(session.conn.fd, session.conn.id) catch {};
                }
            }
            continue;
        }
        // T153: a detached (SM resume pending) session has no live connection —
        // its conn.fd was already closed by detachSession(). Attempting
        // conn.queueSend()/changes.addWrite() here would register a kqueue
        // watch on a stale fd number that the OS may have already recycled
        // for an unrelated connection, misrouting future events onto this
        // session slot. Track the stanza for resume replay instead of
        // attempting live delivery.
        if (target_session.sm_detached) {
            target_session.smTrackOutbound(sent_data);
            local_delivery_succeeded = true;
            continue;
        }
        target_session.conn.queueSend(sent_data) catch |err| {
            delivery_failed = true;
            log.warn("connection {d} could not queue stanza for {s}: {s}", .{ tid, to_str, @errorName(err) });
            continue;
        };
        target_session.smTrackOutbound(sent_data);
        local_delivery_succeeded = true;
        if (target_session.conn.hasPendingWrite()) {
            changes.addWrite(target_session.conn.fd, tid) catch {};
        }
    }

    const bounceable = (session.stanza_kind == .message and !std.mem.eql(u8, type_str, "error")) or
        (session.stanza_kind == .iq and (std.mem.eql(u8, type_str, "get") or std.mem.eql(u8, type_str, "set")));
    if (delivery_failed and !local_delivery_succeeded and !remote_delivered and !hold_bounced and bounceable) {
        log.info("connection {d} stanza to {s} could not be delivered to any resource", .{ session.conn.id, to_str });
        sendServiceUnavailable(session, id_str, to_str, from_str);
        if (session.conn.hasPendingWrite()) {
            changes.addWrite(session.conn.fd, session.conn.id) catch {};
        }
    }

    // XEP-0280: Message Carbons — send copies to sender's and recipient's other resources
    // XEP-0334: Skip carbons if <no-copy xmlns='urn:xmpp:hints'/> is present
    if (session.stanza_kind == .message and !has_no_copy and
        (std.mem.eql(u8, type_str, "chat") or type_str.len == 0))
    {
        // The serialized stanza is dead now that the delivery loop above has
        // consumed it; give the bank back so sendCarbons, which still reads
        // delivery_inner_xml out of the augmented bank, can take it.
        out_lease.release();

        sendCarbons(server, "sent", session, from_jid.local, from_jid.domain, from_str, to_str, type_str, id_str, delivery_inner_xml, changes);
        sendCarbons(server, "received", session, to_jid.local, to_jid.domain, from_str, to_str, type_str, id_str, delivery_inner_xml, changes);
    }
}

/// Build the form that is written to the archive and held for offline replay:
/// the message with its attributes, its body, and (when one was minted) the
/// XEP-0359 stanza-id element. Returns null when the result does not fit
/// `buf`, so a caller can skip the store rather than persist and later replay
/// a truncated stanza (E2d). Pass an empty stanza_id to omit the element.
fn buildStoredStanza(
    buf: []u8,
    from_str: []const u8,
    to_str: []const u8,
    type_str: []const u8,
    id_str: []const u8,
    inner_xml: []const u8,
    stanza_id: []const u8,
    server_host: []const u8,
) ?[]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();

    w.writeAll("<message from='") catch return null;
    xml.escapeWrite(w, from_str) catch return null;
    w.writeAll("' to='") catch return null;
    xml.escapeWrite(w, to_str) catch return null;
    w.writeByte('\'') catch return null;
    if (type_str.len > 0) {
        w.writeAll(" type='") catch return null;
        xml.escapeWrite(w, type_str) catch return null;
        w.writeByte('\'') catch return null;
    }
    if (id_str.len > 0) {
        w.writeAll(" id='") catch return null;
        xml.escapeWrite(w, id_str) catch return null;
        w.writeByte('\'') catch return null;
    }
    if (inner_xml.len == 0) {
        w.writeAll("/>") catch return null;
        return fbs.getWritten();
    }
    w.writeByte('>') catch return null;
    w.writeAll(inner_xml) catch return null;
    if (stanza_id.len > 0) {
        w.writeAll("<stanza-id xmlns='urn:xmpp:sid:0' id='") catch return null;
        xml.escapeWrite(w, stanza_id) catch return null;
        w.writeAll("' by='") catch return null;
        xml.escapeWrite(w, server_host) catch return null;
        w.writeAll("'/>") catch return null;
    }
    w.writeAll("</message>") catch return null;
    return fbs.getWritten();
}

/// Serialize a stanza for delivery to a local target into `buf`, returning the
/// bytes written or null when they do not fit. `emit_type` is decided by the
/// caller because type='normal' is omitted on messages (RFC 6121 section
/// 8.5.2.1.1) but carried on other stanza kinds.
fn buildDeliveryStanza(
    buf: []u8,
    tag_name: []const u8,
    from_str: []const u8,
    to_str: []const u8,
    type_str: []const u8,
    emit_type: bool,
    id_str: []const u8,
    inner_xml: []const u8,
) ?[]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();

    w.writeByte('<') catch return null;
    w.writeAll(tag_name) catch return null;
    w.writeAll(" from='") catch return null;
    xml.escapeWrite(w, from_str) catch return null;
    w.writeAll("' to='") catch return null;
    xml.escapeWrite(w, to_str) catch return null;
    w.writeByte('\'') catch return null;
    if (emit_type) {
        w.writeAll(" type='") catch return null;
        xml.escapeWrite(w, type_str) catch return null;
        w.writeByte('\'') catch return null;
    }
    if (id_str.len > 0) {
        w.writeAll(" id='") catch return null;
        xml.escapeWrite(w, id_str) catch return null;
        w.writeByte('\'') catch return null;
    }
    if (inner_xml.len == 0) {
        w.writeAll("/>") catch return null;
    } else {
        w.writeByte('>') catch return null;
        w.writeAll(inner_xml) catch return null;
        w.writeAll("</") catch return null;
        w.writeAll(tag_name) catch return null;
        w.writeByte('>') catch return null;
    }
    return fbs.getWritten();
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
        .iq => "iq",
        .none => return,
    };

    var stanza_lease = server.leaseByteScratch() orelse return;
    defer stanza_lease.release();
    var stanza_fbs = std.io.fixedBufferStream(stanza_lease.buf);
    const sw = stanza_fbs.writer();

    sw.writeByte('<') catch return;
    sw.writeAll(tag_name) catch return;
    sw.writeAll(" from='") catch return;
    xml.escapeWrite(sw, from_str) catch return;
    sw.writeAll("' to='") catch return;
    xml.escapeWrite(sw, to_str) catch return;
    sw.writeByte('\'') catch return;
    if (type_str.len > 0) {
        if (!(session.stanza_kind == .message and std.mem.eql(u8, type_str, "normal"))) {
            sw.writeAll(" type='") catch return;
            xml.escapeWrite(sw, type_str) catch return;
            sw.writeByte('\'') catch return;
        }
    }
    if (id_str.len > 0) {
        sw.writeAll(" id='") catch return;
        xml.escapeWrite(sw, id_str) catch return;
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

    // Write interest is armed by reconcileIpcWriteInterest, once per loop
    // iteration (S10). Arming here would leave a persistent filter with
    // s2s_write_armed still false, so nothing would ever remove it.
    log.info("connection {d} stanza to remote {s} forwarded via S2S", .{ session.conn.id, to_str });
}

/// Serialize a stanza and enqueue for cross-thread delivery via MPSC.
/// Returns false when the stanza did not fit a delivery slot or the queue
/// failed; the caller must treat that recipient as undelivered (S14).
fn enqueueCrossThreadStanza(
    server: *Server,
    route: SessionEntry,
    from_str: []const u8,
    to_str: []const u8,
    type_str: []const u8,
    id_str: []const u8,
    inner_xml: []const u8,
    kind: StanzaKind,
) bool {
    const ds = server.delivery_system orelse return false;

    const tag_name: []const u8 = switch (kind) {
        .message => "message",
        .presence => "presence",
        .iq => "iq",
        .none => return false,
    };

    var buf: [delivery_queue_mod.MAX_PAYLOAD_SIZE]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();

    w.writeByte('<') catch return dropOversize(inner_xml.len, route);
    w.writeAll(tag_name) catch return dropOversize(inner_xml.len, route);
    w.writeAll(" from='") catch return dropOversize(inner_xml.len, route);
    xml.escapeWrite(w, from_str) catch return dropOversize(inner_xml.len, route);
    w.writeAll("' to='") catch return dropOversize(inner_xml.len, route);
    xml.escapeWrite(w, to_str) catch return dropOversize(inner_xml.len, route);
    w.writeByte('\'') catch return dropOversize(inner_xml.len, route);
    if (type_str.len > 0) {
        if (!(kind == .message and std.mem.eql(u8, type_str, "normal"))) {
            w.writeAll(" type='") catch return dropOversize(inner_xml.len, route);
            xml.escapeWrite(w, type_str) catch return dropOversize(inner_xml.len, route);
            w.writeByte('\'') catch return dropOversize(inner_xml.len, route);
        }
    }
    if (id_str.len > 0) {
        w.writeAll(" id='") catch return dropOversize(inner_xml.len, route);
        xml.escapeWrite(w, id_str) catch return dropOversize(inner_xml.len, route);
        w.writeByte('\'') catch return dropOversize(inner_xml.len, route);
    }
    if (inner_xml.len == 0) {
        w.writeAll("/>") catch return dropOversize(inner_xml.len, route);
    } else {
        w.writeByte('>') catch return dropOversize(inner_xml.len, route);
        w.writeAll(inner_xml) catch return dropOversize(inner_xml.len, route);
        w.writeAll("</") catch return dropOversize(inner_xml.len, route);
        w.writeAll(tag_name) catch return dropOversize(inner_xml.len, route);
        w.writeByte('>') catch return dropOversize(inner_xml.len, route);
    }

    ds.deliver(route.worker_id, route.local_session_id, route.generation, fbs.getWritten()) catch |err| {
        log.warn("cross-thread delivery failed to worker {d} session {d}: {}", .{ route.worker_id, route.local_session_id, err });
        _ = delivery_queue_mod.cross_worker_drops.fetchAdd(1, .monotonic);
        return false;
    };
    return true;
}

fn dropOversize(inner_len: usize, route: SessionEntry) bool {
    _ = delivery_queue_mod.cross_worker_drops.fetchAdd(1, .monotonic);
    log.warn("cross-thread stanza exceeds {d}-byte delivery slot (inner {d} bytes) to worker {d} session {d} — routed to offline/bounce fallback (S14)", .{ delivery_queue_mod.MAX_PAYLOAD_SIZE, inner_len, route.worker_id, route.local_session_id });
    return false;
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
    var lease_b = server.leaseScratch(.b);
    defer lease_b.release();
    const entries = lease_b.entries;
    const count = sm.findAvailableByBareJid(user_local, user_domain, entries);
    if (count == 0) return;

    // Reuse one serialization buffer across resources: each carbon is fully
    // consumed by queueSend or the MPSC delivery before the next iteration.
    // The pool lease keeps per-recipient serialization storage off the stack.
    var carbon_lease = server.leaseByteScratch() orelse return;
    defer carbon_lease.release();
    const cbuf = carbon_lease.buf;

    for (entries[0..count]) |entry| {
        if (entry.worker_id == server.worker_id) {
            const target = server.sessions[entry.local_session_id] orelse continue;
            if (&target.conn == &sender_session.conn) continue;
            if (!target.carbons_enabled) continue;

            var cfbs = std.io.fixedBufferStream(cbuf);
            const cw = cfbs.writer();

            cw.writeAll("<message from='") catch continue;
            xml.escapeWrite(cw, user_local) catch continue;
            cw.writeByte('@') catch continue;
            xml.escapeWrite(cw, user_domain) catch continue;
            cw.writeAll("' to='") catch continue;
            xml.escapeWrite(cw, user_local) catch continue;
            cw.writeByte('@') catch continue;
            xml.escapeWrite(cw, user_domain) catch continue;
            cw.writeByte('/') catch continue;
            xml.escapeWrite(cw, entry.resource()) catch continue;
            cw.writeAll("' type='chat'>") catch continue;

            cw.writeByte('<') catch continue;
            cw.writeAll(carbon_type) catch continue;
            cw.writeAll(" xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'>") catch continue;

            cw.writeAll("<message from='") catch continue;
            xml.escapeWrite(cw, from_str) catch continue;
            cw.writeAll("' to='") catch continue;
            xml.escapeWrite(cw, to_str) catch continue;
            cw.writeByte('\'') catch continue;
            if (type_str.len > 0) {
                cw.writeAll(" type='") catch continue;
                xml.escapeWrite(cw, type_str) catch continue;
                cw.writeByte('\'') catch continue;
            }
            if (id_str.len > 0) {
                cw.writeAll(" id='") catch continue;
                xml.escapeWrite(cw, id_str) catch continue;
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

            const carbon_data = cfbs.getWritten();
            fanout.deliverToSession(target, carbon_data, entry.local_session_id, changes);
        } else {
            // T89: Cross-thread carbon delivery via MPSC
            const ds = server.delivery_system orelse continue;

            var cfbs = std.io.fixedBufferStream(cbuf);
            const cw = cfbs.writer();

            cw.writeAll("<message from='") catch continue;
            xml.escapeWrite(cw, user_local) catch continue;
            cw.writeByte('@') catch continue;
            xml.escapeWrite(cw, user_domain) catch continue;
            cw.writeAll("' to='") catch continue;
            xml.escapeWrite(cw, user_local) catch continue;
            cw.writeByte('@') catch continue;
            xml.escapeWrite(cw, user_domain) catch continue;
            cw.writeByte('/') catch continue;
            xml.escapeWrite(cw, entry.resource()) catch continue;
            cw.writeAll("' type='chat'>") catch continue;

            cw.writeByte('<') catch continue;
            cw.writeAll(carbon_type) catch continue;
            cw.writeAll(" xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'>") catch continue;

            cw.writeAll("<message from='") catch continue;
            xml.escapeWrite(cw, from_str) catch continue;
            cw.writeAll("' to='") catch continue;
            xml.escapeWrite(cw, to_str) catch continue;
            cw.writeByte('\'') catch continue;
            if (type_str.len > 0) {
                cw.writeAll(" type='") catch continue;
                xml.escapeWrite(cw, type_str) catch continue;
                cw.writeByte('\'') catch continue;
            }
            if (id_str.len > 0) {
                cw.writeAll(" id='") catch continue;
                xml.escapeWrite(cw, id_str) catch continue;
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

            ds.deliver(entry.worker_id, entry.local_session_id, entry.generation, cfbs.getWritten()) catch |err| {
                log.warn("cross-thread carbon delivery failed to worker {d}: {}", .{ entry.worker_id, err });
                _ = delivery_queue_mod.cross_worker_drops.fetchAdd(1, .monotonic);
            };
        }
    }
}

/// Send a not-authorized error for a stanza received before resource
/// binding (RFC 6120 §7.6). There is no established sender JID yet, so the
/// error carries only from=<original-to> and the original stanza id.
pub fn sendNotAuthorized(session: *Session, id_str: []const u8, to_str: []const u8) void {
    const tag_name: []const u8 = switch (session.stanza_kind) {
        .iq => "iq",
        .message => "message",
        else => "message",
    };

    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    w.writeByte('<') catch return;
    w.writeAll(tag_name) catch return;
    w.writeAll(" type='error'") catch return;
    if (id_str.len > 0) {
        w.writeAll(" id='") catch return;
        xml.escapeWrite(w, id_str) catch return;
        w.writeByte('\'') catch return;
    }
    if (to_str.len > 0) {
        w.writeAll(" from='") catch return;
        xml.escapeWrite(w, to_str) catch return;
        w.writeByte('\'') catch return;
    }
    w.writeAll("><error type='auth'><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></") catch return;
    w.writeAll(tag_name) catch return;
    w.writeByte('>') catch return;
    session.queueSendStanza(fbs.getWritten()) catch return;
}

/// Send a service-unavailable error for a stanza that can't be delivered.
/// Uses the correct element name based on the stanza kind (message or iq).
pub fn sendServiceUnavailable(session: *Session, id_str: []const u8, to_str: []const u8, from_str: []const u8) void {
    const tag_name: []const u8 = switch (session.stanza_kind) {
        .iq => "iq",
        .message => "message",
        else => "message",
    };

    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    w.writeByte('<') catch return;
    w.writeAll(tag_name) catch return;
    w.writeAll(" type='error'") catch return;
    if (id_str.len > 0) {
        w.writeAll(" id='") catch return;
        xml.escapeWrite(w, id_str) catch return;
        w.writeByte('\'') catch return;
    }
    w.writeAll(" from='") catch return;
    xml.escapeWrite(w, to_str) catch return;
    w.writeAll("' to='") catch return;
    xml.escapeWrite(w, from_str) catch return;
    w.writeAll("'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></") catch return;
    w.writeAll(tag_name) catch return;
    w.writeByte('>') catch return;
    session.queueSendStanza(fbs.getWritten()) catch return;
}
