//! # Presence Handler — C2S presence + subscription state machine
//!
//! Handles presence stanzas (available, unavailable, subscribe, subscribed,
//! unsubscribe, unsubscribed) and presence broadcast/probing. Extracted from
//! server.zig as part of T51 decomposition.
//!
//! ## Entry Points
//!
//! Called from server.zig's handleElementStart when presence stanzas are received.
//!
//! - `handlePresence` — main dispatcher (routes to MUC, available, subscribe, etc.)
//! - `broadcastPresence` — notify roster subscribers of available presence
//! - `broadcastUnavailable` — notify roster subscribers of unavailable presence
//! - `sendPresenceProbes` — probe subscribed contacts for their current status

const std = @import("std");
const xml = @import("xml");
const xmpp = @import("xmpp");

const server_mod = @import("server.zig");
const Server = server_mod.Server;
const Session = server_mod.Session;
const caps_mod = server_mod.caps_mod;
const ChangeList = @import("event_loop.zig").ChangeList;

const session_map_mod = @import("session_map");
const SessionEntry = session_map_mod.SessionEntry;
const generic_roster = @import("roster_store");
const store_keys = @import("store_keys");
const backend_mod = @import("backend");
const Subscription = generic_roster.Subscription;
const muc_handler = @import("muc_handler.zig");
const session_lifecycle = @import("session_lifecycle.zig");
const iq_handler = @import("iq_handler.zig");
const fanout = @import("fanout.zig");
const router = @import("router.zig");
const sub_cache_mod = server_mod.sub_cache_mod;

const log = std.log.scoped(.presence);

/// Cold error paths. Each helper is noinline and marked cold so the log
/// formatter's stack frame stays out of the per-message callers; the call
/// site holds only the call.
noinline fn noteDrop(comptime fmt: []const u8, args: anytype) void {
    @branchHint(.cold);
    log.warn(fmt, args);
}

/// Record one over-long-JID skip on the cold path (S4).
noinline fn noteJidOverflow(comptime fmt: []const u8, args: anytype) void {
    @branchHint(.cold);
    router.countJidOverflow();
    log.warn(fmt, args);
}

/// Hot-path info logs: noinline, but NOT cold; they fire on every normal
/// presence update. They keep the formatter's stack frame out of the
/// per-stanza callers; the call site holds only the call.
noinline fn logAvailable(conn_id: usize, local: []const u8, domain: []const u8, resource: []const u8, prio: i8) void {
    log.info("connection {d} now available: {s}@{s}/{s} (priority={d})", .{ conn_id, local, domain, resource, prio });
}

noinline fn logUnavailable(local: []const u8, domain: []const u8, resource: []const u8) void {
    log.info("{s}@{s}/{s} now unavailable", .{ local, domain, resource });
}

/// Handle a presence stanza from a bound session.
/// Routes to MUC handler for MUC domain, or dispatches by presence type.
pub fn handlePresence(server: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
    var type_str: []const u8 = "";
    var to_str: []const u8 = "";
    for (elem.attributes) |attr| {
        if (std.mem.eql(u8, attr.local_name, "type")) type_str = attr.value;
        if (std.mem.eql(u8, attr.local_name, "to")) to_str = attr.value;
    }

    // Directed presence — has a 'to' attribute.
    // Subscription stanzas also have 'to' but are NOT directed presence;
    // they fall through to the switch below.
    if (to_str.len > 0) {
        const ptype_directed = xmpp.PresenceType.fromString(type_str);
        const is_subscription = switch (ptype_directed) {
            .subscribe, .subscribed, .unsubscribe, .unsubscribed => true,
            else => false,
        };

        if (!is_subscription) {
            const to_jid = xmpp.Jid.parse(to_str) catch return;

            // MUC domain → MUC join/part. The host compare is
            // case-insensitive; the room localpart keeps its spelling.
            if (server.muc_host) |muc_host| {
                if (std.ascii.eqlIgnoreCase(to_jid.domain, muc_host)) {
                    muc_handler.handleMucPresence(server, session, to_jid.local, to_jid.resource, type_str, changes);
                    return;
                }
            }

            const is_local = std.mem.eql(u8, to_jid.domain, server.server_host);

            if (is_local and to_jid.resource.len == 0) {
                // RFC 6121 §8.5.2.1.2: Directed presence to a local bare JID —
                // deliver to ALL available resources of the target user.
                session.stanza_kind = .presence;
                session.stanza_buf_len = 0;
                session.stanza_to = to_str;
                session.stanza_id = "";
                session.stanza_type = type_str;
                session.pres_priority_collecting = false;
                session.pres_priority_len = 0;
                if (elem.self_closing) {
                    dispatchDirectedPresenceToBareJid(server, session, to_jid.local, to_jid.domain, changes);
                }
                return;
            }

            // RFC 6121 §8.5.3: Directed presence to a full JID — forward via
            // stanza accumulation pipeline. Remote-domain directed presence
            // (full or bare JID) takes the same path: dispatchStanza forwards
            // non-local domains to the S2S daemon (T166).
            var id_str: []const u8 = "";
            for (elem.attributes) |attr| {
                if (std.mem.eql(u8, attr.local_name, "id")) id_str = attr.value;
            }
            session.stanza_kind = .presence;
            session.stanza_buf_len = 0;
            session.stanza_to = to_str;
            session.stanza_id = id_str;
            session.stanza_type = type_str;
            session.pres_priority_collecting = false;
            session.pres_priority_len = 0;
            if (elem.self_closing) {
                router.dispatchStanza(server, session, changes);
            }
            return;
        }
    }

    const ptype = xmpp.PresenceType.fromString(type_str);
    if (session.stream.bound_jid == null) return;

    switch (ptype) {
        .available => {
            // Start presence accumulation — defer action to </presence> to capture <priority>.
            session.stanza_kind = .presence;
            session.stanza_buf_len = 0;
            session.stanza_to = "";
            session.stanza_id = "";
            session.stanza_type = "";
            session.pres_priority_collecting = false;
            session.pres_priority_len = 0;

            // Self-closing <presence/> — dispatch immediately
            if (elem.self_closing) {
                dispatchPresence(server, session, changes);
            }
        },
        .unavailable => {
            // Start accumulation for unavailable too (consistent handling).
            session.stanza_kind = .presence;
            session.stanza_buf_len = 0;
            session.stanza_to = "";
            session.stanza_id = "";
            session.stanza_type = "unavailable";
            session.pres_priority_collecting = false;
            session.pres_priority_len = 0;

            if (elem.self_closing) {
                dispatchPresence(server, session, changes);
            }
        },
        .subscribe, .subscribed, .unsubscribe, .unsubscribed => {
            session.stanza_to = to_str;
            session.stanza_type = type_str;
            if (elem.self_closing) {
                dispatchSubscription(server, session, ptype, "", changes);
            } else {
                // Non-self-closing: accumulate child elements (extensions) until </presence>.
                // Dispatch happens in handleElementEnd via the subscription type check.
                session.stanza_kind = .presence;
                session.stanza_buf_len = 0;
                session.stanza_id = "";
                session.pres_priority_collecting = false;
                session.pres_priority_len = 0;
            }
        },
        else => {},
    }
}

/// Check if a presence type string is a subscription management type.
pub fn isSubscriptionType(type_str: []const u8) bool {
    return std.mem.eql(u8, type_str, "subscribe") or
        std.mem.eql(u8, type_str, "subscribed") or
        std.mem.eql(u8, type_str, "unsubscribe") or
        std.mem.eql(u8, type_str, "unsubscribed");
}

/// Dispatch a subscription stanza with accumulated inner XML (extensions).
/// Called from handlePresence (self-closing) or handleElementEnd (accumulated).
/// RFC 6121 §3.1: Subscription processing always uses bare JIDs — strip any resource.
pub fn dispatchSubscription(server: *Server, session: *Session, ptype: xmpp.PresenceType, inner_xml: []const u8, changes: *ChangeList) void {
    defer session.resetStanza();

    // Normalize stanza_to to bare JID (strip resource if present).
    const to_str = session.stanza_to;
    if (to_str.len > 0) {
        const to_jid = xmpp.Jid.parse(to_str) catch {
            return;
        };
        if (to_jid.resource.len > 0) {
            // Rebuild as bare JID in a stable buffer within session's write_scratch.
            var bare_fbs = std.io.fixedBufferStream(&session.write_scratch);
            const bw = bare_fbs.writer();
            session.stanza_to = stripped: {
                bw.writeAll(to_jid.local) catch break :stripped null;
                bw.writeByte('@') catch break :stripped null;
                bw.writeAll(to_jid.domain) catch break :stripped null;
                break :stripped bare_fbs.getWritten();
            } orelse {
                noteJidOverflow("subscription target too long to strip its resource; stanza dropped", .{});
                return;
            };
        }
    }

    // An over-long target would overflow the bounded roster key and fail
    // silently downstream (S4): reject it at ingress.
    if (to_str.len > 0) {
        const bound = session.stream.bound_jid orelse return;
        var ob_buf: [router.BARE_JID_MAX]u8 = undefined;
        const owner_jid = router.buildBareJid(bound.local, bound.domain, &ob_buf) catch {
            noteJidOverflow("subscription owner JID '{s}@{s}' exceeds {d} bytes; stanza dropped", .{ bound.local, bound.domain, router.BARE_JID_MAX });
            return;
        };
        if (!store_keys.fits2(owner_jid, session.stanza_to)) {
            rejectOversizeSubscriptionTo(session, session.stanza_to, changes);
            return;
        }
    }

    // The handlers stay inlinable: each runs once per stanza and only one of
    // them runs per call, so their buffers union inside this frame.
    switch (ptype) {
        .subscribe => handleSubscribe(server, session, inner_xml, changes),
        .subscribed => handleSubscribed(server, session, inner_xml, changes),
        .unsubscribe => handleUnsubscribe(server, session, inner_xml, changes),
        .unsubscribed => handleUnsubscribed(server, session, inner_xml, changes),
        else => {},
    }
}

/// Dispatch a completed presence stanza — called from handleElementEnd on </presence>.
/// Extracts priority from accumulated buffer, updates SessionMap, and broadcasts.
pub fn dispatchPresence(server: *Server, session: *Session, changes: *ChangeList) void {
    defer session.resetStanza();

    const bound = session.stream.bound_jid orelse return;
    const type_str = session.stanza_type;

    // Parse priority from accumulated <priority> text (RFC 6121 §4.7.2.3)
    var prio: i8 = 0;
    if (session.pres_priority_len > 0) {
        const prio_text = session.pres_priority_buf[0..session.pres_priority_len];
        prio = std.fmt.parseInt(i8, prio_text, 10) catch 0;
    }

    if (type_str.len == 0) {
        // Available presence
        if (server.session_map) |sm| {
            sm.setPresenceAvailable(bound.local, bound.domain, bound.resource, true);
            sm.setPriority(bound.local, bound.domain, bound.resource, prio);
        }
        const inner_xml = session.stanza_buf[0..session.stanza_buf_len];

        // RFC 6121 §3.1.5: Store the presence inner XML so that subscription
        // approval can forward the full current presence (with status/show/priority).
        const store_len = @min(inner_xml.len, session.last_presence_inner.len);
        @memcpy(session.last_presence_inner[0..store_len], inner_xml[0..store_len]);
        session.last_presence_inner_len = store_len;

        // XEP-0115: Extract caps `ver` hash from <c> element in presence
        if (caps_mod.extractVerFromPresence(inner_xml)) |ver| {
            const vlen: u8 = @intCast(@min(ver.len, caps_mod.MAX_VER_LEN));
            @memcpy(session.caps_ver_buf[0..vlen], ver[0..vlen]);
            session.caps_ver_len = vlen;

            // If this ver hash is not in the cache, send a disco#info query
            // to the client to discover its features (XEP-0115 §5.3).
            if (server.caps_cache.lookup(ver) == null) {
                if (caps_mod.extractNodeFromPresence(inner_xml)) |node| caps_query: {
                    // Build the full JID for the query target
                    var jid_buf: [router.FULL_JID_MAX]u8 = undefined;
                    const full_jid = router.buildFullJid(bound.local, bound.domain, bound.resource, &jid_buf) catch {
                        noteJidOverflow("connection {d} bound full JID exceeds {d} bytes; caps query skipped", .{ session.conn.id, router.FULL_JID_MAX });
                        break :caps_query;
                    };

                    var query_buf: [1024]u8 = undefined;
                    if (caps_mod.buildCapsQuery(&query_buf, server.server_host, full_jid, node, ver, @intCast(session.conn.id))) |query_xml| {
                        session.queueSendStanza(query_xml) catch {};
                        if (session.conn.hasPendingWrite()) {
                            changes.addWrite(session.conn.fd, session.conn.id) catch {};
                        }
                    }
                }
            }
        }

        broadcastPresence(server, bound.local, bound.domain, bound.resource, inner_xml, changes);

        // RFC 6121 §4.4.2: Send presence to all of the user's own available resources.
        broadcastToOwnResources(server, session, bound.local, bound.domain, bound.resource, changes);

        // RFC 6121 §4.4.2: Send the user's other available resources' presence to this new resource.
        sendOtherResourcesPresence(server, session, bound.local, bound.domain, bound.resource, changes);

        // Send presence probes to contacts we're subscribed to
        sendPresenceProbes(server, session, bound.local, bound.domain, changes);

        // Deliver any offline messages queued for this user
        session_lifecycle.deliverOfflineMessages(server, session, bound.local, bound.domain, changes);

        // RFC 6121 §3.1.3 rule 4: Deliver pending subscription requests
        deliverPendingSubscriptions(server, session, bound.local, bound.domain, changes);

        logAvailable(session.conn.id, bound.local, bound.domain, bound.resource, prio);
    } else if (std.mem.eql(u8, type_str, "unavailable")) {
        if (server.session_map) |sm| {
            sm.setPresenceAvailable(bound.local, bound.domain, bound.resource, false);
            sm.setPriority(bound.local, bound.domain, bound.resource, -128);
        }
        broadcastUnavailable(server, bound.local, bound.domain, bound.resource, changes);

        // RFC 6121 §4.4.2: Send unavailable presence to user's own remaining resources.
        broadcastToOwnResources(server, session, bound.local, bound.domain, bound.resource, changes);
    }
}

/// Broadcast available presence to all roster subscribers.
/// inner_xml contains child elements (priority, show, status) serialized from the client stanza.
pub fn broadcastPresence(server: *Server, local: []const u8, domain: []const u8, resource: []const u8, inner_xml: []const u8, changes: *ChangeList) void {
    const roster = server.roster orelse return;

    // Build the from JID string
    var from_buf: [router.FULL_JID_MAX]u8 = undefined;
    const from_str = router.buildFullJid(local, domain, resource, &from_buf) catch {
        noteJidOverflow("presence from '{s}@{s}/{s}' exceeds {d} bytes; broadcast skipped", .{ local, domain, resource, router.FULL_JID_MAX });
        return;
    };

    // Build bare JID for roster lookup
    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const bare_jid = router.buildBareJid(local, domain, &bare_buf) catch {
        noteJidOverflow("presence bare JID '{s}@{s}' exceeds {d} bytes; broadcast skipped", .{ local, domain, router.BARE_JID_MAX });
        return;
    };

    // Find subscribers (contacts with "from" or "both" in our roster) — cached (T129)
    //
    // Both buffers below stay live into deliverPresenceToSubscribers: the
    // subscriber JID pointers index into the first, and the presence XML the
    // delivery loop copies out is built into the second. So they are separate
    // leased banks rather than one reused (S18).
    var sub_lease = server.leaseByteScratch() orelse {
        noteDrop("byte-scratch exhausted; presence broadcast for '{s}' skipped", .{bare_jid});
        return;
    };
    defer sub_lease.release();
    const sub_jid_buf = sub_lease.buf;
    var sub_jid_ptrs: [256][]const u8 = undefined;
    const bare_hash = sub_cache_mod.hashBareJid(bare_jid);
    const now = std.time.timestamp();
    const sub_count = server.sub_cache.lookupSubscribers(bare_hash, now, sub_jid_buf, &sub_jid_ptrs) orelse blk: {
        const count = roster.getPresenceSubscribersFixed(bare_jid, sub_jid_buf, &sub_jid_ptrs) catch return;
        server.sub_cache.storeSubscribers(bare_hash, now, sub_jid_ptrs[0..count]);
        break :blk count;
    };
    const subscriber_jids = sub_jid_ptrs[0..sub_count];

    // Build presence stanza with inner XML content
    var pres_lease = server.leaseByteScratch() orelse {
        noteDrop("byte-scratch exhausted; presence broadcast for '{s}' skipped", .{bare_jid});
        return;
    };
    defer pres_lease.release();
    var pres_fbs = std.io.fixedBufferStream(pres_lease.buf);
    const pw = pres_fbs.writer();
    const presence_xml = stanza: {
        pw.writeAll("<presence from='") catch break :stanza null;
        xml.escapeWrite(pw, from_str) catch break :stanza null;
        pw.writeByte('\'') catch break :stanza null;
        if (inner_xml.len > 0) {
            pw.writeByte('>') catch break :stanza null;
            pw.writeAll(inner_xml) catch break :stanza null;
            pw.writeAll("</presence>") catch break :stanza null;
        } else {
            pw.writeAll("/>") catch break :stanza null;
        }
        break :stanza pres_fbs.getWritten();
    } orelse {
        noteJidOverflow("presence stanza for '{s}' exceeds {d} bytes; broadcast skipped", .{ from_str, pres_lease.buf.len });
        return;
    };

    // Deliver to each subscriber
    deliverPresenceToSubscribers(server, subscriber_jids, bare_jid, presence_xml, changes);
}

/// Broadcast unavailable presence to roster subscribers.
pub fn broadcastUnavailable(server: *Server, local: []const u8, domain: []const u8, resource: []const u8, changes: *ChangeList) void {
    const roster = server.roster orelse return;

    var from_buf: [router.FULL_JID_MAX]u8 = undefined;
    const from_str = router.buildFullJid(local, domain, resource, &from_buf) catch {
        noteJidOverflow("unavailable from '{s}@{s}/{s}' exceeds {d} bytes; broadcast skipped", .{ local, domain, resource, router.FULL_JID_MAX });
        return;
    };

    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const bare_jid = router.buildBareJid(local, domain, &bare_buf) catch {
        noteJidOverflow("unavailable bare JID '{s}@{s}' exceeds {d} bytes; broadcast skipped", .{ local, domain, router.BARE_JID_MAX });
        return;
    };

    // Subscriber JID pointers index into this buffer and stay live through
    // delivery, so it is leased rather than taken on the stack (S18). The
    // presence stanza below is small enough to keep on the stack.
    var sub_lease = server.leaseByteScratch() orelse {
        noteDrop("byte-scratch exhausted; unavailable broadcast for '{s}' skipped", .{bare_jid});
        return;
    };
    defer sub_lease.release();
    const sub_jid_buf2 = sub_lease.buf;
    var sub_jid_ptrs2: [256][]const u8 = undefined;
    const bare_hash = sub_cache_mod.hashBareJid(bare_jid);
    const now = std.time.timestamp();
    const sub_count2 = server.sub_cache.lookupSubscribers(bare_hash, now, sub_jid_buf2, &sub_jid_ptrs2) orelse blk: {
        const count = roster.getPresenceSubscribersFixed(bare_jid, sub_jid_buf2, &sub_jid_ptrs2) catch return;
        server.sub_cache.storeSubscribers(bare_hash, now, sub_jid_ptrs2[0..count]);
        break :blk count;
    };
    const subscriber_jids = sub_jid_ptrs2[0..sub_count2];

    var pres_buf: [router.JID_STANZA_MAX]u8 = undefined;
    var pres_fbs = std.io.fixedBufferStream(&pres_buf);
    const pw = pres_fbs.writer();
    const presence_xml = stanza: {
        pw.writeAll("<presence from='") catch break :stanza null;
        xml.escapeWrite(pw, from_str) catch break :stanza null;
        pw.writeAll("' type='unavailable'/>") catch break :stanza null;
        break :stanza pres_fbs.getWritten();
    } orelse {
        noteJidOverflow("unavailable stanza for '{s}' exceeds {d} bytes; broadcast skipped", .{ from_str, router.JID_STANZA_MAX });
        return;
    };

    deliverPresenceToSubscribers(server, subscriber_jids, bare_jid, presence_xml, changes);

    logUnavailable(local, domain, resource);
}

/// Send presence probes to contacts we're subscribed to (to get their current status).
/// For each available contact resource, sends a per-resource full-JID presence.
/// Cross-thread contacts receive delivery via MPSC queue.
pub fn sendPresenceProbes(server: *Server, session: *Session, local: []const u8, domain: []const u8, changes: *ChangeList) void {
    const roster = server.roster orelse return;
    const sm = server.session_map orelse return;

    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const bare_jid = router.buildBareJid(local, domain, &bare_buf) catch {
        noteJidOverflow("probe source '{s}@{s}' exceeds {d} bytes; probes skipped", .{ local, domain, router.BARE_JID_MAX });
        return;
    };

    // Get contacts whose presence we should receive (to/both) — cached (T129)
    // Contact JID pointers index into this buffer and stay live across the
    // loop below, which also builds a probe stanza into a second leased bank.
    var probe_lease = server.leaseByteScratch() orelse {
        noteDrop("byte-scratch exhausted; presence probes for '{s}' skipped", .{bare_jid});
        return;
    };
    defer probe_lease.release();
    const probe_jid_buf = probe_lease.buf;
    var probe_jid_ptrs: [256][]const u8 = undefined;
    const bare_hash = sub_cache_mod.hashBareJid(bare_jid);
    const now = std.time.timestamp();
    const probe_count = server.sub_cache.lookupSubscriptions(bare_hash, now, probe_jid_buf, &probe_jid_ptrs) orelse blk: {
        const count = roster.getPresenceSubscriptionsFixed(bare_jid, probe_jid_buf, &probe_jid_ptrs) catch return;
        server.sub_cache.storeSubscriptions(bare_hash, now, probe_jid_ptrs[0..count]);
        break :blk count;
    };
    const contact_jids = probe_jid_ptrs[0..probe_count];

    // Build our full JID as the 'to' attribute for cross-thread deliveries
    const bound = session.stream.bound_jid orelse return;
    var to_buf: [router.FULL_JID_MAX]u8 = undefined;
    const to_str = router.buildFullJid(bound.local, bound.domain, bound.resource, &to_buf) catch {
        noteJidOverflow("bound full JID '{s}@{s}/{s}' exceeds {d} bytes; probes skipped", .{ bound.local, bound.domain, bound.resource, router.FULL_JID_MAX });
        return;
    };

    // For each subscribed contact, check if local or remote. T130: local
    // contacts resolve in chunks of one lock hold instead of one per JID.
    // S18: chunk scratch lives on the heap, sized to the session map's
    // resource cap (SUBS_PER_CHUNK * cap), so a chunk cannot truncate.
    const SUBS_PER_CHUNK = Server.SCRATCH_CHUNK_JIDS;

    var contact_i: usize = 0;
    while (contact_i < contact_jids.len) {
        var parts_buf: [SUBS_PER_CHUNK]session_map_mod.JidParts = undefined;
        var parts_len: usize = 0;
        const end = @min(contact_i + SUBS_PER_CHUNK, contact_jids.len);

        for (contact_jids[contact_i..end]) |contact_bare| {
            const at_pos = std.mem.indexOf(u8, contact_bare, "@") orelse continue;
            const contact_local = contact_bare[0..at_pos];
            const contact_domain = contact_bare[at_pos + 1 ..];

            // Remote domain? Send a presence probe via S2S.
            // The remote server will respond with the contact's current presence.
            if (!std.mem.eql(u8, contact_domain, server.server_host)) {
                var probe_buf: [router.JID_STANZA_MAX]u8 = undefined;
                var probe_fbs = std.io.fixedBufferStream(&probe_buf);
                const pbw = probe_fbs.writer();
                const probe_xml = stanza: {
                    pbw.writeAll("<presence from='") catch break :stanza null;
                    xml.escapeWrite(pbw, bare_jid) catch break :stanza null;
                    pbw.writeAll("' to='") catch break :stanza null;
                    xml.escapeWrite(pbw, contact_bare) catch break :stanza null;
                    pbw.writeAll("' type='probe'/>") catch break :stanza null;
                    break :stanza probe_fbs.getWritten();
                } orelse {
                    noteJidOverflow("probe stanza to '{s}' exceeds {d} bytes; skipped", .{ contact_bare, router.JID_STANZA_MAX });
                    continue;
                };
                server.sendPresenceViaS2s(bare_jid, contact_bare, probe_xml, changes);
                continue;
            }
            parts_buf[parts_len] = .{ .local = contact_local, .domain = contact_domain };
            parts_len += 1;
        }

        var lease_a = server.leaseScratch(.a);
        defer lease_a.release();
        const entries = lease_a.entries;
        const jid_idxs = server.scratchJidIdxsA();
        const target_count = sm.findAvailableByBareJidBatch(parts_buf[0..parts_len], entries, jid_idxs);

        for (entries[0..target_count], jid_idxs[0..target_count]) |entry, idx| {
            const contact = parts_buf[idx];

            // Retrieve the contact's stored presence inner XML (status/show/priority)
            const contact_inner = if (entry.worker_id == server.worker_id) blk: {
                const contact_sess = server.sessions[entry.local_session_id] orelse break :blk @as([]const u8, "");
                break :blk contact_sess.last_presence_inner[0..contact_sess.last_presence_inner_len];
            } else @as([]const u8, "");

            // Build presence from the contact's full JID (per-resource)
            var pres_buf: [4608]u8 = undefined;
            var pres_fbs = std.io.fixedBufferStream(&pres_buf);
            const ppw = pres_fbs.writer();
            const presence_xml = stanza: {
                ppw.writeAll("<presence from='") catch break :stanza null;
                xml.escapeWrite(ppw, contact.local) catch break :stanza null;
                ppw.writeByte('@') catch break :stanza null;
                xml.escapeWrite(ppw, contact.domain) catch break :stanza null;
                ppw.writeByte('/') catch break :stanza null;
                xml.escapeWrite(ppw, entry.resource()) catch break :stanza null;
                ppw.writeAll("' to='") catch break :stanza null;
                xml.escapeWrite(ppw, to_str) catch break :stanza null;
                ppw.writeByte('\'') catch break :stanza null;
                if (contact_inner.len > 0) {
                    ppw.writeByte('>') catch break :stanza null;
                    ppw.writeAll(contact_inner) catch break :stanza null;
                    ppw.writeAll("</presence>") catch break :stanza null;
                } else {
                    ppw.writeAll("/>") catch break :stanza null;
                }
                break :stanza pres_fbs.getWritten();
            } orelse {
                noteJidOverflow("contact presence for '{s}@{s}' exceeds {d} bytes; skipped", .{ contact.local, contact.domain, pres_buf.len });
                continue;
            };

            // The presence stanza is directed TO us (the session that just
            // became available). Deliver locally regardless of which worker
            // the contact is on — we already have their resource from the
            // session map; no need to ask the remote worker.
            session.queueSendStanza(presence_xml) catch continue;
            if (session.conn.hasPendingWrite()) {
                changes.addWrite(session.conn.fd, session.conn.id) catch {};
            }
        }

        contact_i = end;
    }
}

/// RFC 6120 4.9.3.10: a subscription stanza whose over-long `to` would
/// overflow the 511-byte store key is rejected, not dropped (S4).
fn rejectOversizeSubscriptionTo(session: *Session, to_str: []const u8, changes: *ChangeList) void {
    const jid = session.stream.authenticated_jid orelse return;
    var buf: [4608]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();
    const err_xml = stanza: {
        w.writeAll("<presence from='") catch break :stanza null;
        xml.escapeWrite(w, to_str) catch break :stanza null;
        w.writeAll("' to='") catch break :stanza null;
        xml.escapeWrite(w, jid.local) catch break :stanza null;
        w.writeByte('@') catch break :stanza null;
        xml.escapeWrite(w, jid.domain) catch break :stanza null;
        w.writeByte('/') catch break :stanza null;
        xml.escapeWrite(w, jid.resource) catch break :stanza null;
        w.writeAll("' type='error'") catch break :stanza null;
        if (session.stanza_id.len > 0) {
            w.writeAll(" id='") catch break :stanza null;
            xml.escapeWrite(w, session.stanza_id) catch break :stanza null;
            w.writeByte('\'') catch break :stanza null;
        }
        w.writeAll("><error type='modify'><jid-malformed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>") catch break :stanza null;
        break :stanza fbs.getWritten();
    } orelse {
        noteJidOverflow("jid-malformed reply exceeds {d} bytes; over-long subscription target unanswered", .{buf.len});
        return;
    };
    session.queueSendStanza(err_xml) catch return;
    if (session.conn.hasPendingWrite()) {
        changes.addWrite(session.conn.fd, session.conn.id) catch {};
    }
}

// ========================================================================
// Subscription state machine (RFC 6121 Section 3)
// ========================================================================

/// Handle <presence type='subscribe' to='contact@host'/> — outbound subscription request.
fn handleSubscribe(server: *Server, session: *Session, inner_xml: []const u8, changes: *ChangeList) void {
    const roster = server.roster orelse return;
    const bound = session.stream.bound_jid orelse return;

    const to_str = session.stanza_to;
    if (to_str.len == 0) return;

    // Build owner bare JID
    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const owner_bare = router.buildBareJid(bound.local, bound.domain, &bare_buf) catch {
        noteJidOverflow("owner bare JID '{s}@{s}' exceeds {d} bytes; subscription stanza dropped", .{ bound.local, bound.domain, router.BARE_JID_MAX });
        return;
    };

    // Update owner's roster: set ask='subscribe' (preserve existing name/subscription)
    var result_sub: Subscription = .none;
    if (roster.getItem(server.allocator, owner_bare, to_str) catch null) |existing| {
        defer if (existing.name.len > 0) server.allocator.free(existing.name);
        defer if (existing.groups.len > 0) server.allocator.free(existing.groups);
        result_sub = existing.subscription;
        roster.setItem(owner_bare, to_str, existing.name, existing.subscription, true) catch return;
    } else {
        roster.setItem(owner_bare, to_str, "", Subscription.none, true) catch return;
    }
    server.invalidateSubCache(owner_bare);

    // RFC 6121 §3.1.2: Push roster item to all of owner's interested resources
    iq_handler.pushRosterItem(server, bound.local, bound.domain, to_str, "", result_sub, true, changes);

    // Forward subscribe to the target
    const to_jid = xmpp.Jid.parse(to_str) catch return;

    // Build presence stanza (include extensions from inner_xml). Stays live
    // across the delivery or store below, so it is leased (S18).
    var sub_pres_lease = server.leaseByteScratch() orelse {
        noteDrop("byte-scratch exhausted; subscribe forward to '{s}' skipped", .{to_str});
        return;
    };
    defer sub_pres_lease.release();
    var sub_pres_fbs = std.io.fixedBufferStream(sub_pres_lease.buf);
    const spw = sub_pres_fbs.writer();
    const sub_pres_xml = stanza: {
        spw.writeAll("<presence from='") catch break :stanza null;
        xml.escapeWrite(spw, owner_bare) catch break :stanza null;
        spw.writeAll("' to='") catch break :stanza null;
        xml.escapeWrite(spw, to_str) catch break :stanza null;
        spw.writeAll("' type='subscribe'") catch break :stanza null;
        if (inner_xml.len > 0) {
            spw.writeByte('>') catch break :stanza null;
            spw.writeAll(inner_xml) catch break :stanza null;
            spw.writeAll("</presence>") catch break :stanza null;
        } else {
            spw.writeAll("/>") catch break :stanza null;
        }
        break :stanza sub_pres_fbs.getWritten();
    } orelse {
        noteJidOverflow("subscribe stanza to '{s}' exceeds {d} bytes; dropped", .{ to_str, sub_pres_lease.buf.len });
        return;
    };

    // Remote domain? Forward via S2S.
    if (!std.mem.eql(u8, to_jid.domain, server.server_host)) {
        server.forwardPresenceXmlToS2s(session, owner_bare, to_str, sub_pres_xml, changes);
    } else {
        // RFC 6121 §3.1.3 rule 4: If the contact has no available sessions,
        // store the subscription request for deferred delivery when they come online.
        const sm = server.session_map orelse {
            deliverPresenceToTarget(server, to_jid.local, to_jid.domain, sub_pres_xml, changes);
            log.info("{s} subscribing to {s}", .{ owner_bare, to_str });
            return;
        };
        const target_count = blk: {
            var lease_b = server.leaseScratch(.b);
            defer lease_b.release();
            break :blk sm.findAvailableByBareJid(to_jid.local, to_jid.domain, lease_b.entries);
        };
        if (target_count > 0) {
            deliverPresenceToTarget(server, to_jid.local, to_jid.domain, sub_pres_xml, changes);
        } else {
            // Target is offline: store for deferred delivery.
            storePendingSubscription(server, to_str, sub_pres_xml);
        }
    }

    log.info("{s} subscribing to {s}", .{ owner_bare, to_str });
}

/// Handle <presence type='subscribed' to='contact@host'/> — approve inbound subscription.
fn handleSubscribed(server: *Server, session: *Session, inner_xml: []const u8, changes: *ChangeList) void {
    _ = inner_xml;
    const roster = server.roster orelse return;
    const bound = session.stream.bound_jid orelse return;

    const to_str = session.stanza_to;
    if (to_str.len == 0) return;

    // Build owner bare JID
    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const owner_bare = router.buildBareJid(bound.local, bound.domain, &bare_buf) catch {
        noteJidOverflow("owner bare JID '{s}@{s}' exceeds {d} bytes; subscription stanza dropped", .{ bound.local, bound.domain, router.BARE_JID_MAX });
        return;
    };

    // Update our roster: contact's subscription gains "from" direction
    var owner_new_sub: Subscription = .from;
    if (roster.getItem(server.allocator, owner_bare, to_str) catch null) |existing| {
        defer if (existing.name.len > 0) server.allocator.free(existing.name);
        owner_new_sub = switch (existing.subscription) {
            .none => .from,
            .to => .both,
            else => existing.subscription,
        };
        roster.setItem(owner_bare, to_str, existing.name, owner_new_sub, false) catch return;
    } else {
        roster.setItem(owner_bare, to_str, "", .from, false) catch return;
    }
    server.invalidateSubCache(owner_bare);

    // RFC 6121 §3.1.5: Push updated roster to owner's interested resources
    iq_handler.pushRosterItem(server, bound.local, bound.domain, to_str, "", owner_new_sub, false, changes);

    // Update contact's roster: their subscription gains "to" direction
    var contact_new_sub: Subscription = .to;
    var contact_name_buf: [256]u8 = undefined;
    var contact_name_len: usize = 0;
    if (roster.getItem(server.allocator, to_str, owner_bare) catch null) |existing| {
        defer if (existing.name.len > 0) server.allocator.free(existing.name);
        contact_new_sub = switch (existing.subscription) {
            .none => .to,
            .from => .both,
            else => existing.subscription,
        };
        // Preserve existing display name
        if (existing.name.len > 0) {
            const copy_len = @min(existing.name.len, contact_name_buf.len);
            @memcpy(contact_name_buf[0..copy_len], existing.name[0..copy_len]);
            contact_name_len = copy_len;
        }
        roster.setItem(to_str, owner_bare, contact_name_buf[0..contact_name_len], contact_new_sub, false) catch |err| {
            noteDrop("contact roster update failed for {s}: {s}", .{ to_str, @errorName(err) });
        };
    } else {
        roster.setItem(to_str, owner_bare, "", .to, false) catch |err| {
            noteDrop("contact roster insert failed for {s}: {s}", .{ to_str, @errorName(err) });
        };
    }
    server.invalidateSubCache(to_str);

    // RFC 6121 §3.1.5: Push updated roster to contact's interested resources
    const to_jid_parsed = xmpp.Jid.parse(to_str) catch return;
    if (std.mem.eql(u8, to_jid_parsed.domain, server.server_host)) {
        iq_handler.pushRosterItem(server, to_jid_parsed.local, to_jid_parsed.domain, owner_bare, "", contact_new_sub, false, changes);
    }

    // Forward subscribed to the target
    const to_jid = to_jid_parsed;

    // Build presence stanza
    var sd_pres_buf: [router.JID_STANZA_MAX]u8 = undefined;
    var sd_pres_fbs = std.io.fixedBufferStream(&sd_pres_buf);
    const sdpw = sd_pres_fbs.writer();
    const sd_pres_xml = stanza: {
        sdpw.writeAll("<presence from='") catch break :stanza null;
        xml.escapeWrite(sdpw, owner_bare) catch break :stanza null;
        sdpw.writeAll("' to='") catch break :stanza null;
        xml.escapeWrite(sdpw, to_str) catch break :stanza null;
        sdpw.writeAll("' type='subscribed'/>") catch break :stanza null;
        break :stanza sd_pres_fbs.getWritten();
    } orelse {
        noteJidOverflow("subscribed stanza to '{s}' exceeds {d} bytes; dropped", .{ to_str, router.JID_STANZA_MAX });
        return;
    };

    // Remote domain? Forward via S2S.
    if (!std.mem.eql(u8, to_jid.domain, server.server_host)) {
        server.forwardPresenceXmlToS2s(session, owner_bare, to_str, sd_pres_xml, changes);
    } else {
        deliverPresenceToTarget(server, to_jid.local, to_jid.domain, sd_pres_xml, changes);
    }

    // Also send our current presence to the newly subscribed contact (they can now see us).
    // Use the stored last_presence_inner so the subscriber receives the full presence
    // including status, show, and priority (RFC 6121 §3.1.5).
    const sd_sm = server.session_map orelse return;
    if (sd_sm.findByFullJid(bound.local, bound.domain, bound.resource)) |ent| {
        if (ent.presence_available) {
            const own_inner = session.last_presence_inner[0..session.last_presence_inner_len];
            broadcastPresence(server, bound.local, bound.domain, bound.resource, own_inner, changes);
        }
    }

    // RFC 6121 §3.1.5: Send the contact's current presence to the approver.
    // The approver now has 'from' the contact = contact's presence should be visible.
    if (std.mem.eql(u8, to_jid.domain, server.server_host)) {
        var lease_b = server.leaseScratch(.b);
        defer lease_b.release();
        const probe_entries = lease_b.entries;
        const probe_count = sd_sm.findAvailableByBareJid(to_jid.local, to_jid.domain, probe_entries);
        for (probe_entries[0..probe_count]) |pentry| {
            // Look up the contact's session to retrieve their stored presence inner XML.
            const contact_inner = if (pentry.worker_id == server.worker_id) blk: {
                const contact_sess = server.sessions[pentry.local_session_id] orelse break :blk @as([]const u8, "");
                break :blk contact_sess.last_presence_inner[0..contact_sess.last_presence_inner_len];
            } else @as([]const u8, "");

            var cpres_buf: [4608]u8 = undefined;
            var cpres_fbs = std.io.fixedBufferStream(&cpres_buf);
            const cpw = cpres_fbs.writer();
            const cpres_xml = stanza: {
                cpw.writeAll("<presence from='") catch break :stanza null;
                xml.escapeWrite(cpw, to_jid.local) catch break :stanza null;
                cpw.writeByte('@') catch break :stanza null;
                xml.escapeWrite(cpw, to_jid.domain) catch break :stanza null;
                cpw.writeByte('/') catch break :stanza null;
                xml.escapeWrite(cpw, pentry.resource()) catch break :stanza null;
                cpw.writeByte('\'') catch break :stanza null;
                if (contact_inner.len > 0) {
                    cpw.writeByte('>') catch break :stanza null;
                    cpw.writeAll(contact_inner) catch break :stanza null;
                    cpw.writeAll("</presence>") catch break :stanza null;
                } else {
                    cpw.writeAll("/>") catch break :stanza null;
                }
                break :stanza cpres_fbs.getWritten();
            } orelse {
                noteJidOverflow("contact presence '{s}@{s}' exceeds {d} bytes; skipped", .{ to_jid.local, to_jid.domain, cpres_buf.len });
                continue;
            };
            // Deliver to the approver's session
            session.queueSendStanza(cpres_xml) catch continue;
        }
        if (session.conn.hasPendingWrite()) {
            changes.addWrite(session.conn.fd, session.conn.id) catch {};
        }
    }

    log.info("{s} approved subscription from {s}", .{ owner_bare, to_str });
}

/// Handle <presence type='unsubscribe' to='contact@host'/> — cancel outbound subscription.
fn handleUnsubscribe(server: *Server, session: *Session, inner_xml: []const u8, changes: *ChangeList) void {
    _ = inner_xml;
    const roster = server.roster orelse return;
    const bound = session.stream.bound_jid orelse return;

    const to_str = session.stanza_to;
    if (to_str.len == 0) return;

    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const owner_bare = router.buildBareJid(bound.local, bound.domain, &bare_buf) catch {
        noteJidOverflow("owner bare JID '{s}@{s}' exceeds {d} bytes; subscription stanza dropped", .{ bound.local, bound.domain, router.BARE_JID_MAX });
        return;
    };

    // Update our roster: remove "to" direction
    var owner_new_sub: Subscription = .none;
    if (roster.getItem(server.allocator, owner_bare, to_str) catch null) |existing| {
        defer if (existing.name.len > 0) server.allocator.free(existing.name);
        defer if (existing.groups.len > 0) server.allocator.free(existing.groups);
        owner_new_sub = switch (existing.subscription) {
            .to => .none,
            .both => .from,
            else => existing.subscription,
        };
        roster.setItemWithGroups(owner_bare, to_str, existing.name, owner_new_sub, false, existing.groups, existing.group_count) catch |e| {
            log.err("handleUnsubscribe: setItem owner failed: {}", .{e});
            return;
        };
        server.invalidateSubCache(owner_bare);
    }

    // RFC 6121 §3.2.2: Push updated roster to owner's interested resources
    iq_handler.pushRosterItem(server, bound.local, bound.domain, to_str, "", owner_new_sub, false, changes);

    // Update contact's roster: remove "from" direction (idempotent — skip if already done)
    const to_jid_parsed = xmpp.Jid.parse(to_str) catch return;
    if (std.mem.eql(u8, to_jid_parsed.domain, server.server_host)) {
        if (roster.getItem(server.allocator, to_str, owner_bare) catch null) |existing| {
            defer if (existing.name.len > 0) server.allocator.free(existing.name);
            defer if (existing.groups.len > 0) server.allocator.free(existing.groups);
            const contact_new_sub: Subscription = switch (existing.subscription) {
                .from => .none,
                .both => .to,
                else => existing.subscription,
            };
            if (contact_new_sub != existing.subscription) {
                roster.setItemWithGroups(to_str, owner_bare, existing.name, contact_new_sub, false, existing.groups, existing.group_count) catch |e| {
                    log.err("handleUnsubscribe: setItem contact failed: {}", .{e});
                    return;
                };
                server.invalidateSubCache(to_str);
                iq_handler.pushRosterItem(server, to_jid_parsed.local, to_jid_parsed.domain, owner_bare, "", contact_new_sub, false, changes);
            }
        }
    }

    // Forward unsubscribe
    const to_jid = to_jid_parsed;

    // Build presence stanza
    var unsub_pres_buf: [router.JID_STANZA_MAX]u8 = undefined;
    var unsub_pres_fbs = std.io.fixedBufferStream(&unsub_pres_buf);
    const usbw = unsub_pres_fbs.writer();
    const unsub_pres_xml = stanza: {
        usbw.writeAll("<presence from='") catch break :stanza null;
        xml.escapeWrite(usbw, owner_bare) catch break :stanza null;
        usbw.writeAll("' to='") catch break :stanza null;
        xml.escapeWrite(usbw, to_str) catch break :stanza null;
        usbw.writeAll("' type='unsubscribe'/>") catch break :stanza null;
        break :stanza unsub_pres_fbs.getWritten();
    } orelse {
        noteJidOverflow("unsubscribe stanza to '{s}' exceeds {d} bytes; dropped", .{ to_str, router.JID_STANZA_MAX });
        return;
    };

    // Remote domain? Forward via S2S.
    if (!std.mem.eql(u8, to_jid.domain, server.server_host)) {
        server.forwardPresenceXmlToS2s(session, owner_bare, to_str, unsub_pres_xml, changes);
    } else {
        deliverPresenceToTarget(server, to_jid.local, to_jid.domain, unsub_pres_xml, changes);
    }

    log.info("{s} unsubscribing from {s}", .{ owner_bare, to_str });
}

/// Handle <presence type='unsubscribed' to='contact@host'/> — deny/revoke inbound subscription.
fn handleUnsubscribed(server: *Server, session: *Session, inner_xml: []const u8, changes: *ChangeList) void {
    _ = inner_xml;
    const roster = server.roster orelse return;
    const bound = session.stream.bound_jid orelse return;

    const to_str = session.stanza_to;
    if (to_str.len == 0) return;

    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const owner_bare = router.buildBareJid(bound.local, bound.domain, &bare_buf) catch {
        noteJidOverflow("owner bare JID '{s}@{s}' exceeds {d} bytes; subscription stanza dropped", .{ bound.local, bound.domain, router.BARE_JID_MAX });
        return;
    };

    // Update our roster: remove "from" direction
    var owner_new_sub: Subscription = .none;
    var owner_ask: bool = false;
    if (roster.getItem(server.allocator, owner_bare, to_str) catch null) |existing| {
        defer if (existing.name.len > 0) server.allocator.free(existing.name);
        defer if (existing.groups.len > 0) server.allocator.free(existing.groups);
        owner_ask = existing.ask;
        owner_new_sub = switch (existing.subscription) {
            .from => .none,
            .both => .to,
            else => existing.subscription,
        };
        roster.setItemWithGroups(owner_bare, to_str, existing.name, owner_new_sub, existing.ask, existing.groups, existing.group_count) catch |e| {
            log.err("handleUnsubscribed: setItem owner failed: {}", .{e});
            return;
        };
        server.invalidateSubCache(owner_bare);
    }

    // RFC 6121 §3.2.2: Push updated roster to owner's interested resources
    iq_handler.pushRosterItem(server, bound.local, bound.domain, to_str, "", owner_new_sub, owner_ask, changes);

    // Update contact's roster: remove "to" direction (idempotent — skip if already done)
    const to_jid_parsed = xmpp.Jid.parse(to_str) catch return;
    if (std.mem.eql(u8, to_jid_parsed.domain, server.server_host)) {
        if (roster.getItem(server.allocator, to_str, owner_bare) catch null) |existing| {
            defer if (existing.name.len > 0) server.allocator.free(existing.name);
            defer if (existing.groups.len > 0) server.allocator.free(existing.groups);
            const contact_new_sub: Subscription = switch (existing.subscription) {
                .to => .none,
                .both => .from,
                else => existing.subscription,
            };
            if (contact_new_sub != existing.subscription) {
                roster.setItemWithGroups(to_str, owner_bare, existing.name, contact_new_sub, false, existing.groups, existing.group_count) catch |e| {
                    log.err("handleUnsubscribed: setItem contact failed: {}", .{e});
                    return;
                };
                server.invalidateSubCache(to_str);
                iq_handler.pushRosterItem(server, to_jid_parsed.local, to_jid_parsed.domain, owner_bare, "", contact_new_sub, false, changes);
            }
        }
    }

    // RFC 6121 §3.2.2: Send unavailable from all of owner's available resources
    // to the contact BEFORE the unsubscribed stanza.
    const to_jid = to_jid_parsed;
    if (std.mem.eql(u8, to_jid.domain, server.server_host)) {
        const unsub_sm = server.session_map orelse return;
        var lease_b = server.leaseScratch(.b);
        defer lease_b.release();
        const owner_entries = lease_b.entries;
        const owner_count = unsub_sm.findAvailableByBareJid(bound.local, bound.domain, owner_entries);
        for (owner_entries[0..owner_count]) |oent| {
            var unavail_buf: [router.JID_STANZA_MAX]u8 = undefined;
            var unavail_fbs = std.io.fixedBufferStream(&unavail_buf);
            const uw = unavail_fbs.writer();
            const unavail_xml = stanza: {
                uw.writeAll("<presence from='") catch break :stanza null;
                xml.escapeWrite(uw, bound.local) catch break :stanza null;
                uw.writeByte('@') catch break :stanza null;
                xml.escapeWrite(uw, bound.domain) catch break :stanza null;
                uw.writeByte('/') catch break :stanza null;
                xml.escapeWrite(uw, oent.resource()) catch break :stanza null;
                uw.writeAll("' to='") catch break :stanza null;
                xml.escapeWrite(uw, to_str) catch break :stanza null;
                uw.writeAll("' type='unavailable'/>") catch break :stanza null;
                break :stanza unavail_fbs.getWritten();
            } orelse {
                noteJidOverflow("unavailable stanza to '{s}' exceeds {d} bytes; resource skipped", .{ to_str, router.JID_STANZA_MAX });
                continue;
            };
            deliverPresenceToTarget(server, to_jid.local, to_jid.domain, unavail_xml, changes);
        }
    }

    // Forward unsubscribed

    // Build presence stanza
    var unsd_pres_buf: [router.JID_STANZA_MAX]u8 = undefined;
    var unsd_pres_fbs = std.io.fixedBufferStream(&unsd_pres_buf);
    const usdw = unsd_pres_fbs.writer();
    const unsd_pres_xml = stanza: {
        usdw.writeAll("<presence from='") catch break :stanza null;
        xml.escapeWrite(usdw, owner_bare) catch break :stanza null;
        usdw.writeAll("' to='") catch break :stanza null;
        xml.escapeWrite(usdw, to_str) catch break :stanza null;
        usdw.writeAll("' type='unsubscribed'/>") catch break :stanza null;
        break :stanza unsd_pres_fbs.getWritten();
    } orelse {
        noteJidOverflow("unsubscribed stanza to '{s}' exceeds {d} bytes; dropped", .{ to_str, router.JID_STANZA_MAX });
        return;
    };

    // Remote domain? Forward via S2S.
    if (!std.mem.eql(u8, to_jid.domain, server.server_host)) {
        server.forwardPresenceXmlToS2s(session, owner_bare, to_str, unsd_pres_xml, changes);
    } else {
        deliverPresenceToTarget(server, to_jid.local, to_jid.domain, unsd_pres_xml, changes);
    }

    log.info("{s} denied/revoked subscription from {s}", .{ owner_bare, to_str });
}

// ========================================================================
// Pending subscription storage (RFC 6121 §3.1.3 rule 4)
// ========================================================================

pub const PENDING_SUB_NS = backend_mod.registered("pending_sub");

/// Store a pending subscription request for deferred delivery to an offline contact.
/// Key: contact_bare\x00subscriber_bare. Value: raw subscribe presence XML.
/// Deduplication: only one pending subscribe per subscriber→contact pair (overwrites).
fn storePendingSubscription(server: *Server, contact_bare: []const u8, sub_pres_xml: []const u8) void {
    const roster = server.roster orelse return;

    // Extract subscriber bare JID from the presence XML's 'from' attribute.
    // The XML format is: <presence from='subscriber@host' to='contact@host' type='subscribe'...
    // Use the contact_bare as prefix and the from JID as suffix for the key.
    const from_start = std.mem.indexOf(u8, sub_pres_xml, "from='") orelse return;
    const from_value_start = from_start + 6;
    const from_end = std.mem.indexOfPos(u8, sub_pres_xml, from_value_start, "'") orelse return;
    const subscriber_bare = sub_pres_xml[from_value_start..from_end];

    var key_buf: [store_keys.MAX_KEY_LEN]u8 = undefined;
    const key = store_keys.join2(&key_buf, contact_bare, subscriber_bare) catch {
        noteDrop("pending-subscription key too long for contact {s}: not stored", .{contact_bare});
        return;
    };

    roster.backend.put(PENDING_SUB_NS, key, sub_pres_xml) catch |e| {
        log.err("storePendingSubscription failed for {s}: {}", .{ contact_bare, e });
    };
    log.info("stored pending subscribe for offline contact {s} from {s}", .{ contact_bare, subscriber_bare });
}

/// Deliver any pending subscription requests to a user who just became available.
/// Called from dispatchPresence on initial available presence.
pub fn deliverPendingSubscriptions(server: *Server, session: *Session, local: []const u8, domain: []const u8, changes: *ChangeList) void {
    const roster = server.roster orelse return;

    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const bare_jid = router.buildBareJid(local, domain, &bare_buf) catch {
        noteDrop("deliverPendingSubscriptions: bare JID too long for {s}@{s}", .{ local, domain });
        return;
    };

    // Prefix scan: all keys starting with "contact_bare\x00"
    var prefix_buf: [store_keys.MAX_KEY_LEN]u8 = undefined;
    const prefix = store_keys.prefix(&prefix_buf, bare_jid) catch {
        noteDrop("deliverPendingSubscriptions: prefix too long for {s}", .{bare_jid});
        return;
    };

    var iter = roster.backend.iterator(PENDING_SUB_NS, prefix) catch return;
    defer iter.deinit();

    var delivered: usize = 0;
    while (iter.next()) |kv| {
        // Value is the stored subscribe presence XML
        session.queueSendStanza(kv.value) catch continue;
        delivered += 1;

        // Delete after delivery (dequeue)
        roster.backend.delete(PENDING_SUB_NS, kv.key) catch {};
    }

    if (delivered > 0) {
        if (session.conn.hasPendingWrite()) {
            changes.addWrite(session.conn.fd, session.conn.id) catch {};
        }
        log.info("delivered {d} pending subscriptions to {s}", .{ delivered, bare_jid });
    }
}

// ========================================================================
// Internal delivery helpers
// ========================================================================

/// RFC 6121 §4.4.2: Send presence from a resource to all of the user's own
/// available resources (including the originator). This allows multi-resource
/// clients to see each other's presence updates.
fn broadcastToOwnResources(
    server: *Server,
    sender_session: *Session,
    local: []const u8,
    domain: []const u8,
    resource: []const u8,
    changes: *ChangeList,
) void {
    const sm = server.session_map orelse return;

    // Build the from full JID
    var from_buf: [router.FULL_JID_MAX]u8 = undefined;
    const from_str = router.buildFullJid(local, domain, resource, &from_buf) catch {
        noteJidOverflow("own-resources presence from '{s}@{s}/{s}' exceeds {d} bytes; skipped", .{ local, domain, resource, router.FULL_JID_MAX });
        return;
    };

    // Build presence stanza including inner XML (priority, show, status, etc.)
    // Stays live across the delivery loop below, so it is leased (S18).
    const inner_xml = sender_session.stanza_buf[0..sender_session.stanza_buf_len];
    var pres_lease = server.leaseByteScratch() orelse {
        noteDrop("byte-scratch exhausted; own-resources presence for '{s}' skipped", .{from_str});
        return;
    };
    defer pres_lease.release();
    var pres_fbs = std.io.fixedBufferStream(pres_lease.buf);
    const pw = pres_fbs.writer();
    const presence_xml = stanza: {
        pw.writeAll("<presence from='") catch break :stanza null;
        xml.escapeWrite(pw, from_str) catch break :stanza null;
        pw.writeByte('\'') catch break :stanza null;
        if (sender_session.stanza_type.len > 0) {
            pw.writeAll(" type='") catch break :stanza null;
            xml.escapeWrite(pw, sender_session.stanza_type) catch break :stanza null;
            pw.writeByte('\'') catch break :stanza null;
        }
        if (inner_xml.len > 0) {
            pw.writeByte('>') catch break :stanza null;
            pw.writeAll(inner_xml) catch break :stanza null;
            pw.writeAll("</presence>") catch break :stanza null;
        } else {
            pw.writeAll("/>") catch break :stanza null;
        }
        break :stanza pres_fbs.getWritten();
    } orelse {
        noteJidOverflow("own-resources presence stanza for '{s}' exceeds {d} bytes; skipped", .{ from_str, pres_lease.buf.len });
        return;
    };

    var lease_b = server.leaseScratch(.b);
    defer lease_b.release();
    const entries = lease_b.entries;
    const count = sm.findByBareJid(local, domain, entries);

    for (entries[0..count]) |entry| {
        if (entry.worker_id == server.worker_id) {
            const target = server.sessions[entry.local_session_id] orelse continue;
            // T153: detached (SM resume pending) session — no live connection.
            if (target.sm_detached) {
                target.smTrackOutbound(presence_xml);
                continue;
            }
            target.queueSendStanza(presence_xml) catch continue;
            _ = target.conn.flushSend() catch {};
            if (target.conn.hasPendingWrite()) {
                changes.addWrite(target.conn.fd, entry.local_session_id) catch {};
            }
        } else if (server.delivery_system) |ds| {
            ds.deliver(entry.worker_id, entry.local_session_id, entry.generation, presence_xml) catch {};
        }
    }
}

/// RFC 6121 §4.4.2 (reverse direction): When a new resource becomes available,
/// send the current presence of all OTHER already-available resources to it.
/// This allows the new resource to know the full presence state of the account.
fn sendOtherResourcesPresence(
    server: *Server,
    new_session: *Session,
    local: []const u8,
    domain: []const u8,
    new_resource: []const u8,
    changes: *ChangeList,
) void {
    const sm = server.session_map orelse return;

    var lease_b = server.leaseScratch(.b);
    defer lease_b.release();
    const entries = lease_b.entries;
    const count = sm.findAvailableByBareJid(local, domain, entries);

    for (entries[0..count]) |entry| {
        const entry_resource = entry.resource();
        // Skip self — the new resource already knows its own presence.
        if (std.mem.eql(u8, entry_resource, new_resource)) continue;

        // Build presence from the existing resource with its current priority.
        var pres_buf: [router.JID_STANZA_MAX]u8 = undefined;
        var pres_fbs = std.io.fixedBufferStream(&pres_buf);
        const pw = pres_fbs.writer();
        const presence_xml = stanza: {
            pw.writeAll("<presence from='") catch break :stanza null;
            xml.escapeWrite(pw, local) catch break :stanza null;
            pw.writeByte('@') catch break :stanza null;
            xml.escapeWrite(pw, domain) catch break :stanza null;
            pw.writeByte('/') catch break :stanza null;
            xml.escapeWrite(pw, entry_resource) catch break :stanza null;
            pw.writeByte('\'') catch break :stanza null;
            if (entry.priority != 0) {
                pw.writeAll("><priority>") catch break :stanza null;
                pw.print("{d}", .{entry.priority}) catch break :stanza null;
                pw.writeAll("</priority></presence>") catch break :stanza null;
            } else {
                pw.writeAll("/>") catch break :stanza null;
            }
            break :stanza pres_fbs.getWritten();
        } orelse {
            noteJidOverflow("other-resource presence '{s}@{s}/{s}' exceeds {d} bytes; skipped", .{ local, domain, entry_resource, router.JID_STANZA_MAX });
            continue;
        };

        new_session.queueSendStanza(presence_xml) catch continue;
        if (new_session.conn.hasPendingWrite()) {
            changes.addWrite(new_session.conn.fd, new_session.conn.id) catch {};
        }
    }
}

/// RFC 6121 §8.5.2.1.2: Dispatch directed presence to all available resources
/// of a bare JID target. Called when presence has a 'to' targeting a bare JID
/// on the local domain (e.g., <presence type='unavailable' to='bob@domain'/>).
pub fn dispatchDirectedPresenceToBareJid(
    server: *Server,
    sender_session: *Session,
    target_local: []const u8,
    target_domain: []const u8,
    changes: *ChangeList,
) void {
    defer sender_session.resetStanza();

    const sm = server.session_map orelse return;
    const bound = sender_session.stream.bound_jid orelse return;

    // Build the from full JID
    var from_buf: [router.FULL_JID_MAX]u8 = undefined;
    const from_str = router.buildFullJid(bound.local, bound.domain, bound.resource, &from_buf) catch {
        noteJidOverflow("directed presence from '{s}@{s}/{s}' exceeds {d} bytes; dropped", .{ bound.local, bound.domain, bound.resource, router.FULL_JID_MAX });
        return;
    };

    // Build presence stanza with inner XML. Stays live across the delivery
    // loop below, so it is leased (S18).
    const inner_xml = sender_session.stanza_buf[0..sender_session.stanza_buf_len];
    var pres_lease = server.leaseByteScratch() orelse {
        noteDrop("byte-scratch exhausted; directed presence for '{s}' skipped", .{from_str});
        return;
    };
    defer pres_lease.release();
    var pres_fbs = std.io.fixedBufferStream(pres_lease.buf);
    const pw = pres_fbs.writer();
    const presence_xml = stanza: {
        pw.writeAll("<presence from='") catch break :stanza null;
        xml.escapeWrite(pw, from_str) catch break :stanza null;
        pw.writeByte('\'') catch break :stanza null;
        if (sender_session.stanza_type.len > 0) {
            pw.writeAll(" type='") catch break :stanza null;
            xml.escapeWrite(pw, sender_session.stanza_type) catch break :stanza null;
            pw.writeByte('\'') catch break :stanza null;
        }
        if (inner_xml.len > 0) {
            pw.writeByte('>') catch break :stanza null;
            pw.writeAll(inner_xml) catch break :stanza null;
            pw.writeAll("</presence>") catch break :stanza null;
        } else {
            pw.writeAll("/>") catch break :stanza null;
        }
        break :stanza pres_fbs.getWritten();
    } orelse {
        noteJidOverflow("directed presence stanza from '{s}' exceeds {d} bytes; dropped", .{ from_str, pres_lease.buf.len });
        return;
    };

    // Deliver to all available resources of the target bare JID
    var lease_b = server.leaseScratch(.b);
    defer lease_b.release();
    const entries = lease_b.entries;
    const count = sm.findAvailableByBareJid(target_local, target_domain, entries);

    for (entries[0..count]) |entry| {
        if (entry.worker_id == server.worker_id) {
            const target = server.sessions[entry.local_session_id] orelse continue;
            fanout.deliverToSession(target, presence_xml, entry.local_session_id, changes);
        } else if (server.delivery_system) |ds| {
            ds.deliver(entry.worker_id, entry.local_session_id, entry.generation, presence_xml) catch {};
        }
    }
}

/// Deliver a presence stanza to all available sessions of subscriber JIDs.
/// Handles local delivery + cross-thread MPSC + S2S forwarding.
///
/// T130 batching: subscribers are processed in fixed-size chunks. Per chunk,
/// the session-map resolution happens in ONE shared-lock hold
/// (findAvailableByBareJidBatch) and each remote worker's MPSC queue gets a
/// single pipe wake regardless of how many target sessions it has
/// (enqueue + one wakeWorker), instead of a lock per JID and a pipe write
/// per session. Chunking caps stack usage at 32 subscribers x 16 resources.
fn deliverPresenceToSubscribers(
    server: *Server,
    subscriber_jids: []const []const u8,
    sender_bare: []const u8,
    presence_xml: []const u8,
    changes: *ChangeList,
) void {
    const sm = server.session_map orelse return;

    // S18: chunk scratch is heap, sized to the session map's resource
    // cap (SUBS_PER_CHUNK * cap), so a chunk cannot truncate.
    const SUBS_PER_CHUNK = Server.SCRATCH_CHUNK_JIDS;

    var i: usize = 0;
    while (i < subscriber_jids.len) {
        // Pass 1: blocklist filter, S2S split, collect local-domain JIDs.
        var parts_buf: [SUBS_PER_CHUNK]session_map_mod.JidParts = undefined;
        var parts_len: usize = 0;
        const end = @min(i + SUBS_PER_CHUNK, subscriber_jids.len);
        for (subscriber_jids[i..end]) |sub_bare_jid| {
            // XEP-0191: Skip subscribers who have blocked us
            if (server.block_store) |bs| {
                if (bs.isBlocked(server.allocator, sub_bare_jid, sender_bare) catch false) continue;
            }

            // Parse the subscriber bare JID to get local/domain
            const at_pos = std.mem.indexOf(u8, sub_bare_jid, "@") orelse continue;
            const sub_local = sub_bare_jid[0..at_pos];
            const sub_domain = sub_bare_jid[at_pos + 1 ..];

            // Remote domain? Forward via S2S.
            if (!std.mem.eql(u8, sub_domain, server.server_host)) {
                server.sendPresenceViaS2s(sender_bare, sub_bare_jid, presence_xml, changes);
                continue;
            }
            parts_buf[parts_len] = .{ .local = sub_local, .domain = sub_domain };
            parts_len += 1;
        }

        // Resolve the whole chunk under one lock hold.
        var lease_a = server.leaseScratch(.a);
        defer lease_a.release();
        const entries = lease_a.entries;
        const count = sm.findAvailableByBareJidBatch(parts_buf[0..parts_len], entries, null);

        // Local targets deliver inline.
        for (entries[0..count]) |entry| {
            if (entry.worker_id != server.worker_id) continue;
            const target_session = server.sessions[entry.local_session_id] orelse continue;
            fanout.deliverToSession(target_session, presence_xml, entry.local_session_id, changes);
        }

        // Remote targets: bucket by worker, wake each worker once.
        if (server.delivery_system) |ds| {
            var w: u16 = 0;
            while (w < ds.worker_count) : (w += 1) {
                if (w == server.worker_id) continue;
                var pending = false;
                for (entries[0..count]) |entry| {
                    if (entry.worker_id != w) continue;
                    ds.enqueue(w, entry.local_session_id, entry.generation, presence_xml) catch continue;
                    pending = true;
                }
                if (pending) ds.wakeWorker(w);
            }
        }

        i = end;
    }
}

/// Deliver a presence stanza to all sessions of a target bare JID (local domain).
/// Used by subscription handlers for forwarding subscribe/subscribed/etc.
pub fn deliverPresenceToTarget(
    server: *Server,
    target_local: []const u8,
    target_domain: []const u8,
    presence_xml: []const u8,
    changes: *ChangeList,
) void {
    const sm = server.session_map orelse return;
    // Leaf delivery: bank C so callers iterating bank B keep their results.
    var lease_c = server.leaseScratch(.c);
    defer lease_c.release();
    const entries = lease_c.entries;
    const count = sm.findByBareJid(target_local, target_domain, entries);

    for (entries[0..count]) |ent| {
        if (ent.worker_id == server.worker_id) {
            const target_session = server.sessions[ent.local_session_id] orelse continue;
            fanout.deliverToSession(target_session, presence_xml, ent.local_session_id, changes);
        } else if (server.delivery_system) |ds| {
            ds.deliver(ent.worker_id, ent.local_session_id, ent.generation, presence_xml) catch {};
        }
    }
}

test "S4: subscription presence with an over-long to gets jid-malformed" {
    const posix = std.posix;
    const allocator = std.testing.allocator;

    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();

    var fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds));
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 0, server.server_host, false, allocator);
    server.sessions[0] = session;
    session.stream.bound_jid = xmpp.Jid.parse("alice@localhost/res") catch null;
    session.stream.authenticated_jid = session.stream.bound_jid;

    // 600-byte target: inside the stanza budget but over a 511-byte store key.
    var to_buf: [600]u8 = undefined;
    @memset(&to_buf, 'a');
    @memcpy(to_buf[588..], "@example.org");
    session.stanza_to = &to_buf;
    session.stanza_id = "sess-1";

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    dispatchSubscription(&server, session, .subscribe, "", &changes);

    _ = try session.conn.flushSend();
    var buf: [2048]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    const reply = buf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, reply, "type='error'") != null);
    try std.testing.expect(std.mem.indexOf(u8, reply, "jid-malformed") != null);
    // The error reply echoes the original stanza id so the client can correlate.
    try std.testing.expect(std.mem.indexOf(u8, reply, "id='sess-1'") != null);
}

test "S18: unsubscribed fan-out keeps the owner's own resources" {
    const posix = std.posix;
    const allocator = std.testing.allocator;

    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const db_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(db_path);
    var db = try server_mod.OpBackendType.open(db_path, .{});
    defer db.close();
    var roster = generic_roster.RosterStore(server_mod.OpBackendType).init(&db);
    server.roster = &roster;

    var sm = session_map_mod.SessionMap.init(allocator, false, 0);
    defer sm.deinit();
    server.session_map = &sm;

    // Sender alice has two available resources. Only the sending one needs a
    // live session; the fan-out targets the contact.
    var alice_fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &alice_fds));
    defer posix.close(alice_fds[1]);
    const alice = try allocator.create(Session);
    alice.* = Session.init(alice_fds[0], 1, server.server_host, false, allocator);
    server.sessions[1] = alice;
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/desk") catch null;
    alice.stream.authenticated_jid = alice.stream.bound_jid;

    // Contact bob has two available resources. The second one is what an
    // aliased bank writes over alice's still-unread slot.
    var bob_fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &bob_fds));
    defer posix.close(bob_fds[1]);
    const bob = try allocator.create(Session);
    bob.* = Session.init(bob_fds[0], 2, server.server_host, false, allocator);
    server.sessions[2] = bob;

    _ = try sm.bind(0, 1, "alice", "localhost", "desk");
    _ = try sm.bind(0, 4, "alice", "localhost", "mobile");
    _ = try sm.bind(0, 2, "bob", "localhost", "laptop");
    _ = try sm.bind(0, 5, "bob", "localhost", "tablet");
    for ([_]struct { []const u8, []const u8 }{
        .{ "alice", "desk" }, .{ "alice", "mobile" },
        .{ "bob", "laptop" }, .{ "bob", "tablet" },
    }) |jid| {
        sm.setPresenceAvailable(jid[0], "localhost", jid[1], true);
    }

    const to = "bob@localhost";
    alice.stanza_to = to;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    dispatchSubscription(&server, alice, .unsubscribed, "", &changes);

    _ = try bob.conn.flushSend();
    var buf: [4096]u8 = undefined;
    const n = posix.read(bob_fds[1], &buf) catch 0;
    const got = buf[0..n];

    // One unavailable stanza per available alice resource, each naming that
    // resource. Reusing one bank for the outer iteration and the delivery
    // lookup replaced the second resource with one of bob's.
    try std.testing.expect(std.mem.indexOf(u8, got, "from='alice@localhost/desk'") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "from='alice@localhost/mobile'") != null);
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, got, "type='unavailable'"));
    try std.testing.expect(std.mem.indexOf(u8, got, "laptop") == null);
    try std.testing.expect(std.mem.indexOf(u8, got, "tablet") == null);
    try std.testing.expect(std.mem.indexOf(u8, got, "type='unsubscribed'") != null);
}

test "S1: subscription presence escapes the owner bare JID" {
    const posix = std.posix;
    const allocator = std.testing.allocator;
    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const db_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(db_path);
    var db = try server_mod.OpBackendType.open(db_path, .{});
    defer db.close();
    var roster = generic_roster.RosterStore(server_mod.OpBackendType).init(&db);
    server.roster = &roster;

    var sm = session_map_mod.SessionMap.init(allocator, false, 0);
    defer sm.deinit();
    server.session_map = &sm;

    var owner_fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &owner_fds));
    defer posix.close(owner_fds[1]);
    const owner = try allocator.create(Session);
    owner.* = Session.init(owner_fds[0], 1, server.server_host, false, allocator);
    server.sessions[1] = owner;
    owner.stream.bound_jid = .{ .local = "o'wner", .domain = "localhost", .resource = "desk" };
    owner.stanza_to = "bob@localhost";

    var bob_fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &bob_fds));
    defer posix.close(bob_fds[1]);
    const bob = try allocator.create(Session);
    bob.* = Session.init(bob_fds[0], 2, server.server_host, false, allocator);
    server.sessions[2] = bob;
    _ = try sm.bind(0, 2, "bob", "localhost", "laptop");
    sm.setPresenceAvailable("bob", "localhost", "laptop", true);

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    dispatchSubscription(&server, owner, .subscribe, "", &changes);

    _ = try bob.conn.flushSend();
    var buf: [4096]u8 = undefined;
    const n = posix.read(bob_fds[1], &buf) catch 0;
    const got = buf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, got, "from='o&apos;wner@localhost'") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "from='o'wner@localhost'") == null);
    try std.testing.expect(std.mem.indexOf(u8, got, "type='subscribe'") != null);
}

test "A62: pending-subscription delivery for a 256-byte bare JID" {
    const posix = std.posix;
    const allocator = std.testing.allocator;
    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const db_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(db_path);
    var db = try server_mod.OpBackendType.open(db_path, .{});
    defer db.close();
    var roster = generic_roster.RosterStore(server_mod.OpBackendType).init(&db);
    server.roster = &roster;

    // Bare JID of exactly 256 bytes: 246-byte localpart + "@localhost".
    var local_buf: [246]u8 = undefined;
    @memset(&local_buf, 'l');
    const local = local_buf[0..];
    var bare_buf: [256]u8 = undefined;
    const contact_bare = std.fmt.bufPrint(&bare_buf, "{s}@localhost", .{local}) catch unreachable;
    try std.testing.expectEqual(@as(usize, 256), contact_bare.len);

    // Seed a pending subscription for that contact.
    const sub_xml = "<presence from='bob@localhost' to='x' type='subscribe'/>";
    storePendingSubscription(&server, contact_bare, sub_xml);

    var fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds));
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, server.server_host, false, allocator);
    server.sessions[1] = session;
    session.stream.bound_jid = .{ .local = local, .domain = "localhost", .resource = "res" };

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    deliverPendingSubscriptions(&server, session, local, "localhost", &changes);

    _ = try session.conn.flushSend();
    var rbuf: [2048]u8 = undefined;
    const n = posix.read(fds[1], &rbuf) catch 0;
    const got = rbuf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, got, "type='subscribe'") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "from='bob@localhost'") != null);
}

test "A62: oversized bare JIDs skip pending-subscription delivery" {
    const posix = std.posix;
    const allocator = std.testing.allocator;
    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const db_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(db_path);
    var db = try server_mod.OpBackendType.open(db_path, .{});
    defer db.close();
    var roster = generic_roster.RosterStore(server_mod.OpBackendType).init(&db);
    server.roster = &roster;

    var fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds));
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, server.server_host, false, allocator);
    server.sessions[1] = session;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    var rbuf: [64]u8 = undefined;

    // 511-byte bare JID: builds, but the bare\x00 prefix exceeds MAX_KEY_LEN.
    var big_local: [1023]u8 = undefined;
    @memset(&big_local, 'l');
    deliverPendingSubscriptions(&server, session, big_local[0..501], "localhost", &changes);
    const n1 = posix.read(fds[1], &rbuf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n1);

    // RFC 7622 maximum bare JID (2047 bytes) exceeds BARE_JID_MAX entirely.
    var big_domain: [1023]u8 = undefined;
    @memset(&big_domain, 'd');
    deliverPendingSubscriptions(&server, session, &big_local, &big_domain, &changes);
    const n2 = posix.read(fds[1], &rbuf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n2);
}

test "A62: block check sees a >256-byte recipient JID in full" {
    const posix = std.posix;
    const allocator = std.testing.allocator;
    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const db_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(db_path);
    var db = try server_mod.OpBackendType.open(db_path, .{});
    defer db.close();
    var bs = @import("block_store").BlockStore(server_mod.OpBackendType).init(&db);
    server.block_store = &bs;

    var sm = session_map_mod.SessionMap.init(allocator, false, 0);
    defer sm.deinit();
    server.session_map = &sm;

    // Sender alice, bound and live.
    var alice_fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &alice_fds));
    defer posix.close(alice_fds[1]);
    const alice = try allocator.create(Session);
    alice.* = Session.init(alice_fds[0], 1, server.server_host, false, allocator);
    server.sessions[1] = alice;
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/res") catch null;

    // Two recipients with 300-byte bare JIDs (290-byte localpart).
    var rbuf: [290]u8 = undefined;
    @memset(&rbuf, 'r');
    const recip_local = rbuf[0..];
    var bare_buf1: [512]u8 = undefined;
    const blocked_bare = std.fmt.bufPrint(&bare_buf1, "{s}@localhost", .{recip_local}) catch unreachable;
    var jid_buf1: [600]u8 = undefined;
    const blocked_full = std.fmt.bufPrint(&jid_buf1, "{s}/one", .{blocked_bare}) catch unreachable;

    var ubuf: [290]u8 = undefined;
    @memset(&ubuf, 'u');
    const open_local = ubuf[0..];
    var jid_buf2: [600]u8 = undefined;
    const open_full = std.fmt.bufPrint(&jid_buf2, "{s}@localhost/two", .{open_local}) catch unreachable;

    var b_fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &b_fds));
    defer posix.close(b_fds[1]);
    const bsess = try allocator.create(Session);
    bsess.* = Session.init(b_fds[0], 2, server.server_host, false, allocator);
    server.sessions[2] = bsess;
    _ = try sm.bind(0, 2, recip_local, "localhost", "one");

    var o_fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &o_fds));
    defer posix.close(o_fds[1]);
    const osess = try allocator.create(Session);
    osess.* = Session.init(o_fds[0], 3, server.server_host, false, allocator);
    server.sessions[3] = osess;
    _ = try sm.bind(0, 3, open_local, "localhost", "two");

    // The 300-byte recipient blocks alice; a truncated block key would miss.
    try bs.block(blocked_bare, "alice@localhost");

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    alice.stanza_kind = .message;
    alice.stanza_to = blocked_full;
    alice.stanza_id = "m1";
    alice.stanza_type = "chat";
    router.dispatchStanza(&server, alice, &changes);

    _ = try bsess.conn.flushSend();
    var drain: [4096]u8 = undefined;
    const n_blocked = posix.read(b_fds[1], &drain) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n_blocked);

    // Control: the unblocked 300-byte recipient still receives the stanza.
    alice.stanza_kind = .message;
    alice.stanza_to = open_full;
    alice.stanza_id = "m2";
    alice.stanza_type = "chat";
    router.dispatchStanza(&server, alice, &changes);

    _ = try osess.conn.flushSend();
    const n_open = posix.read(o_fds[1], &drain) catch 0;
    try std.testing.expect(n_open > 0);
    try std.testing.expect(std.mem.indexOf(u8, drain[0..n_open], "from='alice@localhost/res'") != null);
}
