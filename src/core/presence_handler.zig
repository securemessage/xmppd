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
const ChangeList = @import("event_loop.zig").ChangeList;

const session_map_mod = @import("session_map");
const SessionEntry = session_map_mod.SessionEntry;
const generic_roster = @import("roster_store");
const Subscription = generic_roster.Subscription;
const muc_handler = @import("muc_handler.zig");
const session_lifecycle = @import("session_lifecycle.zig");

const log = std.log.scoped(.presence);

/// Handle a presence stanza from a bound session.
/// Routes to MUC handler for MUC domain, or dispatches by presence type.
pub fn handlePresence(server: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
    var type_str: []const u8 = "";
    var to_str: []const u8 = "";
    for (elem.attributes) |attr| {
        if (std.mem.eql(u8, attr.local_name, "type")) type_str = attr.value;
        if (std.mem.eql(u8, attr.local_name, "to")) to_str = attr.value;
    }

    // Directed presence to MUC domain → MUC join/part
    if (to_str.len > 0) {
        if (server.muc_host) |muc_host| {
            const to_jid = xmpp.Jid.parse(to_str) catch return;
            if (std.mem.eql(u8, to_jid.domain, muc_host)) {
                muc_handler.handleMucPresence(server, session, to_jid.local, to_jid.resource, type_str, changes);
                return;
            }
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
        .subscribe => {
            handleSubscribe(server, session, elem, changes);
        },
        .subscribed => {
            handleSubscribed(server, session, elem, changes);
        },
        .unsubscribe => {
            handleUnsubscribe(server, session, elem, changes);
        },
        .unsubscribed => {
            handleUnsubscribed(server, session, elem, changes);
        },
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
        broadcastPresence(server, bound.local, bound.domain, bound.resource, changes);

        // Send presence probes to contacts we're subscribed to
        sendPresenceProbes(server, session, bound.local, bound.domain, changes);

        // Deliver any offline messages queued for this user
        session_lifecycle.deliverOfflineMessages(server, session, bound.local, bound.domain, changes);

        log.info("connection {d} now available: {s}@{s}/{s} (priority={d})", .{
            session.conn.id, bound.local, bound.domain, bound.resource, prio,
        });
    } else if (std.mem.eql(u8, type_str, "unavailable")) {
        if (server.session_map) |sm| {
            sm.setPresenceAvailable(bound.local, bound.domain, bound.resource, false);
            sm.setPriority(bound.local, bound.domain, bound.resource, -128);
        }
        broadcastUnavailable(server, bound.local, bound.domain, bound.resource, changes);
    }
}

/// Broadcast available presence to all roster subscribers.
pub fn broadcastPresence(server: *Server, local: []const u8, domain: []const u8, resource: []const u8, changes: *ChangeList) void {
    const roster = server.roster orelse return;

    // Build the from JID string
    var from_buf: [256]u8 = undefined;
    var from_fbs = std.io.fixedBufferStream(&from_buf);
    const fw = from_fbs.writer();
    fw.writeAll(local) catch return;
    fw.writeByte('@') catch return;
    fw.writeAll(domain) catch return;
    fw.writeByte('/') catch return;
    fw.writeAll(resource) catch return;
    const from_str = from_fbs.getWritten();

    // Build bare JID for roster lookup
    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(domain) catch return;
    const bare_jid = bare_fbs.getWritten();

    // Find subscribers (contacts with "from" or "both" in our roster)
    const subscriber_jids = roster.getPresenceSubscribers(server.allocator, bare_jid) catch return;
    defer {
        for (subscriber_jids) |s| server.allocator.free(s);
        server.allocator.free(subscriber_jids);
    }
    // Build presence stanza
    var pres_buf: [512]u8 = undefined;
    var pres_fbs = std.io.fixedBufferStream(&pres_buf);
    const pw = pres_fbs.writer();
    pw.writeAll("<presence from='") catch return;
    pw.writeAll(from_str) catch return;
    pw.writeAll("'/>") catch return;
    const presence_xml = pres_fbs.getWritten();

    // Deliver to each subscriber
    deliverPresenceToSubscribers(server, subscriber_jids, bare_jid, presence_xml, changes);
}

/// Broadcast unavailable presence to roster subscribers.
pub fn broadcastUnavailable(server: *Server, local: []const u8, domain: []const u8, resource: []const u8, changes: *ChangeList) void {
    const roster = server.roster orelse return;

    var from_buf: [256]u8 = undefined;
    var from_fbs = std.io.fixedBufferStream(&from_buf);
    const fw = from_fbs.writer();
    fw.writeAll(local) catch return;
    fw.writeByte('@') catch return;
    fw.writeAll(domain) catch return;
    fw.writeByte('/') catch return;
    fw.writeAll(resource) catch return;
    const from_str = from_fbs.getWritten();

    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(domain) catch return;
    const bare_jid = bare_fbs.getWritten();

    const subscriber_jids = roster.getPresenceSubscribers(server.allocator, bare_jid) catch return;
    defer {
        for (subscriber_jids) |s| server.allocator.free(s);
        server.allocator.free(subscriber_jids);
    }

    var pres_buf: [512]u8 = undefined;
    var pres_fbs = std.io.fixedBufferStream(&pres_buf);
    const pw = pres_fbs.writer();
    pw.writeAll("<presence from='") catch return;
    pw.writeAll(from_str) catch return;
    pw.writeAll("' type='unavailable'/>") catch return;
    const presence_xml = pres_fbs.getWritten();

    deliverPresenceToSubscribers(server, subscriber_jids, bare_jid, presence_xml, changes);

    log.info("{s}@{s}/{s} now unavailable", .{ local, domain, resource });
}

/// Send presence probes to contacts we're subscribed to (to get their current status).
/// For each available contact resource, sends a per-resource full-JID presence.
/// Cross-thread contacts receive delivery via MPSC queue.
pub fn sendPresenceProbes(server: *Server, session: *Session, local: []const u8, domain: []const u8, changes: *ChangeList) void {
    const roster = server.roster orelse return;
    const sm = server.session_map orelse return;

    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(domain) catch return;
    const bare_jid = bare_fbs.getWritten();

    // Get contacts whose presence we should receive (to/both)
    const contact_jids = roster.getPresenceSubscriptions(server.allocator, bare_jid) catch return;
    defer {
        for (contact_jids) |s| server.allocator.free(s);
        server.allocator.free(contact_jids);
    }

    // Build our full JID as the 'to' attribute for cross-thread deliveries
    const bound = session.stream.bound_jid orelse return;
    var to_buf: [256]u8 = undefined;
    var to_fbs = std.io.fixedBufferStream(&to_buf);
    to_fbs.writer().writeAll(bound.local) catch return;
    to_fbs.writer().writeByte('@') catch return;
    to_fbs.writer().writeAll(bound.domain) catch return;
    to_fbs.writer().writeByte('/') catch return;
    to_fbs.writer().writeAll(bound.resource) catch return;
    const to_str = to_fbs.getWritten();

    // For each subscribed contact, check if local or remote
    for (contact_jids) |contact_bare| {
        const at_pos = std.mem.indexOf(u8, contact_bare, "@") orelse continue;
        const contact_local = contact_bare[0..at_pos];
        const contact_domain = contact_bare[at_pos + 1 ..];

        // Remote domain? Send a presence probe via S2S.
        // The remote server will respond with the contact's current presence.
        if (!std.mem.eql(u8, contact_domain, server.server_host)) {
            var probe_buf: [512]u8 = undefined;
            var probe_fbs = std.io.fixedBufferStream(&probe_buf);
            const pbw = probe_fbs.writer();
            pbw.writeAll("<presence from='") catch continue;
            pbw.writeAll(bare_jid) catch continue;
            pbw.writeAll("' to='") catch continue;
            pbw.writeAll(contact_bare) catch continue;
            pbw.writeAll("' type='probe'/>") catch continue;
            server.sendPresenceViaS2s(bare_jid, contact_bare, probe_fbs.getWritten(), changes);
            continue;
        }

        // Local contact — iterate their available sessions
        var probe_entries: [16]SessionEntry = undefined;
        const target_count = sm.findAvailableByBareJid(contact_local, contact_domain, &probe_entries);

        for (probe_entries[0..target_count]) |entry| {
            // Build presence from the contact's full JID (per-resource)
            var pres_buf: [512]u8 = undefined;
            var pres_fbs = std.io.fixedBufferStream(&pres_buf);
            const ppw = pres_fbs.writer();
            ppw.writeAll("<presence from='") catch continue;
            ppw.writeAll(contact_local) catch continue;
            ppw.writeByte('@') catch continue;
            ppw.writeAll(contact_domain) catch continue;
            ppw.writeByte('/') catch continue;
            ppw.writeAll(entry.resource()) catch continue;
            ppw.writeAll("' to='") catch continue;
            ppw.writeAll(to_str) catch continue;
            ppw.writeAll("'/>") catch continue;
            const presence_xml = pres_fbs.getWritten();

            // The presence stanza is directed TO us (the session that just
            // became available). Deliver locally regardless of which worker
            // the contact is on — we already have their resource from the
            // session map; no need to ask the remote worker.
            session.conn.queueSend(presence_xml) catch continue;
            if (session.conn.hasPendingWrite()) {
                changes.addWrite(session.conn.fd, session.conn.id) catch {};
            }
        }
    }
}

// ========================================================================
// Subscription state machine (RFC 6121 Section 3)
// ========================================================================

/// Handle <presence type='subscribe' to='contact@host'/> — outbound subscription request.
fn handleSubscribe(server: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
    const roster = server.roster orelse return;
    const bound = session.stream.bound_jid orelse return;

    var to_str: []const u8 = "";
    for (elem.attributes) |attr| {
        if (std.mem.eql(u8, attr.local_name, "to")) to_str = attr.value;
    }
    if (to_str.len == 0) return;

    // Build owner bare JID
    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(bound.local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(bound.domain) catch return;
    const owner_bare = bare_fbs.getWritten();

    // Update owner's roster: set ask='subscribe'
    if (roster.getItem(server.allocator, owner_bare, to_str) catch null) |existing| {
        defer if (existing.name.len > 0) server.allocator.free(existing.name);
        roster.setItem(owner_bare, to_str, "", existing.subscription, true) catch return;
    } else {
        roster.setItem(owner_bare, to_str, "", Subscription.none, true) catch return;
    }

    // Forward subscribe to the target
    const to_jid = xmpp.Jid.parse(to_str) catch return;

    // Build presence stanza
    var sub_pres_buf: [512]u8 = undefined;
    var sub_pres_fbs = std.io.fixedBufferStream(&sub_pres_buf);
    const spw = sub_pres_fbs.writer();
    spw.writeAll("<presence from='") catch return;
    spw.writeAll(owner_bare) catch return;
    spw.writeAll("' to='") catch return;
    spw.writeAll(to_str) catch return;
    spw.writeAll("' type='subscribe'/>") catch return;
    const sub_pres_xml = sub_pres_fbs.getWritten();

    // Remote domain? Forward via S2S.
    if (!std.mem.eql(u8, to_jid.domain, server.server_host)) {
        server.forwardPresenceXmlToS2s(session, owner_bare, to_str, sub_pres_xml, changes);
    } else {
        deliverPresenceToTarget(server, to_jid.local, to_jid.domain, sub_pres_xml, changes);
    }

    log.info("{s} subscribing to {s}", .{ owner_bare, to_str });
}

/// Handle <presence type='subscribed' to='contact@host'/> — approve inbound subscription.
fn handleSubscribed(server: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
    const roster = server.roster orelse return;
    const bound = session.stream.bound_jid orelse return;

    var to_str: []const u8 = "";
    for (elem.attributes) |attr| {
        if (std.mem.eql(u8, attr.local_name, "to")) to_str = attr.value;
    }
    if (to_str.len == 0) return;

    // Build owner bare JID
    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(bound.local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(bound.domain) catch return;
    const owner_bare = bare_fbs.getWritten();

    // Update our roster: contact's subscription gains "from" direction
    if (roster.getItem(server.allocator, owner_bare, to_str) catch null) |existing| {
        defer if (existing.name.len > 0) server.allocator.free(existing.name);
        const new_sub: Subscription = switch (existing.subscription) {
            .none => .from,
            .to => .both,
            else => existing.subscription,
        };
        roster.setItem(owner_bare, to_str, "", new_sub, false) catch return;
    } else {
        roster.setItem(owner_bare, to_str, "", .from, false) catch return;
    }

    // Update contact's roster: their subscription gains "to" direction
    if (roster.getItem(server.allocator, to_str, owner_bare) catch null) |existing| {
        defer if (existing.name.len > 0) server.allocator.free(existing.name);
        const new_sub: Subscription = switch (existing.subscription) {
            .none => .to,
            .from => .both,
            else => existing.subscription,
        };
        roster.setItem(to_str, owner_bare, "", new_sub, false) catch {};
    } else {
        roster.setItem(to_str, owner_bare, "", .to, false) catch {};
    }

    // Forward subscribed to the target
    const to_jid = xmpp.Jid.parse(to_str) catch return;

    // Build presence stanza
    var sd_pres_buf: [512]u8 = undefined;
    var sd_pres_fbs = std.io.fixedBufferStream(&sd_pres_buf);
    const sdpw = sd_pres_fbs.writer();
    sdpw.writeAll("<presence from='") catch return;
    sdpw.writeAll(owner_bare) catch return;
    sdpw.writeAll("' to='") catch return;
    sdpw.writeAll(to_str) catch return;
    sdpw.writeAll("' type='subscribed'/>") catch return;
    const sd_pres_xml = sd_pres_fbs.getWritten();

    // Remote domain? Forward via S2S.
    if (!std.mem.eql(u8, to_jid.domain, server.server_host)) {
        server.forwardPresenceXmlToS2s(session, owner_bare, to_str, sd_pres_xml, changes);
    } else {
        deliverPresenceToTarget(server, to_jid.local, to_jid.domain, sd_pres_xml, changes);
    }

    // Also send our current presence to the newly subscribed contact
    const sd_sm = server.session_map orelse return;
    if (sd_sm.findByFullJid(bound.local, bound.domain, bound.resource)) |ent| {
        if (ent.presence_available) {
            broadcastPresence(server, bound.local, bound.domain, bound.resource, changes);
        }
    }

    log.info("{s} approved subscription from {s}", .{ owner_bare, to_str });
}

/// Handle <presence type='unsubscribe' to='contact@host'/> — cancel outbound subscription.
fn handleUnsubscribe(server: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
    const roster = server.roster orelse return;
    const bound = session.stream.bound_jid orelse return;

    var to_str: []const u8 = "";
    for (elem.attributes) |attr| {
        if (std.mem.eql(u8, attr.local_name, "to")) to_str = attr.value;
    }
    if (to_str.len == 0) return;

    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(bound.local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(bound.domain) catch return;
    const owner_bare = bare_fbs.getWritten();

    // Update our roster: remove "to" direction
    if (roster.getItem(server.allocator, owner_bare, to_str) catch null) |existing| {
        defer if (existing.name.len > 0) server.allocator.free(existing.name);
        const new_sub: Subscription = switch (existing.subscription) {
            .to => .none,
            .both => .from,
            else => existing.subscription,
        };
        roster.setItem(owner_bare, to_str, "", new_sub, false) catch {};
    }

    // Update contact's roster: remove "from" direction
    if (roster.getItem(server.allocator, to_str, owner_bare) catch null) |existing| {
        defer if (existing.name.len > 0) server.allocator.free(existing.name);
        const new_sub: Subscription = switch (existing.subscription) {
            .from => .none,
            .both => .to,
            else => existing.subscription,
        };
        roster.setItem(to_str, owner_bare, "", new_sub, false) catch {};
    }

    // Forward unsubscribe
    const to_jid = xmpp.Jid.parse(to_str) catch return;

    // Build presence stanza
    var unsub_pres_buf: [512]u8 = undefined;
    var unsub_pres_fbs = std.io.fixedBufferStream(&unsub_pres_buf);
    const usbw = unsub_pres_fbs.writer();
    usbw.writeAll("<presence from='") catch return;
    usbw.writeAll(owner_bare) catch return;
    usbw.writeAll("' to='") catch return;
    usbw.writeAll(to_str) catch return;
    usbw.writeAll("' type='unsubscribe'/>") catch return;
    const unsub_pres_xml = unsub_pres_fbs.getWritten();

    // Remote domain? Forward via S2S.
    if (!std.mem.eql(u8, to_jid.domain, server.server_host)) {
        server.forwardPresenceXmlToS2s(session, owner_bare, to_str, unsub_pres_xml, changes);
    } else {
        deliverPresenceToTarget(server, to_jid.local, to_jid.domain, unsub_pres_xml, changes);
    }

    log.info("{s} unsubscribing from {s}", .{ owner_bare, to_str });
}

/// Handle <presence type='unsubscribed' to='contact@host'/> — deny/revoke inbound subscription.
fn handleUnsubscribed(server: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
    const roster = server.roster orelse return;
    const bound = session.stream.bound_jid orelse return;

    var to_str: []const u8 = "";
    for (elem.attributes) |attr| {
        if (std.mem.eql(u8, attr.local_name, "to")) to_str = attr.value;
    }
    if (to_str.len == 0) return;

    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(bound.local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(bound.domain) catch return;
    const owner_bare = bare_fbs.getWritten();

    // Update our roster: remove "from" direction
    if (roster.getItem(server.allocator, owner_bare, to_str) catch null) |existing| {
        defer if (existing.name.len > 0) server.allocator.free(existing.name);
        const new_sub: Subscription = switch (existing.subscription) {
            .from => .none,
            .both => .to,
            else => existing.subscription,
        };
        roster.setItem(owner_bare, to_str, "", new_sub, existing.ask) catch {};
    }

    // Update contact's roster: remove "to" direction
    if (roster.getItem(server.allocator, to_str, owner_bare) catch null) |existing| {
        defer if (existing.name.len > 0) server.allocator.free(existing.name);
        const new_sub: Subscription = switch (existing.subscription) {
            .to => .none,
            .both => .from,
            else => existing.subscription,
        };
        roster.setItem(to_str, owner_bare, "", new_sub, false) catch {};
    }

    // Forward unsubscribed
    const to_jid = xmpp.Jid.parse(to_str) catch return;

    // Build presence stanza
    var unsd_pres_buf: [512]u8 = undefined;
    var unsd_pres_fbs = std.io.fixedBufferStream(&unsd_pres_buf);
    const usdw = unsd_pres_fbs.writer();
    usdw.writeAll("<presence from='") catch return;
    usdw.writeAll(owner_bare) catch return;
    usdw.writeAll("' to='") catch return;
    usdw.writeAll(to_str) catch return;
    usdw.writeAll("' type='unsubscribed'/>") catch return;
    const unsd_pres_xml = unsd_pres_fbs.getWritten();

    // Remote domain? Forward via S2S.
    if (!std.mem.eql(u8, to_jid.domain, server.server_host)) {
        server.forwardPresenceXmlToS2s(session, owner_bare, to_str, unsd_pres_xml, changes);
    } else {
        deliverPresenceToTarget(server, to_jid.local, to_jid.domain, unsd_pres_xml, changes);
    }

    log.info("{s} denied/revoked subscription from {s}", .{ owner_bare, to_str });
}

// ========================================================================
// Internal delivery helpers
// ========================================================================

/// Deliver a presence stanza to all available sessions of subscriber JIDs.
/// Handles local delivery + cross-thread MPSC + S2S forwarding.
fn deliverPresenceToSubscribers(
    server: *Server,
    subscriber_jids: []const []const u8,
    sender_bare: []const u8,
    presence_xml: []const u8,
    changes: *ChangeList,
) void {
    const sm = server.session_map orelse return;
    for (subscriber_jids) |sub_bare_jid| {
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

        var entries_buf: [16]SessionEntry = undefined;
        const route_count = sm.findAvailableByBareJid(sub_local, sub_domain, &entries_buf);
        for (entries_buf[0..route_count]) |entry| {
            if (entry.worker_id == server.worker_id) {
                const target_session = server.sessions[entry.local_session_id] orelse continue;
                target_session.conn.queueSend(presence_xml) catch continue;
                if (target_session.conn.hasPendingWrite()) {
                    changes.addWrite(target_session.conn.fd, entry.local_session_id) catch {};
                }
            } else {
                if (server.delivery_system) |ds| {
                    ds.deliver(entry.worker_id, entry.local_session_id, entry.generation, presence_xml) catch {};
                }
            }
        }
    }
}

/// Deliver a presence stanza to all sessions of a target bare JID (local domain).
/// Used by subscription handlers for forwarding subscribe/subscribed/etc.
fn deliverPresenceToTarget(
    server: *Server,
    target_local: []const u8,
    target_domain: []const u8,
    presence_xml: []const u8,
    changes: *ChangeList,
) void {
    const sm = server.session_map orelse return;
    var entries: [16]SessionEntry = undefined;
    const count = sm.findByBareJid(target_local, target_domain, &entries);

    for (entries[0..count]) |ent| {
        if (ent.worker_id == server.worker_id) {
            const target_session = server.sessions[ent.local_session_id] orelse continue;
            target_session.conn.queueSend(presence_xml) catch continue;
            if (target_session.conn.hasPendingWrite()) {
                changes.addWrite(target_session.conn.fd, ent.local_session_id) catch {};
            }
        } else if (server.delivery_system) |ds| {
            ds.deliver(ent.worker_id, ent.local_session_id, ent.generation, presence_xml) catch {};
        }
    }
}
