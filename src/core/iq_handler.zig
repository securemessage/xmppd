//! # IQ Stanza Handler
//!
//! Handles all IQ (Info/Query) stanza dispatch including:
//! - Roster queries (jabber:iq:roster)
//! - Service Discovery (XEP-0030: disco#info, disco#items)
//! - XMPP Ping (XEP-0199)
//! - vCard-temp (XEP-0054)
//! - Software Version (XEP-0092)
//! - Legacy session establishment
//! - MAM queries (XEP-0313: urn:xmpp:mam:2)
//!
//! Extracted from server.zig to reduce monolith size and enable
//! MAM query parsing without further bloating the main event loop.
//!
//! This file is imported directly by server.zig via @import("iq_handler.zig")
//! and shares the same named module imports (xml, xmpp, roster_store, etc.).

const std = @import("std");
const xml = @import("xml");

const log = std.log.scoped(.xmppd);

// Types from server.zig — imported via the parent module's compilation unit.
const server_mod = @import("server.zig");
const Session = server_mod.Session;
const Server = server_mod.Server;
const ChangeList = @import("event_loop.zig").ChangeList;

/// Start IQ accumulation — called from handleElementStart when an <iq> is seen.
pub fn handleIq(session: *Session, elem: xml.Element) void {
    session.iq_active = true;
    session.iq_child_ns = "";
    session.iq_child_name = "";
    session.iq_roster_item_jid = "";
    session.iq_roster_item_name = "";
    session.iq_roster_item_sub = "";

    for (elem.attributes) |attr| {
        if (std.mem.eql(u8, attr.local_name, "type")) session.iq_type = attr.value;
        if (std.mem.eql(u8, attr.local_name, "id")) session.iq_id = attr.value;
    }
}

/// Handle child elements inside an IQ stanza (query, item, etc.)
pub fn handleIqChild(session: *Session, elem: xml.Element) void {
    const ns = elem.namespace_uri;

    if (std.mem.eql(u8, elem.local_name, "query")) {
        session.iq_child_ns = ns;
        session.iq_child_name = elem.local_name;
    } else if (std.mem.eql(u8, elem.local_name, "item") and std.mem.eql(u8, ns, xml.ns.roster)) {
        // Roster item inside <query xmlns='jabber:iq:roster'>
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "jid")) session.iq_roster_item_jid = attr.value;
            if (std.mem.eql(u8, attr.local_name, "name")) session.iq_roster_item_name = attr.value;
            if (std.mem.eql(u8, attr.local_name, "subscription")) session.iq_roster_item_sub = attr.value;
        }
    } else if (std.mem.eql(u8, elem.local_name, "ping") and std.mem.eql(u8, ns, xml.ns.ping)) {
        session.iq_child_ns = ns;
        session.iq_child_name = elem.local_name;
    } else if (session.iq_child_ns.len == 0) {
        // First child element determines the IQ payload namespace
        session.iq_child_ns = ns;
        session.iq_child_name = elem.local_name;
    }
}

/// Dispatch a complete IQ stanza based on accumulated state.
pub fn dispatchIq(server: *Server, session: *Session, changes: *ChangeList) void {
    defer {
        session.iq_active = false;
        session.iq_type = "";
        session.iq_id = "";
        session.iq_child_ns = "";
        session.iq_child_name = "";
        session.iq_roster_item_jid = "";
        session.iq_roster_item_name = "";
        session.iq_roster_item_sub = "";
    }

    const iq_type = session.iq_type;
    const iq_id = session.iq_id;
    const child_ns = session.iq_child_ns;

    // Roster query
    if (std.mem.eql(u8, child_ns, xml.ns.roster)) {
        if (std.mem.eql(u8, iq_type, "get")) {
            handleRosterGet(server, session, iq_id, changes);
            return;
        } else if (std.mem.eql(u8, iq_type, "set")) {
            handleRosterSet(server, session, iq_id, changes);
            return;
        }
    }

    // Service Discovery — disco#info (XEP-0030)
    if (std.mem.eql(u8, child_ns, xml.ns.disco_info) and std.mem.eql(u8, iq_type, "get")) {
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        writeIqHeader(server, w, session, "result", iq_id);
        w.writeAll("><query xmlns='http://jabber.org/protocol/disco#info'>") catch return;
        w.writeAll("<identity category='server' type='im' name='xmppd'/>") catch return;
        w.writeAll("<feature var='http://jabber.org/protocol/disco#info'/>") catch return;
        w.writeAll("<feature var='http://jabber.org/protocol/disco#items'/>") catch return;
        w.writeAll("<feature var='urn:xmpp:ping'/>") catch return;
        w.writeAll("<feature var='jabber:iq:roster'/>") catch return;
        w.writeAll("<feature var='vcard-temp'/>") catch return;
        w.writeAll("<feature var='jabber:iq:version'/>") catch return;
        w.writeAll("<feature var='msgoffline'/>") catch return;
        w.writeAll("<feature var='urn:xmpp:mam:2'/>") catch return;
        w.writeAll("</query></iq>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
        return;
    }

    // Service Discovery — disco#items (XEP-0030)
    if (std.mem.eql(u8, child_ns, xml.ns.disco_items) and std.mem.eql(u8, iq_type, "get")) {
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        writeIqHeader(server, w, session, "result", iq_id);
        w.writeAll("><query xmlns='http://jabber.org/protocol/disco#items'/></iq>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
        return;
    }

    // XMPP Ping (XEP-0199)
    if (std.mem.eql(u8, child_ns, xml.ns.ping) and std.mem.eql(u8, iq_type, "get")) {
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        writeIqHeader(server, w, session, "result", iq_id);
        w.writeAll("/>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
        return;
    }

    // Legacy session establishment (urn:ietf:params:xml:ns:xmpp-session)
    if (std.mem.eql(u8, child_ns, xml.ns.session) or
        (std.mem.eql(u8, iq_type, "set") and child_ns.len == 0))
    {
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        writeIqHeader(server, w, session, "result", iq_id);
        w.writeAll("/>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
        return;
    }

    // vCard-temp (XEP-0054) — return empty vCard
    if (std.mem.eql(u8, child_ns, xml.ns.vcard_temp) and std.mem.eql(u8, iq_type, "get")) {
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        writeIqHeader(server, w, session, "result", iq_id);
        w.writeAll("><vCard xmlns='vcard-temp'/></iq>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
        return;
    }

    // Software Version (XEP-0092)
    if (std.mem.eql(u8, child_ns, xml.ns.version) and std.mem.eql(u8, iq_type, "get")) {
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        writeIqHeader(server, w, session, "result", iq_id);
        w.writeAll("><query xmlns='jabber:iq:version'>") catch return;
        w.writeAll("<name>xmppd</name>") catch return;
        w.writeAll("<version>0.1.0</version>") catch return;
        w.writeAll("<os>FreeBSD</os>") catch return;
        w.writeAll("</query></iq>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
        return;
    }

    // MAM query (XEP-0313)
    if (std.mem.eql(u8, child_ns, xml.ns.mam) and std.mem.eql(u8, iq_type, "set")) {
        handleMamQuery(server, session, iq_id, changes);
        return;
    }

    // Unknown IQ — return service-unavailable per RFC 6120 §8.4
    sendIqError(server, session, iq_id, "service-unavailable");
}

/// Handle IQ roster get — return the user's roster.
fn handleRosterGet(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
    _ = changes;
    const roster = server.roster orelse {
        // No roster configured — return empty roster
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        writeIqHeader(server, w, session, "result", iq_id);
        w.writeAll("><query xmlns='jabber:iq:roster'/></iq>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
        return;
    };

    const bound = session.stream.bound_jid orelse return;

    // Build bare JID for roster lookup
    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(bound.local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(bound.domain) catch return;
    const bare_jid = bare_fbs.getWritten();

    // Build roster response
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    writeIqHeader(server, w, session, "result", iq_id);
    w.writeAll("><query xmlns='jabber:iq:roster'>") catch return;

    // Add each roster item
    for (roster.items.items) |item| {
        if (!std.mem.eql(u8, item.owner, bare_jid)) continue;
        w.writeAll("<item jid='") catch return;
        w.writeAll(item.jid) catch return;
        w.writeByte('\'') catch return;
        if (item.name.len > 0) {
            w.writeAll(" name='") catch return;
            w.writeAll(item.name) catch return;
            w.writeByte('\'') catch return;
        }
        w.writeAll(" subscription='") catch return;
        w.writeAll(item.subscription.toString()) catch return;
        w.writeByte('\'') catch return;
        if (item.ask.len > 0) {
            w.writeAll(" ask='") catch return;
            w.writeAll(item.ask) catch return;
            w.writeByte('\'') catch return;
        }
        w.writeAll("/>") catch return;
    }

    w.writeAll("</query></iq>") catch return;
    session.conn.queueSend(fbs.getWritten()) catch return;
}

/// Handle IQ roster set — add/update/remove a roster item.
fn handleRosterSet(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
    _ = changes;
    const roster = server.roster orelse {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    };

    const bound = session.stream.bound_jid orelse return;
    const item_jid = session.iq_roster_item_jid;
    if (item_jid.len == 0) {
        sendIqError(server, session, iq_id, "bad-request");
        return;
    }

    // Build bare JID for roster lookup
    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(bound.local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(bound.domain) catch return;
    const bare_jid = bare_fbs.getWritten();

    const item_sub = session.iq_roster_item_sub;
    const Subscription = @import("roster_store").Subscription;

    if (std.mem.eql(u8, item_sub, "remove")) {
        // Remove roster item
        _ = roster.removeItem(bare_jid, item_jid);
        roster.save() catch {};
    } else {
        // Add or update
        const sub = if (roster.getItem(bare_jid, item_jid)) |existing|
            existing.subscription
        else
            Subscription.none;
        roster.setItem(bare_jid, item_jid, session.iq_roster_item_name, sub, "") catch {
            sendIqError(server, session, iq_id, "internal-server-error");
            return;
        };
        roster.save() catch {};
    }

    // Ack with result
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    writeIqHeader(server, w, session, "result", iq_id);
    w.writeAll("/>") catch return;
    session.conn.queueSend(fbs.getWritten()) catch return;
}

/// Handle MAM query (XEP-0313). Queries the archive store and sends results.
/// NOTE: Full MAM query parsing (with/start/end/RSM from <x>/<field>/<value>
/// child elements) requires extending handleIqChild. For now, returns an
/// empty result set with <fin complete='true'/>.
fn handleMamQuery(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
    _ = changes;
    _ = server.archive orelse {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    };

    // Send empty fin result (placeholder until query parsing is wired)
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    writeIqHeader(server, w, session, "result", iq_id);
    w.writeAll("><fin xmlns='urn:xmpp:mam:2' complete='true'><set xmlns='http://jabber.org/protocol/rsm'><count>0</count></set></fin></iq>") catch return;
    session.conn.queueSend(fbs.getWritten()) catch return;
}

/// Write IQ opening tag with type, from (server), to (client full JID), and id.
/// Per RFC 6120 §8.1.2.1, server-generated IQ results MUST include from/to.
pub fn writeIqHeader(server: *Server, w: anytype, session: *Session, iq_type: []const u8, iq_id: []const u8) void {
    w.writeAll("<iq type='") catch return;
    w.writeAll(iq_type) catch return;
    w.writeByte('\'') catch return;
    // from = server host for server-directed IQs
    w.writeAll(" from='") catch return;
    w.writeAll(server.server_host) catch return;
    w.writeByte('\'') catch return;
    // to = client's full JID
    if (session.stream.bound_jid) |bound| {
        w.writeAll(" to='") catch return;
        w.writeAll(bound.local) catch return;
        w.writeByte('@') catch return;
        w.writeAll(bound.domain) catch return;
        if (bound.resource.len > 0) {
            w.writeByte('/') catch return;
            w.writeAll(bound.resource) catch return;
        }
        w.writeByte('\'') catch return;
    }
    if (iq_id.len > 0) {
        w.writeAll(" id='") catch return;
        w.writeAll(iq_id) catch return;
        w.writeByte('\'') catch return;
    }
}

pub fn sendIqError(server: *Server, session: *Session, iq_id: []const u8, condition: []const u8) void {
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    writeIqHeader(server, w, session, "error", iq_id);
    w.writeAll("><error type='cancel'><") catch return;
    w.writeAll(condition) catch return;
    w.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>") catch return;
    session.conn.queueSend(fbs.getWritten()) catch return;
}
