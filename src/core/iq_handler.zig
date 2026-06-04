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
const mam_handler = @import("mam_handler");

const log = std.log.scoped(.xmppd);

// Types from server.zig — imported via the parent module's compilation unit.
const server_mod = @import("server.zig");
const Session = server_mod.Session;
const Server = server_mod.Server;
const MamCollecting = server_mod.MamCollecting;
const ChangeList = @import("event_loop.zig").ChangeList;

/// RSM namespace URI.
const ns_rsm = "http://jabber.org/protocol/rsm";
/// jabber:x:data namespace URI.
const ns_xdata = "jabber:x:data";

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
        // MAM query — extract queryid attribute
        if (std.mem.eql(u8, ns, xml.ns.mam)) {
            for (elem.attributes) |attr| {
                if (std.mem.eql(u8, attr.local_name, "queryid")) {
                    session.mam_query_id = attr.value;
                    break;
                }
            }
        }
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
    } else if (std.mem.eql(u8, elem.local_name, "field") and std.mem.eql(u8, ns, ns_xdata)) {
        // <field var='with|start|end'> inside <x xmlns='jabber:x:data'>
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "var")) {
                session.mam_field_var = attr.value;
                break;
            }
        }
    } else if (std.mem.eql(u8, elem.local_name, "value") and session.mam_field_var.len > 0) {
        // <value> inside a <field> — start collecting text
        session.mam_collecting = .field_value;
        session.mam_text_len = 0;
    } else if (std.mem.eql(u8, ns, ns_rsm)) {
        // RSM elements: <max>, <after>, <before>
        if (std.mem.eql(u8, elem.local_name, "max")) {
            session.mam_collecting = .rsm_max;
            session.mam_text_len = 0;
        } else if (std.mem.eql(u8, elem.local_name, "after")) {
            session.mam_collecting = .rsm_after;
            session.mam_text_len = 0;
        } else if (std.mem.eql(u8, elem.local_name, "before")) {
            session.mam_collecting = .rsm_before;
            session.mam_text_len = 0;
        }
    } else if (std.mem.eql(u8, elem.local_name, "vCard") and std.mem.eql(u8, ns, xml.ns.vcard_temp)) {
        session.iq_child_ns = ns;
        session.iq_child_name = elem.local_name;
        // For vcard-temp SET, start accumulating the <vCard> XML into vcard_buf
        if (std.mem.eql(u8, session.iq_type, "set")) {
            session.vcard_collecting = true;
            session.vcard_buf_len = 0;
            // Write the opening <vCard xmlns='vcard-temp'> tag
            var fbs = std.io.fixedBufferStream(&session.vcard_buf);
            const w = fbs.writer();
            w.writeAll("<vCard xmlns='vcard-temp'") catch return;
            if (elem.self_closing) {
                w.writeAll("/>") catch return;
                session.vcard_collecting = false;
            } else {
                w.writeByte('>') catch return;
            }
            session.vcard_buf_len = fbs.pos;
        }
    } else if (session.iq_child_ns.len == 0) {
        // First child element determines the IQ payload namespace
        session.iq_child_ns = ns;
        session.iq_child_name = elem.local_name;
    }
}

/// Commit collected MAM text to the appropriate session field.
/// Called from handleElementEnd when a text-collecting element closes.
pub fn commitMamText(session: *Session) void {
    const text = session.mam_text_buf[0..session.mam_text_len];

    switch (session.mam_collecting) {
        .field_value => {
            // Route based on current field var
            const field_var = session.mam_field_var;
            if (std.mem.eql(u8, field_var, "with")) {
                session.mam_with = text;
            } else if (std.mem.eql(u8, field_var, "start")) {
                session.mam_start = text;
            } else if (std.mem.eql(u8, field_var, "end")) {
                session.mam_end = text;
            }
            // Reset field_var after consuming value
            session.mam_field_var = "";
        },
        .rsm_max => {
            session.mam_max = text;
        },
        .rsm_after => {
            session.mam_after = text;
        },
        .rsm_before => {
            session.mam_before = text;
        },
        .none => {},
    }

    session.mam_collecting = .none;
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
        // Reset MAM accumulation
        session.mam_query_id = "";
        session.mam_with = "";
        session.mam_start = "";
        session.mam_end = "";
        session.mam_after = "";
        session.mam_before = "";
        session.mam_max = "";
        session.mam_field_var = "";
        session.mam_collecting = .none;
        session.mam_text_len = 0;
        // Reset vCard accumulation
        session.vcard_collecting = false;
        session.vcard_buf_len = 0;
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

    // vCard-temp (XEP-0054)
    if (std.mem.eql(u8, child_ns, xml.ns.vcard_temp)) {
        if (std.mem.eql(u8, iq_type, "get")) {
            handleVcardGet(server, session, iq_id);
            return;
        } else if (std.mem.eql(u8, iq_type, "set")) {
            handleVcardSet(server, session, iq_id);
            return;
        }
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

    // Build roster response using prefix iteration
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    writeIqHeader(server, w, session, "result", iq_id);
    w.writeAll("><query xmlns='jabber:iq:roster'>") catch return;

    // Iterate all roster items for this owner via backend prefix scan
    var prefix_buf: [256]u8 = undefined;
    @memcpy(prefix_buf[0..bare_jid.len], bare_jid);
    prefix_buf[bare_jid.len] = 0;
    const prefix = prefix_buf[0 .. bare_jid.len + 1];

    var iter = roster.backend.iterator("rosters", prefix) catch return;
    defer iter.deinit();

    const generic_roster_mod = @import("roster_store");
    while (iter.next()) |entry| {
        // Key is "owner\x00contact" — extract contact after separator
        const contact_jid = entry.key[bare_jid.len + 1 ..];
        // Deserialize value to get subscription + name
        const parsed = generic_roster_mod.deserializeEntry(server.allocator, entry.value) catch continue;
        defer if (parsed.name.len > 0) server.allocator.free(parsed.name);

        w.writeAll("<item jid='") catch return;
        w.writeAll(contact_jid) catch return;
        w.writeByte('\'') catch return;
        if (parsed.name.len > 0) {
            w.writeAll(" name='") catch return;
            w.writeAll(parsed.name) catch return;
            w.writeByte('\'') catch return;
        }
        w.writeAll(" subscription='") catch return;
        w.writeAll(parsed.subscription.toString()) catch return;
        w.writeByte('\'') catch return;
        if (parsed.ask) {
            w.writeAll(" ask='subscribe'") catch return;
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
        roster.removeItem(bare_jid, item_jid) catch {};
    } else {
        // Add or update — preserve existing subscription if item exists
        const sub = if (roster.getItem(server.allocator, bare_jid, item_jid) catch null) |existing| blk: {
            defer if (existing.name.len > 0) server.allocator.free(existing.name);
            break :blk existing.subscription;
        } else Subscription.none;
        roster.setItem(bare_jid, item_jid, session.iq_roster_item_name, sub, false) catch {
            sendIqError(server, session, iq_id, "internal-server-error");
            return;
        };
    }

    // Ack with result
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    writeIqHeader(server, w, session, "result", iq_id);
    w.writeAll("/>") catch return;
    session.conn.queueSend(fbs.getWritten()) catch return;
}

/// Handle MAM query (XEP-0313). Queries the archive store and sends results.
fn handleMamQuery(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
    _ = changes;
    const archive = server.archive orelse {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    };

    const bound = session.stream.bound_jid orelse return;

    // Build bare JID for archive lookup
    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(bound.local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(bound.domain) catch return;
    const bare_jid = bare_fbs.getWritten();

    // Parse max from text (default 50)
    const max: u32 = if (session.mam_max.len > 0)
        std.fmt.parseInt(u32, session.mam_max, 10) catch 50
    else
        50;

    // Parse timestamps from ISO 8601 if provided
    const start_ts = if (session.mam_start.len > 0) parseTimestamp(session.mam_start) else null;
    const end_ts = if (session.mam_end.len > 0) parseTimestamp(session.mam_end) else null;

    // Build MamQuery from accumulated session state
    const query = mam_handler.MamQuery{
        .iq_id = iq_id,
        .owner = bare_jid,
        .query_id = if (session.mam_query_id.len > 0) session.mam_query_id else iq_id,
        .with = if (session.mam_with.len > 0) session.mam_with else null,
        .start = start_ts,
        .end = end_ts,
        .after_id = if (session.mam_after.len > 0) session.mam_after else null,
        .before_id = if (session.mam_before.len > 0) session.mam_before else null,
        .max = max,
    };

    const OpBackendType = server_mod.OpBackendType;
    var response = mam_handler.handleMamQuery(OpBackendType, archive, query, server.allocator) catch {
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };
    defer response.deinit();

    // Send each result message
    for (response.messages) |msg| {
        session.conn.queueSend(msg.xml) catch continue;
    }

    // Send the fin IQ
    session.conn.queueSend(response.fin_iq) catch return;
}

/// Parse a subset of ISO 8601 timestamps (YYYY-MM-DDThh:mm:ssZ) to unix epoch.
/// Returns null if parsing fails.
fn parseTimestamp(text: []const u8) ?u64 {
    // Minimal parser: "2023-11-14T22:13:20Z" (20 chars)
    if (text.len < 19) return null;
    const year = std.fmt.parseInt(u16, text[0..4], 10) catch return null;
    const month = std.fmt.parseInt(u8, text[5..7], 10) catch return null;
    const day = std.fmt.parseInt(u8, text[8..10], 10) catch return null;
    const hour = std.fmt.parseInt(u8, text[11..13], 10) catch return null;
    const minute = std.fmt.parseInt(u8, text[14..16], 10) catch return null;
    const second = std.fmt.parseInt(u8, text[17..19], 10) catch return null;

    if (month < 1 or month > 12) return null;
    if (day < 1 or day > 31) return null;
    if (hour > 23 or minute > 59 or second > 59) return null;

    // Days per month (non-leap)
    const days_per_month = [_]u16{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

    // Calculate days from epoch (1970-01-01)
    var days: u64 = 0;
    var y: u16 = 1970;
    while (y < year) : (y += 1) {
        days += if (isLeapYear(y)) 366 else 365;
    }
    var m: u8 = 1;
    while (m < month) : (m += 1) {
        days += days_per_month[m - 1];
        if (m == 2 and isLeapYear(year)) days += 1;
    }
    days += @as(u64, day) - 1;

    return days * 86400 + @as(u64, hour) * 3600 + @as(u64, minute) * 60 + @as(u64, second);
}

fn isLeapYear(year: u16) bool {
    return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
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

/// Handle vCard-temp GET — return stored vCard or empty fallback.
fn handleVcardGet(server: *Server, session: *Session, iq_id: []const u8) void {
    const bound = session.stream.bound_jid orelse return;

    // Build bare JID
    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(bound.local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(bound.domain) catch return;
    const bare_jid = bare_fbs.getWritten();

    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    writeIqHeader(server, w, session, "result", iq_id);

    if (server.vcard) |vcard| {
        const xml_data = vcard.get(server.allocator, bare_jid) catch null;
        if (xml_data) |data| {
            defer server.allocator.free(data);
            w.writeByte('>') catch return;
            w.writeAll(data) catch return;
            w.writeAll("</iq>") catch return;
        } else {
            w.writeAll("><vCard xmlns='vcard-temp'/></iq>") catch return;
        }
    } else {
        w.writeAll("><vCard xmlns='vcard-temp'/></iq>") catch return;
    }

    session.conn.queueSend(fbs.getWritten()) catch return;
}

/// Handle vCard-temp SET — persist accumulated vCard XML from session.vcard_buf.
fn handleVcardSet(server: *Server, session: *Session, iq_id: []const u8) void {
    const bound = session.stream.bound_jid orelse return;

    // Build bare JID
    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(bound.local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(bound.domain) catch return;
    const bare_jid = bare_fbs.getWritten();

    const vcard_xml = session.vcard_buf[0..session.vcard_buf_len];

    if (server.vcard) |vcard| {
        vcard.set(bare_jid, vcard_xml) catch {
            sendIqError(server, session, iq_id, "internal-server-error");
            return;
        };
    } else {
        // No store configured — silently accept (RFC allows no-op)
    }

    // Ack with empty result
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    writeIqHeader(server, w, session, "result", iq_id);
    w.writeAll("/>") catch return;
    session.conn.queueSend(fbs.getWritten()) catch return;
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
