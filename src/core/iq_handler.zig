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
const muc_handler = @import("muc_handler.zig");

const log = std.log.scoped(.xmppd);

// Types from server.zig — imported via the parent module's compilation unit.
const server_mod = @import("server.zig");
const Session = server_mod.Session;
const Server = server_mod.Server;
const MamCollecting = server_mod.MamCollecting;
const generic_roster = @import("roster_store");
const GenericRosterStore = generic_roster.RosterStore(server_mod.OpBackendType);
const ChangeList = @import("event_loop.zig").ChangeList;
const session_map_mod = @import("session_map");
const SessionEntry = session_map_mod.SessionEntry;

/// RSM namespace URI.
const ns_rsm = "http://jabber.org/protocol/rsm";
/// jabber:x:data namespace URI.
const ns_xdata = "jabber:x:data";

/// Start IQ accumulation — called from handleElementStart when an <iq> is seen.
pub fn handleIq(session: *Session, elem: xml.Element) void {
    session.iq_active = true;
    session.iq_child_ns = "";
    session.iq_child_name = "";
    session.iq_to = "";
    session.iq_roster_item_jid = "";
    session.iq_roster_item_name = "";
    session.iq_roster_item_sub = "";

    for (elem.attributes) |attr| {
        if (std.mem.eql(u8, attr.local_name, "type")) session.iq_type = attr.value;
        if (std.mem.eql(u8, attr.local_name, "id")) session.iq_id = attr.value;
        if (std.mem.eql(u8, attr.local_name, "to")) session.iq_to = attr.value;
    }
}

/// Handle child elements inside an IQ stanza (query, item, etc.)
pub fn handleIqChild(session: *Session, elem: xml.Element) void {
    const ns = elem.namespace_uri;

    if (std.mem.eql(u8, elem.local_name, "query") or
        std.mem.eql(u8, elem.local_name, "enable") or
        std.mem.eql(u8, elem.local_name, "disable") or
        std.mem.eql(u8, elem.local_name, "blocklist") or
        std.mem.eql(u8, elem.local_name, "block") or
        std.mem.eql(u8, elem.local_name, "unblock"))
    {
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
    } else if (std.mem.eql(u8, elem.local_name, "pubsub") and std.mem.eql(u8, ns, xml.ns.pubsub)) {
        session.iq_child_ns = ns;
        session.iq_child_name = elem.local_name;
    } else if (std.mem.eql(u8, elem.local_name, "publish") and std.mem.eql(u8, ns, xml.ns.pubsub)) {
        // <publish node='...'> inside <pubsub>
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "node")) {
                session.iq_to = attr.value; // reuse iq_to for node name
                break;
            }
        }
    } else if (std.mem.eql(u8, elem.local_name, "items") and std.mem.eql(u8, ns, xml.ns.pubsub)) {
        // <items node='...'> inside <pubsub>
        session.iq_child_name = elem.local_name;
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "node")) {
                session.iq_to = attr.value; // reuse iq_to for node name
                break;
            }
        }
    } else if (std.mem.eql(u8, elem.local_name, "item") and std.mem.eql(u8, ns, xml.ns.pubsub)) {
        // <item id='...'> inside <publish> or <items>
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "id")) {
                session.iq_roster_item_jid = attr.value; // reuse for item id
                break;
            }
        }
        // Start collecting the item payload XML
        session.vcard_collecting = true; // reuse vcard buf for PEP payload
        session.vcard_buf_len = 0;
    } else if (std.mem.eql(u8, elem.local_name, "item") and std.mem.eql(u8, ns, xml.ns.blocking)) {
        // Block/unblock item: <item jid='...'> inside <block>/<unblock>
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "jid")) {
                session.iq_roster_item_jid = attr.value;
                break;
            }
        }
    } else if (std.mem.eql(u8, elem.local_name, "item") and std.mem.eql(u8, ns, xml.ns.roster)) {
        // Roster item inside <query xmlns='jabber:iq:roster'>
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "jid")) session.iq_roster_item_jid = attr.value;
            if (std.mem.eql(u8, attr.local_name, "name")) session.iq_roster_item_name = attr.value;
            if (std.mem.eql(u8, attr.local_name, "subscription")) session.iq_roster_item_sub = attr.value;
        }
    } else if (std.mem.eql(u8, elem.local_name, "item") and std.mem.eql(u8, ns, xml.ns.muc_admin)) {
        // MUC admin item: reuse roster item fields (nick→jid, role→sub)
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "nick")) session.iq_roster_item_jid = attr.value;
            if (std.mem.eql(u8, attr.local_name, "role")) session.iq_roster_item_sub = attr.value;
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
    } else if (std.mem.eql(u8, elem.local_name, "username") and
        std.mem.eql(u8, session.iq_child_ns, xml.ns.register))
    {
        // <username> inside <query xmlns='jabber:iq:register'> — collect text
        session.reg_collecting_username = true;
        session.reg_username_len = 0;
    } else if (std.mem.eql(u8, elem.local_name, "password") and
        std.mem.eql(u8, session.iq_child_ns, xml.ns.register))
    {
        // <password> inside <query xmlns='jabber:iq:register'> — collect text
        session.reg_collecting_password = true;
        session.reg_password_len = 0;
    } else if (std.mem.eql(u8, elem.local_name, "remove") and
        std.mem.eql(u8, session.iq_child_ns, xml.ns.register))
    {
        // <remove/> inside <query xmlns='jabber:iq:register'> — account deletion
        session.reg_has_remove = true;
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
        session.iq_to = "";
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
        // Reset registration accumulation
        session.reg_collecting_username = false;
        session.reg_username_len = 0;
        session.reg_collecting_password = false;
        session.reg_password_len = 0;
        session.reg_has_remove = false;
    }

    const iq_type = session.iq_type;
    const iq_id = session.iq_id;
    const iq_to = session.iq_to;
    const child_ns = session.iq_child_ns;

    // IQ addressed to MUC service domain — handle MUC disco and admin commands
    if (server.muc_host) |muc_host| {
        if (iq_to.len > 0) {
            // Check if 'to' matches the MUC service domain (bare or with localpart)
            const xmpp = @import("xmpp");
            const to_jid = xmpp.Jid.parse(iq_to) catch {
                sendIqError(server, session, iq_id, "jid-malformed");
                return;
            };
            if (std.mem.eql(u8, to_jid.domain, muc_host)) {
                if (to_jid.local.len == 0) {
                    // Bare MUC service JID: disco#info or disco#items for the service
                    if (std.mem.eql(u8, child_ns, xml.ns.disco_info) and std.mem.eql(u8, iq_type, "get")) {
                        muc_handler.handleMucDiscoInfo(server, session, iq_id, changes);
                        return;
                    }
                    if (std.mem.eql(u8, child_ns, xml.ns.disco_items) and std.mem.eql(u8, iq_type, "get")) {
                        muc_handler.handleMucDiscoItems(server, session, iq_id, changes);
                        return;
                    }
                } else {
                    // IQ to a specific room: admin commands (kick/ban)
                    if (std.mem.eql(u8, child_ns, xml.ns.muc_admin) and std.mem.eql(u8, iq_type, "set")) {
                        muc_handler.handleMucAdminIq(server, session, to_jid.local, iq_id, changes);
                        return;
                    }
                    // disco#info for a specific room
                    if (std.mem.eql(u8, child_ns, xml.ns.disco_info) and std.mem.eql(u8, iq_type, "get")) {
                        muc_handler.handleRoomDiscoInfo(server, session, to_jid.local, iq_id, changes);
                        return;
                    }
                    // MAM query for a room (XEP-0313 + XEP-0045 §T83)
                    if (std.mem.eql(u8, child_ns, xml.ns.mam) and std.mem.eql(u8, iq_type, "set")) {
                        handleMucMamQuery(server, session, to_jid.local, muc_host, iq_id, changes);
                        return;
                    }
                }
                // Unknown IQ to MUC domain
                sendIqError(server, session, iq_id, "service-unavailable");
                return;
            }
        }
    }

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
        w.writeAll("<feature var='urn:xmpp:sid:0'/>") catch return;
        w.writeAll("<feature var='urn:xmpp:carbons:2'/>") catch return;
        w.writeAll("<feature var='http://jabber.org/protocol/chatstates'/>") catch return;
        w.writeAll("<feature var='urn:xmpp:receipts'/>") catch return;
        w.writeAll("<feature var='urn:xmpp:message-correct:0'/>") catch return;
        w.writeAll("<feature var='urn:xmpp:blocking'/>") catch return;
        w.writeAll("<feature var='urn:xmpp:sm:3'/>") catch return;
        w.writeAll("<feature var='http://jabber.org/protocol/pubsub#publish'/>") catch return;
        w.writeAll("<feature var='http://jabber.org/protocol/pubsub#subscribe'/>") catch return;
        w.writeAll("<feature var='http://jabber.org/protocol/pubsub#auto-subscribe'/>") catch return;
        w.writeAll("<feature var='http://jabber.org/protocol/pubsub#auto-create'/>") catch return;
        w.writeAll("<feature var='http://jabber.org/protocol/pubsub#persistent-items'/>") catch return;
        w.writeAll("<feature var='http://jabber.org/protocol/pubsub#retrieve-items'/>") catch return;
        w.writeAll("</query></iq>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
        return;
    }

    // Service Discovery — disco#items (XEP-0030)
    if (std.mem.eql(u8, child_ns, xml.ns.disco_items) and std.mem.eql(u8, iq_type, "get")) {
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        writeIqHeader(server, w, session, "result", iq_id);
        w.writeAll("><query xmlns='http://jabber.org/protocol/disco#items'>") catch return;
        // Advertise MUC service if configured
        if (server.muc_host) |muc_host| {
            w.writeAll("<item jid='") catch return;
            w.writeAll(muc_host) catch return;
            w.writeAll("' name='Chat Rooms'/>") catch return;
        }
        w.writeAll("</query></iq>") catch return;
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

    // XEP-0280: Message Carbons (enable/disable)
    if (std.mem.eql(u8, child_ns, xml.ns.carbons) and std.mem.eql(u8, iq_type, "set")) {
        const child_name = session.iq_child_name;
        if (std.mem.eql(u8, child_name, "enable")) {
            session.carbons_enabled = true;
            log.info("connection {d} carbons enabled", .{session.conn.id});
        } else if (std.mem.eql(u8, child_name, "disable")) {
            session.carbons_enabled = false;
            log.info("connection {d} carbons disabled", .{session.conn.id});
        }
        // Send empty result
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        writeIqHeader(server, w, session, "result", iq_id);
        w.writeAll("/>") catch return;
        session.conn.queueSend(fbs.getWritten()) catch return;
        return;
    }

    // MAM query (XEP-0313)
    if (std.mem.eql(u8, child_ns, xml.ns.mam) and std.mem.eql(u8, iq_type, "set")) {
        handleMamQuery(server, session, iq_id, changes);
        return;
    }

    // XEP-0163: PEP (simplified PubSub)
    if (std.mem.eql(u8, child_ns, xml.ns.pubsub)) {
        if (std.mem.eql(u8, iq_type, "set")) {
            // Publish
            handlePepPublish(server, session, iq_id, changes);
            return;
        } else if (std.mem.eql(u8, iq_type, "get") and std.mem.eql(u8, session.iq_child_name, "items")) {
            // Items retrieval
            handlePepItems(server, session, iq_id, changes);
            return;
        }
    }

    // XEP-0191: Blocking Command
    if (std.mem.eql(u8, child_ns, xml.ns.blocking)) {
        if (std.mem.eql(u8, iq_type, "get") and std.mem.eql(u8, session.iq_child_name, "blocklist")) {
            handleBlocklistGet(server, session, iq_id, changes);
            return;
        } else if (std.mem.eql(u8, iq_type, "set") and std.mem.eql(u8, session.iq_child_name, "block")) {
            handleBlock(server, session, iq_id, changes);
            return;
        } else if (std.mem.eql(u8, iq_type, "set") and std.mem.eql(u8, session.iq_child_name, "unblock")) {
            handleUnblock(server, session, iq_id, changes);
            return;
        }
    }

    // XEP-0077 — jabber:iq:register
    if (std.mem.eql(u8, child_ns, xml.ns.register)) {
        if (std.mem.eql(u8, iq_type, "get")) {
            // Registration form query (pre-auth or post-auth)
            handleRegisterGet(server, session, iq_id);
            return;
        } else if (std.mem.eql(u8, iq_type, "set")) {
            if (session.reg_has_remove) {
                // Account deletion (post-auth only)
                handleAccountDelete(server, session, iq_id, changes);
            } else if (session.stream.bound_jid != null) {
                // Authenticated — password change
                handlePasswordChange(server, session, iq_id, changes);
            } else {
                // Pre-auth — in-band registration
                handleRegisterSubmit(server, session, iq_id, changes);
            }
            return;
        }
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

    // Get all roster items via the store's domain API
    const items = roster.getAllItems(server.allocator, bare_jid) catch return;
    defer GenericRosterStore.freeAllItems(server.allocator, items);

    for (items) |item| {
        w.writeAll("<item jid='") catch return;
        w.writeAll(item.contact_jid) catch return;
        w.writeByte('\'') catch return;
        if (item.entry.name.len > 0) {
            w.writeAll(" name='") catch return;
            w.writeAll(item.entry.name) catch return;
            w.writeByte('\'') catch return;
        }
        w.writeAll(" subscription='") catch return;
        w.writeAll(item.entry.subscription.toString()) catch return;
        w.writeByte('\'') catch return;
        if (item.entry.ask) {
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

/// Handle password change (XEP-0077 §3.3). Sends PasswordChangeRequest to auth daemon.
/// Only allowed for authenticated sessions with a bound JID.
fn handlePasswordChange(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {

    // Must be authenticated
    const bound = session.stream.bound_jid orelse {
        sendIqError(server, session, iq_id, "not-authorized");
        return;
    };

    // Get the new password from accumulated text
    const new_password = session.reg_password_buf[0..session.reg_password_len];
    if (new_password.len == 0) {
        sendIqError(server, session, iq_id, "bad-request");
        return;
    }

    // Send PasswordChangeRequest via IPC to auth daemon
    if (!server.ipc.connected) {
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    }

    server.ipc.send(.{
        .password_change_request = .{
            .conn_id = @intCast(session.conn.id),
            .username = bound.local,
            .new_password = new_password,
        },
    }) catch {
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };

    // Store the IQ id so we can respond when the result arrives
    session.reg_pending_iq_id = iq_id;

    // Ensure IPC write is registered
    if (server.ipc.hasPendingSend()) {
        changes.addWrite(server.ipc.fd, server_mod.IPC_AUTH_UDATA) catch {};
    }
}

/// Handle registration form query (XEP-0077 §3.1).
/// Returns the registration form with required fields.
fn handleRegisterGet(server: *Server, session: *Session, iq_id: []const u8) void {
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    writeIqHeader(server, w, session, "result", iq_id);
    w.writeAll("><query xmlns='jabber:iq:register'>") catch return;
    w.writeAll("<instructions>Choose a username and password to register.</instructions>") catch return;
    w.writeAll("<username/>") catch return;
    w.writeAll("<password/>") catch return;
    w.writeAll("</query></iq>") catch return;
    session.conn.queueSend(fbs.getWritten()) catch return;
}

/// Handle registration submission (XEP-0077 §3.1, pre-auth).
/// Sends RegisterRequest to auth daemon via IPC.
fn handleRegisterSubmit(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
    const reg_username = session.reg_username_buf[0..session.reg_username_len];
    const reg_password = session.reg_password_buf[0..session.reg_password_len];

    if (reg_username.len == 0 or reg_password.len == 0) {
        sendIqError(server, session, iq_id, "bad-request");
        return;
    }

    if (!server.ipc.connected) {
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    }

    // TODO: extract invite code from <x xmlns='jabber:x:data'> form field
    // For now, invite code is empty (works when --no-require-invite is set)

    server.ipc.send(.{
        .register_request = .{
            .conn_id = @intCast(session.conn.id),
            .username = reg_username,
            .password = reg_password,
            .invite_code = "",
            .client_ip = session.conn.peerAddr(),
        },
    }) catch {
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };

    session.reg_pending_iq_id = iq_id;

    if (server.ipc.hasPendingSend()) {
        changes.addWrite(server.ipc.fd, server_mod.IPC_AUTH_UDATA) catch {};
    }
}

/// Handle account deletion (XEP-0077 §3.2). Sends AccountDeleteRequest to auth daemon.
/// On success, core performs cascade cleanup (roster, vcard, offline, MAM).
fn handleAccountDelete(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
    // Must be authenticated
    const bound = session.stream.bound_jid orelse {
        sendIqError(server, session, iq_id, "not-authorized");
        return;
    };

    // Send AccountDeleteRequest via IPC to auth daemon
    if (!server.ipc.connected) {
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    }

    server.ipc.send(.{
        .account_delete_request = .{
            .conn_id = @intCast(session.conn.id),
            .username = bound.local,
        },
    }) catch {
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };

    // Store the IQ id so we can respond when the result arrives
    session.reg_pending_iq_id = iq_id;

    // Ensure IPC write is registered
    if (server.ipc.hasPendingSend()) {
        changes.addWrite(server.ipc.fd, server_mod.IPC_AUTH_UDATA) catch {};
    }
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

    const ArchBackend = @import("archive_backend").Backend;
    var response = mam_handler.handleMamQuery(ArchBackend, archive, query, server.allocator) catch {
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

/// Handle MAM query for a MUC room (XEP-0313 + XEP-0045).
/// The archive owner is the room JID (room@conference.host).
fn handleMucMamQuery(server: *Server, session: *Session, room_local: []const u8, muc_host: []const u8, iq_id: []const u8, changes: *ChangeList) void {
    _ = changes;
    const archive = server.archive orelse {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    };

    // Build the room bare JID as archive owner
    var room_buf: [320]u8 = undefined;
    var room_fbs = std.io.fixedBufferStream(&room_buf);
    room_fbs.writer().writeAll(room_local) catch return;
    room_fbs.writer().writeByte('@') catch return;
    room_fbs.writer().writeAll(muc_host) catch return;
    const room_jid = room_fbs.getWritten();

    // Parse max from text (default 50)
    const max: u32 = if (session.mam_max.len > 0)
        std.fmt.parseInt(u32, session.mam_max, 10) catch 50
    else
        50;

    // Parse timestamps from ISO 8601 if provided
    const start_ts = if (session.mam_start.len > 0) parseTimestamp(session.mam_start) else null;
    const end_ts = if (session.mam_end.len > 0) parseTimestamp(session.mam_end) else null;

    const query = mam_handler.MamQuery{
        .iq_id = iq_id,
        .owner = room_jid,
        .query_id = if (session.mam_query_id.len > 0) session.mam_query_id else iq_id,
        .with = if (session.mam_with.len > 0) session.mam_with else null,
        .start = start_ts,
        .end = end_ts,
        .after_id = if (session.mam_after.len > 0) session.mam_after else null,
        .before_id = if (session.mam_before.len > 0) session.mam_before else null,
        .max = max,
    };

    const ArchBackend = @import("archive_backend").Backend;
    var response = mam_handler.handleMamQuery(ArchBackend, archive, query, server.allocator) catch {
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

/// Handle XEP-0163 PEP publish — store an item in a PEP node.
/// The node name is in iq_to (reused), item ID in iq_roster_item_jid (reused),
/// and the payload XML is in vcard_buf (reused).
fn handlePepPublish(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
    _ = changes;
    const ps = server.pep_store orelse {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    };
    const bound = session.stream.bound_jid orelse return;

    // Build bare JID
    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(bound.local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(bound.domain) catch return;
    const bare_jid = bare_fbs.getWritten();

    const node = session.iq_to;
    if (node.len == 0) {
        sendIqError(server, session, iq_id, "bad-request");
        return;
    }

    // Item ID — use provided or default to "current"
    const item_id = if (session.iq_roster_item_jid.len > 0) session.iq_roster_item_jid else "current";
    const payload = session.vcard_buf[0..session.vcard_buf_len];

    ps.publish(bare_jid, node, item_id, payload) catch {
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };

    log.info("connection {d} PEP publish node={s} item={s} ({d} bytes)", .{
        session.conn.id, node, item_id, payload.len,
    });

    // Ack with pubsub result including the item ID
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    writeIqHeader(server, w, session, "result", iq_id);
    w.writeAll("><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='") catch return;
    w.writeAll(node) catch return;
    w.writeAll("'><item id='") catch return;
    w.writeAll(item_id) catch return;
    w.writeAll("'/></publish></pubsub></iq>") catch return;
    session.conn.queueSend(fbs.getWritten()) catch return;
}

/// Handle XEP-0163 PEP items retrieval — get items from a PEP node.
fn handlePepItems(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
    _ = changes;
    const ps = server.pep_store orelse {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    };

    // PEP items can be queried for self or another user's bare JID
    // iq_to contains the node name (from <items node='...'> parsing)
    const node = session.iq_to;
    if (node.len == 0) {
        sendIqError(server, session, iq_id, "bad-request");
        return;
    }

    // The target user is the IQ 'to' attribute, or self if not specified
    const bound = session.stream.bound_jid orelse return;
    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(bound.local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(bound.domain) catch return;
    const bare_jid = bare_fbs.getWritten();

    const items = ps.getItems(server.allocator, bare_jid, node) catch {
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };
    defer {
        for (items) |item| {
            server.allocator.free(item.id);
            server.allocator.free(item.payload);
        }
        server.allocator.free(items);
    }

    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    writeIqHeader(server, w, session, "result", iq_id);
    w.writeAll("><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='") catch return;
    w.writeAll(node) catch return;
    w.writeAll("'>") catch return;
    for (items) |item| {
        w.writeAll("<item id='") catch return;
        w.writeAll(item.id) catch return;
        w.writeAll("'>") catch return;
        w.writeAll(item.payload) catch return;
        w.writeAll("</item>") catch return;
    }
    w.writeAll("</items></pubsub></iq>") catch return;
    session.conn.queueSend(fbs.getWritten()) catch return;
}

/// Handle XEP-0191 <blocklist/> get — return the user's block list.
fn handleBlocklistGet(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
    _ = changes;
    const bs = server.block_store orelse {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    };
    const bound = session.stream.bound_jid orelse return;

    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(bound.local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(bound.domain) catch return;
    const bare_jid = bare_fbs.getWritten();

    const items = bs.getBlockList(server.allocator, bare_jid) catch {
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };
    defer {
        for (items) |item| server.allocator.free(item);
        server.allocator.free(items);
    }

    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    writeIqHeader(server, w, session, "result", iq_id);
    w.writeAll("><blocklist xmlns='urn:xmpp:blocking'>") catch return;
    for (items) |jid| {
        w.writeAll("<item jid='") catch return;
        w.writeAll(jid) catch return;
        w.writeAll("'/>") catch return;
    }
    w.writeAll("</blocklist></iq>") catch return;
    session.conn.queueSend(fbs.getWritten()) catch return;
}

/// Handle XEP-0191 <block/> set — add JIDs to user's block list.
fn handleBlock(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
    const bs = server.block_store orelse {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    };
    const bound = session.stream.bound_jid orelse return;

    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(bound.local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(bound.domain) catch return;
    const bare_jid = bare_fbs.getWritten();

    const item_jid = session.iq_roster_item_jid;
    if (item_jid.len == 0) {
        sendIqError(server, session, iq_id, "bad-request");
        return;
    }

    bs.block(bare_jid, item_jid) catch {
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };

    log.info("connection {d} blocked {s}", .{ session.conn.id, item_jid });

    // Ack with empty result
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    writeIqHeader(server, w, session, "result", iq_id);
    w.writeAll("/>") catch return;
    session.conn.queueSend(fbs.getWritten()) catch return;

    // Push block list update to all resources of the blocking user (XEP-0191 §3.3)
    pushBlockPush(server, session, bound.local, bound.domain, "block", item_jid, changes);
}

/// Handle XEP-0191 <unblock/> set — remove JIDs from user's block list.
fn handleUnblock(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
    const bs = server.block_store orelse {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    };
    const bound = session.stream.bound_jid orelse return;

    var bare_buf: [256]u8 = undefined;
    var bare_fbs = std.io.fixedBufferStream(&bare_buf);
    bare_fbs.writer().writeAll(bound.local) catch return;
    bare_fbs.writer().writeByte('@') catch return;
    bare_fbs.writer().writeAll(bound.domain) catch return;
    const bare_jid = bare_fbs.getWritten();

    const item_jid = session.iq_roster_item_jid;
    if (item_jid.len == 0) {
        // Empty <unblock/> means unblock all
        bs.removeAll(server.allocator, bare_jid) catch {};
        log.info("connection {d} unblocked all", .{session.conn.id});
    } else {
        bs.unblock(bare_jid, item_jid) catch {
            sendIqError(server, session, iq_id, "internal-server-error");
            return;
        };
        log.info("connection {d} unblocked {s}", .{ session.conn.id, item_jid });
    }

    // Ack with empty result
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    writeIqHeader(server, w, session, "result", iq_id);
    w.writeAll("/>") catch return;
    session.conn.queueSend(fbs.getWritten()) catch return;

    // Push unblock update to all resources
    pushBlockPush(server, session, bound.local, bound.domain, "unblock", item_jid, changes);
}

/// Push a block/unblock notification to all of the user's connected resources.
/// Per XEP-0191 §3.3, when a block list changes, the server pushes an IQ set
/// to all resources of the user who made the change.
fn pushBlockPush(
    server: *Server,
    sender_session: *const Session,
    user_local: []const u8,
    user_domain: []const u8,
    action: []const u8,
    item_jid: []const u8,
    changes: *ChangeList,
) void {
    const sm = server.session_map orelse return;
    var entries: [16]SessionEntry = undefined;
    const count = sm.findAvailableByBareJid(user_local, user_domain, &entries);
    if (count == 0) return;

    for (entries[0..count]) |entry| {
        if (entry.worker_id == server.worker_id) {
            const target = server.sessions[entry.local_session_id] orelse continue;
            // Skip the originating session (it already got the IQ result)
            if (&target.conn == &sender_session.conn) continue;

            var push_buf: [1024]u8 = undefined;
            var pfbs = std.io.fixedBufferStream(&push_buf);
            const pw = pfbs.writer();
            pw.writeAll("<iq type='set' to='") catch continue;
            pw.writeAll(user_local) catch continue;
            pw.writeByte('@') catch continue;
            pw.writeAll(user_domain) catch continue;
            pw.writeByte('/') catch continue;
            pw.writeAll(entry.resource()) catch continue;
            pw.writeAll("'><") catch continue;
            pw.writeAll(action) catch continue;
            pw.writeAll(" xmlns='urn:xmpp:blocking'>") catch continue;
            if (item_jid.len > 0) {
                pw.writeAll("<item jid='") catch continue;
                pw.writeAll(item_jid) catch continue;
                pw.writeAll("'/>") catch continue;
            }
            pw.writeAll("</") catch continue;
            pw.writeAll(action) catch continue;
            pw.writeAll("></iq>") catch continue;

            target.conn.queueSend(pfbs.getWritten()) catch continue;
            if (target.conn.hasPendingWrite()) {
                changes.addWrite(target.conn.fd, entry.local_session_id) catch {};
            }
        }
        // Cross-thread push: deferred to post-V1 (T89 pattern)
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
