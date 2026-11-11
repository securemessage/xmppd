//! # IQ Stanza Handler
//!
//! Handles all IQ (Info/Query) stanza dispatch including:
//! - Roster queries (jabber:iq:roster)
//! - Service Discovery (XEP-0030: disco#info, disco#items)
//! - XMPP Ping (XEP-0199)
//! - Last activity (XEP-0012: jabber:iq:last)
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
const build_options = @import("build_options");
const mam_handler = @import("mam_handler");
const muc_handler = @import("muc_handler.zig");
const fanout = @import("fanout.zig");
const room_registry_mod = @import("room_registry");
const actor_message = @import("message.zig");
const delivery_queue = @import("delivery_queue");

const log = std.log.scoped(.xmppd);

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

/// Record one cross-worker delivery drop on the cold path (S14).
noinline fn noteCrossWorkerDrop(comptime fmt: []const u8, args: anytype) void {
    @branchHint(.cold);
    _ = delivery_queue.cross_worker_drops.fetchAdd(1, .monotonic);
    log.warn(fmt, args);
}

/// Queue a built stanza to a session. A refused send lands on the cold
/// path: it is logged, and a full write buffer flags the session for
/// overflow teardown (R1), the same classification dispatchStanza uses.
fn queueStanzaOrDrop(session: *Session, stanza: []const u8, comptime what: []const u8) void {
    session.queueSendStanza(stanza) catch |err| {
        noteQueueDrop(session, err, what);
    };
}

/// Classify and log one refused queueSendStanza on the cold path (R5).
noinline fn noteQueueDrop(session: *Session, err: anyerror, comptime what: []const u8) void {
    @branchHint(.cold);
    if (err == error.WriteBufferFull) session.sm_overflow = true;
    log.warn("connection {d}: {s} could not be queued ({s})", .{ session.conn.id, what, @errorName(err) });
}

// Types from server.zig — imported via the parent module's compilation unit.
const server_mod = @import("server.zig");
const precis = @import("precis_username");

/// Per-thread registration preparation scratch, shared by this worker's
/// sequential registrations without allocating on each request.
threadlocal var register_precis_scratch: precis.Scratch = undefined;
const Session = server_mod.Session;
const Server = server_mod.Server;
const MamCollecting = server_mod.MamCollecting;
const generic_roster = @import("roster_store");
const GenericRosterStore = generic_roster.RosterStore(server_mod.OpBackendType);
const ChangeList = @import("event_loop.zig").ChangeList;
const session_map_mod = @import("session_map");
const SessionEntry = session_map_mod.SessionEntry;
const router = @import("router.zig");

/// RSM namespace URI.
const ns_rsm = "http://jabber.org/protocol/rsm";
/// jabber:x:data namespace URI.
const ns_xdata = "jabber:x:data";

/// Start IQ accumulation — called from handleElementStart when an <iq> is seen.
/// If the IQ is addressed to another local user (full or bare JID), switches to
/// stanza accumulation mode (stanza_kind = .iq) for forwarding via dispatchStanza.
/// Per RFC 6121 §8.5.2.1.3 and §8.5.3, the server delivers IQs to the target
/// user's resource(s) rather than handling them server-side.
pub fn handleIq(session: *Session, elem: xml.Element, server_host: []const u8) void {
    var to_str: []const u8 = "";
    var type_str: []const u8 = "";
    var id_str: []const u8 = "";

    for (elem.attributes) |attr| {
        if (std.mem.eql(u8, attr.local_name, "type")) type_str = attr.value;
        if (std.mem.eql(u8, attr.local_name, "id")) id_str = attr.value;
        if (std.mem.eql(u8, attr.local_name, "to")) to_str = attr.value;
    }

    // RFC 6121 §8.5.3: IQ addressed to another user's full JID — forward via stanza
    // accumulation pipeline instead of server-side IQ handling.
    // Bare-JID IQs to other users are handled server-side in dispatchIq (roster,
    // disco, vCard), with unknown namespaces returning service-unavailable per
    // RFC 6121 §8.5.2.1.3.
    if (to_str.len > 0) {
        const xmpp2 = @import("xmpp");
        if (xmpp2.Jid.parse(to_str)) |to_jid| {
            if (to_jid.resource.len > 0 and std.mem.eql(u8, to_jid.domain, server_host)) {
                // Check it's not our own full JID
                const is_own = if (session.stream.bound_jid) |bound|
                    std.mem.eql(u8, to_jid.local, bound.local) and
                        std.mem.eql(u8, to_jid.resource, bound.resource)
                else
                    false;
                if (!is_own) {
                    // Use stanza accumulation pipeline for forwarding
                    session.stanza_kind = .iq;
                    session.stanza_buf_len = 0;
                    session.stanza_to = to_str;
                    session.stanza_id = id_str;
                    session.stanza_type = type_str;
                    return;
                }
            }
        } else |_| {}
    }

    session.iq_active = true;
    session.iq_child_ns = "";
    session.iq_child_name = "";
    session.iq_to = to_str;
    session.iq_roster_item_jid = "";
    session.iq_roster_item_name = "";
    session.iq_roster_item_sub = "";
    session.iq_type = type_str;
    session.iq_id = id_str;
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
        // disco#info query — extract node attribute (XEP-0115 §5.3)
        if (std.mem.eql(u8, ns, xml.ns.disco_info)) {
            session.disco_node = "";
            for (elem.attributes) |attr| {
                if (std.mem.eql(u8, attr.local_name, "node")) {
                    session.disco_node = attr.value;
                    break;
                }
            }
        }
    } else if (std.mem.eql(u8, elem.local_name, "pubsub") and
        (std.mem.eql(u8, ns, xml.ns.pubsub) or std.mem.eql(u8, ns, xml.ns.pubsub_owner)))
    {
        session.iq_child_ns = ns;
        session.iq_child_name = elem.local_name;
    } else if (std.mem.eql(u8, elem.local_name, "configure") and std.mem.eql(u8, ns, xml.ns.pubsub_owner)) {
        // <configure node='...'> inside <pubsub xmlns='...#owner'>
        session.iq_child_name = elem.local_name;
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "node")) {
                session.iq_pep_node = attr.value;
                break;
            }
        }
    } else if (std.mem.eql(u8, elem.local_name, "publish") and std.mem.eql(u8, ns, xml.ns.pubsub)) {
        // <publish node='...'> inside <pubsub>
        session.iq_pubsub_verb = elem.local_name;
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "node")) {
                session.iq_pep_node = attr.value;
                break;
            }
        }
    } else if (std.mem.eql(u8, elem.local_name, "items") and std.mem.eql(u8, ns, xml.ns.pubsub)) {
        // <items node='...'> inside <pubsub>
        session.iq_child_name = elem.local_name;
        session.iq_pubsub_verb = elem.local_name;
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "node")) {
                session.iq_pep_node = attr.value;
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
        // Start collecting the item payload XML (dynamic buffer for large payloads)
        session.vcard_collecting = true;
        session.pep_collecting = true;
        session.pep_payload.clearRetainingCapacity();
        session.vcard_collect_depth = 4; // <iq><pubsub><publish><item>
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
        session.iq_roster_item_count += 1;
        // Reset per-item group tracking for this new item
        session.iq_roster_group_count = 0;
        session.iq_roster_group_hash_count = 0;
        session.iq_roster_groups_len = 0;
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "jid")) session.iq_roster_item_jid = attr.value;
            if (std.mem.eql(u8, attr.local_name, "name")) session.iq_roster_item_name = attr.value;
            if (std.mem.eql(u8, attr.local_name, "subscription")) session.iq_roster_item_sub = attr.value;
        }
    } else if (std.mem.eql(u8, elem.local_name, "group") and std.mem.eql(u8, ns, xml.ns.roster)) {
        // <group> inside a roster <item>
        session.iq_roster_group_count += 1;
        session.iq_roster_collecting_group = true;
        session.iq_roster_group_text_len = 0;
        // Self-closing <group/> is an empty group
        if (elem.self_closing) {
            session.iq_roster_collecting_group = false;
            session.iq_roster_has_empty_group = true;
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
    } else if (std.mem.eql(u8, elem.local_name, "feature") and std.mem.eql(u8, ns, xml.ns.disco_info)) {
        // XEP-0115: Accumulate +notify features from disco#info result
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "var")) {
                const caps_mod2 = @import("caps.zig");
                if (std.mem.eql(u8, attr.value, "urn:xmpp:avatar:metadata+notify")) {
                    session.caps_disco_features |= (@as(u64, 1) << @intFromEnum(caps_mod2.Feature.avatar_metadata));
                } else if (std.mem.eql(u8, attr.value, "urn:xmpp:bookmarks:1#notify")) {
                    session.caps_disco_features |= (@as(u64, 1) << @intFromEnum(caps_mod2.Feature.bookmarks));
                }
                break;
            }
        }
    } else if (std.mem.eql(u8, elem.local_name, "field") and std.mem.eql(u8, ns, ns_xdata)) {
        // <field var='with|start|end'> inside <x xmlns='jabber:x:data'>
        // XEP-0077: also track the invite/token field of a registration form
        const in_register = std.mem.eql(u8, session.iq_child_ns, xml.ns.register);
        if (in_register) session.reg_invite_field = false;
        for (elem.attributes) |attr| {
            if (std.mem.eql(u8, attr.local_name, "var")) {
                session.mam_field_var = attr.value;
                if (in_register) {
                    session.reg_invite_field = std.mem.eql(u8, attr.value, "invite") or
                        std.mem.eql(u8, attr.value, "token");
                }
                break;
            }
        }
    } else if (std.mem.eql(u8, elem.local_name, "value") and session.mam_field_var.len > 0) {
        // <value> inside a <field> — start collecting text
        session.mam_collecting = .field_value;
        session.mam_text_len = 0;
        if (session.reg_invite_field) {
            session.reg_collecting_invite = true;
            session.reg_invite_len = 0;
        }
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
            session.vcard_overflow = false;
            session.vcard_collect_depth = 2; // <iq><vCard>
            // Write the opening <vCard xmlns='vcard-temp'> tag
            var fbs = std.io.fixedBufferStream(&session.vcard_buf);
            const w = fbs.writer();
            const open_ok = stanza: {
                w.writeAll("<vCard xmlns='vcard-temp'") catch break :stanza false;
                if (elem.self_closing) {
                    w.writeAll("/>") catch break :stanza false;
                } else {
                    w.writeByte('>') catch break :stanza false;
                }
                break :stanza true;
            };
            if (!open_ok) {
                session.vcard_collecting = false;
                noteDrop("vCard open tag exceeds {d} bytes; collection skipped", .{session.vcard_buf.len});
                return;
            }
            if (elem.self_closing) session.vcard_collecting = false;
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
    } else if (std.mem.eql(u8, ns, xml.ns.pubsub) and
        std.mem.eql(u8, session.iq_child_ns, xml.ns.pubsub) and
        session.iq_pubsub_verb.len == 0)
    {
        // First child of <pubsub> in no other branch: record the set verb so
        // dispatchIq can route it instead of assuming publish.
        session.iq_pubsub_verb = elem.local_name;
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
        session.iq_pep_node = "";
        session.iq_pubsub_verb = "";
        session.iq_roster_item_jid = "";
        session.iq_roster_item_name = "";
        session.iq_roster_item_sub = "";
        session.iq_roster_item_count = 0;
        session.iq_roster_group_count = 0;
        session.iq_roster_has_empty_group = false;
        session.iq_roster_has_duplicate_group = false;
        session.iq_roster_collecting_group = false;
        session.iq_roster_group_text_len = 0;
        session.iq_roster_group_hash_count = 0;
        session.iq_roster_groups_len = 0;
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
        // Reset vCard/PEP accumulation
        session.vcard_collecting = false;
        session.vcard_buf_len = 0;
        session.vcard_overflow = false;
        session.pep_collecting = false;
        // Reset XEP-0115 caps disco accumulation
        session.disco_node = "";
        session.caps_disco_features = 0;
        // Reset registration accumulation
        session.reg_collecting_username = false;
        session.reg_username_len = 0;
        session.reg_collecting_password = false;
        session.reg_password_len = 0;
        session.reg_invite_field = false;
        session.reg_collecting_invite = false;
        session.reg_invite_len = 0;
        session.reg_has_remove = false;
    }

    const iq_type = session.iq_type;
    const iq_id = session.iq_id;
    const iq_to = session.iq_to;
    const child_ns = session.iq_child_ns;

    // XEP-0115: Handle disco#info result for our caps query.
    // When we sent a caps query (id='caps-N'), the client responds with features.
    // Insert the accumulated bitmap into the caps cache keyed by the session's ver hash.
    if (std.mem.eql(u8, iq_type, "result") and std.mem.startsWith(u8, iq_id, "caps-")) {
        if (session.caps_ver_len > 0) {
            const ver = session.caps_ver_buf[0..session.caps_ver_len];
            server.caps_cache.insert(ver, session.caps_disco_features);
            log.info("XEP-0115: cached caps for ver='{s}' features=0x{x}", .{ ver, session.caps_disco_features });
        }
        session.caps_disco_features = 0;
        return;
    }

    // IQ type='result' or 'error' for other server-initiated IQs — silently consume.
    if (std.mem.eql(u8, iq_type, "result") or std.mem.eql(u8, iq_type, "error")) {
        // Clients may send IQ results in response to roster pushes or other
        // server-initiated IQs. These are acknowledgements — nothing to do.
        return;
    }

    // RFC 6120 §7.1 (T182): an IQ received before resource binding (pre-auth
    // or pre-bind) MUST NOT be processed, but IQs MUST always be answered —
    // reply with a not-authorized stanza error; the connection stays open.
    // (Third-party-addressed pre-bind stanzas never get here — the
    // handleElementStart gates close those streams per §7.1.) XEP-0077
    // registration is the only legal pre-bind IQ namespace; <bind/> itself
    // never reaches dispatchIq.
    if (session.stream.bound_jid == null and !std.mem.eql(u8, child_ns, xml.ns.register)) {
        sendIqErrorWithType(server, session, iq_id, "auth", "not-authorized");
        return;
    }

    // IQ addressed to MUC service domain — handle MUC disco and admin commands
    if (server.muc_host) |muc_host| {
        if (iq_to.len > 0) {
            // Check if 'to' matches the MUC service domain (bare or with localpart)
            const xmpp = @import("xmpp");
            const to_jid = xmpp.Jid.parse(iq_to) catch {
                sendIqError(server, session, iq_id, "jid-malformed");
                return;
            };
            // Case-insensitive host compare; the room localpart keeps
            // its spelling.
            if (std.ascii.eqlIgnoreCase(to_jid.domain, muc_host)) {
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
                    // Room configuration (XEP-0045 §10.1 — owner only)
                    if (std.mem.eql(u8, child_ns, xml.ns.muc_owner)) {
                        if (std.mem.eql(u8, iq_type, "get")) {
                            muc_handler.handleMucOwnerGet(server, session, to_jid.local, iq_id, changes);
                            return;
                        } else if (std.mem.eql(u8, iq_type, "set")) {
                            muc_handler.handleMucOwnerSet(server, session, to_jid.local, iq_id, changes);
                            return;
                        }
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

    // IQ addressed to a local bare JID (user@domain) that is NOT the sender's own.
    // Full-JID IQs to other users are forwarded via stanza accumulation in handleIq().
    // Bare-JID IQs are handled server-side for known namespaces (disco, vCard),
    // with unknown namespaces returning service-unavailable per RFC 6121 §8.5.2.1.3.
    if (iq_to.len > 0 and std.mem.indexOfScalar(u8, iq_to, '@') != null) {
        const xmpp2 = @import("xmpp");
        const to_jid = xmpp2.Jid.parse(iq_to) catch {
            sendIqError(server, session, iq_id, "jid-malformed");
            return;
        };
        const is_own_jid = if (session.stream.bound_jid) |bound| blk: {
            break :blk std.mem.eql(u8, to_jid.local, bound.local) and
                std.mem.eql(u8, to_jid.domain, bound.domain);
        } else false;

        if (!is_own_jid) {
            if (std.mem.eql(u8, child_ns, xml.ns.disco_items) and std.mem.eql(u8, iq_type, "get")) {
                var fbs = std.io.fixedBufferStream(&session.write_scratch);
                const w = fbs.writer();
                const reply_xml = stanza: {
                    writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
                    w.writeAll("><query xmlns='http://jabber.org/protocol/disco#items'/></iq>") catch break :stanza null;
                    break :stanza fbs.getWritten();
                } orelse {
                    noteJidOverflow("disco#items reply to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
                    return;
                };
                queueStanzaOrDrop(session, reply_xml, "disco#items reply");
                return;
            }
            if (std.mem.eql(u8, child_ns, xml.ns.disco_info) and std.mem.eql(u8, iq_type, "get")) {
                var fbs = std.io.fixedBufferStream(&session.write_scratch);
                const w = fbs.writer();
                const reply_xml = stanza: {
                    writeIqHeader(server, w, session, "error", iq_id) catch break :stanza null;
                    w.writeAll("><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>") catch break :stanza null;
                    break :stanza fbs.getWritten();
                } orelse {
                    noteJidOverflow("disco#info error reply to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
                    return;
                };
                queueStanzaOrDrop(session, reply_xml, "disco#info error reply");
                return;
            }
            if (std.mem.eql(u8, child_ns, xml.ns.vcard_temp) and std.mem.eql(u8, iq_type, "get")) {
                handleVcardGetFor(server, session, iq_id, iq_to);
                return;
            }
            if (std.mem.eql(u8, child_ns, xml.ns.vcard_temp) and std.mem.eql(u8, iq_type, "set")) {
                sendIqError(server, session, iq_id, "not-allowed");
                return;
            }
            // Last Activity (XEP-0012) about another JID. Server-answered on behalf
            // of the bare JID; see handleLastActivityFor for the disclosure policy.
            if (std.mem.eql(u8, child_ns, xml.ns.last) and std.mem.eql(u8, iq_type, "get")) {
                handleLastActivityFor(server, session, iq_id, to_jid);
                return;
            }
            // RFC 6121 §2.1.5: Roster set/get to another user — forbidden.
            if (std.mem.eql(u8, child_ns, xml.ns.roster)) {
                sendIqErrorWithType(server, session, iq_id, "auth", "forbidden");
                return;
            }
            // RFC 6121 §8.5.2.1.3: Unknown IQ to another user — return service-unavailable.
            sendIqError(server, session, iq_id, "service-unavailable");
            return;
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
        // XEP-0115 §5.3: If the query includes a node attribute, check if it matches
        // our server's caps node#ver. If it does, return the same features. If not,
        // return item-not-found per XEP-0030 §3.3.
        const caps_mod = @import("caps.zig");
        const disco_node = session.disco_node;
        if (disco_node.len > 0) {
            const expected_node = caps_mod.SERVER_NODE;
            const server_ver = server.server_caps.getVer();
            // Expected format: "node#ver"
            if (disco_node.len != expected_node.len + 1 + server_ver.len or
                !std.mem.startsWith(u8, disco_node, expected_node) or
                disco_node[expected_node.len] != '#' or
                !std.mem.eql(u8, disco_node[expected_node.len + 1 ..], server_ver))
            {
                sendIqError(server, session, iq_id, "item-not-found");
                return;
            }
            // Node matches — fall through to return features with node attribute
        }
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        const reply_xml = stanza: {
            writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
            if (disco_node.len > 0) {
                w.writeAll("><query xmlns='http://jabber.org/protocol/disco#info' node='") catch break :stanza null;
                xml.escapeWrite(w, disco_node) catch break :stanza null;
                w.writeAll("'>") catch break :stanza null;
            } else {
                w.writeAll("><query xmlns='http://jabber.org/protocol/disco#info'>") catch break :stanza null;
            }
            // XEP-0163 §6.1: the service also answers as a PEP pubsub service.
            w.writeAll("<identity category='pubsub' type='pep'/>") catch break :stanza null;
            w.writeAll("<identity category='server' type='im' name='xmppd'/>") catch break :stanza null;
            caps_mod.writeDiscoFeatures(w) catch break :stanza null;
            w.writeAll("</query></iq>") catch break :stanza null;
            break :stanza fbs.getWritten();
        } orelse {
            noteJidOverflow("disco#info reply to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
            return;
        };
        queueStanzaOrDrop(session, reply_xml, "disco#info reply");
        return;
    }

    // Service Discovery — disco#items (XEP-0030)
    if (std.mem.eql(u8, child_ns, xml.ns.disco_items) and std.mem.eql(u8, iq_type, "get")) {
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        const reply_xml = stanza: {
            writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
            w.writeAll("><query xmlns='http://jabber.org/protocol/disco#items'>") catch break :stanza null;
            // Advertise MUC service if configured
            if (server.muc_host) |muc_host| {
                w.writeAll("<item jid='") catch break :stanza null;
                xml.escapeWrite(w, muc_host) catch break :stanza null;
                w.writeAll("' name='Chat Rooms'/>") catch break :stanza null;
            }
            w.writeAll("</query></iq>") catch break :stanza null;
            break :stanza fbs.getWritten();
        } orelse {
            noteJidOverflow("disco#items reply to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
            return;
        };
        queueStanzaOrDrop(session, reply_xml, "disco#items reply");
        return;
    }

    // XMPP Ping (XEP-0199)
    if (std.mem.eql(u8, child_ns, xml.ns.ping) and std.mem.eql(u8, iq_type, "get")) {
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        const reply_xml = stanza: {
            writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
            w.writeAll("/>") catch break :stanza null;
            break :stanza fbs.getWritten();
        } orelse {
            noteJidOverflow("ping result to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
            return;
        };
        queueStanzaOrDrop(session, reply_xml, "ping result");
        return;
    }

    // Legacy session establishment (urn:ietf:params:xml:ns:xmpp-session)
    if (std.mem.eql(u8, child_ns, xml.ns.session) or
        (std.mem.eql(u8, iq_type, "set") and child_ns.len == 0))
    {
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        const reply_xml = stanza: {
            writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
            w.writeAll("/>") catch break :stanza null;
            break :stanza fbs.getWritten();
        } orelse {
            noteJidOverflow("session result to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
            return;
        };
        queueStanzaOrDrop(session, reply_xml, "session result");
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
        const reply_xml = stanza: {
            writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
            w.writeAll("><query xmlns='jabber:iq:version'>") catch break :stanza null;
            w.writeAll("<name>xmppd</name>") catch break :stanza null;
            w.writeAll("<version>") catch break :stanza null;
            xml.escapeWrite(w, build_options.version) catch break :stanza null;
            w.writeAll("</version>") catch break :stanza null;
            w.writeAll("<os>FreeBSD</os>") catch break :stanza null;
            w.writeAll("</query></iq>") catch break :stanza null;
            break :stanza fbs.getWritten();
        } orelse {
            noteJidOverflow("version reply to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
            return;
        };
        queueStanzaOrDrop(session, reply_xml, "version reply");
        return;
    }

    // Last Activity (XEP-0012, T164): queries reaching the general flow are
    // server-directed (uptime) or about the querying account itself (0).
    // Other-account queries are answered in the foreign-JID branch above.
    if (std.mem.eql(u8, child_ns, xml.ns.last) and std.mem.eql(u8, iq_type, "get")) {
        handleLastActivitySelfOrServer(server, session, iq_id);
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
        const reply_xml = stanza: {
            writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
            w.writeAll("/>") catch break :stanza null;
            break :stanza fbs.getWritten();
        } orelse {
            noteJidOverflow("carbons result to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
            return;
        };
        queueStanzaOrDrop(session, reply_xml, "carbons result");
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
            if (std.mem.eql(u8, session.iq_pubsub_verb, "publish")) {
                // Publish
                handlePepPublish(server, session, iq_id, changes);
                return;
            }
            // The other pubsub set verbs name XEP-0060 features this PEP
            // subset does not implement; each answers with its feature token
            // so the sender can tell unsupported from malformed.
            if (pubsubUnsupportedFeature(session.iq_pubsub_verb)) |feature| {
                sendPubsubUnsupported(server, session, iq_id, feature);
            } else {
                sendIqError(server, session, iq_id, "bad-request");
            }
            return;
        } else if (std.mem.eql(u8, iq_type, "get") and std.mem.eql(u8, session.iq_child_name, "items")) {
            // Items retrieval
            handlePepItems(server, session, iq_id, changes);
            return;
        }
    }

    // XEP-0163/XEP-0060: PEP node configuration (pubsub#owner)
    if (std.mem.eql(u8, child_ns, xml.ns.pubsub_owner)) {
        if (std.mem.eql(u8, iq_type, "get") and std.mem.eql(u8, session.iq_child_name, "configure")) {
            handlePepNodeConfig(server, session, iq_id);
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
                handleAccountDelete(server, session, iq_id);
            } else if (session.stream.bound_jid != null) {
                // Authenticated — password change
                handlePasswordChange(server, session, iq_id);
            } else {
                // Pre-auth — in-band registration
                handleRegisterSubmit(server, session, iq_id);
            }
            return;
        }
    }

    // Unknown IQ — return service-unavailable per RFC 6120 §8.4
    sendIqError(server, session, iq_id, "service-unavailable");
}

/// Handle IQ roster get — return the user's roster.
/// Marks the session as "interested" for receiving roster pushes (RFC 6121 §2.1.6).
fn handleRosterGet(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
    _ = changes;
    session.roster_interested = true;
    const roster = server.roster orelse {
        // No roster configured — return empty roster
        var fbs = std.io.fixedBufferStream(&session.write_scratch);
        const w = fbs.writer();
        const reply_xml = stanza: {
            writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
            w.writeAll("><query xmlns='jabber:iq:roster'/></iq>") catch break :stanza null;
            break :stanza fbs.getWritten();
        } orelse {
            noteJidOverflow("roster result to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
            return;
        };
        queueStanzaOrDrop(session, reply_xml, "roster result");
        return;
    };

    const bound = session.stream.bound_jid orelse return;

    // Build bare JID for roster lookup
    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const bare_jid = router.buildBareJid(bound.local, bound.domain, &bare_buf) catch {
        noteJidOverflow("connection {d} bound bare JID exceeds {d} bytes; IQ answered with error", .{ session.conn.id, router.BARE_JID_MAX });
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };

    // Get all roster items via the store's domain API
    const items = roster.getAllItems(server.allocator, bare_jid) catch {
        noteDrop("connection {d} roster fetch failed; IQ answered with error", .{session.conn.id});
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };
    defer GenericRosterStore.freeAllItems(server.allocator, items);

    // Build roster response. A reply that cannot fit every item is not
    // sent half-written: the requester gets a resource-constraint error.
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    const reply_xml = stanza: {
        writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
        w.writeAll("><query xmlns='jabber:iq:roster'>") catch break :stanza null;

        for (items) |item| {
            w.writeAll("<item jid='") catch break :stanza null;
            xml.escapeWrite(w, item.contact_jid) catch break :stanza null;
            w.writeByte('\'') catch break :stanza null;
            if (item.entry.name.len > 0) {
                w.writeAll(" name='") catch break :stanza null;
                xml.escapeWrite(w, item.entry.name) catch break :stanza null;
                w.writeByte('\'') catch break :stanza null;
            }
            w.writeAll(" subscription='") catch break :stanza null;
            w.writeAll(item.entry.subscription.toString()) catch break :stanza null;
            w.writeByte('\'') catch break :stanza null;
            if (item.entry.ask) {
                w.writeAll(" ask='subscribe'") catch break :stanza null;
            }
            if (item.entry.group_count > 0) {
                w.writeByte('>') catch break :stanza null;
                writeGroupElements(w, item.entry.groups, item.entry.group_count) catch break :stanza null;
                w.writeAll("</item>") catch break :stanza null;
            } else {
                w.writeAll("/>") catch break :stanza null;
            }
        }

        w.writeAll("</query></iq>") catch break :stanza null;
        break :stanza fbs.getWritten();
    } orelse {
        noteJidOverflow("roster reply to connection {d} exceeds {d} bytes; answering resource-constraint", .{ session.conn.id, session.write_scratch.len });
        sendIqError(server, session, iq_id, "resource-constraint");
        return;
    };
    queueStanzaOrDrop(session, reply_xml, "roster reply");
}

/// Handle IQ roster set — add/update/remove a roster item.
/// Performs validation per RFC 6121 §2.1.5 and §2.3.
fn handleRosterSet(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
    const roster = server.roster orelse {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    };

    const bound = session.stream.bound_jid orelse return;
    const iq_to = session.iq_to;

    // RFC 6121 §2.1.5: Roster set addressed to another user's bare JID is forbidden.
    if (iq_to.len > 0) {
        const xmpp2 = @import("xmpp");
        if (xmpp2.Jid.parse(iq_to)) |to_jid| {
            const is_own = std.mem.eql(u8, to_jid.local, bound.local) and
                std.mem.eql(u8, to_jid.domain, bound.domain);
            if (!is_own) {
                sendIqErrorWithType(server, session, iq_id, "auth", "forbidden");
                return;
            }
        } else |_| {
            sendIqError(server, session, iq_id, "jid-malformed");
            return;
        }
    }

    // RFC 6121 §2.1.5: Roster set MUST contain exactly one <item>.
    if (session.iq_roster_item_count != 1) {
        sendIqError(server, session, iq_id, "bad-request");
        return;
    }

    const item_jid_raw = session.iq_roster_item_jid;
    if (item_jid_raw.len == 0) {
        sendIqError(server, session, iq_id, "bad-request");
        return;
    }

    // Validate group elements: reject empty groups and duplicate group names.
    if (session.iq_roster_has_empty_group) {
        sendIqError(server, session, iq_id, "not-acceptable");
        return;
    }
    if (session.iq_roster_has_duplicate_group) {
        sendIqError(server, session, iq_id, "bad-request");
        return;
    }

    // F6: fold a local contact JID once so every key and push below uses the
    // configured spelling; remote-domain JIDs pass through unchanged.
    const item_jid = @import("xmpp").prepareLocalDomainJid(item_jid_raw, server.server_host, &session.iq_jid_prep_buf) catch {
        sendIqError(server, session, iq_id, "jid-malformed");
        return;
    };

    // Build bare JID for roster lookup
    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const bare_jid = router.buildBareJid(bound.local, bound.domain, &bare_buf) catch {
        noteJidOverflow("connection {d} bound bare JID exceeds {d} bytes; IQ answered with error", .{ session.conn.id, router.BARE_JID_MAX });
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };

    // S4: the store key joins owner + contact into a bounded buffer; a
    // contact JID that cannot fit must be rejected at ingress instead of
    // aborting the daemon downstream.
    if (!@import("store_keys").fits2(bare_jid, item_jid)) {
        sendIqError(server, session, iq_id, "jid-malformed");
        return;
    }

    const item_sub = session.iq_roster_item_sub;
    const Subscription = @import("roster_store").Subscription;

    var result_sub: Subscription = .none;
    var result_ask: bool = false;

    if (std.mem.eql(u8, item_sub, "remove")) {
        // RFC 6121 §2.5: Remove roster item and cancel existing subscriptions.
        const old_entry = roster.getItem(server.allocator, bare_jid, item_jid) catch null;
        defer if (old_entry) |e| {
            if (e.name.len > 0) server.allocator.free(e.name);
            if (e.groups.len > 0) server.allocator.free(e.groups);
        };

        // RFC 6121 §2.5: Removing a non-existing item is an error.
        if (old_entry == null) {
            sendIqErrorWithType(server, session, iq_id, "cancel", "item-not-found");
            return;
        }

        roster.removeItem(bare_jid, item_jid) catch |err| {
            noteDrop("roster remove '{s}' for '{s}' failed: {s}", .{ item_jid, bare_jid, @errorName(err) });
        };
        server.invalidateSubCache(bare_jid);
        result_sub = .remove;

        // Send unsubscribe/unsubscribed to contact and update contact's roster.
        if (old_entry) |entry| {
            const presence_handler = @import("presence_handler.zig");
            const to_jid_parsed = @import("xmpp").Jid.parse(item_jid) catch null;

            // If we had subscription TO the contact, send unsubscribe
            if (entry.subscription == .to or entry.subscription == .both) {
                var unsub_buf: [router.JID_STANZA_MAX]u8 = undefined;
                var unsub_fbs = std.io.fixedBufferStream(&unsub_buf);
                const uw = unsub_fbs.writer();
                const unsub_xml: ?[]const u8 = stanza: {
                    uw.writeAll("<presence from='") catch break :stanza null;
                    xml.escapeWrite(uw, bare_jid) catch break :stanza null;
                    uw.writeAll("' to='") catch break :stanza null;
                    xml.escapeWrite(uw, item_jid) catch break :stanza null;
                    uw.writeAll("' type='unsubscribe'/>") catch break :stanza null;
                    break :stanza unsub_fbs.getWritten();
                };
                if (unsub_xml) |uxml| {
                    if (to_jid_parsed) |to_jid| {
                        if (std.mem.eql(u8, to_jid.domain, server.server_host)) {
                            presence_handler.deliverPresenceToTarget(server, to_jid.local, to_jid.domain, uxml, changes);
                        } else {
                            server.sendPresenceViaS2s(bare_jid, item_jid, uxml, changes);
                        }
                    }
                } else {
                    noteJidOverflow("unsubscribe stanza to '{s}' exceeds {d} bytes; not sent", .{ item_jid, router.JID_STANZA_MAX });
                }
                // Update contact's roster: remove "to" direction (they lose "from" us)
                if (to_jid_parsed) |to_jid| {
                    if (std.mem.eql(u8, to_jid.domain, server.server_host)) {
                        if (roster.getItem(server.allocator, item_jid, bare_jid) catch null) |contact_entry| {
                            defer if (contact_entry.name.len > 0) server.allocator.free(contact_entry.name);
                            defer if (contact_entry.groups.len > 0) server.allocator.free(contact_entry.groups);
                            const new_sub: Subscription = switch (contact_entry.subscription) {
                                .from => .none,
                                .both => .to,
                                else => contact_entry.subscription,
                            };
                            roster.setItem(item_jid, bare_jid, "", new_sub, contact_entry.ask) catch |err| {
                                noteDrop("contact roster update failed for {s}: {s}", .{ item_jid, @errorName(err) });
                            };
                            server.invalidateSubCache(item_jid);
                            pushRosterItem(server, to_jid.local, to_jid.domain, bare_jid, "", new_sub, contact_entry.ask, changes);
                        }
                    }
                }
            }

            // If we had subscription FROM the contact, send unsubscribed
            if (entry.subscription == .from or entry.subscription == .both) {
                var unsd_buf: [router.JID_STANZA_MAX]u8 = undefined;
                var unsd_fbs = std.io.fixedBufferStream(&unsd_buf);
                const udw = unsd_fbs.writer();
                const unsd_xml: ?[]const u8 = stanza: {
                    udw.writeAll("<presence from='") catch break :stanza null;
                    xml.escapeWrite(udw, bare_jid) catch break :stanza null;
                    udw.writeAll("' to='") catch break :stanza null;
                    xml.escapeWrite(udw, item_jid) catch break :stanza null;
                    udw.writeAll("' type='unsubscribed'/>") catch break :stanza null;
                    break :stanza unsd_fbs.getWritten();
                };
                if (unsd_xml) |uxml| {
                    if (to_jid_parsed) |to_jid| {
                        if (std.mem.eql(u8, to_jid.domain, server.server_host)) {
                            presence_handler.deliverPresenceToTarget(server, to_jid.local, to_jid.domain, uxml, changes);
                        } else {
                            server.sendPresenceViaS2s(bare_jid, item_jid, uxml, changes);
                        }
                    }
                } else {
                    noteJidOverflow("unsubscribed stanza to '{s}' exceeds {d} bytes; not sent", .{ item_jid, router.JID_STANZA_MAX });
                }
                // Update contact's roster: remove "from" direction (they lose "to" us)
                if (to_jid_parsed) |to_jid| {
                    if (std.mem.eql(u8, to_jid.domain, server.server_host)) {
                        if (roster.getItem(server.allocator, item_jid, bare_jid) catch null) |contact_entry| {
                            defer if (contact_entry.name.len > 0) server.allocator.free(contact_entry.name);
                            defer if (contact_entry.groups.len > 0) server.allocator.free(contact_entry.groups);
                            const new_sub: Subscription = switch (contact_entry.subscription) {
                                .to => .none,
                                .both => .from,
                                else => contact_entry.subscription,
                            };
                            roster.setItem(item_jid, bare_jid, "", new_sub, false) catch |err| {
                                noteDrop("contact roster update failed for {s}: {s}", .{ item_jid, @errorName(err) });
                            };
                            server.invalidateSubCache(item_jid);
                            pushRosterItem(server, to_jid.local, to_jid.domain, bare_jid, "", new_sub, false, changes);
                        }
                    }
                }
            }
        }
    } else {
        // Add or update — preserve existing subscription if item exists
        if (roster.getItem(server.allocator, bare_jid, item_jid) catch null) |existing| {
            defer if (existing.name.len > 0) server.allocator.free(existing.name);
            defer if (existing.groups.len > 0) server.allocator.free(existing.groups);
            result_sub = existing.subscription;
            result_ask = existing.ask;
        }
        const groups_data = session.iq_roster_groups_buf[0..session.iq_roster_groups_len];
        const group_count_val = session.iq_roster_group_hash_count;
        roster.setItemWithGroups(bare_jid, item_jid, session.iq_roster_item_name, result_sub, result_ask, groups_data, group_count_val) catch {
            sendIqError(server, session, iq_id, "internal-server-error");
            return;
        };
        server.invalidateSubCache(bare_jid);
    }

    // Ack with result
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    const reply_xml = stanza: {
        writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
        w.writeAll("/>") catch break :stanza null;
        break :stanza fbs.getWritten();
    } orelse {
        noteJidOverflow("roster-set result to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
        return;
    };
    queueStanzaOrDrop(session, reply_xml, "roster-set result");

    // RFC 6121 §2.1.6: Send roster push to all interested resources.
    pushRosterItem(server, bound.local, bound.domain, item_jid, session.iq_roster_item_name, result_sub, result_ask, changes);
}

/// Stage the IQ id for a pending auth-daemon reply. The id borrows the
/// reader arena, which resets when the next stanza arrives (S11), long
/// before the reply; copy it into the session. Returns false (after
/// sending not-acceptable) when the id cannot be tracked.
fn stageRegPendingIq(server: *Server, session: *Session, iq_id: []const u8) bool {
    if (iq_id.len > session.reg_pending_iq_buf.len) {
        sendIqError(server, session, iq_id, "not-acceptable");
        return false;
    }
    @memcpy(session.reg_pending_iq_buf[0..iq_id.len], iq_id);
    session.reg_pending_iq_len = iq_id.len;
    session.reg_pending_iq_id = session.reg_pending_iq_buf[0..iq_id.len];
    return true;
}

/// Handle password change (XEP-0077 §3.3). Sends PasswordChangeRequest to auth daemon.
/// Only allowed for authenticated sessions with a bound JID.
fn handlePasswordChange(server: *Server, session: *Session, iq_id: []const u8) void {

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

    if (!stageRegPendingIq(server, session, iq_id)) return;

    server.ipc.send(.{
        .password_change_request = .{
            .conn_id = session.ipcConnId(),
            .username = bound.local,
            .new_password = new_password,
        },
    }) catch {
        session.reg_pending_iq_id = "";
        session.reg_pending_iq_len = 0;
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };
}

/// Handle registration form query (XEP-0077 §3.1).
/// Returns the registration form with required fields.
fn handleRegisterGet(server: *Server, session: *Session, iq_id: []const u8) void {
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    const reply_xml = stanza: {
        writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
        w.writeAll("><query xmlns='jabber:iq:register'>") catch break :stanza null;
        w.writeAll("<instructions>Choose a username and password to register.</instructions>") catch break :stanza null;
        w.writeAll("<username/>") catch break :stanza null;
        w.writeAll("<password/>") catch break :stanza null;
        // XEP-0004 data form mirroring the legacy fields, plus the optional
        // invite field (T165) — marked optional because whether an invite is
        // required is the auth daemon's configuration, unknown to core.
        w.writeAll("<x xmlns='jabber:x:data' type='form'>") catch break :stanza null;
        w.writeAll("<instructions>Choose a username and password to register.</instructions>") catch break :stanza null;
        w.writeAll("<field var='username' type='text-single' label='Username'><required/></field>") catch break :stanza null;
        w.writeAll("<field var='password' type='text-private' label='Password'><required/></field>") catch break :stanza null;
        w.writeAll("<field var='invite' type='text-single' label='Invite code (if required)'/>") catch break :stanza null;
        w.writeAll("</x>") catch break :stanza null;
        w.writeAll("</query></iq>") catch break :stanza null;
        break :stanza fbs.getWritten();
    } orelse {
        noteJidOverflow("register form reply to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
        return;
    };
    queueStanzaOrDrop(session, reply_xml, "register form reply");
}

/// Handle registration submission (XEP-0077 §3.1, pre-auth).
/// Sends RegisterRequest to auth daemon via IPC.
fn handleRegisterSubmit(server: *Server, session: *Session, iq_id: []const u8) void {
    const reg_username = session.reg_username_buf[0..session.reg_username_len];
    const reg_password = session.reg_password_buf[0..session.reg_password_len];

    if (reg_username.len == 0 or reg_password.len == 0) {
        sendIqError(server, session, iq_id, "bad-request");
        return;
    }

    // RFC 7622 Section 3.3 localparts are stored and compared in canonical
    // form only, so the auth daemon is asked about the prepared name.
    const canon_username = register_precis_scratch.localpart(reg_username) catch {
        sendIqError(server, session, iq_id, "not-acceptable");
        return;
    };

    if (!server.ipc.connected) {
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    }

    // Invite code from the <x xmlns='jabber:x:data'> invite/token field (T165).
    // Empty when the client did not supply one — the auth daemon decides
    // whether an invite is required.
    const reg_invite = session.reg_invite_buf[0..session.reg_invite_len];

    if (!stageRegPendingIq(server, session, iq_id)) return;

    server.ipc.send(.{
        .register_request = .{
            .conn_id = session.ipcConnId(),
            .username = canon_username,
            .password = reg_password,
            .invite_code = reg_invite,
            .client_ip = session.conn.peerAddr(),
        },
    }) catch {
        session.reg_pending_iq_id = "";
        session.reg_pending_iq_len = 0;
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };
}

/// Handle account deletion (XEP-0077 §3.2). Sends AccountDeleteRequest to auth daemon.
/// On success, core performs cascade cleanup (roster, vcard, offline, MAM).
fn handleAccountDelete(server: *Server, session: *Session, iq_id: []const u8) void {
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

    if (!stageRegPendingIq(server, session, iq_id)) return;

    server.ipc.send(.{
        .account_delete_request = .{
            .conn_id = session.ipcConnId(),
            .username = bound.local,
        },
    }) catch {
        session.reg_pending_iq_id = "";
        session.reg_pending_iq_len = 0;
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };
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
    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const bare_jid = router.buildBareJid(bound.local, bound.domain, &bare_buf) catch {
        noteJidOverflow("connection {d} bound bare JID exceeds {d} bytes; IQ answered with error", .{ session.conn.id, router.BARE_JID_MAX });
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };

    // Parse max from text (default 50)
    const max: u32 = if (session.mam_max.len > 0)
        std.fmt.parseInt(u32, session.mam_max, 10) catch 50
    else
        50;

    // Parse timestamps from ISO 8601 if provided
    const start_ts = if (session.mam_start.len > 0) parseTimestamp(session.mam_start) else null;
    const end_ts = if (session.mam_end.len > 0) parseTimestamp(session.mam_end) else null;

    // F6: fold a local 'with' JID once so the by_contact index key matches
    // the spelling messages were archived under; remote JIDs pass through.
    var with_prepared: ?[]const u8 = null;
    if (session.mam_with.len > 0) {
        with_prepared = @import("xmpp").prepareLocalDomainJid(session.mam_with, server.server_host, &session.iq_jid_prep_buf) catch {
            sendIqError(server, session, iq_id, "jid-malformed");
            return;
        };
    }

    // Build MamQuery from accumulated session state
    const query = mam_handler.MamQuery{
        .iq_id = iq_id,
        .owner = bare_jid,
        .query_id = if (session.mam_query_id.len > 0) session.mam_query_id else iq_id,
        .with = with_prepared,
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
        queueStanzaOrDrop(session, msg.xml, "MAM result message");
    }

    // Send the fin IQ
    queueStanzaOrDrop(session, response.fin_iq, "MAM fin iq");
}

/// Handle MAM query for a MUC room (XEP-0313 + XEP-0045).
/// The archive owner is the room JID (room@conference.host).
fn handleMucMamQuery(server: *Server, session: *Session, room_local: []const u8, muc_host: []const u8, iq_id: []const u8, changes: *ChangeList) void {
    _ = changes;

    // Build the room bare JID as archive owner
    var room_buf: [320]u8 = undefined;
    var room_fbs = std.io.fixedBufferStream(&room_buf);
    const room_jid = jid: {
        room_fbs.writer().writeAll(room_local) catch break :jid null;
        room_fbs.writer().writeByte('@') catch break :jid null;
        room_fbs.writer().writeAll(muc_host) catch break :jid null;
        break :jid room_fbs.getWritten();
    } orelse {
        noteJidOverflow("room JID for MAM query from connection {d} exceeds {d} bytes; query dropped", .{ session.conn.id, room_buf.len });
        return;
    };

    // F6: fold a local 'with' JID once so the by_contact index key matches
    // the spelling messages were archived under, on this worker or the
    // owning one; remote JIDs pass through.
    var with_prepared: ?[]const u8 = null;
    if (session.mam_with.len > 0) {
        with_prepared = @import("xmpp").prepareLocalDomainJid(session.mam_with, server.server_host, &session.iq_jid_prep_buf) catch {
            sendIqError(server, session, iq_id, "jid-malformed");
            return;
        };
    }

    // Ownership routing (T112): MAM archives live on the owning worker
    const owner = room_registry_mod.roomOwner(room_jid, server.getWorkerCount());
    if (owner != server.worker_id) {
        // Route to owning worker — they have the archive data
        log.info("routing MAM query for room {s} to owning worker {d} (from {d})", .{ room_jid, owner, server.worker_id });
        const bound = session.stream.bound_jid orelse return;
        var jid_buf: [router.FULL_JID_MAX]u8 = undefined;
        const requester_jid = router.buildFullJid(bound.local, bound.domain, bound.resource, &jid_buf) catch {
            noteJidOverflow("connection {d} bound full JID exceeds {d} bytes; MAM forward skipped", .{ session.conn.id, router.FULL_JID_MAX });
            return;
        };

        // T173: capture the requester's ABA generation here, where its session
        // is live — the reply's ds.deliver() validates it.
        const reply_gen: u32 = if (server.session_map) |sm| sm.getGeneration(bound.local, bound.domain, bound.resource) orelse 0 else 0;

        server.enqueueRoomActorMessage(owner, .{ .room_mam_query = .{
            .room_jid = room_jid,
            .iq_id = iq_id,
            .query_id = if (session.mam_query_id.len > 0) session.mam_query_id else iq_id,
            .start = session.mam_start,
            .end_field = session.mam_end,
            .with = if (with_prepared) |w| w else "",
            .max = session.mam_max,
            .after_id = session.mam_after,
            .before_id = session.mam_before,
            .reply_to_worker = server.worker_id,
            .reply_to_session = @intCast(session.conn.id),
            .reply_to_generation = reply_gen,
            .reply_to_jid = requester_jid,
        } });
        return;
    }

    const archive = server.archive orelse {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    };

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
        .with = with_prepared,
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
        queueStanzaOrDrop(session, msg.xml, "MAM room result message");
    }

    // Send the fin IQ
    queueStanzaOrDrop(session, response.fin_iq, "MAM room fin iq");
}

/// Parse a subset of ISO 8601 timestamps (YYYY-MM-DDThh:mm:ssZ) to unix epoch.
/// Returns null if parsing fails.
pub fn parseTimestamp(text: []const u8) ?u64 {
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

// ============================================================================
// XEP-0012 Last Activity (T164)
// ============================================================================

/// Emit a successful jabber:iq:last result IQ.
fn sendLastActivityResult(server: *Server, session: *Session, iq_id: []const u8, seconds: u64) void {
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    const reply_xml = stanza: {
        writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
        w.writeAll("><query xmlns='jabber:iq:last' seconds='") catch break :stanza null;
        w.print("{d}", .{seconds}) catch break :stanza null;
        w.writeAll("'/></iq>") catch break :stanza null;
        break :stanza fbs.getWritten();
    } orelse {
        noteJidOverflow("last-activity result to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
        return;
    };
    queueStanzaOrDrop(session, reply_xml, "last-activity result");
}

/// Server-directed queries (uptime, XEP-0012 §2.2) and self queries (the
/// querying account is online by definition => 0). Queries about other
/// accounts never reach here — dispatchIq's foreign-JID branch handles them.
fn handleLastActivitySelfOrServer(server: *Server, session: *Session, iq_id: []const u8) void {
    const iq_to = session.iq_to;
    if (iq_to.len == 0 or std.ascii.eqlIgnoreCase(iq_to, server.server_host)) {
        const start = if (server.start_time > 0) server.start_time else std.time.timestamp();
        const uptime: u64 = @intCast(@max(std.time.timestamp() - start, 0));
        sendLastActivityResult(server, session, iq_id, uptime);
        return;
    }
    if (std.mem.indexOfScalar(u8, iq_to, '@') == null) {
        // '@'-less address that is not our domain — not ours to answer.
        sendIqError(server, session, iq_id, "service-unavailable");
        return;
    }
    // '@'-bearing JIDs reaching here are the requester's own.
    sendLastActivityResult(server, session, iq_id, 0);
}

/// Query about another local account. Disclosure policy (XEP-0012 §3.7):
/// the target's roster entry for the requester must carry subscription
/// "from" or "both" — the same parties that receive the target's presence.
/// Online targets answer 0; offline targets answer seconds since the last
/// resource teardown; no record (or no store) is indistinguishable from a
/// nonexistent account per the vCard anti-harvesting precedent.
fn handleLastActivityFor(server: *Server, session: *Session, iq_id: []const u8, to_jid: @import("xmpp").Jid) void {
    const bound = session.stream.bound_jid orelse return;

    if (!std.ascii.eqlIgnoreCase(to_jid.domain, server.server_host)) {
        sendIqError(server, session, iq_id, "service-unavailable");
        return;
    }

    var target_buf: [router.BARE_JID_MAX]u8 = undefined;
    const target_bare = router.buildBareJid(to_jid.local, to_jid.domain, &target_buf) catch {
        noteJidOverflow("connection {d} last-activity target JID exceeds {d} bytes", .{ session.conn.id, router.BARE_JID_MAX });
        sendIqError(server, session, iq_id, "jid-malformed");
        return;
    };

    var requester_buf: [router.BARE_JID_MAX]u8 = undefined;
    const requester_bare = router.buildBareJid(bound.local, bound.domain, &requester_buf) catch {
        noteJidOverflow("connection {d} bound bare JID exceeds {d} bytes; IQ answered with error", .{ session.conn.id, router.BARE_JID_MAX });
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };

    const roster = server.roster orelse {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    };
    const allowed = roster.isSubscribedToPresence(server.allocator, target_bare, requester_bare) catch false;
    if (!allowed) {
        sendIqErrorWithType(server, session, iq_id, "auth", "forbidden");
        return;
    }

    // Online anywhere (bound — SM-detached included) => 0.
    if (server.session_map) |sm| {
        var probe: [1]SessionEntry = undefined;
        if (sm.findByBareJid(to_jid.local, to_jid.domain, &probe) > 0) {
            sendLastActivityResult(server, session, iq_id, 0);
            return;
        }
    }

    const lastact = @import("last_activity_store");
    const last = lastact.get(server.allocator, roster.backend, target_bare) catch null orelse {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    };
    const now = std.time.timestamp();
    const elapsed: u64 = @intCast(@max(now - @as(i64, @intCast(last)), 0));
    sendLastActivityResult(server, session, iq_id, elapsed);
}

/// Write IQ opening tag with type, from, to (client full JID), and id.
/// Per RFC 6120 §8.1.2.1, the 'from' in a response MUST be the JID to which
/// the original stanza was sent (i.e., the 'to' from the request).
pub fn writeIqHeader(server: *Server, w: anytype, session: *Session, iq_type: []const u8, iq_id: []const u8) !void {
    try w.writeAll("<iq type='");
    try xml.escapeWrite(w, iq_type);
    try w.writeByte('\'');
    // from = iq_to if set (echo back request's 'to'), otherwise server host
    const from = if (session.iq_to.len > 0) session.iq_to else server.server_host;
    try w.writeAll(" from='");
    try xml.escapeWrite(w, from);
    try w.writeByte('\'');
    // to = client's full JID
    if (session.stream.bound_jid) |bound| {
        try w.writeAll(" to='");
        try xml.escapeWrite(w, bound.local);
        try w.writeByte('@');
        try xml.escapeWrite(w, bound.domain);
        if (bound.resource.len > 0) {
            try w.writeByte('/');
            try xml.escapeWrite(w, bound.resource);
        }
        try w.writeByte('\'');
    }
    if (iq_id.len > 0) {
        try w.writeAll(" id='");
        try xml.escapeWrite(w, iq_id);
        try w.writeByte('\'');
    }
}

/// Handle vCard-temp GET — return stored vCard or Gravatar fallback.
/// Uses multiple queueSend calls to avoid write_scratch overflow when
/// the stored vCard XML is large (vcard_buf and write_scratch are both 4KB).
fn handleVcardGet(server: *Server, session: *Session, iq_id: []const u8) void {
    const bound = session.stream.bound_jid orelse return;

    // Build bare JID
    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const bare_jid = router.buildBareJid(bound.local, bound.domain, &bare_buf) catch {
        noteJidOverflow("connection {d} bound bare JID exceeds {d} bytes; IQ answered with error", .{ session.conn.id, router.BARE_JID_MAX });
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };

    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    writeIqHeader(server, w, session, "result", iq_id) catch {
        noteJidOverflow("vCard reply header to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
        return;
    };

    if (server.vcard) |vcard| {
        const xml_data = vcard.get(server.allocator, bare_jid) catch null;
        if (xml_data) |data| {
            defer server.allocator.free(data);
            // Assemble the complete stanza so SM tracking buffers the whole
            // thing (S15) — a split send would leave a truncated replay entry.
            var stanza: std.ArrayList(u8) = .empty;
            defer stanza.deinit(server.allocator);
            const sw = stanza.writer(server.allocator);
            const assembled = blk: {
                sw.writeAll(fbs.getWritten()) catch break :blk false;
                sw.writeByte('>') catch break :blk false;
                sw.writeAll(data) catch break :blk false;
                sw.writeAll("</iq>") catch break :blk false;
                break :blk true;
            };
            if (!assembled) {
                noteDrop("connection {d} vCard reply assembly failed; dropped", .{session.conn.id});
                return;
            }
            queueStanzaOrDrop(session, stanza.items, "vCard reply");
            return;
        }
    }

    // No stored vCard — return Gravatar fallback
    const reply_xml = stanza: {
        w.writeAll("><vCard xmlns='vcard-temp'><PHOTO><EXTVAL>https://www.gravatar.com/avatar/") catch break :stanza null;
        writeGravatarHash(w, bare_jid) catch break :stanza null;
        w.writeAll("?d=mp&amp;s=96</EXTVAL></PHOTO></vCard></iq>") catch break :stanza null;
        break :stanza fbs.getWritten();
    } orelse {
        noteJidOverflow("vCard fallback reply to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
        return;
    };
    queueStanzaOrDrop(session, reply_xml, "vCard fallback reply");
}

/// Handle vCard-temp GET for a specific bare JID (another user).
/// Per XEP-0054 §3.3: server MUST respond on behalf of the requestee.
/// Returns the stored vCard, or service-unavailable both when the user
/// has no vCard and when the user does not exist (spec v1.3.0 — the two
/// cases must be indistinguishable to prevent account harvesting).
fn handleVcardGetFor(server: *Server, session: *Session, iq_id: []const u8, target_jid: []const u8) void {
    // Strip resource if present (use bare JID for lookup)
    const at_pos = std.mem.indexOfScalar(u8, target_jid, '@') orelse {
        sendIqError(server, session, iq_id, "bad-request");
        return;
    };
    const slash_pos = std.mem.indexOfScalar(u8, target_jid[at_pos..], '/');
    const bare_end = if (slash_pos) |sp| at_pos + sp else target_jid.len;
    const bare_jid = target_jid[0..bare_end];

    // Check if target domain matches our server — we can only serve local users
    const target_domain = target_jid[at_pos + 1 .. bare_end];
    if (!std.mem.eql(u8, target_domain, server.server_host)) {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    }

    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();

    if (server.vcard) |vcard| {
        const xml_data = vcard.get(server.allocator, bare_jid) catch null;
        if (xml_data) |data| {
            defer server.allocator.free(data);
            // User has a vCard — assemble the complete stanza so SM tracking
            // buffers the whole thing (S15), then send once.
            writeIqHeader(server, w, session, "result", iq_id) catch {
                noteJidOverflow("vCard reply header to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
                return;
            };
            var stanza: std.ArrayList(u8) = .empty;
            defer stanza.deinit(server.allocator);
            const sw = stanza.writer(server.allocator);
            const assembled = blk: {
                sw.writeAll(fbs.getWritten()) catch break :blk false;
                sw.writeByte('>') catch break :blk false;
                sw.writeAll(data) catch break :blk false;
                sw.writeAll("</iq>") catch break :blk false;
                break :blk true;
            };
            if (!assembled) {
                noteDrop("connection {d} vCard reply assembly failed; dropped", .{session.conn.id});
                return;
            }
            queueStanzaOrDrop(session, stanza.items, "vCard reply");
            return;
        }
    }

    // No vCard stored — return service-unavailable whether or not the
    // user exists (XEP-0054 §3.3, v1.3.0 anti-harvesting rule).
    sendIqError(server, session, iq_id, "service-unavailable");
}

/// Handle vCard-temp SET — persist accumulated vCard XML from session.vcard_buf.
fn handleVcardSet(server: *Server, session: *Session, iq_id: []const u8) void {
    const bound = session.stream.bound_jid orelse return;
    if (session.vcard_overflow) {
        noteDrop("connection {d} vCard exceeds {d} bytes: not-acceptable", .{ session.conn.id, session.vcard_buf.len });
        sendIqErrorWithType(server, session, iq_id, "modify", "not-acceptable");
        return;
    }

    // Build bare JID
    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const bare_jid = router.buildBareJid(bound.local, bound.domain, &bare_buf) catch {
        noteJidOverflow("connection {d} bound bare JID exceeds {d} bytes; IQ answered with error", .{ session.conn.id, router.BARE_JID_MAX });
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };

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
    const reply_xml = stanza: {
        writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
        w.writeAll("/>") catch break :stanza null;
        break :stanza fbs.getWritten();
    } orelse {
        noteJidOverflow("vCard-set result to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
        return;
    };
    queueStanzaOrDrop(session, reply_xml, "vCard-set result");
}

/// Handle XEP-0163 PEP publish — store an item in a PEP node.
/// The node name is in iq_pep_node, item ID in iq_roster_item_jid (reused),
/// and the payload XML is in pep_payload (dynamic ArrayList).
fn handlePepPublish(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
    const ps = server.pep_store orelse {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    };
    const bound = session.stream.bound_jid orelse return;

    // Build bare JID
    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const bare_jid = router.buildBareJid(bound.local, bound.domain, &bare_buf) catch {
        noteJidOverflow("connection {d} bound bare JID exceeds {d} bytes; IQ answered with error", .{ session.conn.id, router.BARE_JID_MAX });
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };

    const node = session.iq_pep_node;
    if (node.len == 0) {
        sendIqError(server, session, iq_id, "bad-request");
        return;
    }

    // Item ID — use provided or default to "current"
    const item_id = if (session.iq_roster_item_jid.len > 0) session.iq_roster_item_jid else "current";
    const payload = session.pep_payload.items;

    // S4: bounded store keys; reject a node/item pair that cannot fit.
    if (!@import("store_keys").fits3(bare_jid, node, item_id)) {
        sendIqError(server, session, iq_id, "not-acceptable");
        return;
    }

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
    const reply_xml = stanza: {
        writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
        w.writeAll("><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='") catch break :stanza null;
        xml.escapeWrite(w, node) catch break :stanza null;
        w.writeAll("'><item id='") catch break :stanza null;
        xml.escapeWrite(w, item_id) catch break :stanza null;
        w.writeAll("'/></publish></pubsub></iq>") catch break :stanza null;
        break :stanza fbs.getWritten();
    } orelse {
        noteJidOverflow("PEP publish result to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
        return;
    };
    queueStanzaOrDrop(session, reply_xml, "PEP publish result");

    // XEP-0163 §4.3: Send PEP event notification to presence subscribers
    sendPepNotification(server, session, bare_jid, node, item_id, payload, changes);
}

/// Handle XEP-0060 §8.2: PEP node configuration query (pubsub#owner).
/// Returns default PEP node settings (persist_items=true, access_model=presence, max_items=1).
fn handlePepNodeConfig(server: *Server, session: *Session, iq_id: []const u8) void {
    const node = session.iq_pep_node;

    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    const reply_xml = stanza: {
        writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
        w.writeAll("><pubsub xmlns='http://jabber.org/protocol/pubsub#owner'><configure") catch break :stanza null;
        if (node.len > 0) {
            w.writeAll(" node='") catch break :stanza null;
            xml.escapeWrite(w, node) catch break :stanza null;
            w.writeByte('\'') catch break :stanza null;
        }
        w.writeAll("><x xmlns='jabber:x:data' type='form'>") catch break :stanza null;
        w.writeAll("<field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/pubsub#node_config</value></field>") catch break :stanza null;
        w.writeAll("<field var='pubsub#persist_items' type='boolean'><value>1</value></field>") catch break :stanza null;
        w.writeAll("<field var='pubsub#access_model' type='list-single'><value>presence</value></field>") catch break :stanza null;
        w.writeAll("<field var='pubsub#max_items' type='text-single'><value>1</value></field>") catch break :stanza null;
        w.writeAll("</x></configure></pubsub></iq>") catch break :stanza null;
        break :stanza fbs.getWritten();
    } orelse {
        noteJidOverflow("PEP node config reply to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
        return;
    };
    queueStanzaOrDrop(session, reply_xml, "PEP node config reply");
}

/// Handle XEP-0163 PEP items retrieval — get items from a PEP node.
/// Supports querying self (no 'to') or another user's PEP node (to='user@host').
/// If a specific item ID is requested, returns only that item.
fn handlePepItems(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
    _ = changes;
    const ps = server.pep_store orelse {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    };

    const node = session.iq_pep_node;
    if (node.len == 0) {
        sendIqError(server, session, iq_id, "bad-request");
        return;
    }

    // The target user is the IQ 'to' attribute, or self if not specified
    const bound = session.stream.bound_jid orelse return;
    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const iq_to = session.iq_to;
    const bare_jid = jid: {
        if (iq_to.len > 0) {
            // Query another user's PEP node — strip resource if full JID
            const at_pos = std.mem.indexOf(u8, iq_to, "@") orelse {
                sendIqError(server, session, iq_id, "bad-request");
                return;
            };
            const slash_pos = std.mem.indexOf(u8, iq_to[at_pos..], "/");
            const bare_end = if (slash_pos) |sp| at_pos + sp else iq_to.len;
            const bare_src = iq_to[0..bare_end];
            const sep = std.mem.indexOfScalar(u8, bare_src, '@') orelse {
                sendIqError(server, session, iq_id, "bad-request");
                return;
            };
            break :jid router.buildBareJid(bare_src[0..sep], bare_src[sep + 1 ..], &bare_buf) catch {
                noteJidOverflow("connection {d} PEP target JID exceeds {d} bytes", .{ session.conn.id, router.BARE_JID_MAX });
                sendIqError(server, session, iq_id, "jid-malformed");
                return;
            };
        }
        // Query own PEP node
        break :jid router.buildBareJid(bound.local, bound.domain, &bare_buf) catch {
            noteJidOverflow("connection {d} bound bare JID exceeds {d} bytes; IQ answered with error", .{ session.conn.id, router.BARE_JID_MAX });
            sendIqError(server, session, iq_id, "internal-server-error");
            return;
        };
    };

    // Check if a specific item ID was requested
    const requested_id = session.iq_roster_item_jid;

    if (requested_id.len > 0) {
        // Single item retrieval
        const payload = ps.getItem(server.allocator, bare_jid, node, requested_id) catch {
            sendIqError(server, session, iq_id, "internal-server-error");
            return;
        };
        if (payload == null) {
            sendIqError(server, session, iq_id, "item-not-found");
            return;
        }
        defer server.allocator.free(payload.?);

        // Build response — use dynamic buffer since PEP payloads (avatars) can be large
        var resp: std.ArrayList(u8) = .empty;
        defer resp.deinit(server.allocator);
        const rw = resp.writer(server.allocator);
        const reply_xml = stanza: {
            writePepIqHeader(rw, bare_jid, session, "result", iq_id) catch break :stanza null;
            rw.writeAll("><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='") catch break :stanza null;
            xml.escapeWrite(rw, node) catch break :stanza null;
            rw.writeAll("'><item id='") catch break :stanza null;
            xml.escapeWrite(rw, requested_id) catch break :stanza null;
            rw.writeAll("'>") catch break :stanza null;
            rw.writeAll(payload.?) catch break :stanza null;
            rw.writeAll("</item></items></pubsub></iq>") catch break :stanza null;
            break :stanza resp.items;
        } orelse {
            noteDrop("connection {d} PEP item reply assembly failed; dropped", .{session.conn.id});
            return;
        };
        queueStanzaOrDrop(session, reply_xml, "PEP item reply");
    } else {
        // All items retrieval
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

        // Build response — use dynamic buffer since PEP payloads can be large
        var resp: std.ArrayList(u8) = .empty;
        defer resp.deinit(server.allocator);
        const rw = resp.writer(server.allocator);
        const reply_xml = stanza: {
            writePepIqHeader(rw, bare_jid, session, "result", iq_id) catch break :stanza null;
            rw.writeAll("><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='") catch break :stanza null;
            xml.escapeWrite(rw, node) catch break :stanza null;
            rw.writeAll("'>") catch break :stanza null;
            for (items) |item| {
                rw.writeAll("<item id='") catch break :stanza null;
                xml.escapeWrite(rw, item.id) catch break :stanza null;
                rw.writeAll("'>") catch break :stanza null;
                rw.writeAll(item.payload) catch break :stanza null;
                rw.writeAll("</item>") catch break :stanza null;
            }
            rw.writeAll("</items></pubsub></iq>") catch break :stanza null;
            break :stanza resp.items;
        } orelse {
            noteDrop("connection {d} PEP items reply assembly failed; dropped", .{session.conn.id});
            return;
        };
        queueStanzaOrDrop(session, reply_xml, "PEP items reply");
    }
}

/// Write IQ header for PEP responses with correct 'from' (target user's bare JID).
fn writePepIqHeader(w: anytype, from_bare: []const u8, session: *Session, iq_type: []const u8, iq_id: []const u8) !void {
    try w.writeAll("<iq type='");
    try xml.escapeWrite(w, iq_type);
    try w.writeByte('\'');
    try w.writeAll(" from='");
    try xml.escapeWrite(w, from_bare);
    try w.writeByte('\'');
    if (session.stream.bound_jid) |bound_val| {
        try w.writeAll(" to='");
        try xml.escapeWrite(w, bound_val.local);
        try w.writeByte('@');
        try xml.escapeWrite(w, bound_val.domain);
        if (bound_val.resource.len > 0) {
            try w.writeByte('/');
            try xml.escapeWrite(w, bound_val.resource);
        }
        try w.writeByte('\'');
    }
    if (iq_id.len > 0) {
        try w.writeAll(" id='");
        try xml.escapeWrite(w, iq_id);
        try w.writeByte('\'');
    }
}

/// Send PEP event notification to presence subscribers (XEP-0163 §4.3).
/// Delivers a <message type='headline'> with a pubsub#event payload to all
/// online contacts who have a presence subscription from the publisher,
/// plus the publisher's own other resources (self-notification).
fn sendPepNotification(
    server: *Server,
    session: *Session,
    publisher_bare: []const u8,
    node: []const u8,
    item_id: []const u8,
    payload: []const u8,
    changes: *ChangeList,
) void {
    const roster = server.roster orelse return;
    const sm = server.session_map orelse return;

    // Pre-compute the message body after the 'to' attribute value.
    // Each recipient gets: <message from='PUB' type='headline' to='RECIP'>BODY</message>
    const body_prefix_1 = "<message from='";
    const body_prefix_2 = "' type='headline' to='";
    const body_mid = "'><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='";
    const body_item_open = "'><item id='";
    const body_item_mid = "'>";
    const body_suffix = "</item></items></event></message>";

    // Build the shared suffix (everything after the to='...' value) into a
    // leased bank: it is read while building every notification below (S18).
    var notif_lease = server.leaseByteScratch() orelse return;
    defer notif_lease.release();
    var nfbs = std.io.fixedBufferStream(notif_lease.buf);
    const nw = nfbs.writer();
    const body_after_to = suffix: {
        nw.writeAll(body_mid) catch break :suffix null;
        xml.escapeWrite(nw, node) catch break :suffix null;
        nw.writeAll(body_item_open) catch break :suffix null;
        xml.escapeWrite(nw, item_id) catch break :suffix null;
        nw.writeAll(body_item_mid) catch break :suffix null;
        nw.writeAll(payload) catch break :suffix null;
        nw.writeAll(body_suffix) catch break :suffix null;
        break :suffix nfbs.getWritten();
    } orelse {
        noteDrop("PEP notification body for node '{s}' exceeds {d} bytes; fanout skipped", .{ node, notif_lease.buf.len });
        return;
    };

    // Deliver to the publisher's own resources (self-notification per XEP-0163 §4.3)
    const bound = session.stream.bound_jid orelse return;
    {
        var lease_self = server.leaseScratch(.b);
        defer lease_self.release();
        const self_entries = lease_self.entries;
        const self_count = sm.findAvailableByBareJid(bound.local, bound.domain, self_entries);

        // One buffer reused per resource: deliverToSession and ds.deliver both
        // copy, so a resource's stanza is dead before the next is built (S18).
        var self_msg_lease = server.leaseByteScratch() orelse return;
        defer self_msg_lease.release();

        for (self_entries[0..self_count]) |entry| {
            if (entry.worker_id == server.worker_id) {
                const target = server.sessions[entry.local_session_id] orelse continue;
                // XEP-0163 section 4.3: notify ALL subscribed resources including the publisher

                var mfbs = std.io.fixedBufferStream(self_msg_lease.buf);
                const mw = mfbs.writer();
                const notif_xml = stanza: {
                    mw.writeAll(body_prefix_1) catch break :stanza null;
                    xml.escapeWrite(mw, publisher_bare) catch break :stanza null;
                    mw.writeAll(body_prefix_2) catch break :stanza null;
                    xml.escapeWrite(mw, bound.local) catch break :stanza null;
                    mw.writeByte('@') catch break :stanza null;
                    xml.escapeWrite(mw, bound.domain) catch break :stanza null;
                    mw.writeByte('/') catch break :stanza null;
                    xml.escapeWrite(mw, entry.resource()) catch break :stanza null;
                    mw.writeAll(body_after_to) catch break :stanza null;
                    break :stanza mfbs.getWritten();
                } orelse {
                    noteJidOverflow("PEP notification to '{s}@{s}/{s}' exceeds {d} bytes; resource skipped", .{ bound.local, bound.domain, entry.resource(), self_msg_lease.buf.len });
                    continue;
                };
                fanout.deliverToSession(target, notif_xml, entry.local_session_id, changes);
            } else {
                // Cross-thread: build full stanza and deliver via MPSC
                if (server.delivery_system) |ds| {
                    var mfbs = std.io.fixedBufferStream(self_msg_lease.buf);
                    const mw = mfbs.writer();
                    const notif_xml = stanza: {
                        mw.writeAll(body_prefix_1) catch break :stanza null;
                        xml.escapeWrite(mw, publisher_bare) catch break :stanza null;
                        mw.writeAll(body_prefix_2) catch break :stanza null;
                        xml.escapeWrite(mw, bound.local) catch break :stanza null;
                        mw.writeByte('@') catch break :stanza null;
                        xml.escapeWrite(mw, bound.domain) catch break :stanza null;
                        mw.writeByte('/') catch break :stanza null;
                        xml.escapeWrite(mw, entry.resource()) catch break :stanza null;
                        mw.writeAll(body_after_to) catch break :stanza null;
                        break :stanza mfbs.getWritten();
                    } orelse {
                        noteJidOverflow("PEP notification to '{s}@{s}/{s}' exceeds {d} bytes; resource skipped", .{ bound.local, bound.domain, entry.resource(), self_msg_lease.buf.len });
                        continue;
                    };
                    ds.deliver(entry.worker_id, entry.local_session_id, entry.generation, notif_xml) catch |err| {
                        noteCrossWorkerDrop("PEP notification to worker {d} session {d} dropped ({s})", .{ entry.worker_id, entry.local_session_id, @errorName(err) });
                    };
                }
            }
        }
    }

    // Deliver to presence subscribers (contacts with "from" or "both" subscription) — cached (T129)
    // Subscriber JID pointers index into this buffer and stay live across the
    // loop below, which also builds each notification into a third bank, so
    // the shared suffix above, this list, and one notification are all live at
    // once: three banks, which is BYTE_BANK_COUNT (S18).
    var pep_sub_lease = server.leaseByteScratch() orelse return;
    defer pep_sub_lease.release();
    const pep_sub_buf = pep_sub_lease.buf;
    var pep_sub_ptrs: [256][]const u8 = undefined;
    const pep_hash = server_mod.sub_cache_mod.hashBareJid(publisher_bare);
    const pep_now = std.time.timestamp();
    const pep_sub_count = server.sub_cache.lookupSubscribers(pep_hash, pep_now, pep_sub_buf, &pep_sub_ptrs) orelse blk: {
        const count = roster.getPresenceSubscribersFixed(publisher_bare, pep_sub_buf, &pep_sub_ptrs) catch {
            noteDrop("presence-subscriber lookup for '{s}' failed; PEP notification skipped", .{publisher_bare});
            return;
        };
        server.sub_cache.storeSubscribers(pep_hash, pep_now, pep_sub_ptrs[0..count]);
        break :blk count;
    };
    const subscriber_jids = pep_sub_ptrs[0..pep_sub_count];

    // One buffer reused for every notification below: both delivery paths
    // copy, so a stanza is dead before the next subscriber is built (S18).
    var sub_msg_lease = server.leaseByteScratch() orelse return;
    defer sub_msg_lease.release();

    for (subscriber_jids) |sub_bare_jid| {
        // Skip blocked contacts
        if (server.block_store) |bs| {
            if (bs.isBlocked(server.allocator, sub_bare_jid, publisher_bare) catch false) continue;
        }

        const at_pos = std.mem.indexOf(u8, sub_bare_jid, "@") orelse continue;
        const sub_local = sub_bare_jid[0..at_pos];
        const sub_domain = sub_bare_jid[at_pos + 1 ..];

        // Only deliver to local users for now (S2S PEP notifications are post-V1)
        if (!std.mem.eql(u8, sub_domain, server.server_host)) continue;

        var lease_b = server.leaseScratch(.b);
        defer lease_b.release();
        const entries = lease_b.entries;
        const count = sm.findAvailableByBareJid(sub_local, sub_domain, entries);
        for (entries[0..count]) |entry| {
            if (entry.worker_id == server.worker_id) {
                const target = server.sessions[entry.local_session_id] orelse continue;

                var mfbs = std.io.fixedBufferStream(sub_msg_lease.buf);
                const mw = mfbs.writer();
                const notif_xml = stanza: {
                    mw.writeAll(body_prefix_1) catch break :stanza null;
                    xml.escapeWrite(mw, publisher_bare) catch break :stanza null;
                    mw.writeAll(body_prefix_2) catch break :stanza null;
                    xml.escapeWrite(mw, sub_local) catch break :stanza null;
                    mw.writeByte('@') catch break :stanza null;
                    xml.escapeWrite(mw, sub_domain) catch break :stanza null;
                    mw.writeByte('/') catch break :stanza null;
                    xml.escapeWrite(mw, entry.resource()) catch break :stanza null;
                    mw.writeAll(body_after_to) catch break :stanza null;
                    break :stanza mfbs.getWritten();
                } orelse {
                    noteJidOverflow("PEP notification to '{s}@{s}/{s}' exceeds {d} bytes; resource skipped", .{ sub_local, sub_domain, entry.resource(), sub_msg_lease.buf.len });
                    continue;
                };
                fanout.deliverToSession(target, notif_xml, entry.local_session_id, changes);
            } else {
                if (server.delivery_system) |ds| {
                    var mfbs = std.io.fixedBufferStream(sub_msg_lease.buf);
                    const mw = mfbs.writer();
                    const notif_xml = stanza: {
                        mw.writeAll(body_prefix_1) catch break :stanza null;
                        xml.escapeWrite(mw, publisher_bare) catch break :stanza null;
                        mw.writeAll(body_prefix_2) catch break :stanza null;
                        xml.escapeWrite(mw, sub_local) catch break :stanza null;
                        mw.writeByte('@') catch break :stanza null;
                        xml.escapeWrite(mw, sub_domain) catch break :stanza null;
                        mw.writeByte('/') catch break :stanza null;
                        xml.escapeWrite(mw, entry.resource()) catch break :stanza null;
                        mw.writeAll(body_after_to) catch break :stanza null;
                        break :stanza mfbs.getWritten();
                    } orelse {
                        noteJidOverflow("PEP notification to '{s}@{s}/{s}' exceeds {d} bytes; resource skipped", .{ sub_local, sub_domain, entry.resource(), sub_msg_lease.buf.len });
                        continue;
                    };
                    ds.deliver(entry.worker_id, entry.local_session_id, entry.generation, notif_xml) catch |err| {
                        noteCrossWorkerDrop("PEP notification to worker {d} session {d} dropped ({s})", .{ entry.worker_id, entry.local_session_id, @errorName(err) });
                    };
                }
            }
        }
    }
}

/// Handle XEP-0191 <blocklist/> get — return the user's block list.
fn handleBlocklistGet(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
    _ = changes;
    const bs = server.block_store orelse {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    };
    const bound = session.stream.bound_jid orelse return;

    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const bare_jid = router.buildBareJid(bound.local, bound.domain, &bare_buf) catch {
        noteJidOverflow("connection {d} bound bare JID exceeds {d} bytes; IQ answered with error", .{ session.conn.id, router.BARE_JID_MAX });
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };

    const items = bs.getBlockList(server.allocator, bare_jid) catch {
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };
    defer {
        for (items) |item| server.allocator.free(item);
        server.allocator.free(items);
    }

    // A blocklist reply that cannot fit every item is not sent
    // half-written: the requester gets a resource-constraint error.
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    const reply_xml = stanza: {
        writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
        w.writeAll("><blocklist xmlns='urn:xmpp:blocking'>") catch break :stanza null;
        for (items) |jid| {
            w.writeAll("<item jid='") catch break :stanza null;
            xml.escapeWrite(w, jid) catch break :stanza null;
            w.writeAll("'/>") catch break :stanza null;
        }
        w.writeAll("</blocklist></iq>") catch break :stanza null;
        break :stanza fbs.getWritten();
    } orelse {
        noteJidOverflow("blocklist reply to connection {d} exceeds {d} bytes; answering resource-constraint", .{ session.conn.id, session.write_scratch.len });
        sendIqError(server, session, iq_id, "resource-constraint");
        return;
    };
    queueStanzaOrDrop(session, reply_xml, "blocklist reply");
}

/// Handle XEP-0191 <block/> set — add JIDs to user's block list.
fn handleBlock(server: *Server, session: *Session, iq_id: []const u8, changes: *ChangeList) void {
    const bs = server.block_store orelse {
        sendIqError(server, session, iq_id, "item-not-found");
        return;
    };
    const bound = session.stream.bound_jid orelse return;

    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const bare_jid = router.buildBareJid(bound.local, bound.domain, &bare_buf) catch {
        noteJidOverflow("connection {d} bound bare JID exceeds {d} bytes; IQ answered with error", .{ session.conn.id, router.BARE_JID_MAX });
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };

    const item_jid_raw = session.iq_roster_item_jid;
    if (item_jid_raw.len == 0) {
        sendIqError(server, session, iq_id, "bad-request");
        return;
    }

    // F6: fold a local blocked JID once so the block key and the push below
    // use the configured spelling; remote-domain JIDs pass through.
    const item_jid = @import("xmpp").prepareLocalDomainJid(item_jid_raw, server.server_host, &session.iq_jid_prep_buf) catch {
        sendIqError(server, session, iq_id, "jid-malformed");
        return;
    };

    // S4: bounded store keys; an oversized blocked JID is malformed.
    if (!@import("store_keys").fits2(bare_jid, item_jid)) {
        sendIqError(server, session, iq_id, "jid-malformed");
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
    const reply_xml = stanza: {
        writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
        w.writeAll("/>") catch break :stanza null;
        break :stanza fbs.getWritten();
    } orelse {
        noteJidOverflow("block result to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
        return;
    };
    queueStanzaOrDrop(session, reply_xml, "block result");

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

    var bare_buf: [router.BARE_JID_MAX]u8 = undefined;
    const bare_jid = router.buildBareJid(bound.local, bound.domain, &bare_buf) catch {
        noteJidOverflow("connection {d} bound bare JID exceeds {d} bytes; IQ answered with error", .{ session.conn.id, router.BARE_JID_MAX });
        sendIqError(server, session, iq_id, "internal-server-error");
        return;
    };

    var item_jid = session.iq_roster_item_jid;
    if (item_jid.len == 0) {
        // Empty <unblock/> means unblock all
        bs.removeAll(server.allocator, bare_jid) catch |err| {
            noteDrop("blocklist clear for '{s}' failed: {s}", .{ bare_jid, @errorName(err) });
        };
        log.info("connection {d} unblocked all", .{session.conn.id});
    } else {
        // F6: fold a local blocked JID once so the unblock key and the push
        // below use the configured spelling; remote JIDs pass through.
        item_jid = @import("xmpp").prepareLocalDomainJid(item_jid, server.server_host, &session.iq_jid_prep_buf) catch {
            sendIqError(server, session, iq_id, "jid-malformed");
            return;
        };
        // S4: bounded store keys; an oversized blocked JID is malformed.
        if (!@import("store_keys").fits2(bare_jid, item_jid)) {
            sendIqError(server, session, iq_id, "jid-malformed");
            return;
        }
        bs.unblock(bare_jid, item_jid) catch {
            sendIqError(server, session, iq_id, "internal-server-error");
            return;
        };
        log.info("connection {d} unblocked {s}", .{ session.conn.id, item_jid });
    }

    // Ack with empty result
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    const reply_xml = stanza: {
        writeIqHeader(server, w, session, "result", iq_id) catch break :stanza null;
        w.writeAll("/>") catch break :stanza null;
        break :stanza fbs.getWritten();
    } orelse {
        noteJidOverflow("unblock result to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
        return;
    };
    queueStanzaOrDrop(session, reply_xml, "unblock result");

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
    var lease_b = server.leaseScratch(.b);
    defer lease_b.release();
    const entries = lease_b.entries;
    const count = sm.findAvailableByBareJid(user_local, user_domain, entries);
    if (count == 0) return;

    for (entries[0..count]) |entry| {
        if (entry.worker_id == server.worker_id) {
            const target = server.sessions[entry.local_session_id] orelse continue;
            // Skip the originating session (it already got the IQ result)
            if (&target.conn == &sender_session.conn) continue;

            var push_buf: [router.JID_STANZA_MAX]u8 = undefined;
            var pfbs = std.io.fixedBufferStream(&push_buf);
            const pw = pfbs.writer();
            const push_xml = stanza: {
                pw.writeAll("<iq type='set' to='") catch break :stanza null;
                xml.escapeWrite(pw, user_local) catch break :stanza null;
                pw.writeByte('@') catch break :stanza null;
                xml.escapeWrite(pw, user_domain) catch break :stanza null;
                pw.writeByte('/') catch break :stanza null;
                xml.escapeWrite(pw, entry.resource()) catch break :stanza null;
                pw.writeAll("'><") catch break :stanza null;
                pw.writeAll(action) catch break :stanza null;
                pw.writeAll(" xmlns='urn:xmpp:blocking'>") catch break :stanza null;
                if (item_jid.len > 0) {
                    pw.writeAll("<item jid='") catch break :stanza null;
                    xml.escapeWrite(pw, item_jid) catch break :stanza null;
                    pw.writeAll("'/>") catch break :stanza null;
                }
                pw.writeAll("</") catch break :stanza null;
                pw.writeAll(action) catch break :stanza null;
                pw.writeAll("></iq>") catch break :stanza null;
                break :stanza pfbs.getWritten();
            } orelse {
                noteJidOverflow("block-push IQ to '{s}@{s}/{s}' exceeds {d} bytes; resource skipped", .{ user_local, user_domain, entry.resource(), router.JID_STANZA_MAX });
                continue;
            };

            fanout.deliverToSession(target, push_xml, entry.local_session_id, changes);
        }
        // Cross-thread push: deferred to post-V1 (T89 pattern)
    }
}

pub fn sendIqError(server: *Server, session: *Session, iq_id: []const u8, condition: []const u8) void {
    sendIqErrorWithType(server, session, iq_id, "cancel", condition);
}

/// XEP-0060 §10.2.1: the <unsupported feature='...'> token naming the pubsub
/// feature a set verb would exercise. Verbs without a listed feature are
/// malformed rather than unimplemented and get bad-request instead.
fn pubsubUnsupportedFeature(verb: []const u8) ?[]const u8 {
    const map = .{
        .{ "subscribe", "subscribe" },
        .{ "unsubscribe", "subscribe" },
        .{ "options", "subscription-options" },
        .{ "configure", "config-node" },
        .{ "create", "create-nodes" },
        .{ "delete", "delete-nodes" },
        .{ "purge", "purge-nodes" },
        .{ "retract", "retract-items" },
    };
    inline for (map) |entry| {
        if (std.mem.eql(u8, verb, entry[0])) return entry[1];
    }
    return null;
}

/// feature-not-implemented carrying the pubsub#error <unsupported> element
/// for the feature the verb maps to (XEP-0060 §10.2.1).
fn sendPubsubUnsupported(server: *Server, session: *Session, iq_id: []const u8, feature: []const u8) void {
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    const reply_xml = stanza: {
        writeIqHeader(server, w, session, "error", iq_id) catch break :stanza null;
        w.writeAll("><error type='cancel'><feature-not-implemented xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>") catch break :stanza null;
        w.writeAll("<unsupported xmlns='http://jabber.org/protocol/pubsub#errors' feature='") catch break :stanza null;
        w.writeAll(feature) catch break :stanza null;
        w.writeAll("'/></error></iq>") catch break :stanza null;
        break :stanza fbs.getWritten();
    } orelse {
        noteJidOverflow("pubsub unsupported error to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
        return;
    };
    queueStanzaOrDrop(session, reply_xml, "pubsub unsupported error");
}

pub fn sendIqErrorWithType(server: *Server, session: *Session, iq_id: []const u8, err_type: []const u8, condition: []const u8) void {
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    const reply_xml = stanza: {
        writeIqHeader(server, w, session, "error", iq_id) catch break :stanza null;
        w.writeAll("><error type='") catch break :stanza null;
        w.writeAll(err_type) catch break :stanza null;
        w.writeAll("'><") catch break :stanza null;
        w.writeAll(condition) catch break :stanza null;
        w.writeAll(" xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>") catch break :stanza null;
        break :stanza fbs.getWritten();
    } orelse {
        noteJidOverflow("IQ error reply to connection {d} exceeds {d} bytes; dropped", .{ session.conn.id, session.write_scratch.len });
        return;
    };
    queueStanzaOrDrop(session, reply_xml, "IQ error reply");
}

/// Write <group>text</group> elements from serialized groups data.
/// Format: [len_be(2) | text] * group_count.
fn writeGroupElements(w: anytype, groups_data: []const u8, group_count: u8) !void {
    var offset: usize = 0;
    var i: u8 = 0;
    while (i < group_count) : (i += 1) {
        if (offset + 2 > groups_data.len) break;
        const glen = std.mem.readInt(u16, groups_data[offset..][0..2], .big);
        offset += 2;
        if (offset + glen > groups_data.len) break;
        const gtext = groups_data[offset .. offset + glen];
        offset += glen;
        try w.writeAll("<group>");
        try xml.escapeWrite(w, gtext);
        try w.writeAll("</group>");
    }
}

/// RFC 6121 §2.1.6: Push a roster item update to all interested resources of a user.
/// Sends an IQ type='set' with the updated item to each connected resource that
/// has previously requested the roster.
pub fn pushRosterItem(
    server: *Server,
    user_local: []const u8,
    user_domain: []const u8,
    item_jid: []const u8,
    item_name: []const u8,
    subscription: generic_roster.Subscription,
    ask: bool,
    changes: *ChangeList,
) void {
    const sm = server.session_map orelse return;
    var lease_b = server.leaseScratch(.b);
    defer lease_b.release();
    const entries = lease_b.entries;
    const count = sm.findByBareJid(user_local, user_domain, entries);
    if (count == 0) return;

    // Look up current item to get groups and name for the push.
    var groups_data: []const u8 = "";
    var group_count: u8 = 0;
    var stored_name: []const u8 = "";
    if (server.roster) |roster| owner_lookup: {
        var owner_buf: [router.BARE_JID_MAX]u8 = undefined;
        const owner_bare = router.buildBareJid(user_local, user_domain, &owner_buf) catch {
            noteJidOverflow("roster-push owner '{s}@{s}' exceeds {d} bytes; item lookup skipped", .{ user_local, user_domain, router.BARE_JID_MAX });
            break :owner_lookup;
        };
        if (roster.getItem(server.allocator, owner_bare, item_jid) catch null) |existing| {
            // groups_data and stored_name are allocator-owned — will free after push loop
            groups_data = existing.groups;
            group_count = existing.group_count;
            stored_name = existing.name;
        }
    }
    defer if (groups_data.len > 0) server.allocator.free(groups_data);
    defer if (stored_name.len > 0) server.allocator.free(stored_name);

    // Use stored name from roster if caller didn't provide one.
    const effective_name = if (item_name.len > 0) item_name else stored_name;

    // Build the push XML once (same for all targets)
    var push_buf: [4096]u8 = undefined;
    var pfbs = std.io.fixedBufferStream(&push_buf);
    const pw = pfbs.writer();
    // We'll prepend per-target header, so build item portion first
    const item_xml = stanza: {
        pw.writeAll("<item jid='") catch break :stanza null;
        xml.escapeWrite(pw, item_jid) catch break :stanza null;
        pw.writeByte('\'') catch break :stanza null;
        if (effective_name.len > 0) {
            pw.writeAll(" name='") catch break :stanza null;
            xml.escapeWrite(pw, effective_name) catch break :stanza null;
            pw.writeByte('\'') catch break :stanza null;
        }
        pw.writeAll(" subscription='") catch break :stanza null;
        pw.writeAll(subscription.toString()) catch break :stanza null;
        pw.writeByte('\'') catch break :stanza null;
        if (ask) {
            pw.writeAll(" ask='subscribe'") catch break :stanza null;
        }
        if (group_count > 0) {
            pw.writeByte('>') catch break :stanza null;
            writeGroupElements(pw, groups_data, group_count) catch break :stanza null;
            pw.writeAll("</item>") catch break :stanza null;
        } else {
            pw.writeAll("/>") catch break :stanza null;
        }
        break :stanza pfbs.getWritten();
    } orelse {
        noteJidOverflow("roster-push item '{s}' exceeds {d} bytes; push skipped", .{ item_jid, push_buf.len });
        return;
    };

    for (entries[0..count]) |entry| {
        // Build full push IQ per target (different 'to' and 'id')
        var full_buf: [4096]u8 = undefined;
        var ffbs = std.io.fixedBufferStream(&full_buf);
        const fw = ffbs.writer();
        var id_buf: [32]u8 = undefined;
        const push_id = server.generateStanzaId(&id_buf);

        const full_xml = stanza: {
            fw.writeAll("<iq type='set' to='") catch break :stanza null;
            xml.escapeWrite(fw, user_local) catch break :stanza null;
            fw.writeByte('@') catch break :stanza null;
            xml.escapeWrite(fw, user_domain) catch break :stanza null;
            fw.writeByte('/') catch break :stanza null;
            xml.escapeWrite(fw, entry.resource()) catch break :stanza null;
            fw.writeAll("' id='") catch break :stanza null;
            xml.escapeWrite(fw, push_id) catch break :stanza null;
            fw.writeAll("'><query xmlns='jabber:iq:roster'>") catch break :stanza null;
            fw.writeAll(item_xml) catch break :stanza null;
            fw.writeAll("</query></iq>") catch break :stanza null;
            break :stanza ffbs.getWritten();
        } orelse {
            noteJidOverflow("roster push to '{s}@{s}/{s}' exceeds {d} bytes; resource skipped", .{ user_local, user_domain, entry.resource(), full_buf.len });
            continue;
        };

        if (entry.worker_id == server.worker_id) {
            const target = server.sessions[entry.local_session_id] orelse continue;
            if (!target.roster_interested) continue;
            fanout.deliverToSession(target, full_xml, entry.local_session_id, changes);
        } else if (server.delivery_system) |ds| {
            ds.deliver(entry.worker_id, entry.local_session_id, entry.generation, full_xml) catch |err| {
                noteCrossWorkerDrop("roster push to worker {d} session {d} dropped ({s})", .{ entry.worker_id, entry.local_session_id, @errorName(err) });
            };
        }
    }
}

/// Write the MD5 hex hash of a bare JID for Gravatar URL construction.
/// Gravatar uses MD5(lowercase(email)) — bare JIDs are already email-like.
fn writeGravatarHash(writer: anytype, bare_jid: []const u8) !void {
    var lower_buf: [router.BARE_JID_MAX]u8 = undefined;
    const len = @min(bare_jid.len, lower_buf.len);
    for (bare_jid[0..len], 0..) |c, i| {
        lower_buf[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
    }
    var digest: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(lower_buf[0..len], &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    try writer.writeAll(&hex);
}

// ============================================================================
// Tests
// ============================================================================

test "S11: staged reg IQ id survives the reader-arena reset" {
    const posix = std.posix;
    const allocator = std.testing.allocator;
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();

    var fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds));
    defer posix.close(fds[1]);

    const session = try allocator.create(Session);
    defer allocator.destroy(session);
    session.* = Session.init(fds[0], 0, server.server_host, false, allocator);
    defer session.deinit(); // closes fds[0]

    // The id arrives as a slice into the connection's reader arena.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_id = try arena.allocator().dupe(u8, "pw-change-42");
    try std.testing.expect(stageRegPendingIq(&server, session, arena_id));

    // The next stanza resets the arena (S11) and later stanzas reuse the
    // memory; the staged id must be a session-owned copy.
    _ = arena.reset(.retain_capacity);
    _ = try arena.allocator().dupe(u8, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    try std.testing.expectEqualStrings("pw-change-42", session.reg_pending_iq_id);

    // Overlong ids are rejected and leave the staged id untouched.
    var long_buf: [300]u8 = undefined;
    @memset(&long_buf, 'y');
    try std.testing.expect(!stageRegPendingIq(&server, session, &long_buf));
    try std.testing.expectEqualStrings("pw-change-42", session.reg_pending_iq_id);
}

test "A62: roster get for a >256-byte owner bare JID" {
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
    var roster = GenericRosterStore.init(&db);
    server.roster = &roster;

    // 300-byte owner bare JID (290-byte localpart).
    var obuf: [290]u8 = undefined;
    @memset(&obuf, 'o');
    const owner_local = obuf[0..];
    var bare_buf: [512]u8 = undefined;
    const owner_bare = std.fmt.bufPrint(&bare_buf, "{s}@localhost", .{owner_local}) catch unreachable;
    try std.testing.expectEqual(@as(usize, 300), owner_bare.len);

    try roster.setItem(owner_bare, "contact@example.org", "c", .none, false);

    var fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds));
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.* = Session.init(fds[0], 1, server.server_host, false, allocator);
    server.sessions[1] = session;
    session.stream.bound_jid = .{ .local = owner_local, .domain = "localhost", .resource = "res" };

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    handleRosterGet(&server, session, "iq1", &changes);

    _ = try session.conn.flushSend();
    var rbuf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &rbuf) catch 0;
    const got = rbuf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, got, "contact@example.org") != null);
}

test "F6: last-activity query to the domain in another case is server-addressed" {
    const posix = std.posix;
    const allocator = std.testing.allocator;
    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();

    var fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds));
    defer posix.close(fds[1]);

    const session = try allocator.create(Session);
    defer allocator.destroy(session);
    session.* = Session.init(fds[0], 0, server.server_host, false, allocator);
    defer session.deinit();

    session.iq_to = "LOCALHOST";
    handleLastActivitySelfOrServer(&server, session, "la1");
    _ = try session.conn.flushSend();
    var buf: [2048]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    const reply = buf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, reply, "jabber:iq:last") != null);
    try std.testing.expect(std.mem.indexOf(u8, reply, "service-unavailable") == null);
}

test "F6: last-activity query for a mixed-case local domain is not remote" {
    const posix = std.posix;
    const allocator = std.testing.allocator;
    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();

    var fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds));
    defer posix.close(fds[1]);

    const session = try allocator.create(Session);
    defer allocator.destroy(session);
    session.* = Session.init(fds[0], 0, server.server_host, false, allocator);
    defer session.deinit();

    session.stream.bound_jid = .{ .local = "alice", .domain = "localhost", .resource = "phone" };
    handleLastActivityFor(&server, session, "la2", .{ .local = "bob", .domain = "LOCALHOST" });
    _ = try session.conn.flushSend();
    var buf: [2048]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    const reply = buf[0..n];
    // Local evaluation continues to the roster check; a remote verdict
    // short-circuits with service-unavailable.
    try std.testing.expect(std.mem.indexOf(u8, reply, "item-not-found") != null);
    try std.testing.expect(std.mem.indexOf(u8, reply, "service-unavailable") == null);
}

test "F6: roster set stores the contact under the configured local spelling" {
    const posix = std.posix;
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try server_mod.OpBackendType.open(path, .{});
    defer db.close();
    var roster = GenericRosterStore.init(&db);

    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();
    server.roster = &roster;

    var fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds));
    defer posix.close(fds[1]);

    const session = try allocator.create(Session);
    defer allocator.destroy(session);
    session.* = Session.init(fds[0], 0, server.server_host, false, allocator);
    defer session.deinit();
    session.stream.bound_jid = .{ .local = "alice", .domain = "localhost", .resource = "phone" };
    session.iq_roster_item_jid = "NaplesTB@LOCALHOST";
    session.iq_roster_item_count = 1;

    var scratch: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&scratch);
    handleRosterSet(&server, session, "rs1", &changes);

    const entry = try roster.getItem(allocator, "alice@localhost", "naplestb@localhost");
    try std.testing.expect(entry != null);
    if (entry) |e| {
        defer if (e.name.len > 0) allocator.free(e.name);
        defer if (e.groups.len > 0) allocator.free(e.groups);
    }
    // The as-typed spelling is not a second key.
    try std.testing.expect((try roster.getItem(allocator, "alice@localhost", "NaplesTB@LOCALHOST")) == null);
}

test "F6: block and unblock use the configured local spelling for the store key" {
    const posix = std.posix;
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try server_mod.OpBackendType.open(path, .{});
    defer db.close();
    const GenericBlockStore = @import("block_store").BlockStore(server_mod.OpBackendType);
    var bs = GenericBlockStore.init(&db);

    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();
    server.block_store = &bs;

    var fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds));
    defer posix.close(fds[1]);

    const session = try allocator.create(Session);
    defer allocator.destroy(session);
    session.* = Session.init(fds[0], 0, server.server_host, false, allocator);
    defer session.deinit();
    session.stream.bound_jid = .{ .local = "alice", .domain = "localhost", .resource = "phone" };

    var scratch: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&scratch);

    session.iq_roster_item_jid = "NaplesTB@LOCALHOST";
    handleBlock(&server, session, "b1", &changes);
    try std.testing.expect(try bs.isBlocked(allocator, "alice@localhost", "naplestb@localhost"));
    try std.testing.expect(!(try bs.isBlocked(allocator, "alice@localhost", "NaplesTB@LOCALHOST")));

    // The unblock path folds too: an entry stored folded comes out.
    try bs.block("alice@localhost", "carolx@localhost");
    session.iq_roster_item_jid = "CarolX@LOCALHOST";
    handleUnblock(&server, session, "u1", &changes);
    try std.testing.expect(!(try bs.isBlocked(allocator, "alice@localhost", "carolx@localhost")));
}

test "F6: MAM 'with' matches the folded archive contact key" {
    const posix = std.posix;
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    const ArchBackend = @import("archive_backend").Backend;
    var arch_db = try ArchBackend.open(path, .{});
    defer arch_db.close();
    var arch_store = @import("archive_store").ArchiveStore(ArchBackend).init(&arch_db, allocator);

    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();
    server.archive = &arch_store;

    try arch_store.store("alice@localhost", "naplestb@localhost", "m-1", 1700000000, "<message><body>hi</body></message>");

    var fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds));
    defer posix.close(fds[1]);

    const session = try allocator.create(Session);
    defer allocator.destroy(session);
    session.* = Session.init(fds[0], 0, server.server_host, false, allocator);
    defer session.deinit();
    session.stream.bound_jid = .{ .local = "alice", .domain = "localhost", .resource = "phone" };
    session.mam_with = "NaplesTB@LOCALHOST";

    var scratch: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&scratch);
    handleMamQuery(&server, session, "mam1", &changes);

    // The folded 'with' hits the by_contact key the archive wrote.
    _ = try session.conn.flushSend();
    var buf: [8192]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    const reply = buf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, reply, "id='m-1'") != null);
    try std.testing.expect(std.mem.indexOf(u8, reply, "<count>1</count>") != null);
}

test "F6: MUC MAM 'with' matches the folded archive contact key" {
    const posix = std.posix;
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    const ArchBackend = @import("archive_backend").Backend;
    var arch_db = try ArchBackend.open(path, .{});
    defer arch_db.close();
    var arch_store = @import("archive_store").ArchiveStore(ArchBackend).init(&arch_db, allocator);

    var reg = room_registry_mod.RoomRegistry.init(allocator);
    defer reg.deinit();

    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();
    server.archive = &arch_store;
    server.room_registry = &reg;
    server.worker_id = 0;

    try arch_store.store("lobby@conference.localhost", "naplestb@localhost", "rm-1", 1700000000, "<message><body>hi</body></message>");

    var fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds));
    defer posix.close(fds[1]);

    const session = try allocator.create(Session);
    defer allocator.destroy(session);
    session.* = Session.init(fds[0], 0, server.server_host, false, allocator);
    defer session.deinit();
    session.stream.bound_jid = .{ .local = "alice", .domain = "localhost", .resource = "phone" };
    session.mam_with = "NaplesTB@LOCALHOST";

    var scratch: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&scratch);
    // A single worker owns every room, so the local query path runs.
    handleMucMamQuery(&server, session, "lobby", "conference.localhost", "mam2", &changes);

    _ = try session.conn.flushSend();
    var buf: [8192]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    const reply = buf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, reply, "id='rm-1'") != null);
    try std.testing.expect(std.mem.indexOf(u8, reply, "<count>1</count>") != null);
}

var f6_with_seen: [512]u8 = undefined;
var f6_with_len: usize = 0;
fn f6Drain(_: void, _: u32, _: u32, payload: []const u8) void {
    const m = actor_message.decode(payload) orelse return;
    switch (m) {
        .room_mam_query => |q| {
            @memcpy(f6_with_seen[0..q.with.len], q.with);
            f6_with_len = q.with.len;
        },
        else => {},
    }
}

test "F6: cross-worker MUC MAM forwards the prepared 'with'" {
    const posix = std.posix;
    const allocator = std.testing.allocator;
    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();
    var ds = try @import("delivery_queue").DeliverySystem.init(allocator, 2);
    defer ds.deinit();
    server.delivery_system = &ds;
    var name_buf: [64]u8 = undefined;
    var room_local: []const u8 = "";
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        room_local = try std.fmt.bufPrint(&name_buf, "r{d}", .{i});
        var jb: [128]u8 = undefined;
        const rj = try std.fmt.bufPrint(&jb, "{s}@conference.localhost", .{room_local});
        if (room_registry_mod.roomOwner(rj, 2) == 1) break;
    }
    server.worker_id = 0;
    var fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds));
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    defer allocator.destroy(session);
    session.* = Session.init(fds[0], 0, server.server_host, false, allocator);
    defer session.deinit();
    session.stream.bound_jid = .{ .local = "alice", .domain = "localhost", .resource = "phone" };
    session.mam_with = "NaplesTB@LOCALHOST";
    var scratch: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&scratch);
    handleMucMamQuery(&server, session, room_local, "conference.localhost", "mamx", &changes);
    _ = ds.getQueue(1).drain({}, f6Drain);
    try std.testing.expectEqualStrings("naplestb@localhost", f6_with_seen[0..f6_with_len]);
}

test "R5: an unaddressable IQ error reply is counted, never a truncated stanza" {
    const posix = std.posix;
    const allocator = std.testing.allocator;
    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();

    var fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds));
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    defer allocator.destroy(session);
    session.* = Session.init(fds[0], 0, server.server_host, false, allocator);
    defer session.deinit();

    // A bound localpart wider than the 4 KiB scratch: the header cannot be
    // written, so no reply can even be addressed. The drop must be counted
    // (R5); a silently truncated stanza would leave bytes pending.
    var big: [4096]u8 = undefined;
    @memset(&big, 'b');
    session.stream.bound_jid = .{ .local = &big, .domain = "localhost", .resource = "res" };

    const drops_before = router.jid_overflow_drops.load(.monotonic);
    sendIqErrorWithType(&server, session, "e1", "cancel", "internal-server-error");
    try std.testing.expectEqual(drops_before + 1, router.jid_overflow_drops.load(.monotonic));
    try std.testing.expect(!session.conn.hasPendingWrite());
}

test "R5: a roster push to a full remote queue is counted" {
    const posix = std.posix;
    const allocator = std.testing.allocator;
    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();
    var sm = session_map_mod.SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    server.session_map = &sm;
    var delivery_sys = try delivery_queue.DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();
    server.delivery_system = &delivery_sys;
    server.worker_id = 0;

    _ = try sm.bind(1, 7, "bob", "localhost", "mobile");

    const queue = delivery_sys.getQueue(1);
    for (0..delivery_queue.QUEUE_SLOTS) |_| try queue.enqueue(1, 1, "fill");

    const drops_before = delivery_queue.cross_worker_drops.load(.monotonic);
    var scratch: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&scratch);
    pushRosterItem(&server, "bob", "localhost", "carol@example.com", "Carol", .both, false, &changes);
    try std.testing.expectEqual(drops_before + 1, delivery_queue.cross_worker_drops.load(.monotonic));
}

test "R5: an unbuildable PEP self-notification is counted, never silent" {
    const posix = std.posix;
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var db = try server_mod.OpBackendType.open(path, .{});
    defer db.close();
    var roster = GenericRosterStore.init(&db);

    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();
    server.roster = &roster;
    server.worker_id = 0;
    var sm = session_map_mod.SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    server.session_map = &sm;
    var delivery_sys = try delivery_queue.DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();
    server.delivery_system = &delivery_sys;

    // The publisher's other resource lives on worker 1; the cross-worker
    // build is what overflows.
    _ = try sm.bind(1, 7, "alice", "localhost", "desk");
    sm.setPresenceAvailable("alice", "localhost", "desk", true);

    var fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM | std.c.SOCK.NONBLOCK, 0, &fds));
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    defer allocator.destroy(session);
    session.* = Session.init(fds[0], 0, server.server_host, false, allocator);
    defer session.deinit();
    session.stream.bound_jid = .{ .local = "alice", .domain = "localhost", .resource = "phone" };

    // A publisher JID wider than the 20 KiB bank: every per-resource
    // notification is unbuildable and the skip must be counted (R5).
    var big: [Server.BYTE_BANK_SIZE]u8 = undefined;
    @memset(&big, 'p');

    const drops_before = router.jid_overflow_drops.load(.monotonic);
    var scratch: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&scratch);
    sendPepNotification(&server, session, &big, "urn:xmpp:microblog:0", "i1", "<entry/>", &changes);
    try std.testing.expectEqual(drops_before + 1, router.jid_overflow_drops.load(.monotonic));
}
