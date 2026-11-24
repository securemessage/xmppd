//! # iq/carbons: XEP-0280 carbon-copy fan-out tests
//!
//! Tests moved out of server.zig (ADR-12). They exercise the cross-worker
//! received-carbon path through router.dispatchStanza and
//! routing/deliver.zig's drainDeliveryQueue; carbons has no production
//! decls yet, so server.zig force-references this file from its
//! sibling-analysis test block.

const std = @import("std");
const posix = std.posix;
const xmpp = @import("xmpp");
const server_mod = @import("../worker/worker.zig");
const Server = server_mod.Server;
const Session = server_mod.Session;
const OpBackendMod = @import("op_backend");
const OpBackendType = server_mod.OpBackendType;
const offline_store_mod = @import("generic_offline_store");
const GenericOfflineStore = offline_store_mod.GenericOfflineStore;
const session_map_mod = @import("session_map");
const SessionMap = session_map_mod.SessionMap;
const delivery_queue_mod = @import("delivery_queue");
const DeliverySystem = delivery_queue_mod.DeliverySystem;
const ChangeList = @import("../worker/loop.zig").ChangeList;
const c2s_session = @import("../c2s/session.zig");
const makeSocketPair = c2s_session.makeSocketPair;
const router = @import("../routing/router.zig");
const routing_deliver = @import("../routing/deliver.zig");

// A bare-JID dispatch routes the message to bob's phone on the other worker
// and queues a <received> carbon for it in the same drain. The phone never
// enabled carbons, so the consumer drops the copy and the wire carries only
// the routed stanza (XEP-0280 section 2).
test "carbons: a phone with carbons off on another worker gets only the routed message" {
    const allocator = std.testing.allocator;

    var sm = try SessionMap.init(allocator, 2, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var w0: Server = undefined;
    try w0.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;

    var w1: Server = undefined;
    try w1.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w1.deinit();
    w1.worker_id = 1;
    w1.session_map = &sm;
    w1.delivery_system = &delivery_sys;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.state = .active;
    phone.stream.authenticated = true;
    phone.stream.setBoundJid(.{ .local = "bob", .domain = "localhost", .resource = "phone" });
    w1.sessions[6] = phone;
    _ = try sm.bind(1, w1.sessionToken(6), "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice: Session = undefined;
    alice.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.setBoundJid(xmpp.Jid.parse("alice@localhost/mobile") catch null);
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-off";
    const body = "<body>once</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var w0_changes_buf: [64]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    router.dispatchStanza(&w0, &alice, &w0_changes);

    var w1_changes_buf: [32]posix.Kevent = undefined;
    var w1_changes = ChangeList.init(&w1_changes_buf);
    routing_deliver.drainDeliveryQueue(&w1, &w1_changes);

    _ = phone.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const wire_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expect(wire_len > 0);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, wire[0..wire_len], "<message"));
    try std.testing.expect(std.mem.indexOf(u8, wire[0..wire_len], "urn:xmpp:carbons:2") == null);
}

// The message went to bob's desktop full JID, so the phone on the other
// worker did not receive it under RFC 6121 rules: its <received> carbon is
// the only stanza the cross-worker path owes it. A carbon is an outer
// <message> wrapping a <forwarded> inner one, so the wire carries exactly
// two <message opens for the single copy.
test "carbons: a Carbons-enabled resource on another worker gets exactly one carbon" {
    const allocator = std.testing.allocator;

    var sm = try SessionMap.init(allocator, 2, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var w0: Server = undefined;
    try w0.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;

    const desk_fds = try makeSocketPair();
    defer posix.close(desk_fds[1]);
    const desk = try allocator.create(Session);
    desk.init(desk_fds[0], 5, "localhost", false, allocator);
    desk.stream.state = .active;
    desk.stream.authenticated = true;
    desk.stream.setBoundJid(.{ .local = "bob", .domain = "localhost", .resource = "desktop" });
    w0.sessions[5] = desk;
    _ = try sm.bind(0, w0.sessionToken(5), "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    var w1: Server = undefined;
    try w1.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w1.deinit();
    w1.worker_id = 1;
    w1.session_map = &sm;
    w1.delivery_system = &delivery_sys;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.state = .active;
    phone.stream.authenticated = true;
    phone.stream.setBoundJid(.{ .local = "bob", .domain = "localhost", .resource = "phone" });
    phone.carbons_enabled = true;
    w1.sessions[6] = phone;
    _ = try sm.bind(1, w1.sessionToken(6), "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice: Session = undefined;
    alice.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.setBoundJid(xmpp.Jid.parse("alice@localhost/mobile") catch null);
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost/desktop";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-on";
    const body = "<body>copy me</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var w0_changes_buf: [64]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    router.dispatchStanza(&w0, &alice, &w0_changes);

    var w1_changes_buf: [32]posix.Kevent = undefined;
    var w1_changes = ChangeList.init(&w1_changes_buf);
    routing_deliver.drainDeliveryQueue(&w1, &w1_changes);

    _ = phone.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const wire_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expect(wire_len > 0);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, wire[0..wire_len], "<received xmlns='urn:xmpp:carbons:2'"));
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, wire[0..wire_len], "<message"));
    try std.testing.expect(std.mem.indexOf(u8, wire[0..wire_len], "copy me") != null);
}

// The same dispatch, but the phone never enabled carbons: it was not a
// delivery target, so the producer queued a carbon for it, and the
// receiving worker applies carbons_enabled and drops it on the floor.
test "carbons: a cross-worker carbon to a disabled resource is dropped" {
    const allocator = std.testing.allocator;

    var sm = try SessionMap.init(allocator, 2, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var w0: Server = undefined;
    try w0.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;

    const desk_fds = try makeSocketPair();
    defer posix.close(desk_fds[1]);
    const desk = try allocator.create(Session);
    desk.init(desk_fds[0], 5, "localhost", false, allocator);
    desk.stream.state = .active;
    desk.stream.authenticated = true;
    desk.stream.setBoundJid(.{ .local = "bob", .domain = "localhost", .resource = "desktop" });
    w0.sessions[5] = desk;
    _ = try sm.bind(0, w0.sessionToken(5), "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    var w1: Server = undefined;
    try w1.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w1.deinit();
    w1.worker_id = 1;
    w1.session_map = &sm;
    w1.delivery_system = &delivery_sys;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.state = .active;
    phone.stream.authenticated = true;
    phone.stream.setBoundJid(.{ .local = "bob", .domain = "localhost", .resource = "phone" });
    phone.carbons_enabled = false;
    w1.sessions[6] = phone;
    _ = try sm.bind(1, w1.sessionToken(6), "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice: Session = undefined;
    alice.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.setBoundJid(xmpp.Jid.parse("alice@localhost/mobile") catch null);
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost/desktop";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-drop";
    const body = "<body>not for you</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var w0_changes_buf: [64]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    router.dispatchStanza(&w0, &alice, &w0_changes);

    var w1_changes_buf: [32]posix.Kevent = undefined;
    var w1_changes = ChangeList.init(&w1_changes_buf);
    routing_deliver.drainDeliveryQueue(&w1, &w1_changes);

    _ = phone.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const wire_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expectEqual(@as(usize, 0), wire_len);
}

// A carbon is delivered live or not at all: while the phone drains its
// offline tail, the original (held for the desktop's tail) is the only row
// the store ever sees. The carbon itself reaches the phone's wire; it is
// never held behind the tail and never bounced.
test "carbons: a draining worker delivers the carbon live and stores no carbon row" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = try SessionMap.init(allocator, 2, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var w0: Server = undefined;
    try w0.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;
    w0.offline = &offline_store;

    const desk_fds = try makeSocketPair();
    defer posix.close(desk_fds[1]);
    const desk = try allocator.create(Session);
    desk.init(desk_fds[0], 5, "localhost", false, allocator);
    desk.offline_pending = true;
    desk.stream.setBoundJid(.{ .local = "bob", .domain = "localhost", .resource = "desktop" });
    w0.sessions[5] = desk;
    _ = try sm.bind(0, w0.sessionToken(5), "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    var w1: Server = undefined;
    try w1.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w1.deinit();
    w1.worker_id = 1;
    w1.session_map = &sm;
    w1.delivery_system = &delivery_sys;
    w1.offline = &offline_store;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.offline_pending = true;
    phone.carbons_enabled = true;
    phone.stream.setBoundJid(.{ .local = "bob", .domain = "localhost", .resource = "phone" });
    w1.sessions[6] = phone;
    _ = try sm.bind(1, w1.sessionToken(6), "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice: Session = undefined;
    alice.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.setBoundJid(xmpp.Jid.parse("alice@localhost/mobile") catch null);
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost/desktop";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-drain";
    const body = "<body>held for desk</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var w0_changes_buf: [64]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    router.dispatchStanza(&w0, &alice, &w0_changes);

    var w1_changes_buf: [32]posix.Kevent = undefined;
    var w1_changes = ChangeList.init(&w1_changes_buf);
    routing_deliver.drainDeliveryQueue(&w1, &w1_changes);

    // The carbon went out live; the draining tail never owned it.
    _ = phone.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const wire_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expect(wire_len > 0);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..wire_len], "urn:xmpp:carbons:2") != null);

    // Only the routed message is held, for the desktop's tail. No row
    // anywhere carries the carbon namespace.
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    var carbon_rows: usize = 0;
    for (ptrs) |ptr| {
        const held = try offline_store.getHeldStanza(ptr) orelse continue;
        defer allocator.free(held);
        if (std.mem.indexOf(u8, held, "urn:xmpp:carbons:2") != null) carbon_rows += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    try std.testing.expectEqual(@as(usize, 0), carbon_rows);
}

// The bare-JID message already reached the phone under RFC 6121 delivery
// rules, so a <received> carbon would hand it the same stanza twice. The
// producer skips delivered resources before the worker split, so the rule
// holds wherever the resource lives (XEP-0280 section 7).
test "carbons: a delivered resource gets no received copy on the same dispatch" {
    const allocator = std.testing.allocator;

    var sm = try SessionMap.init(allocator, 2, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var w0: Server = undefined;
    try w0.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;

    var w1: Server = undefined;
    try w1.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w1.deinit();
    w1.worker_id = 1;
    w1.session_map = &sm;
    w1.delivery_system = &delivery_sys;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.state = .active;
    phone.stream.authenticated = true;
    phone.stream.setBoundJid(.{ .local = "bob", .domain = "localhost", .resource = "phone" });
    phone.carbons_enabled = true;
    w1.sessions[6] = phone;
    _ = try sm.bind(1, w1.sessionToken(6), "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice: Session = undefined;
    alice.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.setBoundJid(xmpp.Jid.parse("alice@localhost/mobile") catch null);
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-dupe";
    const body = "<body>no dupe</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var w0_changes_buf: [64]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    router.dispatchStanza(&w0, &alice, &w0_changes);

    var w1_changes_buf: [32]posix.Kevent = undefined;
    var w1_changes = ChangeList.init(&w1_changes_buf);
    routing_deliver.drainDeliveryQueue(&w1, &w1_changes);

    _ = phone.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const wire_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expect(wire_len > 0);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, wire[0..wire_len], "<message"));
    try std.testing.expect(std.mem.indexOf(u8, wire[0..wire_len], "urn:xmpp:carbons:2") == null);
}

// Same rule on the local branch: a phone with carbons on the sending
// worker also already received the bare-JID original.
test "carbons: the local received-carbon path skips a resource that got the original" {
    const allocator = std.testing.allocator;

    var sm = try SessionMap.init(allocator, 2, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var w0: Server = undefined;
    try w0.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.state = .active;
    phone.stream.authenticated = true;
    phone.stream.setBoundJid(.{ .local = "bob", .domain = "localhost", .resource = "phone" });
    phone.carbons_enabled = true;
    w0.sessions[6] = phone;
    _ = try sm.bind(0, w0.sessionToken(6), "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice: Session = undefined;
    alice.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.setBoundJid(xmpp.Jid.parse("alice@localhost/mobile") catch null);
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-dupe-local";
    const body = "<body>no dupe</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var w0_changes_buf: [64]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    router.dispatchStanza(&w0, &alice, &w0_changes);

    _ = phone.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const wire_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expect(wire_len > 0);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, wire[0..wire_len], "<message"));
    try std.testing.expect(std.mem.indexOf(u8, wire[0..wire_len], "urn:xmpp:carbons:2") == null);
}

// The delivered set is what the delivery loop actually handed the stanza
// to, not a recompute of the routing rule. A CSI-inactive phone is skipped
// for a typing-only message, so it never saw the original: a <received>
// carbon to it is the only copy it gets, on the bare-JID fan-out and on a
// full-JID dispatch alike.
test "carbons: a resource the delivery loop skipped still gets the received carbon" {
    const allocator = std.testing.allocator;

    var sm = try SessionMap.init(allocator, 2, 0);
    defer sm.deinit();

    var w0: Server = undefined;
    try w0.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.state = .active;
    phone.stream.authenticated = true;
    phone.stream.setBoundJid(.{ .local = "bob", .domain = "localhost", .resource = "phone" });
    phone.carbons_enabled = true;
    phone.csi_active = false;
    w0.sessions[6] = phone;
    _ = try sm.bind(0, w0.sessionToken(6), "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const laptop_fds = try makeSocketPair();
    defer posix.close(laptop_fds[1]);
    const laptop = try allocator.create(Session);
    laptop.init(laptop_fds[0], 5, "localhost", false, allocator);
    laptop.stream.state = .active;
    laptop.stream.authenticated = true;
    laptop.stream.setBoundJid(.{ .local = "bob", .domain = "localhost", .resource = "laptop" });
    laptop.carbons_enabled = true;
    w0.sessions[5] = laptop;
    _ = try sm.bind(0, w0.sessionToken(5), "bob", "localhost", "laptop");
    sm.setPresenceAvailable("bob", "localhost", "laptop", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice: Session = undefined;
    alice.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.setBoundJid(xmpp.Jid.parse("alice@localhost/mobile") catch null);
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-csi";
    const body = "<composing xmlns='http://jabber.org/protocol/chatstates'/>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var changes_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&changes_buf);
    router.dispatchStanza(&w0, &alice, &changes);

    // Bare JID: the laptop got the original and no carbon; the phone was
    // skipped in delivery so the carbon is its only copy.
    _ = laptop.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const laptop_len = posix.read(laptop_fds[1], &wire) catch 0;
    try std.testing.expect(laptop_len > 0);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, wire[0..laptop_len], "<message"));
    try std.testing.expect(std.mem.indexOf(u8, wire[0..laptop_len], "urn:xmpp:carbons:2") == null);

    _ = phone.conn.flushSend() catch 0;
    const phone_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expect(phone_len > 0);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..phone_len], "<received xmlns='urn:xmpp:carbons:2'>") != null);

    // Full JID to the same skipped phone: the routed set is not the
    // delivered set here either, so the phone again gets the carbon.
    // dispatchStanza resets the stanza fields, so rebuild them all.
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost/phone";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-csi-full";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;
    router.dispatchStanza(&w0, &alice, &changes);

    _ = phone.conn.flushSend() catch 0;
    const full_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expect(full_len > 0);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..full_len], "<received xmlns='urn:xmpp:carbons:2'>") != null);
}

// The private hint only counts as a top-level child of the stanza. The
// same strings nested inside a <forwarded/> payload are content, not a
// hint, so the carbon still flows to a resource that never saw the
// original.
test "carbons: a nested private-looking payload does not suppress the carbon" {
    const allocator = std.testing.allocator;

    var sm = try SessionMap.init(allocator, 2, 0);
    defer sm.deinit();

    var w0: Server = undefined;
    try w0.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.state = .active;
    phone.stream.authenticated = true;
    phone.stream.setBoundJid(.{ .local = "bob", .domain = "localhost", .resource = "phone" });
    phone.carbons_enabled = true;
    w0.sessions[6] = phone;
    _ = try sm.bind(0, w0.sessionToken(6), "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const watch_fds = try makeSocketPair();
    defer posix.close(watch_fds[1]);
    const watch = try allocator.create(Session);
    watch.init(watch_fds[0], 5, "localhost", false, allocator);
    watch.stream.state = .active;
    watch.stream.authenticated = true;
    watch.stream.setBoundJid(.{ .local = "bob", .domain = "localhost", .resource = "watch" });
    watch.carbons_enabled = true;
    w0.sessions[5] = watch;
    _ = try sm.bind(0, w0.sessionToken(5), "bob", "localhost", "watch");
    sm.setPresenceAvailable("bob", "localhost", "watch", true);
    sm.setPriority("bob", "localhost", "watch", -1);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice: Session = undefined;
    alice.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.setBoundJid(xmpp.Jid.parse("alice@localhost/mobile") catch null);
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "carb-nested";
    const body = "<body>see this</body><forwarded xmlns='urn:xmpp:forward:0'><message from='mallory@x/a' to='bob@localhost/phone'><private xmlns='urn:xmpp:carbons:2'/></message></forwarded>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var changes_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&changes_buf);
    router.dispatchStanza(&w0, &alice, &changes);

    _ = watch.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const watch_len = posix.read(watch_fds[1], &wire) catch 0;
    try std.testing.expect(watch_len > 0);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..watch_len], "<received xmlns='urn:xmpp:carbons:2'>") != null);
}

// A <private/> child asks the server not to carbon copy the message at all
// (XEP-0280 section 6), and a <no-copy/> hint does the same (XEP-0334).
// Both suppress the copy on the cross-worker path, so the phone's wire
// stays empty.
test "carbons: private and no-copy hints suppress the cross-worker carbon" {
    const allocator = std.testing.allocator;

    var sm = try SessionMap.init(allocator, 2, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var w0: Server = undefined;
    try w0.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;

    const desk_fds = try makeSocketPair();
    defer posix.close(desk_fds[1]);
    const desk = try allocator.create(Session);
    desk.init(desk_fds[0], 5, "localhost", false, allocator);
    desk.stream.state = .active;
    desk.stream.authenticated = true;
    desk.stream.setBoundJid(.{ .local = "bob", .domain = "localhost", .resource = "desktop" });
    w0.sessions[5] = desk;
    _ = try sm.bind(0, w0.sessionToken(5), "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    var w1: Server = undefined;
    try w1.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w1.deinit();
    w1.worker_id = 1;
    w1.session_map = &sm;
    w1.delivery_system = &delivery_sys;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.state = .active;
    phone.stream.authenticated = true;
    phone.stream.setBoundJid(.{ .local = "bob", .domain = "localhost", .resource = "phone" });
    phone.carbons_enabled = true;
    w1.sessions[6] = phone;
    _ = try sm.bind(1, w1.sessionToken(6), "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice: Session = undefined;
    alice.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.setBoundJid(xmpp.Jid.parse("alice@localhost/mobile") catch null);
    alice.stanza_kind = .message;
    alice.stanza_type = "chat";

    const inners = [_][]const u8{
        "<body>shh</body><private xmlns='urn:xmpp:carbons:2'/>",
        "<body>shh</body><no-copy xmlns='urn:xmpp:hints'/>",
    };
    var w0_changes_buf: [64]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    var w1_changes_buf: [32]posix.Kevent = undefined;
    var w1_changes = ChangeList.init(&w1_changes_buf);

    for (inners, 0..) |inner, round| {
        alice.stanza_to = "bob@localhost/desktop";
        alice.stanza_id = if (round == 0) "carb-priv" else "carb-nocopy";
        @memcpy(alice.stanza_buf[0..inner.len], inner);
        alice.stanza_buf_len = inner.len;
        router.dispatchStanza(&w0, &alice, &w0_changes);
        routing_deliver.drainDeliveryQueue(&w1, &w1_changes);
    }

    _ = phone.conn.flushSend() catch 0;
    var wire: [8192]u8 = undefined;
    const wire_len = posix.read(phone_fds[1], &wire) catch 0;
    try std.testing.expectEqual(@as(usize, 0), wire_len);
}
