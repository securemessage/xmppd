//! # routing/deliver: cross-worker delivery drain, holds and bounces
//!
//! The MPSC delivery-queue drain, the offline-tail hold and the bounce
//! paths moved out of server.zig (ADR-12). Functions take the worker as
//! `self: *Server`; tests exercise the drain and hold semantics through
//! both the c2s dispatchStanza and the S2S dispatchS2sResponse entries.

const std = @import("std");
const posix = std.posix;
const xml = @import("xml");
const xmpp = @import("xmpp");
const ipc_protocol = @import("ipc_protocol");
const server_mod = @import("../worker/worker.zig");
const Server = server_mod.Server;
const Session = server_mod.Session;
const TestIpcListener = server_mod.TestIpcListener;
const ChangeList = @import("../worker/loop.zig").ChangeList;
const c2s_session = @import("../c2s/session.zig");
const makeSocketPair = c2s_session.makeSocketPair;
const c2s_sm = @import("../c2s/sm.zig");
const sm_state = @import("../c2s/sm_state.zig");
const archive_store_mod = @import("archive_store");
const ArchiveBackendType = ArchiveBackendMod.Backend;
const session_lifecycle = @import("../c2s/lifecycle.zig");
const session_map_mod = @import("session_map");
const SessionMap = session_map_mod.SessionMap;
const SessionEntry = session_map_mod.SessionEntry;
const delivery_queue_mod = @import("delivery_queue");
const DeliverySystem = delivery_queue_mod.DeliverySystem;
const Token = delivery_queue_mod.Token;
const token_kinds = @import("token_kinds");
const stanza_facts = @import("../stanza/facts.zig");
const stanza_writer = @import("../stanza/writer.zig");
const fanout_mod = @import("../muc/fanout.zig");
const room_registry_mod = @import("room_registry");
const metrics = @import("../worker/metrics.zig");
const offline_store_mod = @import("generic_offline_store");
const GenericOfflineStore = offline_store_mod.GenericOfflineStore;
const OpBackendMod = @import("op_backend");
const OpBackendType = OpBackendMod.Backend;
const ArchiveBackendMod = @import("archive_backend");
const router = @import("router.zig");
const muc_actor = @import("../muc/actor.zig");

const log = std.log.scoped(.xmppd);

/// Park a message behind a session's draining offline tail. The held bytes
/// are authoritative; archive metadata is retained only for fallback reads.
///
/// Returns true when the message is held, which includes the case where this
/// dispatch is already held for this bare JID: the tail is per bare JID, so
/// every draining resource and every worker holding one sees the same
/// message and must not add a second row for it. `token` identifies the
/// dispatch, so two messages with identical bytes stay two rows.
pub fn holdBehindOfflineTail(
    self: *Server,
    target: *Session,
    local: []const u8,
    domain: []const u8,
    from_jid: []const u8,
    stanza_id: []const u8,
    timestamp: u64,
    stanza_xml: []const u8,
    token: offline_store_mod.HoldToken,
) bool {
    if (!target.offline_pending) return false;
    const store = self.offline orelse return false;
    var recipient_buf: [router.BARE_JID_MAX]u8 = undefined;
    const recipient = router.buildBareJid(local, domain, &recipient_buf) catch return false;
    const outcome = store.storeHeldPointerOnce(recipient, from_jid, stanza_id, timestamp, stanza_xml, token) catch |err| {
        log.warn("message to {s} could not be held behind the offline tail: {s}", .{ recipient, @errorName(err) });
        return false;
    };
    return switch (outcome) {
        .stored, .already_held => true,
        .full => false,
    };
}

/// Return a service-unavailable error over the inbound S2S link.
pub fn bounceS2sInbound(self: *Server, remote_from: []const u8, local_to: []const u8, tag_name: []const u8, stanza_id: []const u8) void {
    _ = sendS2sError(self, remote_from, local_to, tag_name, stanza_id);
}

/// Serialize and queue a service-unavailable bounce for an inbound S2S
/// stanza. Returns false when the bounce could not be handed to the S2S
/// daemon, so callers can count and log the refusal instead of assuming
/// the sender was told.
pub fn sendS2sError(self: *Server, remote_from: []const u8, local_to: []const u8, tag_name: []const u8, stanza_id: []const u8) bool {
    if (!self.s2s_ipc.connected) {
        log.warn("S2S bounce for {s} dropped: no S2S daemon", .{remote_from});
        return false;
    }

    var lease = self.leaseByteScratch() orelse return false;
    defer lease.release();
    var fbs = std.io.fixedBufferStream(lease.buf);
    stanza_writer.writeS2sError(fbs.writer(), tag_name, local_to, remote_from, stanza_id) catch {
        log.warn("S2S bounce for {s} dropped: serialization failed", .{remote_from});
        return false;
    };

    self.s2s_ipc.send(.{ .s2s_deliver = .{
        .from_jid = local_to,
        .to_jid = remote_from,
        .stanza_xml = fbs.getWritten(),
    } }) catch {
        log.err("failed to bounce S2S inbound for {s}", .{remote_from});
        return false;
    };
    _ = delivery_queue_mod.s2s_bounces.fetchAdd(1, .monotonic);
    // Write interest: reconcileIpcWriteInterest (S10).
    return true;
}

/// Tell the sender of a cross-worker stanza that it could not be held
/// behind the recipient's draining offline tail. The sender may live on
/// another worker, so the bounce is routed through the session map and
/// the MPSC queue the same way a delivery is.
fn bounceCrossWorkerUnavailable(
    self: *Server,
    sender_wire: []const u8,
    recipient_bare: []const u8,
    stanza_id: []const u8,
    tag_name: []const u8,
    changes: *ChangeList,
) void {
    _ = changes; // Sends dirty-link the conn for the batch-tail flush (ADR-2).
    const sm = self.session_map orelse return;
    // sender_wire is the raw on-wire attribute, still entity-encoded.
    var sender_buf: [512]u8 = undefined;
    var sender_fbs = std.io.fixedBufferStream(&sender_buf);
    xml.decodeWrite(sender_fbs.writer(), sender_wire) catch {
        log.warn("cross-worker bounce dropped: sender attribute does not decode", .{});
        return;
    };
    const sender_full = sender_fbs.getWritten();
    const sender = xmpp.Jid.parse(sender_full) catch {
        log.warn("cross-worker bounce for {s} dropped: unparsable sender", .{sender_full});
        return;
    };
    if (sender.resource.len == 0) {
        log.warn("cross-worker bounce for {s} dropped: sender is a bare JID", .{sender_full});
        return;
    }
    const entry = sm.findByFullJid(sender.local, sender.domain, sender.resource) orelse {
        log.warn("cross-worker bounce for {s} dropped: sender session gone", .{sender_full});
        return;
    };

    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    stanza_writer.writeCrossWorkerError(fbs.writer(), tag_name, recipient_bare, sender_full, stanza_id) catch {
        log.warn("cross-worker bounce for {s} dropped: serialization failed", .{sender_full});
        return;
    };
    const stanza = fbs.getWritten();

    if (entry.worker_id == self.worker_id) {
        const session = self.sessionForEventToken(entry.token) orelse {
            log.warn("cross-worker bounce for {s} dropped: sender slot empty", .{sender_full});
            return;
        };
        if (session.stanza(stanza) == .failed_closed) {
            log.warn("cross-worker bounce for {s} not queued: {s}", .{ sender_full, if (session.conn.isClosed()) "ConnectionClosed" else "WriteBufferFull" });
            return;
        }
    } else if (self.delivery_system) |ds| {
        ds.deliver(self.worker_id, entry.worker_id, entry.token, stanza) catch {
            _ = delivery_queue_mod.cross_worker_drops.fetchAdd(1, .monotonic);
            log.warn("cross-worker bounce for {s} dropped: delivery queue full", .{sender_full});
            return;
        };
    } else {
        log.warn("cross-worker bounce for {s} dropped: no delivery system", .{sender_full});
        return;
    }
    _ = delivery_queue_mod.offline_hold_bounces.fetchAdd(1, .monotonic);
}

/// Handle EVFILT_READ on the wake pipe — drain pipe bytes, then drain the MPSC queue,
/// then drain per-room mailboxes.
pub fn handleDeliveryWake(self: *Server, changes: *ChangeList) void {
    const ds = self.delivery_system orelse return;
    if (metrics.get()) |c| metrics.bump(&c.wakes, 1);
    ds.drainPipe(self.worker_id);
    drainDeliveryQueue(self, changes);
    _ = muc_actor.drainRoomMailboxes(self, changes);
}

/// Drain all pending deliveries from this worker's MPSC queue.
/// Session tokens are validated against this worker's slot generations
/// (ADR-4); a stale token is counted and dropped.
pub fn drainDeliveryQueue(self: *Server, changes: *ChangeList) void {
    const ds = self.delivery_system orelse return;
    const queue = ds.getQueue(self.worker_id);

    const Ctx = struct {
        server: *Server,
        changes: *ChangeList,
        queue: *delivery_queue_mod.MpscQueue,
    };
    const ctx = Ctx{ .server = self, .changes = changes, .queue = queue };

    _ = queue.drain(ctx, struct {
        fn handle(c: Ctx, target: Token, payload: []const u8) void {
            switch (target.kind) {
                // Multicast delivery: fan-out to all local occupants in a room
                token_kinds.multicast => {
                    handleMulticastDelivery(c.server, payload, c.changes);
                    return;
                },
                // Room actor message: decode and dispatch to local room shard
                token_kinds.room_actor => {
                    muc_actor.handleRoomActorMessage(c.server, payload, c.changes);
                    return;
                },
                // SM resume handoff actor message (T177)
                token_kinds.sm_actor => {
                    c2s_sm.handleSmActorMessage(c.server, payload, c.changes);
                    return;
                },
                token_kinds.session => {},
                else => {
                    c.server.stale_token_skips += 1;
                    return;
                },
            }

            // Unicast: the slot generation check replaces the session-map
            // scan. A token minted for a freed-then-reused slot fails here.
            const target_session = c.server.sessionForEventToken(target) orelse return;
            const local_session_id = target.index;
            const parts = stanza_facts.extractStanzaParts(payload);
            // XEP-0280 sections 2 and 7: a carbon copy reaches only a
            // Carbons-enabled resource, live or not at all. The producer
            // tags the slot so the same per-session policy the local
            // carbon path applies (sendCarbons -> deliverToSession,
            // which never holds) applies to a remote target: it is
            // never held behind a draining offline tail, never stored
            // and never bounced.
            const is_carbon = c.queue.current_slot_kind == .carbon;
            if (is_carbon and !target_session.carbons_enabled) return;
            // The hold check comes before the SM-detach check: a detached
            // session may still have an undrained offline tail, and a
            // message pushed into its replay queue would be replayed
            // ahead of that tail (H3). The c2s router orders them the
            // same way.
            if (target_session.offline_pending and !is_carbon and parts.is_message and !std.mem.eql(u8, parts.msg_type, "error")) {
                const hold_id = if (parts.msg_id.len > 0) parts.msg_id else "offline";
                // Stamp the producer's receipt time, not the time a busy
                // consumer worker got to the slot.
                const timestamp: u64 = if (c.queue.current_slot_receipt_ts != 0)
                    c.queue.current_slot_receipt_ts
                else
                    @intCast(std.time.timestamp());
                const from_jid = stanza_facts.extractAttrValue(payload, "from");
                const bound = target_session.stream.bound_jid orelse {
                    log.warn("cross-worker message to session {d} has no bound recipient for its offline hold", .{local_session_id});
                    return;
                };
                // A producer that minted a token (the router, S2S inbound)
                // has every worker holding a resource of this bare JID
                // collapse the same dispatch. A producer that did not gets
                // a token here, so the message is still stored; only the
                // cross-worker collapse is lost, never the message.
                const token = if (c.queue.current_slot_token != 0)
                    c.queue.current_slot_token
                else
                    c.server.mintHoldToken();
                if (holdBehindOfflineTail(c.server, target_session, bound.local, bound.domain, from_jid, hold_id, timestamp, payload, token)) return;
                // The stanza can neither be held nor sent without
                // overtaking the draining tail. Tell the sender rather
                // than dropping it (H2), as the c2s router does.
                var recip_buf: [router.BARE_JID_MAX]u8 = undefined;
                const recipient_bare = router.buildBareJid(bound.local, bound.domain, &recip_buf) catch "";
                log.warn("cross-worker message to session {d} not held, bouncing to the sender", .{local_session_id});
                if (recipient_bare.len > 0) {
                    bounceCrossWorkerUnavailable(c.server, from_jid, recipient_bare, parts.msg_id, "message", c.changes);
                }
                return;
            }
            // stanza() covers the T153 detached case itself: it tracks
            // for resume replay and reports tracked_detached.
            if (target_session.stanza(payload) == .failed_closed) return;
        }
    }.handle);
}

/// Handle a multicast delivery from the MPSC queue.
/// Decodes the payload (room_jid + prefix + suffix), finds the room,
/// and delivers the pre-built stanza to all local occupants.
fn handleMulticastDelivery(self: *Server, payload: []const u8, changes: *ChangeList) void {
    _ = changes; // Sends dirty-link the conn for the batch-tail flush (ADR-2).
    const decoded = fanout_mod.decodeMulticastPayload(payload) orelse {
        log.warn("malformed multicast payload ({d} bytes)", .{payload.len});
        return;
    };

    const reg = self.room_registry orelse return;
    const room = reg.findByJid(decoded.room_jid) orelse return;

    // One delivery buffer reused for every local occupant (S18). The
    // prefix and suffix read here live in the decoded multicast payload.
    var deliver_lease = self.leaseByteScratch() orelse return;
    defer deliver_lease.release();

    for (&room.occupants) |*slot| {
        const occ = slot.* orelse continue;
        if (occ.worker_id != self.worker_id) continue;
        if (occ.isRemote()) continue;

        const target_session = self.sessionForEventToken(occ.token) orelse continue;
        fanout_mod.deliverPrebuiltToSession(target_session, deliver_lease.buf, decoded.prefix, occ.getRealJid(), decoded.suffix, occ.token.index);
    }
}

/// Encode and enqueue a multicast delivery to each remote worker that has
/// occupants in the given room. Iterates set bits in worker_mask, excluding self.
/// The payload is serialized once into one refcounted blob that every
/// target ring shares (ADR-3).
pub fn deliverMulticastToWorkers(self: *Server, room: *const room_registry_mod.Room, prefix: []const u8, suffix: []const u8) void {
    const ds = self.delivery_system orelse return;

    var mcast_lease = self.leaseByteScratch() orelse {
        log.err("byte-scratch exhausted; multicast for room {s} dropped", .{room.getJid()});
        return;
    };
    defer mcast_lease.release();
    const mcast_len = fanout_mod.encodeMulticastPayload(mcast_lease.buf, room.getJid(), prefix, suffix) orelse {
        log.warn("multicast payload too large for room {s}", .{room.getJid()});
        return;
    };
    const blob = ds.produceBlob(self.worker_id, mcast_lease.buf[0..mcast_len]) catch |err| {
        log.warn("multicast blob for room {s} refused: {}", .{ room.getJid(), err });
        return;
    };
    defer blob.release();

    // Iterate set bits in worker_mask, excluding self
    var mask = room.worker_mask;
    mask.unset(self.worker_id);
    var mask_it = mask.iterator(.{});
    while (mask_it.next()) |bit| {
        const wid: u16 = @intCast(bit);
        ds.deliverBlob(wid, delivery_queue_mod.MULTICAST_TARGET, blob, 0, 0, .stanza) catch |err| {
            log.warn("multicast delivery failed to worker {d}: {}", .{ wid, err });
        };
    }
}

test "cross-thread delivery: enqueue and drain" {
    const allocator = std.testing.allocator;

    // Set up shared infrastructure
    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    // Create a server that acts as worker 1 (the one draining)
    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 1;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;

    // Create a target session on worker 1 using a socketpair
    // Local session ID = 5
    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.init(fds[0], 5, "localhost", false, allocator);
    server.sessions[5] = session;

    // Bind in session map (session slot = 5, worker = 1)
    try sm.bind(1, server.sessionToken(5), "bob", "localhost", "desktop");

    // Simulate a cross-thread enqueue FROM worker 0 TO session 5 on worker 1
    const route = sm.findByFullJid("bob", "localhost", "desktop").?;
    try std.testing.expectEqual(@as(u16, 1), route.worker_id);
    try std.testing.expect(route.token.eql(server.sessionToken(5)));

    // Build a stanza and enqueue it (as if worker 0 is sending)
    try delivery_sys.deliver(server.worker_id, route.worker_id, route.token, "<message from='alice@localhost/mobile' to='bob@localhost' type='chat'><body>cross-thread!</body></message>");

    // Worker 1 drains its queue
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    drainDeliveryQueue(&server, &changes);

    // The session should now have pending write data
    try std.testing.expect(session.conn.hasPendingWrite());

    // Flush and read from the client side of the socketpair
    _ = try session.conn.flushSend();
    var buf: [4096]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    const received = buf[0..n];

    // Verify the stanza arrived intact
    try std.testing.expect(std.mem.indexOf(u8, received, "cross-thread!") != null);
    try std.testing.expect(std.mem.indexOf(u8, received, "alice@localhost/mobile") != null);
    try std.testing.expect(std.mem.indexOf(u8, received, "bob@localhost") != null);
}

test "cross-thread delivery: a token minted for a freed-then-reused slot is dropped (ADR-4)" {
    const allocator = std.testing.allocator;

    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 1;
    server.delivery_system = &delivery_sys;

    // Slot 5 holds session A at generation 1; its token is minted now.
    const fds_a = try makeSocketPair();
    defer posix.close(fds_a[1]);
    const session_a = try allocator.create(Session);
    session_a.init(fds_a[0], 5, "localhost", false, allocator);
    server.sessions[5] = session_a;
    const stale = server.sessionToken(5);

    // The slot is freed and a different session reuses it at generation 2.
    server.sessions[5] = null;
    server.releaseSessionSlot(5);
    session_a.deinit();
    allocator.destroy(session_a);
    const fds_b = try makeSocketPair();
    defer posix.close(fds_b[1]);
    const session_b = try allocator.create(Session);
    session_b.init(fds_b[0], 5, "localhost", false, allocator);
    server.sessions[5] = session_b;
    const fresh = server.sessionToken(5);
    try std.testing.expectEqual(stale.index, fresh.index);
    try std.testing.expect(fresh.gen > stale.gen);

    // A delivery minted against generation 1 must not reach session B.
    try delivery_sys.deliver(0, 1, stale, "<message type='chat'><body>stale!</body></message>");
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    drainDeliveryQueue(&server, &changes);
    try std.testing.expect(!session_b.conn.hasPendingWrite());
    try std.testing.expectEqual(@as(u64, 1), server.stale_token_skips);

    // The generation-2 token still resolves: delivery reaches session B.
    try delivery_sys.deliver(0, 1, fresh, "<message type='chat'><body>fresh!</body></message>");
    drainDeliveryQueue(&server, &changes);
    try std.testing.expect(session_b.conn.hasPendingWrite());
}

test "V13: shadow multicast to a freed-then-reused slot is not delivered (ADR-4)" {
    const allocator = std.testing.allocator;

    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 1;
    server.delivery_system = &delivery_sys;

    // The shadow room on this worker records an occupant addressed at
    // session A in slot 5, generation 1.
    var reg = room_registry_mod.RoomRegistry.init(allocator);
    defer reg.deinit();
    server.room_registry = &reg;
    const room = try reg.createRoom("hall@conference.localhost", .{ .persistent = false });
    const fds_a = try makeSocketPair();
    defer posix.close(fds_a[1]);
    const session_a = try allocator.create(Session);
    session_a.init(fds_a[0], 5, "localhost", false, allocator);
    server.sessions[5] = session_a;
    const stale = server.sessionToken(5);
    _ = try room.addOccupant("alice", "alice@localhost/m", "alice@localhost", stale, 1, .participant, .none);

    // The slot is freed (generation bumps) and a new session reuses it.
    server.sessions[5] = null;
    server.releaseSessionSlot(5);
    session_a.deinit();
    allocator.destroy(session_a);
    const fds_b = try makeSocketPair();
    defer posix.close(fds_b[1]);
    const session_b = try allocator.create(Session);
    session_b.init(fds_b[0], 5, "localhost", false, allocator);
    server.sessions[5] = session_b;

    // A multicast arriving for the stale occupant record must not reach
    // session B; the skip is counted like any other stale token.
    var mcast_buf: [256]u8 = undefined;
    const mcast_len = fanout_mod.encodeMulticastPayload(&mcast_buf, room.getJid(), "<message to='", "'/>") orelse unreachable;
    try delivery_sys.deliver(0, 1, delivery_queue_mod.MULTICAST_TARGET, mcast_buf[0..mcast_len]);
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    drainDeliveryQueue(&server, &changes);
    try std.testing.expect(!session_b.conn.hasPendingWrite());
    try std.testing.expectEqual(@as(u64, 1), server.stale_token_skips);
}

test "S35: the cross-worker hold stamps the producer receipt time" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 16);
    defer server.deinit();
    server.worker_id = 1;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try allocator.create(Session);
    session.init(fds[0], 5, "localhost", false, allocator);
    session.stream.state = .features_bind;
    session.stream.authenticated = true;
    session.stream.authenticated_jid = xmpp.Jid{ .local = "bob", .domain = "localhost" };
    session.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "desktop" };
    session.offline_pending = true;
    server.sessions[5] = session;
    try sm.bind(1, server.sessionToken(5), "bob", "localhost", "desktop");

    // The producer tags the slot with its own receipt time; the hold on the
    // consuming worker must store that time, not the time the drain ran.
    try delivery_sys.deliverDelivery(0, 1, server.sessionToken(5), "<message from='alice@localhost' to='bob@localhost' id='cw1'><body>held</body></message>", 42, 12345, .stanza);
    drainDeliveryQueue(&server, &changes);

    session_lifecycle.drainOfflinePending(&server, session, &changes);

    _ = try session.conn.flushSend();
    var buf: [2048]u8 = undefined;
    const n = posix.read(fds[1], &buf) catch 0;
    const wire = buf[0..n];
    // 12345 seconds past the epoch, not the consumer-side wall clock.
    try std.testing.expect(std.mem.indexOf(u8, wire, "stamp='1970-01-01T03:25:45Z'") != null);
}

test "cross-thread delivery: generation mismatch drops stanza" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var server: Server = undefined;
    try server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;

    // Bind a session, then unbind (simulating disconnect); a token minted
    // for a different slot generation is stale on arrival.
    try sm.bind(0, server.sessionToken(3), "alice", "localhost", "mobile");
    _ = sm.unbind("alice", "localhost", "mobile");
    const stale = Token.init(3, server.slot_gen[3] + 1, token_kinds.session);
    try delivery_sys.deliver(0, 0, stale, "<message>stale</message>");

    // Drain — should silently drop (generation mismatch)
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    drainDeliveryQueue(&server, &changes);

    // No session at slot 3, so nothing should crash or write
    try std.testing.expect(server.sessions[3] == null);
}

test "Server: S13 message held behind a draining offline tail" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    try tmp.dir.makePath("archive");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    const arch_path = try tmp.dir.realpathAlloc(allocator, "archive");
    defer allocator.free(arch_path);

    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var arch_db = try ArchiveBackendMod.Backend.open(arch_path, .{});
    defer arch_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);
    var arch_store = archive_store_mod.ArchiveStore(ArchiveBackendType).init(&arch_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();

    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;
    server.archive = &arch_store;

    // bob is online but his offline tail is still draining (S13).
    const target_fds = try makeSocketPair();
    defer posix.close(target_fds[1]);
    const target = try allocator.create(Session);
    target.init(target_fds[0], 5, "localhost", false, allocator);
    target.offline_pending = true;
    server.sessions[5] = target;

    _ = try sm.bind(0, server.sessionToken(5), "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice: Session = undefined;
    alice.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "m1";
    const body = "<body>held</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    // Not delivered live: it would overtake the draining tail.
    _ = target.conn.flushSend() catch {};
    var buf: [1024]u8 = undefined;
    const n = posix.read(target_fds[1], &buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n);

    _ = alice.conn.flushSend() catch {};
    const sender_n = posix.read(alice_fds[1], &buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), sender_n);

    // Parked behind the tail instead: one offline pointer whose held copy
    // carries the stanza itself, so the drain does not depend on an archive
    // row the async writer queue may not have committed yet (E2a).
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    const held = try offline_store.getHeldStanza(ptrs[0]);
    try std.testing.expect(held != null);
    if (held) |h| {
        defer allocator.free(h);
        try std.testing.expect(std.mem.indexOf(u8, h, "<body>held</body>") != null);
    }
}

// Two draining resources on one worker ask to hold the same message. The
// store would collapse them, but the second ask must not happen at all: it
// would log a second hold and count a second dispatch.
test "Re-review 6.8: the router holds a bare-JID message once per worker" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();

    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;

    for ([_]struct { id: u32, res: []const u8 }{ .{ .id = 5, .res = "desktop" }, .{ .id = 6, .res = "phone" } }) |r| {
        const fds = try makeSocketPair();
        defer posix.close(fds[1]);
        const sess = try allocator.create(Session);
        sess.init(fds[0], r.id, "localhost", false, allocator);
        sess.offline_pending = true;
        server.sessions[r.id] = sess;
        _ = try sm.bind(0, server.sessionToken(r.id), "bob", "localhost", r.res);
        sm.setPresenceAvailable("bob", "localhost", r.res, true);
    }

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice: Session = undefined;
    alice.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "r1b";
    const body = "<body>one hold</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    // One row, and exactly one store call: the second resource short-circuits
    // on the flag instead of asking the store to collapse it.
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    try std.testing.expectEqual(@as(u32, 1), offline_store.test_hold_calls);
}

// The S2S inbound loop keeps its own per-worker flag for the same reason: two
// draining resources of one bare JID ask once, not twice.
test "Re-review 6.8: the S2S hold asks the store once per worker" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();

    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;

    for ([_]struct { id: u32, res: []const u8 }{ .{ .id = 5, .res = "desktop" }, .{ .id = 6, .res = "phone" } }) |r| {
        const fds = try makeSocketPair();
        defer posix.close(fds[1]);
        const sess = try allocator.create(Session);
        sess.init(fds[0], r.id, "localhost", false, allocator);
        sess.offline_pending = true;
        server.sessions[r.id] = sess;
        _ = try sm.bind(0, server.sessionToken(r.id), "bob", "localhost", r.res);
        sm.setPresenceAvailable("bob", "localhost", r.res, true);
    }

    const stanza = "<message from='carol@example.com/res' to='bob@localhost' id='r1c' type='chat'><body>one hold</body></message>";
    var change_buf: [32]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = stanza,
    } }, &changes);

    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    try std.testing.expectEqual(@as(u32, 1), offline_store.test_hold_calls);
}

test "Server: G3 cross-worker delivery parks behind a draining offline tail" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();
    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;

    const target_fds = try makeSocketPair();
    defer posix.close(target_fds[1]);
    const target = try allocator.create(Session);
    target.init(target_fds[0], 5, "localhost", false, allocator);
    target.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch null;
    target.offline_pending = true;
    server.sessions[5] = target;
    _ = try sm.bind(0, server.sessionToken(5), "bob", "localhost", "desktop");
    const entry = sm.findByFullJid("bob", "localhost", "desktop") orelse return error.MissingSession;

    const payload = "<message from='alice@localhost/mobile' to='bob@localhost' id='q1' type='chat'><body>queued</body></message>";
    try delivery_sys.deliver(0, 0, entry.token, payload);
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    drainDeliveryQueue(&server, &changes);

    _ = target.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(target_fds[1], &buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n);
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    const pointers = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 1), pointers.len);
    try std.testing.expectEqualStrings("q1", pointers[0].stanza_id);
    const held = try offline_store.getHeldStanza(pointers[0]);
    try std.testing.expect(held != null);
    defer if (held) |xml_bytes| allocator.free(xml_bytes);
    try std.testing.expectEqualStrings(payload, held.?);
}

test "Server: G3 inbound S2S delivery parks behind a draining offline tail" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.offline = &offline_store;

    const target_fds = try makeSocketPair();
    defer posix.close(target_fds[1]);
    const target = try allocator.create(Session);
    target.init(target_fds[0], 5, "localhost", false, allocator);
    target.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch null;
    target.offline_pending = true;
    server.sessions[5] = target;
    _ = try sm.bind(0, server.sessionToken(5), "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    const payload = "<message from='carol@example.com/res' to='bob@localhost' id='s1' type='chat'><body>federated-tail</body></message>";
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = payload,
    } }, &changes);

    _ = target.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(target_fds[1], &buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n);
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    const pointers = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 1), pointers.len);
    try std.testing.expectEqualStrings("s1", pointers[0].stanza_id);
    const held = try offline_store.getHeldStanza(pointers[0]);
    try std.testing.expect(held != null);
    defer if (held) |xml_bytes| allocator.free(xml_bytes);
    try std.testing.expectEqualStrings(payload, held.?);
}

test "Server: G3 type normal parks behind a draining offline tail" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.offline = &offline_store;

    const target_fds = try makeSocketPair();
    defer posix.close(target_fds[1]);
    const target = try allocator.create(Session);
    target.init(target_fds[0], 5, "localhost", false, allocator);
    target.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch null;
    target.offline_pending = true;
    server.sessions[5] = target;
    _ = try sm.bind(0, server.sessionToken(5), "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice: Session = undefined;
    alice.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "normal";
    alice.stanza_id = "n1";
    const body = "<body>normal-tail</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;
    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    _ = target.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(target_fds[1], &buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), n);
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    const pointers = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(pointers);
    try std.testing.expectEqual(@as(usize, 1), pointers.len);
    try std.testing.expectEqualStrings("n1", pointers[0].stanza_id);
    const held = try offline_store.getHeldStanza(pointers[0]);
    try std.testing.expect(held != null);
    defer if (held) |xml_bytes| allocator.free(xml_bytes);
    try std.testing.expect(std.mem.indexOf(u8, held.?, "<body>normal-tail</body>") != null);
}

// H4: the G3 tests above start with an empty store, so none of them proves
// that a live message lands behind rows that were already queued. Each of
// these starts with a stored row and checks both the pointer order and the
// order the drain puts on the wire.
test "Server: H4 a cross-worker message lands behind an existing offline tail" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    try tmp.dir.makePath("archive");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    const arch_path = try tmp.dir.realpathAlloc(allocator, "archive");
    defer allocator.free(arch_path);

    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var arch_db = try ArchiveBackendMod.Backend.open(arch_path, .{});
    defer arch_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);
    var arch_store = archive_store_mod.ArchiveStore(ArchiveBackendType).init(&arch_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();
    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;
    server.archive = &arch_store;

    // The row bob never received, stored before anything live arrives.
    const tail = "<message from='alice@localhost/mobile' to='bob@localhost' id='tail-0' type='chat'><body>tail</body></message>";
    try std.testing.expect(try offline_store.storeHeldPointer("bob@localhost", "alice@localhost/mobile", "tail-0", 1000, tail));

    const target_fds = try makeSocketPair();
    defer posix.close(target_fds[1]);
    const target = try allocator.create(Session);
    target.init(target_fds[0], 5, "localhost", false, allocator);
    target.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch null;
    target.offline_pending = true;
    server.sessions[5] = target;
    try sm.bind(0, server.sessionToken(5), "bob", "localhost", "desktop");

    const live = "<message from='alice@localhost/mobile' to='bob@localhost' id='live-1' type='chat'><body>live</body></message>";
    try delivery_sys.deliver(0, 0, server.sessionToken(5), live);

    var change_buf: [32]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    drainDeliveryQueue(&server, &changes);

    // Both are in the store, and the live one is behind the tail.
    try std.testing.expectEqual(@as(usize, 2), try offline_store.countMessages("bob@localhost"));
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    try std.testing.expectEqual(@as(usize, 2), ptrs.len);
    try std.testing.expectEqualStrings("tail-0", ptrs[0].stanza_id);
    try std.testing.expectEqualStrings("live-1", ptrs[1].stanza_id);

    // The drain puts the tail on the wire first.
    session_lifecycle.deliverOfflineMessages(&server, target, "bob", "localhost", &changes);
    _ = target.conn.flushSend() catch {};
    var wire = std.ArrayList(u8){};
    defer wire.deinit(allocator);
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = posix.read(target_fds[1], &buf) catch break;
        if (n == 0) break;
        try wire.appendSlice(allocator, buf[0..n]);
    }
    try std.testing.expect(!target.offline_pending);
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));
    const tail_at = std.mem.indexOf(u8, wire.items, "<body>tail</body>");
    const live_at = std.mem.indexOf(u8, wire.items, "<body>live</body>");
    try std.testing.expect(tail_at != null);
    try std.testing.expect(live_at != null);
    try std.testing.expect(tail_at.? < live_at.?);
}

// E2b: an inbound S2S stanza for an offline local user is stored with its
// payload, and a full offline queue bounces back over the same link instead of
// dropping the stanza silently.
test "Server: E2b an inbound S2S stanza for an offline user holds its payload" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    try tmp.dir.makePath("archive");
    var dir_path: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_path);
    var sock_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&sock_buf, "{s}/s2s.sock", .{dir});

    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    const arch_path = try tmp.dir.realpathAlloc(allocator, "archive");
    defer allocator.free(arch_path);

    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var arch_db = try ArchiveBackendMod.Backend.open(arch_path, .{});
    defer arch_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);
    var arch_store = archive_store_mod.ArchiveStore(ArchiveBackendType).init(&arch_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();

    var listener = try TestIpcListener.init(sock_path);
    defer listener.deinit();

    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;
    server.archive = &arch_store;
    try server.configureS2s(sock_path);
    try std.testing.expect(server.s2s_ipc.connected);

    // Accept the daemon side so the bounce frame can be read back. Non-blocking:
    // this test asserts that nothing was sent.
    const daemon_fd = try posix.accept(listener.fd, null, null, posix.SOCK.NONBLOCK);
    defer posix.close(daemon_fd);

    // bob is offline: no session bound anywhere.
    const stanza = "<message from='carol@example.com/res' to='bob@localhost' id='r1' type='chat'><body>federated</body></message>";
    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = stanza,
    } }, &changes);

    // The pointer carries the payload, so a drain cannot depend on the archive
    // row landing first.
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    try std.testing.expectEqual(@as(usize, 1), ptrs.len);

    const held = try offline_store.getHeldStanza(ptrs[0]);
    try std.testing.expect(held != null);
    defer if (held) |h| allocator.free(h);
    try std.testing.expect(std.mem.indexOf(u8, held.?, "<body>federated</body>") != null);

    // Nothing was bounced back to the remote sender.
    _ = server.s2s_ipc.flush() catch {};
    var frame_buf: [4096]u8 = undefined;
    const got = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), got);

    changes.reset();
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = "<message from='carol@example.com/res' to='bob@localhost' id='gc1' type='groupchat'><body>not offline</body></message>",
    } }, &changes);
    _ = server.s2s_ipc.flush() catch {};
    const groupchat_n = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expect(groupchat_n > 0);
    const groupchat_frame = try ipc_protocol.parseFrame(frame_buf[0..groupchat_n]);
    try std.testing.expect(groupchat_frame != null);
    const groupchat_bounce = switch (try ipc_protocol.decode(groupchat_frame.?.payload)) {
        .s2s_deliver => |d| d,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(std.mem.indexOf(u8, groupchat_bounce.stanza_xml, "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, groupchat_bounce.stanza_xml, "id='gc1'") != null);
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
}

// H2: a message that cannot be held behind a draining offline tail has to
// bounce (and count) on every path, so the sender is never told nothing.
test "Server: H2 a cross-worker hold failure bounces to the sender on the same worker" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    // No offline store at all: the hold cannot succeed.

    // alice (the sender) lives on this worker.
    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    const alice = try allocator.create(Session);
    alice.init(alice_fds[0], 9, "localhost", false, allocator);
    server.sessions[9] = alice;
    _ = try sm.bind(0, server.sessionToken(9), "alice", "localhost", "mobile");
    const alice_bound = xmpp.Jid.parse("alice@localhost/mobile") catch unreachable;
    alice.stream.bound_jid = alice_bound;

    // bob (the recipient) lives here too, with a draining offline tail.
    const bob_fds = try makeSocketPair();
    defer posix.close(bob_fds[1]);
    const bob = try allocator.create(Session);
    bob.init(bob_fds[0], 5, "localhost", false, allocator);
    bob.offline_pending = true;
    bob.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch unreachable;
    server.sessions[5] = bob;
    try sm.bind(0, server.sessionToken(5), "bob", "localhost", "desktop");

    const stanza = "<message from='alice@localhost/mobile' to='bob@localhost' id='h2-1' type='chat'><body>hi</body></message>";
    try delivery_sys.deliver(0, 0, server.sessionToken(5), stanza);

    const bounces_before = delivery_queue_mod.offline_hold_bounces.load(.monotonic);
    var change_buf: [32]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    drainDeliveryQueue(&server, &changes);

    // alice is told the message was not accepted.
    const alice_n = try alice.conn.flushSend();
    try std.testing.expect(alice_n > 0);
    var buf: [4096]u8 = undefined;
    const n = posix.read(alice_fds[1], &buf) catch 0;
    const got = buf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, got, "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "id='h2-1'") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "from='bob@localhost'") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "to='alice@localhost/mobile'") != null);

    // bob's socket got nothing: the stanza never overtook his tail.
    _ = bob.conn.flushSend() catch {};
    var bbuf: [4096]u8 = undefined;
    const bn = posix.read(bob_fds[1], &bbuf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), bn);

    try std.testing.expectEqual(bounces_before + 1, delivery_queue_mod.offline_hold_bounces.load(.monotonic));
}

test "Server: H2 a cross-worker hold failure bounces across workers" {
    const allocator = std.testing.allocator;

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    // Worker 1 drains bob's queue; alice lives on worker 0.
    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 1;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;

    const bob_fds = try makeSocketPair();
    defer posix.close(bob_fds[1]);
    const bob = try allocator.create(Session);
    bob.init(bob_fds[0], 5, "localhost", false, allocator);
    bob.offline_pending = true;
    bob.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch unreachable;
    server.sessions[5] = bob;
    try sm.bind(1, server.sessionToken(5), "bob", "localhost", "desktop");

    _ = try sm.bind(0, server.sessionToken(9), "alice", "localhost", "mobile");

    const stanza = "<message from='alice@localhost/mobile' to='bob@localhost' id='h2-2' type='chat'><body>hi</body></message>";
    try delivery_sys.deliver(0, 1, server.sessionToken(5), stanza);

    var change_buf: [32]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    drainDeliveryQueue(&server, &changes);

    // bob got nothing.
    _ = bob.conn.flushSend() catch {};
    var bbuf: [4096]u8 = undefined;
    const bn = posix.read(bob_fds[1], &bbuf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), bn);

    // The bounce went back through worker 0's queue, generation-checked.
    const Seen = struct {
        count: usize = 0,
        session_id: u32 = 0,
        unavailable: bool = false,
        id_echo: bool = false,

        fn handle(self: *@This(), target: Token, payload: []const u8) void {
            self.count += 1;
            self.session_id = target.index;
            if (std.mem.indexOf(u8, payload, "service-unavailable") != null) self.unavailable = true;
            if (std.mem.indexOf(u8, payload, "id='h2-2'") != null) self.id_echo = true;
        }
    };
    var seen = Seen{};
    _ = delivery_sys.getQueue(0).drain(&seen, Seen.handle);
    try std.testing.expectEqual(@as(usize, 1), seen.count);
    try std.testing.expectEqual(@as(u32, 9), seen.session_id);
    try std.testing.expect(seen.unavailable);
    try std.testing.expect(seen.id_echo);
}

// H3: a detached session can still have an undrained offline tail. A live
// message must be parked behind that tail, not pushed into the SM replay
// queue, which would replay it ahead of the tail.
test "Server: H3 a cross-worker message to a detached session is held behind its tail" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();
    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const target = try allocator.create(Session);
    target.init(fds[0], 5, "localhost", false, allocator);
    target.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch null;
    target.sm_detached = true;
    target.sm_resume_enabled = true;
    target.sm_detach_time = std.time.timestamp();
    target.sm_id_len = sm_state.SM_ID_HEX_LEN;
    const sm_id = "11112222333344445555666677778888";
    @memcpy(&target.sm_id, sm_id);
    target.offline_pending = true;
    const queue = try allocator.create(sm_state.SmUnackedQueue);
    queue.* = sm_state.SmUnackedQueue.init(allocator);
    queue.base_seq = 1;
    target.sm_unacked = queue;
    server.sessions[5] = target;
    server.detached_count = 1;
    c2s_sm.smIdMapInsert(&server, &target.sm_id, 5);
    try sm.bind(0, server.sessionToken(5), "bob", "localhost", "desktop");

    const payload = "<message from='alice@localhost/mobile' to='bob@localhost' id='h3-1' type='chat'><body>live</body></message>";
    try delivery_sys.deliver(0, 0, server.sessionToken(5), payload);

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    drainDeliveryQueue(&server, &changes);

    // Nothing went into the replay queue: that would have replayed ahead of
    // the undrained tail.
    try std.testing.expectEqual(@as(u32, 0), queue.count);
    // Parked in the offline store instead.
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    const held = try offline_store.getHeldStanza(ptrs[0]);
    try std.testing.expect(held != null);
    if (held) |h| {
        defer allocator.free(h);
        try std.testing.expect(std.mem.indexOf(u8, h, "<body>live</body>") != null);
    }
    // The flag survives: the tail is still outstanding.
    try std.testing.expect(target.offline_pending);
}

test "Server: H2 an unstorable S2S hold behind a draining tail bounces" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    var dir_path: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_path);
    var sock_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&sock_buf, "{s}/s2s.sock", .{dir});

    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);

    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();

    var listener = try TestIpcListener.init(sock_path);
    defer listener.deinit();

    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;
    try server.configureS2s(sock_path);

    const daemon_fd = try posix.accept(listener.fd, null, null, posix.SOCK.NONBLOCK);
    defer posix.close(daemon_fd);

    // bob is online but his offline tail is still draining, and his queue is
    // at quota so the hold cannot succeed.
    const bob_fds = try makeSocketPair();
    defer posix.close(bob_fds[1]);
    const bob = try allocator.create(Session);
    bob.init(bob_fds[0], 5, "localhost", false, allocator);
    bob.offline_pending = true;
    server.sessions[5] = bob;
    _ = try sm.bind(0, server.sessionToken(5), "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var id_buf: [16]u8 = undefined;
        const sid = std.fmt.bufPrint(&id_buf, "q{d}", .{i}) catch unreachable;
        const stored = try offline_store.storePointer("bob@localhost", "carol@example.com", sid, 100 + @as(u64, @intCast(i)));
        try std.testing.expect(stored);
    }

    const stanza = "<message from='carol@example.com/res' to='bob@localhost' id='h2-3' type='chat'><body>federated</body></message>";
    const bounces_before = delivery_queue_mod.s2s_bounces.load(.monotonic);
    var change_buf: [32]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = stanza,
    } }, &changes);

    // The remote sender learns the stanza was refused.
    _ = server.s2s_ipc.flush() catch {};
    var frame_buf: [4096]u8 = undefined;
    const got = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expect(got > 0);
    const frame = try ipc_protocol.parseFrame(frame_buf[0..got]);
    try std.testing.expect(frame != null);
    const bounced = switch (try ipc_protocol.decode(frame.?.payload)) {
        .s2s_deliver => |d| d,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("carol@example.com/res", bounced.to_jid);
    try std.testing.expect(std.mem.indexOf(u8, bounced.stanza_xml, "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, bounced.stanza_xml, "id='h2-3'") != null);
    try std.testing.expectEqual(bounces_before + 1, delivery_queue_mod.s2s_bounces.load(.monotonic));

    // Nothing was stored on top of the full queue, and bob's socket stayed
    // empty: the stanza did not overtake his tail.
    try std.testing.expectEqual(@as(usize, 100), try offline_store.countMessages("bob@localhost"));
    _ = bob.conn.flushSend() catch {};
    var bbuf: [4096]u8 = undefined;
    const bn = posix.read(bob_fds[1], &bbuf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), bn);
}

test "Server: E2b a full offline queue bounces the inbound S2S stanza" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    try tmp.dir.makePath("archive");
    var dir_path: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_path);
    var sock_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&sock_buf, "{s}/s2s.sock", .{dir});

    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    const arch_path = try tmp.dir.realpathAlloc(allocator, "archive");
    defer allocator.free(arch_path);

    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var arch_db = try ArchiveBackendMod.Backend.open(arch_path, .{});
    defer arch_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);
    var arch_store = archive_store_mod.ArchiveStore(ArchiveBackendType).init(&arch_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();

    var listener = try TestIpcListener.init(sock_path);
    defer listener.deinit();

    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;
    server.archive = &arch_store;
    try server.configureS2s(sock_path);

    const daemon_fd = try posix.accept(listener.fd, null, null, posix.SOCK.NONBLOCK);
    defer posix.close(daemon_fd);

    // Fill bob's offline queue to the per-user maximum.
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var id_buf: [16]u8 = undefined;
        const sid = std.fmt.bufPrint(&id_buf, "q{d}", .{i}) catch unreachable;
        const stored = try offline_store.storePointer("bob@localhost", "carol@example.com", sid, 100 + @as(u64, @intCast(i)));
        try std.testing.expect(stored);
    }

    const stanza = "<message from='carol@example.com/res' to='bob@localhost' id='r2' type='chat'><body>too much</body></message>";
    const bounces_before = delivery_queue_mod.s2s_bounces.load(.monotonic);
    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = stanza,
    } }, &changes);

    // The queue stayed exactly at quota: nothing new was accepted.
    try std.testing.expectEqual(@as(usize, 100), try offline_store.countMessages("bob@localhost"));

    // The remote sender learns the stanza was dropped rather than being told
    // it was delivered.
    _ = server.s2s_ipc.flush() catch {};
    var frame_buf: [4096]u8 = undefined;
    const got = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expect(got > 0);
    const frame = try ipc_protocol.parseFrame(frame_buf[0..got]);
    try std.testing.expect(frame != null);
    const msg = try ipc_protocol.decode(frame.?.payload);
    const delivered = switch (msg) {
        .s2s_deliver => |d| d,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("carol@example.com/res", delivered.to_jid);
    try std.testing.expect(std.mem.indexOf(u8, delivered.stanza_xml, "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, delivered.stanza_xml, "id='r2'") != null);
    try std.testing.expectEqual(bounces_before + 1, delivery_queue_mod.s2s_bounces.load(.monotonic));
}

// E2b: with no offline store the inbound message still bounces rather than
// vanishing, and an inbound error stanza is never bounced back (two servers
// would otherwise trade bounces forever).
test "Server: E2b an unstorable inbound S2S stanza bounces but an error stanza does not" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_path: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_path);
    var sock_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&sock_buf, "{s}/s2s.sock", .{dir});

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();

    var listener = try TestIpcListener.init(sock_path);
    defer listener.deinit();

    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    // No offline store, no archive: nothing here can hold the stanza.
    try server.configureS2s(sock_path);

    const daemon_fd = try posix.accept(listener.fd, null, null, posix.SOCK.NONBLOCK);
    defer posix.close(daemon_fd);

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = "<message from='carol@example.com/res' to='bob@localhost' id='r3' type='chat'><body>hello</body></message>",
    } }, &changes);

    _ = server.s2s_ipc.flush() catch {};
    var frame_buf: [4096]u8 = undefined;
    const got = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expect(got > 0);
    const frame = try ipc_protocol.parseFrame(frame_buf[0..got]);
    try std.testing.expect(frame != null);
    const bounced = switch (try ipc_protocol.decode(frame.?.payload)) {
        .s2s_deliver => |d| d,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(std.mem.indexOf(u8, bounced.stanza_xml, "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, bounced.stanza_xml, "id='r3'") != null);

    // An error stanza for the same offline recipient is dropped without a
    // reply, so the bounce cannot come back as another bounce.
    changes.reset();
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = "<message from='carol@example.com/res' to='bob@localhost' id='r4' type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
    } }, &changes);

    _ = server.s2s_ipc.flush() catch {};
    const second = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), second);

    changes.reset();
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = "<iq from='carol@example.com/res' to='bob@localhost' id='q1' type='get'><query xmlns='jabber:iq:version'/></iq>",
    } }, &changes);
    _ = server.s2s_ipc.flush() catch {};
    const iq_n = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expect(iq_n > 0);
    const iq_frame = try ipc_protocol.parseFrame(frame_buf[0..iq_n]);
    try std.testing.expect(iq_frame != null);
    const iq_bounce = switch (try ipc_protocol.decode(iq_frame.?.payload)) {
        .s2s_deliver => |d| d,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(std.mem.startsWith(u8, iq_bounce.stanza_xml, "<iq type='error'"));
    try std.testing.expect(std.mem.indexOf(u8, iq_bounce.stanza_xml, "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, iq_bounce.stanza_xml, "id='q1'") != null);

    changes.reset();
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = "<iq from='carol@example.com/res' to='bob@localhost' id='q2' type='result'><query xmlns='jabber:iq:version'/></iq>",
    } }, &changes);
    _ = server.s2s_ipc.flush() catch {};
    const iq_result_n = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), iq_result_n);
}

// G7: an inbound id carrying an XML entity is escaped exactly once through the
// real parse and bounce path.
test "Server: G7 an inbound id with an entity is escaped once in the bounce" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_path: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_path);
    var sock_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&sock_buf, "{s}/s2s.sock", .{dir});

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();

    var listener = try TestIpcListener.init(sock_path);
    defer listener.deinit();

    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    // No offline store: the stanza bounces.
    try server.configureS2s(sock_path);

    const daemon_fd = try posix.accept(listener.fd, null, null, posix.SOCK.NONBLOCK);
    defer posix.close(daemon_fd);

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = "<message from='carol@example.com/res' to='bob@localhost' id='a&amp;b' type='chat'><body>hello</body></message>",
    } }, &changes);

    _ = server.s2s_ipc.flush() catch {};
    var frame_buf: [4096]u8 = undefined;
    const got = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expect(got > 0);
    const frame = try ipc_protocol.parseFrame(frame_buf[0..got]);
    try std.testing.expect(frame != null);
    const bounced = switch (try ipc_protocol.decode(frame.?.payload)) {
        .s2s_deliver => |d| d,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(std.mem.indexOf(u8, bounced.stanza_xml, "id='a&amp;b'") != null);
    try std.testing.expect(std.mem.indexOf(u8, bounced.stanza_xml, "a&amp;amp;") == null);
}

// G7: a storage error, not only a full queue, bounces the inbound stanza. An
// over-long recipient makes the offline hold fail with KeyTooLong.
test "Server: G7 a storage error on the offline hold still bounces" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    var dir_path: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &dir_path);
    var sock_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sock_path = try std.fmt.bufPrint(&sock_buf, "{s}/s2s.sock", .{dir});
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);

    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();

    var listener = try TestIpcListener.init(sock_path);
    defer listener.deinit();

    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;
    try server.configureS2s(sock_path);

    const daemon_fd = try posix.accept(listener.fd, null, null, posix.SOCK.NONBLOCK);
    defer posix.close(daemon_fd);

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const long_to = "bob@" ++ ("d" ** 520);
    server.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = long_to,
        .stanza_xml = "<message from='carol@example.com/res' to='bob@localhost' id='r9' type='chat'><body>hello</body></message>",
    } }, &changes);

    _ = server.s2s_ipc.flush() catch {};
    var frame_buf: [4096]u8 = undefined;
    const got = posix.read(daemon_fd, &frame_buf) catch 0;
    try std.testing.expect(got > 0);
    const frame = try ipc_protocol.parseFrame(frame_buf[0..got]);
    try std.testing.expect(frame != null);
    const bounced = switch (try ipc_protocol.decode(frame.?.payload)) {
        .s2s_deliver => |d| d,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(std.mem.indexOf(u8, bounced.stanza_xml, "service-unavailable") != null);
}

// S13: when the offline queue is at quota the held copy cannot be stored.
// Dropping it silently lost the message, so the sender must be told.
test "Server: S13 hold at quota bounces instead of dropping silently" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    try tmp.dir.makePath("archive");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    const arch_path = try tmp.dir.realpathAlloc(allocator, "archive");
    defer allocator.free(arch_path);

    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var arch_db = try ArchiveBackendMod.Backend.open(arch_path, .{});
    defer arch_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);
    var arch_store = archive_store_mod.ArchiveStore(ArchiveBackendType).init(&arch_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();

    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;
    server.archive = &arch_store;

    // Fill bob's offline queue to MAX_PER_USER so the hold is refused.
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var id_buf: [16]u8 = undefined;
        const sid = std.fmt.bufPrint(&id_buf, "q{d}", .{i}) catch unreachable;
        const stored = try offline_store.storePointer("bob@localhost", "carol@localhost", sid, 100 + @as(u64, @intCast(i)));
        try std.testing.expect(stored);
    }

    // bob is online but his offline tail is still draining.
    const target_fds = try makeSocketPair();
    defer posix.close(target_fds[1]);
    const target = try allocator.create(Session);
    target.init(target_fds[0], 5, "localhost", false, allocator);
    target.offline_pending = true;
    server.sessions[5] = target;

    _ = try sm.bind(0, server.sessionToken(5), "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice: Session = undefined;
    alice.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "m1";
    const body = "<body>bounced</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    const hold_bounces_before = delivery_queue_mod.offline_hold_bounces.load(.monotonic);
    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    // The sender gets a service-unavailable error rather than silence.
    _ = alice.conn.flushSend() catch {};
    var buf: [4096]u8 = undefined;
    const n = posix.read(alice_fds[1], &buf) catch 0;
    const got = buf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, got, "service-unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "id='m1'") != null);

    // Nothing was held: the queue is still exactly at quota.
    try std.testing.expectEqual(@as(usize, 100), try offline_store.countMessages("bob@localhost"));
    try std.testing.expectEqual(hold_bounces_before + 1, delivery_queue_mod.offline_hold_bounces.load(.monotonic));

    // bob got nothing out of order.
    _ = target.conn.flushSend() catch {};
    var tbuf: [4096]u8 = undefined;
    const tn = posix.read(target_fds[1], &tbuf) catch 0;
    try std.testing.expectEqual(@as(usize, 0), tn);
}

// N1: the offline tail is per bare JID, but the hold decision is per session,
// so every draining resource asks to hold the same message. The store keeps one
// row per dispatch, and that row reaches whichever resource drains first. The
// other resource finds the tail empty and gets nothing: the tail is shared, not
// per resource.
test "N1: two draining resources hold a bare-JID message once" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 1);
    defer delivery_sys.deinit();

    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;

    const desktop_fds = try makeSocketPair();
    defer posix.close(desktop_fds[1]);
    const desktop = try allocator.create(Session);
    desktop.init(desktop_fds[0], 5, "localhost", false, allocator);
    desktop.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch unreachable;
    desktop.offline_pending = true;
    server.sessions[5] = desktop;
    _ = try sm.bind(0, server.sessionToken(5), "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.stream.bound_jid = xmpp.Jid.parse("bob@localhost/phone") catch unreachable;
    phone.offline_pending = true;
    server.sessions[6] = phone;
    _ = try sm.bind(0, server.sessionToken(6), "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice: Session = undefined;
    alice.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch unreachable;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "n1-1";
    const body = "<body>held once</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    router.dispatchStanza(&server, &alice, &changes);

    // One message, one row, however many resources are draining it.
    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));

    // The tail is per bare JID, so exactly one resource receives the message:
    // the first to drain. The second finds the tail empty and sends nothing.
    var delivered_copies: usize = 0;
    for ([_]*Session{ desktop, phone }) |session| {
        session_lifecycle.deliverOfflineMessages(&server, session, "bob", "localhost", &changes);
        _ = session.conn.flushSend() catch {};
        var wire: [8192]u8 = undefined;
        const fd = if (session == desktop) desktop_fds[1] else phone_fds[1];
        const got = posix.read(fd, &wire) catch 0;
        delivered_copies += std.mem.count(u8, wire[0..got], "<body>held once</body>");
    }
    try std.testing.expectEqual(@as(usize, 1), delivered_copies);
    try std.testing.expectEqual(@as(usize, 0), try offline_store.countMessages("bob@localhost"));
}

// N1: the same collapse has to hold across workers. The tail is one bare JID
// row, so a resource of bob on each worker both ask to hold the same message
// and the store must write it once, whichever worker wins the race.
// Two identical messages must stay two rows. A message with no server
// stanza-id (type='normal', no id) serializes identically on both dispatches,
// so only the token minted per dispatch can tell them apart.
test "N1: two identical stanza-less messages to a draining bare JID are two rows" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.worker_id = 0;
    server.session_map = &sm;
    server.offline = &offline_store;

    const desktop_fds = try makeSocketPair();
    defer posix.close(desktop_fds[1]);
    const desktop = try allocator.create(Session);
    desktop.init(desktop_fds[0], 5, "localhost", false, allocator);
    desktop.stream.bound_jid = xmpp.Jid.parse("bob@localhost/desktop") catch null;
    desktop.offline_pending = true;
    server.sessions[5] = desktop;
    _ = try sm.bind(0, server.sessionToken(5), "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice: Session = undefined;
    alice.init(alice_fds[0], 9, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch unreachable;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "normal";
    const body = "<body>otr</body>";

    var change_buf: [64]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // Two dispatches, byte-identical: type='normal' gets no stanza-id and the
    // client sent no id.
    var round: usize = 0;
    while (round < 2) : (round += 1) {
        // dispatchStanza consumes the parsed stanza, so each round rebuilds the
        // identical one from scratch.
        alice.stanza_kind = .message;
        alice.stanza_to = "bob@localhost";
        alice.stanza_type = "normal";
        alice.stanza_id = "";
        @memcpy(alice.stanza_buf[0..body.len], body);
        alice.stanza_buf_len = body.len;
        router.dispatchStanza(&server, &alice, &changes);
    }

    const got_rows = try offline_store.countMessages("bob@localhost");
    try std.testing.expectEqual(@as(usize, 2), got_rows);
}

// The same dispatch identity must survive the c2s router's hop through the
// delivery slot: the receiving worker reads the token off the slot instead of
// minting its own.
test "c2s: one routed message to two draining workers holds one row" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var w1: Server = undefined;
    try w1.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w1.deinit();
    w1.worker_id = 1;
    w1.session_map = &sm;
    w1.delivery_system = &delivery_sys;
    w1.offline = &offline_store;

    const desk_fds = try makeSocketPair();
    defer posix.close(desk_fds[1]);
    const desk = try allocator.create(Session);
    desk.init(desk_fds[0], 5, "localhost", false, allocator);
    desk.offline_pending = true;
    desk.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "desktop" };
    w1.sessions[5] = desk;
    _ = try sm.bind(1, w1.sessionToken(5), "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    var w0: Server = undefined;
    try w0.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;
    w0.offline = &offline_store;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.offline_pending = true;
    phone.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "phone" };
    w0.sessions[6] = phone;
    _ = try sm.bind(0, w0.sessionToken(6), "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const alice_fds = try makeSocketPair();
    defer posix.close(alice_fds[1]);
    var alice: Session = undefined;
    alice.init(alice_fds[0], 7, "localhost", false, allocator);
    defer alice.deinit();
    alice.stream.bound_jid = xmpp.Jid.parse("alice@localhost/mobile") catch null;
    alice.stanza_kind = .message;
    alice.stanza_to = "bob@localhost";
    alice.stanza_type = "chat";
    alice.stanza_id = "c2s-one";
    const body = "<body>one row</body>";
    @memcpy(alice.stanza_buf[0..body.len], body);
    alice.stanza_buf_len = body.len;

    var w1_changes_buf: [64]posix.Kevent = undefined;
    var w1_changes = ChangeList.init(&w1_changes_buf);
    router.dispatchStanza(&w1, &alice, &w1_changes);

    var w0_changes_buf: [32]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    drainDeliveryQueue(&w0, &w0_changes);

    // Count the routed message only. T-D689B13D: a <received> carbon to a
    // resource that got the original is never produced, and a carbon is
    // never held behind an offline tail, so no second row can appear.
    const ptrs = try offline_store.getPointers("bob@localhost");
    defer offline_store.freePointers(ptrs);
    var message_rows: usize = 0;
    for (ptrs) |ptr| {
        const held = try offline_store.getHeldStanza(ptr) orelse continue;
        defer allocator.free(held);
        if (std.mem.indexOf(u8, held, "urn:xmpp:carbons:2") != null) continue;
        if (std.mem.indexOf(u8, held, "from='alice@localhost/mobile' to='bob@localhost'") != null) message_rows += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), message_rows);
}

// An S2S dispatch that reaches one resource locally and another on a second
// worker must hold one row. The remote worker learns the dispatch identity
// from the delivery slot; a fresh token there would store the stanza twice.
test "S2S: one inbound stanza to two draining workers holds one row" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    // Worker 1 receives the stanza and owns the first resource of the bare JID.
    var w1: Server = undefined;
    try w1.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w1.deinit();
    w1.worker_id = 1;
    w1.session_map = &sm;
    w1.delivery_system = &delivery_sys;
    w1.offline = &offline_store;

    const desk_fds = try makeSocketPair();
    defer posix.close(desk_fds[1]);
    const desk = try allocator.create(Session);
    desk.init(desk_fds[0], 5, "localhost", false, allocator);
    desk.offline_pending = true;
    desk.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "desktop" };
    w1.sessions[5] = desk;
    _ = try sm.bind(1, w1.sessionToken(5), "bob", "localhost", "desktop");
    sm.setPresenceAvailable("bob", "localhost", "desktop", true);

    // Worker 0 owns the second resource, so the second target is remote.
    var w0: Server = undefined;
    try w0.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer w0.deinit();
    w0.worker_id = 0;
    w0.session_map = &sm;
    w0.delivery_system = &delivery_sys;
    w0.offline = &offline_store;

    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.offline_pending = true;
    phone.stream.bound_jid = .{ .local = "bob", .domain = "localhost", .resource = "phone" };
    w0.sessions[6] = phone;
    _ = try sm.bind(0, w0.sessionToken(6), "bob", "localhost", "phone");
    sm.setPresenceAvailable("bob", "localhost", "phone", true);

    const stanza = "<message from='carol@example.com/res' to='bob@localhost' id='h1' type='chat'><body>cross</body></message>";
    var w1_changes_buf: [32]posix.Kevent = undefined;
    var w1_changes = ChangeList.init(&w1_changes_buf);
    w1.dispatchS2sResponse(.{ .s2s_inbound = .{
        .from_jid = "carol@example.com/res",
        .to_jid = "bob@localhost",
        .stanza_xml = stanza,
    } }, &w1_changes);

    var w0_changes_buf: [32]posix.Kevent = undefined;
    var w0_changes = ChangeList.init(&w0_changes_buf);
    drainDeliveryQueue(&w0, &w0_changes);

    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
}

test "N1: two workers draining one bare JID hold a message once" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("op");
    const op_path = try tmp.dir.realpathAlloc(allocator, "op");
    defer allocator.free(op_path);
    var op_db = try OpBackendMod.Backend.open(op_path, .{});
    defer op_db.close();
    var offline_store = GenericOfflineStore(OpBackendType).init(&op_db, allocator);

    var sm = SessionMap.init(allocator, true, 0);
    defer sm.deinit();
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();

    var server: Server = undefined;
    try server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 64);
    defer server.deinit();
    server.session_map = &sm;
    server.delivery_system = &delivery_sys;
    server.offline = &offline_store;

    // One draining resource of bob per worker, same bare JID.
    server.worker_id = 0;
    const desk_fds = try makeSocketPair();
    defer posix.close(desk_fds[1]);
    const desk = try allocator.create(Session);
    desk.init(desk_fds[0], 5, "localhost", false, allocator);
    desk.offline_pending = true;
    server.sessions[5] = desk;
    _ = try sm.bind(0, server.sessionToken(5), "bob", "localhost", "desktop");

    server.worker_id = 1;
    const phone_fds = try makeSocketPair();
    defer posix.close(phone_fds[1]);
    const phone = try allocator.create(Session);
    phone.init(phone_fds[0], 6, "localhost", false, allocator);
    phone.offline_pending = true;
    server.sessions[6] = phone;
    _ = try sm.bind(1, server.sessionToken(6), "bob", "localhost", "phone");

    const stanza = "<message from='alice@localhost/mobile' to='bob@localhost' type='chat' id='n1-2'><body>cross</body></message>";
    const ts: u64 = 1700000000;

    // Both workers hold the same dispatch under the one token the producer
    // minted, so the store writes one row whichever worker wins.
    const token = server.mintHoldToken();
    try std.testing.expect(holdBehindOfflineTail(&server, desk, "bob", "localhost", "alice@localhost/mobile", "n1-2", ts, stanza, token));
    try std.testing.expect(holdBehindOfflineTail(&server, phone, "bob", "localhost", "alice@localhost/mobile", "n1-2", ts, stanza, token));

    try std.testing.expectEqual(@as(usize, 1), try offline_store.countMessages("bob@localhost"));
}
