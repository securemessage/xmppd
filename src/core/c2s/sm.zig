//! # c2s stream management: XEP-0198 state machine
//!
//! SM enable/resume, cross-worker resume handoff, session kicks, the SM-ID
//! map and redirect breadcrumbs moved out of server.zig (ADR-12). Functions
//! take the worker as `self: *Server`.

const std = @import("std");
const posix = std.posix;
const xml = @import("xml");
const xmpp = @import("xmpp");
const sasl = @import("sasl");
const precis = @import("precis_username");
const EventLoop = @import("../worker/loop.zig").EventLoop;
const ChangeList = @import("../worker/loop.zig").ChangeList;
const Connection = @import("../connection.zig").Connection;
pub const connection_mod = @import("../connection.zig");
const Listener = @import("../listener.zig").Listener;
const Event = @import("../worker/loop.zig").Event;

const ssl = @import("ssl");
const IpcClient = @import("ipc_client").IpcClient;
const ipc_protocol = @import("ipc_protocol");
const backend_mod = @import("backend");
const OpBackendMod = @import("op_backend");
pub const OpBackendType = OpBackendMod.Backend;
const generic_roster = @import("roster_store");
const GenericRosterStore = generic_roster.RosterStore(OpBackendType);
const Subscription = generic_roster.Subscription;
const session_map_mod = @import("session_map");
const SessionMap = session_map_mod.SessionMap;
const SessionEntry = session_map_mod.SessionEntry;

const delivery_queue_mod = @import("delivery_queue");
const DeliverySystem = delivery_queue_mod.DeliverySystem;
const offline_store_mod = @import("generic_offline_store");
const GenericOfflineStore = offline_store_mod.GenericOfflineStore;
const OfflinePointer = offline_store_mod.OfflinePointer;
const archive_store_mod = @import("archive_store");
const ArchiveBackendMod = @import("archive_backend");
const ArchiveBackendType = ArchiveBackendMod.Backend;
const archive_queue_mod = @import("archive_queue");
const vcard_store_mod = @import("vcard_store");
const GenericVCardStore = vcard_store_mod.VCardStore(OpBackendType);
const iq_handler = @import("../iq/dispatch.zig");
const muc_handler = @import("../muc/handler.zig");
const presence_handler = @import("../presence/handler.zig");
pub const sub_cache_mod = @import("../subscription_cache.zig");
pub const caps_mod = @import("../caps.zig");
const router = @import("../routing/router.zig");
const session_lifecycle = @import("lifecycle.zig");
const stanza_writer = @import("../stanza/writer.zig");
const stanza_facts = @import("../stanza/facts.zig");
const room_registry_mod = @import("room_registry");
const room_mailbox_mod = @import("room_mailbox");
const RoomRegistry = room_registry_mod.RoomRegistry;
const room_store_mod = @import("room_store");
const GenericRoomStore = room_store_mod.RoomStore(OpBackendType);
const fanout_mod = @import("../muc/fanout.zig");
const muc_actor = @import("../muc/actor.zig");
const FanoutQueue = fanout_mod.FanoutQueue;
const actor_message = @import("../xworker/envelope.zig");
pub const sm_state = @import("sm_state.zig");
const sm_handoff = @import("sm_handoff.zig");
const block_store_mod = @import("block_store");
const metrics = @import("../worker/metrics.zig");
const GenericBlockStore = block_store_mod.BlockStore(OpBackendType);
const pep_store_mod = @import("pep_store");
const GenericPepStore = pep_store_mod.PepStore(OpBackendType);

const server_mod = @import("../worker/worker.zig");
const Server = server_mod.Server;
const c2s_session = @import("session.zig");
const Session = c2s_session.Session;
const noteDrop = c2s_session.noteDrop;
const makeSocketPair = c2s_session.makeSocketPair;

const log = std.log.scoped(.xmppd);

/// T177: breadcrumb left when a detached session is handed off to another
/// worker. resolved hop-by-hop because the SM-ID prefix never updates.
pub const SmRedirect = struct {
    worker: u16,
    moved_at: i64,
};

/// Bound on redirect entries per worker; a full map evicts the oldest.
const MAX_SM_REDIRECTS: usize = 256;

/// Bound on redirect hops per request. A cycle means stale state — the
/// client gets item-not-found and full-rebinds.
const MAX_SM_REDIRECT_HOPS: u8 = 8;

/// Handle <enable xmlns='urn:xmpp:sm:3'/> — activate SM for this session.
/// If the client includes resume='true', session resumption is enabled and
/// an SM-ID is generated for future reconnection.
pub fn handleSmEnable(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
    _ = changes; // Sends dirty-link the conn for the batch-tail flush (ADR-2).
    session.sm_enabled = true;
    session.sm_in_h = 0;
    session.sm_out_h = 0;
    session.sm_out_seq = 0;

    // Check for resume='true' attribute
    var resume_requested = false;
    for (elem.attributes) |attr| {
        if (std.mem.eql(u8, attr.local_name, "resume")) {
            resume_requested = std.mem.eql(u8, attr.value, "true");
            break;
        }
    }

    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();

    if (resume_requested) {
        // Generate SM-ID and enable resume
        sm_state.generateSmId(self.worker_id, &session.sm_id);
        session.sm_id_len = sm_state.SM_ID_HEX_LEN;
        session.sm_resume_enabled = true;

        // Allocate unacked stanza queue
        const queue = self.allocator.create(sm_state.SmUnackedQueue) catch {
            log.err("connection {d} failed to allocate SM unacked queue", .{session.conn.id});
            // Fall back to SM without resume
            session.sm_resume_enabled = false;
            session.sm_id_len = 0;
            w.writeAll("<enabled xmlns='urn:xmpp:sm:3'/>") catch return;
            if (session.nonza(fbs.getWritten()) == .failed_closed) return;
            return;
        };
        queue.* = sm_state.SmUnackedQueue.init(self.allocator);
        session.sm_unacked = queue;

        w.writeAll("<enabled xmlns='urn:xmpp:sm:3' id='") catch return;
        w.writeAll(&session.sm_id) catch return;
        w.writeAll("' resume='true' max='") catch return;
        std.fmt.format(w, "{d}", .{sm_state.DEFAULT_RESUME_TIMEOUT}) catch return;
        w.writeAll("'/>") catch return;

        log.info("connection {d} stream management enabled with resume (id={s})", .{
            session.conn.id, &session.sm_id,
        });
    } else {
        w.writeAll("<enabled xmlns='urn:xmpp:sm:3'/>") catch return;
        log.info("connection {d} stream management enabled", .{session.conn.id});
    }

    if (session.nonza(fbs.getWritten()) == .failed_closed) return;
}

/// Handle <resume xmlns='urn:xmpp:sm:3' previd='...' h='N'/> — attempt session resume.
/// Finds the detached session by SM-ID, verifies the authenticated user matches,
/// transfers the resumed state to the current session, and replays unacked stanzas.
pub fn handleSmResume(self: *Server, session: *Session, elem: xml.Element, changes: *ChangeList) void {
    var previd: []const u8 = "";
    var h_value: u32 = 0;
    var h_found = false;

    for (elem.attributes) |attr| {
        if (std.mem.eql(u8, attr.local_name, "previd")) {
            previd = attr.value;
        } else if (std.mem.eql(u8, attr.local_name, "h")) {
            h_value = std.fmt.parseInt(u32, attr.value, 10) catch {
                // Malformed h must not silently become 0: that would
                // look like a backwards report and desync the replay
                // (S24).
                sendSmFailed(self, session, "bad-request", changes);
                return;
            };
            h_found = true;
        }
    }

    if (previd.len == 0 or !h_found) {
        sendSmFailed(self, session, "unexpected-request", changes);
        return;
    }

    // T177: SM-IDs embed the owning worker id (sm_state.generateSmId).
    // A resume arriving on the wrong worker goes through the cross-worker
    // handoff instead of failing item-not-found.
    if (muc_actor.getWorkerCount(self) > 1) {
        if (sm_state.workerIdFromSmId(previd)) |owner| {
            if (owner != self.worker_id and owner < muc_actor.getWorkerCount(self)) {
                startCrossWorkerResume(self, session, previd, h_value, owner, changes);
                return;
            }
        }
    }

    // Find the detached session with matching SM-ID
    const detached_id = findDetachedSession(self, previd) orelse {
        // T177: prefix routed here but the session was handed off —
        // follow the redirect breadcrumb instead of failing.
        if (muc_actor.getWorkerCount(self) > 1) {
            if (smRedirectLookup(self, previd)) |target| {
                if (target != self.worker_id and target < muc_actor.getWorkerCount(self)) {
                    startCrossWorkerResume(self, session, previd, h_value, target, changes);
                    return;
                }
            }
        }
        sendSmFailed(self, session, "item-not-found", changes);
        return;
    };

    const detached = self.sessions[detached_id] orelse {
        sendSmFailed(self, session, "item-not-found", changes);
        return;
    };

    // T178: the detached session's unacked queue overflowed in this event
    // batch — its replay queue is corrupt. Fail the resume as if the
    // session were already gone; reapOutboundOverflow destroys it at batch end.
    if (detached.sm_overflow) {
        sendSmFailed(self, session, "item-not-found", changes);
        return;
    }

    // Verify the authenticated user matches the detached session's user
    const auth_jid = session.stream.authenticated_jid orelse {
        sendSmFailed(self, session, "not-authorized", changes);
        return;
    };
    const detached_jid = detached.stream.bound_jid orelse {
        sendSmFailed(self, session, "item-not-found", changes);
        return;
    };

    if (!std.mem.eql(u8, auth_jid.local, detached_jid.local) or
        !std.mem.eql(u8, auth_jid.domain, detached_jid.domain))
    {
        sendSmFailed(self, session, "not-authorized", changes);
        return;
    }

    // Process client's h value — ack stanzas the client received before disconnect
    if (detached.sm_unacked) |queue| {
        switch (queue.ack(h_value)) {
            .ok => {},
            // XEP-0198 §4: h above the number sent fails the resume.
            .too_high => {
                sendSmFailed(self, session, "handled-count-too-high", changes);
                return;
            },
            // A backwards report means the client lost track of what it
            // already acked; replaying would redeliver stanzas it
            // processed (S24).
            .backwards => {
                sendSmFailed(self, session, "unexpected-request", changes);
                return;
            },
        }
    }

    // Snapshot local MUC occupancies (T177): the detached slot is torn
    // down below, so the room list must be captured now. Slices point
    // into Room structs, which stay alive across this handler.
    var move_rooms_buf: [sm_handoff.MAX_BUNDLE_ROOMS][]const u8 = undefined;
    var move_room_count: usize = 0;
    if (self.room_registry) |reg| {
        for (&reg.rooms) |*rslot| {
            const room = rslot.* orelse continue;
            if (!room.active) continue;
            for (&room.occupants) |*occ_slot| {
                const occ = occ_slot.* orelse continue;
                if (occ.worker_id == self.worker_id and occ.session_id == detached_id) {
                    if (move_room_count >= move_rooms_buf.len) {
                        log.warn("SM resume: session occupies more than {d} rooms — remaining occupancies will not migrate", .{sm_handoff.MAX_BUNDLE_ROOMS});
                        break;
                    }
                    move_rooms_buf[move_room_count] = room.getJid();
                    move_room_count += 1;
                }
            }
        }
    }

    // Transfer resumed state to the current session
    session.sm_enabled = true;
    session.sm_in_h = detached.sm_in_h;
    session.sm_out_h = h_value;
    session.sm_out_seq = detached.sm_out_seq;
    session.sm_resume_enabled = detached.sm_resume_enabled;
    session.sm_id = detached.sm_id;
    session.sm_id_len = detached.sm_id_len;
    session.sm_unacked = detached.sm_unacked;
    detached.sm_unacked = null; // Ownership transferred

    // Transfer XMPP session state — copy JID strings into session-owned buffers
    // because the detached session's buffers will be freed below.
    const d_username_len = detached.auth_username_len;
    @memcpy(session.auth_username_buf[0..d_username_len], detached.auth_username_buf[0..d_username_len]);
    session.auth_username_len = d_username_len;
    // Resource from the detached bound JID, not the bind accumulator:
    // bind_resource_len is reset to 0 after a successful bind dispatch
    // (parser accumulator reuse), but bound_jid.resource keeps pointing at
    // the buffer's still-intact contents.
    const d_resource_len = detached_jid.resource.len;
    @memcpy(session.bind_resource_buf[0..d_resource_len], detached_jid.resource);
    session.bind_resource_len = d_resource_len;
    session.stream.bound_jid = .{
        .local = session.auth_username_buf[0..d_username_len],
        .domain = self.server_host,
        .resource = session.bind_resource_buf[0..d_resource_len],
    };
    session.stream.authenticated_jid = .{
        .local = session.auth_username_buf[0..d_username_len],
        .domain = self.server_host,
    };
    session.stream.authenticated = true;
    session.stream.state = .active;
    session.roster_interested = detached.roster_interested;
    session.carbons_enabled = detached.carbons_enabled;
    session.offline_pending = detached.offline_pending;
    session.offline_last_sent_sequence = detached.offline_last_sent_sequence;
    @memcpy(
        session.last_presence_inner[0..detached.last_presence_inner_len],
        detached.last_presence_inner[0..detached.last_presence_inner_len],
    );
    session.last_presence_inner_len = detached.last_presence_inner_len;

    // Re-bind in session map: unbind old slot, bind new slot with same JID
    var bound_generation: ?u32 = null;
    if (self.session_map) |sm| {
        _ = sm.unbind(detached_jid.local, detached_jid.domain, detached_jid.resource);
        if (sm.bind(self.worker_id, @intCast(session.conn.id), detached_jid.local, detached_jid.domain, detached_jid.resource)) |gen| {
            bound_generation = gen;
        } else |err| {
            log.err("SM resume: session_map re-bind failed for {s}@{s}/{s}: {}", .{
                detached_jid.local, detached_jid.domain, detached_jid.resource, err,
            });
        }
    }

    // Clean up detached session bookkeeping before destroying
    if (self.detached_count > 0) self.detached_count -= 1;
    smIdMapRemove(self, detached.sm_id[0..detached.sm_id_len]);
    smRedirectDrop(self, previd); // session lives here again

    // Destroy the detached session (slot freed for reuse)
    detached.sm_resume_enabled = false; // Prevent re-detach
    detached.deinit();
    self.allocator.destroy(detached);
    self.sessions[detached_id] = null;

    // Return detached slot to free-list
    if (self.free_count < self.free_ids.len) {
        self.free_ids[self.free_count] = detached_id;
        self.free_count += 1;
    }

    // T177 occupant migration: replay the room moves before <resumed/> —
    // the detached slot was just destroyed, so every room record pointing
    // at it is stale until moved. Doing this before the client learns of
    // the resume guarantees its post-resume traffic is ordered after the
    // moves. Same-worker moves apply in place on the owning worker
    // (possibly remote); roomOwner == self applies synchronously.
    if (move_room_count > 0) {
        if (bound_generation) |gen| {
            replayOccupantMoves(self, session, move_rooms_buf[0..move_room_count], gen, self.worker_id);
        } else {
            log.warn("connection {d} resumed with {d} MUC rooms but no session-map generation — occupant moves skipped", .{
                session.conn.id, move_room_count,
            });
        }
    }

    // Send <resumed/> to the client
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    w.writeAll("<resumed xmlns='urn:xmpp:sm:3' h='") catch return;
    std.fmt.format(w, "{d}", .{session.sm_in_h}) catch return;
    w.writeAll("' previd='") catch return;
    w.writeAll(session.sm_id[0..session.sm_id_len]) catch return;
    w.writeAll("'/>") catch return;
    if (session.nonza(fbs.getWritten()) == .failed_closed) return;

    // Replay unacked stanzas
    if (session.sm_unacked) |queue| {
        var iter = queue.getUnacked();
        while (iter.next()) |stanza| {
            // Replayed stanzas are already counted in sm_unacked: nonza
            // appends without re-tracking, or resume would count them twice.
            if (session.nonza(stanza) == .failed_closed) break;
        }
    }

    if (session.conn.hasPendingWrite()) {
        _ = session.conn.flushSend() catch {};
    }

    // Resume sends no initial presence, so nothing else would restart a
    // tail that was still draining at detach (H3).
    if (session.offline_pending) {
        session_lifecycle.drainOfflinePending(self, session, changes);
    }

    log.info("connection {d} session resumed (id={s}, replayed {d} stanzas, {d} rooms)", .{
        session.conn.id,
        session.sm_id[0..session.sm_id_len],
        if (session.sm_unacked) |q| q.pending() else 0,
        move_room_count,
    });
}

/// T177 step 1 — requesting worker. Park the resuming session and ask the
/// owning worker (decoded from the SM-ID prefix) to hand off the detached
/// session's state. Nothing is sent to the client until the reply arrives.
pub fn startCrossWorkerResume(self: *Server, session: *Session, previd: []const u8, h_value: u32, owner: u16, changes: *ChangeList) void {
    const auth_jid = session.stream.authenticated_jid orelse {
        sendSmFailed(self, session, "not-authorized", changes);
        return;
    };
    if (session.sm_resume_pending) {
        sendSmFailed(self, session, "unexpected-request", changes);
        return;
    }

    session.sm_resume_pending = true;
    session.sm_resume_epoch +%= 1;
    @memcpy(&session.sm_resume_previd, previd[0..sm_state.SM_ID_HEX_LEN]);

    log.info("connection {d} cross-worker SM resume: previd={s} owned by worker {d}", .{
        session.conn.id, previd, owner,
    });

    enqueueSmActor(self, owner, .{ .sm_resume_request = .{
        .previd = previd,
        .h = h_value,
        .req_worker = self.worker_id,
        .req_session = @intCast(session.conn.id),
        .req_epoch = session.sm_resume_epoch,
        .auth_local = auth_jid.local,
        .auth_domain = auth_jid.domain,
    } }) catch |err| {
        log.warn("cross-worker SM resume: enqueue to worker {d} failed: {}", .{ owner, err });
        session.sm_resume_pending = false;
        sendSmFailed(self, session, "item-not-found", changes);
    };
}

/// T177 step 2 — owning worker. Validate, snapshot the detached session
/// into the handoff store, dismantle the slot, reply.
///
/// Runs on this worker's MPSC drain, after any stanza deliveries that were
/// queued to the detached slot ahead of this request, so the snapshot
/// includes them. Stanzas arriving after the unbind fall to the offline
/// path until the requesting worker re-binds (known micro-window).
pub fn handleSmResumeRequest(self: *Server, req: actor_message.SmResumeRequest) void {
    const fail = struct {
        fn send(server: *Server, r: actor_message.SmResumeRequest, status: []const u8, why: []const u8) void {
            log.info("cross-worker SM resume handoff for {s} rejected: {s}", .{ r.previd, why });
            enqueueSmActor(server, r.req_worker, .{ .sm_resume_reply = .{
                .previd = r.previd,
                .req_session = r.req_session,
                .req_epoch = r.req_epoch,
                .status = status,
            } }) catch {};
        }
    }.send;

    const detached_id = findDetachedSession(self, req.previd) orelse {
        // T177: this worker handed the session off earlier — follow the
        // breadcrumb, preserving the original requester addressing.
        if (req.hops < MAX_SM_REDIRECT_HOPS) {
            if (smRedirectLookup(self, req.previd)) |target| {
                if (target != self.worker_id and target < muc_actor.getWorkerCount(self)) {
                    log.info("cross-worker SM resume: {s} relocated to worker {d}, forwarding (hop {d})", .{
                        req.previd, target, req.hops + 1,
                    });
                    var fwd = req;
                    fwd.hops += 1;
                    enqueueSmActor(self, target, .{ .sm_resume_request = fwd }) catch
                        return fail(self, req, "item-not-found", "redirect forward failed");
                    return;
                }
            }
        }
        return fail(self, req, "item-not-found", "no such detached session");
    };
    const detached = self.sessions[detached_id] orelse
        return fail(self, req, "item-not-found", "slot empty");

    if (detached.sm_overflow)
        return fail(self, req, "item-not-found", "unacked queue overflowed");
    if (std.time.timestamp() - detached.sm_detach_time > sm_state.DEFAULT_RESUME_TIMEOUT)
        return fail(self, req, "item-not-found", "resume window expired");
    if (detached.sm_detached == false)
        return fail(self, req, "unexpected-request", "session not detached");

    const dj = detached.stream.bound_jid orelse
        return fail(self, req, "item-not-found", "no bound JID");
    if (!std.mem.eql(u8, dj.local, req.auth_local) or !std.mem.eql(u8, dj.domain, req.auth_domain))
        return fail(self, req, "not-authorized", "JID mismatch");

    // T177 occupant migration: MUC-occupying sessions are now handoff-
    // eligible — the bundle carries the room list and the requesting
    // worker replays occupant moves after it re-binds.

    if (detached.sm_unacked) |q| {
        switch (q.ack(req.h)) {
            .ok => {},
            .too_high => return fail(self, req, "handled-count-too-high", "h above sent count"),
            .backwards => return fail(self, req, "unexpected-request", "h moved backwards"),
        }
    }

    const bundle = sm_handoff.allocator.create(sm_handoff.ResumeBundle) catch
        return fail(self, req, "item-not-found", "bundle alloc failed");
    bundle.* = .{
        .previd = undefined,
        .sm_in_h = detached.sm_in_h,
        .sm_out_seq = detached.sm_out_seq,
        .sm_out_h = req.h,
        .r_outstanding = detached.sm_r_outstanding,
        .roster_interested = detached.roster_interested,
        .carbons_enabled = detached.carbons_enabled,
        .csi_active = detached.csi_active,
        .username = sm_handoff.allocator.dupe(u8, detached.auth_username_buf[0..detached.auth_username_len]) catch {
            sm_handoff.allocator.destroy(bundle);
            return fail(self, req, "item-not-found", "bundle alloc failed");
        },
        .resource = sm_handoff.allocator.dupe(u8, dj.resource) catch {
            sm_handoff.allocator.free(bundle.username);
            sm_handoff.allocator.destroy(bundle);
            return fail(self, req, "item-not-found", "bundle alloc failed");
        },
        .last_presence = sm_handoff.allocator.dupe(u8, detached.last_presence_inner[0..detached.last_presence_inner_len]) catch {
            sm_handoff.allocator.free(bundle.resource);
            sm_handoff.allocator.free(bundle.username);
            sm_handoff.allocator.destroy(bundle);
            return fail(self, req, "item-not-found", "bundle alloc failed");
        },
        .base_seq = if (detached.sm_unacked) |q| q.base_seq else 1,
        .last_h = if (detached.sm_unacked) |q| q.last_h else 0,
        .offline_pending = detached.offline_pending,
        .offline_last_sent_sequence = detached.offline_last_sent_sequence,
        .created = std.time.timestamp(),
    };
    @memcpy(&bundle.previd, req.previd[0..sm_state.SM_ID_HEX_LEN]);

    if (detached.sm_unacked) |q| {
        var iter = q.getUnacked();
        while (iter.next()) |stanza| {
            const copy = sm_handoff.allocator.dupe(u8, stanza) catch {
                bundle.deinit();
                sm_handoff.allocator.destroy(bundle);
                return fail(self, req, "item-not-found", "bundle alloc failed");
            };
            bundle.stanzas.append(sm_handoff.allocator, copy) catch {
                sm_handoff.allocator.free(copy);
                bundle.deinit();
                sm_handoff.allocator.destroy(bundle);
                return fail(self, req, "item-not-found", "bundle alloc failed");
            };
        }
    }

    // Snapshot the detached session's MUC occupancies into the bundle.
    // Over the cap: refuse the handoff (full re-bind + rejoin fallback,
    // the pre-migration behavior).
    if (!gatherSessionRooms(self, self.worker_id, detached_id, bundle)) {
        bundle.deinit();
        sm_handoff.allocator.destroy(bundle);
        return fail(self, req, "item-not-found", "occupancy exceeds migration cap");
    }

    sm_handoff.put(req.previd, bundle) catch {
        bundle.deinit();
        sm_handoff.allocator.destroy(bundle);
        enqueueSmActor(self, req.req_worker, .{ .sm_resume_reply = .{
            .previd = req.previd,
            .req_session = req.req_session,
            .req_epoch = req.req_epoch,
            .status = "item-not-found",
        } }) catch {};
        return;
    };

    // Dismantle the detached slot: same teardown as a successful local
    // resume (session-map unbind, sm-id map removal, free the slot).
    // MUC occupant records are deliberately LEFT in place — occupancy is
    // keyed by the full JID, which survives the move; the requesting
    // worker replays occupant moves to retarget each record's
    // (worker, session, generation) triple.
    if (self.session_map) |sm| {
        _ = sm.unbind(dj.local, dj.domain, dj.resource);
    }
    if (self.detached_count > 0) self.detached_count -= 1;
    smIdMapRemove(self, detached.sm_id[0..detached.sm_id_len]);
    detached.sm_resume_enabled = false; // Prevent re-detach
    detached.deinit();
    self.allocator.destroy(detached);
    self.sessions[detached_id] = null;
    if (self.free_count < self.free_ids.len) {
        self.free_ids[self.free_count] = detached_id;
        self.free_count += 1;
    }

    // Breadcrumb: the SM-ID prefix still names THIS worker; a repeat
    // resume of the relocated session must find worker req.req_worker.
    smRedirectNote(self, req.previd, req.req_worker);

    log.info("cross-worker SM resume: handed off {s} to worker {d} ({d} stanzas, {d} rooms)", .{
        req.previd, req.req_worker, bundle.stanzas.items.len, bundle.rooms.items.len,
    });

    enqueueSmActor(self, req.req_worker, .{ .sm_resume_reply = .{
        .previd = req.previd,
        .req_session = req.req_session,
        .req_epoch = req.req_epoch,
        .status = "ok",
    } }) catch |err| {
        log.warn("cross-worker SM resume: reply to worker {d} failed: {}", .{ req.req_worker, err });
    };
}

/// T177 step 3 — requesting worker. Apply the handed-off state to the
/// parked session, re-bind it in the session map, send <resumed/> and
/// replay. The epoch check makes stale replies to a reused slot harmless.
pub fn handleSmResumeReply(self: *Server, rep: actor_message.SmResumeReply, changes: *ChangeList) void {
    const session = self.sessions[rep.req_session] orelse {
        // Requesting connection is gone — drop any parked bundle.
        if (sm_handoff.take(rep.previd)) |orphan| sm_handoff.release(orphan);
        return;
    };

    if (!session.sm_resume_pending or
        session.sm_resume_epoch != rep.req_epoch or
        !std.mem.eql(u8, session.sm_resume_previd[0..], rep.previd))
    {
        log.warn("cross-worker SM resume: stale reply for {s} ignored", .{rep.previd});
        if (std.mem.eql(u8, rep.status, "ok")) {
            if (sm_handoff.take(rep.previd)) |orphan| sm_handoff.release(orphan);
        }
        return;
    }
    session.sm_resume_pending = false;

    if (!std.mem.eql(u8, rep.status, "ok")) {
        log.info("connection {d} cross-worker SM resume failed: {s}", .{ session.conn.id, rep.status });
        sendSmFailed(self, session, rep.status, changes);
        return;
    }

    const bundle = sm_handoff.take(rep.previd) orelse {
        sendSmFailed(self, session, "item-not-found", changes);
        return;
    };
    defer sm_handoff.release(bundle);
    smRedirectDrop(self, rep.previd); // session lives here again

    // Rebuild the unacked queue on this worker's allocator.
    const queue = self.allocator.create(sm_state.SmUnackedQueue) catch {
        sendSmFailed(self, session, "item-not-found", changes);
        return;
    };
    queue.* = sm_state.SmUnackedQueue.init(self.allocator);
    queue.base_seq = bundle.base_seq;
    queue.last_h = bundle.last_h;
    var replay_count: u32 = 0;
    for (bundle.stanzas.items) |stanza| {
        switch (queue.push(stanza)) {
            .pushed => replay_count += 1,
            else => {
                // Source was already ack-trimmed and bounded by
                // UNACKED_CAPACITY — an overflow here means corruption.
                log.err("cross-worker SM resume: rebuilt queue overflow", .{});
                queue.deinit();
                self.allocator.destroy(queue);
                sendSmFailed(self, session, "item-not-found", changes);
                return;
            },
        }
    }

    session.sm_enabled = true;
    session.sm_in_h = bundle.sm_in_h;
    session.sm_out_h = bundle.sm_out_h;
    session.sm_out_seq = bundle.sm_out_seq;
    session.sm_r_outstanding = bundle.r_outstanding;
    session.sm_resume_enabled = true;
    @memcpy(&session.sm_id, &bundle.previd);
    session.sm_id_len = sm_state.SM_ID_HEX_LEN;
    session.sm_unacked = queue;

    @memcpy(session.auth_username_buf[0..bundle.username.len], bundle.username);
    session.auth_username_len = bundle.username.len;
    @memcpy(session.bind_resource_buf[0..bundle.resource.len], bundle.resource);
    session.bind_resource_len = bundle.resource.len;
    session.stream.bound_jid = .{
        .local = session.auth_username_buf[0..session.auth_username_len],
        .domain = self.server_host,
        .resource = session.bind_resource_buf[0..session.bind_resource_len],
    };
    session.stream.authenticated_jid = .{
        .local = session.auth_username_buf[0..session.auth_username_len],
        .domain = self.server_host,
    };
    session.stream.authenticated = true;
    session.stream.state = .active;
    session.roster_interested = bundle.roster_interested;
    session.carbons_enabled = bundle.carbons_enabled;
    session.csi_active = bundle.csi_active;
    session.offline_pending = bundle.offline_pending;
    session.offline_last_sent_sequence = bundle.offline_last_sent_sequence;
    @memcpy(session.last_presence_inner[0..bundle.last_presence.len], bundle.last_presence);
    session.last_presence_inner_len = bundle.last_presence.len;

    var bound_generation: ?u32 = null;
    if (self.session_map) |sm| {
        if (sm.bind(self.worker_id, @intCast(session.conn.id), bundle.username, self.server_host, bundle.resource)) |gen| {
            bound_generation = gen;
        } else |err| {
            log.err("cross-worker SM resume: session_map bind failed for {s}@{s}/{s}: {}", .{
                bundle.username, self.server_host, bundle.resource, err,
            });
        }
    }

    // T177 occupant migration: replay room moves before <resumed/> — SM
    // state applied, SessionMap bind done (generation known); the client
    // has not been told yet, so its post-resume traffic is ordered after
    // the moves. Old worker identity comes from the SM-ID prefix.
    if (bundle.rooms.items.len > 0) {
        if (bound_generation) |gen| {
            const old_worker = sm_state.workerIdFromSmId(&bundle.previd) orelse self.worker_id;
            replayOccupantMoves(self, session, bundle.rooms.items, gen, old_worker);
        } else {
            log.warn("connection {d} resumed with {d} MUC rooms but no session-map generation — occupant moves skipped (client should MAM/rejoin)", .{
                session.conn.id, bundle.rooms.items.len,
            });
        }
    }

    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    w.writeAll("<resumed xmlns='urn:xmpp:sm:3' h='") catch return;
    std.fmt.format(w, "{d}", .{session.sm_in_h}) catch return;
    w.writeAll("' previd='") catch return;
    w.writeAll(session.sm_id[0..session.sm_id_len]) catch return;
    w.writeAll("'/>") catch return;
    if (session.nonza(fbs.getWritten()) == .failed_closed) return;

    if (session.sm_unacked) |q| {
        var iter = q.getUnacked();
        while (iter.next()) |stanza| {
            // Replayed stanzas are already counted in sm_unacked: nonza
            // appends without re-tracking, or resume would count them twice.
            if (session.nonza(stanza) == .failed_closed) break;
        }
    }

    if (session.conn.hasPendingWrite()) {
        _ = session.conn.flushSend() catch {};
    }

    // Resume sends no initial presence, so nothing else would restart a
    // tail that was still draining at detach (H3).
    if (session.offline_pending) {
        session_lifecycle.drainOfflinePending(self, session, changes);
    }

    log.info("connection {d} cross-worker session resumed (id={s}, replayed {d} stanzas, {d} rooms)", .{
        session.conn.id,
        session.sm_id[0..session.sm_id_len],
        replay_count,
        bundle.rooms.items.len,
    });
}

/// Dispatch an SM-handoff/session actor message (MPSC, SM_ACTOR_SENTINEL).
/// Covers the T177 resume handoff pair and the T154 session_kick pair.
pub fn handleSmActorMessage(self: *Server, payload: []const u8, changes: *ChangeList) void {
    const msg = actor_message.decode(payload) orelse {
        log.warn("malformed SM actor message ({d} bytes)", .{payload.len});
        return;
    };
    switch (msg) {
        .sm_resume_request => |ev| handleSmResumeRequest(self, ev),
        .sm_resume_reply => |ev| handleSmResumeReply(self, ev, changes),
        .session_kick_request => |ev| handleSessionKickRequest(self, ev, changes),
        .session_kick_reply => |ev| handleSessionKickReply(self, ev, changes),
        else => log.warn("unexpected tag in SM actor dispatch: 0x{x:0>2}", .{msg.tag()}),
    }
}

/// T154 step 1 — requesting worker. The bind hit AlreadyBound against a
/// session owned by `owner`; park the bind and ask that worker to evict.
/// Returns false when the kick couldn't even be armed (caller falls back
/// to conflict + close).
pub fn startSessionKick(self: *Server, session: *Session, local: []const u8, domain: []const u8, resource: []const u8, owner: u16, changes: *ChangeList) bool {
    _ = changes;
    if (session.bind_kick_pending) return false;
    if (session.bind_kick_rounds >= session_lifecycle.MAX_BIND_KICK_ROUNDS) return false;
    if (resource.len > session.bind_kick_resource_buf.len) return false;

    session.bind_kick_pending = true;
    session.bind_kick_epoch +%= 1;
    session.bind_kick_rounds += 1;
    @memcpy(session.bind_kick_resource_buf[0..resource.len], resource);
    session.bind_kick_resource_len = @intCast(resource.len);

    enqueueSmActor(self, owner, .{ .session_kick_request = .{
        .local = local,
        .domain = domain,
        .resource = resource,
        .req_worker = self.worker_id,
        .req_session = @intCast(session.conn.id),
        .req_epoch = session.bind_kick_epoch,
    } }) catch |err| {
        log.warn("session_kick to worker {d} failed to enqueue: {}", .{ owner, err });
        session.bind_kick_pending = false;
        return false;
    };
    log.info("connection {d} bind parked: kicking {s}@{s}/{s} on worker {d} (round {d})", .{
        session.conn.id, local, domain, resource, owner, session.bind_kick_rounds,
    });
    return true;
}

/// T154 step 2 — holding worker. Destroy the session owning the full JID
/// (RFC 6120 §7.7.3 conflict), then confirm. The destroySession teardown
/// removes the session-map entry, so the requester's retry bind succeeds.
pub fn handleSessionKickRequest(self: *Server, req: actor_message.SessionKickRequest, changes: *ChangeList) void {
    if (self.session_map) |sm| {
        if (sm.findByFullJid(req.local, req.domain, req.resource)) |entry| {
            if (entry.worker_id == self.worker_id) {
                const old_id: usize = @intCast(entry.local_session_id);
                if (self.sessions[old_id]) |old| {
                    log.warn("session {d} evicted: resource {s}@{s}/{s} taken by worker {d}", .{
                        old_id, req.local, req.domain, req.resource, req.req_worker,
                    });
                    c2s_session.sendStreamError(self, old, .conflict);
                    old.conn.flushSync(); // deliver the conflict before teardown closes the fd
                    session_lifecycle.forceCloseSession(self, old_id, changes);
                } else {
                    // Dangling entry with no session — just drop it.
                    _ = sm.unbind(req.local, req.domain, req.resource);
                }
            }
        }
    }

    enqueueSmActor(self, req.req_worker, .{ .session_kick_reply = .{
        .req_session = req.req_session,
        .req_epoch = req.req_epoch,
    } }) catch |err| {
        log.warn("session_kick reply to worker {d} failed: {}", .{ req.req_worker, err });
    };
}

/// T154 step 3 — requesting worker. Epoch-guarded, then retry the bind.
pub fn handleSessionKickReply(self: *Server, rep: actor_message.SessionKickReply, changes: *ChangeList) void {
    const session = self.sessions[rep.req_session] orelse return;

    if (!session.bind_kick_pending or session.bind_kick_epoch != rep.req_epoch) {
        log.warn("stale session_kick reply for conn {d} ignored", .{rep.req_session});
        return;
    }
    session.bind_kick_pending = false;

    session_lifecycle.completeBindAfterKick(self, session, changes);
}

/// Encode an actor message and enqueue it to a target worker's MPSC queue
/// under the SM handoff sentinel.
pub fn enqueueSmActor(self: *Server, target_worker: u16, msg: actor_message.Message) !void {
    const ds = self.delivery_system orelse return error.NoDeliverySystem;
    var buf: [actor_message.MAX_ENCODED_SIZE]u8 = undefined;
    const len = actor_message.encode(&buf, msg) orelse return error.EncodeFailed;
    try ds.deliver(target_worker, delivery_queue_mod.SM_ACTOR_SENTINEL, 0, buf[0..len]);
}

/// Append the JIDs of every MUC room the given session occupies into the
/// bundle (T177 occupant migration). Every worker's registry carries
/// occupant records for its own sessions — canonical records for rooms it
/// owns, shadow copies for rooms owned elsewhere — so a local scan sees
/// all of them. Only the room JID is bundled: the canonical record on the
/// room's owning worker keeps the authoritative nick/role/affiliation and
/// is updated in place by the occupant move. Returns false on alloc
/// failure or when occupancy exceeds sm_handoff.MAX_BUNDLE_ROOMS (the
/// caller then falls back to a full re-bind).
pub fn gatherSessionRooms(self: *Server, worker_id: u16, session_id: usize, bundle: *sm_handoff.ResumeBundle) bool {
    const reg = self.room_registry orelse return true;
    for (&reg.rooms) |*slot| {
        const room = slot.* orelse continue;
        if (!room.active) continue;
        for (&room.occupants) |*occ_slot| {
            const occ = occ_slot.* orelse continue;
            if (occ.worker_id != worker_id or occ.session_id != session_id) continue;
            if (bundle.rooms.items.len >= sm_handoff.MAX_BUNDLE_ROOMS) return false;
            const copy = sm_handoff.allocator.dupe(u8, room.getJid()) catch return false;
            bundle.rooms.append(sm_handoff.allocator, copy) catch {
                sm_handoff.allocator.free(copy);
                return false;
            };
        }
    }
    return true;
}

/// T177: replay occupant moves for a successfully resumed session — one
/// per room's owning worker, which updates the canonical record (and
/// shadow copies) to the new (worker, session, generation) without any
/// presence fan-out.
///
/// Ordering: runs after the SessionMap bind (generation known) and before
/// <resumed/> reaches the client, so traffic the client sends after the
/// resume is always ordered behind the moves. Rooms owned by THIS worker
/// are applied synchronously — an async hop would let same-batch room
/// traffic (a groupchat from another client read in the same kevent
/// batch) see the pre-move triple and drop the stanza on the stale slot.
///
/// If the resumed connection dies before or while these apply,
/// destroySession's session_closed broadcast removes the occupant by
/// full JID everywhere — no ghost occupancy.
pub fn replayOccupantMoves(self: *Server, session: *Session, room_jids: []const []const u8, generation: u32, old_worker: u16) void {
    const bound = session.stream.bound_jid orelse return;
    var jid_buf: [router.FULL_JID_MAX]u8 = undefined;
    const real_jid = router.buildFullJid(bound.local, bound.domain, bound.resource, &jid_buf) catch {
        noteDrop("occupant moves for {s}@{s} not replayed: full JID exceeds {d} bytes", .{ bound.local, bound.domain, router.FULL_JID_MAX });
        return;
    };

    for (room_jids) |room_jid| {
        const move = actor_message.RoomOccupantMove{
            .room_jid = room_jid,
            .real_jid = real_jid,
            .old_worker_id = old_worker,
            .new_worker_id = self.worker_id,
            .new_session_id = @intCast(session.conn.id),
            .new_generation = generation,
        };
        const owner = room_registry_mod.roomOwner(room_jid, muc_actor.getWorkerCount(self));
        if (owner == self.worker_id) {
            muc_handler.handleOccupantMove(self, move);
        } else {
            muc_actor.enqueueRoomActorMessage(self, owner, .{ .room_occupant_move = move });
        }
    }
}

/// XEP-0198 §3: an <a/> whose handled-count is malformed or above the
/// number of stanzas sent fails the stream (S24). A parseable but too-high
/// `h` is echoed with the count sent (XEP-0198 Example 17); a malformed `h`
/// cannot be echoed, so the optional attributes are omitted.
pub fn sendSmHandledCountError(self: *Server, session: *Session, h: ?u32, changes: *ChangeList) void {
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    w.writeAll("<stream:error><undefined-condition xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>" ++
        "<handled-count-too-high xmlns='urn:xmpp:sm:3'") catch return;
    if (h) |v| {
        w.print(" h='{d}' send-count='{d}'", .{ v, session.sm_out_seq }) catch return;
    }
    w.writeAll("/></stream:error>") catch return;
    if (session.nonza(fbs.getWritten()) == .failed_closed) return;
    session.conn.flushSync();
    session_lifecycle.forceCloseSession(self, session.conn.id, changes);
}

/// Send SM <failed/> with a specific error condition.
pub fn sendSmFailed(self: *Server, session: *Session, condition: []const u8, changes: *ChangeList) void {
    _ = changes; // Sends dirty-link the conn for the batch-tail flush (ADR-2).
    _ = self;
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    w.writeAll("<failed xmlns='urn:xmpp:sm:3'><") catch return;
    w.writeAll(condition) catch return;
    // handled-count-too-high lives in the SM namespace (XEP-0198 §4),
    // the failure conditions in the stanza namespace.
    const ns = if (std.mem.eql(u8, condition, "handled-count-too-high"))
        "urn:xmpp:sm:3"
    else
        "urn:ietf:params:xml:ns:xmpp-stanzas";
    w.writeAll(" xmlns='") catch return;
    w.writeAll(ns) catch return;
    w.writeAll("'/></failed>") catch return;
    if (session.nonza(fbs.getWritten()) == .failed_closed) return;
    if (session.conn.hasPendingWrite()) {
        _ = session.conn.flushSend() catch {};
    }
}

/// Find a detached session by SM-ID. O(1) via hash map (T127).
pub fn findDetachedSession(self: *Server, sm_id: []const u8) ?usize {
    if (sm_id.len != sm_state.SM_ID_HEX_LEN) return null;
    var key: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
    @memcpy(&key, sm_id[0..sm_state.SM_ID_HEX_LEN]);
    return self.sm_id_map.get(key);
}

/// Insert an SM-ID → slot mapping.
pub fn smIdMapInsert(self: *Server, sm_id: []const u8, slot: usize) void {
    if (sm_id.len != sm_state.SM_ID_HEX_LEN) return;
    var key: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
    @memcpy(&key, sm_id[0..sm_state.SM_ID_HEX_LEN]);
    self.sm_id_map.put(self.allocator, key, slot) catch |err| {
        // An SM-ID that is not findable loses its resume capability.
        log.err("SM-ID map insert failed ({}): detached sessions become unresumable", .{err});
    };
}

/// Remove an SM-ID from the map.
pub fn smIdMapRemove(self: *Server, sm_id: []const u8) void {
    if (sm_id.len != sm_state.SM_ID_HEX_LEN) return;
    var key: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
    @memcpy(&key, sm_id[0..sm_state.SM_ID_HEX_LEN]);
    _ = self.sm_id_map.remove(key);
}

/// T177: record that previd's session moved to `worker` (cross-worker
/// handoff on this worker). Breadcrumbs expire with the SM resume window;
/// a full map evicts the oldest entry.
pub fn smRedirectNote(self: *Server, previd: []const u8, worker: u16) void {
    if (previd.len != sm_state.SM_ID_HEX_LEN) return;
    var key: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
    @memcpy(&key, previd);
    const now = std.time.timestamp();
    smRedirectsPurgeExpired(self, now);
    if (self.sm_redirects.count() >= MAX_SM_REDIRECTS and !self.sm_redirects.contains(key)) {
        var oldest_key: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
        var oldest_ts: i64 = std.math.maxInt(i64);
        var found = false;
        var it = self.sm_redirects.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.moved_at < oldest_ts) {
                oldest_ts = kv.value_ptr.moved_at;
                oldest_key = kv.key_ptr.*;
                found = true;
            }
        }
        if (found) _ = self.sm_redirects.remove(oldest_key);
    }
    self.sm_redirects.put(self.allocator, key, .{ .worker = worker, .moved_at = now }) catch {};
}

/// Where did previd's session go? null if unknown/expired.
pub fn smRedirectLookup(self: *Server, previd: []const u8) ?u16 {
    if (previd.len != sm_state.SM_ID_HEX_LEN) return null;
    var key: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
    @memcpy(&key, previd);
    const entry = self.sm_redirects.getPtr(key) orelse return null;
    if (std.time.timestamp() - entry.moved_at > sm_state.DEFAULT_RESUME_TIMEOUT) {
        _ = self.sm_redirects.remove(key);
        return null;
    }
    return entry.worker;
}

/// Drop a redirect for previd (session resumed or destroyed here).
pub fn smRedirectDrop(self: *Server, previd: []const u8) void {
    if (previd.len != sm_state.SM_ID_HEX_LEN) return;
    var key: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
    @memcpy(&key, previd);
    _ = self.sm_redirects.remove(key);
}

pub fn smRedirectsPurgeExpired(self: *Server, now: i64) void {
    var stale: [16][sm_state.SM_ID_HEX_LEN]u8 = undefined;
    var stale_count: usize = 0;
    var it = self.sm_redirects.iterator();
    while (it.next()) |kv| {
        if (now - kv.value_ptr.moved_at > sm_state.DEFAULT_RESUME_TIMEOUT) {
            if (stale_count < stale.len) {
                stale[stale_count] = kv.key_ptr.*;
                stale_count += 1;
            }
        }
    }
    for (stale[0..stale_count]) |key| _ = self.sm_redirects.remove(key);
}

/// Handle <r xmlns='urn:xmpp:sm:3'/> — respond with server's inbound h value.
/// Flushes immediately to avoid latency from changelist-based deferred writes.
pub fn handleSmRequest(self: *Server, session: *Session, changes: *ChangeList) void {
    _ = changes; // Sends dirty-link the conn for the batch-tail flush (ADR-2).
    _ = self;
    var fbs = std.io.fixedBufferStream(&session.write_scratch);
    const w = fbs.writer();
    w.writeAll("<a xmlns='urn:xmpp:sm:3' h='") catch return;
    std.fmt.format(w, "{d}", .{session.sm_in_h}) catch return;
    w.writeAll("'/>") catch return;
    if (session.nonza(fbs.getWritten()) == .failed_closed) return;
    // Attempt immediate flush — SM acks are latency-critical. A stall
    // leaves the conn dirty-linked; the batch tail arms EVFILT_WRITE
    // only on a real EAGAIN.
    _ = session.conn.flushSend() catch {};
}

test "S17: SM-ID map holds more than 64 detached sessions" {
    const allocator = std.testing.allocator;
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 256);
    defer server.deinit();

    // 200 inserts: the old 64-entry table silently dropped everything past 64.
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        var id: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
        _ = std.fmt.bufPrint(&id, "{x:0>32}", .{i}) catch unreachable;
        smIdMapInsert(&server, &id, i);
    }
    try std.testing.expectEqual(@as(u32, 200), server.sm_id_map.count());

    i = 0;
    while (i < 200) : (i += 1) {
        var id: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
        _ = std.fmt.bufPrint(&id, "{x:0>32}", .{i}) catch unreachable;
        try std.testing.expectEqual(@as(?usize, i), findDetachedSession(&server, &id));
    }
}

test "S17: SM-ID map remove does not break later lookups" {
    const allocator = std.testing.allocator;
    var server = try Server.initWithMaxSessions("localhost", "127.0.0.1", 0, allocator, 256);
    defer server.deinit();

    // Insert a batch, remove every third entry, then verify the rest are
    // still findable (open addressing without tombstones lost the tail of
    // each probe chain here).
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var id: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
        _ = std.fmt.bufPrint(&id, "{x:0>32}", .{i}) catch unreachable;
        smIdMapInsert(&server, &id, i + 1000);
    }
    i = 0;
    while (i < 100) : (i += 3) {
        var id: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
        _ = std.fmt.bufPrint(&id, "{x:0>32}", .{i}) catch unreachable;
        smIdMapRemove(&server, &id);
    }
    i = 0;
    while (i < 100) : (i += 1) {
        var id: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
        _ = std.fmt.bufPrint(&id, "{x:0>32}", .{i}) catch unreachable;
        if (i % 3 == 0) {
            try std.testing.expectEqual(@as(?usize, null), findDetachedSession(&server, &id));
        } else {
            try std.testing.expectEqual(@as(?usize, i + 1000), findDetachedSession(&server, &id));
        }
    }
}

test "Server: replaced-resource notice fits worst-case XML escaping" {
    const allocator = std.testing.allocator;
    var server = try Server.init("localhost", "127.0.0.1", 0, allocator);
    defer server.deinit();
    var registry = RoomRegistry.init(allocator);
    defer registry.deinit();
    server.room_registry = &registry;
    server.muc_host = "conference.localhost";
    var delivery_sys = try DeliverySystem.init(allocator, 2);
    defer delivery_sys.deinit();
    server.delivery_system = &delivery_sys;
    server.worker_id = 0;

    var room_jid: [256]u8 = undefined;
    @memset(&room_jid, '\'');
    var nick: [64]u8 = undefined;
    @memset(&nick, '\'');
    var first_jid: [256]u8 = undefined;
    @memset(&first_jid, '\'');
    @memcpy(first_jid[200..211], "@localhost/");
    var second_jid = first_jid;
    second_jid[second_jid.len - 1] = 'x';

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);
    muc_handler.processRemoteJoin(&server, .{
        .room_jid = &room_jid,
        .real_jid = &first_jid,
        .nick = &nick,
        .worker_id = 1,
        .session_id = 7,
        .generation = 1,
    }, &changes);
    muc_handler.processRemoteJoin(&server, .{
        .room_jid = &room_jid,
        .real_jid = &second_jid,
        .nick = &nick,
        .worker_id = 1,
        .session_id = 9,
        .generation = 2,
    }, &changes);

    const NoticeCheck = struct {
        seen: bool = false,
        len: usize = 0,
        complete: bool = false,

        fn onDelivery(self: *@This(), session_id: u32, generation: u32, payload: []const u8) void {
            _ = session_id;
            _ = generation;
            if (std.mem.indexOf(u8, payload, "type='unavailable'") == null) return;
            self.seen = true;
            self.len = payload.len;
            self.complete = std.mem.endsWith(u8, payload, "</presence>") and
                std.mem.indexOf(u8, payload, "&apos;") != null;
        }
    };
    var check = NoticeCheck{};
    _ = delivery_sys.getQueue(1).drain(&check, NoticeCheck.onDelivery);
    try std.testing.expect(check.seen);
    try std.testing.expect(check.complete);
    try std.testing.expect(check.len > 1024);
}

test "Server: S24 a h above the sent count fails the stream" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    c2s_session.handleReadable(&server, 1, &changes);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    session.stream.state = .active;
    session.sm_enabled = true;
    const queue = try std.testing.allocator.create(sm_state.SmUnackedQueue);
    queue.* = sm_state.SmUnackedQueue.init(std.testing.allocator);
    _ = queue.push("<message/>");
    _ = queue.push("<presence/>");
    session.sm_unacked = queue;

    // 2 stanzas outstanding, client claims 5 handled.
    _ = try posix.write(fds[1], "<a xmlns='urn:xmpp:sm:3' h='5'/>");
    c2s_session.handleReadable(&server, 1, &changes);

    try std.testing.expect(server.sessions[1] == null);
    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (posix.read(fds[1], buf[total..])) |n| {
        if (n == 0) break;
        total += n;
    } else |_| {}
    try std.testing.expect(std.mem.indexOf(u8, buf[0..total], "undefined-condition") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..total], "handled-count-too-high") != null);
}

test "Server: S24 malformed a h fails the stream" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    c2s_session.handleReadable(&server, 1, &changes);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    session.stream.state = .active;
    session.sm_enabled = true;

    _ = try posix.write(fds[1], "<a xmlns='urn:xmpp:sm:3' h='five'/>");
    c2s_session.handleReadable(&server, 1, &changes);

    try std.testing.expect(server.sessions[1] == null);
    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (posix.read(fds[1], buf[total..])) |n| {
        if (n == 0) break;
        total += n;
    } else |_| {}
    try std.testing.expect(std.mem.indexOf(u8, buf[0..total], "handled-count-too-high") != null);
}

test "Server: S24 SM without resume rejects h above the sent count" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    c2s_session.handleReadable(&server, 1, &changes);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    session.stream.state = .active;
    session.sm_enabled = true;
    // SM without resume has no unacked queue, but the sent count is tracked.
    // Five stanzas sent; the client claims ten handled.
    session.sm_out_seq = 5;
    session.sm_unacked = null;

    _ = try posix.write(fds[1], "<a xmlns='urn:xmpp:sm:3' h='10'/>");
    c2s_session.handleReadable(&server, 1, &changes);

    try std.testing.expect(server.sessions[1] == null);
    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (posix.read(fds[1], buf[total..])) |n| {
        if (n == 0) break;
        total += n;
    } else |_| {}
    try std.testing.expect(std.mem.indexOf(u8, buf[0..total], "handled-count-too-high") != null);
    // XEP-0198 Example 17: the error reports the offending h and the send count.
    try std.testing.expect(std.mem.indexOf(u8, buf[0..total], "h='10'") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..total], "send-count='5'") != null);
}

test "Server: S24 a backwards or duplicate a h does not corrupt the accepted count" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);

    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    c2s_session.handleReadable(&server, 1, &changes);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    session.stream.state = .active;
    session.sm_enabled = true;
    session.sm_out_seq = 5;
    session.sm_out_h = 3;
    session.sm_unacked = null;

    // A backwards report (h=2 below the accepted 3) must not move sm_out_h.
    _ = try posix.write(fds[1], "<a xmlns='urn:xmpp:sm:3' h='2'/>");
    c2s_session.handleReadable(&server, 1, &changes);
    try std.testing.expect(server.sessions[1] != null);
    try std.testing.expectEqual(@as(u32, 3), session.sm_out_h);

    // A duplicate of the accepted count is a no-op as well.
    _ = try posix.write(fds[1], "<a xmlns='urn:xmpp:sm:3' h='3'/>");
    c2s_session.handleReadable(&server, 1, &changes);
    try std.testing.expect(server.sessions[1] != null);
    try std.testing.expectEqual(@as(u32, 3), session.sm_out_h);

    // A forward report within the sent count is accepted and advances sm_out_h.
    _ = try posix.write(fds[1], "<a xmlns='urn:xmpp:sm:3' h='4'/>");
    c2s_session.handleReadable(&server, 1, &changes);
    try std.testing.expect(server.sessions[1] != null);
    try std.testing.expectEqual(@as(u32, 4), session.sm_out_h);
}

test "Server: S24 backwards and too-high resume h fail without replay" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    // Detached session on slot 2: client had acked 5, 3 stanzas outstanding.
    const det_fds = try makeSocketPair();
    defer posix.close(det_fds[1]);
    const detached = try std.testing.allocator.create(Session);
    detached.* = Session.init(det_fds[0], 2, "localhost", false, std.testing.allocator);
    detached.stream.bound_jid = xmpp.Jid.parse("alice@localhost/res") catch null;
    detached.sm_detached = true;
    detached.sm_detach_time = std.time.timestamp();
    const det_queue = try std.testing.allocator.create(sm_state.SmUnackedQueue);
    det_queue.* = sm_state.SmUnackedQueue.init(std.testing.allocator);
    det_queue.base_seq = 6;
    det_queue.last_h = 5;
    _ = det_queue.push("<message/>");
    _ = det_queue.push("<message/>");
    _ = det_queue.push("<message/>");
    detached.sm_unacked = det_queue;
    server.sessions[2] = detached;

    var previd: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
    sm_state.generateSmId(server.worker_id, &previd);
    smIdMapInsert(&server, &previd, 2);

    // Fresh connection resuming the detached session.
    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    const stream_open = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>";
    _ = try posix.write(fds[1], stream_open);
    c2s_session.handleReadable(&server, 1, &changes);
    var drain_buf: [4096]u8 = undefined;
    _ = posix.read(fds[1], &drain_buf) catch 0;

    session.stream.state = .features_bind;
    session.stream.authenticated_jid = xmpp.Jid.parse("alice@localhost") catch null;

    var resume_buf: [128]u8 = undefined;
    const backwards = std.fmt.bufPrint(&resume_buf, "<resume xmlns='urn:xmpp:sm:3' previd='{s}' h='3'/>", .{previd}) catch unreachable;
    _ = try posix.write(fds[1], backwards);
    c2s_session.handleReadable(&server, 1, &changes);

    var buf: [4096]u8 = undefined;
    const n1 = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n1], "<failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n1], "unexpected-request") != null);
    // The detached session and its replay queue are untouched.
    try std.testing.expect(server.sessions[2] != null);
    try std.testing.expectEqual(@as(u32, 3), det_queue.count);
    try std.testing.expectEqual(@as(u32, 5), det_queue.last_h);

    const too_high = std.fmt.bufPrint(&resume_buf, "<resume xmlns='urn:xmpp:sm:3' previd='{s}' h='100'/>", .{previd}) catch unreachable;
    _ = try posix.write(fds[1], too_high);
    c2s_session.handleReadable(&server, 1, &changes);

    const n2 = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n2], "<failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n2], "handled-count-too-high") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n2], "urn:xmpp:sm:3'/></failed>") != null);
    try std.testing.expectEqual(@as(u32, 3), det_queue.count);

    // Malformed h fails instead of parsing as 0.
    const malformed = std.fmt.bufPrint(&resume_buf, "<resume xmlns='urn:xmpp:sm:3' previd='{s}' h='x'/>", .{previd}) catch unreachable;
    _ = try posix.write(fds[1], malformed);
    c2s_session.handleReadable(&server, 1, &changes);

    const n3 = posix.read(fds[1], &buf) catch 0;
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n3], "<failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n3], "bad-request") != null);
    try std.testing.expectEqual(@as(u32, 3), det_queue.count);
}

test "Server: S24 cross-worker handoff carries last_h" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();
    sm_handoff.resetForTesting();

    var change_buf: [16]posix.Kevent = undefined;
    var changes = ChangeList.init(&change_buf);

    const fds = try makeSocketPair();
    defer posix.close(fds[1]);
    const session = try std.testing.allocator.create(Session);
    session.* = Session.init(fds[0], 1, "localhost", false, std.testing.allocator);
    server.sessions[1] = session;

    var previd: [sm_state.SM_ID_HEX_LEN]u8 = undefined;
    sm_state.generateSmId(server.worker_id, &previd);

    session.sm_resume_pending = true;
    session.sm_resume_epoch = 7;
    @memcpy(&session.sm_resume_previd, &previd);

    // The owning worker's queue: client had acked 5, 3 stanzas outstanding.
    const bundle = sm_handoff.allocator.create(sm_handoff.ResumeBundle) catch unreachable;
    bundle.* = .{
        .previd = previd,
        .sm_in_h = 0,
        .sm_out_seq = 8,
        .sm_out_h = 3,
        .r_outstanding = false,
        .roster_interested = false,
        .carbons_enabled = false,
        .csi_active = false,
        .username = sm_handoff.allocator.dupe(u8, "alice") catch unreachable,
        .resource = sm_handoff.allocator.dupe(u8, "res") catch unreachable,
        .last_presence = sm_handoff.allocator.dupe(u8, "") catch unreachable,
        .base_seq = 6,
        .last_h = 5,
        .created = std.time.timestamp(),
    };
    bundle.stanzas.append(sm_handoff.allocator, sm_handoff.allocator.dupe(u8, "<message/>") catch unreachable) catch unreachable;
    try sm_handoff.put(&previd, bundle);

    handleSmResumeReply(&server, .{
        .previd = &previd,
        .req_session = 1,
        .req_epoch = 7,
        .status = "ok",
    }, &changes);

    const queue = session.sm_unacked.?;
    try std.testing.expectEqual(@as(u32, 5), queue.last_h);
    try std.testing.expectEqual(@as(u32, 6), queue.base_seq);
    try std.testing.expectEqual(@as(u32, 1), queue.count);
    try std.testing.expectEqual(@as(u32, 8), session.sm_out_seq);

    // A backwards <a/> after the handoff discards nothing (the carried
    // last_h is what rejects it).
    try std.testing.expectEqual(sm_state.SmUnackedQueue.AckResult.backwards, queue.ack(3));
    try std.testing.expectEqual(@as(u32, 1), queue.count);
    try std.testing.expectEqual(@as(u32, 5), queue.last_h);
}

/// Test helper: the <resume/> reply status drained off a requesting worker's
/// SM actor queue. The status slice points into the transient MPSC payload, so
/// it is copied out before the drain handler returns.
pub const CapturedResumeStatus = struct {
    buf: [64]u8 = undefined,
    len: usize = 0,

    fn slice(self: *const CapturedResumeStatus) []const u8 {
        return self.buf[0..self.len];
    }
};

pub fn captureSmResumeStatus(ds: *DeliverySystem, req_worker: u16, out: *CapturedResumeStatus) void {
    const Ctx = struct { dst: *CapturedResumeStatus };
    _ = ds.getQueue(req_worker).drain(Ctx{ .dst = out }, struct {
        fn handle(c: Ctx, _: u32, _: u32, payload: []const u8) void {
            const msg = actor_message.decode(payload) orelse return;
            switch (msg) {
                .sm_resume_reply => |r| {
                    const n = @min(r.status.len, c.dst.buf.len);
                    @memcpy(c.dst.buf[0..n], r.status[0..n]);
                    c.dst.len = n;
                },
                else => {},
            }
        }
    }.handle);
}

/// Build a detached session on `slot` (acked up to `last_h`, `unacked` stanzas
/// outstanding from `base_seq`) registered under `previd`, ready for a
/// cross-worker resume request. The caller owns the session; on a rejected
/// request it is still there and `server.deinit` frees it.
pub fn makeDetachedForResume(
    server: *Server,
    slot: usize,
    previd: []const u8,
    base_seq: u32,
    last_h: u32,
    unacked: u32,
    fd: posix.fd_t,
) !*Session {
    const detached = try std.testing.allocator.create(Session);
    detached.* = Session.init(fd, slot, "localhost", false, std.testing.allocator);
    detached.stream.bound_jid = xmpp.Jid.parse("alice@localhost/res") catch null;
    detached.sm_detached = true;
    detached.sm_detach_time = std.time.timestamp();
    detached.sm_resume_enabled = true;
    @memcpy(&detached.sm_id, previd[0..sm_state.SM_ID_HEX_LEN]);
    detached.sm_id_len = sm_state.SM_ID_HEX_LEN;
    const queue = try std.testing.allocator.create(sm_state.SmUnackedQueue);
    queue.* = sm_state.SmUnackedQueue.init(std.testing.allocator);
    queue.base_seq = base_seq;
    queue.last_h = last_h;
    var i: u32 = 0;
    while (i < unacked) : (i += 1) _ = queue.push("<message/>");
    detached.sm_unacked = queue;
    server.sessions[slot] = detached;
    smIdMapInsert(server, previd, slot);
    return detached;
}

test "Server: S24 cross-worker resume validates the reported h before handoff" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();
    server.worker_id = 1;
    var delivery_sys = try DeliverySystem.init(std.testing.allocator, 2);
    defer delivery_sys.deinit();
    server.delivery_system = &delivery_sys;
    sm_handoff.resetForTesting();

    const previd = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const det_fds = try makeSocketPair();
    defer posix.close(det_fds[1]);
    const detached = try makeDetachedForResume(&server, 2, previd, 6, 5, 3, det_fds[0]);
    const det_queue = detached.sm_unacked.?;

    var status = CapturedResumeStatus{};

    // A backwards h must fail the handoff and leave the queue untouched.
    handleSmResumeRequest(&server, .{
        .previd = previd,
        .h = 3,
        .req_worker = 1,
        .req_session = 1,
        .req_epoch = 0,
        .auth_local = "alice",
        .auth_domain = "localhost",
        .hops = 0,
    });
    captureSmResumeStatus(&delivery_sys, 1, &status);
    try std.testing.expectEqualStrings("unexpected-request", status.slice());
    try std.testing.expectEqual(@as(usize, 0), sm_handoff.count());
    try std.testing.expect(server.sessions[2] != null);
    try std.testing.expectEqual(@as(u32, 3), det_queue.count);
    try std.testing.expectEqual(@as(u32, 5), det_queue.last_h);

    // An h above the sent count must fail the same way. Only the wrap-aware
    // subtraction catches a report that has passed 2^32 (see the sm_state
    // wrap tests); here the plain overshoot is rejected.
    handleSmResumeRequest(&server, .{
        .previd = previd,
        .h = 100,
        .req_worker = 1,
        .req_session = 1,
        .req_epoch = 0,
        .auth_local = "alice",
        .auth_domain = "localhost",
        .hops = 0,
    });
    captureSmResumeStatus(&delivery_sys, 1, &status);
    try std.testing.expectEqualStrings("handled-count-too-high", status.slice());
    try std.testing.expectEqual(@as(usize, 0), sm_handoff.count());
    try std.testing.expectEqual(@as(u32, 3), det_queue.count);
    try std.testing.expectEqual(@as(u32, 5), det_queue.last_h);

    // A valid forward h is the only one that parks a bundle and tears the
    // detached slot down; its last_h carries into the bundle.
    handleSmResumeRequest(&server, .{
        .previd = previd,
        .h = 5,
        .req_worker = 1,
        .req_session = 1,
        .req_epoch = 0,
        .auth_local = "alice",
        .auth_domain = "localhost",
        .hops = 0,
    });
    captureSmResumeStatus(&delivery_sys, 1, &status);
    try std.testing.expectEqualStrings("ok", status.slice());
    try std.testing.expect(server.sessions[2] == null);
    const bundle = sm_handoff.take(previd) orelse return error.Missing;
    defer sm_handoff.release(bundle);
    try std.testing.expectEqual(@as(u32, 5), bundle.last_h);
    try std.testing.expectEqual(@as(u32, 6), bundle.base_seq);
    try std.testing.expectEqual(@as(usize, 3), bundle.stanzas.items.len);
}

test "Re-review 7.4: the resume request carries the drain sequence into the bundle" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();
    server.worker_id = 1;
    var delivery_sys = try DeliverySystem.init(std.testing.allocator, 2);
    defer delivery_sys.deinit();
    server.delivery_system = &delivery_sys;
    sm_handoff.resetForTesting();

    const previd = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const det_fds = try makeSocketPair();
    defer posix.close(det_fds[1]);
    const detached = try makeDetachedForResume(&server, 2, previd, 6, 5, 3, det_fds[0]);
    detached.offline_pending = true;
    detached.offline_last_sent_sequence = 41;

    var status = CapturedResumeStatus{};
    handleSmResumeRequest(&server, .{
        .previd = previd,
        .h = 5,
        .req_worker = 1,
        .req_session = 1,
        .req_epoch = 0,
        .auth_local = "alice",
        .auth_domain = "localhost",
        .hops = 0,
    });
    captureSmResumeStatus(&delivery_sys, 1, &status);
    try std.testing.expectEqualStrings("ok", status.slice());

    const bundle = sm_handoff.take(previd) orelse return error.Missing;
    defer sm_handoff.release(bundle);
    try std.testing.expect(bundle.offline_pending);
    try std.testing.expectEqual(@as(u64, 41), bundle.offline_last_sent_sequence);
}

test "Server: S24 cross-worker resume rejects a wrapped h above the sent count" {
    var server = try Server.init("localhost", "127.0.0.1", 0, std.testing.allocator);
    defer server.deinit();
    server.worker_id = 1;
    var delivery_sys = try DeliverySystem.init(std.testing.allocator, 2);
    defer delivery_sys.deinit();
    server.delivery_system = &delivery_sys;
    sm_handoff.resetForTesting();

    // sent=2 (one stanza outstanding at sequence 2), last_h=0xFFFFFFFE. The
    // client reports h=3: numerically 3 is above the 2 sent but below
    // 0xFFFFFFFE, so a plain `h > sent` check reads it as small and accepts
    // credit for a stanza that was never sent. Only the wrap-aware check
    // (h -% last_h is forward, h -% sent overshoots) rejects it.
    const previd = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const det_fds = try makeSocketPair();
    defer posix.close(det_fds[1]);
    _ = try makeDetachedForResume(&server, 2, previd, 2, 0xFFFF_FFFE, 1, det_fds[0]);

    var status = CapturedResumeStatus{};
    handleSmResumeRequest(&server, .{
        .previd = previd,
        .h = 3,
        .req_worker = 1,
        .req_session = 1,
        .req_epoch = 0,
        .auth_local = "alice",
        .auth_domain = "localhost",
        .hops = 0,
    });
    captureSmResumeStatus(&delivery_sys, 1, &status);
    try std.testing.expectEqualStrings("handled-count-too-high", status.slice());
    try std.testing.expectEqual(@as(usize, 0), sm_handoff.count());
    try std.testing.expect(server.sessions[2] != null);
}
