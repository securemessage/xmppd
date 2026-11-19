//! # muc/actor: room actor dispatch and mailbox drain
//!
//! The cross-worker room actor moved out of server.zig (ADR-12): inbound
//! actor messages are demultiplexed into per-room mailboxes, the mailboxes
//! drain round-robin, and enqueue/getWorkerCount are the producer side.

const std = @import("std");
const server_mod = @import("../worker/worker.zig");
const Server = server_mod.Server;
const sub_cache_mod = server_mod.sub_cache_mod;
const ChangeList = @import("../worker/loop.zig").ChangeList;
const actor_message = @import("../xworker/envelope.zig");
const room_registry_mod = @import("room_registry");
const room_mailbox_mod = @import("room_mailbox");
const delivery_queue_mod = @import("delivery_queue");
const muc_handler = @import("handler.zig");
const router = @import("../routing/router.zig");
const noteDrop = @import("../c2s/session.zig").noteDrop;

const log = std.log.scoped(.xmppd);

/// Handle a room actor message from the MPSC queue.
/// Room-targeted messages (join, part, groupchat, disco) are pushed into the
/// target room's per-room mailbox for fair scheduling. Non-room messages
/// (shadow updates, session close) are dispatched immediately.
pub fn handleRoomActorMessage(self: *Server, blob: *delivery_queue_mod.Blob, changes: *ChangeList) void {
    const payload = blob.bytes();
    const msg = actor_message.decode(payload) orelse {
        log.warn("malformed room actor message ({d} bytes)", .{payload.len});
        return;
    };

    switch (msg) {
        .room_join, .room_part, .room_message, .room_disco_info, .room_disco_items, .room_admin, .room_mam_query => {
            // Extract room_jid to find target room's mailbox
            const room_jid = switch (msg) {
                .room_join, .room_part => |ev| ev.room_jid,
                .room_message => |ev| ev.room_jid,
                .room_disco_info, .room_disco_items => |ev| ev.room_jid,
                .room_admin => |ev| ev.room_jid,
                .room_mam_query => |ev| ev.room_jid,
                else => unreachable,
            };
            const reg = self.room_registry orelse return;
            // Find room — for room_join, the room may not exist yet.
            // processRemoteJoin will create it (with proper is_new_room logic).
            var room = reg.findByJid(room_jid);
            if (room == null) {
                if (std.meta.activeTag(msg) == .room_join) {
                    // Create a minimal room so the mailbox exists for enqueue
                    room = reg.createRoom(room_jid, .{ .persistent = false }) catch {
                        _ = room_mailbox_mod.mailbox_drops.fetchAdd(1, .monotonic);
                        log.warn("room_join for {s} dropped: room table full", .{room_jid});
                        return;
                    };
                    // Mark that processRemoteJoin should treat this as new
                    room.?.occupant_count = 0;
                } else {
                    log.debug("room actor msg for unknown room: {s}", .{room_jid});
                    return;
                }
            }
            const r = room.?;
            r.mailbox.enqueue(&reg.item_pool, blob) catch {
                _ = room_mailbox_mod.mailbox_drops.fetchAdd(1, .monotonic);
                log.warn("room mailbox full for {s} — bouncing to sender (S16)", .{room_jid});
                muc_handler.bounceRoomMailboxFull(self, msg, room_jid, changes);
            };
            if (r.mailbox.hasPending()) reg.markPending(r);
        },
        .room_directory_update => |ev| {
            muc_handler.handleRoomDirectoryUpdate(self, ev);
        },
        .invalidate_subscription => |ev| {
            // Cross-worker cache invalidation — local invalidate only;
            // do NOT re-broadcast (would cascade).
            self.sub_cache.invalidate(sub_cache_mod.hashBareJid(ev.bare_jid));
        },
        .shadow_join => |ev| {
            muc_handler.handleShadowJoin(self, ev);
        },
        .shadow_part => |ev| {
            muc_handler.handleShadowPart(self, ev);
        },
        .room_occupant_move => |ev| {
            // T177: immediate dispatch (see handleOccupantMove) — the move
            // only mutates a delivery triple, so mailbox ordering with
            // queued join/part/message traffic is not required.
            muc_handler.handleOccupantMove(self, ev);
        },
        .session_closed => |ev| {
            var jid_buf: [router.FULL_JID_MAX]u8 = undefined;
            const real_jid = router.buildFullJid(ev.local, ev.domain, ev.resource, &jid_buf) catch {
                noteDrop("session_closed for {s}@{s}: full JID exceeds {d} bytes; room cleanup skipped", .{ ev.local, ev.domain, router.FULL_JID_MAX });
                return;
            };
            // local_only=true: this is already a broadcast from the originating
            // worker. Do NOT re-broadcast to avoid infinite cascade.
            muc_handler.handleSessionCloseLocal(self, real_jid, changes);
        },
        else => {
            log.warn("unexpected actor message tag in room dispatch: 0x{x:0>2}", .{msg.tag()});
        },
    }
}

/// Drain per-room mailboxes via the registry's pending FIFO: only rooms
/// that actually hold mail are visited — no per-tick scan of reg.rooms.
/// One message per room per visit, re-linked at the tail when more
/// remains, so the round-robin fairness is identical to the old scan.
/// Bounded to MAX_DRAIN_PER_TICK total messages.
/// Returns true if rooms still hold mail (caller should self-wake).
pub fn drainRoomMailboxes(self: *Server, changes: *ChangeList) bool {
    const reg = self.room_registry orelse return false;
    const MAX_DRAIN_PER_TICK: usize = 32;
    var processed: usize = 0;

    while (processed < MAX_DRAIN_PER_TICK) {
        const room = reg.popPending() orelse break;
        const blob = room.mailbox.dequeue(&reg.item_pool) orelse continue;
        // Re-link BEFORE processing: the handler may destroy the room
        // (cleanupEmptyRooms runs below, but a handler can still end its
        // active flag), and a still-pending room must keep its place in
        // the FIFO.
        if (room.mailbox.hasPending()) reg.markPending(room);
        processRoomMailboxMessage(self, room, blob.bytes(), changes);
        blob.release();
        processed += 1;
    }

    // Deferred room cleanup: destroy empty transient rooms AFTER all mailbox
    // processing. This is the single destruction point — avoids ordering
    // conflicts between session_closed (immediate) and room_part (mailbox),
    // and avoids use-after-free of decoded payload slices during processing.
    muc_handler.cleanupEmptyRooms(self);

    return reg.pending_head != null;
}

/// Process a single message from a room's mailbox.
fn processRoomMailboxMessage(self: *Server, room: *room_registry_mod.Room, payload: []const u8, changes: *ChangeList) void {
    const msg = actor_message.decode(payload) orelse return;
    switch (msg) {
        .room_join => |ev| {
            muc_handler.processRemoteJoin(self, ev, changes);
        },
        .room_part => |ev| {
            muc_handler.processRemotePart(self, ev, changes);
        },
        .room_message => |ev| {
            muc_handler.processRemoteGroupchat(self, ev, changes);
        },
        .room_disco_info => |ev| {
            muc_handler.processRemoteDiscoInfo(self, ev, changes);
        },
        .room_disco_items => |ev| {
            muc_handler.processRemoteDiscoItems(self, ev, changes);
        },
        .room_admin => |ev| {
            muc_handler.processRemoteAdminAction(self, ev, changes);
        },
        .room_mam_query => |ev| {
            muc_handler.processRemoteMamQuery(self, ev, changes);
        },
        else => {
            _ = room;
            log.warn("unexpected message in room mailbox: 0x{x:0>2}", .{msg.tag()});
        },
    }
}

/// Enqueue a room actor message to the owning worker via MPSC.
/// Used by muc_handler when a MUC operation lands on a non-owning worker.
pub fn enqueueRoomActorMessage(self: *Server, target_worker: u16, msg: actor_message.Message) void {
    const ds = self.delivery_system orelse return;
    var enc_lease = self.leaseByteScratch() orelse {
        log.warn("byte-scratch exhausted; room actor message dropped", .{});
        return;
    };
    defer enc_lease.release();
    const len = actor_message.encode(enc_lease.buf, msg) orelse {
        log.warn("room actor message encode failed", .{});
        return;
    };
    ds.deliverActor(self.worker_id, target_worker, delivery_queue_mod.ROOM_ACTOR_TARGET, enc_lease.buf[0..len], 0, 0, .room_actor) catch |err| {
        _ = delivery_queue_mod.actor_retry_drops.fetchAdd(1, .monotonic);
        log.warn("room actor enqueue to worker {d} failed: {}", .{ target_worker, err });
    };
}

/// Re-attempt actor envelopes this worker produced whose target ring was
/// full; exhausted entries take their class fallback and are counted.
pub fn drainActorRetries(self: *Server) void {
    const ds = self.delivery_system orelse return;
    ds.retry_lists[self.worker_id].drain(ds, self, muc_handler.noteActorRetryExhausted);
}

/// Get the number of workers (for room ownership computation).
pub fn getWorkerCount(self: *const Server) u16 {
    if (self.delivery_system) |ds| return ds.worker_count;
    return 1;
}
