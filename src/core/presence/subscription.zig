//! # presence/subscription: subscription-cache invalidation
//!
//! invalidateSubCache moved out of server.zig (ADR-12). The subscription
//! cache is per-worker memory, so a roster or subscription change drops the
//! entry locally and on every other worker through the room-actor mailbox.

const server_mod = @import("../server.zig");
const Server = server_mod.Server;
const sub_cache_mod = server_mod.sub_cache_mod;
const muc_actor = @import("../muc/actor.zig");

/// Invalidate a bare JID's subscription-cache entry locally AND on all
/// other workers. The sub_cache is per-worker memory with a 30s TTL —
/// a roster/subscription change on one worker must not leave the others
/// serving a stale subscriber list (cross-worker presence broadcast was
/// silently skipped: e2e-subscription Test 7 at workers>1).
pub fn invalidateSubCache(self: *Server, bare_jid: []const u8) void {
    self.sub_cache.invalidate(sub_cache_mod.hashBareJid(bare_jid));
    const wc = muc_actor.getWorkerCount(self);
    if (wc <= 1) return;
    var w: u16 = 0;
    while (w < wc) : (w += 1) {
        if (w == self.worker_id) continue;
        muc_actor.enqueueRoomActorMessage(self, w, .{ .invalidate_subscription = .{ .bare_jid = bare_jid } });
    }
}
