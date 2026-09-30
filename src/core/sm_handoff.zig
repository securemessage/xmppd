//! # SM Handoff Store — cross-worker XEP-0198 resume state transfer (T177)
//!
//! The MPSC delivery ring uses fixed 4KB slots, but a resumable session's
//! unacked queue can hold 256 stanzas — far beyond a slot. Since all workers
//! are threads in one process, the owning worker parks a deep-copied bundle
//! here under a mutex, and the resuming worker takes it when the reply
//! arrives. Only the small request/reply messages ride the MPSC queue.
//!
//! ## Lifetime
//!
//! Bundles are owned by the store between put() and take(). The resuming
//! worker takes and frees. Orphans (resuming connection died mid-handoff)
//! are purged on insert once older than the SM resume timeout. The store is
//! bounded (MAX_BUNDLES) so a burst of zombie resumes cannot grow it without
//! bound.
//!
//! ## Allocator discipline
//!
//! Everything here is allocated with the C allocator: per-worker allocators
//! are not required to be thread-safe, and a bundle produced on worker A is
//! freed on worker B.

const std = @import("std");
const sm_state = @import("sm_state.zig");

const log = std.log.scoped(.sm_handoff);

/// Maximum bundles held concurrently. Each can carry up to UNACKED_CAPACITY
/// stanzas, so this bounds worst-case store memory.
pub const MAX_BUNDLES: usize = 32;

/// Deep-copied state of a detached SM session being transferred between
/// workers. All slices are owned by the bundle (C allocator).
pub const ResumeBundle = struct {
    previd: [sm_state.SM_ID_HEX_LEN]u8,
    sm_in_h: u32,
    sm_out_seq: u32,
    sm_out_h: u32,
    r_outstanding: bool,
    roster_interested: bool,
    carbons_enabled: bool,
    csi_active: bool,
    username: []u8,
    resource: []u8,
    last_presence: []u8,
    /// Remaining unacked stanzas (source queue was ack()-trimmed first).
    stanzas: std.ArrayListUnmanaged([]u8) = .{},
    /// sm_out_seq value of stanzas[0], i.e. the source queue's base_seq.
    base_seq: u32,
    created: i64,

    pub fn deinit(self: *ResumeBundle) void {
        allocator.free(self.username);
        allocator.free(self.resource);
        allocator.free(self.last_presence);
        for (self.stanzas.items) |s| allocator.free(s);
        self.stanzas.deinit(allocator);
    }
};

pub const allocator = std.heap.c_allocator;

var mutex: std.Thread.Mutex = .{};
var bundles: std.StringHashMapUnmanaged(*ResumeBundle) = .{};

/// Publish a bundle keyed by previd. Fails if the store is full or the key
/// is already present (a stale bundle for the same id is replaced).
pub fn put(previd: []const u8, bundle: *ResumeBundle) !void {
    mutex.lock();
    defer mutex.unlock();

    if (previd.len != sm_state.SM_ID_HEX_LEN) return error.InvalidPrevid;

    purgeExpiredLocked(std.time.timestamp());

    // A second extract for the same previd (double resume racing): evict the
    // older bundle — the newest extraction reflects the queue's final state.
    if (bundles.fetchRemove(previd)) |old| {
        old.value.deinit();
        allocator.destroy(old.value);
    }

    if (bundles.count() >= MAX_BUNDLES) {
        log.warn("handoff store full ({d} bundles), rejecting", .{bundles.count()});
        return error.StoreFull;
    }

    const key = try allocator.dupe(u8, previd);
    try bundles.put(allocator, key, bundle);
}

/// Remove and return the bundle for previd, or null. Caller owns it.
pub fn take(previd: []const u8) ?*ResumeBundle {
    mutex.lock();
    defer mutex.unlock();

    const kv = bundles.fetchRemove(previd) orelse return null;
    allocator.free(kv.key);
    return kv.value;
}

/// Free a bundle no longer needed (consumed or abandoned).
pub fn release(bundle: *ResumeBundle) void {
    bundle.deinit();
    allocator.destroy(bundle);
}

/// Drop bundles older than the SM resume timeout. Also runs on put().
fn purgeExpiredLocked(now: i64) void {
    var stale: [MAX_BUNDLES][]const u8 = undefined;
    var stale_count: usize = 0;

    var it = bundles.iterator();
    while (it.next()) |kv| {
        if (now - kv.value_ptr.*.created > sm_state.DEFAULT_RESUME_TIMEOUT) {
            if (stale_count < stale.len) {
                stale[stale_count] = kv.key_ptr.*;
                stale_count += 1;
            }
        }
    }

    for (stale[0..stale_count]) |key| {
        const kv = bundles.fetchRemove(key).?;
        log.info("purged abandoned resume bundle {s}", .{kv.key});
        kv.value.deinit();
        allocator.destroy(kv.value);
        allocator.free(kv.key);
    }
}

pub fn count() usize {
    mutex.lock();
    defer mutex.unlock();
    return bundles.count();
}

/// Test helper: drop all bundles.
pub fn resetForTesting() void {
    mutex.lock();
    defer mutex.unlock();
    var it = bundles.iterator();
    while (it.next()) |kv| {
        kv.value_ptr.*.deinit();
        allocator.destroy(kv.value_ptr.*);
        allocator.free(kv.key_ptr.*);
    }
    bundles.clearRetainingCapacity();
}

// ============================================================================
// Tests
// ============================================================================

fn testBundle(previd_suffix: u8) !*ResumeBundle {
    const b = try allocator.create(ResumeBundle);
    b.* = .{
        .previd = [_]u8{previd_suffix} ** sm_state.SM_ID_HEX_LEN,
        .sm_in_h = 7,
        .sm_out_seq = 42,
        .sm_out_h = 40,
        .r_outstanding = false,
        .roster_interested = true,
        .carbons_enabled = false,
        .csi_active = true,
        .username = try allocator.dupe(u8, "alice"),
        .resource = try allocator.dupe(u8, "phone"),
        .last_presence = try allocator.dupe(u8, "<show>away</show>"),
        .base_seq = 3,
        .created = std.time.timestamp(),
    };
    try b.stanzas.append(allocator, try allocator.dupe(u8, "<message/>"));
    try b.stanzas.append(allocator, try allocator.dupe(u8, "<presence/>"));
    return b;
}

test "handoff store: put and take roundtrip" {
    defer resetForTesting();
    const b = try testBundle('a');
    try put(&b.previd, b);
    try std.testing.expectEqual(@as(usize, 1), count());

    const got = take(&b.previd) orelse return error.Missing;
    try std.testing.expectEqual(@as(u32, 7), got.sm_in_h);
    try std.testing.expectEqual(@as(u32, 3), got.base_seq);
    try std.testing.expectEqualStrings("alice", got.username);
    try std.testing.expectEqual(@as(usize, 2), got.stanzas.items.len);
    release(got);
    try std.testing.expectEqual(@as(usize, 0), count());
}

test "handoff store: take of unknown key returns null" {
    defer resetForTesting();
    const unknown = [_]u8{'z'} ** sm_state.SM_ID_HEX_LEN;
    try std.testing.expect(take(&unknown) == null);
}

test "handoff store: re-put of same key replaces bundle" {
    defer resetForTesting();
    const b1 = try testBundle('a');
    try put(&b1.previd, b1);
    const b2 = try testBundle('a');
    b2.sm_in_h = 99;
    try put(&b2.previd, b2);
    try std.testing.expectEqual(@as(usize, 1), count());

    const got = take(&b1.previd) orelse return error.Missing;
    try std.testing.expectEqual(@as(u32, 99), got.sm_in_h);
    release(got);
}

test "handoff store: expired bundles are purged on put" {
    defer resetForTesting();
    const old = try testBundle('o');
    old.created = std.time.timestamp() - (sm_state.DEFAULT_RESUME_TIMEOUT + 60);
    try put(&old.previd, old);
    try std.testing.expectEqual(@as(usize, 1), count());

    const fresh = try testBundle('f');
    try put(&fresh.previd, fresh);
    // Only the fresh entry survives
    try std.testing.expectEqual(@as(usize, 1), count());
    try std.testing.expect(take(&old.previd) == null);

    const got = take(&fresh.previd) orelse return error.Missing;
    release(got);
}

test "handoff store: cap rejects excess bundles" {
    defer resetForTesting();
    var i: usize = 0;
    while (i < MAX_BUNDLES) : (i += 1) {
        const b = try testBundle('x');
        b.previd[sm_state.SM_ID_HEX_LEN - 1] = @intCast(i % 26 + 'a');
        b.previd[sm_state.SM_ID_HEX_LEN - 2] = @intCast(i / 26 + 'A');
        try put(&b.previd, b);
    }
    const extra = try testBundle('x');
    try std.testing.expectError(error.StoreFull, put(&extra.previd, extra));
    release(extra);
}
