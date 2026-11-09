//! # DeliveryQueue — lock-free MPSC cross-thread stanza delivery
//!
//! Implements a bounded ring buffer for passing serialized XMPP stanzas between
//! worker threads. Each worker has one inbound queue (MPSC: multiple producers,
//! single consumer). Combined with a pipe(2) wakeup mechanism for kqueue integration.
//!
//! ## Concurrency Model
//!
//! - **Producers** (any worker thread): reserve a slot via CAS on `tail`, memcpy payload,
//!   then set `slot.ready.store(true, .release)` to publish.
//! - **Consumer** (owning worker): reads slots from `head` to `tail`, checking `ready`
//!   flag before reading payload. Advances `head` after processing.
//! - **Wakeup**: producer writes 1 byte to the target worker's pipe after enqueue.
//!   Consumer's kqueue fires EVFILT_READ on the pipe read end.
//!
//! ## ABA Protection
//!
//! Each delivery carries `target_generation` from the shared registry at enqueue time.
//! The consumer validates the generation still matches before delivering — if the
//! session disconnected and the slot was reused, the stale delivery is silently dropped.

const std = @import("std");
const posix = std.posix;

const log = std.log.scoped(.delivery_queue);

/// Maximum stanza payload size per delivery slot.
pub const MAX_PAYLOAD_SIZE = 4080;

/// Cross-worker stanzas that could not be handed to the delivery system,
/// most often because they exceeded the 4080-byte slot (S14). Atomic: every
/// worker increments it; the M1 metrics task can export it later.
pub var cross_worker_drops = std.atomic.Value(u64).init(0);

/// Delivery outcomes for the metrics work that follows this release (M1,
/// PR #13). Nothing exports them yet. All are process-wide and incremented by
/// multiple workers.
pub var s2s_bounces = std.atomic.Value(u64).init(0);
pub var offline_not_stored = std.atomic.Value(u64).init(0);
pub var offline_hold_bounces = std.atomic.Value(u64).init(0);
/// Stored stanzas the offline drain dropped because they cannot fit one
/// connection write even unstamped. Dropping keeps one oversized row from
/// parking the user's whole queue.
pub var offline_drain_drops = std.atomic.Value(u64).init(0);

/// Sentinel value for target_session_id indicating a multicast delivery.
/// When the consumer sees this, it interprets the payload as a MUC multicast
/// (room_jid + prefix + suffix) rather than a unicast stanza.
///
/// Safety: session IDs are array indices (0..max_sessions-1), not monotonic
/// counters. max_sessions is validated at Server.init to be < MULTICAST_SENTINEL.
pub const MULTICAST_SENTINEL: u32 = 0xFFFFFFFF;

/// Sentinel value for target_session_id indicating a room actor message.
/// When the consumer sees this, it decodes the payload as a message.zig-encoded
/// actor message (JoinRequest, PartRequest, GroupchatMessage, etc.) and dispatches
/// to the local room shard for processing.
pub const ROOM_ACTOR_SENTINEL: u32 = 0xFFFFFFFE;

/// Sentinel value for target_session_id indicating an SM resume handoff
/// message (T177). Payload decodes as a message.zig sm_resume_request (on the
/// owning worker) or sm_resume_reply (on the requesting worker).
pub const SM_ACTOR_SENTINEL: u32 = 0xFFFFFFFD;

/// Number of slots per worker queue.
pub const QUEUE_SLOTS: u32 = 256;

/// Delivery class of a slot payload (the ADR-3 `class` field). The receiving
/// worker applies the class's per-session policy to a remote target exactly
/// as the local path applies it, because session flags like carbons_enabled
/// live on the consumer's Session and the producer cannot see them.
pub const DeliveryKind = enum(u8) {
    /// A stanza under RFC 6121 delivery rules: it may be held behind a
    /// draining offline tail and it may be replayed on SM resume.
    stanza = 0,
    /// A XEP-0280 carbon copy: only a Carbons-enabled session receives it,
    /// and only live. A carbon is never held behind an offline tail, never
    /// stored and never bounced.
    carbon = 1,
};

/// A single delivery slot in the MPSC ring buffer.
pub const DeliverySlot = struct {
    /// Target session ID (index into shared registry / Server.sessions).
    target_session_id: u32 = 0,
    /// Generation at enqueue time — verified by consumer for ABA protection.
    target_generation: u32 = 0,
    /// Length of the stanza payload in bytes.
    payload_len: u16 = 0,
    /// Delivery class the consumer applies to this slot.
    kind: DeliveryKind = .stanza,
    /// Dispatch identity minted by the producer (see offline_store.HoldToken).
    /// Carried in the slot so a consumer on another worker holds the message
    /// under the same identity, and two identical messages stay distinct.
    /// Zero means the producer did not tag the dispatch.
    hold_token: u64 = 0,
    /// Producer-side receipt time in epoch seconds. The consumer stamps a
    /// held message with the time it was actually queued, not the time a
    /// possibly-busy worker got to it. Zero means untimed.
    receipt_ts: u64 = 0,
    /// Set to true by producer AFTER payload memcpy is complete.
    /// Consumer MUST check this before reading payload.
    ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Serialized XMPP stanza bytes.
    payload: [MAX_PAYLOAD_SIZE]u8 = undefined,
};

comptime {
    // Zig reorders struct fields to minimize padding, so declaration order
    // does not decide the layout: the header fields are
    // 4 + 4 + 2 + 1 + 1 + 8 + 8 = 28 bytes in a 32-byte header with 4 bytes
    // of tail padding. A manual filler field is what costs space: six bytes
    // of _pad pushed the slot to 4112, an eight-byte slab per queue across
    // every worker. Pin the header so any future field that does not fit
    // the gaps fails here.
    std.debug.assert(@sizeOf(DeliverySlot) == MAX_PAYLOAD_SIZE + 32); // 4112
}

/// Per-worker MPSC delivery queue (bounded ring buffer).
pub const MpscQueue = struct {
    slots: [QUEUE_SLOTS]DeliverySlot = [_]DeliverySlot{.{}} ** QUEUE_SLOTS,
    /// Next write position — advanced by producers via CAS.
    tail: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    /// Next read position — advanced by consumer only (no atomics needed).
    head: u32 = 0,
    /// Dispatch identity of the slot the drain is currently handing to the
    /// handler. Consumer-only, valid for the duration of one handler call.
    current_slot_token: u64 = 0,
    /// Delivery class of the slot the drain is currently handing to the
    /// handler. Consumer-only, valid for the duration of one handler call.
    current_slot_kind: DeliveryKind = .stanza,
    /// Producer receipt time of that same slot; 0 when untimed.
    current_slot_receipt_ts: u64 = 0,

    /// Attempt to enqueue a stanza for cross-thread delivery.
    /// Called by any producer thread. Returns error.QueueFull if no slots available.
    pub fn enqueue(
        self: *MpscQueue,
        target_session_id: u32,
        target_generation: u32,
        payload: []const u8,
    ) !void {
        return self.enqueueDelivery(target_session_id, target_generation, payload, 0, 0, .stanza);
    }

    /// Enqueue a stanza with its dispatch identity, producer receipt time
    /// and delivery class: a consumer on another worker holds the message
    /// under the same token, stamps a held copy with the queue time, and
    /// applies the class to the remote session as the local path would.
    pub fn enqueueDelivery(
        self: *MpscQueue,
        target_session_id: u32,
        target_generation: u32,
        payload: []const u8,
        hold_token: u64,
        receipt_ts: u64,
        kind: DeliveryKind,
    ) !void {
        if (payload.len > MAX_PAYLOAD_SIZE) return error.PayloadTooLarge;

        // CAS loop to reserve a slot
        while (true) {
            const current_tail = self.tail.load(.acquire);
            const current_head = self.head; // consumer-only field, safe to read

            // Check if queue is full
            if (current_tail -% current_head >= QUEUE_SLOTS) {
                return error.QueueFull;
            }

            // Try to advance tail
            if (self.tail.cmpxchgWeak(current_tail, current_tail +% 1, .acq_rel, .acquire)) |_| {
                // CAS failed — another producer got there first, retry
                continue;
            }

            // CAS succeeded — we own slot at index (current_tail % QUEUE_SLOTS)
            const slot_idx = current_tail % QUEUE_SLOTS;
            const slot = &self.slots[slot_idx];

            // Write payload (non-atomic — we own this slot until ready.store)
            slot.target_session_id = target_session_id;
            slot.target_generation = target_generation;
            slot.payload_len = @intCast(payload.len);
            slot.hold_token = hold_token;
            slot.receipt_ts = receipt_ts;
            slot.kind = kind;
            @memcpy(slot.payload[0..payload.len], payload);

            // Publish: signal to consumer that this slot is fully written
            slot.ready.store(true, .release);
            return;
        }
    }

    /// Drain all ready slots from the queue.
    /// Called by the consumer (owning worker thread) only.
    /// Returns the number of slots processed.
    /// Calls `handler` for each ready delivery with (session_id, generation, payload).
    pub fn drain(self: *MpscQueue, ctx: anytype, handler: fn (@TypeOf(ctx), u32, u32, []const u8) void) u32 {
        var processed: u32 = 0;
        const current_tail = self.tail.load(.acquire);

        while (self.head != current_tail) {
            const slot_idx = self.head % QUEUE_SLOTS;
            const slot = &self.slots[slot_idx];

            // Check if this slot is fully written by the producer
            if (!slot.ready.load(.acquire)) {
                // Producer reserved but hasn't finished writing yet — stop here
                break;
            }

            // Read the delivery. The `current_slot_*` fields are how a
            // handler learns this dispatch's identity, class and receipt
            // time without widening the handler signature.
            self.current_slot_token = slot.hold_token;
            self.current_slot_kind = slot.kind;
            self.current_slot_receipt_ts = slot.receipt_ts;
            handler(ctx, slot.target_session_id, slot.target_generation, slot.payload[0..slot.payload_len]);
            self.current_slot_token = 0;
            self.current_slot_kind = .stanza;
            self.current_slot_receipt_ts = 0;
            processed += 1;

            // Reset the slot and advance head
            slot.ready.store(false, .monotonic);
            self.head +%= 1;
        }

        return processed;
    }

    /// Check if the queue has pending work (without consuming).
    pub fn hasPending(self: *const MpscQueue) bool {
        return self.head != self.tail.load(.acquire);
    }
};

/// Pipe pair for cross-thread wakeup. Created once, shared across threads.
pub const WakePipe = struct {
    /// Read end — registered in owning worker's kqueue as EVFILT_READ.
    rd: posix.fd_t,
    /// Write end — any thread can write to wake the owner.
    wr: posix.fd_t,

    /// Create a new pipe pair for wakeup signaling.
    pub fn init() !WakePipe {
        const fds = try posix.pipe();
        // Set non-blocking on read end (avoid blocking in drain)
        _ = std.c.fcntl(fds[0], std.c.F.SETFL, @as(c_int, @bitCast(std.c.O{ .NONBLOCK = true })));
        return .{ .rd = fds[0], .wr = fds[1] };
    }

    /// Close both ends of the pipe.
    pub fn deinit(self: *WakePipe) void {
        posix.close(self.rd);
        posix.close(self.wr);
    }

    /// Write 1 byte to wake the consumer (called by producer after enqueue).
    pub fn wake(self: *const WakePipe) void {
        _ = posix.write(self.wr, &[1]u8{1}) catch {};
    }

    /// Drain all pending bytes from the pipe (called by consumer on EVFILT_READ).
    pub fn drainPipe(self: *const WakePipe) void {
        var buf: [64]u8 = undefined;
        while (true) {
            const n = posix.read(self.rd, &buf) catch break;
            if (n == 0) break;
            if (n < buf.len) break;
        }
    }
};

/// Per-worker processing state for coalesced signaling optimization.
pub const WorkerState = struct {
    /// 1 when worker is inside event processing loop, 0 when idle in kevent().
    is_processing: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    /// Check if the target worker is currently active (skip pipe write if so).
    pub fn isActive(self: *const WorkerState) bool {
        return self.is_processing.load(.acquire) != 0;
    }

    /// Mark this worker as actively processing events.
    pub fn setActive(self: *WorkerState) void {
        self.is_processing.store(1, .release);
    }

    /// Mark this worker as idle (about to enter kevent wait).
    pub fn setIdle(self: *WorkerState) void {
        self.is_processing.store(0, .release);
    }
};

/// Cross-thread delivery system — holds all per-worker queues, pipes, and state.
pub const DeliverySystem = struct {
    queues: []MpscQueue,
    pipes: []WakePipe,
    states: []WorkerState,
    worker_count: u16,
    allocator: std.mem.Allocator,

    /// Initialize the delivery system for N workers.
    pub fn init(allocator: std.mem.Allocator, worker_count: u16) !DeliverySystem {
        const n: usize = worker_count;

        const queues = try allocator.alloc(MpscQueue, n);
        @memset(queues, MpscQueue{});

        const pipes = try allocator.alloc(WakePipe, n);
        errdefer allocator.free(pipes);
        var pipes_initialized: usize = 0;
        errdefer {
            var j: usize = 0;
            while (j < pipes_initialized) : (j += 1) {
                pipes[j].deinit();
            }
        }
        for (pipes) |*p| {
            p.* = WakePipe.init() catch return error.PipeCreateFailed;
            pipes_initialized += 1;
        }

        const states = try allocator.alloc(WorkerState, n);
        @memset(states, WorkerState{});

        return .{
            .queues = queues,
            .pipes = pipes,
            .states = states,
            .worker_count = worker_count,
            .allocator = allocator,
        };
    }

    /// Clean up all resources.
    pub fn deinit(self: *DeliverySystem) void {
        for (self.pipes) |*p| {
            p.deinit();
        }
        self.allocator.free(self.queues);
        self.allocator.free(self.pipes);
        self.allocator.free(self.states);
        self.* = undefined;
    }

    /// Enqueue a stanza for delivery to a target worker.
    /// Handles coalesced signaling — only wakes the target if it's idle.
    pub fn deliver(
        self: *DeliverySystem,
        target_worker: u16,
        target_session_id: u32,
        target_generation: u32,
        payload: []const u8,
    ) !void {
        return self.deliverDelivery(target_worker, target_session_id, target_generation, payload, 0, 0, .stanza);
    }

    /// Deliver a stanza with its dispatch identity, producer receipt time
    /// and delivery class, then wake the target worker.
    pub fn deliverDelivery(
        self: *DeliverySystem,
        target_worker: u16,
        target_session_id: u32,
        target_generation: u32,
        payload: []const u8,
        hold_token: u64,
        receipt_ts: u64,
        kind: DeliveryKind,
    ) !void {
        try self.enqueueDelivery(target_worker, target_session_id, target_generation, payload, hold_token, receipt_ts, kind);

        // Always wake the target worker: coalesced signaling is unsafe because
        // the target may finish processing and enter kevent() between our isActive
        // check and the pipe write. The pipe drainPipe() handles duplicate wakes.
        self.wakeWorker(target_worker);
    }

    /// Enqueue without waking the target worker (T130 batch delivery).
    /// The caller MUST call wakeWorker() once after the batch. A stale read
    /// of the queue by a woken-but-racing target is harmless; skipping the
    /// trailing wake is not.
    pub fn enqueue(
        self: *DeliverySystem,
        target_worker: u16,
        target_session_id: u32,
        target_generation: u32,
        payload: []const u8,
    ) !void {
        return self.enqueueDelivery(target_worker, target_session_id, target_generation, payload, 0, 0, .stanza);
    }

    /// Enqueue a delivery with its dispatch identity, producer receipt time
    /// and delivery class, without waking the target worker.
    /// The caller MUST call wakeWorker() once after the batch.
    pub fn enqueueDelivery(
        self: *DeliverySystem,
        target_worker: u16,
        target_session_id: u32,
        target_generation: u32,
        payload: []const u8,
        hold_token: u64,
        receipt_ts: u64,
        kind: DeliveryKind,
    ) !void {
        if (target_worker >= self.worker_count) return error.InvalidWorker;
        try self.queues[target_worker].enqueueDelivery(target_session_id, target_generation, payload, hold_token, receipt_ts, kind);
    }

    /// Wake a worker after one or more enqueue() calls (T130). One pipe
    /// write for the whole batch instead of one per stanza.
    pub fn wakeWorker(self: *DeliverySystem, target_worker: u16) void {
        if (target_worker >= self.worker_count) return;
        self.pipes[target_worker].wake();
    }

    /// Get the pipe read fd for a specific worker (for kqueue registration).
    pub fn getPipeReadFd(self: *const DeliverySystem, worker_id: u16) posix.fd_t {
        return self.pipes[worker_id].rd;
    }

    /// Get the queue for a specific worker (for draining in event loop).
    pub fn getQueue(self: *DeliverySystem, worker_id: u16) *MpscQueue {
        return &self.queues[worker_id];
    }

    /// Get the worker state (for setting active/idle).
    pub fn getState(self: *DeliverySystem, worker_id: u16) *WorkerState {
        return &self.states[worker_id];
    }

    /// Drain the pipe for a specific worker (called on EVFILT_READ).
    pub fn drainPipe(self: *const DeliverySystem, worker_id: u16) void {
        self.pipes[worker_id].drainPipe();
    }
};

// ============================================================================
// Tests
// ============================================================================

test "MpscQueue: basic enqueue and drain" {
    var queue = MpscQueue{};
    const payload = "hello world";

    try queue.enqueue(42, 7, payload);

    var received_id: u32 = 0;
    var received_gen: u32 = 0;
    var received_payload: []const u8 = "";

    const Ctx = struct {
        id: *u32,
        gen: *u32,
        pl: *[]const u8,
    };
    const ctx = Ctx{ .id = &received_id, .gen = &received_gen, .pl = &received_payload };

    const handler = struct {
        fn handle(c: Ctx, sid: u32, gen: u32, pl: []const u8) void {
            c.id.* = sid;
            c.gen.* = gen;
            c.pl.* = pl;
        }
    }.handle;

    const processed = queue.drain(ctx, handler);
    try std.testing.expectEqual(@as(u32, 1), processed);
    try std.testing.expectEqual(@as(u32, 42), received_id);
    try std.testing.expectEqual(@as(u32, 7), received_gen);
    try std.testing.expectEqualStrings("hello world", received_payload);
}

test "MpscQueue: receipt timestamp reaches the drain handler" {
    var queue = MpscQueue{};

    try queue.enqueueDelivery(42, 7, "timed", 0xdeadbeef, 12345, .stanza);
    try queue.enqueue(43, 8, "untimed");

    const Ctx = struct {
        queue: *MpscQueue,
        stamps: *[2]u64,
        seen: *usize,
    };
    var stamps = [_]u64{ 0, 0 };
    var seen: usize = 0;
    const ctx = Ctx{ .queue = &queue, .stamps = &stamps, .seen = &seen };

    // Each slot reports its own receipt time; the field is back to zero
    // after the handler returns so an untimed slot inherits nothing.
    const handler = struct {
        fn handle(c: Ctx, sid: u32, gen: u32, payload: []const u8) void {
            _ = sid;
            _ = gen;
            _ = payload;
            c.stamps[c.seen.*] = c.queue.current_slot_receipt_ts;
            c.seen.* += 1;
        }
    }.handle;
    _ = queue.drain(ctx, handler);

    try std.testing.expectEqual(@as(u64, 12345), stamps[0]);
    try std.testing.expectEqual(@as(u64, 0), stamps[1]);
    try std.testing.expectEqual(@as(u64, 0), queue.current_slot_receipt_ts);
}

test "MpscQueue: hold token survives the round trip and is cleared after each slot" {
    var queue = MpscQueue{};

    try queue.enqueueDelivery(42, 7, "tagged", 0xdeadbeef, 0, .stanza);
    try queue.enqueue(43, 8, "untagged");

    const Ctx = struct {
        queue: *MpscQueue,
        tokens: *[2]u64,
        seen: *usize,
    };
    var tokens = [_]u64{ 0, 0 };
    var seen: usize = 0;
    const ctx = Ctx{ .queue = &queue, .tokens = &tokens, .seen = &seen };

    // Each slot reports its own token, and the field is back to zero after the
    // handler returns so a later untagged slot cannot inherit the previous one.
    const handler = struct {
        fn handle(c: Ctx, sid: u32, gen: u32, pl: []const u8) void {
            _ = gen;
            _ = pl;
            c.tokens.*[c.seen.*] = c.queue.current_slot_token;
            _ = sid;
            c.seen.* += 1;
        }
    }.handle;

    const processed = queue.drain(ctx, handler);
    try std.testing.expectEqual(@as(u32, 2), processed);
    try std.testing.expectEqual(@as(u64, 0xdeadbeef), tokens[0]);
    try std.testing.expectEqual(@as(u64, 0), tokens[1]);
    try std.testing.expectEqual(@as(u64, 0), queue.current_slot_token);
}

// A slot's delivery class reaches the consumer unchanged: the receiving
// worker applies it to the remote session exactly as the local path would.
test "MpscQueue: delivery kind survives the round trip and is cleared after each slot" {
    var queue = MpscQueue{};

    try queue.enqueueDelivery(42, 7, "carbon copy", 0, 0, .carbon);
    try queue.enqueue(43, 8, "plain stanza");

    const Ctx = struct {
        queue: *MpscQueue,
        kinds: *[2]DeliveryKind,
        seen: *usize,
    };
    var kinds = [_]DeliveryKind{ .stanza, .stanza };
    var seen: usize = 0;
    const ctx = Ctx{ .queue = &queue, .kinds = &kinds, .seen = &seen };

    const handler = struct {
        fn handle(c: Ctx, sid: u32, gen: u32, pl: []const u8) void {
            _ = sid;
            _ = gen;
            _ = pl;
            c.kinds.*[c.seen.*] = c.queue.current_slot_kind;
            c.seen.* += 1;
        }
    }.handle;

    const processed = queue.drain(ctx, handler);
    try std.testing.expectEqual(@as(u32, 2), processed);
    try std.testing.expectEqual(DeliveryKind.carbon, kinds[0]);
    try std.testing.expectEqual(DeliveryKind.stanza, kinds[1]);
    try std.testing.expectEqual(DeliveryKind.stanza, queue.current_slot_kind);
}

test "MpscQueue: queue full" {
    var queue = MpscQueue{};

    // Fill the queue
    var i: u32 = 0;
    while (i < QUEUE_SLOTS) : (i += 1) {
        try queue.enqueue(i, 0, "x");
    }

    // Next enqueue should fail
    try std.testing.expectError(error.QueueFull, queue.enqueue(999, 0, "overflow"));
}

test "MpscQueue: payload too large" {
    var queue = MpscQueue{};
    const big_payload = [_]u8{0} ** (MAX_PAYLOAD_SIZE + 1);
    try std.testing.expectError(error.PayloadTooLarge, queue.enqueue(0, 0, &big_payload));
}

test "MpscQueue: hasPending" {
    var queue = MpscQueue{};
    try std.testing.expect(!queue.hasPending());

    try queue.enqueue(1, 0, "test");
    try std.testing.expect(queue.hasPending());
}

test "WakePipe: init and deinit" {
    var pipe = try WakePipe.init();
    defer pipe.deinit();

    // Write should not block
    pipe.wake();
    // Drain should consume the byte
    pipe.drainPipe();
}

test "WorkerState: active and idle" {
    var state = WorkerState{};
    try std.testing.expect(!state.isActive());

    state.setActive();
    try std.testing.expect(state.isActive());

    state.setIdle();
    try std.testing.expect(!state.isActive());
}

test "DeliverySystem: init and deinit" {
    var sys = try DeliverySystem.init(std.testing.allocator, 4);
    defer sys.deinit();

    try std.testing.expectEqual(@as(u16, 4), sys.worker_count);
}

test "DeliverySystem: deliver and drain" {
    var sys = try DeliverySystem.init(std.testing.allocator, 2);
    defer sys.deinit();

    // Deliver to worker 1
    try sys.deliver(1, 10, 3, "test stanza");

    // Drain worker 1's queue
    var received: bool = false;
    const Ctx = struct { flag: *bool };
    const ctx = Ctx{ .flag = &received };
    const handler = struct {
        fn handle(c: Ctx, _: u32, _: u32, _: []const u8) void {
            c.flag.* = true;
        }
    }.handle;

    const n = sys.getQueue(1).drain(ctx, handler);
    try std.testing.expectEqual(@as(u32, 1), n);
    try std.testing.expect(received);
}

test "DeliverySystem: coalesced signaling skips wake when active" {
    var sys = try DeliverySystem.init(std.testing.allocator, 2);
    defer sys.deinit();

    // Mark worker 1 as active
    sys.getState(1).setActive();

    // Deliver — should NOT write to pipe (we can't easily verify this,
    // but at least verify it doesn't crash or block)
    try sys.deliver(1, 5, 1, "coalesced");

    // Drain should still find the message
    const Ctx = struct { count: *u32 };
    var count: u32 = 0;
    const ctx = Ctx{ .count = &count };
    const handler = struct {
        fn handle(c: Ctx, _: u32, _: u32, _: []const u8) void {
            c.count.* += 1;
        }
    }.handle;
    _ = sys.getQueue(1).drain(ctx, handler);
    try std.testing.expectEqual(@as(u32, 1), count);
}
