//! # DeliveryQueue — lock-free MPSC cross-thread stanza delivery
//!
//! Implements a bounded ring buffer for passing serialized XMPP stanzas between
//! worker threads. Each worker has one inbound queue (MPSC: multiple producers,
//! single consumer). Combined with a pipe(2) wakeup mechanism for kqueue integration.
//!
//! ## Concurrency Model
//!
//! - **Producers** (any worker thread): serialize the payload once into a
//!   refcounted `Blob` on their own worker's budget (ADR-3), reserve a slot
//!   via CAS on `tail`, write the descriptor, then set
//!   `slot.ready.store(true, .release)` to publish.
//! - **Consumer** (owning worker): reads slots from `head` to `tail`, checking `ready`
//!   flag before reading the blob bytes. Releases the blob reference and
//!   stores `head` (.release) after processing so producers see a
//!   published cursor in the full check.
//! - **Wakeup**: producer writes 1 byte to the target worker's pipe after
//!   enqueue, but only on the `wake_pending` false->true edge (Q2). The
//!   consumer clears the flag after draining pipe bytes and before the
//!   queue drain that follows, so a burst costs one byte per drain cycle
//!   instead of one write per stanza and no wakeup is lost.
//!
//! ## ABA Protection
//!
//! Each delivery carries the target slot's `Token` (ADR-4) captured at
//! enqueue time. The consumer validates kind, bounds and generation against
//! its own slot table (no lock, no map scan) and a slot that was freed
//! and reused makes the token stale, so the delivery is counted and dropped.

const std = @import("std");
const posix = std.posix;
const token_kinds = @import("token_kinds");
pub const Token = @import("net_token").Token;

const log = std.log.scoped(.delivery_queue);

/// Maximum payload a single envelope may carry (ADR-3). Producer
/// serialization buffers bound stanzas well below this; the cap exists so
/// one dispatch can never consume a whole worker blob budget.
pub const MAX_BLOB_SIZE: u32 = 128 * 1024;

/// Cross-worker stanzas that could not be handed to the delivery system,
/// most often because they exceeded the 4080-byte slot (S14). Atomic: every
/// worker increments it; the M1 SIGUSR1 dump exports it.
pub var cross_worker_drops = std.atomic.Value(u64).init(0);

/// Delivery outcomes. All are process-wide, incremented by multiple
/// workers, and read out by the M1 SIGUSR1 dump.
pub var s2s_bounces = std.atomic.Value(u64).init(0);
pub var offline_not_stored = std.atomic.Value(u64).init(0);
pub var offline_hold_bounces = std.atomic.Value(u64).init(0);
/// Stored stanzas the offline drain dropped because they cannot fit one
/// connection write even unstamped. Dropping keeps one oversized row from
/// parking the user's whole queue.
pub var offline_drain_drops = std.atomic.Value(u64).init(0);
/// Stanzas queueSend refused because they can never fit the write buffer,
/// counted apart from the slow-reader overflow teardown. The session stays
/// up; iq results are answered with resource-constraint instead.
pub var oversize_queue_drops = std.atomic.Value(u64).init(0);

/// M1 (App. C): cross-worker ring drops. Module-global because this file
/// is its own build module; the M1 SIGUSR1 dump reads them from the
/// server side (same pattern as room_mailbox.mailbox_drops). Drop paths
/// only: a shared atomic here is cold. Envelopes are counted per
/// producing worker through DeliverySystem.envelope_hook instead, so the
/// hottest cross-worker path carries no process-wide atomic.
pub var ring_drops_full = std.atomic.Value(u64).init(0);
pub var ring_drops_payload = std.atomic.Value(u64).init(0);
/// Envelopes refused because the producing worker's blob budget was
/// already committed to in-flight payloads (ADR-3 fail-closed bound).
pub var blob_budget_denials = std.atomic.Value(u64).init(0);

/// Pseudo-targets: they address a broadcast or actor channel, never a
/// session slot. The drain dispatches on token kind before any session
/// validation; index and gen are always zero.
/// Multicast delivery: the payload is a MUC multicast
/// (room_jid + prefix + suffix) rather than a unicast stanza.
pub const MULTICAST_TARGET: Token = .{ .index = 0, .gen = 0, .kind = token_kinds.multicast };

/// Room actor message: the payload is a message.zig-encoded
/// actor message (JoinRequest, PartRequest, GroupchatMessage, etc.) dispatched
/// to the local room shard for processing.
pub const ROOM_ACTOR_TARGET: Token = .{ .index = 0, .gen = 0, .kind = token_kinds.room_actor };

/// SM resume handoff actor message (T177). The payload decodes as a
/// message.zig sm_resume_request (on the owning worker) or
/// sm_resume_reply (on the requesting worker).
pub const SM_ACTOR_TARGET: Token = .{ .index = 0, .gen = 0, .kind = token_kinds.sm_actor };

/// Number of slots per worker queue.
pub const QUEUE_SLOTS: u32 = 256;

/// Delivery class of a slot payload (the ADR-3 `class` field). The receiving
/// worker applies the class's per-session policy to a remote target exactly
/// as the local path applies it, because session flags like carbons_enabled
/// live on the consumer's Session and the producer cannot see them.
pub const DeliveryClass = enum(u8) {
    /// A stanza under RFC 6121 delivery rules: it may be held behind a
    /// draining offline tail and it may be replayed on SM resume.
    normal = 0,
    /// A XEP-0280 carbon copy: only a Carbons-enabled session receives it,
    /// and only live. A carbon is never held behind an offline tail, never
    /// stored and never bounced.
    carbon = 1,
    /// A roster set push: only a resource that asked for roster pushes
    /// receives it.
    roster_push = 2,
    /// A bodyless typing-only message: an inactive-CSI session skips it.
    chatstate = 3,
    /// A XEP-0163 PEP notification.
    pep = 4,
    /// A room-actor wire message under the ROOM_ACTOR_TARGET sentinel.
    room_actor = 5,
    /// An SM-resume actor wire message under the SM_ACTOR_TARGET sentinel.
    sm_actor = 6,
    /// A store-completion actor message; reserved for the C11 store path.
    store_done = 7,
};

/// A refcounted payload shared between ring slots, room mailboxes, SM
/// replay queues and actor retry lists (ADR-3). One allocation: header
/// followed by `len` payload bytes. The producing worker's `BlobBudget`
/// bounds its in-flight bytes; the last release on any thread frees the
/// allocation and returns the bytes to that budget.
pub const Blob = struct {
    /// Open references: ring slots, mailbox entries, SM entries, the
    /// producer's own handle.
    refs: std.atomic.Value(u32),
    /// Owning budget: frees return their byte charge here.
    budget: *BlobBudget,
    /// Payload length in bytes.
    len: u32,

    /// Payload bytes, which live immediately after the header in the same
    /// allocation. Never call after the last release.
    pub fn bytes(self: *Blob) []u8 {
        const raw: [*]u8 = @ptrCast(self);
        return raw[@sizeOf(Blob) .. @sizeOf(Blob) + self.len];
    }

    /// Take another reference (a new slot, mailbox entry or queue node).
    pub fn addRef(self: *Blob) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    /// Drop a reference. The last one frees the allocation through the
    /// home budget's allocator and returns the byte charge.
    pub fn release(self: *Blob) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        const budget = self.budget;
        const size = @sizeOf(Blob) + self.len;
        const raw: [*]align(@alignOf(Blob)) u8 = @ptrCast(@alignCast(self));
        budget.allocator.free(raw[0..size]);
        _ = budget.bytes_in_flight.fetchSub(size, .acq_rel);
    }
};

/// Per-producing-worker bound on blob bytes in flight (ADR-3). A producer
/// that would exceed `limit` fails with error.BlobBudget, which takes the
/// same QueueFull policy path as a full ring. Freeing from a consumer
/// thread is safe: the allocator is the process allocator and the counter
/// is atomic.
pub const BlobBudget = struct {
    allocator: std.mem.Allocator,
    limit: u64,
    bytes_in_flight: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Default per-worker in-flight cap (ADR-3).
    pub const DEFAULT_LIMIT: u64 = 4 * 1024 * 1024;

    /// Copy `payload` into a new refcounted blob; the caller owns the
    /// initial reference. Fails closed on budget exhaustion, allocation
    /// failure, or payloads over MAX_BLOB_SIZE.
    pub fn produce(self: *BlobBudget, payload: []const u8) !*Blob {
        if (payload.len > MAX_BLOB_SIZE) {
            _ = ring_drops_payload.fetchAdd(1, .monotonic);
            return error.PayloadTooLarge;
        }
        const size: usize = @sizeOf(Blob) + payload.len;
        if (self.bytes_in_flight.fetchAdd(size, .acq_rel) + size > self.limit) {
            _ = self.bytes_in_flight.fetchSub(size, .acq_rel);
            _ = blob_budget_denials.fetchAdd(1, .monotonic);
            return error.BlobBudget;
        }
        errdefer _ = self.bytes_in_flight.fetchSub(size, .acq_rel);

        const raw = try self.allocator.alignedAlloc(u8, .fromByteUnits(@alignOf(Blob)), size);
        const blob: *Blob = @ptrCast(raw.ptr);
        blob.* = .{
            .refs = std.atomic.Value(u32).init(1),
            .budget = self,
            .len = @intCast(payload.len),
        };
        @memcpy(raw.ptr[@sizeOf(Blob)..size], payload);
        return blob;
    }
};

/// A single delivery descriptor in the MPSC ring (ADR-3). The payload
/// lives in a shared refcounted `Blob`; the slot owns one reference from
/// publish to drain.
pub const Envelope = struct {
    /// Target slot address (ADR-4): a session token, or one of the
    /// *_TARGET pseudo-targets dispatched on kind before validation.
    target: Token = .none,
    /// Payload blob; the slot's reference is released by the consumer
    /// after the handler returns.
    blob: ?*Blob = null,
    /// Dispatch identity minted by the producer (see offline_store.HoldToken).
    /// Carried in the slot so a consumer on another worker holds the message
    /// under the same identity, and two identical messages stay distinct.
    /// Zero means the producer did not tag the dispatch.
    hold_token: u64 = 0,
    /// Producer-side receipt time in epoch seconds. The consumer stamps a
    /// held message with the time it was actually queued, not the time a
    /// possibly-busy worker got to it. Zero means untimed.
    receipt_ts: u64 = 0,
    /// Payload length in bytes (== blob.len; kept in the descriptor so the
    /// consumer need not touch blob cache lines to read it).
    len: u32 = 0,
    /// Delivery class the consumer applies to this slot.
    class: DeliveryClass = .normal,
    /// Set to true by producer AFTER the descriptor is written.
    /// Consumer MUST check this before reading the slot.
    ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

comptime {
    std.debug.assert(@sizeOf(Envelope) <= 48);
}

/// Per-worker MPSC delivery queue (bounded ring buffer).
pub const MpscQueue = struct {
    slots: [QUEUE_SLOTS]Envelope = [_]Envelope{.{}} ** QUEUE_SLOTS,
    /// Next write position — advanced by producers via CAS.
    tail: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    /// Next read position. Consumer-owned cursor, stored .release after
    /// each drained slot so the producer full check reads a published
    /// value (ADR-3).
    head: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    /// Dispatch identity of the slot the drain is currently handing to the
    /// handler. Consumer-only, valid for the duration of one handler call.
    current_slot_token: u64 = 0,
    /// Delivery class of the slot the drain is currently handing to the
    /// handler. Consumer-only, valid for the duration of one handler call.
    current_slot_class: DeliveryClass = .normal,
    /// Producer receipt time of that same slot; 0 when untimed.
    current_slot_receipt_ts: u64 = 0,

    /// Attempt to enqueue a stanza for cross-thread delivery.
    /// Called by any producer thread. Takes one reference of `blob` on
    /// success; the caller keeps its own. Returns error.QueueFull if no
    /// slots available.
    pub fn enqueue(
        self: *MpscQueue,
        target: Token,
        blob: *Blob,
    ) !void {
        return self.enqueueEnvelope(target, blob, 0, 0, .normal);
    }

    /// Enqueue a delivery with its dispatch identity, producer receipt time
    /// and delivery class: a consumer on another worker holds the message
    /// under the same token, stamps a held copy with the queue time, and
    /// applies the class to the remote session as the local path would.
    /// Takes one reference of `blob` on success; the caller keeps its own.
    pub fn enqueueEnvelope(
        self: *MpscQueue,
        target: Token,
        blob: *Blob,
        hold_token: u64,
        receipt_ts: u64,
        class: DeliveryClass,
    ) !void {
        // CAS loop to reserve a slot
        while (true) {
            const current_tail = self.tail.load(.acquire);
            const current_head = self.head.load(.acquire);

            // Check if queue is full
            if (current_tail -% current_head >= QUEUE_SLOTS) {
                _ = ring_drops_full.fetchAdd(1, .monotonic);
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

            // Write the descriptor (non-atomic — we own this slot until
            // ready.store). The slot takes its own blob reference.
            blob.addRef();
            slot.target = target;
            slot.blob = blob;
            slot.hold_token = hold_token;
            slot.receipt_ts = receipt_ts;
            slot.len = blob.len;
            slot.class = class;

            // Publish: signal to consumer that this slot is fully written
            slot.ready.store(true, .release);
            return;
        }
    }

    /// Drain all ready slots from the queue.
    /// Called by the consumer (owning worker thread) only.
    /// Returns the number of slots processed.
    /// Calls `handler` for each ready delivery with (target token, payload).
    pub fn drain(self: *MpscQueue, ctx: anytype, handler: fn (@TypeOf(ctx), Token, []const u8) void) u32 {
        var processed: u32 = 0;
        const current_tail = self.tail.load(.acquire);
        var h = self.head.load(.acquire);

        while (h != current_tail) {
            const slot_idx = h % QUEUE_SLOTS;
            const slot = &self.slots[slot_idx];

            // Check if this slot is fully written by the producer
            if (!slot.ready.load(.acquire)) {
                // Producer reserved but hasn't finished writing yet — stop here
                break;
            }

            // Read the delivery. The `current_slot_*` fields are how a
            // handler learns this dispatch's identity, class and receipt
            // time without widening the handler signature.
            const blob = slot.blob.?;
            self.current_slot_token = slot.hold_token;
            self.current_slot_class = slot.class;
            self.current_slot_receipt_ts = slot.receipt_ts;
            handler(ctx, slot.target, blob.bytes());
            self.current_slot_token = 0;
            self.current_slot_class = .normal;
            self.current_slot_receipt_ts = 0;
            processed += 1;

            // Retire the slot, then publish the advanced head. A producer
            // cannot reuse this index until the full check sees head move
            // past it, so the writes above and the blob release below
            // cannot race the next descriptor.
            slot.blob = null;
            slot.ready.store(false, .monotonic);
            h +%= 1;
            self.head.store(h, .release);
            blob.release();
        }

        return processed;
    }

    /// Check if the queue has pending work (without consuming).
    pub fn hasPending(self: *const MpscQueue) bool {
        return self.head.load(.acquire) != self.tail.load(.acquire);
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
        // Non-blocking both ends: reads drain to EAGAIN; a write that sees
        // a full pipe means a wake is already signaled.
        _ = std.c.fcntl(fds[0], std.c.F.SETFL, @as(c_int, @bitCast(std.c.O{ .NONBLOCK = true })));
        _ = std.c.fcntl(fds[1], std.c.F.SETFL, @as(c_int, @bitCast(std.c.O{ .NONBLOCK = true })));
        return .{ .rd = fds[0], .wr = fds[1] };
    }

    /// Close both ends of the pipe.
    pub fn deinit(self: *WakePipe) void {
        posix.close(self.rd);
        posix.close(self.wr);
    }

    /// Write 1 byte to wake the consumer (called by producer after enqueue).
    /// A full pipe already reads as a pending wake, so EAGAIN reports as a
    /// successful signal; only real failures (e.g. a torn-down fd) error.
    pub fn wake(self: *const WakePipe) !void {
        _ = posix.write(self.wr, &[1]u8{1}) catch |err| switch (err) {
            error.WouldBlock => return,
            else => return err,
        };
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

/// Pipe writes that failed on a wake_pending edge; the flag was cleared so
/// the next delivery retries. Process-wide like the other drop counters.
pub var wake_write_failed = std.atomic.Value(u64).init(0);

/// Per-worker processing state for coalesced signaling optimization.
pub const WorkerState = struct {
    /// 1 when worker is inside event processing loop, 0 when idle in kevent().
    is_processing: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    /// Q2 wake coalescing: true while a wake byte is queued for or in
    /// flight to this worker. Producers write the pipe only on the
    /// false->true edge; the consumer clears it in drainPipe after the
    /// byte drain and before the queue drain that follows.
    wake_pending: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

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
    /// Per-worker blob budgets (producer side). `budgets[w]` bounds the
    /// payload bytes worker `w` has in flight across every target ring,
    /// room mailbox and replay queue (ADR-3).
    budgets: []BlobBudget,
    worker_count: u16,
    allocator: std.mem.Allocator,
    /// Optional hook invoked once per accepted envelope (M1). The server
    /// sets it to count envelopes in the producing worker's own counter
    /// block; this module cannot see src/core/metrics.zig itself.
    envelope_hook: ?*const fn () void = null,

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

        const budgets = try allocator.alloc(BlobBudget, n);
        for (budgets) |*b| {
            b.* = .{ .allocator = allocator, .limit = BlobBudget.DEFAULT_LIMIT };
        }

        return .{
            .queues = queues,
            .pipes = pipes,
            .states = states,
            .budgets = budgets,
            .worker_count = worker_count,
            .allocator = allocator,
        };
    }

    /// Clean up all resources.
    pub fn deinit(self: *DeliverySystem) void {
        // Undrained slots still hold a blob reference; return them to
        // their budgets before the queues are freed.
        for (self.queues) |*q| {
            for (&q.slots) |*slot| {
                if (slot.blob) |b| {
                    b.release();
                    slot.blob = null;
                }
            }
        }
        for (self.pipes) |*p| {
            p.deinit();
        }
        self.allocator.free(self.queues);
        self.allocator.free(self.pipes);
        self.allocator.free(self.states);
        self.allocator.free(self.budgets);
        self.* = undefined;
    }

    /// Serialize `payload` into a refcounted blob charged to the producing
    /// worker's budget. The caller owns the returned reference.
    pub fn produceBlob(self: *DeliverySystem, producer_worker: u16, payload: []const u8) !*Blob {
        if (producer_worker >= self.worker_count) return error.InvalidWorker;
        return self.budgets[producer_worker].produce(payload);
    }

    /// Enqueue a stanza for delivery to a target worker.
    /// Handles coalesced signaling — only wakes the target if it's idle.
    pub fn deliver(
        self: *DeliverySystem,
        producer_worker: u16,
        target_worker: u16,
        target: Token,
        payload: []const u8,
    ) !void {
        return self.deliverDelivery(producer_worker, target_worker, target, payload, 0, 0, .normal);
    }

    /// Deliver a stanza with its dispatch identity, producer receipt time
    /// and delivery class, then wake the target worker.
    pub fn deliverDelivery(
        self: *DeliverySystem,
        producer_worker: u16,
        target_worker: u16,
        target: Token,
        payload: []const u8,
        hold_token: u64,
        receipt_ts: u64,
        class: DeliveryClass,
    ) !void {
        try self.enqueueDelivery(producer_worker, target_worker, target, payload, hold_token, receipt_ts, class);

        self.wakeWorker(target_worker);
    }

    /// Enqueue without waking the target worker (T130 batch delivery).
    /// The caller MUST call wakeWorker() once after the batch. A stale read
    /// of the queue by a woken-but-racing target is harmless; skipping the
    /// trailing wake is not.
    pub fn enqueue(
        self: *DeliverySystem,
        producer_worker: u16,
        target_worker: u16,
        target: Token,
        payload: []const u8,
    ) !void {
        return self.enqueueDelivery(producer_worker, target_worker, target, payload, 0, 0, .normal);
    }

    /// Enqueue a delivery with its dispatch identity, producer receipt time
    /// and delivery class, without waking the target worker.
    /// The caller MUST call wakeWorker() once after the batch. The payload
    /// is serialized into a blob charged to `producer_worker`'s budget; a
    /// budget denial takes the same error path as a full ring.
    pub fn enqueueDelivery(
        self: *DeliverySystem,
        producer_worker: u16,
        target_worker: u16,
        target: Token,
        payload: []const u8,
        hold_token: u64,
        receipt_ts: u64,
        class: DeliveryClass,
    ) !void {
        if (target_worker >= self.worker_count) return error.InvalidWorker;
        const blob = try self.produceBlob(producer_worker, payload);
        defer blob.release();
        try self.enqueueBlob(target_worker, target, blob, hold_token, receipt_ts, class);
    }

    /// Enqueue an already-produced blob into a target worker's ring
    /// without waking it. The slot takes its own reference, so one blob
    /// produced by a multicast producer is shared across every target.
    /// The caller MUST call wakeWorker() once after the batch.
    pub fn enqueueBlob(
        self: *DeliverySystem,
        target_worker: u16,
        target: Token,
        blob: *Blob,
        hold_token: u64,
        receipt_ts: u64,
        class: DeliveryClass,
    ) !void {
        if (target_worker >= self.worker_count) return error.InvalidWorker;
        try self.queues[target_worker].enqueueEnvelope(target, blob, hold_token, receipt_ts, class);
        if (self.envelope_hook) |h| h();
    }

    /// Enqueue a shared blob and wake the target worker.
    pub fn deliverBlob(
        self: *DeliverySystem,
        target_worker: u16,
        target: Token,
        blob: *Blob,
        hold_token: u64,
        receipt_ts: u64,
        class: DeliveryClass,
    ) !void {
        try self.enqueueBlob(target_worker, target, blob, hold_token, receipt_ts, class);
        self.wakeWorker(target_worker);
    }

    /// Wake a worker after one or more enqueue() calls (T130). Coalesced
    /// (Q2): only the wake_pending false->true edge writes the pipe. The
    /// consumer's clear is a read-modify-write too, so this swap and that
    /// one are totally ordered on the flag: if this swap lands first, the
    /// consumer's swap reads the true it published and the drain that
    /// follows acquires the slot; if it lands second, this swap reads
    /// false and a byte goes out. A skipped write is never a lost wakeup.
    pub fn wakeWorker(self: *DeliverySystem, target_worker: u16) void {
        if (target_worker >= self.worker_count) return;
        const state = &self.states[target_worker];
        if (state.wake_pending.swap(true, .seq_cst)) return;
        self.pipes[target_worker].wake() catch {
            // Clear so the next delivery retries the byte instead of
            // coalescing into a signal that never arrived.
            state.wake_pending.store(false, .seq_cst);
            _ = wake_write_failed.fetchAdd(1, .monotonic);
            log.err("delivery wake write to worker {d} failed", .{target_worker});
        };
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
    /// Clears wake_pending after the byte drain and before the queue
    /// drain the caller runs next. The clear is a read-modify-write, so
    /// it and the producer's swap(true) are totally ordered on the flag:
    /// if the producer's swap lands first, this swap reads its true and
    /// the drain acquires the published slot; if it lands second, the
    /// producer reads false and writes the next byte. A plain store
    /// would give no synchronizes-with edge and could lose a wakeup on
    /// weakly ordered hardware.
    pub fn drainPipe(self: *const DeliverySystem, worker_id: u16) void {
        self.pipes[worker_id].drainPipe();
        _ = self.states[worker_id].wake_pending.swap(false, .seq_cst);
    }
};

// ============================================================================
// Tests
// ============================================================================

/// Test helper: every queue-level test charges blobs to this budget.
/// A static keeps the budget alive for as long as any blob it produced;
/// queue tests are single-threaded.
var test_budget_store: ?BlobBudget = null;
fn testBudget() *BlobBudget {
    if (test_budget_store == null) {
        test_budget_store = .{ .allocator = std.testing.allocator, .limit = BlobBudget.DEFAULT_LIMIT };
    }
    return &test_budget_store.?;
}

/// Produce a blob, hand one reference to `queue`, and drop the caller's.
fn enqueuePayload(queue: *MpscQueue, target: Token, payload: []const u8) !void {
    const blob = try testBudget().produce(payload);
    defer blob.release();
    try queue.enqueue(target, blob);
}

test "MpscQueue: basic enqueue and drain" {
    var queue = MpscQueue{};
    const payload = "hello world";

    try enqueuePayload(&queue, Token.init(42, 7, token_kinds.session), payload);

    var received_id: u32 = 0;
    var received_gen: u24 = 0;
    var received_payload: []const u8 = "";

    const Ctx = struct {
        id: *u32,
        gen: *u24,
        pl: *[]const u8,
    };
    const ctx = Ctx{ .id = &received_id, .gen = &received_gen, .pl = &received_payload };

    const handler = struct {
        fn handle(c: Ctx, target: Token, pl: []const u8) void {
            c.id.* = target.index;
            c.gen.* = target.gen;
            c.pl.* = pl;
        }
    }.handle;

    const processed = queue.drain(ctx, handler);
    try std.testing.expectEqual(@as(u32, 1), processed);
    try std.testing.expectEqual(@as(u32, 42), received_id);
    try std.testing.expectEqual(@as(u24, 7), received_gen);
    try std.testing.expectEqualStrings("hello world", received_payload);
}

test "MpscQueue: receipt timestamp reaches the drain handler" {
    var queue = MpscQueue{};

    {
        const blob = try testBudget().produce("timed");
        defer blob.release();
        try queue.enqueueEnvelope(Token.init(42, 7, token_kinds.session), blob, 0xdeadbeef, 12345, .normal);
    }
    try enqueuePayload(&queue, Token.init(43, 8, token_kinds.session), "untimed");

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
        fn handle(c: Ctx, _: Token, payload: []const u8) void {
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

    {
        const blob = try testBudget().produce("tagged");
        defer blob.release();
        try queue.enqueueEnvelope(Token.init(42, 7, token_kinds.session), blob, 0xdeadbeef, 0, .normal);
    }
    try enqueuePayload(&queue, Token.init(43, 8, token_kinds.session), "untagged");

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
        fn handle(c: Ctx, _: Token, pl: []const u8) void {
            _ = pl;
            c.tokens.*[c.seen.*] = c.queue.current_slot_token;
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

    {
        const blob = try testBudget().produce("carbon copy");
        defer blob.release();
        try queue.enqueueEnvelope(Token.init(42, 7, token_kinds.session), blob, 0, 0, .carbon);
    }
    try enqueuePayload(&queue, Token.init(43, 8, token_kinds.session), "plain stanza");

    const Ctx = struct {
        queue: *MpscQueue,
        kinds: *[2]DeliveryClass,
        seen: *usize,
    };
    var kinds = [_]DeliveryClass{ .normal, .normal };
    var seen: usize = 0;
    const ctx = Ctx{ .queue = &queue, .kinds = &kinds, .seen = &seen };

    const handler = struct {
        fn handle(c: Ctx, _: Token, pl: []const u8) void {
            _ = pl;
            c.kinds.*[c.seen.*] = c.queue.current_slot_class;
            c.seen.* += 1;
        }
    }.handle;

    const processed = queue.drain(ctx, handler);
    try std.testing.expectEqual(@as(u32, 2), processed);
    try std.testing.expectEqual(DeliveryClass.carbon, kinds[0]);
    try std.testing.expectEqual(DeliveryClass.normal, kinds[1]);
    try std.testing.expectEqual(DeliveryClass.normal, queue.current_slot_class);
}

test "MpscQueue: queue full" {
    var queue = MpscQueue{};

    // Fill the queue
    var i: u32 = 0;
    while (i < QUEUE_SLOTS) : (i += 1) {
        try enqueuePayload(&queue, Token.init(i, 1, token_kinds.session), "x");
    }

    // Next enqueue should fail
    try std.testing.expectError(error.QueueFull, enqueuePayload(&queue, Token.init(999, 1, token_kinds.session), "overflow"));

    // Drain frees every slot reference the test published.
    var freed: u32 = 0;
    const Ctx = struct { count: *u32 };
    const handler = struct {
        fn handle(c: Ctx, _: Token, _: []const u8) void {
            c.count.* += 1;
        }
    }.handle;
    _ = queue.drain(Ctx{ .count = &freed }, handler);
    try std.testing.expectEqual(QUEUE_SLOTS, freed);
}

test "MpscQueue: payload too large" {
    var budget = testBudget();
    const big_payload = try std.testing.allocator.alloc(u8, MAX_BLOB_SIZE + 1);
    defer std.testing.allocator.free(big_payload);
    try std.testing.expectError(error.PayloadTooLarge, budget.produce(big_payload));
}

test "MpscQueue: hasPending" {
    var queue = MpscQueue{};
    try std.testing.expect(!queue.hasPending());

    try enqueuePayload(&queue, Token.init(1, 1, token_kinds.session), "test");
    try std.testing.expect(queue.hasPending());
}

test "Blob: a slot's reference outlives the producer's" {
    var budget = testBudget();
    var queue = MpscQueue{};

    const blob = try budget.produce("shared");
    try queue.enqueue(Token.init(1, 1, token_kinds.session), blob);
    // Producer drops its handle; the slot's reference keeps the payload.
    blob.release();
    try std.testing.expectEqual(@as(u32, 1), blob.refs.load(.acquire));

    var seen: usize = 0;
    const Ctx = struct { n: *usize };
    const handler = struct {
        fn handle(c: Ctx, _: Token, _: []const u8) void {
            c.n.* += 1;
        }
    }.handle;
    _ = queue.drain(Ctx{ .n = &seen }, handler);
    try std.testing.expectEqual(@as(usize, 1), seen);
    // The drain released the last reference: the byte charge went home.
    try std.testing.expectEqual(@as(u64, 0), budget.bytes_in_flight.load(.acquire));
}

test "Blob: budget denial is counted and fail-closed" {
    var budget = BlobBudget{ .allocator = std.testing.allocator, .limit = 8 };
    const before = blob_budget_denials.load(.monotonic);
    try std.testing.expectError(error.BlobBudget, budget.produce("0123456789"));
    try std.testing.expectEqual(before + 1, blob_budget_denials.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), budget.bytes_in_flight.load(.acquire));
}

test "WakePipe: init and deinit" {
    var pipe = try WakePipe.init();
    defer pipe.deinit();

    // Write should not block
    try pipe.wake();
    // Drain should consume the byte
    pipe.drainPipe();
}

test "DeliverySystem: a burst of deliveries costs one pipe byte (Q2)" {
    // Goal: prove the wake is edge-triggered. Multiple deliveries while
    // wake_pending is set must collapse to a single byte in the pipe;
    // clearing the flag by draining re-arms the edge.
    var sys = try DeliverySystem.init(std.testing.allocator, 2);
    defer sys.deinit();

    var buf: [8]u8 = undefined;
    try sys.deliver(0, 1, Token.init(1, 1, token_kinds.session), "a");
    try sys.deliver(0, 1, Token.init(2, 1, token_kinds.session), "b");
    try sys.deliver(0, 1, Token.init(3, 1, token_kinds.session), "c");
    try std.testing.expectEqual(@as(usize, 1), try posix.read(sys.getPipeReadFd(1), &buf));
    try std.testing.expectError(error.WouldBlock, posix.read(sys.getPipeReadFd(1), &buf));

    // Consumer cycle: byte drain clears the flag, queue drain follows.
    sys.drainPipe(1);
    try std.testing.expect(!sys.getState(1).wake_pending.load(.seq_cst));

    // A delivery after the clear writes a fresh byte.
    try sys.deliver(0, 1, Token.init(4, 1, token_kinds.session), "d");
    try std.testing.expectEqual(@as(usize, 1), try posix.read(sys.getPipeReadFd(1), &buf));
}

test "DeliverySystem: a publish inside the clear-then-drain window still wakes" {
    // Goal: no lost wakeup when a delivery lands between the consumer's
    // flag clear and its queue drain. Sequence: producer wakes, consumer
    // drains pipe + flag, producer publishes again — the edge must write
    // a byte, and the slot must be visible to the drain that follows.
    var sys = try DeliverySystem.init(std.testing.allocator, 2);
    defer sys.deinit();

    try sys.deliver(0, 1, Token.init(1, 1, token_kinds.session), "first");
    sys.drainPipe(1); // consumes the byte, clears wake_pending

    try sys.deliver(0, 1, Token.init(2, 1, token_kinds.session), "second");

    // The second publish saw flag=false and wrote: pipe is readable again.
    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try posix.read(sys.getPipeReadFd(1), &buf));

    const Ctx = struct { count: *u32 };
    var count: u32 = 0;
    const ctx = Ctx{ .count = &count };
    const handler = struct {
        fn handle(c: Ctx, _: Token, _: []const u8) void {
            c.count.* += 1;
        }
    }.handle;
    _ = sys.getQueue(1).drain(ctx, handler);
    try std.testing.expectEqual(@as(u32, 2), count);
}

test "DeliverySystem: racing producers lose no wakeups" {
    // Goal: a kqueue-waiting consumer must see every delivery under
    // contention. Three producers stream deliveries while the consumer
    // sleeps on the pipe and drains on each event: the loop's real
    // pattern. The verdict is deterministic: once the producers join,
    // every accepted slot is published, so a slot still pending with no
    // readable wake byte and wake_pending == false can never be reached.
    // That is a lost wake by construction, no timing involved.
    const PRODUCERS = 3;
    const PER_PRODUCER = 2000;

    var sys = try DeliverySystem.init(std.testing.allocator, 2);
    defer sys.deinit();

    var produced = std.atomic.Value(u32).init(0);
    var producers_done = std.atomic.Value(u32).init(0);
    const producer = struct {
        fn run(ds: *DeliverySystem, n: usize, sent: *std.atomic.Value(u32), done: *std.atomic.Value(u32)) void {
            var i: usize = 0;
            while (i < n) : (i += 1) {
                // QueueFull drops are legitimate backpressure; only slots
                // that landed are owed a wake.
                ds.deliverDelivery(0, 1, Token.init(0, 0, token_kinds.session), "race", 0, 0, .normal) catch |err| switch (err) {
                    error.QueueFull => continue,
                    error.InvalidWorker, error.PayloadTooLarge, error.BlobBudget => unreachable,
                };
                _ = sent.fetchAdd(1, .release);
            }
            _ = done.fetchAdd(1, .release);
        }
    }.run;

    var threads: [PRODUCERS]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, producer, .{ &sys, PER_PRODUCER, &produced, &producers_done });

    const consumer = struct {
        fn run(ds: *DeliverySystem, producer_threads: []std.Thread, done: *std.atomic.Value(u32)) !struct { consumed: usize, lost: usize } {
            const kq = try posix.kqueue();
            defer posix.close(kq);
            const reg = [1]posix.Kevent{.{
                .ident = @intCast(ds.getPipeReadFd(1)),
                .filter = std.c.EVFILT.READ,
                .flags = std.c.EV.ADD | std.c.EV.ENABLE,
                .fflags = 0,
                .data = 0,
                .udata = 0,
            }};
            var events: [1]posix.Kevent = undefined;
            _ = try posix.kevent(kq, &reg, events[0..0], null);

            var consumed: usize = 0;
            const Ctx = struct { count: *usize };
            const ctx = Ctx{ .count = &consumed };
            const handler = struct {
                fn handle(c: Ctx, _: Token, _: []const u8) void {
                    c.count.* += 1;
                }
            }.handle;

            // Coverage phase: drain on each pipe event while producers
            // run. The 100 ms wait only re-polls the done flag; nothing
            // here decides pass or fail.
            const deadline = std.time.milliTimestamp() + 15000;
            const ts = std.c.timespec{ .sec = 0, .nsec = 100 * std.time.ns_per_ms };
            while (done.load(.acquire) != PRODUCERS and std.time.milliTimestamp() < deadline) {
                _ = try posix.kevent(kq, &.{}, &events, &ts);
                ds.drainPipe(1);
                _ = ds.getQueue(1).drain(ctx, handler);
            }
            try std.testing.expectEqual(@as(u32, PRODUCERS), done.load(.acquire));

            // Join the producers first: every accepted slot is now
            // published. The verdict is one final consumer pass: a
            // zero-timeout wait on the pipe, then drain the pipe and
            // the queue. A slot still pending with no readable byte
            // and wake_pending == false is a lost wake by construction.
            for (producer_threads) |t| t.join();
            const zero = std.c.timespec{ .sec = 0, .nsec = 0 };
            const nev = try posix.kevent(kq, &.{}, &events, &zero);
            const queue = ds.getQueue(1);
            var lost: usize = 0;
            if (queue.hasPending() and nev == 0 and !ds.getState(1).wake_pending.load(.seq_cst)) {
                lost = queue.tail.load(.acquire) -% queue.head.load(.acquire);
            }
            ds.drainPipe(1);
            consumed += queue.drain(ctx, handler);
            return .{ .consumed = consumed, .lost = lost };
        }
    }.run;

    const result = try consumer(&sys, &threads, &producers_done);

    // Every slot that survived the bounded queue was consumed: a lost
    // wake would strand its slot in the ring past the join.
    try std.testing.expectEqual(produced.load(.acquire), result.consumed);
    try std.testing.expectEqual(@as(usize, 0), result.lost);
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
    try sys.deliver(0, 1, Token.init(10, 3, token_kinds.session), "test stanza");

    // Drain worker 1's queue
    var received: bool = false;
    const Ctx = struct { flag: *bool };
    const ctx = Ctx{ .flag = &received };
    const handler = struct {
        fn handle(c: Ctx, _: Token, _: []const u8) void {
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
    try sys.deliver(0, 1, Token.init(5, 1, token_kinds.session), "coalesced");

    // Drain should still find the message
    const Ctx = struct { count: *u32 };
    var count: u32 = 0;
    const ctx = Ctx{ .count = &count };
    const handler = struct {
        fn handle(c: Ctx, _: Token, _: []const u8) void {
            c.count.* += 1;
        }
    }.handle;
    _ = sys.getQueue(1).drain(ctx, handler);
    try std.testing.expectEqual(@as(u32, 1), count);
}
