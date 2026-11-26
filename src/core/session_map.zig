//! # SessionMap — thread-safe JID-keyed session routing table
//!
//! Single source of truth for all session routing. Keys are normalized JID
//! values (`Key`): the domain is ASCII-folded once and both the full-JID and
//! bare-JID hashes are computed before any lock is taken, so no map operation
//! hashes inside a critical section.
//!
//! ## Indexes
//!
//! - `full_map`: normalized full JID ("alice@host/mobile") -> *SessionEntry -
//!   O(1) exact lookup; this is the one entry store.
//! - `bare_map`: normalized bare JID ("alice@host") -> list of *SessionEntry -
//!   O(1) multi-resource index into the same entries. Presence and priority
//!   updates touch a single object; nothing is kept in sync by hand.
//!
//! Fan-out reads go through the copy-out API (`collectBound`,
//! `collectAvailable`): under one shared-lock hold the map copies the
//! account's `SessionEntry` values - the bounded routing state - into the
//! caller's buffer, and the caller serializes, delivers and logs after the
//! lock is released. The caller must pass a buffer of at least
//! `max_resources` entries, the same cap the bind path enforces on each
//! account's entry list. The API reports `error.ScratchTooSmall` rather than
//! truncating a fan-out into a partial recipient set.
//!
//! ## Thread Safety
//!
//! All locking is internal. The map is sharded by bare-JID hash: every JID of
//! one account resolves to one shard, each shard holds its own `RwLock` and
//! index pair. A `multi_worker` flag gates lock acquisition - in
//! single-worker mode there is exactly one shard and no lock overhead.
//!
//! - Read (shared) lock: findByFullJid, collectBound, collectAvailable,
//!   isAvailable, hasBound
//! - Write (exclusive) lock: bind, unbind, setPresenceState,
//!   setPresenceAvailable, setPriority
//!
//! No logging happens while a lock is held. A thread-local hold counter
//! asserts in safe builds that no map entry point is re-entered while a lock
//! is held, which is the only way a nested hold could deadlock a thread.

const std = @import("std");
const token_kinds = @import("token_kinds");
pub const Token = @import("net_token").Token;

const log = std.log.scoped(.session_map);

/// Maximum resource length stored inline in SessionEntry.
/// Covers all practical resources (RFC allows 1023, but clients use ≤32).
const MAX_RESOURCE_LEN: usize = 64;
/// Full JIDs may contain a maximum-length RFC 7622 localpart plus domain and
/// resource, so bare/full lookup buffers cannot cap at the old 320/384 bytes.
/// Public so router can assert its stanza bound covers the bind cap.
pub const MAX_JID_OCTETS: usize = 2112;

/// Result of a session lookup — contains routing information for cross-thread delivery.
pub const SessionEntry = struct {
    worker_id: u16,
    /// Generational address of the session slot on `worker_id` (ADR-4).
    /// The owning worker validates it against its slot generations with no
    /// lock and no map scan; a stale token resolves to "session gone".
    token: Token,
    presence_available: bool = false,
    priority: i8 = 0,
    resource_buf: [MAX_RESOURCE_LEN]u8 = undefined,
    resource_len: u8 = 0,

    /// Get the resource string for this entry.
    pub fn resource(self: *const SessionEntry) []const u8 {
        return self.resource_buf[0..self.resource_len];
    }
};

/// A pre-split bare JID for caller-side fan-out chunking (T130).
pub const JidParts = struct {
    local: []const u8,
    domain: []const u8,
};

/// A routing address: the owning worker plus the slot token that names the
/// session there. Per-dispatch bookkeeping (the carbons delivered set)
/// carries RouteRefs where a whole SessionEntry copy is not needed.
pub const RouteRef = struct {
    worker_id: u16,
    token: Token,
};

/// Default per-account (bare JID) resource cap (T198). Operator-tunable via
/// [core] max_resources_per_account; 256 covers bot/agent deployments that
/// bind one resource per session (Sonya), at ~88B/entry heap per bound
/// resource — no inline 16-slot tax on every account.
pub const DEFAULT_MAX_RESOURCES: usize = 256;

/// Normalized session-routing key: "local@domain[/resource]" with the domain
/// part ASCII-lowercased at build time (T305). `bytes[0..bare_len]` is the
/// bare JID, so one string serves both indexes. `full_hash` and `bare_hash`
/// are computed in `initBuf`, before any lock is taken; map contexts return
/// them directly so no lock hold ever pays for hashing.
///
/// The localpart is not folded here: its spelling is owned by the RFC 7622
/// UsernameCaseMapped preparation at ingress. The resource is
/// case-sensitive.
pub const Key = struct {
    bytes: []const u8,
    bare_len: u16,
    full_hash: u64,
    bare_hash: u64,

    pub fn bare(self: Key) []const u8 {
        return self.bytes[0..self.bare_len];
    }

    /// Build a normalized key into `buf` without allocating. Returns null
    /// when the JID does not fit.
    pub fn initBuf(buf: []u8, local: []const u8, domain: []const u8, resource: []const u8) ?Key {
        const bare_len = local.len + 1 + domain.len;
        const len = bare_len + if (resource.len > 0) 1 + resource.len else 0;
        if (len > buf.len or bare_len > std.math.maxInt(u16)) return null;

        var pos: usize = 0;
        @memcpy(buf[pos..][0..local.len], local);
        pos += local.len;
        buf[pos] = '@';
        pos += 1;
        for (domain, 0..) |c, i| {
            buf[pos + i] = std.ascii.toLower(c);
        }
        pos += domain.len;
        if (resource.len > 0) {
            buf[pos] = '/';
            pos += 1;
            @memcpy(buf[pos..][0..resource.len], resource);
        }

        const bytes = buf[0..len];
        return .{
            .bytes = bytes,
            .bare_len = @intCast(bare_len),
            .full_hash = std.hash.Wyhash.hash(0, bytes),
            .bare_hash = std.hash.Wyhash.hash(0, bytes[0..bare_len]),
        };
    }

    /// Heap-copy the key bytes for map storage. Caller frees with
    /// `allocator.free(key.bytes)`.
    fn dupeBytes(self: Key, allocator: std.mem.Allocator) !Key {
        var owned = self;
        owned.bytes = try allocator.dupe(u8, self.bytes);
        return owned;
    }
};

/// Precomputed-hash context for the full-JID index.
const FullCtx = struct {
    pub fn hash(_: FullCtx, key: Key) u64 {
        return key.full_hash;
    }
    pub fn eql(_: FullCtx, a: Key, b: Key) bool {
        return std.mem.eql(u8, a.bytes, b.bytes);
    }
};

/// Precomputed-hash context for the bare-JID index.
const BareCtx = struct {
    pub fn hash(_: BareCtx, key: Key) u64 {
        return key.bare_hash;
    }
    pub fn eql(_: BareCtx, a: Key, b: Key) bool {
        return std.mem.eql(u8, a.bare(), b.bare());
    }
};

const FullMap = std.HashMapUnmanaged(Key, *SessionEntry, FullCtx, std.hash_map.default_max_load_percentage);
const BareMap = std.HashMapUnmanaged(Key, EntryList, BareCtx, std.hash_map.default_max_load_percentage);

/// Heap-backed list of entry ids (*SessionEntry) for one bare JID
/// (multi-resource). Grows on demand up to the SessionMap's max_resources
/// cap (T198). Entries are the same objects full_map owns; nothing is
/// duplicated.
pub const EntryList = struct {
    /// Backing buffer; slice length is the allocated CAPACITY.
    buf: []*SessionEntry = &.{},
    /// Number of live entries.
    len: usize = 0,

    const GROW_STEP: usize = 16;

    pub fn append(self: *EntryList, allocator: std.mem.Allocator, entry: *SessionEntry, max: usize) !void {
        if (self.len >= max) return error.TooManyResources;
        if (self.len >= self.buf.len) {
            const grown = try allocator.alloc(*SessionEntry, self.buf.len + GROW_STEP);
            @memcpy(grown[0..self.len], self.buf[0..self.len]);
            if (self.buf.len > 0) allocator.free(self.buf);
            self.buf = grown;
        }
        self.buf[self.len] = entry;
        self.len += 1;
    }

    pub fn constSlice(self: *const EntryList) []const *SessionEntry {
        return self.buf[0..self.len];
    }

    pub fn slice(self: *EntryList) []*SessionEntry {
        return self.buf[0..self.len];
    }

    pub fn orderedRemove(self: *EntryList, index: usize) *SessionEntry {
        const removed = self.buf[index];
        var i = index;
        while (i + 1 < self.len) : (i += 1) {
            self.buf[i] = self.buf[i + 1];
        }
        self.len -= 1;
        return removed;
    }

    /// Remove one entry by identity. Returns false when absent.
    pub fn removePtr(self: *EntryList, entry: *SessionEntry) bool {
        for (self.slice(), 0..) |candidate, i| {
            if (candidate == entry) {
                _ = self.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn deinit(self: *EntryList, allocator: std.mem.Allocator) void {
        if (self.buf.len > 0) allocator.free(self.buf);
        self.buf = &.{};
        self.len = 0;
    }
};

/// One shard: a bare-JID hash bucket with its own lock and index pair.
const Shard = struct {
    full_map: FullMap = .empty,
    bare_map: BareMap = .empty,
    lock: std.Thread.RwLock = .{},
};

/// Number of locks the calling thread holds on this map right now. Checked
/// at every acquisition: a nested hold is a programmer error and deadlocks
/// the thread in multi-worker mode or corrupts the iteration in
/// single-worker mode.
threadlocal var hold_depth: usize = 0;

/// Thread-safe, JID-keyed session routing table.
pub const SessionMap = struct {
    shards: []Shard,
    /// shard_count - 1; shard_count is always a power of two.
    shard_mask: usize,
    multi_worker: bool,
    allocator: std.mem.Allocator,
    /// Per-account (bare JID) resource cap (T198).
    max_resources: usize,

    /// `workers` is the configured core worker count. One shard when there is
    /// a single worker (locks then never taken); otherwise
    /// pow2ceil(8 * workers) clamped to [8, 256] - 8 shards per worker keeps
    /// a fan-out's lock hold from colliding with a same-shard writer except
    /// on ~1/shard_count of accounts, and the clamp bounds the table cost.
    pub fn init(allocator: std.mem.Allocator, workers: usize, max_resources: usize) !SessionMap {
        const shard_count: usize = if (workers <= 1) 1 else blk: {
            const scaled = 8 *| workers;
            break :blk std.math.ceilPowerOfTwo(usize, @min(scaled, 256)) catch unreachable;
        };
        const shards = try allocator.alloc(Shard, shard_count);
        for (shards) |*shard| shard.* = .{};
        return .{
            .shards = shards,
            .shard_mask = shard_count - 1,
            .multi_worker = workers > 1,
            .allocator = allocator,
            .max_resources = if (max_resources == 0) DEFAULT_MAX_RESOURCES else max_resources,
        };
    }

    pub fn deinit(self: *SessionMap) void {
        for (self.shards) |*shard| {
            // Free all owned key strings and entry objects in full_map
            var full_iter = shard.full_map.iterator();
            while (full_iter.next()) |kv| {
                self.allocator.free(kv.key_ptr.bytes);
                self.allocator.destroy(kv.value_ptr.*);
            }
            shard.full_map.deinit(self.allocator);

            // Free all owned entry lists + key strings in bare_map
            var bare_iter = shard.bare_map.iterator();
            while (bare_iter.next()) |kv| {
                kv.value_ptr.deinit(self.allocator);
                self.allocator.free(kv.key_ptr.bytes);
            }
            shard.bare_map.deinit(self.allocator);
        }
        self.allocator.free(self.shards);
    }

    /// Every JID of one account resolves to one shard: full-JID operations
    /// shard on the same bare hash, so a bind and a later unbind always meet.
    fn shardFor(self: *SessionMap, key: Key) *Shard {
        return &self.shards[key.bare_hash & self.shard_mask];
    }

    fn lockShard(self: *SessionMap, shard: *Shard, comptime exclusive: bool) void {
        std.debug.assert(hold_depth == 0);
        hold_depth = 1;
        if (self.multi_worker) {
            if (exclusive) shard.lock.lock() else shard.lock.lockShared();
        }
    }

    fn unlockShard(self: *SessionMap, shard: *Shard, comptime exclusive: bool) void {
        hold_depth = 0;
        if (self.multi_worker) {
            if (exclusive) shard.lock.unlock() else shard.lock.unlockShared();
        }
    }

    /// Register a session after successful resource binding. `token` names
    /// the session slot on `worker_id` as of this bind (ADR-4); the caller
    /// mints it from its own slot generations.
    pub fn bind(
        self: *SessionMap,
        worker_id: u16,
        token: Token,
        local: []const u8,
        domain: []const u8,
        resource: []const u8,
    ) !void {
        if (resource.len > MAX_RESOURCE_LEN) return error.ResourceTooLong;

        // Normalize and hash outside the lock; allocations that only commit
        // on success happen there too so a rejected bind owns nothing.
        var key_buf: [MAX_JID_OCTETS]u8 = undefined;
        const key = Key.initBuf(&key_buf, local, domain, resource) orelse return error.JidTooLong;

        const owned_key = try key.dupeBytes(self.allocator);
        errdefer self.allocator.free(owned_key.bytes);

        const entry = try self.allocator.create(SessionEntry);
        errdefer self.allocator.destroy(entry);
        entry.* = .{
            .worker_id = worker_id,
            .token = token,
            .resource_len = @intCast(resource.len),
        };
        @memcpy(entry.resource_buf[0..resource.len], resource);

        {
            const shard = self.shardFor(key);
            self.lockShard(shard, true);
            defer self.unlockShard(shard, true);

            if (shard.full_map.contains(key)) {
                return error.AlreadyBound;
            }

            // Bare index first so a TooManyResources cap does not leave the
            // full_map entry dangling (roll back both on append failure).
            var fresh_bare_key: ?Key = null;
            const list = if (shard.bare_map.getPtr(key)) |list| list else blk: {
                const bare_key = Key{
                    .bytes = undefined,
                    .bare_len = key.bare_len,
                    .full_hash = key.bare_hash,
                    .bare_hash = key.bare_hash,
                };
                const bare_bytes = try self.allocator.dupe(u8, key.bare());
                errdefer self.allocator.free(bare_bytes);
                var stored_bare = bare_key;
                stored_bare.bytes = bare_bytes;
                try shard.bare_map.put(self.allocator, stored_bare, .{});
                fresh_bare_key = stored_bare;
                break :blk shard.bare_map.getPtr(stored_bare).?;
            };

            // A fresh bare entry that never houses a binding is rolled back
            // by this flag (T254).
            var bare_owned = fresh_bare_key != null;
            defer if (bare_owned) {
                var kv = shard.bare_map.fetchRemove(fresh_bare_key.?).?;
                kv.value.deinit(self.allocator);
                self.allocator.free(kv.key.bytes);
            };

            list.append(self.allocator, entry, self.max_resources) catch |err| {
                return err;
            };
            shard.full_map.put(self.allocator, owned_key, entry) catch |err| {
                _ = list.orderedRemove(list.len - 1);
                return err;
            };
            bare_owned = false; // the fresh bare key now houses a binding
        }

        log.info("bind {s} worker={d} session={d} gen={d}", .{
            key.bytes, worker_id, token.index, token.gen,
        });
    }

    /// Unregister a session. Returns the entry that was removed, or null if not found.
    pub fn unbind(
        self: *SessionMap,
        local: []const u8,
        domain: []const u8,
        resource: []const u8,
    ) ?SessionEntry {
        var key_buf: [MAX_JID_OCTETS]u8 = undefined;
        const key = Key.initBuf(&key_buf, local, domain, resource) orelse return null;

        var removed: SessionEntry = undefined;
        {
            const shard = self.shardFor(key);
            self.lockShard(shard, true);
            defer self.unlockShard(shard, true);

            const kv = shard.full_map.fetchRemove(key) orelse return null;
            const entry_ptr = kv.value;
            removed = entry_ptr.*;

            if (shard.bare_map.getPtr(key)) |list| {
                _ = list.removePtr(entry_ptr);
                // If bare JID has no more resources, remove the entry entirely
                if (list.len == 0) {
                    var bare_kv = shard.bare_map.fetchRemove(key).?;
                    bare_kv.value.deinit(self.allocator);
                    self.allocator.free(bare_kv.key.bytes);
                }
            }

            self.allocator.free(kv.key.bytes);
            self.allocator.destroy(entry_ptr);
        }

        log.info("unbind {s} (was worker={d} session={d} gen={d})", .{
            key.bytes, removed.worker_id, removed.token.index, removed.token.gen,
        });

        return removed;
    }

    /// Find a session by full JID (local@domain/resource). O(1).
    pub fn findByFullJid(
        self: *SessionMap,
        local: []const u8,
        domain: []const u8,
        resource: []const u8,
    ) ?SessionEntry {
        var key_buf: [MAX_JID_OCTETS]u8 = undefined;
        const key = Key.initBuf(&key_buf, local, domain, resource) orelse return null;

        const shard = self.shardFor(key);
        self.lockShard(shard, false);
        defer self.unlockShard(shard, false);

        const entry = shard.full_map.get(key) orelse return null;
        return entry.*;
    }

    /// Copy the routing entry of every bound resource of a bare JID into
    /// `out` under one shared-lock hold (S18, ADR-4 item 4). The locked
    /// section only selects and copies bounded routing state; callers
    /// serialize, deliver and log on the copies after this returns, so no
    /// stanza build, enqueue or log line ever extends a shard hold. `out`
    /// must have room for the per-account resource cap (`max_resources`):
    /// the bind path caps the entry list there, so a cap-sized buffer
    /// always receives the complete fan-out. Returns the number copied, or
    /// `error.ScratchTooSmall` when `out` cannot hold the capped worst case.
    pub fn collectBound(
        self: *SessionMap,
        local: []const u8,
        domain: []const u8,
        out: []SessionEntry,
    ) error{ScratchTooSmall}!usize {
        if (out.len < self.max_resources) return error.ScratchTooSmall;

        var key_buf: [MAX_JID_OCTETS]u8 = undefined;
        const key = Key.initBuf(&key_buf, local, domain, "") orelse return 0;

        const shard = self.shardFor(key);
        self.lockShard(shard, false);
        defer self.unlockShard(shard, false);

        const list = shard.bare_map.getPtr(key) orelse return 0;
        for (list.constSlice(), out[0..list.len]) |entry_ptr, *dst| dst.* = entry_ptr.*;
        return list.len;
    }

    /// `collectBound` restricted to presence-available resources. The same
    /// full-capacity scratch contract applies even though presence filtering
    /// can only shrink the copied set.
    pub fn collectAvailable(
        self: *SessionMap,
        local: []const u8,
        domain: []const u8,
        out: []SessionEntry,
    ) error{ScratchTooSmall}!usize {
        if (out.len < self.max_resources) return error.ScratchTooSmall;

        var key_buf: [MAX_JID_OCTETS]u8 = undefined;
        const key = Key.initBuf(&key_buf, local, domain, "") orelse return 0;

        const shard = self.shardFor(key);
        self.lockShard(shard, false);
        defer self.unlockShard(shard, false);

        const list = shard.bare_map.getPtr(key) orelse return 0;
        var copied: usize = 0;
        for (list.constSlice()) |entry_ptr| {
            if (entry_ptr.presence_available) {
                out[copied] = entry_ptr.*;
                copied += 1;
            }
        }
        return copied;
    }

    /// Check if any session is bound for a bare JID (presence state ignored).
    pub fn hasBound(self: *SessionMap, local: []const u8, domain: []const u8) bool {
        var key_buf: [MAX_JID_OCTETS]u8 = undefined;
        const key = Key.initBuf(&key_buf, local, domain, "") orelse return false;

        const shard = self.shardFor(key);
        self.lockShard(shard, false);
        defer self.unlockShard(shard, false);

        const list = shard.bare_map.getPtr(key) orelse return false;
        return list.len > 0;
    }

    /// Check if any session for a bare JID is presence-available.
    pub fn isAvailable(self: *SessionMap, local: []const u8, domain: []const u8) bool {
        var key_buf: [MAX_JID_OCTETS]u8 = undefined;
        const key = Key.initBuf(&key_buf, local, domain, "") orelse return false;

        const shard = self.shardFor(key);
        self.lockShard(shard, false);
        defer self.unlockShard(shard, false);

        const list = shard.bare_map.getPtr(key) orelse return false;
        for (list.constSlice()) |entry_ptr| {
            if (entry_ptr.presence_available) return true;
        }
        return false;
    }

    /// Update presence availability and priority for a session under one
    /// exclusive hold (T268). The entry is one object behind both indexes,
    /// so this is a single lookup and write - no re-lookup and nothing to
    /// keep in sync.
    pub fn setPresenceState(
        self: *SessionMap,
        local: []const u8,
        domain: []const u8,
        resource: []const u8,
        available: bool,
        priority: i8,
    ) void {
        var key_buf: [MAX_JID_OCTETS]u8 = undefined;
        const key = Key.initBuf(&key_buf, local, domain, resource) orelse return;

        const shard = self.shardFor(key);
        self.lockShard(shard, true);
        defer self.unlockShard(shard, true);

        if (shard.full_map.getPtr(key)) |entry_ptr| {
            entry_ptr.*.presence_available = available;
            entry_ptr.*.priority = priority;
        }
    }

    /// Mark a session as presence-available or unavailable, keeping its
    /// current priority.
    pub fn setPresenceAvailable(
        self: *SessionMap,
        local: []const u8,
        domain: []const u8,
        resource: []const u8,
        available: bool,
    ) void {
        var key_buf: [MAX_JID_OCTETS]u8 = undefined;
        const key = Key.initBuf(&key_buf, local, domain, resource) orelse return;

        const shard = self.shardFor(key);
        self.lockShard(shard, true);
        defer self.unlockShard(shard, true);

        if (shard.full_map.getPtr(key)) |entry_ptr| {
            entry_ptr.*.presence_available = available;
        }
    }

    /// Set resource priority for a session (RFC 6121 §4.7.2.3), keeping its
    /// current availability.
    pub fn setPriority(
        self: *SessionMap,
        local: []const u8,
        domain: []const u8,
        resource: []const u8,
        prio: i8,
    ) void {
        var key_buf: [MAX_JID_OCTETS]u8 = undefined;
        const key = Key.initBuf(&key_buf, local, domain, resource) orelse return;

        const shard = self.shardFor(key);
        self.lockShard(shard, true);
        defer self.unlockShard(shard, true);

        if (shard.full_map.getPtr(key)) |entry_ptr| {
            entry_ptr.*.priority = prio;
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

fn collectBound(map: *SessionMap, local: []const u8, domain: []const u8, out: []SessionEntry) usize {
    return map.collectBound(local, domain, out) catch @panic("test scratch below session map capacity");
}

fn collectAvailable(map: *SessionMap, local: []const u8, domain: []const u8, out: []SessionEntry) usize {
    return map.collectAvailable(local, domain, out) catch @panic("test scratch below session map capacity");
}

test "SessionMap: bind and findByFullJid" {
    var map = try SessionMap.init(std.testing.allocator, 1, 0);
    defer map.deinit();

    const tok = Token.init(5, 1, token_kinds.session);
    try map.bind(0, tok, "alice", "localhost", "mobile");

    const entry = map.findByFullJid("alice", "localhost", "mobile").?;
    try std.testing.expectEqual(@as(u16, 0), entry.worker_id);
    try std.testing.expect(entry.token.eql(tok));
    try std.testing.expect(!entry.presence_available);
}

test "SessionMap: unbind removes entry" {
    var map = try SessionMap.init(std.testing.allocator, 1, 0);
    defer map.deinit();

    _ = try map.bind(1, Token.init(3, 1, token_kinds.session), "bob", "localhost", "desktop");

    const removed = map.unbind("bob", "localhost", "desktop").?;
    try std.testing.expectEqual(@as(u16, 1), removed.worker_id);
    try std.testing.expectEqual(@as(u32, 3), removed.token.index);

    try std.testing.expect(map.findByFullJid("bob", "localhost", "desktop") == null);
}

test "SessionMap: collectBound copies every bound resource" {
    var map = try SessionMap.init(std.testing.allocator, 1, 0);
    defer map.deinit();

    _ = try map.bind(0, Token.init(1, 1, token_kinds.session), "alice", "localhost", "mobile");
    _ = try map.bind(1, Token.init(2, 1, token_kinds.session), "alice", "localhost", "desktop");
    _ = try map.bind(0, Token.init(3, 1, token_kinds.session), "bob", "localhost", "laptop");

    var buf: [DEFAULT_MAX_RESOURCES]SessionEntry = undefined;
    const count = collectBound(&map, "alice", "localhost", &buf);
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "SessionMap: collectAvailable" {
    var map = try SessionMap.init(std.testing.allocator, 1, 0);
    defer map.deinit();

    _ = try map.bind(0, Token.init(1, 1, token_kinds.session), "alice", "localhost", "mobile");
    _ = try map.bind(1, Token.init(2, 1, token_kinds.session), "alice", "localhost", "desktop");

    try std.testing.expect(!map.isAvailable("alice", "localhost"));

    map.setPresenceAvailable("alice", "localhost", "mobile", true);
    try std.testing.expect(map.isAvailable("alice", "localhost"));

    var buf: [DEFAULT_MAX_RESOURCES]SessionEntry = undefined;
    const count = collectAvailable(&map, "alice", "localhost", &buf);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(@as(u32, 1), buf[0].token.index);
}

test "SessionMap: copy-out rejects a scratch below the resource cap" {
    var map = try SessionMap.init(std.testing.allocator, 1, 0);
    defer map.deinit();

    _ = try map.bind(0, Token.init(1, 1, token_kinds.session), "alice", "localhost", "mobile");
    map.setPresenceAvailable("alice", "localhost", "mobile", true);

    var small: [1]SessionEntry = undefined;
    try std.testing.expectError(error.ScratchTooSmall, map.collectBound("alice", "localhost", &small));
    try std.testing.expectError(error.ScratchTooSmall, map.collectAvailable("alice", "localhost", &small));

    var full: [DEFAULT_MAX_RESOURCES]SessionEntry = undefined;
    try std.testing.expectEqual(@as(usize, 1), try map.collectBound("alice", "localhost", &full));
    try std.testing.expectEqual(@as(usize, 1), try map.collectAvailable("alice", "localhost", &full));
}

test "SessionMap: per-JID collects resolve many JIDs, grouped per JID" {
    var map = try SessionMap.init(std.testing.allocator, 1, 0);
    defer map.deinit();

    _ = try map.bind(0, Token.init(1, 1, token_kinds.session), "alice", "localhost", "mobile");
    _ = try map.bind(1, Token.init(2, 1, token_kinds.session), "alice", "localhost", "desktop");
    _ = try map.bind(0, Token.init(3, 1, token_kinds.session), "bob", "localhost", "laptop");
    _ = try map.bind(2, Token.init(4, 1, token_kinds.session), "carol", "localhost", "web");

    map.setPresenceAvailable("alice", "localhost", "mobile", true);
    map.setPresenceAvailable("alice", "localhost", "desktop", true);
    map.setPresenceAvailable("carol", "localhost", "web", true);
    // bob stays unavailable

    const jids = [_]JidParts{
        .{ .local = "alice", .domain = "localhost" },
        .{ .local = "bob", .domain = "localhost" },
        .{ .local = "carol", .domain = "localhost" },
        .{ .local = "nobody", .domain = "localhost" },
    };
    // T130 callers collect per JID; the results stay grouped in request
    // order when each collect's output is appended to one buffer.
    var buf: [DEFAULT_MAX_RESOURCES]SessionEntry = undefined;
    var idxs: [8]usize = undefined;
    var scratch: [DEFAULT_MAX_RESOURCES]SessionEntry = undefined;
    var total: usize = 0;
    for (&jids, 0..) |jid, jid_idx| {
        const n = collectAvailable(&map, jid.local, jid.domain, &scratch);
        for (scratch[0..n]) |e| {
            buf[total] = e;
            idxs[total] = jid_idx;
            total += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 3), total);
    // alice (jid 0) x2 available, carol (jid 2) x1, bob/nobody none
    try std.testing.expectEqual(@as(usize, 0), idxs[0]);
    try std.testing.expectEqual(@as(usize, 0), idxs[1]);
    try std.testing.expectEqual(@as(usize, 2), idxs[2]);
}

test "SessionMap: S18 fan-out over 32 accounts does not truncate at the old bound" {
    var map = try SessionMap.init(std.testing.allocator, 1, 0);
    defer map.deinit();

    // 32 JIDs x 20 available resources = 640 entries, over the old
    // 32x16 chunk cap and the old inline-16 per-account bound.
    var local_buf: [32][10]u8 = undefined;
    var jid_storage: [32]JidParts = undefined;
    var sid: u32 = 1;
    for (0..32) |j| {
        const local = std.fmt.bufPrint(&local_buf[j], "user{d:0>6}", .{j}) catch unreachable;
        jid_storage[j] = .{ .local = local, .domain = "localhost" };
        for (0..20) |r| {
            var res_buf: [16]u8 = undefined;
            const res = std.fmt.bufPrint(&res_buf, "res{d:0>2}", .{r}) catch unreachable;
            _ = try map.bind(0, Token.init(sid, 1, token_kinds.session), local, "localhost", res);
            map.setPresenceAvailable(local, "localhost", res, true);
            sid += 1;
        }
    }

    // Per-JID collect into a cap-sized scratch never truncates; entries
    // stay grouped by JID in request order.
    var scratch: [DEFAULT_MAX_RESOURCES]SessionEntry = undefined;
    const buf = try std.testing.allocator.alloc(SessionEntry, 640);
    defer std.testing.allocator.free(buf);
    const idxs = try std.testing.allocator.alloc(usize, 640);
    defer std.testing.allocator.free(idxs);
    var total: usize = 0;
    for (&jid_storage, 0..) |jid, jid_idx| {
        const n = collectAvailable(&map, jid.local, jid.domain, &scratch);
        try std.testing.expectEqual(@as(usize, 20), n);
        for (scratch[0..n]) |e| {
            buf[total] = e;
            idxs[total] = jid_idx;
            total += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 640), total);
    try std.testing.expectEqual(@as(usize, 0), idxs[0]);
    try std.testing.expectEqual(@as(usize, 0), idxs[19]);
    try std.testing.expectEqual(@as(usize, 1), idxs[20]);
    try std.testing.expectEqual(@as(usize, 31), idxs[639]);
}

test "SessionMap: duplicate bind fails" {
    var map = try SessionMap.init(std.testing.allocator, 1, 0);
    defer map.deinit();

    _ = try map.bind(0, Token.init(5, 1, token_kinds.session), "alice", "localhost", "mobile");
    try std.testing.expectError(error.AlreadyBound, map.bind(1, Token.init(6, 1, token_kinds.session), "alice", "localhost", "mobile"));
}

test "SessionMap: resource cap is configurable (T198)" {
    var map = try SessionMap.init(std.testing.allocator, 1, 3);
    defer map.deinit();

    _ = try map.bind(0, Token.init(1, 1, token_kinds.session), "u", "localhost", "a");
    _ = try map.bind(0, Token.init(2, 1, token_kinds.session), "u", "localhost", "b");
    _ = try map.bind(0, Token.init(3, 1, token_kinds.session), "u", "localhost", "c");
    try std.testing.expectError(error.TooManyResources, map.bind(0, Token.init(4, 1, token_kinds.session), "u", "localhost", "d"));
    // The failed bind must not leave a dangling full_map entry
    try std.testing.expect(map.findByFullJid("u", "localhost", "d") == null);
    // Cap messages come from the bare list staying consistent
    var buf: [DEFAULT_MAX_RESOURCES]SessionEntry = undefined;
    try std.testing.expectEqual(@as(usize, 3), collectBound(&map, "u", "localhost", &buf));

    // After eviction a new bind lands
    _ = map.unbind("u", "localhost", "a");
    _ = try map.bind(0, Token.init(4, 1, token_kinds.session), "u", "localhost", "d");
    try std.testing.expectEqual(@as(usize, 3), collectBound(&map, "u", "localhost", &buf));
}

test "SessionMap: default cap no longer hits the old inline-16 wall (T198)" {
    var map = try SessionMap.init(std.testing.allocator, 1, 0);
    defer map.deinit();

    var res_buf: [8]u8 = undefined;
    var i: usize = 0;
    while (i < 40) : (i += 1) {
        const res = std.fmt.bufPrint(&res_buf, "r{d}", .{i}) catch unreachable;
        _ = try map.bind(0, Token.init(100 + i, 1, token_kinds.session), "many", "localhost", res);
    }
    var buf: [DEFAULT_MAX_RESOURCES]SessionEntry = undefined;
    try std.testing.expectEqual(@as(usize, 40), collectBound(&map, "many", "localhost", &buf));

    // and leaves cleanly
    i = 0;
    while (i < 40) : (i += 1) {
        const res = std.fmt.bufPrint(&res_buf, "r{d}", .{i}) catch unreachable;
        _ = map.unbind("many", "localhost", res);
    }
    var probe: [DEFAULT_MAX_RESOURCES]SessionEntry = undefined;
    try std.testing.expectEqual(@as(usize, 0), collectBound(&map, "many", "localhost", &probe));
    try std.testing.expectEqual(@as(usize, 0), map.shards[0].bare_map.count());
}

test "SessionMap: unbind nonexistent returns null" {
    var map = try SessionMap.init(std.testing.allocator, 1, 0);
    defer map.deinit();

    try std.testing.expect(map.unbind("alice", "localhost", "ghost") == null);
}

test "SessionMap: a re-bound slot stores the caller's fresh token" {
    var map = try SessionMap.init(std.testing.allocator, 1, 0);
    defer map.deinit();

    // Generations are minted by the owning worker, not the map: a slot
    // freed and rebound arrives with a newer token.
    const first = Token.init(1, 1, token_kinds.session);
    try map.bind(0, first, "alice", "localhost", "mobile");
    _ = map.unbind("alice", "localhost", "mobile");
    const second = Token.init(1, 2, token_kinds.session);
    try map.bind(0, second, "alice", "localhost", "mobile");
    try std.testing.expect(map.findByFullJid("alice", "localhost", "mobile").?.token.eql(second));
}

test "SessionMap: bare_map cleaned on last unbind" {
    var map = try SessionMap.init(std.testing.allocator, 1, 0);
    defer map.deinit();

    _ = try map.bind(0, Token.init(1, 1, token_kinds.session), "alice", "localhost", "mobile");
    _ = try map.bind(1, Token.init(2, 1, token_kinds.session), "alice", "localhost", "desktop");

    var buf: [DEFAULT_MAX_RESOURCES]SessionEntry = undefined;
    try std.testing.expectEqual(@as(usize, 2), collectBound(&map, "alice", "localhost", &buf));

    _ = map.unbind("alice", "localhost", "mobile");
    try std.testing.expectEqual(@as(usize, 1), collectBound(&map, "alice", "localhost", &buf));

    _ = map.unbind("alice", "localhost", "desktop");
    try std.testing.expectEqual(@as(usize, 0), collectBound(&map, "alice", "localhost", &buf));
}

test "SessionMap: T254 resource cap rejection keeps maps consistent" {
    var map = try SessionMap.init(std.testing.allocator, 1, 2);
    defer map.deinit();

    _ = try map.bind(0, Token.init(1, 1, token_kinds.session), "alice", "localhost", "a");
    _ = try map.bind(0, Token.init(2, 1, token_kinds.session), "alice", "localhost", "b");
    try std.testing.expectError(error.TooManyResources, map.bind(0, Token.init(3, 1, token_kinds.session), "alice", "localhost", "c"));

    var buf: [DEFAULT_MAX_RESOURCES]SessionEntry = undefined;
    try std.testing.expectEqual(@as(usize, 2), collectBound(&map, "alice", "localhost", &buf));
    try std.testing.expect(map.findByFullJid("alice", "localhost", "c") == null);

    // The rejected bind consumed nothing: a freed slot is reusable.
    _ = map.unbind("alice", "localhost", "a");
    _ = try map.bind(0, Token.init(4, 1, token_kinds.session), "alice", "localhost", "c");
    try std.testing.expectEqual(@as(usize, 2), collectBound(&map, "alice", "localhost", &buf));
}

test "SessionMap: T254 OOM rollback at every bind allocation point" {
    // Fail each allocation in turn. A failed bind must leave both maps
    // without the half-bound account and own no memory: deinit on the
    // testing allocator reports any leak or double free.
    var fail_index: usize = 0;
    while (fail_index < 32) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        // init itself allocates (the shard slice); an init failure consumed
        // this index without reaching bind.
        var map = SessionMap.init(failing.allocator(), 1, 0) catch {
            continue;
        };
        if (map.bind(0, Token.init(1, 1, token_kinds.session), "alice", "localhost", "mobile")) |_| {
            map.deinit();
            break;
        } else |_| {
            var buf: [DEFAULT_MAX_RESOURCES]SessionEntry = undefined;
            try std.testing.expectEqual(@as(usize, 0), collectBound(&map, "alice", "localhost", &buf));
            try std.testing.expect(map.findByFullJid("alice", "localhost", "mobile") == null);
            map.deinit();
        }
    } else {
        return error.TestUnexpectedResult; // bind never succeeded: test is stuck
    }
}

test "SessionMap: workers on different threads" {
    var map = try SessionMap.init(std.testing.allocator, 4, 0);
    defer map.deinit();

    _ = try map.bind(0, Token.init(1, 1, token_kinds.session), "alice", "host", "mobile");
    _ = try map.bind(1, Token.init(1, 1, token_kinds.session), "bob", "host", "desktop");
    _ = try map.bind(2, Token.init(1, 1, token_kinds.session), "charlie", "host", "tablet");

    const alice = map.findByFullJid("alice", "host", "mobile").?;
    try std.testing.expectEqual(@as(u16, 0), alice.worker_id);

    const bob = map.findByFullJid("bob", "host", "desktop").?;
    try std.testing.expectEqual(@as(u16, 1), bob.worker_id);

    const charlie = map.findByFullJid("charlie", "host", "tablet").?;
    try std.testing.expectEqual(@as(u16, 2), charlie.worker_id);
}

test "SessionMap: resource stored in entry" {
    var map = try SessionMap.init(std.testing.allocator, 1, 0);
    defer map.deinit();

    _ = try map.bind(0, Token.init(1, 1, token_kinds.session), "alice", "host", "mobile");
    _ = try map.bind(1, Token.init(2, 1, token_kinds.session), "alice", "host", "desktop");
    map.setPresenceAvailable("alice", "host", "mobile", true);
    map.setPresenceAvailable("alice", "host", "desktop", true);

    var buf: [DEFAULT_MAX_RESOURCES]SessionEntry = undefined;
    const count = collectAvailable(&map, "alice", "host", &buf);
    try std.testing.expectEqual(@as(usize, 2), count);

    // Verify resources are stored and accessible
    var found_mobile = false;
    var found_desktop = false;
    for (buf[0..count]) |*entry| {
        const res = entry.resource();
        if (std.mem.eql(u8, res, "mobile")) found_mobile = true;
        if (std.mem.eql(u8, res, "desktop")) found_desktop = true;
    }
    try std.testing.expect(found_mobile);
    try std.testing.expect(found_desktop);
}

test "SessionMap: a 320-octet localpart binds and resolves" {
    var map = try SessionMap.init(std.testing.allocator, 1, 0);
    defer map.deinit();

    var local: [320]u8 = undefined;
    @memset(&local, 'n');
    _ = try map.bind(0, Token.init(42, 1, token_kinds.session), &local, "localhost", "res");
    map.setPresenceAvailable(&local, "localhost", "res", true);
    const entry = map.findByFullJid(&local, "localhost", "res");
    try std.testing.expect(entry != null);

    var buf: [DEFAULT_MAX_RESOURCES]SessionEntry = undefined;
    try std.testing.expectEqual(@as(usize, 1), collectAvailable(&map, &local, "localhost", &buf));
    try std.testing.expect(map.unbind(&local, "localhost", "res") != null);
}

test "SessionMap: setPresenceState updates both fields under one hold (T268)" {
    var map = try SessionMap.init(std.testing.allocator, 1, 0);
    defer map.deinit();

    _ = try map.bind(0, Token.init(1, 1, token_kinds.session), "alice", "localhost", "desk");
    map.setPresenceState("alice", "localhost", "desk", true, 42);

    const entry = map.findByFullJid("alice", "localhost", "desk").?;
    try std.testing.expect(entry.presence_available);
    try std.testing.expectEqual(@as(i8, 42), entry.priority);

    // The bare index sees the same object: no second copy to keep in sync.
    var buf: [DEFAULT_MAX_RESOURCES]SessionEntry = undefined;
    try std.testing.expectEqual(@as(usize, 1), collectAvailable(&map, "alice", "localhost", &buf));
    try std.testing.expectEqual(@as(i8, 42), buf[0].priority);
}

test "SessionMap: domain is case-folded for keys (T305)" {
    var map = try SessionMap.init(std.testing.allocator, 1, 0);
    defer map.deinit();

    _ = try map.bind(0, Token.init(1, 1, token_kinds.session), "Alice", "Example.COM", "Mobile");

    // Any case spelling of the domain resolves to the same entry.
    const folded = map.findByFullJid("Alice", "example.com", "Mobile");
    try std.testing.expect(folded != null);
    var buf: [DEFAULT_MAX_RESOURCES]SessionEntry = undefined;
    try std.testing.expectEqual(@as(usize, 1), collectBound(&map, "Alice", "EXAMPLE.com", &buf));

    // Localpart and resource keep their case: different localpart is a
    // different account, different resource a different binding.
    try std.testing.expect(map.findByFullJid("alice", "example.com", "Mobile") == null);
    try std.testing.expect(map.findByFullJid("Alice", "example.com", "mobile") == null);

    // The same full JID under another domain case is a duplicate, not a
    // second binding.
    try std.testing.expectError(error.AlreadyBound, map.bind(1, Token.init(2, 1, token_kinds.session), "Alice", "EXAMPLE.com", "Mobile"));

    // Unbind under yet another spelling removes the single entry.
    try std.testing.expect(map.unbind("Alice", "eXaMpLe.CoM", "Mobile") != null);
    try std.testing.expect(map.findByFullJid("Alice", "example.com", "Mobile") == null);
    try std.testing.expectEqual(@as(usize, 0), map.shards[0].bare_map.count());
}

test "SessionMap: shard count derives from the worker count" {
    var one = try SessionMap.init(std.testing.allocator, 1, 0);
    defer one.deinit();
    try std.testing.expectEqual(@as(usize, 1), one.shards.len);

    // pow2ceil(8 * 4) = 32; the lock is taken in multi-worker mode.
    var four = try SessionMap.init(std.testing.allocator, 4, 0);
    defer four.deinit();
    try std.testing.expectEqual(@as(usize, 32), four.shards.len);
    try std.testing.expect(four.multi_worker);

    // pow2ceil(8 * workers) clamps at 256 from 32 workers up.
    var sixty_four = try SessionMap.init(std.testing.allocator, 64, 0);
    defer sixty_four.deinit();
    try std.testing.expectEqual(@as(usize, 256), sixty_four.shards.len);
}

test "SessionMap: every JID of one account lands on one shard" {
    var map = try SessionMap.init(std.testing.allocator, 4, 0);
    defer map.deinit();

    var full_buf: [MAX_JID_OCTETS]u8 = undefined;
    const full = Key.initBuf(&full_buf, "alice", "example.com", "mobile").?;
    var bare_buf: [MAX_JID_OCTETS]u8 = undefined;
    const bare = Key.initBuf(&bare_buf, "alice", "example.com", "").?;
    var other_buf: [MAX_JID_OCTETS]u8 = undefined;
    const other_res = Key.initBuf(&other_buf, "alice", "example.com", "desk").?;

    // A bind, an unbind and a bare-JID lookup all address the same shard, so
    // account state is never split across locks.
    try std.testing.expect(map.shardFor(full) == map.shardFor(bare));
    try std.testing.expect(map.shardFor(full) == map.shardFor(other_res));

    // Cross-account keys may spread, but each lands deterministically.
    var bob_buf: [MAX_JID_OCTETS]u8 = undefined;
    const bob = Key.initBuf(&bob_buf, "bob", "example.com", "mobile").?;
    _ = map.shardFor(bob);

    _ = try map.bind(0, Token.init(1, 1, token_kinds.session), "alice", "example.com", "mobile");
    _ = try map.bind(1, Token.init(2, 1, token_kinds.session), "alice", "example.com", "desk");
    var found: [DEFAULT_MAX_RESOURCES]SessionEntry = undefined;
    try std.testing.expectEqual(@as(usize, 2), collectBound(&map, "alice", "example.com", &found));
}

test "SessionMap: normalized key computes both hashes once" {
    var buf: [MAX_JID_OCTETS]u8 = undefined;
    const key = Key.initBuf(&buf, "Alice", "Example.COM", "Mobile").?;

    try std.testing.expectEqualStrings("Alice@example.com/Mobile", key.bytes);
    try std.testing.expectEqualStrings("Alice@example.com", key.bare());
    try std.testing.expectEqual(std.hash.Wyhash.hash(0, "Alice@example.com/Mobile"), key.full_hash);
    try std.testing.expectEqual(std.hash.Wyhash.hash(0, "Alice@example.com"), key.bare_hash);

    // A bare lookup key (no resource) is the bare string itself.
    const bare_only = Key.initBuf(&buf, "Alice", "Example.COM", "").?;
    try std.testing.expectEqualStrings("Alice@example.com", bare_only.bytes);
    try std.testing.expectEqual(key.bare_hash, bare_only.bare_hash);
}
